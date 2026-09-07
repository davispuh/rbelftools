# frozen_string_literal: true

require 'stringio'

require 'elftools/constants'
require 'elftools/elf_file'
require 'elftools/exceptions'
require 'elftools/structs'
require 'elftools/string_table'
require 'elftools/util'

module ELFTools
  # Builds an ELF file.
  #
  # Add sections, segments and symbols with {#add_section}, {#add_segment}
  # and {#add_symbol}, or drop them with {#remove_section} and {#remove_segment}.
  class ELFBuilder < ELFFile
    # Added with {#add_section}; layout fills in offsets, addresses, indices and name offsets.
    Section = Struct.new(:name, :data, :type, :flags, :addr, :align,
                         :link, :info, :entsize, :pinned_offset,
                         :offset, :index, :name_offset, :sh_size,
                         keyword_init: true)

    # Added with {#add_segment}; bounds derive from +covers+ unless passed.
    Segment = Struct.new(:type, :flags, :covers, :offset, :vaddr, :paddr,
                         :filesz, :memsz, :align, keyword_init: true)

    # Added with {#add_symbol}.
    Symbol = Struct.new(:name, :value, :sym_size, :info, :other, :section,
                        keyword_init: true)

    PAGE_ALIGN = 0x1000
    private_constant :PAGE_ALIGN

    # Instantiate {ELFBuilder} empty or as a copy of +source+.
    # Anything passed explicitly overrides +source+ copy.
    # @param [#read, String, ELFFile, nil] source
    #   An ELF to copy: a stream, a path, or an {ELFFile}.
    # @option opts [Integer, Symbol, String] :machine
    #   An {ELFTools::Constants::EM} name (+:x86_64+) or value.
    # @option opts [Integer] :elf_class 32 or 64.
    # @option opts [:little, :big] :endian
    # @option opts [Integer, Symbol, String] :type
    #   An {ELFTools::Constants::ET} name or value.
    # @option opts [Integer, nil] :entry
    #   Entry point address. Defaults to the lowest loaded address.
    # @option opts [Integer] :flags +e_flags+.
    # @option opts [Integer] :osabi +EI_OSABI+.
    # @option opts [Integer] :abiversion +EI_ABIVERSION+.
    # @raise [ArgumentError] If +machine+ is missing without +source+.
    # @raise [ArgumentError] If +elf_class+ is not 32 or 64, +endian+ is not
    #   +:little+ or +:big+, or +machine+ or +type+ names nothing.
    # @example Copy an ELF, then add .extra section.
    #   builder = ELFTools::ELFBuilder.new(File.open('/bin/cat', 'rb'))
    #   builder.add_section('.extra', data: 'extra'.b)
    #   builder.save('cat.extra')
    #   #=> true
    def initialize(source = nil, **opts)
      source = normalize_source(source)
      opts = source_defaults(source).merge(opts)
      machine = opts.delete(:machine)
      raise ArgumentError, 'machine is required when no source is given' if machine.nil?

      elf_class = opts.delete(:elf_class) || 64
      endian = opts.delete(:endian) || :little
      type = opts.delete(:type) || :exec
      check_header(elf_class, endian)

      @pending_machine = resolve_value(Constants::EM, machine)
      @pending_type = resolve_value(Constants::ET, type)
      @pending_entry = opts[:entry]
      @pending_flags = opts.fetch(:flags, 0)
      @pending_osabi = opts.fetch(:osabi, 0)
      @pending_abiversion = opts.fetch(:abiversion, 0)
      @pending_sections = []
      @pending_segments = []
      @pending_symbols = []
      @skipped_segment_types = []

      @elf_class = elf_class
      @endian = endian
      copy_from(source) if source
      @bytes = assemble
      @dirty = false
      super(StringIO.new(@bytes.dup))
    end

    # Add section. Names must be unique; sections lay out in insertion
    # order, ahead of the generated +.symtab+, +.strtab+ and +.shstrtab+,
    # except that a pinned +offset+ lands wherever stated.
    # @param [String] name Section name.
    # @param [String, nil] data Section bytes. For +SHT_NOBITS+ only the length
    #   is kept; pass +size:+ instead to state it directly.
    # @param [Array<Integer, Symbol, String>, Integer] flags
    #   {ELFTools::Constants::SHF} names OR'ed together, or a bitmask.
    # @option rest [Integer, Symbol, String] :type
    #   An {ELFTools::Constants::SHT} name or value (+:progbits+ by default,
    #   +:nobits+ for a +.bss+-style section).
    # @option rest [Integer] :size Zero bytes to add instead of +data+.
    # @option rest [Integer, nil] :addr
    #   Load address. When omitted, an alloc section of an executable or
    #   shared object takes its file offset; any other section takes 0.
    # @option rest [Integer] :align Alignment. Defaults to 1.
    # @option rest [Integer, nil] :offset
    #   File offset, pinning where the section lands. When omitted, the
    #   section follows the previous one, aligned up.
    # @option rest [Integer, String] :link +sh_link+: an index, or a section
    #   name resolved to its index at layout.
    # @option rest [Integer] :info +sh_info+.
    # @option rest [Integer] :entsize +sh_entsize+.
    # @return [ELFBuilder::Section] Added section.
    # @raise [ArgumentError] If the name is taken, both +data+ and +size+ are
    #   passed, or +size:+ is not a non-negative +Integer+.
    def add_section(name, data: nil, flags: [], **opts)
      raise ArgumentError, "section #{name.inspect} already added" if @pending_sections.any? { |s| s.name == name }

      type = resolve_value(Constants::SHT, opts.fetch(:type, :progbits))
      data, sh_size = section_payload(type, data, opts)
      section = Section.new(
        name: name,
        data: data,
        type: type,
        flags: flag_value(Constants::SHF, flags),
        addr: opts[:addr],
        align: opts.fetch(:align, 1),
        pinned_offset: opts[:offset],
        link: opts.fetch(:link, 0),
        info: opts.fetch(:info, 0),
        entsize: opts.fetch(:entsize, 0),
        sh_size: sh_size
      )
      @pending_sections << section
      @dirty = true
      section
    end

    # Add symbol.
    #
    # +.symtab+ and +.strtab+ sections are created automatically.
    # @param [String] name Symbol name.
    # @param [Integer] value +st_value+.
    # @param [Integer] size +st_size+.
    # @param [Integer, Symbol, String] bind An {ELFTools::Constants::STB} name or value.
    # @option rest [Integer, Symbol, String] :type
    #   An {ELFTools::Constants::STT} name or value (+:notype+ by default).
    # @option rest [Integer, Symbol, String] :visibility
    #   An {ELFTools::Constants::STV} name or value (+:default+ by default).
    # @option rest [String, Integer, Symbol] :section
    #   An added section's name, or an {ELFTools::Constants::SHN} name or
    #   value (+:abs+ for absolute, +:undef+ by default).
    # @return [ELFBuilder::Symbol] Added symbol.
    # @raise [ArgumentError] If +section+ names a section that was not added.
    #   Will raise if +.symtab+ or +.strtab+ sections are already present.
    def add_symbol(name, value: 0, size: 0, bind: :global, **opts)
      bind = Util.fits!(resolve_value(Constants::STB, bind), 4, 'Symbol binding')
      type = Util.fits!(resolve_value(Constants::STT, opts.fetch(:type, :notype)), 4, 'Symbol type')
      visibility = Util.fits!(resolve_value(Constants::STV, opts.fetch(:visibility, :default)), 2, 'Symbol visibility')

      sym = Symbol.new(
        name: name, value: value, sym_size: size,
        info: (bind << 4) | type, other: visibility,
        section: opts.fetch(:section, :undef)
      )
      @pending_symbols << sym
      @dirty = true
      sym
    end

    # Add program header. With +covers+, offset, vaddr, filesz and
    # memsz derive from those sections.
    # @param [Integer, Symbol, String] type
    #   A {ELFTools::Constants::PT} name or value (+:load+ by default).
    # @param [Array<Integer, Symbol, String>, Integer] flags
    #   {ELFTools::Constants::PF} names OR'ed together, or a bitmask.
    # @param [Array<String>, String, :all, nil] covers
    #   Sections to derive the bounds from (+:all+ specifies all sections).
    #   Without it, +offset+, +vaddr+ and +filesz+ are required.
    # @option rest [Integer, nil] :offset File offset.
    # @option rest [Integer, nil] :vaddr Load address.
    # @option rest [Integer, nil] :paddr Physical address. Defaults to +vaddr+.
    # @option rest [Integer, nil] :filesz File size.
    # @option rest [Integer, nil] :memsz Memory size. Defaults to +filesz+.
    # @option rest [Integer] :align Defaults to 0 (no alignment).
    # @return [ELFBuilder::Segment] Added segment.
    # @raise [ArgumentError] If +type+ names nothing, or +covers+ is neither
    #   nil, +:all+, a section name nor an array of names.
    def add_segment(type: :load, flags: [], covers: nil, **opts)
      covers = Array(covers).map(&:to_s) if covers.is_a?(Array) || covers.is_a?(String)
      unless covers.nil? || covers == :all || covers.is_a?(Array)
        raise ArgumentError, "covers must be nil, :all, a section name or an array of names, got #{covers.inspect}"
      end

      seg = Segment.new(
        type: resolve_value(Constants::PT, type),
        flags: flag_value(Constants::PF, flags),
        covers: covers,
        offset: opts[:offset],
        vaddr: opts[:vaddr],
        paddr: opts[:paddr],
        filesz: opts[:filesz],
        memsz: opts[:memsz],
        align: opts.fetch(:align, 0)
      )
      @pending_segments << seg
      @dirty = true
      seg
    end

    # Opt out of derived segments: +:phdr+ drops the header table and its
    # mapping load, +:interp+, +:dynamic+ and +:note+ drop those, +:load+ drops
    # loads from alloc sections.
    # @param [Array<Integer, Symbol, String>] types
    #   {ELFTools::Constants::PT} names or values to not derive.
    # @return [Array<Integer>] Every skipped type value so far.
    # @raise [ArgumentError] If a type names nothing.
    # @example Drop the header table from a fresh executable.
    #   elf = ELFTools::ELFBuilder.new(machine: :x86_64, type: :exec)
    #   elf.add_section('.text', data: "\x90".b, addr: 0x401000, flags: %i[alloc execinstr])
    #   elf.skip_segment(:phdr)
    #   elf.segment_by_type(:phdr)
    #   #=> nil
    def skip_segment(*types)
      @skipped_segment_types |= types.map { |type| resolve_value(Constants::PT, type) }
      @dirty = true
      @skipped_segment_types.dup
    end

    # Drop section, pruning it from any segment's +covers+.
    #
    # @param [String] name Section name.
    # @return [ELFBuilder::Section] The removed section.
    # @raise [ArgumentError] If no such section, or one is still referenced.
    # @example Copy /bin/cat without its comment section.
    #   elf = ELFTools::ELFBuilder.new('/bin/cat')
    #   elf.remove_section('.comment')
    #   elf.section_by_name('.comment')
    #   #=> nil
    def remove_section(name)
      section = @pending_sections.find { |s| s.name == name }
      raise ArgumentError, "no such section #{name.inspect}" if section.nil?

      removed = @pending_sections.index(section) + 1 # +1 for the leading NULL section.
      check_section_removal!(name, removed)
      shift_section_indices!(name, removed)
      @pending_sections.delete(section)
      @pending_segments.each do |seg|
        next unless seg.covers.is_a?(Array)
        next unless seg.covers.delete(name)

        seg.offset = seg.vaddr = seg.filesz = seg.memsz = nil
      end
      @dirty = true
      section
    end

    # Drop all segments with specified type.
    # @param [Integer, Symbol, String] type
    #   A {ELFTools::Constants::PT} name or value.
    # @return [Array<ELFBuilder::Segment>] The removed segments.
    # @raise [ArgumentError] If no such segment.
    # @example Drop a copied file's note segments.
    #   elf = ELFTools::ELFBuilder.new('/bin/cat')
    #   elf.remove_segment(:note)
    #   elf.segments_by_type(:note)
    #   #=> []
    def remove_segment(type)
      value = resolve_value(Constants::PT, type)
      removed = @pending_segments.select { |seg| seg.type == value }
      raise ArgumentError, "no such #{type.inspect} segment" if removed.empty?

      @pending_segments -= removed
      @skipped_segment_types |= [value]
      @dirty = true
      removed
    end

    # Get built ELF data.
    # @return [String] The bytes of built ELF file.
    # @raise [ArgumentError] If layout is invalid.
    def to_s
      sync!
      bytes = @bytes.dup
      patches.each { |pos, val| bytes[pos, val.size] = val }
      bytes
    end

    # Write built ELF to a path or anything answering to +#write+,
    # and return the builder itself.
    # @param [String, #write] output Where to write.
    # @return [ELFBuilder] Itself.
    # @example Write a copy of /bin/cat's .text out to a file.
    #   cat = ELFTools::ELFFile.new(File.open('/bin/cat', 'rb'))
    #   elf = ELFTools::ELFBuilder.new(machine: :x86_64)
    #   elf.add_section('.text', data: cat.section_by_name('.text').data)
    #   elf.write('text.elf')
    #   elf.section_by_name('.text').data == cat.section_by_name('.text').data
    #   #=> true
    def write(output)
      bytes = to_s
      if output.respond_to?(:write)
        output.write(bytes)
      else
        File.binwrite(output, bytes)
      end
      self
    end

    # The rest of the public interface is {ELFFile}'s which memoizes parsed state,
    # so every reader needs its own mirror here.
    %i[stream header build_id dynamic machine elf_type num_sections section_by_name
       each_section sections section_at sections_by_type section_name_table num_segments
       each_segment segments segment_by_type segments_by_type segment_at
       offset_from_vma vma_from_offset patches].each do |reader|
      define_method(reader) do |*args, &block|
        sync!
        super(*args, &block)
      end
    end

    alias each_sections each_section
    alias each_segments each_segment

    # {#save} is inherited as-is: it reads through {#stream} and {#patches}.

    private

    def section_payload(type, data, opts)
      raise ArgumentError, 'pass data: or size:, not both' if !data.nil? && opts.key?(:size)
      return nobits_payload(data, opts) if type == Constants::SHT_NOBITS
      return ["\x00".b * opts.delete(:size), nil] if opts.key?(:size)

      [data.to_s.b, nil]
    end

    def nobits_payload(data, opts)
      size = data.nil? ? opts.delete(:size) || 0 : data.to_s.bytesize
      raise ArgumentError, 'size must be a non-negative Integer' unless size.is_a?(Integer) && !size.negative?

      [''.b, size]
    end

    def normalize_source(source)
      return nil if source.nil?
      return source if source.is_a?(ELFFile)

      source = StringIO.new(File.binread(source)) if source.is_a?(String)
      ELFFile.new(source)
    end

    def check_header(elf_class, endian)
      raise ArgumentError, "elf_class must be 32 or 64, got #{elf_class}" unless [32, 64].include?(elf_class)

      return if %i[little big].include?(endian)

      raise ArgumentError, "endian must be :little or :big, got #{endian.inspect}"
    end

    def source_defaults(source)
      return {} if source.nil?

      {
        machine: source.header.e_machine.to_i,
        elf_class: source.elf_class,
        endian: source.endian,
        type: source.header.e_type.to_i,
        entry: source.header.e_entry.to_i,
        flags: source.header.e_flags.to_i,
        osabi: source.header.e_ident.ei_osabi.to_i,
        abiversion: source.header.e_ident.ei_abiversion.to_i
      }
    end

    def copy_from(source)
      copy_sections_from(source)
      copy_segments_from(source)
    end

    def copy_sections_from(source)
      source.sections.each do |section|
        next if section.name.empty?

        header = section.header
        opts = { type: header.sh_type.to_i, flags: header.sh_flags.to_i,
                 addr: header.sh_addr.to_i, align: header.sh_addralign.to_i,
                 offset: header.sh_offset.to_i,
                 link: header.sh_link.to_i, info: header.sh_info.to_i,
                 entsize: header.sh_entsize.to_i }
        if header.sh_type.to_i == Constants::SHT_NOBITS
          add_section(section.name, **opts, size: header.sh_size.to_i)
        else
          add_section(section.name, data: section.data, **opts)
        end
      end
    end

    def copy_segments_from(source)
      source.segments.each do |segment|
        header = segment.header
        covered = source.sections.select { |s| covers_section?(s, header) }.map(&:name)
        covers = header.p_type.to_i == pt(:load) && !covered.empty? && !header.p_offset.to_i.zero? ? covered : nil
        add_segment(type: header.p_type.to_i, flags: header.p_flags.to_i, covers: covers,
                    offset: header.p_offset.to_i, vaddr: header.p_vaddr.to_i, paddr: header.p_paddr.to_i,
                    filesz: header.p_filesz.to_i, memsz: header.p_memsz.to_i, align: header.p_align.to_i)
      end
    end

    def covers_section?(section, header)
      return false if section.name.empty? || section.name == '.shstrtab'

      sh = section.header
      if sh.sh_type.to_i == Constants::SHT_NOBITS
        sh.sh_addr.to_i >= header.p_vaddr.to_i &&
          sh.sh_addr.to_i + sh.sh_size.to_i <= header.p_vaddr.to_i + header.p_memsz.to_i
      else
        !header.p_filesz.to_i.zero? && sh.sh_offset.to_i >= header.p_offset.to_i &&
          sh.sh_offset.to_i + sh.sh_size.to_i <= header.p_offset.to_i + header.p_filesz.to_i
      end
    end

    def sync!
      return unless @dirty

      @bytes = assemble
      @stream = StringIO.new(@bytes.dup)
      reset!
      @dirty = false
    end

    def assemble
      all = ordered_sections
      segments = effective_segments
      table_end = headers_size(segments.size)
      data_end = place_sections(all, table_end)
      shoff = align_up(data_end, word_align)
      resolved = resolve_segments(all, segments, table_end)

      out = +''.b
      out << build_ehdr(all, shoff, segments).to_binary_s
      build_phdrs(resolved).each { |phdr| out << phdr.to_binary_s }

      all.select { |sec| !sec.index.zero? && sec.type != Constants::SHT_NOBITS }
         .sort_by { |sec| [sec.offset, sec.index] }
         .each do |sec|
        pad_to(out, sec.offset)
        out << sec.data
      end

      pad_to(out, shoff)
      all.each { |sec| out << build_shdr(sec) }
      out
    end

    def pad_to(out, offset)
      pad = offset - out.bytesize
      out << ("\x00".b * pad) if pad.positive?
    end

    def ordered_sections
      null = Section.new(name: '', data: +''.b, type: Constants::SHT_NULL,
                         flags: 0, addr: 0, align: 0)

      symtab, strtab = build_symbol_tables
      sections = [null] + @pending_sections + [symtab, strtab].compact
      sections << shstrtab_section(sections)

      sections.each_with_index { |sec, i| sec.index = i }
      symtab.link = sections.index(strtab) if symtab
      resolve_section_links(sections)
      sections
    end

    def shstrtab_section(sections)
      provided = sections.find { |sec| sec.name == '.shstrtab' }
      sections.delete(provided) unless provided.nil?
      table = provided ? provided.data.dup : +"\x00".b
      sections.each { |sec| sec.name_offset = shstrtab_offset(table, sec.name) }
      section = shstrtab_shell(provided, table)
      section.name_offset = shstrtab_offset(table, section.name)
      section
    end

    def shstrtab_shell(provided, table)
      if provided.nil?
        return Section.new(name: '.shstrtab', data: table, type: Constants::SHT_STRTAB,
                           flags: 0, addr: 0, align: 1)
      end
      return provided if table.bytesize == provided.data.bytesize

      shell = provided.dup
      shell.data = table
      shell.pinned_offset = nil
      shell
    end

    def shstrtab_offset(table, name)
      return 0 if name.empty?

      offset = table.index("\x00#{name}\x00")
      if offset.nil?
        table << "\x00".b unless table.end_with?("\x00")
        offset = table.bytesize - 1
        table << name.b << "\x00".b
      end
      offset + 1
    end

    def resolve_section_links(sections)
      by_name = sections.to_h { |sec| [sec.name, sec.index] }
      sections.each do |sec|
        next unless sec.link.is_a?(String)

        index = by_name[sec.link]
        raise ArgumentError, "section #{sec.name.inspect} links unknown section #{sec.link.inspect}" if index.nil?

        sec.link = index
      end
    end

    def build_symbol_tables
      return [nil, nil] if @pending_symbols.empty?

      sections = @pending_sections.map(&:name) & %w[.symtab .strtab]
      unless sections.empty?
        raise ArgumentError,
              "cannot add symbols with #{sections.map(&:inspect).join(' and ')} already added"
      end

      strtab = StringTable.new

      locals, globals = @pending_symbols.partition { |s| (s.info >> 4) == Constants::STB_LOCAL }

      null_info = (Constants::STB_LOCAL << 4) | Constants::STT_NOTYPE
      null_sym = Symbol.new(name: '', value: 0, sym_size: 0, info: null_info, other: 0, section: :undef)
      ordered_syms = [null_sym] + locals + globals

      sym_klass = Structs::ELF_sym[@elf_class]
      sym_bytes = ordered_syms.map do |sym|
        s = sym_klass.new(endian: @endian)
        s.st_name = strtab.add(sym.name)
        s.st_value = sym.value
        s.st_size = sym.sym_size
        s.st_info = sym.info
        s.st_other = sym.other
        s.st_shndx = resolve_shndx(sym.section)
        s.to_binary_s
      end.join

      strtab_section = Section.new(
        name: '.strtab', data: strtab.bytes,
        type: Constants::SHT_STRTAB, flags: 0, addr: 0, align: 1
      )
      symtab_section = Section.new(
        name: '.symtab', data: sym_bytes,
        type: Constants::SHT_SYMTAB, flags: 0, addr: 0,
        align: word_align,
        info: 1 + locals.length,
        entsize: sym_klass.num_bytes(elf_class: @elf_class, endian: @endian)
      )
      [symtab_section, strtab_section]
    end

    def resolve_shndx(section)
      return resolve_value(Constants::SHN, section) unless section.is_a?(String)

      index = @pending_sections.find_index { |s| s.name == section }
      raise ArgumentError, "symbol references unadded section #{section.inspect}" if index.nil?

      index + 1 # +1 for the leading NULL section.
    end

    def check_section_removal!(name, removed)
      check_section_links!(name, removed)
      @pending_sections.each do |sec|
        next if sec.name == name

        remap_indexed_data!(sec, name, removed, check_only: true)
      end
    end

    def check_section_links!(name, removed)
      @pending_sections.each do |sec|
        next if sec.name == name

        if sec.link.is_a?(Integer) && sec.link == removed
          raise ArgumentError,
                "cannot remove #{name.inspect}: #{sec.name.inspect} links to it; remove #{sec.name.inspect} first"
        end
        next unless reloc_section?(sec) && sec.info == removed

        raise ArgumentError,
              "cannot remove #{name.inspect}: relocations in #{sec.name.inspect} apply to it; " \
              "remove #{sec.name.inspect} first"
      end
    end

    def reloc_section?(sec)
      [Constants::SHT_REL, Constants::SHT_RELA].include?(sec.type)
    end

    def remap_indexed_data!(sec, name, removed, check_only:)
      case sec.type
      when Constants::SHT_SYMTAB, Constants::SHT_DYNSYM
        remap_symbols!(sec, name, removed, check_only: check_only)
      when Constants::SHT_GROUP
        remap_members!(sec, name, removed, skip_first: true, check_only: check_only)
      when Constants::SHT_SYMTAB_SHNDX
        remap_members!(sec, name, removed, skip_first: false, check_only: check_only)
      end
    end

    def remap_symbols!(sec, name, removed, check_only:)
      entries, rest = symbol_entries(sec)
      entries.each_with_index do |entry, i|
        slid = slid_index(entry.st_shndx.to_i, removed)
        if slid.nil?
          raise ArgumentError,
                "cannot remove #{name.inspect}: symbol #{i} in #{sec.name.inspect} is defined in it; " \
                "remove #{sec.name.inspect} first"
        end
        entry.st_shndx = slid unless check_only
      end
      return if check_only

      sec.data = entries.map(&:to_binary_s).join + rest
    end

    def slid_index(index, removed)
      return index if index.zero? || index >= Constants::SHN_LORESERVE
      return nil if index == removed

      index > removed ? index - 1 : index
    end

    def remap_members!(sec, name, removed, skip_first:, check_only:)
      words, rest = index_words(sec.data)
      head = skip_first ? words.first(1) : []
      tail = words.drop(skip_first ? 1 : 0).map do |index|
        slid = slid_index(index, removed)
        next slid unless slid.nil?

        reason = skip_first ? "group #{sec.name.inspect} contains it" : "symbol in #{sec.name.inspect} is defined in it"
        raise ArgumentError, "cannot remove #{name.inspect}: #{reason}; remove #{sec.name.inspect} first"
      end
      return if check_only

      sec.data = (head + tail).pack("#{word_format}*") + rest
    end

    def shift_section_indices!(name, removed)
      @pending_sections.each do |sec|
        next if sec.name == name

        sec.link -= 1 if sec.link.is_a?(Integer) && sec.link > removed
        sec.info -= 1 if reloc_section?(sec) && sec.info.is_a?(Integer) && sec.info > removed
        remap_indexed_data!(sec, name, removed, check_only: false)
      end
    end

    def symbol_entries(sec)
      klass = Structs::ELF_sym[@elf_class]
      size = klass.num_bytes(elf_class: @elf_class, endian: @endian)
      count = sec.data.bytesize / size
      entries = Array.new(count) do |i|
        klass.new(endian: @endian).read(StringIO.new(sec.data.byteslice(i * size, size)))
      end
      [entries, sec.data.byteslice(count * size..) || +''.b]
    end

    def index_words(data)
      words = data.unpack("#{word_format}*")
      [words, data.byteslice(words.length * 4..) || +''.b]
    end

    def word_format
      @endian == :big ? 'L>' : 'L<'
    end

    def section_size(sec)
      sec.type == Constants::SHT_NOBITS && !sec.sh_size.nil? ? sec.sh_size : sec.data.bytesize
    end

    def place_sections(sections, start)
      offset = start
      ranges = [[0, start]]
      sections.each do |sec|
        next if sec.index.zero?

        offset = place_section(sec, offset, ranges)
      end
      offset
    end

    def place_section(sec, offset, ranges)
      sec.offset = sec.pinned_offset.nil? ? auto_offset(sec, offset) : checked_pinned_offset(sec, ranges)
      sec.addr = auto_addr(sec) if sec.addr.nil?
      unless sec.type == Constants::SHT_NOBITS
        ranges << [sec.offset, sec.offset + sec.data.bytesize]
        offset = [offset, sec.offset + sec.data.bytesize].max
      end
      offset
    end

    def auto_offset(sec, offset)
      offset = align_up(offset, sec.align) if sec.align > 1
      align_to_segment(sec, offset)
    end

    def align_to_segment(sec, offset)
      alloc = (sec.flags & Constants::SHF_ALLOC) != 0
      return offset unless sec.addr && alloc && loadable_type?

      offset + ((sec.addr - offset) % PAGE_ALIGN)
    end

    def loadable_type?
      [Constants::ET_EXEC, Constants::ET_DYN].include?(@pending_type)
    end

    def auto_addr(sec)
      return 0 if (sec.flags & Constants::SHF_ALLOC).zero?
      return 0 unless loadable_type?

      sec.offset
    end

    def checked_pinned_offset(sec, ranges)
      unless sec.type == Constants::SHT_NOBITS
        if sec.align > 1 && (sec.pinned_offset % sec.align) != 0
          raise ArgumentError,
                "offset #{sec.pinned_offset} for section #{sec.name.inspect} is not a multiple of its alignment"
        end
        if ranges.any? { |from, to| sec.pinned_offset < to && from < sec.pinned_offset + sec.data.bytesize }
          raise ArgumentError,
                "offset #{sec.pinned_offset} for section #{sec.name.inspect} overlaps an earlier section or a header"
        end
      end
      sec.pinned_offset
    end

    def default_entry(sections)
      loaded = sections.select { |s| !s.index.zero? && (s.flags & Constants::SHF_ALLOC) != 0 }
      loaded.map(&:addr).min || 0
    end

    def build_ehdr(sections, shoff, segments)
      ehdr = Structs::ELF_Ehdr.new(endian: @endian)
      ehdr.elf_class = @elf_class
      ehdr.e_ident.magic = Constants::ELFMAG
      ehdr.e_ident.ei_class = (@elf_class == 64 ? 2 : 1)
      ehdr.e_ident.ei_data = (@endian == :little ? 1 : 2)
      ehdr.e_ident.ei_version = 1 # EV_CURRENT.
      ehdr.e_ident.ei_osabi = @pending_osabi
      ehdr.e_ident.ei_abiversion = @pending_abiversion
      ehdr.e_ident.ei_padding = "\x00".b * 7

      ehdr.e_type = @pending_type
      ehdr.e_machine = @pending_machine
      ehdr.e_version = 1
      ehdr.e_entry = @pending_entry.nil? ? default_entry(sections) : @pending_entry
      ehdr.e_phoff = segments.empty? ? 0 : Structs::ELF_Ehdr.num_bytes(elf_class: @elf_class, endian: @endian)
      ehdr.e_shoff = shoff
      ehdr.e_flags = @pending_flags
      ehdr.e_ehsize = ehdr.num_bytes
      ehdr.e_phentsize = Structs::ELF_Phdr[@elf_class].num_bytes(elf_class: @elf_class, endian: @endian)
      ehdr.e_phnum = segments.length
      ehdr.e_shentsize = Structs::ELF_Shdr.num_bytes(elf_class: @elf_class, endian: @endian)
      ehdr.e_shnum = sections.length
      ehdr.e_shstrndx = sections.length - 1
      ehdr
    end

    def build_shdr(sec)
      shdr = Structs::ELF_Shdr.new(endian: @endian)
      shdr.elf_class = @elf_class
      shdr.sh_name = sec.name_offset || 0
      shdr.sh_type = sec.type
      shdr.sh_flags = sec.flags
      shdr.sh_addr = sec.addr
      shdr.sh_offset = sec.index.zero? ? 0 : (sec.offset || 0)
      shdr.sh_size = sec.index.zero? ? 0 : section_size(sec)
      shdr.sh_link = sec.link || 0
      shdr.sh_info = sec.info || 0
      shdr.sh_addralign = sec.align
      shdr.sh_entsize = sec.entsize || 0
      shdr.to_binary_s
    end

    def build_phdrs(segments)
      segments.map do |seg|
        phdr = Structs::ELF_Phdr[@elf_class].new(endian: @endian)
        phdr.elf_class = @elf_class
        phdr.p_type = seg.type
        phdr.p_flags = seg.flags || 0
        phdr.p_offset = seg.offset
        phdr.p_vaddr = seg.vaddr
        phdr.p_paddr = seg.paddr || seg.vaddr
        phdr.p_filesz = seg.filesz
        phdr.p_memsz = seg.memsz || seg.filesz
        phdr.p_align = seg.align || 0
        phdr
      end
    end

    def effective_segments
      return @pending_segments unless loadable_type?

      derived_segments(@pending_sections) + @pending_segments
    end

    def derived_segments(sections)
      suppressed = @pending_segments.map(&:type) | @skipped_segment_types
      segs = derived_interp(sections, suppressed)
      segs.concat(derived_loads(sections, suppressed))
      segs.concat(derived_dynamic(sections, suppressed))
      segs.concat(derived_notes(sections, suppressed))
      unless suppressed.include?(pt(:phdr))
        segs.unshift(derived_header_load)
        segs.unshift(derived_phdr(segs.size + @pending_segments.size + 1))
      end
      segs
    end

    def derived_header_load
      Segment.new(type: pt(:load), flags: Constants::PF_R, covers: :headers, align: PAGE_ALIGN)
    end

    def derived_phdr(count)
      ehsize = Structs::ELF_Ehdr.num_bytes(elf_class: @elf_class, endian: @endian)
      filesz = count * Structs::ELF_Phdr[@elf_class].num_bytes(elf_class: @elf_class, endian: @endian)
      Segment.new(type: pt(:phdr), flags: Constants::PF_R, covers: :headers, offset: ehsize, filesz: filesz,
                  align: word_align)
    end

    def derived_interp(sections, suppressed)
      return [] if suppressed.include?(pt(:interp))

      interp = sections.find { |s| s.name == '.interp' }
      return [] if interp.nil?

      [Segment.new(type: pt(:interp), flags: Constants::PF_R, covers: [interp.name], align: 1)]
    end

    def derived_dynamic(sections, suppressed)
      return [] if suppressed.include?(pt(:dynamic))

      dynamic = sections.find { |s| s.type == Constants::SHT_DYNAMIC }
      return [] if dynamic.nil?

      [Segment.new(type: pt(:dynamic), flags: Constants::PF_R | Constants::PF_W, covers: [dynamic.name],
                   align: word_align)]
    end

    def derived_notes(sections, suppressed)
      return [] if suppressed.include?(pt(:note))

      sections.select { |s| s.type == Constants::SHT_NOTE }.map do |note|
        Segment.new(type: pt(:note), flags: Constants::PF_R, covers: [note.name], align: 4)
      end
    end

    def pt(name)
      resolve_value(Constants::PT, name)
    end

    def derived_loads(sections, suppressed)
      return [] if suppressed.include?(pt(:load))

      alloc = sections.reject { |s| (s.flags & Constants::SHF_ALLOC).zero? }
      alloc.group_by(&:flags).map do |flags, group|
        pf = Constants::PF_R
        pf |= Constants::PF_W if (flags & Constants::SHF_WRITE) != 0
        pf |= Constants::PF_X if (flags & Constants::SHF_EXECINSTR) != 0
        Segment.new(type: pt(:load), flags: pf, covers: group.map(&:name), align: PAGE_ALIGN)
      end
    end

    def resolve_segments(sections, segments, table_end)
      segments.map { |seg| resolve_segment(seg.dup, sections, table_end) }
    end

    def resolve_segment(seg, sections, table_end)
      if seg.covers.nil?
        check_explicit_segment(seg)
      elsif seg.covers == :headers
        apply_header_bounds(seg, sections, table_end)
      else
        covered = resolve_covered_sections(seg.covers, sections)
        raise ArgumentError, 'segment covers no sections' if covered.empty?

        apply_covered_bounds(seg, covered)
      end
      seg
    end

    def apply_header_bounds(seg, sections, table_end)
      stop = sections.find { |s| !s.index.zero? && (s.flags & Constants::SHF_ALLOC).zero? }
      base = header_base_vaddr(sections, stop)
      if seg.type == pt(:phdr)
        seg.vaddr = base + seg.offset
      else
        seg.offset = 0
        seg.vaddr = base
        seg.filesz = table_end
        check_load_alignment!(seg)
      end
      seg
    end

    def header_base_vaddr(sections, stop)
      first = sections.find do |s|
        !s.index.zero? && (s.flags & Constants::SHF_ALLOC) != 0 && (stop.nil? || s.offset < stop.offset)
      end
      first.nil? ? 0 : [first.addr - first.offset, 0].max
    end

    def apply_covered_bounds(seg, covered)
      offset, filesz = segment_file_bounds(covered)
      seg.offset = offset if seg.offset.nil?
      seg.filesz = filesz if seg.filesz.nil?
      seg.vaddr = covered.map(&:addr).min if seg.vaddr.nil?
      seg.memsz = covered.map { |s| s.addr + section_size(s) }.max - seg.vaddr if seg.memsz.nil?
      seg.memsz = seg.filesz if seg.memsz < seg.filesz
      check_load_alignment!(seg)
      seg
    end

    def check_load_alignment!(seg)
      return unless seg.type == pt(:load) && (seg.align || 0) > 1
      return if ((seg.offset - seg.vaddr) % seg.align).zero?

      raise ArgumentError,
            "load segment offset #{seg.offset} mismatches vaddr #{seg.vaddr} for alignment #{seg.align}"
    end

    def check_explicit_segment(seg)
      missing = %i[offset vaddr filesz].select { |field| seg[field].nil? }
      raise ArgumentError, "segment without covers: needs #{missing.join(', ')}" unless missing.empty?
    end

    def segment_file_bounds(covered)
      non_nobits = covered.reject { |s| s.type == Constants::SHT_NOBITS }
      return [covered.first.offset, 0] if non_nobits.empty?

      offset = non_nobits.map(&:offset).min
      filesz = non_nobits.map { |s| s.offset + s.data.bytesize }.max - offset
      [offset, filesz]
    end

    def resolve_covered_sections(names, sections)
      names = @pending_sections.map(&:name) if names == :all
      names.map do |name|
        sec = sections.find { |s| s.name == name }
        raise ArgumentError, "segment covers unknown section #{name.inspect}" if sec.nil?

        sec
      end
    end

    def align_up(offset, align)
      ((offset + align - 1) / align) * align
    end

    def headers_size(count)
      Structs::ELF_Ehdr.num_bytes(elf_class: @elf_class, endian: @endian) +
        count * Structs::ELF_Phdr[@elf_class].num_bytes(elf_class: @elf_class, endian: @endian)
    end

    def word_align
      @elf_class == 64 ? 8 : 4
    end

    def resolve_value(mod, val)
      return val if val.is_a?(Integer)

      Util.to_constant(mod, val)
    end

    def flag_value(mod, flags)
      Array(flags).reduce(0) { |mask, flag| mask | resolve_value(mod, flag) }
    end
  end
end
