# frozen_string_literal: true

require 'stringio'
require 'tempfile'

require 'elftools'

describe ELFTools::ELFBuilder do
  def build(**options)
    builder = described_class.new(**options)
    yield builder
    builder
  end

  def build_id_note
    [4, 20, 3].pack('VVV') + "GNU\0".b + "\xab".b * 20
  end

  def sym_bytes(*shndxs)
    klass = ELFTools::Structs::ELF_sym[64]
    shndxs.map do |shndx|
      s = klass.new(endian: :little)
      s.st_name = 0
      s.st_info = 0
      s.st_other = 0
      s.st_shndx = shndx
      s.st_value = 0
      s.st_size = 0
      s.to_binary_s
    end.join
  end

  def amd64_copy
    described_class.new(StringIO.new(File.binread('spec/files/amd64.elf')))
  end

  def build_elf
    build(machine: :x86_64, type: :dyn, entry: 0x400000) do |b|
      b.add_section('.text', data: "\x90\xc3".b, addr: 0x400000, flags: %i[alloc execinstr], align: 16)
      b.add_section('.rodata', data: 'ro'.b, addr: 0x401000, flags: %i[alloc], align: 8)
      b.add_section('.note.gnu.build-id', data: build_id_note, type: :note, flags: %i[alloc], addr: 0x401020)
      b.add_section('.data', data: 'hi'.b, addr: 0x402000, flags: %i[alloc write], align: 8)
      b.add_section('.bss', type: :nobits, size: 64, flags: %i[alloc write], addr: 0x402068, align: 8)
      b.add_section('.dynamic', data: "\x00".b * 32, type: :dynamic, flags: %i[alloc write], addr: 0x402048,
                                align: 8)
      b.add_symbol('pie.c', type: :file, bind: :local, section: :abs)
      b.add_symbol('helper', type: :func, bind: :local, value: 0x400000, size: 2, section: '.text')
      b.add_symbol('main', type: :func, value: 0x400000, size: 2, section: '.text')
      b.add_symbol('_heap', value: 0x403000, section: :abs)
      b.add_symbol('puts')
      b.add_segment(type: :note, covers: %w[.note.gnu.build-id], flags: %i[r])
      b.add_segment(type: :dynamic, covers: %w[.dynamic], flags: %i[r w])
      b.add_segment(type: :gnu_stack, flags: %i[r w], offset: 0, vaddr: 0, filesz: 0, align: 0x10)
      b.add_segment(type: :phdr, flags: %i[r], offset: 64, vaddr: 0x40, filesz: 56 * 7, align: 8)
    end
  end

  it 'builds a small ELF that reopens byte-identically' do
    elf = build_elf
    expect(elf).to be_a(ELFTools::ELFFile)
    expect(elf.elf_class).to be 64
    expect(elf.endian).to be :little
    expect(elf.header.e_machine.to_i).to eq ELFTools::Constants::EM_X86_64
    expect(elf.elf_type).to eq 'DYN'
    expect(elf.header.e_entry.to_i).to eq 0x400000
    expect(elf.num_sections).to eq 10
    expect(elf.num_segments).to eq 7
    expect(elf.section_by_name('.text').data).to eq "\x90\xc3".b
    expect(elf.section_by_name('.rodata').data).to eq 'ro'.b
    expect(elf.section_by_name('.data').data).to eq 'hi'.b
    expect(elf.section_by_name('.bss').header.sh_size.to_i).to eq 64
    expect(elf.build_id).to eq 'ab' * 20
    expect(elf.dynamic).not_to be_nil

    symtab = elf.section_by_name('.symtab')
    expect(symtab.header.sh_info.to_i).to eq 3 # null + 2 locals before the globals
    main = symtab.symbol_by_name('main')
    expect(main.value).to eq 0x400000
    expect(main.type_name).to eq 'STT_FUNC'
    expect(main.bind_name).to eq 'STB_GLOBAL'
    expect(main.section_index).to eq 1 # .text, after NULL
    expect(symtab.symbol_by_name('pie.c').type_name).to eq 'STT_FILE'
    expect(symtab.symbol_by_name('_heap').value).to eq 0x403000
    expect(symtab.symbol_by_name('puts').section_index).to be 0

    loads = elf.segments_by_type(:load)
    expect(loads.size).to eq 3
    text_seg = loads.find { |s| s.header.p_vaddr.to_i == 0x400000 }
    expect(text_seg.header.p_filesz.to_i).to eq 2
    data_seg = loads.find { |s| s.header.p_vaddr.to_i == 0x402000 }
    expect(data_seg.header.p_memsz.to_i - data_seg.header.p_filesz.to_i).to eq 64 # the .bss tail
    expect(elf.segment_by_type(:note)).not_to be_nil

    reopened = ELFTools::ELFFile.new(StringIO.new(elf.to_s))
    expect(reopened.section_by_name('.text').data).to eq "\x90\xc3".b
    expect(reopened.header.e_entry.to_i).to eq 0x400000
  end

  it 'copies from stream, path and ELFFile' do
    source_elf = build_elf
    elf = described_class.new(StringIO.new(source_elf.to_s))
    expect(elf.to_s).to eq source_elf.to_s
    expect(elf.sections.map(&:name)).to eq source_elf.sections.map(&:name)
    expect(elf.section_by_name('.bss').header.sh_size.to_i).to eq 64
    expect(elf.build_id).to eq source_elf.build_id
    expect(elf.header.e_entry.to_i).to eq source_elf.header.e_entry.to_i

    io = StringIO.new
    io.binmode
    elf.write(io)
    io.rewind
    expect(io.read).to eq elf.to_s

    Tempfile.create(['elf', '.bin']) do |f|
      source_elf.write(f.path)
      from_path = described_class.new(f.path)
      expect(from_path.section_by_name('.text').data).to eq "\x90\xc3".b
      expect(from_path.num_segments).to eq 7
    end
    from_elf = described_class.new(ELFTools::ELFFile.new(StringIO.new(source_elf.to_s)))
    expect(from_elf.header.e_entry.to_i).to eq 0x400000
    overridden = described_class.new(StringIO.new(source_elf.to_s), entry: 0x1234, type: :exec)
    expect(overridden.header.e_entry.to_i).to eq 0x1234
    expect(overridden.elf_type).to eq 'EXEC'

    elf.add_section('.extra', data: 'e'.b)
    expect(elf.section_by_name('.extra').data).to eq 'e'.b
    expect(elf.section_by_name('.text').data).to eq "\x90\xc3".b
    expect(elf.num_sections).to eq source_elf.num_sections + 1
    expect(elf.segments_by_type(:load).size).to eq source_elf.segments_by_type(:load).size
  end

  it 'rejects bad input' do
    expect { described_class.new }.to raise_error(ArgumentError, /machine is required/)
    expect { described_class.new(machine: :nope) }.to raise_error(ArgumentError, /EM/)
    expect { described_class.new(machine: :x86_64, elf_class: 48) }.to raise_error(ArgumentError, /elf_class/)
    expect { described_class.new(machine: :x86_64, endian: :middle) }.to raise_error(ArgumentError, /endian/)
    expect { described_class.new(machine: :x86_64, type: :nope) }.to raise_error(ArgumentError, /ET/)
    expect do
      build(machine: :x86_64) do |b|
        b.add_section('.text', data: 'x'.b)
        b.add_section('.text', data: 'y'.b)
      end
    end.to raise_error(ArgumentError, /already added/)
    expect do
      build(machine: :x86_64) { |b| b.add_section('.bss', data: "\x00".b, size: 1) }
    end.to raise_error(ArgumentError, /data: or size:/)
    expect do
      build(machine: :x86_64) { |b| b.add_symbol('orphan', section: '.nope') }.to_s
    end.to raise_error(ArgumentError, /unadded section/)
    expect do
      build(machine: :x86_64) do |b|
        b.add_segment(type: :load, covers: %w[.nope], flags: %i[r x])
      end.to_s
    end.to raise_error(ArgumentError, /unknown section/)
    expect do
      build(machine: :x86_64) do |b|
        b.add_section('.text', data: "\x90".b)
        b.add_segment(type: :load, flags: %i[r x])
      end.to_s
    end.to raise_error(ArgumentError, /needs offset, vaddr, filesz/)
    expect do
      build(machine: :x86_64) { |b| b.add_segment(type: :load, covers: [], flags: %i[r x]) }.to_s
    end.to raise_error(ArgumentError, /covers no sections/)
    expect do
      build(machine: :x86_64) { |b| b.skip_segment(:bogus) }
    end.to raise_error(ArgumentError, /PT/)
    expect do
      build(machine: :x86_64) { |b| b.add_segment(type: :load, covers: 123, flags: %i[r]) }
    end.to raise_error(ArgumentError, /covers must be/)
    expect do
      build(machine: :x86_64) { |b| b.add_section('.a', data: 'a'.b, link: '.missing') }.to_s
    end.to raise_error(ArgumentError, /unknown section/)
    expect do
      build(machine: :x86_64) { |b| b.remove_section('.nope') }
    end.to raise_error(ArgumentError, /no such section/)
    expect do
      build(machine: :x86_64) { |b| b.remove_segment(:note) }
    end.to raise_error(ArgumentError, /no such .* segment/)
    expect do
      build(machine: :x86_64) do |b|
        b.add_section('.a', data: 'aa'.b, offset: 0x100)
        b.add_section('.b', data: 'b'.b, offset: 0x101)
      end.to_s
    end.to raise_error(ArgumentError, /overlaps/)
    expect do
      build(machine: :x86_64) { |b| b.add_section('.a', data: 'aa'.b, align: 2, offset: 0x101) }.to_s
    end.to raise_error(ArgumentError, /multiple of its alignment/)
    expect do
      build(machine: :x86_64, type: :exec, entry: 0x401000) do |b|
        b.add_section('.text', data: "\x90".b, addr: 0x401000, flags: %i[alloc execinstr], offset: 0x100)
      end.to_s
    end.to raise_error(ArgumentError, /mismatches vaddr/)
  end

  it 'derives segment bounds from covers' do
    elf = build(machine: :x86_64) do |b|
      b.add_section('.a', data: 'aa'.b, align: 2048)
      b.add_section('.b', data: 'bbbbb'.b, align: 1024)
      b.add_segment(type: :load, flags: %i[r], covers: :all)
    end
    expect(elf.segments_by_type(:load).length).to eq 2
    seg = elf.segments_by_type(:load).find { |s| s.header.p_offset.to_i == 2048 }
    expect(seg.header.p_offset.to_i).to eq 2048
    expect(seg.header.p_memsz.to_i).to eq 1024 + 5
    expect(seg.header.p_filesz.to_i).to eq 1024 + 5

    explicit = build(machine: :x86_64) do |b|
      b.add_section('.text', data: "\x90".b, addr: 0x400000, flags: %i[alloc execinstr])
      b.add_segment(type: :load, covers: %w[.text], offset: 0x200, vaddr: 0x400000, filesz: 1, memsz: 0x1234,
                    paddr: 0x400100, flags: %i[r x])
    end
    header = explicit.segments_by_type(:load).find { |s| s.header.p_vaddr.to_i == 0x400000 }.header
    expect([header.p_offset.to_i, header.p_vaddr.to_i, header.p_filesz.to_i,
            header.p_memsz.to_i, header.p_paddr.to_i]).to eq [0x200, 0x400000, 1, 0x1234, 0x400100]

    lone = build(machine: :x86_64) do |b|
      b.add_section('.text', data: "\x90".b)
      b.add_segment(type: :load, flags: %i[r], covers: '.text')
    end
    expect(lone.segments_by_type(:load).find { |s| !s.header.p_offset.to_i.zero? }.header.p_filesz.to_i).to eq 1

    recopied = described_class.new(StringIO.new(explicit.to_s))
    load = recopied.segments_by_type(:load).find { |s| s.header.p_vaddr.to_i == 0x400000 }
    expect(load.header.p_paddr.to_i).to eq 0x400100

    source = build(machine: :x86_64) do |b|
      b.add_section('.text', data: "\x90" * 16, addr: 0x400000)
      b.add_section('.bss', type: :nobits, size: 64, addr: 0x401000, flags: %i[alloc write])
      b.add_segment(type: :load, flags: %i[r w], offset: 0x100, vaddr: 0x400000, filesz: 0x10, memsz: 0x2000)
    end
    nobits = described_class.new(StringIO.new(source.to_s))
    seg = nobits.segments_by_type(:load).find { |s| s.header.p_vaddr.to_i == 0x400000 }
    expect(seg.header.p_offset.to_i).to eq 0x100
    expect(seg.header.p_filesz.to_i).to eq 0x10
    expect(seg.header.p_memsz.to_i).to eq 0x2000
    expect(nobits.section_by_name('.bss').header.sh_size.to_i).to eq 64

    sparse = build(machine: :x86_64) do |b|
      b.add_section('.a', data: 'aa', addr: 0x1000, flags: %i[alloc], offset: 0x1000)
      b.add_section('.b', data: 'b', addr: 0x1001, flags: %i[alloc], offset: 0x2000)
      b.add_segment(type: :load, flags: %i[r], covers: %w[.a .b])
    end
    load = sparse.segments_by_type(:load).find { |s| !s.header.p_offset.to_i.zero? }
    expect(load.header.p_filesz.to_i).to eq 0x1001
    expect(load.header.p_memsz.to_i).to eq 0x1001
  end

  it 'defaults missing addresses to file offsets, entry to the lowest one' do
    elf = build(machine: :x86_64) do |b|
      b.add_section('.text', data: "\x90" * 3, flags: %i[alloc execinstr], align: 16)
      b.add_section('.rodata', data: 'ro', flags: %i[alloc], align: 8)
      b.add_section('.comment', data: 'c')
      b.add_section('.data', data: 'd', addr: 0x1000, flags: %i[alloc write])
      b.add_section('.bss', type: :nobits, size: 16, flags: %i[alloc write], align: 16)
    end
    offsets = elf.sections.map { |s| [s.name, s.header.sh_offset.to_i] }.to_h
    addrs = elf.sections.map { |s| [s.name, s.header.sh_addr.to_i] }.to_h
    expect(addrs.values_at('.text', '.rodata', '.bss')).to eq(
      [offsets['.text'], offsets['.rodata'], offsets['.bss']]
    )
    expect(addrs['.comment']).to be 0
    expect(addrs['.data']).to eq 0x1000
    expect(elf.header.e_entry.to_i).to eq offsets['.text']

    rw = elf.segments_by_type(:load).find { |s| !s.header.p_offset.to_i.zero? && s.header.p_flags.to_i == 6 }
    expect(rw.header.p_offset.to_i).to eq 0x1000
    expect(rw.header.p_vaddr.to_i).to eq 0x1000
    expect(rw.header.p_memsz.to_i).to eq offsets['.bss'] + 16 - 0x1000
  end

  it 'derives loads' do
    elf = build(machine: :x86_64, type: :exec, entry: 0x401000) do |b|
      b.add_section('.text', data: "\x90".b, addr: 0x401000, flags: %i[alloc execinstr])
      b.add_section('.rodata', data: 'r'.b, addr: 0x402000, flags: %i[alloc])
      b.add_section('.interp', data: "/lib/ld.so\x00".b, addr: 0x402100, flags: %i[alloc])
      b.add_section('.data', data: 'd'.b, addr: 0x403000, flags: %i[alloc write])
      b.add_section('.bss', type: :nobits, size: 64, addr: 0x403008, flags: %i[alloc write])
      b.add_section('.dynamic', data: "\x00".b * 16, type: :dynamic, flags: %i[alloc write], addr: 0x403100,
                                link: '.dynstr')
      b.add_section('.comment', data: 'c'.b)
      b.add_section('.note.one', data: 'n1'.b, type: :note)
      b.add_section('.note.two', data: 'n2'.b, type: :note)
      b.add_section('.dynstr', data: "\x00".b, type: :strtab)
    end
    off = ->(name) { elf.section_by_name(name).header.sh_offset.to_i }

    loads = elf.segments_by_type(:load)
    expect(loads.size).to eq 4
    expect(loads.map { |s| s.header.p_flags.to_i }.sort).to eq [4, 4, 5, 6]
    loads.each do |load|
      offset = load.header.p_offset.to_i
      vaddr = load.header.p_vaddr.to_i
      align = load.header.p_align.to_i
      expect((offset - vaddr) % align).to be 0
    end
    by_flags = loads.reject { |s| s.header.p_offset.to_i.zero? }
                    .to_h { |s| [s.header.p_flags.to_i, s.header.p_vaddr.to_i] }
    expect(by_flags).to eq(5 => 0x401000, 4 => 0x402000, 6 => 0x403000)
    expect(elf.header.e_phnum.to_i).to eq 9
    expect(elf.segments.first.header.p_type.to_i).to eq ELFTools::Constants::PT_PHDR

    text_offset = off.call('.text')
    phdr = elf.segment_by_type(:phdr)
    expect(phdr.header.p_flags.to_i).to eq ELFTools::Constants::PF_R
    expect(phdr.header.p_offset.to_i).to eq 64
    expect(phdr.header.p_filesz.to_i).to eq 9 * 56
    header = elf.segments[1]
    expect(header.header.p_type.to_i).to eq ELFTools::Constants::PT_LOAD
    expect(header.header.p_flags.to_i).to eq ELFTools::Constants::PF_R
    expect(header.header.p_offset.to_i).to eq 0
    expect(header.header.p_vaddr.to_i).to eq 0x401000 - text_offset
    expect(header.header.p_filesz.to_i).to eq 64 + elf.header.e_phnum.to_i * 56
    expect(header.header.p_memsz.to_i).to eq header.header.p_filesz.to_i
    expect(phdr.header.p_vaddr.to_i).to eq header.header.p_vaddr.to_i + 64
    expect(phdr.header.p_offset.to_i).to be >= header.header.p_offset.to_i
    expect(phdr.header.p_offset.to_i + phdr.header.p_filesz.to_i).to be <= header.header.p_filesz.to_i
    header_end = header.header.p_offset.to_i + header.header.p_filesz.to_i
    loads.each do |load|
      next if load.header.p_offset.to_i.zero?

      expect(load.header.p_offset.to_i).to be >= header_end
    end

    interp = elf.segment_by_type(:interp)
    expect(interp.header.p_flags.to_i).to eq ELFTools::Constants::PF_R
    expect(interp.header.p_offset.to_i).to eq off.call('.interp')
    expect(interp.header.p_filesz.to_i).to eq 11

    dynamic = elf.segment_by_type(:dynamic)
    expect(dynamic.header.p_flags.to_i).to eq ELFTools::Constants::PF_R | ELFTools::Constants::PF_W
    expect(dynamic.header.p_offset.to_i).to eq off.call('.dynamic')
    expect(dynamic.header.p_filesz.to_i).to eq 16
    expect(elf.section_by_name('.dynamic').header.sh_link.to_i).to eq elf.sections.map(&:name).index('.dynstr')

    notes = elf.segments_by_type(:note)
    expect(notes.size).to eq 2
    expect(notes.map { |s| s.header.p_offset.to_i }.sort).to eq [off.call('.note.one'), off.call('.note.two')].sort

    r_load = loads.find { |s| !s.header.p_offset.to_i.zero? && s.header.p_flags.to_i == ELFTools::Constants::PF_R }
    interp_offset = off.call('.interp')
    expect(interp_offset).to be >= r_load.header.p_offset.to_i
    expect(interp_offset).to be < r_load.header.p_offset.to_i + r_load.header.p_filesz.to_i

    copied = described_class.new(StringIO.new(elf.to_s))
    expect(copied.to_s).to eq elf.to_s

    rel = build(machine: :x86_64, type: :rel) do |b|
      b.add_section('.text', data: "\x90".b, flags: %i[alloc execinstr])
      b.add_section('.dynamic', data: "\x00".b * 16, type: :dynamic)
    end
    expect(rel.section_by_name('.text').header.sh_addr.to_i).to be 0
    expect(rel.header.e_entry.to_i).to be 0
    expect(rel.dynamic).to be rel.section_by_name('.dynamic')
    expect(rel.num_segments).to be 0
    bare = build(machine: :x86_64, type: :exec) { |b| b.add_section('.text', data: "\x90".b) }
    expect(bare.dynamic).to be_nil
  end

  it 'maps headers below alloc sections when none is non-alloc' do
    elf = build(machine: :x86_64, type: :exec, entry: 0x401000) do |b|
      b.add_section('.text', data: "\x90".b, addr: 0x401000, flags: %i[alloc execinstr])
      b.add_section('.shstrtab', data: "\x00.shstrtab\x00.text\x00".b, type: :strtab, flags: %i[alloc],
                                 addr: 0x402000)
    end
    header = elf.segments_by_type(:load).find { |s| s.header.p_offset.to_i.zero? }
    expect(header.header.p_vaddr.to_i).to eq 0x401000 - elf.section_by_name('.text').header.sh_offset.to_i
    table = elf.segments_by_type(:load).find { |s| s.header.p_vaddr.to_i == 0x402000 }
    expect(table.header.p_offset.to_i).to eq elf.section_by_name('.shstrtab').header.sh_offset.to_i
    expect(elf.section_by_name('.shstrtab').header.sh_addr.to_i).to eq 0x402000
  end

  it 'records NOBITS sizes without allocating their bytes' do
    elf = build(machine: :x86_64, type: :exec, entry: 0x401000) do |b|
      b.add_section('.text', data: "\x90".b, addr: 0x401000, flags: %i[alloc execinstr])
      s = b.add_section('.bss', type: :nobits, size: 0x4000_0000, addr: 0x402000, flags: %i[alloc write])
      expect(s.data.bytesize).to be 0
    end
    expect(elf.section_by_name('.bss').header.sh_size.to_i).to eq 0x4000_0000
    expect(elf.to_s.bytesize).to be < 0x10000

    recopied = described_class.new(StringIO.new(elf.to_s))
    expect(recopied.section_by_name('.bss').header.sh_size.to_i).to eq 0x4000_0000
    expect(recopied.to_s.bytesize).to be < 0x10000
    expect(recopied.to_s).to eq elf.to_s

    sized = build(machine: :x86_64) { |b| b.add_section('.z', size: 3) }
    expect(sized.section_by_name('.z').data).to eq "\x00\x00\x00".b
  end

  it 'works with 32-bit big-endian file' do
    elf = build(machine: :arm, elf_class: 32, endian: :big, type: :exec, entry: 0x8000) do |b|
      b.add_section('.text', data: "\xe3\xa0\x00\x00".b, addr: 0x8000, flags: %i[alloc execinstr])
      b.add_section('.dynamic', data: "\x00".b * 16, type: :dynamic, flags: %i[alloc write])
      b.add_symbol('start', type: :func, value: 0x8000, size: 4, section: '.text')
    end
    bytes = elf.to_s
    expect(bytes[0, 4]).to eq ELFTools::Constants::ELFMAG
    expect(bytes[4].ord).to eq 1 # ELFCLASS32
    expect(bytes[5].ord).to eq 2 # ELFDATA2MSB
    expect(elf.header.e_machine.to_i).to eq ELFTools::Constants::EM_ARM
    expect(elf.section_by_name('.symtab').symbol_by_name('start').value).to eq 0x8000
    expect(elf.segment_by_type(:dynamic).header.p_align.to_i).to eq 4
    phdr = elf.segment_by_type(:phdr)
    expect([phdr.header.p_offset.to_i, phdr.header.p_filesz.to_i, phdr.header.p_align.to_i]).to eq [52, 5 * 32, 4]
  end

  it 'skip_segment suppresses derived ones' do
    elf = build(machine: :x86_64) do |b|
      b.add_section('.interp', data: '/x'.b, flags: %i[alloc])
      b.add_section('.note.a', data: 'a'.b, type: :note)
      b.add_segment(type: :interp, covers: %w[.interp], flags: %i[r])
      b.add_segment(type: :note, covers: %w[.note.a], flags: %i[r])
      b.skip_segment(:interp)
    end
    expect(elf.segments_by_type(:interp).size).to eq 1
    expect(elf.segments_by_type(:note).size).to eq 1
    expect(elf.segments_by_type(:load).size).to eq 2
    expect(elf.segments_by_type(:phdr).size).to eq 1
    expect(elf.header.e_phnum.to_i).to eq 5
    header = elf.segments_by_type(:load).find { |s| s.header.p_offset.to_i.zero? }
    expect(header.header.p_vaddr.to_i).to eq 0
    expect(header.header.p_filesz.to_i).to eq 64 + elf.header.e_phnum.to_i * 56

    elf = build(machine: :x86_64, type: :dyn, entry: 0x1000) do |b|
      b.add_section('.text', data: "\x90".b, addr: 0x1000, flags: %i[alloc execinstr])
      b.add_section('.interp', data: "/lib/ld.so\x00".b, flags: %i[alloc])
      b.add_section('.dynamic', data: "\x00".b * 16, type: :dynamic, flags: %i[alloc write])
      b.add_section('.note.a', data: 'a'.b, type: :note)
      b.skip_segment(:interp, :dynamic, :note)
    end
    expect(elf.segment_by_type(:interp)).to be_nil
    expect(elf.segment_by_type(:dynamic)).to be_nil
    expect(elf.segments_by_type(:note)).to be_empty
    expect(elf.header.e_phnum.to_i).to eq 5
    expect(elf.segments_by_type(:load).size).to eq 4
    expect(elf.segments_by_type(:phdr).size).to eq 1

    phdrless = build(machine: :x86_64, type: :exec, entry: 0x401000) do |b|
      b.add_section('.text', data: "\x90".b, addr: 0x401000, flags: %i[alloc execinstr])
      b.skip_segment(:phdr)
    end
    expect(phdrless.segments_by_type(:phdr)).to be_empty
    expect(phdrless.segments_by_type(:load).size).to eq 1
    expect(phdrless.header.e_phnum.to_i).to eq 1

    loadless = build(machine: :x86_64, type: :exec, entry: 0x401000) do |b|
      b.add_section('.text', data: "\x90".b, addr: 0x401000, flags: %i[alloc execinstr])
      b.add_section('.note', data: 'n'.b, type: :note)
      b.skip_segment(:load)
    end
    expect(loadless.segments_by_type(:load).size).to eq 1
    expect(loadless.header.e_phoff.to_i).not_to be_zero
    expect(loadless.header.e_phnum.to_i).to eq 3
  end

  it 'supports dropping sections and segments' do
    elf = build(machine: :x86_64, type: :exec, entry: 0x401000) do |b|
      b.add_section('.text', data: "\x90".b, addr: 0x401000, flags: %i[alloc execinstr])
      b.add_section('.comment', data: 'c'.b)
      b.add_segment(type: :load, covers: %w[.text .comment], flags: %i[r])
    end
    expect(elf.num_sections).to eq 4
    elf.remove_section('.comment')
    expect(elf.section_by_name('.comment')).to be_nil
    expect(elf.num_sections).to eq 3
    load = elf.segments_by_type(:load).find { |s| !s.header.p_offset.to_i.zero? }
    expect(load.header.p_filesz.to_i).to eq 1

    elf.add_segment(type: :load, covers: %w[.text], flags: %i[r x])
    elf.remove_segment(:load)
    expect(elf.segments_by_type(:load).size).to eq 1
    expect(elf.header.e_phnum.to_i).to eq 2

    noted = build(machine: :x86_64, type: :exec, entry: 0x401000) do |b|
      b.add_section('.text', data: "\x90".b, addr: 0x401000, flags: %i[alloc execinstr])
      b.add_section('.note.a', data: 'a'.b, type: :note)
      b.add_segment(type: :note, covers: %w[.note.a], flags: %i[r])
      b.remove_segment(:note)
    end
    expect(noted.segments_by_type(:note)).to be_empty
    expect(noted.header.e_phnum.to_i).to eq 3
  end

  it 'honors header edits in to_s, write and save' do
    elf = build(machine: :x86_64, type: :exec) do |b|
      b.add_section('.text', data: "\x90".b, addr: 0x401000, flags: %i[alloc execinstr])
    end
    elf.header.e_entry = 0x1234
    elf.section_by_name('.text').header.sh_addr = 0xdeadbeef
    reread = ->(bytes) { ELFTools::ELFFile.new(StringIO.new(bytes)) }

    patched = reread.call(elf.to_s)
    expect(patched.header.e_entry.to_i).to eq 0x1234
    expect(patched.section_by_name('.text').header.sh_addr.to_i).to eq 0xdeadbeef

    io = StringIO.new(+''.b)
    elf.write(io)
    expect(reread.call(io.string).header.e_entry.to_i).to eq 0x1234

    Tempfile.create(['patched', '.bin']) do |f|
      elf.save(f.path)
      expect(reread.call(File.binread(f.path)).header.e_entry.to_i).to eq 0x1234
    end

    expect(elf.header.e_entry.to_i).to eq 0x1234
  end

  it 'reindexes references when dropping a section' do
    elf = amd64_copy
    elf.remove_section('.shstrtab') # index 28: nothing links it, no symbol lives in it
    reopened = ELFTools::ELFFile.new(StringIO.new(elf.to_s))

    names = reopened.sections.map(&:name)
    expect(reopened.section_by_name('.symtab').header.sh_link.to_i).to eq names.index('.strtab')
    expect(reopened.section_by_name('.dynamic').header.sh_link.to_i).to eq names.index('.dynstr')
    expect(names[reopened.section_by_name('.rela.plt').header.sh_info.to_i]).to eq '.got.plt'

    main = reopened.section_by_name('.symtab').symbol_by_name('main')
    expect(names[main.section_index]).to eq '.text'
    stdin = reopened.section_by_name('.dynsym').symbol_by_name('stdin')
    expect(names[stdin.section_index]).to eq '.bss'
    abs = reopened.section_by_name('.symtab').symbol_by_name('crtstuff.c')
    expect(abs.section_index).to eq ELFTools::Constants::SHN_ABS
    expect(reopened.dynamic).not_to be_nil
  end

  it 'rejects dropping a section others still reference' do
    elf = amd64_copy
    expect { elf.remove_section('.strtab') }.to raise_error(ArgumentError, /links to it/)
    expect { elf.remove_section('.dynsym') }.to raise_error(ArgumentError, /links to it/)
    expect { elf.remove_section('.got.plt') }.to raise_error(ArgumentError, /apply to it/)
    expect { elf.remove_section('.text') }.to raise_error(ArgumentError, /defined in it/)
    expect { elf.remove_section('.bss') }.to raise_error(ArgumentError, /defined in it/)

    fresh = amd64_copy
    expect(elf.to_s).to eq fresh.to_s
  end

  it 'drops the static tables for a strip-like copy' do
    elf = amd64_copy
    elf.remove_section('.symtab')
    elf.remove_section('.strtab')
    reopened = ELFTools::ELFFile.new(StringIO.new(elf.to_s))

    expect(reopened.section_by_name('.symtab')).to be_nil
    expect(reopened.section_by_name('.strtab')).to be_nil
    stdin = reopened.section_by_name('.dynsym').symbol_by_name('stdin')
    expect(reopened.sections[stdin.section_index].name).to eq '.bss'
    fresh = ELFTools::ELFFile.new(StringIO.new(File.binread('spec/files/amd64.elf')))
    expect(reopened.section_by_name('.text').data).to eq fresh.section_by_name('.text').data
    expect(reopened.dynamic).not_to be_nil
  end

  it 'shifts recorded symbol indices, group members and extended indices' do
    elf = build(machine: :x86_64) do |b|
      b.add_section('.a', data: 'a'.b)
      b.add_section('.victim', data: 'v'.b)
      b.add_section('.b', data: 'b'.b)
      b.add_section('.strtab', data: "\x00".b, type: :strtab)
      b.add_section('.symtab', type: :symtab, data: sym_bytes(0, 1, 3, 0xfff1),
                               link: '.strtab', info: 1, entsize: 24)
      b.add_section('.g', type: :group, data: [1, 1, 3].pack('L<3'))
      b.add_section('.x', type: :symtab_shndx, data: [0, 1, 3].pack('L<3'))
    end
    elf.remove_section('.victim')
    reopened = ELFTools::ELFFile.new(StringIO.new(elf.to_s))

    expect(reopened.section_by_name('.symtab').data).to eq sym_bytes(0, 1, 2, 0xfff1)
    expect(reopened.section_by_name('.g').data.unpack('L<*')).to eq [1, 1, 2]
    expect(reopened.section_by_name('.x').data.unpack('L<*')).to eq [0, 1, 2]

    grouped = build(machine: :x86_64) do |b|
      b.add_section('.a', data: 'a'.b)
      b.add_section('.victim', data: 'v'.b)
      b.add_section('.g', type: :group, data: [1, 2].pack('L<2'))
    end
    expect { grouped.remove_section('.victim') }.to raise_error(ArgumentError, /contains it/)

    indexed = build(machine: :x86_64) do |b|
      b.add_section('.a', data: 'a'.b)
      b.add_section('.victim', data: 'v'.b)
      b.add_section('.x', type: :symtab_shndx, data: [0, 2].pack('L<2'))
    end
    expect { indexed.remove_section('.victim') }.to raise_error(ArgumentError, /defined in it/)
  end

  it 'keeps copied segment bounds instead of deriving them' do
    src = build(machine: :x86_64, type: :exec, entry: 0x401000) do |b|
      b.add_section('.text', data: "\x90".b, addr: 0x401000, flags: %i[alloc execinstr], offset: 0x1000)
      b.add_section('.data', data: 'd'.b, addr: 0x402000, flags: %i[alloc write], offset: 0x2000)
      b.add_segment(type: :load, flags: %i[r x], offset: 0x1000, vaddr: 0x401000,
                    filesz: 0x1010, memsz: 0x1010, align: 0x1000)
    end
    elf = described_class.new(StringIO.new(src.to_s))

    load = elf.segments_by_type(:load).find { |s| s.header.p_flags.to_i == 5 && !s.header.p_offset.to_i.zero? }
    expect([load.header.p_offset.to_i, load.header.p_filesz.to_i,
            load.header.p_vaddr.to_i, load.header.p_memsz.to_i]).to eq [0x1000, 0x1010, 0x401000, 0x1010]
    expect(elf.to_s).to eq src.to_s

    elf.remove_section('.data')
    shrunk = elf.segments_by_type(:load).find { |s| s.header.p_flags.to_i == 5 && !s.header.p_offset.to_i.zero? }
    expect([shrunk.header.p_offset.to_i, shrunk.header.p_filesz.to_i,
            shrunk.header.p_vaddr.to_i]).to eq [0x1000, 1, 0x401000]
  end

  it 'allows replacing generated tables' do
    src = build(machine: :x86_64, type: :exec, entry: 0x401000) do |b|
      b.add_section('.note', data: 'n'.b, type: :note, offset: 0x2000)
      b.add_section('.text', data: "\x90".b, addr: 0x401000, flags: %i[alloc execinstr], offset: 0x1000)
    end
    elf = described_class.new(StringIO.new(src.to_s))
    expect(elf.section_by_name('.text').header.sh_offset.to_i).to eq 0x1000
    expect(elf.section_by_name('.note').header.sh_offset.to_i).to eq 0x2000
    expect(elf.section_by_name('.shstrtab').data).to eq src.section_by_name('.shstrtab').data
    expect(elf.to_s).to eq src.to_s

    elf.add_section('.extra', data: 'e'.b)
    shstrtab = src.section_by_name('.shstrtab').data
    expect(elf.section_by_name('.shstrtab').data).to eq shstrtab + '.extra'.b + "\x00".b
    expect(elf.section_by_name('.extra').header.sh_name.to_i).to eq shstrtab.bytesize
    expect(elf.section_by_name('.text').header.sh_name.to_i).to eq src.section_by_name('.text').header.sh_name.to_i
    expect(elf.section_by_name('.text').header.sh_offset.to_i).to eq 0x1000

    custom = build(machine: :x86_64) do |b|
      b.add_section('.text', data: "\x90".b, flags: %i[alloc])
      b.add_section('.rodata', data: 'r'.b, flags: %i[alloc])
      b.add_section('.shstrtab', data: "\x00.shstrtab\x00.rodata\x00.text\x00".b, type: :strtab)
    end
    expect(custom.section_by_name('.shstrtab').data).to eq "\x00.shstrtab\x00.rodata\x00.text\x00".b
    expect(custom.section_by_name('.shstrtab').header.sh_name.to_i).to eq 1
    expect(custom.section_by_name('.text').header.sh_name.to_i).to eq 19
    expect(custom.section_by_name('.rodata').header.sh_name.to_i).to eq 11
    expect(custom.header.e_shstrndx.to_i).to eq custom.num_sections - 1
    expect(custom.section_by_name('.text').data).to eq "\x90".b

    merged = build(machine: :x86_64) do |b|
      b.add_section('.text', data: "\x90".b)
      b.add_section('.shstrtab', data: "\x00.shstrtab\x00".b, type: :strtab)
    end
    expect(merged.section_by_name('.shstrtab').data).to eq "\x00.shstrtab\x00.text\x00".b
    expect(merged.section_by_name('.text').header.sh_name.to_i).to eq 11
  end

  it 'rejects adding symbols when .strtab / .symtab already present' do
    recorded = build(machine: :x86_64, type: :exec, entry: 0x400000) do |b|
      b.add_section('.strtab', data: "\x00main\x00".b, type: :strtab)
      b.add_section('.symtab', type: :symtab, data: "\x00".b * 24, link: '.strtab', info: 1, entsize: 24)
      b.add_symbol('main')
    end
    expect { recorded.to_s }.to raise_error(ArgumentError, /already added/)

    reversed = build(machine: :x86_64) { |b| b.add_symbol('early') }
    reversed.add_section('.symtab', type: :symtab, data: "\x00".b * 24)
    expect { reversed.to_s }.to raise_error(ArgumentError, /already added/)

    copied = amd64_copy
    copied.add_symbol('extra')
    expect { copied.to_s }.to raise_error(ArgumentError, /already added/)

    copied.remove_section('.symtab')
    copied.remove_section('.strtab')
    expect(copied.section_by_name('.symtab').symbol_by_name('extra').value).to eq 0
  end
end
