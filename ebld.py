#!/usr/bin/python2
# Copyright (c) 2019 Solarflare Communications Ltd
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import optparse
import struct
import elves

VERSION = None

def link_strings(*srce):
    strings = set()
    for e in srce:
        for s in e.sections:
            if isinstance(s.body, elves.ElfStringSection):
                strings |= set(s.body.strings)
    # '' must be first
    strings -= set([''])
    return elves.ElfStringSection('', *strings)

def link(opts, *srcb):
    srce = map(elves.ElfFile.read, srcb)
    for e in srce:
        if e.header['machine'] != 0xf7:
            raise Exception("machine_type must be Linux BPF (0xf7)")
    strings = link_strings(*srce)
    strings.add('.strtab') # we will use this name for output strtab
    strings.add('.symtab') # ditto output symtab
    iprog = set() # progbits, includes text & data
    oprog = dict()
    progflags = dict()
    for e in srce:
        for s in e.sections:
            if s.shdr['sh_type'] == 1: # progbits
                iprog.add(s)
                off = oprog.get(s.name, 0)
                s.off = off
                oprog[s.name] = off + len(s.write())
                if s.name in progflags:
                    assert progflags[s.name] == s.shdr['sh_flags'], "Mixed flags for progbits %s" % (s.name,)
                progflags[s.name] = s.shdr['sh_flags']
    oprog = {name: elves.WriteBuffer(length) for name, length in oprog.items()}
    isym = dict()
    irel = dict()
    relnames = dict()
    for e in srce:
        for s in e.sections:
            if isinstance(s.body, elves.ElfSymbolSection):
                for sym in s.body.syms:
                    if sym['st_shndx']:
                        sec = e.sections[sym['st_shndx']]
                        isym.setdefault(sec.name, {})[sym['name']] = (sym, sec)
            elif isinstance(s.body, elves.ElfRelocSection):
                sec = e.sections[s.shdr['sh_info']]
                s.link = sec
                irel.setdefault(sec.name, []).append(s)
                relnames.setdefault(sec.name, s.name)

    arel = dict()
    orel = dict()
    for pn, rsl in irel.items():
        st = isym[pn]
        for rs in rsl:
            for r in rs.body.relocs:
                name = r['sym']['name']
                if name in st:
                    arel.setdefault(pn, []).append((r, rs.link, st[name]))
                else:
                    if not opts.allow_undef:
                        raise Exception("Unresolved reloc", name, "in", pn)
                    orel.setdefault(pn, []).append((r, rs.link))

    # Output layout:
    # SHTBL
    # 0 NULL
    # 1 STRTAB (incl shstrtab)
    # 2 SYMTAB
    # 3...x PROGBITS
    # x+1...y REL

    pi = {n: i+3 for i,n in enumerate(oprog)}
    ri = {n: i+3+len(oprog) for i,n in enumerate(orel)}

    osym = []
    for pn, st in isym.items():
        for sn, (sym, sec) in st.items():
            if sn not in arel.get(pn, []):
                osym.append(elves.ElfSymbol(st_name=strings.offset(sn),
                                            st_info=sym['st_info'],
                                            st_other=sym['st_other'],
                                            st_shndx=pi[pn],
                                            st_value=sym['st_value'] + sec.off,
                                            st_size=sym['st_size']))
    for pn, rt in orel.items():
        for r, link in rt:
            sym = r['sym']
            osym.append(elves.ElfSymbol(st_name=strings.offset(sym['name']),
                                        st_info=sym['st_info'],
                                        st_other=sym['st_other'],
                                        st_shndx=0, # UND
                                        st_value=0, st_size=sym['st_size']))
    symtab = elves.ElfSymbolSection(*osym)
    symtab.calc_symbol_names(strings)

    for s in iprog:
        b = s.write()
        oprog[s.name][s.off:s.off + len(b)] = b

    # Apply relocations.  This is the bit where we actually "link"!
    for pn, st in arel.items():
        for r, link, (sym, sec) in st:
            prog = oprog[pn]
            off = r['r_offset'] + link.off
            instr = prog[off:off+8]
            opcode = ord(instr[0])
            if opcode != 0x85:
                # For now JMP|CALL is the only one we know how to handle
                raise Exception("Relocation applies to non-CALL instruction")
            if ord(instr[1]) != 0x10: # BPF_PSEUDO_CALL
                raise Exception("Relocation applies to non-BPF_PSEUDO_CALL")
            dest = sym['st_value'] + sec.off
            instr = instr[:4] + struct.pack('<i', (dest-off)/8-1)
            prog[off:off+8] = instr

    nullsec = elves.ElfSection('')
    strsec = elves.ElfSection(strings.write(),
                              sh_name=strings.offset('.strtab'),
                              sh_type=3, sh_size=len(strings.write()))
    symsec = elves.ElfSection(symtab.write(),
                              sh_name=strings.offset('.symtab'),
                              sh_type=2, sh_flags=3,
                              sh_size=len(symtab.write()),
                              sh_link=1, sh_entsize=elves.ElfSymbol.len())
    oprog = {n: elves.ElfRawSection(str(p)) for n,p in oprog.items()}
    progsecs = [elves.ElfSection(str(p), sh_name=strings.offset(n),
                                 sh_type=1, sh_flags=progflags[n],
                                 sh_size=len(p)) for n,p in oprog.items()]
    relsecs = []
    for pn, rl in orel.items():
        relocs = []
        for (r, link) in rl:
            relocs.append(elves.ElfReloc(r_offset=r['r_offset'] + link.off,
                                         r_type=r['r_type'],
                                         r_sym=symtab.find(r['sym']['name'])))
        rs = elves.ElfRelocSection(*relocs)
        rn = relnames[pn]
        relsecs.append(elves.ElfSection(rs.write(),
                                        sh_name=strings.offset(rn), sh_type=9,
                                        sh_link=2, sh_info=pi[pn],
                                        sh_entsize=elves.ElfReloc.len()))
    oute = elves.ElfFile(nullsec, strsec, symsec, *(progsecs + relsecs),
                         ident=elves.ElfMagic, Class=2, endianness=1,
                         ei_version=1, Type=1, machine=0xf7, version=1,
                         shoff=elves.ElfHeader.len(),
                         hdr_size=elves.ElfHeader.len(),
                         shentsize=elves.ElfShdr.len(),
                         shnum=3 + len(progsecs) + len(relsecs), shstrndx=1)
    oute.calc_section_offsets()
    return oute.write()

def parse_args():
    x = optparse.OptionParser(usage='%prog srcfile [...] -o outfile',
                              version='%prog ' + (VERSION if VERSION else '(dev)'))
    x.add_option('-o', '--output', type='string', default='a.out')
    x.add_option('-c', '--allow-undef', action='store_true')
    opts, args = x.parse_args()
    if not args:
        x.error('Missing srcfile(s).')
    return opts, args

if __name__ == '__main__':
    opts, args = parse_args()
    srcb = tuple(open(src, 'r').read() for src in args)
    outb = link(opts, *srcb)
    with open(opts.output, 'wb') as f:
        f.write(outb)
