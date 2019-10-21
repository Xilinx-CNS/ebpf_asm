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

from collections import OrderedDict
import struct

class MetaStruct(type):
    """Metaclass for AbStruct.  Turns ._fields into OrderedDict .fields"""
    def __new__(cls, name, bases, attrs):
        fields = attrs.pop('_fields')
        attrs['fields'] = OrderedDict(((t, n) for n,t in fields))
        return super(MetaStruct, cls).__new__(cls, name, bases, attrs)

class AbStruct(object):
    __metaclass__ = MetaStruct
    _fields = ()
    type_map = {'u8': 'B', 'u16': 'H', 'u32': 'I', 'u64': 'Q'}
    def __init__(self, **kwargs):
        self.values = {k:0 for k in self.fields}
        for k,v in kwargs.items():
            if k not in self.fields:
                raise KeyError(k)
            self.values[k] = v
    @classmethod
    def struct(cls):
        # Force little-endian for now
        return '<' + ''.join(cls.type_map[f] for f in cls.fields.values())
    @classmethod
    def len(cls):
        return struct.calcsize(cls.struct())
    def write(self):
        return struct.pack(self.struct(), *(self.values[k] for k in self.fields))
    @classmethod
    def read(cls, binary):
        f = struct.unpack(cls.struct(), binary)
        d = dict(zip(cls.fields, f))
        return cls(**d)
    def __str__(self):
        return str(self.values)
    def __repr__(self):
        return repr(self.values)
    def __getitem__(self, k):
        return self.values[k]

class ElfHeader(AbStruct):
    _fields = (('u32', 'ident'),
               ('u8', 'Class'), # class, but usable in kwargs
               ('u8', 'endianness'),
               ('u8', 'ei_version'),
               ('u8', 'os_abi'),
               ('u8', 'abi_ver'),
               ('u32', 'padding0'),
               ('u16', 'padding1'),
               ('u8', 'padding2'),
               ('u16', 'Type'), # type, ditto
               ('u16', 'machine'),
               ('u32', 'version'),
               ('u64', 'entry'),
               ('u64', 'phoff'),
               ('u64', 'shoff'),
               ('u32', 'flags'),
               ('u16', 'hdr_size'),
               ('u16', 'phentsize'),
               ('u16', 'phnum'),
               ('u16', 'shentsize'),
               ('u16', 'shnum'),
               ('u16', 'shstrndx'))
ElfMagic = struct.unpack('I', '\x7fELF')[0]

class ElfShdr(AbStruct):
    _fields = (('u32', 'sh_name'),
               ('u32', 'sh_type'),
               ('u64', 'sh_flags'),
               ('u64', 'sh_addr'),
               ('u64', 'sh_offset'),
               ('u64', 'sh_size'),
               ('u32', 'sh_link'),
               ('u32', 'sh_info'),
               ('u64', 'sh_addralign'),
               ('u64', 'sh_entsize'))

class ElfSymbol(AbStruct):
	_fields = (('u32', 'st_name'), # index into strtab
               ('u8', 'st_info'), # type in low nibble, flags in high
               ('u8', 'st_other'),
               ('u16', 'st_shndx'), # section idx
               ('u64', 'st_value'),
               ('u64', 'st_size'))

class ElfReloc(AbStruct):
    _fields = (('u64', 'r_offset'),
               ('u32', 'r_type'), # r_info low dword
               ('u32', 'r_sym')) # r_info high dword

def align(s, a): # pad a string out to specified alignment
    l = len(s)
    if l % a:
        l = l + a - (l % a)
    return s.ljust(l, '\0')

class WriteBuffer(object):
    def __init__(self, length):
        self.length = length
        self.buf = '\0' * length
    def __getslice__(self, i, j):
        return self.buf[i:j]
    def __setslice__(self, i, j, y):
        if i + len(y) != j:
            raise ValueError(i, j, y)
        self.buf = self.buf[:i] + y + self.buf[j:]
    def __str__(self):
        return self.buf

class ElfRawSection(str):
    def write(self):
        return align(self, 8)
    @classmethod
    def read(cls, binary):
        return cls(binary)

class ElfStringSection(object):
    def __init__(self, *strings):
        self.strings = strings
    def add(self, string):
        if string not in self.strings:
            self.strings.append(string)
    def write(self):
        return align('\0'.join(self.strings + ('',)), 8)
    def offset(self, s):
        if s not in self.strings:
            return KeyError(s)
        l = 0
        for t in self.strings:
            if t == s:
                return l
            l += len(t) + 1
        assert False, 'not found (already checked)'
    def at_offset(self, o):
        return self.write()[o:].partition('\0')[0]
    @classmethod
    def read(cls, binary):
        return cls(*binary.split('\0')[:-1])
    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__,
                           ', '.join(map(repr, self.strings)))

class ElfSymbolSection(object):
    def __init__(self, *syms):
        self.syms = syms
    def write(self):
        return ''.join(s.write() for s in self.syms)
    @classmethod
    def read(cls, binary):
        syms = []
        slen = ElfSymbol.len()
        for i in xrange(0, len(binary), slen):
            syms.append(ElfSymbol.read(binary[i: i + slen]))
        return cls(*syms)
    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__,
                           ', '.join(map(repr, self.syms)))
    def calc_symbol_names(self, strtab):
        for s in self.syms:
            s.values['name'] = strtab.at_offset(s['st_name'])
    def find(self, name):
        for i,s in enumerate(self.syms):
            if s['name'] == name:
                return i
        raise KeyError(name)

class ElfRelocSection(object):
    def __init__(self, *relocs):
        self.relocs = relocs
    def write(self):
        return ''.join(r.write() for r in self.relocs)
    @classmethod
    def read(cls, binary):
        relocs = []
        rlen = ElfReloc.len()
        for i in xrange(0, len(binary), rlen):
            relocs.append(ElfReloc.read(binary[i : i + rlen]))
        return cls(*relocs)
    def __repr__(self):
        def rr(r):
            return '%s @ %d' % (r['sym']['name'], r['r_offset'])
        return '%s(%s)' % (self.__class__.__name__,
                           ', '.join(map(rr, self.relocs)))
    def calc_symbol_refs(self, symtab):
        for r in self.relocs:
            r.values['sym'] = symtab.syms[r['r_sym']]

class ElfSection(object):
    def __init__(self, binary, **shdr):
        cls = ElfRawSection
        sh_type = shdr.get('sh_type', 0)
        if sh_type == 2: # symtab
            cls = ElfSymbolSection
        elif sh_type == 3: # strtab
            cls = ElfStringSection
        elif sh_type == 9: # reltab
            cls = ElfRelocSection
        self.body = cls.read(binary)
        self.shdr = shdr
        self.name = None
    def write(self):
        return self.body.write()
    def __str__(self):
        return '%s: %r' % (self.name, self.body)
    __repr__ = __str__

class ElfFile(object):
    def __init__(self, *sections, **header):
        self.sections = sections
        self.header = header
        self.calc_section_names()
        self.calc_symbol_names()
        self.calc_reloc_symbols()
    def write(self):
        hdr = ElfHeader(**self.header).write()
        shtbl = ''.join(ElfShdr(**sec.shdr).write() for sec in self.sections)
        sections = [sec.write() for sec in self.sections]
        binary = WriteBuffer(len(hdr) + len(shtbl) + sum(map(len, sections)))
        binary[0:len(hdr)] = hdr
        binary[self.header['shoff']:self.header['shoff'] + len(shtbl)] = shtbl
        for i,sec in enumerate(self.sections):
            o = sec.shdr['sh_offset']
            binary[o:o + len(sections[i])] = sections[i]
        return str(binary)
    @classmethod
    def read(cls, binary):
        hdr = ElfHeader.read(binary[:ElfHeader.len()])
        if hdr['Class'] != 2:
            raise Exception("Only 64-bit ELF files supported!")
        if hdr['endianness'] != 1:
            raise Exception("Only little-endian ELF files supported!")
        b_shtbl = binary[hdr['shoff']:]
        shlen = ElfShdr.len()
        sections = []
        for i in xrange(hdr['shnum']):
            shdr = ElfShdr.read(b_shtbl[shlen * i: shlen * (i + 1)])
            sbin = binary[shdr['sh_offset']:shdr['sh_offset']+shdr['sh_size']]
            sections.append(ElfSection(sbin, **shdr.values))
        return cls(*sections, **hdr.values)
    def calc_section_names(self):
        self.section_names = []
        shstrtab = self.sections[self.header['shstrndx']].body
        if not isinstance(shstrtab, ElfStringSection):
            raise Exception("Section name table is not a strtab", shstrtab)
        for s in self.sections:
            s.name = shstrtab.at_offset(s.shdr.get('sh_name', 0))
            self.section_names.append(s.name)
    def calc_symbol_names(self):
        for s in self.sections:
            if isinstance(s.body, ElfSymbolSection):
                strndx = s.shdr['sh_link']
                strtab = self.sections[strndx].body
                s.body.calc_symbol_names(strtab)
    def calc_reloc_symbols(self):
        for s in self.sections:
            if isinstance(s.body, ElfRelocSection):
                symndx = s.shdr['sh_link']
                symtab = self.sections[symndx].body
                s.body.calc_symbol_refs(symtab)
    def calc_section_offsets(self):
        off = ElfHeader.len() + ElfShdr.len() * self.header['shnum']
        for s in self.sections:
            s.shdr['sh_size'] = len(s.write())
            s.shdr['sh_offset'] = off
            off += s.shdr['sh_size']
