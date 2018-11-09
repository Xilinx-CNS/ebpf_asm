#!/usr/bin/python2
# Copyright (c) 2018 Solarflare Communications Ltd
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

import sys
from ebpf_asm import BtfAssembler as BTF

def freeze_references(asm):
    # BtfAssembler stores references to member-type BTF.BtfKind()s in struct
    # and union types, and these appear in the .tuple() form.
    # Since we just want the raw information that would go in the .BTF section
    # of the ELF file, throw that away and just keep the name and type_id.
    for t in asm.types:
        if isinstance(t, (BTF.BtfStruct, BTF.BtfUnion)):
            t.members = tuple(tuple(memb[:2]) for memb in t.members)
    # BtfAssembler stores names in reverse, with a mapping from name to type_id.
    # We want what would go in the ELF, which is a name (really a name_off) in
    # the type record.
    for n,i in asm.named_types.iteritems():
        asm.types[i].type_name = n

def print_btf_section(asm):
    for i,t in enumerate(asm.types):
        if hasattr(t, 'type_name'):
            print '%d: [%s] %s' % (i, t.type_name, t.tuple)
        else:
            print '%d: (anon) %s' % (i, t.tuple)

class BtfMerger(object):
    def __init__(self):
        self.types = []
    def merge(self, src):
        # TODO handle names
        src_types = list(t.tuple for t in src.types) # Decouple from src
        refs = {} # src type_id => set of referenced src type_ids
        id_map = {} # src type_id => our type_id, or set of tentatives
        # First, pre-topologically sort src
        visited = set() # temporary mark
        consumed = list() # permanent mark, and result list
        def visit(ti):
            if ti in consumed: return
            if ti in visited: return
            visited.add(ti)
            # Follow references.  Types are (with .tuple index of ref):
            # 'int' no refs.
            # 'pointer' [1]
            # 'array' [1]
            # 'struct' [1][*][1]
            # 'union' [1][*][1]
            # 'enum' no refs
            # 'forward' no refs
            # 'typedef' [1]
            # 'volatile' [1]
            # 'const' [1]
            # 'restrict' [1]
            t = src_types[ti]
            if t[0] in ('pointer', 'array', 'typedef', 'volatile',
                              'const', 'restrict'):
                # Single referenced type in [1]
                refs[ti] = set([t[1]])
            elif t[0] in ('struct', 'union'):
                # List of referenced types in [1][*][1]
                refs[ti] = set(m[1] for m in t[1])
            for ref in refs.get(ti, ()):
                visit(ref)
            consumed.append(ti)
            return
        for ti,_ in enumerate(src_types):
            visit(ti)

        for ti in consumed:
            print ti, src_types[ti]
        pass #XXX

if __name__ == '__main__':
    """For each file named on the command line, we parse it as a .BTF section in
    ebpf_asm's format for BTF.  We then take the resulting information (which is
    just a representation of the data that would be stored in the .BTF of an
    ELF) and merge all the BTF sections together.
    """
    sources = {}
    for src in sys.argv[1:]:
        with open(src, 'r') as srcf:
            asm = BTF({})
            cont = ''
            for line in srcf:
                # handle continuation lines
                line = cont + line.rstrip('\n')
                if line and line[-1] == '\\':
                    cont = line[:-1]
                    continue
                cont = ''
                line = line.strip()
                if ';' in line: # comment to EOL
                    line, _, _ = line.partition(';')
                if not line: # blank line (or just a comment)
                    continue
                asm.feed_line(line)
            sources[src] = asm
            # Mangle the output to look more like what .BTF actually stores
            freeze_references(asm)
            print "Input:", src
            print_btf_section(asm)

    result = BtfMerger()
    for src in sources:
        print "Merging", src
        result.merge(sources[src])
    print "Result:"
    print_btf_section(result)
