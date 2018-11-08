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
    result = []
