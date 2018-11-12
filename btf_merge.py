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
import optparse
from ebpf_asm import BtfAssembler as BTF
from agm import ADG

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
        name = getattr(t, 'type_name', None)
        name = '(anon)' if name is None else '[%s]' % (name,)
        print '%d: %s %s' % (i, name, t.tuple)

class FrozenBtf(object):
    def __init__(self, tpl, name):
        self.tuple = tpl
        self.type_name = name

class Unresolved(object):
    def __init__(self, src_ref):
        self.src_ref = src_ref
    def __repr__(self):
        return 'unres(%d)' % (self.src_ref,)
    __str__ = __repr__

class BtfMerger(object):
    def __init__(self):
        self.types = []
    def merge(self, src):
        # XXX we're not properly handling arrays' index_type.  However that
        # should be easy in principle since there's only one (int 1 64) and it
        # doesn't present any circularity issues.
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
            if t[0] in ('pointer', 'array', 'typedef', 'volatile', 'const',
                        'restrict'):
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

        def maybe_resolve(t):
            if t.tuple[0] in ('pointer', 'array', 'typedef', 'volatile',
                              'const', 'restrict'):
                if isinstance(t.tuple[1], Unresolved):
                    if isinstance(id_map.get(t.tuple[1].src_ref), int):
                        t.tuple = (t.tuple[0], id_map[t.tuple[1].src_ref]) + t.tuple[2:]
            elif t.tuple[0] in ('struct', 'union'):
                nm = []
                for m in t.tuple[1]:
                    if isinstance(m[1], Unresolved) and \
                       isinstance(id_map.get(m[1].src_ref), int):
                        nm.append((m[0], id_map[m[1].src_ref]))
                    else:
                        nm.append(m)
                t.tuple = (t.tuple[0], tuple(nm))

        pi = 0
        while set(consumed) != set(id_map) or \
              not all(isinstance(i, int) for i in id_map.values()):
            print "Pass", pi
            pi += 1
            changes = False
            for ti in consumed:
                if isinstance(id_map.get(ti), int):
                    # Already done this one
                    continue
                t = src_types[ti]
                name = getattr(src.types[ti], 'type_name', None)
                print "Adding", ti, "(anon)" if name is None else '[%s]'%(name,), t
                rs = refs.get(ti, ())
                if all(isinstance(id_map.get(r), int) for r in rs):
                    # Dependencies already exist, we can just add it
                    if t[0] in ('pointer', 'array', 'typedef', 'volatile',
                                'const', 'restrict'):
                        new = (t[0], id_map[t[1]]) + t[2:]
                    elif t[0] in ('struct', 'union'):
                        new = (t[0], tuple((m[0], id_map[m[1]]) for m in t[1]))
                    else:
                        new = t # no refs to translate
                    for ui,u in enumerate(self.types):
                        if new[0] != u.tuple[0]:
                            continue
                        maybe_resolve(u)
                        if new == u.tuple:
                            id_map[ti] = ui
                            print "Match", ui
                            changes = True
                            assert name in (None, u.type_name), (name, u.type_name)
                            break
                    else:
                        id_map[ti] = len(self.types)
                        self.types.append(FrozenBtf(new, name))
                        changes = True
                        print "New", id_map[ti]
                else:
                    print "Tentative"
                    # In the case where there are no tentative refs, we just take
                    # a tentative with all the targets that match us locally.
                    # If there _are_ tentative refs, we can only take a target into
                    # our tentative if its refs are in our refs' tentatives.
                    tents = set()
                    for ui,u in enumerate(self.types):
                        if t[0] != u.tuple[0]:
                            continue
                        # If we have a name mismatch, then we can't be the same
                        # type.
                        if name is not None and u.type_name is not None and \
                           u.type_name != name:
                            continue
                        maybe_resolve(u)
                        if t[0] in ('pointer', 'array', 'typedef', 'volatile',
                                    'const', 'restrict'):
                            if t[1] in id_map: # tentative ref
                                if u.tuple[1] not in id_map[t[1]] and \
                                   not isinstance(u.tuple[1], Unresolved):
                                    continue
                        elif t[0] in ('struct', 'union'):
                            if len(t[1]) != len(u.tuple[1]):
                                continue
                            ok = True
                            for m,n in zip(t[1], u.tuple[1]):
                                if m[0] != n[0]:
                                    ok = False
                                    break
                                if m[1] not in id_map:
                                    continue
                                if isinstance(id_map[m[1]], set): # tentative ref
                                    if n[1] not in id_map[m[1]] and \
                                       not isinstance(n[1], Unresolved):
                                        ok = False
                                        break
                            if not ok:
                                continue
                        tents.add(ui)
                    print "Tents", tents
                    if tents:
                        if id_map.get(ti) != tents:
                            id_map[ti] = tents
                            changes = True
                    else:
                        # Doesn't already exist, let's add it (but unresolved)
                        if t[0] in ('pointer', 'array', 'typedef', 'volatile',
                                'const', 'restrict'):
                            new = (t[0], Unresolved(t[1])) + t[2:]
                        elif t[0] in ('struct', 'union'):
                            new = (t[0], tuple((m[0], Unresolved(m[1])) for m in t[1]))
                        else:
                            new = t # no refs to translate
                        id_map[ti] = len(self.types)
                        self.types.append(FrozenBtf(new, name))
                        changes = True
                        print "New unres", id_map[ti]
            print id_map
            if not changes:
                print "Firming up tentatives"
                for ti in consumed:
                    if isinstance(id_map.get(ti), set):
                        tents = id_map[ti]
                        assert len(tents) == 1, (ti, tents)
                        ui = tents.pop()
                        print "Matched", ti, "=>", ui
                        id_map[ti] = ui
                        t = src_types[ti]
                        name = getattr(src.types[ti], 'type_name', None)
                        u = self.types[ui]
                        assert name in (None, u.type_name), (t, name, u.tuple, u.type_name)
        # Fix up unres
        for ti,t in enumerate(self.types):
            if t.tuple[0] in ('pointer', 'array', 'typedef', 'volatile',
                              'const', 'restrict'):
                if isinstance(t.tuple[1], Unresolved):
                    assert t.tuple[1].src_ref in id_map, t
                    t.tuple = (t.tuple[0], id_map[t.tuple[1].src_ref]) + t.tuple[2:]
            elif t.tuple[0] in ('struct', 'union'):
                nm = []
                for m in t.tuple[1]:
                    if isinstance(m[1], Unresolved):
                        assert m[1].src_ref in id_map, t
                        nm.append((m[0], id_map[m[1].src_ref]))
                    else:
                        nm.append(m)
                t.tuple = (t.tuple[0], tuple(nm))
        print "Completed in %d passes" % (pi,)

class TypeName(str):
    def __eq__(self, other):
        if other is None:
            return True
        return super(TypeName, self).__eq__(other)

class AdgBtfMerger(object):
    def __init__(self):
        self.adg = ADG()
    @classmethod
    def btf_to_adg(cls, src):
        def typ_to_anno(t):
            # Everything about the type except for its refs if any
            if t.tuple[0] in ('pointer', 'typedef', 'volatile', 'const',
                              'restrict'):
                r = t.tuple[0:1]
            elif t.tuple[0] == 'array':
                r = (t.tuple[0], t.tuple[2])
            elif t.tuple[0] in ('struct', 'union'):
                r = (t.tuple[0],) + tuple(m[0] for m in t.tuple[1])
            elif t.tuple[0] in ('int', 'enum', 'forward', 'unknown'):
                r = t.tuple
            else: # No such kind!
                assert 0, t.tuple
            name = getattr(t, 'type_name', None)
            if name is not None:
                name = TypeName(name)
            return (name,) + r
        nodes = tuple((t, typ_to_anno(t)) for t in src.types)
        ret = ADG(*(n[1] for n in nodes))
        for i,(t,a) in enumerate(nodes):
            if t.tuple[0] in ('pointer', 'array', 'typedef', 'volatile',
                              'const', 'restrict'):
                ret.link(i, t.tuple[1])
            elif t.tuple[0] in ('struct', 'union'):
                for m in t.tuple[1]:
                    ret.link(i, m[1])
        return ret
    def merge(self, src):
        sg = self.btf_to_adg(src)
        self.adg.merge(sg)
    @classmethod
    def node_to_type(cls, n):
        name = n.anno[0]
        kind = n.anno[1]
        if kind in BTF.btf_kinds:
            t = BTF.btf_kinds[kind]
        elif kind == 'pointer':
            t = BTF.BtfPointer
        elif kind == 'unknown':
            t = BTF.BtfUnknown
        elif kind == 'forward':
            t = BTF.BtfForward
        else: # No such kind!
            assert 0, n
        tpl = n.anno[1:]
        if kind in ('pointer', 'array', 'typedef', 'volatile', 'const',
                    'restrict'):
            tpl = (tpl[0], n.outs[0]) + tpl[1:]
        elif kind in ('struct', 'union'):
            tpl = (kind, tuple(zip(tpl[1:], n.outs)))
        t = t.from_tuple(tpl)
        t.type_name = name
        return t
    @property
    def types(self):
        return [self.node_to_type(n) for n in self.adg.nodes]

def parse_args():
    x = optparse.OptionParser(usage='%s srcfile [...] [opts]')
    x.add_option('--use-agm', action='store_true')
    opts, args = x.parse_args()
    if not args:
        x.error('Missing srcfile(s).')
    return opts, args

if __name__ == '__main__':
    """For each file named on the command line, we parse it as a .BTF section in
    ebpf_asm's format for BTF.  We then take the resulting information (which is
    just a representation of the data that would be stored in the .BTF of an
    ELF) and merge all the BTF sections together.
    """
    sources = {}
    opts, args = parse_args()
    for src in args:
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

    if opts.use_agm:
        result = AdgBtfMerger()
    else:
        result = BtfMerger()
    for src in args:
        print "Merging", src
        result.merge(sources[src])
    print "Result:"
    print_btf_section(result)
