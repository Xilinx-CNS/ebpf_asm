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

# AGM: Annotated Graph Merge
# A less cluttered reimplementation of the btf_merge algorithm, to make clearer
# how it works.
# Problem statement:
# Let an _annotated directed graph_ G = <N, E, A> consist of a set N of nodes,
# an edge function E: N -> List(N), and an annotation function A: N -> X for
# some set X.
# Given a collection S of such graphs, find sup(S), the minimal annotated
# directed graph containing each element of S as a sub-a.d.g. (i.e. a subdigraph
# preserving annotations).

# With appropriate annotation functions, this can be used to merge BTF sections
# together, even in the presence of circular references.

class Node(object):
    def __init__(self, anno, idx, graph):
        self.anno = anno
        self.outs = list()
        self.idx = idx
        self.graph = graph
    def add_out(self, to):
        self.outs.append(to)
    def __str__(self):
        def edge(to):
            if isinstance(to, int):
                return '-> %d %s' % (to, self.graph.nodes[to].anno)
            return '-> %s' % (to,)
        return '%d %s:\n\t%s' % (self.idx, self.anno,
                                 '\n\t'.join(map(edge, self.outs)))
    __repr__ = __str__

class Unresolved(object):
    def __init__(self, src_ref):
        self.src_ref = src_ref
    def __repr__(self):
        return 'unres(%d)' % (self.src_ref,)
    __str__ = __repr__

class ADG(object):
    def __init__(self, *node_names):
        self.nodes = [Node(n, i, self) for i,n in enumerate(node_names)]
        self.by_name = dict((name, i) for i,name in enumerate(node_names))
    def link(self, frm, to):
        self.nodes[frm].add_out(to)
    def link_by_name(self, frm, to):
        self.link(self.by_name[frm], self.by_name[to])
    def __str__(self):
        return '\n'.join(map(str, self.nodes))
    def merge(self, other):
        def maybe_resolve(n):
            new = []
            for o in n.outs:
                if isinstance(o, Unresolved) and \
                   isinstance(id_map.get(o.src_ref), int):
                    new.append(self.nodes[id_map.get(o.src_ref)])
                else:
                    new.append(o)
            n.outs = new

        # Merge other into self
        id_map = {}
        pi = 0
        want = set((n.idx for n in other.nodes))
        while want != set(id_map) or \
              not all(isinstance(i, int) for i in id_map.values()):
            print "Pass", pi
            pi += 1
            changes = False
            for i in want:
                n = other.nodes[i]
                if isinstance(id_map.get(i), int):
                    # Already done this one
                    continue
                print "Adding", i, n.anno
                if all(isinstance(id_map.get(r), int) for r in n.outs):
                    # Dependencies already exist, we can just add it
                    new = [id_map[oi] for oi in n.outs]
                    for ui,u in enumerate(self.nodes):
                        if n.anno != u.anno:
                            continue
                        maybe_resolve(u)
                        if new == u.outs:
                            id_map[i] = ui
                            print "Match", ui
                            changes = True
                            break
                    else:
                        idx = len(self.nodes)
                        id_map[i] = idx
                        newnode = Node(n.anno, idx, self)
                        self.nodes.append(newnode)
                        for oi in new:
                            self.link(idx, oi)
                        changes = True
                        print "New", idx, new
                        self.by_name[n.anno] = idx
                else:
                    print "Tentative"
                    # In the case where there are no tentative refs, we just take
                    # a tentative with all the targets that match us locally.
                    # If there _are_ tentative refs, we can only take a target into
                    # our tentative if its refs are in our refs' tentatives.
                    tents = set()
                    for ui,u in enumerate(self.nodes):
                        if n.anno != u.anno:
                            continue
                        maybe_resolve(u)
                        if len(n.outs) != len(u.outs):
                                continue
                        ok = True
                        for j,k in zip(n.outs, u.outs):
                            if j not in id_map:
                                continue
                            if isinstance(id_map[j], set): # tentative ref
                                if k not in id_map[j] and \
                                   not isinstance(k, Unresolved):
                                    ok = False
                                    break
                        if not ok:
                            continue
                        tents.add(ui)
                    print "Tents", tents
                    if tents:
                        if id_map.get(i) != tents:
                            id_map[i] = tents
                            changes = True
                    else:
                        # Doesn't already exist, let's add it (but unresolved)
                        new = [Unresolved(oi) for oi in n.outs]
                        idx = len(self.nodes)
                        id_map[i] = idx
                        self.nodes.append(Node(n.anno, idx, self))
                        for oi in new:
                            self.link(idx, oi)
                        changes = True
                        print "New unres", idx, new
                        self.by_name[n.anno] = idx
            print id_map
            if not changes:
                print "Firming up tentatives"
                for i in want:
                    if isinstance(id_map.get(i), set):
                        tents = id_map[i]
                        assert len(tents) == 1, (i, tents)
                        ui = tents.pop()
                        print "Matched", i, "=>", ui
                        id_map[i] = ui
                        n = other.nodes[i]
                        u = self.nodes[ui]
                        assert n.anno == u.anno, map(str(n, u))
        # Fix up unres
        for n in self.nodes:
            new = []
            for o in n.outs:
                if isinstance(o, Unresolved):
                    assert isinstance(id_map.get(o.src_ref), int), id_map.get(o.src_ref)
                    new.append(id_map[o.src_ref])
                else:
                    new.append(o)
            n.outs = new
        print "Completed in %d passes" % (pi,)

def test_simple():
    """Test merging two DAGs"""
    G1 = ADG('a', 'b', 'c')
    G1.link_by_name('a', 'b')
    G1.link_by_name('b', 'c')
    print 'G1'
    print G1
    G2 = ADG('a', 'b', 'c')
    G2.link_by_name('a', 'c')
    G2.link_by_name('b', 'c')
    print 'G2'
    print G2
    Got = ADG()
    print 'Merge G1'
    Got.merge(G1)
    print 'Merge G2'
    Got.merge(G2)
    print 'Got'
    print Got
    names = sorted(n.anno for n in Got.nodes)
    assert names == ['a', 'a', 'b', 'c'], names
    c = Got.nodes[Got.by_name['c']]
    b = Got.nodes[Got.by_name['b']]
    aa = set(n for n in Got.nodes if n.anno == 'a')
    assert not c.outs, c.outs
    assert b.outs == [c.idx], b.outs
    assert sorted(a.outs for a in aa) == sorted([[b.idx], [c.idx]]), [a.outs for a in aa]

def test_loop():
    """Test merging a 2-loop with itself"""
    G1 = ADG('a', 'b')
    G1.link_by_name('a', 'b')
    G1.link_by_name('b', 'a')
    print 'G1'
    print G1
    Got = ADG()
    print 'Merge G1'
    Got.merge(G1)
    print 'Merge G1 again'
    Got.merge(G1)
    print 'Got'
    print Got
    names = sorted(n.anno for n in Got.nodes)
    assert names == ['a', 'b'], names
    a = Got.nodes[Got.by_name['a']]
    b = Got.nodes[Got.by_name['b']]
    assert a.outs == [b.idx], a.outs
    assert b.outs == [a.idx], b.outs

def test_loop_different_names():
    """Test merging a 2-loop with one named differently"""
    G1 = ADG('a', 'b')
    G1.link_by_name('a', 'b')
    G1.link_by_name('b', 'a')
    print 'G1'
    print G1
    G2 = ADG('a', 'c')
    G2.link_by_name('a', 'c')
    G2.link_by_name('c', 'a')
    print 'G2'
    print G2
    Got = ADG()
    print 'Merge G1'
    Got.merge(G1)
    a = Got.nodes[Got.by_name['a']]
    print 'Merge G2'
    Got.merge(G2)
    print 'Got'
    print Got
    names = sorted(n.anno for n in Got.nodes)
    assert names == ['a', 'a', 'b', 'c'], names
    aa = set(n for n in Got.nodes if n.anno == 'a')
    a2 = (aa - set([a])).pop()
    b = Got.nodes[Got.by_name['b']]
    c = Got.nodes[Got.by_name['c']]
    assert a.outs == [b.idx], a.outs
    assert a2.outs == [c.idx], a2.outs
    assert b.outs == [a.idx], b.outs
    assert c.outs == [a2.idx], c.outs

def test_loops_2_4():
    """Test merging a 2-loop with a 4-loop"""
    G1 = ADG('a', 'b')
    G1.link_by_name('a', 'b')
    G1.link_by_name('b', 'a')
    print 'G1'
    print G1
    G2 = ADG('a', 'b', 'a', 'b')
    G2.link(0, 1)
    G2.link(1, 2)
    G2.link(2, 3)
    G2.link(3, 0)
    print 'G2'
    print G2
    Got = ADG()
    print 'Merge G1'
    Got.merge(G1)
    a = Got.nodes[Got.by_name['a']]
    b = Got.nodes[Got.by_name['b']]
    print 'Merge G2'
    Got.merge(G2)
    print 'Got'
    print Got
    # The two 'a's in G2 are identical, so the 4-loop gets folded down to 2
    names = sorted(n.anno for n in Got.nodes)
    assert names == ['a', 'b'], names
    assert a.outs == [b.idx], a.outs
    assert b.outs == [a.idx], b.outs

def test_loops_2_3():
    """Test merging a 2-loop with a 3-loop"""
    G1 = ADG('a', 'b')
    G1.link_by_name('a', 'b')
    G1.link_by_name('b', 'a')
    print 'G1'
    print G1
    G2 = ADG('a', 'a', 'b')
    G2.link(0, 1)
    G2.link(1, 2)
    G2.link(2, 0)
    print 'G2'
    print G2
    Got = ADG()
    print 'Merge G1'
    Got.merge(G1)
    a = Got.nodes[Got.by_name['a']]
    b = Got.nodes[Got.by_name['b']]
    print 'Merge G2'
    Got.merge(G2)
    print 'Got'
    print Got
    names = sorted(n.anno for n in Got.nodes)
    assert names == ['a', 'a', 'a', 'b', 'b'], names
    assert a.outs == [b.idx], a.outs
    assert b.outs == [a.idx], b.outs
    bb = set(n for n in Got.nodes if n.anno == 'b')
    b2 = (bb - set([b])).pop()
    assert len(b2.outs) == 1, b2.outs
    a2 = Got.nodes[b2.outs[0]]
    assert a2 != a, b2.outs
    assert a2.anno == 'a', a2
    assert len(a2.outs) == 1, a2.outs
    a3 = Got.nodes[a2.outs[0]]
    assert a3 not in (a, a2), a2.outs
    assert a3.anno == 'a', a3
    assert a3.outs == [b2.idx], a3.outs

def main():
    test_simple()
    test_loop()
    test_loop_different_names()
    test_loops_2_4()
    test_loops_2_3()

if __name__ == '__main__':
    main()
