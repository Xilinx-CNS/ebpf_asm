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

def parse_string(s):
    """Parse a string representation of a tree structure
    
    Nodes are separated by whitespace, while child lists are enclosed in
    balanced parentheses.
    
    Return value is the tree structure represented with tuples; terminal
    nodes are strings."""
    return _parse_string(s)[0]

def _parse_string(s):
    """Parse a string representation of a tree structure (implementation)
    
    Nodes are separated by whitespace, while child lists are enclosed in
    balanced parentheses.
    
    Return value is a tuple of (tree_structure, length_in_characters)"""
    if '(' not in s:
        s, _, _ = s.partition(')')
        return tuple(s.split()), len(s)
    i = s.index('(')
    j = s.index(')')
    if j < i:
        return _parse_string(s[:j])
    b, n = _parse_string(s[i+1:])
    j = i + n
    a = tuple(s[:i].split())
    c, m = _parse_string(s[j+2:])
    return a + (b,) + c, j+2+m

def main():
    tests = [("a (b\t (c))", ('a', ('b', ('c',)))),
             ("a (b c (d)) e (f)", ('a', ('b', 'c', ('d',)), 'e', ('f',))),
             ]
    for i,o in tests:
        assert parse_string(i) == o, (i, o)

if __name__ == '__main__':
    main()
