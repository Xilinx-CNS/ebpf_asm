#!/usr/bin/python2
# Copyright (c) 2017 Solarflare Communications Ltd
# Provided under the MIT license; see top of ebpf_asm.py for details

# Regression tests for ebpf_asm

import ebpf_asm as asm
import difflib
import struct

class TestFailure(Exception): pass

class BaseAsmTest(object):
    @property
    def prog_header(self):
        return """
        .include defs.i
        
        .text
        .section prog
        """
    @property
    def prog(self):
        return self.prog_header + self.src
    def assemble(self):
        self.asm = asm.Assembler()
        for line in self.prog.splitlines():
            self.asm.feed_line(line)
        self.asm.resolve_symbols()
        self.prog_bin = self.asm.sections['prog'].binary

class AsmTest(BaseAsmTest):
    """Test a program snippet, compare result against known binary"""
    def __init__(self, name, src, out):
        self.name = name
        self.src = src
        self.out = out
    def __str__(self):
        return 'ACC ' + self.name
    def dump(self):
        self.prog_dis = []
        for i in xrange(0, len(self.prog_bin), 8):
            op, regs, off, imm = struct.unpack('<BBhi', self.prog_bin[i:i+8])
            dst = regs & 0xf
            src = regs >> 4
            self.prog_dis.append((op, dst, src, off, imm))
    def run(self):
        self.assemble()
        self.dump()
        if self.out != self.prog_dis:
            differ = difflib.SequenceMatcher(a=self.out, b=self.prog_dis)
            delta = []
            for group in differ.get_grouped_opcodes(1):
                delta.append('@ %d+%d -> %d+%d:' % (group[0][1],
                                                    group[-1][2] - group[0][1],
                                                    group[0][3],
                                                    group[-1][4] - group[0][3]))
                for o, ai, aj, bi, bj in group:
                    if o == 'equal':
                        for a in xrange(ai, aj):
                            delta.append('  ' + str(self.out[a]))
                    else:
                        for a in xrange(ai, aj):
                            delta.append('- ' + str(self.out[a]))
                        for b in xrange(bi, bj):
                            delta.append('+ ' + str(self.prog_dis[b]))
            raise TestFailure("%s failed:\n%s" % (self.name, '\n'.join(delta)))

class BadAsmTest(BaseAsmTest):
    """Test an invalid program snippet, check that correct error is thrown"""
    def __init__(self, name, src, err):
        self.name = name
        self.src = src
        self.err = err
    def __str__(self):
        return 'REJ ' + self.name
    def run(self):
        try:
            self.assemble()
        except Exception as e:
            msg = ' '.join(map(str, e.args))
            if not msg.startswith(self.err):
                raise TestFailure("%s failed:\n  expected: %s\n       got: %s" %
                                  (self.name, self.err, msg))
        else:
            raise TestFailure("%s failed\n  expected: %s\n  but prog was accepted" %
                              (self.name, self.err))

AllTests = [

    # Register-to-register loads

    BadAsmTest('Invalid operand', 'ld r0, :', 'Bad direct operand :'),
    BadAsmTest('Too few args to ld', 'ld r0', 'Bad ld, expected 2 args'),
    BadAsmTest('Too many args to ld', 'ld r0, r1, r2', 'Bad ld, expected 2 args'),

    AsmTest('ld reg, imm', """
        ld  r1, 2
        ld  r2, 0x7fffffff.l
        ld  r3.q, 0x7fffffff00000001
    """, [
        (0x18, 1, 0, 0, 2),
        (0, 0, 0, 0, 0),
        (0xb4, 2, 0, 0, (1<<31) - 1),
        (0x18, 3, 0, 0, 1),
        (0, 0, 0, 0, (1<<31) - 1),
    ]),

    BadAsmTest('Size mismatch in ld reg, imm', 'ld r0.l, 1.q', 'Mismatched sizes'),
    BadAsmTest('Word-sized ld reg, imm', 'ld r0.w, 1', 'Bad size w for register load'),
    BadAsmTest('Byte-sized ld reg, imm', 'ld r0, 1.b', 'Bad size b for register load'),
    BadAsmTest('Offset where imm expected', 'ld r0, +1', 'Bad direct operand +1'),
    BadAsmTest('Immediate too big', 'ld r0.l, 0x80000000', 'Value out of range for s32'),
    BadAsmTest('Immediate too big', 'ld r0.l, -0x80000001', 'Value out of range for s32'),
    BadAsmTest('Immediate too big', 'ld r0, 0x10000000000000000', 'Value out of range for u64'),
    BadAsmTest('Negative imm64', 'ld r0, -1', 'Value out of range for u64'),
    BadAsmTest('ld imm, reg', 'ld 0, r0', 'ld imm,... illegal'),

    AsmTest('ld reg, reg', """
        ld  r1, r2
        ld  r3.l, r4
        ld  r5, r6.l
        ld  r7.l, r8.l
        ld  r9.q, fp
    """, [
        (0xbf, 1, 2, 0, 0),
        (0xbc, 3, 4, 0, 0),
        (0xbc, 5, 6, 0, 0),
        (0xbc, 7, 8, 0, 0),
        (0xbf, 9, 10, 0, 0),
    ]),

    BadAsmTest('Size mismatch in ld reg, reg', 'ld r0.l, r1.q', 'Mismatched sizes'),
    BadAsmTest('Word-sized ld reg, imm', 'ld r0.w, r1', 'Bad size w for register load'),
    BadAsmTest('Byte-sized ld reg, imm', 'ld r0, r1.b', 'Bad size b for register load'),
    BadAsmTest('Offset operand without indirection', 'ld r0, r1+1', 'Bad direct operand r1+1'),

    # Register-to-memory loads

    BadAsmTest('Empty indirection', 'ld [], r0', 'Bad direct operand'),
    BadAsmTest('Missing ]', 'ld [r0, r1', 'Bad indirect operand'),
    BadAsmTest('Missing ] before size', 'ld [r0.l, r1', 'Bad indirect operand'),
    BadAsmTest('Size inside indirection', 'ld [r0.l], r1', 'Bad size in indirect operand'),
    BadAsmTest('Size inside indirection', 'ld [r0.q+0], r1', 'Bad size in offset operand'),

    AsmTest('ld [ptr], imm', """
        ld  [r1], 2
        ld  [r1+0x7fff.b].l, 2 ; size suffixes on disp are ignored
        ld  [r0+1.q], 2.w ; ... even if they're bigger than .w
        ld  [r0-0x8000].b, -2.b
        ld  [r0], 0x7fffffff
        ld  [r0], -0x80000000
    """, [
        (0x7a, 1, 0, 0, 2),
        (0x62, 1, 0, 32767, 2),
        (0x6a, 0, 0, 1, 2),
        (0x72, 0, 0, -32768, -2),
        (0x7a, 0, 0, 0, (1<<31) - 1),
        (0x7a, 0, 0, 0, -(1<<31)),
    ]),

    BadAsmTest('Size mismatch in ld [ptr], imm', 'ld [r0].l, 1.q', 'Mismatched sizes'),
    BadAsmTest('Offset where imm expected', 'ld [r0], +1', 'Bad direct operand +1'),
    BadAsmTest('Immediate too big', 'ld [r0], 0x80000000', 'Value out of range for s32'),
    BadAsmTest('Offset too big', 'ld [r0+0x8000], 1', 'Value out of range for s16'),
    BadAsmTest('Offset too big', 'ld [r0-0x8001], 1', 'Value out of range for s16'),

    AsmTest('ld [ptr], reg', """
        ld  [r1], r2
        ld  [r1+2].l, r3
        ld  [r1-2], r3.w
        ld  [fp-1.b].b, r3.b
    """, [
        (0x7b, 1, 2, 0, 0),
        (0x63, 1, 3, 2, 0),
        (0x6b, 1, 3, -2, 0),
        (0x73, 10, 3, -1, 0),
    ]),

    BadAsmTest('Size mismatch in ld [ptr], reg', 'ld [r0].l, r1.q', 'Mismatched sizes'),
    BadAsmTest('Offset operand without indirection', 'ld [r0], r1+1', 'Bad direct operand r1+1'),

    # Memory-to-register loads

    BadAsmTest('Empty indirection', 'ld r0, []', 'Bad direct operand'),
    BadAsmTest('Missing ]', 'ld r0, [r1', 'Bad indirect operand'),
    BadAsmTest('Missing ] before size', 'ld r0, [r1.l', 'Bad indirect operand'),
    BadAsmTest('Size inside indirection', 'ld r0, [r1.l]', 'Bad size in indirect operand'),
    BadAsmTest('Size inside indirection', 'ld r0, [r1.q+0]', 'Bad size in offset operand'),

    AsmTest('ld reg, [ptr]', """
        ld  r2, [r1]
        ld  r3, [r1+2].l
        ld  r3.w, [r1-2]
        ld  r3.b, [fp-1.b].b
    """, [
        (0x79, 2, 1, 0, 0),
        (0x61, 3, 1, 2, 0),
        (0x69, 3, 1, -2, 0),
        (0x71, 3, 10, -1, 0),
    ]),

    BadAsmTest('ld imm, reg', 'ld 0, [r0]', 'ld imm,... illegal'),
    BadAsmTest('Offset too big', 'ld r1, [r0+0x8000]', 'Value out of range for s16'),
    BadAsmTest('Offset too big', 'ld r1, [r0-0x8001]', 'Value out of range for s16'),
    BadAsmTest('Size mismatch in ld reg, [ptr]', 'ld r1.q, [r0].l', 'Mismatched sizes'),
    BadAsmTest('Offset operand without indirection', 'ld r1+1, [r0]', 'Bad direct operand r1+1'),

    # ldpkt

    BadAsmTest('Too few args to ldpkt', 'ldpkt r0', 'Bad ldpkt, expected 2 args'),
    BadAsmTest('Too many args to ldpkt', 'ldpkt r0, [r1], +2', 'Bad ldpkt, expected 2 args'),
    BadAsmTest('ldpkt missing indirection', 'ldpkt r0, r1', 'Bad ldpkt, src must be indirect'),
    BadAsmTest('ldpkt missing indirection', 'ldpkt r0, r1+2', 'Bad direct operand r1+2'),

    #  LD_ABS
    AsmTest('LD_ABS (ldpkt)', """
        ldpkt   r0, [1]
        ldpkt   r0.w, [2]
        ldpkt   r0, [-0x80000000].b
        ldpkt   r0.l, [0x7fffffff].l
    """, [
        (0x20, 0, 0, 0, 1),
        (0x28, 0, 0, 0, 2),
        (0x30, 0, 0, 0, -(1 << 31)),
        (0x20, 0, 0, 0, (1 << 31) - 1),
    ]),

    BadAsmTest('ldpkt bad dst_reg', 'ldpkt r1, [0]', 'ldpkt dst must be r0, not r1'),
    BadAsmTest('Extraneous + before disp', 'ldpkt r0, [+2]', 'Bad direct operand'),
    BadAsmTest('Displacement too big', 'ldpkt r0, [0x80000000]', 'Value out of range for s32'),
    BadAsmTest('Displacement too big', 'ldpkt r0, [-0x80000001]', 'Value out of range for s32'),
    BadAsmTest('64-bit ldpkt', 'ldpkt r0.q, [0]', 'ldpkt .q illegal'),
    BadAsmTest('Size mismatch in LD_ABS', 'ldpkt r0.q, [0].l', 'Mismatched sizes'),
    BadAsmTest('Size inside LD_ABS indirection', 'ldpkt r0, [0.l]', 'Bad size in indirect operand'),

    #  LD_IND
    AsmTest('LD_IND (ldpkt)', """
        ldpkt   r0, [r1]
        ldpkt   r0.w, [r1+-2] ; that +- isn't pretty but we allow it
        ldpkt   r0, [r2-0x80000000.b].b ; size suffixes on disp are ignored
        ldpkt   r0.l, [r2+0x7fffffff].l
    """, [
        (0x40, 0, 1, 0, 0),
        (0x48, 0, 1, 0, -2),
        (0x50, 0, 2, 0, -(1 << 31)),
        (0x40, 0, 2, 0, (1 << 31) - 1),
    ]),

    BadAsmTest('ldpkt bad dst_reg', 'ldpkt r1, [r0]', 'ldpkt dst must be r0, not r1'),
    BadAsmTest('Extraneous + before disp', 'ldpkt r0, [r1++2]', 'Bad immediate +2'),
    BadAsmTest('Displacement too big', 'ldpkt r0, [r1+0x80000000]', 'Value out of range for s32'),
    BadAsmTest('Displacement too big', 'ldpkt r0, [r1-0x80000001]', 'Value out of range for s32'),
    BadAsmTest('64-bit ldpkt', 'ldpkt r0.q, [r1]', 'ldpkt .q illegal'),
    BadAsmTest('Size mismatch in LD_IND', 'ldpkt r0.q, [r1].l', 'Mismatched sizes'),
    BadAsmTest('Size inside LD_IND indirection', 'ldpkt r0, [r1.l]', 'Bad size in indirect operand'),

    # xadd

    BadAsmTest('Too few args to xadd', 'xadd [r0+0]', 'Bad xadd, expected 2 args'),
    BadAsmTest('Too many args to xadd', 'xadd [r0+0], r0, 0', 'Bad xadd, expected 2 args'),
    BadAsmTest('xadd missing indirection', 'xadd r0, r1', 'xadd direct_operand,... illegal'),
    BadAsmTest('xadd missing indirection', 'xadd r0+0, r1', 'Bad direct operand r0+0'),
    BadAsmTest('xadd indirect src', 'xadd [r0], [r1]', 'Bad direct operand [r1]'),

    AsmTest('xadd', """
        xadd    [r0], r1
        xadd    [r1+0x7fff].l, r3
        xadd    [r1-2], r3.l
        xadd    [r1+-0x8000].l, r3.l
    """, [
        (0xdb, 0, 1, 0, 0),
        (0xc3, 1, 3, 32767, 0),
        (0xc3, 1, 3, -2, 0),
        (0xc3, 1, 3, -32768, 0),
    ]),

    BadAsmTest('Extraneous + before disp', 'xadd [r0++2], r1', 'Bad immediate +2'),
    BadAsmTest('Displacement too big', 'xadd [r1+0x8000], r0', 'Value out of range for s16'),
    BadAsmTest('Displacement too big', 'xadd [r1-0x8001], r0', 'Value out of range for s16'),
    BadAsmTest('Size mismatch in xadd', 'xadd [r1].q, r0.l', 'Mismatched sizes'),
    BadAsmTest('Word-sized xadd', 'xadd [r0].w, r1', 'Bad size w for xadd'),
    BadAsmTest('Byte-sized xadd', 'xadd [r0], r1.b', 'Bad size b for xadd'),

]

def run_testset(tests, verbose=False):
    passes = 0
    fails = 0
    for i,test in enumerate(tests):
        try:
            test.run()
            if verbose:
                print "%03d %s PASS" % (i, test)
            passes += 1
        except Exception as e:
            print "%03d %s FAIL %s" % (i, test, e)
            fails += 1
    return passes, fails

if __name__ == '__main__':
    import sys
    verbose = '-v' in sys.argv[1:]
    passes, fails = run_testset(AllTests, verbose=verbose)
    if verbose:
        print "DONE; %d PASS, %d FAIL" % (passes, fails)
    if fails or not passes:
        sys.exit(1)
