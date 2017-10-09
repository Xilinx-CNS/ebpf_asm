#!/usr/bin/python2
# Copyright (c) 2017 Solarflare Communications Ltd
# Provided under the MIT license; see top of ebpf_asm.py for details

# Regression tests for ebpf_asm

import ebpf_asm as asm
import difflib
import struct

class TestFailure(Exception): pass

class AcceptTestMixin(object):
    """Test a program snippet, compare result against known binary"""
    def __init__(self, name, src, out):
        self.name = name
        self.src = src
        self.out = out
    def __str__(self):
        return 'ACC ' + self.name
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

class RejectTestMixin(object):
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
    def dump(self):
        self.prog_dis = []
        for i in xrange(0, len(self.prog_bin), 8):
            op, regs, off, imm = struct.unpack('<BBhi', self.prog_bin[i:i+8])
            dst = regs & 0xf
            src = regs >> 4
            self.prog_dis.append((op, dst, src, off, imm))

class AsmTest(BaseAsmTest, AcceptTestMixin): pass
class BadAsmTest(BaseAsmTest, RejectTestMixin): pass

class BaseDataTest(object):
    @property
    def prog_header(self):
        return """
        .include defs.i

        .data
        .section data
        """
    @property
    def prog(self):
        return self.prog_header + self.src
    def assemble(self):
        self.asm = asm.Assembler()
        for line in self.prog.splitlines():
            self.asm.feed_line(line)
        self.asm.resolve_symbols()
        self.prog_bin = self.asm.sections['data'].binary
    def dump(self):
        # TODO teach this to return offsets & symbols
        self.prog_dis = self.prog_bin.split('\0')

class DataTest(BaseDataTest, AcceptTestMixin): pass
class BadDataTest(BaseDataTest, RejectTestMixin): pass

AllTests = [

    ## PROGRAM TEXT

    # Bogus format

    BadAsmTest('Nonexistent insn', 'frob r0', 'Unrecognised instruction frob'),
    BadAsmTest('Label and insn on same line', 'label: exit', 'Unrecognised instruction label:'),
    BadAsmTest('Comma before insn', ', exit', 'Unrecognised instruction ,'),
    BadAsmTest('Comma after insn', 'ld, r0', 'Unrecognised instruction ld,'),
    BadAsmTest('Bad character in label', 'a,:', 'Unrecognised instruction a,:'),
    BadAsmTest('Whitespace in label', 'a :', 'Unrecognised instruction a'),
    BadAsmTest('Numeric label', '1:', 'Unrecognised instruction 1:'),
    BadAsmTest('Invalid label', '-1:', 'Unrecognised instruction -1:'),
    BadAsmTest('Data in program section', 'asciz "foo"', 'Unrecognised instruction asciz'),

    # Register-to-register loads

    BadAsmTest('Invalid operand', 'ld r0, :', 'Bad direct operand :'),
    BadAsmTest('Empty operand', 'ld , 1', 'Bad direct operand '),
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
    BadAsmTest('Non-existent register', 'ld r11, 0', 'Bad register r11'),
    BadAsmTest('Double size suffix on ld dst', 'ld r0.l.q, 1', 'Bad direct operand r0.l'),
    BadAsmTest('Double size suffix on ld src_imm', 'ld r0, 1.l.q', 'Bad direct operand 1.l'),

    AsmTest('ld reg, reg', """
        ld  r1, r2
        ld  r3.l, r4
        ld  r5, r6.l
        ld  r7.l, r8.l
        ld  r10.q, fp
    """, [
        (0xbf, 1, 2, 0, 0),
        (0xbc, 3, 4, 0, 0),
        (0xbc, 5, 6, 0, 0),
        (0xbc, 7, 8, 0, 0),
        (0xbf, 10, 10, 0, 0),
    ]),

    BadAsmTest('Size mismatch in ld reg, reg', 'ld r0.l, r1.q', 'Mismatched sizes'),
    BadAsmTest('Word-sized ld reg, imm', 'ld r0.w, r1', 'Bad size w for register load'),
    BadAsmTest('Byte-sized ld reg, imm', 'ld r0, r1.b', 'Bad size b for register load'),
    BadAsmTest('Offset operand without indirection', 'ld r0, r1+1', 'Bad direct operand r1+1'),
    BadAsmTest('Double size suffix on ld src_reg', 'ld r0, r1.l.q', 'Bad direct operand r1.l'),

    # Register-to-memory loads

    BadAsmTest('Empty indirection', 'ld [], r0', 'Bad direct operand'),
    BadAsmTest('Missing ]', 'ld [r0, r1', 'Bad indirect operand'),
    BadAsmTest('Missing ] before size', 'ld [r0.l, r1', 'Bad indirect operand'),
    BadAsmTest('Size inside indirection', 'ld [r0.l], r1', 'Bad size in indirect operand'),
    BadAsmTest('Size inside indirection', 'ld [r0.q+0], r1', 'Bad size in offset operand'),

    AsmTest('ld [ptr], imm', """
        ld  [r1], 2
        ld  [r1+0x7fff].l, 2
        ld  [r0+1], 2.w
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
    BadAsmTest('Size suffix on displacement', 'ld [r0+1.b], 1', 'Bad immediate 1.b'),
    BadAsmTest('Double size suffix on ld src_imm', 'ld [r0], 4.w.b', 'Bad direct operand 4.w'),

    AsmTest('ld [ptr], reg', """
        ld  [r1], r2
        ld  [r1+2].l, r3
        ld  [r1-2], r3.w
        ld  [fp-1].b, r3.b
    """, [
        (0x7b, 1, 2, 0, 0),
        (0x63, 1, 3, 2, 0),
        (0x6b, 1, 3, -2, 0),
        (0x73, 10, 3, -1, 0),
    ]),

    BadAsmTest('Size mismatch in ld [ptr], reg', 'ld [r0].l, r1.q', 'Mismatched sizes'),
    BadAsmTest('Offset operand without indirection', 'ld [r0], r1+1', 'Bad direct operand r1+1'),
    BadAsmTest('Double size suffix on ld src_reg', 'ld [r0], r1.w.b', 'Bad direct operand r1.w'),

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
        ld  r3.b, [fp-1].b
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
    BadAsmTest('Double size suffix on ld dst', 'ld r0.w.b, [r1]', 'Bad direct operand r0.w'),
    BadAsmTest('Size suffix on displacement', 'ld r0, [fp-1.b]', 'Bad immediate 1.b'),

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
    BadAsmTest('Size suffix on displacement', 'ldpkt r0, [-1.b]', 'Bad size in indirect operand'),

    #  LD_IND
    AsmTest('LD_IND (ldpkt)', """
        ldpkt   r0, [r1]
        ldpkt   r0.w, [r1+-2] ; that +- isn't pretty but we allow it
        ldpkt   r0, [r2-0x80000000].b
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
    BadAsmTest('Size suffix on displacement', 'ldpkt r0, [r1-1.b]', 'Bad immediate 1.b'),

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

    # Jumps

    BadAsmTest('Jump with no args', 'jr', 'Bad jr, expected 1 or 4 args'),
    BadAsmTest('Jump with two args', 'jr cc, +1', 'Bad jr, expected 1 or 4 args'),
    BadAsmTest('Jump with five args', 'jr nz, r0, r1, 2, +1', 'Bad jr, expected 1 or 4 args'),

    #  Unconditional
    AsmTest('Unconditional jump', """
        jr  +0x7fff
        label:
        jr  -0x8000
        jr  label
    """, [
        (0x05, 0, 0, 32767, 0),
        (0x05, 0, 0, -32768, 0),
        (0x05, 0, 0, -2, 0),
    ]),

    BadAsmTest('Jump offset too big', 'jr +0x8000', 'Value out of range for s16'),
    BadAsmTest('Jump offset too big', 'jr -0x8001', 'Value out of range for s16'),
    BadAsmTest('Jump to undefined label', 'jr undefined', 'Undefined symbol undefined'),
    BadAsmTest('Jump offset missing +', 'jr 1', 'Bad jump offset (missing + sign?)'),
    BadAsmTest('Jump offset with two + signs', 'jr ++1', 'Bad immediate +1'),
    BadAsmTest('Size suffix on jump offset', 'jr +1.b', 'Bad immediate 1.b'),

    #  Conditional, BPF_K
    AsmTest('Compare immediate and jump', """
        jr  z, r1, 0, +1
        label:
        jr  gt, r1, 0x7fffffff, +2
        jr  eq, r1, -0x80000000, label
        jr  &, r1, 1, -1
        jr  sle, fp, 0, +-1 ; that +- isn't pretty but we allow it
    """, [
        (0x15, 1, 0, 1, 0),
        (0x25, 1, 0, 2, (1 << 31) - 1),
        (0x15, 1, 0, -2, -(1 << 31)),
        (0x45, 1, 0, -1, 1),
        (0xd5, 10, 0, -1, 0),
    ]),

    BadAsmTest('Immediate too big', 'jr  ge, r1, 0x80000000, +1', 'Value out of range for s32'),
    BadAsmTest('Immediate too big', 'jr  sgt, r1, -0x80000001, +1', 'Value out of range for s32'),
    BadAsmTest('Jump with bogus cc', 'jr  foo, r1, 0, +1', 'Bad jump op foo'),
    BadAsmTest('jr cc, imm, imm', 'jr nz, 0, 0, +0', 'jr cc,imm,... illegal'),
    BadAsmTest('Offset where imm expected', 'jr nz, r0, +0, +0', 'Bad direct operand +0'),
    BadAsmTest('Size suffix on compare dst_reg', 'jr z, r0.l, 1, +1', 'Bad size in jump dst'),
    BadAsmTest('Size suffix on compare immediate', 'jr z, r0, 1.l, +1', 'Bad size in jump src'),
    BadAsmTest('Size suffix on jump offset', 'jr nz, r0, 1, +1.b', 'Bad immediate 1.b'),

    #  Conditional, BPF_X
    AsmTest('Compare register and jump', """
        jr  ne, r1, r2, +1
        jr  <, r3, r4, -1
        jr  sge, r0, fp, +0
    """, [
        (0x5d, 1, 2, 1, 0),
        (0xad, 3, 4, -1, 0),
        (0x7d, 0, 10, 0, 0),
    ]),

    BadAsmTest('jr cc, imm, reg', 'jr nz, 0, r0, +0', 'jr cc,imm,... illegal'),
    BadAsmTest('Jump dst [ptr]', 'jr nz, [r0], r1, +0', 'Bad direct operand [r0]'),
    BadAsmTest('Jump src [ptr]', 'jr nz, r0, [r1], +0', 'Bad direct operand [r1]'),
    BadAsmTest('Size suffix on compare src_reg', 'jr z, r0, r1.l, +1', 'Bad size in jump src'),
    BadAsmTest('Size suffix on jump offset', 'jr nz, r0, r1, +1.b', 'Bad immediate 1.b'),

    # Function calls

    BadAsmTest('Missing arg to call', 'call', 'Bad call, expected 1 arg'),
    BadAsmTest('Too many args to call', 'call 1, 2', 'Bad call, expected 1 arg'),

    AsmTest('Function calls', """
        call    011 ; let's test octal while we're here
        call    bpf_map_update_elem
        call    0x7fffffff
        call    -0x80000000
    """, [
        (0x85, 0, 0, 0, 9),
        (0x85, 0, 0, 0, 2),
        (0x85, 0, 0, 0, (1 << 31) - 1),
        (0x85, 0, 0, 0, -(1 << 31)),
    ]),

    BadAsmTest('Immediate too big', 'call 0x80000000', 'Value out of range for s32'),
    BadAsmTest('Immediate too big', 'call -0x80000001', 'Value out of range for s32'),
    BadAsmTest('Offset where imm expected', 'call +0', 'Bad immediate +0'),
    BadAsmTest('Call undefined function', 'call undefined', 'Bad immediate undefined'),
    BadAsmTest('Call register', 'call r0', 'Bad immediate r0'),
    BadAsmTest('Size suffix on call number', 'call 1.b', 'Bad immediate 1.b'),

    # Program exit

    BadAsmTest('Too many args to exit', 'exit 1', 'Bad exit, expected no args'),
    AsmTest('exit', 'exit', [(0x95, 0, 0, 0, 0)]),

    # ALU

    #  binary ops
    BadAsmTest('Too few args to ALU binary op', 'add r1', 'Bad add, expected 2 args'),
    BadAsmTest('Too many args to ALU binary op', 'sub r1, r2, r3', 'Bad sub, expected 2 args'),

    AsmTest('ALU binary ops, BPF_K', """
        add r1, 2
        sub r2, 0x7fffffff
        and r3, -0x80000000
        xor r4.l, 1
        lsh r5, 03.l ; this treats r5 as a .l, which is slightly odd
        mod r6.l, 0x10.l
        arsh    fp, 1.q
    """, [
        (0x07, 1, 0, 0, 2),
        (0x17, 2, 0, 0, (1 << 31) - 1),
        (0x57, 3, 0, 0, -(1 << 31)),
        (0xa4, 4, 0, 0, 1),
        (0x64, 5, 0, 0, 3),
        (0x94, 6, 0, 0, 16),
        (0xc7, 10, 0, 0, 1),
    ]),

    BadAsmTest('ALU indirect dst', 'add [r1], 0', 'Bad direct operand [r1]'),
    BadAsmTest('ALU immediate dst', 'or 1, 0', 'or imm,... illegal'),
    BadAsmTest('Immediate too big', 'mul r1, 0x80000000', 'Value out of range for s32'),
    BadAsmTest('Immediate too big', 'div r1, -0x80000001', 'Value out of range for s32'),
    BadAsmTest('Word-sized ALU', 'add r0.w, 1', 'Bad size w for ALU op'),
    BadAsmTest('Byte-sized ALU', 'add r0.b, 1', 'Bad size b for ALU op'),
    BadAsmTest('Size mismatch in ALU reg, imm', 'add r0.q, 0.l', 'Mismatched sizes'),
    BadAsmTest('Offset where imm expected', 'add r1, +0', 'Bad direct operand +0'),

    AsmTest('ALU binary ops, BPF_X', """
        or  r1, r2
        mul r3.l, r4
        rsh r5, r6.l
        div r7.l, r8.l
        add r9, fp.q
    """, [
        (0x4f, 1, 2, 0, 0),
        (0x2c, 3, 4, 0, 0),
        (0x7c, 5, 6, 0, 0),
        (0x3c, 7, 8, 0, 0),
        (0x0f, 9, 10, 0, 0),
    ]),

    BadAsmTest('ALU indirect dst', 'add [r1], r0', 'Bad direct operand [r1]'),
    BadAsmTest('ALU immediate dst', 'xor 1, r0', 'xor imm,... illegal'),
    BadAsmTest('Word-sized ALU', 'add r0.w, r1', 'Bad size w for ALU op'),
    BadAsmTest('Byte-sized ALU', 'add r0.b, r1', 'Bad size b for ALU op'),
    BadAsmTest('Size mismatch in ALU reg, imm', 'add r0.q, r1.l', 'Mismatched sizes'),

    #  unary op (neg)
    BadAsmTest('Too few args to neg', 'neg', 'Bad neg, expected 1 arg'),
    BadAsmTest('Too many args to neg', 'neg r1, 0', 'Bad neg, expected 1 arg'),

    AsmTest('ALU unary neg', """
        neg r1
        neg r2.l
        neg fp.q
    """, [
        (0x87, 1, 0, 0, 0),
        (0x84, 2, 0, 0, 0),
        (0x87, 10, 0, 0, 0),
    ]),

    BadAsmTest('neg immediate dst', 'neg 1', 'neg imm illegal'),
    BadAsmTest('neg indirect dst', 'neg [r1]', 'Bad direct operand [r1]'),
    BadAsmTest('Word-sized neg', 'neg r0.w', 'Bad size w for ALU op'),
    BadAsmTest('Byte-sized neg', 'neg r0.b', 'Bad size b for ALU op'),

    #  endianness op
    BadAsmTest('Too few args to end', 'end le', 'Bad end, expected 2 args'),
    BadAsmTest('Too many args to end', 'end le, r1.w, r2', 'Bad end, expected 2 args'),

    AsmTest('Endianness op', """
        end le, r1
        end be, r2.w
        end le, fp.q
        end le, r3.l
    """, [
        (0xd4, 1, 0, 0, 64),
        (0xdc, 2, 0, 0, 16),
        (0xd4, 10, 0, 0, 64),
        (0xd4, 3, 0, 0, 32),
    ]),

    BadAsmTest('end immediate dst', 'end le, 1', 'end ..., imm illegal'),
    BadAsmTest('end indirect dst', 'end le, [r1]', 'Bad direct operand [r1]'),
    BadAsmTest('Byte-sized end', 'end le, r0.b', 'Bad size b for endian op'),
    BadAsmTest('Bad endian direction', 'end r1, r2', 'Bad end, expected le or be'),
    BadAsmTest('Size on endian direction', 'end le.l, r0', 'Bad end, expected le or be'),

    ## STATIC DATA

    BadDataTest('Instruction in data section', 'ld r0, 0', 'No such .data insn'),
    BadDataTest('asciz bad type', 'asciz 1', 'asciz takes a string'),
    BadDataTest('asciz malformed', 'asciz "', 'EOL while scanning string literal'),
    BadDataTest('Too few args to asciz', 'asciz', 'unexpected EOF while parsing'),
    BadDataTest('Too many args to asciz', 'asciz "a", "b"', 'asciz takes a string'),

    DataTest('Static strings', """
    strings:
        asciz "foo"
        asciz 'ba"r'
        asciz '''quu'x'''
    """, ['foo', 'ba"r', "quu'x", '']),

    ## ASSEMBLER DIRECTIVES

    # Equates

    BadAsmTest('Too few args to .equ', '.equ name', 'Bad .equ, expected 2 args'),
    BadAsmTest('Too many args to .equ', '.equ name, 1, 2', 'Bad .equ, expected 2 args'),
    BadAsmTest('Malformed equate value', '.equ name, :', 'Bad immediate :'),
    BadAsmTest('Comma after .equ', '.equ, name, 1', 'No such directive .equ,'),
    BadAsmTest('Empty equate name', '.equ , 1', 'Bad .equ name '),
    BadAsmTest('Equate name starts with digit', '.equ 1, 2', 'Bad .equ name 1'),
    BadAsmTest('Equate value undefined', '.equ name, value', 'Bad immediate value'),
    BadAsmTest('Offset where imm expected', '.equ name, +0', 'Bad immediate +0'),

    AsmTest('Equates', """
        .equ    foo, 1
        .equ    a b, foo
        .equ    :, -1
        .equ    r1, :
        .equ    foo.b, 2
        ld  r1, a b
        ld  r2, :.l
        ld  r3, r1.l ; register name takes priority over equate name
        ld  [r4+r1], 1 ; can't be a register, so must be an equate
        ld  [r5], foo.b ; resolves to foo
        ld  [r6], foo.b.b ; resolves to foo.b
    """, [
        (0x18, 1, 0, 0, 1),
        (0, 0, 0, 0, 0),
        (0xb4, 2, 0, 0, -1),
        (0xbc, 3, 1, 0, 0),
        (0x7a, 4, 0, -1, 1),
        (0x72, 5, 0, 0, 1),
        (0x72, 6, 0, 0, 2),
    ]),

    BadAsmTest('Size suffix stripping from equate', """
        .equ    foo.b, 1
        ld  [r1], foo.b ; 'foo' matches the _label_ref_re
    """, 'Value out of range for s32 foo'),
    BadAsmTest('Size suffix stripping from equate', """
        .equ    foo.b, 1
        ld  [r1], foo.b.b.b
    """, 'Bad direct operand foo.b.b'),
    BadAsmTest('Size suffix on equate value', '.equ foo, 1.b', 'Bad immediate 1.b'),
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
