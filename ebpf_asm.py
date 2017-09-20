#!/usr/bin/python2
# Copyright (c) 2017 Solarflare Communications Ltd

import re
import struct
import ast
import optparse

VERSION = None

"""Input language for .section prog:

Based on Intel syntax:
* operands go dest, source
* memory dereferences in [square brackets]

We have to cover the following insn classes:
* BPF_LD    0x00
* BPF_LDX   0x01
* BPF_ST    0x02
* BPF_STX   0x03
* BPF_ALU   0x04
* BPF_JMP   0x05
* BPF_ALU64 0x07
Let's first consider LD[X]/ST[X].  These have a two-bit 'size' field:
* BPF_W   0x00    l
* BPF_H   0x08    w
* BPF_B   0x10    b
* BPF_DW  0x18    q
and a three-bit 'mode' field:
* BPF_IMM  0x00
* BPF_ABS  0x20
* BPF_IND  0x40
* BPF_MEM  0x60
* BPF_XADD 0xc0
For BPF_IMM we can write
ld      reg, imm        ; implicitly 64-bit
ld      reg.q, imm      ; can be explicit instead
For BPF_MEM we can write
ld      reg.sz, [reg+disp]  ; LDX.  Omitting .sz always implies 'q', i.e. 64-bit
ld      [reg+disp], reg.sz  ; STX
ld      [reg+disp], imm.sz  ; ST
For BPF_ABS, we can write
ldpkt   r0.sz, [disp]
For BPF_IND, we can write
ldpkt   r0.sz, [reg+disp]
For BPF_XADD we can write
xadd    [reg+disp], reg.sz  ; sz must be 'q' or 'l'
Next let's consider ALU[64].  This has a one-bit 'source' (K|X) field, and a
four-bit 'operation code' field:
* BPF_ADD   0x00
* BPF_SUB   0x10
* BPF_MUL   0x20
* BPF_DIV   0x30
* BPF_OR    0x40
* BPF_AND   0x50
* BPF_LSH   0x60
* BPF_RSH   0x70
* BPF_NEG   0x80
* BPF_MOD   0x90
* BPF_XOR   0xa0
* BPF_MOV   0xb0
* BPF_ARSH  0xc0
* BPF_END   0xd0
For BPF_MOV we can write:
ld      reg, reg.sz     ; sz must be 'q' or 'l'
ld      reg.sz, reg     ; alternate syntax for the above
ld      reg.l, imm      ; only 32-bit (for 64-bit see LD|IMM)
For BPF_NEG we can write:
neg     reg.sz          ; sz must be 'q' or 'l'
For BPF_END we can write:
end     be, reg.sz      ; sz must be 'q', 'l', or 'w'; 'q' assumed
end     le, reg.sz      ; cpu to/from LE
For the others, we use the lower-case name of the op and write e.g.
add     reg, reg.sz     ; sz must be 'q' or 'l'
add     reg.sz, reg     ; alternate syntax for the above
add     reg.l, imm      ; '.l' may be omitted
Finally the BPF_JMP class:
* BPF_JA    0x00
* BPF_JEQ   0x10
* BPF_JGT   0x20
* BPF_JGE   0x30
* BPF_JSET  0x40
* BPF_JNE   0x50
* BPF_JSGT  0x60
* BPF_JSGE  0x70
* BPF_CALL  0x80
* BPF_EXIT  0x90
* BPF_JLT   0xa0
* BPF_JLE   0xb0
* BPF_JSLT  0xc0
* BPF_JSLE  0xd0
For BPF_CALL, we can write:
call    function        ; calls helper function, r0=function(r1, r2, r3, r4, r5)
For BPF_EXIT, we can write:
exit                    ; return r0
For BPF_JA, we can write:
jr      offset_or_label
For the others, we use the lower-case name of the op and write e.g.
jr z,   reg, reg, offset_or_label   ; if (reg1.q == reg2.q) jr offset_or_label
jr z,   reg, imm, offset_or_label   ; if (reg.q == imm.l) jr offset_or_label

Register names: r0-r10, fp (== r10)
"""

class BaseAssembler(object):
    def __init__(self, equates):
        self.equates = equates
    _size_re = re.compile(r'\.([bwlq])$')
    _octal_re = re.compile(r'0\d+$')
    _decimal_re = re.compile(r'\d+$')
    _hex_re = re.compile(r'0x[0-9a-fA-F]+$')
    def parse_immediate(self, imm):
        d = {}
        if self._size_re.search(imm):
            d['size'] = imm[-1]
            imm = imm[:-2]
        neg = False
        if imm.startswith('-'):
            neg = True
            imm = imm[1:]
        if self._octal_re.match(imm):
            d['imm'] = int(imm, 8)
        elif self._decimal_re.match(imm):
            d['imm'] = int(imm)
        elif self._hex_re.match(imm):
            d['imm'] = int(imm, 16)
        elif imm in self.equates:
            d['imm'] = self.equates[imm]
        else:
            raise Exception("Bad immediate", imm)
        if neg:
            d['imm'] = -d['imm']
        return d
    _op_args_re = re.compile('(\S+)\s+(\S.*)$')
    def parse_op_args(self, line):
        m = self._op_args_re.match(line)
        if not m:
            return (line, '')
        return m.groups()
    _label_re = re.compile('\s*(\w+):$')

class ProgAssembler(BaseAssembler):
    elf_flags = 'AX'
    def __init__(self, equates):
        super(ProgAssembler, self).__init__(equates)
        self.symbols = {}
        self.symrefs = {}
        self.relocs = {}
        self.section = []
    @property
    def current_index(self):
        return len(self.section)
    def append_insn(self, r):
        f,so,si = r
        if so is not None:
            self.symrefs[self.current_index] = so
        if si is not None:
            self.relocs[self.current_index] = si
        self.section.append(f)
    def feed_line(self, line):
        d = self.parse_line(line.strip())
        if 'label' in d:
            self.symbols[d['label']] = self.current_index
            return
        e = self.generate_insn(d)
        r = self.assemble_insn(e) # little-endian for now
        if isinstance(r, list): # BPF_LD_IMM64 is two insns
            self.append_insn(r[0])
            self.append_insn(r[1])
        else:
            self.append_insn(r)
    def resolve_symbols(self):
        for index in self.symrefs:
            symbol = self.symrefs[index]
            if symbol not in self.symbols:
                raise Exception("Undefined symbol", symbol)
            offset = self.symbols[symbol] - index
            op, regs, off, imm = struct.unpack('<BBhi', self.section[index])
            off += offset
            self.section[index] = struct.pack('<BBhi', op, regs, off, imm)
    @property
    def binary(self):
        return ''.join(self.section)
    @property
    def length(self):
        return len(self.binary)

    _register_re = re.compile(r'r(\d+)|(fp)$')
    _label_ref_re = re.compile(r'\w+$')
    def parse_direct_operand(self, operand):
        """Direct operand forms:
        
        r0      register
        123     decimal imm
        077     octal imm
        0xfe    hex imm
        """
        d = {}
        if self._size_re.search(operand):
            d['size'] = operand[-1]
            operand = operand[:-2]
        m = self._register_re.match(operand)
        if m:
            if m.group(2):
                d['reg'] = 10
            else:
                d['reg'] = int(m.group(1), 10)
            return d
        try:
            d.update(self.parse_immediate(operand))
            return d
        except:
            if self._label_ref_re.match(operand):
                d['imm'] = operand
                return d
            raise Exception("Bad direct operand", operand)

    def parse_offset_operand(self, operand):
        if '+' in operand:
            operand, _, disp = operand.partition('+')
            d = self.parse_direct_operand(operand)
            if 'size' in d: # can't have e.g. [reg.sz], only [reg].sz is legal
                raise Exception("Bad size in offset operand", operand)
            d['off'] = self.parse_immediate(disp)['imm']
            return d
        if '-' in operand:
            operand, _, disp = operand.partition('-')
            d = self.parse_direct_operand(operand)
            if 'size' in d: # can't have e.g. [reg.sz], only [reg].sz is legal
                raise Exception("Bad size in offset operand", operand)
            d['off'] = -self.parse_immediate(disp)['imm']
            return d
        return self.parse_direct_operand(operand)

    def parse_operand(self, operand):
        """Operand forms:
        
        direct_operand
        [direct_operand]
        [direct_operand+imm]
        """
        if operand.startswith('['):
            d = {}
            if self._size_re.search(operand):
                d['size'] = operand[-1]
                operand = operand[:-2]
            if not operand.endswith(']'):
                raise Exception("Bad indirect operand", operand)
            d.update(self.parse_offset_operand(operand[1:-1]))
            d['ind'] = True
            return d
        return self.parse_direct_operand(operand)

    def parse_ld(self, _, args):
        """ld dest, src"""
        if len(args) != 2:
            raise Exception("Bad ld, expected 2 args, got", args)
        dst, src = map(self.parse_operand, args)
        return {'op': 'ld', 'dst': dst, 'src': src}

    def parse_alu(self, op, args):
        """op dest, src"""
        if len(args) != 2:
            raise Exception("Bad %s, expected 2 args, got"%(op,), args)
        dst, src = map(self.parse_direct_operand, args)
        return {'op': op, 'dst': dst, 'src': src}

    def parse_neg(self, op, args):
        """neg reg.sz"""
        if len(args) != 1:
            raise Exception("Bad neg, expected 1 arg, got", args)
        reg = self.parse_direct_operand(args[0])
        return {'op': 'neg', 'dst': reg}

    def parse_end(self, op, args):
        """end dir, reg.sz"""
        if len(args) != 2:
            raise Exception("Bad end, expected 2 args, got", args)
        if args[0] not in ('le', 'be'):
            raise Exception("Bad end, expected le or be, got", args)
        reg = self.parse_direct_operand(args[1])
        return {'op': 'end', 'dir': args[0], 'dst': reg}

    def parse_offset(self, arg):
        if arg.startswith('+'):
            return self.parse_immediate(arg[1:])['imm']
        if arg.startswith('-'):
            return -self.parse_immediate(arg[1:])['imm']
        try:
            self.parse_immediate(arg)
        except:
            pass
        else:
            raise Exception("Bad jump offset (missing + sign?), got", arg)
        if self._label_ref_re.match(arg):
            return arg
        raise Exception("Bad jump offset, expected label or +/-imm, got", arg)

    def parse_ja(self, op, args):
        "jr  label_or_offset"
        off = self.parse_offset(args[0])
        return {'op': 'jr', 'off': off}

    # Each jump op has its 'canonical' BPF name, and some aliases
    jr_conds = {'eq': 'jeq', 'e': 'jeq', '=': 'jeq', 'z': 'jeq', # difference Zero
                'gt': 'jgt', '>': 'jgt',
                'ge': 'jge', '>=': 'jge',
                'set': 'jset', '&': 'jset', 'and': 'jset',
                'ne': 'jne', '!=': 'jne', 'nz': 'jne', # difference Not Zero
                'sgt': 'jsgt', 's>': 'jsgt',
                'sge': 'jsge', 's>=': 'jsge', 'p': 'jsge', # difference Positive
                'lt': 'jlt', '<': 'jlt',
                'le': 'jle', '<=': 'jle',
                'slt': 'jslt', 's<': 'jslt', 'n': 'jslt', # difference Negative
                'sle': 'jsle', 's<=': 'jsle',}

    def parse_jrcc(self, op, args):
        cc = args[0]
        if cc not in self.jr_conds:
            raise Exception("Bad jump op", cc)
        dst, src = map(self.parse_direct_operand, args[1:3])
        off = self.parse_offset(args[3])
        return {'op': 'jr', 'cc': self.jr_conds[cc], 'dst': dst, 'src': src,
                'off': off}

    def parse_jmp(self, op, args):
        """jr forms:
        
        jr  label_or_offset
        jr  cc, dst, src, label_or_offset
        """
        if len(args) == 1:
            return self.parse_ja(op, args)
        if len(args) == 4:
            return self.parse_jrcc(op, args)
        raise Exception("Bad jr, expected 1 or 4 args, got", args)

    def parse_call(self, op, args):
        """call function ; implicit args"""
        if len(args) != 1:
            raise Exception("Bad call, expected 1 arg, got", args)
        imm = self.parse_immediate(args[0])['imm']
        return {'op': 'call', 'function': imm}

    def parse_exit(self, op, args):
        if args:
            raise Exception("Bad exit, expected no args, got", args)
        return {'op': 'exit'}

    def parse_xadd(self, op, args):
        if len(args) != 2:
            raise Exception("Bad xadd, expected 2 args, got", args)
        dst = self.parse_operand(args[0])
        src = self.parse_direct_operand(args[1])
        return {'op': 'xadd', 'dst': dst, 'src': src}

    op_parsers = {'ld': parse_ld, 'add': parse_alu,
                  'sub': parse_alu, 'mul': parse_alu,
                  'div': parse_alu, 'or': parse_alu,
                  'and': parse_alu, 'lsh': parse_alu,
                  'rsh': parse_alu, 'neg': parse_neg,
                  'mod': parse_alu, 'xor': parse_alu,
                  'arsh': parse_alu, 'end': parse_end,
                  'jr': parse_jmp, 'call': parse_call,
                  'exit': parse_exit, 'xadd': parse_xadd,}

    def parse_line(self, line):
        m = self._label_re.match(line)
        if m:
            return {'label': m.group(1)}
        op, args = self.parse_op_args(line)
        if op not in self.op_parsers:
            raise Exception("Unrecognised instruction", line)
        args = map(str.strip, args.split(','))
        if args == ['']:
            args = []
        d = self.op_parsers[op](self, op, args)
        d['line'] = line # save source line for error messages
        return d

    def generate_ld(self, insn):
        """ld forms:
        
        ld  reg.q, imm  ; BPF_LD|BPF_IMM
        ld  reg.q, reg  ; BPF_MOV64, src=X
        ld  reg.l, imm  ; BPF_MOV, src=K
        ld  reg.l, reg  ; BPF_MOV, src=X
        ld  [reg+disp], src     ; BPF_ST[X]_MEM
        ld  reg.sz, [reg+disp]  ; BPF_LDX_MEM
        (note: LD IND/ABS are 'ldpkt' insn)
        """
        src = insn['src']
        dst = insn['dst']
        size = src.get('size', dst.get('size'))
        if 'size' in src and 'size' in dst:
            # Normally we don't specify both.  But if we do, they must match
            if size != dst['size']:
                raise Exception("Mismatched sizes", insn['line'])
        if dst.get('imm') is not None:
            raise Exception("ld imm,... illegal", insn['line'])
        if dst.get('ind'): # BPF_ST[X]_MEM
            assert dst.get('reg') is not None, dst
            if src.get('ind'):
                raise Exception("ld mem,mem illegal", insn['line'])
            if src.get('off') is not None:
                raise Exception("ld mem,reg+disp illegal", insn['line'])
            if src.get('reg') is not None: # BPF_STX_MEM (size, dst, src, off)
                return {'class': 'stx', 'mode': 'mem', 'size': size or 'q',
                        'dst': dst['reg'], 'src': src['reg'],
                        'off': dst.get('off', 0)}
            # BPF_ST_MEM (size, dst, off)
            return {'class': 'st', 'mode': 'mem', 'size': size or 'q',
                    'dst': dst['reg'], 'off': dst.get('off', 0), 'imm': src['imm']}
        if dst.get('off') is not None:
            raise Exception("ld reg+disp,... illegal (missing []?)", insn['line'])
        if src.get('ind'): # BPF_LDX_MEM
            assert dst.get('reg') is not None, dst
            if src.get('reg') is None:
                raise Exception("ld ...,[imm] illegal", insn['line'])
            # BPF_LDX_MEM (size, dst, src, off)
            return {'class': 'ldx', 'mode': 'mem', 'size': size or 'q',
                    'dst': dst['reg'], 'src': src['reg'], 'off': src.get('off', 0)}
        if src.get('off') is not None:
            raise Exception("ld ...,reg+disp illegal (missing []?)", insn['line'])
        assert dst.get('reg') is not None, dst
        if size is None:
            size = 'q'
        if size not in ['q', 'l']:
            raise Exception("Bad size", size, "for register load", insn['line'])
        if src.get('reg') is not None: # ld reg, reg
            if size == 'q': # BPF_MOV64
                return {'class': 'alu64', 'op': 'mov',
                        'src': src['reg'], 'dst': dst['reg']}
            # BPF_MOV
            return {'class': 'alu', 'op': 'mov',
                    'src': src['reg'], 'dst': dst['reg']}
        # ld reg, imm
        if size == 'q': # BPF_LD_IMM64
            return {'class': 'ld', 'mode': 'imm', 'size': 'q', 'dst': dst['reg'],
                    'imm': src['imm']}
        # BPF_MOV
        return {'class': 'alu', 'op': 'mov', 'dst': dst['reg'], 'imm': src['imm']}

    def generate_alu(self, insn):
        """alu forms:
        
        alu dst, src    ; BPF_ALU[64], BPF_X
        alu dst, imm    ; BPF_ALU[64], BPF_K
        """
        op = insn['op']
        src = insn['src']
        dst = insn['dst']
        size = src.get('size', dst.get('size'))
        if 'size' in src and 'size' in dst:
            # Normally we don't specify both.  But if we do, they must match
            if size != dst['size']:
                raise Exception("Mismatched sizes", insn['line'])
        if size in ['q', None]:
            klass = 'alu64'
        elif size == 'l':
            klass = 'alu'
        else:
            raise Exception("Bad size", size, "for ALU op", insn['line'])
        if dst.get('imm') is not None:
            raise Exception(op+" imm,... illegal", insn['line'])
        if src.get('reg') is not None: # BPF_X
            return {'class': klass, 'op': op, 'dst': dst['reg'], 'src': src['reg']}
        # BPF_K
        return {'class': klass, 'op': op, 'dst': dst['reg'], 'imm': src['imm']}

    def generate_neg(self, insn):
        dst = insn['dst']
        size = dst.get('size')
        if size in ['q', None]:
            klass = 'alu64'
        elif size == 'l':
            klass = 'alu'
        else:
            raise Exception("Bad size", size, "for ALU op", insn['line'])
        if dst.get('imm') is not None:
            raise Exception("neg imm illegal", insn['line'])
        return {'class': klass, 'op': 'neg', 'dst': dst['reg'], 'src': 0}

    def generate_end(self, insn):
        dst = insn['dst']
        size = dst.get('size', 'q')
        imm = {'q': 64, 'l': 32, 'w': 16}.get(size)
        if imm is None:
            raise Exception("Bad size", size, "for endian op", insn['line'])
        if dst.get('imm') is not None:
            raise Exception("end ..., imm illegal", insn['line'])
        dr = insn['dir']
        # All BPF_END (even 64-bit) use (32-bit) BPF_ALU class
        if dr == 'le': # BPF_TO_LE == BPF_K
            return {'class': 'alu', 'op': 'end', 'dst': dst['reg'],
                    'imm': imm}
        if dr == 'be': # BPF_TO_BE == BPF_X, so use 'fake' src reg
            return {'class': 'alu', 'op': 'end', 'dst': dst['reg'], 'src': 0,
                    'imm': imm}
        # can't happen, already checked in parse_end
        raise Exception("Bad direction", dr, "for endian op", insn['line'])

    def generate_jr(self, insn):
        off = insn['off']
        cc = insn.get('cc')
        if cc is not None:
            dst = insn['dst']
            src = insn['src']
            if dst.get('reg') is None:
                raise Exception("jr cc,imm,... illegal", insn['line'])
            dst = dst['reg']
            if src.get('reg') is None: # JMP_IMM
                return {'class': 'jmp', 'op': cc, 'dst': dst, 'imm': src['imm'],
                        'off': off}
            # JMP_REG
            src = src['reg']
            return {'class': 'jmp', 'op': cc, 'dst': dst, 'src': src, 'off': off}
        return {'class': 'jmp', 'op': 'ja', 'off': off}

    def generate_call(self, insn):
        func = insn['function']
        return {'class': 'jmp', 'op': 'call', 'imm': func}

    def generate_exit(self, insn):
        return {'class': 'jmp', 'op': 'exit'}

    def generate_xadd(self, insn):
        dst = insn['dst']
        src = insn['src']
        size = src.get('size', dst.get('size'))
        if 'size' in src and 'size' in dst:
            # Normally we don't specify both.  But if we do, they must match
            if size != dst['size']:
                raise Exception("Mismatched sizes", insn['line'])
        if not dst.get('ind'):
            raise Exception("xadd direct_operand,... illegal", insn['line'])
        if dst.get('reg') is None:
            raise Exception("xadd [imm],... illegal", insn['line'])
        if src.get('reg') is None:
            raise Exception("xadd ...,imm illegal", insn['line'])
        if size is None:
            size = 'q'
        return {'class': 'stx', 'mode': 'xadd', 'size': size,
                'dst': dst['reg'], 'src': src['reg'], 'off': dst.get('off', 0)}

    op_generators = {'ld': generate_ld, 'add': generate_alu,
                     'sub': generate_alu, 'mul': generate_alu,
                     'div': generate_alu, 'or': generate_alu,
                     'and': generate_alu, 'lsh': generate_alu,
                     'rsh': generate_alu, 'neg': generate_neg,
                     'mod': generate_alu, 'xor': generate_alu,
                     'arsh': generate_alu, 'end': generate_end,
                     'jr': generate_jr, 'call': generate_call,
                     'exit': generate_exit, 'xadd': generate_xadd,}

    def generate_insn(self, insn):
        if insn['op'] not in self.op_generators:
            raise Exception("Unhandled op", insn)
        d = self.op_generators[insn['op']](self, insn)
        d['line'] = insn['line'] # saved source line for error messages
        return d

    # Output format: op:8, dst_reg:4, src_reg:4, off:16, imm:32
    classes = {'ld': 0, 'ldx': 1, 'st': 2, 'stx': 3, 'alu': 4, 'jmp': 5, 'alu64': 7}
    ld_modes = {'imm': 0x00, 'abs': 0x20, 'ind': 0x40, 'mem': 0x60, 'xadd': 0xc0}
    alu_ops = {'add': 0x00, 'sub': 0x10, 'mul': 0x20, 'div': 0x30, 'or': 0x40,
               'and': 0x50, 'lsh': 0x60, 'rsh': 0x70, 'neg': 0x80, 'mod': 0x90,
               'xor': 0xa0, 'mov': 0xb0, 'arsh': 0xc0, 'end': 0xd0}
    jmp_ops = {'ja': 0x00, 'jeq': 0x10, 'jgt': 0x20, 'jge': 0x30, 'jset': 0x40,
               'jne': 0x50, 'jsgt': 0x60, 'jsge': 0x70, 'call': 0x80, 'exit': 0x90,
               'jlt': 0xa0, 'jle': 0xb0, 'jslt': 0xc0, 'jsle': 0xd0}
    sizes = {'l': 0x00, 'w': 0x08, 'b': 0x10, 'q': 0x18}
    BPF_K = 0
    BPF_X = 8

    def check_s16(self, imm):
        if imm > 0x7fff or imm < -0x8000:
            raise Exception("Value out of range for s16", imm)
        return imm

    def check_s32(self, imm):
        if imm > 0x7fffffff or imm < -0x80000000:
            raise Exception("Value out of range for s32", imm)
        return imm

    def assemble_ld(self, insn):
        # LD_IMM64: class, dst, src, imm + second insn
        # LD_ABS: class, mode, size, off32
        # LD_IND: class, mode, size, src, off32
        op = self.classes[insn['class']] | self.ld_modes[insn['mode']] | self.sizes[insn['size']]
        if insn['mode'] == 'imm':
            regs = insn['dst']
            return [(op, regs, 0, insn['imm']), (0, 0, 0, 0)]
        regs = insn['src'] << 4
        return (op, regs, 0, self.check_s32(insn['off']))

    def assemble_ldx(self, insn):
        # class, mode, size, dst, src, off
        op = self.classes[insn['class']] | self.ld_modes[insn['mode']] | self.sizes[insn['size']]
        regs = (insn['src'] << 4) | insn['dst']
        return (op, regs, self.check_s16(insn['off']), 0)

    def assemble_st(self, insn):
        # class, mode, size, dst, off, imm
        op = self.classes[insn['class']] | self.ld_modes[insn['mode']] | self.sizes[insn['size']]
        regs = insn['dst']
        return (op, regs, self.check_s16(insn['off']), self.check_s32(insn['imm']))

    def assemble_stx(self, insn):
        # class, mode, size, dst, src, off
        op = self.classes[insn['class']] | self.ld_modes[insn['mode']] | self.sizes[insn['size']]
        regs = (insn['src'] << 4) | insn['dst']
        return (op, regs, self.check_s16(insn['off']), 0)

    def assemble_alu(self, insn):
        # class, op, dst, {x, src | k, imm}
        if 'src' in insn: # ALU[64]_REG
            op = self.classes[insn['class']] | self.BPF_X | self.alu_ops[insn['op']]
            regs = (insn['src'] << 4) | insn['dst']
            # Could still have an 'imm' in case of BPF_END | BPF_TO_BE
            return (op, regs, 0, self.check_s32(insn.get('imm', 0)))
        # ALU[64]_IMM
        op = self.classes[insn['class']] | self.BPF_K | self.alu_ops[insn['op']]
        regs = insn['dst']
        return (op, regs, 0, self.check_s32(insn['imm']))

    def assemble_jmp(self, insn):
        # class, op, dest, {x, src | k, imm}, off
        off = insn.get('off', 0)
        if isinstance(off, (int, long)):
            self.check_s16(off)
        if 'src' in insn: # JMP_REG
            op = self.classes[insn['class']] | self.BPF_X | self.jmp_ops[insn['op']]
            regs = (insn['src'] << 4) | insn['dst']
            return (op, regs, off, 0)
        if 'dst' in insn: # JMP_IMM
            op = self.classes[insn['class']] | self.BPF_K | self.jmp_ops[insn['op']]
            regs = insn.get('dst', 0)
            return (op, regs, off, self.check_s32(insn['imm']))
        if insn['op'] == 'call':
            op = self.classes[insn['class']] | self.jmp_ops[insn['op']]
            return (op, 0, 0, insn['imm'])
        # ja, exit
        op = self.classes[insn['class']] | self.jmp_ops[insn['op']]
        return (op, 0, off, 0)

    class_assemblers = {'ld': assemble_ld, 'ldx': assemble_ldx, 'st': assemble_st,
                        'stx': assemble_stx, 'alu': assemble_alu,
                        'jmp': assemble_jmp, 'alu64': assemble_alu}

    def pack_binary(self, fields, endian):
        symbol_off = None
        symbol_imm = None
        if isinstance(fields[2], str):
            # symbol
            symbol_off = fields[2]
            fields = fields[:2] + (-1,) + fields[3:]
        if isinstance(fields[3], str):
            # relocation entry
            symbol_imm = fields[3]
            fields = fields[:3] + (0,)
        return (struct.pack(endian+'BBhi', *fields), symbol_off, symbol_imm)

    def assemble_insn(self, insn, endian='<'):
        if insn['class'] not in self.class_assemblers:
            raise Exception("Unhandled class", insn)
        fields = self.class_assemblers[insn['class']](self, insn)
        if isinstance(fields, list): # BPF_LD_IMM64 is two insns
            return [self.pack_binary(f, endian) for f in fields]
        return self.pack_binary(fields, endian)

class MapsAssembler(BaseAssembler):
    """Input language for .section maps:

    name: type, ks, vs, maxent
    name: type, ks, vs, maxent, flags

    flags are P (NO_PREALLOC), L (NO_COMMON_LRU)
    """
    map_flags = 'PL'
    elf_flags = 'WA'
    def __init__(self, equates):
        super(MapsAssembler, self).__init__(equates)
        self.maps = {}
    def parse_map(self, args):
        if len(args) == 4:
            args = args + ('',)
        if len(args) != 5:
            raise Exception("Bad map defn, expected 4 or 5 args, got", args)
        typ, ks, vs, maxent, flags = args
        typ = self.parse_immediate(typ)['imm']
        ks = self.parse_immediate(ks)['imm']
        vs = self.parse_immediate(vs)['imm']
        maxent = self.parse_immediate(maxent)['imm']
        flagv = 0
        for c in flags:
            if c not in self.map_flags:
                raise Exception("Bad map flag", c)
            flagv |= 1 << self.map_flags.index(c)
        return {'type': typ, 'key_size': ks, 'value_size': vs,
                'max_entries': maxent, 'flags': flagv}
    def assemble_map(self, d):
        # /* per iproute2:include/bpf_elf.h */
        # struct bpf_elf_map {
        #   __u32 type;
        #   __u32 size_key;
        #   __u32 size_value;
        #   __u32 max_elem;
        #   __u32 flags;
        #   __u32 id; /* We don't use this */
        #   __u32 pinning; /* PIN_GLOBAL_NS == 2 */
        #   __u32 inner_id; /* We don't use this */
        #   __u32 inner_idx; /* We don't use this */
        # };
        return struct.pack('=7i', d['type'], d['key_size'], d['value_size'],
                           d['max_entries'], d['flags'], 0, 2)
    def feed_line(self, line):
        name, _, args = line.strip().partition(': ')
        args = map(str.strip, args.split(','))
        if name in self.maps:
            raise Exception("Duplicate map", name)
        d = self.parse_map(args)
        self.maps[name] = self.assemble_map(d)
    def resolve_symbols(self):
        self.section = []
        self.symbols = {}
        for k, v in self.maps.iteritems():
            self.symbols[k] = len(self.section)
            self.section.append(v)
    @property
    def binary(self):
        return ''.join(self.section)
    @property
    def length(self):
        return len(self.binary)
    @property
    def relocs(self):
        return {}

class DataAssembler(BaseAssembler):
    elf_flags = 'WA'
    def __init__(self, equates):
        super(DataAssembler, self).__init__(equates)
        self.section = ''
        self.symbols = {}
    def feed_line(self, line):
        m = self._label_re.match(line)
        if m:
            self.symbols[m.group(1)] = len(self.section)
            return
        op, args = self.parse_op_args(line.strip())
        if hasattr(self, 'do_' + op):
            getattr(self, 'do_' + op)(args)
        else:
            raise Exception("No such .data insn", op)
    def do_asciz(self, args):
        string = ast.literal_eval(args.strip())
        if not isinstance(string, str):
            raise Exception("asciz takes a string, not", args)
        self.section += string + '\0'
    def resolve_symbols(self):
        pass # nothing to do
    @property
    def relocs(self):
        return {}
    @property
    def binary(self):
        return self.section

class Assembler(BaseAssembler):
    def __init__(self):
        super(Assembler, self).__init__({})
        self.sections = {}
        self.section = None
        self.sectype = None
    def directive(self, d, args):
        if hasattr(self, 'do_' + d):
            getattr(self, 'do_' + d)(args)
        else:
            raise Exception("No such directive", '.' + d)
    def do_text(self, args):
        self.sectype = ProgAssembler
        self.section = None
    def do_data(self, args):
        self.sectype = DataAssembler
        self.section = None
    def do_section(self, args):
        if len(args) != 1:
            raise Exception("Bad .section, expected 1 arg, got", args)
        name = args[0]
        if name == 'maps':
            asm = MapsAssembler(self.equates)
        elif self.sectype is None:
            raise Exception("Must specify .text or .data before .section")
        else:
            asm = self.sectype(self.equates)
        if name in self.sections:
            if not isinstance(self.sections[name], asm.__class__):
                raise Exception("Section", name, "redefined as different type",
                                asm.__class__.__name__, "previously",
                                self.sections[name].__class__.__name__)
            # throw away our new asm, use the existing one
        else:
            self.sections[name] = asm
        self.section = name
    def do_include(self, args):
        if len(args) != 1:
            raise Exception("Bad .include, expected 1 arg, got", args)
        with open(args[0], "r") as srcf:
            for line in srcf:
                self.feed_line(line)
    def do_equ(self, args):
        if len(args) != 2:
            raise Exception("Bad .equ, expected 2 args, got", args)
        name, val = args
        val = self.parse_immediate(val)['imm']
        self.equates[name] = val
    def feed_line(self, line):
        line = line.strip()
        if ';' in line: # comment to EOL
            line, _, _ = line.partition(';')
        if line.startswith('.'):
            d, args = op, args = self.parse_op_args(line[1:])
            args = map(str.strip, args.split(','))
            if args == ['']:
                args = []
            self.directive(d, args)
            return
        if not line: # blank line (or just a comment)
            return
        if self.section is None:
            raise Exception("Not in a section at", line)
        self.sections[self.section].feed_line(line)
    def resolve_symbols(self):
        for sec in self.sections.values():
            sec.resolve_symbols()

class ElfSection(object):
    types = {'null': 0, 'progbits': 1, 'symtab': 2, 'strtab': 3, 'rel': 9}
    entsizes = {'symtab': 0x18, 'rel': 0x10}
    flag_bits = 'WAX'
    def __init__(self, typ, name, flags='', relfor=0):
        self.typ = typ
        if typ not in self.types:
            raise Exception("Unhandled ElfSection type", typ)
        self.typ_i = self.types[typ]
        self.entsize = self.entsizes.get(typ, 0)
        self.name = name
        self.text = ''
        flagv = 0
        for flag in flags:
            if flag not in self.flag_bits:
                raise Exception("Unhandled ElfSection flag", flag)
            flagv |= 1 << self.flag_bits.index(flag)
        self.flags = flagv
        self.relfor = relfor
    @property
    def len(self):
        return len(self.text)

class ElfGenerator(object):
    def __init__(self, asm):
        self.asm = asm
        self.sections = [ElfSection('null', ''),
                         ElfSection('strtab', '.strtab'),
                         ElfSection('progbits', '.text'),
                         ]
        for section, sec in self.asm.sections.iteritems():
            idx = len(self.sections)
            self.sections.append(ElfSection('progbits', section, sec.elf_flags))
            if sec.relocs:
                self.sections.append(ElfSection('rel', '.rel'+section,
                                                relfor=idx))
        self.sections.append(ElfSection('symtab', '.symtab', sec.elf_flags))
        for i, sec in enumerate(self.sections):
            sec.idx = i
        self.gen_strtab()
        self.gen_symtab()
        self.get_section('.strtab').text = self.strtab
        self.get_section('.symtab').text = self.symtab
        for section, sec in self.asm.sections.iteritems():
            s = self.get_section(section)
            s.text = sec.binary
            if sec.relocs:
                r = self.get_section('.rel'+section)
                r.text = self.gen_relocs(sec.relocs)
        self.gen_offsets()
        self.gen_shtbl()
        self.ehdr = self.elf_header()
        assert len(self.ehdr) == 64, (len(self.ehdr), repr(self.ehdr))
    @property
    def binary(self):
        sectext = ''
        for sec in self.sections:
            sectext += sec.text
            if sec.len % 8:
                sectext += '\0' * (8 - (sec.len % 8))
        return self.ehdr + sectext + self.shtbl
    def get_section(self, name):
        for sec in self.sections:
            if sec.name == name:
                return sec
        return None
    def add_string(self, string):
        self.strings[string] = len(self.strtab)
        self.strtab += string + '\0'
    def gen_strtab(self):
        self.strtab = ''
        self.strings = {}
        for sec in self.sections:
            self.add_string(sec.name)
        for sec in self.asm.sections.values():
            for sym in sec.symbols:
                self.add_string(sym)
    def add_symbol(self, name, globl, secidx, value):
        # struct elf_symbol {
        #   u32 st_name; // index into strtab
        #   u8  st_info; // 0 (LOCAL|NOTYPE) or 16 (GLOBAL|NOTYPE)
        #   u8  st_other; // 0
        #   u16 st_shndx; // section idx
        #   u64 st_value;
        #   u64 st_size; // 0
        #};
        self.symbols[name] = len(self.symbols)
        stridx = self.strings[name]
        self.symtab += struct.pack('<IBBHQQ', stridx, 16 if globl else 0, 0,
                                   secidx, value, 0)
    def gen_symtab(self):
        self.symtab = ''
        self.symbols = {}
        # LOCAL symbols (from .text sections)
        self.add_symbol('', False, 0, 0)
        for section, sec in self.asm.sections.iteritems():
            s = self.get_section(section)
            if s is None:
                raise Exception("Couldn't find ELF section", section)
            if not isinstance(sec, ProgAssembler):
                continue
            for sym in sec.symbols:
                self.add_symbol(sym, False, s.idx, sec.symbols[sym])
        self.locals = len(self.symbols)
        # GLOBAL symbols (from .data or maps sections)
        for section, sec in self.asm.sections.iteritems():
            s = self.get_section(section)
            if s is None:
                raise Exception("Couldn't find ELF section", section)
            if isinstance(sec, ProgAssembler):
                continue
            for sym in sec.symbols:
                self.add_symbol(sym, True, s.idx, sec.symbols[sym])
    def gen_relocs(self, relocs):
        def gen_reloc(k, v):
            return struct.pack('<QII', k * 8, 1, self.symbols[v])
        return ''.join(gen_reloc(k, v) for k,v in relocs.iteritems())
    def gen_offsets(self):
        self.shoff = 0x40 # sizeof(struct elf_header)
        for sec in self.sections:
            sec.off = self.shoff
            self.shoff += sec.len
            if self.shoff % 8:
                self.shoff = (self.shoff + 7) & ~7
    def gen_shtbl(self):
        self.shtbl = ''
        # struct elf_shdr {
        #   u32 sh_name;
        #   u32 sh_type;
        #   u64 sh_flags;
        #   u64 sh_addr;
        #   u64 sh_offset;
        #   u64 sh_size;
        #   u32 sh_link;
        #   u32 sh_info;
        #   u64 sh_addralign;
        #   u64 sh_entsize;
        # };
        for sec in self.sections:
            link = 0
            info = 0
            if sec.typ == 'rel':
                link = self.get_section('.symtab').idx
                info = sec.relfor
            if sec.typ == 'symtab':
                link = self.get_section('.strtab').idx
                info = self.locals
            self.shtbl += struct.pack('<II4QIIQQ', self.strings[sec.name],
                                      sec.typ_i, sec.flags, 0, sec.off, sec.len,
                                      link, info, 8, sec.entsize)

    def elf_header(self):
        # struct elf_header {
        #   u8  ident[4]; // "\x7fELF"
        #   u8  class; // 2: 64-bit
        #   u8  endianness; // 1: little-endian
        #   u8  ei_version; // 1
        #   u8  os_abi; // 0
        #   u8  abi_ver; // 0
        #   u8  padding[7];
        #   u16 type; // 1: relocatable
        #   u16 machine; // 0x7f: eBPF
        #   u32 version; // 1
        #   u64 entry;
        #   u64 phoff;
        #   u64 shoff;
        #   u32 flags;
        #   u16 hdr_size;
        #   u16 phentsize;
        #   u16 phnum;
        #   u16 shentsize;
        #   u16 shnum;
        #   u16 shstrndx; // 1: first section is STRTAB
        # };

        shnum = len(self.sections)
        return struct.pack('<9B7xHHIQQQI6H',
                           0x7f, ord('E'), ord('L'), ord('F'),
                           2, 1, 1, 0, 0,
                           1, 0xf7, 1, 0, 0,
                           self.shoff, 0, 64, 0, 0, 64, shnum,
                           self.get_section('.strtab').idx)

def parse_args():
    x = optparse.OptionParser(usage='%s srcfile [...] -o outfile',
                              version='%prog ' + VERSION if VERSION else None)
    x.add_option('-o', '--output', type='string', default='a.out')
    opts, args = x.parse_args()
    if not args:
        x.error('Missing srcfile(s).')
    return opts, args

if __name__ == '__main__':
    opts, args = parse_args()
    asm = Assembler()
    for src in args:
        with open(src, 'r') as srcf:
            for line in srcf:
                asm.feed_line(line)
    asm.resolve_symbols()
    elf = ElfGenerator(asm)
    with open(opts.output, 'wb') as f:
        f.write(elf.binary)
