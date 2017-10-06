# ebpf_asm

An assembler for eBPF programs written in an Intel-like assembly syntax.

## Synopsis

`ebpf_asm.py <sourcefile> [...] -o <outputfile>`

## Rationale

It's great that you can write eBPF programs in C and then compile them with
clang/LLVM.  But clang's really rather big, and sometimes you don't have room
for a gigantic toolchain — and your program is really small and simple.  For
such a case, writing the program directly in assembly is a feasible alternative.

I chose the Intel syntax because my ability to read assembly code is directly
proportional to how much it resembles Z80.  If you dislike that as much as I
dislike AT&T-syntax x86 assembly, this may not be the tool for you.

## License

`ebpf_asm` itself and the supplied header files (`defs.i` and `net_hdrs.i`) are
provided under the MIT license (see comment block at the top of `ebpf_asm.py`).
The included example programs (`test.s` and `dropper.s`) are dual MIT/GPL.

## Syntax

Comments are introduced with a semicolon `;` and continue to end of line.

### Directives

#### .text

Following sections will consist of program text (i.e. executable instructions).

#### .data

Following sections will consist of program data (currently just asciz strings).

#### .section

`.section maps` starts (or continues) the maps section, containing map
definitions.

Otherwise, `.section name` starts (or continues) a section with the given name.
This section will contain either text or data (depending on the last `.text` or
`.data` directive) and will run until the next `.section`, `.text` or `.data`
directive.

#### .include

`.include name` includes the specified file (relative to the cwd) textually.

#### .equ

`.equ name, immediate` defines the given name to equal the immediate (which
could be a literal, or the name of another equate).  Any size suffix on the
immediate will be ignored.

### Labels

A label consists of a sequence of alphanumeric characters followed by a colon
 `:`, which is omitted when referring to the label.  The label points at the
 following instruction (in .text) or datum (in .data).

### Instructions

Text sections consist of instructions generally in the form `op dst, src`,
though a few instructions take more (or fewer) operands.

Operands typically may be either register names (`r0` to `r10`, or `fp` as a
synonym for `r10`) or literals (decimal, 0octal, 0xhex, or an equate name); some
instructions can also take memory references `[reg+disp]`.

Operands can also include a _size suffix_, a dot `.` followed by a letter:

* `.b`  byte
* `.w`  word (16 bits)
* `.l`  long (32 bits)
* `.q`  quad (64 bits)

#### ld

The load instruction `ld dst, src` is used for register-to-register, register-
to-memory and memory-to-register moves.

If both operands have size suffixes, they must match; if neither has, then quad
(`.q`) is assumed.

##### Register-to-register

`ld dst_reg, src_reg`

`ld dst_reg, src_imm`

Size must be quad (`.q`) or long (`.l`).

##### Register-to-memory

`ld [ptr_reg+disp], src_reg`

`ld [ptr_reg+disp], src_imm`

The displacement `disp` may be omitted (as `ld [ptr_reg], src`) or negative (as
`ld [ptr_reg-disp], src`).  It is a signed 16-bit quantity (i.e. word, `.w`).

A size suffix goes outside the brackets (as `ld [ptr_reg].sz, src`), not inside
(since the pointer must always be full-sized).

`src_imm` is a signed 32-bit quantity (i.e. long, `.l`).

##### Memory-to-register

`ld dst_reg, [ptr_reg+disp]`

The same notes apply to the `[ptr_reg+disp]` as for Register-to-memory, above.

#### ldpkt

The packet-load instruction `ldpkt r0, src` is used for reading packet data into
registers, in a complicated way for historical reasons.  It represents the
BPF\_ABS and BPF\_IND modes of the BPF\_LD opcode, which can only be used in
socket filter, sched\_cls and sched\_act programs.

`ldpkt r0, [disp]`

`ldpkt r0, [off_reg+disp]`

If both operands have size suffixes, they must match; if neither has, then,
**unlike most other instructions**, long (`.l`) is assumed.  This is because
these instructions, being holdovers from classic BPF, _do not have_ quad-sized
forms (which would be rejected by the verifier).

There are other restrictions on its use: the destination register must be `r0`,
`r6` must contain a pointer to the sk\_buff, and registers `r1`-`r5` are
clobbered.  The value read will be converted to host-endianness.

Unless you know you want this, you probably want an ordinary
[memory-to-register load](#memory-to-register) using a packet-pointer, instead.

See the kernel's [BPF documentation][1] for further enlightenment.

[1]: https://www.kernel.org/doc/Documentation/networking/filter.txt

#### xadd

`xadd [ptr_reg+disp], src_reg`

Atomic memory add (BPF\_STX | BPF\_XADD).  The same notes apply to the
`[ptr_reg+disp]` as for `ld` instructions, above.

#### jr

The relative jump instruction, `jr offset` or `jr cc, dst, src, offset`, is used
to jump elsewhere in the program.  `offset` may be either a signed literal (the
`+` must be included for positive values) or a label name.

##### Unconditional jump

`jr offset`

##### Conditional jump

`jr cc, dst, src, offset`

Jump if condition `cc` holds on `dst` (a register) and `src` (a register or
immediate).  There are multiple synonyms for each condition.

* `eq`, `e`, `=`, `z`: Jump if `dst` is equal to `src`.
* `ne`, `!=`, `nz`: Jump if `dst` is not equal to `src`.
* `gt`, `>`: Jump if `dst` is strictly greater than `src`.
* `ge`, `>=`: Jump if `dst` is greater than or equal to `src`.
* `lt`, `<`: Jump if `dst` is strictly less than `src`.
* `le`, `<=`: Jump if `dst`is less than or equal to `src`.
* `sgt`, `s>`: Signed greater-than.
* `sge`, `s>=`, `p`: Signed greater-than-or-equal.
* `slt`, `s<`, `n`: Signed less-than.
* `sle`, `s<=`: Signed less-than-or-equal.
* `set`, `&`, `and`: Jump if the bitwise AND of `dst` and `src` is nonzero.

Both `dst` and `src` registers are considered as quads (`.q`); a `src` immediate
is considered a long (`.l`).

#### call

`call helper_function_id`

In eBPF, calls are to helper functions identified by an integer (see defs.i),
taking arguments `r1` to `r5` and returning in `r0`.  Consult the kernel's eBPF
documentation for details.

#### exit

`exit`

Exit the program, returning the current value of `r0`.

#### add, sub, mul, div, mod, and, or, xor, lsh, rsh, arsh

`alu_op dst_reg, src_reg`

`alu_op dst_reg, src_imm`

Size must be either quad (`.q`) or long (`.l`).  If both operands have size
suffixes, they must match; if neither has, then quad (`.q`) is assumed.
`src_imm` is a signed 32-bit quantity, even when size is quad (`.q`).

#### neg

`neg dst_reg`

Negate the specified register.  Size must be either quad (`.q`) or long (`.l`);
if omitted, quad (`.q`) is assumed.

#### end

`end le, dst_reg.sz`

`end be, dst_reg.sz`

Converts the specified register between Little or Big Endian and CPU endianness.
Size must be one of quad (`.q`), long (`.l`) or word (`.w`); if omitted, quad
(`.q`) is assumed.
The same operation is used for conversions both from and to CPU endianness.

### Map definitions

May only appear in `.section maps`.

`name: type, key_size, value_size, max_entries`

`name: type, key_size, value_size, max_entries, flags`

Defines a map with the given `name`, which can subsequently be used as a quad
immediate.  `type` is an integer ID (see defs.i).  `key_size` and `value_size`
are the sizes, in bytes, of the map key and map value.  `max_entries` is the
maximum number of entries this map can hold.

`flags` is one or more of the following letters:

* `P`: `BPF_F_NO_PREALLOC`
* `L`: `BPF_F_NO_COMMON_LRU`

Consult the kernel documentation for details of these flags and of the various
map types.

### Data definitions

As it is not possible to reference .data sections from eBPF code, they have
rather limited uses; hence the assembler has rather limited support for them.

#### asciz

`asciz "String text"`

NUL-terminated ASCII string.  Typically this is only used for the following
snippet:
```
.data
.section license
_license:
    asciz   "GPL"
```

## Output format

The assembler generates ELF object files, suitable for passing to standard tools
like iproute2's `ip link set dev ethX xdp obj object-file.o verb`.

## Testing

`ebpf_asm` has a suite of regression tests: run `./regression.py`.  If all is
well, there should be no output.
