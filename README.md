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
The included example programs (`test.s`, `dropper.s` and `call.s`) are dual
MIT/GPL.

## Syntax

Comments are introduced with a semicolon `;` and continue to end of line.

A backslash (`\`) at end of line indicates line continuation.  This remains the
case even within comments, for example:
`; This is all \`
`  one comment`

### Directives

#### .text

Following sections will consist of program text (i.e. executable instructions).

#### .data

Following sections will consist of program data (currently just asciz strings).

#### .section

`.section maps` starts (or continues) the maps section, containing
[map definitions](#map-definitions).

`.section .BTF` starts (or continues) the BTF section, containing
[type definitions](#type-definitions).

Otherwise, `.section name` starts (or continues) a section with the given name.
This section will contain either text or [data](#data-definitions) (depending on
the last `.text` or `.data` directive) and will run until the next `.section`,
`.text` or `.data` directive.

#### .include

`.include name` includes the specified file (relative to the cwd) textually.

#### .equ

`.equ name, immediate` defines the given name to equal the `immediate` (which
could be a literal, or the name of another equate).  The `immediate` does not
accept a size suffix.

`name` is any string which does not start with a digit and does not contain a
comma (`,`).  It _may_ contain internal whitespace.

Register names are legal as equate names, but where an operand could be either
it will be treated as a register name.  However, operands which are required to
be immediates, not registers, will treat it as an equate.  This is potentially
very confusing, so don't do this!

An equate can be defined with a `name` that ends in a size suffix, but accessing
the equate in a context where a size suffix would be allowed will require using
**two** size suffixes.  This is also confusing, so don't do this either!

An equate can be redefined; the new value takes effect from the following line.
This could also be confusing, so maybe you shouldn't do it.

#### .globl

`.globl name` specifies that the label `name:` should create a global, rather
 than local, symbol; it is only needed for labels in text, not data, sections.

The scope of the directive is the containing section; a .globl in one section
 does not affect similar labels in other sections.

A warning will be written to stderr for any `.globl` whose referenced label does
 not exist, or for any `.globl` appearing in a non-text section.

### Labels

A label consists of a sequence of alphanumeric characters followed by a colon
 `:`, which is omitted when referring to the label.  The label points at the
 following instruction (in .text) or datum (in .data).  A label may not begin
 with a digit, since that could cause confusion if references to the label look
 like numeric literals.  (Strictly speaking we could allow this, because jumps
 always prefix their literals with `+` or `-`, but we forbid it so that when you
 forget the `+` you get a meaningful error.)

Note that code cannot appear on the same line as the label!  This is something
 we probably ought to support, but currently don't.

Labels appear as symbols in the output binary; by default labels in .text are
 local whereas those in .data or maps sections are global.  Global labels in
 .text sections can be created with the [.globl directive](#.globl).

### Instructions

Text sections consist of instructions generally in the form `op dst, src`,
though a few instructions take more (or fewer) operands.

Operands typically may be either register names (`r0` to `r10`, or `fp` as a
synonym for `r10`) or literals (decimal, 0octal, 0xhex, or an equate name).
Literals normally must fit in a 32-bit signed integer, except for
[`ld reg.q, imm`](#register-to-register).  Some instructions can also take
memory references `[reg+disp]` for some operands.

Operands in many cases can also include a _size suffix_, a dot `.` followed by a
letter:

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

Size must be quad (`.q`) or long (`.l`).  For size quad, `src_imm` may be a map
name (defined in the maps section); otherwise, it is an _unsigned_ 64-bit
integer.

##### Register-to-memory

`ld [ptr_reg+disp], src_reg`

`ld [ptr_reg+disp], src_imm`

The displacement `disp` may be omitted (as `ld [ptr_reg], src`) or negative (as
`ld [ptr_reg-disp], src`).  It is a signed 16-bit quantity (i.e. word) and does
not accept a size suffix.

A size suffix goes outside the brackets (as `ld [ptr_reg].sz, src`), not inside
(since the pointer must always be full-sized).

Regardless of size suffix, `src_imm` must fit in a signed 32-bit integer.

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
forms (which would be rejected by the verifier).  The displacement `disp` may be
omitted from the latter form, and in either case does not accept a size suffix.

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
`+` must be included for positive values) or a label name; it does not accept a
size suffix.

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
is considered a long (`.l`).  Explicit size suffixes are not accepted.

#### call

##### Helper function

`call helper_function_id`

In eBPF, the original call instruction calls a helper function identified by an
integer (see defs.i), taking arguments `r1` to `r5` and returning in `r0`; these
registers are clobbered, while the remaining registers (`r6` to `r9` and `fp`)
are preserved across the call.  Consult the kernel's eBPF documentation for
details.  The `helper_function_id` does not accept a size suffix.

##### BPF-to-BPF

`call offset`

Since Linux 4.16, eBPF programs can make calls to other functions within the
same program.  Currently these must be statically linked; the kernel is unable
to resolve the relocation entries at program load time.  Thus the `offset` to
such a `call` instruction is similar to that on a `jr`.  However, since negative
numbers are accepted as `helper_function_id`s, a call with a negative literal
offset has to be written like `call +-1` to mark it as an `offset`.
Thus, the possible forms of BPF-to-BPF call are as follows:

`call label`

`call +1`

`call +-1`

`call +equate`

`call +-equate`

In most circumstances, however, only the first (`label`) form is likely to be
useful.  A simple example of usage can be found in the `call.s` sample program.

#### exit

`exit`

Exit the program, returning the current value of `r0`.

#### add, sub, mul, div, mod, and, or, xor, lsh, rsh, arsh

`alu_op dst_reg, src_reg`

`alu_op dst_reg, src_imm`

Size must be either quad (`.q`) or long (`.l`).  If both operands have size
suffixes, they must match; if neither has, then quad (`.q`) is assumed.
`src_imm` is a signed 32-bit quantity, even when size is quad (`.q`).

Note the slight oddity that even for `lsh`, `rsh`, `arsh` instructions (where
the size of the source operand should be irrelevant), the size suffix rules
still apply - e.g. `lsh r1, 2.l` is a 32-bit shift.

#### neg

`neg dst_reg`

Negate the specified register.  Size must be either quad (`.q`) or long (`.l`);
if omitted, quad (`.q`) is assumed.

#### end

`end le, dst_reg.sz`

`end be, dst_reg.sz`

Converts the specified register between Little or Big Endian and CPU endianness.
Size `.sz` must be one of quad (`.q`), long (`.l`) or word (`.w`); if omitted,
quad (`.q`) is assumed.
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

Normally, maps will be auto-pinned when the program is loaded.  But unlike
`iproute2`, `bpftool` doesn't support auto-pinning and will reject object files
which request this in the map metadata.  So, the ebpf_asm command-line option
`--no-pin-maps` can be used to suppress this.

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

### Type definitions

May only appear in `.section .BTF`.

`name: definition`

Defines a type with the given `name`.  As well as being associated with the
type's entry in the BTF section of the binary, the name can also be used in
subsequent definitions.  Note, however, that a definition must precede all uses
of the name; use [forward declarations](#forward-declarations) to get around
this when defining e.g. self- or mutually-referential types.

The type `void` is pre-defined (as `BTF_KIND_UNKN`).

A `definition` consists of a `kind` followed by arguments (whose number and
semantics depend on the `kind`).  A group of arguments enclosed by parentheses
acts as a single argument, allowing the recursive construction of complex types.

A type is _sizeable_ if its size in bytes can be calculated.  Some derived types
require their underlying types to be _sizeable_; see below for details.

#### Integers

`int encoding nbits`

`int (encoding encoding ...) nbits`

Defines an integer type.

`encoding` is one of the following flags: `signed`, `unsigned`, `char`, `bool`.
Since `unsigned` is the default, the following definitions are equivalent:

`int unsigned 32`

`int () 32`

As of Linux 4.19, the kernel does not accept any combination of flags (there is
no flag bit associated with `unsigned`), but the field in the BTF structures is
clearly intended as a bitmask.

`nbits` is the number of bits in the integer.  At present the assembler only
properly supports power-of-two sizes, as it doesn't support struct bitfields.

An integer type is _sizeable_.

#### Pointers

`* type`

Defines a type of pointer to `type`, which is either a `definition` or the
`name` of another type defined previously.  `type` does not need to be enclosed
in parentheses, even if it consists of multiple tokens.

A pointer type is _sizeable_ even if `type` is not.

#### Arrays

`array type nelems`

Defines a type of array of `type` with `nelems` elements.  `type` is either a
`definition` or the `name` of another type defined previously; if it consists of
multiple tokens, it must be parenthesised.  `nelems` is an immediate literal,
and may be an [equate name](#equ).

`type` must be _sizeable_, as is the resulting array type.

#### Structures

`struct (type name) [(type name) ...]`

Defines a structure with members of the given types and names.  `type` is either
a `definition` or the `name` of another type defined previously; if it consists
of multiple tokens, it must be parenthesised.  `name` is unquoted and thus may
contain any characters other than parens and whitespace.

Each `type` must be _sizeable_, as is the resulting structure type.

#### Unions

`union (type name) [(type name) ...]`

Defines a union with members of the given types and names.  `type` is either a
`definition` or the `name` of another type defined previously; if it consists of
multiple tokens, it must be parenthesised.  `name` is unquoted and thus may
contain any characters other than parens and whitespace.

Each `type` must be _sizeable_, as is the resulting structure type.

#### Enumerations

`enum size (name value) [(name value) ...]`

Defines an enumeration of `size` bytes, with defined values of the given names
and values.  `name` is unquoted and thus may contain any characters other than
parens and whitespace.  `value` is an immediate literal, and may be an
[equate name](#equ).

An enumeration type is _sizeable_.

#### Forward declarations

`...`

Defines an incomplete type.  If this is a named type, it may be overridden by a
later redefinition of the same name; thus for instance a singly-linked list
could be defined as:
```
list: ...
list: struct ((* list) next)
```

Alternatively, the type may be left incomplete, in which case a `BTF_KIND_FWD`
definition will be emitted.  Such a type is not _sizeable_.

#### Typedefs

`typedef type`

Defines a type identical to `type` but with a different name.  `type` is either
a `definition` or the `name` of another type defined previously.  `type` does
not need to be enclosed in parentheses, even if it consists of multiple tokens.

A typedef is _sizeable_ if and only if its underlying `type` is.

#### Qualifiers

`qualifier type`

Defines a type derived from `type` but qualified according to `qualifier`.
`type` is either a `definition` or the `name` of another type defined
previously.  `type` does not need to be enclosed in parentheses, even if it
consists of multiple tokens.  `qualifier` is one of `const`, `volatile` or
`restrict`.

A qualified type is _sizeable_ if and only if its underlying `type` is.

## Output format

The assembler generates ELF object files, suitable for passing to standard tools
like iproute2's `ip link set dev ethX xdp obj object-file.o verb`.  Currently
only little-endian output (aka 'bpfel') is supported.
If using the `bpftool` utility from the kernel's `tools/lib/bpf`, as in
`bpftool prog load object-file.o /sys/fs/bpf/xdp/name type xdp`, note that you
will need to assemble with `--no-pin-maps` (see [maps](#map-definitions)).

## Testing

`ebpf_asm` has a suite of regression tests: run `./regression.py`.  If all is
well, there should be no output, and the return code will be zero.  For verbose
mode, use the switch `-v`.

## To Do

Ideas for the future.

* Test behaviour around trying to use labels as immediates/displacements.
* Tests for map definitions.
* "Loose mode" that allows bad things like registers `r11`-`r15`, a `raw`
  instruction that takes a 5-tuple, invalid sizes to various ops, etc.; in order
  to construct bad binaries to test the kernel's verifier.
* Support `label: instruction`.
* Support big-endian output ('bpfeb') and _maybe_ default to host endianness.
* Constant expressions.  Wherever a literal is expected, we should be able to
  have an expression instead.  We can even use `(parentheses)` for grouping,
  since indirection uses `[brackets]`.
