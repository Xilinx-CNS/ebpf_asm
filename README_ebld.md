# ebld

A static linker for eBPF programs.

## Synopsis

`ebld.py <objectfile> [...] -o <outputfile>`

## Rationale

With the increasingly wide usage of eBPF comes the need to allow multiple
applications to attach programs to the same hook.  While there exist tail-call
based schemes to chain co-operating programs, these require modification of the
program source, and tail calls are problematic in various ways.  One proposal[1]
is for the kernel directly to support chaining programs, but this then requires
a declarative specification of how each program's return code should affect
which program is run next, and how the final return code is determined (e.g. for
XDP, should the packet be passed, dropped or redirected?).

[1]: https://lore.kernel.org/netdev/20191009121955.29cad5bb@carbon/T/

Using a linker, instead, one can write a master program which consists of
function calls into the individual programs, and control flow based on their
return codes.  A simple example might look like this:

```
.include defs.i
.text
.section prog
.globl	firewall
.globl	xdpdump
.globl	main
main:
	ld	r6, r1 ; save the ctx
	call	firewall ; run firewall prog on ctx
	jr	z, r0.l, XDP_PASS, out
	jr	z, r0.l, XDP_TX, out
	jr	z, r0.l, XDP_REDIRECT, out
	; got here == DROP, ABORTED or bad return code, so dump it
	ld	r1, r6 ; restore the ctx
	ld	r6, r0 ; save the original return code
	call	xdpdump ; run xdpdump prog on ctx
	ld	r0, r6 ; restore the original return code
out:
	exit ; performs whatever action firewall chose
```

Note the presence of `.globl` declarations for the external functions.  These
will be accepted by ebpf_asm if the `-c` switch is passed.  Then, the resulting
object file can be linked with object files implementing `firewall()` and
`xdpdump()`, to produce a complete object file with all symbols resolved, which
can then be installed in the kernel.

Note that ebld isn't tied to ebpf_asm; if your C compiler can emit relocations
for undefined symbols, that should work too.  The C code for the above example
would look something like:

```c
#include <linux/bpf.h>

int firewall(struct xdp_md *ctx);
int xdpdump(struct xdp_md *ctx);

SEC("prog")
int main(struct xdp_md *ctx)
{
	int rc;

	rc = firewall(ctx);
	switch(rc) {
	case XDP_PASS:
	case XDP_TX:
	case XDP_REDIRECT:
		break;
	default:
		xdpdump(ctx); /* Ignore xdpdump return code */
		break;
	}
	return rc; /* Original firewall return code */
}
```

## License

Like ebpf_asm, ebld is provided under the MIT license.

## To Do

* Support BTF and BTF.ext sections.  (Currently they will be silently discarded,
  as being none of STRTAB, SYMTAB, PROGBITS or REL.)
* Support relocating other instruction types than calls, particularly LDX/STX,
  for handling struct member offsets (CO-RE).
* Support RELA sections.  CO-RE may make use of these.
