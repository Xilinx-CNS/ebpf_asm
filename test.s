; test.s
; A semantically-nonsense test file for the eBPF assembler

.include defs.i

.text
.section prog
	ld	r0.l, [r1+013]
	ld	r2, fp
	ld	r4.l, 0xfe
	add	r0, r4
	mul	r1, 4
	neg	r2
	ld	[r0].b, 12
	ld	r1, bar
	jr	+6
	jr	nz, r0, r1, +6
	jr	>=, r0, 14, +6
foo:
	call	bpf_map_update_elem
	exit
	jr	foo
.section maps
; ip.src => counter
bar: percpu_hash, 4, 4, 1024, P
.data
.section license
_license:
	asciz	"GPL"
