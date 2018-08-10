; call.s
; XDP program to test intra-program CALL instruction.
; Copyright (c) 2018 Solarflare Communications Ltd

.include defs.i
.include net_hdrs.i

.text
.section prog
	call	pass_fn
	exit

pass_fn:
	ld	r0.l, XDP_PASS
	exit

.data
.section license
_license:
	asciz	"Dual MIT/GPL"
