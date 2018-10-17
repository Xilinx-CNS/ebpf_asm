; dropper.s
; simple IP-based XDP drop program
; Copyright (c) 2017 Solarflare Communications Ltd

.include defs.i
.include net_hdrs.i

.text
.section prog
	ld	r0.l, XDP_PASS ; On errors we return pass
	ld	r2.l, [r1+XDP_MD_DATA]
	ld	r3.l, [r1+XDP_MD_DATA_END]
	ld	r1, r2
	add	r1, ETHER_HDR__LEN
	jr	ge, r3, r1, +1 ; Do we have the entire ether-hdr?
	exit
	ld	r4.w, [r2+ETHER_HDR_PROTO]
	end	be, r4.w
	jr	z, r4, ETHERTYPE_IPV4, +1 ; Is it IPv4?
	exit
	ld	r2, r1 ; done with the ether-hdr
	add	r1, IP_HDR__LEN
	jr	ge, r3, r1, +1 ; Do we have the entire IP hdr?
	exit
	add	r2, IP_HDR_SADDR
	ld	r1, dropcnt
	call	bpf_map_lookup_elem
	jr	nz, r0, 0, drop
	; Not in the map, pass it
	ld	r0.l, XDP_PASS
	exit
drop:
	; Increment the counter
	ld	r1.l, [r0]
	add	r1.l, 1
	ld	[r0], r1.l
	; return drop verdict
	ld	r0.l, XDP_DROP
	exit

.section .BTF
u32: int unsigned 32 ; int encoding nbits
__be32: typedef u32 ; No support yet for endianness / __bitwise in BTF :-(
____btf_map_dropcnt: struct (__be32 key) (u32 value) ; define map type
; A bunch more types, just to test BTF support
__le32: typedef (typedef (int signed 32)) ; gratuitous example of anonymous types
char: int (char) 8 ; can't use (signed char) as kernel rejects combination
ppi: * * int () 32 ; pointer-to-pointer-to-int
name: array (char) 4 ; the brackets are unnecessary but permitted
names: struct (name first) (name last) ; mumble sizes
ipv4: union (__be32 addr) ((array char 4) octets)
xdprc: enum 4 (XDP_DROP XDP_DROP) (XDP_PASS XDP_PASS) (XDP_ABORTED 0) ; size (name value)
crpvi: const restrict * volatile u32 ; const restrict pointer to volatile int
memptr: * void ; pointer to void

.section maps
; __be32 ip.src => u32 counter
dropcnt: percpu_hash, 4, 4, 256, P
.data
.section license
_license:
	asciz	"Dual MIT/GPL"
