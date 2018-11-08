u32: int unsigned 32 ; int encoding nbits
__be32: typedef u32 ; No support yet for endianness / __bitwise in BTF :-(
____btf_map_dropcnt: struct (__be32 key) (u32 value) ; define map type
; A bunch more types, just to test BTF support
__le32: typedef typedef int signed 32 ; gratuitous example of anonymous types
char: int (char) 8 ; can't use (signed char) as kernel rejects combination
ppi: * (* int () 32) ; pointer-to-pointer-to-int
name: array (char) 4 ; the brackets are unnecessary but permitted
names: struct ((name) first) (name last) ; mumble sizes
ipv4: union (__be32 addr) ((array char 4) octets)
xdprc: enum 4 (XDP_DROP 1) (XDP_PASS 2) (XDP_ABORTED 0) ; size (name value)
crpvi: const restrict (* volatile (u32)); const restrict pointer to volatile int
memptr: * (void) ; pointer to void
list: ... ; forward-declaration
list: struct ((* list) next)
forward: ... ; uncompleted fwd-declaration
