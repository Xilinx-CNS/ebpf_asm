; net_hdrs.i
; Network header offsets

; Ethernet
.equ	ETHER_HDR_DEST, 0
.equ	ETHER_HDR_SRC, 6
.equ	ETHER_HDR_PROTO, 12
.equ	ETHER_HDR__LEN, 14

;TODO: implement the BPF_END opcode in the assembler, so we can do this properly
.equ	ETHERTYPE_IPV4_LE, 0x0008 ; IPv4 is 0x0800, but Ethertype is Big-Endian

; IPv4
.equ	IP_HDR_IHLVER, 0
.equ	IP_HDR_TOS, 1
.equ	IP_HDR_TOT_LEN, 2
.equ	IP_HDR_ID, 4
.equ	IP_HDR_FRAG_OFF, 6
.equ	IP_HDR_TTL, 8
.equ	IP_HDR_PROTOCOL, 9
.equ	IP_HDR_CSUM, 10
.equ	IP_HDR_SADDR, 12
.equ	IP_HDR_DADDR, 16
.equ	IP_HDR__LEN, 20 ; length of fixed part, excl. options

.equ    IPPROTO_UDP, 17

; UDP
.equ    UDP_HDR_SPORT, 0
.equ    UDP_HDR_DPORT, 2
.equ    UDP_HDR_DLEN, 4
.equ    UDP_HDR_CSUM, 6
.equ    UDP_HDR__LEN, 8
