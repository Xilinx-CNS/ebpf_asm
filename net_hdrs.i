; net_hdrs.i
; Network header offsets

; Ethernet
.equ	ETHER_HDR_DEST, 0
.equ	ETHER_HDR_SRC, 6
.equ	ETHER_HDR_PROTO, 12
.equ	ETHER_HDR__LEN, 14

.equ	ETHERTYPE_IPV4, 0x0800
.equ	ETHERTYPE_8021Q, 0x8100 ; really the 802.1q "TPID", but appears at the same offset as Ethertype

; VLAN (802.1q) considered as coming _after_ the Ethertype (which is saner)
.equ	VLAN_HDR_TCI, 0
.equ	VLAN_HDR_INNER_PROTO, 2 ; Officially this is the Ethertype and where it should be is the TPID.  But that's needlessly confusing; treat it as though that the Ethertype is 0x8100, the VLAN header starts after that, and includes an 'inner-Ethertype' field.
.equ	VLAN_HDR__LEN, 4

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
