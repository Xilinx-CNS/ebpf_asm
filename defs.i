; defs.i
; Platform constant definitions header

; Map types
.equ	hash, 1
.equ	array, 2
.equ	prog_array, 3
.equ	perf_event_array, 4
.equ	percpu_hash, 5
.equ	percpu_array, 6
.equ	stack_trace, 7
.equ	cgroup_array, 8
.equ	lru_hash, 9
.equ	lru_percpu_hash, 10
.equ	lpm_trie, 11
.equ	array_of_maps, 12
.equ	hash_of_maps, 13
.equ	devmap, 14
.equ	sockmap, 15

; Helper function IDs
.equ	bpf_map_lookup_elem, 1
.equ	bpf_map_update_elem, 2
.equ	bpf_map_delete_elem, 3
.equ	bpf_probe_read, 4
.equ	bpf_ktime_get_ns, 5
.equ	bpf_trace_printk, 6
.equ	bpf_get_prandom_u32, 7
.equ	bpf_get_smp_processor_id, 8
.equ	bpf_skb_store_bytes, 9
.equ	bpf_l3_csum_replace, 10
.equ	bpf_l4_csum_replace, 11
.equ	bpf_tail_call, 12
.equ	bpf_clone_redirect, 13
.equ	bpf_get_current_pid_tgid, 14
.equ	bpf_get_current_uid_gid, 15
.equ	bpf_get_current_comm, 16
.equ	bpf_get_cgroup_classid, 17
.equ	bpf_skb_vlan_push, 18
.equ	bpf_skb_vlan_pop, 19
.equ	bpf_skb_get_tunnel_key, 20
.equ	bpf_skb_set_tunnel_key, 21
.equ	bpf_perf_event_read, 22
.equ	bpf_redirect, 23
.equ	bpf_get_route_realm, 24
.equ	bpf_perf_event_output, 25
.equ	bpf_skb_load_bytes, 26
.equ	bpf_get_stackid, 27
.equ	bpf_csum_diff, 28
.equ	bpf_skb_get_tunnel_opt, 29
.equ	bpf_skb_set_tunnel_opt, 30
.equ	bpf_skb_change_proto, 31
.equ	bpf_skb_change_type, 32
.equ	bpf_skb_under_cgroup, 33
.equ	bpf_get_hash_recalc, 34
.equ	bpf_get_current_task, 35
.equ	bpf_probe_write_user, 36
.equ	bpf_current_task_under_cgroup, 37
.equ	bpf_skb_change_tail, 38
.equ	bpf_skb_pull_data, 39
.equ	bpf_csum_update, 40
.equ	bpf_set_hash_invalid, 41
.equ	bpf_get_numa_node_id, 42
.equ	bpf_skb_change_head, 43
.equ	bpf_xdp_adjust_head, 44
.equ	bpf_probe_read_str, 45
.equ	bpf_get_socket_cookie, 46
.equ	bpf_get_socket_uid, 47
.equ	bpf_set_hash, 48
.equ	bpf_setsockopt, 49
.equ	bpf_skb_adjust_room, 50
.equ	bpf_redirect_map, 51
.equ	bpf_sk_redirect_map, 52
.equ	bpf_sock_map_update, 53

; XDP return codes
.equ	XDP_ABORTED, 0
.equ	XDP_DROP, 1
.equ	XDP_PASS, 2
.equ	XDP_TX, 3
.equ	XDP_REDIRECT, 4

; struct xdp_md
.equ	XDP_MD_DATA, 0
.equ	XDP_MD_DATA_END, 4
