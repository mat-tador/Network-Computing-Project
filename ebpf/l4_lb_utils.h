#ifndef L4_LB_UTILS_H_
#define L4_LB_UTILS_H_

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stddef.h>
#include <stdint.h>

    typedef struct{
		__uint32_t backend_ip; 
		__uint16_t flows_count;
		__uint16_t pkts_count;
		__uint16_t load; 
	} backend_info;
	
	typedef struct{
		__uint32_t src_ip;
		__uint32_t dst_ip;
		__uint16_t src_port;
		__uint16_t dst_port;
	} four_tuple;

	typedef struct{
		__uint32_t backend_ip;
		__uint16_t index;
	} chosen_backend;

	/* VIP map is used in order to share the information about the VIP from userspacce to kernel space
	This is used to filter out all non ARP packets that do not contain as destination the  VIP. */

	struct{
		__uint(type, BPF_MAP_TYPE_ARRAY); 
		__type(key, int); 
		__type(value, __u32); 
		__uint(max_entries, 1); 
	} VIP SEC(".maps"); 

	
	/*The total backends is used in order to limit the amount of access to memory 
	when finding the least loaded backend server */
	struct{
		__uint(type, BPF_MAP_TYPE_ARRAY);
		__type(key, int); 
		__type(value, __u32);
		__uint(max_entries, 1);
	} total_backends SEC(".maps");

	/*THE HASH TABLE IS USED IN ORDER TO FIND IF THE FLOW 
	ALREADY PASSED THROUGH THE LOAD BALANCERE. IF IT WAS SEEN IT WILL STORE 
	THE INFORMATION OF THE BACKEND SERVER WHERE IT SHOULD BE FORWARDED. 
	OTHERWISE INFORMATION WILL BE STORE INSIDE
	THE DIMENSION IS 65535 WHICH WILL GIVE A COLLISION PROBABILITY OF ROUGHLY 7%
	WITH 100 different flows. 
	*/

	struct {
		__uint(type, BPF_MAP_TYPE_HASH);
		__type(key, four_tuple );
		__type(value, chosen_backend);
		__uint(max_entries, 65535);
	} flow_map SEC(".maps");

	/*
	AN ARRAY TABLE IS USED IN ORDER TO FIND THE MINIMUM LOAD BACKEND
	THE DIMENSION OF THE ARRAY NEED TO BE AS BIG AS THE AMOUNT OF BACKENDS 
	SERVER. 
	100 WAS CHOSEN AS THE DIMENSION OF THE ARRAY 
	*/
	
	struct {
		__uint(type, BPF_MAP_TYPE_ARRAY);
		__type(key, __u32);
		__type(value, backend_info);
		__uint(max_entries, 100);
	} flow_packets_count_map SEC(".maps");


#endif // L4_LB_UTILS_H_
