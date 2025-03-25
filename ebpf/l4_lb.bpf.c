#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
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
#include "l4_lb_utils.h"

typedef struct {
    __be32 destination;
    __be16 total_length;
    __u8 protocol;
} ip_parse_ret;

struct bpf_iter_num {
    int start;
    int end;
    int current;
};


static __always_inline int parse_iphdr(void *data, void *data_end, __u16 *nh_off, struct iphdr **iphdr, ip_parse_ret *result) {
    struct iphdr *ip = data + *nh_off;
    int hdr_size;

    if ((void *)ip + sizeof(*ip) > data_end)
        return -1;
    
    hdr_size = ip->ihl * 4;

    /* Sanity check packet field is valid */
        if(hdr_size < sizeof(*ip))
            return -1;

    /* Variable-length IPv4 header, need to use byte-based arithmetic */
        if ((void *)ip + hdr_size > data_end)
            return -1;

    *nh_off += hdr_size;
    *iphdr = ip;

    result->destination = ip->addrs.daddr;
    result->total_length = ip->tot_len;
    result->protocol = ip->protocol;

   return 0;
}

static __always_inline int parse_ethhdr(void *data, void *data_end, __u16 *nh_off, struct ethhdr **ethhdr) {
   struct ethhdr *eth = (struct ethhdr *)data;
   int hdr_size = sizeof(*eth);

   /* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
   if ((void *)eth + hdr_size > data_end)
      return -1;

   *nh_off += hdr_size;
   *ethhdr = eth;

//    bpf_printk("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
//            eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
//            eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

//     // Print source MAC address
//     bpf_printk("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
//            eth->h_source[0], eth->h_source[1], eth->h_source[2],
//            eth->h_source[3], eth->h_source[4], eth->h_source[5]);

   

   return eth->h_proto; /* network-byte-order */
}

static __always_inline int parse_udphdr(void *data, void *data_end, __u16 *nh_off, struct udphdr **udphdr)
{
    struct udphdr *udp = data + *nh_off; 

    if ((void *)udp + sizeof(udp) > data_end){
        return -1; 
    }

    *nh_off += sizeof(*udp);
    *udphdr = udp; 

    return 0; 

}

static __always_inline int flow_check(four_tuple tuple1){
    chosen_backend *res; 
    res = bpf_map_lookup_elem(&flow_map, &tuple1);
    if (!res){
        //THE FLOW IS NEW
        bpf_printk("[NEW FLOW]");
        return 0;
    }
    else {   

        bpf_printk("[OLD FLOW]");
        return 1; 
    }
}

static __always_inline int least_loaded_backend(){

    int min = 10000; 
    int index_min = 0;
    int *n_backends = bpf_map_lookup_elem(&total_backends, &index_min);
    if (!n_backends){
        return -1; 
    }
     
    backend_info *back;
    int i;  
    bpf_for(i,0,*n_backends){
        back = bpf_map_lookup_elem(&flow_packets_count_map, &i);
        
        if (!back){
            bpf_printk("ERRORE nel calcolo del minimo "); 
            return -1; 
        }
        bpf_printk("IP %d- FLOW%d- PACK%d- LOAD %d",back ->backend_ip, back->flows_count, back->pkts_count, back->load);

        if (back->load<min){
            min = back->load; 
            index_min = i; 
        }
    }
    return index_min; 
}

static __always_inline __u16 ip_checksum(struct iphdr *iphdr) {
    __u32 sum = 0;
    __u16 *ptr = (__u16 *)iphdr;

    #pragma clang loop unroll(full)
    for (int i = 0; i < sizeof(*iphdr) >> 1; i++) {
        sum += *ptr++;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    return (__u16)(~sum);
}


SEC("xdp")
int l4_lb(struct xdp_md *ctx) {

    int key = 0; 

    /*Extracting the VIP from the MAP*/
    __u32  *vip = bpf_map_lookup_elem(&VIP, &key);
    if (vip == NULL){
        bpf_printk("[VIP] is NULL");
        goto drop; 
    }
    //bpf_printk("The VIP is %u",*vip); 
    
    /*Extracting the data and data end pointer*/
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /*Parsing the packet*/
    __u16 nf_off = 0;
    struct ethhdr *eth;
    int eth_type;
    struct iphdr *ip;
    int ip_result;
    ip_parse_ret result;
    struct udphdr *udp; 

   // __u32 target_ip = 0x0509A8C0; // HERE YOU CAN HARDCODE THE IP 

    eth_type = parse_ethhdr(data, data_end, &nf_off, &eth);

    // THE HOST WILL SEND AN ARP PACKET IN ORDER TO KNOW THE MAC ADDRESS
    // WE LET IT PASS 
    if (eth_type == bpf_ntohs(ETH_P_ARP)) {
        bpf_printk("[ARP]: received an arp request");
        bpf_printk("[ARP]: XDP_PASS");
        goto pass;
    }

    // if the ether type is not IP it should drop the packet
    if (eth_type != bpf_ntohs(ETH_P_IP)) {
        bpf_printk("[DROP] ETHERTYPE is NOT IP");
        goto drop;
    }


    ip_result = parse_iphdr(data, data_end, &nf_off, &ip, &result);

    bpf_printk("The destination is %u", bpf_ntohl(result.destination));
    
    if (ip_result != 0){
        bpf_printk("[ERROR] IP_RESTUL != 0");
        goto drop;
    }
    if (result.protocol == IPPROTO_ICMP) {
        bpf_printk("[ICMP]");
        goto pass;
    }
    // if the ip protocol is not UDP it should drop the packet
    if (result.protocol != IPPROTO_UDP) {
        bpf_printk("[DROP] IP PROTOCOL IS NOT UDP");
        goto drop;
    }
    
    // if the ip destination is not actually the VIP the packet should be dropped
    if (bpf_ntohl(result.destination) != *vip){
        bpf_printk("[DROP] The IP destination is not correct");
        goto drop;
    }

    /*UPD parsing*/
    int udp_parsing = parse_udphdr(data, data_end, &nf_off, &udp);
    if (udp_parsing != 0)
    {
        bpf_printk("[DROP] The udp parsing was not successful");
        goto drop; 
    }
    
    bpf_printk("[READY] Packet is ready for the Load Balancer");
    
    // //FORGE PACKET

    /*TODO 1: get the 4 tuple*/
    four_tuple tuple; 
    tuple.dst_ip = bpf_ntohl(ip->addrs.daddr);
    tuple.src_ip = bpf_ntohl(ip->addrs.saddr);
    tuple.src_port = bpf_ntohs(udp->source);
    tuple.dst_port = bpf_ntohs(udp->dest);  

    /*Displaying the 4 tuple*/
    // bpf_printk("IP_destination %u", tuple.dst_ip);
    // bpf_printk("IP source %u", tuple.src_ip);
    // bpf_princhatk("Source prot %u", tuple.src_port);
    // bpf_printk("Destination port %u", tuple.dst_port);
    
    
    /*TODO 2: check the value of the map*/
    int index; 
    backend_info *back; 
    int ret; 
    uint32_t final_backend; 

    if( flow_check(tuple) == 0){

        //The flow is new
        index = least_loaded_backend(); 
        bpf_printk("[INDEX] the index is %d", index); 
        
        back = bpf_map_lookup_elem(&flow_packets_count_map, &index); 
        if (!back)
        {  
            return XDP_DROP; 
        }
        back->flows_count++; 
        back->pkts_count++;
        back->load = back->pkts_count / back->flows_count; 

        bpf_printk("IP %d- FLOW%d- PACK%d- LOAD %d",back ->backend_ip, back->flows_count, back->pkts_count, back->flows_count);

        ret = bpf_map_update_elem(&flow_packets_count_map, &index, back, BPF_ANY);
        //bpf_printk("[DEBUG] bpf_map_update_elem return value: %d", ret);

        if (ret < 0) {
            bpf_printk("[NEW]Failed to update the element in the map\n");
            return XDP_DROP;
        }


        chosen_backend chosen ={
            .backend_ip = back->backend_ip,
            .index = index
        };
        
        final_backend = back->backend_ip; 
        ret = bpf_map_update_elem(&flow_map, &tuple, &chosen, BPF_ANY);
        if (ret < 0){
            bpf_printk("[NEW] Failed to update the flow map"); 
            return XDP_DROP; 
        }
        
    }
    else{
        //The flow is old
        chosen_backend *index2 = bpf_map_lookup_elem(&flow_map, &tuple); 
        if (!index2){
            return XDP_DROP; 
        }
        bpf_printk("[INDEX] the index is %d", index2->index); 
        back = bpf_map_lookup_elem(&flow_packets_count_map, &index2->index); 
        if (!back)
        {  
            bpf_printk("ERRORE"); 
            return XDP_DROP; 
        }
        back->pkts_count++;
        back->load = back->pkts_count / back->flows_count; 
        final_backend = index2->backend_ip; 

    }
    
    //CONVERTIRE BACKEND FINALE
    /*
    CONVERSIONE
    167772417 -> 10.0.1.1
    167772674 -> 10.0.2.2
    167772931 -> 10.0.3.3
    167773188 -> 10.0.4.4
    */
    bpf_printk("IL BACKEND FINALE IN FORMATO HOST E: %d", bpf_ntohl(final_backend)); 
    
    /* ADESSO BISOGNA INSERIRE INGRANDIRE IL PACCHETTO PER INSERIRE L'HEADER IP NUOVO
    
    */

    unsigned char tmp_mac[ETH_ALEN]; //address length
  
    #pragma unroll 
    for (int i = 0; i< ETH_ALEN; i++){
        /*
        Il codice sostituisce il mac destinatino con 
        il mac sorgente 
        */
        tmp_mac[i] = eth->h_dest[i];
        eth->h_dest[i] = eth->h_source[i];
        eth->h_source[i] = tmp_mac[i];
    }


    int tot_len = ip->tot_len; 
    int delta = sizeof(struct iphdr); // Dimensione di un pacchetto IP

    bpf_printk("%d", delta); 
    bpf_printk("TOTAL [NTOHS] LENGHT PRIMA DELL?ENLARGING%d", bpf_ntohs(tot_len));
    bpf_printk("TOTAL [NO] LENGHT PRIMA DELL?ENLARGING%d", tot_len);

    //Negative will increase the packeet dimension 
    if (bpf_xdp_adjust_head(ctx, 0-delta)){
        bpf_printk("ERRORE NELL?AUMENTARE LA GRANDEZZA DEL PACCHETTO"); 
        return XDP_DROP; 
    }
   
    // Recalculate data and data_end after header adjustment
    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;

    //Check if the 
    if (data + sizeof(*eth) + delta + sizeof(*ip) + sizeof(*udp) > data_end) {
        bpf_printk("[ERROR] Not enough space for new headers");
        goto drop;
    }

    struct ethhdr *new_eth = data;

    /*COPYING DATA OF THE HOLD ETH HEADER TO THE NEW ETH HEADER*/
    __builtin_memcpy(new_eth, data + delta, sizeof(struct ethhdr));

    // Print destination MAC address
    // bpf_printk("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
    //        new_eth->h_dest[0], new_eth->h_dest[1], new_eth->h_dest[2],
    //        new_eth->h_dest[3], new_eth->h_dest[4], new_eth->h_dest[5]);

    // // Print source MAC address
    // bpf_printk("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
    //        new_eth->h_source[0], new_eth->h_source[1], new_eth->h_source[2],
    //        new_eth->h_source[3], new_eth->h_source[4], new_eth->h_source[5]);

    // Print protocol number (in hexadecimal)
    //bpf_printk("Protocol: %04x\n", bpf_ntohs(new_eth->h_proto));
    
    //BUILDING THE NEW IP HEADER
    struct iphdr *new_ip = data + sizeof(struct ethhdr);

    new_ip->version = 4; 
    new_ip->ihl = 5; 
    new_ip->tos = 0; 
    new_ip->tot_len = bpf_htons(bpf_ntohs(tot_len) + delta);  
    new_ip->id = bpf_htons(1); 
    new_ip->frag_off = 0; 
    new_ip->ttl = 64; 
    new_ip->protocol = IPPROTO_IPIP; 
    new_ip->check = 0; 
    new_ip->addrs.saddr = bpf_htonl(tuple.src_ip); 
    new_ip->addrs.daddr = final_backend; 

    //new_ip->addrs.saddr = 16777226; 
    //new_ip->addrs.daddr = 4261412874; 

    // Calculate IP checksum
    new_ip->check = ip_checksum(new_ip);



    bpf_printk("TOTAL [NO] LENGHT DOPO DELL?ENLARGING%d", new_ip->tot_len);
    bpf_printk("TOTAL [NTOHS] LENGHT PRIMA DELL?ENLARGING%d", bpf_ntohs(new_ip->tot_len) );


    bpf_printk("################################################"); 
    struct ethhdr *prova = data;
    bpf_printk("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           prova->h_dest[0], prova->h_dest[1], prova->h_dest[2],
           prova->h_dest[3], prova->h_dest[4], prova->h_dest[5]);

    // Print source MAC address
    bpf_printk("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           prova->h_source[0], prova->h_source[1], prova->h_source[2],
           prova->h_source[3], prova->h_source[4], prova->h_source[5]);

    bpf_printk("IP src %u", new_ip->addrs.saddr);
    bpf_printk("IP dst %u", new_ip->addrs.daddr);
    bpf_printk("IP ttl %u", new_ip->ttl);
    bpf_printk("IP protocol %u", new_ip->protocol);
    bpf_printk("IP id %u", new_ip->id);
    struct iphdr *new_ip2 = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    bpf_printk("IP2 src %u", new_ip2->addrs.saddr);
    bpf_printk("IP2 src %u", new_ip2->addrs.daddr);
    bpf_printk("IP2 ttl %u", new_ip2->ttl);
    bpf_printk("################################################"); 

    goto transmit; 


pass:
    return XDP_PASS;
drop:
    bpf_printk("DROPPATO");
    return XDP_DROP;
transmit: 
    bpf_printk("TRASMESSO"); 
    /*I pacchetti non si vedono con XDP_TX
    L'interfaccia li blocca per qualche motivo. 
    Si può vedere che il pacchetto è formato correttamente 
    sostituiendo XDP_PASS
    e osservando l'interfaccia veth1_*/
    return XDP_TX;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
