#include "routerHelper.h"
#include "./include/skel.h"
#include <netinet/if_ether.h>
#include <queue>
#include <iostream>
#include <algorithm>
#define macValue 6
#define ipValue 4
#define defTTL 64
#define defLenMessage 42
#define one 1
#define zero 0


struct route_table *get_best_route(__u32 ip_dest, route_table *rTable, int rTable_size, int left, int right) {
	while (left <= right) {
		int middle = left + (right - left) / 2;
		if ((ip_dest & rTable[middle].mask) == rTable[middle].prefix) {
			int k = middle;
			while (rTable[k - one].prefix == rTable[middle].prefix) {
				k--;
			}
			return &rTable[k];
 		}
		if ((ip_dest & rTable[middle].mask) > rTable[middle].prefix) {
 			return get_best_route(ip_dest, rTable, rTable_size, left + one, right);
 		} else {
 			return get_best_route(ip_dest, rTable, rTable_size, left, right - one);
		}
	}
	return NULL;
}

struct arp_entry *get_arp_entry(__u32 ip, int last_arp, arp_entry *arp_table) {
    for (int i = zero; i < last_arp; i++) {
    	if (ip == arp_table[i].ip) {
    		return &arp_table[i];
    	}
    }
    return NULL;
}

void doTheTTL(struct icmphdr *icmp_hdr, struct ether_header *eth_hdr, struct iphdr *ip_hdr, packet *m) {
    uint32_t temp;
    memcpy(&temp, &ip_hdr->daddr, sizeof(uint32_t));
    memcpy(&ip_hdr->daddr, &ip_hdr->saddr, sizeof(uint32_t));
    memcpy(&ip_hdr->saddr, &temp, sizeof(uint32_t));

    icmp_hdr->code = zero;
    icmp_hdr->type = ICMP_TIMXCEED;
    icmp_hdr->checksum = zero;
    icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof(struct icmphdr));

    ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmp));
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->check = zero;
    ip_hdr->check = ip_checksum(ip_hdr , sizeof(struct iphdr));

    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, macValue * sizeof(uint8_t));
    get_interface_mac(m->interface, eth_hdr->ether_shost);
    m->len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
    send_packet(m->interface, m);
}
void doTheRouterDestination(struct icmphdr *icmp_hdr, struct ether_header *eth_hdr, struct iphdr *ip_hdr, packet *m) {
    ip_hdr->ttl = defTTL;
    uint32_t temp;
    memcpy(&temp, &ip_hdr->daddr, sizeof(uint32_t));
    memcpy(&ip_hdr->daddr, &ip_hdr->saddr, sizeof(uint32_t));
    memcpy(&ip_hdr->saddr, &temp, sizeof(uint32_t));

    icmp_hdr->type = ICMP_ECHOREPLY;
    icmp_hdr->checksum = zero;
    icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof(struct icmphdr));


    ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmp));
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->check = zero;
    ip_hdr->check = ip_checksum(ip_hdr , sizeof(struct iphdr));

    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, macValue * sizeof(uint8_t));
    get_interface_mac(m->interface, eth_hdr->ether_shost);

    m->len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
    send_packet(m->interface, m);
}

void doTheUnreach(struct icmphdr *icmp_hdr, struct ether_header *eth_hdr, struct iphdr *ip_hdr, packet *m) {
    uint32_t temp;
    memcpy(&temp, &ip_hdr->daddr, sizeof(uint32_t));
    memcpy(&ip_hdr->daddr, &ip_hdr->saddr, sizeof(uint32_t));
    memcpy(&ip_hdr->saddr, &temp, sizeof(uint32_t));


    icmp_hdr->code = zero;
    icmp_hdr->type = ICMP_DEST_UNREACH;
    icmp_hdr->checksum = zero;
    icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof(struct icmphdr));


    ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmp));
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->check = zero;
    ip_hdr->check = ip_checksum(ip_hdr , sizeof(struct iphdr));

    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, macValue * sizeof(uint8_t));
    get_interface_mac(m->interface, eth_hdr->ether_shost);
    m->len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
    send_packet(m->interface, m);
}

void doNoArpEntry(struct ether_arp  *arp_hdr , struct ether_header *eth_hdr,  packet *m, uint32_t copyDaddr,
                struct route_table *rTable) {
    arp_hdr->ea_hdr.ar_op = htons(ARPOP_REQUEST);

    
    // Target zero
    memset(arp_hdr->arp_tha, 0x00, macValue * sizeof(uint8_t));

    // Broadcast
    memset(eth_hdr->ether_dhost, 0xFF, macValue * sizeof(uint8_t));
                    
    // Prepare the Mac adress
    get_interface_mac(m->interface, eth_hdr->ether_shost);
    get_interface_mac(rTable->interface, arp_hdr->arp_sha);

    memcpy(arp_hdr->arp_tpa, &copyDaddr,  ipValue * sizeof(uint8_t));
    memcpy(arp_hdr->arp_spa, get_interface_ip(rTable->interface) , ipValue * sizeof(uint8_t));

    // Protocol
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);

    // Creating Arp Request
    arp_hdr->ea_hdr.ar_pln = ipValue;
    arp_hdr->ea_hdr.ar_hln = macValue;
    arp_hdr->ea_hdr.ar_hrd = htons(0x01);
    arp_hdr->ea_hdr.ar_pro = htons(ETH_P_IP);

    m->len = defLenMessage;
    send_packet(rTable->interface, m);
}

void doTheArpReq(struct ether_arp  *arp_hdr , struct ether_header *eth_hdr,  packet *m) {
    arp_hdr->ea_hdr.ar_op = htons(ARPOP_REPLY);
    uint8_t temp[ipValue];
    memcpy(temp, arp_hdr->arp_tpa, ipValue * sizeof(uint8_t));
    memcpy(arp_hdr->arp_tpa, arp_hdr->arp_spa, ipValue * sizeof(uint8_t));
    memcpy(arp_hdr->arp_spa, temp, ipValue * sizeof(uint8_t));

    memcpy(arp_hdr->arp_tha, arp_hdr->arp_sha, macValue * sizeof(uint8_t));
    get_interface_mac(m->interface, arp_hdr->arp_sha);

    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, macValue * sizeof(uint8_t));
    get_interface_mac(m->interface, eth_hdr->ether_shost);
    send_packet(m->interface, m);
}

void doTheArpReply(struct ether_arp  *arp_hdr , struct ether_header *eth_hdr, struct iphdr *ip_hdr, int *last_arp, struct route_table *rTable, 
                    struct arp_entry *arp_table, packet *m) {
    memcpy(arp_table[*last_arp].mac, arp_hdr->arp_sha, macValue * sizeof(uint8_t));

    memcpy(&(arp_table[*last_arp].ip), arp_hdr->arp_spa, sizeof(uint32_t));
    last_arp++;

    ip_hdr->ttl--;
    ip_hdr->check = zero;
    ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

    // Send the packet
    get_interface_mac(m->interface, eth_hdr->ether_shost);
    memcpy(eth_hdr->ether_dhost, arp_hdr->arp_sha, macValue * sizeof(uint8_t));
    send_packet(rTable->interface, m);
}