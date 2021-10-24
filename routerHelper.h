#ifndef ROUTERHELPER_H
#define ROUTERHELPER_H
#include "./include/skel.h"
#include <netinet/if_ether.h>
#include <queue>
#define routeSize 700001
#define arpSize 5
#define defValue 0

struct route_table *get_best_route(uint32_t ip_dest, struct route_table *rt, int rTable_size, int left, int right);
struct arp_entry *get_arp_entry(__u32 ip, int last_arp, struct arp_entry* arp_table);
void doTheTTL(struct icmphdr *icmp_hdr, struct ether_header *eth_hdr, struct iphdr *ip_hdr, packet *m);
void doTheRouterDestination(struct icmphdr *icmp_hdr, struct ether_header *eth_hdr, struct iphdr *ip_hdr, packet *m);
void doTheUnreach(struct icmphdr *icmp_hdr, struct ether_header *eth_hdr, struct iphdr *ip_hdr, packet *m);
void doNoArpEntry(struct ether_arp  *arp_hdr, struct ether_header *eth_hdr,  packet *m , uint32_t copyDaddr, struct route_table *rTable);
void doTheArpReq(struct ether_arp  *arp_hdr, struct ether_header *eth_hdr,  packet *m);
void doTheArpReply(struct ether_arp  *arp_hdr, struct ether_header *eth_hdr, struct iphdr *ip_hdr, int *last_arp, struct route_table *rTable,
                    struct arp_entry *arp_table, packet *m);

#endif