#include "./include/skel.h"
#include <netinet/if_ether.h>
#include <queue>
#include <iostream>
#include <algorithm>
#include "routerHelper.h"

#define macLength 6
#define ipLength 4
#define defValue 0


int main(int argc, char *argv[])
{
	packet m;
	int rc, last_arp = defValue;
	std::queue<packet> myqueue;
	init();
	route_table *rT = (route_table*) malloc(sizeof(struct route_table) * routeSize);
	arp_entry  *arp_table = (arp_entry*) malloc(sizeof(struct arp_entry) * arpSize);
	DIE(rT == NULL, "mem");	
	int secvence = defValue;	
	int rTable_size = read_rtable(rT);
	int i = 0;
	while (1) {
		++i;
		rc = get_packet(&m);
		DIE(rc < defValue, "get_message");
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));


		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload +  sizeof(struct ether_header) + sizeof(struct iphdr));

			/*
				Check the checksums
			*/ 
		
			uint16_t oldChecksum = ip_hdr->check;
			ip_hdr->check = defValue;

			if (oldChecksum != ip_checksum(ip_hdr, sizeof(struct iphdr))) {
				continue;
			}
			/*
				Verify if the TTL is less than 1
			*/
			if (ip_hdr->ttl <= 1) {
				doTheTTL(icmp_hdr, eth_hdr, ip_hdr, &m);
				continue;
			}
			/*
				Verify if the packet is for the router
			*/
			if(ip_hdr->daddr == inet_addr(get_interface_ip(m.interface))) {
				if (icmp_hdr->type == ICMP_ECHO) {
					doTheRouterDestination(icmp_hdr, eth_hdr, ip_hdr, &m);
					continue;
				}
			}
			/*
				Get the best route to send the packet
				Also check if it exists, if it doesn't, send to the source
				an icmp message with host unknown
			*/
			struct route_table *rTable = get_best_route(ip_hdr->daddr, rT, rTable_size, 0, rTable_size - 1);
			if (rTable == NULL) {
				doTheUnreach(icmp_hdr, eth_hdr, ip_hdr, &m);
				continue;
			}

			 /*
			 	Take the mac from the arp entry.
			 	Also  if it doesn't exists make an arp request and send it.
			 */
			struct arp_entry* a_entry = get_arp_entry(rTable->next_hop, last_arp, arp_table);
			if (a_entry == NULL) {
				uint32_t copyDaddr = ip_hdr->daddr;
				myqueue.push(m);
				struct ether_arp *arp_hdr = (struct ether_arp*) (m.payload + sizeof(struct ether_header));
				doNoArpEntry(arp_hdr, eth_hdr, &m, copyDaddr, rTable);
				continue;
			}

			/*
				Update the ttl and checksums
			*/	
				ip_hdr->ttl--;
				ip_hdr->check = defValue;
				ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

				icmp_hdr->un.echo.sequence = htons(secvence);
				icmp_hdr->checksum = defValue;
				icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof(struct icmphdr));
				secvence++;
				// Send the packet
				get_interface_mac(m.interface, eth_hdr->ether_shost);
				memcpy(eth_hdr->ether_dhost, a_entry->mac, macLength * sizeof(uint8_t));
				send_packet(rTable->interface, &m);
		} else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) { 

			/*
				Verify if it's an arp request and reply with an arp reply 
			*/
			struct ether_arp* arp_hdr = (struct ether_arp*) (m.payload + sizeof(struct ether_header));
			if (ntohs(arp_hdr->ea_hdr.ar_op) == ARPOP_REQUEST) {
				doTheArpReq(arp_hdr, eth_hdr, &m);
				continue;
				/*
					Verify if it needs an arp reply and send the packets forward.
				*/
			} else if (ntohs(arp_hdr->ea_hdr.ar_op) == ARPOP_REPLY) {
				memcpy(arp_table[last_arp].mac, arp_hdr->arp_sha, macLength * sizeof(uint8_t));
				memcpy(&(arp_table[last_arp].ip), arp_hdr->arp_spa, sizeof(uint32_t));
				last_arp++;
				while (!myqueue.empty()) {
					packet newPacket = myqueue.front();
					myqueue.pop();
					struct ether_header *eth_hdr = (struct ether_header *)newPacket.payload;
					struct iphdr *ip_hdr = (struct iphdr *)(newPacket.payload + sizeof(struct ether_header));
					struct icmphdr *icmp_hdr = (struct icmphdr *)(newPacket.payload +  sizeof(struct ether_header) + sizeof(struct iphdr));
					struct route_table *rTable = get_best_route(ip_hdr->daddr, rT, rTable_size, 0, rTable_size - 1);
					
					// Update the ttl and checksums
					ip_hdr->ttl--;
					ip_hdr->check = defValue;
					ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

					icmp_hdr->checksum = defValue;
					icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof(struct icmphdr));
					icmp_hdr->un.echo.sequence = htons(secvence);
					// Send the packet
					secvence++;
					get_interface_mac(newPacket.interface, eth_hdr->ether_shost);
					memcpy(eth_hdr->ether_dhost, arp_hdr->arp_sha, macLength * sizeof(uint8_t));
					send_packet(rTable->interface, &newPacket);
				}
			}
		}
	}
	delete[] rT;
	delete[] arp_table;
}
