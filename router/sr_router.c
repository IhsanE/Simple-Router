/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/
/* This is in BITS */
#define ICMP_PACKET_SIZE 64

void sr_init(struct sr_instance* sr)
{
		/* REQUIRES */
		assert(sr);

		/* Initialize cache and cache cleanup thread */
		sr_arpcache_init(&(sr->cache));

		pthread_attr_init(&(sr->attr));
		pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
		pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
		pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
		pthread_t thread;

		pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
		
		/* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

int arp_cache_check_add_queue_remove (struct sr_arpcache *cache, unsigned char *mac, uint32_t ip) {
	/* Look up request in cache
	struct sr_arpentry * arp_cache_lookup_result = sr_arpcache_lookup(cache, ip);
	
	 DO WE SKIP ADDING TO CACHE IF IT'S ALREADY THERE?
	if (arp_cache_lookup_result != NULL) {
		free(arp_cache_lookup_result);
	} 
	*/

	/* Add to cache */
	struct sr_arpreq * arp_queue_req = sr_arpcache_insert(
		cache,
		mac,
		ip
	);

	/* In queue, delete */
	if (arp_queue_req != NULL) {
		sr_arpreq_destroy(cache, arp_queue_req);
	}

	return 0;
}

struct sr_rt * longest_prefix_match(struct sr_instance* sr, uint8_t * packet) {
	sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	uint32_t ipaddr = ip_header->ip_dst;;
	struct sr_rt *ptr;
	uint32_t masked_ip;
	uint32_t bestmask = 0;
	uint32_t curmask = 0;
	struct sr_rt *lm_ptr = NULL;

	for(ptr=sr->routing_table ; ptr != NULL ; ptr = ptr->next) {
		masked_ip = ipaddr & (ptr->mask).s_addr;
		curmask = (ptr->mask).s_addr;

		if (masked_ip == (ptr->dest).s_addr) {
			if(bestmask != -1 && (curmask > bestmask || curmask == -1)) {
				lm_ptr = ptr;
				bestmask = curmask;
			}
		}
	}
	if(lm_ptr == NULL) {
		return NULL;
	}
	return lm_ptr;
}

void handle_ip_packets_for_us(struct sr_instance* sr, uint8_t * packet, unsigned int len) {
	struct sr_rt * routing_entry = longest_prefix_match(sr, packet);
	struct sr_arpentry * arp_entry = arp_cache_contains_entry(sr, routing_entry);
	if (arp_entry) {
		forward_packet(sr, packet, len, routing_entry->interface, arp_entry->mac);
		free(arp_entry);
	} else {
		sr_arpcache_queuereq(
			&(sr->cache),
			routing_entry->gw.s_addr,
			packet,
			len,
			routing_entry->interface
		);
	}
}

/* Modify packet in place; returns reply packet */
void arp_reply(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
	sr_ethernet_hdr_t * ethernet_header = (sr_ethernet_hdr_t *)packet;
	sr_arp_hdr_t * arp_header = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	struct sr_if * interface_struct = sr_get_interface(sr, interface);
	/* 
		 Set ARP op_code -> reply
		 Set ARP target ip to source ip
		 Set ARP source ip to our ip (from interface)
	*/

	arp_header->ar_op = htons(arp_op_reply);
	arp_header->ar_tip = arp_header->ar_sip;
	arp_header->ar_sip = interface_struct->ip;

	/* Reconfigure ARP src/dest targets */
	memcpy(
		arp_header->ar_tha,
		arp_header->ar_sha,
		sizeof(unsigned char)*ETHER_ADDR_LEN
	);

	memcpy(
		arp_header->ar_sha,
		interface_struct->addr,
		sizeof(unsigned char)*ETHER_ADDR_LEN
	);

	/* Swap Ethernet dest/src addrs */
	memcpy(
		ethernet_header->ether_dhost,
		ethernet_header->ether_shost,
		sizeof(uint8_t)*ETHER_ADDR_LEN
	);

	memcpy(
		ethernet_header->ether_shost,
		interface_struct->addr,
		sizeof(uint8_t)*ETHER_ADDR_LEN
	);
	sr_send_packet(sr, packet, len, interface);
}

int is_arp_reply_for_us(struct sr_instance* sr, uint8_t * packet) {
	struct sr_if * if_list = sr->if_list;
	sr_arp_hdr_t * arp_header = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	while(if_list) {
		if (ntohs(if_list->ip) == ntohs(arp_header->ar_tip)) {
			return 1;
		}
		if_list = if_list->next;
	}
	return 0;
}

int is_ip_packet_matches_interfaces(struct sr_instance* sr, uint8_t * packet) {
	struct sr_if * if_list = sr->if_list;
	sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	while(if_list) {
		if (if_list->ip == ip_header->ip_dst) {
			return 1;
		}
		if_list = if_list->next;
	}
	return 0;
}

int is_ttl_valid(uint8_t * packet) {
	sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	return ip_header->ip_ttl > 1;
}

void modify_send_icmp(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, uint8_t type, uint8_t code) {
	/*sr_ethernet_hdr_t * ethernet_header = (sr_ethernet_hdr_t *)packet;*/
	sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	sr_icmp_t11_hdr_t * icmp_header = (sr_icmp_t11_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	struct sr_if * interface_struct = sr_get_interface(sr, interface);

	/* Update ICMP header */
	icmp_header->icmp_type = type;
	icmp_header->icmp_code = code;
	if (code == (uint8_t) 0 && type == (uint8_t) 11) {
		icmp_header->unused = (uint32_t) 0;

		memcpy(
			icmp_header->data,
			ip_header,
			ICMP_DATA_SIZE
		);
	}
	icmp_header->icmp_sum = 0; 
	icmp_header->icmp_sum = cksum(icmp_header, len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))); 

	/* Update IP header */
	ip_header->ip_ttl = INIT_TTL;
	uint32_t original_src = ip_header->ip_src;
	ip_header->ip_src = ip_header->ip_dst;
	if (code == (uint8_t) 0 && type == (uint8_t) 11) {
		ip_header->ip_src = interface_struct->ip;
	}
	ip_header->ip_dst = original_src;
	/*
	ip_header->ip_sum = 0;
	ip_header->ip_sum = cksum(ip_header, ip_header->ip_hl*4);
	*/
	
	/* Swap Ethernet dest/src addrs
	memcpy(
		ethernet_header->ether_dhost,
		ethernet_header->ether_shost,
		sizeof(uint8_t)*ETHER_ADDR_LEN
	);

	memcpy(
		ethernet_header->ether_shost,
		interface_struct->addr,
		sizeof(uint8_t)*ETHER_ADDR_LEN
	);
	*/
	handle_ip_packets_for_us(sr, packet, len);
	/* sr_send_packet(sr, packet, len, interface); */
}

void modify_send_icmp_reply(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
	modify_send_icmp(sr, packet, len, interface, (uint8_t) 0, (uint8_t) 0);
}

void modify_send_icmp_time_exceeded(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
	modify_send_icmp(sr, packet, len, interface, (uint8_t) 11, (uint8_t) 0);
}

void modify_send_icmp_type3(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, uint8_t code) {
	struct sr_packet * new_packet = (struct sr_packet*)malloc(sizeof(struct sr_packet));
	new_packet->buf = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
	new_packet->len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

	memset(new_packet->buf, 0, new_packet->len);

	/*sr_ethernet_hdr_t * old_ethernet_header = (sr_ethernet_hdr_t *)packet;*/
	sr_ip_hdr_t * old_ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));


	sr_ethernet_hdr_t * ethernet_header = (sr_ethernet_hdr_t *)new_packet->buf;
	sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(new_packet->buf + sizeof(sr_ethernet_hdr_t));

	sr_icmp_t3_hdr_t * type3_icmp_header = (sr_icmp_t3_hdr_t *)(new_packet->buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	struct sr_if * interface_struct = sr_get_interface(sr, interface);
	
	/* Update ICMP header */
	type3_icmp_header->icmp_type = (uint8_t) 3;
	type3_icmp_header->icmp_code = code;
	type3_icmp_header->unused = (uint16_t) 0;
	type3_icmp_header->next_mtu = (uint16_t) 1500;
	type3_icmp_header->icmp_sum = (uint16_t) 0;
	
	/* IP Header + first 8 bytes */
	memcpy(
		type3_icmp_header->data,
		old_ip_header,
		ICMP_DATA_SIZE
	);
	type3_icmp_header->icmp_sum = cksum(type3_icmp_header, sizeof(sr_icmp_t3_hdr_t)); 

	/* Set fields in IP header */
	ip_header->ip_hl = old_ip_header->ip_hl;
	ip_header->ip_v = old_ip_header->ip_v;
	ip_header->ip_tos = old_ip_header->ip_tos;
	ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
	ip_header->ip_id = 0;
	ip_header->ip_off = old_ip_header->ip_off;
	ip_header->ip_ttl = INIT_TTL;
	ip_header->ip_p = (uint8_t) 1;
	if (code == (uint8_t) 3) {
		ip_header->ip_src = old_ip_header->ip_dst;  
	}
	else if (code == (uint8_t) 0) {
		ip_header->ip_src = interface_struct->ip;
	}
	/* JUST MAKE THIS AN ELSE IF ITS NOT DIFFERENT */
	else {
		ip_header->ip_src = interface_struct->ip;
	}
	ip_header->ip_dst = old_ip_header->ip_src;
	/*
	ip_header->ip_sum = 0;
	ip_header->ip_sum = cksum(ip_header, ip_header->ip_hl*4);
	*/
	/* Swap Ethernet dest/src addrs */
	/*
	memcpy(
		ethernet_header->ether_dhost,
		old_ethernet_header->ether_shost,
		sizeof(uint8_t)*ETHER_ADDR_LEN
	);

	memcpy(
		ethernet_header->ether_shost,
		interface_struct->addr,
		sizeof(uint8_t)*ETHER_ADDR_LEN
	);*/

	ethernet_header->ether_type = htons(ethertype_ip);
	packet = new_packet->buf;
	handle_ip_packets_for_us(sr, packet, new_packet->len);
	/* sr_send_packet(sr, packet, len, interface); */
}

void modify_send_icmp_port_unreachable(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
	modify_send_icmp_type3(sr, packet, len, interface, (uint8_t) 3);  
}

void modify_send_icmp_net_unreachable(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
	modify_send_icmp_type3(sr, packet, len, interface, (uint8_t) 0);  
}

void modify_send_icmp_host_unreachable(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
	modify_send_icmp_type3(sr, packet, len, interface, (uint8_t) 1);  
}

int handle_icmp(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
	sr_icmp_hdr_t * icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	uint8_t request = 8;
	uint8_t reply = 0;
	uint8_t unreachable = 3;
	uint8_t time_exceeded = 11;

	if (icmp_header->icmp_type == request) {
		modify_send_icmp_reply(sr, packet, len, interface);
	} else if (icmp_header->icmp_type == reply) {
	} else if (icmp_header->icmp_type == unreachable) {
	} else if (icmp_header->icmp_type == time_exceeded) {
	}
	return 0;
}

int handle_ip_for_us(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
	sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	if (ip_header->ip_p == ip_protocol_icmp){
		sr_icmp_hdr_t * icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		uint16_t original_checksum = icmp_header->icmp_sum;  
		icmp_header->icmp_sum = (uint16_t) 0;
		uint16_t check_sum = cksum(icmp_header, len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
		if (check_sum == original_checksum) {
			handle_icmp(sr, packet, len, interface);
		}
		return 0;
	} else {
		modify_send_icmp_port_unreachable(sr, packet, len, interface);
	}
	return 0;
}

int is_ip_checksum_valid (uint8_t * packet) {
	sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	uint16_t original_checksum = ip_header->ip_sum;
	ip_header->ip_sum = (uint16_t) 0;
	uint16_t check_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
	ip_header->ip_sum = original_checksum;
	if (check_sum == original_checksum) {
		return 1;
	}
	return 0;
}

struct sr_arpentry * arp_cache_contains_entry(struct sr_instance* sr, struct sr_rt * entry) {
	struct sr_arpcache *cache = &(sr->cache);
	return sr_arpcache_lookup(cache, entry->gw.s_addr);
}

void forward_packet(
	struct sr_instance* sr,
	uint8_t * packet,
	unsigned int len,
	char* interface,
	unsigned char * dest_mac) {

	sr_ethernet_hdr_t * ethernet_header = (sr_ethernet_hdr_t *)packet;
	sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

	struct sr_if* interface_to_send_from = sr_get_interface(sr, interface);


	/* Update IP header */
	/*if (ip_header->ip_ttl != INIT_TTL) {*/
		/*ip_header->ip_ttl--;
		ip_header->ip_sum = 0;
		ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));*/
	/*}*/

	/* Swap Ethernet dest/src addrs */
	memcpy(
		ethernet_header->ether_dhost,
		dest_mac,
		sizeof(uint8_t)*ETHER_ADDR_LEN
	);

	memcpy(
		ethernet_header->ether_shost,
		interface_to_send_from->addr,
		sizeof(uint8_t)*ETHER_ADDR_LEN
	);
	ip_header->ip_sum = 0;
	ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
	print_hdrs(packet, len);
	sr_send_packet(sr, packet, len, interface);
}

void send_arp_req_packets(struct sr_instance* sr, struct sr_arpreq * req, unsigned char * dest_mac) {
	struct sr_packet * head = req->packets;
	while (head) {
			sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(head->buf + sizeof(sr_ethernet_hdr_t));
			if (ip_header->ip_ttl != INIT_TTL) {
				ip_header->ip_ttl--;
			}
			forward_packet(sr, head->buf, head->len, head->iface, dest_mac);
			head = head->next;
	}
	sr_arpreq_destroy(&(sr->cache), req);
	return;
}

void sr_handlepacket(struct sr_instance* sr,
				uint8_t * packet/* lent */,
				unsigned int len,
				char* interface/* lent */)
{
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);
	sr_ethernet_hdr_t * ethernet_header = (sr_ethernet_hdr_t *)packet;
	if (ntohs(ethernet_header->ether_type) == ethertype_arp) {
		sr_arp_hdr_t * arp_header = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

		/* ARP REQUEST */
		if (ntohs(arp_header->ar_op) == arp_op_request) {
			/*
				1) If ARP Request in Cache, add it anyway
				2) If ARP Request not in Cache, add it, remove from queue if was in queue
			*/
			arp_cache_check_add_queue_remove(
				&(sr->cache),
				arp_header->ar_sha,
				arp_header->ar_sip
			);

			arp_reply(sr, packet, len, interface);
		/* ARP REPLY */
		} else {
			if (is_arp_reply_for_us(sr, packet) != 0) {
				struct sr_arpreq * req = sr_arpcache_insert(
					&(sr->cache),
					arp_header->ar_sha,
					arp_header->ar_sip
				);
				if (req) {
					send_arp_req_packets(sr, req, arp_header->ar_sha);
				}
			}
		}
	} else {
		if (is_ip_checksum_valid(packet)) {
			/* FOR US */
			if (is_ip_packet_matches_interfaces(sr, packet)) {
				/* Nat DISABLED */
				if (sr->nat != NULL) {
					handle_ip_for_us(sr, packet, len, interface);
				}

				/* Nat ENABLED */
				else {

					/* INTERNAL 10.0.1.1, respond as before : handle_ip_for_us(sr, packet, len, interface); */
					if (strcmp(interface, "eth1") == 0) {
						handle_ip_for_us(sr, packet, len, interface);		
					}
					/* EXTERNAL 172.64.3.1, check if in mappings */

						/* IN: route */
						/* OUT: drop */
					sr_icmp_t8_hdr_t * icmp_header = (sr_icmp_t8_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
					sr_nat_mapping *external_mapping = sr_nat_lookup_external(sr->nat, icmp_header->icmp_id, nat_mapping_icmp);
					if (external_mapping) {
						/* forward to internal host */
						free(external_mapping);
					}
					/*ELSE: DROP*/
				}
			/* FORWARD */
			} else {
				/*
					1) Check ttl > 1
					3) Longest Prefix Match
						3.i) MATCH -> Forward
						3.ii)NO MATCH -> Send Arp Req, add to req queue
				*/
				if (!is_ttl_valid(packet)) {
					modify_send_icmp_time_exceeded(sr, packet, len, interface);
					return;
				}

				struct sr_rt * routing_entry = longest_prefix_match(sr, packet);
				if (routing_entry) {
					struct sr_arpentry * arp_entry = arp_cache_contains_entry(sr, routing_entry);
					if (arp_entry) {
						sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
						ip_header->ip_ttl--;
						forward_packet(sr, packet, len, routing_entry->interface, arp_entry->mac);
						free(arp_entry);
					} else {
						sr_arpcache_queuereq(
							&(sr->cache),
							routing_entry->gw.s_addr,
							packet,
							len,
							routing_entry->interface
						);
					}
					return;
				} else {
					modify_send_icmp_net_unreachable(sr, packet, len, interface);
					/* Drop packet because no entry found in routing table */ 
				}
			}
		}
	}


}/* end sr_ForwardPacket */
