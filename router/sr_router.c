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
#include "sr_nat.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

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
	/* make a copy of the packet to pass to the functions */
	uint8_t * packet_copy = (uint8_t *)malloc(sizeof(uint8_t) * len);
	memcpy(packet_copy, packet, len);
	if (ntohs(ethernet_header->ether_type) == ethertype_arp) {
		sr_handle_arp_packet(sr, packet_copy, len, interface);
	} else {
		sr_handle_ip_packet(sr, packet_copy, len, interface);
	}
	free(packet_copy);
}

void sr_handle_arp_packet(struct sr_instance* sr,
				uint8_t * packet/* lent */,
				unsigned int len,
				char* interface/* lent */)
{
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

	set_arp_sha_tha(arp_header, interface_struct->addr, arp_header->ar_sha);

	/* Swap Ethernet dest/src addrs */
	set_ethernet_src_dst(ethernet_header, interface_struct->addr, ethernet_header->ether_shost);

	sr_send_packet(sr, packet, len, interface);
}

void sr_handle_ip_packet(struct sr_instance* sr,
				uint8_t * packet/* lent */,
				unsigned int len,
				char* interface/* lent */)
{
	if (is_ip_checksum_valid(packet)) {
		/* FOR US */
		if (is_ip_packet_matches_interfaces(sr, packet)) {
				/* Nat DISABLED */
			if (sr->nat == NULL) {
				handle_ip_for_us(sr, packet, len, interface);
			}

			/* Nat ENABLED */
			else {

				/* INTERNAL 10.0.1.1, respond as before : handle_ip_for_us(sr, packet, len, interface); */
				sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
				if (strcmp(interface, "eth1") == 0) {
					handle_ip_for_us(sr, packet, len, interface);
					return;
				}

				if (ip_header->ip_p == ip_protocol_icmp) {
					/* EXTERNAL 172.64.3.1, check if in mappings */

						/* IN: route */
						/* OUT: drop */
					sr_icmp_t8_hdr_t * icmp_header = (sr_icmp_t8_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
					struct sr_nat_mapping *external_mapping = sr_nat_lookup_external(sr->nat, icmp_header->icmp_id, nat_mapping_icmp);
					/* forward to internal host */
					if (external_mapping) {

						/* Change dest IP and icmp id*/
						icmp_header->icmp_id = external_mapping->aux_int;
						ip_header->ip_dst = external_mapping->ip_int;
						icmp_header->icmp_sum = 0;
						icmp_header->icmp_sum = cksum(icmp_header, len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
						forwarding_logic(sr, packet, len, interface);
						free(external_mapping);
					}
					/*ELSE: DROP*/
				} else if (ip_header->ip_p == ip_protocol_tcp) {
					printf("TCP PACKET ADDRESSED TO ME\n");
					/* external server sent packet for us */
					/* check mappings */
					sr_tcp_hdr_t * tcp_header = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
					struct sr_nat_mapping *external_mapping = sr_nat_lookup_external(sr->nat, tcp_header->dest_port, nat_mapping_tcp);

					if (external_mapping) {
						/* check if there is a connection */
						struct sr_nat_connection* connection = sr_nat_get_connection(sr->nat, external_mapping, ip_header->ip_src, tcp_header->src_port);

						if (connection) {
							/* if SYN (from server) */
							if ((ntohs(tcp_header->flags) & tcp_flag_syn) == tcp_flag_syn) {
								sr_nat_update_connection_state(sr->nat, external_mapping, ip_header->ip_src, tcp_header->src_port, tcp_state_syn_sent, tcp_state_syn_recv);
								/* if syn_sent */
	/*							if (connection->state == tcp_state_syn_sent) {
									 set state to syn_recv
									connection->state = tcp_state_syn_recv;
								}
	*/							tcp_header->dest_port = external_mapping->aux_int;
								/*tcp_header->flags = ((20<<12) | (tcp_header->flags)); */

								ip_header->ip_dst = external_mapping->ip_int;

								set_tcp_checksum(packet, len);
								forwarding_logic(sr, packet, len, interface);
							} else {
								/* forward? */
								tcp_header->dest_port = external_mapping->aux_int;

								ip_header->ip_dst = external_mapping->ip_int;
								set_tcp_checksum(packet, len);
								forwarding_logic(sr, packet, len, interface);
							}
							/* if FIN ACK */
							free(connection);
						} else {
							/* forward? */
							sr_nat_insert_tcp_connection(sr->nat, external_mapping, ip_header->ip_src, tcp_header->src_port);
							tcp_header->dest_port = external_mapping->aux_int;

							ip_header->ip_dst = external_mapping->ip_int;
							set_tcp_checksum(packet, len);
							forwarding_logic(sr, packet, len, interface);
						}

						free(external_mapping);

					} else {
						/* UNSOLICITED */
						if (tcp_header->dest_port == htons(22)) {
							modify_send_icmp_port_unreachable(sr, packet, len, interface);
						}
						/* else */
							/* check if SYN flag is set */
							/* if SYN */
								/* wait 6 seconds */
								/* if client sends SYN for this connection, then drop this packet */
								/* else */
									/* send port unreachable for original packet */
							/* else */
								/* drop packet*/
						else {
							if ((ntohs(tcp_header->flags) & tcp_flag_syn) == tcp_flag_syn && tcp_header->dest_port >= 1024) {
								struct sr_possible_connection *new_conn = (struct sr_possible_connection *)malloc(sizeof(struct sr_possible_connection));
								new_conn->ip = ip_header->ip_src;
								new_conn->port = tcp_header->dest_port;
								new_conn->recv_time = time(NULL);
								new_conn->unsolicited_packet = packet;
								new_conn->len = len;
								new_conn->interface = interface;
								new_conn->next = sr->nat->possible_conns;
								sr->nat->possible_conns = new_conn;
							} else {
								modify_send_icmp_port_unreachable(sr, packet, len, interface);
							}
						}
					}
				}
			}
		/* FORWARD */
		} else {
			/*
				1) Check ttl > 1
				3) Longest Prefix Match
					3.i) MATCH -> Forward
					3.ii)NO MATCH -> Send Arp Req, add to req queue
			*/

			/* NAT DISABLED */
			if (sr->nat == NULL) {
				forwarding_logic(sr, packet, len, interface);
			}

			/* NAT ENABLED */
			else {
				if (!is_ttl_valid(packet)) {
					send_icmp_time_exceeded(sr, packet, len, interface);
					return;
				}
				struct sr_rt * routing_entry = longest_prefix_match(sr, packet);
				if (routing_entry) {
						sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
						/* We found a match in the routing table */
						if (ip_header->ip_p == ip_protocol_icmp) {
							sr_icmp_t8_hdr_t * icmp_header = (sr_icmp_t8_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
							struct sr_nat_mapping *mapping = sr_nat_insert_mapping(sr->nat, ip_header->ip_src, icmp_header->icmp_id, nat_mapping_icmp);
							icmp_header->icmp_id = htons(mapping->aux_ext);
							ip_header->ip_src = mapping->ip_ext;
							icmp_header->icmp_sum = 0;
							icmp_header->icmp_sum = cksum(icmp_header, len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
							handle_send_to_next_hop_ip(sr, packet, len, routing_entry);
						}

						else if (ip_header->ip_p == ip_protocol_tcp) {
							/*RECEIVED TCP PACKET TO FORWARD*/
							printf("I RECEIVED A TCP PACKET TO FORWARD\n");
							print_addr_ip_int(ip_header->ip_dst);
/*
				  		sr_tcp_hdr_t * tcp_header = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
							sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

									struct sr_nat_mapping *mapping = sr_nat_insert_mapping(sr->nat, ip_header->ip_src, icmp_header->icmp_id, nat_mapping_icmp);
						icmp_header->icmp_id = mapping->aux_ext;
						ip_header->ip_src = htonl(mapping->ip_ext);
							handle_send_to_next_hop_ip(sr, packet, len, routing_entry);*/
							handle_tcp_packet_from_int(sr, packet, len, interface, routing_entry);
						}
				} else {
					/* didn't find match, need to send net unreachable */
					modify_send_icmp_net_unreachable(sr, packet, len, interface);
					/* Drop packet because no entry found in routing table */
				}
			}
		}
	}
}
void set_tcp_checksum(uint8_t * packet, unsigned int len) {
	sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	sr_tcp_hdr_t * tcp_header = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	sr_tcp_pseudo_hdr_t * pseudo_hdr = (sr_tcp_pseudo_hdr_t *) malloc(sizeof(sr_tcp_pseudo_hdr_t));
	void * checksum_struct = malloc(len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) + sizeof(sr_tcp_pseudo_hdr_t));

	pseudo_hdr->ip_src = ip_header->ip_src;
	pseudo_hdr->ip_dst = ip_header->ip_dst;
	pseudo_hdr->reserved = 0;
	pseudo_hdr->protocol = ip_header->ip_p;
	pseudo_hdr->segment_len = htons(len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
	tcp_header->checksum = 0;

	memcpy(
		checksum_struct,
		pseudo_hdr,
		sizeof(sr_tcp_pseudo_hdr_t)
		);
	memcpy(
		checksum_struct + sizeof(sr_tcp_pseudo_hdr_t),
		tcp_header,
		len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))
		);
	tcp_header->checksum = cksum(checksum_struct, len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) + sizeof(sr_tcp_pseudo_hdr_t));
	free(checksum_struct);
}
void handle_tcp_packet_from_int(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, struct sr_rt * routing_entry) {
	sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	sr_tcp_hdr_t * tcp_header = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

	struct sr_nat_mapping *internal_mapping = sr_nat_lookup_internal(sr->nat, ip_header->ip_src, tcp_header->src_port, nat_mapping_tcp);

	if (internal_mapping == NULL) {
		internal_mapping = sr_nat_insert_mapping(sr->nat, ip_header->ip_src, tcp_header->src_port, nat_mapping_tcp);
	}

	struct sr_nat_connection* connection = sr_nat_get_connection(sr->nat, internal_mapping, ip_header->ip_dst, tcp_header->dest_port);

	if (connection) {
		if ((ntohs(tcp_header->flags) & tcp_flag_ack) == tcp_flag_ack) {
			sr_nat_update_connection_state(sr->nat, internal_mapping, ip_header->ip_dst, tcp_header->dest_port, tcp_state_syn_recv, tcp_state_established);
		} else if ((ntohs(tcp_header->flags) & tcp_flag_syn) == tcp_flag_syn) {
			sr_nat_update_connection_state(sr->nat, internal_mapping, ip_header->ip_dst, tcp_header->dest_port, tcp_state_syn_listen, tcp_state_syn_sent);
		}
		else if (tcp_header->flags == 0) {
			/* need to check if there is a connection, if so, forward it*/
			if (connection->state != tcp_state_established) {
				free(connection);
				return;
			}
		}
		free(connection);
		/* if FIN ACK */
	} else {		

		if ((ntohs(tcp_header->flags) & tcp_flag_syn) == tcp_flag_syn) {
			/* go through possible connections */
			struct sr_possible_connection *curr_conn = sr->nat->possible_conns;
			struct sr_possible_connection *prev_conn = NULL;
			while(curr_conn) {
				if (curr_conn->port == internal_mapping->aux_ext &&
					curr_conn->ip == ip_header->ip_dst) {
					if (prev_conn) {
						prev_conn->next = curr_conn->next;
					} else {
						sr->nat->possible_conns = curr_conn->next;
					}
					free(curr_conn);
					break;
				}
				curr_conn = curr_conn->next;
			}
			sr_nat_insert_tcp_connection(sr->nat, internal_mapping, ip_header->ip_dst, tcp_header->dest_port);
		}
		sr_nat_get_connection(sr->nat, internal_mapping, ip_header->ip_dst, tcp_header->dest_port);


	}
	tcp_header->src_port = htons(internal_mapping->aux_ext);
	/*tcp_header->flags = ((20<<12) | (tcp_header->flags));*/
	ip_header->ip_src = internal_mapping->ip_ext;
	set_tcp_checksum(packet, len);
	forwarding_logic(sr, packet, len, interface);

	free(internal_mapping);
}

/* Check if we have a match for the next hop IP of this routing entry in
our arpcache. If we do, just forward the packet to that MAC address, otherwise
we need to send an arprequest, and put this packet on the queue. */
void handle_send_to_next_hop_ip(struct sr_instance* sr,
	uint8_t * packet,
	unsigned int len,
	struct sr_rt * routing_entry)
{
	struct sr_arpentry * arp_entry = arp_cache_contains_entry(sr, routing_entry);
	if (arp_entry) {
		/* we found a match in the cache, can just forward the packet there */
		sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
		ip_header->ip_ttl--;
		forward_packet(sr, packet, len, routing_entry->interface, arp_entry->mac);
		free(arp_entry);
	} else {
		/* didn't find match in the cache, need to send an arp request for this */
		sr_arpcache_queuereq(
			&(sr->cache),
			routing_entry->gw.s_addr,
			packet,
			len,
			routing_entry->interface
		);
	}
}

int arp_cache_check_add_queue_remove (struct sr_arpcache *cache, unsigned char *mac, uint32_t ip) {
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
	struct sr_rt *routing_table = sr->routing_table;

	struct sr_rt* matching = NULL;

    while(routing_table) {
        if((routing_table->dest.s_addr & routing_table->mask.s_addr) == (ip_header->ip_dst & routing_table->mask.s_addr)){
            if(matching == NULL || routing_table->mask.s_addr > matching->mask.s_addr)
                matching = routing_table;
        }
        routing_table = routing_table->next;
    }

    return matching;
}

void set_ethernet_src_dst(sr_ethernet_hdr_t * ethernet_header, uint8_t * new_src, uint8_t * new_dst) {
	/* Swap Ethernet dest/src addrs */
	memcpy(
		ethernet_header->ether_dhost,
		new_dst,
		sizeof(uint8_t)*ETHER_ADDR_LEN
	);

	memcpy(
		ethernet_header->ether_shost,
		new_src,
		sizeof(uint8_t)*ETHER_ADDR_LEN
	);
}

void set_arp_sha_tha(sr_arp_hdr_t * arp_header, unsigned char * new_sha, unsigned char * new_tha) {
	/* Reconfigure ARP src/dest targets */
	memcpy(
		arp_header->ar_tha,
		new_tha,
		sizeof(unsigned char)*ETHER_ADDR_LEN
	);

	memcpy(
		arp_header->ar_sha,
		new_sha,
		sizeof(unsigned char)*ETHER_ADDR_LEN
	);
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

int check_ip_in_if_list(struct sr_instance* sr, uint32_t ip) {
	struct sr_if * if_list = sr->if_list;
	while(if_list) {
		if (if_list->ip == ip) {
			return 1;
		}
		if_list = if_list->next;
	}
	return 0;
}

int is_arp_reply_for_us(struct sr_instance* sr, uint8_t * packet) {
	sr_arp_hdr_t * arp_header = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	return check_ip_in_if_list(sr, arp_header->ar_tip);
}

int is_ip_packet_matches_interfaces(struct sr_instance* sr, uint8_t * packet) {
	sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	return check_ip_in_if_list(sr, ip_header->ip_dst);
}

int is_ttl_valid(uint8_t * packet) {
	sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	return ip_header->ip_ttl > 1;
}

void modify_send_icmp(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, uint8_t type, uint8_t code) {
	sr_ethernet_hdr_t * ethernet_header = (sr_ethernet_hdr_t *)packet;
	sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
	sr_icmp_hdr_t * icmp_header = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

	/* Update ICMP header */
	icmp_header->icmp_type = type;
	icmp_header->icmp_code = code;
	icmp_header->icmp_sum = 0;
	icmp_header->icmp_sum = cksum(icmp_header, len - (sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));

	/* Update IP header */
	ip_header->ip_ttl = INIT_TTL;
	uint32_t original_src = ip_header->ip_src;
	ip_header->ip_src = ip_header->ip_dst;
	ip_header->ip_len = htons(len - (sizeof(sr_ethernet_hdr_t)));
	ip_header->ip_p = (uint8_t) 1;
	ip_header->ip_dst = original_src;

	ethernet_header->ether_type = htons(ethertype_ip);
	handle_ip_packets_for_us(sr, packet, len);
	/* sr_send_packet(sr, packet, len, interface); */
}

void put_ip_header_in_icmp_data(uint8_t * data, sr_ip_hdr_t * ip_header) {
	/* IP Header + first 8 bytes */
	memcpy(
		data,
		ip_header,
		ICMP_DATA_SIZE
	);
}

void set_ip_header_fields_new_icmp(sr_ip_hdr_t * ip_header, sr_ip_hdr_t * old_ip_header, size_t icmp_size) {
	ip_header->ip_hl = old_ip_header->ip_hl;
	ip_header->ip_v = old_ip_header->ip_v;
	ip_header->ip_tos = old_ip_header->ip_tos;
	ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + icmp_size);
	ip_header->ip_id = 0;
	ip_header->ip_off = old_ip_header->ip_off;
	ip_header->ip_ttl = INIT_TTL;
	ip_header->ip_p = (uint8_t) 1;

}
void send_new_icmp_type11(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
	struct sr_packet * new_packet = (struct sr_packet*)malloc(sizeof(struct sr_packet));
	new_packet->buf = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
	new_packet->len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

	memset(new_packet->buf, 0, new_packet->len);

	/*sr_ethernet_hdr_t * old_ethernet_header = (sr_ethernet_hdr_t *)packet;*/
	sr_ip_hdr_t * old_ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

	sr_ethernet_hdr_t * ethernet_header = (sr_ethernet_hdr_t *)new_packet->buf;
	sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(new_packet->buf + sizeof(sr_ethernet_hdr_t));

	sr_icmp_t11_hdr_t * type11_icmp_header = (sr_icmp_t11_hdr_t *)(new_packet->buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	struct sr_if * interface_struct = sr_get_interface(sr, interface);

	put_ip_header_in_icmp_data(type11_icmp_header->data, old_ip_header);

	set_fields_in_icmp_type11_header(type11_icmp_header);

	set_ip_header_fields_new_icmp(ip_header, old_ip_header, sizeof(sr_icmp_t11_hdr_t));

	ip_header->ip_src = interface_struct->ip;
	ip_header->ip_dst = old_ip_header->ip_src;

	ethernet_header->ether_type = htons(ethertype_ip);
	handle_ip_packets_for_us(sr, new_packet->buf, new_packet->len);
	free(new_packet->buf);
	free(new_packet);
}

void set_fields_in_icmp_type11_header(sr_icmp_t11_hdr_t * type11_icmp_header) {
	type11_icmp_header->icmp_type = (uint8_t) 11;
	type11_icmp_header->icmp_code = (uint8_t) 0;
	type11_icmp_header->unused = (uint32_t) 0;
	type11_icmp_header->icmp_sum = (uint16_t) 0;

	type11_icmp_header->icmp_sum = cksum(type11_icmp_header, sizeof(sr_icmp_t11_hdr_t));
}

void modify_send_icmp_reply(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
	modify_send_icmp(sr, packet, len, interface, (uint8_t) 0, (uint8_t) 0);
}

void send_icmp_time_exceeded(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
	send_new_icmp_type11(sr, packet, len, interface);
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

	put_ip_header_in_icmp_data(type3_icmp_header->data, old_ip_header);

	type3_icmp_header->icmp_sum = cksum(type3_icmp_header, sizeof(sr_icmp_t3_hdr_t));

	set_ip_header_fields_new_icmp(ip_header, old_ip_header, sizeof(sr_icmp_t3_hdr_t));

	if (code == (uint8_t) 3) {
		ip_header->ip_src = old_ip_header->ip_dst;
	} else {
		ip_header->ip_src = interface_struct->ip;
	}
	ip_header->ip_dst = old_ip_header->ip_src;

	ethernet_header->ether_type = htons(ethertype_ip);
	handle_ip_packets_for_us(sr, new_packet->buf, new_packet->len);
	free(new_packet->buf);
	free(new_packet);
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
	/*uint8_t reply = 0;
	uint8_t unreachable = 3;
	uint8_t time_exceeded = 11;*/

	if (icmp_header->icmp_type == request) {
		modify_send_icmp_reply(sr, packet, len, interface);
	}
	/* we don't handle the other types */
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

	set_ethernet_src_dst(ethernet_header, interface_to_send_from->addr, dest_mac);

	ip_header->ip_sum = 0;
	ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
	sr_send_packet(sr, packet, len, interface);
}

void forward_packet_nat_in(
	struct sr_instance* sr,
	uint8_t * packet,
	unsigned int len,
	char* interface,
	unsigned char * dest_mac,
	struct sr_nat_mapping* mapping) {

	sr_ethernet_hdr_t * ethernet_header = (sr_ethernet_hdr_t *)packet;
	sr_ip_hdr_t * ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

	struct sr_if* interface_to_send_from = sr_get_interface(sr, interface);
	sr_icmp_t8_hdr_t * icmp_header = (sr_icmp_t8_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

	/* Set ICMP ID to internal */
	icmp_header->icmp_id = mapping->aux_int;

	set_ethernet_src_dst(ethernet_header, interface_to_send_from->addr, dest_mac);

	ip_header->ip_dst = mapping->ip_int;
	ip_header->ip_sum = 0;
	ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
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

void forwarding_logic(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface) {
	if (!is_ttl_valid(packet)) {
		send_icmp_time_exceeded(sr, packet, len, interface);
		return;
	}
	struct sr_rt * routing_entry = longest_prefix_match(sr, packet);
	if (routing_entry) {
		/* We found a match in the routing table */
		handle_send_to_next_hop_ip(sr, packet, len, routing_entry);
	} else {
		/* didn't find match, need to send net unreachable */
		modify_send_icmp_net_unreachable(sr, packet, len, interface);
		/* Drop packet because no entry found in routing table */
	}
}
