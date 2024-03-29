
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_router.h"

int EXT_ID = 1;

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

	assert(nat);

	/* Acquire mutex lock */
	pthread_mutexattr_init(&(nat->attr));
	pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
	int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

	/* Initialize timeout thread */

	pthread_attr_init(&(nat->thread_attr));
	pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
	pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
	pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

	/* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

	nat->mappings = NULL;
	/* Initialize any variables here */

	return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

	pthread_mutex_lock(&(nat->lock));

	/* free nat memory here */

	pthread_kill(nat->thread, SIGKILL);
	return pthread_mutex_destroy(&(nat->lock)) &&
		pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
	struct sr_nat *nat = (struct sr_nat *)nat_ptr;
	while (1) {
		sleep(1.0);
		pthread_mutex_lock(&(nat->lock));

		time_t curtime = time(NULL);

		/* handle periodic tasks here */
		struct sr_nat_mapping *mapping = nat->mappings;
		struct sr_nat_mapping *to_free = NULL;
		struct sr_nat_mapping *prev = NULL;
		struct sr_nat_connection *conn = NULL;
		struct sr_nat_connection *conn_to_free = NULL;
		struct sr_nat_connection *prev_conn = NULL;

		while (mapping) {
			if (mapping->type == nat_mapping_icmp) {
				if (difftime(curtime,mapping->last_updated) > nat->icmpTimeout) {
					to_free = mapping;
					if (prev) {
						prev->next = mapping->next;
					} else {
						nat->mappings = mapping->next;
					}
					mapping = mapping->next;
					free(to_free);
				} else {
					prev = mapping;
					mapping = mapping->next;
				}
			} else if (mapping->type == nat_mapping_tcp) {
				conn = mapping->conns;
				prev_conn = NULL;
				while (conn) {
					if (conn->state == tcp_state_established) {
						if (difftime(curtime, conn->last_updated) >= nat->tcpEstablishedTimeout) {
							conn_to_free = conn;
							if (prev_conn) {
								prev_conn->next = conn->next;
							} else {
								mapping->conns = conn->next;
							}
							conn = conn->next;
							free(conn_to_free);
						} else {
							prev_conn = conn;
							conn = conn->next;
						}
					} else {
						if (difftime(curtime, conn->last_updated) >= nat->tcpTransitoryTimeout) {
							conn_to_free = conn;
							if (prev_conn) {
								prev_conn->next = conn->next;
							} else {
								mapping->conns = conn->next;
							}
							conn = conn->next;
							free(conn_to_free);
						} else {
							prev_conn = conn;
							conn = conn->next;
						}
					}
				}
				if (!(mapping->conns)) {
					to_free = mapping;
					if (prev) {
						prev->next = mapping->next;
					} else {
						nat->mappings = mapping->next;
					}
					mapping = mapping->next;
					free(to_free);
				} else {
					prev = mapping;
					mapping = mapping->next;
				}
			}
		}

		struct sr_possible_connection *p_conn = nat->possible_conns;
		struct sr_possible_connection *p_conn_to_free = NULL;
		struct sr_possible_connection *prev_p_conn = NULL;

		while (p_conn) {
			if (difftime(curtime,p_conn->recv_time) >= 6) {
				modify_send_icmp_port_unreachable(nat->sr_instance, p_conn->unsolicited_packet, p_conn->len, p_conn->interface);
				p_conn_to_free = p_conn;
				if (prev_p_conn) {
					prev_p_conn->next = p_conn->next;
				} else {
					nat->possible_conns = p_conn->next;
				}
				p_conn = p_conn->next;
				free(p_conn_to_free);
			} else {
				prev_p_conn = p_conn;
				p_conn = p_conn->next;
			}
		}	


		pthread_mutex_unlock(&(nat->lock));
	}
	return NULL;
}

/* Get the mapping associated with given external port.
	 You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
		uint16_t aux_ext, sr_nat_mapping_type type ) {

	pthread_mutex_lock(&(nat->lock));

	/* handle lookup here, malloc and assign to copy */
	struct sr_nat_mapping *copy = NULL;

	struct sr_nat_mapping *mapping = nat->mappings;

	while (mapping) {
		if ((mapping->type == type) && (mapping->aux_ext == ntohs(aux_ext))) {
			copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
			memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
			break;
		}
		mapping = mapping->next;
	}

	pthread_mutex_unlock(&(nat->lock));
	return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
	 You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
	uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

	pthread_mutex_lock(&(nat->lock));

	/* handle lookup here, malloc and assign to copy. */
	struct sr_nat_mapping *copy = NULL;

	struct sr_nat_mapping *mapping = nat->mappings;

	while (mapping) {
		if (
			(mapping->type == type) &&
			(mapping->ip_int == ip_int) &&
			(mapping->aux_int == aux_int)
		) {
			copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
			memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
			break;
		}
		mapping = mapping->next;
	}

	pthread_mutex_unlock(&(nat->lock));
	return copy;
}

/* Insert a new mapping into the nat's mapping table.
	 Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
	uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

	pthread_mutex_lock(&(nat->lock));

	/* handle insert here, create a mapping, and then return a copy of it */
	struct sr_nat_mapping *new_entry = NULL;
	struct sr_nat_mapping *copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
	struct sr_nat_mapping *mapping = nat->mappings;


		/* If in list, update time */
		while (mapping) {
			if (
				(mapping->type == type) &&
				(mapping->ip_int == ip_int) &&
				(mapping->aux_int == aux_int)
			) {
				mapping->last_updated = time(NULL);
				memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
				break;
			}
			mapping = mapping->next;
		}
		/* If NOT in list, return new object */
		if (mapping == NULL) {
			new_entry =	(struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
			new_entry->ip_int = ip_int;
			new_entry->aux_int = aux_int;

			struct sr_if * if_list = nat->sr_instance->if_list;
			while(if_list) {
			    if (strcmp(if_list->name, "eth2") == 0) {
			        break;
			    }
			    if_list = if_list->next;
			}
			new_entry->ip_ext = if_list->ip;
			new_entry->aux_ext = generate_aux_ext(nat, type);
			new_entry->last_updated = time(NULL);
			new_entry->conns = NULL;
			new_entry->type = type;

			new_entry->next = nat->mappings;
			nat->mappings = new_entry;

			memcpy(copy, new_entry, sizeof(struct sr_nat_mapping));
		}

	pthread_mutex_unlock(&(nat->lock));
	return copy;
}

int generate_aux_ext(struct sr_nat *nat, sr_nat_mapping_type type) {
	if (type == nat_mapping_icmp) {
		return EXT_ID++;
	} else {
		struct sr_nat_mapping * mapping = NULL;
		int not_found = 0;
		int port = 1024;
		while (1) {
			mapping = nat->mappings;
			while (mapping) {
				if (mapping->aux_ext == port) {
					not_found = 1;
					break;
				}
				mapping = mapping->next;
			}
			if (not_found == 1){
				port = 1024 + (port+1)%(65535 - 1024);
				not_found = 0;
			} else {
				break;
			}
		}
		return port;
	}

}

void sr_nat_update_tcp_connection(struct sr_nat_mapping *mapping, uint32_t ip_dest, uint16_t port_dest) {
	struct sr_nat_connection *current_connection = mapping->conns;
	time_t curtime = time(NULL);
	while(current_connection) {
		if (
			(current_connection->ip_dest == ip_dest) &&
			(current_connection->port_dest == port_dest)
		) {
			break;
		}
		current_connection = current_connection->next;
	}
	/* found connection with ip/port */
	if (current_connection != NULL) {
		if (current_connection->state == tcp_state_syn_sent) {
			current_connection->last_updated = curtime;
		}
	} else {
		struct sr_nat_connection *new_connection = (struct sr_nat_connection *) malloc(sizeof(struct sr_nat_connection));
		new_connection->ip_dest = ip_dest;
		new_connection->port_dest = port_dest;
		new_connection->last_updated = curtime;
		new_connection->state = tcp_state_syn_sent;

		new_connection->next = mapping->conns;
		mapping->conns = new_connection;
	}
}

/* Return the connection specified by (ip_dest, port_dest) in mapping->conns. If it doesn't exist,
return NULL */
struct sr_nat_connection* sr_nat_get_connection(struct sr_nat *nat, struct sr_nat_mapping *mapping, uint32_t ip_dest, uint16_t port_dest) {
	struct sr_nat_connection *current_connection = mapping->conns;
	struct sr_nat_connection *copy = NULL;

	pthread_mutex_lock(&(nat->lock));

	while (current_connection) {
		if (
			(current_connection->ip_dest == ip_dest) &&
			(current_connection->port_dest == port_dest)
		) {
			copy = (struct sr_nat_connection *) malloc(sizeof(struct sr_nat_connection));
			memcpy(copy, current_connection, sizeof(struct sr_nat_connection));
			break;
		}
		current_connection = current_connection->next;
	}

	pthread_mutex_unlock(&(nat->lock));

	return copy;
}

/* Return the connection specified by (ip_dest, port_dest) in mapping->conns. If it doesn't exist,
return NULL */
void sr_nat_update_connection_state(struct sr_nat *nat, struct sr_nat_mapping *mapping, uint32_t ip_dest, uint16_t port_dest, sr_tcp_state expected_state,
	sr_tcp_state new_state) {

	pthread_mutex_lock(&(nat->lock));
	struct sr_nat_connection *current_connection = mapping->conns;

	while (current_connection) {
		if (
			(current_connection->ip_dest == ip_dest) &&
			(current_connection->port_dest == port_dest)
		) {
			if (current_connection->state == expected_state) {
				current_connection->state = new_state;
			}
			break;
		}
		current_connection = current_connection->next;
	}

	pthread_mutex_unlock(&(nat->lock));
}

void sr_nat_insert_tcp_connection(struct sr_nat *nat, struct sr_nat_mapping *mapping_cpy, uint32_t ip_dest, uint16_t port_dest) {
	pthread_mutex_lock(&(nat->lock));
	time_t curtime = time(NULL);

	struct sr_nat_mapping *mapping = nat->mappings;

	while (mapping) {
		if (
		(mapping->type == mapping_cpy->type) &&
		(mapping->aux_ext == mapping_cpy->aux_ext)
		) {
			/* found connection with ip/port */
			struct sr_nat_connection *new_connection = (struct sr_nat_connection *) malloc(sizeof(struct sr_nat_connection));
			new_connection->ip_dest = ip_dest;
			new_connection->port_dest = port_dest;
			new_connection->last_updated = curtime;
			new_connection->state = tcp_state_syn_sent;

			new_connection->next = mapping->conns;
			mapping->conns = new_connection;
		}
		mapping = mapping->next;
	}


	pthread_mutex_unlock(&(nat->lock));
}


void sr_nat_insert_connection_packet(struct sr_nat *nat, struct sr_nat_mapping *mapping_cpy, uint32_t ip_dest, uint16_t port_dest, uint8_t * packet, unsigned int len, char * interface) {
	pthread_mutex_lock(&(nat->lock));

	struct sr_nat_mapping *mapping = nat->mappings;

	while (mapping) {
		if (
		(mapping->type == mapping_cpy->type) &&
		(mapping->aux_ext == mapping_cpy->aux_ext)
		) {
			struct sr_nat_connection *conn = mapping->conns;
			while (conn) {
				if (
				(conn->ip_dest == ip_dest) &&
				(conn->port_dest == port_dest)
				) {
					conn->unsolicited_packet = packet;
					conn->len = len;
					conn->interface = interface;
					break;
				}
				conn = conn->next;
			}
			break;
		}
		mapping = mapping->next;
	}


	pthread_mutex_unlock(&(nat->lock));
}