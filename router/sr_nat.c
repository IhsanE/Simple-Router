
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
	sr_nat_timeout(nat);
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
	if (type == nat_mapping_icmp) {
		while (mapping) {
			if ((mapping->type == type) && (mapping->aux_ext == aux_ext)) {
				copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
				memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
				break;
			}
			mapping = mapping->next;
		}
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
	if (type == nat_mapping_icmp) {
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

	if (type == nat_mapping_icmp) {
		/* If in list, update time */
		while (mapping) {
			if (
				(mapping->type == type) &&
				(mapping->ip_int == ip_int) &&
				(mapping->aux_int == aux_int)
			) {
				printf("FOUND\n");
				mapping->last_updated = time(NULL);
				memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
				break;
			}
			mapping = mapping->next;
		}
		/* If NOT in list, return new object */
		if (mapping == NULL) {
			printf("NOT FOUND\n");
			new_entry =	(struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
			new_entry->ip_int = ip_int;
			new_entry->aux_int = aux_int;
			new_entry->ip_ext = 2889876225;
			new_entry->aux_ext = EXT_ID;
			new_entry->last_updated = time(NULL);
			new_entry->conns = NULL;
			new_entry->type = nat_mapping_icmp;

			new_entry->next = nat->mappings;
			nat->mappings = new_entry;

			memcpy(copy, new_entry, sizeof(struct sr_nat_mapping));
		}
	}

	pthread_mutex_unlock(&(nat->lock));
	return copy;
}
