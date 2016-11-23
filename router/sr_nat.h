
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

typedef enum {
    tcp_state_listen,
    tcp_state_syn_sent,
    tcp_state_syn_recv,
    tcp_state_established,
    tcp_state_fin_wait1,
    tcp_state_fin_wait2,
    tcp_state_close_wait,
    tcp_state_time_wait,
    tcp_state_last_ack,
    tcp_state_closed
} sr_tcp_state;

struct sr_nat_connection {
  /* add TCP connection state data members here */
  uint32_t ip_dest;
  uint16_t port_dest;
  time_t last_updated;
  sr_tcp_state state;

  struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

typedef struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;
  uint32_t ip_external;

  int tcpTransitoryTimeout;
  int tcpEstablishedTimeout;
  int icmpTimeout;


  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
} sr_nat_t;


int sr_nat_init(sr_nat_t *nat);     /* Initializes the nat */
int sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );


int generate_aux_ext(struct sr_nat *nat, sr_nat_mapping_type type);
void sr_nat_update_tcp_connection(struct sr_nat_mapping *mapping, uint32_t ip_dest, uint16_t port_dest);

struct sr_nat_connection* sr_nat_get_connection(struct sr_nat *nat, struct sr_nat_mapping *mapping, uint32_t ip_dest, uint16_t port_dest);
void sr_nat_update_connection_state(struct sr_nat *nat, struct sr_nat_mapping *mapping, uint32_t ip_dest, uint16_t port_dest, sr_tcp_state expected_state, sr_tcp_state new_state);
void sr_nat_insert_tcp_connection(struct sr_nat *nat, struct sr_nat_mapping *mapping, uint32_t ip_dest, uint16_t port_dest);

#endif
