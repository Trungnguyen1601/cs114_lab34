
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>
#include "sr_router.h"
#include "sr_utils.h"

/* Define */

#define INIT_PORT_TCP 10000
#define INIT_ICMP_ID 10000

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

struct sr_nat_connection {
  /* add TCP connection state data members here */

  uint8_t state;

  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */

  long lastConnected;

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

enum{
  ICMP_QUERY_TIMEOUT = 60,
  TCP_ESTABLISHED_IDLE_TIMEOUT = 7440,
  TCP_TRANSITORY_IDLE_TIMEOUT = 300,
};

struct sr_nat {
  /* add any fields here */
  bool nat_enable;
  struct sr_if *interface;

  struct sr_nat_mapping *mappings;

  uint16_t portTCP_mapping;
  uint16_t idICMP_mapping;

  uint16_t icmp_query_timeout;
  uint16_t tcp_established_idle_timeout;
  uint16_t tcp_transitory_idle_timeout;

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};

/*Function for NAT handle*/

void sr_nat_handle_icmp(struct sr_instance *sr, uint8_t *packet, struct sr_if *interface);
void sr_nat_handle_tcp(struct sr_instance *sr, uint8_t *packet, struct sr_if *interface);
void sr_nat_forward_icmp_to_internal(struct sr_instance *sr, uint8_t *packet, unsigned int len,sr_ip_hdr_t *ip_header, struct sr_if *interface_send);
void sr_nat_forward_icmp_to_external(struct sr_instance *sr, uint8_t *packet, unsigned int len,struct sr_arpentry *arp_lookup, struct sr_if *interface_send);

void sr_nat_forward_tcp_to_internal(struct sr_instance *sr, uint8_t *packet, unsigned int len,sr_ip_hdr_t *ip_header, struct sr_if *interface_send);
void sr_nat_forward_tcp_to_external(struct sr_instance *sr, uint8_t *packet, unsigned int len,struct sr_arpentry *arp_lookup, struct sr_if *interface_send);

void sr_nat_handle_packet();

bool nat_check_packet_from_external_or_internal(uint32_t ip_src);
void defunct_mapping(struct sr_nat *nat, struct sr_nat_mapping *mapping);


int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
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


#endif