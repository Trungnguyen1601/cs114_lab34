#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include "sr_arpcache.h"


/*Function for NAT handle*/


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
  nat->portTCP_mapping = INIT_PORT_TCP;
  nat->idICMP_mapping = INIT_ICMP_ID;

  nat->icmp_query_timeout = ICMP_QUERY_TIMEOUT;
  nat->tcp_established_idle_timeout = TCP_ESTABLISHED_IDLE_TIMEOUT;
  nat->tcp_transitory_idle_timeout = TCP_TRANSITORY_IDLE_TIMEOUT;
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
  /*struct sr_nat_mapping *mapping = NULL;*/
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);
    
    /* handle periodic tasks here */
    /*for (mapping = nat->mappings; mapping != NULL; mapping = mapping->next)
    {
      if (difftime(curtime,mapping->last_updated) > nat->icmp_query_timeout)
      {
        defunct_mapping(nat,mapping);
      }
    }*/

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));


  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *mapping = NULL;
  struct sr_nat_mapping *copy = NULL;
  for (mapping = nat->mappings ; mapping != NULL; mapping = mapping->next)
  {
    if ( (mapping->aux_ext == aux_ext) && (mapping->type == type) )
    {
      break;
    }
  }

  if (mapping)
  {
    copy = (struct sr_nat_mapping *)calloc(1,sizeof(struct sr_nat_mapping));
    memcpy(copy,mapping,sizeof(struct sr_nat_mapping));
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
  struct sr_nat_mapping *mapping = NULL;
  struct sr_nat_mapping *copy = NULL;
  for (mapping = nat->mappings ; mapping != NULL; mapping = mapping->next)
  {
    if ((mapping->ip_int == ip_int) && (mapping->aux_int == aux_int) 
    && (mapping->type == type))
    {
      break;
    }
  }

  if (mapping)
  {
    copy = (struct sr_nat_mapping *)calloc(1,sizeof(struct sr_nat_mapping));
    memcpy(copy,mapping,sizeof(struct sr_nat_mapping));
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
  uint16_t init_aux_ext;
  if (type == nat_mapping_icmp)
  {
    init_aux_ext = nat->idICMP_mapping;
    nat->idICMP_mapping += 1;
  }
  else if (type == nat_mapping_tcp)
  {
    init_aux_ext = nat->portTCP_mapping;
    nat->portTCP_mapping += 1;
  }

  struct sr_nat_mapping *mapping = NULL;
  for (mapping = nat->mappings ; mapping != NULL; mapping = mapping->next)
  {
    if ((mapping->ip_int == ip_int) && (mapping->type == type)
        && (mapping->aux_int = ntohs(init_aux_ext)))
    {
      break;
    }
  }

  if (!mapping)
  {
    mapping = (struct sr_nat_mapping*)calloc(1,sizeof(struct sr_nat_mapping));
    mapping->aux_ext = init_aux_ext;
    mapping->ip_int = ip_int;
    mapping->aux_int = aux_int;
    mapping->last_updated = time(NULL);
    /* Add to mapping table */
    mapping->next = nat->mappings;
    nat->mappings = mapping;
  }

  if (mapping)
  {
    struct sr_nat_mapping *mapping_add = (struct sr_nat_mapping*)calloc(1,sizeof(struct sr_nat_mapping));
    mapping_add->aux_ext = init_aux_ext + 1;
    mapping_add->ip_int = ip_int;
    mapping_add->aux_int = aux_int;
    mapping->last_updated = time(NULL);
    /* Add to mapping table */
    mapping_add->next = nat->mappings;
    nat->mappings = mapping;
  }

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}


bool nat_check_packet_from_external_or_internal(uint32_t ip_src)
{
  /* 10.0.0.0 - 10.255.255.255*/
  if ((ip_src >= 0x0A000000) && (ip_src <= 0x0AFFFFFF)) {
      return true;
  }

  /* 172.16.0.0 - 172.31.255.255 */
  if ((ip_src >= 0xAC100000) && (ip_src <= 0xAC1FFFFF)) {
      return true;
  }

  /* 192.168.0.0 - 192.168.255.255 */
  if ((ip_src >= 0xC0A80000) && (ip_src <= 0xC0A8FFFF)) {
      return true;
  }
  return false;
}

void sr_nat_forward_icmp_to_internal(struct sr_instance *sr, uint8_t *packet, unsigned int len, sr_ip_hdr_t *ip_header, struct sr_if *interface)
{
  sr_ethernet_hdr_t *send_ethernet_packet = (sr_ethernet_hdr_t *) packet;
  sr_ip_hdr_t *ip_header_packet = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp_header = NULL;
  
  uint16_t aux_external = 0;
  printf("IN NAT IP TO INTERNAL\n ");
  /* Should check for icmp or tcp */
  if (ip_header->ip_p == ip_protocol_icmp)
  {
    icmp_header = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    aux_external = icmp_header->icmp_id;
    printf("aux_external %d\n",aux_external);
  }
  
  struct sr_nat_mapping *mapping = sr_nat_lookup_external(sr->nat, aux_external,nat_mapping_icmp);
  if (mapping == NULL)
  {
    /*sr_nat_insert_mapping(sr->nat,ip_header->ip_src,aux_internal,nat_mapping_icmp);*/
    printf("mapping NULL\n");
  }
  struct sr_rt *ip_routing = sr_find_lpm_routingtable(sr->routing_table,ntohl(mapping->ip_int));
  struct sr_if *interface_send = sr_get_interface(sr,ip_routing->interface);

  struct sr_arpentry *arp_lookup = sr_arpcache_lookup(&(sr->cache),mapping->ip_int);
  if (arp_lookup == NULL)
  {
    /* IP TO INTERNAL Send ARP request */
    #if DEBUG_IP_FORWARD
    printf("Send ARP request %x in IP forward \n",ip_header_packet->ip_dst);
    #endif

    /* IP TO INTERNAL struct sr_arpreq *arp_req = sr_arpcache_find_arpreq(&(sr->cache),ip_header_packet->ip_dst);*/
    printf("Ip routing %x to queue \n",ip_routing->gw.s_addr);
  
    sr_arpcache_queuereq(&(sr->cache),mapping->ip_int, packet, len, ip_routing->interface);
  }
  else
  {
    /* Ether header*/  
    memcpy(send_ethernet_packet->ether_shost,interface_send->addr,ETHER_ADDR_LEN);
    memcpy(send_ethernet_packet->ether_dhost,arp_lookup->mac,ETHER_ADDR_LEN);


    /* IP header */
    print_addr_ip_int(mapping->ip_int);
    ip_header_packet->ip_dst= mapping->ip_int;
    ip_header_packet->ip_sum = 0;
    ip_header_packet->ip_sum = cksum(ip_header_packet,MIN_LENGTH_OF_IP_HEADER);

    icmp_header->icmp_id = mapping->aux_int; 

    #if DEBUG
    print_hdrs(packet_copy,len);
    #endif
    int ret = sr_send_packet(sr,(uint8_t*)packet,len,interface_send->name);
    printf("Send %d\n",ret);

  }


}
void sr_nat_forward_icmp_to_external(struct sr_instance *sr, uint8_t *packet, 
                                        unsigned int len, 
                                        struct sr_arpentry *arp_lookup,
                                        struct sr_if *interface_send)
{
  sr_ethernet_hdr_t *send_ethernet_packet = (sr_ethernet_hdr_t *) packet;
  sr_ip_hdr_t *ip_header_packet = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp_header = NULL;

  uint16_t aux_internal = 0;
  printf("IN NAT ICMP TO EXTERNAL\n ");

  icmp_header = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  aux_internal = icmp_header->icmp_id;
  printf("aux_internal %d\n",aux_internal);

  struct sr_nat_mapping *mapping = sr_nat_lookup_internal(sr->nat,ip_header_packet->ip_src, aux_internal,nat_mapping_icmp);
  if (mapping == NULL)
  {
    sr_nat_insert_mapping(sr->nat,ip_header_packet->ip_src,aux_internal,nat_mapping_icmp);
  }
  struct sr_nat_mapping *mapping_index = NULL;
  for (mapping_index = sr->nat->mappings; mapping_index != NULL; mapping_index = mapping_index->next)
  {
    printf("mapping aux int : %d\n", mapping_index->aux_int);
    printf("mapping aux ext : %d\n", mapping_index->aux_ext);
  } 

  /* Ether header*/  
  memcpy(send_ethernet_packet->ether_shost,interface_send->addr,ETHER_ADDR_LEN);
  memcpy(send_ethernet_packet->ether_dhost,arp_lookup->mac,ETHER_ADDR_LEN);

  /* IP header */
  print_addr_ip_int(sr->nat->interface->ip);
  ip_header_packet->ip_src = sr->nat->interface->ip;
  ip_header_packet->ip_sum = 0;
  ip_header_packet->ip_sum = cksum(ip_header_packet,MIN_LENGTH_OF_IP_HEADER);

  icmp_header->icmp_id = sr->nat->idICMP_mapping - 1; 

  #if DEBUG
  print_hdrs(packet_copy,len);
  #endif
  int ret = sr_send_packet(sr,(uint8_t*)packet,len,interface_send->name);
  printf("Send %d\n",ret);

}

struct sr_nat_connection *sr_nat_lookup_connection(struct sr_nat_mapping nat_mapping, uint32_t ip_ext,
                                                  uint16_t port_ext)
{
  struct sr_nat_connection *connection = nat_mapping->conns;
  while(connection != NULL)
  {
    if ( (connection->ip_ext == ip_ext) 
        && (connection->aux_ext == port_ext))
    {
      connection->lastConnected = time(NULL);
      break;
    }

    connection = connection->next;
  }
  return connection;
}
void sr_nat_forward_tcp_to_internal(struct sr_instance *sr, uint8_t *packet, unsigned int len,sr_ip_hdr_t *ip_header, struct sr_if *interface_send)
{


}
void sr_nat_forward_tcp_to_external(struct sr_instance *sr, uint8_t *packet, unsigned int len,struct sr_arpentry *arp_lookup, struct sr_if *interface_send)
{
  sr_ethernet_hdr_t *send_ethernet_packet = (sr_ethernet_hdr_t *) packet;
  sr_ip_hdr_t *ip_header_packet = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  sr_tcp_hdr_t *tcp_header = NULL;

  /*Variable for NAT mapping */
  struct sr_nat_mapping *nat_mapping = NULL;

  uint16_t port_internal = 0;
  printf("IN NAT TCP TO EXTERNAL\n ");

  tcp_header = (sr_tcp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
  port_internal = tcp_header->sport;
  printf("port internal %d\n",port_internal);

  /* check sum TCP packet */

  /* check nat_mapping */
  
  /* check flags */
  if (getFlag_tcp_header(tcp_header) & FLAG_SYN)
  {
    if (nat_mapping == NULL)
    {
      /* Outbound SYN with first mapping. create mapping*/
      pthread_mutex_lock(&(sr->nat->lock));
      struct sr_nat_connection *first_connection = (struct sr_nat_connection*)calloc(1,sizeof(struct sr_nat_connection));
      struct sr_nat_mapping *tcp_nat_mapping;
      nat_mapping = (struct sr_nat_mapping*)calloc(1,sizeof(struct sr_nat_mapping));

      tcp_nat_mapping = create_mapping(sr->nat,ip_header_packet->ip_src, tcp_header->tcp_sport,nat_mapping_tcp);

      /* Create first connection */
      first_connection->tcp_state = nat_outbound_syn;
      first_connection->lastConnected = time(NULL);
      first_connection->queueSYN_ippacket = NULL;
      first_connection->ip_ext = ip_header_packet->ip_dst;
      first_connection->aux_ext = tcp_header->tcp_dhost;

      /*Add to list connection */
      first_connection->next = tcp_nat_mapping->conns;
      tcp_nat_mapping->conns = first_connection;

      memcpy(nat_mapping,tcp_nat_mapping,sizeof(struct sr_nat_mapping));
      pthread_mutex_unlock(&(sr->nat->lock));

    }
    else
    /*Had external SYN before */
    {
      pthread_mutex_lock(&(sr->nat->lock));
      struct sr_nat_mapping *tcp_nat_mapping = sr_nat_lookup_internal(sr->nat,ip_header_packet->ip_src,
                                                                      tcp_header->tcp_shost, nat_mapping_tcp);
      assert(tcp_nat_mapping);

      struct sr_nat_connection *tcp_connection = sr_nat_lookup_connection(sr->nat,ip_header_packet->ip_dst,tcp_header->tcp_dhost);

      if(tcp_connection == NULL)
      {
        tcp_connection = (sr_tcp_hdr_t*)calloc(sizeof(sr_tcp_hdr_t),1);
        assert(tcp_connection);

        tcp_connection->tcp_state = nat_outbound_syn;
        tcp_connection->ip_ext = ip_header_packet->ip_dst;
        tcp_connection->aux_ext = tcp_header->tcp_dhost;

        /*Add to the list of connections*/
        tcp_connection->next = tcp_nat_mapping->conns;
        tcp_nat_mapping->conns = tcp_connection;


      }
      else if (tcp_connection->tcp_state == nat_time_wait)
      {
        /*reopen the connection*/
        tcp_connection->tcp_state = nat_outbound_syn;
      }
      else if (tcp_connection->tcp_state == nat_inbound_syn_waiting)
      {
        tcp_connection->tcp_state = nat_conn_connectd;

        if (tcp_connection->queueSYN_ippacket)
        {
          free (tcp_connection->queueSYN_ippacket);
        }
      }
      pthread_mutex_unlock(&(sr->nat->lock));
    }
  }
  else if (nat_mapping == NULL)
  {
    return;
  }
  else if (getFlag_tcp_header(tcp_header) & FLAG_SYN)
  {
    pthread_mutex_lock(&(sr->nat->lock));
    struct sr_nat_mapping *tcp_nat_mapping = sr_nat_lookup_internal(sr->nat,ip_header_packet->ip_src,
                                                                    tcp_header->tcp_dhost, nat_mapping_tcp);
    
    struct sr_nat_connection *tcp_connection = sr_nat_lookup_connection(tcp_connection,ip_header_packet->ip_dst,
                                                                        tcp_header->tcp_dhost);
    
    if (tcp_connection)
    {
      tcp_connection->tcp_state = nat_time_wait;
    }
    pthread_mutex_unlock(&(sr->nat->lock));
    /*Send outbound TCP packet*/
    
  }
  else /*Inbound TCP */
  {
    struct sr_nat_mapping *nat_mapping = sr_nat_lookup_external(sr->nat,tcp_header->tcp_dhost,nat_mapping_tcp);
    
  }
}

void create_mapping(struct sr_nat *nat, uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type)
{
/* handle insert here, create a mapping, and then return a copy of it */
  uint16_t init_aux_ext;
  if (type == nat_mapping_icmp)
  {
    init_aux_ext = nat->idICMP_mapping;
    nat->idICMP_mapping += 1;
  }
  else if (type == nat_mapping_tcp)
  {
    init_aux_ext = nat->portTCP_mapping;
    nat->portTCP_mapping += 1;
  }

  struct sr_nat_mapping *mapping = NULL;
  for (mapping = nat->mappings ; mapping != NULL; mapping = mapping->next)
  {
    if ((mapping->ip_int == ip_int) && (mapping->type == type)
        && (mapping->aux_int = ntohs(init_aux_ext)))
    {
      break;
    }
  }

  if (!mapping)
  {
    mapping = (struct sr_nat_mapping*)calloc(1,sizeof(struct sr_nat_mapping));
    mapping->aux_ext = init_aux_ext;
    mapping->ip_int = ip_int;
    mapping->aux_int = aux_int;
    mapping->last_updated = time(NULL);
    /* Add to mapping table */
    mapping->next = nat->mappings;
    nat->mappings = mapping;
  }

  if (mapping)
  {
    struct sr_nat_mapping *mapping_add = (struct sr_nat_mapping*)calloc(1,sizeof(struct sr_nat_mapping));
    mapping_add->aux_ext = init_aux_ext + 1;
    mapping_add->ip_int = ip_int;
    mapping_add->aux_int = aux_int;
    mapping->last_updated = time(NULL);
    /* Add to mapping table */
    mapping_add->next = nat->mappings;
    nat->mappings = mapping;
  }

  pthread_mutex_unlock(&(nat->lock));
  return mapping;
}

void defunct_mapping(struct sr_nat *nat, struct sr_nat_mapping *mapping)
{
  pthread_mutex_lock(&(nat->lock));

  if (mapping) {
    struct sr_nat_mapping *map, *prev = NULL, *next = NULL;
    for (map = nat->mappings; map != NULL; map = map->next) {
      if (map == mapping) {
        if (prev) {
          next = map->next;
          prev->next = next;
        }
        else {
          next = map->next;
          nat->mappings = next;
        }

        break;
      }
      prev = map;
    }
    /*
    */
  }

  pthread_mutex_unlock(&(nat->lock));
}