
/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

 #ifndef SR_ROUTER_H
 #define SR_ROUTER_H
 
 #include <netinet/in.h>
 #include <sys/time.h>
 #include <stdio.h>
 #include <stdbool.h>
 
 
 #include "sr_protocol.h"
 #include "sr_arpcache.h"
 #include "sr_if.h"
 #include "sr_rt.h"
 
 
 /* we dont like this debug , but what to do for varargs ? */
 #ifdef _DEBUG_
 #define Debug(x, args...) printf(x, ## args)
 #define DebugMAC(x) \
   do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
   (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
 #else
 #define Debug(x, args...) do{}while(0)
 #define DebugMAC(x) do{}while(0)
 #endif
 
 #define INIT_TTL 255
 #define PACKET_DUMP_SIZE 1024
 
 
 #define MIN_IP_HEADER_LENGTH 5
 #define MIN_LENGTH_OF_IP_HEADER 20
 #define IP_VERSION 4
 #define DEFAULT_TTL INIT_TTL
 #define LENGTH_ICMP_TYPE3_HDR 36
 #define LENGTH_ICMP_HDR 4
 
 /* forward declare */
 struct sr_if;
 struct sr_rt;
 
 /* ----------------------------------------------------------------------------
  * struct sr_instance
  *
  * Encapsulation of the state for a single virtual router.
  *
  * -------------------------------------------------------------------------- */
 
 struct sr_instance
 {
     int  sockfd;   /* socket to server */
     char user[32]; /* user name */
     char host[32]; /* host name */ 
     char template[30]; /* template name if any */
     unsigned short topo_id;
     struct sockaddr_in sr_addr; /* address to server */
     struct sr_if* if_list; /* list of interfaces */
     struct sr_rt* routing_table; /* routing table */
     struct sr_arpcache cache;   /* ARP cache */
     struct sr_nat *nat; /*NAT*/
     pthread_attr_t attr;
     FILE* logfile;
 };
 
 /* -- sr_main.c -- */
 int sr_verify_routing_table(struct sr_instance* sr);
 
 /* -- sr_vns_comm.c -- */
 int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
 int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
 int sr_read_from_server(struct sr_instance* );
 
 /* -- sr_router.c -- */
 void sr_init(struct sr_instance* );
 void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );
 void sr_send_arp_request1( struct sr_instance *sr, struct sr_arpreq *arp_req);
 
 
 /* -- sr_if.c -- */
 void sr_add_interface(struct sr_instance* , const char* );
 void sr_set_ether_ip(struct sr_instance* , uint32_t );
 void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
 void sr_print_if_list(struct sr_instance* );
 
 /*
   Function for handle of router
 */
 void sr_handle_receive_arppacket(struct sr_instance* sr, uint8_t *packet,unsigned int len,struct sr_if* interface);
 void sr_handle_receive_ippacket(struct sr_instance* sr, uint8_t *packet,unsigned int len, struct sr_if* interface);
 
 void sr_send_type3_icmp(struct sr_instance* sr, sr_ip_hdr_t *ip_hdr, uint8_t icmp_code, struct sr_if* interface, uint8_t *packet );
 void sr_send_icmp_timeexceeded(struct sr_instance* sr, uint8_t *packet,sr_ip_hdr_t *ip_header,struct sr_if* interface);
 void sr_send_icmp_echoreply(struct sr_instance* sr, uint8_t *packet,sr_ip_hdr_t *ip_header,struct sr_if* interface);
 
 /* Function for IP handle*/
 bool check_destIP_for_router(struct sr_instance *sr, sr_ip_hdr_t *ip_header);
 struct sr_rt *sr_find_lpm_routingtable(struct sr_rt *routing_table, uint32_t ip_addr);
 void sr_handle_IP_forward(struct sr_instance *sr, unsigned int len, uint8_t*packet, struct sr_if* receive_interface);
 int16_t calc_length_of_mask(struct sr_rt *routing_index);
 
 /* Function for ARP handle*/
 void sr_send_arp_request(struct sr_instance *sr, sr_ip_hdr_t *ip_header, struct sr_rt *route);
 void sr_send_arp_reply(struct sr_instance *sr, sr_arp_hdr_t * arp_header, struct sr_if *interface);
 void sr_check_arptable_send_packet( struct sr_instance *sr, uint8_t *packet, unsigned int len,
                                     sr_ip_hdr_t* ip_header);
 void sr_handle_recv_arp_request(struct sr_instance *sr, sr_arp_hdr_t * arp_header, struct sr_if *interface);
 void sr_handle_recv_arp_reply(struct sr_instance *sr, sr_arp_hdr_t * arp_header, struct sr_if *interface);
 
 /* Function for validation */
 bool check_validation_ip_header(sr_ip_hdr_t *ip_header, unsigned int len);
 bool check_packet_from_external_or_internal(uint32_t ip_src);
 
 /* Function for handle TCP packet */
 struct sr_tcp_hdr *get_TCPheader(uint8_t *packet);
 void print_infor_tcp_header(sr_tcp_hdr_t *tcp_header);
 uint16_t getFlag_tcp_header(sr_tcp_hdr_t *tcp_header);
 
 #endif /* SR_ROUTER_H */
 