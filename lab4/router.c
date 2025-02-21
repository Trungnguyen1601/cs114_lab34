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
#include <assert.h>
#include <string.h>
#include <stdlib.h>


#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_nat.h"
#include "sr_utils.h"

#define DEBUG 0
#define DEBUG_IP_FORWARD 1
#define DEBUG_ARP_TABLE 1


enum sr_arp_length_address {
  length_of_hardware = 6,
  length_of_protocol = 4,
};

unsigned char broadcastAddr[ETHER_ADDR_LEN] = {
  0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
};

static uint16_t id_number = 0;


struct sr_arpreq *sr_arpcache_find_arpreq(struct sr_arpcache *cache, uint32_t ip)
{
  pthread_mutex_lock(&(cache->lock));
  
  struct sr_arpreq *req, *prev = NULL, *next = NULL; 
  for (req = cache->requests; req != NULL; req = req->next) {
      if (req->ip == ip) {            
          if (prev) {
              next = req->next;
              prev->next = next;
          } 
          else {
              next = req->next;
              /*cache->requests = next;*/
          }
          
          break;
      }
      prev = req;
  }
  pthread_mutex_unlock(&(cache->lock));
  return req; 
}

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
    sr_nat_init(sr->nat);

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

  /**/
  #if DEBUG
    printf("*** -> Received packet of length %d \n",len);
    print_hdrs(packet,len);
    printf("*********************************************\n");
  #endif

  /* fill in code here */

  uint16_t ethernet_type = 0;
  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)packet;
  assert(ethernet_hdr);
  /* check length of packet receive */
  if (len < sizeof(sr_ethernet_hdr_t))
  {
    /* len < length of Ethernet packet header */
    return;
  }
  uint8_t *packet_copy = (uint8_t*)calloc(1,len);
  memcpy(packet_copy,packet,len );

  struct sr_if *receiveInterface = sr_get_interface(sr,interface);
  assert(receiveInterface);

  sr->nat->interface = sr_get_external_interface(sr);

  /* check ether_type */

  ethernet_type = ntohs(ethernet_hdr->ether_type);
  switch(ethernet_type)
  {
    case ethertype_arp :
    {
      #if DEBUG
      printf("Receive ARP packet\n");
      #endif 
      sr_handle_receive_arppacket(sr,packet_copy,len,receiveInterface);
      break;
    }

    case ethertype_ip :
    {
      #if DEBUG
      printf("Receive IP packet\n");
      #endif
      sr_handle_receive_ippacket(sr,packet_copy,len,receiveInterface);
      break;
    }

    default :
    {
      break;
    }
  }


}/* end sr_ForwardPacket */


void sr_handle_receive_ippacket(struct sr_instance* sr, uint8_t *packet,
                        unsigned int len, struct sr_if *interface)
{
  sr_ethernet_hdr_t *ether_ip = (sr_ethernet_hdr_t*)packet;
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t*)((uint8_t*)ether_ip + sizeof(sr_ethernet_hdr_t));

  #ifdef DEBUG
  /*print_hdr_ip((uint8_t*)ip_header);*/
  #endif

  if (ip_header->ip_p == ip_protocol_tcp)
  {
    get_TCPheader(packet);
  }
  if(check_validation_ip_header(ip_header,MIN_LENGTH_OF_IP_HEADER) == false)
  {
    return;
  }

  ip_header->ip_ttl = ip_header->ip_ttl - 1;
  if (ip_header->ip_ttl == 0)
  {
    #if DEBUG
    printf("Send ICMP time exceeded\n");
    #endif
    sr_send_icmp_timeexceeded(sr,packet,ip_header,interface);
  }
  else
  {
    ip_header->ip_sum = 0;
    ip_header->ip_sum = cksum(ip_header,MIN_LENGTH_OF_IP_HEADER);

    if (check_destIP_for_router(sr,ip_header))
    {
      /* Packet from external and NAT enable */
      if (!nat_check_packet_from_external_or_internal(ip_header->ip_src) && sr->nat->nat_enable)
      {
        if (ip_header->ip_p == ip_protocol_icmp)
        {
          sr_nat_forward_icmp_to_internal(sr,packet,len,ip_header,interface);
        }
        else if (ip_header->ip_p == ip_protocol_tcp)
        {
          sr_nat_forward_tcp_to_internal(sr,packet,len,ip_header,interface);
        }
      }
      else
      {
        /* Packet from internal */
        if(ip_header->ip_p == ip_protocol_icmp)
        {
          sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t*)((uint8_t*)ip_header + sizeof(sr_ip_hdr_t));
          if (icmp_hdr->icmp_type == 8)
          {
            /* Send ICMP echo reply */
            sr_send_icmp_echoreply(sr,packet,ip_header,interface);
          }
        }
        else
        {
          /* Send ICMP port unreachable */
          sr_send_type3_icmp(sr,ip_header,3,interface,packet);
        }
      }
    }
    else
    {
      #if DEBUG
      printf("Handle IP forward\n");
      #endif
      sr_handle_IP_forward(sr,len,packet,interface);
    }
  }

}

void sr_handle_IP_forward(struct sr_instance *sr, 
                          unsigned int len, 
                          uint8_t *packet,
                          struct sr_if* receive_interface)
{
  sr_ethernet_hdr_t *send_ethernet_packet = (sr_ethernet_hdr_t *) packet;
  sr_ip_hdr_t *ip_header_packet = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  struct sr_rt *ip_routing = sr_find_lpm_routingtable(sr->routing_table,ntohl(ip_header_packet->ip_dst));

  if (ip_routing == NULL)
  {
    /* Send ICMP net unreachable */
    #if DEBUG
    printf("Send ICMP net unreachable\n");
    #endif
    sr_send_type3_icmp(sr,ip_header_packet,0,receive_interface,packet);
  }
  else
  {
    /* Forward IP packet */
    struct sr_arpentry *arp_lookup = sr_arpcache_lookup(&(sr->cache),ip_header_packet->ip_dst);
    if (arp_lookup == NULL)
    {
      /* Handle arp request*/
      /*Before send, add arp request to queue request*/

      /* Send ARP request */
      #if DEBUG_IP_FORWARD
      printf("Send ARP request %x in IP forward \n",ip_header_packet->ip_dst);
      #endif

      /*struct sr_arpreq *arp_req = sr_arpcache_find_arpreq(&(sr->cache),ip_header_packet->ip_dst);*/
      printf("Ip routing %x to queue \n",ip_routing->gw.s_addr);
      
      sr_arpcache_queuereq(&(sr->cache),ip_header_packet->ip_dst, packet, len, ip_routing->interface);
      sr_send_arp_request(sr,ip_header_packet,ip_routing);
    }
    else
    {
      struct sr_if *interface_send = sr_get_interface(sr,ip_routing->interface);
      /* Packet from internal and NAT enable*/
      if (nat_check_packet_from_external_or_internal(ntohl(ip_header_packet->ip_src)) && sr->nat->nat_enable)
      {
        if (ip_header->ip_p == ip_protocol_icmp)
        {
          sr_nat_forward_icmp_to_external(sr,packet,len,arp_lookup,interface_send);
        }
        if (ip_header->ip_p == ip_protocol_tcp)
        {
          sr_nat_forward_tcp_to_external(sr,packet,len,arp_lookup,interface_send);
        }
      }
      /*Packet from external*/
      else
      {
        /* Forward IP packet to ip dest */
        #if DEBUG
        printf("Send IP forward\n");
        #endif
        /* Ether header*/
        memcpy(send_ethernet_packet->ether_shost,interface_send->addr,ETHER_ADDR_LEN);
        memcpy(send_ethernet_packet->ether_dhost,arp_lookup->mac,ETHER_ADDR_LEN);
        send_ethernet_packet->ether_type = htons(ethertype_ip);

        /* IP header */
        ip_header_packet->ip_src = ip_header_packet->ip_src;
        ip_header_packet->ip_dst = arp_lookup->ip;
        ip_header_packet->ip_sum = 0;
        ip_header_packet->ip_sum = cksum(ip_header_packet,MIN_LENGTH_OF_IP_HEADER);

        #if DEBUG
        print_hdrs(packet_copy,len);
        #endif
        sr_send_packet(sr,(uint8_t*)packet,len,interface_send->name);
      }

    }
  }
}

void sr_send_icmp_timeexceeded(struct sr_instance* sr, uint8_t *packet, sr_ip_hdr_t *ip_header,struct sr_if* interface)
{

  uint8_t *icmp_packet = (uint8_t*)calloc(1,ntohs(ip_header->ip_len) + sizeof(sr_ethernet_hdr_t));
  memcpy(icmp_packet,packet,ntohs(ip_header->ip_len) + sizeof(sr_ethernet_hdr_t));
  sr_ethernet_hdr_t *ether_icmp = (sr_ethernet_hdr_t*)icmp_packet;
  sr_ip_hdr_t *ip_header_icmp = (sr_ip_hdr_t*)((uint8_t*)ether_icmp + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *icmp_header = (sr_icmp_t3_hdr_t*)((uint8_t*)ip_header_icmp + sizeof(sr_ip_hdr_t));

  /* Create ICMP */
  memcpy(ether_icmp->ether_dhost, ether_icmp->ether_shost, ETHER_ADDR_LEN);
  memcpy(ether_icmp->ether_shost, interface->addr, ETHER_ADDR_LEN);
  ether_icmp->ether_type = htons(ethertype_ip);

  ip_header_icmp->ip_ttl = 1;
  ip_header_icmp->ip_p = ip_protocol_icmp;
  ip_header_icmp->ip_src = interface->ip;
  ip_header_icmp->ip_dst = ip_header->ip_src;

  ip_header_icmp->ip_sum = 0;
  ip_header_icmp->ip_sum = cksum(ip_header_icmp,MIN_LENGTH_OF_IP_HEADER);

  /*ICMP header*/
  icmp_header->icmp_type = 11;
  icmp_header->icmp_code = 0;
  memcpy(icmp_header->data,packet + sizeof(sr_ethernet_hdr_t),ICMP_DATA_SIZE);
  icmp_header->icmp_sum = 0;
  icmp_header->icmp_sum = cksum(icmp_header,LENGTH_ICMP_TYPE3_HDR);

  #if DEBUG
  print_hdrs((uint8_t*)icmp_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + 16);
  #endif
  
  sr_send_packet(sr,(uint8_t*)icmp_packet,
                          ntohs(ip_header->ip_len) + sizeof(sr_ethernet_hdr_t),
                          interface->name);

}


void sr_send_icmp_echoreply(struct sr_instance* sr, uint8_t *packet, sr_ip_hdr_t *ip_header, struct sr_if* interface)
{
  #if DEBUG
  printf("Send ICMP reply\n");
  #endif

  uint8_t *icmp_packet = (uint8_t*)calloc(1,ntohs(ip_header->ip_len) + 14);
  memcpy(icmp_packet,packet,ntohs(ip_header->ip_len) + 14);
  sr_ethernet_hdr_t *ether_icmp = (sr_ethernet_hdr_t*)icmp_packet;
  sr_ip_hdr_t *ip_header_icmp = (sr_ip_hdr_t*)((uint8_t*)ether_icmp + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t*)((uint8_t*)ip_header_icmp + sizeof(sr_ip_hdr_t));

  /* Create ICMP */
  memcpy(ether_icmp->ether_dhost, ether_icmp->ether_shost, ETHER_ADDR_LEN);
  memcpy(ether_icmp->ether_shost, interface->addr, ETHER_ADDR_LEN);
  ether_icmp->ether_type = htons(ethertype_ip);

  /*IP header of icmp */
  ip_header_icmp->ip_hl = MIN_IP_HEADER_LENGTH;
  ip_header_icmp->ip_v = IP_VERSION;
  ip_header_icmp->ip_tos = 0;
  ip_header_icmp->ip_len = ip_header->ip_len;
  ip_header_icmp->ip_id = htons(id_number); id_number ++;
  ip_header_icmp->ip_off = htons(IP_DF);
  ip_header_icmp->ip_ttl = 64;
  ip_header_icmp->ip_p = ip_protocol_icmp;
  ip_header_icmp->ip_src = ip_header->ip_dst;
  ip_header_icmp->ip_dst = ip_header->ip_src;

  ip_header_icmp->ip_sum = 0;
  ip_header_icmp->ip_sum = cksum(ip_header_icmp,MIN_LENGTH_OF_IP_HEADER);

  /*ICMP header*/
  icmp_header->icmp_type = 0;
  icmp_header->icmp_code = 0;

  icmp_header->icmp_sum = 0;
  icmp_header->icmp_sum = cksum(icmp_header,16);

  #if DEBUG
  print_hdrs((uint8_t*)icmp_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + 16);
  #endif
  
  sr_send_packet(sr,(uint8_t*)icmp_packet,
                          ntohs(ip_header->ip_len) + 14,
                          interface->name);
}


void sr_send_type3_icmp(struct sr_instance* sr, 
                        sr_ip_hdr_t *ip_hdr, 
                        uint8_t icmp_code, 
                        struct sr_if* interface,
                        uint8_t *original_packet )
{
  uint8_t *icmp_packet = (uint8_t*)calloc(1,sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + LENGTH_ICMP_TYPE3_HDR);
  sr_ethernet_hdr_t *ether_icmp = (sr_ethernet_hdr_t*) icmp_packet;
  sr_ip_hdr_t *ip_header_icmp = (sr_ip_hdr_t*)((uint8_t*)icmp_packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *icmp_header = (sr_icmp_t3_hdr_t*)((uint8_t*)ip_header_icmp + sizeof(sr_ip_hdr_t));

  sr_ethernet_hdr_t *original_ether = (sr_ethernet_hdr_t*)original_packet;
  sr_ip_hdr_t *original_ip_header = (sr_ip_hdr_t*)((uint8_t*)original_ether + sizeof(sr_ethernet_hdr_t));

  /* Create ICMP */
  memcpy(ether_icmp->ether_shost, interface->addr, ETHER_ADDR_LEN);
  memcpy(ether_icmp->ether_dhost, original_ether->ether_shost, ETHER_ADDR_LEN);
  ether_icmp->ether_type = htons(ethertype_ip);

  /*IP header of icmp */
  ip_header_icmp->ip_hl = MIN_IP_HEADER_LENGTH;
  ip_header_icmp->ip_v = IP_VERSION;
  ip_header_icmp->ip_tos = 0;
  ip_header_icmp->ip_len = htons(MIN_LENGTH_OF_IP_HEADER + LENGTH_ICMP_TYPE3_HDR);
  ip_header_icmp->ip_id = htons(id_number); id_number ++;
  ip_header_icmp->ip_off = htons(IP_DF);
  ip_header_icmp->ip_ttl = 64;
  ip_header_icmp->ip_p = ip_protocol_icmp;
  ip_header_icmp->ip_src = interface->ip;
  ip_header_icmp->ip_dst = original_ip_header->ip_src;

  ip_header_icmp->ip_sum = 0;
  ip_header_icmp->ip_sum = cksum(ip_header_icmp,MIN_LENGTH_OF_IP_HEADER);

  /*ICMP header*/
  icmp_header->icmp_type = 3;
  icmp_header->icmp_code = icmp_code;
  memcpy(icmp_header->data,original_ip_header,ICMP_DATA_SIZE);
  icmp_header->icmp_sum = 0;
  icmp_header->icmp_sum = cksum(icmp_header,LENGTH_ICMP_TYPE3_HDR);

  sr_send_packet(sr,(uint8_t*)icmp_packet,
                sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + LENGTH_ICMP_TYPE3_HDR,
                interface->name);

}

/* Handle ARP packet */
void sr_handle_receive_arppacket(struct sr_instance* sr, uint8_t *packet,
                                unsigned int len, struct sr_if* interface)
{
  sr_ethernet_hdr_t *arp_ethernet = (sr_ethernet_hdr_t*)packet;
  sr_arp_hdr_t *arp_header = (sr_arp_hdr_t*)((uint8_t*)arp_ethernet + sizeof(sr_ethernet_hdr_t));
  
  assert(arp_ethernet);
  #if DEBUG
    /*print_hdr_arp((uint8_t*)arp_header);*/
  #endif
  unsigned short arp_opcode = ntohs(arp_header->ar_op);
  switch(arp_opcode)
  {
    case arp_op_request :
    {
      sr_handle_recv_arp_request(sr,arp_header,interface);
      break;
    }
    case arp_op_reply :
    {
      sr_handle_recv_arp_reply(sr,arp_header,interface);
      break;
    }

    default :
    {
      /* */
      break;
    }
  }

}

void sr_handle_recv_arp_request(struct sr_instance *sr, sr_arp_hdr_t * arp_header, struct sr_if *interface)
{
  /* Send ARP reply */
  #if DEBUG
  printf("Send arp reply\n");
  #endif
  sr_send_arp_reply(sr,arp_header,interface);
}

void sr_handle_recv_arp_reply(struct sr_instance *sr, sr_arp_hdr_t * arp_header, struct sr_if *interface)
{
  struct sr_arpreq *arp_req_check;
  struct sr_arpentry *sr_arp_entry ;
  struct sr_nat_mapping *mapping ;
  uint16_t aux = 0;
  printf("Receive ARP REPLY %x \n",arp_header->ar_sip);
  /* Cache the ARP reply */
  arp_req_check = sr_arpcache_find_arpreq(&(sr->cache),arp_header->ar_sip);

  /* Check correct MAC address to interface */
  if (memcmp(interface->addr, arp_header->ar_tha,ETHER_ADDR_LEN) == 0)
  {
      unsigned char mac_insert[ETHER_ADDR_LEN];
      memcpy(mac_insert,arp_header->ar_sha,ETHER_ADDR_LEN);
      sr_arp_entry = sr_arpcache_lookup(&(sr->cache),arp_header->ar_sip);
      if (sr_arp_entry == NULL)
      {
        sr_arpcache_insert(&(sr->cache),mac_insert,arp_header->ar_sip);
      }
      /*arp_req_insert = sr_arpcache_insert(&(sr->cache),mac_insert,arp_header->ar_sip);*/

    #if DEBUG_ARP_TABLE
    sr_arpcache_dump(&(sr->cache));
    #endif
    /* Check request queue */
    if (arp_req_check == NULL)
    {
      printf("***************NULL*****************\n");
    }
    /* Send all outstanding packets in the queue */
    if (arp_req_check != NULL)
    {

      struct sr_packet *current_packet_queue = arp_req_check->packets;
      #if 1
      printf("IP ARP QUEUE %x\n",arp_req_check->ip);
      printf("Interface queue %s\n",current_packet_queue->iface);
      #endif
      /*struct sr_if *interface_send = sr_get_interface(sr,current_packet_queue->iface);*/
      
      /*print_addr_eth(interface_send->addr);*/

      struct sr_rt *routing_arp = sr_find_lpm_routingtable(sr->routing_table,ntohl(arp_req_check->ip));
      struct sr_if *interface_send = sr_get_interface(sr,routing_arp->interface);

      while(current_packet_queue)
      {
        sr_ethernet_hdr_t *ethernet_header = (sr_ethernet_hdr_t*)(current_packet_queue->buf);
        sr_ip_hdr_t *ip_header = (sr_ip_hdr_t*)( (uint8_t*)ethernet_header + sizeof(sr_ethernet_hdr_t));
        sr_icmp_hdr_t *icmp_header = NULL;
        if (ip_header->ip_p == ip_protocol_icmp)
        {
          icmp_header = (sr_icmp_hdr_t*)( (uint8_t*)ip_header + sizeof(sr_ip_hdr_t));
          aux = icmp_header->icmp_id;
        }
        if(nat_check_packet_from_external_or_internal(ntohl(ip_header->ip_src)) && sr->nat->nat_enable)
        {
          printf("queue arp internal\n");
          mapping = sr_nat_lookup_internal(sr->nat,ip_header->ip_src,aux,nat_mapping_icmp);
          if(mapping)
          {
          ip_header->ip_src = sr->nat->interface->ip;
          icmp_header->icmp_id = mapping->aux_ext;
          }
          
        }

        memcpy(ethernet_header->ether_shost, interface_send->addr,ETHER_ADDR_LEN);
        memcpy(ethernet_header->ether_dhost, arp_header->ar_sha,ETHER_ADDR_LEN);

        sr_send_packet(sr,current_packet_queue->buf, current_packet_queue->len,
          routing_arp->interface);
        #if DEBUG
        print_hdrs(current_packet_queue->buf,current_packet_queue->len);
        #endif
        current_packet_queue = current_packet_queue->next;
      }
    }
    sr_arpreq_destroy(&(sr->cache),arp_req_check);
  }
}

void sr_send_arp_reply(struct sr_instance *sr, sr_arp_hdr_t * arp_header,struct sr_if *interface )
{
  uint8_t *arp_packet = (uint8_t*)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  sr_ethernet_hdr_t *arp_ethernet = (sr_ethernet_hdr_t*)arp_packet;
  sr_arp_hdr_t *arpreply_header = (sr_arp_hdr_t*)((uint8_t*)arp_packet + sizeof(sr_ethernet_hdr_t));

  /*
    Create Arp packet
  */

  /* Ethernet header*/
  memcpy(arp_ethernet->ether_shost, interface->addr,ETHER_ADDR_LEN);
  memcpy(arp_ethernet->ether_dhost, arp_header->ar_sha,ETHER_ADDR_LEN);
  arp_ethernet->ether_type = htons(ethertype_arp);
  /* Arp header */
  arpreply_header->ar_hrd = htons(arp_hrd_ethernet);
  arpreply_header->ar_pro = htons(ethertype_ip);
  arpreply_header->ar_hln = length_of_hardware;
  arpreply_header->ar_pln = length_of_protocol;
  arpreply_header->ar_op = htons(arp_op_reply);
  memcpy(arpreply_header->ar_sha,interface->addr,ETHER_ADDR_LEN);
  arpreply_header->ar_sip = interface->ip;
  memcpy(arpreply_header->ar_tha, arp_header->ar_sha,ETHER_ADDR_LEN);
  arpreply_header->ar_tip = arp_header->ar_sip;
  
  #if DEBUG
  print_hdr_arp((uint8_t*)arpreply_header);
  #endif
  sr_arpcache_insert(&(sr->cache),arp_header->ar_sha,arp_header->ar_sip);

  sr_send_packet(sr, arp_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface->name);

}

void sr_send_arp_request( struct sr_instance *sr, sr_ip_hdr_t *ip_header, 
                          struct sr_rt *route)
{
  #if DEBUG
  printf("Send ARP request\n");
  #endif
  uint8_t *arp_packet = (uint8_t*)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  sr_ethernet_hdr_t *arp_ethernet = (sr_ethernet_hdr_t*)arp_packet;
  sr_arp_hdr_t *arp_header = (sr_arp_hdr_t*)((uint8_t*)arp_packet + sizeof(sr_ethernet_hdr_t));

  struct sr_if *interface_send = sr_get_interface(sr,route->interface);
  /*
    Create Arp packet
  */

  /* Ethernet header*/
  memcpy(arp_ethernet->ether_shost, interface_send->addr,ETHER_ADDR_LEN);
  memcpy(arp_ethernet->ether_dhost, broadcastAddr,ETHER_ADDR_LEN);
  arp_ethernet->ether_type = htons(ethertype_arp);
  /* Arp header */
  arp_header->ar_hrd = htons(arp_hrd_ethernet);
  arp_header->ar_pro = htons(ethertype_ip);
  arp_header->ar_hln = length_of_hardware;
  arp_header->ar_pln = length_of_protocol;
  arp_header->ar_op = htons(arp_op_request);
  memcpy(arp_header->ar_sha,interface_send->addr,ETHER_ADDR_LEN);
  arp_header->ar_sip = interface_send->ip;
  memset(arp_header->ar_tha,0x00,ETHER_ADDR_LEN);
  arp_header->ar_tip = ip_header->ip_dst;
  
  #if DEBUG
  print_hdrs((uint8_t*)arp_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  #endif

  sr_send_packet(sr, arp_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface_send->name);

}

void sr_send_arp_request1( struct sr_instance *sr, struct sr_arpreq *arp_req)
{
  #if DEBUG
  printf("Send ARP request\n");
  #endif

  uint8_t *arp_packet = (uint8_t*)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  sr_ethernet_hdr_t *arp_ethernet = (sr_ethernet_hdr_t*)arp_packet;
  sr_arp_hdr_t *arp_header = (sr_arp_hdr_t*)((uint8_t*)arp_packet + sizeof(sr_ethernet_hdr_t));

  struct sr_rt *routing_arp = sr_find_lpm_routingtable(sr->routing_table,ntohl(arp_req->ip));
  struct sr_if *interface_send = sr_get_interface(sr,routing_arp->interface);
  /*struct sr_if *interface_send = sr_get_interface(sr,arp_req->packets->iface);*/
  /*
  Create Arp packet
  */

  /* Ethernet header*/
  memcpy(arp_ethernet->ether_shost, interface_send->addr,ETHER_ADDR_LEN);
  memcpy(arp_ethernet->ether_dhost, broadcastAddr,ETHER_ADDR_LEN);
  arp_ethernet->ether_type = htons(ethertype_arp);
  /* Arp header */
  arp_header->ar_hrd = htons(arp_hrd_ethernet);
  arp_header->ar_pro = htons(ethertype_ip);
  arp_header->ar_hln = length_of_hardware;
  arp_header->ar_pln = length_of_protocol;
  arp_header->ar_op = htons(arp_op_request);
  memcpy(arp_header->ar_sha,interface_send->addr,ETHER_ADDR_LEN);
  arp_header->ar_sip = interface_send->ip;
  memset(arp_header->ar_tha,0x00,ETHER_ADDR_LEN);
  arp_header->ar_tip = arp_req->ip;

  #if DEBUG
  print_hdrs((uint8_t*)arp_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  #endif

  sr_send_packet(sr, arp_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface_send->name);

}

/*
****************************************************************************************
************************************ Handle TCP ****************************************
****************************************************************************************
*/
struct sr_tcp_hdr *get_TCPheader(uint8_t *packet)
{
  sr_tcp_hdr_t *tcp_header_copy = NULL;
  tcp_header_copy = (sr_tcp_hdr_t*)calloc(1,sizeof(sr_tcp_hdr_t));

  sr_ethernet_hdr_t *ether_header = (sr_ethernet_hdr_t*)packet;
  sr_ip_hdr_t *ip_header = (sr_ip_hdr_t*)( (uint8_t*)ether_header + sizeof(sr_ethernet_hdr_t));
  sr_tcp_hdr_t *tcp_header = (sr_tcp_hdr_t*)( (uint8_t*)ip_header + sizeof(sr_ip_hdr_t));

  print_infor_tcp_header(tcp_header);
  memcpy(tcp_header_copy,tcp_header,sizeof(sr_tcp_hdr_t));

  return tcp_header_copy;
}

void print_infor_tcp_header(sr_tcp_hdr_t *tcp_header)
{
  printf("TCP shost %d\n",ntohs(tcp_header->tcp_sport));
  printf("TCP dhost %d\n",ntohs(tcp_header->tcp_dport));
  printf("TCP_seq %u\n",ntohl(tcp_header->tcp_seq));
  printf("TCP_ack %u\n",ntohl(tcp_header->tcp_ack));
  printf("TCP_hdrlen_flags %x\n",getFlag_tcp_header(tcp_header));
  printf("TCP_windowsize %d\n",ntohs(tcp_header->tcp_windowsize));
  printf("TCP sum %x\n",ntohs(tcp_header->tcp_sum));
}

uint16_t getFlag_tcp_header(sr_tcp_hdr_t *tcp_header)
{
  return ((ntohs((tcp_header->tcp_hdrlen_flags)) & MASK_FLAGS));
}

/*************************************************************************************/

bool check_destIP_for_router(struct sr_instance *sr, sr_ip_hdr_t *ip_header)
{
  int check = false;
  struct sr_if *sr_if_index = sr->if_list;
  while(sr_if_index)
  {
    if (sr_if_index->ip == ip_header->ip_dst)
    {
      check = true;
    }
    sr_if_index = sr_if_index->next;
  }
  return check;
}

bool check_validation_ip_header(sr_ip_hdr_t *ip_header, unsigned int len)
{
  bool check = false;
  uint16_t check_sum = ip_header->ip_sum;

  if (ip_header->ip_v != 4)
  {
    check = false;
    return check;
  }

  ip_header->ip_sum = 0;
  uint16_t cksum_calc = cksum(ip_header,MIN_LENGTH_OF_IP_HEADER);

  if (check_sum == cksum_calc)
  {
    check = true;
  }
  return check;
}


struct sr_rt *sr_find_lpm_routingtable(struct sr_rt *routing_table, uint32_t ip_addr)
{
  struct sr_rt *rtable_index = routing_table;
  int16_t longgest_bit_match = -1;
  struct sr_rt * ip_routing = (struct sr_rt*)calloc(1,sizeof(struct sr_rt));
  while(rtable_index)
  {
    if ((ip_addr & ntohl(rtable_index->mask.s_addr))
        == (ntohl(rtable_index->dest.s_addr) & ntohl(rtable_index->mask.s_addr)) )
    {
      if (calc_length_of_mask(rtable_index) > longgest_bit_match)
      {
        memcpy(ip_routing,rtable_index,sizeof(struct sr_rt));
        longgest_bit_match = calc_length_of_mask(rtable_index);
      }
    }
    rtable_index = rtable_index->next;
  }

  if ((longgest_bit_match == 0) && (ip_addr != 0x0a000164))
  {
    #if DEBUG
    printf("check 10.0.1.100\n");
    #endif
    return NULL;
  }

  return ip_routing;
}

int16_t calc_length_of_mask(struct sr_rt *routing_index)
{
  int16_t count_bit_1 = 0;
  uint32_t mask_base = 1 << 31;

  while (mask_base & (ntohl(routing_index->mask.s_addr)))
  {
    count_bit_1 = count_bit_1 + 1;
    mask_base = mask_base >> 1;
  }
  return count_bit_1;
}
