#ifndef __ETTIN_H
#define __ETTIN_H
#include <stdlib.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;


#include <ettin_pcap.h>
#include <ettin_arp.h>
#include <ettin_mac.h>



struct global_params
{
  uint8_t   global_verbosity;
  uint8_t   do_list;
  uint8_t   is_wireless;
  char*     device;
  char*     source_ip;
  uint32_t  source_ip_AF;
  char**    destination_ips;
  uint32_t* destination_ips_AF;
  char**    progfilters;
  int       progfilters_cnt;
  unsigned char      port_cnt;
  unsigned int *     portlist;
  uint32_t  destinations_cnt;
  uint32_t  max_threads;
  uint32_t  timeout_millis;
  char *    pcapfilter;
  char      filter_is_alloced;
  volatile char      poisonning;
  int filter_chain_IO_fds [2];
} global_params ;


int check_targets();

#endif
