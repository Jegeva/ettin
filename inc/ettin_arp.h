#ifndef __ETTIN_ARP_H
#define __ETTIN_ARP_H

#include <time.h>
#include <net/if_arp.h>
#include <zlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

typedef struct IP4_arp_state_t
{
    uint32_t ip4_h;
    uint32_t ip4_n;
    char arp_sent;
    struct timeval * tv_sent;
    char * ip4_string;
    char arp_received;
    char mac_addr[6];
    char * mac_addr_string;
    struct timeval * tv_lastpoison;
    struct IP4_arp_state_t *prev;
    struct IP4_arp_state_t *next;
    unsigned char is_target;

} IP4_arp_state_t;

IP4_arp_state_t * IP4_arp_state_head;


void start_poison();
void print_ip_list();
void free_ip_list();
void make_ip_list();
void arping();



#endif
