#ifndef __ETTIN_PCAP_H
#define __ETTIN_PCAP_H

#include <main.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>


struct {
    char * name;
    char type;
    pcap_t * handle;
    pcap_if_t * curr_dev;
    pcap_if_t * alldevsp;
    char * localmac_string;
    unsigned char localmac[6];
    struct bpf_program * fp;


    char * ip_string_v4;
    char * mask_string_v4;
    char * broad_string_v4;
    char * dstaddr_string_v4;
    uint32_t ip_raw_v4;
    uint32_t mask_raw_v4;
    uint32_t broad_raw_v4;
    uint32_t dstaddr_raw_v4;

    char * ip_string_v6;
    char * mask_string_v6;
    char * broad_string_v6;
    char * dstaddr_string_v6;
    uint128_t ip_raw_v6;
    uint128_t mask_raw_v6;
    uint128_t broad_raw_v6;
    uint128_t dstaddr_raw_v6;

} pcap_device_infos;


int ettin_init_pcap_device(char *);
void ettin_pcap_cleanup();
void stop_poison();


#endif
