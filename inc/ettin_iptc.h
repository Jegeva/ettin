#ifndef __ETTIN_IPTC_H
#define __ETTIN_IPTC_H

#include <main.h>
#include <ettin.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <libiptc/libiptc.h>
static int insert_rule    ( const char *table,  const char *chain,
                              unsigned int src, int inverted_src,
                              unsigned int dest, int inverted_dst,
                              const char *target);

/*static int insert_rule_str( const char *table, const char *chain,
                              char * strsrc, int inverted_src,
                              char * strdest,int inverted_dst,
                              const char *target);

*/
#endif
