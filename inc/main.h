#ifndef __ETTIN_MAIN_H
#define __ETTIN_MAIN_H
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <math.h>
#include <poll.h>
#include <getopt.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>

#include <ettin.h>

#define RESET   "\033[0m"
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */



#define ETTIN_PERROR(a,b,...) if(global_params.global_verbosity>a){fprintf(stderr,"%d:"b,a,##__VA_ARGS__);fflush(NULL);}


#endif
