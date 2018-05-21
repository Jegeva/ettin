#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <zlib.h>

#define RESET   "\033[0m"
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */

struct tcp_header
{
    unsigned short tcp_sprt;
    unsigned short tcp_dprt;
    unsigned int tcp_seq;
    unsigned int tcp_ack;
    unsigned char tcp_res:4;
    unsigned char tcp_off:4;
    unsigned char tcp_flags;
    unsigned short tcp_win;
    unsigned short tcp_csum;
    unsigned short tcp_urp;
} tcp_header;

struct
{
    unsigned int ip_src;
    unsigned int ip_dst;
    unsigned char zero;//always zero
    unsigned char protocol;// = 6;//for tcp
    unsigned short tcp_len;
    struct tcp_header tcph;
} pseudoTcpHeader;


// only call if you changed something in the pkt


int main(int argc,char** argv){
  unsigned int msgsz;
  char * msg=NULL;
  char * target;

  int msg_alloc_sz=0;
  while(1){
    read(STDIN_FILENO,&msgsz,4);
    fprintf(stderr,"%s MSz:%d\n",argv[0],msgsz);
    if(msgsz>msg_alloc_sz){
      msg = (char*)realloc(msg,msgsz);
      msg_alloc_sz=msgsz;
    }else{
      memset(msg,0,msgsz+1);
    }
    read(STDIN_FILENO,msg,msgsz);

    // do stuff here



    write(STDOUT_FILENO,&msgsz,4);
    write(STDOUT_FILENO,msg,msgsz);

  }
}
