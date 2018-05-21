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
    uint16_t L1_type,    L2_type,    L3_type,    L4_type;
    uint16_t L1_head_len,L2_head_len,L3_head_len,L4_head_len;
    uint16_t L1_len,     L2_len,     L3_len,     L4_len;
    L1_type=    L2_type=    L3_type=    L4_type=0;
    L1_head_len=L2_head_len=L3_head_len=L4_head_len=0;
    L1_len=     L2_len=     L3_len=     L4_len=0;

    // assuming ETH L1
    L2_type = ntohs(*(uint16_t*)(msg+12));

    switch(L2_type){
    case ETH_P_IP:
        L2_head_len = sizeof(uint32_t) * (0xf & *(uint8_t*)(msg+L1_head_len));
        L3_type = *(uint8_t*)(msg+L1_head_len+9);
        L2_len= ntohs(*(uint16_t*)(msg+L1_head_len+2));
        break;

    }




    if(msgsz>0x40){
        target = msg+0x40;
        while(target){
            target = strstr(target,"div");
            if (target !=NULL   )
            {
                target++;
                *(target)='a';
            }
        }
    }

    write(STDOUT_FILENO,&msgsz,4);
    write(STDOUT_FILENO,msg,msgsz);

  }
}
