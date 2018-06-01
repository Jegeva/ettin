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


uint32_t seq_side1_h1,ack_side1_h1,seq_side1_h2,ack_side1_h2;
uint32_t seq_side2_h1,ack_side2_h1,seq_side2_h2,ack_side2_h2;
int32_t deltaS1, deltaS2;
uint32_t ip_side1=0,ip_side2=0;

int balance_legs(char * msg, uint32_t msgsz, uint32_t ippaystart,uint32_t tcppaystart)
{
    char str[INET6_ADDRSTRLEN];
    if(ip_side1 == ip_side2){
        //init
        ip_side1 = *(uint32_t*)(msg+ippaystart+12);
        ip_side2 = *(uint32_t*)(msg+ippaystart+16);

        seq_side1_h1= ntohl(*(uint32_t*)(msg+tcppaystart+4));
        ack_side1_h1= ntohl(*(uint32_t*)(msg+tcppaystart+8));

        inet_ntop(AF_INET,&ip_side1,str,INET6_ADDRSTRLEN);
        fprintf(stderr,"1:%s ",str);
        inet_ntop(AF_INET,&ip_side2,str,INET6_ADDRSTRLEN);
        fprintf(stderr,"2:%s\n%d %d\n",str,ippaystart,tcppaystart);

    } else {
        if(ip_side1 == *(uint32_t*)(msg+ippaystart+12)){
            // 1->2
            seq_side1_h1= ntohl(*(uint32_t*)(msg+tcppaystart+4));
            ack_side1_h1= ntohl(*(uint32_t*)(msg+tcppaystart+8));
        } else {
            // 2->1
            seq_side2_h2= ntohl(*(uint32_t*)(msg+tcppaystart+4));
            ack_side2_h2= ntohl(*(uint32_t*)(msg+tcppaystart+8));
        }
        fprintf(stderr,"0x%.08x 0x%.08x 0x%.08x 0x%.08x\n",seq_side1_h1,ack_side1_h1,seq_side2_h2,ack_side2_h2);

    }
}



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
    L1_head_len=14;
    L2_type = ntohs(*(uint16_t*)(msg+12));

    switch(L2_type){
    case ETH_P_IP:
        L2_head_len = sizeof(uint32_t) * (0xf & *(uint8_t*)(msg+L1_head_len));
        L3_type = *(uint8_t*)(msg+L1_head_len+9);
        L2_len= ntohs(*(uint16_t*)(msg+L1_head_len+2));
        break;

    }



    switch(L3_type){
    case IPPROTO_TCP:
        if(msgsz>0x40){
            target = msg+0x40+20;
            while(target){
                target = strstr(target,"2018");
                if (target !=NULL   )
                {
                    *(target+3)='9';
                    target++;
                }
            }
        }
        balance_legs(msg,msgsz,L1_head_len,L1_head_len+L2_head_len);

    }

    write(STDOUT_FILENO,&msgsz,4);
    write(STDOUT_FILENO,msg,msgsz);

  }
}
