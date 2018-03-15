#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
extern int errno;


#define P104_OFFSET 54
#define INPAYOFF_APDULEN 1
#define INPAYOFF_RX 2
#define INPAYOFF_TX 4
#define INPAYOFF_TYPE 6
#define INPAYOFF_IDFIELD 7
#define INPAYOFF_OA 9
#define INPAYOFF_ADDR 10
#define INPAYOFF_IOA 12

static const unsigned char template_ieac104[70] = {
  0x00, 0xa0, 0x45, 0xb1, 0xb4, 0x80, //dmac
  0x00, 0xe0, 0xa8, 0xb0, 0x58, 0xc4, //smac
  0x08, 0x00,                         //ipv4
  0x45,                               //v + iph len
  0x00, 0x00, 0x38, 0x2c, 0x86, 0x00, 0x00, 0x3c, 0x06, // ip head
  0x36, 0xf1, // ip chksum
  0x0a, 0x82, 0xff, 0x65, //ip src
  0x0a, 0x7f, 0x06, 0xe3, //ip dst
  
  0x09, 0x64, //sport
  0xfe, 0x04, //dport
  
  0x70, 0xc4, 0x9c, 0x06, // seq
  0x69, 0x55, 0x6f, 0xa2, // ack

  0x50, 0x18, 0x20, 0x00,

  0x65, 0x4c, // tcp head chk

  0x00, 0x00,

  /// IEC 104 NOW
  0x68, 0x0e, 0x4c, 0x00, 0x0a, 0x00,
  0x2e, 0x01, 0x07, 0x60, 0x2c, 0x03,
  0x01, 0x03, 0x01, 0x85
};


typedef struct {
  unsigned char  pkttype;
  unsigned char  apdulen;
  unsigned short tx;
  unsigned short rx;
  unsigned char  type;
  unsigned char  idfield;
  unsigned char  oa;
  unsigned short addr;
} __attribute__((packed)) header_104_t;






int main(int argc,char** argv){
  unsigned int msgsz;
  char * msg=NULL;
  int msg_alloc_sz=0;
  int r;
  
  int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
  fcntl(STDIN_FILENO, F_SETFL, flags & ~O_NONBLOCK);
  flags = fcntl(STDOUT_FILENO, F_GETFL, 0);
  fcntl(STDOUT_FILENO, F_SETFL, flags & ~O_NONBLOCK);

  header_104_t oldhead;
  header_104_t * newhead;

  unsigned int participants_ip[2];
  unsigned int participants_seq_orig[2];
  unsigned int participants_seq_mitm[2];
  unsigned int rxtx[2]; // in the p0 -> p1 direction
  unsigned int deltas_tcpseq[2]; // how far is the MITMed tcp seq
  unsigned int deltas_iecseq[2]; // how far is the MITMed iec seq
    
  participants_ip[0]=0;
  participants_ip[1]=0;
  
  
  while(1){
    r=read(STDIN_FILENO,&msgsz,4);
    if(r==0)
      exit(0);
    if(r!=4){
      perror("R=");
    }else{
      fprintf(stderr,"\n%s MSz:%d\n",argv[0],msgsz);
      fsync(STDERR_FILENO);
      if(msgsz>msg_alloc_sz){
        msg = (char*)realloc(msg,msgsz);
        msg_alloc_sz=msgsz;
      }else{
        memset(msg,0,msgsz+1);
      }
      newhead=(header_104_t*)(msg+P104_OFFSET);
      read(STDIN_FILENO,msg,msgsz);

      fprintf(stderr,"pkttype:\t\t0x%x\n",newhead->pkttype);
      fprintf(stderr,"apdulen:\t\t0x%x %d\n",newhead->apdulen,newhead->apdulen);
      fprintf(stderr,"tx:     \t\t  %d\n",newhead->tx>>1);
      fprintf(stderr,"rx:     \t\t  %d\n",newhead->rx>>1);
      fprintf(stderr,"type:   \t\t0x%x\n",newhead->type);
      fprintf(stderr,"idfield:\t\t0x%x\n",newhead->idfield);
      fprintf(stderr,"oa:     \t\t0x%x\n",newhead->oa);
      fprintf(stderr,"addr:   \t\t0x%x\n",newhead->addr);      
      
      // do stuff here

      if(participants_ip[0]==0){
	// initial pass
	participants_ip[0] = *(int*)(msg+26);
	participants_ip[1] = *(int*)(msg+30); 
	participants_seq_orig[0] = participants_seq_mitm[0] = *(int*)(msg+38);
	participants_seq_orig[1] = participants_seq_mitm[1] = *(int*)(msg+42);
	rxtx[0] = (*(short*)(msg+56))>>1 ;
	rxtx[1] = (*(short*)(msg+58))>>1 ; 
      } else {
	

      }
      
      // *(msg+3) +=1;

      // until here
      fcntl(STDOUT_FILENO, F_SETPIPE_SZ, 4);
      write(STDOUT_FILENO,&msgsz,4);
      fsync(STDOUT_FILENO);
      fcntl(STDOUT_FILENO, F_SETPIPE_SZ, msgsz);
      write(STDOUT_FILENO,msg,msgsz);
      fsync(STDOUT_FILENO);
      msgsz=0;
    }
  }
}
