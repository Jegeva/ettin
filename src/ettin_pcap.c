#include <ettin_pcap.h>



#define ETTIN_HAVEIPv4 1
#define ETTIN_HAVEIPv6 2


void ettin_pcap_cleanup()
{
    free(pcap_device_infos.name);

    pcap_close(pcap_device_infos.handle);
    if(pcap_device_infos.ip_string_v4 != NULL)
		free(pcap_device_infos.ip_string_v4);
    if(pcap_device_infos.mask_string_v4 != NULL)
		free(pcap_device_infos.mask_string_v4);
    if(pcap_device_infos.broad_string_v4 != NULL)
		free(pcap_device_infos.broad_string_v4);
    if(pcap_device_infos.dstaddr_string_v4 != NULL)
		free(pcap_device_infos.dstaddr_string_v4);
    if(pcap_device_infos.ip_string_v6 != NULL)
		free(pcap_device_infos.ip_string_v6);
    if(pcap_device_infos.mask_string_v6 != NULL)
		free(pcap_device_infos.mask_string_v6);
    if(pcap_device_infos.broad_string_v6 != NULL)
		free(pcap_device_infos.broad_string_v6);
    if(pcap_device_infos.dstaddr_string_v6 != NULL)
		free(pcap_device_infos.dstaddr_string_v6);
    if(pcap_device_infos.fp != NULL){
		pcap_freecode(pcap_device_infos.fp);
		free(pcap_device_infos.fp);
	}
    if(pcap_device_infos.localmac_string != NULL)
		free(pcap_device_infos.localmac_string);
    if(pcap_device_infos.alldevsp != NULL)
		pcap_freealldevs(pcap_device_infos.alldevsp);
    if(global_params.pcapfilter != NULL && global_params. filter_is_alloced)
		free(global_params.pcapfilter);
}



int ettin_findpcapdevice(char *device) {/* Name of device (e.g. eth0, wlan0) */
    char found = 0;
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
    pcap_if_t * alldevsp,*curr_dev;
    pcap_findalldevs(&alldevsp,error_buffer);
    curr_dev=alldevsp;
    while(curr_dev->next != NULL){
		ETTIN_PERROR(3," Name:%s\tDescr:%s,\tflags:%d\n",curr_dev->name,curr_dev->description, curr_dev->flags);
		if(strcmp(device,curr_dev->name)==0) found =1;
		curr_dev = curr_dev->next;
    }
    pcap_freealldevs(alldevsp);
    if((global_params.global_verbosity >0)) {
		if ( (found == 0) ){
			ETTIN_PERROR(1,"Error finding device: %s\n", device);
		} else {
			ETTIN_PERROR(1,"Network device found: %s\n", device);
		}
    }
    return found;
}

int ettin_init_pcap_device(char *device)
{
    pcap_if_t * alldevsp,*curr_dev;
    pcap_addr_t * curr_address;
    char * curr_buff;
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
    FILE * f;
    struct bpf_program * fp =(struct bpf_program *)malloc(sizeof(struct bpf_program)); ;

    memset(&pcap_device_infos,0,sizeof(pcap_device_infos ));
    if(ettin_findpcapdevice(device)){
		pcap_findalldevs(&alldevsp,error_buffer);
		curr_dev=alldevsp;
		while(strcmp(device,curr_dev->name)!=0)
			curr_dev = curr_dev->next;
		pcap_device_infos.alldevsp = alldevsp;
		pcap_device_infos.curr_dev = curr_dev;
		pcap_device_infos.name = (char*)calloc(strlen(curr_dev->name)+1,sizeof(char));
		strcpy(pcap_device_infos.name,curr_dev->name);
		ETTIN_PERROR(2,"Adresses for: %s\n", pcap_device_infos.name);
		curr_address = curr_dev->addresses;
		//	while(curr_address->next != NULL){
			while(curr_address != NULL){
			if(curr_address->addr->sa_family == AF_INET){
				pcap_device_infos.type |= ETTIN_HAVEIPv4;
				curr_buff = (char*)calloc(INET_ADDRSTRLEN+1,sizeof(char));
				inet_ntop(AF_INET,&(((struct sockaddr_in*)curr_address->addr)->sin_addr),curr_buff,INET_ADDRSTRLEN );
				pcap_device_infos.ip_string_v4 = curr_buff;
				pcap_device_infos.ip_raw_v4 = (uint32_t)(((struct sockaddr_in*)curr_address->addr)->sin_addr).s_addr;
				ETTIN_PERROR(2,"Add:%s\n",curr_buff);
				if(curr_address->netmask != NULL){
					curr_buff = (char*)calloc(INET_ADDRSTRLEN+1,sizeof(char));
					inet_ntop(AF_INET,&(((struct sockaddr_in*)curr_address->netmask)->sin_addr),curr_buff,INET_ADDRSTRLEN );
					pcap_device_infos.mask_string_v4 = curr_buff;
					pcap_device_infos.mask_raw_v4 = (uint32_t)(((struct sockaddr_in*)curr_address->netmask)->sin_addr).s_addr;
					ETTIN_PERROR(2,"Msk:%s\n",curr_buff);
				}
				if(curr_address->broadaddr != NULL){
					curr_buff = (char*)calloc(INET_ADDRSTRLEN+1,sizeof(char));
					inet_ntop(AF_INET,&(((struct sockaddr_in*)curr_address->broadaddr)->sin_addr),curr_buff,INET_ADDRSTRLEN );
					pcap_device_infos.broad_string_v4 = curr_buff;
					pcap_device_infos.broad_raw_v4 = (uint32_t)(((struct sockaddr_in*)curr_address->broadaddr)->sin_addr).s_addr;
					ETTIN_PERROR(2,"Brd:%s\n",curr_buff);
				}
				if(curr_address->dstaddr != NULL){
					curr_buff = (char*)calloc(INET_ADDRSTRLEN+1,sizeof(char));
					inet_ntop(AF_INET,&(((struct sockaddr_in*)curr_address->dstaddr)->sin_addr),curr_buff,INET_ADDRSTRLEN );
					pcap_device_infos.dstaddr_string_v4 = curr_buff;
					pcap_device_infos.dstaddr_raw_v4 = (uint32_t)(((struct sockaddr_in*)curr_address->dstaddr)->sin_addr).s_addr;
					ETTIN_PERROR(2,"Dst:%s\n",curr_buff);
				}
			} else {
				if(curr_address->addr->sa_family == AF_INET6){
					pcap_device_infos.type |= ETTIN_HAVEIPv6;
					curr_buff = (char*)calloc(INET6_ADDRSTRLEN,sizeof(char));
					inet_ntop(AF_INET6,&(((struct sockaddr_in6*)curr_address->addr)->sin6_addr),curr_buff,INET6_ADDRSTRLEN );
					pcap_device_infos.ip_string_v6 = curr_buff;
					memcpy(&pcap_device_infos.ip_raw_v6,&(((struct sockaddr_in6*)curr_address->addr)->sin6_addr).__in6_u.__u6_addr8,
						   sizeof(uint128_t));
					ETTIN_PERROR(2,"Add6:%s\n",curr_buff);
					if(curr_address->netmask != NULL){
						curr_buff = (char*)calloc(INET6_ADDRSTRLEN,sizeof(char));
						inet_ntop(AF_INET6,&(((struct sockaddr_in6*)curr_address->netmask)->sin6_addr),curr_buff,INET6_ADDRSTRLEN );
						pcap_device_infos.mask_string_v6 = curr_buff;
						memcpy(&pcap_device_infos.mask_raw_v6,&(((struct sockaddr_in6*)curr_address->netmask)->sin6_addr).__in6_u.__u6_addr8,
							   sizeof(uint128_t));
						ETTIN_PERROR(2,"Msk6:%s\n",curr_buff);
					}
					if(curr_address->broadaddr != NULL){
						curr_buff = (char*)calloc(INET6_ADDRSTRLEN,sizeof(char));
						inet_ntop(AF_INET6,&(((struct sockaddr_in6*)curr_address->broadaddr)->sin6_addr),curr_buff,INET6_ADDRSTRLEN );
						pcap_device_infos.broad_string_v6 = curr_buff;
						memcpy(&pcap_device_infos.broad_raw_v6,&(((struct sockaddr_in6*)curr_address->broadaddr)->sin6_addr).__in6_u.__u6_addr8,
							   sizeof(uint128_t));
						ETTIN_PERROR(2,"Brd6:%s\n",curr_buff);
					}
					if(curr_address->dstaddr != NULL){
						curr_buff = (char*)calloc(INET6_ADDRSTRLEN,sizeof(char));
						inet_ntop(AF_INET6,&(((struct sockaddr_in6*)curr_address->dstaddr)->sin6_addr),curr_buff,INET6_ADDRSTRLEN );
						pcap_device_infos.dstaddr_string_v6 = curr_buff;
						memcpy(&pcap_device_infos.dstaddr_raw_v6,&(((struct sockaddr_in6*)curr_address->dstaddr)->sin6_addr).__in6_u.__u6_addr8,
							   sizeof(uint128_t));
						ETTIN_PERROR(2,"Dst6:%s\n",curr_buff);
					}
				} else {
					;

				}
			}
			curr_address = curr_address->next;
		}


		pcap_device_infos.handle = pcap_create(pcap_device_infos.name, error_buffer);

		if(pcap_device_infos.handle == NULL){
			fprintf(stderr,"can't open %s: %s\n",pcap_device_infos.name,error_buffer);
			return(0);
		}

		if(global_params.is_wireless){
			switch( pcap_can_set_rfmon(pcap_device_infos.handle)  ){
			case 0:
				break;
			case PCAP_ERROR_PERM_DENIED:
				ETTIN_PERROR(1, "Can't put in monitor mode, not enough rights\n");
				return 0;
			case PCAP_ERROR:
				ETTIN_PERROR(1, " Can't put in monitor mode, %s\n",error_buffer);
			}

			pcap_set_rfmon(pcap_device_infos.handle, 1);
		}




		pcap_set_immediate_mode(pcap_device_infos.handle, 1);
		pcap_set_promisc(pcap_device_infos.handle, 1); /* Capture packets that are not yours */
		pcap_set_snaplen(pcap_device_infos.handle, 2048); /* Snapshot length */
		pcap_set_timeout(pcap_device_infos.handle, 1000); /* Timeout in milliseconds */
		switch(pcap_activate(pcap_device_infos.handle)){
		case 0:
			ETTIN_PERROR(0, "Activated %s \n",pcap_device_infos.name);
			break;

		case PCAP_WARNING_PROMISC_NOTSUP:
			ETTIN_PERROR(0, "Promiscuous mode not supported\n");
			break;
		case PCAP_WARNING:
			ETTIN_PERROR(0, "Activated with Warning\n");
			break;
		case PCAP_ERROR_ACTIVATED:
			ETTIN_PERROR(0, "Already activated\n");
			break;
		case PCAP_ERROR_NO_SUCH_DEVICE:
			ETTIN_PERROR(0, "No such device\n");
			break;
		case PCAP_ERROR_PERM_DENIED:
			ETTIN_PERROR(0, "Not enough rights\n");
			return 0;

			break;
		case PCAP_ERROR_RFMON_NOTSUP:
			ETTIN_PERROR(0, "RFMon not supported\n");
			break;
		case PCAP_ERROR_IFACE_NOT_UP:
			ETTIN_PERROR(0, "Iface not up\n");
			break;
		case PCAP_ERROR:
			break;
		}

		if(global_params.pcapfilter != NULL){

			 char * arp_filter ;
			 asprintf(&arp_filter,"%s or arp",global_params.pcapfilter);
			 //			global_params.filter_is_alloced = 1;

			if(pcap_compile(pcap_device_infos.handle,fp,arp_filter,0,ntohl(pcap_device_infos.mask_raw_v4))<0){
				ETTIN_PERROR(0, "filter compile failed: %s\n",pcap_geterr(pcap_device_infos.handle));
				exit(0);
			} else {
				ETTIN_PERROR(2, "filter compile success: %s\n",global_params.pcapfilter);
				pcap_setfilter(pcap_device_infos.handle,fp);
			}
			free(arp_filter);


		}


		pcap_device_infos.fp = fp;




		pcap_device_infos.localmac_string = calloc(18,sizeof(char));
		char * string_file_mac = calloc(1024,sizeof(char));
		sprintf(string_file_mac, "/sys/class/net/%s/address",pcap_device_infos.name);
		//  printf("%s\n",string_file_mac);
		f=fopen(string_file_mac,"r");
		fread(string_file_mac,17,sizeof(char),f);

		strncpy(pcap_device_infos.localmac_string,string_file_mac,17);
		printf("LOCAL MAC %s\n",pcap_device_infos.localmac_string);
		sscanf(pcap_device_infos.localmac_string,"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
			   &pcap_device_infos.localmac[0],   &pcap_device_infos.localmac[1],
			   &pcap_device_infos.localmac[2],   &pcap_device_infos.localmac[3],
			   &pcap_device_infos.localmac[4],   &pcap_device_infos.localmac[5]
			   );
		/* printf("->%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		   pcap_device_infos.localmac[0],   pcap_device_infos.localmac[1],
		   pcap_device_infos.localmac[2],   pcap_device_infos.localmac[3],
		   pcap_device_infos.localmac[4],   pcap_device_infos.localmac[5]
		   );*/
		ETTIN_PERROR(2,"Mac:%s\n",pcap_device_infos.localmac_string);
		fclose(f);
		free(string_file_mac);

		return 1;

    } else {
		return 0;
    }
}
