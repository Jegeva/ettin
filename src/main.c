#include <main.h>

extern char *optarg;
extern int optind, opterr, optopt;

const char * opts = "s:D:d:mlt:vhb:w:f:p:";

static struct option long_options[] = {
    {"source-ip"           ,required_argument      , 0            ,  's' },
    {"device"              ,required_argument      , 0            ,  'D' },
    {"destination-ip"      ,required_argument      , 0            ,  'd' },
    {"max-threads"         ,required_argument      , 0            ,  'm' },
    {"list"                ,no_argument            , 0            ,  'l' },
    {"timeout"             ,required_argument      , 0            ,  't' },
    {"verbose"             ,no_argument            , 0            ,  'v' },
    {"help"                ,no_argument            , 0            ,  'h' },
    {"bpffilter"           ,required_argument      , 0            ,  'b' },
    {"wireless"            ,required_argument      , 0            ,  'w' },
    {"execfilter"          ,required_argument      , 0            ,  'f' },
    {"port"                ,required_argument      , 0            ,  'p' },
    {0                     ,0                      , 0            ,  0   }
};

char * long_options_help[] = {
    "source ip :the victim",
    "device (eth0,vmnet1,etc...)",
    "destination ip: the gateway",
    "max threads (>2)",
    "list hosts and quit",
    "timeout between repoisonnings (millisseconds)",
    "verbodity (repeat for more)",
    "this",
    "a pcap filter (man 7 pcap-filter)",
    "the interface is rf (requiring monitor mode)",
    "path to an executable filter, if multiple, behaves like f1|f2|...|fx",
    "port list (comma separated -separated ranges, pay attention that your bpf filters matches)",

    0
};



void print_help(char* name)
{
    int i;
    int n;
    for(i=0;i<(sizeof(long_options)/sizeof(struct option))-1;i++){
        n=printf("--%s (-%c):",long_options[i].name,long_options[i].val);

        if(n<16)
            putchar('\t');
        putchar('\t');
        printf("%s\n",long_options_help[i]);
    }

}

char * params_default_device = "eth0";
void init_default_options()
{
    memset(&global_params,0,sizeof(struct global_params));
    global_params.destinations_cnt=0;
    global_params.device = params_default_device;
    global_params.is_wireless = 0;
    global_params.timeout_millis=4000;
    global_params.poisonning=0;
    global_params.portlist=NULL;
    global_params.progfilters= NULL;
    global_params.progfilters_cnt= 0;


}


int main(int argc,char** argv)
{
    int opt;
    int option_index = 0;
    int i,j;
    pid_t pid;
    char * tmpptr;
    global_params.global_verbosity=0;


    int* filter_chain_internal_fds;
    /*
    int wr_sz,re_sz;
    char * wr_testbuff ="abcd";
    char * re_testbuff = calloc(5,sizeof(char));
    */

    init_default_options();


    while ((opt = getopt_long(argc, argv, opts, long_options, &option_index)) != -1) {
        if(!option_index){
            if(global_params.global_verbosity>3) fprintf(stderr,"CLI OPT: %c:%s\n",opt,optarg==NULL?"":optarg);
        } else {
            if(global_params.global_verbosity>3) fprintf(stderr,"CLI OPT: %s:%s\n",long_options[option_index].name,optarg);
        }
        switch (opt) {
        case 0:
            break;
        case 's':
            global_params.source_ip = optarg;
            global_params.destinations_cnt++;
            if(global_params.destinations_cnt){
                global_params.destination_ips=realloc(
                                                      global_params.destination_ips,
                                                      global_params.destinations_cnt*sizeof(char*)
                                                      );
            }else{
                global_params.destination_ips = (char**)calloc(1,sizeof(char*));
            }
            global_params.destination_ips[global_params.destinations_cnt-1] = optarg;
            break;
        case 'D':
            global_params.device = optarg;
            break;
        case 'd':
            global_params.destinations_cnt++;
            global_params.destination_ips=realloc(
                                                  global_params.destination_ips,
                                                  global_params.destinations_cnt*sizeof(char*)
                                                  );
            global_params.destination_ips[global_params.destinations_cnt-1] = optarg;
            break;
        case 'f':
            global_params.progfilters_cnt++;
            global_params.progfilters=realloc(
                                              global_params.progfilters,
                                              global_params.progfilters_cnt*sizeof(char*)
                                              );
            global_params.progfilters[global_params.progfilters_cnt-1] = optarg;
            printf("f%d\n",global_params.progfilters_cnt);
            break;
        case 'm':
            global_params.max_threads = strtoll(optarg,NULL,10);
            break;
        case 'l':
            global_params.do_list = 1;
            break;
        case 't':
            global_params.timeout_millis = strtoll(optarg,NULL,10);
            break;
        case 'v':
            global_params.global_verbosity++;
            break;
        case 'h':
            print_help(argv[0]);
            exit(0);
            break;
        case 'b':
            global_params.pcapfilter = optarg;
            break;
        case 'w':
            global_params.is_wireless = 1;
            break;
	case 'p':
	  i=0;global_params.port_cnt=1;
	  while(*(optarg+i) != 0){
	    if(*(optarg+i)==','){
	      global_params.port_cnt++;
	      *(optarg+i)=0;	      
	    }
	    i++;
	  }
	  global_params.portlist=(unsigned int*)calloc(global_params.port_cnt,sizeof(unsigned int));
	  j=global_params.port_cnt;tmpptr=optarg;
	  while(j){
	    while(*(optarg+i) != 0 && *(optarg+i) != ',')
	      i++;
	    j--;
	    global_params.portlist[j] = strtol(tmpptr,&tmpptr,10);
	    tmpptr++;
	  }	
	  break;

        }
    }


    if(global_params.progfilters_cnt){
        // have filters
        //    pipe(global_params.filter_chain_IO_fds);
        filter_chain_internal_fds = (int*)calloc(2*(global_params.progfilters_cnt+1),sizeof(int));
        for(i=0;i<=global_params.progfilters_cnt;i++){
            pipe(filter_chain_internal_fds+(2*i));
        }
        for(i=0;i<global_params.progfilters_cnt;i++){
            pid = fork ();
            if (pid == (pid_t) 0) {
                printf("forked:%s %d %d %d\n",
                       global_params.progfilters[i],
                       getpid(),
                       *(filter_chain_internal_fds+(2*i)),
                       *(filter_chain_internal_fds+(2*(i+1))+1)
                       );
                /* This is the child process.*/
                dup2(*(filter_chain_internal_fds+(2*i))  , STDIN_FILENO);
                dup2(*(filter_chain_internal_fds+(2*(i+1))+1), STDOUT_FILENO);
                execl(global_params.progfilters[i],global_params.progfilters[i],NULL);
            }
        }
        global_params.filter_chain_IO_fds[0]=dup(*(filter_chain_internal_fds+1));
        global_params.filter_chain_IO_fds[1]=dup(*(filter_chain_internal_fds+(2*(global_params.progfilters_cnt))));

    }

    //   if(ettin_findpcapdevice(global_params.device)==0) return 1;
    if(ettin_init_pcap_device(global_params.device)){

        make_ip_list();
	printf("arping\n");
        arping();
        if(global_params.destinations_cnt){
            i=check_targets();
            fprintf(stderr,"Requested %d target(s)", global_params.destinations_cnt );
            if(i != global_params.destinations_cnt ){
                fprintf(stderr,
                        " but %d are alive on the network\n"
                        ,i);
                fflush(NULL);
            }else{
                fprintf(stderr," and all are alive on the network\n");
            }
            if(global_params.do_list == 0 ){
                start_poison();
            }

	    
            /*
            for(i=0;i<26;i++){
                wr_sz = 4;
                write(*(filter_chain_internal_fds+1),&wr_sz,wr_sz);
                write(*(filter_chain_internal_fds+1),wr_testbuff,wr_sz);
                re_sz=4;
                read(*(filter_chain_internal_fds+(2*(global_params.progfilters_cnt))),&re_sz,re_sz);
                read(*(filter_chain_internal_fds+(2*(global_params.progfilters_cnt))),re_testbuff,re_sz);
                printf("%d:%d->%s\n",
                       *(filter_chain_internal_fds+(2*(global_params.progfilters_cnt))),
                       re_sz,
                       re_testbuff
                       );

            }

            */
            int c = 0;
            while(c!=0x20){
                ETTIN_PERROR(8,"w-%d\n",c);
                c = getchar_unlocked();
            }
	    stop_poison();
            // cleanup
            free_ip_list();
            ettin_pcap_cleanup();

        }
    }

    if(global_params.progfilters_cnt){
        for(i=0;i<global_params.progfilters_cnt*2;i++){
            close(filter_chain_internal_fds[i]);
        }
        free(filter_chain_internal_fds);
    }
    free(global_params.destination_ips);
    fflush(NULL);
}
