#include <main.h>
#include <ettin.h>


int check_targets(){

  int i,j;
  IP4_arp_state_t * curr_ip_list;

  j=0;
  curr_ip_list = IP4_arp_state_head;
  while( curr_ip_list!=NULL){
    for(i=0;i<global_params.destinations_cnt;i++){
      if( strcmp(global_params.destination_ips[i],curr_ip_list->ip4_string) == 0 && curr_ip_list->arp_received  ){
        curr_ip_list->is_target=1;
        j++;
      }
    }
    curr_ip_list=curr_ip_list->next;
  }

  return j;
}
