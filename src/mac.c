#include <ettin_mac.h>


typedef struct mac_tree_t * mac_tree_ptr;
typedef struct mac_tree_t {
  struct mac_tree_t * macbyte[256];
  uint8_t msk;
  uint8_t is_leaf;
  char * company;
} mac_tree_t;

struct mac_tree_t treehead;
char * map;
struct stat mstat;
uint8_t inited = 0;

char * str_not_found = "not found";

char * findvendor(uint8_t * m){
  if(!inited)
    init_mac("./data/listmac.txt");
  mac_tree_ptr curr = & treehead;
  uint8_t k=0;//,go=1;
  while(curr->macbyte[ (m[k] & curr->msk) ]!=NULL){
    printf("%02hhx ",(m[k] & curr->msk));
    curr = curr->macbyte[ (m[k] & curr->msk)];
    k++;
  }

  if(curr->is_leaf)
    return curr->company;
  else
    return str_not_found;
}

int init_mac(char * fp){
  int fd = open(fp,O_RDONLY);
  fstat(fd, &mstat);
  inited=1;
  mac_tree_ptr curr;
  char ** mac_ar, ** name_ar, ** msk_ar;
  uint8_t mac_addr[6];
  uint8_t msk;
  map = mmap(NULL,mstat.st_size,PROT_READ|PROT_WRITE,MAP_PRIVATE,fd,0);
  int i=0,j=0,k=0,nlines=0;
  while(i<mstat.st_size){
    if(*(map+i)=='\n' ){
      nlines++;
    }
    i++;
  }
  if(*(map+mstat.st_size-1) == '\n')
    nlines--;
  mac_ar=(char**)calloc(nlines,sizeof(char*));
  name_ar=(char**)calloc(nlines,sizeof(char*));
  msk_ar=(char**)calloc(nlines,sizeof(char*));
  i=0;j=0;
  *(mac_ar+j)=map;
  while(i<mstat.st_size){
    if(*(map+i)=='\n' ){
      *(map+i)=0;
      *(mac_ar+j) = (map+i+1);

    }
    if(*(map+i)=='/' ){
      *(map+i)=0;
      *(msk_ar+j) = (map+i+1);
    }
    if(*(map+i)==';' ){
      *(map+i)=0;
      *(name_ar+j) = (map+i+1);
      j++;
    }
    i++;
  }

  i=k=0;

  memset(&treehead.macbyte,0,256*sizeof(struct mac_tree_t *));

  while(i<j){

    sscanf(*(mac_ar+i),"%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
           &mac_addr[0],&mac_addr[1],&mac_addr[2],
           &mac_addr[3],&mac_addr[4],&mac_addr[5]);
    msk=atoi(*(msk_ar+i));
    /*    printf("%d %s %s %s : %d %02hhx,%02hhx,%02hhx,%02hhx,%02hhx,%02hhx\n",
           i,
           *(name_ar+i),
           *(mac_ar+i),
           *(msk_ar+i),
           msk,
           mac_addr[0],mac_addr[1],mac_addr[2],mac_addr[3],mac_addr[4],mac_addr[5]);
    */
    k=0; curr = & treehead;
    while(msk>=8){
      if(curr->macbyte[mac_addr[k]] == NULL){
        //     putchar('.');
        curr->macbyte[mac_addr[k]] = (mac_tree_ptr) calloc(1,sizeof(struct mac_tree_t));
        curr->msk=0xff;
        curr = curr->macbyte[mac_addr[k]];
        memset(&curr->macbyte,0,256*sizeof(struct mac_tree_t *));
      }else{
        //  putchar('*');

        curr = curr->macbyte[mac_addr[k]];

      }
      k++;
      msk-=8;
    }
    if(msk){
      curr->msk=0xff;
      //     putchar('.');
      curr->macbyte[mac_addr[k]] = (mac_tree_ptr) calloc(1,sizeof(struct mac_tree_t));
      curr = curr->macbyte[mac_addr[k]];
      memset(&curr->macbyte,0,256*sizeof(struct mac_tree_t *));

      k++;
    }
    curr->msk = 0xff >> (8-msk);
    curr->msk <<= (8-msk);
    curr->is_leaf = 1;
    curr->company = *(name_ar+i);

    //   printf(" k=%d ",k);
    //putchar('\n');
    i++;
  }


  //  printf("%d\n",nlines);

  free(mac_ar);
  free(name_ar);
  free(msk_ar);

  return 0;
}


void free_mac_tree(mac_tree_ptr p, int j){
  int i;
  for(i=0;i<256;i++){
    if(p->macbyte[i] != NULL){
      free_mac_tree(p->macbyte[i],i);
    }
  }
  if(p!=&treehead)
    free(p);
}

void free_mac(){
  free_mac_tree(&treehead,-1);
  munmap(map,mstat.st_size);
}
