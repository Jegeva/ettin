#include <stdio.h>
#include <string.h>


int main(int argc,char** argv){
  unsigned int msgsz;
  char * msg=NULL;
  int msg_alloc_sz=0;
  while(1){
    read(STDIN,&msgsz,4);
    fprintf(stderr,"%s MSz:%d\n",argv[0],msgsz);
    if(msgsz>msg_alloc_sz){
      msg = (char*)realloc(msg,msgsz);
      msg_alloc_sz=msgsz;
    }else{
      memset(msg,0,msgsz+1);
    }
    read(STDIN,&msg,msgsz);

    // do stuff here

    write(STDOUT,msg,msgsz);

  }
}
