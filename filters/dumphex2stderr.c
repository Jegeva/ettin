#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc,char** argv){
    unsigned int msgsz,i;
  unsigned char * msg=NULL;
  int msg_alloc_sz=0;
  while(1){
    read(STDIN_FILENO,&msgsz,4);
    fprintf(stderr,"%s MSz:%d\n",argv[0],msgsz);
    if(msgsz>msg_alloc_sz){
      msg = (unsigned char*)realloc(msg,msgsz);
      msg_alloc_sz=msgsz;
    }else{
      memset(msg,0,msgsz+1);
    }

    if( read(STDIN_FILENO,msg,msgsz) != msgsz ){
        fprintf(stderr,"?? read ??");


    };

    // do stuff here

    /*   for(i=0;i<msgsz;i++){
        if(*(msg+i)=='a'){
            *(msg+i)='0';
            fputc('*',stderr);
        };
        }*/
    for(i=0;i<msgsz;i++){
        fprintf(stderr,"%02x ",*(unsigned char*)(msg+i));
        if(i%16==0){
            fprintf(stderr,"%.16s",(msg+i));
            fputc('\n',stderr);
        }
    }

    fputc('\n',stderr);
    write(STDOUT_FILENO,&msgsz,4);
    write(STDOUT_FILENO,msg,msgsz);

  }
}
