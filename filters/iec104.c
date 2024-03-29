#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
extern int errno;


int main(int argc,char** argv){
  unsigned int msgsz;
  char * msg=NULL;
  int msg_alloc_sz=0;
  int r;
  int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
  fcntl(STDIN_FILENO, F_SETFL, flags & ~O_NONBLOCK);
  flags = fcntl(STDOUT_FILENO, F_GETFL, 0);
  fcntl(STDOUT_FILENO, F_SETFL, flags & ~O_NONBLOCK);
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
      read(STDIN_FILENO,msg,msgsz);

      // do stuff here

      *(msg+3) +=1;

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
