// Bounded, non-networking substitute. Never linked into a shipped worker.
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
int main(int argc,char **argv) {
    alarm(15); // A failed harness must not leave an indefinite fake process.
    if(argc!=3 || strcmp(argv[1],"-C") || strcmp(argv[2],"-"))return 60;
    char path[1024],mode[40];
    if(!fgets(path,sizeof(path),stdin) || !fgets(mode,sizeof(mode),stdin))return 61;
    path[strcspn(path,"\n")]=0;mode[strcspn(mode,"\n")]=0;
    if(!strcmp(mode,"ignore"))signal(SIGTERM,SIG_IGN);
    for(int fd=3;fd<64;fd++) { if(fcntl(fd,F_GETFD)!=-1 || errno!=EBADF)return 62; }
    if(getenv("PROXYPILOT_TEST_SECRET") || getenv("PATH"))return 63;
    int fd=open(path,O_WRONLY|O_CREAT|O_EXCL,0600);if(fd<0)return 64;
    char value[80];int size=snprintf(value,sizeof(value),"%d %d\n",getpid(),getppid());
    if(write(fd,value,size)!=size)return 65;close(fd);
    if(!strcmp(mode,"exit")) { usleep(200000);return 0; }
    for(;;)pause();
}
