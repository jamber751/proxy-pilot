// Bounded substitute; identity mode owns only an AF_UNIX test endpoint.
// Never linked into a shipped worker; no TCP/UDP/DNS or external resources.
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
int main(int argc,char **argv) {
    alarm(15);
    if(argc!=3 || strcmp(argv[1],"-C") || strcmp(argv[2],"-"))return 60;
    char path[1024],mode[40];
    if(!fgets(path,sizeof(path),stdin) || !fgets(mode,sizeof(mode),stdin))return 61;
    path[strcspn(path,"\n")]=0;mode[strcspn(mode,"\n")]=0;
    if(!strcmp(mode,"ignore"))signal(SIGTERM,SIG_IGN);
    for(int fd=3;fd<64;fd++) { if(fcntl(fd,F_GETFD)!=-1 || errno!=EBADF)return 62; }
    if(getenv("PROXYPILOT_TEST_SECRET") || getenv("PATH"))return 63;
    int server=-1;
    if(!strcmp(mode,"identity")) {
        server=socket(AF_UNIX,SOCK_STREAM,0);if(server<0)return 66;
        struct sockaddr_un address;memset(&address,0,sizeof(address));address.sun_family=AF_UNIX;
        if(snprintf(address.sun_path,sizeof(address.sun_path),"%s.sock",path)>=(int)sizeof(address.sun_path))return 67;
        address.sun_len=sizeof(address);
        if(bind(server,(struct sockaddr*)&address,sizeof(address)) || listen(server,1))return 68;
    }
    // Publish readiness only after the whole record AND optional listener exist.
    char temporary[1100];
    if(snprintf(temporary,sizeof(temporary),"%s.tmp",path)>=(int)sizeof(temporary))return 70;
    int fd=open(temporary,O_WRONLY|O_CREAT|O_EXCL,0600);if(fd<0)return 64;
    char value[80];int size=snprintf(value,sizeof(value),"%d %d\n",getpid(),getppid());
    if(write(fd,value,size)!=size)return 65;close(fd);
    if(rename(temporary,path))return 71;
    if(!strcmp(mode,"exit")) {
        char command[1100];
        if(snprintf(command,sizeof(command),"%s.exit",path)>=(int)sizeof(command))return 72;
        while(access(command,F_OK))usleep(1000);
        return 0;
    }
    if(server>=0 && accept(server,0,0)<0)return 69;
    for(;;)pause();
}
