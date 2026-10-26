// No listener, DNS, argv credentials or environment; only private fixture files.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
int main(int argc,char **argv) {
    (void)argv;alarm(15);if(argc!=1)return 60;
    for(int fd=3;fd<64;fd++)if(fcntl(fd,F_GETFD)!=-1 || errno!=EBADF)return 61;
    if(getenv("PATH") || getenv("PROXYPILOT_TEST_SECRET"))return 62;
    char line[513];if(!fgets(line,sizeof(line),stdin))return 63;
    char *mode=strchr(line,'|');
    if(mode) {
        *mode++=0;mode[strcspn(mode,"\n")]=0;
        char temp[600],record[80];snprintf(temp,sizeof(temp),"%s.tmp",line);
        int fd=open(temp,O_WRONLY|O_CREAT|O_EXCL,0600);if(fd<0)return 64;
        int n=snprintf(record,sizeof(record),"%d %d\n",getpid(),getppid());
        if(write(fd,record,n)!=n)return 65;close(fd);if(rename(temp,line))return 66;
    } else mode="normal";
    if(!strcmp(mode,"ignore"))signal(SIGTERM,SIG_IGN);
    if(!strcmp(mode,"hang"))for(;;)pause();
    if(!strcmp(mode,"long")) { for(int i=0;i<4097;i++)putchar('x');putchar('\n'); }
    else printf("{\"port\":12345,\"certificate\":\"fixture\"}\n");
    fflush(stdout);
    if(!strcmp(mode,"ignore"))for(;;)pause();
    while(getchar()!=EOF) {}
    return 0;
}
