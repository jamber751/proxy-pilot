/* Disposable GHA VM fixture only; no production symbols or guessed ioctls.
 * Public SDK definitions / Apple source:
 * https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_utun.h
 * https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/kern_control.h
 */
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int pp_dns_utun_open(char *name, size_t capacity) {
    const char *gha = getenv("GITHUB_ACTIONS");
    const char *opt = getenv("PROXYPILOT_VM_DNS_UTUN_TESTS");
    if (getuid() != 0 || geteuid() != 0 || !gha || strcmp(gha, "true") || !opt || strcmp(opt, "1")) {
        errno = EPERM; return -1;
    }
    if (!name || capacity < IFNAMSIZ) { errno = EINVAL; return -1; }
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) return -1;
    struct ctl_info info = {0};
    strlcpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name));
    struct sockaddr_ctl address = {0};
    address.sc_len = sizeof(address);
    address.sc_family = AF_SYSTEM;
    address.ss_sysaddr = AF_SYS_CONTROL;
    address.sc_unit = 0; /* Exclusively autoallocate. Never request/adopt a unit. */
    if (ioctl(fd, CTLIOCGINFO, &info) != 0) goto failed;
    address.sc_id = info.ctl_id;
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) goto failed;
    socklen_t length = IFNAMSIZ;
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name, &length) != 0) goto failed;
    if (!length || length > capacity || !memchr(name, 0, length)) { errno = EINVAL; goto failed; }
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) goto failed;
    return fd;
failed:;
    int saved = errno;
    close(fd); errno = saved; return -1;
}
