/* Fresh root GHA VM viability probe ONLY. No packet transmission, default-route
 * replacement, interface changes, PF, DNS or installed ProxyPilot access.
 * Tests HOST/nil-mask versus NET/full-mask coexistence for ONE exact address.
 * Does not prove a working deny backend or forwarding/interface-death behavior.
 * Public route socket ABI: <net/route.h>, <netinet/in.h>, <net/if.h>.
 */
#include <sys/socket.h>
#include <net/route.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct message { struct rt_msghdr header; unsigned char bytes[1024]; };
struct reply { unsigned flags; unsigned index; int exact, full_mask, local_gateway; };
static int sequence;
static int family;
static unsigned lo_index;
static unsigned char destination[16];
static const char *stage = "guard";
static int backup_added, host_added;
static int route_error, last_exact, last_mask;
static unsigned last_flags;
static size_t align4(size_t n) { return (n + 3) & ~(size_t)3; }
static int64_t now_ms(void) {
    struct timespec t; if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static size_t address(unsigned char *output, int mask, int gateway) {
    if (family == AF_INET) {
        struct sockaddr_in a = {0}; a.sin_len = sizeof(a); a.sin_family = mask ? 0 : AF_INET;
        if (mask) memset(&a.sin_addr, 255, 4);
        else if (gateway) inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        else memcpy(&a.sin_addr, destination, 4);
        memcpy(output, &a, sizeof(a)); return sizeof(a);
    }
    struct sockaddr_in6 a = {0}; a.sin6_len = sizeof(a); a.sin6_family = mask ? 0 : AF_INET6;
    if (mask) memset(&a.sin6_addr, 255, 16);
    else if (gateway) inet_pton(AF_INET6, "::1", &a.sin6_addr);
    else memcpy(&a.sin6_addr, destination, 16);
    memcpy(output, &a, sizeof(a)); return sizeof(a);
}
static int inspect(const unsigned char *data, size_t size, struct reply *result) {
    if (size < sizeof(struct rt_msghdr)) return EINVAL;
    struct rt_msghdr h; memcpy(&h, data, sizeof(h));
    if (h.rtm_msglen > size || h.rtm_msglen < sizeof(h)) return EINVAL;
    memset(result, 0, sizeof(*result)); result->flags = (unsigned)h.rtm_flags; result->index = h.rtm_index;
    size_t at = sizeof(h), width = family == AF_INET ? 4 : 16;
    size_t offset = family == AF_INET ? offsetof(struct sockaddr_in, sin_addr) : offsetof(struct sockaddr_in6, sin6_addr);
    unsigned char loopback[16] = {0}; inet_pton(family, family == AF_INET ? "127.0.0.1" : "::1", loopback);
    for (unsigned i = 0; i < RTAX_MAX; i++) {
        if (!(h.rtm_addrs & (1 << i))) continue;
        if (at + 2 > h.rtm_msglen) return EINVAL;
        size_t rounded = data[at] ? align4(data[at]) : 4;
        if ((data[at] < 2 && !(i == RTAX_NETMASK && data[at] == 0)) || at + rounded > h.rtm_msglen) return EINVAL;
        size_t length = data[at]; const unsigned char *a = data + at;
        if (i == RTAX_DST && length >= offset + width && a[1] == family)
            result->exact = memcmp(a + offset, destination, width) == 0;
        if (i == RTAX_GATEWAY && length >= offset + width && a[1] == family)
            result->local_gateway = memcmp(a + offset, loopback, width) == 0;
        if (i == RTAX_NETMASK && length >= offset + width) {
            result->full_mask = 1;
            for (size_t j = 0; j < width; j++) if (a[offset + j] != 255) result->full_mask = 0;
        }
        at += rounded;
    }
    return 0;
}
static int request(int type, int host, int backup, struct reply *result) {
    struct message m = {0}; size_t length = 0;
    m.header.rtm_version = RTM_VERSION; m.header.rtm_type = type;
    m.header.rtm_pid = getpid(); m.header.rtm_seq = ++sequence;
    m.header.rtm_addrs = RTA_DST;
    length += align4(address(m.bytes + length, 0, 0));
    if (type != RTM_GET) {
        m.header.rtm_flags = RTF_UP | RTF_STATIC | RTF_GATEWAY | (host ? RTF_HOST : 0) | (backup ? RTF_BLACKHOLE : 0);
        m.header.rtm_addrs |= RTA_GATEWAY;
        length += align4(address(m.bytes + length, 0, 1));
    }
    if (!host) { m.header.rtm_addrs |= RTA_NETMASK; length += align4(address(m.bytes + length, 1, 0)); }
    m.header.rtm_msglen = (unsigned short)(sizeof(m.header) + length);
    int fd = socket(PF_ROUTE, SOCK_RAW, 0); if (fd < 0) { route_error = errno; return route_error; }
    int flags = fcntl(fd, F_GETFL), error = 0;
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) || fcntl(fd, F_SETFD, FD_CLOEXEC)) { error = errno; goto done; }
    int64_t began = now_ms(); if (began < 0) { error = EIO; goto done; }
    int64_t end = began + 2000;
    ssize_t sent = write(fd, &m, m.header.rtm_msglen);
    if (sent != m.header.rtm_msglen) { error = sent < 0 ? errno : EIO; goto done; }
    for (int i = 0; i < 128; i++) {
        int64_t now = now_ms(); if (now < began) { error = EIO; goto done; }
        int64_t remaining = end - now; if (remaining <= 0) { error = ETIMEDOUT; goto done; }
        struct pollfd p = {.fd = fd, .events = POLLIN}; int status = poll(&p, 1, (int)remaining);
        if (status < 0 && errno == EINTR) continue;
        if (status <= 0) { error = status == 0 ? ETIMEDOUT : errno; goto done; }
        unsigned char bytes[8192]; ssize_t count = read(fd, bytes, sizeof(bytes));
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count >= 4 && (bytes[3] == RTM_NEWADDR || bytes[3] == RTM_DELADDR ||
            bytes[3] == RTM_IFINFO || bytes[3] == RTM_IFINFO2 || bytes[3] == RTM_NEWMADDR ||
            bytes[3] == RTM_DELMADDR || bytes[3] == RTM_NEWMADDR2)) continue;
        if (count < (ssize_t)sizeof(struct rt_msghdr)) { error = EIO; goto done; }
        struct rt_msghdr h; memcpy(&h, bytes, sizeof(h));
        if (h.rtm_version != RTM_VERSION || h.rtm_pid != getpid() || h.rtm_seq != sequence) continue;
        if (h.rtm_type != type) { error = EINVAL; goto done; }
        if (h.rtm_errno) { error = h.rtm_errno; goto done; }
        error = inspect(bytes, (size_t)count, result); goto done;
    }
    error = EOVERFLOW;
done:
    route_error = error;
    if (!error) { last_flags = result->flags; last_exact = result->exact; last_mask = result->full_mask; }
    close(fd); return error;
}
static int owned(const struct reply *r, int host, int backup) {
    unsigned required = RTF_UP | RTF_STATIC | RTF_GATEWAY;
    return r->exact && r->local_gateway && r->index == lo_index &&
        (r->flags & required) == required && !(r->flags & RTF_IFSCOPE) &&
        !!(r->flags & RTF_HOST) == host && !!(r->flags & RTF_BLACKHOLE) == backup && (host || r->full_mask);
}
static int absent(int host) {
    struct reply r; int e = request(RTM_GET, host, 0, &r);
    if (e == ESRCH) return 1;
    return e == 0 && !((r.flags & RTF_HOST) ? r.exact : (r.exact && r.full_mask));
}
static int check(int value) {
    if (!value) fprintf(stderr, "FAIL exact-route-pair stage=%s errno=%d flags=%u exact=%d fullMask=%d\n",
        stage, route_error, last_flags, last_exact, last_mask);
    return value;
}
static int probe(void) {
    struct reply r;
    stage = "baseline"; if (!check(absent(1) && absent(0))) return 1;
    stage = "backupAdd"; if (!check(request(RTM_ADD, 0, 1, &r) == 0)) return 1; backup_added = 1;
    stage = "backupIdentity"; if (!check(request(RTM_GET, 0, 1, &r) == 0 && owned(&r, 0, 1))) return 1;
    stage = "backupSelected"; if (!check(request(RTM_GET, 1, 0, &r) == 0 && owned(&r, 0, 1))) return 1;
    stage = "hostAdd"; if (!check(request(RTM_ADD, 1, 0, &r) == 0)) return 1; host_added = 1;
    stage = "hostSelected"; if (!check(request(RTM_GET, 1, 0, &r) == 0 && owned(&r, 1, 0))) return 1;
    stage = "backupCoexists"; if (!check(request(RTM_GET, 0, 1, &r) == 0 && owned(&r, 0, 1))) return 1;
    stage = "hostDelete"; if (!check(request(RTM_DELETE, 1, 0, &r) == 0)) return 1; host_added = 0;
    stage = "backupReselected"; if (!check(request(RTM_GET, 1, 0, &r) == 0 && owned(&r, 0, 1))) return 1;
    stage = "backupDelete"; if (!check(request(RTM_DELETE, 0, 1, &r) == 0)) return 1; backup_added = 0;
    stage = "baselineRestored"; return !check(absent(1) && absent(0));
}
int main(void) {
    const char *gha = getenv("GITHUB_ACTIONS"), *opt = getenv("PROXYPILOT_VM_EXACT_ROUTE_PAIR");
    if (getuid() != 0 || geteuid() != 0 || !gha || strcmp(gha, "true") || !opt || strcmp(opt, "1")) return 77;
    lo_index = if_nametoindex("lo0"); if (!lo_index) return 1;
    for (int i = 0; i < 2; i++) {
        family = i ? AF_INET6 : AF_INET;
        if (inet_pton(family, i ? "2001:db8:fff:fd::c9" : "198.19.253.201", destination) != 1) return 1;
        if (probe()) {
            /* Never delete an unproven/rebound identity. A failed fresh VM may
             * retain this synthetic exact-address rule until VM disposal. */
            struct reply r;
            if (host_added && request(RTM_GET, 1, 0, &r) == 0 && owned(&r, 1, 0))
                if (request(RTM_DELETE, 1, 0, &r) == 0) host_added = 0;
            if (backup_added && request(RTM_GET, 0, 1, &r) == 0 && owned(&r, 0, 1))
                if (request(RTM_DELETE, 0, 1, &r) == 0) backup_added = 0;
            fprintf(stderr, "UNRESOLVED exact-route-pair confirmedHost=%d confirmedBackup=%d\n", host_added, backup_added);
            return 1;
        }
        puts(i ? "PASS exact-route-pair-ipv6" : "PASS exact-route-pair-ipv4"); fflush(stdout);
    }
    return 0;
}
