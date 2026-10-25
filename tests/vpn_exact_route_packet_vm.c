/* Disposable opted-in root GHA VM only. UDP forwarding/death experiment;
 * NOT TCP, boot, WARP, production custody or general no-leak acceptance. */
#define main pair_viability_main
#include "vpn_exact_route_pair_vm.c"
#undef main
#include <sys/wait.h>
#include <sys/stat.h>
#include <spawn.h>
#include <signal.h>
#include <ifaddrs.h>
#include <net/if_utun.h>
#include <sys/sys_domain.h>

int pp_dns_utun_open(char *, size_t);
extern char **environ;
static int active_fd = -1, escape_fd = -1, cached_fd = -1, fresh_fd = -1, neighbor_fd = -1;
static unsigned active_index, escape_index;
static char active_name[IFNAMSIZ], escape_name[IFNAMSIZ];
static unsigned char cover[16], neighbor[16], local[16];
static int cover_added;
static pid_t owner_pid = -1;
static const unsigned short port = 49317;
static unsigned char nonce[16];

static int interface_owned(int fd, const char *name, unsigned index) {
    char observed[IFNAMSIZ] = {0}; socklen_t n = sizeof(observed);
    return fd >= 0 && getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, observed, &n) == 0 &&
        n > 0 && n <= sizeof(observed) && memchr(observed, 0, n) && strcmp(observed, name) == 0 && if_nametoindex(name) == index;
}
static int configure_one(int fd, const char *name, unsigned index, int ipv6, const char *a, const char *peer) {
    if (!interface_owned(fd, name, index)) return 0;
    char *v4[] = {"/sbin/ifconfig", (char *)name, "inet", (char *)a, (char *)peer, "netmask", "255.255.255.255", "up", NULL};
    char *v6[] = {"/sbin/ifconfig", (char *)name, "inet6", (char *)a, "prefixlen", "128", "-dad", NULL};
    posix_spawn_file_actions_t actions; if (posix_spawn_file_actions_init(&actions)) return 0;
    int e = posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    if (!e) e = posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    pid_t pid = -1; char *env[] = {"PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL};
    if (!e) e = posix_spawn(&pid, "/sbin/ifconfig", &actions, NULL, ipv6 ? v6 : v4, env);
    posix_spawn_file_actions_destroy(&actions); if (e) return 0;
    int status = 0; int64_t end = now_ms() + 5000;
    pid_t observed;
    while ((observed = waitpid(pid, &status, WNOHANG)) == 0) {
        if (now_ms() >= end) { kill(pid, SIGKILL); waitpid(pid, &status, 0); return 0; }
        usleep(5000);
    }
    return observed == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0 && interface_owned(fd, name, index);
}
static int addresses_free(void) {
    const char *texts[] = {"192.0.2.1", "192.0.2.2", "192.0.2.5", "192.0.2.6", "fd00:7070:1::1", "fd00:7070:2::1"};
    struct ifaddrs *list = NULL; if (getifaddrs(&list)) return 0;
    int free_all = 1;
    for (struct ifaddrs *p = list; p; p = p->ifa_next) {
        if (!p->ifa_addr) continue;
        for (size_t i = 0; i < sizeof(texts)/sizeof(*texts); i++) {
            int f = i < 4 ? AF_INET : AF_INET6; unsigned char bytes[16] = {0}; inet_pton(f, texts[i], bytes);
            if (p->ifa_addr->sa_family != f) continue;
            const void *ip = f == AF_INET ? (void *)&((struct sockaddr_in *)p->ifa_addr)->sin_addr : (void *)&((struct sockaddr_in6 *)p->ifa_addr)->sin6_addr;
            if (!memcmp(ip, bytes, f == AF_INET ? 4 : 16)) free_all = 0;
        }
    }
    freeifaddrs(list); return free_all;
}
static int direct_request(int type, int host, unsigned index, struct reply *r) {
    struct message m = {0}; size_t n = 0; unsigned char saved[16]; memcpy(saved, destination, 16);
    if (!host) memcpy(destination, cover, 16);
    m.header.rtm_version = RTM_VERSION; m.header.rtm_type = type;
    m.header.rtm_pid = getpid(); m.header.rtm_seq = ++sequence;
    m.header.rtm_flags = RTF_UP | RTF_STATIC | RTF_PROTO2 | (host ? RTF_HOST : 0);
    m.header.rtm_addrs = RTA_DST; n += align4(address(m.bytes + n, 0, 0));
    if (type != RTM_GET) {
        struct sockaddr_dl link = {0}; link.sdl_len = 8; link.sdl_family = AF_LINK; link.sdl_index = index;
        memcpy(m.bytes + n, &link, 8); n += 8; m.header.rtm_addrs |= RTA_GATEWAY;
    }
    if (!host) {
        size_t length = address(m.bytes + n, 1, 0);
        size_t offset = family == AF_INET ? offsetof(struct sockaddr_in, sin_addr) : offsetof(struct sockaddr_in6, sin6_addr);
        memset(m.bytes + n + offset, 0, family == AF_INET ? 4 : 16);
        memset(m.bytes + n + offset, 255, family == AF_INET ? 3 : 8);
        n += align4(length); m.header.rtm_addrs |= RTA_NETMASK;
    }
    m.header.rtm_msglen = sizeof(m.header) + n;
    memcpy(destination, saved, 16); return exchange(&m, type, r);
}
static int cover_exact(const struct reply *r) {
    unsigned char mask[16] = {0}; size_t width = family == AF_INET ? 4 : 16;
    memset(mask, 255, family == AF_INET ? 3 : 8);
    return !memcmp(r->dst, cover, width) && !memcmp(r->mask, mask, width) && !(r->flags & RTF_HOST);
}
static int direct_owned(const struct reply *r, int host, unsigned index) {
    unsigned required = RTF_UP | RTF_STATIC | RTF_PROTO2;
    unsigned forbidden = RTF_GATEWAY | RTF_BLACKHOLE | RTF_REJECT | RTF_IFSCOPE;
    return (host ? r->exact && !!(r->flags & RTF_HOST) : cover_exact(r)) && r->index == index &&
        r->link_index == index && (r->flags & required) == required && !(r->flags & forbidden);
}
static void endpoint(struct sockaddr_storage *s, const unsigned char *ip) {
    memset(s, 0, sizeof(*s));
    if (family == AF_INET) { struct sockaddr_in *a = (void *)s; a->sin_len = sizeof(*a); a->sin_family = family; a->sin_port = htons(port); memcpy(&a->sin_addr, ip, 4); }
    else { struct sockaddr_in6 *a = (void *)s; a->sin6_len = sizeof(*a); a->sin6_family = family; a->sin6_port = htons(port); memcpy(&a->sin6_addr, ip, 16); }
}
static int udp_socket(const unsigned char *ip) {
    int fd = socket(family, SOCK_DGRAM, 0); if (fd < 0) return -1;
    struct sockaddr_storage s; endpoint(&s, ip);
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) || connect(fd, (void *)&s, family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))) { close(fd); return -1; }
    return fd; /* Deliberately no IP_BOUND_IF, bind(), or interface hint. */
}
static int emit(int fd, int may_refuse) {
    ssize_t n = send(fd, nonce, sizeof(nonce), 0);
    return n == sizeof(nonce) || (may_refuse && n < 0 && (errno == EHOSTUNREACH || errno == ENETUNREACH || errno == ENETDOWN || errno == EADDRNOTAVAIL));
}
/* Reject malformed/truncated/fragmented packets; inspect bounded own utun only. */
static int matching(const unsigned char *p, size_t n, const unsigned char *ip, int source_required) {
    size_t h, width = family == AF_INET ? 4 : 16, d, s;
    if (n < 4) return 0;
    uint32_t tag; memcpy(&tag, p, 4); if (ntohl(tag) != (unsigned)family) return 0;
    p += 4; n -= 4;
    if (family == AF_INET) {
        if (n < 20 || p[0] >> 4 != 4 || p[9] != IPPROTO_UDP || (p[6] & 0x3f) || p[7]) return 0;
        h = (p[0] & 15) * 4; d = 16; s = 12;
        if (h < 20 || (size_t)(p[2] * 256 + p[3]) != n) return 0;
    } else {
        if (n < 40 || p[0] >> 4 != 6 || p[6] != IPPROTO_UDP || (size_t)(40 + p[4] * 256 + p[5]) != n) return 0;
        h = 40; d = 24; s = 8;
    }
    if (n < h + 8 + sizeof(nonce) || memcmp(p + d, ip, width) ||
        (unsigned)(p[h+2] * 256 + p[h+3]) != port ||
        (size_t)(p[h+4] * 256 + p[h+5]) != 8 + sizeof(nonce) || n != h + 8 + sizeof(nonce)) return 0;
    return (!source_required || !memcmp(p + s, local, width)) && !memcmp(p + h + 8, nonce, sizeof(nonce));
}
/* Pure malformed-packet regressions, callable by an ordinary user. No I/O. */
static int packet_parser_checks(void) {
    memset(nonce, 0x71, sizeof(nonce));
    for (int ipv6 = 0; ipv6 < 2; ipv6++) {
        family = ipv6 ? AF_INET6 : AF_INET;
        inet_pton(family, ipv6 ? "2001:db8:fff:fd::c9" : "198.19.253.201", destination);
        inet_pton(family, ipv6 ? "fd00:7070:1::1" : "192.0.2.1", local);
        unsigned char p[128] = {0}; uint32_t tag = htonl(family); memcpy(p, &tag, 4);
        size_t h = ipv6 ? 40 : 20, size = 4 + h + 8 + sizeof(nonce), width = ipv6 ? 16 : 4;
        unsigned char *ip = p + 4, *udp = ip + h;
        ip[0] = ipv6 ? 0x60 : 0x45;
        if (ipv6) { ip[5] = 8 + sizeof(nonce); ip[6] = IPPROTO_UDP; }
        else { ip[3] = h + 8 + sizeof(nonce); ip[9] = IPPROTO_UDP; }
        memcpy(ip + (ipv6 ? 8 : 12), local, width); memcpy(ip + (ipv6 ? 24 : 16), destination, width);
        udp[2] = port >> 8; udp[3] = port & 255; udp[5] = 8 + sizeof(nonce); memcpy(udp + 8, nonce, sizeof(nonce));
        if (!matching(p,size,destination,1)) return 1;
        for (size_t n = 0; n < size; n++) if (matching(p,n,destination,1)) return 1;
        p[size] = 0; if (matching(p,size+1,destination,1)) return 1;
        udp[3] ^= 1; if (matching(p,size,destination,1)) return 1; udp[3] ^= 1;
        udp[8] ^= 1; if (matching(p,size,destination,1)) return 1; udp[8] ^= 1;
        ip[ipv6 ? 24 : 16] ^= 1; if (matching(p,size,destination,1)) return 1; ip[ipv6 ? 24 : 16] ^= 1;
        ip[ipv6 ? 8 : 12] ^= 1; if (matching(p,size,destination,1) || !matching(p,size,destination,0)) return 1;
        ip[ipv6 ? 8 : 12] ^= 1;
        ip[ipv6 ? 6 : 9] = IPPROTO_TCP; if (matching(p,size,destination,1)) return 1;
        ip[ipv6 ? 6 : 9] = IPPROTO_UDP;
        if (!ipv6) { ip[6] = 0x20; if (matching(p,size,destination,1)) return 1; }
        struct message m = {0}; struct reply r;
        size_t offset = ipv6 ? offsetof(struct sockaddr_in6,sin6_addr) : offsetof(struct sockaddr_in,sin_addr);
        size_t mask_bytes = ipv6 ? 8 : 3;
        m.header.rtm_addrs = RTA_NETMASK;
        m.bytes[0] = offset + mask_bytes; memset(m.bytes + offset,255,mask_bytes);
        m.header.rtm_msglen = sizeof(m.header) + align4(m.bytes[0]);
        if (inspect((void *)&m,m.header.rtm_msglen,&r) || r.full_mask) return 1;
        for (size_t j = 0; j < width; j++) if (r.mask[j] != (j < mask_bytes ? 255 : 0)) return 1;
        m.header.rtm_msglen = sizeof(m.header) + 4;
        if (inspect((void *)&m,m.header.rtm_msglen,&r) != EINVAL) return 1;
    }
    return 0;
}
static int observe(int fd, const unsigned char *ip, int source_required, int expected, int milliseconds) {
    int seen = 0, reads = 0; int64_t end = now_ms() + milliseconds;
    while (now_ms() < end) {
        int64_t left = end - now_ms(); if (left <= 0) break;
        struct pollfd p = {.fd=fd,.events=POLLIN}; int x = poll(&p, 1, (int)left);
        if (x < 0 && errno == EINTR) continue;
        if (x < 0 || (x > 0 && !(p.revents & POLLIN))) return 0;
        if (!x) break;
        unsigned char bytes[4096]; ssize_t n = read(fd, bytes, sizeof(bytes));
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (n <= 0 || n >= (ssize_t)sizeof(bytes) || ++reads > 512) return 0;
        if (matching(bytes, (size_t)n, ip, source_required)) { seen = 1; if (!expected) return 0; }
        if (expected && seen) return 1;
    }
    return expected ? seen : !seen;
}
static int kill_interface_owner(void) {
    int ready[2]; if (pipe(ready)) return 0;
    owner_pid = fork();
    if (owner_pid == 0) {
        close(ready[0]); close(escape_fd); close(cached_fd); close(neighbor_fd);
        if (write(ready[1], "R", 1) != 1) _exit(1);
        close(ready[1]); for (;;) pause();
    }
    close(ready[1]);
    if (owner_pid < 0) { close(ready[0]); return 0; }
    struct pollfd p = {.fd=ready[0],.events=POLLIN}; char c = 0;
    int ok = poll(&p, 1, 2000) == 1 && read(ready[0], &c, 1) == 1 && c == 'R'; close(ready[0]);
    if (!ok) return 0;
    close(active_fd); active_fd = -1;
    if (kill(owner_pid, SIGKILL)) return 0;
    int status; if (waitpid(owner_pid, &status, 0) != owner_pid) return 0; owner_pid = -1;
    if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) return 0;
    int64_t end = now_ms() + 3000;
    while (if_nametoindex(active_name) && now_ms() < end) usleep(5000);
    return !if_nametoindex(active_name);
}
static int packet_probe(void) {
    struct reply r;
    stage = "packetBaseline";
    if (!check(absent(1) && absent(0))) return 1;
    int e = direct_request(RTM_GET, 0, escape_index, &r);
    if (!check(e == ESRCH || (e == 0 && !cover_exact(&r)))) return 1;
    stage = "packetCoverAdd"; if (!check(direct_request(RTM_ADD, 0, escape_index, &r) == 0)) return 1; cover_added = 1;
    if (!check(direct_request(RTM_GET, 0, escape_index, &r) == 0 && direct_owned(&r, 0, escape_index))) return 1;
    stage = "packetBackupAdd"; if (!check(request(RTM_ADD, 0, 1, &r) == 0)) return 1; backup_added = 1;
    stage = "packetActiveAdd"; if (!check(direct_request(RTM_ADD, 1, active_index, &r) == 0)) return 1; host_added = 1;
    if (!check(request(RTM_GET, 1, 0, &r) == 0 && direct_owned(&r, 1, active_index))) return 1;
    cached_fd = udp_socket(destination); neighbor_fd = udp_socket(neighbor);
    stage = "packetUnboundActive";
    if (!check(cached_fd >= 0 && neighbor_fd >= 0 && emit(cached_fd, 0) && observe(active_fd, destination, 1, 1, 2000) && observe(escape_fd, destination, 0, 0, 100))) return 1;
    stage = "packetNeighborBefore";
    if (!check(emit(neighbor_fd, 0) && observe(escape_fd, neighbor, 0, 1, 2000))) return 1;
    stage = "packetOwnerDeath"; if (!check(kill_interface_owner())) return 1;
    stage = "packetBackupSelected"; if (!check(request(RTM_GET, 1, 0, &r) == 0 && owned(&r, 0, 1))) return 1; host_added = 0;
    stage = "packetCachedAfterDeath"; if (!check(emit(cached_fd, 1))) return 1;
    /* New sockets may also fail connect when the exact blackhole is selected. */
    errno = 0; fresh_fd = udp_socket(destination); int connect_error = errno;
    stage = "packetFreshAfterDeath";
    if (!check(fresh_fd >= 0 ? emit(fresh_fd, 1) : (connect_error == EHOSTUNREACH || connect_error == ENETUNREACH))) return 1;
    stage = "packetNoEscape"; if (!check(observe(escape_fd, destination, 0, 0, 2000))) return 1;
    stage = "packetNeighborAfter"; if (!check(emit(neighbor_fd, 0) && observe(escape_fd, neighbor, 0, 1, 2000))) return 1;
    return 0;
}
static int cleanup(void) {
    if (owner_pid > 0) { kill(owner_pid, SIGKILL); waitpid(owner_pid, NULL, 0); owner_pid = -1; }
    int *clients[] = {&cached_fd, &fresh_fd, &neighbor_fd};
    for (size_t i = 0; i < 3; i++) if (*clients[i] >= 0) { close(*clients[i]); *clients[i] = -1; }
    struct reply r;
    if (host_added && request(RTM_GET, 1, 0, &r) == 0 && direct_owned(&r, 1, active_index))
        if (direct_request(RTM_DELETE, 1, active_index, &r) == 0) host_added = 0;
    if (host_added && !if_nametoindex(active_name) && absent(1)) host_added = 0;
    if (host_added) return 0; /* Retain backup and cover rather than weaken uncertainty. */
    if (backup_added && request(RTM_GET, 0, 1, &r) == 0 && owned(&r, 0, 1))
        if (request(RTM_DELETE, 0, 1, &r) == 0) backup_added = 0;
    if (backup_added) return 0;
    if (cover_added && direct_request(RTM_GET, 0, escape_index, &r) == 0 && direct_owned(&r, 0, escape_index))
        if (direct_request(RTM_DELETE, 0, escape_index, &r) == 0) cover_added = 0;
    if (cover_added) return 0;
    if (active_fd >= 0) { close(active_fd); active_fd = -1; }
    if (escape_fd >= 0) { close(escape_fd); escape_fd = -1; }
    int64_t end = now_ms() + 3000;
    while ((if_nametoindex(active_name) == active_index || if_nametoindex(escape_name) == escape_index) && now_ms() < end) usleep(5000);
    return if_nametoindex(active_name) != active_index && if_nametoindex(escape_name) != escape_index && absent(1) && absent(0);
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--pure-packets")) return packet_parser_checks();
    if (argc != 1) return 77;
    const char *gha = getenv("GITHUB_ACTIONS"), *flag = getenv("PROXYPILOT_VM_EXACT_ROUTE_PACKETS");
    if (getuid() != 0 || geteuid() != 0 || !gha || strcmp(gha,"true") || !flag || strcmp(flag,"1")) return 77;
    const char *support_flag = getenv("PROXYPILOT_VM_DNS_UTUN_TESTS");
    if (!support_flag || strcmp(support_flag,"1")) return 77;
    if (!addresses_free()) return 1;
    lo_index = if_nametoindex("lo0"); if (!lo_index) return 1;
    for (int i = 0; i < 2; i++) {
        family = i ? AF_INET6 : AF_INET; arc4random_buf(nonce,sizeof(nonce));
        inet_pton(family, i ? "2001:db8:fff:fd::c9" : "198.19.253.201", destination);
        inet_pton(family, i ? "2001:db8:fff:fd::ca" : "198.19.253.202", neighbor);
        inet_pton(family, i ? "2001:db8:fff:fd::" : "198.19.253.0", cover);
        inet_pton(family, i ? "fd00:7070:1::1" : "192.0.2.1", local);
        active_fd = pp_dns_utun_open(active_name,sizeof(active_name)); escape_fd = pp_dns_utun_open(escape_name,sizeof(escape_name));
        active_index = if_nametoindex(active_name); escape_index = if_nametoindex(escape_name);
        stage = "packetConfigure";
        int ok = active_fd >= 0 && escape_fd >= 0 && active_index && escape_index && active_index != escape_index &&
            configure_one(active_fd,active_name,active_index,0,"192.0.2.1","192.0.2.2") &&
            configure_one(active_fd,active_name,active_index,1,"fd00:7070:1::1",NULL) &&
            configure_one(escape_fd,escape_name,escape_index,0,"192.0.2.5","192.0.2.6") &&
            configure_one(escape_fd,escape_name,escape_index,1,"fd00:7070:2::1",NULL);
        if (!check(ok) || packet_probe()) { (void)cleanup(); fputs("FAIL exact-route-udp-unresolved-VM-disposal\n",stderr); return 1; }
        stage = "packetCleanup"; if (!check(cleanup())) return 1;
        puts(i ? "PASS exact-route-udp-ipv6-active-cached-fresh-death-neighbor" : "PASS exact-route-udp-ipv4-active-cached-fresh-death-neighbor"); fflush(stdout);
    }
    return 0;
}
