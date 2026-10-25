/* Disposable opted-in root GHA VM only. UDP/TCP forwarding/death experiment;
 * NOT boot, WARP, production custody or general no-leak acceptance. */
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
#include <netinet/tcp.h>

int pp_dns_utun_open(char *, size_t);
extern char **environ;
static int active_fd = -1, escape_fd = -1, cached_fd = -1, fresh_fd = -1, neighbor_fd = -1;
static int cached_tcp = -1, fresh_tcp = -1;
static unsigned active_index, escape_index;
static char active_name[IFNAMSIZ], escape_name[IFNAMSIZ];
static unsigned char cover[16], neighbor[16], local[16];
static int cover_added;
static pid_t owner_pid = -1;
static const unsigned short port = 49317;
static unsigned char nonce[16];
#ifdef PP_NATIVE_EXACT_FENCE
static int native_fence_after_active;
#endif

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

struct tcp_packet {
    const unsigned char *source, *target, *payload;
    unsigned short source_port, target_port;
    uint32_t sequence, ack;
    unsigned char flags;
    size_t payload_size;
};
static unsigned short read16(const unsigned char *p) { return (unsigned short)((p[0] << 8) | p[1]); }
static uint32_t read32(const unsigned char *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static void put16(unsigned char *p, unsigned short value) { p[0] = value >> 8; p[1] = value & 255; }
static void put32(unsigned char *p, uint32_t value) { p[0] = value >> 24; p[1] = value >> 16; p[2] = value >> 8; p[3] = value; }
static unsigned short checksum(const unsigned char *p, size_t n) {
    uint32_t sum = 0;
    for (size_t i = 0; i < n; i += 2) { sum += (uint32_t)p[i] << 8; if (i+1 < n) sum += p[i+1]; }
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    return (unsigned short)~sum;
}
static int tcp_parse(const unsigned char *p, size_t n, struct tcp_packet *r) {
    if (n < 4 || read32(p) != (unsigned)family) return 0;
    p += 4; n -= 4; size_t h;
    if (family == AF_INET) {
        if (n < 20 || p[0] >> 4 != 4 || p[9] != IPPROTO_TCP || (p[6] & 0x3f) || p[7]) return 0;
        h = (p[0] & 15) * 4;
        if (h < 20 || read16(p+2) != n) return 0;
        r->source = p+12; r->target = p+16;
    } else {
        if (n < 40 || p[0] >> 4 != 6 || p[6] != IPPROTO_TCP || (size_t)(40 + read16(p+4)) != n) return 0;
        h = 40; r->source = p+8; r->target = p+24;
    }
    if (n < h+20) return 0;
    const unsigned char *t = p+h; size_t th = (t[12] >> 4) * 4;
    if (th < 20 || n < h+th) return 0;
    r->source_port = read16(t); r->target_port = read16(t+2);
    r->sequence = read32(t+4); r->ack = read32(t+8); r->flags = t[13];
    r->payload = t+th; r->payload_size = n-h-th;
    return 1;
}
static int tcp_to_target(const unsigned char *p, size_t n) {
    struct tcp_packet r;
    return tcp_parse(p,n,&r) && r.target_port == port && !memcmp(r.target,destination,family == AF_INET ? 4 : 16);
}
static size_t tcp_frame(unsigned char *p, unsigned short client_port, uint32_t seq, uint32_t ack,
                        unsigned char flags, const unsigned char *payload, size_t size) {
    if (size > sizeof(nonce)) return 0;
    size_t h = family == AF_INET ? 20 : 40, width = family == AF_INET ? 4 : 16, len = 20+size;
    memset(p,0,128); put32(p,(unsigned)family); unsigned char *ip = p+4, *tcp = ip+h;
    ip[0] = family == AF_INET ? 0x45 : 0x60;
    if (family == AF_INET) {
        put16(ip+2,h+len); ip[8] = 64; ip[9] = IPPROTO_TCP;
        memcpy(ip+12,destination,4); memcpy(ip+16,local,4); put16(ip+10,checksum(ip,h));
    } else {
        put16(ip+4,len); ip[6] = IPPROTO_TCP; ip[7] = 64;
        memcpy(ip+8,destination,16); memcpy(ip+24,local,16);
    }
    put16(tcp,port); put16(tcp+2,client_port); put32(tcp+4,seq); put32(tcp+8,ack);
    tcp[12] = 0x50; tcp[13] = flags; put16(tcp+14,65535);
    if (size) memcpy(tcp+20,payload,size);
    unsigned char pseudo[80] = {0}; size_t at = 2*width;
    memcpy(pseudo,destination,width); memcpy(pseudo+width,local,width);
    if (family == AF_INET) { pseudo[at+1] = IPPROTO_TCP; put16(pseudo+at+2,len); at += 4; }
    else { put32(pseudo+at,len); pseudo[at+7] = IPPROTO_TCP; at += 8; }
    memcpy(pseudo+at,tcp,len); put16(tcp+16,checksum(pseudo,at+len));
    return 4+h+len;
}
static int tcp_reply(unsigned short client_port, uint32_t seq, uint32_t ack, unsigned char flags,
                     const unsigned char *payload, size_t size) {
    unsigned char packet[128]; size_t n = tcp_frame(packet,client_port,seq,ack,flags,payload,size);
    return n && write(active_fd,packet,n) == (ssize_t)n;
}
static int tcp_socket(void) {
    int fd = socket(family,SOCK_STREAM,0); if (fd < 0) return -1;
    int yes = 1; struct linger abortive = {.l_onoff=1,.l_linger=0};
    if (fcntl(fd,F_SETFL,O_NONBLOCK) || fcntl(fd,F_SETFD,FD_CLOEXEC) ||
        setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&yes,sizeof(yes)) ||
        setsockopt(fd,SOL_SOCKET,SO_LINGER,&abortive,sizeof(abortive))) { int e = errno; close(fd); errno = e; return -1; }
    return fd;
}
static int tcp_connect(int fd) {
    struct sockaddr_storage s; endpoint(&s,destination);
    int result = connect(fd,(void *)&s,family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
    return result == 0 || (result < 0 && (errno == EINPROGRESS || errno == EWOULDBLOCK));
}
static int tcp_next(unsigned short client_port, unsigned char flags, uint32_t ack, int check_ack, size_t payload_size,
                    unsigned char *packet, size_t capacity, struct tcp_packet *r) {
    int64_t end = now_ms()+2000; int reads = 0;
    while (now_ms() < end) {
        int64_t left = end-now_ms(); if (left <= 0) break;
        struct pollfd p = {.fd=active_fd,.events=POLLIN}; int x = poll(&p,1,(int)left);
        if (x < 0 && errno == EINTR) continue;
        if (x < 0 || (x > 0 && !(p.revents & POLLIN))) return 0;
        if (!x) break;
        ssize_t n = read(active_fd,packet,capacity);
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (n <= 0 || n >= (ssize_t)capacity || ++reads > 512) return 0;
        if (!tcp_parse(packet,(size_t)n,r) || r->source_port != client_port || r->target_port != port ||
            memcmp(r->source,local,family == AF_INET ? 4 : 16) || memcmp(r->target,destination,family == AF_INET ? 4 : 16)) continue;
        if (r->flags & (TH_RST|TH_FIN)) return 0;
        if ((r->flags & (TH_SYN|TH_ACK)) != flags || (check_ack && r->ack != ack) || r->payload_size != payload_size) continue;
        return 1;
    }
    return 0;
}
static int tcp_establish(void) {
    stage = "packetTCPOpen"; cached_tcp = tcp_socket(); if (cached_tcp < 0 || !tcp_connect(cached_tcp)) return 0;
    struct sockaddr_storage s; socklen_t length = sizeof(s);
    if (getsockname(cached_tcp,(void *)&s,&length)) return 0;
    unsigned short client_port = ntohs(family == AF_INET ? ((struct sockaddr_in *)&s)->sin_port : ((struct sockaddr_in6 *)&s)->sin6_port);
    if (!client_port) return 0;
    unsigned char packet[4096]; struct tcp_packet r;
    stage = "packetTCPSyn";
    if (!tcp_next(client_port,TH_SYN,0,0,0,packet,sizeof(packet),&r) || r.payload_size) return 0;
    uint32_t client_next = r.sequence+1, server_next = 0x5344aa9a;
    stage = "packetTCPSynAckWrite";
    if (!tcp_reply(client_port,server_next-1,client_next,TH_SYN|TH_ACK,NULL,0)) return 0;
    stage = "packetTCPAck";
    if (!tcp_next(client_port,TH_ACK,server_next,1,0,packet,sizeof(packet),&r) || r.sequence != client_next) return 0;
    int error = 0; socklen_t error_size = sizeof(error);
    if (getsockopt(cached_tcp,SOL_SOCKET,SO_ERROR,&error,&error_size) || error) return 0;
    stage = "packetTCPRequestWrite";
    if (send(cached_tcp,nonce,sizeof(nonce),0) != sizeof(nonce)) return 0;
    stage = "packetTCPRequestObserve";
    if (!tcp_next(client_port,TH_ACK,server_next,1,sizeof(nonce),packet,sizeof(packet),&r) || r.sequence != client_next ||
        r.payload_size != sizeof(nonce) || memcmp(r.payload,nonce,sizeof(nonce))) return 0;
    client_next += sizeof(nonce);
    unsigned char response[sizeof(nonce)]; memcpy(response,nonce,sizeof(response)); response[0] ^= 1;
    stage = "packetTCPResponseWrite";
    if (!tcp_reply(client_port,server_next,client_next,TH_ACK|TH_PUSH,response,sizeof(response))) return 0;
    stage = "packetTCPResponseRead";
    unsigned char received[sizeof(response)]; size_t count = 0; int64_t end = now_ms()+2000;
    while (count < sizeof(received) && now_ms() < end) {
        ssize_t n = recv(cached_tcp,received+count,sizeof(received)-count,0);
        if (n < 0 && (errno == EAGAIN || errno == EINTR)) { usleep(5000); continue; }
        if (n <= 0) return 0;
        count += (size_t)n;
    }
    return count == sizeof(response) && !memcmp(received,response,sizeof(response));
}
static int tcp_after_death(void) {
    ssize_t n = send(cached_tcp,nonce,sizeof(nonce),0);
    if (n != sizeof(nonce) && !(n < 0 && (errno == EHOSTUNREACH || errno == ENETUNREACH ||
        errno == ENETDOWN || errno == EADDRNOTAVAIL || errno == ECONNRESET || errno == EPIPE))) return 0;
    fresh_tcp = tcp_socket(); if (fresh_tcp < 0) return 0;
    if (!tcp_connect(fresh_tcp) && errno != EHOSTUNREACH && errno != ENETUNREACH && errno != ENETDOWN && errno != EADDRNOTAVAIL) return 0;
    return 1;
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
        const unsigned char vector[] = {0x00,0x01,0xf2,0x03,0xf4,0xf5,0xf6,0xf7};
        if (checksum(vector,sizeof(vector)) != 0x220d) return 1;
        unsigned char tcp_bytes[128]; struct tcp_packet tcp;
        size_t tcp_size = tcp_frame(tcp_bytes,52918,0x10203040,0xffeeddcc,TH_ACK|TH_PUSH,nonce,sizeof(nonce));
        if (!tcp_parse(tcp_bytes,tcp_size,&tcp) || tcp.source_port != port || tcp.target_port != 52918 ||
            tcp.sequence != 0x10203040 || tcp.ack != 0xffeeddcc || tcp.flags != (TH_ACK|TH_PUSH) ||
            tcp.payload_size != sizeof(nonce) || memcmp(tcp.payload,nonce,sizeof(nonce)) ||
            memcmp(tcp.source,destination,width) || memcmp(tcp.target,local,width)) return 1;
        for (size_t n = 0; n < tcp_size; n++) if (tcp_parse(tcp_bytes,n,&tcp)) return 1;
        if (tcp_parse(tcp_bytes,tcp_size+1,&tcp)) return 1;
        size_t th = ipv6 ? 40 : 20;
        if (!ipv6 && checksum(tcp_bytes+4,20)) return 1;
        unsigned char pseudo[80] = {0}; size_t ph = ipv6 ? 40 : 12;
        memcpy(pseudo,destination,width); memcpy(pseudo+width,local,width);
        if (ipv6) { put32(pseudo+32,36); pseudo[39] = IPPROTO_TCP; }
        else { pseudo[9] = IPPROTO_TCP; put16(pseudo+10,36); }
        memcpy(pseudo+ph,tcp_bytes+4+th,36);
        if (checksum(pseudo,ph+36)) return 1;
        tcp_bytes[4+th+12] = 0x40; if (tcp_parse(tcp_bytes,tcp_size,&tcp)) return 1;
        tcp_bytes[4+th+12] = 0xf0; if (tcp_parse(tcp_bytes,tcp_size,&tcp)) return 1;
        tcp_bytes[4+th+12] = 0x50;
        tcp_bytes[4+(ipv6 ? 6 : 9)] = IPPROTO_UDP; if (tcp_parse(tcp_bytes,tcp_size,&tcp)) return 1;
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
        if (!expected && tcp_to_target(bytes,(size_t)n)) return 0;
        if (matching(bytes, (size_t)n, ip, source_required)) { seen = 1; if (!expected) return 0; }
        if (expected && seen) return 1;
    }
    return expected ? seen : !seen;
}
static int kill_interface_owner(void) {
    int ready[2]; if (pipe(ready)) return 0;
    owner_pid = fork();
    if (owner_pid == 0) {
        close(ready[0]); close(escape_fd); close(cached_fd); close(neighbor_fd); close(cached_tcp);
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
static int packet_active_add(struct reply *r) {
    stage = "packetActiveAdd";
    if (!check(direct_request(RTM_ADD, 1, active_index, r) == 0)) return 0;
    host_added = 1;
    return 1;
}
static int packet_probe(void) {
    struct reply r;
    stage = "packetBaseline";
    if (!check(absent(1) && absent(0))) return 1;
    int e = direct_request(RTM_GET, 0, escape_index, &r);
    if (!check(e == ESRCH || (e == 0 && !cover_exact(&r)))) return 1;
    stage = "packetCoverAdd"; if (!check(direct_request(RTM_ADD, 0, escape_index, &r) == 0)) return 1; cover_added = 1;
    if (!check(direct_request(RTM_GET, 0, escape_index, &r) == 0 && direct_owned(&r, 0, escape_index))) return 1;
#ifdef PP_NATIVE_EXACT_FENCE
    if (native_fence_after_active && !packet_active_add(&r)) return 1;
#endif
    stage = "packetBackupAdd"; if (!check(request(RTM_ADD, 0, 1, &r) == 0)) return 1; backup_added = 1;
#ifdef PP_NATIVE_EXACT_FENCE
    if (!native_fence_after_active)
#endif
    { if (!packet_active_add(&r)) return 1; }
    if (!check(request(RTM_GET, 1, 0, &r) == 0 && direct_owned(&r, 1, active_index))) return 1;
    cached_fd = udp_socket(destination); neighbor_fd = udp_socket(neighbor);
    stage = "packetUnboundActive";
    if (!check(cached_fd >= 0 && neighbor_fd >= 0 && emit(cached_fd, 0) && observe(active_fd, destination, 1, 1, 2000) && observe(escape_fd, destination, 0, 0, 100))) return 1;
    stage = "packetNeighborBefore";
    if (!check(emit(neighbor_fd, 0) && observe(escape_fd, neighbor, 0, 1, 2000))) return 1;
    stage = "packetTCPEstablished"; if (!check(tcp_establish())) return 1;
    stage = "packetTCPNoEscapeBefore"; if (!check(observe(escape_fd,destination,0,0,100))) return 1;
    stage = "packetOwnerDeath"; if (!check(kill_interface_owner())) return 1;
    stage = "packetBackupSelected"; if (!check(request(RTM_GET, 1, 0, &r) == 0 && owned(&r, 0, 1))) return 1; host_added = 0;
    stage = "packetCachedAfterDeath"; if (!check(emit(cached_fd, 1))) return 1;
    /* New sockets may also fail connect when the exact blackhole is selected. */
    errno = 0; fresh_fd = udp_socket(destination); int connect_error = errno;
    stage = "packetFreshAfterDeath";
    if (!check(fresh_fd >= 0 ? emit(fresh_fd, 1) : (connect_error == EHOSTUNREACH || connect_error == ENETUNREACH))) return 1;
    stage = "packetTCPAfterDeath"; if (!check(tcp_after_death())) return 1;
    stage = "packetNoEscape"; if (!check(observe(escape_fd, destination, 0, 0, 2000))) return 1;
    stage = "packetNeighborAfter"; if (!check(emit(neighbor_fd, 0) && observe(escape_fd, neighbor, 0, 1, 2000))) return 1;
    return 0;
}
static int cleanup(void) {
    if (owner_pid > 0) { kill(owner_pid, SIGKILL); waitpid(owner_pid, NULL, 0); owner_pid = -1; }
    int *clients[] = {&cached_fd, &fresh_fd, &neighbor_fd, &cached_tcp, &fresh_tcp};
    for (size_t i = 0; i < sizeof(clients)/sizeof(*clients); i++) if (*clients[i] >= 0) { close(*clients[i]); *clients[i] = -1; }
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
#ifdef PP_NATIVE_EXACT_FENCE
    const char *native = getenv("PROXYPILOT_VM_NATIVE_EXACT_FENCE");
    if (!native || strcmp(native,"1")) return 77;
    const char *after = getenv("PROXYPILOT_VM_NATIVE_FENCE_AFTER_ACTIVE");
    if (!after || (strcmp(after,"0") && strcmp(after,"1"))) return 77;
    native_fence_after_active = !strcmp(after,"1");
    /* The C fixture and Swift controller share this PID. Reserve disjoint
     * sequence ranges here; production Swift uses its shared allocator. */
    sequence = 1000000;
#endif
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
        puts(i ? "PASS exact-route-udp-ipv6-active-cached-fresh-death-neighbor" : "PASS exact-route-udp-ipv4-active-cached-fresh-death-neighbor");
        puts(i ? "PASS exact-route-tcp-ipv6-established-exchange-cached-fresh-death" : "PASS exact-route-tcp-ipv4-established-exchange-cached-fresh-death"); fflush(stdout);
    }
    return 0;
}
