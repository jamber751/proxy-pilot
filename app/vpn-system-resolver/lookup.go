package main

/*
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
// Direct Darwin getaddrinfo, not Go's pure resolver and not a flattened server
// list. Synchronous: admission remains held until the native call really ends.
static int pp_lookup(const char *host, int family, char *out, int stride, int capacity, int *count) {
    struct addrinfo hints, *head = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family; hints.ai_socktype = SOCK_STREAM;
    int status = getaddrinfo(host, NULL, &hints, &head);
    if (status != 0) return status;
    *count = 0;
    for (struct addrinfo *p = head; p != NULL; p = p->ai_next) {
        const void *address = NULL;
        if (p->ai_family == AF_INET && p->ai_addrlen >= sizeof(struct sockaddr_in))
            address = &((struct sockaddr_in *)p->ai_addr)->sin_addr;
        if (p->ai_family == AF_INET6 && p->ai_addrlen >= sizeof(struct sockaddr_in6)) {
            struct sockaddr_in6 *a = (struct sockaddr_in6 *)p->ai_addr;
            if (a->sin6_scope_id != 0) continue;
            address = &a->sin6_addr;
        }
        if (address == NULL) continue;
        if (*count >= capacity || inet_ntop(p->ai_family, address, out + *count * stride, stride) == NULL) {
            freeaddrinfo(head); return EAI_FAIL;
        }
        (*count)++;
    }
    freeaddrinfo(head); return 0;
}
*/
import "C"
import (
	"errors"
	"net/netip"
	"strings"
	"unsafe"
)

func nativeLookup(network, host string) ([]string, error) {
	family := C.int(C.AF_UNSPEC)
	if network == "ip4" {
		family = C.AF_INET
	}
	if network == "ip6" {
		family = C.AF_INET6
	}
	input := C.CString(host)
	defer C.free(unsafe.Pointer(input))
	const stride = 46
	output := make([]byte, 64*stride)
	count := C.int(0)
	status := C.pp_lookup(input, family, (*C.char)(unsafe.Pointer(&output[0])), stride, 64, &count)
	if status != 0 || count < 1 || count > 64 {
		return nil, errors.New("resolution")
	}
	result := make([]string, 0, int(count))
	seen := make(map[netip.Addr]bool)
	for i := 0; i < int(count); i++ {
		row := string(output[i*stride : (i+1)*stride])
		at := strings.IndexByte(row, 0)
		if at < 1 {
			return nil, errors.New("resolution")
		}
		ip, err := netip.ParseAddr(row[:at])
		if err != nil || ip.Zone() != "" || ip.Is4In6() {
			return nil, errors.New("resolution")
		}
		if !seen[ip] {
			seen[ip] = true
			result = append(result, ip.String())
		}
	}
	return result, nil
}
