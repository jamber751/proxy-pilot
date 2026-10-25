// An owned ordinary-user resolver worker. Startup takes a secret on inherited
// stdin, never argv/environment. Native DNS is used only for authenticated calls.
// The parent must verify this signed child, pin its per-process TLS certificate,
// and retire GOST with this epoch; this worker alone is not a domain authority.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

type lookupFunc func(string, string) ([]string, error)
type request struct{ Network, Host, Client string }
type response struct {
	IPs []string `json:"ips"`
	OK  bool     `json:"ok"`
}

func decodeFields(reader io.Reader, maximum int, names ...string) (map[string]string, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, int64(maximum+1)))
	if err != nil || len(raw) > maximum {
		return nil, errors.New("request")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return nil, errors.New("request")
	}
	result := make(map[string]string)
	allowed := make(map[string]bool)
	for _, name := range names {
		allowed[name] = true
	}
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || !allowed[name] {
			return nil, errors.New("request")
		}
		if _, present := result[name]; present {
			return nil, errors.New("request")
		}
		var value string
		if decoder.Decode(&value) != nil {
			return nil, errors.New("request")
		}
		result[name] = value
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || len(result) != len(names) {
		return nil, errors.New("request")
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, errors.New("request")
	}
	return result, nil
}
func passwordValid(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func hostValid(value string) bool {
	if len(value) < 1 || len(value) > 253 || strings.IndexByte(value, 0) >= 0 {
		return false
	}
	if ip, err := netip.ParseAddr(value); err == nil {
		return ip.Zone() == "" && !ip.Is4In6()
	}
	// DNS labels only; no URL, zone or embedded credentials. Native macOS
	// search/scoping rules remain the resolver's responsibility.
	for _, label := range strings.Split(strings.TrimSuffix(value, "."), ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func makeHandler(password, address string, lookup lookupFunc, slots chan struct{}) http.Handler {
	authorization := "Basic " + base64.StdEncoding.EncodeToString([]byte("proxypilot:"+password))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Connection", "close")
		fail := func(status int) { w.WriteHeader(status); _, _ = io.WriteString(w, "{\"ips\":[],\"ok\":false}") }
		if r.Method != "POST" || r.URL.Path != "/resolve" || r.URL.RawQuery != "" || r.Host != address {
			fail(http.StatusBadRequest)
			return
		}
		if len(r.Header.Values("Authorization")) != 1 || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(authorization)) != 1 {
			fail(http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			fail(http.StatusBadRequest)
			return
		}
		fields, err := decodeFields(r.Body, 1024, "network", "host", "client")
		if err != nil || !hostValid(fields["host"]) || len(fields["client"]) > 128 ||
			!(fields["network"] == "ip" || fields["network"] == "ip4" || fields["network"] == "ip6") {
			fail(http.StatusBadRequest)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			fail(http.StatusServiceUnavailable)
			return
		}
		if r.Context().Err() != nil {
			fail(http.StatusRequestTimeout)
			return
		}
		// Keep admission until synchronous Darwin getaddrinfo actually returns.
		// HTTP cancellation cannot falsely free a still-running native lookup.
		ips, err := lookup(fields["network"], fields["host"])
		if err != nil || len(ips) == 0 || len(ips) > 64 || r.Context().Err() != nil {
			fail(http.StatusBadGateway)
			return
		}
		for _, value := range ips {
			ip, err := netip.ParseAddr(value)
			if err != nil || ip.Zone() != "" || ip.Is4In6() ||
				fields["network"] == "ip4" && !ip.Is4() || fields["network"] == "ip6" && !ip.Is6() {
				fail(http.StatusBadGateway)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response{IPs: ips, OK: true})
	})
}

// Limit accepted connections as well as lookups. Header/body slow clients cannot
// allocate an unbounded number of handlers or native DNS calls.
type limitedListener struct {
	net.Listener
	slots chan struct{}
}
type ownedConn struct {
	net.Conn
	released chan struct{}
	once     sync.Once
}

func (c *ownedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.released) })
	return err
}
func (l *limitedListener) Accept() (net.Conn, error) {
	l.slots <- struct{}{}
	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	released := make(chan struct{})
	go func() { <-released; <-l.slots }()
	return &ownedConn{Conn: conn, released: released}, nil
}
func certificate() (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "ProxyPilot owned resolver"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}
func run() error {
	if runtime.GOOS != "darwin" || os.Getuid() != os.Geteuid() || os.Getuid() < 500 || len(os.Args) != 1 {
		return errors.New("guard")
	}
	input := os.Stdin
	info, err := input.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		return errors.New("startup")
	}
	fields, err := decodeFields(input, 512, "password")
	_ = input.Close()
	if err != nil || !passwordValid(fields["password"]) {
		return errors.New("startup")
	}
	cert, public, err := certificate()
	if err != nil {
		return errors.New("startup")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return errors.New("startup")
	}
	defer listener.Close()
	address := listener.Addr().String()
	server := &http.Server{Handler: makeHandler(fields["password"], address, nativeLookup, make(chan struct{}, 16)),
		ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 5 * time.Second,
		IdleTimeout: time.Second, MaxHeaderBytes: 4096, ErrorLog: log.New(io.Discard, "", 0),
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler))}
	limited := &limitedListener{Listener: listener, slots: make(chan struct{}, 32)}
	secured := tls.NewListener(limited, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	// This public certificate is not sufficient evidence on an arbitrary pipe.
	// Parent must own/authenticate this exact signed child before trusting READY.
	if json.NewEncoder(os.Stdout).Encode(struct {
		Port        int    `json:"port"`
		Certificate string `json:"certificate"`
	}{listener.Addr().(*net.TCPAddr).Port, string(public)}) != nil {
		return errors.New("startup")
	}
	return server.Serve(secured)
}
func main() {
	if run() != nil {
		_, _ = io.WriteString(os.Stderr, "resolver worker unavailable\n")
		os.Exit(69)
	}
}
