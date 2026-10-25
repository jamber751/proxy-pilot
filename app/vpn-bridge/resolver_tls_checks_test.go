package resolver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/go-gost/x/config"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func ownedCertificate(t *testing.T) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("fixture")
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned resolver"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal("fixture")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("fixture")
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
func TestProxyPilotResolverPinsOwnedCA(t *testing.T) {
	cert, encoded := ownedCertificate(t)
	foreign, _ := ownedCertificate(t)
	path := filepath.Join(t.TempDir(), "ca.pem")
	if os.WriteFile(path, encoded, 0600) != nil {
		t.Fatal("fixture")
	}
	cfg, err := proxyPilotPluginTLS(&config.TLSConfig{Secure: true, CAFile: path, ServerName: "127.0.0.1"})
	if err != nil || cfg == nil || cfg.InsecureSkipVerify || cfg.RootCAs == nil || cfg.ServerName != "127.0.0.1" {
		t.Fatal("TLS configuration")
	}
	options := x509.VerifyOptions{Roots: cfg.RootCAs, DNSName: cfg.ServerName}
	if _, err = cert.Verify(options); err != nil {
		t.Fatal("owned CA refused")
	}
	if _, err = foreign.Verify(options); err == nil {
		t.Fatal("foreign CA trusted")
	}
	options.DNSName = "foreign.example"
	if _, err = cert.Verify(options); err == nil {
		t.Fatal("wrong server name trusted")
	}
}
func TestProxyPilotResolverCARequiresVerification(t *testing.T) {
	_, encoded := ownedCertificate(t)
	path := filepath.Join(t.TempDir(), "ca.pem")
	if os.WriteFile(path, encoded, 0600) != nil {
		t.Fatal("fixture")
	}
	if _, err := proxyPilotPluginTLS(&config.TLSConfig{CAFile: path, Secure: false}); err == nil {
		t.Fatal("insecure custom CA")
	}
	cfg, err := proxyPilotPluginTLS(nil)
	if err != nil || cfg != nil {
		t.Fatal("default TLS behavior changed")
	}
	cfg, err = proxyPilotPluginTLS(&config.TLSConfig{Secure: true})
	if err != nil || cfg.InsecureSkipVerify || cfg.RootCAs != nil {
		t.Fatal("default roots changed")
	}
}
