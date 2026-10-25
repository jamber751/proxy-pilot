package resolver

import (
	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	xlogger "github.com/go-gost/x/logger"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Existing public parser must reject a requested CA it cannot actually use.
// These assertions also compile on untouched x0.8.1 and fail there.
func TestProxyPilotResolverRefusesIgnoredCA(t *testing.T) {
	logger.SetDefault(xlogger.Nop())
	folder := t.TempDir()
	invalid := filepath.Join(folder, "invalid.pem")
	oversized := filepath.Join(folder, "oversized.pem")
	if os.WriteFile(invalid, []byte("not a certificate"), 0600) != nil || os.WriteFile(oversized, []byte(strings.Repeat("x", 65537)), 0600) != nil {
		t.Fatal("fixture")
	}
	for _, path := range []string{filepath.Join(folder, "missing.pem"), invalid, oversized, folder} {
		_, err := ParseResolver(&config.ResolverConfig{Name: "owned-test", Plugin: &config.PluginConfig{
			Type: "http", Addr: "https://127.0.0.1:1/resolve", TLS: &config.TLSConfig{Secure: true, CAFile: path}}})
		if err == nil {
			t.Fatal("requested CA ignored")
		}
	}
}
