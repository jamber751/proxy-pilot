package registry_test

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-gost/core/bypass"
	xbypass "github.com/go-gost/x/bypass"
	"github.com/go-gost/x/registry"
)

// No sockets, DNS, interfaces, GOST process, root API or external target.
func closeBypass(value bypass.Bypass) {
	if closer, ok := value.(io.Closer); ok {
		closer.Close()
	}
}
func positive() bypass.Bypass {
	return xbypass.NewBypass(xbypass.MatchersOption([]string{"198.19.253.201/32", "2001:db8:fff:fd::c9/128"}))
}
func containsBoth(value bypass.Bypass) bool {
	ctx := context.Background()
	return value.Contains(ctx, "tcp", "198.19.253.201:443") && value.Contains(ctx, "tcp", "[2001:db8:fff:fd::c9]:443") && !value.IsWhitelist()
}
func TestProxyPilotInitialMatchersAreSynchronous(t *testing.T) {
	for i := 0; i < 1000; i++ {
		value := positive()
		if !containsBoth(value) {
			t.Fatal("initial matcher not ready")
		}
		closeBypass(value)
	}
}
func TestProxyPilotAtomicReplacementRetainsPublishedIPs(t *testing.T) {
	const name = "proxypilot-owned-atomic-test"
	if err := registry.BypassRegistry().Register(name, positive()); err != nil {
		t.Fatal("register")
	}
	defer registry.BypassRegistry().Unregister(name)
	wrapper := registry.BypassRegistry().Get(name)
	var group sync.WaitGroup
	var failed atomic.Bool
	start := make(chan struct{})
	for r := 0; r < 8; r++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			for i := 0; i < 4000; i++ {
				if !containsBoth(wrapper) {
					failed.Store(true)
					return
				}
			}
		}()
	}
	close(start)
	for i := 0; i < 1000; i++ {
		if err := registry.ReplaceBypass(name, positive()); err != nil {
			t.Fatal("replace")
		}
	}
	group.Wait()
	if failed.Load() || !containsBoth(wrapper) {
		t.Fatal("published IP lost during replacement")
	}
}
func TestProxyPilotMissingReplacementDoesNotInsert(t *testing.T) {
	const name = "proxypilot-missing-test"
	value := positive()
	defer closeBypass(value)
	if registry.ReplaceBypass(name, value) == nil {
		t.Fatal("adopted missing target")
	}
	if registry.BypassRegistry().IsRegistered(name) {
		t.Fatal("inserted target")
	}
}
func TestProxyPilotPreviousReaderSurvivesSwap(t *testing.T) {
	const name = "proxypilot-old-reader-test"
	previous := positive()
	if err := registry.BypassRegistry().Register(name, previous); err != nil {
		t.Fatal("register")
	}
	defer registry.BypassRegistry().Unregister(name)
	if err := registry.ReplaceBypass(name, positive()); err != nil {
		t.Fatal("replace")
	}
	if !containsBoth(previous) {
		t.Fatal("old reader invalidated")
	}
}
