package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/config"
	parser "github.com/go-gost/x/config/parsing/bypass"
	xlogger "github.com/go-gost/x/logger"
	"github.com/go-gost/x/registry"
)

// Actual updateBypass handler, in-memory requests only. No listener or DNS.
func TestProxyPilotAPIUpdatePublishesReadyMatchers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger.SetDefault(xlogger.Nop())
	const name = "proxypilot-owned-api-test"
	initial := &config.BypassConfig{Name: name, Matchers: []string{"198.19.253.201/32"}}
	config.Set(&config.Config{Bypasses: []*config.BypassConfig{initial}})
	if err := registry.BypassRegistry().Register(name, parser.ParseBypass(initial)); err != nil {
		t.Fatal("register")
	}
	defer registry.BypassRegistry().Unregister(name)
	wrapper := registry.BypassRegistry().Get(name)
	deadline := time.Now().Add(time.Second)
	for !wrapper.Contains(context.Background(), "tcp", "198.19.253.201:443") {
		if time.Now().After(deadline) {
			t.Fatal("initial setup")
		}
		runtime.Gosched()
	}
	var readers sync.WaitGroup
	var failed atomic.Bool
	start := make(chan struct{})
	for r := 0; r < 8; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			<-start
			for i := 0; i < 8000; i++ {
				if !wrapper.Contains(context.Background(), "tcp", "198.19.253.201:443") {
					failed.Store(true)
					return
				}
			}
		}()
	}
	close(start)
	for i := 0; i < 200; i++ {
		response := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(response)
		ctx.Params = gin.Params{{Key: "bypass", Value: name}}
		ctx.Request = httptest.NewRequest(http.MethodPut, "/config/bypasses/"+name,
			bytes.NewBufferString(`{"name":"proxypilot-owned-api-test","matchers":["198.19.253.201/32","2001:db8:fff:fd::c9/128"]}`))
		ctx.Request.Header.Set("Content-Type", "application/json")
		updateBypass(ctx)
		if response.Code != http.StatusOK || response.Body.String() != `{"msg":"OK"}` {
			t.Fatal("update acknowledgement")
		}
		// ACK must follow the initial matcher load, including the new IPv6 value.
		if !wrapper.Contains(context.Background(), "tcp", "[2001:db8:fff:fd::c9]:443") {
			t.Fatal("ack before activation")
		}
	}
	readers.Wait()
	if failed.Load() {
		t.Fatal("published IP lost through API update")
	}
}
