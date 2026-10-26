package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const secret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestStartupRequiresBoundedCompleteLine(t *testing.T) {
	valid := `{"password":"` + secret + `"}`
	for _, input := range []string{valid, "", "{}\n", valid + "\nextra", valid + "\n\n", valid + strings.Repeat(" ", 512) + "\n", `{"password":"` + secret + `","password":"` + secret + `"}` + "\n"} {
		if _, _, err := startup(strings.NewReader(input)); err == nil {
			t.Fatal("invalid startup accepted")
		}
	}
	fields, _, err := startup(strings.NewReader(valid + "\n"))
	if err != nil || fields["password"] != secret {
		t.Fatal("complete startup refused")
	}
}

func TestOwnerLifetimeRetiresOnEOFDataAndError(t *testing.T) {
	for _, mode := range []string{"eof", "data", "error"} {
		t.Run(mode, func(t *testing.T) {
			reader, writer := io.Pipe()
			defer reader.Close()
			defer writer.Close()
			done := ownerLifetime(reader)
			select {
			case <-done:
				t.Fatal("live owner retired")
			case <-time.After(10 * time.Millisecond):
			}
			writeDone := make(chan struct{})
			go func() {
				defer close(writeDone)
				switch mode {
				case "eof":
					_ = writer.Close()
				case "error":
					_ = writer.CloseWithError(errors.New("fixture"))
				case "data":
					_, _ = writer.Write([]byte{'!'})
				}
			}()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("lost owner remained live")
			}
			select {
			case <-writeDone:
			case <-time.After(time.Second):
				t.Fatal("owner input was not consumed")
			}
		})
	}
}

func requestFor(body string) *http.Request {
	r := httptest.NewRequest("POST", "https://127.0.0.1:12345/resolve", strings.NewReader(body))
	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("proxypilot:"+secret)))
	r.Header.Set("Content-Type", "application/json")
	return r
}

const question = `{"network":"ip","host":"company.example","client":"owned"}`

func TestStrictRequestBeforeLookup(t *testing.T) {
	cases := []string{`{}`, `{"network":"ip","host":"company.example","client":"x","host":"other.example"}`,
		`{"network":"ip","host":"company.example","client":"x","extra":"y"}`, question + `{}`,
		`{"network":"udp","host":"company.example","client":"x"}`,
		`{"network":"ip","host":"https://company.example","client":"x"}`,
		`{"network":"ip","host":"x\u0000.example","client":"x"}`, strings.Repeat("x", 1025)}
	for _, body := range cases {
		calls := 0
		handler := makeHandler(secret, "127.0.0.1:12345", func(string, string) ([]string, error) { calls++; return []string{"192.0.2.1"}, nil }, make(chan struct{}, 1))
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, requestFor(body))
		if out.Code != 400 || calls != 0 {
			t.Fatal("invalid request admitted")
		}
	}
}
func TestAuthenticationBeforeBodyAndLookup(t *testing.T) {
	for _, mode := range []string{"missing", "wrong", "duplicate", "path", "method", "host", "type"} {
		called := false
		handler := makeHandler(secret, "127.0.0.1:12345", func(string, string) ([]string, error) { called = true; return nil, nil }, make(chan struct{}, 1))
		r := requestFor(question)
		switch mode {
		case "missing":
			r.Header.Del("Authorization")
		case "wrong":
			r.Header.Set("Authorization", "Basic invalid")
		case "duplicate":
			r.Header.Add("Authorization", r.Header.Get("Authorization"))
		case "path":
			r.URL.Path = "/other"
		case "method":
			r.Method = "GET"
		case "host":
			r.Host = "foreign.example"
		case "type":
			r.Header.Set("Content-Type", "text/plain")
		}
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, r)
		if out.Code == 200 || called {
			t.Fatal("unauthenticated lookup")
		}
	}
}
func TestNativeFailureNeverFallsBack(t *testing.T) {
	for _, ips := range [][]string{nil, {}, {"bad"}, {"::ffff:192.0.2.1"}, {"fe80::1%lo0"}} {
		calls := 0
		handler := makeHandler(secret, "127.0.0.1:12345", func(string, string) ([]string, error) { calls++; return ips, nil }, make(chan struct{}, 1))
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, requestFor(question))
		if out.Code != 502 || calls != 1 || strings.Contains(out.Body.String(), "company") {
			t.Fatal("failed lookup escaped")
		}
	}
	handler := makeHandler(secret, "127.0.0.1:12345", func(string, string) ([]string, error) { return []string{"192.0.2.1"}, errors.New("private details") }, make(chan struct{}, 1))
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, requestFor(question))
	if out.Code != 502 || strings.Contains(out.Body.String(), "private") {
		t.Fatal("error leaked")
	}
}
func TestNativeResultAndFamily(t *testing.T) {
	for _, network := range []string{"ip", "ip4", "ip6"} {
		handler := makeHandler(secret, "127.0.0.1:12345", func(n, h string) ([]string, error) {
			if n != network || h != "company.example" {
				t.Fatal("question changed")
			}
			if n == "ip4" {
				return []string{"192.0.2.1"}, nil
			}
			return []string{"2001:db8::1"}, nil
		}, make(chan struct{}, 1))
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, requestFor(strings.Replace(question, `"ip"`, `"`+network+`"`, 1)))
		var decoded response
		if out.Code != 200 || json.Unmarshal(out.Body.Bytes(), &decoded) != nil || !decoded.OK || len(decoded.IPs) != 1 {
			t.Fatal("native result changed")
		}
	}
}
func TestAdmissionHeldUntilNativeCallActuallyEnds(t *testing.T) {
	entered, finish := make(chan struct{}), make(chan struct{})
	slots := make(chan struct{}, 1)
	handler := makeHandler(secret, "127.0.0.1:12345", func(string, string) ([]string, error) { close(entered); <-finish; return []string{"192.0.2.1"}, nil }, slots)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := httptest.NewRecorder()
	r := requestFor(question).WithContext(ctx)
	done := make(chan struct{})
	go func() { defer close(done); handler.ServeHTTP(first, r) }()
	<-entered
	cancel()
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, requestFor(question))
	if out.Code != 503 {
		t.Fatal("native admission overflow")
	}
	close(finish)
	<-done
	if len(slots) != 0 || first.Code != 502 {
		t.Fatal("cancelled lookup released an answer")
	}
}
func TestCertificateIsFreshAndLoopbackOnly(t *testing.T) {
	a, pem, err := certificate()
	if err != nil {
		t.Fatal("certificate")
	}
	b, _, err := certificate()
	if err != nil {
		t.Fatal("certificate")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("CA")
	}
	parsed, err := x509.ParseCertificate(a.Certificate[0])
	if err != nil {
		t.Fatal("certificate")
	}
	if _, err = parsed.Verify(x509.VerifyOptions{Roots: roots, DNSName: "127.0.0.1"}); err != nil {
		t.Fatal("own certificate refused")
	}
	if _, err = parsed.Verify(x509.VerifyOptions{Roots: roots, DNSName: "other.example"}); err == nil {
		t.Fatal("foreign name accepted")
	}
	other, _ := x509.ParseCertificate(b.Certificate[0])
	if _, err = other.Verify(x509.VerifyOptions{Roots: roots, DNSName: "127.0.0.1"}); err == nil {
		t.Fatal("foreign epoch accepted")
	}
}
func TestPasswordAndHostInputs(t *testing.T) {
	for _, value := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("g", 64)} {
		if passwordValid(value) {
			t.Fatal("password")
		}
	}
	if !passwordValid(secret) {
		t.Fatal("password")
	}
	for _, value := range []string{"", "https://a.example", "a..example", "-a.example", "a-.example", "fe80::1%lo0", strings.Repeat("a", 64) + ".example"} {
		if hostValid(value) {
			t.Fatal("host")
		}
	}
	for _, value := range []string{"company.example", "company.example.", "192.0.2.1", "2001:db8::1"} {
		if !hostValid(value) {
			t.Fatal("host")
		}
	}
}

// httptest.NewRecorder never listens; fake lookups above never call nativeLookup.
