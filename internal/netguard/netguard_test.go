package netguard

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestPolicy(t *testing.T) {
	lan := netip.MustParsePrefix("192.168.1.10/24")
	vpn := []netip.Prefix{netip.MustParsePrefix("10.8.0.0/24")}

	tests := []struct {
		name   string
		policy Policy
		addr   string
		want   bool
	}{
		{"default: loopback", NewPolicy(netip.Prefix{}, nil), "127.0.0.1", true},
		{"default: ipv6 loopback", NewPolicy(netip.Prefix{}, nil), "::1", true},
		{"default: rfc1918", NewPolicy(netip.Prefix{}, nil), "192.168.178.20", true},
		{"default: docker bridge", NewPolicy(netip.Prefix{}, nil), "172.18.0.5", true},
		{"default: ula", NewPolicy(netip.Prefix{}, nil), "fd12:3456::1", true},
		{"default: link-local with zone", NewPolicy(netip.Prefix{}, nil), "fe80::1%eth0", true},
		{"default: public", NewPolicy(netip.Prefix{}, nil), "8.8.8.8", false},
		{"default: public v6", NewPolicy(netip.Prefix{}, nil), "2001:db8::1", false},
		{"default: mapped public", NewPolicy(netip.Prefix{}, nil), "::ffff:8.8.8.8", false},
		{"default: mapped private", NewPolicy(netip.Prefix{}, nil), "::ffff:192.168.1.5", true},
		{"strict: same subnet", NewPolicy(lan, nil), "192.168.1.77", true},
		{"strict: loopback", NewPolicy(lan, nil), "127.0.0.1", true},
		{"strict: other private subnet", NewPolicy(lan, nil), "192.168.2.1", false},
		{"strict: cloudflared container", NewPolicy(lan, nil), "172.18.0.5", false},
		{"strict: extra vpn", NewPolicy(lan, vpn), "10.8.0.3", true},
		{"strict: outside vpn", NewPolicy(lan, vpn), "10.9.0.3", false},
		{"zero value allows nothing", Policy{}, "127.0.0.1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.policy.Allows(netip.MustParseAddr(tt.addr)); got != tt.want {
				t.Errorf("Allows(%s) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

// TestListenerDropsDisallowed checks that a rejected client gets its
// connection closed without any data, and that Accept keeps serving.
func TestListenerDropsDisallowed(t *testing.T) {
	inner, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rejected := make(chan netip.AddrPort, 1)
	// NewPolicy always allows loopback, so build a policy without it to make
	// the loopback test client a disallowed one.
	l := &Listener{
		Listener: inner,
		Policy:   Policy{allowed: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}},
		OnReject: func(ap netip.AddrPort) { rejected <- ap },
	}

	go func() {
		c, err := l.Accept() // returns only when the listener closes
		if err == nil {
			_ = c.Close()
		}
	}()

	d := net.Dialer{Timeout: time.Second}
	c, err := d.DialContext(context.Background(), "tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Read(make([]byte, 1))
	if n != 0 || err == nil {
		t.Fatalf("want closed connection, got n=%d err=%v", n, err)
	}
	select {
	case ap := <-rejected:
		if !ap.Addr().IsLoopback() {
			t.Errorf("rejected address = %v", ap)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("OnReject not called")
	}
	_ = inner.Close()
}

func TestListenerAcceptsAllowed(t *testing.T) {
	inner, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = inner.Close() }()
	l := &Listener{Listener: inner, Policy: NewPolicy(netip.MustParsePrefix("192.168.1.10/24"), nil)}

	accepted := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			_, err = c.Write([]byte("x"))
			_ = c.Close()
		}
		accepted <- err
	}()
	d := net.Dialer{Timeout: time.Second}
	c, err := d.DialContext(context.Background(), "tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	b, _ := io.ReadAll(c)
	if string(b) != "x" {
		t.Errorf("read %q", b)
	}
	if err := <-accepted; err != nil {
		t.Fatal(err)
	}
}

func TestRejectCloudflare(t *testing.T) {
	h := RejectCloudflare(slog.New(slog.NewTextHandler(io.Discard, nil)),
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))

	tests := []struct {
		name   string
		header map[string]string
		want   int
	}{
		{"plain", nil, http.StatusOK},
		{"cf-ray", map[string]string{"CF-RAY": "8a1b2c3d4e5f-FRA"}, http.StatusForbidden},
		{"cf-connecting-ip", map[string]string{"Cf-Connecting-IP": "203.0.113.7"}, http.StatusForbidden},
		{"cdn-loop", map[string]string{"CDN-Loop": "cloudflare; loops=1"}, http.StatusForbidden},
		{"other cdn-loop", map[string]string{"CDN-Loop": "fastly"}, http.StatusOK},
		{"x-forwarded-for ignored", map[string]string{"X-Forwarded-For": "8.8.8.8"}, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
			for k, v := range tt.header {
				r.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tt.want {
				t.Errorf("status %d, want %d", w.Code, tt.want)
			}
		})
	}
}

func TestRejectLoggerThrottles(t *testing.T) {
	var buf lineCounter
	f := RejectLogger(slog.New(slog.NewTextHandler(&buf, nil)), time.Hour)
	a := netip.MustParseAddrPort("203.0.113.7:5000")
	b := netip.MustParseAddrPort("203.0.113.8:5000")
	f(a)
	f(a)
	f(b)
	if buf.n != 2 {
		t.Errorf("logged %d lines, want 2", buf.n)
	}
}

type lineCounter struct{ n int }

func (c *lineCounter) Write(p []byte) (int, error) {
	for _, b := range p {
		if b == '\n' {
			c.n++
		}
	}
	return len(p), nil
}
