// Package netguard keeps BelayPoint unreachable from outside the allowed
// networks (see "Network access" in docs/architecture.md):
//
//   - Listener closes connections from disallowed source addresses right
//     after accept, before the TLS handshake. The client sees no
//     certificate and no HTTP response.
//   - RejectCloudflare refuses HTTP requests that came through a Cloudflare
//     tunnel (they carry Cf-* headers), which only happens on a
//     misconfiguration.
//
// Only the TCP source address is used. Forwarding headers such as
// X-Forwarded-For are never trusted.
package netguard

import (
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// defaultRanges are allowed when no LAN address is configured: loopback and
// private ranges (RFC 1918, IPv6 ULA and link-local).
var defaultRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

var loopback = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("::1/128"),
}

// Policy decides which source addresses may connect. The zero value allows
// nothing.
type Policy struct {
	allowed []netip.Prefix
}

// NewPolicy builds the allowlist. If lan is valid (strict mode), only its
// network and loopback are allowed; otherwise loopback and the private
// default ranges. extra networks are allowed in both modes.
func NewPolicy(lan netip.Prefix, extra []netip.Prefix) Policy {
	allowed := append([]netip.Prefix{}, loopback...)
	if lan.IsValid() {
		allowed = append(allowed, lan.Masked())
	} else {
		allowed = append(allowed, defaultRanges...)
	}
	for _, p := range extra {
		allowed = append(allowed, p.Masked())
	}
	return Policy{allowed: allowed}
}

// Allows reports whether a connection from addr is allowed.
func (p Policy) Allows(addr netip.Addr) bool {
	// An IPv4 client on a dual-stack socket appears as ::ffff:a.b.c.d.
	// Prefix.Contains never matches an address with a zone (fe80::1%eth0).
	addr = addr.Unmap().WithZone("")
	for _, pr := range p.allowed {
		if pr.Contains(addr) {
			return true
		}
	}
	return false
}

// Networks returns the allowed networks (for the startup log).
func (p Policy) Networks() []netip.Prefix {
	return append([]netip.Prefix{}, p.allowed...)
}

// Listener wraps a TCP listener and drops connections the Policy does not
// allow. It must sit below tls.NewListener so that dropped clients never get
// a TLS handshake.
type Listener struct {
	net.Listener
	Policy Policy
	// OnReject is called (if not nil) for every dropped connection.
	OnReject func(netip.AddrPort)
}

// Accept returns the next allowed connection. Disallowed connections are
// closed and skipped; Accept only returns on an allowed connection or an
// error of the underlying listener.
func (l *Listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ap, ok := remoteAddrPort(c)
		if ok && l.Policy.Allows(ap.Addr()) {
			return c, nil
		}
		_ = c.Close()
		if l.OnReject != nil {
			l.OnReject(ap)
		}
	}
}

func remoteAddrPort(c net.Conn) (netip.AddrPort, bool) {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.AddrPort(), true
	}
	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	return ap, err == nil
}

// RejectLogger returns an OnReject callback that logs a dropped source
// address at most once per interval, so a scanner cannot flood the log.
func RejectLogger(log *slog.Logger, interval time.Duration) func(netip.AddrPort) {
	var mu sync.Mutex
	last := map[netip.Addr]time.Time{}
	return func(ap netip.AddrPort) {
		now := time.Now()
		mu.Lock()
		if len(last) > 1024 { // bound memory; forgetting only means one more log line
			clear(last)
		}
		t, seen := last[ap.Addr()]
		if seen && now.Sub(t) < interval {
			mu.Unlock()
			return
		}
		last[ap.Addr()] = now
		mu.Unlock()
		log.Warn("connection from a network that is not allowed was dropped",
			"remote", ap.Addr().String(), "hint", dropHint(ap.Addr()))
	}
}

// dockerGateway matches the gateway addresses of Docker's default address
// pools (x.y.0.1 in 172.16.0.0/12).
func dockerGateway(a netip.Addr) bool {
	a = a.Unmap()
	if !a.Is4() || !netip.MustParsePrefix("172.16.0.0/12").Contains(a) {
		return false
	}
	b := a.As4()
	return b[2] == 0 && b[3] == 1
}

// dropHint explains a dropped connection. A Docker bridge gateway as source
// usually means Docker replaced the client's address (userland proxy or
// NAT); allowing that address would allow everybody.
func dropHint(a netip.Addr) string {
	if dockerGateway(a) {
		return "this looks like a Docker bridge gateway: Docker replaced the client's address; " +
			"use network_mode: host instead of allowing this address (see docs/architecture.md, Network access)"
	}
	return "see BELAYPOINT_LAN_ADDRESS / BELAYPOINT_ALLOW_CIDRS"
}

// cloudflareHeaders are set by Cloudflare on requests that came through its
// network (including tunnels).
var cloudflareHeaders = []string{"Cf-Ray", "Cf-Connecting-Ip", "Cf-Ipcountry", "Cf-Visitor"}

// FromCloudflare reports whether a request came through Cloudflare.
func FromCloudflare(r *http.Request) bool {
	for _, h := range cloudflareHeaders {
		if r.Header.Get(h) != "" {
			return true
		}
	}
	for _, v := range r.Header.Values("Cdn-Loop") {
		if strings.Contains(strings.ToLower(v), "cloudflare") {
			return true
		}
	}
	return false
}

// RejectCloudflare is middleware that answers 403 to requests that came
// through Cloudflare and logs them as a misconfiguration.
func RejectCloudflare(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if FromCloudflare(r) {
			log.Error("request through Cloudflare rejected: BelayPoint must not be reachable through the tunnel",
				"remote", r.RemoteAddr, "path", r.URL.Path)
			w.Header().Set("Connection", "close")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
