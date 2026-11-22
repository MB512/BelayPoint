// Command belaypoint runs the BelayPoint web app.
//
//	belaypoint                 start the server (same as "serve")
//	belaypoint healthcheck     used by the image's HEALTHCHECK
//	belaypoint cert reset      delete the server certificate (new one on next start)
//	belaypoint cert reset --ca also replace the local CA
//	belaypoint version
//
// Configuration is read from the environment (see internal/config).
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // embeds the time zone database: TZ works without /usr/share/zoneinfo

	"github.com/MB512/belaypoint/internal/buildinfo"
	"github.com/MB512/belaypoint/internal/config"
	"github.com/MB512/belaypoint/internal/netguard"
	"github.com/MB512/belaypoint/internal/tlscert"
	"github.com/MB512/belaypoint/internal/vault"
	"github.com/MB512/belaypoint/internal/web"
)

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "serve":
		// NotifyContext cancels ctx on SIGINT/SIGTERM, like a
		// CancellationToken wired to Console.CancelKeyPress in C#.
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		code := serve(ctx, os.Getenv, os.Stderr, nil)
		stop()
		os.Exit(code)
	case "healthcheck":
		os.Exit(healthcheck(context.Background(), os.Getenv, os.Stderr))
	case "cert":
		os.Exit(certCmd(args, os.Getenv, os.Stdout, os.Stderr))
	case "version":
		fmt.Println(buildinfo.Version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q (serve, healthcheck, cert reset [--ca], version)\n", cmd)
		os.Exit(2)
	}
}

// shutdownTimeout bounds how long in-flight requests may take after
// SIGTERM. Docker's default stop timeout is 10s.
const shutdownTimeout = 8 * time.Second

// serve runs the server until ctx is cancelled. ready, if not nil, is called
// with the listen address once connections are accepted (used by tests).
func serve(ctx context.Context, getenv func(string) string, stderr io.Writer, ready func(addr string)) int {
	cfg, err := config.Load(getenv)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error:\n%v\n", err)
		return 2
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
	logger.Info("starting BelayPoint", "version", buildinfo.Version)
	checkOwner(logger, cfg.ReposDir)

	// The vault is opened (not unsealed) at startup, so a damaged file
	// stops the start instead of being replaced by a new, empty vault.
	vlt, err := vault.Open(filepath.Join(cfg.ConfigDir, "vault.json"))
	if err != nil {
		logger.Error("vault", "err", err)
		return 1
	}
	if vlt.Initialized() {
		logger.Info("vault: sealed, log in to unseal", "secrets", len(vlt.Names()))
	} else {
		logger.Info("vault: not initialized, set the admin password in the web UI")
	}

	var ips []netip.Addr
	if cfg.HasLANAddress() {
		ips = append(ips, cfg.LANAddress.Addr())
	}
	cert, err := tlscert.Ensure(tlscert.Options{Dir: filepath.Join(cfg.ConfigDir, "tls"), IPs: ips, DNSNames: cfg.Hostnames})
	if err != nil {
		logger.Error("TLS certificate", "err", err)
		return 1
	}
	logCert(logger, cert)

	policy := netguard.NewPolicy(cfg.LANAddress, cfg.AllowCIDRs)
	mode := "default (private networks)"
	if cfg.HasLANAddress() {
		mode = "strict (" + config.EnvLANAddress + ")"
	}
	logger.Info("network access", "mode", mode, "allowed", fmt.Sprint(policy.Networks()))

	tcp, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.Listen)
	if err != nil {
		logger.Error("listen", "addr", cfg.Listen, "err", err)
		return 1
	}
	guarded := &netguard.Listener{
		Listener: tcp,
		Policy:   policy,
		OnReject: netguard.RejectLogger(logger, 10*time.Minute),
	}

	srv := &http.Server{
		Handler: web.New(web.Options{
			Version:       buildinfo.Version,
			CAPEM:         cert.CAPEM,
			CAFingerprint: cert.CAFingerprint,
			Logger:        logger,
		}),
		TLSConfig:         tlsConfig(cert),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Minute,
		IdleTimeout:       2 * time.Minute,
		// TLS handshake errors (e.g. a browser that does not trust the
		// certificate yet) are normal here; keep them out of the default log.
		ErrorLog: log.New(debugWriter{logger}, "", 0),
	}

	errc := make(chan error, 1)
	go func() {
		// ServeTLS wraps the guarded listener, so rejected clients never
		// reach the TLS handshake.
		errc <- srv.ServeTLS(guarded, "", "")
	}()
	logger.Info("listening", "addr", tcp.Addr().String())
	if ready != nil {
		ready(tcp.Addr().String())
	}

	select {
	case err := <-errc:
		logger.Error("server stopped", "err", err)
		return 1
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("shutdown", "err", err)
	}
	logger.Info("stopped")
	return 0
}

func logCert(logger *slog.Logger, cert tlscert.Result) {
	if cert.Custom {
		logger.Info("TLS: using custom certificate", "sha256", cert.ServerFingerprint)
		return
	}
	if cert.Warning != "" {
		logger.Warn("TLS: " + cert.Warning)
	}
	if cert.CACreated {
		logger.Info("TLS: created a new local CA")
	}
	if cert.Reissued {
		attrs := []any{"reason", cert.Reason}
		if cert.OldFingerprint != "" {
			attrs = append(attrs, "old_sha256", cert.OldFingerprint)
		}
		logger.Info("TLS: issued a new server certificate", attrs...)
	}
	logger.Info("TLS: CA certificate (compare before importing it into the browser)", "sha256", cert.CAFingerprint)
	logger.Info("TLS: server certificate", "sha256", cert.ServerFingerprint)
}

func tlsConfig(cert tlscert.Result) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert.Certificate},
		MinVersion:   tls.VersionTLS12,
	}
}

// checkOwner warns if the process does not run as the owner of the
// repository root: files written by prune must stay usable for the
// rest-server (see "Container" in docs/architecture.md).
func checkOwner(logger *slog.Logger, dir string) {
	st, err := os.Stat(dir)
	if err != nil {
		logger.Warn("repository directory not accessible", "dir", dir, "err", err)
		return
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	uid, gid := os.Getuid(), os.Getgid()
	if uid == 0 {
		logger.Warn("running as root: set the container user to the owner of the repository files", "owner", fmt.Sprintf("%d:%d", sys.Uid, sys.Gid))
		return
	}
	if uint32(uid) != sys.Uid || uint32(gid) != sys.Gid { //nolint:gosec // uid/gid are small non-negative ids
		logger.Warn("container user differs from the owner of the repository directory; files written by prune may become unusable for the rest-server",
			"user", fmt.Sprintf("%d:%d", uid, gid), "owner", fmt.Sprintf("%d:%d", sys.Uid, sys.Gid), "dir", dir)
	}
}

// debugWriter sends the http.Server's internal log lines to slog at debug
// level.
type debugWriter struct{ l *slog.Logger }

func (d debugWriter) Write(p []byte) (int, error) {
	d.l.Debug("http: " + string(trimNewline(p)))
	return len(p), nil
}

func trimNewline(p []byte) []byte {
	for len(p) > 0 && (p[len(p)-1] == '\n' || p[len(p)-1] == '\r') {
		p = p[:len(p)-1]
	}
	return p
}

// healthcheck calls /healthz over loopback. Loopback is always allowed by
// netguard.
func healthcheck(ctx context.Context, getenv func(string) string, stderr io.Writer) int {
	cfg, err := config.Load(getenv)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return 1
	}
	_, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		fmt.Fprintf(stderr, "listen address %q: %v\n", cfg.Listen, err)
		return 1
	}
	client := &http.Client{
		Timeout: 4 * time.Second,
		Transport: &http.Transport{
			// Liveness check of our own process over loopback: the
			// certificate is not issued for 127.0.0.1 (and may be custom),
			// so it is not verified here.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // loopback liveness check
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+net.JoinHostPort("127.0.0.1", port)+"/healthz", nil)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "status %d\n", resp.StatusCode)
		return 1
	}
	return 0
}

// certCmd implements "cert reset [--ca]".
func certCmd(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	var withCA bool
	switch strings.Join(args, " ") {
	case "reset":
	case "reset --ca":
		withCA = true
	default:
		fmt.Fprintln(stderr, "usage: belaypoint cert reset [--ca]")
		return 2
	}
	cfg, err := config.Load(getenv)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return 1
	}
	if err := tlscert.Reset(filepath.Join(cfg.ConfigDir, "tls"), withCA); err != nil {
		fmt.Fprintf(stderr, "%v\n", err)
		return 1
	}
	what := "server certificate"
	if withCA {
		what = "server certificate and CA"
	}
	fmt.Fprintf(stdout, "%s deleted; restart the container to generate new ones\n", what)
	return 0
}
