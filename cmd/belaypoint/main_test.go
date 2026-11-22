package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MB512/belaypoint/internal/config"
)

// TestServeEndToEnd starts the server on a random loopback port, checks
// that it speaks TLS with a certificate from the generated CA, that the
// health check passes, and that it shuts down on cancel.
func TestServeEndToEnd(t *testing.T) {
	cfgDir, reposDir := t.TempDir(), t.TempDir()
	envs := map[string]string{
		config.EnvListen:     "127.0.0.1:0",
		config.EnvConfigDir:  cfgDir,
		config.EnvReposDir:   reposDir,
		config.EnvHostnames:  "localhost",
		config.EnvLANAddress: "192.168.1.10/24",
	}
	getenv := func(k string) string { return envs[k] }

	ctx, cancel := context.WithCancel(context.Background())
	addrc := make(chan string, 1)
	done := make(chan int, 1)
	var logBuf syncBuffer
	go func() { done <- serve(ctx, getenv, &logBuf, func(a string) { addrc <- a }) }()

	var addr string
	select {
	case addr = <-addrc:
	case code := <-done:
		t.Fatalf("serve exited with %d:\n%s", code, logBuf.String())
	case <-time.After(10 * time.Second):
		t.Fatal("server did not start")
	}

	caPEM, err := os.ReadFile(filepath.Join(cfgDir, "tls", "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12},
	}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+addr+"/healthz", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /healthz with CA trust: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok\n" {
		t.Errorf("healthz: %d %q", resp.StatusCode, body)
	}

	_, port, _ := net.SplitHostPort(addr)
	envs[config.EnvListen] = ":" + port
	var hcErr bytes.Buffer
	if code := healthcheck(ctx, getenv, &hcErr); code != 0 {
		t.Errorf("healthcheck = %d: %s", code, hcErr.String())
	}

	if !strings.Contains(logBuf.String(), "sha256=") {
		t.Errorf("fingerprints not logged:\n%s", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "setup_code=") {
		t.Errorf("vault state not logged:\n%s", logBuf.String())
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit code %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestServeDamagedVault(t *testing.T) {
	cfgDir := t.TempDir()
	vaultPath := filepath.Join(cfgDir, "vault.json")
	if err := os.WriteFile(vaultPath, []byte("{damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	envs := map[string]string{
		config.EnvListen:    "127.0.0.1:0",
		config.EnvConfigDir: cfgDir,
		config.EnvReposDir:  t.TempDir(),
	}
	var stderr syncBuffer
	code := serve(context.Background(), func(k string) string { return envs[k] }, &stderr, func(string) {
		t.Error("server started with a damaged vault")
	})
	if code != 1 || !strings.Contains(stderr.String(), "vault") {
		t.Errorf("code %d, log:\n%s", code, stderr.String())
	}
	if data, _ := os.ReadFile(vaultPath); string(data) != "{damaged" {
		t.Errorf("damaged vault was overwritten: %q", data)
	}
}

func TestServeConfigError(t *testing.T) {
	var stderr bytes.Buffer
	code := serve(context.Background(), func(k string) string {
		if k == config.EnvLANAddress {
			return "not-an-address"
		}
		return ""
	}, &stderr, nil)
	if code != 2 || !strings.Contains(stderr.String(), config.EnvLANAddress) {
		t.Errorf("code %d, stderr %q", code, stderr.String())
	}
}

func TestCertCmdUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := certCmd([]string{"renew"}, func(string) string { return "" }, &out, &errb); code != 2 {
		t.Errorf("code %d", code)
	}
}

// syncBuffer is a bytes.Buffer safe for the server goroutine writing logs
// while the test reads them.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
