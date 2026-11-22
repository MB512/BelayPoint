package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func handler(caPEM []byte) http.Handler {
	return New(Options{
		Version:       "test",
		CAPEM:         caPEM,
		CAFingerprint: "AB:CD",
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func get(h http.Handler, path string, header map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range header {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestHealthz(t *testing.T) {
	w := get(handler(nil), "/healthz", nil)
	if w.Code != http.StatusOK || w.Body.String() != "ok\n" {
		t.Errorf("got %d %q", w.Code, w.Body.String())
	}
}

func TestCADownload(t *testing.T) {
	pem := []byte("-----BEGIN CERTIFICATE-----\n")
	w := get(handler(pem), "/ca.crt", nil)
	if w.Code != http.StatusOK || w.Body.String() != string(pem) {
		t.Errorf("got %d %q", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-x509-ca-cert" {
		t.Errorf("Content-Type %q", ct)
	}
	if w := get(handler(nil), "/ca.crt", nil); w.Code != http.StatusNotFound {
		t.Errorf("without CA: %d", w.Code)
	}
}

func TestIndexShowsFingerprint(t *testing.T) {
	w := get(handler([]byte("x")), "/", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "AB:CD") {
		t.Errorf("got %d %q", w.Code, w.Body.String())
	}
}

func TestSecurityHeaders(t *testing.T) {
	w := get(handler(nil), "/", nil)
	for _, h := range []string{"Content-Security-Policy", "Cache-Control", "X-Content-Type-Options", "X-Frame-Options"} {
		if w.Header().Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
	if w.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS must not be set (breaks certificate exceptions)")
	}
}

func TestCloudflareRejected(t *testing.T) {
	w := get(handler(nil), "/healthz", map[string]string{"Cf-Ray": "abc"})
	if w.Code != http.StatusForbidden {
		t.Errorf("got %d", w.Code)
	}
}
