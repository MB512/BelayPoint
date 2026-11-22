// Package web contains the HTTP handlers. For now it serves the health
// check, the CA download and a placeholder start page.
package web

import (
	"embed"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MB512/belaypoint/internal/netguard"
)

//go:embed templates/*.html
var templateFS embed.FS

var templates = template.Must(template.ParseFS(templateFS, "templates/*.html"))

// Options configure the handler.
type Options struct {
	Version string
	// CAPEM is the local CA certificate offered at /ca.crt; nil (custom
	// certificate) disables the download.
	CAPEM []byte
	// CAFingerprint is shown next to the download link.
	CAFingerprint string
	Logger        *slog.Logger
}

// New returns the root handler.
func New(opts Options) http.Handler {
	r := chi.NewRouter()
	r.Use(securityHeaders)
	r.Use(func(next http.Handler) http.Handler { return netguard.RejectCloudflare(opts.Logger, next) })

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})

	r.Get("/ca.crt", func(w http.ResponseWriter, req *http.Request) {
		if opts.CAPEM == nil {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", `attachment; filename="belaypoint-ca.crt"`)
		_, _ = w.Write(opts.CAPEM)
	})

	r.Get("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		data := map[string]any{
			"Version":       opts.Version,
			"HasCA":         opts.CAPEM != nil,
			"CAFingerprint": opts.CAFingerprint,
		}
		if err := templates.ExecuteTemplate(w, "index.html", data); err != nil {
			opts.Logger.Error("rendering page", "err", err)
		}
	})
	return r
}

// securityHeaders sets headers for every response. There is deliberately no
// Strict-Transport-Security: with a self-signed certificate, HSTS would make
// Firefox refuse the "accept the risk" exception for that host name.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
