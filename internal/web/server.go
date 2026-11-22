// Package web contains the HTTP handlers: health check, CA download,
// first-start setup, login (= unseal), logout and seal, and the pages
// behind the login.
package web

import (
	"context"
	"embed"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MB512/belaypoint/internal/auth"
	"github.com/MB512/belaypoint/internal/netguard"
	"github.com/MB512/belaypoint/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

var templates = template.Must(template.New("").Funcs(template.FuncMap{
	"active": func(title, want string) string {
		if title == want {
			return "page"
		}
		return ""
	},
}).ParseFS(templateFS, "templates/*.html"))

// Vault is the part of *vault.Vault the handlers use. (Go interfaces are
// satisfied implicitly: *vault.Vault needs no "implements" declaration,
// and tests pass a fake.)
type Vault interface {
	Initialized() bool
	Sealed() bool
	Create(password []byte) error
	Unseal(password []byte) error
	Seal()
}

// Auditor records security-relevant events (docs/security.md, rule 12).
// details must not contain secrets.
type Auditor interface {
	Audit(ctx context.Context, event, details string)
}

// AuditLog reads the audit log (implemented by *store.Store).
type AuditLog interface {
	ListAudit(ctx context.Context, limit int, before int64) ([]store.AuditEntry, error)
}

// Options configure the handler.
type Options struct {
	Version string
	// CAPEM is the local CA certificate offered at /ca.crt; nil (custom
	// certificate) disables the download.
	CAPEM []byte
	// CAFingerprint is shown next to the download link.
	CAFingerprint string
	Logger        *slog.Logger

	Vault    Vault
	Sessions *auth.Sessions
	Limiter  *auth.Limiter
	Audit    Auditor
	AuditLog AuditLog
	// Location is the time zone for times shown in the UI (TZ).
	Location *time.Location
	// SetupCode must be entered to create the vault on first start (see
	// auth.NewSetupCode). Empty when the vault already exists.
	SetupCode string
}

type server struct {
	Options

	setupMu   sync.Mutex
	setupCode string // cleared once the vault is created
}

// New returns the root handler.
func New(opts Options) http.Handler {
	s := &server{Options: opts, setupCode: opts.SetupCode}

	r := chi.NewRouter()
	r.Use(securityHeaders)
	r.Use(func(next http.Handler) http.Handler { return netguard.RejectCloudflare(opts.Logger, next) })

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	r.Get("/ca.crt", s.caCert)
	static, _ := fs.Sub(staticFS, "static")
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServerFS(static)))

	r.Get("/setup", s.setupPage)
	r.Post("/setup", s.setup)
	r.Get("/login", s.loginPage)
	r.Post("/login", s.login)

	// Everything in this group needs a session; s.requireSession
	// redirects to /setup or /login otherwise.
	r.Group(func(r chi.Router) {
		r.Use(s.requireSession)
		r.Get("/", s.home)
		r.Get("/audit", s.auditPage)
		r.Post("/logout", s.logout)
		r.Post("/seal", s.seal)
	})

	// CrossOriginProtection rejects state-changing requests that a browser
	// marks as cross-site (Sec-Fetch-Site / Origin). The per-session CSRF
	// token is the second layer (docs/security.md, rule 8).
	return http.NewCrossOriginProtection().Handler(r)
}

func (s *server) caCert(w http.ResponseWriter, r *http.Request) {
	if s.CAPEM == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="belaypoint-ca.crt"`)
	_, _ = w.Write(s.CAPEM)
}

// page is the data of every template.
type page struct {
	Title         string
	Version       string
	HasCA         bool
	CAFingerprint string
	// CSRF is set on pages behind the login; forms put it in a hidden
	// field.
	CSRF  string
	Error string

	// login page
	Sealed bool
	// setup page
	MinPassword, MaxPassword int
	// audit page
	Audit      []auditRow
	NextBefore int64
}

func (s *server) render(w http.ResponseWriter, status int, name string, p page) {
	p.Version = s.Version
	p.HasCA = s.CAPEM != nil
	p.CAFingerprint = s.CAFingerprint
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := templates.ExecuteTemplate(w, name, p); err != nil {
		s.Logger.Error("rendering page", "page", name, "err", err)
	}
}

// redirect sends the browser to path. HTMX requests get HX-Redirect, since
// HTMX would otherwise follow a 303 itself and swap the target page into
// the current one.
func redirect(w http.ResponseWriter, r *http.Request, path string) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", path)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

// remote is the client's TCP address for audit entries. Forwarding headers
// are never used (no reverse proxy support).
func remote(r *http.Request) string { return "from " + r.RemoteAddr }

// lockoutMessage tells the user how long the login stays locked.
func lockoutMessage(wait time.Duration) string {
	if wait <= 0 {
		return "Another login attempt is in progress. Try again in a moment."
	}
	return "Too many failed attempts. Try again in " + wait.Round(time.Second).String() + "."
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
