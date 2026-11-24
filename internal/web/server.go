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
	"add": func(a, b int) int { return a + b },
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
	Has(name string) bool
	SetSecret(name string, value []byte) error
	DeleteSecret(name string) error
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

// RepoList lists the known repositories (implemented by *store.Store).
type RepoList interface {
	ListRepos(ctx context.Context) ([]store.Repo, error)
}

// Scanner runs repository discovery and disk usage in the background.
type Scanner interface {
	// Rescan starts a scan; false if one is already running.
	Rescan() bool
	Scanning() bool
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
	Repos    RepoList
	Users    Users
	Scanner  Scanner
	// Restic checks repository passwords; Jobs runs restic jobs. Both are
	// nil when restic is missing.
	Restic  Restic
	Jobs    Jobs
	JobList JobList
	// Policies stores the retention policies, Plans the maintenance plans;
	// Schedule is the running scheduler (nil without restic).
	Policies Policies
	Plans    Plans
	// Archives stores the archive flag of the repositories.
	Archives Archives
	Schedule Schedule
	// JobLogDir holds the job logs (<id>.log).
	JobLogDir string
	// ReposDir is the repository root (BELAYPOINT_REPOS_DIR).
	ReposDir string
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
		r.Post("/repos/rescan", s.rescan)
		r.Get("/repos/password", s.repoPasswordPage)
		r.Post("/repos/password", s.setRepoPassword)
		r.Post("/repos/password/remove", s.forgetRepoPassword)
		r.Post("/repos/snapshots", s.refreshSnapshots)
		r.Get("/repos/view", s.repoPage)
		r.Post("/repos/policy", s.setPolicy)
		r.Post("/repos/archive", s.setArchived)
		r.Post("/repos/plan", s.setPlan)
		r.Post("/repos/forget-preview", s.previewForget)
		r.Get("/repos/maintenance", s.maintenancePage)
		r.Post("/repos/maintenance", s.startMaintenance)
		r.Post("/repos/unlock", s.unlock)
		r.Get("/repos/unlock-all", s.unlockAllPage)
		r.Post("/repos/unlock-all", s.unlockAll)
		r.Get("/jobs", s.jobsPage)
		r.Get("/jobs/{id}/log", s.jobLog)
		r.Get("/users", s.usersPage)
		r.Post("/users/add", s.addUser)
		r.Get("/users/reset", s.confirmUser("reset"))
		r.Post("/users/reset", s.resetUser)
		r.Get("/users/remove", s.confirmUser("remove"))
		r.Post("/users/remove", s.removeUser)
		r.Get("/storage", s.storagePage)
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
	Title   string
	Version string
	// Refresh > 0 reloads the page after that many seconds.
	Refresh       int
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
	// overview
	Repos    []repoRow
	Overview *overviewData
	Total    ownerRow
	Scanning bool
	// users pages
	Users *usersData
	// repository password page
	RepoPassword *repoPasswordData
	// Disk is the volume of the repository root, shown on every page
	// behind the login.
	Disk *diskData
	// jobs page; JobsAvailable is false without restic
	Jobs          []jobRow
	JobsAvailable bool
	Log           *logData
	// repository page
	Repo        *repoData
	Maintenance *maintenanceData
	// storage page
	Storage *storageData
}

func (s *server) render(w http.ResponseWriter, status int, name string, p page) {
	p.Version = s.Version
	p.HasCA = s.CAPEM != nil
	p.CAFingerprint = s.CAFingerprint
	if p.CSRF != "" && p.Disk == nil {
		p.Disk = s.disk()
	}
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
