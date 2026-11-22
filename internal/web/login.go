package web

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"unicode/utf8"

	"github.com/MB512/belaypoint/internal/auth"
	"github.com/MB512/belaypoint/internal/vault"
)

// Admin password length in characters (docs/security.md, rule 6).
const (
	MinPasswordLen = 12
	MaxPasswordLen = 256
)

const sessionCookie = "__Host-belaypoint_session"

// sessionKey is the context key under which requireSession stores the
// current session. A private type makes collisions with other packages'
// keys impossible.
type sessionKey struct{}

type currentSession struct {
	token string
	auth.Session
}

// sessionFrom returns the session stored by requireSession.
func sessionFrom(ctx context.Context) currentSession {
	cs, _ := ctx.Value(sessionKey{}).(currentSession)
	return cs
}

// requireSession lets a request through only with a valid session while
// the vault is unsealed. It stores the session in the request's context
// (comparable to HttpContext.Items in ASP.NET).
func (s *server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.Vault.Initialized() {
			redirect(w, r, "/setup")
			return
		}
		token := cookieToken(r)
		sess, ok := s.Sessions.Lookup(token)
		if ok && s.Vault.Sealed() {
			// Seal drops all sessions; this only guards against a
			// session that survived it by a race.
			s.Sessions.Delete(token)
			ok = false
		}
		if !ok {
			clearCookie(w)
			redirect(w, r, "/login")
			return
		}
		ctx := context.WithValue(r.Context(), sessionKey{}, currentSession{token: token, Session: sess})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// postForm reads the form of a state-changing request behind the login and
// checks its CSRF token (header X-CSRF-Token for HTMX, or the form field
// csrf_token). On failure it has written the response and returns false.
func (s *server) postForm(w http.ResponseWriter, r *http.Request) (form, bool) {
	f, err := readForm(r)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return nil, false
	}
	token := r.Header.Get("X-CSRF-Token")
	if token == "" {
		token = f.get("csrf_token")
	}
	want := sessionFrom(r.Context()).CSRF
	if want == "" || subtle.ConstantTimeCompare([]byte(token), []byte(want)) != 1 {
		f.wipe()
		s.Logger.Warn("CSRF token mismatch", "path", r.URL.Path, "remote", r.RemoteAddr)
		http.Error(w, "invalid or missing CSRF token; reload the page", http.StatusForbidden)
		return nil, false
	}
	return f, true
}

func cookieToken(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

// startSession creates a session and sets its cookie. The __Host- prefix
// makes browsers accept the cookie only with Secure, Path=/ and no Domain.
func (s *server) startSession(w http.ResponseWriter) error {
	token, _, err := s.Sessions.Create()
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// checkPassword validates a new admin password.
func checkPassword(pw, confirm []byte) string {
	if !utf8.Valid(pw) {
		return "The password is not valid UTF-8."
	}
	if n := utf8.RuneCount(pw); n < MinPasswordLen || n > MaxPasswordLen {
		return fmt.Sprintf("The password must have %d to %d characters.", MinPasswordLen, MaxPasswordLen)
	}
	if subtle.ConstantTimeCompare(pw, confirm) != 1 {
		return "The passwords do not match."
	}
	return ""
}

func (s *server) setupPage(w http.ResponseWriter, r *http.Request) {
	if s.Vault.Initialized() {
		redirect(w, r, "/login")
		return
	}
	s.render(w, http.StatusOK, "setup.html", page{Title: "Set up", MinPassword: MinPasswordLen, MaxPassword: MaxPasswordLen})
}

// setup creates the vault on first start. It needs the setup code from the
// container log, so network access to the page alone is not enough.
func (s *server) setup(w http.ResponseWriter, r *http.Request) {
	if s.Vault.Initialized() {
		redirect(w, r, "/login")
		return
	}
	f, err := readForm(r)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	defer f.wipe()
	fail := func(status int, msg string) {
		s.render(w, status, "setup.html", page{Title: "Set up", Error: msg, MinPassword: MinPasswordLen, MaxPassword: MaxPasswordLen})
	}

	wait, ok := s.Limiter.Begin()
	if !ok {
		fail(http.StatusTooManyRequests, lockoutMessage(wait))
		return
	}
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	if !auth.SetupCodeMatches(s.setupCode, f.get("setup_code")) {
		s.Limiter.End(false)
		s.Audit.Audit(r.Context(), "setup failed", "wrong setup code, "+remote(r))
		fail(http.StatusUnauthorized, "The setup code is wrong. It is printed in the container log.")
		return
	}
	if msg := checkPassword(f["password"], f["confirm"]); msg != "" {
		s.Limiter.Abort()
		fail(http.StatusBadRequest, msg)
		return
	}
	if err := s.Vault.Create(f["password"]); err != nil {
		s.Limiter.Abort()
		if errors.Is(err, vault.ErrInitialized) {
			redirect(w, r, "/login")
			return
		}
		s.Logger.Error("creating vault", "err", err)
		fail(http.StatusInternalServerError, "Creating the vault failed; see the container log.")
		return
	}
	s.Limiter.End(true)
	s.setupCode = ""
	s.Audit.Audit(r.Context(), "setup", "vault created, "+remote(r))
	if err := s.startSession(w); err != nil {
		s.Logger.Error("creating session", "err", err)
		redirect(w, r, "/login")
		return
	}
	redirect(w, r, "/")
}

func (s *server) loginPage(w http.ResponseWriter, r *http.Request) {
	if !s.Vault.Initialized() {
		redirect(w, r, "/setup")
		return
	}
	if _, ok := s.Sessions.Lookup(cookieToken(r)); ok && !s.Vault.Sealed() {
		redirect(w, r, "/")
		return
	}
	s.render(w, http.StatusOK, "login.html", page{Title: "Log in", Sealed: s.Vault.Sealed()})
}

// login checks the password by unsealing the vault (also when it is
// already unsealed, e.g. a login from a second browser).
func (s *server) login(w http.ResponseWriter, r *http.Request) {
	if !s.Vault.Initialized() {
		redirect(w, r, "/setup")
		return
	}
	f, err := readForm(r)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	defer f.wipe()
	wasSealed := s.Vault.Sealed()
	fail := func(status int, msg string) {
		s.render(w, status, "login.html", page{Title: "Log in", Sealed: wasSealed, Error: msg})
	}

	wait, ok := s.Limiter.Begin()
	if !ok {
		fail(http.StatusTooManyRequests, lockoutMessage(wait))
		return
	}
	err = s.Vault.Unseal(f["password"])
	if errors.Is(err, vault.ErrWrongPassword) {
		lock := s.Limiter.End(false)
		details := fmt.Sprintf("%d failed since last login, %s", s.Limiter.Failures(), remote(r))
		s.Audit.Audit(r.Context(), "login failed", details)
		msg := "Wrong password."
		if lock > 0 {
			msg += " " + lockoutMessage(lock)
		}
		fail(http.StatusUnauthorized, msg)
		return
	}
	if err != nil {
		s.Limiter.Abort()
		s.Logger.Error("unsealing vault", "err", err)
		fail(http.StatusInternalServerError, "Login failed; see the container log.")
		return
	}
	s.Limiter.End(true)
	s.Audit.Audit(r.Context(), "login", remote(r))
	if wasSealed {
		s.Audit.Audit(r.Context(), "unseal", remote(r))
	}
	if err := s.startSession(w); err != nil {
		s.Logger.Error("creating session", "err", err)
		fail(http.StatusInternalServerError, "Login failed; see the container log.")
		return
	}
	redirect(w, r, "/")
}

// logout ends this session only; the vault stays unsealed, so scheduled
// jobs keep running.
func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	f, ok := s.postForm(w, r)
	if !ok {
		return
	}
	f.wipe()
	s.Sessions.Delete(sessionFrom(r.Context()).token)
	clearCookie(w)
	s.Audit.Audit(r.Context(), "logout", remote(r))
	redirect(w, r, "/login")
}

// seal zeroes the vault key and ends all sessions.
func (s *server) seal(w http.ResponseWriter, r *http.Request) {
	f, ok := s.postForm(w, r)
	if !ok {
		return
	}
	f.wipe()
	s.Vault.Seal()
	s.Sessions.DeleteAll()
	clearCookie(w)
	s.Audit.Audit(r.Context(), "seal", remote(r))
	redirect(w, r, "/login")
}
