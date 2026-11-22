package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// post sends a form. cookie may be empty.
func post(h http.Handler, path, cookie string, values url.Values, header map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "192.168.1.20:50000"
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	}
	for k, v := range header {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func getWithCookie(h http.Handler, path, cookie string) *httptest.ResponseRecorder {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: cookie})
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// sessionFromResponse returns the session cookie set by w ("" if none).
func sessionFromResponse(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookie && c.MaxAge >= 0 {
			if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
				t.Errorf("cookie attributes: %+v", c)
			}
			return c.Value
		}
	}
	return ""
}

var csrfRe = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

func csrfFromPage(t *testing.T, h http.Handler, cookie string) string {
	t.Helper()
	w := getWithCookie(h, "/", cookie)
	m := csrfRe.FindStringSubmatch(w.Body.String())
	if w.Code != http.StatusOK || m == nil {
		t.Fatalf("GET / = %d, no CSRF token:\n%s", w.Code, w.Body.String())
	}
	return m[1]
}

func wantRedirect(t *testing.T, w *httptest.ResponseRecorder, to string) {
	t.Helper()
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != to {
		t.Fatalf("got %d Location %q, want 303 to %s\n%s", w.Code, w.Header().Get("Location"), to, w.Body.String())
	}
}

func TestSetup(t *testing.T) {
	const pw = "correct horse battery"
	tests := []struct {
		name       string
		code       string
		password   string
		confirm    string
		wantStatus int
		wantText   string
	}{
		{"wrong code", "AAAA-AAAA-AAAA-AAAA", pw, pw, http.StatusUnauthorized, "setup code is wrong"},
		{"missing code", "", pw, pw, http.StatusUnauthorized, "setup code is wrong"},
		{"too short", testSetupCode, "short", "short", http.StatusBadRequest, "12 to 256"},
		{"too long", testSetupCode, strings.Repeat("x", 257), strings.Repeat("x", 257), http.StatusBadRequest, "12 to 256"},
		{"mismatch", testSetupCode, pw, pw + "!", http.StatusBadRequest, "do not match"},
		{"invalid UTF-8", testSetupCode, "\xff" + pw, "\xff" + pw, http.StatusBadRequest, "UTF-8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(nil, false)
			w := post(e.h, "/setup", "", url.Values{"setup_code": {tt.code}, "password": {tt.password}, "confirm": {tt.confirm}}, nil)
			if w.Code != tt.wantStatus || !strings.Contains(w.Body.String(), tt.wantText) {
				t.Errorf("got %d, want %d with %q:\n%s", w.Code, tt.wantStatus, tt.wantText, w.Body.String())
			}
			if e.vault.Initialized() {
				t.Error("vault created")
			}
		})
	}

	t.Run("only a wrong code counts as failed attempt", func(t *testing.T) {
		e := newEnv(nil, false)
		post(e.h, "/setup", "", url.Values{"setup_code": {testSetupCode}, "password": {"short"}, "confirm": {"short"}}, nil)
		post(e.h, "/setup", "", url.Values{"setup_code": {"wrong"}, "password": {pw}, "confirm": {pw}}, nil)
		if got := e.limiter.Failures(); got != 1 {
			t.Errorf("failures = %d, want 1", got)
		}
	})

	t.Run("success", func(t *testing.T) {
		e := newEnv(nil, false)
		wantRedirect(t, getWithCookie(e.h, "/", ""), "/setup")
		wantRedirect(t, getWithCookie(e.h, "/login", ""), "/setup")
		if w := getWithCookie(e.h, "/setup", ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `name="setup_code"`) {
			t.Fatalf("setup page: %d", w.Code)
		}
		code := strings.ToLower(strings.ReplaceAll(testSetupCode, "-", " "))
		w := post(e.h, "/setup", "", url.Values{"setup_code": {code}, "password": {pw}, "confirm": {pw}}, nil)
		wantRedirect(t, w, "/")
		cookie := sessionFromResponse(t, w)
		if cookie == "" {
			t.Fatal("no session after setup")
		}
		if string(e.vault.password) != pw || e.vault.Sealed() {
			t.Errorf("vault: password %q sealed %v", e.vault.password, e.vault.Sealed())
		}
		if !e.audit.has("setup") {
			t.Error("setup not audited")
		}
		csrfFromPage(t, e.h, cookie) // logged in
		wantRedirect(t, getWithCookie(e.h, "/setup", ""), "/login")
		// The code is used up even for a second, racing setup request.
		w = post(e.h, "/setup", "", url.Values{"setup_code": {testSetupCode}, "password": {"another password"}, "confirm": {"another password"}}, nil)
		wantRedirect(t, w, "/login")
		if string(e.vault.password) != pw {
			t.Error("second setup changed the password")
		}
	})
}

func TestLoginLogoutSeal(t *testing.T) {
	e := newEnv(nil, true)
	wantRedirect(t, getWithCookie(e.h, "/", ""), "/login")
	wantRedirect(t, getWithCookie(e.h, "/", "forged"), "/login")
	if w := getWithCookie(e.h, "/login", ""); !strings.Contains(w.Body.String(), "sealed") {
		t.Errorf("login page does not say sealed:\n%s", w.Body.String())
	}

	w := post(e.h, "/login", "", url.Values{"password": {"wrong password"}}, nil)
	if w.Code != http.StatusUnauthorized || sessionFromResponse(t, w) != "" || !e.vault.Sealed() {
		t.Fatalf("wrong password: %d, sealed %v", w.Code, e.vault.Sealed())
	}
	if !e.audit.has("login failed") {
		t.Error("failed login not audited")
	}

	login := func() string {
		t.Helper()
		w := post(e.h, "/login", "", url.Values{"password": {"correct horse battery"}}, nil)
		wantRedirect(t, w, "/")
		c := sessionFromResponse(t, w)
		if c == "" {
			t.Fatal("no session cookie")
		}
		return c
	}
	first := login()
	if e.vault.Sealed() || !e.audit.has("unseal") || e.limiter.Failures() != 0 {
		t.Errorf("after login: sealed %v, unseal audited %v, failures %d", e.vault.Sealed(), e.audit.has("unseal"), e.limiter.Failures())
	}
	wantRedirect(t, getWithCookie(e.h, "/login", first), "/")
	second := login()
	csrf := csrfFromPage(t, e.h, first)

	// Logout: needs the session's own CSRF token.
	for name, token := range map[string]string{"missing": "", "wrong": "x", "other session's": csrfFromPage(t, e.h, second)} {
		if w := post(e.h, "/logout", first, url.Values{"csrf_token": {token}}, nil); w.Code != http.StatusForbidden {
			t.Errorf("logout with %s CSRF token: %d", name, w.Code)
		}
	}
	wantRedirect(t, post(e.h, "/logout", first, url.Values{"csrf_token": {csrf}}, nil), "/login")
	wantRedirect(t, getWithCookie(e.h, "/", first), "/login")
	if e.vault.Sealed() {
		t.Error("logout sealed the vault")
	}
	csrfFromPage(t, e.h, second) // other session still valid
	if !e.audit.has("logout") {
		t.Error("logout not audited")
	}

	// Seal: header token (HTMX), ends all sessions.
	third := login()
	w = post(e.h, "/seal", second, nil, map[string]string{"X-CSRF-Token": csrfFromPage(t, e.h, second), "HX-Request": "true"})
	if w.Header().Get("HX-Redirect") != "/login" {
		t.Errorf("seal via HTMX: %d HX-Redirect %q", w.Code, w.Header().Get("HX-Redirect"))
	}
	if !e.vault.Sealed() || !e.audit.has("seal") {
		t.Errorf("after seal: sealed %v audited %v", e.vault.Sealed(), e.audit.has("seal"))
	}
	for _, c := range []string{second, third} {
		wantRedirect(t, getWithCookie(e.h, "/", c), "/login")
	}
}

func TestLoginLockout(t *testing.T) {
	e := newEnv(nil, true)
	for i := range 6 {
		w := post(e.h, "/login", "", url.Values{"password": {"wrong password"}}, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i+1, w.Code)
		}
	}
	calls := len(e.vault.seen)
	w := post(e.h, "/login", "", url.Values{"password": {"correct horse battery"}}, nil)
	if w.Code != http.StatusTooManyRequests || !strings.Contains(w.Body.String(), "Try again in") {
		t.Errorf("during lockout: %d\n%s", w.Code, w.Body.String())
	}
	if len(e.vault.seen) != calls || !e.vault.Sealed() {
		t.Error("password checked during lockout")
	}
}

func TestPasswordsZeroed(t *testing.T) {
	e := newEnv(nil, false)
	pw := "correct horse battery"
	post(e.h, "/setup", "", url.Values{"setup_code": {testSetupCode}, "password": {pw}, "confirm": {pw}}, nil)
	e.vault.Seal()
	post(e.h, "/login", "", url.Values{"password": {"wrong password"}}, nil)
	post(e.h, "/login", "", url.Values{"password": {pw}}, nil)
	if len(e.vault.seen) != 3 {
		t.Fatalf("vault saw %d passwords, want 3", len(e.vault.seen))
	}
	for i, b := range e.vault.seen {
		if strings.Trim(string(b), "\x00") != "" {
			t.Errorf("password %d not zeroed after the request: %q", i, b)
		}
	}
}

func TestCrossOriginPostRejected(t *testing.T) {
	e := newEnv(nil, true)
	w := post(e.h, "/login", "", url.Values{"password": {"correct horse battery"}}, map[string]string{"Sec-Fetch-Site": "cross-site"})
	if w.Code != http.StatusForbidden || !e.vault.Sealed() {
		t.Errorf("cross-site login: %d, sealed %v", w.Code, e.vault.Sealed())
	}
}

func TestBadFormRejected(t *testing.T) {
	e := newEnv(nil, true)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/login", strings.NewReader(`{"password":"x"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest || len(e.vault.seen) != 0 {
		t.Errorf("JSON body: %d, vault calls %d", w.Code, len(e.vault.seen))
	}
}
