package web

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func htpasswdContent(t *testing.T, e *testEnv) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.reposDir, ".htpasswd"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

var passwordRe = regexp.MustCompile(`<code class="secret">([^<]+)</code>`)

func TestUsers(t *testing.T) {
	e := newEnv(t, nil, true)
	ctx := context.Background()
	makeRepo(t, e.reposDir, "alice/main")
	makeRepo(t, e.reposDir, "ghost/old")
	_ = e.store.SyncRepos(ctx, []string{"alice/main", "ghost/old"})
	cookie := login(t, e)
	csrf := csrfFromPage(t, e.h, cookie)
	form := func(v url.Values) url.Values { v.Set("csrf_token", csrf); return v }

	wantRedirect(t, getWithCookie(e.h, "/users", ""), "/login")
	if w := post(e.h, "/users/add", cookie, url.Values{"name": {"alice"}}, nil); w.Code != http.StatusForbidden {
		t.Errorf("add without CSRF: %d", w.Code)
	}

	// Generated password: shown once, matches the stored hash.
	w := post(e.h, "/users/add", cookie, form(url.Values{"name": {"alice"}, "password": {""}}), nil)
	m := passwordRe.FindStringSubmatch(w.Body.String())
	if w.Code != http.StatusOK || m == nil {
		t.Fatalf("add alice: %d\n%s", w.Code, w.Body.String())
	}
	_, hash, _ := strings.Cut(strings.TrimSpace(htpasswdContent(t, e)), ":")
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(m[1])) != nil {
		t.Error("shown password does not match the stored hash")
	}
	if !e.audit.has("user added") {
		t.Error("not audited")
	}

	// Entered password: no password page.
	wantRedirect(t, post(e.h, "/users/add", cookie, form(url.Values{"name": {"bob"}, "password": {"bobs long password"}}), nil), "/users")
	for name, v := range map[string]url.Values{
		"duplicate":      {"name": {"bob"}},
		"invalid name":   {"name": {"Bob Smith"}},
		"short password": {"name": {"carol"}, "password": {"short"}},
	} {
		if w := post(e.h, "/users/add", cookie, form(v), nil); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, w.Code)
		}
	}

	body := getWithCookie(e.h, "/users", cookie).Body.String()
	for _, want := range []string{"alice", "bob", "alice/main", "ghost/old", "without a user"} {
		if !strings.Contains(body, want) {
			t.Errorf("users page lacks %q", want)
		}
	}

	// Reset: confirmation page, then POST with confirm=yes.
	if w := getWithCookie(e.h, "/users/reset?name=nobody", cookie); w.Code != http.StatusNotFound {
		t.Errorf("confirm page for unknown user: %d", w.Code)
	}
	if w := getWithCookie(e.h, "/users/reset?name=alice", cookie); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `name="confirm" value="yes"`) {
		t.Errorf("reset confirm page: %d", w.Code)
	}
	before := htpasswdContent(t, e)
	if w := post(e.h, "/users/reset", cookie, form(url.Values{"name": {"alice"}}), nil); w.Code != http.StatusBadRequest {
		t.Errorf("reset without confirm: %d", w.Code)
	}
	if htpasswdContent(t, e) != before {
		t.Error("unconfirmed reset changed the file")
	}
	w = post(e.h, "/users/reset", cookie, form(url.Values{"name": {"alice"}, "confirm": {"yes"}}), nil)
	if m2 := passwordRe.FindStringSubmatch(w.Body.String()); m2 == nil || m2[1] == m[1] {
		t.Errorf("reset: %d, no new password", w.Code)
	}
	if !e.audit.has("user password reset") {
		t.Error("reset not audited")
	}

	// Remove: the repository stays.
	if w := getWithCookie(e.h, "/users/remove?name=alice", cookie); !strings.Contains(w.Body.String(), "alice/main") {
		t.Error("remove confirm page does not list the repositories")
	}
	wantRedirect(t, post(e.h, "/users/remove", cookie, form(url.Values{"name": {"alice"}, "confirm": {"yes"}}), nil), "/users")
	if strings.Contains(htpasswdContent(t, e), "alice:") || !e.audit.has("user removed") {
		t.Error("alice not removed or not audited")
	}
	if _, err := os.Stat(filepath.Join(e.reposDir, "alice", "main", "config")); err != nil {
		t.Errorf("repository touched: %v", err)
	}
	if w := post(e.h, "/users/remove", cookie, form(url.Values{"name": {"alice"}, "confirm": {"yes"}}), nil); w.Code != http.StatusNotFound {
		t.Errorf("removing again: %d", w.Code)
	}
}

func TestUsersUnparsableFile(t *testing.T) {
	e := newEnv(t, nil, true)
	const broken = "garbage line\n"
	p := filepath.Join(e.reposDir, ".htpasswd")
	_ = os.WriteFile(p, []byte(broken), 0o640)
	cookie := login(t, e)
	csrf := csrfFromPage(t, e.h, cookie)
	if w := getWithCookie(e.h, "/users", cookie); w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "cannot be parsed") {
		t.Errorf("users page: %d", w.Code)
	}
	post(e.h, "/users/add", cookie, url.Values{"csrf_token": {csrf}, "name": {"x"}}, nil)
	if b, _ := os.ReadFile(p); string(b) != broken {
		t.Errorf("file changed: %q", b)
	}
}
