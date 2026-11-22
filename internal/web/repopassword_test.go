package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/MB512/belaypoint/internal/vault"
)

func TestRepoPassword(t *testing.T) {
	e := newEnv(t, nil, true)
	ctx := context.Background()
	dir := makeRepo(t, e.reposDir, "alice/main")
	if err := e.store.SyncRepos(ctx, []string{"alice/main", "gone/repo"}); err != nil {
		t.Fatal(err)
	}
	if err := e.store.SyncRepos(ctx, []string{"alice/main"}); err != nil {
		t.Fatal(err)
	}
	cookie := login(t, e)
	csrf := csrfFromPage(t, e.h, cookie)
	name := vault.RepoSecret("alice/main")

	if w := getWithCookie(e.h, "/repos/password?repo=alice/main", cookie); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), "No password is stored") {
		t.Fatalf("page: %d", w.Code)
	}
	for _, path := range []string{"gone/repo", "unknown/x", "../etc", ""} {
		if w := getWithCookie(e.h, "/repos/password?repo="+url.QueryEscape(path), cookie); w.Code != http.StatusNotFound {
			t.Errorf("page for %q: %d", path, w.Code)
		}
		w := post(e.h, "/repos/password", cookie, url.Values{"csrf_token": {csrf}, "repo": {path}, "password": {"repo secret"}}, nil)
		if w.Code != http.StatusNotFound {
			t.Errorf("set for %q: %d", path, w.Code)
		}
	}

	// Without CSRF token.
	if w := post(e.h, "/repos/password", cookie, url.Values{"repo": {"alice/main"}, "password": {"repo secret"}}, nil); w.Code != http.StatusForbidden {
		t.Errorf("without CSRF: %d", w.Code)
	}

	// Wrong password: rejected, audited, not stored.
	w := post(e.h, "/repos/password", cookie, url.Values{"csrf_token": {csrf}, "repo": {"alice/main"}, "password": {"guess"}}, nil)
	if w.Code != http.StatusBadRequest || strings.Count(w.Body.String(), "does not accept") != 1 {
		t.Errorf("wrong password: %d, message must appear once", w.Code)
	}
	if e.vault.Has(name) || !e.audit.has("repository password rejected") {
		t.Error("wrong password stored or not audited")
	}

	// Empty after trimming.
	w = post(e.h, "/repos/password", cookie, url.Values{"csrf_token": {csrf}, "repo": {"alice/main"}, "password": {"  \n"}}, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("blank password: %d", w.Code)
	}

	// Right password with surrounding whitespace: checked trimmed against
	// the validated directory, stored trimmed, form zeroed.
	w = post(e.h, "/repos/password", cookie, url.Values{"csrf_token": {csrf}, "repo": {"alice/main"}, "password": {" repo secret\n"}}, nil)
	wantRedirect(t, w, "/")
	if got := string(e.vault.values[name]); got != "repo secret" {
		t.Errorf("stored %q", got)
	}
	if last := e.restic.dirs[len(e.restic.dirs)-1]; last != dir {
		t.Errorf("restic got dir %q, want %q", last, dir)
	}
	for _, pw := range e.restic.seen {
		if strings.Trim(string(pw), "\x00") != "" {
			t.Errorf("password not zeroed after the request: %q", pw)
		}
	}
	if !e.audit.has("repository password set") {
		t.Error("not audited")
	}
	if w := getWithCookie(e.h, "/repos/password?repo=alice/main", cookie); !strings.Contains(w.Body.String(), "A password is stored") {
		t.Error("page does not show the stored password")
	}

	// Remove needs the confirmation field.
	w = post(e.h, "/repos/password/remove", cookie, url.Values{"csrf_token": {csrf}, "repo": {"alice/main"}}, nil)
	if w.Code != http.StatusBadRequest || !e.vault.Has(name) {
		t.Errorf("remove without confirm: %d", w.Code)
	}
	w = post(e.h, "/repos/password/remove", cookie, url.Values{"csrf_token": {csrf}, "repo": {"alice/main"}, "confirm": {"yes"}}, nil)
	wantRedirect(t, w, "/")
	if e.vault.Has(name) || !e.audit.has("repository password removed") {
		t.Error("not removed or not audited")
	}
}

func TestRepoPasswordWithoutRestic(t *testing.T) {
	e := newEnv(t, nil, true)
	makeRepo(t, e.reposDir, "alice/main")
	_ = e.store.SyncRepos(context.Background(), []string{"alice/main"})
	e.h = New(func() Options { o := e.opts; o.Restic, o.Jobs = nil, nil; return o }())
	cookie := login(t, e)
	if w := getWithCookie(e.h, "/repos/password?repo=alice/main", cookie); !strings.Contains(w.Body.String(), "not available") {
		t.Error("missing restic not shown")
	}
}
