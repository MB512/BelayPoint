package web

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MB512/belaypoint/internal/repos"
	"github.com/MB512/belaypoint/internal/vault"
)

func makeRepo(t *testing.T, root, rel string) string {
	t.Helper()
	dir := filepath.Join(root, filepath.FromSlash(rel))
	for _, d := range []string{"data", "index", "keys", "locks", "snapshots"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func login(t *testing.T, e *testEnv) string {
	t.Helper()
	w := post(e.h, "/login", "", url.Values{"password": {"correct horse battery"}}, nil)
	c := sessionFromResponse(t, w)
	if c == "" {
		t.Fatalf("login failed: %d", w.Code)
	}
	return c
}

func TestOverview(t *testing.T) {
	e := newEnv(t, nil, true)
	ctx := context.Background()
	makeRepo(t, e.reposDir, "alice/main")
	bob := makeRepo(t, e.reposDir, "bob/main")
	stale := filepath.Join(bob, "locks", "abc")
	_ = os.WriteFile(stale, []byte("x"), 0o644)
	old := time.Now().Add(-30 * time.Hour)
	_ = os.Chtimes(stale, old, old)
	if err := e.store.SyncRepos(ctx, []string{"alice/main", "bob/main", "gone/repo"}); err != nil {
		t.Fatal(err)
	}
	if err := e.store.SyncRepos(ctx, []string{"alice/main", "bob/main"}); err != nil { // gone/repo now missing
		t.Fatal(err)
	}
	_ = e.store.SetRepoUsage(ctx, "alice/main", repos.Usage{Bytes: 3 << 30, Files: 42}, time.Now())
	e.vault.secrets = []string{vault.RepoSecret("alice/main")}

	cookie := login(t, e)
	w := getWithCookie(e.h, "/", cookie)
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("overview: %d", w.Code)
	}
	for _, want := range []string{"alice/main", "3.0 GiB", "42", "bob/main", "1, oldest 30 h", "badge bad", "gone/repo", "missing", "stored", "not set"} {
		if !strings.Contains(body, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
}

func TestRescan(t *testing.T) {
	e := newEnv(t, nil, true)
	cookie := login(t, e)
	if w := post(e.h, "/repos/rescan", cookie, url.Values{}, nil); w.Code != http.StatusForbidden {
		t.Errorf("rescan without CSRF: %d", w.Code)
	}
	csrf := csrfFromPage(t, e.h, cookie)
	wantRedirect(t, post(e.h, "/repos/rescan", cookie, url.Values{"csrf_token": {csrf}}, nil), "/")
	if e.scanner.rescans != 1 || !e.audit.has("rescan") {
		t.Errorf("rescans %d, audited %v", e.scanner.rescans, e.audit.has("rescan"))
	}
}

func TestFormatBytes(t *testing.T) {
	tests := map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 1536: "1.5 KiB", 5 << 20: "5.0 MiB", 3 << 40: "3.0 TiB"}
	for n, want := range tests {
		if got := formatBytes(n); got != want {
			t.Errorf("formatBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestFormatAge(t *testing.T) {
	tests := map[time.Duration]string{
		30 * time.Second: "30 s", 5 * time.Minute: "5 min", 3 * time.Hour: "3 h", 47 * time.Hour: "47 h", 72 * time.Hour: "3 d",
	}
	for d, want := range tests {
		if got := formatAge(d); got != want {
			t.Errorf("formatAge(%v) = %q, want %q", d, got, want)
		}
	}
}
