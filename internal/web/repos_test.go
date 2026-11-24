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
	for _, want := range []string{"alice/main", "3.0 GiB", "42", "100 %", "Per user", "<meter", "bob/main", "1, oldest 30 h", "badge bad", "gone/repo", "missing", "stored", "set…", "/repos/password?repo=bob%2fmain"} {
		if !strings.Contains(body, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
	// Locks link to the Run now tab; unlocking happens there.
	if !strings.Contains(body, `href="/repos/view?repo=bob%2fmain&amp;tab=run"`) || strings.Contains(body, "/repos/unlock") {
		t.Error("overview: locks not linked to the Run now tab, or unlock buttons left")
	}
	e.vault.secrets = append(e.vault.secrets, vault.RepoSecret("bob/main"))
	run := getWithCookie(e.h, "/repos/view?repo=bob/main&tab=run", cookie).Body.String()
	for _, want := range []string{"Locks now:", "1, oldest 30 h", "probably stale", `action="/repos/unlock"`} {
		if !strings.Contains(run, want) {
			t.Errorf("Run now tab lacks %q", want)
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

func TestSummarize(t *testing.T) {
	rows := []repoRow{
		{Path: "alice/a", Owner: "alice", Size: "x", Bytes: 100, Files: 1},
		{Path: "alice/b", Owner: "alice", Size: "x", Bytes: 50, Files: 2},
		{Path: "bob/a", Owner: "bob", Size: "x", Bytes: 300, Files: 3},
		{Path: "bob/b", Owner: "bob"}, // not measured yet
		{Path: "carol/a", Owner: "carol", Size: "x", Bytes: 1, Files: 1},
		{Path: "gone/a", Owner: "gone", Size: "x", Bytes: 999, Missing: true},
	}
	owners, total := summarize(rows)
	if len(owners) != 3 {
		t.Fatalf("owners = %+v", owners)
	}
	want := []struct {
		name       string
		repos      int
		bytes      int64
		unmeasured int
		share      string
	}{
		{"bob", 2, 300, 1, "66 %"},
		{"alice", 2, 150, 0, "33 %"},
		{"carol", 1, 1, 0, "< 1 %"},
	}
	for i, w := range want {
		o := owners[i]
		if o.Name != w.name || o.Repos != w.repos || o.Bytes != w.bytes || o.Unmeasured != w.unmeasured || o.Share != w.share || o.MaxBytes != 300 {
			t.Errorf("owner %d = %+v, want %+v", i, o, w)
		}
	}
	if total.Repos != 5 || total.Bytes != 451 || total.Files != 7 || total.Unmeasured != 1 || total.MaxBytes != 300 {
		t.Errorf("total = %+v", total)
	}
}

func TestPercent(t *testing.T) {
	for _, c := range []struct {
		part, whole int64
		want        string
	}{{0, 0, ""}, {0, 10, "0 %"}, {1, 1000, "< 1 %"}, {5, 10, "50 %"}, {10, 10, "100 %"}} {
		if got := percent(c.part, c.whole); got != c.want {
			t.Errorf("percent(%d, %d) = %q, want %q", c.part, c.whole, got, c.want)
		}
	}
}

func TestDiskBar(t *testing.T) {
	e := newEnv(t, nil, true)
	cookie := login(t, e)
	for _, path := range []string{"/", "/users", "/jobs"} {
		body := getWithCookie(e.h, path, cookie).Body.String()
		if !strings.Contains(body, `class="disk`) || !strings.Contains(body, " free") {
			t.Errorf("%s lacks the disk bar", path)
		}
	}
	if body := get(e.h, "/login", nil).Body.String(); strings.Contains(body, `class="disk`) {
		t.Error("disk bar shown before login")
	}
}
