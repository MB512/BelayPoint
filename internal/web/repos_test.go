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
	for _, want := range []string{
		// grouped per user, name without the user
		`scope="rowgroup"><strong>alice</strong>`, `<code>main</code>`, "3.0 GiB", `scope="rowgroup"><strong>bob</strong>`, `scope="rowgroup"><strong>gone</strong>`, "missing",
		// needs attention: bob has no password and a stale lock, gone/repo is missing
		"Needs attention (3)", "no password stored", `href="/repos/password?repo=bob%2Fmain">Set password`, "lock older than 24 h",
		"no longer found below the repository root", `class="badge bad"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
	// Locks link to the Run now tab; unlocking happens there. The storage
	// statistics moved to the Storage page.
	if !strings.Contains(body, `href="/repos/view?repo=bob%2fmain&amp;tab=run"`) || strings.Contains(body, "/repos/unlock") || strings.Contains(body, "Per user") {
		t.Error("overview: locks not linked to the Run now tab, unlock buttons or storage statistics left")
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

func TestOverviewAttention(t *testing.T) {
	now := time.Now()
	ok := repoRow{Path: "a/ok", Owner: "a", Password: true, LastJob: &lastJob{ID: 1, Type: "maintenance", OK: true}}
	for _, c := range []struct {
		name string
		row  repoRow
		want []string // problem texts
	}{
		{"all fine", ok, nil},
		{"no password", repoRow{Path: "a/x", Owner: "a"}, []string{"no password stored: nothing can run"}},
		{"failed", repoRow{Path: "a/x", Owner: "a", Password: true, LastJob: &lastJob{ID: 7, Type: "prune", State: "failed", When: "2 h ago"}}, []string{"prune failed 2 h ago"}},
		{"skipped", repoRow{Path: "a/x", Owner: "a", Password: true, LastJob: &lastJob{ID: 7, Type: "maintenance", State: "skipped", When: "3 days ago"}}, []string{"maintenance skipped 3 days ago"}},
		{"running is fine", repoRow{Path: "a/x", Owner: "a", Password: true, LastJob: &lastJob{ID: 7, Type: "check", State: "running", Active: true}}, nil},
		{"stale lock", repoRow{Path: "a/x", Owner: "a", Password: true, Locks: 1, StaleLock: true}, []string{"lock older than 24 h: probably stale"}},
		{"stale backup", repoRow{Path: "a/x", Owner: "a", Password: true, StaleBackup: true, LastBackup: "Feb 2019"}, []string{"no recent backup (last one Feb 2019)"}},
		{"missing", repoRow{Path: "a/x", Owner: "a", Missing: true}, []string{"no longer found below the repository root"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			var got []string
			for _, a := range problems(c.row) {
				got = append(got, a.Problem)
			}
			if strings.Join(got, "|") != strings.Join(c.want, "|") {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
	_ = now
}

func TestOverviewGroups(t *testing.T) {
	d := overview([]repoRow{
		{Path: "bob/1", Owner: "bob", Bytes: 2, Size: "2 B", Password: true},
		{Path: "alice/1", Owner: "alice", Bytes: 1 << 30, Size: "1.0 GiB", Password: true},
		{Path: "alice/2", Owner: "alice", Bytes: 1 << 30, Size: "1.0 GiB", Password: true},
		{Path: "alice/old", Owner: "alice", Bytes: 1 << 40, Missing: true, Password: true},
	})
	if len(d.Groups) != 2 || d.Groups[0].Owner != "alice" || len(d.Groups[0].Repos) != 3 || d.Groups[0].Size != "2.0 GiB" || d.Groups[1].Owner != "bob" {
		t.Errorf("groups %+v", d.Groups)
	}
}

func TestHumanAge(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	for d, want := range map[time.Duration]string{
		10 * time.Second:      "just now",
		5 * time.Minute:       "5 min ago",
		32 * time.Hour:        "32 h ago",
		3 * 24 * time.Hour:    "3 days ago",
		20 * 24 * time.Hour:   "2 weeks ago",
		153 * 24 * time.Hour:  "Jun 2026",
		2594 * 24 * time.Hour: "Oct 2019",
	} {
		if got := humanAge(now, now.Add(-d), time.UTC); got != want {
			t.Errorf("%v: %q, want %q", d, got, want)
		}
	}
}
