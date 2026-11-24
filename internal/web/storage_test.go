package web

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/MB512/belaypoint/internal/repos"
)

func TestStorage(t *testing.T) {
	const gib = int64(1) << 30
	repo := func(path string, size int64) repoRow {
		r := repoRow{Path: path, Owner: repos.Owner(path), Bytes: size, Files: 1}
		if size >= 0 {
			r.Size = formatBytes(size)
		} else {
			r.Bytes = 0
		}
		return r
	}
	// bob's only repository is not measured yet: no block, but he keeps
	// his colour slot (colours follow the user, not the size).
	rows := []repoRow{repo("zed/a", 10*gib), repo("amy/a", 30*gib), repo("amy/b", 20*gib), repo("bob/x", -1)}

	for _, c := range []struct {
		name  string
		vol   *diskData
		parts []string // name class share
	}{
		{"with volume", &diskData{TotalBytes: 200 * gib, UsedBytes: 100 * gib},
			[]string{"amy series-1 25 %", "zed series-3 5 %", "other data other-data 20 %", "free free 50 %"}},
		{"without volume", nil,
			[]string{"amy series-1 83 %", "zed series-3 16 %"}},
		{"backups larger than used (quota)", &diskData{TotalBytes: 100 * gib, UsedBytes: 40 * gib},
			[]string{"amy series-1 41 %", "zed series-3 8 %", "free free 50 %"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := storage(rows, c.vol)
			var got []string
			for _, p := range d.Parts {
				got = append(got, p.Name+" "+p.Class+" "+p.Share)
			}
			if strings.Join(got, ", ") != strings.Join(c.parts, ", ") {
				t.Errorf("parts\n got %v\nwant %v", got, c.parts)
			}
			if d.Unmeasured != 1 || d.Backups != "60.0 GiB" {
				t.Errorf("unmeasured %d, backups %q", d.Unmeasured, d.Backups)
			}
			// Repositories largest first, the unmeasured last; colour = user.
			if r := d.Repos; len(r) != 4 || r[0].Path != "amy/a" || r[0].W != "100.000" || r[1].W != "66.667" ||
				r[2].Path != "zed/a" || r[2].Class != "series-3" || r[3].Path != "bob/x" || r[3].Class != "series-2" || r[3].W != "" {
				t.Errorf("repos %+v", r)
			}
		})
	}

	// A small block gets no label; the blocks follow each other.
	d := storage(rows, &diskData{TotalBytes: 200 * gib, UsedBytes: 100 * gib})
	if d.Parts[0].Label != true || d.Parts[1].Label != false || d.Parts[1].X != "25.000" || d.Parts[2].X != "30.000" {
		t.Errorf("labels/positions %+v", d.Parts)
	}
}

// More users than colours: the rest is folded into "other users" instead
// of generating more colours.
func TestStorageManyUsers(t *testing.T) {
	var rows []repoRow
	for _, u := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"} {
		rows = append(rows, repoRow{Path: u + "/r", Owner: u, Bytes: 1 << 30, Size: "1.0 GiB"})
	}
	d := storage(rows, nil)
	if len(d.Parts) != 9 || d.Parts[7].Class != "series-8" || d.Parts[8].Name != "other users" || d.Parts[8].Repos != 2 {
		t.Errorf("parts %+v", d.Parts)
	}
	for _, r := range d.Repos {
		if r.Path == "j/r" && r.Class != "other-users" {
			t.Errorf("j/r class %q", r.Class)
		}
	}
}

func TestStoragePage(t *testing.T) {
	e := newEnv(t, nil, true)
	ctx := context.Background()
	makeRepo(t, e.reposDir, "alice/main")
	makeRepo(t, e.reposDir, "bob/main")
	_ = e.store.SyncRepos(ctx, []string{"alice/main", "bob/main"})
	_ = e.store.SetRepoUsage(ctx, "alice/main", repos.Usage{Bytes: 3 << 30, Files: 42}, time.Now())
	cookie := login(t, e)
	w := getWithCookie(e.h, "/storage", cookie)
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("storage: %d", w.Code)
	}
	for _, want := range []string{`<svg class="seg"`, `class="series-1"`, "alice", "Repositories by size", "3.0 GiB",
		"not measured yet", `name="from" value="storage"`, `href="/storage" aria-current="page"`} {
		if !strings.Contains(body, want) {
			t.Errorf("storage page lacks %q", want)
		}
	}
	if strings.Contains(body, "style=") {
		t.Error("storage page uses a style attribute (blocked by the CSP)")
	}
	csrf := csrfFromPage(t, e.h, cookie)
	wantRedirect(t, post(e.h, "/repos/rescan", cookie, map[string][]string{"csrf_token": {csrf}, "from": {"storage"}}, nil), "/storage")
}
