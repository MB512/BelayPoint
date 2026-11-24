package web

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/MB512/belaypoint/internal/restic"
)

func TestAxisBands(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name   string
		keep   restic.Keep
		oldest time.Time
		want   string // labels, oldest first
	}{
		{"production policy", restic.Keep{KeepWithin: "7d", KeepDaily: 30, KeepWeekly: 10, KeepMonthly: 24, KeepYearly: 6},
			now.AddDate(-8, 0, 0), "older|yearly (6)|monthly (24)|weekly (10)|daily (30)|within 7d"},
		{"no older band when everything is within reach", restic.Keep{KeepDaily: 7, KeepWeekly: 4},
			now.AddDate(0, 0, -20), "weekly (4)|daily (7)"},
		{"a rule reaching no further adds no band", restic.Keep{KeepDaily: 30, KeepWeekly: 4},
			now.AddDate(0, 0, -10), "daily (30)"},
		{"keep-last only: plain time", restic.Keep{KeepLast: 2},
			now.AddDate(0, -1, 0), "all snapshots"},
	} {
		t.Run(c.name, func(t *testing.T) {
			bands := axisBands(c.keep, now, c.oldest)
			var labels []string
			total := 0.0
			for _, b := range bands {
				labels = append(labels, b.Label)
				total += b.w
			}
			if strings.Join(labels, "|") != c.want {
				t.Errorf("bands %q, want %q", labels, c.want)
			}
			if total < 99.99 || total > 100.01 {
				t.Errorf("widths add up to %v", total)
			}
		})
	}
}

func TestPosition(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	bands := axisBands(restic.Keep{KeepDaily: 10, KeepWeekly: 10}, now, now.AddDate(0, 0, -70))
	// weekly (10) takes the left half, daily (10) the right half.
	for _, c := range []struct {
		t    time.Time
		want float64
	}{
		{now, 99.4},                  // newest: right end (minus the margin)
		{now.AddDate(0, 0, -5), 75},  // middle of daily
		{now.AddDate(0, 0, -10), 50}, // border
		{now.AddDate(0, 0, -40), 25}, // middle of weekly
		{now.AddDate(-1, 0, 0), 0.6}, // before the axis: clamped
		{now.Add(time.Hour), 99.4},   // clock skew: clamped
	} {
		if got := position(bands, c.t); got < c.want-0.5 || got > c.want+0.5 {
			t.Errorf("%v: %v, want %v", c.t, got, c.want)
		}
	}
}

func TestParseWithin(t *testing.T) {
	for s, want := range map[string][4]int{"7d": {0, 0, 7, 0}, "1y6m": {1, 6, 0, 0}, "36h": {0, 0, 0, 36}, "2y3m4d5h": {2, 3, 4, 5}} {
		y, m, d, h, ok := parseWithin(s)
		if !ok || [4]int{y, m, d, h} != want {
			t.Errorf("%q: %v %v %v %v %v", s, y, m, d, h, ok)
		}
	}
	for _, bad := range []string{"", "7", "d", "7w", "1d2y"} {
		if _, _, _, _, ok := parseWithin(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDescribeKeep(t *testing.T) {
	for k, want := range map[restic.Keep]string{
		{KeepLast: 2}: "keep last 2",
		{KeepWithin: "7d", KeepDaily: 30, KeepWeekly: 10, KeepMonthly: 24, KeepYearly: 6}: "keep within 7d, daily 30, weekly 10, monthly 24, yearly 6",
		{KeepLast: 1, KeepWithin: "3d"}: "keep last 1, within 3d",
	} {
		if got := describeKeep(k); got != want {
			t.Errorf("%+v: %q, want %q", k, got, want)
		}
	}
}

func TestCommonDir(t *testing.T) {
	g := func(paths ...string) restic.ForgetGroup { return restic.ForgetGroup{Paths: paths} }
	for _, c := range []struct {
		groups []restic.ForgetGroup
		want   string
	}{
		{[]restic.ForgetGroup{g("/home/docker/homepage"), g("/home/docker/git")}, "/home/docker/"},
		{[]restic.ForgetGroup{g("/home/docker/a"), g("/home/other/b")}, "/home/"},
		{[]restic.ForgetGroup{g("/srv/a"), g("/home/b")}, ""},
		{[]restic.ForgetGroup{g("/home/docker/a")}, ""}, // one group: nothing to shorten
		{[]restic.ForgetGroup{g("/a/x", "/a/y"), g("/a/z")}, ""},
	} {
		if got := commonDir(c.groups); got != c.want {
			t.Errorf("%v: %q, want %q", c.groups, got, c.want)
		}
	}
}

func TestBuildPass(t *testing.T) {
	now := time.Now()
	snap := func(id string, ago time.Duration) restic.Snapshot {
		return restic.Snapshot{ID: id + "full", ShortID: id, Time: now.Add(-ago)}
	}
	r := restic.PassResult{Groups: []restic.ForgetGroup{
		{Host: "vs06", Paths: []string{"/home/docker/git"}, Keep: []restic.Snapshot{snap("k1", time.Hour)}},
		{Host: "vs06", Paths: []string{"/home/docker/app"}, Keep: []restic.Snapshot{snap("k2", time.Hour)}, Remove: []restic.Snapshot{snap("r1", 48*time.Hour)},
			Reasons: []restic.KeepReason{{Matches: []string{"daily snapshot"}}}},
		{Host: "docker01", Paths: []string{"/home/docker/git"}, Keep: []restic.Snapshot{snap("k3", time.Hour)}},
	}}
	r.Groups[1].Reasons[0].Snapshot.ID = "k2full"
	p := buildPass(r, restic.Keep{KeepDaily: 1}, now, time.UTC)
	if p.Keep != 3 || p.Remove != 1 || p.UnchangedCount != 2 || p.Summary() != "1 removed in 1 group, 3 kept" {
		t.Errorf("pass %+v, summary %q", p, p.Summary())
	}
	if len(p.Changed) != 1 || p.Changed[0].Host != "vs06" || p.Changed[0].Groups[0].Name != "app" {
		t.Fatalf("changed %+v", p.Changed)
	}
	g := p.Changed[0].Groups[0]
	if len(g.Dots) != 2 || !g.Dots[0].Removed || !strings.Contains(g.Dots[1].Title, "kept: daily snapshot") {
		t.Errorf("dots %+v", g.Dots)
	}
	if g.Snapshots[0].ID != "k2" || g.Snapshots[1].Reason != "removed" {
		t.Errorf("list (newest first) %+v", g.Snapshots)
	}
	if len(p.Unchanged) != 2 || p.Unchanged[0].Host != "docker01" || p.Unchanged[1].Groups[0].Name != "git" {
		t.Errorf("unchanged %+v", p.Unchanged)
	}
}

// Nothing to remove: the confirmation page offers no active Run button.
func TestForgetNothingToRemove(t *testing.T) {
	e := newEnv(t, nil, true)
	ctx := context.Background()
	makeRepo(t, e.reposDir, "alice/main")
	_ = e.store.SyncRepos(ctx, []string{"alice/main"})
	cookie := login(t, e)
	e.jobs.keepAll = true
	w := getWithCookie(e.h, "/repos/maintenance?repo=alice/main&job=forget", cookie)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "Nothing to remove") || !strings.Contains(body, `disabled title="The dry-run removes nothing"`) {
		t.Errorf("page %d: no disabled button", w.Code)
	}
	// Unchanged passes are collapsed, not opened.
	if strings.Contains(body, `class="pass" open`) {
		t.Error("a pass without removals is open")
	}
}
