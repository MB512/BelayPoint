package web

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/MB512/belaypoint/internal/restic"
)

// The forget dry-run display (#8): a headline, then one section per pass
// (tag rules first, then "all other snapshots"), each with one compact row
// per host+paths group and a timeline whose axis is split into bands
// derived from the pass's own keep rules.

// previewData is a forget dry-run prepared for display.
type previewData struct {
	Keep, Remove int
	Passes       []previewPass
	// Unsaved is set when the previewed values differ from the saved
	// policy, so the page does not pretend they are in effect.
	Unsaved bool
}

// previewPass is one forget pass: a tag rule (Tag set) or the main policy.
type previewPass struct {
	Tag          string
	Rule         string // "keep last 2", "keep within 7d, daily 30"
	Keep, Remove int
	GroupCount   int
	// Bands is the time axis; Changed are the groups that lose snapshots
	// (per host), Unchanged the others.
	Bands     []band
	Changed   []previewHost
	Unchanged []previewHost
	// UnchangedCount is the number of groups in Unchanged.
	UnchangedCount int
}

// band is one segment of the time axis. X and W are percent of the row
// width (SVG coordinates: the CSP forbids style attributes).
type band struct {
	Label, Title string
	X, W, Mid    string
	start, end   time.Time
	x, w         float64
}

type previewHost struct {
	Host   string
	Groups []previewGroup
	// Bands is the pass's axis, repeated here for the row backgrounds
	// (a template cannot reach the enclosing pass).
	Bands []band
}

// previewGroup is one row: a host+paths group with its dots and, on
// demand, its snapshot list.
type previewGroup struct {
	Name, Paths  string
	Keep, Remove int
	Dots         []dot
	Snapshots    []snapshotRow
}

// dot is one snapshot on the timeline.
type dot struct {
	X       string
	Removed bool
	Title   string
}

type snapshotRow struct {
	ID, Time, Tags, Reason string
	Removed                bool
}

// preview prepares the dry-run of policy p for display.
func (s *server) preview(p restic.Policy, results []restic.PassResult) *previewData {
	now := time.Now()
	d := &previewData{Keep: len(restic.Kept(results)), Remove: restic.Removed(results)}
	for _, r := range results {
		keep := p.Keep
		for _, rule := range p.TagRules {
			if rule.Tag == r.Tag {
				keep = rule.Keep
			}
		}
		d.Passes = append(d.Passes, buildPass(r, keep, now, s.Location))
	}
	return d
}

// buildPass lays out one pass.
func buildPass(r restic.PassResult, keep restic.Keep, now time.Time, loc *time.Location) previewPass {
	pass := previewPass{Tag: r.Tag, Rule: describeKeep(keep), GroupCount: len(r.Groups)}
	oldest := now
	for _, g := range r.Groups {
		for _, sn := range slices.Concat(g.Keep, g.Remove) {
			if sn.Time.Before(oldest) {
				oldest = sn.Time
			}
		}
	}
	pass.Bands = axisBands(keep, now, oldest)
	prefix := commonDir(r.Groups)

	changed, unchanged := map[string]*previewHost{}, map[string]*previewHost{}
	for _, g := range r.Groups {
		pass.Keep += len(g.Keep)
		pass.Remove += len(g.Remove)
		row := previewGroup{Paths: strings.Join(g.Paths, ", "), Keep: len(g.Keep), Remove: len(g.Remove)}
		row.Name = strings.TrimPrefix(row.Paths, prefix)
		if row.Name == "" {
			row.Name = row.Paths
		}
		add := func(sn restic.Snapshot, removed bool) {
			sr := snapshotRow{
				ID: sn.ShortID, Time: sn.Time.In(loc).Format("2006-01-02 15:04"),
				Tags: strings.Join(sn.Tags, ", "), Removed: removed,
			}
			if removed {
				sr.Reason = "removed"
			} else if why := g.ReasonFor(sn.ID); len(why) > 0 {
				sr.Reason = "kept: " + strings.Join(why, ", ")
			} else {
				sr.Reason = "kept"
			}
			row.Snapshots = append(row.Snapshots, sr)
			title := sr.ID + " · " + sr.Time
			if sr.Tags != "" {
				title += " · " + sr.Tags
			}
			row.Dots = append(row.Dots, dot{X: pct(position(pass.Bands, sn.Time)), Removed: removed, Title: title + " · " + sr.Reason})
		}
		// Removed first: the kept dots are drawn on top, so in dense parts
		// the snapshots that stay remain visible.
		for _, sn := range g.Remove {
			add(sn, true)
		}
		for _, sn := range g.Keep {
			add(sn, false)
		}
		slices.SortFunc(row.Snapshots, func(a, b snapshotRow) int { return cmp.Compare(b.Time, a.Time) })

		target := unchanged
		if row.Remove > 0 {
			target = changed
		} else {
			pass.UnchangedCount++
		}
		h := target[g.Host]
		if h == nil {
			h = &previewHost{Host: g.Host, Bands: pass.Bands}
			target[g.Host] = h
		}
		h.Groups = append(h.Groups, row)
	}
	pass.Changed, pass.Unchanged = sortHosts(changed), sortHosts(unchanged)
	return pass
}

// sortHosts returns the hosts by name, each with its groups by name.
func sortHosts(m map[string]*previewHost) []previewHost {
	out := make([]previewHost, 0, len(m))
	for _, h := range m {
		slices.SortFunc(h.Groups, func(a, b previewGroup) int { return cmp.Compare(a.Name, b.Name) })
		out = append(out, *h)
	}
	slices.SortFunc(out, func(a, b previewHost) int { return cmp.Compare(a.Host, b.Host) })
	return out
}

// commonDir is the directory prefix shared by the paths of all groups
// ("/home/docker/"), so rows can show the short rest ("homepage"). "" when
// a group has several paths or there is no common directory.
func commonDir(groups []restic.ForgetGroup) string {
	var prefix string
	for i, g := range groups {
		if len(g.Paths) != 1 {
			return ""
		}
		dir := g.Paths[0][:strings.LastIndex(g.Paths[0], "/")+1]
		if i == 0 {
			prefix = dir
			continue
		}
		for !strings.HasPrefix(dir, prefix) {
			prefix = prefix[:strings.LastIndex(strings.TrimSuffix(prefix, "/"), "/")+1]
		}
	}
	if len(groups) < 2 || prefix == "/" {
		return ""
	}
	return prefix
}

// describeKeep writes the keep rules in words: "keep last 2", "keep within
// 7d, daily 30, weekly 10".
func describeKeep(k restic.Keep) string {
	var parts []string
	for _, r := range []struct {
		name string
		n    int
	}{{"last", k.KeepLast}, {"hourly", k.KeepHourly}, {"daily", k.KeepDaily}, {"weekly", k.KeepWeekly}, {"monthly", k.KeepMonthly}, {"yearly", k.KeepYearly}} {
		if r.n > 0 {
			parts = append(parts, r.name+" "+strconv.Itoa(r.n))
		}
	}
	if k.KeepWithin != "" {
		parts = slices.Insert(parts, min(len(parts), boolInt(k.KeepLast > 0)), "within "+k.KeepWithin)
	}
	return "keep " + strings.Join(parts, ", ")
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Band widths: a band's share of the axis is its number of slots (days,
// weeks, …), limited so that neither a long keep-within nor keep-daily 3
// dominates or vanishes.
const (
	minBandWeight   = 3
	maxBandWeight   = 40
	olderBandWeight = 4
)

// axisBands splits the time axis by the keep rules, newest band left (in
// the order the rules read: within, daily, weekly, …). Each
// rule covers the time from where the shorter rules end back to its own
// reach (daily 30: the last 30 days); a rule that reaches no further than
// a shorter one adds no band. Snapshots beyond the longest reach fall into
// "older". Without time rules (keep-last only) the axis is plain time from
// the oldest snapshot to now. The bands are nominal: restic counts days or
// weeks that have snapshots, so with gaps it keeps further back.
func axisBands(k restic.Keep, now, oldest time.Time) []band {
	type rule struct {
		label, title string
		start        time.Time
		weight       int
	}
	var rules []rule
	if y, m, d, h, ok := parseWithin(k.KeepWithin); ok {
		start := now.AddDate(-y, -m, -d).Add(-time.Duration(h) * time.Hour)
		days := int(now.Sub(start).Hours() / 24)
		rules = append(rules, rule{"within " + k.KeepWithin, "keep-within " + k.KeepWithin + ": every snapshot", start, max(days, 1)})
	}
	for _, r := range []struct {
		name  string
		n     int
		start func(n int) time.Time
	}{
		{"hourly", k.KeepHourly, func(n int) time.Time { return now.Add(-time.Duration(n) * time.Hour) }},
		{"daily", k.KeepDaily, func(n int) time.Time { return now.AddDate(0, 0, -n) }},
		{"weekly", k.KeepWeekly, func(n int) time.Time { return now.AddDate(0, 0, -7*n) }},
		{"monthly", k.KeepMonthly, func(n int) time.Time { return now.AddDate(0, -n, 0) }},
		{"yearly", k.KeepYearly, func(n int) time.Time { return now.AddDate(-n, 0, 0) }},
	} {
		if r.n > 0 {
			label := r.name + " (" + strconv.Itoa(r.n) + ")"
			rules = append(rules, rule{label, "keep-" + r.name + " " + strconv.Itoa(r.n) + ": the newest snapshot of each of the last " + strconv.Itoa(r.n) + " " + unit(r.name), r.start(r.n), r.n})
		}
	}

	var bands []band
	if len(rules) == 0 {
		start := now.Add(-time.Hour) // at least an hour wide
		if oldest.Before(start) {
			start = oldest
		}
		bands = []band{{Label: "all snapshots", Title: describeKeep(k), start: start, end: now, w: 1}}
	} else {
		// Finest rule first (within, hourly, daily, …); each band ends
		// where the previous began, so a rule that reaches no further back
		// than a finer one (weekly 4 after daily 30) adds nothing.
		end := now
		for _, r := range rules {
			if !r.start.Before(end) {
				continue
			}
			bands = append(bands, band{Label: r.label, Title: r.title, start: r.start, end: end,
				w: float64(min(max(r.weight, minBandWeight), maxBandWeight))})
			end = r.start
		}
		if oldest.Before(end) {
			bands = append(bands, band{Label: "older", Title: "older than all keep rules reach", start: oldest, end: end, w: olderBandWeight})
		}
	}
	var total float64
	for _, b := range bands {
		total += b.w
	}
	x := 0.0
	for i := range bands {
		bands[i].w = bands[i].w * 100 / total
		bands[i].x = x
		bands[i].X, bands[i].W, bands[i].Mid = pct(x), pct(bands[i].w), pct(x+bands[i].w/2)
		x += bands[i].w
	}
	return bands
}

func unit(rule string) string {
	return map[string]string{"hourly": "hours", "daily": "days", "weekly": "weeks", "monthly": "months", "yearly": "years"}[rule]
}

// position is the x coordinate (percent) of time t on the axis, now at the
// left; times outside it are clamped to its ends.
func position(bands []band, t time.Time) float64 {
	if len(bands) == 0 {
		return 0
	}
	// A small margin keeps dots at the ends fully visible.
	const margin = 0.6
	clamp := func(v float64) float64 { return min(max(v, margin), 100-margin) }
	if !t.Before(bands[0].end) {
		return clamp(0) // now, or newer (clock skew)
	}
	for _, b := range bands {
		if t.Before(b.start) {
			continue
		}
		span := b.end.Sub(b.start)
		if span <= 0 {
			return clamp(b.x + b.w/2)
		}
		return clamp(b.x + b.w*float64(b.end.Sub(t))/float64(span))
	}
	return clamp(100)
}

// withinRe matches restic's keep-within durations: "1y6m", "14d", "36h".
var withinRe = regexp.MustCompile(`^(?:(\d+)y)?(?:(\d+)m)?(?:(\d+)d)?(?:(\d+)h)?$`)

// parseWithin splits a keep-within duration into years, months, days and
// hours; ok is false for "" or an invalid value.
func parseWithin(s string) (y, m, d, h int, ok bool) {
	parts := withinRe.FindStringSubmatch(s)
	if s == "" || parts == nil {
		return 0, 0, 0, 0, false
	}
	n := func(v string) int {
		i, _ := strconv.Atoi(v) // "" (part absent) is 0
		return i
	}
	return n(parts[1]), n(parts[2]), n(parts[3]), n(parts[4]), true
}

// Summary is the one-line result of a pass in its section header.
func (p previewPass) Summary() string {
	groups := func(n int) string {
		if n == 1 {
			return "1 group"
		}
		return strconv.Itoa(n) + " groups"
	}
	if p.Remove == 0 {
		return fmt.Sprintf("nothing removed (%d kept in %s)", p.Keep, groups(p.GroupCount))
	}
	return fmt.Sprintf("%d removed in %s, %d kept", p.Remove, groups(p.GroupCount-p.UnchangedCount), p.Keep)
}
