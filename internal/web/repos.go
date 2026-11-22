package web

import (
	"cmp"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/MB512/belaypoint/internal/repos"
	"github.com/MB512/belaypoint/internal/vault"
)

// StaleLockAge is the lock file age from which the UI warns (and, later,
// notifications fire).
const StaleLockAge = 24 * time.Hour

type repoRow struct {
	Path    string
	Owner   string
	Missing bool
	Size    string // "" until measured
	Bytes   int64
	Files   int64
	// Share is the repository's part of the total size ("12 %"); the bar
	// is scaled to the largest repository.
	Share    string
	Measured string
	Locks    int
	// OldestLock is the age of the oldest lock file ("" if none);
	// StaleLock is true when it is older than StaleLockAge.
	OldestLock string
	StaleLock  bool
	LockError  bool
	Password   bool
	// Snapshots is "" until listed; SnapshotsTitle says when.
	Snapshots      string
	SnapshotsTitle string
	// Busy: a job for this repository is queued or running.
	Busy bool
}

// home is the overview: all known repositories with what can be read
// without their password.
func (s *server) home(w http.ResponseWriter, r *http.Request) {
	s.renderHome(w, r, http.StatusOK, "")
}

func (s *server) renderHome(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	list, err := s.Repos.ListRepos(r.Context())
	if err != nil {
		s.Logger.Error("listing repositories", "err", err)
		http.Error(w, "listing repositories failed; see the container log", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	p := page{
		Title: "Overview", CSRF: sessionFrom(r.Context()).CSRF, Error: errMsg,
		Scanning: s.Scanner.Scanning(), JobsAvailable: s.Jobs != nil,
	}
	for _, repo := range list {
		row := repoRow{
			Path:     repo.Path,
			Owner:    repos.Owner(repo.Path),
			Missing:  repo.Missing,
			Password: s.Vault.Has(vault.RepoSecret(repo.Path)),
		}
		if repo.Usage != nil {
			row.Size = formatBytes(repo.Usage.Bytes)
			row.Bytes = repo.Usage.Bytes
			row.Files = repo.Usage.Files
			row.Measured = repo.UsageTime.In(s.Location).Format("2006-01-02 15:04")
		}
		if sn := repo.Snapshots; sn != nil {
			row.Snapshots = strconv.Itoa(sn.Count)
			if !sn.Newest.IsZero() {
				row.Snapshots += ", newest " + formatAge(now.Sub(sn.Newest)) + " ago"
			}
			row.SnapshotsTitle = "listed " + sn.Time.In(s.Location).Format("2006-01-02 15:04")
		}
		if !repo.Missing {
			s.addLocks(&row, now)
			row.Busy = s.Jobs != nil && s.Jobs.Busy(repo.Path)
		}
		p.Repos = append(p.Repos, row)
	}
	p.Owners, p.Total = summarize(p.Repos)
	for i := range p.Repos {
		if p.Repos[i].Size != "" && !p.Repos[i].Missing {
			p.Repos[i].Share = percent(p.Repos[i].Bytes, p.Total.Bytes)
		}
	}
	s.render(w, status, "home.html", p)
}

// ownerRow is one line of the per-user summary; the total uses it too.
type ownerRow struct {
	Name     string
	Repos    int
	Bytes    int64
	Size     string
	Files    int64
	Share    string
	MaxBytes int64 // largest repository (total) or user (owner rows)
	// Unmeasured counts repositories without disk usage yet; their size
	// is not in the sum.
	Unmeasured int
}

// summarize sums the present repositories per user, largest first, and in
// total. Missing repositories are left out: their last usage is outdated.
func summarize(rows []repoRow) ([]ownerRow, ownerRow) {
	var total ownerRow
	byName := map[string]*ownerRow{}
	var owners []*ownerRow
	for _, r := range rows {
		if r.Missing {
			continue
		}
		o := byName[r.Owner]
		if o == nil {
			o = &ownerRow{Name: r.Owner}
			byName[r.Owner] = o
			owners = append(owners, o)
		}
		for _, sum := range []*ownerRow{o, &total} {
			sum.Repos++
			if r.Size == "" {
				sum.Unmeasured++
				continue
			}
			sum.Bytes += r.Bytes
			sum.Files += r.Files
		}
		total.MaxBytes = max(total.MaxBytes, r.Bytes)
	}
	// slices.SortFunc with a comparison func is like List.Sort(Comparison)
	// in C#; cmp.Or picks the first non-zero result (then by name).
	slices.SortFunc(owners, func(a, b *ownerRow) int {
		return cmp.Or(cmp.Compare(b.Bytes, a.Bytes), cmp.Compare(a.Name, b.Name))
	})
	out := make([]ownerRow, 0, len(owners))
	for _, o := range owners {
		o.MaxBytes = owners[0].Bytes
		o.Size = formatBytes(o.Bytes)
		o.Share = percent(o.Bytes, total.Bytes)
		out = append(out, *o)
	}
	total.Size = formatBytes(total.Bytes)
	return out, total
}

// percent formats part/whole as a whole percentage; "< 1 %" for small
// non-zero parts.
func percent(part, whole int64) string {
	if whole <= 0 {
		return ""
	}
	p := part * 100 / whole
	if p == 0 && part > 0 {
		return "< 1 %"
	}
	return fmt.Sprintf("%d %%", p)
}

// addLocks reads the lock files of the repository live (one directory
// listing, cheap).
func (s *server) addLocks(row *repoRow, now time.Time) {
	dir, err := repos.Dir(s.ReposDir, row.Path)
	if err != nil {
		s.Logger.Warn("repository", "repo", row.Path, "err", err)
		row.LockError = true
		return
	}
	locks, err := repos.Locks(dir)
	if err != nil {
		s.Logger.Warn("repository", "repo", row.Path, "err", err)
		row.LockError = true
		return
	}
	row.Locks = len(locks)
	if len(locks) > 0 {
		age := now.Sub(locks[0].ModTime)
		row.OldestLock = formatAge(age)
		row.StaleLock = age > StaleLockAge
	}
}

// rescan starts discovery and disk usage in the background.
func (s *server) rescan(w http.ResponseWriter, r *http.Request) {
	f, ok := s.postForm(w, r)
	if !ok {
		return
	}
	f.wipe()
	if s.Scanner.Rescan() {
		s.Audit.Audit(r.Context(), "rescan", remote(r))
	}
	redirect(w, r, "/")
}

// formatBytes formats n with binary units (KiB, MiB, ...), as restic does.
func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 5; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// formatAge formats a duration coarsely: "45 s", "12 min", "5 h", "3 d".
func formatAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h", int(d.Hours()))
	default:
		return fmt.Sprintf("%d d", int(d.Hours()/24))
	}
}
