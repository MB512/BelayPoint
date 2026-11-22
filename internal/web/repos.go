package web

import (
	"fmt"
	"net/http"
	"time"

	"github.com/MB512/belaypoint/internal/repos"
	"github.com/MB512/belaypoint/internal/vault"
)

// StaleLockAge is the lock file age from which the UI warns (and, later,
// notifications fire).
const StaleLockAge = 24 * time.Hour

type repoRow struct {
	Path     string
	Owner    string
	Missing  bool
	Size     string // "" until measured
	Files    int64
	Measured string
	Locks    int
	// OldestLock is the age of the oldest lock file ("" if none);
	// StaleLock is true when it is older than StaleLockAge.
	OldestLock string
	StaleLock  bool
	LockError  bool
	Password   bool
}

// home is the overview: all known repositories with what can be read
// without their password.
func (s *server) home(w http.ResponseWriter, r *http.Request) {
	list, err := s.Repos.ListRepos(r.Context())
	if err != nil {
		s.Logger.Error("listing repositories", "err", err)
		http.Error(w, "listing repositories failed; see the container log", http.StatusInternalServerError)
		return
	}
	now := time.Now()
	p := page{Title: "Overview", CSRF: sessionFrom(r.Context()).CSRF, Scanning: s.Scanner.Scanning()}
	for _, repo := range list {
		row := repoRow{
			Path:     repo.Path,
			Owner:    repos.Owner(repo.Path),
			Missing:  repo.Missing,
			Password: s.Vault.Has(vault.RepoSecret(repo.Path)),
		}
		if repo.Usage != nil {
			row.Size = formatBytes(repo.Usage.Bytes)
			row.Files = repo.Usage.Files
			row.Measured = repo.UsageTime.In(s.Location).Format("2006-01-02 15:04")
		}
		if !repo.Missing {
			s.addLocks(&row, now)
		}
		p.Repos = append(p.Repos, row)
	}
	s.render(w, http.StatusOK, "home.html", p)
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
