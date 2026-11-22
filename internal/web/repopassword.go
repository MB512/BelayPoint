package web

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/MB512/belaypoint/internal/repos"
	"github.com/MB512/belaypoint/internal/restic"
	"github.com/MB512/belaypoint/internal/store"
	"github.com/MB512/belaypoint/internal/vault"
)

// Restic is the part of restic.Runner the handlers use.
type Restic interface {
	CatConfig(ctx context.Context, dir string, password []byte) error
}

// CheckTimeout bounds the password check with "restic cat config".
const CheckTimeout = 2 * time.Minute

// repoPasswordData is the data of the repository password page.
type repoPasswordData struct {
	Path   string
	Owner  string
	Stored bool
	// Available is false when restic is not installed.
	Available bool
}

// knownRepo resolves path to its directory, only for a repository that
// discovery found and that is present (CLAUDE.md: never a free-form path).
func (s *server) knownRepo(ctx context.Context, path string) (string, bool) {
	list, err := s.Repos.ListRepos(ctx)
	if err != nil {
		s.Logger.Error("listing repositories", "err", err)
		return "", false
	}
	if !slices.ContainsFunc(list, func(r store.Repo) bool { return r.Path == path && !r.Missing }) {
		return "", false
	}
	dir, err := repos.Dir(s.ReposDir, path)
	if err != nil {
		s.Logger.Warn("repository", "repo", path, "err", err)
		return "", false
	}
	return dir, true
}

func (s *server) repoPasswordPage(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("repo")
	if _, ok := s.knownRepo(r.Context(), path); !ok {
		http.NotFound(w, r)
		return
	}
	s.renderRepoPassword(w, r, http.StatusOK, path, "")
}

func (s *server) renderRepoPassword(w http.ResponseWriter, r *http.Request, status int, path, errMsg string) {
	s.render(w, status, "repo-password.html", page{
		Title: "Repository password", CSRF: sessionFrom(r.Context()).CSRF, Error: errMsg,
		RepoPassword: &repoPasswordData{
			Path: path, Owner: repos.Owner(path),
			Stored:    s.Vault.Has(vault.RepoSecret(path)),
			Available: s.Restic != nil,
		},
	})
}

// setRepoPassword checks the password with restic and stores it in the
// vault. Like restic with --password-file, leading and trailing whitespace
// is removed (issue #3).
func (s *server) setRepoPassword(w http.ResponseWriter, r *http.Request) {
	f, ok := s.postForm(w, r)
	if !ok {
		return
	}
	defer f.wipe()
	path := f.get("repo")
	dir, ok := s.knownRepo(r.Context(), path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if s.Restic == nil {
		s.renderRepoPassword(w, r, http.StatusServiceUnavailable, path, "restic is not available; see the container log.")
		return
	}
	// TrimSpace returns a sub-slice of the form value, no copy; f.wipe
	// zeroes it.
	pw := bytes.TrimSpace(f["password"])
	if len(pw) == 0 {
		s.renderRepoPassword(w, r, http.StatusBadRequest, path, "Enter the password.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), CheckTimeout)
	defer cancel()
	if err := s.Restic.CatConfig(ctx, dir, pw); err != nil {
		if errors.Is(err, restic.ErrWrongPassword) {
			s.Audit.Audit(r.Context(), "repository password rejected", path+", "+remote(r))
			s.renderRepoPassword(w, r, http.StatusBadRequest, path, "restic does not accept this password for the repository.")
			return
		}
		s.Logger.Error("checking repository password", "repo", path, "err", err)
		s.renderRepoPassword(w, r, http.StatusBadGateway, path, "Checking the password failed: "+err.Error())
		return
	}
	if err := s.Vault.SetSecret(vault.RepoSecret(path), pw); err != nil {
		s.Logger.Error("storing repository password", "repo", path, "err", err)
		s.renderRepoPassword(w, r, http.StatusInternalServerError, path, "Storing the password failed; see the container log.")
		return
	}
	s.Audit.Audit(r.Context(), "repository password set", path+", "+remote(r))
	redirect(w, r, "/")
}

// forgetRepoPassword removes the stored password. Backups are not
// affected; only BelayPoint loses access.
func (s *server) forgetRepoPassword(w http.ResponseWriter, r *http.Request) {
	f, ok := s.postForm(w, r)
	if !ok {
		return
	}
	defer f.wipe()
	path := f.get("repo")
	if f.get("confirm") != "yes" {
		http.Error(w, "not confirmed", http.StatusBadRequest)
		return
	}
	// A missing repository may still have a stored password, so only the
	// name is checked here, not presence.
	if !s.Vault.Has(vault.RepoSecret(path)) {
		http.NotFound(w, r)
		return
	}
	if err := s.Vault.DeleteSecret(vault.RepoSecret(path)); err != nil {
		s.Logger.Error("removing repository password", "repo", path, "err", err)
		http.Error(w, "removing the password failed; see the container log", http.StatusInternalServerError)
		return
	}
	s.Audit.Audit(r.Context(), "repository password removed", path+", "+remote(r))
	redirect(w, r, "/")
}
