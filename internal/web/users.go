package web

import (
	"errors"
	"net/http"
	"slices"

	"github.com/MB512/belaypoint/internal/htpasswd"
	"github.com/MB512/belaypoint/internal/repos"
)

// Users manages the rest-server's users (implemented by *htpasswd.File).
type Users interface {
	Users() ([]htpasswd.User, error)
	Add(name string, password []byte) error
	SetPassword(name string, password []byte) error
	Remove(name string) error
}

type userRow struct {
	Name   string
	Scheme string
	Repos  []string
}

// usersData is the data of the users pages.
type usersData struct {
	Users []userRow
	// Orphans are repositories whose owner (first path component) has
	// no user.
	Orphans []string

	// confirm page
	Action string // "reset" or "remove"
	User   userRow

	// password page: shown once, never stored or logged
	Password string
}

// reposByOwner maps user names to their (present) repositories.
func (s *server) reposByOwner(r *http.Request) (map[string][]string, error) {
	list, err := s.Repos.ListRepos(r.Context())
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, repo := range list {
		if !repo.Missing {
			o := repos.Owner(repo.Path)
			out[o] = append(out[o], repo.Path)
		}
	}
	return out, nil
}

func (s *server) usersPage(w http.ResponseWriter, r *http.Request) {
	s.renderUsers(w, r, http.StatusOK, "")
}

func (s *server) renderUsers(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	p := page{Title: "Users", CSRF: sessionFrom(r.Context()).CSRF, Error: errMsg}
	users, err := s.Users.Users()
	if err != nil {
		s.Logger.Error("reading users", "err", err)
		p.Error = err.Error()
		s.render(w, http.StatusInternalServerError, "users.html", p)
		return
	}
	byOwner, err := s.reposByOwner(r)
	if err != nil {
		s.Logger.Error("listing repositories", "err", err)
	}
	d := &usersData{}
	for _, u := range users {
		d.Users = append(d.Users, userRow{Name: u.Name, Scheme: u.Scheme, Repos: byOwner[u.Name]})
		delete(byOwner, u.Name)
	}
	for _, paths := range byOwner {
		d.Orphans = append(d.Orphans, paths...)
	}
	slices.Sort(d.Orphans)
	p.Users = d
	s.render(w, status, "users.html", p)
}

// addUser adds a user with a generated password, or with the one entered.
func (s *server) addUser(w http.ResponseWriter, r *http.Request) {
	f, ok := s.postForm(w, r)
	if !ok {
		return
	}
	defer f.wipe()
	name := f.get("name")
	pw, generated := f["password"], false
	if len(pw) == 0 {
		var err error
		if pw, err = htpasswd.GeneratePassword(); err != nil {
			s.Logger.Error("generating password", "err", err)
			s.renderUsers(w, r, http.StatusInternalServerError, "Generating a password failed.")
			return
		}
		defer clear(pw)
		generated = true
	}
	if err := s.Users.Add(name, pw); err != nil {
		s.userError(w, r, err)
		return
	}
	how := "password entered"
	if generated {
		how = "password generated"
	}
	s.Audit.Audit(r.Context(), "user added", name+", "+how+", "+remote(r))
	if !generated {
		redirect(w, r, "/users")
		return
	}
	s.showPassword(w, r, name, pw)
}

// confirmUser shows the confirmation page for reset or remove.
func (s *server) confirmUser(action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		users, err := s.Users.Users()
		if err != nil {
			s.renderUsers(w, r, http.StatusInternalServerError, err.Error())
			return
		}
		i := slices.IndexFunc(users, func(u htpasswd.User) bool { return u.Name == name })
		if i < 0 {
			http.NotFound(w, r)
			return
		}
		byOwner, _ := s.reposByOwner(r)
		title := "Reset password"
		if action == "remove" {
			title = "Remove user"
		}
		p := page{Title: title, CSRF: sessionFrom(r.Context()).CSRF, Users: &usersData{
			Action: action,
			User:   userRow{Name: name, Scheme: users[i].Scheme, Repos: byOwner[name]},
		}}
		s.render(w, http.StatusOK, "user-confirm.html", p)
	}
}

// confirmed reads a POST from the confirmation page.
func (s *server) confirmed(w http.ResponseWriter, r *http.Request) (string, bool) {
	f, ok := s.postForm(w, r)
	if !ok {
		return "", false
	}
	defer f.wipe()
	if f.get("confirm") != "yes" {
		http.Error(w, "not confirmed", http.StatusBadRequest)
		return "", false
	}
	return f.get("name"), true
}

func (s *server) resetUser(w http.ResponseWriter, r *http.Request) {
	name, ok := s.confirmed(w, r)
	if !ok {
		return
	}
	pw, err := htpasswd.GeneratePassword()
	if err != nil {
		s.renderUsers(w, r, http.StatusInternalServerError, "Generating a password failed.")
		return
	}
	defer clear(pw)
	if err := s.Users.SetPassword(name, pw); err != nil {
		s.userError(w, r, err)
		return
	}
	s.Audit.Audit(r.Context(), "user password reset", name+", "+remote(r))
	s.showPassword(w, r, name, pw)
}

func (s *server) removeUser(w http.ResponseWriter, r *http.Request) {
	name, ok := s.confirmed(w, r)
	if !ok {
		return
	}
	if err := s.Users.Remove(name); err != nil {
		s.userError(w, r, err)
		return
	}
	s.Audit.Audit(r.Context(), "user removed", name+", "+remote(r))
	redirect(w, r, "/users")
}

// showPassword renders the one-time password page. The password becomes
// part of the response text; it is not stored or logged.
func (s *server) showPassword(w http.ResponseWriter, r *http.Request, name string, pw []byte) {
	p := page{Title: "Password", CSRF: sessionFrom(r.Context()).CSRF, Users: &usersData{
		User:     userRow{Name: name},
		Password: string(pw),
	}}
	s.render(w, http.StatusOK, "user-password.html", p)
}

func (s *server) userError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, htpasswd.ErrExists), errors.Is(err, htpasswd.ErrName), errors.Is(err, htpasswd.ErrPassword):
		s.renderUsers(w, r, http.StatusBadRequest, err.Error())
	case errors.Is(err, htpasswd.ErrNotFound):
		s.renderUsers(w, r, http.StatusNotFound, err.Error())
	default:
		s.Logger.Error("changing users", "err", err)
		s.renderUsers(w, r, http.StatusInternalServerError, err.Error())
	}
}
