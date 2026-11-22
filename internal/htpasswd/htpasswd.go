// Package htpasswd reads and changes the rest-server's .htpasswd file (see
// "Users" in docs/architecture.md and rule 11 in docs/security.md).
//
// The file is re-read before every change; a file that cannot be parsed is
// never overwritten. Lines that are not user entries (comments, blank
// lines) are kept as they are. New hashes are bcrypt.
package htpasswd

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"

	"github.com/MB512/belaypoint/internal/atomicfile"
)

// Password limits for passwords entered by hand. bcrypt uses at most 72
// bytes.
const (
	MinPasswordLen = 12
	MaxPasswordLen = 72
)

// BcryptCost is the bcrypt work factor of new hashes. The rest-server
// verifies the hash on requests (with a short cache), so the NAS CPU sets
// the limit; generated passwords have 160 bits of entropy anyway.
const BcryptCost = 10

// FileMode is used for a new file; an existing file keeps its mode, at
// most 0640.
const FileMode = 0o640

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ValidName reports whether name is allowed for new users.
func ValidName(name string) bool { return nameRe.MatchString(name) }

// Errors.
var (
	ErrExists   = errors.New("user already exists")
	ErrNotFound = errors.New("user not found")
	ErrName     = errors.New("invalid user name: use lowercase letters, digits, '.', '_' and '-' (max. 64, starting with a letter or digit)")
	ErrPassword = fmt.Errorf("password must have %d to %d bytes", MinPasswordLen, MaxPasswordLen)
)

// User is one entry of the file.
type User struct {
	Name string
	// Scheme is "bcrypt" or a short description of another hash type.
	Scheme string
}

// line is one line of the file: a user entry (name != "") or something
// kept verbatim.
type line struct {
	name, hash string
	raw        string
}

// content is the parsed file.
type content struct {
	lines []line
}

// parse accepts "name:hash" entries, blank lines and comments ("#").
// Anything else, or a duplicate name, makes the file unparsable.
func parse(data []byte) (*content, error) {
	c := &content{}
	seen := map[string]bool{}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.TrimSuffix(text, "\n")
	if text == "" {
		return c, nil
	}
	for i, l := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(l)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			c.lines = append(c.lines, line{raw: l})
			continue
		}
		name, hash, ok := strings.Cut(l, ":")
		if !ok || name == "" || hash == "" || strings.ContainsAny(name, " \t") || strings.Contains(hash, ":") {
			return nil, fmt.Errorf("line %d: not a \"user:hash\" entry", i+1)
		}
		if seen[name] {
			return nil, fmt.Errorf("line %d: duplicate user %q", i+1, name)
		}
		seen[name] = true
		c.lines = append(c.lines, line{name: name, hash: hash})
	}
	return c, nil
}

func (c *content) bytes() []byte {
	var b bytes.Buffer
	for _, l := range c.lines {
		if l.name != "" {
			b.WriteString(l.name + ":" + l.hash)
		} else {
			b.WriteString(l.raw)
		}
		b.WriteByte('\n')
	}
	return b.Bytes()
}

func (c *content) find(name string) int {
	for i, l := range c.lines {
		if l.name != "" && l.name == name {
			return i
		}
	}
	return -1
}

func (c *content) users() []User {
	var out []User
	for _, l := range c.lines {
		if l.name != "" {
			out = append(out, User{Name: l.name, Scheme: scheme(l.hash)})
		}
	}
	return out
}

func scheme(hash string) string {
	switch {
	case strings.HasPrefix(hash, "$2a$"), strings.HasPrefix(hash, "$2b$"), strings.HasPrefix(hash, "$2y$"):
		return "bcrypt"
	case strings.HasPrefix(hash, "$apr1$"):
		return "MD5 (apr1)"
	case strings.HasPrefix(hash, "{SHA}"):
		return "SHA-1"
	case strings.HasPrefix(hash, "$5$"):
		return "SHA-256 crypt"
	case strings.HasPrefix(hash, "$6$"):
		return "SHA-512 crypt"
	}
	return "unknown"
}

// File is the .htpasswd file. Its methods serialize changes made by this
// process; the file is re-read for every call.
type File struct {
	Path string
	mu   sync.Mutex
}

// read returns the parsed file (empty if it does not exist) and its mode.
func (f *File) read() (*content, fs.FileMode, error) {
	data, err := os.ReadFile(f.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return &content{}, FileMode, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("reading %s: %w", f.Path, err)
	}
	st, err := os.Stat(f.Path)
	if err != nil {
		return nil, 0, fmt.Errorf("reading %s: %w", f.Path, err)
	}
	c, err := parse(data)
	if err != nil {
		return nil, 0, fmt.Errorf("%s cannot be parsed, so it is left unchanged: %w", f.Path, err)
	}
	return c, st.Mode().Perm() & FileMode, nil
}

// Users lists the users in file order.
func (f *File) Users() ([]User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, _, err := f.read()
	if err != nil {
		return nil, err
	}
	return c.users(), nil
}

// change re-reads the file, applies fn and writes the result atomically.
func (f *File) change(fn func(c *content) error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c, mode, err := f.read()
	if err != nil {
		return err
	}
	if err := fn(c); err != nil {
		return err
	}
	return atomicfile.Write(f.Path, c.bytes(), mode)
}

// Add adds a user with password. The caller zeroes password.
func (f *File) Add(name string, password []byte) error {
	if !ValidName(name) {
		return ErrName
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	return f.change(func(c *content) error {
		if c.find(name) >= 0 {
			return fmt.Errorf("%q: %w", name, ErrExists)
		}
		c.lines = append(c.lines, line{name: name, hash: hash})
		return nil
	})
}

// SetPassword replaces the hash of an existing user. The caller zeroes
// password.
func (f *File) SetPassword(name string, password []byte) error {
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	return f.change(func(c *content) error {
		i := c.find(name)
		if i < 0 {
			return fmt.Errorf("%q: %w", name, ErrNotFound)
		}
		c.lines[i].hash = hash
		return nil
	})
}

// Remove deletes a user. Its repositories are not touched.
func (f *File) Remove(name string) error {
	return f.change(func(c *content) error {
		i := c.find(name)
		if i < 0 {
			return fmt.Errorf("%q: %w", name, ErrNotFound)
		}
		c.lines = append(c.lines[:i], c.lines[i+1:]...)
		return nil
	})
}

func hashPassword(password []byte) (string, error) {
	if len(password) < MinPasswordLen || len(password) > MaxPasswordLen {
		return "", ErrPassword
	}
	hash, err := bcrypt.GenerateFromPassword(password, BcryptCost)
	if err != nil {
		return "", fmt.Errorf("hashing password: %w", err)
	}
	return string(hash), nil
}

// GeneratePassword returns a random password of 160 bits (27 characters,
// base64url). The caller zeroes it after showing it once.
func GeneratePassword() ([]byte, error) {
	raw := make([]byte, 20)
	defer clear(raw)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generating password: %w", err)
	}
	out := make([]byte, base64.RawURLEncoding.EncodedLen(len(raw)))
	base64.RawURLEncoding.Encode(out, raw)
	return out, nil
}
