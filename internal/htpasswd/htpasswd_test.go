package htpasswd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestValidName(t *testing.T) {
	good := []string{"alice", "a", "0day", "bob.smith", "nas_1", "x-y", strings.Repeat("a", 64)}
	bad := []string{"", "Alice", ".hidden", "-x", "_x", "a b", "a:b", "a/b", "ä", strings.Repeat("a", 65), "../x"}
	for _, n := range good {
		if !ValidName(n) {
			t.Errorf("ValidName(%q) = false", n)
		}
	}
	for _, n := range bad {
		if ValidName(n) {
			t.Errorf("ValidName(%q) = true", n)
		}
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name  string
		data  string
		users []string
		ok    bool
	}{
		{"empty", "", nil, true},
		{"entries", "alice:$2y$10$abc\nbob:{SHA}xyz\n", []string{"alice", "bob"}, true},
		{"comments and blanks", "# managed\n\nalice:$2a$x\n", []string{"alice"}, true},
		{"CRLF", "alice:$2a$x\r\nbob:$2a$y\r\n", []string{"alice", "bob"}, true},
		{"no newline at end", "alice:$2a$x", []string{"alice"}, true},
		{"uppercase name kept", "Alice:$2a$x\n", []string{"Alice"}, true},
		{"no colon", "alice\n", nil, false},
		{"empty hash", "alice:\n", nil, false},
		{"empty name", ":hash\n", nil, false},
		{"extra field", "alice:hash:x\n", nil, false},
		{"space in name", "al ice:hash\n", nil, false},
		{"duplicate", "alice:a\nalice:b\n", nil, false},
		{"binary garbage", "\x00\x01\x02\n", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := parse([]byte(tt.data))
			if (err == nil) != tt.ok {
				t.Fatalf("err = %v, want ok=%v", err, tt.ok)
			}
			if !tt.ok {
				return
			}
			var names []string
			for _, u := range c.users() {
				names = append(names, u.Name)
			}
			if strings.Join(names, ",") != strings.Join(tt.users, ",") {
				t.Errorf("users %v, want %v", names, tt.users)
			}
		})
	}
}

func newFile(t *testing.T, content string, mode os.FileMode) *File {
	t.Helper()
	p := filepath.Join(t.TempDir(), ".htpasswd")
	if content != "" {
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	return &File{Path: p}
}

func read(t *testing.T, f *File) string {
	t.Helper()
	b, err := os.ReadFile(f.Path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func hashOf(t *testing.T, f *File, name string) string {
	t.Helper()
	for _, l := range strings.Split(read(t, f), "\n") {
		if n, h, _ := strings.Cut(l, ":"); n == name {
			return h
		}
	}
	t.Fatalf("user %q not in file", name)
	return ""
}

func TestAddSetRemove(t *testing.T) {
	f := newFile(t, "# keep me\nlegacy:{SHA}abc=\n", 0o644)
	pw := []byte("a long password")
	if err := f.Add("alice", pw); err != nil {
		t.Fatal(err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hashOf(t, f, "alice")), pw); err != nil {
		t.Errorf("stored hash does not match: %v", err)
	}
	if err := f.Add("alice", pw); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate Add: %v", err)
	}
	if err := f.Add("Bad Name", pw); !errors.Is(err, ErrName) {
		t.Errorf("bad name: %v", err)
	}
	for _, p := range []string{"short", strings.Repeat("x", 73)} {
		if err := f.Add("bob", []byte(p)); !errors.Is(err, ErrPassword) {
			t.Errorf("password of %d bytes: %v", len(p), err)
		}
	}

	users, err := f.Users()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || users[0] != (User{"legacy", "SHA-1"}) || users[1] != (User{"alice", "bcrypt"}) {
		t.Errorf("users %+v", users)
	}

	old := hashOf(t, f, "alice")
	newPW := []byte("another long password")
	if err := f.SetPassword("alice", newPW); err != nil {
		t.Fatal(err)
	}
	if h := hashOf(t, f, "alice"); h == old || bcrypt.CompareHashAndPassword([]byte(h), newPW) != nil {
		t.Error("password not replaced")
	}
	if err := f.SetPassword("nobody", newPW); !errors.Is(err, ErrNotFound) {
		t.Errorf("SetPassword(nobody): %v", err)
	}

	if err := f.Remove("legacy"); err != nil {
		t.Fatal(err)
	}
	if err := f.Remove("legacy"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Remove: %v", err)
	}
	got := read(t, f)
	if !strings.HasPrefix(got, "# keep me\nalice:$2a$") || strings.Contains(got, "legacy") {
		t.Errorf("file:\n%s", got)
	}
	st, _ := os.Stat(f.Path)
	if st.Mode().Perm() != 0o640 {
		t.Errorf("mode %v, want 0640 (0644 reduced)", st.Mode().Perm())
	}
}

func TestStricterModeKept(t *testing.T) {
	f := newFile(t, "alice:$2a$x\n", 0o600)
	if err := f.Remove("alice"); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(f.Path)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", st.Mode().Perm())
	}
}

func TestMissingFileCreated(t *testing.T) {
	f := newFile(t, "", 0)
	if users, err := f.Users(); err != nil || len(users) != 0 {
		t.Fatalf("Users of missing file: %v, %v", users, err)
	}
	if err := f.Add("alice", []byte("a long password")); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(f.Path)
	if err != nil || st.Mode().Perm() != FileMode {
		t.Errorf("new file: %v, %v", st, err)
	}
}

func TestUnparsableFileUntouched(t *testing.T) {
	const broken = "alice:$2a$x\nthis is not an entry\n"
	f := newFile(t, broken, 0o640)
	if _, err := f.Users(); err == nil {
		t.Error("Users succeeded")
	}
	ops := map[string]func() error{
		"Add":         func() error { return f.Add("bob", []byte("a long password")) },
		"SetPassword": func() error { return f.SetPassword("alice", []byte("a long password")) },
		"Remove":      func() error { return f.Remove("alice") },
	}
	for name, op := range ops {
		if err := op(); err == nil || !strings.Contains(err.Error(), "left unchanged") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if got := read(t, f); got != broken {
		t.Errorf("file changed:\n%s", got)
	}
}

func TestGeneratePassword(t *testing.T) {
	a, err := GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GeneratePassword()
	if len(a) != 27 || string(a) == string(b) {
		t.Errorf("passwords %q %q", a, b)
	}
	if len(a) < MinPasswordLen || len(a) > MaxPasswordLen {
		t.Error("generated password outside the allowed length")
	}
}
