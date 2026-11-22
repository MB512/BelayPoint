package repos

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// makeRepo creates restic's layout at root/rel with one data file of size
// bytes.
func makeRepo(t *testing.T, root, rel string, size int) string {
	t.Helper()
	dir := filepath.Join(root, filepath.FromSlash(rel))
	for _, d := range requiredDirs {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, configFile), []byte("cfg"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "data", "ab"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data", "ab", "abcd"), make([]byte, size), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDiscover(t *testing.T) {
	root := t.TempDir()
	makeRepo(t, root, "alice", 1)             // depth 1: user dir is the repo
	makeRepo(t, root, "bob/main", 1)          // depth 2
	makeRepo(t, root, "bob/main/nested", 1)   // inside a repo: not searched
	makeRepo(t, root, "carol/x/deep", 1)      // depth 3
	makeRepo(t, root, "dave/a/b/too-deep", 1) // depth 4: not found
	makeRepo(t, root, ".hidden/repo", 1)      // hidden: skipped
	makeRepo(t, root, "erin/.trash", 1)       // hidden: skipped
	makeRepo(t, t.TempDir(), "outside", 1)    // target of a symlink below
	if err := os.Symlink(filepath.Join(root, "bob", "main"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	// Incomplete layouts are not repositories.
	incomplete := makeRepo(t, root, "frank/broken", 1)
	if err := os.RemoveAll(filepath.Join(incomplete, "keys")); err != nil {
		t.Fatal(err)
	}
	cfgDir := makeRepo(t, root, "gina/cfgdir", 1)
	_ = os.Remove(filepath.Join(cfgDir, configFile))
	_ = os.Mkdir(filepath.Join(cfgDir, configFile), 0o755)
	// A symlinked "data" dir does not count either.
	symData := makeRepo(t, root, "hank/symdata", 1)
	_ = os.RemoveAll(filepath.Join(symData, "data"))
	_ = os.Symlink(t.TempDir(), filepath.Join(symData, "data"))
	// Plain files at any level are ignored.
	_ = os.WriteFile(filepath.Join(root, ".htpasswd"), []byte("x"), 0o600)

	found, skipped, err := Discover(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"alice", "bob/main", "carol/x/deep"}
	if !slices.Equal(found, want) {
		t.Errorf("found %v, want %v", found, want)
	}
	if len(skipped) != 0 {
		t.Errorf("skipped %v", skipped)
	}
}

func TestDiscoverUnreadableDir(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores permissions")
	}
	root := t.TempDir()
	makeRepo(t, root, "ok/repo", 1)
	locked := filepath.Join(root, "locked")
	if err := os.Mkdir(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	found, skipped, err := Discover(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(found, []string{"ok/repo"}) || len(skipped) != 1 {
		t.Errorf("found %v, skipped %v", found, skipped)
	}
}

func TestDiscoverMissingRoot(t *testing.T) {
	if _, _, err := Discover(context.Background(), filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("no error for missing root")
	}
}

func TestDir(t *testing.T) {
	root := t.TempDir()
	makeRepo(t, root, "bob/main", 1)
	outside := makeRepo(t, t.TempDir(), "evil", 1)
	if err := os.Symlink(outside, filepath.Join(root, "bob", "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "bob"), filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(root, "file"), nil, 0o644)

	if got, err := Dir(root, "bob/main"); err != nil || got != filepath.Join(root, "bob", "main") {
		t.Errorf("Dir(bob/main) = %q, %v", got, err)
	}
	bad := []string{"", ".", "/etc", "../x", "bob/../bob/main", "bob/./main", "bob//main", "bob/main/",
		"bob/link", "alias/main", "file", ".htpasswd", "bob\\main", "bob/missing"}
	for _, rel := range bad {
		if got, err := Dir(root, rel); err == nil {
			t.Errorf("Dir(%q) = %q, want error", rel, got)
		}
	}
	if _, err := Dir(root, "bob/link"); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("symlink: %v, want ErrInvalidPath", err)
	}
}

func TestOwner(t *testing.T) {
	for rel, want := range map[string]string{"alice": "alice", "bob/main": "bob", "carol/x/deep": "carol"} {
		if got := Owner(rel); got != want {
			t.Errorf("Owner(%q) = %q, want %q", rel, got, want)
		}
	}
}

func TestDiskUsage(t *testing.T) {
	root := t.TempDir()
	dir := makeRepo(t, root, "r", 1000)
	_ = os.Symlink("/etc/passwd", filepath.Join(dir, "data", "link")) // not followed
	u, err := DiskUsage(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if u.Bytes != 1000+3 || u.Files != 2 {
		t.Errorf("usage %+v, want 1003 bytes in 2 files", u)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DiskUsage(ctx, dir); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}

func TestLocks(t *testing.T) {
	dir := makeRepo(t, t.TempDir(), "r", 1)
	old := time.Now().Add(-48 * time.Hour)
	for name, mt := range map[string]time.Time{"newlock": time.Now(), "oldlock": old} {
		p := filepath.Join(dir, "locks", name)
		_ = os.WriteFile(p, []byte("x"), 0o644)
		_ = os.Chtimes(p, mt, mt)
	}
	_ = os.Mkdir(filepath.Join(dir, "locks", "subdir"), 0o755)
	locks, err := Locks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(locks) != 2 || locks[0].Name != "oldlock" || locks[1].Name != "newlock" {
		t.Errorf("locks %+v", locks)
	}
	if _, err := Locks(t.TempDir()); err == nil || !strings.Contains(err.Error(), "locks") {
		t.Errorf("missing locks dir: %v", err)
	}
}

// memStore records what the scanner reports.
type memStore struct {
	synced []string
	usage  map[string]Usage
}

func (m *memStore) SyncRepos(_ context.Context, paths []string) error {
	m.synced = paths
	return nil
}

func (m *memStore) SetRepoUsage(_ context.Context, path string, u Usage, _ time.Time) error {
	m.usage[path] = u
	return nil
}

func TestScanner(t *testing.T) {
	root := t.TempDir()
	makeRepo(t, root, "a/one", 10)
	makeRepo(t, root, "b/two", 20)
	st := &memStore{usage: map[string]Usage{}}
	s := &Scanner{Root: root, Store: st, Logger: discardLogger(), Now: time.Now}
	if !s.Start(context.Background()) {
		t.Fatal("Start refused")
	}
	s.Wait()
	if s.Running() {
		t.Error("Running after Wait")
	}
	if !slices.Equal(st.synced, []string{"a/one", "b/two"}) {
		t.Errorf("synced %v", st.synced)
	}
	if st.usage["a/one"].Bytes != 13 || st.usage["b/two"].Bytes != 23 {
		t.Errorf("usage %v", st.usage)
	}
}

func TestFSStat(t *testing.T) {
	u, err := FSStat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if u.Total <= 0 || u.Free < 0 || u.Free > u.Total || u.Avail > u.Free || u.Used() != u.Total-u.Free {
		t.Errorf("usage = %+v", u)
	}
}
