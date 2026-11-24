// Package repos finds restic repositories below the repository root and
// reads what can be read without a password: disk usage and lock files
// (see "Repositories" in docs/architecture.md).
//
// Repository paths come only from Discover. Anything that operates on a
// repository takes a path from that set and resolves it with Dir, which
// re-checks that no component is a symlink or leaves the root.
package repos

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// MaxDepth is how deep below the root repositories are searched: with
// rest-server's --private-repos, "<user>/<repo>" is typical, "<user>" alone
// or one more level also occur.
const MaxDepth = 3

// required are the entries of a restic repository (local layout).
var requiredDirs = []string{"data", "index", "keys", "locks", "snapshots"}

const configFile = "config"

// Discover returns the slash-separated paths, relative to root, of all
// repositories up to MaxDepth levels deep, sorted. Symlinks and hidden
// entries are skipped; a repository's own subdirectories are not searched.
// Unreadable directories are reported in skipped, not as an error.
func Discover(ctx context.Context, root string) (found []string, skipped []error, err error) {
	if _, err := os.ReadDir(root); err != nil {
		return nil, nil, fmt.Errorf("reading repository root: %w", err)
	}
	var walk func(rel string, depth int) error
	walk = func(rel string, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		abs := filepath.Join(root, filepath.FromSlash(rel))
		entries, err := os.ReadDir(abs)
		if err != nil {
			skipped = append(skipped, err)
			return nil
		}
		for _, e := range entries {
			// DirEntry.Type comes from the directory listing (lstat
			// semantics): a symlink to a directory is not IsDir.
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			child := path.Join(rel, e.Name())
			if isRepo(filepath.Join(abs, e.Name())) {
				found = append(found, child)
				continue
			}
			if depth < MaxDepth {
				if err := walk(child, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk("", 1); err != nil {
		return nil, nil, err
	}
	slices.Sort(found)
	return found, skipped, nil
}

// isRepo reports whether dir has restic's layout, without following
// symlinks.
func isRepo(dir string) bool {
	st, err := os.Lstat(filepath.Join(dir, configFile))
	if err != nil || !st.Mode().IsRegular() {
		return false
	}
	for _, d := range requiredDirs {
		st, err := os.Lstat(filepath.Join(dir, d))
		if err != nil || !st.IsDir() {
			return false
		}
	}
	return true
}

// ErrInvalidPath is returned by Dir for paths that are not clean relative
// paths inside the root, or that contain a symlink.
var ErrInvalidPath = errors.New("invalid repository path")

// Dir returns the absolute directory of the repository at rel (a path from
// Discover). It rejects absolute paths, "..", unclean paths and symlinks in
// any component, so the result is always inside root. It does not check
// that rel was discovered; callers look it up in their discovered set
// first.
func Dir(root, rel string) (string, error) {
	if rel == "" || rel == "." || path.IsAbs(rel) || path.Clean(rel) != rel ||
		strings.Contains(rel, "\\") || !fs.ValidPath(rel) {
		return "", fmt.Errorf("%w: %q", ErrInvalidPath, rel)
	}
	cur := root
	for part := range strings.SplitSeq(rel, "/") {
		if part == ".." || strings.HasPrefix(part, ".") {
			return "", fmt.Errorf("%w: %q", ErrInvalidPath, rel)
		}
		cur = filepath.Join(cur, part)
		st, err := os.Lstat(cur)
		if err != nil {
			return "", fmt.Errorf("repository %q: %w", rel, err)
		}
		if !st.IsDir() { // also true for symlinks: Lstat does not follow them
			return "", fmt.Errorf("%w: %q (%s is not a directory)", ErrInvalidPath, rel, part)
		}
	}
	return cur, nil
}

// Owner returns the rest-server user a repository belongs to with
// --private-repos: the first path component.
func Owner(rel string) string {
	owner, _, _ := strings.Cut(rel, "/")
	return owner
}

// Usage is the disk usage of a repository.
type Usage struct {
	Bytes int64
	Files int64
}

// DiskUsage walks the repository directory and sums the sizes of regular
// files. Symlinks are not followed. It can take a while for large
// repositories; ctx cancels it.
func DiskUsage(ctx context.Context, dir string) (Usage, error) {
	var u Usage
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		u.Bytes += info.Size()
		u.Files++
		return nil
	})
	if err != nil {
		return Usage{}, fmt.Errorf("disk usage of %s: %w", dir, err)
	}
	return u, nil
}

// LockFile is a file in the repository's locks directory. Its content is
// encrypted; without the password only name and age are known.
type LockFile struct {
	Name    string
	ModTime time.Time
}

// Locks lists the lock files of the repository at dir, oldest first.
func Locks(dir string) ([]LockFile, error) {
	entries, err := os.ReadDir(filepath.Join(dir, "locks"))
	if err != nil {
		return nil, fmt.Errorf("reading locks: %w", err)
	}
	var out []LockFile
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue // removed meanwhile
		}
		out = append(out, LockFile{Name: e.Name(), ModTime: info.ModTime()})
	}
	slices.SortFunc(out, func(a, b LockFile) int { return a.ModTime.Compare(b.ModTime) })
	return out, nil
}

// SnapshotFiles counts the snapshot files of the repository at dir and
// returns the newest modification time (zero without snapshots). Each
// snapshot is one file, written once when the backup finished, so this
// shows when the repository was last appended to - without the password
// (the contents are encrypted, names and times are not).
func SnapshotFiles(dir string) (count int, newest time.Time, err error) {
	entries, err := os.ReadDir(filepath.Join(dir, "snapshots"))
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("reading snapshots: %w", err)
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue // removed meanwhile (forget)
		}
		count++
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	return count, newest, nil
}

// FSUsage describes the file system holding the repositories, in bytes.
type FSUsage struct {
	Total int64
	Free  int64 // free blocks, including those reserved for root
	Avail int64 // free blocks available to unprivileged users
}

// Used is Total minus Free, as df shows it.
func (u FSUsage) Used() int64 { return u.Total - u.Free }
