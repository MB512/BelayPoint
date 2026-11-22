// Package atomicfile replaces files so that readers see either the old or
// the new content, never a partial write, even after a crash.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write replaces path with data: it writes a temp file in the same
// directory, fsyncs it, renames it over path and fsyncs the directory, so
// the rename itself is durable. mode is applied to the new file.
//
// The temp file lives in the same directory because rename is only atomic
// within one file system. If the target is a single-file bind mount, the
// rename fails or the mount keeps the old inode; mount the directory instead.
func Write(path string, data []byte, mode os.FileMode) error {
	if err := write(path, data, mode); err != nil {
		return fmt.Errorf("writing %s: %w", filepath.Base(path), err)
	}
	return nil
}

func write(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	ok := false
	// The deferred func runs when write returns (like a finally block in
	// C#): it removes the temp file unless the rename succeeded.
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	ok = true
	return syncDir(dir)
}

// syncDir makes a rename in dir durable.
func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // G304: dir is the caller's own target directory
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
