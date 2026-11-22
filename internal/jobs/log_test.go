package jobs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRedactor(t *testing.T) {
	var out bytes.Buffer
	r := &redactor{w: &out, secret: []byte("s3cret")}
	for _, p := range []string{"a s3", "cret b\nc s3cret", "\npartial s3c", "ret"} {
		_, _ = r.Write([]byte(p))
	}
	_ = r.Close()
	want := "a [redacted] b\nc [redacted]\npartial [redacted]"
	if out.String() != want {
		t.Errorf("got %q, want %q", out.String(), want)
	}
}

func TestCleanLogs(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	old := now.Add(-48 * time.Hour)
	for name, mtime := range map[string]time.Time{"1.log": old, "2.log": now, "notes.txt": old, "x.log": old} {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte("x"), 0o600)
		_ = os.Chtimes(p, mtime, mtime)
	}
	n, err := CleanLogs(dir, 24*time.Hour, now)
	if err != nil || n != 1 {
		t.Fatalf("removed %d, %v", n, err)
	}
	for name, want := range map[string]bool{"1.log": false, "2.log": true, "notes.txt": true, "x.log": true} {
		_, err := os.Stat(filepath.Join(dir, name))
		if (err == nil) != want {
			t.Errorf("%s exists = %v", name, err == nil)
		}
	}
	if n, err := CleanLogs(filepath.Join(dir, "missing"), time.Hour, now); n != 0 || err != nil {
		t.Errorf("missing dir: %d %v", n, err)
	}
}
