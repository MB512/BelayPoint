package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWrite(t *testing.T) {
	tests := []struct {
		name     string
		existing []byte
		mode     os.FileMode
	}{
		{name: "new file", mode: 0o600},
		{name: "replace existing", existing: []byte("old content that is longer"), mode: 0o640},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "file")
			if tt.existing != nil {
				if err := os.WriteFile(path, tt.existing, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := Write(path, []byte("new"), tt.mode); err != nil {
				t.Fatalf("Write: %v", err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "new" {
				t.Errorf("content = %q, want %q", got, "new")
			}
			st, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if st.Mode().Perm() != tt.mode {
				t.Errorf("mode = %v, want %v", st.Mode().Perm(), tt.mode)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 {
				t.Errorf("directory has %d entries, want 1 (temp file left behind?)", len(entries))
			}
		})
	}
}

func TestWriteMissingDir(t *testing.T) {
	if err := Write(filepath.Join(t.TempDir(), "missing", "file"), []byte("x"), 0o600); err == nil {
		t.Fatal("Write into a missing directory succeeded")
	}
}
