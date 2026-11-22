package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
)

// testKDF keeps key derivation fast; the real parameters need 64 MiB and
// about a second per derivation under -race.
var testKDF = KDFParams{Time: 1, MemoryKiB: 64, Threads: 1}

func newTestVault(t *testing.T) (*Vault, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.json")
	v, err := openFile(path, testKDF)
	if err != nil {
		t.Fatal(err)
	}
	return v, path
}

func reopen(t *testing.T, path string) *Vault {
	t.Helper()
	v, err := openFile(path, testKDF)
	if err != nil {
		t.Fatalf("reopening: %v", err)
	}
	return v
}

func pw(s string) []byte { return []byte(s) }

func TestNotInitialized(t *testing.T) {
	v, path := newTestVault(t)
	if v.Initialized() {
		t.Error("Initialized() = true for missing file")
	}
	if !v.Sealed() {
		t.Error("Sealed() = false")
	}
	if err := v.Unseal(pw("x")); !errors.Is(err, ErrNotInitialized) {
		t.Errorf("Unseal: %v, want ErrNotInitialized", err)
	}
	if err := v.ChangePassword(pw("x"), pw("y")); !errors.Is(err, ErrNotInitialized) {
		t.Errorf("ChangePassword: %v, want ErrNotInitialized", err)
	}
	if v.Has("a") || v.Names() != nil {
		t.Error("uninitialized vault reports secrets")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("file created without Create: %v", err)
	}
}

func TestCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "vault.json")
	v, err := openFile(path, testKDF)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Create(nil); !errors.Is(err, ErrEmptyPassword) {
		t.Errorf("Create(empty): %v, want ErrEmptyPassword", err)
	}
	if err := v.Create(pw("admin")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !v.Initialized() || v.Sealed() {
		t.Errorf("after Create: Initialized=%v Sealed=%v, want true/false", v.Initialized(), v.Sealed())
	}
	if err := v.Create(pw("other")); !errors.Is(err, ErrInitialized) {
		t.Errorf("second Create: %v, want ErrInitialized", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != fileMode {
		t.Errorf("file mode %v, want %v", st.Mode().Perm(), os.FileMode(fileMode))
	}
	// A second process (restart) must not create over an existing file.
	if err := reopen(t, path).Create(pw("other")); !errors.Is(err, ErrInitialized) {
		t.Errorf("Create on reopened vault: %v, want ErrInitialized", err)
	}
}

func TestUnseal(t *testing.T) {
	v, path := newTestVault(t)
	if err := v.Create(pw("correct horse")); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		password string
		wantErr  error
	}{
		{"correct", "correct horse", nil},
		{"wrong", "correct horse!", ErrWrongPassword},
		{"empty", "", ErrWrongPassword},
		{"whitespace is significant", " correct horse", ErrWrongPassword},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := reopen(t, path)
			if !v.Sealed() {
				t.Fatal("reopened vault is not sealed")
			}
			err := v.Unseal(pw(tt.password))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Unseal: %v, want %v", err, tt.wantErr)
			}
			if v.Sealed() != (tt.wantErr != nil) {
				t.Errorf("Sealed() = %v after Unseal error %v", v.Sealed(), err)
			}
		})
	}
}

func TestWrongPasswordKeepsUnsealed(t *testing.T) {
	// A failed login while unsealed (second browser) must not seal.
	v, _ := newTestVault(t)
	if err := v.Create(pw("admin")); err != nil {
		t.Fatal(err)
	}
	if err := v.Unseal(pw("nope")); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("Unseal: %v", err)
	}
	if v.Sealed() {
		t.Error("failed Unseal sealed the vault")
	}
}

func TestSecrets(t *testing.T) {
	v, path := newTestVault(t)
	if err := v.Create(pw("admin")); err != nil {
		t.Fatal(err)
	}
	a, b := RepoSecret("alice/main"), RepoSecret("bob/main")
	if err := v.SetSecret(a, pw("secret-a")); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret(b, pw("secret-b")); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret(a, pw("secret-a2")); err != nil { // replace
		t.Fatal(err)
	}
	if err := v.SetSecret("", pw("x")); err == nil {
		t.Error("SetSecret with empty name succeeded")
	}
	if err := v.SetSecret(checkName, pw("x")); err == nil {
		t.Error("SetSecret with the key check's name succeeded")
	}

	got, err := v.Secret(a)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret-a2" {
		t.Errorf("Secret(a) = %q", got)
	}
	clear(got) // the caller's copy; must not affect the vault
	if again, _ := v.Secret(a); string(again) != "secret-a2" {
		t.Errorf("Secret(a) after clearing the returned copy = %q", again)
	}
	if _, err := v.Secret("repo:missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Secret(missing): %v, want ErrNotFound", err)
	}

	// Secrets survive a restart, and the file never holds them in clear.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("secret-")) || bytes.Contains(data, []byte(checkText)) {
		t.Error("vault file contains plaintext")
	}
	r := reopen(t, path)
	if !r.Has(a) || !r.Has(b) || r.Has(TOTPSecret) {
		t.Errorf("Has while sealed: a=%v b=%v totp=%v", r.Has(a), r.Has(b), r.Has(TOTPSecret))
	}
	if want := []string{a, b}; !slices.Equal(r.Names(), want) {
		t.Errorf("Names() = %v, want %v", r.Names(), want)
	}
	if _, err := r.Secret(a); !errors.Is(err, ErrSealed) {
		t.Errorf("Secret while sealed: %v, want ErrSealed", err)
	}
	if err := r.SetSecret(a, pw("x")); !errors.Is(err, ErrSealed) {
		t.Errorf("SetSecret while sealed: %v, want ErrSealed", err)
	}
	if err := r.DeleteSecret(a); !errors.Is(err, ErrSealed) {
		t.Errorf("DeleteSecret while sealed: %v, want ErrSealed", err)
	}
	if err := r.Unseal(pw("admin")); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.Secret(b); string(got) != "secret-b" {
		t.Errorf("Secret(b) after restart = %q", got)
	}

	if err := r.DeleteSecret(a); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteSecret(a); err != nil {
		t.Errorf("deleting a missing secret: %v", err)
	}
	if reopen(t, path).Has(a) {
		t.Error("deleted secret still in file")
	}
}

func TestSealZeroesKey(t *testing.T) {
	v, _ := newTestVault(t)
	if err := v.Create(pw("admin")); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret(TOTPSecret, pw("totp")); err != nil {
		t.Fatal(err)
	}
	key := v.key // same backing array
	v.Seal()
	if !v.Sealed() {
		t.Fatal("not sealed")
	}
	if !bytes.Equal(key, make([]byte, keyLen)) {
		t.Error("key not zeroed on seal")
	}
	if _, err := v.Secret(TOTPSecret); !errors.Is(err, ErrSealed) {
		t.Errorf("Secret after Seal: %v, want ErrSealed", err)
	}
	v.Seal() // sealing twice is fine
}

func TestSecretHandedOutBeforeSeal(t *testing.T) {
	// A running job keeps the copy it got; the next one gets ErrSealed.
	v, _ := newTestVault(t)
	if err := v.Create(pw("admin")); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret(RepoSecret("r"), pw("repo-pw")); err != nil {
		t.Fatal(err)
	}
	running, err := v.Secret(RepoSecret("r"))
	if err != nil {
		t.Fatal(err)
	}
	v.Seal()
	if string(running) != "repo-pw" {
		t.Errorf("running job's copy changed by Seal: %q", running)
	}
	if _, err := v.Secret(RepoSecret("r")); !errors.Is(err, ErrSealed) {
		t.Errorf("next job: %v, want ErrSealed", err)
	}
}

func TestChangePassword(t *testing.T) {
	v, path := newTestVault(t)
	if err := v.Create(pw("old")); err != nil {
		t.Fatal(err)
	}
	if err := v.SetSecret(RepoSecret("r"), pw("repo-pw")); err != nil {
		t.Fatal(err)
	}
	oldSalt := slices.Clone(v.file.Salt)

	if err := v.ChangePassword(pw("wrong"), pw("new")); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("wrong old password: %v, want ErrWrongPassword", err)
	}
	if err := v.ChangePassword(pw("old"), nil); !errors.Is(err, ErrEmptyPassword) {
		t.Errorf("empty new password: %v, want ErrEmptyPassword", err)
	}
	v.Seal() // also works while sealed, and unseals
	if err := v.ChangePassword(pw("old"), pw("new")); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if v.Sealed() {
		t.Error("sealed after ChangePassword")
	}
	if bytes.Equal(v.file.Salt, oldSalt) {
		t.Error("salt not replaced")
	}
	if got, _ := v.Secret(RepoSecret("r")); string(got) != "repo-pw" {
		t.Errorf("secret after change in memory = %q", got)
	}

	r := reopen(t, path)
	if err := r.Unseal(pw("old")); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("old password after change: %v, want ErrWrongPassword", err)
	}
	if err := r.Unseal(pw("new")); err != nil {
		t.Fatalf("new password: %v", err)
	}
	if got, _ := r.Secret(RepoSecret("r")); string(got) != "repo-pw" {
		t.Errorf("secret after change from file = %q", got)
	}
}

// editFile applies change to the JSON of the vault file.
func editFile(t *testing.T, path string, change func(f *fileFormat)) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f fileFormat
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	change(&f)
	data, err = json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSwappedSecretsAreRejected(t *testing.T) {
	// Someone with write access to /config copies the sealed password of
	// one repository onto another; GCM's associated data detects it.
	v, path := newTestVault(t)
	if err := v.Create(pw("admin")); err != nil {
		t.Fatal(err)
	}
	a, b := RepoSecret("a"), RepoSecret("b")
	_ = v.SetSecret(a, pw("pw-a"))
	_ = v.SetSecret(b, pw("pw-b"))
	editFile(t, path, func(f *fileFormat) { f.Secrets[a], f.Secrets[b] = f.Secrets[b], f.Secrets[a] })

	r := reopen(t, path)
	if err := r.Unseal(pw("admin")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{a, b} {
		if got, err := r.Secret(name); err == nil {
			t.Errorf("Secret(%s) after swap = %q, want error", name, got)
		}
	}
}

func TestOpenRejectsBadFiles(t *testing.T) {
	valid := func(t *testing.T) string {
		v, path := newTestVault(t)
		if err := v.Create(pw("admin")); err != nil {
			t.Fatal(err)
		}
		return path
	}
	tests := []struct {
		name   string
		change func(f *fileFormat)
		raw    string
	}{
		{name: "not JSON", raw: "{"},
		{name: "empty file", raw: ""},
		{name: "unknown version", change: func(f *fileFormat) { f.Version = 2 }},
		{name: "huge memory", change: func(f *fileFormat) { f.KDF.MemoryKiB = 4 * 1024 * 1024 }},
		{name: "many iterations", change: func(f *fileFormat) { f.KDF.Time = 1000 }},
		{name: "zero threads", change: func(f *fileFormat) { f.KDF.Threads = 0 }},
		{name: "short salt", change: func(f *fileFormat) { f.Salt = f.Salt[:4] }},
		{name: "no key check", change: func(f *fileFormat) { f.Check = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := valid(t)
			if tt.change != nil {
				editFile(t, path, tt.change)
			} else if err := os.WriteFile(path, []byte(tt.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(path)
			if _, err := openFile(path, testKDF); err == nil {
				t.Fatal("Open succeeded")
			}
			if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
				t.Error("bad file was modified")
			}
		})
	}
}

func TestTamperedKeyCheck(t *testing.T) {
	v, path := newTestVault(t)
	if err := v.Create(pw("admin")); err != nil {
		t.Fatal(err)
	}
	editFile(t, path, func(f *fileFormat) { f.Check[len(f.Check)-1] ^= 1 })
	if err := reopen(t, path).Unseal(pw("admin")); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("Unseal with tampered check: %v, want ErrWrongPassword", err)
	}
}

func TestConcurrentUse(t *testing.T) {
	v, _ := newTestVault(t)
	if err := v.Create(pw("admin")); err != nil {
		t.Fatal(err)
	}
	// sync.WaitGroup.Go starts a goroutine and tracks it, like collecting
	// Tasks for Task.WhenAll in C#.
	var wg sync.WaitGroup
	for i := range 8 {
		name := RepoSecret(fmt.Sprint(i))
		wg.Go(func() {
			if err := v.SetSecret(name, pw(name)); err != nil {
				t.Error(err)
				return
			}
			got, err := v.Secret(name)
			if err != nil || string(got) != name {
				t.Errorf("Secret(%s) = %q, %v", name, got, err)
			}
		})
		wg.Go(func() { _ = v.Unseal(pw("admin")) })
		wg.Go(func() { _ = v.Sealed(); _ = v.Names() })
	}
	wg.Wait()
	if n := len(v.Names()); n != 8 {
		t.Errorf("%d secrets, want 8", n)
	}
}

func TestOpenUsesDefaultKDF(t *testing.T) {
	v, err := Open(filepath.Join(t.TempDir(), "vault.json"))
	if err != nil {
		t.Fatal(err)
	}
	if v.kdf != DefaultKDF {
		t.Errorf("kdf = %+v, want %+v", v.kdf, DefaultKDF)
	}
	if DefaultKDF.MemoryKiB != 64*1024 || DefaultKDF.Time != 3 || DefaultKDF.Threads != 2 {
		t.Errorf("DefaultKDF %+v differs from docs/security.md (m=64 MiB, t=3, p=2)", DefaultKDF)
	}
}
