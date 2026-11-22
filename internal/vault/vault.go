// Package vault stores BelayPoint's secrets (repository passwords, the TOTP
// secret) encrypted in one file (see "Vault and sealed state" in
// docs/architecture.md).
//
// The vault key is derived from the admin password with argon2id and exists
// only in memory. While the key is not in memory the vault is sealed: the
// file can be read but no secret can be decrypted. There is no stored
// password hash; a password is correct if the derived key opens the key
// check.
//
// Secrets are AES-256-GCM sealed one by one, with the secret's name as
// associated data, so a sealed value cannot be moved to another name (e.g.
// another repository) without failing authentication.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"

	"github.com/MB512/belaypoint/internal/atomicfile"
)

// Errors returned by the vault. Callers compare with errors.Is (the Go
// counterpart of catching a specific exception type in C#).
var (
	ErrNotInitialized = errors.New("vault not initialized")
	ErrInitialized    = errors.New("vault already initialized")
	ErrSealed         = errors.New("vault is sealed")
	ErrWrongPassword  = errors.New("wrong password")
	ErrNotFound       = errors.New("secret not found")
	ErrEmptyPassword  = errors.New("password must not be empty")
)

// TOTPSecret is the name of the TOTP secret.
const TOTPSecret = "totp"

// RepoSecret returns the name under which the password of the repository
// at path (relative to the repository root) is stored.
func RepoSecret(path string) string { return "repo:" + path }

// KDFParams are the argon2id parameters. They are stored in the file, so
// they can be raised later without breaking existing vaults.
type KDFParams struct {
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
}

// DefaultKDF is used for new vaults and on password change (see
// docs/security.md, rule 3).
var DefaultKDF = KDFParams{Time: 3, MemoryKiB: 64 * 1024, Threads: 2}

// Limits for parameters read from the file: a tampered file must not make
// a login allocate gigabytes or run for minutes.
const (
	maxKDFTime   = 10
	maxKDFMemory = 1024 * 1024 // KiB = 1 GiB
	maxKDFThread = 16
)

const (
	formatVersion = 1
	keyLen        = 32 // AES-256
	saltLen       = 16
	checkName     = "\x00check" // AAD of the key check; not a valid secret name
	checkText     = "BelayPoint vault key check"
	fileMode      = 0o600
)

// fileFormat is the JSON layout of vault.json. []byte fields are
// base64-encoded by encoding/json.
type fileFormat struct {
	Version int       `json:"version"`
	KDF     KDFParams `json:"kdf"`
	Salt    []byte    `json:"salt"`
	// Check is checkText sealed with the vault key.
	Check []byte `json:"check"`
	// Secrets maps names to nonce || ciphertext.
	Secrets map[string][]byte `json:"secrets"`
}

// Vault is safe for concurrent use.
type Vault struct {
	path string
	kdf  KDFParams // for new keys

	// kdfMu allows one key derivation at a time: each needs
	// KDFParams.MemoryKiB of memory.
	kdfMu sync.Mutex

	mu   sync.Mutex
	file *fileFormat // nil: not initialized
	key  []byte      // nil: sealed
}

// Open loads the vault file at path. A missing file is not an error: the
// vault is then not initialized (see Create). A file that cannot be parsed
// is an error; it is never overwritten.
func Open(path string) (*Vault, error) {
	return openFile(path, DefaultKDF)
}

func openFile(path string, kdf KDFParams) (*Vault, error) {
	v := &Vault{path: path, kdf: kdf}
	data, err := os.ReadFile(path) //nolint:gosec // G304: path comes from the configuration
	if errors.Is(err, fs.ErrNotExist) {
		return v, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading vault: %w", err)
	}
	var f fileFormat
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing vault %s: %w", path, err)
	}
	if err := f.validate(); err != nil {
		return nil, fmt.Errorf("vault %s: %w", path, err)
	}
	v.file = &f
	return v, nil
}

func (f *fileFormat) validate() error {
	if f.Version != formatVersion {
		return fmt.Errorf("unsupported version %d", f.Version)
	}
	k := f.KDF
	if k.Time < 1 || k.Time > maxKDFTime || k.MemoryKiB < 8*uint32(k.Threads) || k.MemoryKiB > maxKDFMemory ||
		k.Threads < 1 || k.Threads > maxKDFThread {
		return fmt.Errorf("invalid key derivation parameters %+v", k)
	}
	if len(f.Salt) < saltLen {
		return errors.New("salt too short")
	}
	if len(f.Check) == 0 {
		return errors.New("key check missing")
	}
	if f.Secrets == nil {
		f.Secrets = map[string][]byte{}
	}
	return nil
}

// Initialized reports whether a vault file exists.
func (v *Vault) Initialized() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.file != nil
}

// Sealed reports whether the vault key is not in memory.
func (v *Vault) Sealed() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.key == nil
}

// Create initializes a new, empty vault protected by password and leaves it
// unsealed. The caller zeroes password.
func (v *Vault) Create(password []byte) error {
	if len(password) == 0 {
		return ErrEmptyPassword
	}
	v.kdfMu.Lock()
	defer v.kdfMu.Unlock()
	if v.Initialized() {
		return ErrInitialized
	}
	f := &fileFormat{Version: formatVersion, KDF: v.kdf, Secrets: map[string][]byte{}}
	key, err := f.newKey(password)
	if err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.file != nil {
		clear(key)
		return ErrInitialized
	}
	if err := os.MkdirAll(filepath.Dir(v.path), 0o700); err != nil {
		clear(key)
		return fmt.Errorf("creating vault directory: %w", err)
	}
	if err := write(v.path, f); err != nil {
		clear(key)
		return err
	}
	v.file = f
	v.setKey(key)
	return nil
}

// Unseal derives the key from password and keeps it in memory if it opens
// the key check. It is also how a login verifies the password while the
// vault is already unsealed. The caller zeroes password.
func (v *Vault) Unseal(password []byte) error {
	v.kdfMu.Lock()
	defer v.kdfMu.Unlock()
	v.mu.Lock()
	f := v.file
	v.mu.Unlock()
	if f == nil {
		return ErrNotInitialized
	}
	// The slow derivation runs without holding mu, so Sealed() and
	// friends stay responsive during a login.
	key := deriveKey(password, f.Salt, f.KDF)
	if err := f.verify(key); err != nil {
		clear(key)
		return err
	}
	// f's salt and key check are still current: only ChangePassword
	// replaces them, and it needs kdfMu, which we hold.
	v.mu.Lock()
	defer v.mu.Unlock()
	v.setKey(key)
	return nil
}

// Seal zeroes the key. Secrets handed out earlier are the callers'
// responsibility (they zero them after use).
func (v *Vault) Seal() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.setKey(nil)
}

// ChangePassword re-encrypts the vault with a key derived from newPassword
// and a new salt. oldPassword must be correct. The vault is unsealed
// afterwards. The caller zeroes both passwords.
func (v *Vault) ChangePassword(oldPassword, newPassword []byte) error {
	if len(newPassword) == 0 {
		return ErrEmptyPassword
	}
	v.kdfMu.Lock()
	defer v.kdfMu.Unlock()
	v.mu.Lock()
	cur := v.file
	v.mu.Unlock()
	if cur == nil {
		return ErrNotInitialized
	}
	oldKey := deriveKey(oldPassword, cur.Salt, cur.KDF)
	defer clear(oldKey)
	if err := cur.verify(oldKey); err != nil {
		return err
	}
	next := &fileFormat{Version: formatVersion, KDF: v.kdf, Secrets: make(map[string][]byte, len(cur.Secrets))}
	newKey, err := next.newKey(newPassword)
	if err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	// Secrets may have been added while the keys were derived; use the
	// current set. Only SetSecret/DeleteSecret change it, and they keep the
	// same key, so oldKey still opens all of them.
	for name, sealed := range v.file.Secrets {
		plain, err := open(oldKey, name, sealed)
		if err != nil {
			clear(newKey)
			return fmt.Errorf("re-encrypting %q: %w", name, err)
		}
		next.Secrets[name], err = seal(newKey, name, plain)
		clear(plain)
		if err != nil {
			clear(newKey)
			return err
		}
	}
	if err := write(v.path, next); err != nil {
		clear(newKey)
		return err
	}
	v.file = next
	v.setKey(newKey)
	return nil
}

// Has reports whether a secret with this name is stored. It works while
// sealed.
func (v *Vault) Has(name string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.file == nil {
		return false
	}
	_, ok := v.file.Secrets[name]
	return ok
}

// Names returns the names of all stored secrets, sorted. It works while
// sealed.
func (v *Vault) Names() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.file == nil {
		return nil
	}
	return slices.Sorted(maps.Keys(v.file.Secrets))
}

// Secret returns a copy of the decrypted secret. The caller must zero it
// after use (clear(b)), typically with defer.
func (v *Vault) Secret(name string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return nil, ErrSealed
	}
	sealed, ok := v.file.Secrets[name]
	if !ok {
		return nil, fmt.Errorf("%q: %w", name, ErrNotFound)
	}
	plain, err := open(v.key, name, sealed)
	if err != nil {
		return nil, fmt.Errorf("decrypting %q: %w", name, err)
	}
	return plain, nil
}

// SetSecret stores value under name (replacing an existing one) and writes
// the file. The vault must be unsealed. The caller zeroes value.
func (v *Vault) SetSecret(name string, value []byte) error {
	if err := validName(name); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return ErrSealed
	}
	sealed, err := seal(v.key, name, value)
	if err != nil {
		return err
	}
	next := v.file.withSecrets(func(m map[string][]byte) { m[name] = sealed })
	if err := write(v.path, next); err != nil {
		return err
	}
	v.file = next
	return nil
}

// DeleteSecret removes the secret. The vault must be unsealed, so nobody
// can drop secrets without the admin password. Deleting a missing secret
// is not an error.
func (v *Vault) DeleteSecret(name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return ErrSealed
	}
	if _, ok := v.file.Secrets[name]; !ok {
		return nil
	}
	next := v.file.withSecrets(func(m map[string][]byte) { delete(m, name) })
	if err := write(v.path, next); err != nil {
		return err
	}
	v.file = next
	return nil
}

// setKey replaces the key, zeroing the old one. Callers hold mu.
func (v *Vault) setKey(key []byte) {
	clear(v.key)
	v.key = key
}

func validName(name string) error {
	if name == "" || strings.ContainsRune(name, 0) {
		return fmt.Errorf("invalid secret name %q", name)
	}
	return nil
}

// withSecrets returns a copy of f with a changed secrets map, so the
// in-memory state only changes after the file was written.
func (f *fileFormat) withSecrets(change func(map[string][]byte)) *fileFormat {
	c := *f
	c.Secrets = maps.Clone(f.Secrets)
	change(c.Secrets)
	return &c
}

// newKey sets a fresh salt and key check in f and returns the key.
func (f *fileFormat) newKey(password []byte) ([]byte, error) {
	f.Salt = make([]byte, saltLen)
	if _, err := rand.Read(f.Salt); err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}
	key := deriveKey(password, f.Salt, f.KDF)
	check, err := seal(key, checkName, []byte(checkText))
	if err != nil {
		clear(key)
		return nil, err
	}
	f.Check = check
	return key, nil
}

// verify returns ErrWrongPassword unless key opens the key check.
func (f *fileFormat) verify(key []byte) error {
	plain, err := open(key, checkName, f.Check)
	if err != nil || subtle.ConstantTimeCompare(plain, []byte(checkText)) != 1 {
		return ErrWrongPassword
	}
	return nil
}

func deriveKey(password, salt []byte, p KDFParams) []byte {
	return argon2.IDKey(password, salt, p.Time, p.MemoryKiB, p.Threads, keyLen)
}

// seal encrypts plain with a random nonce and returns nonce || ciphertext.
//
// The AES key schedule built by aes.NewCipher is a copy of the key that Go
// does not let us zero; it is created per call and left to the garbage
// collector (see docs/security.md).
func seal(key []byte, name string, plain []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plain)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plain, []byte(name)), nil
}

// open decrypts nonce || ciphertext sealed under name.
func open(key []byte, name string, sealed []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := sealed[:aead.NonceSize()], sealed[aead.NonceSize():]
	return aead.Open(nil, nonce, ct, []byte(name))
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

func write(path string, f *fileFormat) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding vault: %w", err)
	}
	return atomicfile.Write(path, append(data, '\n'), fileMode)
}
