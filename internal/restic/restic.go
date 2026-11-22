// Package restic runs the restic CLI against a repository on the local
// backend (see "Maintenance jobs" in docs/architecture.md).
//
// The repository password reaches restic only through
// --password-file /dev/fd/3: a pipe whose read end becomes file descriptor 3
// of the child (cmd.ExtraFiles). It never appears in arguments, the
// environment or on disk (docs/security.md, rule 5; issue #3).
package restic

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// Exit codes of restic 0.17 and later (restic docs, "Exit codes").
const (
	exitNoRepository  = 10
	exitLocked        = 11
	exitWrongPassword = 12
)

// Errors that callers can tell apart with errors.Is.
var (
	ErrWrongPassword = errors.New("wrong repository password")
	ErrNoRepository  = errors.New("repository does not exist")
	ErrLocked        = errors.New("repository is locked")
)

// Runner is what the rest of BelayPoint needs from restic. Jobs and handlers
// take this interface, so tests use a fake (comparable to an injected
// interface in C#).
//
// dir is the absolute repository directory, already validated with
// repos.Dir. password is only read; the caller zeroes it afterwards.
type Runner interface {
	// CatConfig reads the repository config; it succeeds only with a
	// valid password.
	CatConfig(ctx context.Context, dir string, password []byte) error
	// Snapshots lists all snapshots without taking a lock.
	Snapshots(ctx context.Context, dir string, password []byte) ([]Snapshot, error)
	// Unlock removes stale locks, or with removeAll every lock (also
	// those of running backups). restic's output goes to log. It returns
	// the number of removed locks.
	Unlock(ctx context.Context, dir string, password []byte, removeAll bool, log io.Writer) (int, error)
	// ForgetPreview shows what forget with the policy would remove,
	// without changing anything.
	ForgetPreview(ctx context.Context, dir string, password []byte, p Policy) ([]PassResult, error)
	// Forget, Prune and Check take an exclusive lock and wait up to
	// RetryLock for other locks. Their output goes to log.
	Forget(ctx context.Context, dir string, password []byte, p Policy, log io.Writer) ([]PassResult, error)
	Prune(ctx context.Context, dir string, password []byte, maxUnused string, log io.Writer) error
	Check(ctx context.Context, dir string, password []byte, subset string, log io.Writer) error
}

// Error is a failed restic run.
type Error struct {
	Args     []string // without the password, which is never an argument
	ExitCode int      // -1 if restic did not exit normally
	Stderr   string   // last part of restic's error output
	kind     error
}

func (e *Error) Error() string {
	msg := "restic " + firstArg(e.Args) + " failed"
	if e.ExitCode >= 0 {
		msg += " (exit code " + strconv.Itoa(e.ExitCode) + ")"
	}
	if e.Stderr != "" {
		msg += ": " + e.Stderr
	}
	return msg
}

// Unwrap makes errors.Is(err, ErrWrongPassword) etc. work, comparable to
// matching on an exception type in C#.
func (e *Error) Unwrap() error { return e.kind }

func firstArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

// CLI is the Runner that executes the restic binary.
type CLI struct {
	// Binary is the path of restic.
	Binary string
	// CacheDir is passed as --cache-dir.
	CacheDir string
	// RetryLock is passed as --retry-lock to commands that take a lock.
	RetryLock time.Duration
	// Env is the complete environment of restic; nothing is inherited.
	Env []string
	// StopTimeout is how long restic gets to clean up (remove its lock)
	// after SIGINT before it is killed.
	StopTimeout time.Duration
}

// New finds restic in PATH and returns a CLI with an allow-listed
// environment: only TZ is taken from BelayPoint's own environment, so
// variables such as RESTIC_PASSWORD or RESTIC_REPOSITORY can never reach
// restic by accident.
func New(cacheDir string, retryLock time.Duration) (*CLI, error) {
	bin, err := exec.LookPath("restic")
	if err != nil {
		return nil, fmt.Errorf("finding restic: %w", err)
	}
	env := []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + cacheDir, "LANG=C"}
	if tz, ok := os.LookupEnv("TZ"); ok {
		env = append(env, "TZ="+tz)
	}
	return &CLI{Binary: bin, CacheDir: cacheDir, RetryLock: retryLock, Env: env, StopTimeout: 30 * time.Second}, nil
}

// Version returns the output of "restic version".
func (c *CLI) Version(ctx context.Context) (string, error) {
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, c.Binary, "version")
	cmd.Env = c.Env
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("restic version: %w", err)
	}
	return string(bytes.TrimSpace(out.Bytes())), nil
}

// CatConfig implements Runner.
func (c *CLI) CatConfig(ctx context.Context, dir string, password []byte) error {
	return c.run(ctx, dir, password, []string{"cat", "config", "--no-lock"}, io.Discard, nil)
}

// run executes restic with the repository, the password pipe and args
// (which include --json where the output is parsed).
// stdout receives restic's standard output; stderr, if not nil, a copy of
// its error output.
func (c *CLI) run(ctx context.Context, dir string, password []byte, args []string, stdout, stderr io.Writer) error {
	full := append([]string{
		"--repo", dir,
		"--password-file", "/dev/fd/3",
		"--cache-dir", c.CacheDir,
	}, args...)

	pr, pw, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("password pipe: %w", err)
	}
	defer pr.Close()
	defer pw.Close()

	tail := &tailBuffer{max: 4 << 10}
	cmd := exec.CommandContext(ctx, c.Binary, full...)
	cmd.Env = c.Env
	cmd.Stdout = stdout
	cmd.Stderr = tail
	if stderr != nil {
		cmd.Stderr = io.MultiWriter(tail, stderr)
	}
	// ExtraFiles[0] becomes fd 3 in the child (0-2 are stdin/out/err).
	cmd.ExtraFiles = []*os.File{pr}
	// On cancel, ask restic to stop (it removes its lock on SIGINT) and
	// kill it only if it does not exit in time.
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = c.StopTimeout

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting restic: %w", err)
	}
	// The child has its own copy of the read end now.
	_ = pr.Close()

	// restic reads the file until EOF, so the write end must be closed
	// after the password. Writing in a goroutine keeps a slow reader from
	// blocking us; done makes sure it has finished with password before
	// run returns and the caller zeroes it.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = pw.Write(password) // EPIPE if restic exits early: Wait reports why
		_ = pw.Close()
	}()
	waitErr := cmd.Wait()
	<-done
	if waitErr == nil {
		return nil
	}
	return classify(args, waitErr, tail.String())
}

// classify turns a failed run into an *Error.
func classify(args []string, err error, stderr string) error {
	e := &Error{Args: args, ExitCode: -1, Stderr: stderr}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		e.kind = err
		return e
	}
	e.ExitCode = exit.ExitCode()
	if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		e.ExitCode = -1
	}
	switch {
	case e.ExitCode == exitWrongPassword,
		// restic before 0.17.1 exits with 1; match its message.
		e.ExitCode == 1 && bytes.Contains([]byte(stderr), []byte("wrong password")):
		e.kind = ErrWrongPassword
	case e.ExitCode == exitNoRepository:
		e.kind = ErrNoRepository
	case e.ExitCode == exitLocked,
		e.ExitCode == 1 && bytes.Contains([]byte(stderr), []byte("repository is already locked")):
		e.kind = ErrLocked
	}
	return e
}

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	max int
	buf []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - t.max; over > 0 {
		t.buf = append(t.buf[:0], t.buf[over:]...)
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return string(bytes.TrimSpace(t.buf)) }
