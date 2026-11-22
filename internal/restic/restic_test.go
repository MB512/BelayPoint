package restic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The test binary doubles as a fake restic: with BELAYPOINT_FAKE_RESTIC
// set, TestMain runs fakeRestic instead of the tests (the usual Go "helper
// process" pattern). cmd.Env is allow-listed by the CLI, so the variable is
// passed explicitly through CLI.Env.
func TestMain(m *testing.M) {
	if mode := os.Getenv("BELAYPOINT_FAKE_RESTIC"); mode != "" {
		os.Exit(fakeRestic(mode))
	}
	os.Exit(m.Run())
}

// fakeReport is what the fake prints: everything a password could leak
// through.
type fakeReport struct {
	Args     []string
	Cmdline  string
	Environ  string
	Password string
}

func fakeRestic(mode string) int {
	pw, err := io.ReadAll(os.NewFile(3, "fd3"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "reading fd 3:", err)
		return 1
	}
	switch mode {
	case "report":
		cmdline, _ := os.ReadFile("/proc/self/cmdline")
		environ, _ := os.ReadFile("/proc/self/environ")
		_ = json.NewEncoder(os.Stdout).Encode(fakeReport{
			Args: os.Args[1:], Cmdline: string(cmdline), Environ: string(environ), Password: string(pw),
		})
		return 0
	case "wrong-password":
		fmt.Fprintln(os.Stderr, "Fatal: wrong password or no key found")
		return exitWrongPassword
	case "old-wrong-password":
		fmt.Fprintln(os.Stderr, "Fatal: wrong password or no key found")
		return 1
	case "locked":
		fmt.Fprintln(os.Stderr, "Fatal: unable to create lock in backend: repository is already locked")
		return exitLocked
	case "wait-for-interrupt":
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt)
		fmt.Println("ready")
		select {
		case <-ch:
			fmt.Fprintln(os.Stderr, "removing lock")
			return 130
		case <-time.After(30 * time.Second):
			return 0
		}
	case "ignore-interrupt":
		signal.Ignore(os.Interrupt)
		time.Sleep(30 * time.Second)
		return 0
	}
	return 2
}

func fakeCLI(t *testing.T, mode string) *CLI {
	t.Helper()
	return &CLI{
		Binary:      os.Args[0],
		CacheDir:    t.TempDir(),
		Env:         []string{"BELAYPOINT_FAKE_RESTIC=" + mode, "LANG=C"},
		StopTimeout: 5 * time.Second,
	}
}

// TestPasswordOnlyOnFD3 covers the checks of issue #3 for our side: the
// password arrives complete on fd 3 and is in neither the arguments nor
// the environment of the child.
func TestPasswordOnlyOnFD3(t *testing.T) {
	t.Setenv("RESTIC_PASSWORD", "from-parent-env") // must not be inherited
	c := fakeCLI(t, "report")
	password := []byte("correct horse battery staple")
	var out bytes.Buffer
	if err := c.run(context.Background(), "/repos/alice/main", password, []string{"cat", "config"}, &out, nil); err != nil {
		t.Fatal(err)
	}
	var rep fakeReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("fake output %q: %v", out.String(), err)
	}
	if rep.Password != string(password) {
		t.Errorf("fd 3 delivered %q", rep.Password)
	}
	for name, s := range map[string]string{"cmdline": rep.Cmdline, "environ": rep.Environ} {
		if strings.Contains(s, "horse") {
			t.Errorf("password visible in /proc/self/%s", name)
		}
	}
	if strings.Contains(rep.Environ, "RESTIC_PASSWORD") {
		t.Error("parent environment was inherited")
	}
	want := []string{"--repo", "/repos/alice/main", "--password-file", "/dev/fd/3", "--cache-dir", c.CacheDir, "cat", "config", "--json"}
	if strings.Join(rep.Args, " ") != strings.Join(want, " ") {
		t.Errorf("args = %q, want %q", rep.Args, want)
	}
}

// A password larger than the pipe buffer (64 KiB) must not deadlock.
func TestLargePassword(t *testing.T) {
	c := fakeCLI(t, "report")
	password := bytes.Repeat([]byte("x"), 200<<10)
	var out bytes.Buffer
	if err := c.run(context.Background(), "/r", password, []string{"cat", "config"}, &out, nil); err != nil {
		t.Fatal(err)
	}
	var rep fakeReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.Password) != len(password) {
		t.Errorf("got %d bytes", len(rep.Password))
	}
}

func TestErrors(t *testing.T) {
	for _, c := range []struct {
		mode string
		want error
	}{
		{"wrong-password", ErrWrongPassword},
		{"old-wrong-password", ErrWrongPassword},
		{"locked", ErrLocked},
	} {
		err := fakeCLI(t, c.mode).CatConfig(context.Background(), "/r", []byte("pw"))
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.mode, err, c.want)
		}
		var re *Error
		if !errors.As(err, &re) || re.Stderr == "" || !strings.Contains(err.Error(), "restic cat failed") {
			t.Errorf("%s: error lacks details: %v", c.mode, err)
		}
	}
}

// Cancelling sends SIGINT so restic can remove its lock.
func TestCancelInterrupts(t *testing.T) {
	c := fakeCLI(t, "wait-for-interrupt")
	ctx, cancel := context.WithCancel(context.Background())
	r, w := io.Pipe()
	errc := make(chan error, 1)
	var stderr bytes.Buffer
	go func() {
		errc <- c.run(ctx, "/r", []byte("pw"), []string{"prune"}, w, &stderr)
		_ = w.Close()
	}()
	buf := make([]byte, 6)
	if _, err := io.ReadFull(r, buf); err != nil || string(buf) != "ready\n" {
		t.Fatalf("fake did not start: %q %v", buf, err)
	}
	go func() { _, _ = io.Copy(io.Discard, r) }()
	cancel()
	err := <-errc
	var re *Error
	if !errors.As(err, &re) || re.ExitCode != 130 {
		t.Fatalf("err = %v, want exit code 130", err)
	}
	if !strings.Contains(stderr.String(), "removing lock") {
		t.Errorf("stderr copy = %q", stderr.String())
	}
}

// A restic that ignores SIGINT is killed after StopTimeout.
func TestCancelKillsAfterTimeout(t *testing.T) {
	c := fakeCLI(t, "ignore-interrupt")
	c.StopTimeout = 200 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := c.run(ctx, "/r", []byte("pw"), []string{"prune"}, io.Discard, nil)
	if err == nil {
		t.Fatal("no error")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("took %v", d)
	}
}

func TestTailBuffer(t *testing.T) {
	tb := &tailBuffer{max: 5}
	_, _ = tb.Write([]byte("abc"))
	_, _ = tb.Write([]byte("defg"))
	if tb.String() != "cdefg" {
		t.Errorf("tail = %q", tb.String())
	}
}

func TestParseSnapshots(t *testing.T) {
	data := []byte(`[{"time":"2026-11-20T03:00:01.5+01:00","tree":"t","paths":["/data"],"hostname":"pc","username":"root",` +
		`"id":"0123456789abcdef","short_id":"01234567","tags":["daily"],"program_version":"restic 0.18.1"}]`)
	list, err := parseSnapshots(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ShortID != "01234567" || list[0].Hostname != "pc" || list[0].Paths[0] != "/data" ||
		list[0].Tags[0] != "daily" || list[0].Time.Year() != 2026 {
		t.Errorf("parsed %+v", list)
	}
	if _, err := parseSnapshots([]byte("not json")); err == nil {
		t.Error("bad output accepted")
	}
}

// TestRealRestic runs the installed restic (skipped without it): the
// end-to-end part of issue #3.
func TestRealRestic(t *testing.T) {
	if _, err := exec.LookPath("restic"); err != nil {
		t.Skip("restic not installed")
	}
	c, err := New(t.TempDir(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	v, err := c.Version(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(v)
	dir := filepath.Join(t.TempDir(), "repo")

	if err := c.CatConfig(ctx, dir, []byte("pw")); !errors.Is(err, ErrNoRepository) && !restic016(v) {
		t.Errorf("missing repository: %v", err)
	}
	// restic trims whitespace around a --password-file password; the
	// vault stores passwords trimmed for the same reason.
	if err := c.run(ctx, dir, []byte("  secret password\n"), []string{"init"}, io.Discard, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.CatConfig(ctx, dir, []byte("secret password")); err != nil {
		t.Errorf("right password: %v", err)
	}
	if err := c.CatConfig(ctx, dir, []byte("wrong")); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("wrong password: %v", err)
	}
	list, err := c.Snapshots(ctx, dir, []byte("secret password"))
	if err != nil || len(list) != 0 {
		t.Errorf("snapshots = %v, %v", list, err)
	}
}

// restic016 reports versions before 0.17, which exit with 1 instead of 10
// for a missing repository.
func restic016(version string) bool {
	f := strings.Fields(version)
	if len(f) < 2 {
		return false
	}
	parts := strings.Split(f[1], ".")
	if len(parts) < 2 {
		return false
	}
	minor, _ := strconv.Atoi(parts[1])
	return parts[0] == "0" && minor < 17
}

func TestParseUnlock(t *testing.T) {
	for in, want := range map[string]int{
		"successfully removed 3 locks\n": 3,
		"successfully removed 1 lock\n":  1,
		"":                               0,
	} {
		if got := parseUnlock([]byte(in)); got != want {
			t.Errorf("parseUnlock(%q) = %d, want %d", in, got, want)
		}
	}
}

// TestRealUnlock leaves a lock behind with a restic process that is
// killed, then removes it as stale.
func TestRealUnlock(t *testing.T) {
	if _, err := exec.LookPath("restic"); err != nil {
		t.Skip("restic not installed")
	}
	c, err := New(t.TempDir(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "repo")
	pw := []byte("pw")
	if err := c.run(ctx, dir, pw, []string{"init"}, io.Discard, nil); err != nil {
		t.Fatal(err)
	}
	// A lock file written as restic does it would need the repository key;
	// instead let a real restic hold a lock and kill it.
	lockCtx, kill := context.WithCancel(ctx)
	c2 := *c
	c2.StopTimeout = time.Millisecond // SIGINT, then SIGKILL almost at once
	started := make(chan error, 1)
	go func() {
		started <- c2.run(lockCtx, dir, pw, []string{"backup", "--stdin", "--stdin-filename", "x"}, io.Discard, nil)
	}()
	locks := filepath.Join(dir, "locks")
	for range 500 {
		if entries, _ := os.ReadDir(locks); len(entries) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	kill()
	if err := <-started; err == nil {
		t.Log("backup finished before it was killed")
	}
	entries, _ := os.ReadDir(locks)
	if len(entries) == 0 {
		t.Skip("restic removed its lock in time; nothing stale to test")
	}
	var log bytes.Buffer
	n, err := c.Unlock(ctx, dir, pw, false, &log)
	if err != nil {
		t.Fatal(err)
	}
	// Whether restic considers the lock stale depends on its version
	// (older ones wait 30 minutes); what matters here is that the count
	// matches what was removed.
	after, _ := os.ReadDir(locks)
	if n != len(entries)-len(after) {
		t.Errorf("reported %d removed, but %d of %d are gone; log %q", n, len(entries)-len(after), len(entries), log.String())
	}
	// --remove-all removes the rest regardless of age.
	if _, err := c.Unlock(ctx, dir, pw, true, io.Discard); err != nil {
		t.Fatal(err)
	}
	if rest, _ := os.ReadDir(locks); len(rest) != 0 {
		t.Errorf("%d locks left after --remove-all", len(rest))
	}
}
