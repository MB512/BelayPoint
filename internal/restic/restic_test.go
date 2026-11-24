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
	"slices"
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
	if err := c.run(context.Background(), "/repos/alice/main", password, []string{"cat", "config", "--no-lock"}, &out, nil); err != nil {
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
	want := []string{"--repo", "/repos/alice/main", "--password-file", "/dev/fd/3", "--cache-dir", c.CacheDir, "cat", "config", "--no-lock"}
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
	entries := stableDir(t, locks)
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
	after := stableDir(t, locks)
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

func TestPolicy(t *testing.T) {
	if err := DefaultPolicy.Validate(); err != nil {
		t.Errorf("default policy: %v", err)
	}
	snaps := []Snapshot{
		{ShortID: "1", Tags: []string{"pre-stop"}}, {ShortID: "2", Tags: []string{"final"}},
		{ShortID: "3"}, {ShortID: "4", Tags: []string{"pre-restore"}}, {ShortID: "5", Tags: []string{"b", "a"}},
	}
	passes, err := DefaultPolicy.Passes(snaps)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range passes {
		got = append(got, p.Tag+"|"+strings.Join(p.Args, " "))
	}
	want := []string{
		"pre-stop|--group-by host,paths --tag pre-stop --keep-last 2",
		"|--group-by host,paths --tag  --tag a,b --tag final --tag pre-restore --keep-daily 7 --keep-weekly 4 --keep-monthly 12 --keep-yearly 3",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("passes:\n%s", strings.Join(got, "\n"))
	}
	// Only pre-stop snapshots: no main pass.
	if passes, _ := DefaultPolicy.Passes(snaps[:1]); len(passes) != 1 || passes[0].Tag != "pre-stop" {
		t.Errorf("passes = %+v", passes)
	}
	// A rule snapshot that also carries "final" would be selected twice.
	overlap := append(slices.Clone(snaps), Snapshot{ShortID: "6", Tags: []string{"final", "pre-stop"}})
	if _, err := DefaultPolicy.Passes(overlap); !errors.Is(err, ErrTagOverlap) {
		t.Errorf("overlap: %v", err)
	}
	if s := DefaultPolicy.String(); s != "--keep-daily 7 --keep-weekly 4 --keep-monthly 12 --keep-yearly 3; tag pre-stop: --keep-last 2" {
		t.Errorf("string = %q", s)
	}
	p := Policy{Keep: Keep{KeepLast: 2, KeepWithin: "1y6m"}}
	if passes, _ := p.Passes(nil); len(passes) != 1 || strings.Join(passes[0].Args, " ") != "--group-by host,paths --keep-last 2 --keep-within 1y6m" {
		t.Errorf("passes = %+v", passes)
	}
	daily := Keep{KeepDaily: 1}
	for _, bad := range []Policy{
		{},
		{Keep: Keep{KeepDaily: -1}},
		{Keep: Keep{KeepDaily: MaxKeep + 1}},
		{Keep: Keep{KeepWithin: "14 days"}},
		{Keep: Keep{KeepWithin: "1y; rm -rf /"}},
		{Keep: Keep{KeepWithin: "--keep-last=1"}},
		{Keep: daily, TagRules: []TagRule{{Tag: "pre-stop"}}},           // empty rule
		{Keep: daily, TagRules: []TagRule{{Tag: "a,b", Keep: daily}}},   // tag list
		{Keep: daily, TagRules: []TagRule{{Tag: "--tag", Keep: daily}}}, // option
		{Keep: daily, TagRules: []TagRule{{Tag: "", Keep: daily}}},      // empty tag
		{Keep: daily, TagRules: []TagRule{{Tag: "x", Keep: daily}, {Tag: "x", Keep: daily}}}, // twice
		{Keep: daily, TagRules: []TagRule{{Tag: "x", Keep: Keep{KeepWithin: "soon"}}}},       // bad within
		{Keep: daily, TagRules: make([]TagRule, MaxTagRules+1)},                              // too many
	} {
		if err := bad.Validate(); !errors.Is(err, ErrPolicy) {
			t.Errorf("%+v accepted: %v", bad, err)
		}
	}
}

func TestResultHelpers(t *testing.T) {
	results := []PassResult{
		{Tag: "pre-stop", Groups: []ForgetGroup{{Keep: make([]Snapshot, 2), Remove: make([]Snapshot, 3)}}},
		{Groups: []ForgetGroup{{Keep: make([]Snapshot, 4), Remove: make([]Snapshot, 1)}, {Keep: make([]Snapshot, 1)}}},
	}
	if Removed(results) != 4 || len(Kept(results)) != 7 {
		t.Errorf("removed %d, kept %d", Removed(results), len(Kept(results)))
	}
	if g, err := parseForget([]byte("\n")); g != nil || err != nil {
		t.Errorf("empty output: %v %v", g, err)
	}
}

func TestRealForgetPreview(t *testing.T) {
	if _, err := exec.LookPath("restic"); err != nil {
		t.Skip("restic not installed")
	}
	c, err := New(t.TempDir(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "repo")
	data := t.TempDir()
	_ = os.WriteFile(filepath.Join(data, "f"), []byte("x"), 0o600)
	pw := []byte("pw")
	if err := c.run(ctx, dir, pw, []string{"init"}, io.Discard, nil); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if err := c.run(ctx, dir, pw, []string{"backup", data}, io.Discard, nil); err != nil {
			t.Fatal(err)
		}
	}
	res, err := c.ForgetPreview(ctx, dir, pw, Policy{Keep: Keep{KeepLast: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || len(res[0].Groups) != 1 || len(Kept(res)) != 1 || Removed(res) != 2 || res[0].Groups[0].Host == "" {
		t.Fatalf("result = %+v", res)
	}
	// restic says why it keeps the snapshot.
	g := res[0].Groups[0]
	if why := g.ReasonFor(g.Keep[0].ID); len(why) != 1 || why[0] != "last snapshot" {
		t.Errorf("reason %q", why)
	}
	// Dry run: all three are still there, and no lock was left.
	if list, _ := c.Snapshots(ctx, dir, pw); len(list) != 3 {
		t.Errorf("%d snapshots after the preview", len(list))
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "locks")); len(entries) != 0 {
		t.Errorf("%d locks after the preview", len(entries))
	}
}

func TestRealMaintenance(t *testing.T) {
	if _, err := exec.LookPath("restic"); err != nil {
		t.Skip("restic not installed")
	}
	c, err := New(t.TempDir(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "repo")
	data := t.TempDir()
	pw := []byte("pw")
	if err := c.run(ctx, dir, pw, []string{"init"}, io.Discard, nil); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		_ = os.WriteFile(filepath.Join(data, "f"), []byte(strings.Repeat("x", 1000*(i+1))), 0o600)
		if err := c.run(ctx, dir, pw, []string{"backup", data}, io.Discard, nil); err != nil {
			t.Fatal(err)
		}
	}
	var log bytes.Buffer
	res, err := c.Forget(ctx, dir, pw, Policy{Keep: Keep{KeepLast: 1}}, &log)
	if err != nil || Removed(res) != 2 || !strings.Contains(log.String(), "1 kept, 2 removed") {
		t.Fatalf("forget: %+v %v\n%s", res, err, log.String())
	}
	if list, _ := c.Snapshots(ctx, dir, pw); len(list) != 1 {
		t.Errorf("%d snapshots left", len(list))
	}
	log.Reset()
	if err := c.Prune(ctx, dir, pw, DefaultMaxUnused, &log); err != nil {
		t.Fatalf("prune: %v\n%s", err, log.String())
	}
	if err := c.Prune(ctx, dir, pw, "5%; rm", io.Discard); err == nil {
		t.Error("bad --max-unused accepted")
	}
	log.Reset()
	if err := c.Check(ctx, dir, pw, "1/2", &log); err != nil || !strings.Contains(log.String(), "no errors") {
		t.Fatalf("check: %v\n%s", err, log.String())
	}

	// Lock conflict with retry: a client backup (reading stdin from a
	// pipe we keep open) holds a lock; forget waits RetryLock (2 s) for it
	// and then fails with ErrLocked.
	pr, pwr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	pwFile := filepath.Join(t.TempDir(), "pw")
	_ = os.WriteFile(pwFile, pw, 0o600)
	holder := exec.CommandContext(ctx, c.Binary, "--repo", dir, "--password-file", pwFile, "--cache-dir", c.CacheDir,
		"backup", "--stdin", "--stdin-filename", "x") //nolint:gosec // test binary and paths
	holder.Stdin = pr
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	_ = pr.Close()
	defer func() { _ = pwr.Close(); _ = holder.Wait() }()
	for range 500 {
		if entries, _ := os.ReadDir(filepath.Join(dir, "locks")); len(entries) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	start := time.Now()
	_, err = c.Forget(ctx, dir, pw, Policy{Keep: Keep{KeepLast: 1}}, io.Discard)
	if !errors.Is(err, ErrLocked) {
		t.Errorf("forget during a backup: %v (%s)", err, mustVersion(t, c))
	}
	if err == nil {
		t.Error("forget succeeded while a backup held a lock")
	}
	if d := time.Since(start); d < 2*time.Second {
		t.Errorf("forget gave up after %v, before --retry-lock", d)
	}
}

func mustVersion(t *testing.T, c *CLI) string {
	t.Helper()
	v, err := c.Version(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// stableDir returns the entries of dir once they have not changed for
// 300 ms: a killed restic may leave a lock file that is still being
// written or renamed.
func stableDir(t *testing.T, dir string) []os.DirEntry {
	t.Helper()
	names := func(e []os.DirEntry) string {
		var s []string
		for _, x := range e {
			s = append(s, x.Name())
		}
		return strings.Join(s, ",")
	}
	prev, _ := os.ReadDir(dir)
	for range 50 {
		time.Sleep(300 * time.Millisecond)
		cur, _ := os.ReadDir(dir)
		if names(cur) == names(prev) {
			return cur
		}
		prev = cur
	}
	return prev
}

// TestRealTagRules mimics StackBelay: each backup is a pre-stop snapshot
// followed by a final one. The pre-stop rule keeps the newest pre-stop
// snapshot; the main policy (keep last 2) must neither count nor remove
// pre-stop snapshots.
func TestRealTagRules(t *testing.T) {
	if _, err := exec.LookPath("restic"); err != nil {
		t.Skip("restic not installed")
	}
	c, err := New(t.TempDir(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "repo")
	data := t.TempDir()
	pw := []byte("pw")
	if err := c.run(ctx, dir, pw, []string{"init"}, io.Discard, nil); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		_ = os.WriteFile(filepath.Join(data, "f"), []byte(strconv.Itoa(i)), 0o600)
		for _, tag := range []string{"pre-stop", "final"} {
			if err := c.run(ctx, dir, pw, []string{"backup", "--tag", tag, data}, io.Discard, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	p := Policy{Keep: Keep{KeepLast: 2}, TagRules: []TagRule{{Tag: TagPreStop, Keep: Keep{KeepLast: 1}}}}
	// A tag without snapshots: restic prints nothing, the pass is empty.
	p2 := Policy{Keep: Keep{KeepLast: 2}, TagRules: []TagRule{{Tag: "pre-restore", Keep: Keep{KeepLast: 1}}}}
	if res, err := c.ForgetPreview(ctx, dir, pw, p2); err != nil || len(res) != 2 || len(res[0].Groups) != 0 || Removed(res) != 4 {
		t.Fatalf("tag without snapshots: %+v %v", res, err)
	}
	preview, err := c.ForgetPreview(ctx, dir, pw, p)
	if err != nil {
		t.Fatal(err)
	}
	if Removed(preview) != 3 { // 2 pre-stop + 1 final
		t.Errorf("preview removes %d, want 3: %+v", Removed(preview), preview)
	}
	var log bytes.Buffer
	res, err := c.Forget(ctx, dir, pw, p, &log)
	if err != nil {
		t.Fatalf("forget: %v\n%s", err, log.String())
	}
	if Removed(res) != 3 {
		t.Errorf("removed %d\n%s", Removed(res), log.String())
	}
	list, _ := c.Snapshots(ctx, dir, pw)
	count := map[string]int{}
	for _, s := range list {
		count[strings.Join(s.Tags, ",")]++
	}
	if count["pre-stop"] != 1 || count["final"] != 2 || len(list) != 3 {
		// keep last 2 applies to the final snapshots only
		t.Errorf("left: %v", count)
	}
	if len(Kept(res)) != 3 {
		t.Errorf("kept = %d, want all 3 remaining", len(Kept(res)))
	}
}

func TestValidSubset(t *testing.T) {
	for s, ok := range map[string]bool{
		"1/1": true, "3/7": true, "365/365": true,
		"": false, "0/7": false, "8/7": false, "1/366": false, "1/0": false,
		"-1/7": false, "1/7/2": false, "10%": false, "1 /7": false, "1/7 ": false,
	} {
		if err := ValidSubset(s); (err == nil) != ok {
			t.Errorf("ValidSubset(%q) = %v, want ok=%v", s, err, ok)
		}
	}
}
