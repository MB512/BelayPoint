package notify

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeNtfy records the requests it receives.
type fakeNtfy struct {
	mu     sync.Mutex
	got    []*http.Request
	bodies []string
	status int
}

func (f *fakeNtfy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.got = append(f.got, r)
	f.bodies = append(f.bodies, string(body))
	status := f.status
	f.mu.Unlock()
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
}

func (f *fakeNtfy) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.got)
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestSendNow(t *testing.T) {
	f := &fakeNtfy{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	n := New(srv.URL+"/belaypoint", "tk_secret", nil, quiet())
	err := n.SendNow(context.Background(), Message{Event: Failed, Title: "prune failed: alice/main\näöü", Body: "disk full"})
	if err != nil {
		t.Fatal(err)
	}
	r := f.got[0]
	if r.Method != http.MethodPost || r.URL.Path != "/belaypoint" || f.bodies[0] != "disk full" {
		t.Errorf("request %s %s %q", r.Method, r.URL.Path, f.bodies[0])
	}
	for h, want := range map[string]string{
		"Title": "prune failed: alice/main ???", "Priority": "high", "Tags": "x", "Authorization": "Bearer tk_secret",
	} {
		if got := r.Header.Get(h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}

	f.status = http.StatusForbidden
	if err := n.SendNow(context.Background(), Message{Event: Test, Title: "t"}); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("403 not reported: %v", err)
	}
	// The URL may contain a secret topic: not in the error text.
	n = New("http://127.0.0.1:1/secret-topic", "", nil, quiet())
	if err := n.SendNow(context.Background(), Message{Event: Test}); err == nil || strings.Contains(err.Error(), "secret-topic") {
		t.Errorf("error %v", err)
	}
}

func TestQueueAndSwitches(t *testing.T) {
	f := &fakeNtfy{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	off := map[Event]bool{Forget: true}
	n := New(srv.URL, "", func(_ context.Context, e Event) bool { return !off[e] }, quiet())
	ctx, cancel := context.WithCancel(context.Background())
	go n.Run(ctx)

	n.Notify(ctx, Message{Event: Failed, Title: "a"})
	n.Notify(ctx, Message{Event: Forget, Title: "switched off"})
	n.Notify(ctx, Message{Event: Prune, Title: "b"})
	deadline := time.Now().Add(5 * time.Second)
	for f.count() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	n.Wait()
	if f.count() != 2 {
		t.Fatalf("%d messages sent, want 2", f.count())
	}
	if f.got[1].Header.Get("Priority") != "low" {
		t.Errorf("summary priority %q", f.got[1].Header.Get("Priority"))
	}
}

// Messages queued before shutdown are still sent.
func TestRunDrainsOnShutdown(t *testing.T) {
	f := &fakeNtfy{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	n := New(srv.URL, "", nil, quiet())
	ctx, cancel := context.WithCancel(context.Background())
	n.Notify(ctx, Message{Event: Sealed, Title: "x"})
	n.Notify(ctx, Message{Event: Sealed, Title: "y"})
	cancel()
	n.Run(ctx) // returns after draining
	if f.count() != 2 {
		t.Errorf("%d sent", f.count())
	}
}

func TestNotConfigured(t *testing.T) {
	n := New("", "", nil, quiet())
	n.Notify(context.Background(), Message{Event: Failed}) // dropped, no panic
	if n.Configured() || n.SendNow(context.Background(), Message{Event: Test}) == nil {
		t.Error("unconfigured notifier sends")
	}
	var none *Notifier
	if none.Configured() {
		t.Error("nil notifier configured")
	}
}

type memSettings map[string]string

func (m memSettings) Setting(_ context.Context, k string) (string, bool, error) {
	v, ok := m[k]
	return v, ok, nil
}

func (m memSettings) SetSetting(_ context.Context, k, v string) error { m[k] = v; return nil }

func TestSwitches(t *testing.T) {
	ctx := context.Background()
	st := memSettings{}
	on := EnabledIn(st)
	if !on(ctx, Prune) {
		t.Error("unset event is off")
	}
	_ = SetEnabled(ctx, st, Prune, false)
	if on(ctx, Prune) || !on(ctx, Forget) {
		t.Error("switch not applied")
	}
	_ = SetEnabled(ctx, st, Prune, true)
	if !on(ctx, Prune) {
		t.Error("not switched on again")
	}
}
