package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/MB512/belaypoint/internal/notify"
)

func TestSettingsPage(t *testing.T) {
	e := newEnv(t, nil, true)
	e.opts.NotifyTarget = "https://ntfy.sh/…"
	e.h = New(e.opts)
	cookie := login(t, e)
	csrf := csrfFromPage(t, e.h, cookie)

	body := getWithCookie(e.h, "/settings", cookie).Body.String()
	for _, want := range []string{"https://ntfy.sh/…", `name="event_failed" value="on" checked`, `name="event_prune" value="on" checked`, "Send test notification"} {
		if !strings.Contains(body, want) {
			t.Errorf("settings page lacks %q", want)
		}
	}
	// Switch prune and forget off.
	wantRedirect(t, post(e.h, "/settings/notifications", cookie, url.Values{"csrf_token": {csrf},
		"event_failed": {"on"}, "event_attention": {"on"}, "event_sealed": {"on"}}, nil), "/settings")
	on := notify.EnabledIn(e.store)
	ctx := context.Background()
	if on(ctx, notify.Prune) || on(ctx, notify.Forget) || !on(ctx, notify.Failed) || !e.audit.has("notification settings changed") {
		t.Error("switches not stored or not audited")
	}
	if body := getWithCookie(e.h, "/settings", cookie).Body.String(); strings.Contains(body, `name="event_prune" value="on" checked`) {
		t.Error("prune still shown as on")
	}
	if w := post(e.h, "/settings/notifications", cookie, url.Values{"event_failed": {"on"}}, nil); w.Code != http.StatusForbidden {
		t.Errorf("without CSRF token: %d", w.Code)
	}

	// Test notification: sent, or the error shown.
	w := post(e.h, "/settings/notifications/test", cookie, url.Values{"csrf_token": {csrf}}, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "was sent") || len(e.notifier.sent) != 1 {
		t.Errorf("test: %d", w.Code)
	}
	e.notifier.sendErr = errors.New("webhook answered 403 Forbidden")
	if w := post(e.h, "/settings/notifications/test", cookie, url.Values{"csrf_token": {csrf}}, nil); w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), "403 Forbidden") {
		t.Errorf("failed test: %d", w.Code)
	}
}

func TestCheckAttention(t *testing.T) {
	e := newEnv(t, nil, true)
	ctx := context.Background()
	makeRepo(t, e.reposDir, "alice/main")
	makeRepo(t, e.reposDir, "bob/main")
	_ = e.store.SyncRepos(ctx, []string{"alice/main", "bob/main"})
	e.notifier.settings = e.store
	s := &server{Options: e.opts}
	now := time.Now()

	// Sealed: nothing is checked (every repository would lack its password).
	e.vault.sealed = true
	if err := s.checkAttention(ctx, now); err != nil || len(e.notifier.sent) != 0 {
		t.Fatalf("sealed: %v %+v", err, e.notifier.sent)
	}
	e.vault.sealed = false

	// First check: both lack a password.
	if err := s.checkAttention(ctx, now); err != nil {
		t.Fatal(err)
	}
	if len(e.notifier.sent) != 1 || e.notifier.sent[0].Title != "Needs attention: 2 new" || !strings.Contains(e.notifier.sent[0].Body, "alice/main: no password stored") {
		t.Fatalf("first: %+v", e.notifier.sent)
	}
	// Unchanged: no message.
	_ = s.checkAttention(ctx, now)
	if len(e.notifier.sent) != 1 {
		t.Errorf("repeated: %+v", e.notifier.sent[1:])
	}
	// alice gets a password: resolved.
	e.vault.secrets = []string{"repo:alice/main"}
	_ = s.checkAttention(ctx, now)
	if len(e.notifier.sent) != 2 || e.notifier.sent[1].Title != "Needs attention: 1 resolved" || !strings.Contains(e.notifier.sent[1].Body, "Resolved:\n- alice/main") {
		t.Errorf("resolved: %+v", e.notifier.sent)
	}
	// Switched off: the state is still kept, nothing is sent.
	_ = notify.SetEnabled(ctx, e.store, notify.Attention, false)
	e.vault.secrets = nil
	_ = s.checkAttention(ctx, now)
	if len(e.notifier.sent) != 2 {
		t.Error("sent although switched off")
	}
	_ = notify.SetEnabled(ctx, e.store, notify.Attention, true)
	_ = s.checkAttention(ctx, now)
	if len(e.notifier.sent) != 2 {
		t.Error("the change while switched off was reported later")
	}
	// Without a webhook nothing happens.
	e.notifier.configured = false
	if err := s.checkAttention(ctx, now); err != nil {
		t.Error(err)
	}
}
