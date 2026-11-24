package web

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/MB512/belaypoint/internal/notify"
)

// Notifications sends notifications (implemented by *notify.Notifier).
type Notifications interface {
	Configured() bool
	Enabled(ctx context.Context, e notify.Event) bool
	Notify(ctx context.Context, m notify.Message)
	SendNow(ctx context.Context, m notify.Message) error
}

// attentionKey is the setting with the last notified "Needs attention"
// entries (JSON: key -> text), so a restart does not repeat them.
const attentionKey = "attention.notified"

// WatchAttention checks "Needs attention" first after the delay first, then
// every interval, and notifies about entries that appeared or were
// resolved since the last notification. It returns when ctx ends; run it
// in a goroutine.
func WatchAttention(ctx context.Context, o Options, first, every time.Duration) {
	s := &server{Options: o}
	t := time.NewTimer(first)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := s.checkAttention(ctx, time.Now()); err != nil {
			s.Logger.Warn("checking what needs attention", "err", err)
		}
		t.Reset(every)
	}
}

// checkAttention compares the current "Needs attention" entries with the
// last notified ones. While sealed nothing is checked: without the vault
// every repository would look like it had no password. Failed maintenance
// is left out: the "failed" event reports it already, when it happens.
// The state is stored even when the event is switched off, so switching
// it on later reports only what changes from then on.
func (s *server) checkAttention(ctx context.Context, now time.Time) error {
	if s.Notifier == nil || !s.Notifier.Configured() || s.Settings == nil || s.Vault.Sealed() {
		return nil
	}
	rows, err := s.repoRows(ctx, now)
	if err != nil {
		return err
	}
	cur := map[string]string{}
	for _, a := range overview(rows).Attention {
		if a.Kind == "job" {
			continue
		}
		cur[a.Path+" ("+a.Kind+")"] = a.Path + ": " + a.Problem
	}
	prev := map[string]string{}
	if v, ok, err := s.Settings.Setting(ctx, attentionKey); err != nil {
		return err
	} else if ok {
		if err := json.Unmarshal([]byte(v), &prev); err != nil {
			s.Logger.Warn("stored attention state unreadable, starting over", "err", err)
			prev = map[string]string{}
		}
	}
	var added, resolved []string
	for k, text := range cur {
		if _, ok := prev[k]; !ok {
			added = append(added, text)
		}
	}
	for k, text := range prev {
		if _, ok := cur[k]; !ok {
			resolved = append(resolved, text)
		}
	}
	if len(added) == 0 && len(resolved) == 0 {
		return nil
	}
	data, err := json.Marshal(cur)
	if err != nil {
		return err
	}
	if err := s.Settings.SetSetting(ctx, attentionKey, string(data)); err != nil {
		return err
	}
	slices.Sort(added)
	slices.Sort(resolved)
	var body strings.Builder
	if len(added) > 0 {
		fmt.Fprintf(&body, "New:\n- %s\n", strings.Join(added, "\n- "))
	}
	if len(resolved) > 0 {
		if body.Len() > 0 {
			body.WriteString("\n")
		}
		fmt.Fprintf(&body, "Resolved:\n- %s\n", strings.Join(resolved, "\n- "))
	}
	fmt.Fprintf(&body, "\n%d %s now.", len(cur), plural(len(cur), "entry needs", "entries need")+" attention")
	title := "Needs attention: "
	switch {
	case len(added) > 0 && len(resolved) > 0:
		title += fmt.Sprintf("%d new, %d resolved", len(added), len(resolved))
	case len(added) > 0:
		title += fmt.Sprintf("%d new", len(added))
	default:
		title += fmt.Sprintf("%d resolved", len(resolved))
	}
	s.Notifier.Notify(ctx, notify.Message{Event: notify.Attention, Title: title, Body: body.String()})
	return nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
