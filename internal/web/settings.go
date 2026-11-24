package web

import (
	"context"
	"net/http"
	"strings"

	"github.com/MB512/belaypoint/internal/notify"
)

// settingsData is the Settings page.
type settingsData struct {
	// Target is the webhook's address without its path (the topic name
	// may act as a secret), "" when not configured.
	Target   string
	TokenSet bool
	Events   []eventSwitch
	// Result is the outcome of "Send test notification".
	Result string
	OK     bool
}

type eventSwitch struct {
	Event notify.Event
	Label string
	On    bool
}

func (s *server) settingsPage(w http.ResponseWriter, r *http.Request) {
	s.renderSettings(w, r, http.StatusOK, "", false)
}

func (s *server) renderSettings(w http.ResponseWriter, r *http.Request, status int, result string, ok bool) {
	d := &settingsData{Target: s.NotifyTarget, TokenSet: s.NotifyTokenSet, Result: result, OK: ok}
	enabled := s.enabledFunc()
	for _, e := range notify.Events {
		d.Events = append(d.Events, eventSwitch{Event: e, Label: e.Label(), On: enabled(r.Context(), e)})
	}
	s.render(w, status, "settings.html", page{Title: "Settings", CSRF: sessionFrom(r.Context()).CSRF, Settings: d})
}

// enabledFunc reads the switches (all on without a settings store).
func (s *server) enabledFunc() notify.Enabled {
	if s.Settings == nil {
		return func(context.Context, notify.Event) bool { return true }
	}
	return notify.EnabledIn(s.Settings)
}

// setNotifications stores the event switches (checkbox event_<name>).
func (s *server) setNotifications(w http.ResponseWriter, r *http.Request) {
	f, ok := s.postForm(w, r)
	if !ok {
		return
	}
	defer f.wipe()
	if s.Settings == nil {
		http.Error(w, "settings are not available", http.StatusServiceUnavailable)
		return
	}
	var parts []string
	for _, e := range notify.Events {
		on := f.get("event_"+string(e)) == "on"
		if err := notify.SetEnabled(r.Context(), s.Settings, e, on); err != nil {
			s.Logger.Error("storing notification setting", "event", e, "err", err)
			http.Error(w, "storing the settings failed; see the container log", http.StatusInternalServerError)
			return
		}
		state := "off"
		if on {
			state = "on"
		}
		parts = append(parts, string(e)+" "+state)
	}
	s.Audit.Audit(r.Context(), "notification settings changed", strings.Join(parts, ", ")+", "+remote(r))
	redirect(w, r, "/settings")
}

// testNotification sends a test message right away and shows the result.
func (s *server) testNotification(w http.ResponseWriter, r *http.Request) {
	f, ok := s.postForm(w, r)
	if !ok {
		return
	}
	f.wipe()
	if s.Notifier == nil || !s.Notifier.Configured() {
		s.renderSettings(w, r, http.StatusBadRequest, "No webhook is configured (BELAYPOINT_NOTIFY_URL).", false)
		return
	}
	err := s.Notifier.SendNow(r.Context(), notify.Message{
		Event: notify.Test, Title: "BelayPoint test notification",
		Body: "Notifications from BelayPoint reach you.",
	})
	if err != nil {
		s.Audit.Audit(r.Context(), "test notification failed", err.Error()+", "+remote(r))
		s.renderSettings(w, r, http.StatusBadGateway, "Sending failed: "+err.Error(), false)
		return
	}
	s.Audit.Audit(r.Context(), "test notification sent", remote(r))
	s.renderSettings(w, r, http.StatusOK, "The test notification was sent.", true)
}
