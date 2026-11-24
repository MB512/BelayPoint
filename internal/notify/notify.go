// Package notify sends notifications to an ntfy-compatible webhook: an
// HTTP POST to the topic URL with the message as text body and the title,
// priority and tags as headers (https://docs.ntfy.sh/publish/).
//
// Messages are queued and sent in the background, so a slow or failing
// webhook never blocks or fails a job; problems are logged. Every event
// type can be switched off (Settings page).
package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Event is the kind of a notification; each can be enabled on its own.
type Event string

// The events (see docs/architecture.md, "Notifications").
const (
	Failed    Event = "failed"    // maintenance failed, refused, interrupted or skipped
	Attention Event = "attention" // "Needs attention" on the overview changed
	Sealed    Event = "sealed"    // started and therefore sealed
	Forget    Event = "forget"    // forget summary
	Prune     Event = "prune"     // prune summary
	Test      Event = "test"      // "Send test notification"; always sent
)

// Events lists the switchable events in display order.
var Events = []Event{Failed, Attention, Sealed, Forget, Prune}

// Label is the text of an event's checkbox.
func (e Event) Label() string {
	return map[Event]string{
		Failed:    "Maintenance failed, was refused, interrupted or skipped",
		Attention: `"Needs attention" changed (problems that appeared or were resolved)`,
		Sealed:    "BelayPoint started and is sealed (nothing runs until someone logs in)",
		Forget:    "Forget summary (snapshots removed and kept)",
		Prune:     "Prune summary (space freed, remaining, duration)",
	}[e]
}

// Message is one notification.
type Message struct {
	Event Event
	Title string
	Body  string
}

// priority and tags are ntfy headers per event: problems are "high", the
// summaries "low" (no sound on the phone).
func (m Message) priority() string {
	switch m.Event {
	case Failed, Attention, Sealed:
		return "high"
	case Forget, Prune:
		return "low"
	}
	return "default"
}

func (m Message) tags() string {
	return map[Event]string{Failed: "x", Attention: "warning", Sealed: "lock", Forget: "broom", Prune: "broom", Test: "white_check_mark"}[m.Event]
}

// Enabled reports whether an event is switched on (implemented by the
// settings in *store.Store).
type Enabled func(ctx context.Context, e Event) bool

// queueSize bounds the messages waiting to be sent; when it is full, new
// ones are dropped (and logged) rather than blocking a job.
const queueSize = 64

// SendTimeout bounds one HTTP request to the webhook.
const SendTimeout = 15 * time.Second

// Notifier queues and sends notifications. The zero value is not usable;
// create it with New. A Notifier without URL drops every message, so
// callers need not check whether notifications are configured.
type Notifier struct {
	url, token string
	enabled    Enabled
	client     *http.Client
	logger     *slog.Logger

	queue chan Message
}

// New returns a Notifier for the webhook url (empty: disabled). token, if
// set, is sent as "Authorization: Bearer" (ntfy access token).
func New(url, token string, enabled Enabled, logger *slog.Logger) *Notifier {
	return &Notifier{
		url: url, token: token, enabled: enabled, logger: logger,
		client: &http.Client{Timeout: SendTimeout},
		queue:  make(chan Message, queueSize),
	}
}

// Configured reports whether a webhook URL is set.
func (n *Notifier) Configured() bool { return n != nil && n.url != "" }

// Run sends queued messages until ctx ends; call it once, in a goroutine
// (like a consumer Task of a Channel<T> in C#), and wait for it to return
// at shutdown. Messages still queued at the end are sent with a short
// grace period, so a shutdown does not lose a final failure notice.
func (n *Notifier) Run(ctx context.Context) {
	for {
		select {
		case m := <-n.queue:
			n.send(context.WithoutCancel(ctx), m)
		case <-ctx.Done():
			grace, cancel := context.WithTimeout(context.WithoutCancel(ctx), SendTimeout)
			defer cancel()
			for {
				select {
				case m := <-n.queue:
					n.send(grace, m)
				default:
					return
				}
			}
		}
	}
}

// Enabled reports whether messages of event e would be sent: a webhook is
// configured and the event is switched on.
func (n *Notifier) Enabled(ctx context.Context, e Event) bool {
	return n.Configured() && (e == Test || n.enabled == nil || n.enabled(ctx, e))
}

// Notify queues a message if notifications are configured and its event is
// enabled. It never blocks: with a full queue the message is dropped.
func (n *Notifier) Notify(ctx context.Context, m Message) {
	if !n.Enabled(ctx, m.Event) {
		return
	}
	select {
	case n.queue <- m:
	default:
		n.logger.Warn("notification dropped: queue full", "event", m.Event, "title", m.Title)
	}
}

// SendNow sends a message synchronously and returns the error (for "Send
// test notification", which reports the result on the page).
func (n *Notifier) SendNow(ctx context.Context, m Message) error {
	if !n.Configured() {
		return fmt.Errorf("no webhook configured (BELAYPOINT_NOTIFY_URL)")
	}
	return n.post(ctx, m)
}

func (n *Notifier) send(ctx context.Context, m Message) {
	if err := n.post(ctx, m); err != nil {
		n.logger.Warn("sending notification", "event", m.Event, "title", m.Title, "err", err)
	}
}

// post sends one message. The token is only ever put into the header; the
// URL is not logged (it may contain a secret topic name).
func (n *Notifier) post(ctx context.Context, m Message) error {
	ctx, cancel := context.WithTimeout(ctx, SendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, strings.NewReader(m.Body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("Title", headerValue(m.Title))
	req.Header.Set("Priority", m.priority())
	if t := m.tags(); t != "" {
		req.Header.Set("Tags", t)
	}
	if n.token != "" {
		req.Header.Set("Authorization", "Bearer "+n.token)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		// The error text of net/http contains the URL; keep it out.
		return fmt.Errorf("webhook request failed: %w", unwrapURL(err))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("webhook answered %s", resp.Status)
	}
	return nil
}

// headerValue keeps a title usable as an HTTP header: one line, ASCII
// (ntfy accepts UTF-8 titles only RFC 2047-encoded; plain ASCII is simpler).
func headerValue(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r > 0x7e:
			b.WriteByte('?')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// unwrapURL drops the *url.Error wrapper of net/http, whose text repeats
// the request URL.
func unwrapURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}
