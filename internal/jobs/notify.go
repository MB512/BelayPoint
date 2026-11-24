package jobs

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/MB512/belaypoint/internal/notify"
)

// Notifier sends notifications (implemented by *notify.Notifier).
type Notifier interface {
	Notify(ctx context.Context, m notify.Message)
	Enabled(ctx context.Context, e notify.Event) bool
}

// notifyResult sends one notification per finished maintenance job: a
// failure (failed, refused, interrupted) or, for a success, the forget and
// prune summaries. A scheduled maintenance run sends one message with all
// its steps, not one per step. Snapshots and unlock jobs send nothing.
func (m *Manager) notifyResult(ctx context.Context, t task, state, summary string, err error, took time.Duration) {
	if m.notifier == nil {
		return
	}
	switch t.typ {
	case Maintenance, Forget, Prune, Check:
	default:
		return
	}
	what := string(t.typ)
	if t.typ == Maintenance {
		what = "maintenance"
	}
	if state != StateSucceeded {
		body := state
		if err != nil {
			body = err.Error()
		}
		m.notifier.Notify(ctx, notify.Message{
			Event: notify.Failed,
			Title: fmt.Sprintf("%s %s: %s", what, state, t.repo),
			Body:  fmt.Sprintf("%s\n\nJob %d, see its log in BelayPoint.", body, t.id),
		})
		return
	}
	// Success: the forget / prune parts of the summary, as far as their
	// events are switched on.
	var lines []string
	event := notify.Event("")
	for _, part := range strings.Split(summary, "; ") {
		step, text, ok := strings.Cut(part, ": ")
		if !ok { // a single-step job: the summary is the step's own text
			step, text = string(t.typ), part
		}
		var e notify.Event
		switch step {
		case "forget":
			e = notify.Forget
		case "prune":
			e = notify.Prune
		default:
			continue
		}
		if !m.notifier.Enabled(ctx, e) {
			continue
		}
		if event == "" {
			event = e
		}
		lines = append(lines, step+": "+text)
	}
	if len(lines) == 0 {
		return
	}
	title := fmt.Sprintf("%s done: %s", what, t.repo)
	if t.typ == Forget || t.typ == Prune {
		title = fmt.Sprintf("%s %s: %s", what, t.repo, strings.TrimPrefix(lines[0], what+": "))
	}
	m.notifier.Notify(ctx, notify.Message{
		Event: event,
		Title: title,
		Body:  strings.Join(lines, "\n") + fmt.Sprintf("\n\nTook %s (job %d).", took.Round(time.Second), t.id),
	})
}

// pruneStats picks the freed and remaining size from restic prune's
// output while it is written to the job log:
//
//	total prune:          62 blobs / 20.123 KiB
//	remaining:            32 blobs / 8.132 MiB
type pruneStats struct {
	buf              []byte
	freed, remaining string
}

var pruneLine = regexp.MustCompile(`^(total prune|remaining):\s+\d+ blobs / (.+)$`)

// Write is io.Writer: it splits the output into lines.
func (p *pruneStats) Write(b []byte) (int, error) {
	p.buf = append(p.buf, b...)
	for {
		i := bytes.IndexAny(p.buf, "\r\n")
		if i < 0 {
			break
		}
		p.line(strings.TrimSpace(string(p.buf[:i])))
		p.buf = p.buf[i+1:]
	}
	if len(p.buf) > 4096 { // a progress line without newline: not needed
		p.buf = p.buf[:0]
	}
	return len(b), nil
}

func (p *pruneStats) line(s string) {
	if m := pruneLine.FindStringSubmatch(s); m != nil {
		if m[1] == "total prune" {
			p.freed = m[2]
		} else {
			p.remaining = m[2]
		}
	}
}
