package web

import (
	"net/http"
	"strconv"
)

const auditPageSize = 100

type auditRow struct {
	Time    string
	Event   string
	Details string
}

// auditPage shows the audit log, newest first, auditPageSize entries per
// page; ?before=<id> continues after the last entry of the previous page.
func (s *server) auditPage(w http.ResponseWriter, r *http.Request) {
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	entries, err := s.AuditLog.ListAudit(r.Context(), auditPageSize, before)
	if err != nil {
		s.Logger.Error("reading audit log", "err", err)
		http.Error(w, "reading the audit log failed; see the container log", http.StatusInternalServerError)
		return
	}
	p := page{Title: "Audit log", CSRF: sessionFrom(r.Context()).CSRF}
	for _, e := range entries {
		p.Audit = append(p.Audit, auditRow{
			Time:    e.Time.In(s.Location).Format("2006-01-02 15:04:05"),
			Event:   e.Event,
			Details: e.Details,
		})
	}
	if len(entries) == auditPageSize {
		p.NextBefore = entries[len(entries)-1].ID
	}
	s.render(w, http.StatusOK, "audit.html", p)
}
