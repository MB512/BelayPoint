package jobs

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// LogPath returns the log file of job id in dir.
func LogPath(dir string, id int64) string {
	return filepath.Join(dir, strconv.FormatInt(id, 10)+".log")
}

// redactor replaces a secret in everything written through it. It works on
// whole lines, so a secret split across two writes is still found; a
// partial line is kept until the next newline or Close.
type redactor struct {
	w      io.Writer
	secret []byte
	buf    []byte
}

var redacted = []byte("[redacted]")

func (r *redactor) Write(p []byte) (int, error) {
	r.buf = append(r.buf, p...)
	i := bytes.LastIndexByte(r.buf, '\n')
	if i < 0 {
		return len(p), nil
	}
	if err := r.flush(r.buf[:i+1]); err != nil {
		return 0, err
	}
	r.buf = append(r.buf[:0], r.buf[i+1:]...)
	return len(p), nil
}

func (r *redactor) flush(b []byte) error {
	if len(r.secret) > 0 {
		b = bytes.ReplaceAll(b, r.secret, redacted)
	}
	_, err := r.w.Write(b)
	return err
}

// Close writes a remaining partial line.
func (r *redactor) Close() error {
	if len(r.buf) == 0 {
		return nil
	}
	err := r.flush(r.buf)
	clear(r.buf)
	r.buf = r.buf[:0]
	return err
}

// jobLog is the log file of one job.
type jobLog struct {
	f   *os.File
	red *redactor
}

func createLog(dir string, id int64, secret []byte) (*jobLog, error) {
	f, err := os.OpenFile(LogPath(dir, id), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("creating job log: %w", err)
	}
	return &jobLog{f: f, red: &redactor{w: f, secret: secret}}, nil
}

// Write implements io.Writer for restic's output.
func (l *jobLog) Write(p []byte) (int, error) { return l.red.Write(p) }

// Printf writes a line of BelayPoint's own (no secrets go here).
func (l *jobLog) Printf(now time.Time, format string, args ...any) {
	_ = l.red.Close() // finish a partial restic line first
	fmt.Fprintf(l.f, "[%s] %s\n", now.Format("2006-01-02 15:04:05"), strings.TrimSpace(fmt.Sprintf(format, args...)))
}

func (l *jobLog) Close() error {
	err := l.red.Close()
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	return err
}

// CleanLogs removes job logs older than retention from dir. Only files
// named <number>.log are touched.
func CleanLogs(dir string, retention time.Duration, now time.Time) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("cleaning job logs: %w", err)
	}
	n := 0
	for _, e := range entries {
		name := e.Name()
		num, ok := strings.CutSuffix(name, ".log")
		if !ok || !e.Type().IsRegular() {
			continue
		}
		if _, err := strconv.ParseInt(num, 10, 64); err != nil {
			continue
		}
		info, err := e.Info()
		if err != nil || now.Sub(info.ModTime()) < retention {
			continue
		}
		if err := os.Remove(filepath.Join(dir, name)); err == nil {
			n++
		}
	}
	return n, nil
}
