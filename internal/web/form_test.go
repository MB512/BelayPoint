package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadForm(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		want        map[string]string
		wantErr     bool
	}{
		{"simple", "application/x-www-form-urlencoded", "a=1&b=two", map[string]string{"a": "1", "b": "two"}, false},
		{"with charset", "application/x-www-form-urlencoded; charset=UTF-8", "a=1", map[string]string{"a": "1"}, false},
		{"escapes", "application/x-www-form-urlencoded", "p=a+b%26c%3D%C3%A4%25", map[string]string{"p": "a b&c=ä%"}, false},
		{"escaped key", "application/x-www-form-urlencoded", "csrf%5Ftoken=x", map[string]string{"csrf_token": "x"}, false},
		{"empty value and no =", "application/x-www-form-urlencoded", "a=&b&&c=3", map[string]string{"a": "", "b": "", "c": "3"}, false},
		{"empty body", "application/x-www-form-urlencoded", "", map[string]string{}, false},
		{"duplicate", "application/x-www-form-urlencoded", "a=1&a=2", nil, true},
		{"truncated escape", "application/x-www-form-urlencoded", "a=%4", nil, true},
		{"bad escape", "application/x-www-form-urlencoded", "a=%zz", nil, true},
		{"too large", "application/x-www-form-urlencoded", "a=" + strings.Repeat("x", maxFormBytes), nil, true},
		{"multipart", "multipart/form-data; boundary=x", "a=1", nil, true},
		{"no content type", "", "a=1", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", strings.NewReader(tt.body))
			if tt.contentType != "" {
				r.Header.Set("Content-Type", tt.contentType)
			}
			f, err := readForm(r)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("no error, got %v", f)
				}
				if !errors.Is(err, errBadForm) {
					t.Errorf("error %v is not errBadForm", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(f) != len(tt.want) {
				t.Errorf("got %d fields, want %d: %v", len(f), len(tt.want), f)
			}
			for k, v := range tt.want {
				if f.get(k) != v {
					t.Errorf("%s = %q, want %q", k, f.get(k), v)
				}
			}
		})
	}
}

func TestFormWipe(t *testing.T) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", strings.NewReader("password=secret"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	f, err := readForm(r)
	if err != nil {
		t.Fatal(err)
	}
	pw := f["password"]
	f.wipe()
	if string(pw) != "\x00\x00\x00\x00\x00\x00" {
		t.Errorf("after wipe: %q", pw)
	}
}
