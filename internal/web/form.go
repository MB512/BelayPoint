package web

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
)

// maxFormBytes bounds a form body; the forms here are small.
const maxFormBytes = 16 << 10

var errBadForm = errors.New("bad form")

// form holds the fields of an application/x-www-form-urlencoded body as
// []byte. net/http's own parser (r.PostFormValue) returns strings, which
// cannot be zeroed; passwords must stay in []byte (CLAUDE.md, hard rules).
// Call wipe when done, typically with defer.
type form map[string][]byte

// readForm reads and parses the request body. The raw body is zeroed after
// parsing. Duplicate fields are rejected.
func readForm(r *http.Request) (form, error) {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/x-www-form-urlencoded" {
		return nil, fmt.Errorf("%w: content type %q", errBadForm, r.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxFormBytes+1))
	defer clear(body)
	if err != nil {
		return nil, fmt.Errorf("reading form: %w", err)
	}
	if len(body) > maxFormBytes {
		return nil, fmt.Errorf("%w: body too large", errBadForm)
	}
	f := form{}
	rest := body
	for len(rest) > 0 {
		var pair []byte
		pair, rest, _ = bytes.Cut(rest, []byte("&"))
		if len(pair) == 0 {
			continue
		}
		k, v, _ := bytes.Cut(pair, []byte("="))
		key, err := unescape(k)
		if err != nil {
			f.wipe()
			return nil, err
		}
		name := string(key)
		val, err := unescape(v)
		if err != nil {
			f.wipe()
			return nil, err
		}
		if _, dup := f[name]; dup {
			clear(val)
			f.wipe()
			return nil, fmt.Errorf("%w: duplicate field %q", errBadForm, name)
		}
		f[name] = val
	}
	return f, nil
}

// get returns a field as string. Use it only for values that are not
// secrets.
func (f form) get(name string) string { return string(f[name]) }

// wipe zeroes all values.
func (f form) wipe() {
	for _, v := range f {
		clear(v)
	}
}

// unescape decodes "+" and %XX into a new slice.
func unescape(s []byte) ([]byte, error) {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '+':
			out = append(out, ' ')
		case '%':
			if i+2 >= len(s) {
				clear(out)
				return nil, fmt.Errorf("%w: truncated escape", errBadForm)
			}
			hi, ok1 := unhex(s[i+1])
			lo, ok2 := unhex(s[i+2])
			if !ok1 || !ok2 {
				clear(out)
				return nil, fmt.Errorf("%w: invalid escape", errBadForm)
			}
			out = append(out, hi<<4|lo)
			i += 2
		default:
			out = append(out, c)
		}
	}
	return out, nil
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
