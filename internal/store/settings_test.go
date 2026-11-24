package store

import (
	"context"
	"testing"
)

func TestSettings(t *testing.T) {
	ctx := context.Background()
	s, _ := openTest(t)
	if v, ok, err := s.Setting(ctx, "notify.failed"); err != nil || ok || v != "" {
		t.Fatalf("unset: %q %v %v", v, ok, err)
	}
	for _, v := range []string{"off", "on"} {
		if err := s.SetSetting(ctx, "notify.failed", v); err != nil {
			t.Fatal(err)
		}
		if got, ok, _ := s.Setting(ctx, "notify.failed"); !ok || got != v {
			t.Errorf("got %q, want %q", got, v)
		}
	}
}
