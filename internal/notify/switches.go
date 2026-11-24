package notify

import "context"

// SettingStore keeps the switches (implemented by *store.Store).
type SettingStore interface {
	Setting(ctx context.Context, key string) (string, bool, error)
	SetSetting(ctx context.Context, key, value string) error
}

func settingKey(e Event) string { return "notify." + string(e) }

// EnabledIn reads the switches from st. An event that was never switched
// is on; if the setting cannot be read, it is on too (better one message
// too many than a missed failure).
func EnabledIn(st SettingStore) Enabled {
	return func(ctx context.Context, e Event) bool {
		v, ok, err := st.Setting(ctx, settingKey(e))
		return err != nil || !ok || v != "off"
	}
}

// SetEnabled switches an event on or off.
func SetEnabled(ctx context.Context, st SettingStore, e Event, on bool) error {
	v := "off"
	if on {
		v = "on"
	}
	return st.SetSetting(ctx, settingKey(e), v)
}
