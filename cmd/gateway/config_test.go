package main

import "testing"

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDevRoutesAreRefusedOutsideDevTestCI(t *testing.T) {
	for _, c := range []struct {
		name string
		env  map[string]string
		ok   bool
	}{
		{"off by default", map[string]string{}, true},
		{"dev with flag", map[string]string{"SYNC_DEV_REGISTER": "1", "HOSTRY_ENV": "dev"}, true},
		{"production with flag", map[string]string{"SYNC_DEV_REGISTER": "1", "HOSTRY_ENV": "production"}, false},
		{"no environment", map[string]string{"SYNC_DEV_REGISTER": "1"}, false},
		{"flag not 1", map[string]string{"SYNC_DEV_REGISTER": "yes", "HOSTRY_ENV": "dev"}, false},
	} {
		if _, err := loadExtras(env(c.env), "postgres://x"); (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
		}
	}
}

func TestRelayNeedsBothSettingsAndPostgres(t *testing.T) {
	if _, err := loadExtras(env(map[string]string{"SYNC_NATS_URL": "nats://x"}), "postgres://x"); err == nil {
		t.Error("a URL without a seed must be refused")
	}
	if _, err := loadExtras(env(map[string]string{"SYNC_NATS_URL": "nats://x", "SYNC_NATS_SEED_FILE": "/s"}), "file:x.db"); err == nil {
		t.Error("a relay on SQLite must be refused")
	}
	if x, err := loadExtras(env(map[string]string{"SYNC_NATS_URL": "nats://x", "SYNC_NATS_SEED_FILE": "/s"}), "postgres://x"); err != nil || x.NatsURL == "" {
		t.Errorf("valid relay config: %+v %v", x, err)
	}
}
