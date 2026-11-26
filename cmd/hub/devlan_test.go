//go:build devlan

package main

import (
	"log/slog"
	"strings"
	"testing"
)

// LT3 (second half): a hub built with the devlan tag refuses to start outside HOSTRY_ENV dev, test and ci.
func TestLT3_DevlanBinaryRefusesToStartOutsideDevTestCI(t *testing.T) {
	for _, env := range []string{"", "prod", "production", "staging"} {
		get := func(k string) string {
			if k == "HOSTRY_ENV" {
				return env
			}
			return ""
		}
		err := run(slog.Default(), get)
		if err == nil || !strings.Contains(err.Error(), "devlan") {
			t.Errorf("HOSTRY_ENV=%q: the devlan binary must refuse to start, got %v", env, err)
		}
	}
	if err := devlanGuard("ci"); err != nil {
		t.Errorf("ci is allowed: %v", err)
	}
}
