//go:build !devlan

package main

import (
	"context"
	"log/slog"
	"testing"
)

// LT3 (release half): a release binary has no plain listener and no pack file source, whatever the environment asks for.
func TestLT3_ReleaseBinaryHasNoPlainListenerAndNoPackFile(t *testing.T) {
	get := func(k string) string {
		return map[string]string{"SYNC_HUB_PLAIN": "1", "SYNC_HUB_PACK": "/tmp/x.json", "HOSTRY_ENV": "dev"}[k]
	}
	if devlanBuild || plainRequested(get) {
		t.Fatal("a release hub must not offer a plain listener")
	}
	if _, ok, _ := filePack(context.Background(), get, slog.Default()); ok {
		t.Fatal("a release hub must not read a pack file")
	}
}

// The dev placement switch is refused outside dev, test and ci.
func TestPlacementLiftNeedsADevEnvironment(t *testing.T) {
	get := func(k string) string {
		return map[string]string{"SYNC_HUB_DEV_PII_LIFT": "1", "HOSTRY_ENV": "production"}[k]
	}
	if err := run(slog.Default(), get); err == nil {
		t.Fatal("the lift must be refused in production")
	}
}
