//go:build !devlan

package main

import (
	"context"
	"log/slog"
)

// devlanBuild is false in a release binary: it has no plain listener and no pack file source (ADR-0002 A3.1 item 1).
const devlanBuild = false

func devlanGuard(string) error { return nil }

func plainRequested(func(string) string) bool { return false }

func filePack(context.Context, func(string) string, *slog.Logger) (*node, bool, error) {
	return nil, false, nil
}
