package keyprotect

import (
	"path/filepath"
	"testing"
)

// F26: a key file the provider creates itself must unwrap in the next process.
func TestDevKeyFileCreatedByProviderSurvivesRestart(t *testing.T) {
	f := filepath.Join(t.TempDir(), "key")
	first, err := NewDev("test", f)
	if err != nil {
		t.Fatal(err)
	}
	w, err := first.Wrap([]byte("data-key"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewDev("test", f)
	if err != nil {
		t.Fatal(err)
	}
	got, err := second.Unwrap(w)
	if err != nil || string(got) != "data-key" {
		t.Fatalf("next process cannot unwrap: %v", err)
	}
}

func TestDevRefusesOutsideDevEnv(t *testing.T) {
	if _, err := NewDev("production", filepath.Join(t.TempDir(), "key")); err == nil {
		t.Fatal("production must be refused")
	}
}
