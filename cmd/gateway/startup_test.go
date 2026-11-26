package main

import "testing"

// P2-M6: the stub directory (an in-process test issuer) and a privileged database role are allowed only in dev, test and ci.
func TestStubDirectoryAndPrivilegedRoleAreTiedToTheEnvironment(t *testing.T) {
	for _, c := range []struct {
		env     string
		allowed bool
	}{{"dev", true}, {"test", true}, {"ci", true}, {"", false}, {"staging", false}, {"production", false}} {
		if err := checkStub(c.env); (err == nil) != c.allowed {
			t.Errorf("SYNC_DEV_STUB in %q: err=%v, want allowed=%v", c.env, err, c.allowed)
		}
		if got := privilegedRoleAllowed(c.env); got != c.allowed {
			t.Errorf("a privileged role in %q: got %v, want %v", c.env, got, c.allowed)
		}
	}
}
