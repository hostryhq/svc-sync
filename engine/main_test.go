package engine

import (
	"os"
	"testing"
)

// The unit tests exercise every policy with the demo entities; the registry itself is checked in
// entities_test.go.
func TestMain(m *testing.M) {
	RegisterDemoEntities()
	os.Exit(m.Run())
}
