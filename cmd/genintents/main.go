// Command genintents generates syncproto/intents_gen.go from the canonical intent registry
// (api-specs sync/intents/*.yaml): the gateway check (ADR-0002 S11) and the hub structural check
// (S8) read the generated table, so the permission strings are the catalogue keys of the registry
// and nothing is typed in twice. A test (syncproto.TestIntentTableIsGenerated) fails when the
// checked-in file differs from what this command writes for the pinned api-specs checkout.
//
//	go run ./cmd/genintents [-out syncproto/intents_gen.go]   (API_SPECS_DIR or a sibling checkout)
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/hostryhq/svc-sync/contract/specs"
	"github.com/hostryhq/svc-sync/syncproto/intentgen"
)

func main() {
	out := flag.String("out", "syncproto/intents_gen.go", "output file")
	flag.Parse()
	dir, err := specs.Path("sync", "intents")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	src, err := intentgen.Generate(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, src, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
