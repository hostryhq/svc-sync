// Command genintents generates, from the api-specs registries, the tables the gateway and the hub read:
// syncproto/intents_gen.go (intents: the gateway check, ADR-0002 S11, and the hub structural check, S8) and
// engine/entities_gen.go (entities: the conflict policy of every field the apply state follows, S6). The
// permission strings are the catalogue keys of the registry and nothing is typed in twice. Tests
// (syncproto.TestIntentTableIsGenerated, engine.TestEntityTableIsGenerated) fail when a checked-in file
// differs from what this command writes for the pinned api-specs checkout.
//
//	go run ./cmd/genintents [-out syncproto/intents_gen.go] [-entities-out engine/entities_gen.go]   (API_SPECS_DIR or a sibling checkout)
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/hostryhq/svc-sync/contract/specs"
	"github.com/hostryhq/svc-sync/engine/entitygen"
	"github.com/hostryhq/svc-sync/syncproto/intentgen"
)

func main() {
	out := flag.String("out", "syncproto/intents_gen.go", "intent table output file")
	eout := flag.String("entities-out", "engine/entities_gen.go", "entity table output file")
	flag.Parse()
	dir, err := specs.Path("sync", "intents")
	fatal(err)
	src, err := intentgen.Generate(dir)
	fatal(err)
	fatal(os.WriteFile(*out, src, 0o644))
	edir, err := specs.Path("entities")
	fatal(err)
	esrc, err := entitygen.Generate(edir)
	fatal(err)
	fatal(os.WriteFile(*eout, esrc, 0o644))
}

func fatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
