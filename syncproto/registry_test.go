package syncproto

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/hostryhq/svc-sync/contract/specs"
	"github.com/hostryhq/svc-sync/syncproto/intentgen"
	"gopkg.in/yaml.v3"
)

// The intent table is generated from the registry; a checked-in table that differs means the
// registry moved (or the table was edited by hand).
func TestIntentTableIsGenerated(t *testing.T) {
	dir, err := specs.Path("sync", "intents")
	if err != nil {
		t.Fatal(err)
	}
	want, err := intentgen.Generate(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("intents_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatal("syncproto/intents_gen.go is out of date; run: go run ./cmd/genintents")
	}
}

// No PoC permission string survives, and every device permission is a catalogue key.
func TestIntentPermissionsAreCatalogueKeys(t *testing.T) {
	p, err := specs.Path("common", "permissions.yaml")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Permissions []struct {
			Key string `yaml:"key"`
		} `yaml:"permissions"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	for _, k := range doc.Permissions {
		keys[k.Key] = true
	}
	if len(keys) < 50 {
		t.Fatalf("the catalogue was not read (%d keys)", len(keys))
	}
	for name, in := range Intents {
		if name == IntentPIIErase {
			continue // provisional, no permission
		}
		if in.Permission != "" && !keys[in.Permission] {
			t.Errorf("intent %s: permission %q is not a catalogue key", name, in.Permission)
		}
		switch in.Permission {
		case "bill.refund", "payment.take", "kds.update", "menu.edit", "stock.adjust":
			t.Errorf("intent %s keeps the PoC permission string %q", name, in.Permission)
		}
	}
}

// The documents the gateway reads from rows (docFields) are exactly the doc_number fields of the entity registry.
func TestDocFieldsMatchTheEntityRegistry(t *testing.T) {
	dir, err := specs.Path("entities")
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*", "*.yaml"))
	var found []string
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		var e struct {
			Entity string `yaml:"entity"`
			Fields map[string]struct {
				DocNumber bool `yaml:"doc_number"`
			} `yaml:"fields"`
		}
		if err := yaml.Unmarshal(raw, &e); err != nil {
			t.Fatal(err)
		}
		for name, fl := range e.Fields {
			if fl.DocNumber {
				found = append(found, e.Entity+"."+name)
			}
		}
	}
	var have []string
	for e, d := range docFields {
		have = append(have, e+"."+d.Field)
	}
	sort.Strings(found)
	sort.Strings(have)
	if len(found) != len(have) {
		t.Fatalf("doc_number fields in entities/ %v, gateway reads %v", found, have)
	}
	for i := range found {
		if found[i] != have[i] {
			t.Fatalf("doc_number fields in entities/ %v, gateway reads %v", found, have)
		}
	}
}

func TestRebillCarriesTwoNumbers(t *testing.T) {
	b := Body{Doc: &Doc{Type: "credit_note", Number: "AAB/2627/000004"}, Muts: []Mut{
		{E: "credit_note", ID: "c1", K: KInsert, F: map[string]any{"number": "AAB/2627/000004"}},
		{E: "bill", ID: "b2", K: KInsert, F: map[string]any{"number": "AAA/2627/000009", "doc_type": "tax_invoice"}},
	}}
	docs := b.Documents()
	if len(docs) != 2 || docs[0].Number != "AAB/2627/000004" || docs[1].Type != "tax_invoice" {
		t.Fatalf("documents: %+v", docs)
	}
}
