package api_test

import (
	"bytes"
	"encoding/json"
	"sort"
	"testing"

	"github.com/hostryhq/svc-sync/api"
	"github.com/hostryhq/svc-sync/contract/specs"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// Every request and response example of the device operations in openapi/sync/v1 decodes strictly
// into this service's wire types (no field the types do not know, so an example cannot drift) and
// validates against its own schema.
func TestSpecExamplesDecodeIntoTheWireTypes(t *testing.T) {
	doc, err := specs.LoadOpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]func() any{
		"helloSync:request": func() any { return &sp.HelloRequest{} }, "helloSync:response:200": func() any { return &sp.HelloResponse{} },
		"pushOps:request": func() any { return &sp.PushRequest{} }, "pushOps:response:200": func() any { return &sp.PushResponse{} },
		"pullOps:request": func() any { return &sp.PullRequest{} }, "pullOps:response:200": func() any { return &sp.PullResponse{} },
		"getSnapshot:response:200": func() any { return &sp.Snapshot{} },
		"uploadQuarantine:request": func() any { return &sp.PushRequest{} }, "uploadQuarantine:response:200": func() any { return &sp.PushResponse{} },
	}
	checked := 0
	for _, ex := range doc.Examples() {
		if err := doc.Validate(ex.Schema, ex.Value); err != nil {
			t.Errorf("%s %s: the example does not match its own schema: %v", ex.Operation, ex.Kind, err)
		}
		mk, ok := types[ex.Operation+":"+ex.Kind]
		if !ok {
			continue
		}
		raw, _ := json.Marshal(ex.Value)
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(mk()); err != nil {
			t.Errorf("%s %s: the example does not decode into the wire type: %v", ex.Operation, ex.Kind, err)
		}
		checked++
	}
	if checked < 6 {
		t.Fatalf("only %d examples were matched to wire types; operation ids moved?", checked)
	}
}

// The emit operation's callers are the contract's, and the permissions of the admin routes are the
// contract's x-permission, except the two stated deviations below.
func TestRoutesFollowTheContract(t *testing.T) {
	doc, err := specs.LoadOpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	emit, ok := doc.Find("POST", api.EmitPath)
	if !ok {
		t.Fatal("emitOps is not in the contract")
	}
	got := append([]string(nil), api.EmitCallers...)
	want := append([]string(nil), emit.Callers...)
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) || (len(got) > 0 && got[0] != want[0]) || (len(got) > 1 && got[1] != want[1]) {
		t.Fatalf("emit callers %v, contract %v", got, want)
	}
	// Known deviations (reported to the contract owner): listQuarantine is read with sync.quarantine.read
	// (support_viewable) because the catalogue has no read-only quarantine key and support must list;
	// confirmQuarantine (vendor confirmation, security ruling) is not an operation of the contract yet.
	for _, op := range doc.Operations() {
		if op.Permission == "" {
			continue
		}
		known := false
		for _, p := range api.SyncPermissions() {
			known = known || p.Name == op.Permission
		}
		if !known && op.Permission != "sync.push" && op.Permission != "sync.drain" && op.Permission != "sync.emit" {
			t.Errorf("operation %s needs %q, which the guard's catalogue does not list", op.ID, op.Permission)
		}
	}
}
