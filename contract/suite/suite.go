// Package suite is the shared contract suite for the sync API (api-contract-standard): the same
// tests run against the real gateway and against double/, so the double cannot drift. It speaks
// only HTTP and the wire types; the target supplies registered devices.
package suite

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// Dev is a device registered with the target.
type Dev struct {
	ID         string
	Key        *sp.KeyPair
	Cred       sp.CredentialEnvelope
	SaleCode   string
	Token      func() string
	DrainToken func(recovers string) string
}

// Target is a running implementation of the contract.
type Target struct {
	Handler     http.Handler
	Tenant      string
	Outlet      string
	Now         func() time.Time
	IdentityPub *ecdsa.PublicKey
	CloudPub    *ecdsa.PublicKey
	NewPOS      func() (Dev, error)
}

type node struct {
	d   Dev
	eng *engine.Engine
}

func (tg Target) node(t *testing.T) *node {
	t.Helper()
	d, err := tg.NewPOS()
	if err != nil {
		t.Fatal(err)
	}
	st, err := repository.Open("file:suite-" + d.ID + "-" + t.Name() + "?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cache := engine.NewCredCache(tg.IdentityPub, tg.Tenant, tg.Outlet, tg.Now)
	_ = cache.Add(d.Cred)
	cache.AddCloudKey("gateway-op-1", tg.CloudPub)
	e := engine.New(engine.Config{Role: engine.RoleDevice, Tenant: tg.Tenant, Outlet: tg.Outlet, Origin: d.ID, Key: d.Key, Store: st, Trust: cache,
		Clock: sp.NewClock(tg.Now), Series: series(d.SaleCode)})
	if err := e.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &node{d: d, eng: e}
}

type series string

func (s series) Code(string) (string, bool) { return string(s), s != "" }

func (tg Target) do(t *testing.T, method, path, token string, in, out any) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	if in != nil {
		body, _ = json.Marshal(in)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	tg.Handler.ServeHTTP(rec, req)
	if out != nil && rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("%s %s: response is not the documented shape: %v", method, path, err)
		}
	}
	return rec
}

func record(t *testing.T, n *node, code string) sp.Item {
	t.Helper()
	it, err := n.eng.Record(context.Background(), engine.Input{Stream: "outlet:" + n.eng.Config().Outlet, Intent: "stock.move", Actor: "m1", SID: "s1", PackV: "v1",
		Muts: []sp.Mut{{E: "stock_level", ID: "item-1", K: sp.KDelta, F: map[string]any{"qty_milli": int64(1000)}}}})
	if err != nil {
		t.Fatal(err)
	}
	return it
}

// Run executes the suite.
func Run(t *testing.T, tg Target) {
	t.Run("hello answers the documented shape and refuses anonymous callers", func(t *testing.T) {
		n := tg.node(t)
		var h sp.HelloResponse
		if rec := tg.do(t, "POST", "/sync/v1/hello", n.d.Token(), sp.HelloRequest{Protocol: 1}, &h); rec.Code != 200 {
			t.Fatalf("hello: %d %s", rec.Code, rec.Body)
		}
		if h.Protocol != 1 || h.Role != "cloud" || h.Epoch == "" || h.SnapshotRequired || h.Vector == nil || h.Time == "" {
			t.Fatalf("hello: %+v", h)
		}
		rec := tg.do(t, "POST", "/sync/v1/hello", "", sp.HelloRequest{Protocol: 1}, nil)
		if rec.Code != 401 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/problem+json") {
			t.Fatalf("anonymous: %d %s", rec.Code, rec.Header().Get("Content-Type"))
		}
	})

	t.Run("push is idempotent and pull delivers verified ops to another device", func(t *testing.T) {
		a, b := tg.node(t), tg.node(t)
		it := record(t, a, a.d.SaleCode)
		req, err := a.eng.Outbound(context.Background(), sp.Vector{}, engine.OutboundOpts{})
		if err != nil || len(req.Items) != 1 {
			t.Fatalf("outbound: %v", err)
		}
		var r1, r2 sp.PushResponse
		tg.do(t, "POST", "/sync/v1/push", a.d.Token(), req, &r1)
		tg.do(t, "POST", "/sync/v1/push", a.d.Token(), req, &r2)
		k := sp.VKey(a.d.ID, it.Stream)
		if r1.Vector[k] != 1 || r2.Vector[k] != 1 || len(r1.Refused)+len(r2.Refused) != 0 {
			t.Fatalf("push replay: %+v %+v", r1, r2)
		}
		var p sp.PullResponse
		if rec := tg.do(t, "POST", "/sync/v1/pull", b.d.Token(), sp.PullRequest{Vector: sp.Vector{}}, &p); rec.Code != 200 {
			t.Fatalf("pull: %d", rec.Code)
		}
		var got *sp.Item
		for i := range p.Items {
			if p.Items[i].Origin == a.d.ID {
				got = &p.Items[i]
			}
		}
		if got == nil || got.IsPlaceholder() {
			t.Fatalf("pull must deliver the op: %+v", p.Items)
		}
		if _, err := sp.VerifyItem(*got); err != nil {
			t.Fatal(err)
		}
		if len(p.Seals) == 0 || len(p.Creds) == 0 || p.OwnHeld == nil {
			t.Fatalf("pull must carry seals, credentials and own_held: %+v", p)
		}
	})

	t.Run("a number in a series the device was never given is held, and only as a coarse code", func(t *testing.T) {
		a, b := tg.node(t), tg.node(t)
		_ = b
		a.eng = engine.New(engine.Config{Role: engine.RoleDevice, Tenant: tg.Tenant, Outlet: tg.Outlet, Origin: a.d.ID, Key: a.d.Key, Store: a.eng.Config().Store, Trust: a.eng.Config().Trust,
			Clock: sp.NewClock(tg.Now), Series: series(b.d.SaleCode)})
		it, err := a.eng.Record(context.Background(), engine.Input{Stream: "outlet:" + tg.Outlet, Intent: "bill.finalize", Actor: "m1", SID: "s1", PackV: "v1", DocType: "tax_invoice",
			MutsFn: func(n string) []sp.Mut {
				return []sp.Mut{{E: "bill", ID: "b1", K: sp.KInsert, F: map[string]any{"number": n, "total_paise": int64(100)}}}
			}})
		if err != nil {
			t.Fatal(err)
		}
		req, _ := a.eng.Outbound(context.Background(), sp.Vector{}, engine.OutboundOpts{})
		var r sp.PushResponse
		tg.do(t, "POST", "/sync/v1/push", a.d.Token(), req, &r)
		if len(r.Held) != 1 || r.Held[0].Code != sp.HoldSupport || r.Held[0].Seq != it.Seq {
			t.Fatalf("held: %+v", r.Held)
		}
		var p sp.PullResponse
		tg.do(t, "POST", "/sync/v1/pull", b.d.Token(), sp.PullRequest{Vector: sp.Vector{}}, &p)
		for _, x := range p.Items {
			if x.Origin == a.d.ID && !x.IsPlaceholder() {
				t.Fatal("a held slot must be served as a placeholder")
			}
		}
		if strings.Contains(string(mustJSON(r)), "foreign") {
			t.Fatal("the reason must not reach the device")
		}
	})

	t.Run("token rules: drain tokens only at the upload, device tokens not there, admin needs a member", func(t *testing.T) {
		a := tg.node(t)
		if rec := tg.do(t, "POST", "/sync/v1/push", a.d.DrainToken(""), sp.PushRequest{}, nil); rec.Code != 401 {
			t.Fatalf("drain token at push: %d", rec.Code)
		}
		if rec := tg.do(t, "POST", "/sync/v1/quarantine-upload", a.d.Token(), sp.PushRequest{}, nil); rec.Code != 403 {
			t.Fatalf("device token at upload: %d", rec.Code)
		}
		if rec := tg.do(t, "GET", "/sync/v1/exceptions", a.d.Token(), nil, nil); rec.Code != 401 {
			t.Fatalf("device token at exceptions: %d", rec.Code)
		}
	})
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
