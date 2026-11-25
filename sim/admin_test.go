package sim

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	"github.com/hostryhq/svc-sync/service"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// Review H2: the manager and vendor endpoints go through the go-auth guard.

const (
	pRead    = service.PermQuarantineRead
	pManage  = service.PermQuarantineManage
	pConfirm = service.PermQuarantineConfirm
)

func (w *World) mint(s authtest.Spec) string {
	s.Tenant = ids.ID(w.Tenant)
	return w.Issuer.Mint(s)
}

func (w *World) serviceToken(t *testing.T) string {
	t.Helper()
	tok, err := w.Services.Signer("admin").Sign("sync", w.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// adminCall makes one request to the gateway's handler and returns the status and the body.
func (w *World) adminCall(method, path, token, svc string, body any) (int, string) {
	var rd *strings.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	} else {
		rd = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if svc != "" {
		req.Header.Set(auth.ServiceTokenHeader, svc)
	}
	rec := httptest.NewRecorder()
	w.CloudH.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

type decision struct {
	sp.Ref
	Reason string `json:"reason"`
}

func refOf(it sp.Item) sp.Ref { return sp.Ref{Origin: it.Origin, Stream: it.Stream, Seq: it.Seq} }

func (w *World) audit(t *testing.T) []repository.AuditRec {
	t.Helper()
	out, err := w.GW.AuditLog(bg, w.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (w *World) vendorLog(t *testing.T) []auth.VendorAccessEntry {
	t.Helper()
	out, err := w.GWStore.(*repository.SQL).VendorAccess(bg, w.Tenant)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func listed(t *testing.T, body string) []service.QuarantineItem {
	t.Helper()
	var out []service.QuarantineItem
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("list body %q: %v", body, err)
	}
	return out
}

// An outlet manager reaches only the held slots of their outlet; a slot of another outlet (or of a
// brand stream) is 404 to them; the decision is audited with who, what, why and before/after.
func TestH2_OutletScopeAndAuditOnReleaseAndDiscard(t *testing.T) {
	w, _ := newTestWorld(t, 41, WorldOptions{Pos: 2})
	a, b := w.Devices[0], w.Devices[1]
	foreign := w.billAs(t, a, b.SaleCode(), "tax_invoice") // outlet stream, foreign series
	a.Skew = 3 * time.Hour
	price := must(a.PriceOp(NewRand(2))) // brand stream, clock review: no number, may be discarded
	a.Skew = 0
	w.toCloud(t, a)
	if r := w.rec(t, foreign); r.Status != repository.StQuarantined {
		t.Fatalf("setup: %s", r.Status)
	}
	if r := w.rec(t, price); r.Status != repository.StQuarantined {
		t.Fatalf("setup: %s", r.Status)
	}
	perms := []string{pRead, pManage}
	inOutlet := w.mint(authtest.Spec{Type: auth.TypeUser, Grants: authtest.Grants([]string{w.Outlet}, perms...)})
	otherOutlet := w.mint(authtest.Spec{Type: auth.TypeUser, Grants: authtest.Grants([]string{"018f0000-0000-7000-8000-0000000000ff"}, perms...)})
	allOutlets := w.mint(authtest.Spec{Type: auth.TypeUser, Grants: authtest.Grants(nil, perms...)})

	for _, tc := range []struct {
		name string
		tok  string
		want int
	}{{"outlet manager", inOutlet, 1}, {"other outlet", otherOutlet, 0}, {"all outlets", allOutlets, 2}} {
		code, body := w.adminCall("GET", "/sync/v1/quarantine", tc.tok, "", nil)
		if code != 200 || len(listed(t, body)) != tc.want {
			t.Fatalf("%s lists %d, want %d (status %d)", tc.name, len(listed(t, body)), tc.want, code)
		}
	}
	// Another outlet's slot is 404 to a manager of a different outlet (as a foreign tenant's would be).
	if code, _ := w.adminCall("POST", "/sync/v1/quarantine/release", otherOutlet, "", decision{refOf(foreign), "mine"}); code != 404 {
		t.Fatalf("release across outlets: %d, want 404", code)
	}
	// A brand-stream slot belongs to no single outlet: it needs the all-outlets grant (go-auth Require
	// with no outlet), so an outlet-scoped manager is refused, whichever outlet they manage.
	for _, tok := range []string{inOutlet, otherOutlet} {
		if code, _ := w.adminCall("POST", "/sync/v1/quarantine/discard", tok, "", decision{refOf(price), "mine"}); code != 403 {
			t.Fatalf("discard of a brand-stream slot by an outlet manager: %d, want 403", code)
		}
	}
	if n := len(w.audit(t)); n != 0 {
		t.Fatalf("refused decisions must write no audit record, got %d", n)
	}
	// A decision needs a reason.
	if code, _ := w.adminCall("POST", "/sync/v1/quarantine/discard", allOutlets, "", decision{Ref: refOf(price)}); code != 400 && code != 422 {
		t.Fatalf("discard without a reason: %d", code)
	}
	if r := w.rec(t, price); r.Status != repository.StQuarantined {
		t.Fatal("a refused discard must change nothing")
	}
	// The permitted discard is carried out and audited in the same transaction.
	if code, body := w.adminCall("POST", "/sync/v1/quarantine/discard", allOutlets, "", decision{refOf(price), "entered by mistake"}); code != 200 {
		t.Fatalf("discard: %d %s", code, body)
	}
	if r := w.rec(t, price); r.Status != repository.StVoided {
		t.Fatalf("discarded slot is %s", r.Status)
	}
	au := w.audit(t)
	if len(au) != 1 || au[0].Action != service.ActionDiscard || au[0].Reason != "entered by mistake" || au[0].Before != repository.StQuarantined ||
		au[0].After != repository.StVoided || au[0].Actor != "member-1" || au[0].Origin != price.Origin || au[0].Seq != price.Seq {
		t.Fatalf("audit record: %+v", au)
	}
	// Release in the outlet: held for the vendor's confirmation (conflict), and only the confirmed hold passes.
	if code, _ := w.adminCall("POST", "/sync/v1/quarantine/release", inOutlet, "", decision{refOf(foreign), "checked"}); code != 409 {
		t.Fatalf("release before vendor confirmation: %d, want 409", code)
	}
	if n := len(w.audit(t)); n != 1 {
		t.Fatalf("a refused release writes no audit record, got %d", n)
	}
}

// A support token works only with the admin service token, never carries a sensitive permission or
// the wildcard, can confirm a hold only in act mode, and every request on its authority is in the
// vendor access log. A tenant member cannot confirm.
func TestH2_SupportNeedsTheServiceTokenAndConfirmsInActMode(t *testing.T) {
	w, _ := newTestWorld(t, 42, WorldOptions{Pos: 2})
	a, b := w.Devices[0], w.Devices[1]
	foreign := w.billAs(t, a, b.SaleCode(), "tax_invoice")
	w.toCloud(t, a)
	ref := refOf(foreign)
	svc := w.serviceToken(t)
	view := w.mint(authtest.Spec{Type: auth.TypeSupport, Mode: auth.ModeView, Grants: authtest.Grants(nil, pRead)})
	act := w.mint(authtest.Spec{Type: auth.TypeSupport, Mode: auth.ModeAct, Grants: authtest.Grants(nil, pRead, pConfirm, pManage)})
	wildcard := w.mint(authtest.Spec{Type: auth.TypeSupport, Mode: auth.ModeAct, Grants: authtest.Grants(nil, auth.Wildcard)})

	if code, _ := w.adminCall("GET", "/sync/v1/quarantine", view, "", nil); code != 401 {
		t.Fatalf("support token without the admin service token: %d, want 401", code)
	}
	if code, _ := w.adminCall("GET", "/sync/v1/quarantine", view, w.mintOtherService(t), nil); code != 401 {
		t.Fatalf("support token with another service's token: %d, want 401", code)
	}
	if code, body := w.adminCall("GET", "/sync/v1/quarantine", view, svc, nil); code != 200 || len(listed(t, body)) != 1 {
		t.Fatalf("support view with the service token: %d %s", code, body)
	}
	if log := w.vendorLog(t); len(log) != 1 || log[0].ActionKey != "listSyncQuarantine" || log[0].TokenType != auth.TypeSupport || log[0].Outcome != auth.OutcomeOK || log[0].ResultCount != 1 {
		t.Fatalf("vendor access log after a support read: %+v", log)
	}
	if code, _ := w.adminCall("GET", "/sync/v1/quarantine", wildcard, svc, nil); code != 403 {
		t.Fatalf("the wildcard on a support token: %d, want 403", code)
	}
	if log := w.vendorLog(t); len(log) != 2 || log[1].Outcome != auth.OutcomeRefused {
		t.Fatalf("a refused support request is logged as refused: %+v", log)
	}
	// Sensitive: never for support, even in act mode with the permission in the token.
	if code, _ := w.adminCall("POST", "/sync/v1/quarantine/release", act, svc, decision{ref, "x"}); code != 403 {
		t.Fatalf("support release: %d, want 403", code)
	}
	// Confirm needs act mode and the support_actable permission.
	if code, _ := w.adminCall("POST", "/sync/v1/quarantine/confirm", view, svc, decision{ref, "cause found"}); code != 403 {
		t.Fatalf("confirm in view mode: %d, want 403", code)
	}
	owner := w.mint(authtest.Spec{Type: auth.TypeUser, Grants: authtest.OwnerGrants()})
	if code, _ := w.adminCall("POST", "/sync/v1/quarantine/confirm", owner, "", decision{ref, "self"}); code != 403 {
		t.Fatalf("a tenant member must not confirm their own hold: %d, want 403", code)
	}
	if code, body := w.adminCall("POST", "/sync/v1/quarantine/confirm", act, svc, decision{ref, "series reissue confirmed with the owner"}); code != 200 {
		t.Fatalf("confirm in act mode: %d %s", code, body)
	}
	if r := w.rec(t, foreign); r.Status != repository.StQuarantined || !hasMark(r, service.MarkVendorConfirmed) {
		t.Fatalf("confirm marks the hold, it does not release it: %s %q", r.Status, r.Marks)
	}
	// Now the owner's manager may release it, audited under their own name.
	if code, body := w.adminCall("POST", "/sync/v1/quarantine/release", owner, "", decision{ref, "approved"}); code != 200 {
		t.Fatalf("release after confirmation: %d %s", code, body)
	}
	au := w.audit(t)
	if len(au) != 2 || au[0].Action != service.ActionConfirm || au[0].ActorType != string(auth.TypeSupport) || au[1].Action != service.ActionRelease || au[1].ActorType != string(auth.TypeUser) {
		t.Fatalf("audit records: %+v", au)
	}
	var okRows int
	for _, e := range w.vendorLog(t) {
		if e.Outcome == auth.OutcomeOK && e.TargetID == ref.Key() {
			okRows++
		}
	}
	if okRows != 1 {
		t.Fatalf("the confirm is in the vendor access log with its target, got %d rows", okRows)
	}
}

func (w *World) mintOtherService(t *testing.T) string {
	t.Helper()
	tok, err := w.Services.Signer("sync").Sign("sync", w.Tenant) // a registered service that is not the admin service
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// Releasing an unsealed tail needs device.recover, which is strong_only: blocked on a device under
// caution without an approval token (ADR-0005 A2.2), refused to a manager who lacks it.
func TestH2_UnsealedTailReleaseNeedsDeviceRecoverOutsideCaution(t *testing.T) {
	w, _ := newTestWorld(t, 43, WorldOptions{Pos: 1})
	ref := sp.Ref{Origin: "dev-lost", Stream: "outlet:" + w.Outlet, Seq: 1}
	if err := w.GWStore.InTx(bg, w.Tenant, func(tx repository.Tx) error {
		return tx.PutOp(repository.OpRec{Tenant: w.Tenant, Stream: ref.Stream, Origin: ref.Origin, Seq: 1, H: "h1", Body: `{}`, Status: repository.StQuarantined, Reason: service.ReasonUnsealedTail})
	}); err != nil {
		t.Fatal(err)
	}
	manager := w.mint(authtest.Spec{Type: auth.TypeUser, Grants: authtest.Grants(nil, pRead, pManage)})
	if code, _ := w.adminCall("POST", "/sync/v1/quarantine/release", manager, "", decision{ref, "checked"}); code != 409 {
		t.Fatalf("a manager without device.recover: %d, want 409", code)
	}
	underCaution := w.mint(authtest.Spec{Type: auth.TypeUser, Grants: authtest.OwnerGrants(), CautionUntil: w.Clock.Now().Add(time.Hour)})
	code, body := w.adminCall("POST", "/sync/v1/quarantine/release", underCaution, "", decision{ref, "checked"})
	if code != 403 || !strings.Contains(body, "approval_required") {
		t.Fatalf("an owner on a new device: %d %s, want 403 approval_required", code, body)
	}
	// A device token is never a member: no route of the manager endpoints takes it.
	dev := w.Token(auth.TypeDevice, w.Devices[0].ID, "")
	if code, _ := w.adminCall("GET", "/sync/v1/exceptions", dev, "", nil); code != 403 && code != 401 {
		t.Fatalf("device token at exceptions: %d", code)
	}
}

var _ = engine.ZeroStamp
var _ = http.StatusOK
