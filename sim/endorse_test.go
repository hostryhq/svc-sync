package sim

import (
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/hostryhq/svc-sync/api"
	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/hub"
	"github.com/hostryhq/svc-sync/repository"
	"github.com/hostryhq/svc-sync/service"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// recoveredAndReleased runs the KL1 story: 3 orders and 25 bills sealed, 15 bills unsealed, key loss,
// recovery on the same installation, upload, and release of everything by the owner.
func recoveredAndReleased(t *testing.T, seed uint64) (w *World, a, b *Device, old string) {
	t.Helper()
	w, rng := newTestWorld(t, seed, WorldOptions{Pos: 2})
	a, b = w.Devices[0], w.Devices[1]
	old = a.ID
	for i := 0; i < 3; i++ {
		must(a.OrderOp(rng))
	}
	for i := 0; i < 25; i++ {
		must(a.BillOp(rng))
	}
	must0(a.Eng.StoreSeals(bg))
	for i := 0; i < 15; i++ {
		must(a.BillOp(rng))
	}
	a.LoseKey()
	rc := must(w.RecoverDevice(a, true))
	w.uploadAll(t, a, rc)
	for _, q := range must(w.GW.Quarantine(bg, w.Tenant)) {
		must(w.GW.Release(bg, w.Tenant, q.Ref, service.ReleaseOpts{DeviceRecover: true}))
	}
	return w, a, b, old
}

func TestKL12_AfterTheReleaseAHubAndAPeerTakeTheTailUnderEndorsementAndMarkItUnsealed(t *testing.T) {
	w, a, b, old := recoveredAndReleased(t, 61)
	if r := w.Quiesce(bg, 60); !r.Converged {
		t.Fatal("no quiescence")
	}
	hubStore := w.Hub.Engine().Config().Store
	for name, st := range map[string]repository.Store{"cloud": w.GWStore, "hub": hubStore, "peer": b.Eng.Config().Store} {
		if n := w.marked(st, old, service.MarkUnsealed); n != 15 {
			t.Fatalf("%s holds %d unsealed tail ops, want 15", name, n)
		}
	}
	// Every node that took the tail holds the endorsements and the adopting device's attestation.
	for name, st := range map[string]repository.Store{"hub": hubStore, "peer": b.Eng.Config().Store} {
		if n := len(endorsementsOf(bg, st, w.Tenant)); n != 15 {
			t.Fatalf("%s stores %d endorsements, want 15", name, n)
		}
		var atts int
		must0(st.InTx(bg, w.Tenant, func(tx repository.Tx) error {
			l, err := tx.Attestations("outlet:"+w.Outlet, old)
			atts = len(l)
			return err
		}))
		if atts != 1 {
			t.Fatalf("%s stores %d attestations", name, atts)
		}
	}
	_ = a
	for _, p := range w.CheckAll(bg, nil) {
		t.Error(p)
	}
}

// batchOf is everything the adopting device holds of the old origin, as a node would receive it:
// 28 ops under a real origin seal and 15 without.
func batchOf(t *testing.T, w *World, a *Device, old string, rec string) sp.PushRequest {
	t.Helper()
	return must(a.Eng.RecoveryUpload(bg, old, sp.Vector{}, 500, func(s string, q int64, h string) (sp.Attestation, error) {
		return sp.MakeAttestation(a.Key, sp.Attestation{Origin: old, Stream: s, Seq: q, H: h, By: a.ID, Rec: rec})
	}))
}

// endorseAll signs an endorsement for every item above seq `from` with key.
func endorseAll(t *testing.T, key *sp.KeyPair, req sp.PushRequest, from int64, rec string) []sp.Endorsement {
	t.Helper()
	var out []sp.Endorsement
	for _, it := range req.Items {
		if it.Seq > from {
			out = append(out, must(sp.MakeEndorsement(key, it.Origin, it.Stream, it.Seq, it.H, rec)))
		}
	}
	return out
}

type kl13Case struct {
	name string
	// build returns the batch for this case and the highest seq of the old origin a node may hold afterwards.
	build func(t *testing.T, w *World, a *Device, old, rec string, base sp.PushRequest) (sp.PushRequest, int64)
	// noRecoverer: the node does not hold the credential of a device that recovers the origin.
	noRecoverer bool
	// revokeKey: the node has revoked the op-signing key before the batch arrives.
	revokeKey bool
	skipOn    string
}

const sealedHead = 29 // session open + 3 orders + 25 bills under the origin seal

func kl13Cases() []kl13Case {
	return []kl13Case{
		{name: "valid endorsements are taken (control)", build: func(t *testing.T, w *World, a *Device, old, rec string, base sp.PushRequest) (sp.PushRequest, int64) {
			base.Endorsements = endorseAll(t, w.Identity.CloudKey, base, sealedHead, rec)
			return base, 44
		}},
		{name: "(a) no credential recovers the origin", noRecoverer: true, skipOn: "gateway", build: func(t *testing.T, w *World, a *Device, old, rec string, base sp.PushRequest) (sp.PushRequest, int64) {
			base.Endorsements = endorseAll(t, w.Identity.CloudKey, base, sealedHead, rec)
			return base, sealedHead
		}},
		{name: "(b) above the attested seq", build: func(t *testing.T, w *World, a *Device, old, rec string, base sp.PushRequest) (sp.PushRequest, int64) {
			var h30 string
			for _, it := range base.Items {
				if it.Seq == 31 {
					h30 = it.H
				}
			}
			base.Attestations = []sp.Attestation{must(sp.MakeAttestation(a.Key, sp.Attestation{Origin: old, Stream: "outlet:" + w.Outlet, Seq: 31, H: h30, By: a.ID, Rec: rec}))}
			base.Endorsements = endorseAll(t, w.Identity.CloudKey, base, sealedHead, rec)
			return base, 31
		}},
		{name: "(c) a different recovery id", build: func(t *testing.T, w *World, a *Device, old, rec string, base sp.PushRequest) (sp.PushRequest, int64) {
			base.Endorsements = endorseAll(t, w.Identity.CloudKey, base, sealedHead, "rec-other")
			return base, sealedHead
		}},
		{name: "(d) an op-signing key under the seal tag for a device origin", build: func(t *testing.T, w *World, a *Device, old, rec string, base sp.PushRequest) (sp.PushRequest, int64) {
			last := base.Items[len(base.Items)-1]
			seal := must(sp.MakeSeal(w.Identity.CloudKey, old, last.Stream, last.Seq, last.H))
			base.Seals = append(base.Seals, seal)
			// The same signature offered as an endorsement does not verify either.
			base.Endorsements = []sp.Endorsement{{Origin: old, Stream: last.Stream, Seq: last.Seq, H: last.H, Rec: rec, Kid: seal.Kid, Sig: seal.Sig}}
			return base, sealedHead
		}},
		{name: "(e) a revoked op-signing key", revokeKey: true, skipOn: "gateway", build: func(t *testing.T, w *World, a *Device, old, rec string, base sp.PushRequest) (sp.PushRequest, int64) {
			base.Endorsements = endorseAll(t, w.Identity.CloudKey, base, sealedHead, rec)
			return base, sealedHead
		}},
		{name: "(e) an op-signing key the pack never carried", build: func(t *testing.T, w *World, a *Device, old, rec string, base sp.PushRequest) (sp.PushRequest, int64) {
			rogue := must(sp.NewKeyPair("gateway-op-rogue", nil))
			base.Endorsements = endorseAll(t, rogue, base, sealedHead, rec)
			return base, sealedHead
		}},
	}
}

// recoveredNotUploaded is KL1 up to the new device's activation: the cloud holds nothing yet.
func recoveredNotUploaded(t *testing.T, seed uint64) (w *World, a, b *Device, old string, rc *Recovery) {
	t.Helper()
	w, rng := newTestWorld(t, seed, WorldOptions{Pos: 2})
	a, b = w.Devices[0], w.Devices[1]
	old = a.ID
	for i := 0; i < 3; i++ {
		must(a.OrderOp(rng))
	}
	for i := 0; i < 25; i++ {
		must(a.BillOp(rng))
	}
	must0(a.Eng.StoreSeals(bg))
	for i := 0; i < 15; i++ {
		must(a.BillOp(rng))
	}
	a.LoseKey()
	rc = must(w.RecoverDevice(a, true))
	return w, a, b, old, rc
}

func TestKL13_EndorsementsThatBreakTheRuleAreRefusedByDeviceHubAndGateway(t *testing.T) {
	stream := ""
	for ci, c := range kl13Cases() {
		for _, target := range []string{"device", "hub", "gateway"} {
			if c.skipOn == target {
				continue
			}
			t.Run(target+"/"+c.name, func(t *testing.T) {
				w, a, b, old, rc := recoveredNotUploaded(t, uint64(70+ci))
				stream = "outlet:" + w.Outlet
				base := batchOf(t, w, a, old, rc.RecID)
				if len(base.Items) != 44 || len(base.Seals) != 1 {
					t.Fatalf("setup: %d items, %d seals", len(base.Items), len(base.Seals))
				}
				req, max := c.build(t, w, a, old, rc.RecID, base)
				var head int64
				switch target {
				case "device":
					eng, cache := standaloneDevice(t, w, c.noRecoverer)
					if c.revokeKey {
						cache.RevokeCloudKey(w.Identity.CloudKey.Kid)
					}
					res := must(eng.Ingest(bg, engine.IngestReq{Items: req.Items, Seals: req.Seals, Attestations: req.Attestations, Endorsements: req.Endorsements,
						FromUpstream: true, Caller: engine.Caller{ID: "upstream"}}))
					head = res.Vector[sp.VKey(old, stream)]
				case "hub":
					h := freshHub(t, w, c.noRecoverer)
					if c.revokeKey {
						h.Cache().RevokeCloudKey(w.Identity.CloudKey.Kid)
					}
					must(h.Push(bg, api.Principal{Tenant: w.Tenant, Caller: engine.Caller{ID: b.ID, Kind: sp.KindPOS, Outlet: w.Outlet}}, req))
					head = must(h.Engine().Vector(bg))[sp.VKey(old, stream)]
				case "gateway":
					// The origin's ops, offered by another device, with nothing uploaded and nothing released.
					must(w.CloudTransport("dev-cloud:"+b.ID, b.ID).Push(bg, req))
					head = must(w.GW.EngineFor(w.Tenant).Vector(bg))[sp.VKey(old, stream)]
				}
				if head > max {
					t.Fatalf("node holds the origin up to seq %d, at most %d allowed", head, max)
				}
				if c.name == "valid endorsements are taken (control)" && head != 44 {
					t.Fatalf("control: head %d, want 44", head)
				}
				if max == 31 && target != "gateway" && head != 31 {
					t.Fatalf("(b): the ops at or below the attested seq are taken: head %d, want 31", head)
				}
			})
		}
	}
}

func standaloneDevice(t *testing.T, w *World, noRecoverer bool) (*engine.Engine, *engine.CredCache) {
	t.Helper()
	kp := must(sp.NewKeyPair("k-standalone", nil))
	cache := engine.NewCredCache(w.Identity.IdentityPub(), w.Tenant, w.Outlet, w.Clock.Now)
	cache.AddCloudKey(w.Identity.CloudKey.Kid, &w.Identity.CloudKey.Priv.PublicKey)
	for _, c := range w.Identity.Devices(w.Tenant, w.Outlet) {
		if noRecoverer && c.Cred.Recovers != "" {
			continue
		}
		must0(cache.Add(c))
	}
	st := must(repository.Open("file:" + filepath.Join(t.TempDir(), "x.db")))
	t.Cleanup(func() { _ = st.Close() })
	eng := engine.New(engine.Config{Role: engine.RoleDevice, Tenant: w.Tenant, Outlet: w.Outlet, Origin: "dev-standalone", Key: kp, Store: st, Trust: cache, Clock: sp.NewClock(w.Clock.Now)})
	must0(eng.Open(bg))
	return eng, cache
}

func freshHub(t *testing.T, w *World, noRecoverer bool) *hub.Hub {
	t.Helper()
	var peers []sp.CredentialEnvelope
	for _, c := range w.Identity.Devices(w.Tenant, w.Outlet) {
		if noRecoverer && c.Cred.Recovers != "" {
			continue
		}
		peers = append(peers, c)
	}
	st := must(repository.Open("file:" + filepath.Join(t.TempDir(), "h.db")))
	t.Cleanup(func() { _ = st.Close() })
	return must(hub.New(bg, hub.Config{Tenant: w.Tenant, Outlet: w.Outlet, Brand: w.Brand, Cred: w.HubCred, CredJWS: w.HubJWS, Key: w.HubKey,
		IdentityPub: w.Identity.IdentityPub(), CloudKeys: map[string]*ecdsaPub{w.Identity.CloudKey.Kid: &w.Identity.CloudKey.Priv.PublicKey},
		Store: st, Now: w.Clock.Now, Peers: peers,
		Members:     func(actor string) bool { return w.Identity.InAnyPackOf(w.Tenant, w.Outlet, actor) },
		SeriesOwner: func(code string) (string, bool) { s, ok := w.Identity.Series(w.Tenant, code); return s.Device, ok }}))
}

func TestKL14_CloudRolledBackAfterTheUploadBeforeTheReleaseTakesTheReleasedOpsBackWithoutTheOwner(t *testing.T) {
	w, rng := newTestWorld(t, 51, WorldOptions{Pos: 2})
	a := w.Devices[0]
	old := a.ID
	for i := 0; i < 3; i++ {
		must(a.OrderOp(rng))
	}
	for i := 0; i < 12; i++ {
		must(a.BillOp(rng))
	}
	must0(a.Eng.StoreSeals(bg))
	for i := 0; i < 8; i++ {
		must(a.BillOp(rng))
	}
	a.LoseKey()
	rc := must(w.RecoverDevice(a, true))
	w.uploadAll(t, a, rc)
	must0(w.SnapshotCloud("post-upload"))
	// The owner releases the sealed part and the first five tail ops; the last three stay held.
	items := must(w.GW.Quarantine(bg, w.Tenant))
	sort.Slice(items, func(i, j int) bool { return items[i].Ref.Seq < items[j].Ref.Seq })
	for _, q := range items[:len(items)-3] {
		must(w.GW.Release(bg, w.Tenant, q.Ref, service.ReleaseOpts{DeviceRecover: true}))
	}
	if r := w.Quiesce(bg, 60); !r.Converged {
		t.Fatal("no quiescence before the restore")
	}
	if n := w.marked(w.GWStore, old, service.MarkUnsealed); n != 5 {
		t.Fatalf("setup: %d released tail ops", n)
	}
	must0(w.RestoreCloud("post-upload", "restore-1"))
	if n := w.marked(w.GWStore, old, service.MarkUnsealed); n != 0 {
		t.Fatalf("the rollback must undo the release, %d released", n)
	}
	if r := w.Quiesce(bg, 80); !r.Converged {
		t.Fatal("no quiescence after the restore")
	}
	if n := w.marked(w.GWStore, old, service.MarkUnsealed); n != 5 {
		t.Fatalf("released ops come back as released and unsealed with no owner action: %d, want 5", n)
	}
	if n := w.heldByReason(t, old)["quarantined/unsealed_tail"]; n != 3 {
		t.Fatalf("the three ops the owner had not released stay in quarantine: %d", n)
	}
	if rep := must(w.GW.Register(bg, w.Tenant)); len(rep.Gaps) != 0 {
		t.Fatalf("the register has no gap: %+v", rep.Gaps)
	}
}

func TestKL15_AfterAnEmergencyRotationEndorsementsAreReissuedAndANewNodeConvergesWithTheNewPackOnly(t *testing.T) {
	w, _, _, old := recoveredAndReleased(t, 62)
	if r := w.Quiesce(bg, 60); !r.Converged {
		t.Fatal("no quiescence")
	}
	must0(w.RotateOpKey("gateway-op-2"))
	for _, e := range endorsementsOf(bg, w.GWStore, w.Tenant) {
		if e.Kid != "gateway-op-2" {
			t.Fatalf("endorsement still under %s", e.Kid)
		}
	}
	// A node holding the new key only, with no route to the hub, takes the tail from the cloud.
	n := must(w.AddDevice("dev-new", sp.KindPOS))
	w.Net.SetDown("dev-hub:"+n.ID, true)
	for i := 0; i < 10; i++ {
		must0(n.SyncCloud(bg))
	}
	if got := w.marked(n.Eng.Config().Store, old, service.MarkUnsealed); got != 15 {
		t.Fatalf("the new node holds %d unsealed tail ops, want 15", got)
	}
	// Existing relays refresh the endorsements they hold, so that the new key is enough everywhere.
	for i := 0; i < 5; i++ {
		_, _ = w.Hub.SyncUpstream(bg)
	}
	for _, e := range endorsementsOf(bg, w.Hub.Engine().Config().Store, w.Tenant) {
		if e.Kid != "gateway-op-2" {
			t.Fatalf("the hub still serves an endorsement under %s", e.Kid)
		}
	}
}

// RS1 (simulator seed 1 as a named case): after a restore the hub holds only a placeholder for a slot
// the cloud lost. Its origin never talked to the cloud while the hub was up; the hub's word that
// the epoch changed is what opens the origin's re-offer, and a direct cloud hello closes it.
func TestRS1_HubHoldsOnlyAPlaceholderTheOriginReoffersToTheCloudDirectly(t *testing.T) {
	w, foreign := reofferWorld(t, 81)
	a := w.Devices[0]
	_, _ = w.Hub.SyncUpstream(bg)
	if a.HubC.ReofferPending(bg) {
		t.Fatal("nothing to re-offer before the restore")
	}
	must0(w.RestoreCloud("t", "restore-1"))
	if v := must(w.GW.EngineFor(w.Tenant).Vector(bg)); v[sp.VKey(foreign.Origin, foreign.Stream)] != 0 {
		t.Fatal("the cloud lost the slot")
	}
	_, _ = w.Hub.SyncUpstream(bg) // the hub hears the new epoch; it holds a placeholder only
	must0(a.SyncHub(bg))
	if !a.HubC.ReofferPending(bg) {
		t.Fatal("the hub's word opens the origin's re-offer")
	}
	must0(a.Sync(bg)) // hub round, then a direct cloud round while the re-offer is open
	if r := w.rec(t, foreign); r.Status != repository.StQuarantined {
		t.Fatalf("the cloud holds the slot again, as the verdict decides: %s", r.Status)
	}
	if a.HubC.ReofferPending(bg) {
		t.Fatal("a direct cloud hello with nothing left to push closes the re-offer")
	}
	if r := w.Quiesce(bg, 40); !r.Converged {
		t.Fatal("no quiescence")
	}
}

// RS2: as RS1 with the device's cloud route cut for 25 hours.
func TestRS2_ReofferStaysOpenWhileTheCloudRouteIsCutTheGapAlertFiresAndClears(t *testing.T) {
	w, foreign := reofferWorld(t, 82)
	a := w.Devices[0]
	_, _ = w.Hub.SyncUpstream(bg)
	must0(w.RestoreCloud("t", "restore-1"))
	_, _ = w.Hub.SyncUpstream(bg) // first report of a vector above the cloud's: the 24-hour clock starts
	w.Net.SetDown("dev-cloud:"+a.ID, true)
	must0(a.SyncHub(bg))
	_ = a.Sync(bg)
	if !a.HubC.ReofferPending(bg) {
		t.Fatal("the re-offer stays open without a cloud route")
	}
	gap := func() bool {
		for _, al := range must(w.GW.Alerts(bg, w.Tenant)) {
			if al.Kind == "unrecoverable_origin_gap" {
				return true
			}
		}
		return false
	}
	w.Advance(23 * time.Hour)
	_, _ = w.Hub.SyncUpstream(bg)
	if gap() {
		t.Fatal("no alert before 24 hours")
	}
	w.Advance(2 * time.Hour)
	_, _ = w.Hub.SyncUpstream(bg)
	if !gap() {
		t.Fatal("the alert fires after 24 hours")
	}
	w.Net.SetDown("dev-cloud:"+a.ID, false)
	must0(a.Sync(bg))
	_, _ = w.Hub.SyncUpstream(bg)
	if a.HubC.ReofferPending(bg) {
		t.Fatal("re-offer closes once the route is back")
	}
	if gap() {
		t.Fatal("the alert clears when the gap closes")
	}
	if r := w.rec(t, foreign); r.Status != repository.StQuarantined {
		t.Fatalf("slot back at the cloud: %s", r.Status)
	}
	if r := w.Quiesce(bg, 40); !r.Converged {
		t.Fatal("no quiescence")
	}
}

// reofferWorld: the cloud is snapshotted empty; device a then bills in another device's series while
// its hub link is down, so the cloud quarantines the bill and the hub learns it only as a placeholder.
func reofferWorld(t *testing.T, seed uint64) (*World, sp.Item) {
	t.Helper()
	w, _ := newTestWorld(t, seed, WorldOptions{Pos: 2})
	a, b := w.Devices[0], w.Devices[1]
	must0(w.SnapshotCloud("t"))
	w.Net.SetDown("dev-hub:"+a.ID, true)
	foreign := w.billAs(t, a, b.SaleCode(), "tax_invoice")
	must0(a.SyncCloud(bg))
	_, _ = w.Hub.SyncUpstream(bg)
	w.Net.SetDown("dev-hub:"+a.ID, false)
	var st string
	must0(w.Hub.Engine().Config().Store.InTx(bg, w.Tenant, func(tx repository.Tx) error {
		r, ok, err := tx.GetOp(foreign.Stream, foreign.Origin, foreign.Seq)
		if err != nil || !ok {
			return err
		}
		st = r.Status
		return nil
	}))
	if st != repository.StPlaceholder {
		t.Fatalf("setup: the hub should hold a placeholder, holds %q", st)
	}
	return w, foreign
}
