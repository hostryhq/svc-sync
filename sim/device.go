package sim

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/svc-sync/directory"
	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/hub"
	"github.com/hostryhq/svc-sync/identitystub"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// NumRec is a legal number and the origin that allocated it.
type NumRec struct{ Number, Origin string }

// Device is a simulated tablet, counter or KDS with a local store and the real sync engine.
type Device struct {
	W      *World
	ID     string // current origin: changes when the device is recovered under a new id
	Kind   string
	Store  repository.Store
	DB     string
	Key    *sp.KeyPair
	Cred   sp.CredentialEnvelope
	Cache  *engine.CredCache
	Eng    *engine.Engine
	Skew   time.Duration
	HubC   *engine.Client
	CloudC *engine.Client

	KeyLost    bool
	Crashes    int
	Recovered  []string // old origins this installation adopted
	Recoveries []*Recovery

	sessions    map[string]string
	badSessions map[string]string
	n           int
	saleCode    string
	cnCode      string
	activated   bool
	badSeries   string // when set, finalisation uses this series code (injected fault)
	lastSeal    time.Time
	// Recorded is every op this installation recorded under any of its origins.
	Recorded []sp.Ref
	// Numbers are the legal numbers it allocated, in order, with the origin that numbered them.
	Numbers []NumRec
}

type seriesSrc struct{ d *Device }

func (s seriesSrc) Code(docType string) (string, bool) {
	if s.d.badSeries != "" {
		return s.d.badSeries, true
	}
	switch docType {
	case "tax_invoice":
		return s.d.saleCode, s.d.saleCode != ""
	case "credit_note":
		return s.d.cnCode, s.d.cnCode != ""
	}
	return "", false
}

// AddDevice registers and starts a device.
func (w *World) AddDevice(id, kind string) (*Device, error) {
	return w.AddDeviceStore(id, kind, sp.StoreProtected)
}

// AddDeviceStore is AddDevice with the device's declared store claim (ADR-0002 A3.5 item 1).
func (w *World) AddDeviceStore(id, kind, store string) (*Device, error) {
	kp, err := sp.NewKeyPair("k-"+id, nil)
	if err != nil {
		return nil, err
	}
	cred, err := w.Identity.ActivateStore(w.Tenant, w.Outlet, w.Brand, id, kind, kp.Kid, kp.PublicB64(), "", store)
	if err != nil {
		return nil, err
	}
	d := &Device{W: w, ID: id, Kind: kind, Key: kp, Cred: cred, sessions: map[string]string{}}
	switch kind {
	case sp.KindPOS:
		d.saleCode = w.Identity.IssueSeries(w.Tenant, id, "tax_invoice", directory.SeriesActive)
		d.cnCode = w.Identity.IssueSeries(w.Tenant, id, "credit_note", directory.SeriesActive)
	case sp.KindWaiter:
		d.saleCode = w.Identity.IssueSeries(w.Tenant, id, "tax_invoice", directory.SeriesDormant)
		d.cnCode = w.Identity.IssueSeries(w.Tenant, id, "credit_note", directory.SeriesDormant)
	}
	w.Identity.IssuePack(w.Tenant, id, 1, 7*24*time.Hour)
	d.DB = fmt.Sprintf("%s/%s.db", w.Opt.Dir, id)
	if err := d.open(); err != nil {
		return nil, err
	}
	w.Devices = append(w.Devices, d)
	w.byID[id] = d
	if w.Hub != nil {
		_ = w.Hub.AddPeer(cred)
	}
	// Every device learns the others' credentials from its pack.
	for _, o := range w.Devices {
		_ = o.Cache.Add(cred)
		_ = d.Cache.Add(o.Cred)
	}
	_ = d.Cache.Add(w.HubCred)
	return d, nil
}

// open (re)opens the store and builds the engine and clients. State is rebuilt from the op log.
func (d *Device) open() error {
	w := d.W
	st, err := repository.Open("file:" + d.DB)
	if err != nil {
		return err
	}
	d.Store = st
	if d.Cache == nil {
		d.Cache = engine.NewCredCache(w.Identity.IdentityPub(), w.Tenant, w.Outlet, w.Clock.Now)
		d.Cache.AddCloudKey(w.Identity.CloudKey.Kid, &w.Identity.CloudKey.Priv.PublicKey)
		_ = d.Cache.Add(d.Cred)
	}
	d.Eng = engine.New(engine.Config{
		Role: engine.RoleDevice, Kind: d.Kind, Tenant: w.Tenant, Outlet: w.Outlet, Origin: d.ID, Key: d.Key, Store: st, Trust: d.Cache,
		Clock: sp.NewClock(func() time.Time { return w.Clock.Now().Add(d.Skew) }), Series: seriesSrc{d},
	})
	if err := d.Eng.Open(w.Ctx); err != nil {
		return err
	}
	streams := []string{"outlet:" + w.Outlet, "brand:" + w.Brand, "tenant:" + w.Tenant}
	jws, ok := w.Identity.LANCredential(d.ID)
	if !ok {
		return fmt.Errorf("sim: no LAN credential for %s", d.ID)
	}
	hubH := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { w.HubH.ServeHTTP(rw, r) })
	lan := &hub.LANClient{CredJWS: jws, Key: d.Key, DeviceID: d.ID, Tenant: w.Tenant, Outlet: w.Outlet,
		Identity: func() []*ecdsaPub { return []*ecdsaPub{w.Identity.IdentityPub()} },
		Revoked:  func(id string) bool { rev, _ := w.Identity.Revoked(w.Tenant, id); return rev },
		Now:      func() time.Time { return w.Clock.Now().Add(d.Skew) },
		Next:     w.Net.RoundTripper("dev-hub:"+d.ID, hubH),
		// The in-memory network has no TLS: a device "sees" the certificate key of the hub it is wired to.
		SPKISeen: func() string { return w.Hub.SPKI() }}
	d.HubC = &engine.Client{E: d.Eng, Cache: d.Cache, Streams: streams, T: &engine.HTTPTransport{
		Base: "http://hub", Client: &http.Client{Transport: lan.RoundTripper()}}}
	d.CloudC = &engine.Client{E: d.Eng, Cache: d.Cache, Streams: streams, UpstreamIsCloud: true, T: w.CloudTransport("dev-cloud:"+d.ID, d.ID)}
	return nil
}

// Crash kills the process: all in-memory state is lost and the node restarts from its disk.
func (d *Device) Crash() error {
	_ = d.Store.Close()
	d.Crashes++
	return d.open()
}

// SyncHub does one round with the hub.
func (d *Device) SyncHub(ctx context.Context) error {
	if d.KeyLost {
		return errors.New("sim: key lost")
	}
	_, err := d.HubC.SyncOnce(ctx)
	return err
}

// SyncCloud does one round with the cloud directly.
func (d *Device) SyncCloud(ctx context.Context) error {
	if d.KeyLost {
		return errors.New("sim: key lost")
	}
	_, err := d.CloudC.SyncOnce(ctx)
	return err
}

// Sync talks to the hub when it answers, otherwise to the cloud (S2, S12).
func (d *Device) Sync(ctx context.Context) error {
	err := d.SyncHub(ctx)
	if err != nil {
		d.W.Via.HubFail++
		err = d.SyncCloud(ctx)
		if err == nil {
			d.W.Via.CloudDirect++
		}
	} else {
		d.W.Via.HubOK++
		if (d.HubC.ReofferPending(ctx) || d.Eng.DirectCloudDue(ctx)) && !d.KeyLost {
			// After a cloud restore the origin re-offers directly: the hub may hold only a placeholder. A node also reaches the cloud directly at least every 24 hours and whenever an unbound slot, an unreported conflict or a stale cloud seal waits (A2.8).
			_ = d.SyncCloud(ctx)
		}
	}
	d.reuploadRecoveries(ctx)
	return err
}

// reuploadRecoveries repeats the recovery upload of every adopted origin: a no-op when the cloud
// holds the attested tail, and the re-offer of it after a cloud restore (A1.3 item 10).
func (d *Device) reuploadRecoveries(ctx context.Context) {
	for _, rc := range d.Recoveries {
		for i := 0; i < 20; i++ {
			if done, err := d.W.UploadRecovery(ctx, d, rc); err != nil || done {
				break
			}
		}
	}
}

// SealTick stores a seal at least every 5 minutes while the device holds unpushed ops (A1.3 item 8).
func (d *Device) SealTick() {
	if d.KeyLost || d.W.Clock.Now().Sub(d.lastSeal) < 5*time.Minute {
		return
	}
	d.lastSeal = d.W.Clock.Now()
	_ = d.Eng.StoreSeals(d.W.Ctx)
}

func (d *Device) session(actor string) (string, error) {
	if sid, ok := d.sessions[actor]; ok {
		return sid, nil
	}
	sid := fmt.Sprintf("s-%s-%s", d.ID, actor)
	d.sessions[actor] = sid
	return sid, d.openSession(actor, sid, "")
}

// openSession records a session.open of a pin session whose proof is the given one ("" means the right PIN).
func (d *Device) openSession(actor, sid, proof string) error {
	_, err := d.record(engine.Input{Stream: "outlet:" + d.W.Outlet, Intent: sp.IntentSessionOpen, Actor: actor, SID: sid, Proof: proof,
		Muts: []sp.Mut{{E: "session", ID: sid, K: sp.KInsert, F: map[string]any{"type": sp.SessionPin, "device": d.ID}}}}, true)
	return err
}

// SessionWith opens a new pin session with its own id and the given proof ("" the right PIN). The session is not cached.
func (d *Device) SessionWith(actor, tag, proof string) (string, error) {
	sid := fmt.Sprintf("s-%s-%s-%s", d.ID, actor, tag)
	return sid, d.openSession(actor, sid, proof)
}

func (d *Device) record(in engine.Input, noSession bool) (sp.Item, error) {
	if d.KeyLost {
		return sp.Item{}, errors.New("sim: device key lost: nothing is recorded (K6)")
	}
	if in.PackV == 0 {
		in.PackV = 1
	}
	// The proof travels only on session.open of a pin session and on approval.grant, with the PIN version, and the
	// open's `at` is the opening time it binds (ADR-0005 A3.1).
	if in.Intent == sp.IntentSessionOpen && openType(in) == sp.SessionPin {
		if in.PinV == 0 {
			in.PinV = 1
		}
		if in.At.IsZero() {
			in.At = d.Eng.Config().Clock.Time()
		}
		if in.Proof == "" {
			in.Proof = d.W.Identity.MintProof(identitystub.ProofQuestion{Kind: "session", Device: d.ID, Member: in.Actor, SID: in.SID,
				PackV: in.PackV, PinV: in.PinV, OpenedAt: in.At})
		}
		if in.Proof == "none" {
			in.Proof = ""
		}
	} else if in.Intent != sp.IntentApprovalGrant {
		in.Proof, in.PinV = "", 0
	}
	it, err := d.Eng.Record(d.W.Ctx, in)
	if err != nil {
		return it, err
	}
	d.Recorded = append(d.Recorded, sp.Ref{Origin: it.Origin, Stream: it.Stream, Seq: it.Seq})
	if in.DocType != "" {
		if b, err := sp.DecodeBody(it.Body); err == nil && b.Doc != nil {
			d.Numbers = append(d.Numbers, NumRec{b.Doc.Number, it.Origin})
		}
	}
	return it, nil
}

// openType is the session type a session.open input opens.
func openType(in engine.Input) string {
	for _, m := range in.Muts {
		if m.E == "session" && m.ID == in.SID {
			t, _ := m.F["type"].(string)
			return t
		}
	}
	return ""
}

// BadSession opens, once per actor, a pin session whose proof is wrong (a tampered tablet): the one session identity
// counts a failure for. Later ops of the session are judged from that verdict.
func (d *Device) BadSession(actor string) (string, error) {
	if sid, ok := d.badSessions[actor]; ok {
		return sid, nil
	}
	if d.badSessions == nil {
		d.badSessions = map[string]string{}
	}
	sid, err := d.SessionWith(actor, "bad", "bogus-proof")
	d.badSessions[actor] = sid
	return sid, err
}

// Do records an op as actor inside the actor's session, opening it if needed.
func (d *Device) Do(actor string, in engine.Input) (sp.Item, error) {
	sid, err := d.session(actor)
	if err != nil {
		return sp.Item{}, err
	}
	in.Actor, in.SID = actor, sid
	if in.Stream == "" {
		in.Stream = "outlet:" + d.W.Outlet
	}
	return d.record(in, false)
}

// ids returns the sorted ids of an entity in the device's state.
func (d *Device) ids(entity string) []string {
	var out []string
	d.Eng.WithState(func(s *engine.State) { out = s.IDs(entity) })
	sort.Strings(out)
	return out
}

func (d *Device) nextID(prefix string) string {
	d.n++
	return fmt.Sprintf("%s-%s-%d", prefix, d.ID, d.n)
}

// OrderOp creates an order with a line and a KDS ticket item (an `append` order, an `append`
// line and a `rank` KDS item in one atomic op).
func (d *Device) OrderOp(rng *Rand) (sp.Item, error) {
	oid, lid, kid := d.nextID("o"), d.nextID("l"), d.nextID("k")
	return d.Do(pCashier, engine.Input{Intent: "order.create", Muts: []sp.Mut{
		{E: "order", ID: oid, K: sp.KInsert, F: map[string]any{"table": int64(rng.Range(1, 20))}},
		{E: "order_line", ID: lid, K: sp.KInsert, F: map[string]any{"order_id": oid, "item": int64(rng.Range(1, 40)), "qty": int64(rng.Range(1, 4))}},
		{E: "kds_item", ID: kid, K: sp.KInsert, F: map[string]any{"order_id": oid, "status": "new"}},
	}})
}

// BillOp finalises a bill for an order of the local state: allocates the next number of the
// device's sale series in the same transaction.
func (d *Device) BillOp(rng *Rand) (sp.Item, error) {
	orders := d.ids("order")
	if len(orders) == 0 {
		return sp.Item{}, errors.New("sim: no order")
	}
	oid := orders[rng.Intn(len(orders))]
	bid := d.nextID("b")
	total := int64(rng.Range(5, 400) * 100)
	return d.Do(pCashier, engine.Input{Intent: "bill.finalize", DocType: "tax_invoice", MutsFn: func(n string) []sp.Mut {
		return []sp.Mut{{E: "bill", ID: bid, K: sp.KInsert, F: map[string]any{"number": n, "total_paise": total, "order_id": oid, "device": d.ID}}}
	}})
}

// PaymentOp records a payment against a bill of the local state; full means the whole total.
func (d *Device) PaymentOp(rng *Rand) (sp.Item, error) {
	bills := d.ids("bill")
	if len(bills) == 0 {
		return sp.Item{}, errors.New("sim: no bill")
	}
	bid := bills[rng.Intn(len(bills))]
	row, _ := d.billRow(bid)
	total, _ := row["total_paise"].(int64)
	amt := total
	if rng.Chance(0.3) {
		amt = total / 2
	}
	return d.Do(pCashier, engine.Input{Intent: "payment.record", Muts: []sp.Mut{
		{E: "payment", ID: d.nextID("p"), K: sp.KInsert, F: map[string]any{"bill_id": bid, "amount_paise": amt}}}})
}

func (d *Device) billRow(id string) (map[string]any, bool) {
	var r map[string]any
	var ok bool
	d.Eng.WithState(func(s *engine.State) { r, ok = s.Row("bill", id) })
	return r, ok
}

// CreditNoteOp issues a credit note against a bill, from the device's credit-note series.
func (d *Device) CreditNoteOp(rng *Rand) (sp.Item, error) {
	bills := d.ids("bill")
	if len(bills) == 0 {
		return sp.Item{}, errors.New("sim: no bill")
	}
	bid := bills[rng.Intn(len(bills))]
	return d.Do(pCashier, engine.Input{Intent: "creditnote.issue", DocType: "credit_note", MutsFn: func(n string) []sp.Mut {
		return []sp.Mut{{E: "credit_note", ID: d.nextID("c"), K: sp.KInsert, F: map[string]any{"number": n, "bill_id": bid, "amount_paise": int64(rng.Range(1, 5) * 100)}}}
	}})
}

// StockOp moves stock with a signed delta.
func (d *Device) StockOp(rng *Rand) (sp.Item, error) {
	item := fmt.Sprintf("item-%d", rng.Range(1, 6))
	return d.Do(pCashier, engine.Input{Intent: "stock.move", Muts: []sp.Mut{
		{E: "stock_level", ID: item, K: sp.KDelta, F: map[string]any{"qty_milli": int64(rng.Range(-3, 5) * 1000)}}}})
}

// KDSOp moves a KDS item to another status (a stale device may move it backwards; rank policy
// keeps the highest).
func (d *Device) KDSOp(rng *Rand) (sp.Item, error) {
	items := d.ids("kds_item")
	if len(items) == 0 {
		return sp.Item{}, errors.New("sim: no kds item")
	}
	st := []string{"new", "preparing", "ready", "served"}[rng.Intn(4)]
	return d.Do(pCashier, engine.Input{Intent: "kds.status", Muts: []sp.Mut{
		{E: "kds_item", ID: items[rng.Intn(len(items))], K: sp.KSet, F: map[string]any{"status": st}}}})
}

// PriceOp edits a menu item price as the manager (a `lww` review field); prev is the stamp of
// the winning candidate this device saw, so a concurrent edit is detected on every node.
func (d *Device) PriceOp(rng *Rand) (sp.Item, error) {
	item := fmt.Sprintf("menu-%d", rng.Range(1, 5))
	var prev string
	var exists bool
	d.Eng.WithState(func(s *engine.State) {
		prev = s.FieldStamp("menu_item", item, "price_paise")
		_, exists = s.Row("menu_item", item)
	})
	price := int64(rng.Range(50, 400) * 100)
	m := sp.Mut{E: "menu_item", ID: item, K: sp.KSet, F: map[string]any{"price_paise": price}, Prev: map[string]string{"price_paise": prev}}
	if !exists {
		// First sight of the item: an insert with its name, so the row exists. Concurrent inserts
		// of one id from two devices merge field by field like any other last-writer-wins edit.
		m = sp.Mut{E: "menu_item", ID: item, K: sp.KInsert, F: map[string]any{"name": item, "price_paise": price}, Prev: map[string]string{"price_paise": prev}}
	}
	return d.Do(pManager, engine.Input{Stream: "brand:" + d.W.Brand, Intent: "menu.price.set", Muts: []sp.Mut{m}})
}

// ActivateSeriesOp is a manager's offline activation of the device's dormant series (S7).
func (d *Device) ActivateSeriesOp() (sp.Item, error) {
	it, err := d.Do(pManager, engine.Input{Intent: "series.activate", Muts: []sp.Mut{
		{E: "series_activation", ID: d.saleCode, K: sp.KInsert, F: map[string]any{"device": d.ID}}}})
	if err == nil {
		d.activated = true
	}
	return it, err
}

// Billing reports whether the device may finalise bills in normal operation.
func (d *Device) Billing() bool {
	if d.Kind == sp.KindPOS {
		return true
	}
	return d.Kind == sp.KindWaiter && d.activated
}

// SaleCode and CNCode expose the series codes the device holds.
func (d *Device) SaleCode() string { return d.saleCode }

// CNCode is the credit-note series code.
func (d *Device) CNCode() string { return d.cnCode }

// SetBadSeries makes finalisation number in another device's series (injected fault V1).
func (d *Device) SetBadSeries(code string) { d.badSeries = code }

// Auth tokens used by key-loss tests.

// DrainToken mints the drain token of a revoked device, or a recovery drain token when
// recovers names the old origin.
func (d *Device) DrainToken(recovers string) string {
	sub := ""
	if recovers != "" {
		sub = "recovers:" + recovers
	}
	return d.W.Token(auth.TypeDrain, d.ID, sub)
}
