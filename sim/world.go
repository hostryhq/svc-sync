package sim

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-common/clock"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/go-common/testkit"
	"github.com/hostryhq/svc-sync/api"
	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/hub"
	"github.com/hostryhq/svc-sync/identitystub"
	"github.com/hostryhq/svc-sync/repository"
	"github.com/hostryhq/svc-sync/service"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// WorldOptions shape a world.
type WorldOptions struct {
	// Dir holds the SQLite files; required.
	Dir string
	// Pos, Waiters, KDS are the device counts. The first waiter holds a dormant sale series.
	Pos, Waiters, KDS int
	// CloudDSN selects the gateway store: empty means SQLite in Dir, "postgres://..." the dev stack.
	CloudDSN string
	// Start is the fake clock's start; zero means 09:00 IST on 24 Nov 2026.
	Start time.Time
	// NoHub builds a world with no LAN hub.
	NoHub bool
}

// World is one outlet with its devices, hub and cloud.
type World struct {
	Ctx      context.Context
	Opt      WorldOptions
	Clock    *testkit.FakeClock
	Net      *Net
	Identity *identitystub.Identity
	Issuer   *authtest.Issuer
	Tenant   string
	Outlet   string
	Brand    string

	GWStore repository.Store
	GW      *service.Gateway
	CloudH  http.Handler
	Hub     *hub.Hub
	HubKey  *sp.KeyPair
	HubCred sp.CredentialEnvelope
	HubDB   string
	hubGen  int
	HubUp   *engine.Client
	HubH    http.Handler

	// Via counts which upstream device syncs used.
	Via     struct{ HubOK, HubFail, CloudDirect int }
	Devices []*Device
	byID    map[string]*Device
}

const (
	pCashier = "m1"
	pManager = "m2"
	pLeaver  = "m3"
)

var cashierPerms = []string{"order.create", "payment.take", "bill.finalize", "bill.refund", "stock.adjust", "kds.update", "session.open"}
var managerPerms = append(append([]string{}, cashierPerms...), "menu.edit", "series.activate", "approval.grant")

// NewWorld builds the whole stack. Nothing is deployed anywhere: it is all in this process.
func NewWorld(ctx context.Context, rng *Rand, opt WorldOptions) (*World, error) {
	clk := testkit.NewClock()
	clk.Set(time.Date(2026, 11, 24, 3, 30, 0, 0, time.UTC)) // 09:00 IST
	if !opt.Start.IsZero() {
		clk.Set(opt.Start)
	}
	w := &World{Ctx: ctx, Opt: opt, Clock: clk, Net: NewNet(rng.R), Tenant: testkit.ContextA().TenantID.String(), Outlet: testkit.ContextA().OutletID.String(),
		Brand: testkit.ContextB().OutletID.String(), byID: map[string]*Device{}}
	id, err := identitystub.New(clk.Now, nil)
	if err != nil {
		return nil, err
	}
	w.Identity = id
	w.Issuer = authtest.NewTenantIssuer(clock.Func(clk.Now))
	id.SetMember(w.Tenant, pCashier, cashierPerms...)
	id.SetMember(w.Tenant, pManager, managerPerms...)
	id.SetMember(w.Tenant, pLeaver, cashierPerms...)

	dsn := opt.CloudDSN
	if dsn == "" {
		dsn = "file:" + filepath.Join(opt.Dir, "cloud.db")
	}
	if w.GWStore, err = repository.Open(dsn); err != nil {
		return nil, err
	}
	if err := w.startGateway(); err != nil {
		return nil, err
	}
	if !opt.NoHub {
		if err := w.newHub(true); err != nil {
			return nil, err
		}
	}
	n := 0
	add := func(kind string) error {
		n++
		_, err := w.AddDevice(fmt.Sprintf("dev-%02d-%s", n, kind), kind)
		return err
	}
	for i := 0; i < opt.Pos; i++ {
		if err := add(sp.KindPOS); err != nil {
			return nil, err
		}
	}
	for i := 0; i < opt.Waiters; i++ {
		if err := add(sp.KindWaiter); err != nil {
			return nil, err
		}
	}
	for i := 0; i < opt.KDS; i++ {
		if err := add(sp.KindKDS); err != nil {
			return nil, err
		}
	}
	return w, nil
}

func (w *World) startGateway() error {
	gw, err := service.New(w.Ctx, service.Config{Store: w.GWStore, Dir: w.Identity, OpKey: w.Identity.CloudKey, Now: w.Clock.Now, Outbox: false})
	if err != nil {
		return err
	}
	w.GW = gw
	mux := http.NewServeMux()
	api.Mount(mux, api.Options{Auth: api.BearerAuth{Verifier: w.Issuer.Verifier(), Dir: w.Identity}, Backend: api.GatewayBackend{G: gw}})
	api.Admin(mux, gw, w.Issuer.Verifier())
	w.CloudH = mux
	return nil
}

// RestartGateway rebuilds the gateway service on the current store (after a restore or a crash).
func (w *World) RestartGateway() error { return w.startGateway() }

func (w *World) cloudClient(link, device string, typ auth.TokenType, subject string) *http.Client {
	return &http.Client{Transport: w.Net.RoundTripper(link, w.cloudIndirect())}
}

// cloudIndirect resolves the gateway handler per call, so a restart or restore of the gateway
// does not strand transports created earlier.
func (w *World) cloudIndirect() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) { w.CloudH.ServeHTTP(rw, r) })
}

// Token mints a device or drain token (the identity service's job in production).
func (w *World) Token(typ auth.TokenType, device, subject string) string {
	return w.Issuer.Mint(authtest.Spec{Type: typ, Tenant: ids.ID(w.Tenant), Device: device, Subject: subject})
}

// CloudTransport is a node's transport to the gateway.
func (w *World) CloudTransport(link, device string) *engine.HTTPTransport {
	return &engine.HTTPTransport{Base: "http://cloud", Client: w.cloudClient(link, device, auth.TypeDevice, ""),
		Authorize: func(r *http.Request, _ []byte) error {
			r.Header.Set("Authorization", "Bearer "+w.Token(auth.TypeDevice, device, ""))
			return nil
		}}
}

// newHub creates (or re-creates, on a wiped disk) the outlet hub.
func (w *World) newHub(first bool) error {
	if first {
		kp, err := sp.NewKeyPair("k-hub", nil)
		if err != nil {
			return err
		}
		w.HubKey = kp
		if w.HubCred, err = w.Identity.Activate(w.Tenant, w.Outlet, w.Brand, "hub-01", sp.KindHub, kp, ""); err != nil {
			return err
		}
	}
	w.hubGen++
	w.HubDB = filepath.Join(w.Opt.Dir, fmt.Sprintf("hub-%d.db", w.hubGen))
	st, err := repository.Open("file:" + w.HubDB)
	if err != nil {
		return err
	}
	w.openHub(st)
	return nil
}

func (w *World) openHub(st repository.Store) {
	h, err := hub.New(w.Ctx, hub.Config{
		Tenant: w.Tenant, Outlet: w.Outlet, Brand: w.Brand, Cred: w.HubCred, Key: w.HubKey,
		IdentityPub: w.Identity.IdentityPub(), CloudKeys: map[string]*ecdsaPub{"gateway-op-1": &w.Identity.CloudKey.Priv.PublicKey},
		Store: st, Now: w.Clock.Now, Peers: w.Identity.Devices(w.Tenant, w.Outlet),
		Members: func(actor string) bool { return w.Identity.InAnyPackOf(w.Tenant, w.Outlet, actor) },
		SeriesOwner: func(code string) (string, bool) {
			s, ok := w.Identity.Series(w.Tenant, code)
			return s.Device, ok
		},
	})
	if err != nil {
		panic(err)
	}
	w.Hub = h
	w.HubH = h.Handler()
	w.HubUp = h.SetUpstream(w.CloudTransport("hub-cloud", "hub-01"))
	for _, d := range w.Devices {
		_ = h.AddPeer(d.Cred)
		if rev, _ := w.Identity.Revoked(w.Tenant, d.ID); rev {
			h.Revoke(d.ID)
		}
	}
}

// WipeHub replaces the hub's disk: a fresh empty store, same identity (S12 item 5).
func (w *World) WipeHub() error {
	_ = w.Hub.Engine().Config().Store.Close()
	return w.newHub(false)
}

// RestartHub reopens the hub from its disk (process killed and started again).
func (w *World) RestartHub() error {
	_ = w.Hub.Engine().Config().Store.Close()
	st, err := repository.Open("file:" + w.HubDB)
	if err != nil {
		return err
	}
	w.openHub(st)
	return nil
}

// Dev returns a device by id.
func (w *World) Dev(id string) *Device { return w.byID[id] }

// Advance moves the fake clock.
func (w *World) Advance(d time.Duration) { w.Clock.Advance(d) }

// Close releases stores.
func (w *World) Close() {
	for _, d := range w.Devices {
		_ = d.Store.Close()
	}
	if w.Hub != nil {
		_ = w.Hub.Engine().Config().Store.Close()
	}
	_ = w.GWStore.Close()
}

func removeDBFiles(path string) {
	for _, s := range []string{"", "-wal", "-shm"} {
		_ = os.Remove(path + s)
	}
}

// SnapshotCloud takes a consistent copy of the gateway database (a backup).
func (w *World) SnapshotCloud(name string) error {
	path := filepath.Join(w.Opt.Dir, "snap-"+name+".db")
	removeDBFiles(path)
	_, err := w.GWStore.DB().ExecContext(w.Ctx, "VACUUM INTO '"+path+"'")
	return err
}

// RestoreCloud replaces the gateway database with a backup and stamps a new restore epoch, as
// hostry-restore does (ADR-0006 H6), then restarts the gateway.
func (w *World) RestoreCloud(name, epoch string) error {
	snap := filepath.Join(w.Opt.Dir, "snap-"+name+".db")
	live := filepath.Join(w.Opt.Dir, "cloud.db")
	if err := w.GWStore.Close(); err != nil {
		return err
	}
	removeDBFiles(live)
	raw, err := os.ReadFile(snap)
	if err != nil {
		return err
	}
	if err := os.WriteFile(live, raw, 0o600); err != nil {
		return err
	}
	if w.GWStore, err = repository.Open("file:" + live); err != nil {
		return err
	}
	if err := repository.SetPlatformMeta(w.Ctx, w.GWStore, service.MetaEpochID, epoch); err != nil {
		return err
	}
	return w.startGateway()
}
