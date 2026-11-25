// Package hub is the restaurant LAN hub (ADR-0002 S8): a relay and a LAN cache, not an
// authority. It stores the outlet's ops, relays them between devices and to the cloud, keeps a
// generic materialised copy so a new tablet can bootstrap without internet, and wakes devices
// when new ops arrive. It assigns no sequence numbers and no bill numbers, and it understands the
// envelope and the generic mutation kinds, never the meaning of a bill. Here it is a plain
// binary; running it as a Windows service is the installer's job (Phase 2).
package hub

import (
	"context"
	"crypto/ecdsa"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/hostryhq/svc-sync/api"
	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// PubKey is an ECDSA public key.
type PubKey = ecdsa.PublicKey

// Config builds a Hub.
type Config struct {
	Tenant, Outlet, Brand string
	// Cred and Key are the hub's own device credential and key (kind hub). Cred.Cred holds the claims; its Sig is empty when the
	// credential came only as a LAN credential JWS (a hub pack), which is all the LAN handshake needs.
	Cred sp.CredentialEnvelope
	Key  *sp.KeyPair
	// CredJWS is the hub's LAN credential (compact JWS) that it shows to a device at helloLan.
	CredJWS string
	// IdentityPub verifies every credential, IdentityNext is the next identity key of the pack (may be nil); CloudKeys are the
	// gateway op-signing keys of the pack.
	IdentityPub  *ecdsa.PublicKey
	IdentityNext *ecdsa.PublicKey
	CloudKeys    map[string]*ecdsa.PublicKey
	Store        repository.Store
	Now          func() time.Time
	Log          *slog.Logger
	// Peers are the outlet's device credentials from the pack.
	Peers []sp.CredentialEnvelope
	// Members and SeriesOwner come from the pack: the staff the outlet knows, and which device
	// holds which series code. They drive the structural check before relaying (S8).
	Members     func(actor string) bool
	SeriesOwner func(code string) (device string, ok bool)
	// PIIToUnprotected lifts the placement rule of ADR-0002 A3.5 item 2 (dev, test and ci only).
	PIIToUnprotected bool
}

// Hub is the relay node.
type Hub struct {
	cfg   Config
	eng   *engine.Engine
	cache *engine.CredCache
	cl    *engine.Client

	keys     *tlsKeys
	mu       sync.Mutex
	pending  map[string]pendingHS
	sessions map[string]session
	revoked  map[string]bool
	poke     int64
	pokeCh   chan struct{}
	held     []sp.HeldSlot // what the cloud last told about the origins relayed here (A1.2)
}

// New builds a hub and opens its store.
func New(ctx context.Context, cfg Config) (*Hub, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	keys, err := newTLSKeys(cfg.Now)
	if err != nil {
		return nil, err
	}
	h := &Hub{cfg: cfg, keys: keys, pending: map[string]pendingHS{}, sessions: map[string]session{}, revoked: map[string]bool{}, pokeCh: make(chan struct{})}
	h.cache = engine.NewCredCache(cfg.IdentityPub, cfg.Tenant, cfg.Outlet, cfg.Now)
	for kid, k := range cfg.CloudKeys {
		h.cache.AddCloudKey(kid, k)
	}
	if err := h.cache.Add(cfg.Cred); err != nil {
		h.cache.AddLAN(cfg.Cred.Cred)
	}
	for _, p := range cfg.Peers {
		_ = h.cache.Add(p)
	}
	h.eng = engine.New(engine.Config{
		Role: engine.RoleHub, Kind: sp.KindHub, Tenant: cfg.Tenant, Outlet: cfg.Outlet, Store: cfg.Store, Trust: h.cache,
		Clock: sp.NewClock(cfg.Now), PIIToUnprotected: cfg.PIIToUnprotected,
		Hooks: engine.Hooks{Authorize: h.authorize, Verdict: h.structural},
	})
	if err := h.eng.Open(ctx); err != nil {
		return nil, err
	}
	return h, nil
}

// Engine exposes the hub's engine (simulator reads vectors and state hashes).
func (h *Hub) Engine() *engine.Engine { return h.eng }

// Cache exposes the credential cache (the pack the hub holds).
func (h *Hub) Cache() *engine.CredCache { return h.cache }

// AddPeer installs a device credential from a pack refresh.
func (h *Hub) AddPeer(e sp.CredentialEnvelope) error { return h.cache.Add(e) }

// Revoke refuses a device on the LAN from now on (pack refresh with a revocation).
func (h *Hub) Revoke(device string) {
	h.mu.Lock()
	h.revoked[device] = true
	h.mu.Unlock()
	h.dropSessions(device)
}

// IsRevoked reports whether the device is refused.
func (h *Hub) IsRevoked(device string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.revoked[device]
}

func (h *Hub) streamOK(stream string) bool {
	switch stream {
	case "outlet:" + h.cfg.Outlet, "tenant:" + h.cfg.Tenant:
		return true
	}
	return h.cfg.Brand != "" && stream == "brand:"+h.cfg.Brand
}

// authorize: the hub stores ops only of unrevoked devices of its own outlet (and cloud origins
// re-offered by a device), in streams inside the outlet's binding.
func (h *Hub) authorize(_ repository.Tx, c engine.Caller, origin, stream string, _, endorsed bool) string {
	if !h.streamOK(stream) {
		return sp.ReasonStream
	}
	if len(origin) > len(engine.CloudOriginPrefix) && origin[:len(engine.CloudOriginPrefix)] == engine.CloudOriginPrefix {
		return ""
	}
	if _, ok := h.cache.Claims(origin); !ok {
		return sp.ReasonOrigin
	}
	// Revocation is enforced where ops are first accepted, not on pull, so the history of a
	// since-revoked device stays readable (S17).
	// An endorsed batch may name a revoked (key-lost) origin: the engine takes the ops only with the
	// endorsement, the recovery credential and the attestation (A2.1).
	if c.ID != "upstream" && h.IsRevoked(origin) && !endorsed {
		return sp.ReasonRevoked
	}
	return ""
}

// structural is the hub's check before relaying (S8): intent allowed for the origin's device
// kind, actor in the outlet's pack, and a document number only from a series granted to the origin
// (A1.1, V8). It cannot verify PIN-derived proofs. A failing op is stored but not relayed to peers;
// the origin still delivers it to the cloud, which decides.
func (h *Hub) structural(_ repository.Tx, p *engine.Parsed, vc engine.VerdictCtx) engine.Verdict {
	ok := engine.Verdict{Status: repository.StAccepted}
	held := engine.Verdict{Status: repository.StHeldLocal, Reason: "structural"}
	if p.Opaque {
		return held
	}
	b := p.Body
	if len(b.Origin) > len(engine.CloudOriginPrefix) && b.Origin[:len(engine.CloudOriginPrefix)] == engine.CloudOriginPrefix {
		return ok
	}
	in, known := sp.Intents[b.Intent]
	cred, have := h.cache.Claims(b.Origin)
	if !known || !have || !in.Allows(cred.Kind) {
		return held
	}
	if h.cfg.Members != nil && (b.Actor == "" || !h.cfg.Members(b.Actor)) {
		return held
	}
	if h.cfg.SeriesOwner != nil {
		for _, doc := range b.Documents() {
			if dev, found := h.cfg.SeriesOwner(doc.SeriesCode()); !found || dev != b.Origin {
				return held
			}
		}
	}
	return ok
}

// --- api.Backend ---

// Hello implements api.Backend.
func (h *Hub) Hello(ctx context.Context, p api.Principal, req sp.HelloRequest) (sp.HelloResponse, error) {
	v, err := h.eng.Vector(ctx)
	if err != nil {
		return sp.HelloResponse{}, err
	}
	epoch := ""
	if h.cl != nil {
		epoch = h.cl.Epoch
	}
	// cloud_vector is what the cloud confirmed to this hub at its last upstream contact: a device
	// may treat its ops under it as delivered to the cloud (delivery state in_cloud via the hub).
	var cv sp.Vector
	if h.cl != nil {
		cv = h.cl.Upstream
	}
	return sp.HelloResponse{
		CloudVector: cv,
		Protocol:    sp.ProtocolVersion, Role: string(engine.RoleHub), NodeID: h.cfg.Cred.Cred.DeviceID,
		Time: h.cfg.Now().UTC().Format(time.RFC3339Nano), Epoch: epoch, Vector: v, MinSupportedVersion: "0.0.0",
		Streams: []string{"outlet:" + h.cfg.Outlet, "tenant:" + h.cfg.Tenant},
	}, nil
}

// Push implements api.Backend.
func (h *Hub) Push(ctx context.Context, p api.Principal, req sp.PushRequest) (sp.PushResponse, error) {
	res, err := h.eng.Ingest(ctx, engine.IngestReq{Items: req.Items, Seals: req.Seals, Endorsements: req.Endorsements, Attestations: req.Attestations, Caller: p.Caller})
	if err != nil {
		return sp.PushResponse{}, err
	}
	if len(res.New) > 0 {
		h.bump()
	}
	return sp.PushResponse{Vector: res.Vector, Refused: res.Refused}, nil
}

// Pull implements api.Backend. The hub returns each device's own held list from what the cloud
// last told it; the device's next direct cloud contact corrects any mistake (A1.2 item 3).
func (h *Hub) Pull(ctx context.Context, p api.Principal, req sp.PullRequest) (sp.PullResponse, error) {
	resp, err := h.eng.Serve(ctx, req, engine.ServeOpts{Caller: p.Caller, Streams: h.streams(), Recoverers: h.cache.Recoverers}, func(origin string) (sp.CredentialEnvelope, bool) {
		return h.cache.Get(origin)
	})
	if err != nil {
		return resp, err
	}
	h.mu.Lock()
	for _, s := range h.held {
		if s.Origin == p.Caller.ID {
			resp.OwnHeld = append(resp.OwnHeld, s)
		}
	}
	h.mu.Unlock()
	return resp, nil
}

func (h *Hub) streams() []string {
	s := []string{"outlet:" + h.cfg.Outlet, "tenant:" + h.cfg.Tenant}
	if h.cfg.Brand != "" {
		s = append(s, "brand:"+h.cfg.Brand)
	}
	return s
}

// Upload implements api.Backend: the hub never takes a quarantine or recovery upload (KL3).
func (h *Hub) Upload(context.Context, api.Principal, sp.PushRequest) (sp.PushResponse, error) {
	return sp.PushResponse{}, api.ErrUnsupported
}

// Snapshot implements api.Backend: the generic materialised copy, so a new tablet bootstraps
// without internet.
func (h *Hub) Snapshot(ctx context.Context, p api.Principal) (sp.Snapshot, error) {
	v, err := h.eng.Vector(ctx)
	if err != nil {
		return sp.Snapshot{}, err
	}
	snap := sp.Snapshot{Vector: v}
	h.eng.WithState(func(s *engine.State) {
		snap.Rows = s.Snapshot()
		for _, k := range s.VoidedRefs() {
			snap.Voids = append(snap.Voids, sp.Ref{Origin: k})
		}
	})
	if err := h.eng.SnapshotPII(ctx, snap.Rows, p.Caller); err != nil {
		return sp.Snapshot{}, err
	}
	return snap, nil
}

// Poke implements api.Backend: it returns when the hub has new ops after the counter.
func (h *Hub) Poke(ctx context.Context, _ api.Principal, after int64, wait time.Duration) int64 {
	h.mu.Lock()
	if h.poke > after {
		n := h.poke
		h.mu.Unlock()
		return n
	}
	ch := h.pokeCh
	h.mu.Unlock()
	select {
	case <-ch:
	case <-time.After(wait):
	case <-ctx.Done():
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.poke
}

func (h *Hub) bump() {
	h.mu.Lock()
	h.poke++
	close(h.pokeCh)
	h.pokeCh = make(chan struct{})
	h.mu.Unlock()
}

// Handler returns the hub's HTTP handler.
func (h *Hub) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /sync/v1/lan/hello", h.handleHello)
	mux.HandleFunc("POST /sync/v1/lan/session", h.handleSession)
	api.Mount(mux, api.Options{Auth: LANAuth{H: h}, Backend: h})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"status":"ok"}`)) })
	return mux
}

// --- upstream (hub to cloud) ---

// SetUpstream wires the hub to the cloud through t and returns the client.
func (h *Hub) SetUpstream(t engine.Transport) *engine.Client {
	h.cl = &engine.Client{E: h.eng, T: t, Cache: h.cache, IsHub: true, UpstreamIsCloud: true, Streams: h.streams()}
	return h.cl
}

// SyncUpstream does one round with the cloud and refreshes the held list.
func (h *Hub) SyncUpstream(ctx context.Context) (engine.SyncResult, error) {
	if h.cl == nil {
		return engine.SyncResult{}, nil
	}
	res, err := h.cl.SyncOnce(ctx)
	h.mu.Lock()
	h.held = append([]sp.HeldSlot(nil), append(h.cl.OwnHeld, h.cl.RelayHeld...)...)
	h.mu.Unlock()
	if err == nil {
		n, perr := h.eng.Promote(ctx, h.cl.Upstream, h.held)
		if perr != nil {
			return res, perr
		}
		res.Pulled += n
	}
	if res.Pulled > 0 {
		h.bump()
	}
	return res, err
}

// RunUpstream syncs continuously with jittered backoff until ctx ends (S11).
func (h *Hub) RunUpstream(ctx context.Context, every time.Duration) {
	delay := every
	for {
		_, err := h.SyncUpstream(ctx)
		if err != nil {
			h.cfg.Log.Warn("hub upstream sync failed", "err", err.Error())
			delay = min(delay*2, 60*time.Second)
		} else {
			delay = every
		}
		jitter := time.Duration(rand.Int64N(int64(delay)/4 + 1))
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay + jitter):
		}
	}
}

// LastRefused is what the cloud refused in the last upstream round.
func (h *Hub) LastRefused() []sp.Refusal {
	if h.cl == nil {
		return nil
	}
	return h.cl.LastRefused
}
