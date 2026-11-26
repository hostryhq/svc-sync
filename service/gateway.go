// Package service is the sync-gateway's business logic: the cloud node of Sync Protocol v1. It
// stores every op an authenticated origin delivers, gives each a verdict (S11, A1.1, A1.3), keeps
// the quarantine, the series register and the restore epoch, and publishes accepted ops through
// the transactional outbox. It has no HTTP and no SQL: api calls it, repository persists for it.
package service

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/go-common/restore"
	"github.com/hostryhq/svc-sync/directory"
	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// Config builds a Gateway.
type Config struct {
	Store repository.Store
	// Epoch gives the restore epoch (go-common restore.Reader): read once at start (A2.4).
	Epoch restore.EpochSource
	Dir   directory.Directory
	// OpKey is the gateway op-signing key (public half in every pack).
	OpKey *sp.KeyPair
	Now   func() time.Time
	Log   *slog.Logger
	// Outbox publishes accepted ops to the transactional outbox (Postgres, needs the outbox table).
	Outbox bool
	// IDs generates event ids; defaults to a time-based generator.
	IDs *ids.Generator
	// ReconciledEvent publishes billing.series.reconciled from the gateway when a closed series is
	// confirmed. Off by default: x-publisher is billing (see series.go).
	ReconciledEvent bool
	// PIIToUnprotected lifts the placement rule of ADR-0002 A3.5 item 2 (dev, test and ci only; the command checks HOSTRY_ENV).
	PIIToUnprotected bool
	// MinSupportedVersion is returned by hello (S13).
	MinSupportedVersion string
}

// Gateway is the cloud node.
type Gateway struct {
	cfg   Config
	mu    sync.Mutex
	epoch string
	guard *restore.Guard
	// revoked op-signing keys: never accepted again (A2.1 item 6).
	revokedKids map[string]bool
	eng         map[string]*engine.Engine
	pokes       map[string]*poker
	emitBuckets map[string]*emitBucket
}

type poker struct {
	mu sync.Mutex
	n  int64
	ch chan struct{}
}

// New starts a gateway and settles the restore epoch before it serves anything (S16 item 1).
func New(ctx context.Context, cfg Config) (*Gateway, error) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.IDs == nil {
		cfg.IDs = ids.NewGenerator(cfg.Now, nil)
	}
	if cfg.MinSupportedVersion == "" {
		cfg.MinSupportedVersion = "0.0.0"
	}
	g := &Gateway{cfg: cfg, eng: map[string]*engine.Engine{}, pokes: map[string]*poker{}, revokedKids: map[string]bool{}}
	g.guard = restore.NewGuard(cfg.Epoch, restore.NewSQLState(cfg.Store.DB(), cfg.Store.Dialect() == "postgres"), cfg.Log)
	// S16 item 2: after a restore the gateway opens a new cloud origin cloud-<epoch>. Its seq starts at 1,
	// so no op identity is reused; the origin is opened by the first op it records, which makes the
	// hook idempotent. The hook only reports it.
	g.guard.OnRestore("sync-new-cloud-origin", func(_ context.Context, from string, to restore.Epoch) error {
		cfg.Log.Info("restore epoch changed: opening new cloud origin", "from", from, "to", to.EpochID)
		return nil
	})
	if err := g.guard.Run(ctx); err != nil {
		return nil, err
	}
	g.epoch = g.guard.Epoch().EpochID
	return g, nil
}

// Guard exposes the restore guard: add Guard().Check to /readyz and start the outbox relay after
// Guard().Done().
func (g *Gateway) Guard() *restore.Guard { return g.guard }

// Epoch returns the epoch the gateway serves under.
func (g *Gateway) Epoch() string { g.mu.Lock(); defer g.mu.Unlock(); return g.epoch }

// opKey is the current op-signing key.
func (g *Gateway) opKey() *sp.KeyPair { g.mu.Lock(); defer g.mu.Unlock(); return g.cfg.OpKey }

// tenantTrust resolves keys for one tenant: device keys from the directory, the current gateway
// op-signing key for cloud origins and endorsements, and the recovery credentials of key-lost
// origins (A2.1).
type tenantTrust struct {
	tenant string
	dir    directory.Directory
	g      *Gateway
}

func (t tenantTrust) OriginKey(origin string) (*ecdsa.PublicKey, bool) {
	if strings.HasPrefix(origin, engine.CloudOriginPrefix) {
		k := t.g.opKey()
		return &k.Priv.PublicKey, true
	}
	c, ok := t.dir.Credential(t.tenant, origin)
	if !ok {
		return nil, false
	}
	pub, err := c.Cred.PubKey()
	return pub, err == nil
}

// OpKey implements engine.RecoveryTrust: only the current key; a rotated-out key is refused.
func (t tenantTrust) OpKey(kid string) (*ecdsa.PublicKey, bool) {
	k := t.g.opKey()
	if k.Kid != kid || t.g.isRevoked(kid) {
		return nil, false
	}
	return &k.Priv.PublicKey, true
}

// Recoverers implements engine.RecoveryTrust.
func (t tenantTrust) Recoverers(origin string) []sp.CredentialEnvelope {
	rec, ok := t.dir.RecoveryFor(t.tenant, origin)
	if !ok {
		return nil
	}
	c, ok := t.dir.Credential(t.tenant, rec.New)
	if !ok || c.Cred.Recovers != origin {
		return nil
	}
	return []sp.CredentialEnvelope{c}
}

func (g *Gateway) isRevoked(kid string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.revokedKids[kid]
}

// engineFor returns the tenant's engine.
func (g *Gateway) engineFor(tenant string) *engine.Engine {
	g.mu.Lock()
	defer g.mu.Unlock()
	if e, ok := g.eng[tenant]; ok {
		return e
	}
	e := engine.New(engine.Config{
		Role: engine.RoleCloud, Tenant: tenant, Origin: engine.CloudOriginPrefix + g.epoch, Key: g.cfg.OpKey,
		Store: g.cfg.Store, Trust: tenantTrust{tenant: tenant, dir: g.cfg.Dir, g: g},
		Clock: sp.NewClock(g.cfg.Now), NoState: true, PIIToUnprotected: g.cfg.PIIToUnprotected,
		Hooks: engine.Hooks{
			Authorize: g.authorize(tenant),
			Verdict: func(tx repository.Tx, p *engine.Parsed, vc engine.VerdictCtx) engine.Verdict {
				var v engine.Verdict
				if vc.Endorsed {
					// A re-offered released op (A2.1 item 5): taken as released, marked unsealed, without
					// asking the owner again. The remaining checks still run.
					v = g.judge(tx, p, vc, &releaseCtx{Marks: []string{MarkUnsealed}})
				} else {
					v = g.judge(tx, p, vc, nil)
				}
				if p.PIIDropped > 0 {
					v.Marks = append(v.Marks, MarkPIIDropped) // personal data that did not match its commitment was discarded
				}
				return v
			},
			QuarantineOwnUnverified: true,
			Stored:                  g.stored,
			OnFork:                  g.onFork,
			OnEndorsed:              g.onEndorsed,
		},
	})
	g.eng[tenant] = e
	return e
}

func (g *Gateway) poker(tenant string) *poker {
	g.mu.Lock()
	defer g.mu.Unlock()
	p := g.pokes[tenant]
	if p == nil {
		p = &poker{ch: make(chan struct{})}
		g.pokes[tenant] = p
	}
	return p
}

func (p *poker) bump() {
	p.mu.Lock()
	p.n++
	close(p.ch)
	p.ch = make(chan struct{})
	p.mu.Unlock()
}

// Poke blocks until the tenant has new ops after the counter value `after`, or wait elapses.
// It carries no data; the caller pulls (S10).
func (g *Gateway) Poke(ctx context.Context, tenant string, after int64, wait time.Duration) int64 {
	p := g.poker(tenant)
	p.mu.Lock()
	if p.n > after {
		n := p.n
		p.mu.Unlock()
		return n
	}
	ch := p.ch
	p.mu.Unlock()
	select {
	case <-ch:
	case <-time.After(wait):
	case <-ctx.Done():
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.n
}

func streamAllowed(c engine.Caller, tenant, stream string) bool {
	kind, id, ok := strings.Cut(stream, ":")
	if !ok {
		return false
	}
	switch kind {
	case "outlet":
		return id == c.Outlet
	case "brand":
		return c.Brand != "" && id == c.Brand
	case "tenant":
		return id == tenant
	}
	return false
}

func allowedStreams(c engine.Caller, tenant string, all []string) []string {
	var out []string
	for _, s := range all {
		if streamAllowed(c, tenant, s) {
			out = append(out, s)
		}
	}
	return out
}

// authorize decides whether the caller may deliver ops of origin in stream (S11 first table row,
// ADR-0005 section 4, A1.3 items 4 and 5).
func (g *Gateway) authorize(tenant string) func(repository.Tx, engine.Caller, string, string, bool, bool) string {
	return func(_ repository.Tx, c engine.Caller, origin, stream string, recovery, endorsed bool) string {
		if !streamAllowed(c, tenant, stream) {
			return sp.ReasonStream
		}
		if recovery {
			if c.Recovers != "" {
				rec, ok := g.cfg.Dir.RecoveryFor(tenant, origin)
				if origin != c.Recovers || !ok || rec.New != c.ID {
					return sp.ReasonRecovery
				}
				return ""
			}
			if revoked, _ := g.cfg.Dir.Revoked(tenant, origin); !c.Drain || c.ID != origin || !revoked {
				return sp.ReasonRecovery
			}
			return ""
		}
		if c.Drain {
			return sp.ReasonRecovery
		}
		if strings.HasPrefix(origin, engine.CloudOriginPrefix) {
			return "" // a re-offered cloud op: its seal must verify under the op-signing key
		}
		cred, ok := g.cfg.Dir.Credential(tenant, origin)
		if !ok || cred.Cred.OutletID != c.Outlet {
			return sp.ReasonOrigin
		}
		if revoked, reason := g.cfg.Dir.Revoked(tenant, origin); revoked && reason == "key_lost" && c.Kind != sp.KindHub && c.ID != origin && !endorsed {
			return sp.ReasonRecovery // KL2: the tail of a key-lost origin comes only through the recovery upload
		}
		return ""
	}
}

// Hello answers the handshake (S10): epoch, the cloud's vector for the caller's streams, time.
func (g *Gateway) Hello(ctx context.Context, tenant string, c engine.Caller, req sp.HelloRequest) (sp.HelloResponse, error) {
	e := g.engineFor(tenant)
	vec, err := e.Vector(ctx)
	if err != nil {
		return sp.HelloResponse{}, err
	}
	out := sp.Vector{}
	streams := map[string]bool{}
	for k, s := range vec {
		_, stream, _ := sp.SplitVKey(k)
		if streamAllowed(c, tenant, stream) {
			out[k] = s
			streams[stream] = true
		}
	}
	list := []string{"outlet:" + c.Outlet, "tenant:" + tenant}
	if c.Brand != "" {
		list = append(list, "brand:"+c.Brand)
	}
	if err := g.noteGaps(ctx, tenant, req.Vector, vec); err != nil {
		return sp.HelloResponse{}, err
	}
	if err := g.noteErasureAcks(ctx, tenant, c, req.PIIErased); err != nil {
		return sp.HelloResponse{}, err
	}
	unboundH, err := g.answerUnbound(ctx, tenant, c, req)
	if err != nil {
		return sp.HelloResponse{}, err
	}
	return sp.HelloResponse{UnboundH: unboundH,
		Protocol: sp.ProtocolVersion, Role: string(engine.RoleCloud), NodeID: "gateway", Time: g.cfg.Now().UTC().Format(time.RFC3339Nano),
		Epoch: g.Epoch(), Vector: out, CloudVector: out, MinSupportedVersion: g.cfg.MinSupportedVersion, Streams: list,
	}, nil
}

// noteGaps raises "unrecoverable origin gap" when a node reports a vector above the cloud's and
// no re-offer has closed it within 24 hours (S16 item 7).
func (g *Gateway) noteGaps(ctx context.Context, tenant string, node, cloud sp.Vector) error {
	return g.cfg.Store.InTx(ctx, tenant, func(tx repository.Tx) error {
		for k, s := range node {
			key := "gap:" + k
			if s <= cloud[k] {
				// The gap closed (a re-offer arrived, A2.2): the alert clears.
				if _, ok, err := tx.GetMeta(key); err != nil {
					return err
				} else if ok {
					for _, m := range []string{key, "gap-alerted:" + k} {
						if err := tx.DeleteMeta(m); err != nil {
							return err
						}
					}
					if err := tx.ResolveAlerts("unrecoverable_origin_gap", k); err != nil {
						return err
					}
				}
				continue
			}
			first, ok, err := tx.GetMeta(key)
			if err != nil {
				return err
			}
			if !ok {
				if err := tx.SetMeta(key, g.cfg.Now().UTC().Format(time.RFC3339)); err != nil {
					return err
				}
				continue
			}
			t, _ := time.Parse(time.RFC3339, first)
			if g.cfg.Now().Sub(t) > 24*time.Hour {
				if done, _, _ := tx.GetMeta("gap-alerted:" + k); done == "" {
					if err := tx.AddAlert("vendor", "high", "unrecoverable_origin_gap", k); err != nil {
						return err
					}
					if err := tx.SetMeta("gap-alerted:"+k, "1"); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
}

// Push stores a batch from an authenticated node and returns what the cloud now holds.
func (g *Gateway) Push(ctx context.Context, tenant string, c engine.Caller, req sp.PushRequest) (sp.PushResponse, error) {
	res, err := g.engineFor(tenant).Ingest(ctx, engine.IngestReq{Items: req.Items, Seals: req.Seals, Endorsements: req.Endorsements, Attestations: req.Attestations, Caller: c})
	if err != nil {
		return sp.PushResponse{}, err
	}
	if len(res.New) > 0 {
		g.poker(tenant).bump()
	}
	return sp.PushResponse{Epoch: g.Epoch(), Vector: res.Vector, Held: res.Held, Refused: res.Refused}, nil
}

// Pull serves the caller's missing slots (S5, A1.2).
func (g *Gateway) Pull(ctx context.Context, tenant string, c engine.Caller, req sp.PullRequest) (sp.PullResponse, error) {
	e := g.engineFor(tenant)
	vec, err := e.Vector(ctx)
	if err != nil {
		return sp.PullResponse{}, err
	}
	var all []string
	seen := map[string]bool{}
	for k := range vec {
		_, s, _ := sp.SplitVKey(k)
		if !seen[s] {
			seen[s] = true
			all = append(all, s)
		}
	}
	resp, err := e.Serve(ctx, req, engine.ServeOpts{Caller: c, Streams: allowedStreams(c, tenant, all), IsHub: c.Kind == sp.KindHub,
		Recoverers: func(origin string) []sp.CredentialEnvelope {
			return tenantTrust{tenant: tenant, dir: g.cfg.Dir, g: g}.Recoverers(origin)
		}},
		func(origin string) (sp.CredentialEnvelope, bool) { return g.cfg.Dir.Credential(tenant, origin) })
	resp.Epoch = g.Epoch()
	return resp, err
}

// Snapshot materialises the tenant's accepted ops visible to the caller, for bootstrap.
func (g *Gateway) Snapshot(ctx context.Context, tenant string, c engine.Caller) (sp.Snapshot, error) {
	st := engine.NewState()
	snap := sp.Snapshot{Vector: sp.Vector{}, Epoch: g.Epoch()}
	err := g.cfg.Store.InTx(ctx, tenant, func(tx repository.Tx) error {
		var after int64
		for {
			page, err := tx.ByArrival(after, 2000)
			if err != nil || len(page) == 0 {
				return err
			}
			after = page[len(page)-1].Arr
			for _, r := range page {
				if !streamAllowed(c, tenant, r.Stream) {
					continue
				}
				snap.Vector[sp.VKey(r.Origin, r.Stream)] = max(snap.Vector[sp.VKey(r.Origin, r.Stream)], r.Seq)
				if r.Body == "" || (r.Status != repository.StAccepted && r.Status != repository.StFlagged) {
					continue
				}
				b, err := sp.DecodeBody(r.Body)
				if err != nil {
					continue
				}
				h, _ := sp.ParseHLC(b.HLC)
				st.ApplyPII(sp.Ref{Origin: b.Origin, Stream: b.Stream, Seq: b.Seq}, h, b.Muts, b.PIIC)
				if b.Intent == sp.IntentVoid {
					for _, m := range b.Muts {
						if m.E == "sync_void" {
							o, _ := m.F["origin"].(string)
							s, _ := m.F["stream"].(string)
							q, _ := m.F["seq"].(int64)
							st.Void(sp.Ref{Origin: o, Stream: s, Seq: q})
							snap.Voids = append(snap.Voids, sp.Ref{Origin: o, Stream: s, Seq: q})
						}
					}
				}
			}
		}
	})
	snap.Rows = st.Snapshot()
	if err == nil {
		err = g.cfg.Store.InTx(ctx, tenant, func(tx repository.Tx) error {
			return engine.AttachSnapshotPII(tx, snap.Rows, c, g.cfg.PIIToUnprotected)
		})
	}
	return snap, err
}

// RecordCloudOp records a cloud-origin op without the registry checks of Emit (tests, the simulator
// and the key-rotation drills): origin cloud-<epoch>, sealed by the gateway. Services never call it;
// they use POST /internal/v1/emit.
func (g *Gateway) RecordCloudOp(ctx context.Context, tenant, stream, intent string, muts []sp.Mut) (sp.Item, error) {
	e := g.engineFor(tenant)
	var it sp.Item
	err := g.cfg.Store.InTx(ctx, tenant, func(tx repository.Tx) error {
		var err error
		it, err = e.RecordAndSealTx(tx, engine.Input{Stream: stream, Intent: intent, Muts: muts})
		if err != nil {
			return err
		}
		rec, _, _ := tx.GetOp(stream, it.Origin, it.Seq)
		return g.publish(tx, rec)
	})
	if err == nil {
		g.poker(tenant).bump()
	}
	return it, err
}

// EngineFor exposes the tenant engine to tests and the simulator (vectors, op log reads).
func (g *Gateway) EngineFor(tenant string) *engine.Engine { return g.engineFor(tenant) }

// ErrNotFound is returned for a slot the tenant does not hold (also for another tenant's).
var ErrNotFound = errors.New("service: not found")

func (g *Gateway) alert(tx repository.Tx, aud, sev, kind string, rec repository.OpRec) error {
	return tx.AddAlert(aud, sev, kind, fmt.Sprintf("%s/%s/%d", rec.Origin, rec.Stream, rec.Seq))
}

// answerUnbound answers a node's list of slots taken by hash with the cloud's own hash for each, and
// raises a vendor alert for every chain conflict the node reports (A2.8 items 1.3 and 1.4). Only
// slots of streams the caller may read are answered or alerted.
func (g *Gateway) answerUnbound(ctx context.Context, tenant string, c engine.Caller, req sp.HelloRequest) ([]sp.SlotHash, error) {
	if len(req.Unbound) == 0 && len(req.Conflicts) == 0 {
		return nil, nil
	}
	var out []sp.SlotHash
	err := g.cfg.Store.InTx(ctx, tenant, func(tx repository.Tx) error {
		out = out[:0]
		for i, u := range req.Unbound {
			if i >= 500 || !streamAllowed(c, tenant, u.Stream) {
				continue
			}
			rec, ok, err := tx.GetOp(u.Stream, u.Origin, u.Seq)
			if err != nil {
				return err
			}
			if ok {
				out = append(out, sp.SlotHash{Origin: rec.Origin, Stream: rec.Stream, Seq: rec.Seq, H: rec.H})
			}
		}
		for i, cf := range req.Conflicts {
			if i >= 100 || !streamAllowed(c, tenant, cf.Stream) {
				continue
			}
			key := fmt.Sprintf("%s/%s/%d", cf.Origin, cf.Stream, cf.Seq)
			if _, done, err := tx.GetMeta("chain-conflict-alerted:" + key); err != nil {
				return err
			} else if done {
				continue
			}
			if err := tx.AddAlert("vendor", "high", "chain_conflict", key); err != nil {
				return err
			}
			if err := tx.SetMeta("chain-conflict-alerted:"+key, "1"); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}
