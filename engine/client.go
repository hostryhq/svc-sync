package engine

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// Transport is the upstream as seen by a node: the same three calls whether the upstream is a
// hub or the cloud (S10).
type Transport interface {
	Hello(ctx context.Context, r sp.HelloRequest) (sp.HelloResponse, error)
	Push(ctx context.Context, r sp.PushRequest) (sp.PushResponse, error)
	Pull(ctx context.Context, r sp.PullRequest) (sp.PullResponse, error)
}

// Client runs the node side of sync against one upstream.
type Client struct {
	E       *Engine
	T       Transport
	Cache   *CredCache
	Streams []string
	// IsHub: relay every origin upstream and report held slots to peers.
	IsHub bool
	// UpstreamIsCloud selects re-offer behaviour for devices (S16 item 4).
	UpstreamIsCloud bool

	// Held state last learned from upstream (A1.2).
	OwnHeld   []sp.HeldSlot
	RelayHeld []sp.HeldSlot
	// ClockWrong is set when upstream time differs by more than 2 minutes (S5).
	ClockWrong bool
	// Upstream is the last vector the upstream reported (delivery state at_hub / in_cloud).
	Upstream sp.Vector
	// Epoch is the cloud epoch last synced under.
	Epoch string
	// LastRefused is what the upstream refused in the last round (diagnostics and status).
	LastRefused []sp.Refusal
}

// SyncResult summarises one round.
type SyncResult struct {
	Pushed, Pulled, Refused int
	EpochChanged            bool
}

// Persisted re-offer state (A2.2): metaEpoch is the newest cloud epoch heard from any upstream,
// metaReoffered the epoch for which this node last finished re-offering. The re-offer is open while
// they differ. A hub's word may open it; only a direct cloud hello may close it.
const metaEpoch, metaReoffered = "epoch", "reoffered_epoch"

// SyncOnce does hello, push until the upstream has everything offerable, then pull until caught
// up. Every step is idempotent; an error leaves the node ready to run it again.
func (c *Client) SyncOnce(ctx context.Context) (SyncResult, error) {
	var res SyncResult
	cfg := c.E.Config()
	vec, err := c.E.Vector(ctx)
	if err != nil {
		return res, err
	}
	var lastEpoch, reoffered string
	_ = cfg.Store.InTx(ctx, cfg.Tenant, func(tx repository.Tx) error {
		lastEpoch, _, _ = tx.GetMeta(metaEpoch)
		reoffered, _, _ = tx.GetMeta(metaReoffered)
		return nil
	})
	sent := cfg.Clock.Time()
	hreq := sp.HelloRequest{Protocol: sp.ProtocolVersion, Vector: vec, Epoch: lastEpoch}
	if c.UpstreamIsCloud {
		// Only the cloud can check a slot taken by hash and only it takes a conflict report (A2.8 item 1.3, 1.4).
		if hreq.Unbound, err = c.E.UnboundSlots(ctx); err != nil {
			return res, err
		}
		if hreq.Conflicts, err = c.E.Conflicts(ctx, true); err != nil {
			return res, err
		}
	}
	if c.UpstreamIsCloud {
		// Acknowledge the erasures applied since the last direct cloud contact (syncproto/piic.go).
		if hreq.PIIErased, err = c.E.PendingErasureAcks(ctx); err != nil {
			return res, err
		}
	}
	hello, err := c.T.Hello(ctx, hreq)
	if err != nil {
		return res, err
	}
	if len(hreq.PIIErased) > 0 {
		if err := c.E.ClearErasureAcks(ctx, hreq.PIIErased); err != nil {
			return res, err
		}
	}
	if c.UpstreamIsCloud {
		if err := c.E.NoteCloudHello(ctx); err != nil {
			return res, err
		}
		if err := c.E.ResolveUnbound(ctx, hello.UnboundH); err != nil {
			return res, err
		}
		if len(hreq.Conflicts) > 0 {
			if err := c.E.markReported(ctx); err != nil {
				return res, err
			}
		}
	}
	if hello.Time != "" {
		if ut, err := time.Parse(time.RFC3339Nano, hello.Time); err == nil {
			skew := ut.Sub(sent)
			c.ClockWrong = skew > 2*time.Minute || skew < -2*time.Minute
			cfg.Clock.SetOffset(cfg.Clock.Offset() + skew)
		}
	}
	// A hub reporting the epoch this node already finished re-offering for is stale, not news: a
	// hub's word never closes a re-offer, and never reopens a closed one with an old epoch.
	if hello.Epoch != "" && hello.Epoch != lastEpoch && (c.UpstreamIsCloud || hello.Epoch != reoffered) {
		if lastEpoch != "" {
			res.EpochChanged = true
		}
		first := reoffered == "" && lastEpoch == ""
		_ = cfg.Store.InTx(ctx, cfg.Tenant, func(tx repository.Tx) error {
			if err := tx.SetMeta(metaEpoch, hello.Epoch); err != nil {
				return err
			}
			if first {
				return tx.SetMeta(metaReoffered, hello.Epoch) // a new store has nothing to re-offer
			}
			return nil
		})
		lastEpoch = hello.Epoch
		if first {
			reoffered = hello.Epoch
		}
	}
	c.Epoch = lastEpoch
	open := lastEpoch != "" && reoffered != lastEpoch
	up := hello.Vector
	if up == nil {
		up = sp.Vector{}
	}
	others := c.IsHub || (c.UpstreamIsCloud && open)
	refused := map[string]bool{}
	// Push.
	for round := 0; round < 200; round++ {
		req, err := c.E.Outbound(ctx, up, OutboundOpts{Others: others, Streams: c.Streams, Reoffer: open && c.UpstreamIsCloud && round == 0})
		if err != nil {
			return res, err
		}
		if len(req.Items) == 0 {
			break
		}
		pr, err := c.T.Push(ctx, req)
		if err != nil {
			return res, err
		}
		progress := false
		for k, s := range pr.Vector {
			if s > up[k] {
				up[k] = s
				progress = true
			}
		}
		res.Pushed += len(req.Items)
		res.Refused += len(pr.Refused)
		c.LastRefused = pr.Refused
		for _, rf := range pr.Refused {
			refused[endKey(rf.Origin, rf.Stream, rf.Seq)] = true
		}
		if !progress {
			break
		}
	}
	// Only a direct cloud hello under the newest epoch, with nothing left to push, closes the
	// re-offer. An op the cloud refused (and refuses again on every push) is not "left to push":
	// otherwise one refused op would keep the re-offer open for ever.
	if c.UpstreamIsCloud && open && hello.Epoch == lastEpoch {
		req, _ := c.E.Outbound(ctx, up, OutboundOpts{Others: true, Streams: c.Streams})
		left := 0
		for _, it := range req.Items {
			if !refused[endKey(it.Origin, it.Stream, it.Seq)] {
				left++
			}
		}
		if left == 0 {
			_ = cfg.Store.InTx(ctx, cfg.Tenant, func(tx repository.Tx) error { return tx.SetMeta(metaReoffered, lastEpoch) })
		}
	}
	c.Upstream = up
	// Pull.
	for round := 0; round < 400; round++ {
		vec, err = c.E.Vector(ctx)
		if err != nil {
			return res, err
		}
		pl, err := c.placeholders(ctx)
		if err != nil {
			return res, err
		}
		stale, err := c.E.StaleSeals(ctx, 200)
		if err != nil {
			return res, err
		}
		pr, err := c.T.Pull(ctx, sp.PullRequest{Vector: vec, Streams: c.Streams, Placeholders: pl, StaleSeals: stale})
		if err != nil {
			return res, err
		}
		if _, err := c.E.RefreshSeals(ctx, pr.SealRefresh); err != nil {
			return res, err
		}
		c.OwnHeld, c.RelayHeld = pr.OwnHeld, pr.RelayHeld
		for _, cr := range pr.Creds {
			if c.Cache != nil {
				_ = c.Cache.Add(cr)
			}
		}
		if len(pr.Items) == 0 {
			break
		}
		ir, err := c.E.Ingest(ctx, IngestReq{Items: pr.Items, Seals: pr.Seals, Endorsements: pr.Endorsements, Attestations: pr.Attestations, FromUpstream: true, FromCloud: c.UpstreamIsCloud, Caller: Caller{ID: "upstream"}})
		if err != nil {
			return res, err
		}
		res.Pulled += len(ir.New)
		if len(ir.New) == 0 && !pr.More {
			break
		}
		if len(ir.New) == 0 && len(ir.Refused) > 0 {
			break
		}
	}
	return res, nil
}

// ReofferPending reports whether the cloud epoch changed and this node has not yet finished
// re-offering what the cloud may have lost (S16 item 4). A device whose upstream is the hub must then
// also sync with the cloud directly: a hub may hold only a placeholder for a slot whose body the
// restored cloud lost, and then the origin is the only node that can deliver it.
func (c *Client) ReofferPending(ctx context.Context) bool {
	cfg := c.E.Config()
	var epoch, done string
	_ = cfg.Store.InTx(ctx, cfg.Tenant, func(tx repository.Tx) error {
		epoch, _, _ = tx.GetMeta(metaEpoch)
		done, _, _ = tx.GetMeta(metaReoffered)
		return nil
	})
	return epoch != "" && epoch != done
}

func (c *Client) placeholders(ctx context.Context) ([]sp.Ref, error) {
	cfg := c.E.Config()
	var out []sp.Ref
	err := cfg.Store.InTx(ctx, cfg.Tenant, func(tx repository.Tx) error {
		recs, err := tx.ByStatus(repository.StPlaceholder)
		if err != nil {
			return err
		}
		for _, r := range recs {
			out = append(out, sp.Ref{Origin: r.Origin, Stream: r.Stream, Seq: r.Seq})
			if len(out) >= 200 {
				break
			}
		}
		// Ops whose pii values this node lacks (pii_incomplete, ADR-0014 A3.1 item 4): any upstream may complete them.
		more, err := c.E.IncompletePII(tx, 200-len(out))
		if err != nil {
			return err
		}
		out = append(out, more...)
		// Endorsements signed by a key this node no longer accepts (rotation, A2.1 item 6): ask
		// for the op again, the answer carries the re-issued endorsement.
		if c.Cache != nil {
			ends, err := tx.Endorsements()
			if err != nil {
				return err
			}
			for _, en := range ends {
				if _, ok := c.Cache.OpKey(en.Kid); !ok && len(out) < 200 {
					out = append(out, sp.Ref{Origin: en.Origin, Stream: en.Stream, Seq: en.Seq})
				}
			}
		}
		return nil
	})
	return out, err
}

// Pending counts own ops the upstream has not confirmed (the pending-operation count of invariant 9).
func (c *Client) Pending(ctx context.Context) (int64, error) {
	cfg := c.E.Config()
	vec, err := c.E.Vector(ctx)
	if err != nil {
		return 0, err
	}
	var n int64
	for k, s := range vec {
		o, _, _ := sp.SplitVKey(k)
		if o == cfg.Origin && s > c.Upstream[k] {
			n += s - c.Upstream[k]
		}
	}
	return n, nil
}

// HTTPTransport speaks the wire protocol over HTTP.
type HTTPTransport struct {
	Base   string
	Client *http.Client
	// Authorize adds credentials to a request (bearer token for the cloud, device assertion on the LAN).
	Authorize func(req *http.Request, body []byte) error
	// VerifyResponse authenticates the answer (the hub's proof on the LAN).
	VerifyResponse func(req *http.Request, resp *http.Response, body []byte) error
}

func (t *HTTPTransport) do(ctx context.Context, method, path string, in, out any) error {
	var body []byte
	var err error
	if in != nil {
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	wire := body
	gz := false
	if len(body) > 1024 {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		_, _ = w.Write(body)
		_ = w.Close()
		wire, gz = buf.Bytes(), true
	}
	var rdr io.Reader
	if wire != nil {
		rdr = bytes.NewReader(wire)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(t.Base, "/")+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if gz {
		req.Header.Set("Content-Encoding", "gzip")
	}
	if t.Authorize != nil {
		// Credentials cover the bytes on the wire (compressed when compressed).
		if err := t.Authorize(req, wire); err != nil {
			return err
		}
	}
	cl := t.Client
	if cl == nil {
		cl = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return &StatusError{Code: resp.StatusCode, Body: string(rb)}
	}
	if t.VerifyResponse != nil {
		if err := t.VerifyResponse(req, resp, rb); err != nil {
			return err
		}
	}
	return json.Unmarshal(rb, out)
}

// StatusError is a non-2xx answer.
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string { return fmt.Sprintf("sync: upstream answered %d", e.Code) }

// IsStatus reports whether err is a StatusError with the code.
func IsStatus(err error, code int) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == code
}

// Hello implements Transport.
func (t *HTTPTransport) Hello(ctx context.Context, r sp.HelloRequest) (out sp.HelloResponse, err error) {
	err = t.do(ctx, http.MethodPost, "/sync/v1/hello", r, &out)
	return
}

// Push implements Transport.
func (t *HTTPTransport) Push(ctx context.Context, r sp.PushRequest) (out sp.PushResponse, err error) {
	err = t.do(ctx, http.MethodPost, "/sync/v1/push", r, &out)
	return
}

// Pull implements Transport.
func (t *HTTPTransport) Pull(ctx context.Context, r sp.PullRequest) (out sp.PullResponse, err error) {
	err = t.do(ctx, http.MethodPost, "/sync/v1/pull", r, &out)
	return
}

// QuarantineUpload posts a drain or recovery upload.
func (t *HTTPTransport) QuarantineUpload(ctx context.Context, r sp.PushRequest) (out sp.PushResponse, err error) {
	err = t.do(ctx, http.MethodPost, "/sync/v1/quarantine-upload", r, &out)
	return
}
