// Package sim is the deterministic simulator of ADR-0002 S15: N devices, a hub and the cloud
// gateway in one process, talking real wire protocol through an in-memory network that injects
// partitions, lost requests, lost responses (the server processed the call), duplicates and
// stale replays. All time is a fake clock and all randomness is seeded, so a failing seed
// reproduces exactly. After a scenario the harness quiesces and asserts convergence and the
// verdict rules.
package sim

import (
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"sync"
)

// ErrNet is every injected network failure.
var ErrNet = errors.New("sim: network failure")

// Link is one directed path from a node to another node's handler.
type Link struct {
	Down bool
	// Loss, LostAck, Dup and Replay are probabilities per call.
	Loss, LostAck, Dup, Replay float64
}

// Net routes calls to handlers and injects faults from a seeded generator.
type Net struct {
	mu    sync.Mutex
	rng   *rand.Rand
	links map[string]*Link
	// stash holds a request to replay later (reordering and duplication across calls).
	stash map[string]*stashed
	Stats NetStats
}

// NetStats counts injected faults, for the report.
type NetStats struct{ Calls, Lost, LostAck, Dups, Replays, Down int }

type stashed struct {
	method, url string
	hdr         http.Header
	body        []byte
}

// NewNet makes a network.
func NewNet(rng *rand.Rand) *Net {
	return &Net{rng: rng, links: map[string]*Link{}, stash: map[string]*stashed{}}
}

// Link returns (creating) the link named name.
func (n *Net) Link(name string) *Link {
	n.mu.Lock()
	defer n.mu.Unlock()
	l := n.links[name]
	if l == nil {
		l = &Link{}
		n.links[name] = l
	}
	return l
}

// Faults sets the fault probabilities on a link.
func (n *Net) Faults(name string, loss, lostAck, dup, replay float64) {
	l := n.Link(name)
	n.mu.Lock()
	l.Loss, l.LostAck, l.Dup, l.Replay = loss, lostAck, dup, replay
	n.mu.Unlock()
}

// SetDown cuts or restores a link.
func (n *Net) SetDown(name string, down bool) {
	l := n.Link(name)
	n.mu.Lock()
	l.Down = down
	n.mu.Unlock()
}

// IsDown reports a cut link.
func (n *Net) IsDown(name string) bool {
	l := n.Link(name)
	n.mu.Lock()
	defer n.mu.Unlock()
	return l.Down
}

func (n *Net) roll(p float64) bool {
	if p <= 0 {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.rng.Float64() < p
}

// RoundTripper is a client transport over the named link to handler.
func (n *Net) RoundTripper(link string, h http.Handler) http.RoundTripper {
	return &rt{n: n, link: link, h: h}
}

type rt struct {
	n    *Net
	link string
	h    http.Handler
}

func serve(h http.Handler, method, url string, hdr http.Header, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, url, bytes.NewReader(body))
	for k, v := range hdr {
		req.Header[k] = v
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func (t *rt) RoundTrip(req *http.Request) (*http.Response, error) {
	n := t.n
	l := n.Link(t.link)
	n.mu.Lock()
	n.Stats.Calls++
	down := l.Down
	loss, lostAck, dup, replay := l.Loss, l.LostAck, l.Dup, l.Replay
	n.mu.Unlock()
	if down {
		n.mu.Lock()
		n.Stats.Down++
		n.mu.Unlock()
		return nil, ErrNet
	}
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		_ = req.Body.Close()
	}
	if n.roll(loss) {
		n.mu.Lock()
		n.Stats.Lost++
		n.mu.Unlock()
		return nil, ErrNet
	}
	// A stale request from an earlier call arrives first (replay and reordering).
	n.mu.Lock()
	old := n.stash[t.link]
	delete(n.stash, t.link)
	n.mu.Unlock()
	if old != nil {
		serve(t.h, old.method, old.url, old.hdr, old.body)
		n.mu.Lock()
		n.Stats.Replays++
		n.mu.Unlock()
	}
	if n.roll(replay) {
		n.mu.Lock()
		n.stash[t.link] = &stashed{req.Method, req.URL.String(), req.Header.Clone(), body}
		n.mu.Unlock()
	}
	rec := serve(t.h, req.Method, req.URL.String(), req.Header, body)
	if n.roll(dup) {
		serve(t.h, req.Method, req.URL.String(), req.Header, body)
		n.mu.Lock()
		n.Stats.Dups++
		n.mu.Unlock()
	}
	if n.roll(lostAck) {
		n.mu.Lock()
		n.Stats.LostAck++
		n.mu.Unlock()
		return nil, ErrNet // the server processed the call; the client never learns
	}
	res := rec.Result()
	return res, nil
}
