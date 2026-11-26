package hub

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"time"

	sp "github.com/hostryhq/svc-sync/syncproto"
)

// ErrHubProof is returned when the answering hub cannot prove it is the outlet's hub over the channel that carried the answer.
var ErrHubProof = errors.New("hub: the hub could not be proven; connection refused")

// LANClient is the device side of the LAN handshake in Go (the simulator, the soak and Node-free tests; client-core has its own).
// It sends nothing but helloLan until the hub is proven, then puts the session token on every request and, on 401
// lan_session_expired, runs the handshake again and repeats the request once.
type LANClient struct {
	// CredJWS is the device's own LAN credential, and Key its device key.
	CredJWS                  string
	Key                      *sp.KeyPair
	DeviceID, Tenant, Outlet string
	// Identity returns the identity keys of the device's own pack (current, next).
	Identity func() []*ecdsa.PublicKey
	// Revoked reports whether the device's own pack lists a hub id as revoked.
	Revoked func(device string) bool
	Now     func() time.Time
	// Next carries the requests. Use NewLANTransport for real TLS; the simulator passes its in-memory network.
	Next http.RoundTripper
	// SPKISeen overrides the measurement of the certificate key hash for a transport that is not TLS (the simulator).
	SPKISeen func() string

	mu       sync.Mutex
	token    string
	exp      time.Time
	proven   atomic.Value // string: the spki of the proven hub
	handshak atomic.Bool
	pin      atomic.Value // string: the spki of the step 1 connection, held while step 2 runs (P2R-L1)
}

// NewLANTransport is the HTTP transport of a device that talks TLS 1.3 to a hub: it accepts any certificate, because the
// handshake proves the hub afterwards, and once a hub is proven it refuses a connection whose certificate key differs.
func NewLANTransport(c *LANClient) *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, //nolint:gosec // trust comes from the hello proofs bound to the key hash (A3.1 item 3)
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return ErrHubProof
				}
				want, _ := c.proven.Load().(string)
				if c.handshak.Load() {
					want, _ = c.pin.Load().(string) // empty during step 1: that connection is what the proofs bind
				}
				if want != "" && sp.SPKIOf(cs.PeerCertificates[0]) != want {
					return ErrHubProof
				}
				return nil
			},
		},
		MaxIdleConnsPerHost: 4,
	}
}

func (c *LANClient) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// RoundTripper returns the transport to put in an http.Client for the hub.
func (c *LANClient) RoundTripper() http.RoundTripper { return lanRT{c} }

// Forget drops the session (a device that learns its hub restarted).
func (c *LANClient) Forget() {
	c.mu.Lock()
	c.token, c.exp = "", time.Time{}
	c.mu.Unlock()
	c.proven.Store("")
}

type lanRT struct{ c *LANClient }

func (t lanRT) RoundTrip(req *http.Request) (*http.Response, error) {
	c := t.c
	var body []byte
	if req.Body != nil {
		var err error
		if body, err = io.ReadAll(req.Body); err != nil {
			return nil, err
		}
		_ = req.Body.Close()
	}
	for attempt := 0; ; attempt++ {
		tok, err := c.ensure(req)
		if err != nil {
			return nil, err
		}
		r2 := req.Clone(req.Context())
		r2.Body = io.NopCloser(bytes.NewReader(body))
		r2.ContentLength = int64(len(body))
		r2.Header.Set(sp.HeaderLanSession, tok)
		resp, err := c.Next.RoundTrip(r2)
		if err != nil {
			c.Forget() // a connection that failed may be a different hub next time: prove again
			if attempt == 0 && errors.Is(err, ErrHubProof) && tok != "" {
				continue // the hub's key changed (a restart): the handshake runs again, hello first
			}
			return nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 && isSessionExpired(resp) {
			c.Forget()
			continue
		}
		return resp, nil
	}
}

func isSessionExpired(resp *http.Response) bool {
	b, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(b))
	var p struct{ Code string }
	return err == nil && json.Unmarshal(b, &p) == nil && p.Code == sp.CodeLanSessionExpired
}

func (c *LANClient) ensure(req *http.Request) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.now().Before(c.exp) {
		return c.token, nil
	}
	tok, err := c.handshake(req)
	if err != nil {
		return "", err
	}
	return tok, nil
}

func (c *LANClient) post(ctx context.Context, base *http.Request, path string, in any) (*http.Response, []byte, string, error) {
	raw, err := json.Marshal(in)
	if err != nil {
		return nil, nil, "", err
	}
	u := *base.URL
	u.Path, u.RawQuery = path, ""
	var seen string
	trace := &httptrace.ClientTrace{GotConn: func(gi httptrace.GotConnInfo) {
		if tc, ok := gi.Conn.(*tls.Conn); ok {
			if st := tc.ConnectionState(); len(st.PeerCertificates) > 0 {
				seen = sp.SPKIOf(st.PeerCertificates[0])
			}
		}
	}}
	r, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodPost, u.String(), bytes.NewReader(raw))
	if err != nil {
		return nil, nil, "", err
	}
	r.Header.Set("Content-Type", "application/json")
	r.Close = true // the handshake runs on a connection of its own, so the spki seen is the one that carried it
	resp, err := c.Next.RoundTrip(r)
	if err != nil {
		return nil, nil, "", err
	}
	b, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, b, seen, err
}

func (c *LANClient) handshake(base *http.Request) (string, error) {
	c.handshak.Store(true)
	c.pin.Store("")
	defer func() { c.handshak.Store(false); c.pin.Store("") }()
	ctx := base.Context()
	nonceD, err := sp.NewNonce()
	if err != nil {
		return "", err
	}
	resp, b, seen, err := c.post(ctx, base, "/sync/v1/lan/hello", sp.LanHelloRequest{Credential: c.CredJWS, NonceD: nonceD})
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("hub: helloLan refused (%d)", resp.StatusCode)
	}
	var hello sp.LanHelloResponse
	if json.Unmarshal(b, &hello) != nil || !sp.ValidNonce(hello.NonceH) {
		return "", ErrHubProof
	}
	step1 := seen // the key the connection of step 1 really showed
	if c.SPKISeen != nil {
		seen = c.SPKISeen()
	}
	hub, err := sp.VerifyCredentialJWS(c.Identity(), hello.Credential)
	if err != nil || hub.Kind != sp.KindHub || hub.TenantID != c.Tenant || hub.OutletID != c.Outlet || c.now().Unix() > hub.NotAfter || (c.Revoked != nil && c.Revoked(hub.DeviceID)) {
		return "", ErrHubProof
	}
	hubPub, err := hub.PubKey()
	if err != nil || !sp.VerifySig(hubPub, sp.LanProofMessage(sp.LanTagHub, nonceD, hello.NonceH, c.DeviceID, hub.DeviceID, seen), hello.HubProof) {
		return "", ErrHubProof
	}
	proof, err := c.Key.Sign(sp.LanProofMessage(sp.LanTagDevice, nonceD, hello.NonceH, c.DeviceID, hub.DeviceID, seen))
	if err != nil {
		return "", err
	}
	c.pin.Store(step1) // step 2 must reach the same key: a relay on that connection alone would otherwise get the proof and the token
	resp, b, _, err = c.post(ctx, base, "/sync/v1/lan/session", sp.LanSessionRequest{NonceD: nonceD, NonceH: hello.NonceH, DeviceProof: proof})
	if err != nil {
		return "", err
	}
	var s sp.LanSession
	if resp.StatusCode != http.StatusOK || json.Unmarshal(b, &s) != nil || !sp.ValidNonce(s.Token) {
		return "", fmt.Errorf("hub: openLanSession refused (%d)", resp.StatusCode)
	}
	c.token, c.exp = s.Token, c.now().Add(time.Duration(s.ExpiresIn)*time.Second)
	c.proven.Store(seen)
	return c.token, nil
}
