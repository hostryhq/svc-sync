// Package identityclient is the sync gateway's client of the identity service. It wraps the generated
// client of the internal routes of the identity contract that name `sync` as caller
// (api-specs openapi/identity/v1, x-service-callers: sync; internal/gen is never edited) and adds what the
// go-service standard requires of every outbound call: a short-lived service token naming the tenant acted
// for (go-auth ServiceSigner), a timeout on every attempt, and one bounded retry with jitter on a transport
// failure or a 502, 503 or 504, always with the same Idempotency-Key so a retry never repeats an effect.
//
// Directory (directory.go) adapts the client to the gateway's directory interface; see its comment for what
// identity does not answer yet.
package identityclient

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-common/ids"
	identity "github.com/hostryhq/svc-sync/identityclient/gen"
)

// Audience is the service name tokens are minted for.
const Audience = "identity"

// ErrUnavailable means identity could not be reached or answered with a server error. The gateway treats it
// as "not known": a verdict that needs identity waits (pending), it never guesses.
var ErrUnavailable = errors.New("identityclient: identity is unavailable")

// ErrRefused means identity refused the service token or the call (401, 403) or found no such device (404).
var ErrRefused = errors.New("identityclient: identity refused the call")

// Client calls the internal routes of identity that the gateway uses.
type Client struct {
	c      *identity.ClientWithResponses
	signer *auth.ServiceSigner
	// Timeout bounds one attempt (default 5s).
	Timeout time.Duration
	// Sleep waits between attempts; tests replace it so no test sleeps.
	Sleep func(ctx context.Context, d time.Duration)
}

// New builds a client for the identity service at baseURL. hc may be nil (http.DefaultClient).
func New(baseURL string, signer *auth.ServiceSigner, hc *http.Client) (*Client, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	if signer == nil {
		return nil, errors.New("identityclient: a service signer is required")
	}
	c, err := identity.NewClientWithResponses(strings.TrimRight(baseURL, "/"), identity.WithHTTPClient(hc))
	if err != nil {
		return nil, err
	}
	return &Client{c: c, signer: signer, Timeout: 5 * time.Second, Sleep: sleep}, nil
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

func retryable(status int) bool {
	return status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

// attempt runs call up to twice with a fresh service token each time; call returns the HTTP status.
func (c *Client) attempt(ctx context.Context, tenant string, call func(ctx context.Context, edit identity.RequestEditorFn) (int, error)) (int, error) {
	var status int
	var err error
	for try := 0; try < 2; try++ {
		status, err = c.once(ctx, tenant, call)
		if err == nil && !retryable(status) {
			return status, nil
		}
		if try == 0 {
			c.Sleep(ctx, time.Duration(50+rand.IntN(100))*time.Millisecond)
			if ctx.Err() != nil {
				break
			}
		}
	}
	return status, ErrUnavailable
}

func (c *Client) once(ctx context.Context, tenant string, call func(ctx context.Context, edit identity.RequestEditorFn) (int, error)) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	tok, err := c.signer.Sign(Audience, tenant)
	if err != nil {
		return 0, err
	}
	return call(ctx, func(_ context.Context, r *http.Request) error {
		r.Header.Set(auth.ServiceTokenHeader, tok)
		return nil
	})
}

func refusal(status int) error {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return ErrRefused
	}
	return fmt.Errorf("%w (status %d)", ErrUnavailable, status)
}

// ProofCheck is one question to verifyProof (ADR-0005 section 7): a session proof, or an approval proof when
// ActionHash is set.
type ProofCheck struct {
	DeviceID, MemberID, SessionID string
	PackV, PinV                   int
	OpenedAt                      time.Time
	Proof, ActionHash             string
}

// Verdict is identity's answer about a proof. Locked is answered without a check and for every kind of op.
type Verdict struct {
	Valid, Locked bool
	Label         string
}

// VerifyProof asks identity whether a proof verifies. The idempotency key is derived from the question, so a
// retried call is a replay.
func (c *Client) VerifyProof(ctx context.Context, tenant string, in ProofCheck) (Verdict, error) {
	body := identity.ProofVerification{Kind: identity.ProofVerificationKindSession, DeviceId: in.DeviceID, MemberId: in.MemberID,
		PackV: in.PackV, PinV: in.PinV, Proof: in.Proof}
	if in.ActionHash != "" {
		body.Kind = identity.ProofVerificationKindApproval
		body.ActionHash = &in.ActionHash
	}
	if in.SessionID != "" {
		body.SessionId = &in.SessionID
	}
	if !in.OpenedAt.IsZero() {
		t := in.OpenedAt.UTC()
		body.OpenedAt = &t
	}
	idem := newKey()
	var out *identity.VerifyProofResponse
	status, err := c.attempt(ctx, tenant, func(ctx context.Context, edit identity.RequestEditorFn) (int, error) {
		r, err := c.c.VerifyProofWithResponse(ctx, &identity.VerifyProofParams{IdempotencyKey: idem}, body, edit)
		if err != nil {
			return 0, err
		}
		out = r
		return r.StatusCode(), nil
	})
	if err != nil {
		return Verdict{}, err
	}
	if status != http.StatusOK || out.JSON200 == nil {
		return Verdict{}, refusal(status)
	}
	v := Verdict{Valid: out.JSON200.Valid, Label: string(out.JSON200.Label)}
	if out.JSON200.Locked != nil {
		v.Locked = *out.JSON200.Locked
	}
	return v, nil
}

// PackHistory is identity's answer about what a pack held (ADR-0005 section 7), judged against the pack the
// device held, not against today.
type PackHistory struct {
	PackKnown, MemberInPack, SeriesIssued bool
}

// CheckPackHistory asks whether a member or a series code was issued to the device in pack packV.
func (c *Client) CheckPackHistory(ctx context.Context, tenant, device string, packV int, member, seriesCode string) (PackHistory, error) {
	body := identity.PackHistoryCheck{DeviceId: device, PackV: packV}
	if member != "" {
		body.MemberId = &member
	}
	if seriesCode != "" {
		body.SeriesCode = &seriesCode
	}
	idem := newKey()
	var out *identity.CheckPackHistoryResponse
	status, err := c.attempt(ctx, tenant, func(ctx context.Context, edit identity.RequestEditorFn) (int, error) {
		r, err := c.c.CheckPackHistoryWithResponse(ctx, &identity.CheckPackHistoryParams{IdempotencyKey: idem}, body, edit)
		if err != nil {
			return 0, err
		}
		out = r
		return r.StatusCode(), nil
	})
	if err != nil {
		return PackHistory{}, err
	}
	if status != http.StatusOK || out.JSON200 == nil {
		return PackHistory{}, refusal(status)
	}
	return PackHistory{PackKnown: out.JSON200.PackKnown, MemberInPack: out.JSON200.MemberInPack, SeriesIssued: out.JSON200.SeriesIssued}, nil
}

// Revocation is one entry of the revocation feed (tenant-id-only, no personal data).
type Revocation struct {
	ID, Subject, Tenant string
	Device              bool // subject_type device; otherwise a session
	At                  time.Time
}

// Revocations reads one page of the revocation feed after cursor. The feed is platform-wide, so the service
// token names no tenant.
func (c *Client) Revocations(ctx context.Context, cursor string) (items []Revocation, next string, err error) {
	params := &identity.ListRevocationsParams{}
	if cursor != "" {
		cur := identity.Cursor(cursor)
		params.Cursor = &cur
	}
	var out *identity.ListRevocationsResponse
	status, err := c.attempt(ctx, "", func(ctx context.Context, edit identity.RequestEditorFn) (int, error) {
		r, err := c.c.ListRevocationsWithResponse(ctx, params, edit)
		if err != nil {
			return 0, err
		}
		out = r
		return r.StatusCode(), nil
	})
	if err != nil {
		return nil, "", err
	}
	if status != http.StatusOK || out.JSON200 == nil {
		return nil, "", refusal(status)
	}
	for _, r := range out.JSON200.Items {
		items = append(items, Revocation{ID: r.Id, Subject: r.SubjectId, Tenant: r.OrganisationId, Device: r.SubjectType == identity.RevocationSubjectTypeDevice, At: r.RevokedAt})
	}
	if out.JSON200.NextCursor != nil {
		next = *out.JSON200.NextCursor
	}
	return items, next, nil
}

// RecordDrained tells identity that a revoked device's stream is stored through the given sequences (stream
// name to highest sequence); identity starts the wipe delay on its own clock. A replay is safe.
func (c *Client) RecordDrained(ctx context.Context, tenant, device string, through map[string]int64) error {
	body := identity.RecordDrain{DrainedThrough: []identity.StreamSequence{}}
	names := make([]string, 0, len(through))
	for n := range through {
		names = append(names, n)
	}
	sortStrings(names)
	for _, n := range names {
		body.DrainedThrough = append(body.DrainedThrough, identity.StreamSequence{Stream: n, Seq: int(through[n])})
	}
	idem := newKey()
	var out *identity.RecordDeviceDrainedResponse
	status, err := c.attempt(ctx, tenant, func(ctx context.Context, edit identity.RequestEditorFn) (int, error) {
		r, err := c.c.RecordDeviceDrainedWithResponse(ctx, device, &identity.RecordDeviceDrainedParams{IdempotencyKey: idem}, body, edit)
		if err != nil {
			return 0, err
		}
		out = r
		return r.StatusCode(), nil
	})
	if err != nil {
		return err
	}
	if status == http.StatusConflict { // already drained: the same answer as the first time
		return nil
	}
	if status != http.StatusOK || out.JSON200 == nil {
		return refusal(status)
	}
	return nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// newKey is one Idempotency-Key per logical call: the retry of a call is a replay, but a later identical
// question is a new call. A question about a proof must never be answered from a stored earlier answer (the
// failure counter moves between asking and asking again).
func newKey() string { return string(ids.New()) }
