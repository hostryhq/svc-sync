package identityclient

import (
	"context"
	"net/http"
	"time"

	identity "github.com/hostryhq/svc-sync/identityclient/gen"
)

// ErrNotFound means identity answered 404 for the question: a different answer from ErrUnavailable, which says
// identity could not be asked. Nothing is ever granted on either.
var ErrNotFound = errNotFound{}

type errNotFound struct{}

func (errNotFound) Error() string { return "identityclient: identity has no such record" }

// ErrRejected means identity refused the question itself (422): for a proof, the proof does not fit the question.
var ErrRejected = errRejected{}

type errRejected struct{}

func (errRejected) Error() string { return "identityclient: identity rejected the question" }

// answer maps a final status to an error: nil for 200, ErrNotFound for 404, ErrRejected for 422, ErrRefused for
// 401 and 403, and ErrUnavailable otherwise.
func answer(status int) error {
	switch status {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusUnprocessableEntity:
		return ErrRejected
	}
	return refusal(status)
}

// DeviceCredential is the identity credential of a device as the pack carries it (getDeviceCredential).
type DeviceCredential struct {
	DeviceID, TenantID, OutletID, BrandID, Kind, Kid, Pub, Recovers string
}

// GetDeviceCredential asks for the credential of a device in any state (A3.2 row 1).
func (c *Client) GetDeviceCredential(ctx context.Context, tenant, device string) (DeviceCredential, error) {
	var out *identity.GetDeviceCredentialResponse
	status, err := c.attempt(ctx, tenant, func(ctx context.Context, edit identity.RequestEditorFn) (int, error) {
		r, err := c.c.GetDeviceCredentialWithResponse(ctx, device, edit)
		if err != nil {
			return 0, err
		}
		out = r
		return r.StatusCode(), nil
	})
	if err != nil {
		return DeviceCredential{}, err
	}
	if err := answer(status); err != nil || out.JSON200 == nil {
		return DeviceCredential{}, orUnavailable(err)
	}
	d := out.JSON200
	cr := DeviceCredential{DeviceID: d.DeviceId, TenantID: d.TenantId, OutletID: d.OutletId, Kind: string(d.Kind), Kid: d.Kid, Pub: d.Pub}
	if d.BrandId != nil {
		cr.BrandID = *d.BrandId
	}
	if d.Recovers != nil {
		cr.Recovers = *d.Recovers
	}
	return cr, nil
}

func orUnavailable(err error) error {
	if err == nil {
		return ErrUnavailable
	}
	return err
}

// PackGrants is what an issued pack version granted (getPackGrants).
type PackGrants struct {
	PackV             int
	IssuedAt          time.Time
	OfflineValidUntil time.Time
	Members           map[string][]string
	SeriesCodes       []string
}

// GetPackGrants asks what pack packV of the device granted (A3.2 row 2).
func (c *Client) GetPackGrants(ctx context.Context, tenant, device string, packV int) (PackGrants, error) {
	var out *identity.GetPackGrantsResponse
	status, err := c.attempt(ctx, tenant, func(ctx context.Context, edit identity.RequestEditorFn) (int, error) {
		r, err := c.c.GetPackGrantsWithResponse(ctx, device, packV, edit)
		if err != nil {
			return 0, err
		}
		out = r
		return r.StatusCode(), nil
	})
	if err != nil {
		return PackGrants{}, err
	}
	if err := answer(status); err != nil || out.JSON200 == nil {
		return PackGrants{}, orUnavailable(err)
	}
	g := out.JSON200
	pg := PackGrants{PackV: g.PackV, IssuedAt: g.IssuedAt, OfflineValidUntil: g.OfflineValidUntil, Members: map[string][]string{}}
	for _, m := range g.Members {
		pg.Members[m.MemberId] = m.Permissions
	}
	pg.SeriesCodes = g.SeriesCodes
	return pg, nil
}

// MemberGrants is a member's status and effective permissions at an outlet now (getMemberGrants).
type MemberGrants struct {
	Status      string
	Permissions []string
	RemovedAt   time.Time
}

// GetMemberGrants asks for the member's current grants at the outlet (A3.2 row 3).
func (c *Client) GetMemberGrants(ctx context.Context, tenant, member, outlet string) (MemberGrants, error) {
	var out *identity.GetMemberGrantsResponse
	status, err := c.attempt(ctx, tenant, func(ctx context.Context, edit identity.RequestEditorFn) (int, error) {
		r, err := c.c.GetMemberGrantsWithResponse(ctx, member, &identity.GetMemberGrantsParams{OutletId: outlet}, edit)
		if err != nil {
			return 0, err
		}
		out = r
		return r.StatusCode(), nil
	})
	if err != nil {
		return MemberGrants{}, err
	}
	if err := answer(status); err != nil || out.JSON200 == nil {
		return MemberGrants{}, orUnavailable(err)
	}
	g := MemberGrants{Status: out.JSON200.Status, Permissions: out.JSON200.Permissions}
	if out.JSON200.RemovedAt != nil {
		g.RemovedAt = *out.JSON200.RemovedAt
	}
	return g, nil
}

// DeviceRecovery is the key-loss recovery record of an old device (getDeviceRecovery). It never carries the code.
type DeviceRecovery struct {
	ID, OldDeviceID, NewDeviceID, ApproverID, State string
	RecoveredAt                                     time.Time
}

// GetDeviceRecovery asks for the recovery of the old device (A3.2 row 4).
func (c *Client) GetDeviceRecovery(ctx context.Context, tenant, old string) (DeviceRecovery, error) {
	var out *identity.GetDeviceRecoveryResponse
	status, err := c.attempt(ctx, tenant, func(ctx context.Context, edit identity.RequestEditorFn) (int, error) {
		r, err := c.c.GetDeviceRecoveryWithResponse(ctx, old, edit)
		if err != nil {
			return 0, err
		}
		out = r
		return r.StatusCode(), nil
	})
	if err != nil {
		return DeviceRecovery{}, err
	}
	if err := answer(status); err != nil || out.JSON200 == nil {
		return DeviceRecovery{}, orUnavailable(err)
	}
	r := out.JSON200
	return DeviceRecovery{ID: r.Id, OldDeviceID: r.OldDeviceId, NewDeviceID: r.NewDeviceId, ApproverID: r.ApproverId, State: string(r.State), RecoveredAt: r.RecoveredAt}, nil
}

// SessionFacts are the fixed facts of a strong session (getSession).
type SessionFacts struct {
	SessionID, MemberID, DeviceID string
	IssuedAt, EndedAt             time.Time
}

// GetSession asks for the facts of a strong session (A3.2 row 6).
func (c *Client) GetSession(ctx context.Context, tenant, sid string) (SessionFacts, error) {
	var out *identity.GetSessionResponse
	status, err := c.attempt(ctx, tenant, func(ctx context.Context, edit identity.RequestEditorFn) (int, error) {
		r, err := c.c.GetSessionWithResponse(ctx, sid, edit)
		if err != nil {
			return 0, err
		}
		out = r
		return r.StatusCode(), nil
	})
	if err != nil {
		return SessionFacts{}, err
	}
	if err := answer(status); err != nil || out.JSON200 == nil {
		return SessionFacts{}, orUnavailable(err)
	}
	s := out.JSON200
	f := SessionFacts{SessionID: s.SessionId, MemberID: s.MemberId, IssuedAt: s.IssuedAt}
	if s.DeviceId != nil {
		f.DeviceID = *s.DeviceId
	}
	if s.EndedAt != nil {
		f.EndedAt = *s.EndedAt
	}
	return f, nil
}
