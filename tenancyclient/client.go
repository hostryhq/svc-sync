// Package tenancyclient is the sync gateway's client of the tenancy service: the series of a device, the paper bill
// books of an outlet and the owner of an outlet or brand stream (api-specs openapi/tenancy/v1, x-service-callers:
// sync; gen/ is generated and never edited). Like identityclient it mints a short-lived service token naming the
// tenant, bounds every attempt with a timeout and retries once with jitter on a transport failure or a 502, 503, 504.
package tenancyclient

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	auth "github.com/hostryhq/go-auth"
	tenancy "github.com/hostryhq/svc-sync/tenancyclient/gen"
)

// Audience is the service name tokens are minted for.
const Audience = "tenancy"

// ErrUnavailable means tenancy could not be reached or answered with a server error.
var ErrUnavailable = errors.New("tenancyclient: tenancy is unavailable")

// ErrNotFound means tenancy answered 404: no such device, outlet or stream in the tenant.
var ErrNotFound = errors.New("tenancyclient: tenancy has no such record")

// Client calls the internal routes of tenancy that the gateway uses.
type Client struct {
	c      *tenancy.ClientWithResponses
	signer *auth.ServiceSigner
	// Timeout bounds one attempt (default 5s).
	Timeout time.Duration
	// Sleep waits between attempts; tests replace it so no test sleeps.
	Sleep func(ctx context.Context, d time.Duration)
}

// New builds a client for the tenancy service at baseURL. hc may be nil.
func New(baseURL string, signer *auth.ServiceSigner, hc *http.Client) (*Client, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	if signer == nil {
		return nil, errors.New("tenancyclient: a service signer is required")
	}
	c, err := tenancy.NewClientWithResponses(strings.TrimRight(baseURL, "/"), tenancy.WithHTTPClient(hc))
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

func (c *Client) attempt(ctx context.Context, tenant string, call func(ctx context.Context, edit tenancy.RequestEditorFn) (int, error)) (int, error) {
	var status int
	for try := 0; try < 2; try++ {
		actx, cancel := context.WithTimeout(ctx, c.Timeout)
		tok, err := c.signer.Sign(Audience, tenant)
		if err != nil {
			cancel()
			return 0, err
		}
		status, err = call(actx, func(_ context.Context, r *http.Request) error {
			r.Header.Set(auth.ServiceTokenHeader, tok)
			return nil
		})
		cancel()
		if err == nil && status != http.StatusBadGateway && status != http.StatusServiceUnavailable && status != http.StatusGatewayTimeout {
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

func answer(status int) error {
	switch status {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return ErrNotFound
	}
	return fmt.Errorf("%w (status %d)", ErrUnavailable, status)
}

// Series is one document series issued to a device (listDeviceSeries). Status is active, dormant, closed or
// closed_unreconciled as tenancy states it.
type Series struct {
	ID, Code, DocType, Status, TaxRegistrationID, OutletID, DeviceID string
}

// DeviceSeries lists every series ever issued to the device, closed ones included (A3.2 row 8).
func (c *Client) DeviceSeries(ctx context.Context, tenant, device string) ([]Series, error) {
	var out *tenancy.ListDeviceSeriesResponse
	status, err := c.attempt(ctx, tenant, func(ctx context.Context, edit tenancy.RequestEditorFn) (int, error) {
		r, err := c.c.ListDeviceSeriesWithResponse(ctx, device, edit)
		if err != nil {
			return 0, err
		}
		out = r
		return r.StatusCode(), nil
	})
	if err != nil {
		return nil, err
	}
	if err := answer(status); err != nil {
		return nil, err
	}
	if out.JSON200 == nil {
		return nil, ErrUnavailable
	}
	var res []Series
	for _, s := range out.JSON200.Items {
		res = append(res, Series{ID: s.Id, Code: s.Code, DocType: string(s.DocType), Status: string(s.Status), TaxRegistrationID: s.TaxRegistrationId, OutletID: s.OutletId, DeviceID: s.DeviceId})
	}
	return res, nil
}

// Book is a registered paper bill book (listOutletManualBookSeries).
type Book struct {
	ID, Code, Status string
	OutletIDs        []string
}

// OutletBooks lists the paper bill books of the outlet's tax registration that list the outlet (active and closed).
func (c *Client) OutletBooks(ctx context.Context, tenant, outlet string) ([]Book, error) {
	var out *tenancy.ListOutletManualBookSeriesResponse
	status, err := c.attempt(ctx, tenant, func(ctx context.Context, edit tenancy.RequestEditorFn) (int, error) {
		r, err := c.c.ListOutletManualBookSeriesWithResponse(ctx, outlet, edit)
		if err != nil {
			return 0, err
		}
		out = r
		return r.StatusCode(), nil
	})
	if err != nil {
		return nil, err
	}
	if err := answer(status); err != nil {
		return nil, err
	}
	if out.JSON200 == nil {
		return nil, ErrUnavailable
	}
	var res []Book
	for _, b := range out.JSON200.Items {
		res = append(res, Book{ID: b.Id, Code: b.Code, Status: string(b.Status), OutletIDs: b.OutletIds})
	}
	return res, nil
}

// StreamOwner is the owner of an outlet or brand stream (getStreamOwner).
type StreamOwner struct {
	Kind, OrganisationID, BrandID string
}

// StreamOwner asks which organisation owns the outlet or brand id; 404 when it is not the tenant's.
func (c *Client) StreamOwner(ctx context.Context, tenant, id string) (StreamOwner, error) {
	var out *tenancy.GetStreamOwnerResponse
	status, err := c.attempt(ctx, tenant, func(ctx context.Context, edit tenancy.RequestEditorFn) (int, error) {
		r, err := c.c.GetStreamOwnerWithResponse(ctx, id, edit)
		if err != nil {
			return 0, err
		}
		out = r
		return r.StatusCode(), nil
	})
	if err != nil {
		return StreamOwner{}, err
	}
	if err := answer(status); err != nil {
		return StreamOwner{}, err
	}
	if out.JSON200 == nil {
		return StreamOwner{}, ErrUnavailable
	}
	o := StreamOwner{Kind: string(out.JSON200.Kind), OrganisationID: out.JSON200.OrganisationId}
	if out.JSON200.BrandId != nil {
		o.BrandID = *out.JSON200.BrandId
	}
	return o, nil
}
