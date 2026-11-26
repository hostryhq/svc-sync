package sim

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/svc-sync/engine"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// LoseKey makes the device key unusable while the database stays intact (ADR-0007 K6): nothing
// is destroyed, nothing is recorded, no bill is opened.
func (d *Device) LoseKey() { d.KeyLost = true }

// CloudTransportToken is a transport to the gateway with an explicit token (drain tokens).
func (w *World) CloudTransportToken(link, token string) *engine.HTTPTransport {
	return &engine.HTTPTransport{Base: "http://cloud", Client: &http.Client{Transport: w.Net.RoundTripper(link, w.cloudIndirect())},
		Authorize: func(r *http.Request, _ []byte) error {
			r.Header.Set("Authorization", "Bearer "+token)
			return nil
		}}
}

// Recovery is the state of one device recovery.
type Recovery struct {
	Old, New, RecID string
	Done            bool
}

// RecoverDevice runs A1.3 items 2 and 3: an owner creates a recovery code, the installation
// creates a new key and activates as a new device with new series codes, and billing reopens
// under the new origin at once. The recovery upload is a separate, resumable step.
func (w *World) RecoverDevice(d *Device, byOwner bool) (*Recovery, error) {
	old := d.ID
	code, err := w.Identity.CreateRecovery(w.Tenant, old, byOwner)
	if err != nil {
		return nil, err
	}
	return w.ActivateRecovery(d, code)
}

// ActivateRecovery activates the installation with a recovery code.
func (w *World) ActivateRecovery(d *Device, code string) (*Recovery, error) {
	if bound, ok := w.Identity.RecoveryCodeDevice(code); !ok || bound != d.ID {
		return nil, ErrRecoveryCode // a code for another device is refused (KL6)
	}
	old := d.ID
	d.Recovered = append(d.Recovered, old)
	newID := fmt.Sprintf("%s-r%d", old, len(d.Recovered))
	kp, err := sp.NewKeyPair("k-"+newID, nil)
	if err != nil {
		return nil, err
	}
	env, rec, err := w.Identity.ActivateRecovery(code, newID, kp)
	if err != nil {
		d.Recovered = d.Recovered[:len(d.Recovered)-1]
		return nil, err
	}
	w.Identity.IssuePack(w.Tenant, newID, 1, 7*24*time.Hour)
	d.ID, d.Key, d.Cred, d.KeyLost = newID, kp, env, false
	d.sessions, d.badSessions = map[string]string{}, nil
	for _, s := range w.Identity.SeriesOf(w.Tenant, newID) {
		switch s.DocType {
		case "tax_invoice":
			d.saleCode = s.Code
		case "credit_note":
			d.cnCode = s.Code
		}
	}
	for _, o := range w.Devices {
		_ = o.Cache.Add(env)
	}
	if w.Hub != nil {
		_ = w.Hub.AddPeer(env)
		w.Hub.Revoke(old)
	}
	w.byID[newID] = d
	_ = d.Store.Close()
	if err := d.open(); err != nil {
		return nil, err
	}
	rc := &Recovery{Old: old, New: newID, RecID: rec.ID}
	d.Recoveries = append(d.Recoveries, rc)
	return rc, nil
}

// UploadRecovery pushes the old origin's unconfirmed ops through the recovery drain token until
// the gateway reports the origin drained. Each call is one batch and safe to repeat.
func (w *World) UploadRecovery(ctx context.Context, d *Device, rc *Recovery) (bool, error) {
	cloud := w.CloudTransport("dev-cloud:"+d.ID, d.ID)
	hello, err := cloud.Hello(ctx, sp.HelloRequest{Protocol: sp.ProtocolVersion})
	if err != nil {
		return false, err
	}
	req, err := d.Eng.RecoveryUpload(ctx, rc.Old, hello.Vector, 500, func(stream string, seq int64, h string) (sp.Attestation, error) {
		return sp.MakeAttestation(d.Key, sp.Attestation{Origin: rc.Old, Stream: stream, Seq: seq, H: h, By: d.ID, Rec: rc.RecID})
	})
	if err != nil {
		return false, err
	}
	up := w.CloudTransportToken("dev-cloud:"+d.ID, d.DrainToken(rc.Old))
	resp, err := up.QuarantineUpload(ctx, req)
	if err != nil {
		return false, err
	}
	if resp.Drained {
		rc.Done = true
	}
	return resp.Drained, nil
}

// UploadRevokedDrain is the ordinary drain of a revoked device with its own key (A1.3 item 9, KL5).
func (w *World) UploadRevokedDrain(ctx context.Context, d *Device, oldID string, oldKey *sp.KeyPair, items sp.PushRequest) (sp.PushResponse, error) {
	tok := w.Token(auth.TypeDrain, oldID, "")
	return w.CloudTransportToken("dev-cloud:"+oldID, tok).QuarantineUpload(ctx, items)
}

// ErrRecoveryCode is returned for a code that is not for this installation.
var ErrRecoveryCode = errors.New("sim: recovery code is not for this device")

// ErrStuck is returned when a bounded loop does not finish.
var ErrStuck = errors.New("sim: did not settle")
