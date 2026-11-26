package hub

import (
	"context"
	"time"

	"github.com/hostryhq/svc-sync/repository"
)

// metaPack is the meta key that holds the signed pack as identity issued it. The hub store encrypts meta values (A3.2).
const metaPack = "hub-pack"

// refreshEvery is the least time between two pack fetches at cloud contacts.
const refreshEvery = 30 * time.Second

// ApplyPack puts a verified hub pack to work: the identity keys, the gateway op-signing key, the hub's own LAN credential (so
// devices see its new `not_after`), the outlet's members, and the revoked list. A device the pack lists as revoked loses its
// LAN sessions at once and is refused at its next hello (HP1). The pack is stored encrypted so a restart works offline.
func (h *Hub) ApplyPack(ctx context.Context, p HubPack) error {
	keys := append([]*PubKey(nil), p.IdentityKeys...)
	h.idKeys.Store(&keys)
	cred := p.CredJWS
	h.credJWS.Store(&cred)
	if p.OpKey != nil {
		h.cache.AddCloudKey(p.OpKid, p.OpKey)
	}
	members := make(map[string][]string, len(p.Members))
	for k, v := range p.Members {
		members[k] = v
	}
	h.members.Store(&members)
	for _, d := range p.Revoked {
		h.Revoke(d)
	}
	// The peers the pack lists are known on the LAN at once, so a tablet relays to another with no cloud contact first. A peer
	// revoked here or earlier is not added.
	for _, pc := range p.Peers {
		if !h.IsRevoked(pc.DeviceID) {
			h.cache.AddLAN(pc)
		}
	}
	return h.cfg.Store.InTx(ctx, h.cfg.Tenant, func(tx repository.Tx) error { return tx.SetMeta(metaPack, p.Raw) })
}

// StoredPack returns the pack the hub stored at its last refresh ("" when none).
func (h *Hub) StoredPack(ctx context.Context) (string, error) {
	var raw string
	err := h.cfg.Store.InTx(ctx, h.cfg.Tenant, func(tx repository.Tx) error {
		var err error
		raw, _, err = tx.GetMeta(metaPack)
		return err
	})
	return raw, err
}

// SetPackRefresh installs the function that fetches and applies a fresh pack; RunUpstream calls it after each successful cloud
// contact, at most every 30 seconds.
func (h *Hub) SetPackRefresh(f func(ctx context.Context) error) { h.refresh = f }

func (h *Hub) refreshPack(ctx context.Context) {
	if h.refresh == nil || h.cfg.Now().Sub(h.refreshed) < refreshEvery {
		return
	}
	h.refreshed = h.cfg.Now()
	if err := h.refresh(ctx); err != nil {
		h.cfg.Log.Warn("hub pack refresh failed", "err", err.Error())
	}
}

// RefreshPack runs the installed refresher now (tests and the status command).
func (h *Hub) RefreshPack(ctx context.Context) error {
	if h.refresh == nil {
		return nil
	}
	return h.refresh(ctx)
}

// IdentityKeys returns the identity keys the hub currently trusts (current and next, from its pack).
func (h *Hub) IdentityKeys() []*PubKey { return append([]*PubKey(nil), *h.idKeys.Load()...) }

// StorePack keeps a pack as identity issued it in a hub store (encrypted there), so a restart works with no internet.
func StorePack(ctx context.Context, st repository.Store, tenant, raw string) error {
	return st.InTx(ctx, tenant, func(tx repository.Tx) error { return tx.SetMeta(metaPack, raw) })
}

// LoadStoredPack reads the pack kept by StorePack and verifies it against the identity keys it names itself: the store's
// authenticated encryption is what vouches for the file, the signature is the integrity check of the pack's content.
func LoadStoredPack(ctx context.Context, st repository.Store, tenant, deviceID string, pol PackPolicy) (HubPack, error) {
	var raw string
	var ok bool
	err := st.InTx(ctx, tenant, func(tx repository.Tx) error {
		var err error
		raw, ok, err = tx.GetMeta(metaPack)
		return err
	})
	if err != nil {
		return HubPack{}, err
	}
	if !ok {
		return HubPack{}, ErrPack
	}
	return VerifyPack(raw, deviceID, pol)
}

// ID is the hub's own device id.
func (h *Hub) ID() string { return h.hubID() }

// Outlet is the outlet the hub serves.
func (h *Hub) Outlet() string { return h.cfg.Outlet }
