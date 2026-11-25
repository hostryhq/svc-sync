package sim

import (
	"context"
	"fmt"
	"strings"

	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// RotateOpKey is the emergency rotation of the gateway op-signing key (ADR-0005 section 2): the
// gateway re-signs its cloud seals and endorsements, and every node's pack refresh adds the new key
// and drops the old. A device added afterwards knows the new key only.
func (w *World) RotateOpKey(kid string) error {
	next, err := sp.NewKeyPair(kid, nil)
	if err != nil {
		return err
	}
	old := w.Identity.CloudKey
	w.Identity.CloudKey = next
	if err := w.GW.RotateOpKey(w.Ctx, next, w.Tenant); err != nil {
		return err
	}
	refresh := func(c *engine.CredCache) {
		c.AddCloudKey(next.Kid, &next.Priv.PublicKey)
		c.RevokeCloudKey(old.Kid)
	}
	for _, d := range w.Devices {
		refresh(d.Cache)
	}
	if w.Hub != nil {
		refresh(w.Hub.Cache())
	}
	return nil
}

// tailOps returns the ops of origin held by the cloud with a mark, in seq order.
func (w *World) marked(store repository.Store, origin, mark string) (n int) {
	recs, err := readAll(w.Ctx, store, w.Tenant)
	if err != nil {
		panic(fmt.Sprint(err))
	}
	for _, r := range recs {
		if r.Origin == origin && r.Status == repository.StAccepted && strings.Contains(","+r.Marks+",", ","+mark+",") {
			n++
		}
	}
	return n
}

// endorsementsOf lists the endorsements a store holds.
func endorsementsOf(ctx context.Context, store repository.Store, tenant string) []repository.EndorsementRec {
	var out []repository.EndorsementRec
	err := store.InTx(ctx, tenant, func(tx repository.Tx) error {
		var err error
		out, err = tx.Endorsements()
		return err
	})
	if err != nil {
		panic(fmt.Sprint(err))
	}
	return out
}
