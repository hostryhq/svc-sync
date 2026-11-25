package engine

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// AttachSnapshotPII fills the `pii` of snapshot rows (values with their `~s:<field>` salts) from the op that won each
// field, for a caller whose credential kind receives them; a kds gets the commitments (`pii_c`) only (ADR-0014 A3.1,
// "A snapshot row carries pii_c always, and pii only where a pull would"). An erased field has no value and is absent.
func AttachSnapshotPII(tx repository.Tx, rows []sp.SnapshotRow, kind string) error {
	if !sp.ServesPII(kind) {
		return nil
	}
	cache := map[sp.Ref]map[string]map[string]map[string]any{}
	for i := range rows {
		r := &rows[i]
		for field, ref := range r.PIISrc {
			vals, ok := cache[ref]
			if !ok {
				raw, found, err := tx.GetPII(ref.Stream, ref.Origin, ref.Seq)
				if err != nil {
					return err
				}
				if found {
					dec := json.NewDecoder(strings.NewReader(raw))
					dec.UseNumber()
					if err := dec.Decode(&vals); err != nil {
						vals = nil
					}
				}
				cache[ref] = vals
			}
			f := vals[r.Entity][r.ID]
			v, has := f[field]
			if !has {
				continue
			}
			if n, isNum := v.(json.Number); isNum {
				if x, err := n.Int64(); err == nil {
					v = x
				}
			}
			if r.PII == nil {
				r.PII = map[string]any{}
			}
			r.PII[field] = v
			if s, ok := f["~s:"+field]; ok {
				r.PII["~s:"+field] = s
			}
		}
	}
	return nil
}

// SnapshotPII is AttachSnapshotPII in the node's own transaction.
func (e *Engine) SnapshotPII(ctx context.Context, rows []sp.SnapshotRow, kind string) error {
	return e.cfg.Store.InTx(ctx, e.cfg.Tenant, func(tx repository.Tx) error { return AttachSnapshotPII(tx, rows, kind) })
}
