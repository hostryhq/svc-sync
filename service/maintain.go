package service

import (
	"context"
	"sort"

	"github.com/hostryhq/svc-sync/repository"
)

// KnownTenants lists the tenants this gateway process has served since it started.
func (g *Gateway) KnownTenants() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]string, 0, len(g.eng))
	for t := range g.eng {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// MaintainOnce does the periodic work that depends on identity and tenancy answering: it asks again about every
// session proof that was pending (A3.1 item 4), re-judges the configuration ops that waited, and repeats the report of
// every accepted drain statement identity has not recorded yet (A3.3 item 4). Errors of one tenant do not stop the
// others; the first is returned.
func (g *Gateway) MaintainOnce(ctx context.Context) error {
	var first error
	for _, t := range g.KnownTenants() {
		if _, err := g.ResolveSessions(ctx, t); err != nil && first == nil {
			first = err
		}
		if err := g.cfg.Store.InTx(ctx, t, func(tx repository.Tx) error {
			_, err := g.expireApprovalWaits(tx)
			return err
		}); err != nil && first == nil {
			first = err
		}
		if _, err := g.ReportPendingDrains(ctx, t); err != nil && first == nil && err != ErrNoDrainRecorder {
			first = err
		}
	}
	return first
}
