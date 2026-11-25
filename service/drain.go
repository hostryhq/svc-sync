package service

import (
	"context"
	"errors"

	"github.com/hostryhq/svc-sync/directory"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// ErrNoDrainRecorder is returned when the configured directory cannot tell identity about a drain.
var ErrNoDrainRecorder = errors.New("service: the directory does not record drains")

// ReportDrained tells identity that a revoked device is drained, with the highest sequence the gateway
// stores per stream of the device's own ops (identity's recordDeviceDrained; identity then starts the wipe
// delay on its own clock). It does not decide that the device is drained: the caller does. The gateway never
// calls it on its own, because an early report wipes a device that still holds ops (the drain criterion is an
// open decision, see docs/phase2-notes.md). The device must be revoked.
func (g *Gateway) ReportDrained(ctx context.Context, tenant, device string) error {
	rec, ok := g.cfg.Dir.(directory.DrainRecorder)
	if !ok {
		return ErrNoDrainRecorder
	}
	if revoked, _ := g.cfg.Dir.Revoked(tenant, device); !revoked {
		return ErrNotFound
	}
	vec, err := g.engineFor(tenant).Vector(ctx)
	if err != nil {
		return err
	}
	through := map[string]int64{}
	for k, seq := range vec {
		if origin, stream, ok := sp.SplitVKey(k); ok && origin == device && seq > 0 {
			through[stream] = seq
		}
	}
	return rec.RecordDrained(ctx, tenant, device, through)
}
