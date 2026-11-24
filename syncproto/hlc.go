// Package syncproto is Sync Protocol v1 (ADR-0002): op envelope, hybrid logical clock,
// canonical JSON, hash chain, seals and the wire request/response types. It has no
// database and no HTTP server; the gateway, the hub, the simulator and the test double
// all build on it. It is meant to move to go-common/sync once that module has a place for it.
package syncproto

import (
	"fmt"
	"strconv"
	"sync"
	"time"
)

// HLC is a 64-bit hybrid logical clock: 48-bit Unix milliseconds and a 16-bit counter.
// It is carried as 16 lowercase hex characters, which sorts like the number.
type HLC uint64

// MakeHLC builds a clock value.
func MakeHLC(ms int64, counter uint16) HLC { return HLC(uint64(ms)<<16 | uint64(counter)) }

// Millis is the physical part.
func (h HLC) Millis() int64 { return int64(h >> 16) }

// String is the 16-character hex form.
func (h HLC) String() string { return fmt.Sprintf("%016x", uint64(h)) }

// ParseHLC parses the hex form.
func ParseHLC(s string) (HLC, error) {
	if len(s) != 16 {
		return 0, fmt.Errorf("hlc: want 16 hex characters")
	}
	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("hlc: %w", err)
	}
	return HLC(v), nil
}

// Clock stamps local events and absorbs remote stamps. Offset is the persisted correction
// towards upstream time (cloud over hub over local, S5).
type Clock struct {
	mu     sync.Mutex
	last   HLC
	now    func() time.Time
	offset time.Duration
}

// NewClock returns a clock reading physical time from now.
func NewClock(now func() time.Time) *Clock { return &Clock{now: now} }

// SetOffset sets the correction added to the local reading.
func (c *Clock) SetOffset(d time.Duration) { c.mu.Lock(); c.offset = d; c.mu.Unlock() }

// Offset returns the current correction.
func (c *Clock) Offset() time.Duration { c.mu.Lock(); defer c.mu.Unlock(); return c.offset }

// Restore raises the clock to at least h (used after a restart from the op log).
func (c *Clock) Restore(h HLC) {
	c.mu.Lock()
	if h > c.last {
		c.last = h
	}
	c.mu.Unlock()
}

// Time returns the corrected physical time.
func (c *Clock) Time() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now().Add(c.offset)
}

// Next returns a stamp strictly greater than every stamp issued or observed so far.
func (c *Clock) Next() HLC {
	c.mu.Lock()
	defer c.mu.Unlock()
	pt := MakeHLC(c.now().Add(c.offset).UnixMilli(), 0)
	if pt > c.last {
		c.last = pt
	} else {
		c.last++
	}
	return c.last
}

// Observe absorbs a stamp seen on a received op, so later local stamps sort after it.
// A stamp further than maxAhead ahead of local time is ignored: a wrong remote clock
// must not drag every later local stamp with it.
func (c *Clock) Observe(h HLC, maxAhead time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	limit := MakeHLC(c.now().Add(c.offset).Add(maxAhead).UnixMilli(), 0xffff)
	if h > c.last && h <= limit {
		c.last = h
	}
}
