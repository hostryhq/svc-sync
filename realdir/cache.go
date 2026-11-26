package realdir

import (
	"sync"
	"time"
)

// cache is a small bounded map with an optional expiry per entry. A zero expiry never expires. The gateway
// caches only what cannot change (ADR-0005 A3.2: a device's key, an issued pack, a recovery record, a stream's
// owner, the facts of a strong session) without an expiry, and everything else for 60 seconds.
type cache[V any] struct {
	mu  sync.Mutex
	max int
	m   map[string]entry[V]
}

type entry[V any] struct {
	v   V
	exp time.Time
}

func newCache[V any](max int) *cache[V] { return &cache[V]{max: max, m: map[string]entry[V]{}} }

func (c *cache[V]) get(k string, now time.Time) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	if !ok || (!e.exp.IsZero() && !now.Before(e.exp)) {
		delete(c.m, k)
		var zero V
		return zero, false
	}
	return e.v, true
}

// put stores v until now+ttl (never when ttl is 0).
func (c *cache[V]) put(k string, v V, now time.Time, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= c.max {
		for key, e := range c.m {
			if !e.exp.IsZero() && !now.Before(e.exp) {
				delete(c.m, key)
			}
		}
		for key := range c.m { // still full: drop a tenth, arbitrary entries first
			if len(c.m) < c.max*9/10 {
				break
			}
			delete(c.m, key)
		}
	}
	e := entry[V]{v: v}
	if ttl > 0 {
		e.exp = now.Add(ttl)
	}
	c.m[k] = e
}

func (c *cache[V]) drop(k string) {
	c.mu.Lock()
	delete(c.m, k)
	c.mu.Unlock()
}

// dropPrefix removes every entry whose key starts with prefix.
func (c *cache[V]) dropPrefix(prefix string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.m {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			delete(c.m, k)
		}
	}
}
