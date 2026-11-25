package sim

import (
	"crypto/ecdsa"
	"math/rand/v2"
)

type ecdsaPub = ecdsa.PublicKey

// Rand is the single seeded source of randomness of a run.
type Rand struct {
	R    *rand.Rand
	Seed uint64
}

// NewRand seeds a generator.
func NewRand(seed uint64) *Rand {
	return &Rand{R: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)), Seed: seed}
}

// Intn returns [0,n).
func (r *Rand) Intn(n int) int {
	if n <= 0 {
		return 0
	}
	return r.R.IntN(n)
}

// Chance is true with probability p.
func (r *Rand) Chance(p float64) bool { return r.R.Float64() < p }

// Range returns [lo,hi].
func (r *Rand) Range(lo, hi int) int { return lo + r.Intn(hi-lo+1) }
