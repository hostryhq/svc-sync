package syncproto

import "errors"

// Limits of protocol v1 (sync/protocol-v1.md "Size limit"; vectors size_limit and emit_batch).
const (
	MaxBodyBytes = 262144 // op body: UTF-8 bytes of the JSON string that h covers
	MaxPIIBytes  = 16384  // pii object: bytes of canonical JSON
	MaxEmitOps   = 200
	MinEmitOps   = 1
	// MaxSafeInt is the largest integer an op may carry (2^53-1).
	MaxSafeInt = 1<<53 - 1
)

// ErrTooLarge is returned for an op whose body or pii is over the limit.
var ErrTooLarge = errors.New("syncproto: op body or pii over the size limit")

// CheckSize refuses a body or pii over the limits.
func CheckSize(bodyBytes, piiBytes int) error {
	if bodyBytes > MaxBodyBytes || piiBytes > MaxPIIBytes {
		return ErrTooLarge
	}
	return nil
}
