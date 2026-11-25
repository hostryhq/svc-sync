package syncproto

// Personal data beside an op: salted per-field commitments (PROVISIONAL, security ruling of the
// Phase 1 re-review; the exact wire shape is still to be settled with security-reviewer).
//
// An op's pii travels outside the hash (ADR-0002 S4) so that erasure never touches the chain. A plain
// hash of it in the sealed body would let a phone number be guessed back, so the sealed body
// carries only commitments:
//
//	pii_c[entity][row id][field] = hex SHA-256( salt || JCS(value) )
//
// salt is 16 random bytes kept with the value, never in the body. JCS is RFC 8785 canonical JSON
// (strings, booleans and integers only, as everywhere in an op). On the wire the salt of a field
// travels in the same pii object under the key "~s:<field>" (base64url), so the pii keeps the
// entity -> row id -> field -> value shape the shared parser reads; the gateway strips salts before
// it publishes the event. A cloud-signed erasure op (intent sync.pii.erase) removes values and
// salts; the commitments stay in the sealed body, and cannot be reversed or re-opened without them.
//
// This file is the ONLY place that knows the construction: CommitPII (recording node) and OpenPII
// (every node that ingests pii) are the whole surface. Changing the ruling means changing this file.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// PII is entity -> row id -> field -> value (string, bool or integer).
type PII map[string]map[string]map[string]any

// PIICommit is entity -> row id -> field -> commitment, the content of body.pii_c.
type PIICommit map[string]map[string]map[string]string

const (
	piiSaltPrefix = "~s:"
	piiSaltBytes  = 16
)

// ErrPII is returned for pii that is not of the documented shape.
var ErrPII = errors.New("syncproto: malformed pii")

func commit(salt []byte, value any) (string, error) {
	c, err := CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(salt)
	h.Write(c)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// CommitPII turns the values of an op into the wire pii (values with their salts) and the
// commitments for the sealed body. entropy defaults to crypto/rand.
func CommitPII(values PII, entropy io.Reader) (wire json.RawMessage, commits PIICommit, err error) {
	if len(values) == 0 {
		return nil, nil, nil
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	out := map[string]map[string]map[string]any{}
	commits = PIICommit{}
	ents := make([]string, 0, len(values))
	for e := range values {
		ents = append(ents, e)
	}
	sort.Strings(ents)
	for _, e := range ents {
		rows := values[e]
		out[e], commits[e] = map[string]map[string]any{}, map[string]map[string]string{}
		for id, fields := range rows {
			out[e][id], commits[e][id] = map[string]any{}, map[string]string{}
			for name, v := range fields {
				if strings.HasPrefix(name, piiSaltPrefix) {
					return nil, nil, fmt.Errorf("%w: field name %q is reserved", ErrPII, name)
				}
				salt := make([]byte, piiSaltBytes)
				if _, err := io.ReadFull(entropy, salt); err != nil {
					return nil, nil, err
				}
				c, err := commit(salt, v)
				if err != nil {
					return nil, nil, fmt.Errorf("%w: %v", ErrPII, err)
				}
				out[e][id][name] = v
				out[e][id][piiSaltPrefix+name] = base64.RawURLEncoding.EncodeToString(salt)
				commits[e][id][name] = c
			}
		}
	}
	raw, err := CanonicalJSON(out)
	return raw, commits, err
}

// Opened is the result of OpenPII.
type Opened struct {
	// Verified is the wire pii reduced to the fields that match their commitment (values and
	// salts), in canonical JSON; empty when nothing verified. This is what a node stores.
	Verified json.RawMessage
	// Values are the verified values without salts: what the event publishes.
	Values PII
	// Dropped counts fields that arrived without a matching commitment or with a wrong salt.
	// Their values are discarded, never stored or published.
	Dropped int
}

// OpenPII verifies wire pii against the commitments of the sealed body. A field with no
// commitment, no salt, or a value that does not match is dropped: an unverifiable value is never
// kept. Body commitments with no value are normal (erased or not sent).
func OpenPII(wire json.RawMessage, c PIICommit) (Opened, error) {
	var o Opened
	if len(bytes.TrimSpace(wire)) == 0 || string(bytes.TrimSpace(wire)) == "null" {
		return o, nil
	}
	var in map[string]map[string]map[string]json.RawMessage
	if err := json.Unmarshal(wire, &in); err != nil {
		return o, fmt.Errorf("%w: %v", ErrPII, err)
	}
	ver := map[string]map[string]map[string]any{}
	o.Values = PII{}
	for e, rows := range in {
		for id, fields := range rows {
			for name, raw := range fields {
				if strings.HasPrefix(name, piiSaltPrefix) {
					continue
				}
				v, err := decodePIIValue(raw)
				if err != nil {
					o.Dropped++
					continue
				}
				want, ok := c[e][id][name]
				saltRaw, hasSalt := fields[piiSaltPrefix+name]
				var saltS string
				_ = json.Unmarshal(saltRaw, &saltS)
				salt, derr := base64.RawURLEncoding.DecodeString(saltS)
				if !ok || !hasSalt || derr != nil || len(salt) != piiSaltBytes {
					o.Dropped++
					continue
				}
				got, err := commit(salt, v)
				if err != nil || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
					o.Dropped++
					continue
				}
				if ver[e] == nil {
					ver[e], o.Values[e] = map[string]map[string]any{}, map[string]map[string]any{}
				}
				if ver[e][id] == nil {
					ver[e][id], o.Values[e][id] = map[string]any{}, map[string]any{}
				}
				ver[e][id][name], o.Values[e][id][name] = v, v
				ver[e][id][piiSaltPrefix+name] = saltS
			}
		}
	}
	if len(ver) > 0 {
		raw, err := CanonicalJSON(ver)
		if err != nil {
			return o, err
		}
		o.Verified = raw
	}
	if len(o.Values) == 0 {
		o.Values = nil
	}
	return o, nil
}

// StripSalts removes the salts from stored wire pii, for the event (values only).
func StripSalts(wire json.RawMessage) (json.RawMessage, error) {
	if len(wire) == 0 {
		return nil, nil
	}
	var in map[string]map[string]map[string]any
	if err := json.Unmarshal(wire, &in); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPII, err)
	}
	for _, rows := range in {
		for _, fields := range rows {
			for name := range fields {
				if strings.HasPrefix(name, piiSaltPrefix) {
					delete(fields, name)
				}
			}
		}
	}
	return CanonicalJSON(in)
}

func decodePIIValue(raw json.RawMessage) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case bool, string:
		return t, nil
	case json.Number:
		n, err := t.Int64()
		if err != nil {
			return nil, err
		}
		return n, nil
	}
	return nil, errors.New("pii values are strings, booleans or integers")
}
