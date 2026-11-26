package syncproto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
)

// ActionHash is the hash an approval binds (ADR-0005 section 8, ADR-0014 A3.3; vectors action_hash): "sha256:" plus the
// lower-case hex SHA-256 of the JCS of {intent, permission, requester, target, approval_id, reason, values}. `target`
// and `reason` are empty strings when the record has none; `values` holds the overridden fields and the new values the
// citing op records (one member per name in the intent's `proof.binds`), `{}` when the intent binds none.
func ActionHash(intent, permission, requester, target, approvalID, reason string, values map[string]any) (string, error) {
	if values == nil {
		values = map[string]any{}
	}
	raw, err := CanonicalJSON(map[string]any{"intent": intent, "permission": permission, "requester": requester, "target": target,
		"approval_id": approvalID, "reason": reason, "values": values})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ApprovalProofMessage is the message of the approver's action proof (sync/protocol-v1.md, Proof messages). Times are UTC
// with three millisecond digits; target and reason are quoted with strconv.Quote.
func ApprovalProofMessage(actionHash, deviceID, approver string, packV, pinV int, approvalID, permission, target, requester, approvedAt, reason string) string {
	return strings.Join([]string{"approval", actionHash, deviceID, approver, strconv.Itoa(packV), strconv.Itoa(pinV), approvalID, permission,
		strconv.Quote(target), requester, approvedAt, strconv.Quote(reason)}, "|")
}

// SessionProofMessage is the message of a PIN session proof.
func SessionProofMessage(sid, deviceID, member string, packV, pinV int, openedAt string) string {
	return strings.Join([]string{"session", sid, deviceID, member, strconv.Itoa(packV), strconv.Itoa(pinV), openedAt}, "|")
}

// ProofMAC is base64url-nopad(HMAC-SHA256(proof key, message)). Only identity and the shell hold a proof key; the
// simulator derives one to make proofs the identity stub accepts.
func ProofMAC(key []byte, message string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(message))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// RowText is the canonical text of one row in a digest or a convergence hash (ADR-0014 A3.2 item 1; vectors digest_row):
// the JCS of `id`, every non-pii field the row has set (absent and null omitted) and, for each pii field the row holds a
// commitment for, the member "~c:<field>" with that commitment. A pii value or salt is never an input, so the text is the
// same on the origin, a peer, a kds, the hub and the cloud, and does not change when a field is erased.
func RowText(id string, fields map[string]any, pii map[string]bool, commitments map[string]string) (string, error) {
	m := map[string]any{"id": id}
	for k, v := range fields {
		if v == nil || pii[k] {
			continue
		}
		m[k] = v
	}
	for k, c := range commitments {
		if pii[k] {
			m["~c:"+k] = c
		}
	}
	raw, err := CanonicalJSON(m)
	return string(raw), err
}
