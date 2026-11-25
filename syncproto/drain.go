package syncproto

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

// DrainTag is the domain tag of the drain statement signature (ADR-0005 A3.3).
const DrainTag = "hostry-drain-v1"

// DrainStream is the head of one stream in which the device's log holds an own-origin op.
type DrainStream struct {
	Stream string `json:"stream"`
	Seq    int64  `json:"seq"`
	H      string `json:"h"`
}

// DrainSeriesLast is one series of the device's pack in the fields of a series_close record; LastNumber is 0 when
// the series was never used.
type DrainSeriesLast struct {
	SeriesID   string `json:"series_id"`
	Code       string `json:"code"`
	FY         string `json:"fy"`
	LastNumber int64  `json:"last_number"`
}

// DrainStatement is the device-signed list of everything a revoked device holds and its last document numbers
// (ADR-0005 A3.3; sync/protocol-v1.md, Drain statement). Ordinary drain: By == Origin, signed with the revoked
// device's key. Key loss: By is the adopting device, Rec the recovery id, signed with the new key.
type DrainStatement struct {
	Origin  string            `json:"origin"`
	Streams []DrainStream     `json:"streams"`
	Series  []DrainSeriesLast `json:"series"`
	By      string            `json:"by"`
	Rec     string            `json:"rec,omitempty"`
	Kid     string            `json:"kid"`
	At      string            `json:"at"`
	Sig     string            `json:"sig"`
}

// Normalize sorts streams by stream and series by series_id, so that one log gives one statement.
func (d *DrainStatement) Normalize() {
	sort.Slice(d.Streams, func(i, j int) bool { return d.Streams[i].Stream < d.Streams[j].Stream })
	sort.Slice(d.Series, func(i, j int) bool { return d.Series[i].SeriesID < d.Series[j].SeriesID })
}

// SignedMessage is the tag, a line feed and the JCS of the statement without its signature.
func (d DrainStatement) SignedMessage() (string, error) {
	d.Sig = ""
	raw, err := drainJCS(d, false)
	if err != nil {
		return "", err
	}
	return DrainTag + "\n" + string(raw), nil
}

// drainJCS canonicalises the statement; withSig false leaves the sig member out.
func drainJCS(d DrainStatement, withSig bool) ([]byte, error) {
	type unsigned struct {
		Origin  string            `json:"origin"`
		Streams []DrainStream     `json:"streams"`
		Series  []DrainSeriesLast `json:"series"`
		By      string            `json:"by"`
		Rec     string            `json:"rec,omitempty"`
		Kid     string            `json:"kid"`
		At      string            `json:"at"`
	}
	u := unsigned{d.Origin, nonNilStreams(d.Streams), nonNilSeries(d.Series), d.By, d.Rec, d.Kid, d.At}
	if !withSig {
		return CanonicalJSON(u)
	}
	return CanonicalJSON(struct {
		unsigned
		Sig string `json:"sig"`
	}{u, d.Sig})
}

func nonNilStreams(s []DrainStream) []DrainStream {
	if s == nil {
		return []DrainStream{}
	}
	return s
}

func nonNilSeries(s []DrainSeriesLast) []DrainSeriesLast {
	if s == nil {
		return []DrainSeriesLast{}
	}
	return s
}

// Hash is the statement_hash of the wipe order: lower-case hex SHA-256 of the JCS of the whole statement, sig
// included. It is computed from the parsed object, never from the received text.
func (d DrainStatement) Hash() (string, error) {
	raw, err := drainJCS(d, true)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// MakeDrainStatement signs the statement with the key (Kid is set from the key).
func MakeDrainStatement(k *KeyPair, d DrainStatement) (DrainStatement, error) {
	d.Kid = k.Kid
	d.Normalize()
	msg, err := d.SignedMessage()
	if err != nil {
		return d, err
	}
	d.Sig, err = k.Sign(msg)
	return d, err
}

// Verify checks the signature against the signing device's public key.
func (d DrainStatement) Verify(pub *ecdsa.PublicKey) bool {
	msg, err := d.SignedMessage()
	return err == nil && VerifySig(pub, msg, d.Sig)
}
