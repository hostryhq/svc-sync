package repository

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hostryhq/svc-sync/keyprotect"
)

// Column encryption of the hub store (ADR-0002 A3.2). Every column that carries a field value is AES-256-GCM sealed under a
// random 256-bit data key: op bodies, personal data (values and salts), meta values (the stored pack, markers), fork
// evidence, alert details and approval-verdict reasons (round 7: both can quote an operator's words). Ids, sequence numbers, clocks, hashes, seals, commitments and intent names stay clear because the hub indexes on
// them. The table, primary key, column and key id are bound as associated data, so a ciphertext copied to another row fails to
// open. The data keys are wrapped by a keyprotect.Provider and stored beside the data; a new data key is made every 90 days.

const (
	encPrefix = "enc1."
	// DataKeyPeriod is how long a data key encrypts new values.
	DataKeyPeriod = 90 * 24 * time.Hour
)

// ErrTampered is returned when a stored value does not open: another row's ciphertext, a changed byte, or a plaintext value in
// an encrypted store.
var ErrTampered = errors.New("repository: stored value failed authentication (tampered or moved)")

type colCipher struct {
	keys map[string][]byte // key id -> 256-bit data key
	cur  string
}

// EncryptOptions open a store with column encryption.
type EncryptOptions struct {
	Provider keyprotect.Provider
	// Now is the clock for the data-key period (default time.Now).
	Now func() time.Time
}

// OpenEncrypted opens a SQLite store whose value columns are encrypted (the hub). A provider that cannot unwrap the stored data
// keys (another Windows user, another machine) makes the open fail.
func OpenEncrypted(dsn string, o EncryptOptions) (*SQL, error) {
	if o.Provider == nil {
		return nil, errors.New("repository: encrypted store needs a key provider")
	}
	s, err := Open(dsn)
	if err != nil {
		return nil, err
	}
	if s.pg {
		_ = s.Close()
		return nil, errors.New("repository: column encryption is the hub's (SQLite) store")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	c, err := s.loadKeys(context.Background(), o)
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	s.crypt = c
	return s, nil
}

func (s *SQL) loadKeys(ctx context.Context, o EncryptOptions) (*colCipher, error) {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS data_keys (key_id TEXT PRIMARY KEY, wrapped TEXT NOT NULL, created_at BIGINT NOT NULL)`); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT key_id, wrapped, created_at FROM data_keys ORDER BY created_at, key_id`)
	if err != nil {
		return nil, err
	}
	c := &colCipher{keys: map[string][]byte{}}
	var newest int64
	for rows.Next() {
		var id, w string
		var at int64
		if err := rows.Scan(&id, &w, &at); err != nil {
			_ = rows.Close()
			return nil, err
		}
		raw, err := base64.RawURLEncoding.DecodeString(w)
		if err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("repository: data key %s: %w", id, err)
		}
		k, err := o.Provider.Unwrap(raw)
		if err != nil || len(k) != 32 {
			_ = rows.Close()
			return nil, fmt.Errorf("repository: data key %s does not unwrap with this key provider: %w", id, keyprotect.ErrUnwrap)
		}
		c.keys[id] = k
		if at >= newest {
			newest, c.cur = at, id
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	_ = rows.Close()
	now := o.Now()
	if c.cur == "" || now.Sub(time.Unix(newest, 0)) >= DataKeyPeriod {
		k := make([]byte, 32)
		idb := make([]byte, 8)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		if _, err := rand.Read(idb); err != nil {
			return nil, err
		}
		id := base64.RawURLEncoding.EncodeToString(idb)
		w, err := o.Provider.Wrap(k)
		if err != nil {
			return nil, err
		}
		if _, err := s.db.ExecContext(ctx, `INSERT INTO data_keys (key_id, wrapped, created_at) VALUES (?,?,?)`, id, base64.RawURLEncoding.EncodeToString(w), now.Unix()); err != nil {
			return nil, err
		}
		c.keys[id], c.cur = k, id
	}
	return c, nil
}

// PruneDataKeys destroys the data keys that no stored value cites (A3.2 item 2).
func (s *SQL) PruneDataKeys(ctx context.Context) error {
	if s.crypt == nil {
		return nil
	}
	for id := range s.crypt.keys {
		if id == s.crypt.cur {
			continue
		}
		cited := false
		for _, q := range []string{`SELECT 1 FROM ops WHERE substr(body,1,?)=? LIMIT 1`, `SELECT 1 FROM op_pii WHERE substr(data,1,?)=? LIMIT 1`, `SELECT 1 FROM meta WHERE substr(v,1,?)=? LIMIT 1`, `SELECT 1 FROM forks WHERE substr(body,1,?)=? LIMIT 1`,
			`SELECT 1 FROM alerts WHERE substr(detail,1,?)=? LIMIT 1`, `SELECT 1 FROM approval_verdicts WHERE substr(reason,1,?)=? LIMIT 1`} {
			p := encPrefix + id + "."
			var one int
			err := s.db.QueryRowContext(ctx, q, len(p), p).Scan(&one)
			if err == nil {
				cited = true
				break
			}
		}
		if !cited {
			if _, err := s.db.ExecContext(ctx, `DELETE FROM data_keys WHERE key_id=?`, id); err != nil {
				return err
			}
			delete(s.crypt.keys, id)
		}
	}
	return nil
}

func aad(table, pk, col, kid string) []byte {
	return []byte(table + "\x00" + pk + "\x00" + col + "\x00" + kid)
}

// seal encrypts v for one column of one row. An empty value (a placeholder) stays empty.
func (s *SQL) seal(table, pk, col, v string) (string, error) {
	if s.crypt == nil || v == "" {
		return v, nil
	}
	c := s.crypt
	b, err := aes.NewCipher(c.keys[c.cur])
	if err != nil {
		return "", err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return "", err
	}
	n := make([]byte, g.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return "", err
	}
	return encPrefix + c.cur + "." + base64.RawURLEncoding.EncodeToString(g.Seal(n, n, []byte(v), aad(table, pk, col, c.cur))), nil
}

// open decrypts a stored value; it returns exactly the bytes that were sealed.
func (s *SQL) open(table, pk, col, v string) (string, error) {
	if s.crypt == nil || v == "" {
		return v, nil
	}
	rest, ok := strings.CutPrefix(v, encPrefix)
	if !ok {
		return "", ErrTampered
	}
	kid, blob, ok := strings.Cut(rest, ".")
	key := s.crypt.keys[kid]
	if !ok || key == nil {
		return "", ErrTampered
	}
	raw, err := base64.RawURLEncoding.DecodeString(blob)
	if err != nil {
		return "", ErrTampered
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	g, err := cipher.NewGCM(b)
	if err != nil || len(raw) < g.NonceSize() {
		return "", ErrTampered
	}
	p, err := g.Open(nil, raw[:g.NonceSize()], raw[g.NonceSize():], aad(table, pk, col, kid))
	if err != nil {
		return "", ErrTampered
	}
	return string(p), nil
}

func pkOp(tenant, stream, origin string, seq int64) string {
	return fmt.Sprintf("%s|%s|%s|%d", tenant, stream, origin, seq)
}

// Encrypted reports whether the store seals its value columns.
func (s *SQL) Encrypted() bool { return s.crypt != nil }

// Checkpoint truncates the SQLite write-ahead log, so that pages freed by an erasure are not left in it.
func (s *SQL) Checkpoint(ctx context.Context) error {
	if s.pg {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}
