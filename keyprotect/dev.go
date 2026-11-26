package keyprotect

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"strings"
)

// Dev is the NON-PRODUCTION provider: a key-encryption key read from a file or from the environment, held beside the data it
// protects. It exists so that Linux CI and the soak can run the encrypted hub store. It protects nothing against anyone who can
// read the hub's files, so a hub using it declares `store: unprotected`, and NewDev refuses outside HOSTRY_ENV dev, test, ci.
type Dev struct{ kek [32]byte }

// DevEnvVar names the environment variable that may hold the dev key (any text; it is hashed to 256 bits).
const DevEnvVar = "SYNC_HUB_DEV_KEY"

// NewDev builds the dev provider from a key file (created with a random key when absent) or, when keyFile is empty, from
// DevEnvVar. env is the value of HOSTRY_ENV.
func NewDev(env, keyFile string) (*Dev, error) {
	if !devEnvOK(env) {
		return nil, errDevEnv(env)
	}
	var seed []byte
	switch {
	case keyFile != "":
		b, err := os.ReadFile(keyFile)
		if errors.Is(err, os.ErrNotExist) {
			raw := make([]byte, 32)
			if _, err = rand.Read(raw); err == nil {
				// The seed is the persisted text, which is what the next process reads back and hashes.
				b = []byte(base64.RawURLEncoding.EncodeToString(raw))
				err = os.WriteFile(keyFile, b, 0o600)
			}
		}
		if err != nil {
			return nil, err
		}
		seed = b
	case os.Getenv(DevEnvVar) != "":
		seed = []byte(os.Getenv(DevEnvVar))
	default:
		return nil, errors.New("keyprotect: the dev provider needs a key file or " + DevEnvVar)
	}
	return &Dev{kek: sha256.Sum256([]byte(strings.TrimSpace(string(seed))))}, nil
}

// Tier implements Provider.
func (*Dev) Tier() string { return TierDev }

func (d *Dev) aead() cipher.AEAD {
	b, _ := aes.NewCipher(d.kek[:])
	g, _ := cipher.NewGCM(b)
	return g
}

// Wrap implements Provider.
func (d *Dev) Wrap(secret []byte) ([]byte, error) {
	g := d.aead()
	n := make([]byte, g.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return g.Seal(n, n, secret, []byte("hostry-keyprotect-dev")), nil
}

// Unwrap implements Provider.
func (d *Dev) Unwrap(w []byte) ([]byte, error) {
	g := d.aead()
	if len(w) < g.NonceSize() {
		return nil, ErrUnwrap
	}
	p, err := g.Open(nil, w[:g.NonceSize()], w[g.NonceSize():], []byte("hostry-keyprotect-dev"))
	if err != nil {
		return nil, ErrUnwrap
	}
	return p, nil
}
