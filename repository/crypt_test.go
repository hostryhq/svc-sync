package repository_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/hostryhq/svc-sync/keyprotect"
	"github.com/hostryhq/svc-sync/repository"
)

const tenant = "t-hub"

func devProvider(t *testing.T, dir, name string) *keyprotect.Dev {
	t.Helper()
	p, err := keyprotect.NewDev("test", filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func openEnc(t *testing.T, dir string, p keyprotect.Provider) *repository.SQL {
	t.Helper()
	s, err := repository.OpenEncrypted("file:"+filepath.Join(dir, "hub.db"), repository.EncryptOptions{Provider: p})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func fileHas(t *testing.T, dir string, needles ...string) []string {
	t.Helper()
	var found []string
	for _, n := range []string{"hub.db", "hub.db-wal"} {
		raw, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		for _, nd := range needles {
			if bytes.Contains(raw, []byte(nd)) {
				found = append(found, n+": "+nd)
			}
		}
	}
	return found
}

// HS1 (the part that runs on Linux): the database file and its write-ahead log hold no customer phone, name, salt or item price
// in the clear, and another key provider cannot open the store.
func TestHubStoreHoldsNoValueInTheClear(t *testing.T) {
	dir := t.TempDir()
	p := devProvider(t, dir, "key")
	s := openEnc(t, dir, p)
	ctx := context.Background()
	body := `{"muts":[{"e":"item","f":{"price_paise":48750,"name":"Butter Chicken Special"}}]}`
	pii := `{"customer":{"c1":{"phone":"+919812345678","name":"Meenakshi Sundaram","~s:phone":"c2FsdHNhbHQ"}}}`
	if err := s.InTx(ctx, tenant, func(tx repository.Tx) error {
		if err := tx.PutOp(repository.OpRec{Stream: "outlet:o", Origin: "d1", Seq: 1, H: "h1", PH: "p", Body: body, Status: "accepted"}); err != nil {
			return err
		}
		if err := tx.PutPII("outlet:o", "d1", 1, pii); err != nil {
			return err
		}
		return tx.SetMeta("pack", `{"member":"Asha Kumar"}`)
	}); err != nil {
		t.Fatal(err)
	}
	var gotBody, gotPII string
	if err := s.InTx(ctx, tenant, func(tx repository.Tx) error {
		o, _, err := tx.GetOp("outlet:o", "d1", 1)
		gotBody = o.Body
		gotPII, _, _ = tx.GetPII("outlet:o", "d1", 1)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if gotBody != body || gotPII != pii {
		t.Fatalf("decryption must return the exact bytes: %q %q", gotBody, gotPII)
	}
	_ = s.Checkpoint(ctx)
	if f := fileHas(t, dir, "+919812345678", "Meenakshi", "c2FsdHNhbHQ", "48750", "Butter Chicken", "Asha Kumar"); len(f) > 0 {
		t.Fatalf("value found in the clear: %v", f)
	}
	_ = s.Close()
	other, _ := keyprotect.NewDev("test", filepath.Join(dir, "other-key"))
	if _, err := repository.OpenEncrypted("file:"+filepath.Join(dir, "hub.db"), repository.EncryptOptions{Provider: other}); !errors.Is(err, keyprotect.ErrUnwrap) {
		t.Fatalf("a store opened with another key provider: %v", err)
	}
	s2 := openEnc(t, dir, p) // the right provider reopens it and reads the same value
	defer s2.Close()
	if err := s2.InTx(ctx, tenant, func(tx repository.Tx) error {
		v, ok, err := tx.GetMeta("pack")
		if err != nil || !ok || v != `{"member":"Asha Kumar"}` {
			t.Fatalf("meta after reopen: %q %v %v", v, ok, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// HS2: a ciphertext copied to another row fails to open.
func TestCiphertextCopiedToAnotherRowFailsAsTampered(t *testing.T) {
	dir := t.TempDir()
	s := openEnc(t, dir, devProvider(t, dir, "key"))
	defer s.Close()
	ctx := context.Background()
	if err := s.InTx(ctx, tenant, func(tx repository.Tx) error {
		if err := tx.PutPII("outlet:o", "d1", 1, `{"customer":{"a":{"phone":"1"}}}`); err != nil {
			return err
		}
		return tx.PutPII("outlet:o", "d1", 2, `{"customer":{"b":{"phone":"2"}}}`)
	}); err != nil {
		t.Fatal(err)
	}
	var c1 string
	if err := s.DB().QueryRow(`SELECT data FROM op_pii WHERE seq=1`).Scan(&c1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`UPDATE op_pii SET data=? WHERE seq=2`, c1); err != nil {
		t.Fatal(err)
	}
	err := s.InTx(ctx, tenant, func(tx repository.Tx) error {
		_, _, err := tx.GetPII("outlet:o", "d1", 2)
		return err
	})
	if !errors.Is(err, repository.ErrTampered) {
		t.Fatalf("a moved ciphertext read as %v, want ErrTampered", err)
	}
}

// HS3: after an erasure neither the database file nor its write-ahead log holds the ciphertext of the erased value.
func TestErasedValueLeavesNoCiphertextInTheFileOrTheWAL(t *testing.T) {
	dir := t.TempDir()
	s := openEnc(t, dir, devProvider(t, dir, "key"))
	defer s.Close()
	ctx := context.Background()
	if err := s.InTx(ctx, tenant, func(tx repository.Tx) error {
		return tx.PutPII("outlet:o", "d1", 1, `{"customer":{"a":{"phone":"+919800000001","~s:phone":"c2FsdA"}}}`)
	}); err != nil {
		t.Fatal(err)
	}
	var ct string
	if err := s.DB().QueryRow(`SELECT data FROM op_pii WHERE seq=1`).Scan(&ct); err != nil {
		t.Fatal(err)
	}
	if err := s.Checkpoint(ctx); err != nil {
		t.Fatal(err)
	}
	if len(fileHas(t, dir, ct)) == 0 {
		t.Fatal("the test cannot see the ciphertext in the file before the erasure")
	}
	if err := s.InTx(ctx, tenant, func(tx repository.Tx) error { return tx.ErasePII("outlet:o", "d1", 1) }); err != nil {
		t.Fatal(err)
	}
	if f := fileHas(t, dir, ct); len(f) > 0 {
		t.Fatalf("erased ciphertext still present: %v", f)
	}
}
