package hub_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/hostryhq/svc-sync/hub"
	"github.com/hostryhq/svc-sync/repository"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// A hub pack built the way identity issues it (HubPackClaims, api-specs 17de74f): signed ES256 with typ hostry-pack+jws under a
// key published in the pack's own identity_public_keys, carrying issuer_env and the outlet's peers.
type packKit struct {
	id, next, other, hubKP, tabA, tabB *sp.KeyPair
	until                              time.Time
}

func newPackKit(t *testing.T) *packKit {
	t.Helper()
	k := &packKit{until: time.Date(2026, 12, 8, 0, 0, 0, 0, time.UTC)}
	for _, p := range []**sp.KeyPair{&k.id, &k.next, &k.other, &k.hubKP, &k.tabA, &k.tabB} {
		kp, err := sp.NewKeyPair("", nil)
		if err != nil {
			t.Fatal(err)
		}
		*p = kp
	}
	k.id.Kid, k.next.Kid, k.other.Kid, k.hubKP.Kid, k.tabA.Kid, k.tabB.Kid = "id-1", "id-2", "id-1", "dev-hub-1", "dev-a-1", "dev-b-1"
	return k
}

func (k *packKit) cred(t *testing.T, signer *sp.KeyPair, dev *sp.KeyPair, id, kind, tenantID string) string {
	t.Helper()
	j, err := sp.SignCredentialJWS(signer, sp.Credential{DeviceID: id, TenantID: tenantID, OutletID: outlet, BrandID: brand, Kind: kind, Kid: dev.Kid,
		Pub: dev.PublicB64(), Store: sp.StoreProtected, NotAfter: k.until.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func jwkKid(kp *sp.KeyPair) hub.Jwk {
	j := hub.JwkOf(&kp.Priv.PublicKey)
	j.Kid = kp.Kid
	return j
}

func (k *packKit) peer(t *testing.T, signer, dev *sp.KeyPair, id string) map[string]any {
	return map[string]any{"device_id": id, "kind": sp.KindPOS, "kid": dev.Kid, "public_key": hub.JwkOf(&dev.Priv.PublicKey), "store": sp.StoreProtected,
		"credential": k.cred(t, signer, dev, id, sp.KindPOS, tenant)}
}

// pack signs claims with signer under the header kid and typ given.
func (k *packKit) pack(t *testing.T, signer *sp.KeyPair, kid, typ string, mod func(c map[string]any)) string {
	t.Helper()
	c := map[string]any{"pack_v": 3, "organisation_id": tenant,
		"device": map[string]any{"device_id": "hub-01", "public_key": hub.JwkOf(&k.hubKP.Priv.PublicKey), "outlet_id": outlet, "brand_id": brand, "kind": sp.KindHub,
			"kid": k.hubKP.Kid, "store": sp.StoreProtected, "credential": k.cred(t, k.id, k.hubKP, "hub-01", sp.KindHub, tenant)},
		"members": []any{}, "revoked_device_ids": []string{}, "intent_table_version": 3,
		"issued_at": "2026-11-25T09:00:00Z", "offline_valid_until": k.until.Format(time.RFC3339), "issuer_env": "dev",
		"peers":                []any{k.peer(t, k.id, k.tabA, "tab-a"), k.peer(t, k.id, k.tabB, "tab-b")},
		"identity_public_keys": []hub.Jwk{jwkKid(k.id), jwkKid(k.next)}, "op_signing_public_key": jwkKid(k.hubKP)}
	if mod != nil {
		mod(c)
	}
	pl, _ := json.Marshal(c)
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": kid, "typ": typ})
	in := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pl)
	sig, err := signer.Sign(in)
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + sig
}

// The whole pack JWS is verified under identity_public_keys (round 7): the kid must be one the pack names, the signature must be
// that key's, and the typ must be a pack's.
func TestVerifyPackChecksTheWholeJWSUnderIdentityPublicKeys(t *testing.T) {
	k := newPackKit(t)
	pol := hub.PackPolicy{Env: "dev"}
	if p, err := hub.VerifyPack(k.pack(t, k.id, "id-1", hub.PackJWSType, nil), "hub-01", pol); err != nil || len(p.Peers) != 2 || p.IssuerEnv != "dev" {
		t.Fatalf("a pack signed by the current identity key: %v %+v", err, p.Peers)
	}
	if _, err := hub.VerifyPack(k.pack(t, k.next, "id-2", hub.PackJWSType, nil), "hub-01", pol); err != nil {
		t.Fatalf("a pack signed by the next identity key: %v", err)
	}
	for _, tc := range []struct {
		name string
		jws  string
	}{
		{"a kid the pack does not publish", k.pack(t, k.id, "id-9", hub.PackJWSType, nil)},
		{"a signature by another key under a published kid", k.pack(t, k.other, "id-1", hub.PackJWSType, nil)},
		{"a credential typ instead of a pack typ", k.pack(t, k.id, "id-1", sp.CredJWSType, nil)},
		{"no kid", k.pack(t, k.id, "", hub.PackJWSType, nil)},
		{"a pack for another device", k.pack(t, k.id, "id-1", hub.PackJWSType, func(c map[string]any) { c["device"].(map[string]any)["device_id"] = "hub-02" })},
	} {
		if _, err := hub.VerifyPack(tc.jws, "hub-01", pol); !errors.Is(err, hub.ErrPack) {
			t.Errorf("%s: got %v, want ErrPack", tc.name, err)
		}
	}
	// A payload changed after signing does not verify.
	good := k.pack(t, k.id, "id-1", hub.PackJWSType, nil)
	parts := splitJWS(good)
	forged := base64.RawURLEncoding.EncodeToString([]byte(`{"pack_v":9}`))
	if _, err := hub.VerifyPack(parts[0]+"."+forged+"."+parts[2], "hub-01", pol); !errors.Is(err, hub.ErrPack) {
		t.Errorf("a changed payload: got %v", err)
	}
}

func splitJWS(s string) [3]string {
	var out [3]string
	n := 0
	start := 0
	for i := 0; i <= len(s) && n < 3; i++ {
		if i == len(s) || s[i] == '.' {
			out[n] = s[start:i]
			n++
			start = i + 1
		}
	}
	return out
}

// issuer_env (round 7): a devlan build refuses a live pack, a live hub refuses a pack from any other environment, a missing or
// unknown claim is refused.
func TestVerifyPackHonoursIssuerEnv(t *testing.T) {
	k := newPackKit(t)
	for _, tc := range []struct {
		name      string
		pol       hub.PackPolicy
		issuerEnv any
		ok        bool
	}{
		{"dev hub, dev pack", hub.PackPolicy{Env: "dev"}, "dev", true},
		{"ci devlan, test pack", hub.PackPolicy{Env: "ci", DevLAN: true}, "test", true},
		{"devlan build, live pack", hub.PackPolicy{Env: "dev", DevLAN: true}, "live", false},
		{"live hub, live pack", hub.PackPolicy{Env: "live"}, "live", true},
		{"live hub, dev pack", hub.PackPolicy{Env: "live"}, "dev", false},
		{"live hub, ci pack", hub.PackPolicy{Env: "live"}, "ci", false},
		{"unknown environment", hub.PackPolicy{Env: "dev"}, "staging", false},
		{"no claim", hub.PackPolicy{Env: "dev"}, nil, false},
	} {
		jws := k.pack(t, k.id, "id-1", hub.PackJWSType, func(c map[string]any) {
			if tc.issuerEnv == nil {
				delete(c, "issuer_env")
				return
			}
			c["issuer_env"] = tc.issuerEnv
		})
		_, err := hub.VerifyPack(jws, "hub-01", tc.pol)
		if tc.ok != (err == nil) {
			t.Errorf("%s: got %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

// A peer entry whose credential does not verify, names another device, another key, another outlet or is a hub refuses the pack.
func TestVerifyPackRefusesAPeerThatIsNotWhatItClaims(t *testing.T) {
	k := newPackKit(t)
	pol := hub.PackPolicy{Env: "dev"}
	withPeer := func(mod func(p map[string]any)) string {
		return k.pack(t, k.id, "id-1", hub.PackJWSType, func(c map[string]any) {
			p := k.peer(t, k.id, k.tabA, "tab-a")
			mod(p)
			c["peers"] = []any{p}
		})
	}
	for name, mod := range map[string]func(p map[string]any){
		"credential signed by a key the pack does not publish": func(p map[string]any) { p["credential"] = k.cred(t, k.hubKP, k.tabA, "tab-a", sp.KindPOS, tenant) },
		"credential of another tenant":                         func(p map[string]any) { p["credential"] = k.cred(t, k.id, k.tabA, "tab-a", sp.KindPOS, "other-tenant") },
		"listed key is not the credential's key":               func(p map[string]any) { p["public_key"] = hub.JwkOf(&k.tabB.Priv.PublicKey) },
		"listed device id is not the credential's":             func(p map[string]any) { p["device_id"] = "tab-z" },
		"a hub as a peer": func(p map[string]any) {
			p["kind"] = sp.KindHub
			p["credential"] = k.cred(t, k.id, k.tabA, "tab-a", sp.KindHub, tenant)
		},
	} {
		if _, err := hub.VerifyPack(withPeer(mod), "hub-01", pol); !errors.Is(err, hub.ErrPack) {
			t.Errorf("%s: got %v, want ErrPack", name, err)
		}
	}
}

// Offline tablet-to-tablet relay needs no cloud contact first (round 7): a hub that restarted with only its stored pack knows the
// outlet's tablets, so it verifies the seal of a tablet that is not connected now; a tablet the pack lists revoked is not known.
func TestApplyPackMakesThePeersKnownOnTheLAN(t *testing.T) {
	k := newPackKit(t)
	ctx := context.Background()
	st, err := repository.Open("file:" + filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := func() time.Time { return time.Date(2026, 11, 25, 9, 0, 0, 0, time.UTC) }
	jws := k.pack(t, k.id, "id-1", hub.PackJWSType, func(c map[string]any) { c["revoked_device_ids"] = []string{"tab-b"} })
	p, err := hub.VerifyPack(jws, "hub-01", hub.PackPolicy{Env: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	h, err := hub.New(ctx, hub.Config{Tenant: tenant, Outlet: outlet, Brand: brand, Cred: sp.CredentialEnvelope{Cred: p.Cred}, CredJWS: p.CredJWS, Key: k.hubKP,
		IdentityPub: p.IdentityKeys[0], Store: st, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := h.Cache().OriginKey("tab-a"); ok {
		t.Fatal("before the pack is applied the hub knows no tablet")
	}
	if err := h.ApplyPack(ctx, p); err != nil {
		t.Fatal(err)
	}
	pub, ok := h.Cache().OriginKey("tab-a")
	if !ok || sp.EncodePub(pub) != k.tabA.PublicB64() {
		t.Fatal("a peer the pack lists must be known with its own key")
	}
	if _, ok := h.Cache().OriginKey("tab-b"); ok {
		t.Fatal("a peer the pack lists revoked must not be known")
	}
	if !h.IsRevoked("tab-b") {
		t.Fatal("revoked in the pack")
	}
}
