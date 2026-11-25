// Command devstack runs a local gateway and hub on real HTTP ports with the identity stub and a
// test token issuer, and writes the fixture the client-core end-to-end test reads
// (SYNC_E2E_FIXTURE). Dev and test only: the keys here are generated per run and nothing is a
// secret. Deployment is out of scope (ADR-0001 AM12).
//
//	go run ./cmd/devstack -out /tmp/sync-fixture.json
package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/go-auth/authtest"
	"github.com/hostryhq/go-common/clock"
	"github.com/hostryhq/go-common/ids"
	"github.com/hostryhq/svc-sync/api"
	"github.com/hostryhq/svc-sync/devepoch"
	"github.com/hostryhq/svc-sync/directory"
	"github.com/hostryhq/svc-sync/engine"
	"github.com/hostryhq/svc-sync/hub"
	"github.com/hostryhq/svc-sync/identitystub"
	"github.com/hostryhq/svc-sync/repository"
	"github.com/hostryhq/svc-sync/service"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

func main() {
	cloudAddr := flag.String("cloud", "127.0.0.1:8081", "gateway listen address")
	hubAddr := flag.String("hub", "127.0.0.1:8082", "hub listen address")
	out := flag.String("out", "sync-fixture.json", "fixture file to write")
	dsn := flag.String("db", "file:"+os.TempDir()+"/devstack-cloud.db", "gateway store (sqlite path or postgres:// DSN)")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	now := time.Now
	id, err := identitystub.New(now, nil)
	check(err)
	issuer := authtest.NewTenantIssuer(clock.Func(now))
	tenant, outlet, brand := "018f0000-0000-7000-8000-0000000000a0", "018f0000-0000-7000-8000-0000000000a1", "018f0000-0000-7000-8000-0000000000b1"
	id.SetMember(tenant, "m1", "order.create", "payment.take", "bill.finalize", "bill.refund", "stock.adjust", "kds.update", "session.open", "menu.edit")

	st, err := repository.Open(*dsn)
	check(err)
	ep, err := devepoch.Reader(ctx, *dsn)
	check(err)
	gw, err := service.New(ctx, service.Config{Store: st, Epoch: ep, Dir: id, OpKey: id.CloudKey, Now: now})
	check(err)
	mux := http.NewServeMux()
	api.Mount(mux, api.Options{Auth: api.BearerAuth{Verifier: issuer.Verifier(), Dir: id}, Backend: api.GatewayBackend{G: gw}})
	services := authtest.NewServiceRegistry(clock.Func(now), "admin", "sync")
	api.Admin(mux, gw, api.AdminAuth{Tenant: issuer.Verifier(), Services: services.Verifier("sync"), Audit: &repository.AccessSink{S: st}, Clock: clock.Func(now)})
	cloudURL := serve(ctx, *cloudAddr, mux)

	fx := map[string]any{"cloud_url": cloudURL, "tenant_id": tenant, "outlet_id": outlet,
		"identity_pub": sp.EncodePub(id.IdentityPub()),
		"cloud_keys":   map[string]string{id.CloudKey.Kid: id.CloudKey.PublicB64()}}

	var devices []map[string]any
	var peers []sp.CredentialEnvelope
	for _, name := range []string{"dev-a", "dev-b"} {
		kp, err := sp.NewKeyPair("k-"+name, nil)
		check(err)
		cred, err := id.Activate(tenant, outlet, brand, name, sp.KindPOS, kp, "")
		check(err)
		peers = append(peers, cred)
		sale := id.IssueSeries(tenant, name, "tax_invoice", directory.SeriesActive)
		cn := id.IssueSeries(tenant, name, "credit_note", directory.SeriesActive)
		id.IssuePack(tenant, name, "p1", 30*24*time.Hour)
		pk, err := x509.MarshalPKCS8PrivateKey(kp.Priv)
		check(err)
		devices = append(devices, map[string]any{"device_id": name, "kid": kp.Kid, "pub": kp.PublicB64(),
			"pkcs8": base64.RawURLEncoding.EncodeToString(pk), "cred": cred,
			"token":  issuer.Mint(authtest.Spec{Type: auth.TypeDevice, Tenant: ids.ID(tenant), Device: name, TTL: 14 * time.Minute}),
			"series": []map[string]string{{"code": sale, "docType": "tax_invoice", "state": "active"}, {"code": cn, "docType": "credit_note", "state": "active"}}})
	}
	fx["devices"] = devices

	hubKey, err := sp.NewKeyPair("k-hub", nil)
	check(err)
	hubCred, err := id.Activate(tenant, outlet, brand, "hub-01", sp.KindHub, hubKey, "")
	check(err)
	fx["hub"] = map[string]any{"cred": hubCred}
	hst, err := repository.Open(":memory:")
	check(err)
	h, err := hub.New(ctx, hub.Config{Tenant: tenant, Outlet: outlet, Brand: brand, Cred: hubCred, Key: hubKey, IdentityPub: id.IdentityPub(),
		CloudKeys: map[string]*hub.PubKey{id.CloudKey.Kid: &id.CloudKey.Priv.PublicKey}, Store: hst, Now: now, Peers: peers,
		Members:     func(a string) bool { return id.InAnyPackOf(tenant, outlet, a) },
		SeriesOwner: func(c string) (string, bool) { s, ok := id.Series(tenant, c); return s.Device, ok }})
	check(err)
	up := &engine.HTTPTransport{Base: cloudURL, Authorize: func(r *http.Request, _ []byte) error {
		r.Header.Set("Authorization", "Bearer "+issuer.Mint(authtest.Spec{Type: auth.TypeDevice, Tenant: ids.ID(tenant), Device: "hub-01"}))
		return nil
	}}
	h.SetUpstream(up)
	go h.RunUpstream(ctx, 500*time.Millisecond)
	fx["hub_url"] = serve(ctx, *hubAddr, h.Handler())

	hpk, err := x509.MarshalPKCS8PrivateKey(hubKey.Priv)
	check(err)
	hp := hub.Pack{Tenant: tenant, Outlet: outlet, Brand: brand, Cred: hubCred, PKCS8: base64.RawURLEncoding.EncodeToString(hpk),
		IdentityPub: sp.EncodePub(id.IdentityPub()), CloudKeys: map[string]string{id.CloudKey.Kid: id.CloudKey.PublicB64()}, Peers: peers,
		Members: []string{"m1"}, SeriesOwner: map[string]string{}, CloudURL: cloudURL}
	for _, d := range devices {
		for _, sr := range d["series"].([]map[string]string) {
			hp.SeriesOwner[sr["code"]] = d["device_id"].(string)
		}
	}
	hraw, _ := json.MarshalIndent(hp, "", "  ")
	check(os.WriteFile(*out+".hub-pack.json", hraw, 0o600))
	raw, _ := json.MarshalIndent(fx, "", "  ")
	check(os.WriteFile(*out, raw, 0o600))
	fmt.Printf("devstack up: cloud %s hub %s fixture %s\n", cloudURL, fx["hub_url"], *out)
	<-ctx.Done()
}

func serve(ctx context.Context, addr string, h http.Handler) string {
	ln, err := net.Listen("tcp", addr)
	check(err)
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	go func() { <-ctx.Done(); _ = srv.Shutdown(context.Background()) }()
	return "http://" + ln.Addr().String()
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
