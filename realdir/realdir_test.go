package realdir

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/hostryhq/go-auth"
	"github.com/hostryhq/svc-sync/directory"
	"github.com/hostryhq/svc-sync/identityclient"
	"github.com/hostryhq/svc-sync/tenancyclient"
)

const (
	tenant = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a60"
	device = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5e"
	outlet = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a61"
)

// fake answers the identity and tenancy routes the directory calls and counts every request per route.
type fake struct {
	mu     sync.Mutex
	hits   map[string]int
	status map[string]int // forced status per route
	books  string         // JSON items of listOutletManualBookSeries
	feed   string         // JSON of the revocation page
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route := r.Method + " " + r.URL.Path
	f.mu.Lock()
	f.hits[route]++
	st := f.status[route]
	books, feed := f.books, f.feed
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/problem+json")
	if st != 0 {
		w.WriteHeader(st)
		_, _ = w.Write([]byte(`{"type":"urn:hostry:problem:test","title":"x","status":0,"code":"test"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case strings.HasSuffix(r.URL.Path, "/credential") && strings.Contains(r.URL.Path, device):
		_, _ = w.Write([]byte(`{"device_id":"` + device + `","tenant_id":"` + tenant + `","outlet_id":"` + outlet + `","brand_id":"brand-1","kind":"pos","kid":"k1","pub":"BAAA"}`))
	case strings.HasSuffix(r.URL.Path, "/series") && strings.Contains(r.URL.Path, device):
		_, _ = w.Write([]byte(`{"items":[{"id":"s1","tax_registration_id":"r1","code":"A7K","doc_type":"tax_invoice","outlet_id":"` + outlet + `","device_id":"` + device + `","status":"closed_unreconciled","issued_at":"2026-11-24T13:15:11.120Z"}]}`))
	case strings.HasSuffix(r.URL.Path, "/manual-book-series"):
		_, _ = w.Write([]byte(`{"items":` + books + `}`))
	case strings.Contains(r.URL.Path, "/stream-owners/"):
		_, _ = w.Write([]byte(`{"stream_id":"` + outlet + `","kind":"outlet","organisation_id":"` + tenant + `"}`))
	case r.URL.Path == "/internal/v1/revocations":
		_, _ = w.Write([]byte(feed))
	default:
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"type":"urn:hostry:problem:not_found","title":"Not found","status":404,"code":"not_found"}`))
	}
}

func (f *fake) count(route string) int { f.mu.Lock(); defer f.mu.Unlock(); return f.hits[route] }

func newDir(t *testing.T) (*Directory, *fake, *time.Time) {
	t.Helper()
	f := &fake{hits: map[string]int{}, status: map[string]int{}, books: `[]`, feed: `{"items":[]}`}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := &auth.ServiceSigner{Name: identityclient.ServiceName, Key: k}
	ic, err := identityclient.New(srv.URL, signer, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	tc, err := tenancyclient.New(srv.URL, signer, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	nosleep := func(context.Context, time.Duration) {}
	ic.Sleep, tc.Sleep = nosleep, nosleep
	now := time.Date(2026, 11, 25, 6, 0, 0, 0, time.UTC)
	return &Directory{Identity: ic, Tenancy: tc, Clock: func() time.Time { return now }}, f, &now
}

// A3.2 row 1: one key per device id for life, so no expiry; 404 is not cached; an answer for another tenant's token
// is never "found".
func TestCredentialIsCachedForLifeAndANotFoundIsNot(t *testing.T) {
	d, f, _ := newDir(t)
	route := "GET /internal/v1/devices/" + device + "/credential"
	for i := 0; i < 3; i++ {
		c, ok := d.Credential(tenant, device)
		if !ok || c.Cred.Kid != "k1" || c.Cred.OutletID != outlet {
			t.Fatalf("credential: %+v %v", c, ok)
		}
	}
	if n := f.count(route); n != 1 {
		t.Fatalf("a found credential is asked once, not %d times", n)
	}
	if _, ok := d.Credential("0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a99", device); ok {
		t.Fatal("the credential belongs to the token's tenant only")
	}
	other := "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a77"
	for i := 0; i < 2; i++ {
		if _, ok := d.Credential(tenant, other); ok {
			t.Fatal("unknown device")
		}
	}
	if n := f.count("GET /internal/v1/devices/" + other + "/credential"); n != 2 {
		t.Fatalf("404 is not cached: %d requests for 2 lookups", n)
	}
	if d.Faults() != 0 {
		t.Fatal("a 404 is an answer, not a fault")
	}
}

// The failure rule: a lookup that cannot be asked answers "not found" to the caller and counts a fault, so that the
// gateway can make the op wait; a refused service token (401, 403) is a fault too.
func TestAnUnaskableLookupIsAFaultNeverAnAnswer(t *testing.T) {
	d, f, _ := newDir(t)
	route := "GET /internal/v1/devices/" + device + "/credential"
	for _, st := range []int{http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusUnauthorized, http.StatusForbidden} {
		f.mu.Lock()
		f.status[route] = st
		f.mu.Unlock()
		before := d.Faults()
		if _, ok := d.Credential(tenant, device); ok {
			t.Fatalf("status %d must not read as found", st)
		}
		if d.Faults() == before {
			t.Fatalf("status %d must count a fault", st)
		}
	}
	f.mu.Lock()
	f.status[route] = 0
	f.mu.Unlock()
	if _, ok := d.Credential(tenant, device); !ok {
		t.Fatal("answered once identity is back")
	}
}

// A3.2 row 8: the series of a device by device, then the paper books of its outlet; cached 60 seconds and dropped on
// the event; closed_unreconciled is closed; a code of nobody is not found.
func TestSeriesComeFromTheDeviceThenTheOutletBooksAndAreCached60Seconds(t *testing.T) {
	d, f, now := newDir(t)
	f.mu.Lock()
	f.books = `[{"id":"b1","tax_registration_id":"r1","code":"BKB","outlet_ids":["` + outlet + `"],"status":"active","created_at":"2026-11-24T13:05:11.120Z"}]`
	f.mu.Unlock()
	si, ok := d.SeriesFor(tenant, device, outlet, "A7K")
	if !ok || si.Device != device || si.State != directory.SeriesClosed || si.DocType != "tax_invoice" || si.ManualBook() {
		t.Fatalf("device series: %+v %v", si, ok)
	}
	bk, ok := d.SeriesFor(tenant, device, outlet, "BKB")
	if !ok || !bk.ManualBook() || bk.Device != "" || len(bk.Outlets) != 1 {
		t.Fatalf("paper book: %+v %v", bk, ok)
	}
	if _, ok := d.SeriesFor(tenant, device, outlet, "ZZZ"); ok {
		t.Fatal("a code of nobody is not found (the gateway holds it as foreign_series)")
	}
	route := "GET /internal/v1/devices/" + device + "/series"
	if n := f.count(route); n != 1 {
		t.Fatalf("one listDeviceSeries for three lookups, got %d", n)
	}
	*now = now.Add(61 * time.Second)
	d.SeriesFor(tenant, device, outlet, "A7K")
	if n := f.count(route); n != 2 {
		t.Fatalf("expired after 60 seconds: %d requests", n)
	}
	booksRoute := "GET /internal/v1/outlets/" + outlet + "/manual-book-series"
	before := f.count(booksRoute)
	d.SeriesFor(tenant, device, outlet, "BKB")
	d.SeriesFor(tenant, device, outlet, "BKB")
	if f.count(booksRoute) != before+1 {
		t.Fatal("books cached within the 60 seconds")
	}
	d.DropBooks(tenant, outlet) // tenancy.manual_book.registered
	d.SeriesFor(tenant, device, outlet, "BKB")
	if f.count(booksRoute) != before+2 {
		t.Fatal("the event drops the cached books")
	}
}

// A3.2 row 5: the feed is the only source of revocation, with its reason; the cursor and the set are persisted and a
// restarted directory knows them; a session on the feed ends the strong session.
func TestRevocationFeedKeepsReasonAndSurvivesARestart(t *testing.T) {
	d, f, _ := newDir(t)
	d.StateFile = filepath.Join(t.TempDir(), "state.json")
	if err := d.Ready(); err == nil {
		t.Fatal("not ready before the feed was read")
	}
	f.mu.Lock()
	f.feed = `{"items":[{"id":"r1","subject_type":"device","subject_id":"` + device + `","organisation_id":"` + tenant + `","revoked_at":"2026-11-25T05:00:00Z","reason":"key_lost","recovery_id":"rec-1"},` +
		`{"id":"r2","subject_type":"session","subject_id":"sess-1","organisation_id":"` + tenant + `","revoked_at":"2026-11-25T05:10:00Z"}]}`
	f.mu.Unlock()
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rev, why := d.Revoked(tenant, device); !rev || why != "key_lost" {
		t.Fatalf("revoked: %v %q", rev, why)
	}
	if rev, _ := d.Revoked("0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a99", device); rev {
		t.Fatal("the entry belongs to its organisation only")
	}
	if err := d.Ready(); err != nil {
		t.Fatal(err)
	}
	again := &Directory{Identity: d.Identity, Tenancy: d.Tenancy, Clock: d.Clock, StateFile: d.StateFile}
	if rev, why := again.Revoked(tenant, device); !rev || why != "key_lost" {
		t.Fatalf("after a restart: %v %q", rev, why)
	}
	if err := again.Ready(); err != nil {
		t.Fatalf("a restart with persisted state is ready: %v", err)
	}
	if _, lk := again.StrongSession(tenant, "sess-1"); lk != directory.NotFound && lk != directory.Unreachable {
		t.Fatalf("a session identity cannot show is not found: %v", lk)
	}
	if rev, _ := again.Revoked(tenant, "other"); rev {
		t.Fatal("only what the feed named")
	}
}

// An outlet or brand stream belongs to the tenant when tenancy says so; found is cached for life.
func TestStreamInTenantAsksTenancyOnce(t *testing.T) {
	d, f, _ := newDir(t)
	for i := 0; i < 3; i++ {
		if !d.StreamInTenant(tenant, "outlet:"+outlet) {
			t.Fatal("the outlet is the tenant's")
		}
	}
	if d.StreamInTenant(tenant, "brand:"+outlet) {
		t.Fatal("the id names an outlet, not a brand")
	}
	if d.StreamInTenant(tenant, "tenant:"+tenant) || d.StreamInTenant(tenant, "outlet:") {
		t.Fatal("only outlet and brand streams are tenancy's to name")
	}
	if n := f.count("GET /internal/v1/stream-owners/" + outlet); n != 1 {
		t.Fatalf("asked %d times", n)
	}
}
