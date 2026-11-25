package double

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hostryhq/svc-sync/contract/suite"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

func target(t *testing.T, d *Double) suite.Target {
	t.Helper()
	return suite.Target{
		Handler: d.Handler(), Tenant: Tenant, Outlet: Outlet, Now: d.Now,
		IdentityPub: d.Identity.IdentityPub(), CloudPub: &d.Identity.CloudKey.Priv.PublicKey,
		NewPOS: func() (suite.Dev, error) {
			v, err := d.NewDevice(sp.KindPOS)
			if err != nil {
				return suite.Dev{}, err
			}
			return suite.Dev{ID: v.ID, Key: v.Key, Cred: v.Cred, SaleCode: v.Sale, Token: v.Token, DrainToken: v.DrainToken}, nil
		},
	}
}

func TestDoublePassesTheSharedContractSuite(t *testing.T) {
	d, err := New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	suite.Run(t, target(t, d))
}

func TestFailureInjectionAnswers5xxThenRecovers(t *testing.T) {
	d, err := New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	v, _ := d.NewDevice(sp.KindPOS)
	call := func() int {
		req := httptest.NewRequest(http.MethodPost, "/sync/v1/hello", strings.NewReader(`{"protocol":1}`))
		req.Header.Set("Authorization", "Bearer "+v.Token())
		rec := httptest.NewRecorder()
		d.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	d.FailNext(2, http.StatusServiceUnavailable)
	if a, b, c := call(), call(), call(); a != 503 || b != 503 || c != 200 {
		t.Fatalf("got %d %d %d", a, b, c)
	}
}
