package sim

import (
	"fmt"
	"testing"

	"github.com/hostryhq/svc-sync/contract/suite"
	sp "github.com/hostryhq/svc-sync/syncproto"
)

// The shared contract suite against the real gateway service.
func TestRealGatewayPassesTheSharedContractSuite(t *testing.T) {
	w, _ := newTestWorld(t, 51, WorldOptions{Pos: 0, NoHub: true})
	n := 0
	suite.Run(t, suite.Target{
		Handler: w.CloudH, Tenant: w.Tenant, Outlet: w.Outlet, Now: w.Clock.Now,
		IdentityPub: w.Identity.IdentityPub(), CloudPub: &w.Identity.CloudKey.Priv.PublicKey,
		NewPOS: func() (suite.Dev, error) {
			n++
			d, err := w.AddDevice(fmt.Sprintf("dev-c%02d-pos", n), sp.KindPOS)
			if err != nil {
				return suite.Dev{}, err
			}
			return suite.Dev{ID: d.ID, Key: d.Key, Cred: d.Cred, SaleCode: d.SaleCode(),
				Token:      func() string { return w.Token("device", d.ID, "") },
				DrainToken: func(r string) string { return d.DrainToken(r) }}, nil
		},
	})
}
