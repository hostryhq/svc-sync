package identitystub

import (
	"fmt"
	"strings"
	"sync"
)

// declared holds streams a test declares for a tenant before any device exists there (a brand
// stream that only a cloud emit writes to). Keyed by identity pointer, tenant and stream.
var declared sync.Map

// DeclareStream registers an outlet or brand stream of a tenant, as tenancy would know it.
func (i *Identity) DeclareStream(tenant, stream string) {
	declared.Store(fmt.Sprintf("%p|%s|%s", i, tenant, stream), true)
}

// StreamInTenant implements service.StreamInTenant: an outlet or brand stream belongs to a tenant
// when a device of the tenant is bound to it or the stream was declared. Another tenant's stream is
// not found.
func (i *Identity) StreamInTenant(tenant, stream string) bool {
	if _, ok := declared.Load(fmt.Sprintf("%p|%s|%s", i, tenant, stream)); ok {
		return true
	}
	kind, id, ok := strings.Cut(stream, ":")
	if !ok {
		return false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, d := range i.devices {
		c := d.Env.Cred
		if c.TenantID != tenant {
			continue
		}
		if (kind == "outlet" && c.OutletID == id) || (kind == "brand" && c.BrandID == id) {
			return true
		}
	}
	return false
}
