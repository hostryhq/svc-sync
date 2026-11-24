package syncproto

// Intent classes (S4, S11).
const (
	ClassTrading = "trading"
	ClassConfig  = "config"
	ClassControl = "control"
)

// Intent is one row of the intent registry (S4). The real registry is api-specs/sync/intents/*.yaml
// and generates the client `can()` table, the gateway check and the hub structural check; this is
// the demo subset used by the PoC and the simulator.
type Intent struct {
	Name       string `json:"name"`
	Class      string `json:"class"`
	Permission string `json:"permission"`
	// Kinds are the device kinds allowed to record it.
	Kinds []string `json:"kinds"`
	// Doc is the document type the intent allocates a legal number for.
	Doc string `json:"doc,omitempty"`
	// MaxV is the highest intent_v the gateway has an upcaster for (S13).
	MaxV int `json:"max_v"`
	// ConfigOnly sessions: sessions allowed to record it ("" means any).
	Sessions []string `json:"sessions,omitempty"`
}

var (
	billingKinds = []string{KindPOS, KindWaiter}
	floorKinds   = []string{KindPOS, KindWaiter, KindKDS}
)

// Intents is the demo registry.
var Intents = map[string]Intent{
	"session.open":     {Name: "session.open", Class: ClassControl, Permission: "session.open", Kinds: floorKinds, MaxV: 1},
	"approval.grant":   {Name: "approval.grant", Class: ClassControl, Permission: "approval.grant", Kinds: billingKinds, MaxV: 1},
	"series.activate":  {Name: "series.activate", Class: ClassControl, Permission: "series.activate", Kinds: billingKinds, MaxV: 1},
	"order.create":     {Name: "order.create", Class: ClassTrading, Permission: "order.create", Kinds: billingKinds, MaxV: 1},
	"order.line.add":   {Name: "order.line.add", Class: ClassTrading, Permission: "order.create", Kinds: billingKinds, MaxV: 1},
	"kot.send":         {Name: "kot.send", Class: ClassTrading, Permission: "order.create", Kinds: billingKinds, MaxV: 1},
	"kds.status":       {Name: "kds.status", Class: ClassTrading, Permission: "kds.update", Kinds: floorKinds, MaxV: 1},
	"bill.finalize":    {Name: "bill.finalize", Class: ClassTrading, Permission: "bill.finalize", Kinds: billingKinds, Doc: "tax_invoice", MaxV: 1},
	"creditnote.issue": {Name: "creditnote.issue", Class: ClassTrading, Permission: "bill.refund", Kinds: billingKinds, Doc: "credit_note", MaxV: 1},
	"payment.record":   {Name: "payment.record", Class: ClassTrading, Permission: "payment.take", Kinds: billingKinds, MaxV: 1},
	"stock.move":       {Name: "stock.move", Class: ClassTrading, Permission: "stock.adjust", Kinds: billingKinds, MaxV: 1},
	"menu.item.edit":   {Name: "menu.item.edit", Class: ClassConfig, Permission: "menu.edit", Kinds: billingKinds, MaxV: 1},
	"menu.price.set":   {Name: "menu.price.set", Class: ClassConfig, Permission: "menu.edit", Kinds: billingKinds, MaxV: 1},
	// Names used by the TypeScript client demo (client-core src/sync); same classes and permissions.
	"stock.out":         {Name: "stock.out", Class: ClassTrading, Permission: "stock.adjust", Kinds: billingKinds, MaxV: 1},
	"stock.in":          {Name: "stock.in", Class: ClassTrading, Permission: "stock.adjust", Kinds: billingKinds, MaxV: 1},
	"pay":               {Name: "pay", Class: ClassTrading, Permission: "payment.take", Kinds: billingKinds, MaxV: 1},
	"refund":            {Name: "refund", Class: ClassTrading, Permission: "bill.refund", Kinds: billingKinds, MaxV: 1},
	"order.edit":        {Name: "order.edit", Class: ClassTrading, Permission: "order.create", Kinds: billingKinds, MaxV: 1},
	"kds.new":           {Name: "kds.new", Class: ClassTrading, Permission: "kds.update", Kinds: floorKinds, MaxV: 1},
	"kds.ready":         {Name: "kds.ready", Class: ClassTrading, Permission: "kds.update", Kinds: floorKinds, MaxV: 1},
	"kds.late":          {Name: "kds.late", Class: ClassTrading, Permission: "kds.update", Kinds: floorKinds, MaxV: 1},
	"credit_note.issue": {Name: "credit_note.issue", Class: ClassTrading, Permission: "bill.refund", Kinds: billingKinds, Doc: "credit_note", MaxV: 1},
	"menu.add":          {Name: "menu.add", Class: ClassConfig, Permission: "menu.edit", Kinds: billingKinds, MaxV: 1},
	"menu.price":        {Name: "menu.price", Class: ClassConfig, Permission: "menu.edit", Kinds: billingKinds, MaxV: 1},
	"menu.rename":       {Name: "menu.rename", Class: ClassConfig, Permission: "menu.edit", Kinds: billingKinds, MaxV: 1},
	"menu.del":          {Name: "menu.del", Class: ClassConfig, Permission: "menu.edit", Kinds: billingKinds, MaxV: 1},
	"menu.undel":        {Name: "menu.undel", Class: ClassConfig, Permission: "menu.edit", Kinds: billingKinds, MaxV: 1},
	"conflict.confirm":  {Name: "conflict.confirm", Class: ClassControl, Permission: "approval.grant", Kinds: billingKinds, MaxV: 1},
	// Cloud-origin only: the void of a refused configuration op, and cloud edits (S6, S11).
	IntentVoid:   {Name: IntentVoid, Class: ClassControl, Permission: "", Kinds: []string{"cloud"}, MaxV: 1},
	"cloud.emit": {Name: "cloud.emit", Class: ClassConfig, Permission: "", Kinds: []string{"cloud"}, MaxV: 1},
}

// Allows reports whether the device kind may record the intent.
func (i Intent) Allows(kind string) bool {
	for _, k := range i.Kinds {
		if k == kind {
			return true
		}
	}
	return false
}
