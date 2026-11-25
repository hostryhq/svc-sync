// identityreal runs svc-sync's identity client and the directory contract test against the real identity
// service layers (svc-identity's double composes the same service and api layers as the real service). It is a
// module of its own so that svc-identity and its dependencies stay out of svc-sync's module graph.
module github.com/hostryhq/svc-sync/identityreal

go 1.27

require (
	github.com/hostryhq/go-auth v0.0.0-20261125030157-94f1970efd79
	github.com/hostryhq/go-common v0.0.0-20261125032613-92884d6c83f8
	github.com/hostryhq/svc-identity v0.0.0-20261125054144-2ba5adc0cd21
	github.com/hostryhq/svc-sync v0.0.0
	github.com/jackc/pgx/v5 v5.13.0
)

require (
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hostryhq/svc-tenancy v0.0.0-20261125053351-3792f07b6054 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.3 // indirect
	github.com/oapi-codegen/runtime v1.9.1 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/hostryhq/svc-sync => ../
