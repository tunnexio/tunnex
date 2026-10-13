module github.com/tunnexio/tunnex/apps/api/localfixture

go 1.26.8

require (
	github.com/google/uuid v1.6.0
	github.com/jackc/pgx/v5 v5.10.0
	github.com/tunnexio/tunnex/apps/api v0.0.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/crypto v0.56.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)

replace github.com/tunnexio/tunnex/apps/api => ../../../apps/api

replace github.com/tunnexio/tunnex/packages/apptransport => ../../../packages/apptransport
