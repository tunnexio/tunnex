module github.com/tunnexio/tunnex/apps/app-proxy

go 1.26.8

require (
 github.com/tunnexio/tunnex/packages/apptransport v0.0.0
 golang.org/x/net v0.57.0
)

replace github.com/tunnexio/tunnex/packages/apptransport => ../../packages/apptransport
