# Isolated GCP site-to-site local control plane

Compose project `tunnexgcps2slocal1010` owns separate PostgreSQL, Redis and API state volumes/network. Bind API `127.0.0.1:38083`, agent mTLS `127.0.0.1:38446`, PostgreSQL `127.0.0.1:35440`; UI preview uses `35173`. AWS environments and ports are not reused.

1. `python3 tests/gcp-s2s-local/prepare.py`
2. Build exact integration source with `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOFLAGS=-mod=readonly go build -trimpath -o ../../tests/gcp-s2s-local/.runtime/bin/tunnex-api ./cmd/server` from `apps/api`.
3. `docker compose --env-file tests/gcp-s2s-local/.runtime/compose.env -f tests/gcp-s2s-local/compose.yaml up -d postgres redis api`

Private generated credentials/binaries remain in ignored `.runtime`. A running local CP proves migration/startup only, not live GCP tunnel acceptance. No local gateway is presented as cloud proof. Use only exact project-scoped commands; no global Docker cleanup. Keep lab resources for inspection.
