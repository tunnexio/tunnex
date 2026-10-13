# Isolated GCP site-to-site local control plane

Compose project `tunnexgcps2slocal1010` owns separate PostgreSQL, Redis and API state volumes/network. Bind API `127.0.0.1:38083`, agent mTLS `127.0.0.1:38446`, PostgreSQL `127.0.0.1:35440`; UI preview uses `35173`. AWS environments and ports are not reused.

1. `python3 tests/gcp-s2s-local/prepare.py`
2. Build exact integration source with `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GOFLAGS=-mod=readonly go build -trimpath -o ../../tests/gcp-s2s-local/.runtime/bin/tunnex-api ./cmd/server` from `apps/api`.
3. `docker compose --env-file tests/gcp-s2s-local/.runtime/compose.env -f tests/gcp-s2s-local/compose.yaml up -d postgres redis api`

Private generated credentials/binaries remain in ignored `.runtime`. A running local CP proves migration/startup only, not live GCP tunnel acceptance. No local gateway is presented as cloud proof. Use only exact project-scoped commands; no global Docker cleanup. Keep lab resources for inspection.

## Genuine local gateway

`gateway-compose.yaml` uses a dedicated gateway state volume and the existing isolated CP network. Obtain a one-time join token through the normal owner `nodes/join-token` API and write it privately as `TUNNEX_JOIN_TOKEN=...` in `.runtime/gateway.env` (mode 0600). Set `GCP_NATIVE_NODE_IMAGE` to the source-verified native image, then start only this Compose project. The real `wgctrl` backend is required; the development default `mem` does not create a WireGuard interface. Register and bind the owned Site through normal API. Never seed gateway capability flags.

2026-10-10: owned gateway `gcp-local-native-gateway` enrolled normally, bound to `GCP local native Site`, and reached ready. Static, BGP, GCP HA and Classic eligibility were observed as true from normal API. This proves native qualification and control-plane admission locally; it does not prove provider tunnel establishment.

Clean native ARM64 image `tunnex-gcp-s2s-native:20261010-c3c6b897` was built from tracked source at `c3c6b8978f2a6ba78a6a5fcdff0a0e4064aa7dd5`, using pinned strongSwan/FRR packaging and separately compiled binaries. Content verification passed in an owned read-only, network-none, all-capabilities-dropped container. Evidence/context: `/private/tmp/gcp-s2s-native-package-20261010-1`. No unaudited historical image layers were imported.
