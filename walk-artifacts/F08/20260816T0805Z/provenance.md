# F08 AWS DEV provenance

- Walk date: 2026-08-16 UTC.
- Story branch content deployed: `cc4bfa8fe85137bb192cb09e944b6372054348f2`.
- Source archive SHA-256: `98afa4d8b431596cfa05805dd074a4c82153d6dbe01fe08266f120b12d2d4b37`.
- API image: `tunnex-api:f08-cc4bfa8-amd64`, revision label exactly the story SHA, healthy, restart count zero.
- Web image: `tunnex-web:f08-cc4bfa8-amd64`, revision label exactly the story SHA, healthy, restart count zero.
- Existing F07 node image remained unchanged and healthy.
- PostgreSQL migration ledger: version 96, dirty false.
- Preflight recorded a verified mode-0700 rollback bundle and sufficient CP/VM disk. `/dev/net/tun` was present on the disposable Ubuntu VM.
- The reusable harness preflight passed after its schema command quoting regression was repaired in `cc4bfa8`.

No cookie, bootstrap token, runtime bearer, private key, raw WireGuard configuration or token hash is present in this artifact.
