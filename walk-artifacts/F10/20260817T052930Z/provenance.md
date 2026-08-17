# F10 AWS DEV provenance

- Content source: `e951927d13f82cea29d71c338c9303370f797392`.
- API image: `sha256:3eee1b10ad9d2cc78a5ee4327c52d0628d629e9012b3bb636309dce6efda1fbc`.
- Web image: `sha256:1c393634a1e8fbb46e5a1217baf3a3a658b952af013222cb27377054024e435f`.
- Both image revision labels matched the content source.
- PostgreSQL migration ledger: version 98, dirty false.
- API, web, nginx, PostgreSQL, Redis and node-agent were healthy; final
  F10-window severe-log count was zero.
- Enterprise `/api/v1/meta` was live after a scoped nginx service-discovery
  refresh. The refresh changed no image or product configuration.
- Verified pre-walk rollback bundle:
  `/home/ubuntu/f10-rollback-e951927-20260817`, including a custom PostgreSQL
  dump, schema/image/deploy inventories and checked `SHA256SUMS`.
- Local exact gates passed before deployment: generate drift, fresh migration,
  both-edition tests/builds, node/helper/cross-compile, TypeScript, 80 web test
  files / 1,079 tests, and production web build.

No credential, cookie, private key, WireGuard configuration or reusable token
is recorded in this packet.
