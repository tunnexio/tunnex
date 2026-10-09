# Supported runtime baseline

Reviewed 2026-10-09. Prefer maintained LTS/stable lines and current security patches over automatic major-version upgrades.

| Component | Baseline | Rationale |
| --- | --- | --- |
| Node | 24.21.0 LTS | Replaces end-of-life Node 20 and aligns CI, local development and container builds. |
| pnpm | 10.34.5 | Supported through April 2027; replaces unsupported pnpm 9 without the pnpm 11/12 configuration migration. |
| nginx | 1.30.5 stable | Updates both the edge proxy and SPA server together. |
| First-party Alpine runtimes and IPsec builder | Alpine 3.24.2 | Replaces 3.20/3.22/3.23 with a release receiving both main and community package maintenance. |
| AI inference runtime | Bifrost v2.0.0 with pinned Tunnex native extensions | One Go runtime; no Python bridge/proxy or Prisma dependency. The upstream modules require at least Go 1.27.0; the independent builder is pinned to patched Go 1.27.2. |
| First-party Go | 1.26.9 | Current security patch on the supported release line; Go 1.27 is a separate compatibility upgrade, not required to remove an EOL runtime. |
| PostgreSQL | 16 | Supported through November 2028. Keep data-directory major migrations separate. |

Container references use registry-verified multi-platform digests. Node's exact local version is in `.nvmrc`; CI reads it. The package engine restricts execution to the tested Node 24 line. `packageManager` selects the exact pnpm version. CI caches include these pins.

Do not treat this baseline as a blanket assertion that every transitive dependency or operating-system package is supported. Native VPN/IPsec and PostgreSQL client qualification must accompany Alpine changes. The gateway builder and runtime use the same multi-platform index and the provenance record includes the verified architecture manifests. The separately pinned upstream Bifrost build is also qualified independently.

The retired LiteLLM Python bridge and optional proxy are no longer runtime dependencies. Licensed static model metadata/pricing is fetched and verified during CI, then baked into the API and private engine artifacts. Python is used only for build/qualification tools.

Recheck lifecycle policies before subsequent releases, especially pnpm before April 2027. Rebuild and test both AMD64 and ARM64 images, run the web gate and open/enterprise E2E checks, and qualify native AI provider extensions whenever the pinned engine changes. Never merge on an unverified version bump alone.

Sources:
- https://nodejs.org/en/about/previous-releases
- https://github.com/pnpm/pnpm/security
- https://nginx.org/en/download.html
- https://www.alpinelinux.org/releases/
- https://devguide.python.org/versions/
- https://www.python.org/downloads/release/python-31214/
- https://go.dev/doc/devel/release
- https://www.postgresql.org/support/versioning/
