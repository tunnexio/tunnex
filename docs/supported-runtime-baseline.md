# Supported runtime baseline

Reviewed 2026-09-27. Prefer maintained LTS/stable lines and current security patches over automatic major-version upgrades.

| Component | Baseline | Rationale |
| --- | --- | --- |
| Node | 24.21.0 LTS | Replaces end-of-life Node 20 and aligns CI, local development and container builds. |
| pnpm | 10.34.5 | Supported through April 2027; replaces unsupported pnpm 9 without the pnpm 11/12 configuration migration. |
| nginx | 1.30.5 stable | Updates both the edge proxy and SPA server together. |
| First-party Alpine runtimes and IPsec builder | Alpine 3.24.2 | Replaces 3.20/3.22/3.23 with a release receiving both main and community package maintenance. |
| Python | 3.12.14 | Security patch within the supported 3.12 line; preserves locked SDK dependencies. |
| First-party Go | 1.26.8 | Supported release line; Go 1.27 is a separate compatibility upgrade, not required to remove an EOL runtime. |
| PostgreSQL | 16 | Supported through November 2028. Keep data-directory major migrations separate. |

Container references changed here use registry-verified multi-platform digests. Application lockfiles and dependency versions are unchanged. Node's exact local version is in `.nvmrc`; CI reads it. The package engine restricts execution to the tested Node 24 line. `packageManager` selects the exact pnpm version. CI caches include these pins.

Do not treat this baseline as a blanket assertion that every transitive dependency or operating-system package is supported. Native VPN/IPsec and PostgreSQL client qualification must accompany Alpine changes. The gateway builder and runtime use the same multi-platform index and the provenance record includes the verified architecture manifests. The separately pinned upstream Bifrost build is also qualified independently.

Known upstream exception: the optional LiteLLM proxy still depends on the deprecated Prisma Python client. Removing it requires an upstream-supported replacement or a separate proxy integration migration; this runtime update does not resolve that dependency. Prisma generation now uses an explicit Node 24.21.0 environment instead of downloading the newest Node automatically.

Recheck lifecycle policies before subsequent releases, especially pnpm before April 2027. Rebuild and test both AMD64 and ARM64 images, run the web gate and open/enterprise E2E checks, and qualify AI SDK adapters whenever Python images change. Never merge on an unverified version bump alone.

Sources:
- https://nodejs.org/en/about/previous-releases
- https://github.com/pnpm/pnpm/security
- https://nginx.org/en/download.html
- https://www.alpinelinux.org/releases/
- https://devguide.python.org/versions/
- https://www.python.org/downloads/release/python-31214/
- https://go.dev/doc/devel/release
- https://www.postgresql.org/support/versioning/
- https://github.com/RobertCraigie/prisma-client-py/issues/1073
