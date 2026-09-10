# Private LiteLLM OSS proxy runtime preparation

This package prepares the actual LiteLLM proxy server, **not** the existing
`apps/ai-bridge` SDK preflight service. It is not connected to Tunnex admission,
credentials, model management, billing or the local preview. No deployment,
schema migration, provider call or existing-stack restart is part of this change.
See `docs/S-AI-litellm-proxy-decisions.md` for the pending integration contract.

## Reproducible dependency boundary

- Python 3.12.13 uses the same immutable Debian base as the existing bridge.
- LiteLLM is pinned to released wheel **1.100.0**. `requirements.in` explicitly
  enumerates that wheel's `proxy` dependencies plus Prisma 0.15.0. Every resolved
  distribution in `requirements.txt` has SHA-256 hashes; installation requires
  hashes. The lock supports Python 3.12 across platforms.
- Do **not** change the input to `litellm[proxy]`: its released metadata includes
  **litellm-enterprise 0.1.62**, whose wheel declares `LicenseRef-Proprietary`.
  Its `litellm_enterprise-0.1.62.dist-info/licenses/LICENSE.md` restricts production
  use and distribution to its enterprise terms. That distribution is omitted.
  The inspected wheel SHA-256 was
  `337697160896d52079290ffe8051c3dee450653d271cb29723af6db8546eb7d9`.
- MIT `litellm-proxy-extras` **0.4.91** is retained for native database migrations.
  Its inspected wheel SHA-256 was
  `d19fe53591b0bbd48aff24cb1a166b0c68ff2491469ceec88eaa83c6a364562d`.
  Its archive contains no separately licensed `enterprise/` tree. Both MIT
  notices are retained here and dependency notices remain installed in the image.
- The unmodified `litellm/proxy/proxy_server.py` imports optional enterprise
  routes inside `try/except ImportError`; this package uses its OSS path.
  No licence checks are removed or bypassed. Installing the proxy's OSS runtime
  does not establish parity with paid LiteLLM features or certify every provider.
- Reviewed UI source revision `168a0055a244acdcf97c330c52e085ab40b1424c` is
  separate from the released wheel. In particular its newer proxy extras pins
  must not be substituted for the 1.100.0 wheel pins.

To refresh the lock deliberately, from the repository root:

```sh
uv pip compile apps/ai-proxy/requirements.in --python-version 3.12 --universal --generate-hashes --no-strip-extras --output-file apps/ai-proxy/requirements.txt
```

`Dockerfile` generates Prisma's Python client at build time for non-root use.
Prisma downloads versioned native engines during generation; those binaries are
outside the Python wheel hash lock and require image build/provenance validation.
No image build has been performed for this preparation.

## Private topology and secrets

`deploy/ai-gateway/compose-proxy.yml` is a **standalone** opt-in `ai-proxy` profile;
do not combine it with the existing control-plane Compose files. It has no API
service override, no shared Bifrost network, no host ports and no external volume.
The PostgreSQL data volume and private database network belong to the explicitly
named project. The reserved proxy egress network is also internal: preparation
has no provider Internet egress. A future approved egress proxy must be attached
explicitly as part of the scoped integration.
The PostgreSQL 16 Alpine multi-platform image digest was read from the official
Docker registry on 2026-09-07; no image was pulled or started.

Before any later deployment, an operator must supply a new non-default project
name through `TUNNEX_AI_PROXY_PROJECT` and three separate absolute file paths:

- `TUNNEX_AI_PROXY_MASTER_KEY_FILE`: random administrative key starting `sk-`.
- `TUNNEX_AI_PROXY_SALT_KEY_FILE`: independent durable encryption salt; retain it
  with protected database backups. Administrative-key rotation must not rotate it.
- `TUNNEX_AI_PROXY_DATABASE_PASSWORD_FILE`: independent database password.

Use at least 32 printable non-space ASCII characters in each file (a final newline
is accepted). Do not commit these files or pass their values on command lines.
Provision file permissions so the non-root proxy UID 65532 can read its mounts;
local Compose bind-mounted secrets do not implement Swarm secret UID/mode mapping.
Postgres reads its password through its official `_FILE` interface and its
official entrypoint drops to the image's postgres user before running the server.
Only the proxy receives master/salt files. The proxy constructs its database DSN
for `ai-proxy-postgres` internally and never logs secret-file errors verbatim.
The admin UI is disabled. No master key or global management API belongs in a
tenant browser, public reverse proxy or the Tunnex UI.

## Database and accounting posture

`config.yaml` has no seeded provider, model, credential or virtual key. Models
will be database-owned (`store_model_in_db: true`) when the scoped adapter exists.
Normal startup disables schema updates. A fresh database still needs a separately
reviewed explicit schema-provisioning step before the server can be qualified;
this preparation neither performs nor implements that migration. Do not point it
at the current Tunnex or Bifrost databases.

Accounting remains enabled. The verified 1.100.0 settings are:

- `general_settings.store_prompts_in_spend_logs: false`, defined in
  `litellm/proxy/_types.py` and applied in `proxy_server.py`.
- `litellm_settings.turn_off_message_logging: true`, implemented by
  `litellm/litellm_core_utils/litellm_logging.py`.
- No success/failure callbacks, cache, verbose logging or automatic retry.

These settings exclude prompt/response bodies from normal spend logging; they
do not prove all error paths and arbitrary metadata are content-free. Future
integration must bound and sanitize metadata, preserve failure/unknown-price
accounting and test logging with canary content. Existing SDK/Bifrost usage is
unchanged; there is no new billing dashboard integration.

## Validation and remaining work

Run local guard and packaging checks without secrets or a database:

```sh
python -m unittest discover -s apps/ai-proxy/tests
```

Validation completed on 2026-09-07 in a separate temporary Python 3.12 environment:
hash-checked installation of 109 distributions; no enterprise distribution or
`enterprise/` subtree in either LiteLLM wheel; actual OSS FastAPI proxy import
(75 routes); CLI help; and full CLI initialization with `--skip_server_startup`,
a temporary model-free/database-free configuration, and socket connection attempts
forbidden. Five secret-boundary tests and standalone Compose `config --quiet`
also passed. These checks used no provider credentials, database or listener.

Image build,
Prisma native-engine generation in Linux, PostgreSQL schema provisioning,
non-root container startup, admission integration, scoped keys, egress policy,
provider calls and end-to-end accounting remain separate acceptance work.
No claim of a running proxy, migration readiness or full LiteLLM feature parity
is made by these packaging checks.
