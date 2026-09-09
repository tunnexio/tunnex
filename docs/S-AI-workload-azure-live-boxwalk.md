# Workload identity: real Azure walk — 2026-09-09

**PASS for the bounded local CP walk below. Production qualification remains incomplete.**

The real application at `http://127.0.0.1:5180` created a temporary workload,
selected the existing `azure` GPT-5 credential and issued a reusable enrollment
key for two independent CLI replicas. The child application received a local
session credential through `tunnex workload run`; it never received the Azure
provider key. Creation, key revocation, instance revocation, usage inspection and
cleanup used the actual signed-in control-plane UI.

The user explicitly approved temporary test access, at most three short inference
attempts, restart/renewal/revocation checks and cleanup. No remote rollout, release,
cloud resource change or provider credential change was performed.

## Boundary and evidence

| Item | Verified value |
| --- | --- |
| Source | `story/S-AI-workload-identity`, documentation HEAD `72e7867d` plus the unchanged local implementation snapshot in the prior CP source manifest |
| Docker context | `colima-tunnex-sso-review` |
| Compose project | `tunnexaiwalk0907repro4` |
| Database / network | `tunnexaiwalk0907repro4-cp-postgres` / `tunnexaiwalk0907repro4_engine` |
| Schema | 153, clean |
| Workload | `Engineering Azure live walk`, `72f8983b-aa63-44ff-a3b7-afd6b4ffdb3d` |
| Configured model | `custom-fd5043c6-3863-4073-80be-f4af3bceefc2/gpt-5` |
| Actual Azure response model | `gpt-5-2025-08-07` |
| Joining key | Reusable, ephemeral instances, one-day expiry, maximum 3 uses; 2 uses consumed |
| Existing provider configuration | Unchanged SHA-256: `aad2b8da9ed6b806b176c22b0934010d2c1f04786037e5907f60feadf9ea8c37` |

Every database-capable verification first checked the non-default compose project,
container label and network. Queries read only identifiers, status and token
timestamps; no token values, hashes, sealed credentials or signing keys were emitted.

The [structured results](../walk-artifacts/workload-azure-live0909/results.json)
contain response IDs, usage, token timestamps, cleanup state and the installed CLI
binary hash. The [child harness](../walk-artifacts/workload-azure-live0909/application.py)
uses injected SDK-style environment variables and a locked three-attempt counter.
It is recorded for reproducibility; running inference again requires a new test
authorization. The deployed source is identified by the existing
[CP source manifest](../walk-artifacts/workload-cp0909/source-sha256.txt).
No product code changed during this walk.

## Live checks

| Check | Result |
| --- | --- |
| Two independent replica enrollments | PASS: distinct instance IDs under the same workload policy. |
| Saved Azure credential used through the gateway | PASS: two actual Azure HTTP 200 responses, both containing the requested marker. |
| Inference accounting | PASS: 161 + 97 = **258 tokens**, attributed to the same workload; 2 requests in the actual usage table. |
| Ungranted model | PASS: HTTP 403 before provider execution. |
| Ordinary restart | PASS: the same instance resumed with the enrollment-key file absent; model listing returned HTTP 200. |
| Key-only revocation | PASS: a fresh third replica received HTTP 401 while capacity remained at 2/3 uses; existing replicas still authenticated. |
| Automatic token renewal | PASS: a running replica continued model-list requests for 340 seconds, beyond its original five-minute token expiry, with the joining key already revoked. |
| Single-instance revocation | PASS: revoked replica received HTTP 401 with no automatic re-enrollment; sibling still returned HTTP 200. |
| Cleanup | PASS: joining key and both replicas revoked, workload disabled at revision 2; both replicas refused authentication with HTTP 401. Local test key/signing-credential files removed after verification. |

Renewal evidence for instance `c0cb5490-4ddd-4017-a267-f0d111f79760`:

- Initial token: created `08:22:10.431551 UTC`, expires `08:27:10.431551 UTC`.
- Automatically renewed token: created `08:26:10.446286 UTC`, expires `08:31:10.446286 UTC`.
- The process continued successfully through the 340-second checkpoint without a
  new enrollment or joining-key use.

Screenshots: [usage](../walk-artifacts/workload-azure-live0909/usage.png),
[single-instance revocation](../walk-artifacts/workload-azure-live0909/replicas.png),
[completed cleanup](../walk-artifacts/workload-azure-live0909/cleanup.png).

## Observed limits

The first inference attempt returned gateway HTTP 400 `invalid_request`: the
harness used `max_completion_tokens` and `reasoning_effort`, which are outside the
current gateway payload allowlist. The harness was corrected to `max_tokens`;
the following two attempts reached Azure successfully. Three attempts total
were made, within the approved limit. This walk does not establish arbitrary
OpenAI SDK parameter compatibility.

**Azure dollar pricing was unavailable.** The actual workload usage row showed
2 requests, 258 tokens, `$0.00` and 2 requests without cost. This zero is not an
actual zero Azure charge. The workload had no USD threshold configured; this
walk does **not** satisfy a real-provider USD soft-threshold proof. Existing
fixture threshold tests remain separate evidence. Missing pricing is an
outstanding accounting/qualification gap, not silently treated as free usage.

This proves two local CLI replicas against one deployed local API. Multi-API
failover, a cloud autoscaling replacement exercise, issuer/network outages and
Windows runtime remain production-qualification work. The previously held W7
retirement lost-response case was not exercised or fixed here. No CI, merge,
release, production HA or full-story completion is claimed.

The disabled temporary workload remains in CP for inspection. Existing workloads,
saved Azure credentials, unrelated local containers and rollback backups were
preserved.
