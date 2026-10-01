# AI Gateway HTTP administrator option — 2026-10-01

## Scope and deployment

Explicit user approval: implement and test an instance-admin switch permitting AI
Gateway over public HTTP, with HTTPS available and required by default. Changes
are on `codex/ai-gateway-transport-controls`; the original AWS CP runs the labeled
`ai-http-admin-review-20261001` review build on its existing v0.1.36 installation.
This does not claim the published v0.1.36 contains the option. No release or merge.

The UI is **Settings → AI Gateway transport → Allow AI Gateway over HTTP → Save
changes**. The policy is installation-wide, defaults OFF, requires a verified
server administrator and uses revision preconditions plus transactional audit.
Migration 0165 stores the policy in PostgreSQL. The legacy environment flag does
not override it. HTTP and HTTPS use separate sessions; provider egress controls,
credential encryption, authentication and organization/model grants remain intact.

## Observed live evidence

| Check | Observed result |
| --- | --- |
| Fresh migration default | `allow_http=false`, revision 1 |
| HTTP while OFF | AI settings unavailable with `https_required`; provider API403 |
| HTTPS while OFF | AI settings available; provider API200 with two saved credentials |
| Save ON through browser | Saved policy changes to HTTP allowed; provider API200 on HTTP and HTTPS |
| Save OFF through HTTP browser | Revision 3; HTTP provider API403 immediately; HTTPS stays200 |
| Restore ON and restart API | Revision 4 and ON survive; browser reload shows saved ON; both protocols200 |
| Final generated API replacement | ON survives another container replacement (revision6 observed) |
| No authenticated session | Admin policy API401 on both protocols |
| Browser workflow on HTTP | Models1, Add Model enabled, wizard and existing Groq credential selection reachable; Credentials2 and Add Credentials enabled |
| Disabled-state UX | Models explains the HTTP policy and offers server administrators the transport-settings link |
| Existing data | Groq configured model and both credential records retained; Azure's pre-existing disabled state unchanged |
| Gateway/engine | Original container IDs, start times, and named volumes retained; both healthy |

Normal certificate validation succeeds on HTTPS. HTTP stays at the original HTTP
origin instead of redirecting to HTTPS. The original port80 operator-IP firewall
restriction was retained; no AWS resources or ingress rules were added.

A browser-only regression was found during this walk: previously cached permanent
HTTP→HTTPS redirects sent some API requests to the other origin without its
session cookie. Secret-free proxy diagnostics identified the scheme change. The
shared client now uses `cache: no-store`; the same original HTTP browser session
then loaded Settings, Models and Credentials successfully. Diagnostics were
removed. Internal settings navigation uses the application's React Router Link.

Screenshots: [HTTP setting](ai-http-admin-20261001/http-setting-enabled.jpg),
[HTTP models](ai-http-admin-20261001/http-models-enabled.jpg), and
[HTTP disabled guidance](ai-http-admin-20261001/http-disabled-guidance.jpg).
These are actual browser captures of the labeled review deployment.

## Preservation and recovery

Before migration, retained a verified custom-format database backup (1,188,672
bytes, `pg_restore --list` passed), environment, Compose, policy and helper copies
in `/opt/tunnex/review-backups/ai-http-admin-20261001T111203Z`. Earlier engine and
volume backups remain. Compared protected environment values without logging
secrets: only API/web/nginx image references, managed Compose hash, exact nginx
proxy trust and the HTTP-console listener flag changed. Unrelated values and
keys are identical. The original gateway and AI engine were never recreated.

Final canonical Compose SHA256:
`a9ecd123126a1f5ebd908e0c3e7fecf13e6d019268bb15cbf79063cfd34279a0`.
Review images were built on the CP from its existing immutable base digests and
locally built Linux amd64 binaries/web assets. No registry release was published.

## Automated verification

- Whole API `go test -p 2 ./...` and enterprise variant passed. Unrelated database
  tests skip without their fixtures; they are not counted as live proof.
- Separately ran real isolated PostgreSQL migration/persistence, concurrent stale
  writes, audit rollback, default/OFF/ON routing, admin and org-owner authorization,
  CSRF, HTTPS continuity and workload tests in both editions. Policy/wire race
  checks passed.
- Real password-login + Redis/PostgreSQL SessionAuth test covers Settings' actual
  endpoint sequence, HTTP/HTTPS cookie separation and logout isolation; passed
  both editions and race detection.
- Full web baseline:142 files,1731 passes,2 existing expected SSO failures. Later
  targeted cache/navigation/provider/Settings suites:134 passes,2 existing expected
  failures. Web typecheck and labeled production build passed.
- Installer, upgrade application, upgrade helper/runner, hosted Compose, public
  URL, existing Helm AI/SageMaker/BYODB contracts passed. Eight edge tests include
  actual pinned Caddy forwarding; Helm tests execute pinned nginx. Trusted peers
  retain HTTPS; forged, duplicate and malformed forwarding cannot grant HTTPS.
  CI runs the new Caddy and Helm regressions.

## Limits

No provider inference was submitted during this transport test. A passing UI or
provider inventory read does not prove Azure credentials, model entitlement or
upstream inference. The existing organization activation preference was preserved.
The workload CLI retains its separate HTTPS requirement except loopback.

The policy survives live restart/container replacement. Upgrade persistence is
covered by durable DB storage, integration tests and installer/upgrade contracts;
a new signed release upgrade containing this feature has not been performed.
Terminated TLS deployments must configure verified immediate proxy peers before
migration; old installed helpers cannot execute the newly added preflight.
