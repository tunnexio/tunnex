# Beam review rooms

Saved projects keep publisher-owned presets and group repeated publishing sessions into a review workspace. They do not grant access or keep a stopped tunnel serving. A publisher still runs the Tunnex CLI or desktop process; reviewers use their signed-in browser.

## Project and session boundaries

Each saved project stores its name, fixed numeric loopback target (and optional path routes), default duration and explicit user/group reviewers. Saving requires the current organization publishing policy, eligible publisher membership, current reviewer eligibility, and valid local targets. Up to 100 projects may be saved per publisher. Editing uses the expected version and rejects stale updates.

A native publication may specify `project_id` when its control plane advertises `saved_projects_v1`. The project must belong to the publishing user in the same organization. The created share snapshots its own target and grants; editing project defaults never changes a serving share's target, connector binding, expiry or audience. Every fresh publication receives a fresh share identity and random HTTPS hostname. Stopped, expired and revoked shares cannot be reopened.

Projects and their saved local target/defaults are visible only to their owner. A granted reviewer receives the existing safe share projection, without local target or reviewer inventory. Owner Active and History views, including a project's sessions, filter effective state before pagination. Active includes starting, active and paused; History includes stopped, expired and revoked.

## Review feedback and screenshots

Feedback supports a comment, an approval, or changes requested. Comments require text or a screenshot; status decisions may omit text. Feedback text is bounded to 4,000 characters. A share holds at most 500 feedback entries; an author may submit at most 20 entries per organization in one minute.

Review endpoints require a current human browser session and current organization membership. They recheck parent logout/auth epoch and fresh MFA when required by policy. A reviewer must retain current explicit user/group access and the share's current source authority. Removing the grant, publisher eligibility, source credential, organization or policy removes reviewer access to feedback and screenshots. Paused/offline previews can retain feedback access while their source authority remains valid. Owners retain read access to their own historical reviews, but ended shares reject new feedback.

Screenshot uploads accept raw base64 PNG or JPEG files, at most 256 KiB. Dimensions are bounded to 2,048 pixels each and 4 million pixels total before decoding. The API reencodes the image as PNG, strips ancillary metadata/trailing data, and rejects results exceeding 256 KiB. Authenticated screenshot endpoints recheck access before returning bytes and use `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, and a restrictive content security policy. Arbitrary attachment URLs, SVG/HTML files and data URLs are not accepted. Feedback metadata requests have a 512 KiB body limit; other Beam metadata retains its 32 KiB limit. Text is rendered as text by the console, without HTML execution.

## In-app updates

The notification endpoint derives preview ready, imminent expiry (10 minutes), and the latest other participant's feedback per accessible share. Its source inventory is bounded to the 100 most recent active owner shares and 100 most recent shared active/paused shares, then deduplicated, authorized, sorted and paginated. The feed is read-time information: it does not persist unread receipts, send email, or send messages externally. Revoked reviewer access disappears from the feed.

## API

All routes are under `/api/v1/organizations/{orgId}/beam` and inherit existing authentication, organization RBAC, forced-password and CSRF gates.

| Route | Method | Result |
| --- | --- | --- |
| `/projects` | GET / POST | Owner project page / save new project |
| `/projects/{id}` | GET / PUT | Owner project / versioned defaults update |
| `/projects/{id}/sessions` | GET | Owner session inventory, `scope=active` or `scope=history` |
| `/shares` | GET | Owner inventory with the same optional scope filter |
| `/shares/{id}/feedback` | GET / POST | Authorized reviews / submit review |
| `/shares/{id}/feedback/{feedbackId}/screenshot` | GET | Authorized sanitized PNG |
| `/notifications` | GET | Current authorized in-app update page |

The dedicated Beam OpenAPI contract and generated frontend types document bounded inputs. Native share creation adds optional `project_id`; path routes remain part of the share's immutable target binding. A native client must negotiate the relevant capabilities before sending project associations or routed targets to older control planes.

## Schema compatibility and rollback

Migration 0213 adds `beam_projects`, `beam_feedback` and nullable `beam_shares.project_id`. Existing share identities, serving targets, credentials, grants, states, versions and policies are unchanged. A composite foreign key ensures a session cannot attach to another organization or publisher's project. Older clients continue publishing shares without a project association.

The down migration rejects rollback while any project or feedback exists. Export required review data and deliberately remove it before a schema downgrade; project associations must be detached before removing their referenced projects. Do not use a downgrade to silently delete customer review data. A binary rollback may retain the additive schema; verify the previous binary's exact compatibility separately. The upgrade/drain/down/up fixture preserves unrelated existing shares and verifies both project and feedback rollback guards.

## Qualification evidence

Executed against disposable PostgreSQL databases, separate from the local CP database:

- Complete Beam backend regression: `go test ./internal/beam -count=1` passed (137.204 seconds).
- Project tests cover frozen serving authority on preset edits, current audience and publisher eligibility, cross-owner/tenant denial, fresh identities after stopping, and Active/History pagination.
- Feedback tests cover sanitized screenshots, status-only reviews, bounded/malformed input, grant withdrawal, source-policy withdrawal, parent logout, auth-epoch change and fresh MFA.
- HTTP tests cover browser authentication, CSRF, forced password change, foreign organization handling, bounded strict JSON decoding, and screenshot response headers/access after logout.
- `check:beam` passed, confirming generated frontend types match the contract.

These backend checks do not alone establish desktop packaging, public production DNS/TLS, platform-native lifecycle or browser visual acceptance. Record local rendered browser and actual native publication proof separately.

### Local integration qualification, 2026-10-07

- Full console `verify` passed: contract freshness, TypeScript, 191 test files (2,375 passed and 2 expected failures), and production build.
- CLI Beam tests, 25 native desktop Beam tests, 8 desktop panel tests and 2 real desktop-to-Go TLS fixtures passed. The transport suite passed with path routing, query preservation and reviewer withdrawal coverage.
- The owned `tunnex-beam-local` stack was backed up before migration, upgraded to schema 213 with `dirty=false`, and rebuilt with final API/proxy/console artifacts. API, proxy, console, gateway, PostgreSQL and Redis were healthy afterward.
- Chrome at `http://127.0.0.1:18283` saved a project with ports 33001 and 33002 (`/api`), generated its complete login/publish command with explicit reviewer IDs, and displayed the actual CLI-created Live session under that project. The review decision was saved and retained after stopping. The stopped session disappeared from Active and remained in project Session history. QR and the preview-ready update were inspected in the rendered console.
- Browser application navigation stopped at the disposable local CA trust boundary. Browser screenshot selection was blocked by the Chrome extension's file URL setting. Neither setting was bypassed; trusted TLS integration fixtures and screenshot processing/sanitization tests passed separately. Real phone reachability is not established by this loopback-only setup.
- The temporary demo servers were stopped and the isolated CLI credential revoked. The saved project and its historical review remain available locally for inspection. No AWS deployment, Git commit or remote push was performed in this qualification.
