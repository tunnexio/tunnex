# Optional sandbox deployment module

Baseline 41697eb, separate source candidate. No live configuration or runner protocol changes.

TUNNEX_SANDBOX_MODULE accepts on, off, or draining. Unset means disabled on a fresh unconfigured server and enabled when legacy runtime/fixture configuration exists, preserving existing configured installations. on exposes the module but does not provision a runtime without its existing explicit configuration. draining keeps inventory/actions/cleanup available and closes new creation; it does not claim physical retirement. off requires removal of runtime/fixture configuration and a durable database retirement check. The same guard applies to implicit off, preventing an existing installation from losing its cleanup adapter through accidental configuration removal.

Turn organization creation off before draining. Retirement requires no creation-enabled organization, no nondeleted sandbox or unretired runtime binding; no active sandbox peer or runtime credential. Saved account public keys and historical records do not block off and are never deleted by a module-state change. No newly configured workers/helpers/listeners/certificates/storage for fresh off. Monolithic API/schema overhead remains.

Metadata carries sandbox_module_state through the existing /meta endpoint. Web capability is default closed while metadata is loading or absent/failed. Sidebar and command palette share the same capability filter; direct routes gate before lazy-loading any sandbox page or fetching inventory. Reuse a single cached public metadata request with the existing health metadata read.

Disabled organization projections already return no rows via SQL authorization; skip that query with the existing snapshot settings flag, preserving empty-policy withdrawal and retained cleanup. An organization disable is not a deployment shutdown; stop/delete and confirmed retirement must precede deployment off.
