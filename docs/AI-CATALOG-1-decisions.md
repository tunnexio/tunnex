# AI-CATALOG-1: model suggestions while adding a provider

Status: built on 2026-11-28 after a founder report from the test deployment.

## Problem

In Add Model, step 3 (Models), a new provider credential only searched the
provider's live model list, using the API key typed in step 2. When that call
failed, the page showed "Model suggestions are unavailable" and left only
manual entry. It fails when:

- the key is rejected, or cannot list models (some providers scope keys to
  inference only);
- the provider's list call is slow or down;
- provider operations are not enabled on the installation.

The release already bundles a reference catalog built from LiteLLM's
`model_prices_and_context_window.json` (`apps/api/internal/aigateway/reference/`),
served without a provider key by `GET /ai-gateway/models` (`listAIProviderModels`).
Saved credentials already use it. New credentials did not.

## Decision

- For a standard provider (one that does not take an endpoint), step 3 searches
  the provider's live list when a valid-looking key is present. If that call
  fails, it searches the bundled reference catalog instead and says so:
  "Your provider's live model list could not be read. Showing known models;
  Test Connect confirms access."
- Reference results are labelled "Unverified catalog suggestions", as they are
  for saved credentials. The live list keeps "Provider catalog".
- Paging stays on the source that answered the first page.
- Endpoint providers (custom, SageMaker, Azure Foundry) are unchanged. They
  have no bundled list for an arbitrary endpoint.
- No security change: the key is still sent only to the live catalog call, and
  every selected model must still pass Test Connect before it is saved.
- Not changed: searching before a key is entered. The wizard asks for the key
  in step 2, before models.
- Rejected: copying LiteLLM's UI model list. The same data is already bundled
  and versioned here, so the change only needs to use it.

## Validation

- Web tests: live success keeps the "Provider catalog" label; live failure
  falls back to reference with the notice and without sending the key; both
  failing keeps manual entry; endpoint providers do not fall back.
- Test deployment: Add Model with OpenRouter, Groq and Gemini shows suggestions.

## Also found

The test deployment did not set `TUNNEX_AI_PROVIDER_MANAGEMENT_ENABLED=true`,
which the installer (`deploy/tunnex.yml`, `deploy/ai-bootstrap.sh`) sets. Fixed
on that deployment only; no product change.

## Grant several models to a user group at once

Founder report, same walk: Access, Grant model access took one model per
grant, so giving a group three models meant opening the dialog three times.
The agent grant dialog already takes several models.

- The Model dropdown becomes a checklist. A model the selected group already
  holds through an enabled grant shows as checked, disabled and "Already
  granted", and is not sent again.
- The API is unchanged: one grant per call. The dialog sends the selected
  models one after another with the same body as before.
- Each grant stands on its own. If some fail, the ones that applied stay
  applied, only the failed models stay selected, and the dialog names them:
  "Granted 1 of 2 models. Could not apply: …". A grant saved but not yet
  active is named the same way.
- The button reads "Grant access to N models" when more than one is selected.
- Rejected: a batch grant endpoint. It would add an API for no safety gain;
  each grant is already independent and audited on its own.

## One row per group on Access, User groups

Founder question: does the grants table scale? It listed one row per group and
model pair, so a group with ten models took ten rows and a page of twenty rows
showed two groups.

- One row per group: the first three models, "+N more", and a count such as
  "3 active · 1 revoked". "Show models" (the group name, or the row menu)
  opens that group's models, each with its own Revoke or Restore.
- The row menu has "Grant more models", which opens the grant dialog with the
  group selected and its granted models marked.
- A model filter ("Filter by model") answers "which groups hold this model".
  A search that matches a group name shows all its models; one that matches
  only model names shows just those models.
- Paging counts groups, not grants.
- The grant dialog's checklist gets a search and "Select all shown" once there
  are more than six models.
- Not changed: grants still load in one request. Server-side paging is worth
  it only at thousands of grants; revisit after launch.

## Daily cost limit for a user group

Founder request: workloads have a daily USD threshold and agent teams have a
daily cost limit, but user groups (Access, User groups) had none, so a group of
people could not be held to a daily budget.

- A user group can have one daily cost limit in USD. It is shared by the whole
  group: the spend of all members together, through all of the group's model
  grants, since midnight UTC.
- Same semantics and wording as the workload threshold: a daily soft
  threshold, not a reservation. It is checked against usage the gateway has
  already observed, so calls running at the same time can overshoot it. Once
  observed spend reaches the limit, new requests through that group are
  refused with `ai_daily_threshold_reached` until midnight UTC.
- Unknown prices block when a limit is set. A model or mode without exact
  pricing is refused with `ai_price_unavailable` for a group with a limit, as
  for workloads. Groups without a limit are unaffected.
- Spend counts every grant the group has held, including revoked ones, because
  their usage today still happened. A grant whose group was deleted no longer
  counts; the limit goes with the group.
- A user in several groups that grant the same model is admitted through any
  group still under its limit. Grants of groups without a limit are tried
  first, so a member's calls do not use up a limited group's shared budget
  when an unlimited group already allows them.
- When no grant admits the request and at least one was stopped by a limit,
  the request gets that error, not a generic denial. Order: threshold reached,
  then price unavailable, then gateway unavailable (a usage read that failed),
  then the usual denial. A failed usage read for one group moves on to the
  next group instead of failing the request.
- "My models" lists a model even while its group is over the limit. The
  refusal comes on the call, with the threshold message, rather than the model
  silently disappearing. The list also does not read usage per model.
- Who can set it: the permission that manages user-group model grants
  (`ai_model_access:manage`). Viewers see the limit in the list.
- Every change writes an audit entry (`ai_user_group.cost_limit_changed`) with
  the new revision and value.
- Removing the limit sets it to null. The row is kept so the revision only
  goes up: a stale editor gets 409 instead of silently overwriting. (The brief
  suggested a NOT NULL column; a nullable one avoids the revision resetting to
  0 after a removal.)
- Changes use an expected revision; a mismatch is 409. Valid values are finite,
  greater than 0 and at most 100000, as for workloads.
- API: `AIUserGroup` gains `daily_usd_threshold` (nullable) and
  `limit_revision`; `PUT /ai-gateway/user-groups/{groupId}/cost-limit` takes
  `{daily_usd_threshold, expected_revision}` and returns the group.
- UI: the group row menu gets "Set daily cost limit" (a small dialog with the
  amount, Remove limit and Save), and the Access column shows it, for example
  "3 active · limit $5/day". Groups with a limit but no grants are not listed;
  the limit has no effect until the group holds a model.
- Migration `0257_ai_user_group_cost_limits`. 0256 is taken by open PR #145,
  which must merge first: golang-migrate does not apply a lower-numbered
  migration to a database already at 0257.
- Rejected: per-member limits. The request was a budget for the group; a
  per-person limit can be added later as its own setting.

## Live model list when adding a model to a saved credential

Founder report, test deployment: Add Model for an existing Groq credential
suggested `groq/gemma-7b-it`, which Groq has decommissioned. Test Connect
failed with provider HTTP 400.

Cause: a new credential searches the provider's live list with the typed key
(`POST /ai-gateway/providers/model-catalog`). A saved credential called
`GET /ai-gateway/models`, which merges the bundled LiteLLM reference list with
the engine's retained model list. For Groq and Gemini the retained list is
empty, so only the reference list showed, and it keeps retired models. It has
no deprecation dates, so filtering by date is not possible.

The control plane does not hold provider keys; the engine does, keyed by the
connection's `key_id`. The saved Test Connect path already uses the stored key
inside the engine without returning it.

Decision:

- Engine: a private route, `POST /api/tunnex/saved-model-catalog`, takes
  `{provider, key_id, key_name, mode, query, limit, offset}`. It finds the
  stored key the way the saved Test Connect does: the `tnx-managed-` id, the
  revision name (`key_name`, so a rotated or replaced key is never used) and
  the same enabled rule. It then runs the same list, filter, paging and
  response shape as the draft catalog, sharing one code path. The key is held
  only in memory for that call; it is never returned or logged, and the route
  takes no `api_key`. Standard providers only: endpoint providers already have
  a connection-scoped catalog.
- The listing uses a transient key with all models allowed, as the draft
  search does, not the stored key's allowlist. The allowlist is the models
  already configured, which would hide the ones the user wants to add.
- API: `GET /ai-gateway/models` with `connection_id` and a standard provider
  is accepted for a saved connection of the same organization and provider.
  It calls the new route with the same 15-second bound and response checks as
  the draft catalog, and the same per-organization probe limiter.
- Refused, with no provider call: a connection of another organization or a
  missing one (404); a connection of a different provider, or an endpoint
  provider on this path (400).
- Falls back to today's list (merged for chat, reference for other modes)
  when the live call cannot run or fails: engine error or bad response,
  provider operations off, the limiter full, or the credential disabled or not
  yet applied. Falling back on the limiter rather than returning 429 matches
  the draft search.
- `AIProviderModelList` gains an optional `source`: `provider` (live list)
  or `reference` (fallback). It is set only on this path; custom, SageMaker
  and Foundry responses are unchanged.
- Web: for a saved standard credential the search sends `connection_id`.
  `source=provider` shows "Provider catalog"; otherwise "Unverified catalog
  suggestions" with the AI-CATALOG-1 notice ("Your provider's live model list
  could not be read. Showing known models; Test Connect confirms access.").
  Paging stays on the source that answered the first page. The draft search is
  unchanged.
- The endpoint stays readable by anyone who can read provider connections,
  but only a provider manager (`ai_provider:manage`) gets the live list. Only
  managers add models, so only they make the gateway call a provider with a
  stored key. A viewer with `connection_id` gets the reference list, marked
  `source: reference`, and no provider call is made.
- Shared limiter: saved-credential searches use the same per-organization
  window as Test Connect and the draft search (one at a time, six a minute).
  Searching a lot, or clicking Test Connect while a slow live list is still
  loading, can make Test Connect answer 429 ("connection test limit
  reached"). The draft flow already behaves this way.
- Known limit: the search runs half a second after typing stops, so typing a
  lot within a minute can use up the limiter and drop to the reference list.
  The draft search behaves the same way.
- Not audited, like the draft catalog and other catalog reads.
- Rejected: dropping the reference list for saved credentials. It is still
  the only answer when the provider list cannot be read.
- Rejected: storing deprecation data. The bundled list has none, and the
  provider's own list is the source of truth.

Next step after Add Credentials (founder feedback, same walk): Add
Credentials asks only for a name and key, so after saving there was no
obvious next step.

- A new credential saved from Add Credentials without models opens a small
  "Credentials saved" panel: "Add models from this credential" or "Later".
- "Add models from this credential" opens the existing Add Model wizard at its
  Models step with that credential selected, so its search uses the live
  saved-key catalog above. The wizard's steps are unchanged, and Back still
  reaches the provider and credential steps.
- Not shown after editing an existing credential, after Add Model, or to
  users who cannot manage providers.
- The credentials and Add Model routes are separate page instances, so the
  credential travels in the URL (`/ai-gateway/models/new?credential=<id>`)
  rather than in page memory. The id is only a preselection; Add Model still
  lists only that organization's saved credentials.

Validation:

- Engine Go tests: the shared listing reads every page, filters, sorts and
  never returns the key; the stored-key lookup matches id, revision name and
  enabled state. The native transport test calls the route on a built engine.
- API tests: live success gives `source=provider`; engine failure gives the
  merged list with `source=reference`; another organization's connection is
  refused; custom and Foundry paths are unchanged.
- Web tests: saved standard credential sends `connection_id`, labels by
  `source`, pages on one source, and the draft search is unchanged; a new
  credential from Add Credentials offers Add Model with it preselected.
