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
