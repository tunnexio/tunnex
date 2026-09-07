# Credential entry and saved-field visibility validation

Decision papers: S-AI-endpoint-entry-decisions.md (f879db4b,998836c5).

## Implemented

- LLM Credentials has a direct Add Credentials creation action using the current
  model-scoped credential API, with explicit at-least-one-model explanation.
- Upstream API Base remains visible before provider selection. Native routes
  show their fixed origin; Use custom endpoint explicitly clears the native
  key/model/test state and selects the approved editable Custom route.
- Selecting Existing Credentials in Add Model hides both endpoint and key
  inputs. None restores the new-credential fields with an empty key and no
  reusable test proof. Edit Credentials retains immutable endpoint readback.
- Create returns to LLM Credentials; dismiss/navigation discards unsent keys.

## Verification

- 27 focused provider tests pass, including direct test/create payload and
  return view, stale result/draft disposal and native/custom saved transitions.
- Full web suite:1359 tests across118 files pass. Typecheck and production build
  pass. Existing Vite large-chunk warning remains.
- Actual local CP browser: Add Credentials opened its drawer, OpenAI showed its
  fixed endpoint, Use custom endpoint selected Custom. Typed
  http://fixture:8091/v1 plus synthetic private-demo model/fixture key produced
  successful Test Connect and enabled Create credentials. No connection saved.
- Actual Existing Credentials selection reused Engineering demo (fixture).
  Rendered DOM contained neither API key nor Upstream API Base input. Existing
  three credentials/four models remained intact; no policy or key was changed.
- Screenshot evidence is in walk-artifacts/ai-gateway-20260907:
  add-credentials-endpoint-local.jpg and
  existing-credentials-fields-hidden-local.jpg. The masked preflight key was
  synthetic local fixture data. No paid inference/cloud action was performed.
- Independent static review covered endpoint approval, native/custom transition,
  secret disposal, immutable saved endpoints and creation return destination.

## Latest requested expansion is not complete

User subsequently supplied an independent Add New Credential modal, eight-mode
selector, model-detail JSON and broader-provider references. Current credentials
still require a model and current runtime still supports chat only. Do not call
this full LiteLLM parity. Concrete recommended state/protocol changes are in
S-AI-credential-modes-decisions.md pending disposition; Foundry saved routing
remains unresolved. Full composite gates retain the earlier VM-capacity blocker;
exact-head remote CI, push, merge and release were not performed.
