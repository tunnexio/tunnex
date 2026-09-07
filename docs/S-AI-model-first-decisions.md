# LiteLLM model-first workspace

User requests the LiteLLM model/provider experience as-is, calls out missing
Azure Foundry and confusion between Connections and Models. Read actual MIT
LiteLLM UI at source168a0055a244acdcf97c330c52e085ab40b1424c:
`ui/litellm-dashboard/src/components/add_model/AddModelForm.tsx`,
`provider_specific_fields.tsx`, `litellm_model_name.tsx`,
`reuse_credentials.tsx` and `handle_add_model_submit.tsx`.

## Locked UI slice

- Models & endpoints opens All Models first. Add Model is the primary action;
  LLM Credentials is the secondary view for retained key rotation, disable and
  deletion. Existing saved connection ownership stays intact.
- One Add Model flow accepts a provider and models, then Existing Credentials
  OR endpoint/key. Creating credentials is automatic in that same submission;
  a separate connection-name setup step is not required. An optional credential
  name can override the generated provider/model label.
- Keep Tunnex theme, drawer, generated API and tenant authorization. Follow the
  upstream field ordering and vocabulary while preserving test-before-save,
  an explicit user requirement stronger than upstream's optional Test Connect.
- Show the standard API base URL for native providers. Alternate URLs continue
  through the approved Custom path until typed provider routing exists.
- Retain every existing mutation surface and explain credential disable/delete
  scope. No stored key readback or fake successful catalog/inference claims.

## Azure Foundry integration finding

LiteLLM's Azure_AI_Studio registry entry maps to runtime azure_ai, accepts a
Target URI/api-version and API key. The installed SDK1.100.0 has this adapter.
The current saved-inference engine custom route always speaks OpenAI /v1 with
Bearer authentication; the SDK is currently used for preflight and the scoped
SageMaker bridge. Adding an azure_ai dropdown or changing preflight alone would
not implement saved Foundry inference. Do not represent it as available that way.
Record the end-to-end routing/credential persistence design before adding this
provider; inspect actual adapter behavior, preserve egress/tenant boundaries and
test both preflight and saved inference. No Azure resource operations authorized.

Validation: model-first create with automatic credential name, saved credential
reuse preserving models and revisions, management actions, stale test refusal,
focused/full web checks and actual local rendered preview.
