# LiteLLM Azure model reference snapshot

Source repository: https://github.com/BerriAI/litellm

Pinned commit: `eeb7732fc11fd47762ca84cc3fb7cc74235d7097`

Commit timestamp: `2026-09-06T01:12:56Z`; retrieved September 8, 2026.

Exact source: https://raw.githubusercontent.com/BerriAI/litellm/eeb7732fc11fd47762ca84cc3fb7cc74235d7097/model_prices_and_context_window.json

Original source SHA-256: `f68d88c12610ea31ab355a1293fde55aeed6fa78a1f4b182c67be47d80b1d202`

Exact license: https://raw.githubusercontent.com/BerriAI/litellm/eeb7732fc11fd47762ca84cc3fb7cc74235d7097/LICENSE

License SHA-256: `b170d6bf8e8835dd357e011681db028f4d51e2fb0ea892058f56e01fb39b8273`

The root catalog is outside the upstream enterprise directory and covered by
the accompanying MIT notice, reproduced without modification in `LiteLLM-LICENSE`.
No upstream Python or JavaScript is executed or included by this reference list.

## Derivation

`litellm_azure_models.json` retains only original entries whose
`litellm_provider` is exactly `azure` or `azure_ai`, with these fields:

- `id`: original root JSON key;
- `provider`: original `litellm_provider`;
- `mode`: original `mode`.

All 351 Azure/Azure AI entries are retained as source evidence, sorted by original
key. Runtime filtering matches the selected operation and each row's provider
prefix, then strips that prefix. GPT, Llama, DeepSeek, Phi, Mistral and other
Foundry families are included. Nested regional/pricing aliases and chat
audio/realtime variants are excluded. Claude chat suggestions are included and
use the Azure Anthropic Messages endpoint. Names are sorted
and deduplicated before pagination. The derived snapshot SHA-256 is
`522e2790c78a318bf165b90965afc516d4c91d44a5b3c1f478bd6afe0bfbafdf`.

These are model-name suggestions, not the customer's deployment inventory or a
promise that a particular Azure resource supports them. Users can enter their
exact deployment name and use Test Connect. No prices, costs or accounting
behavior are imported. Runtime access requires no external fetch or credential.

To refresh, pin a new GitHub commit first, download that commit's root catalog
and license, repeat this field extraction, update these hashes and the snapshot
provenance test, and review the filtered model/mode changes before committing.

The companion `litellm_provider_models.json` uses the same full-source commit and
SHA-256. It retains 668 exact model/mode rows for the nine supported standard
provider forms and the eight requested modes. Bare names are canonicalized to
`provider/name`; provider-prefixed names retain their upstream suffix; unmatched
pricing-path aliases are excluded. It is used for nonchat catalog suggestions and merged with native chat catalogs before pagination,
never for usage accounting or proof of model entitlement. The Azure snapshot is
also filtered by the selected mode before search and pagination.
