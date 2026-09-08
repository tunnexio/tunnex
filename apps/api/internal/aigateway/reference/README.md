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
`litellm_provider` is exactly `azure`, with these fields:

- `id`: original root JSON key;
- `provider`: original `litellm_provider`;
- `mode`: original `mode`.

All 230 Azure entries are retained as source evidence, sorted by original key.
Runtime filtering accepts only `chat` entries with a top-level `azure/` prefix,
then strips that prefix. It includes GPT and o1/o3/o4 families, omits nested
regional/pricing aliases and audio/realtime variants, and refuses other provider
and mode families. Names are sorted and deduplicated before pagination.

These are model-name suggestions, not the customer's deployment inventory or a
promise that a particular Azure resource supports them. Users can enter their
exact deployment name and use Test Connect. No prices, costs or accounting
behavior are imported. Runtime access requires no external fetch or credential.

To refresh, pin a new GitHub commit first, download that commit's root catalog
and license, repeat this field extraction, update these hashes and the snapshot
provenance test, and review the filtered model/mode changes before committing.
