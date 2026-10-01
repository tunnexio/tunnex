# Release-baked model reference and pricing

The API and private Bifrost engine ship static model metadata and USD pricing
estimates. No LiteLLM package, Python inference process, provider key, or runtime
catalog download is required. Live authenticated provider model discovery remains
an explicit operation through the same Bifrost provider transport as serving.

The source is the MIT-licensed root catalog from
[BerriAI/litellm](https://github.com/BerriAI/litellm), used only as build-time data.
`source.pin.json` records the immutable commit, its source date, exact source and
license SHA-256 hashes, and reviewed completeness counts. The unmodified source
license is in `LiteLLM-LICENSE`; it is also embedded in the API and copied into
the engine image. The source catalog is outside upstream's enterprise directory.

Pinned source commit: `eeb7732fc11fd47762ca84cc3fb7cc74235d7097`.
Source date: `2026-09-06T01:12:56Z`.

- [Exact catalog](https://raw.githubusercontent.com/BerriAI/litellm/eeb7732fc11fd47762ca84cc3fb7cc74235d7097/model_prices_and_context_window.json)
- [Exact license](https://raw.githubusercontent.com/BerriAI/litellm/eeb7732fc11fd47762ca84cc3fb7cc74235d7097/LICENSE)

## Build and verification

From the repository root:

```sh
node --test scripts/ai-model-catalog.test.mjs
node scripts/ai-model-catalog.mjs --fetch --check
```

The CI command downloads only those exact pinned files, verifies both hashes,
validates field types, supported-provider coverage and completeness, derives all
artifacts, and requires byte-for-byte agreement with the committed files. The
build fails on network/source/license/checksum/schema drift. It never updates to
`main` or imports upstream code. For offline checks with previously verified
files, pass `--source FILE --license FILE --check` instead of `--fetch`.

To update deliberately, select a reviewed immutable commit, update its source
date and hashes/counts in `source.pin.json`, then run the generator without
`--check`. Review model/mode, price/unit, capability and context changes together;
commit the pin, license, generated artifacts and tests. Releasing refreshed
metadata follows the normal signed Tunnex release process.

## Artifacts and meaning

`model-catalog.json` embeds 969 source rows for the nine standard providers plus
Azure/Azure AI across the eight supported operation modes. Each row retains its
source ID, canonical provider-qualified ID, mode, declared context/capability
metadata, and price fields. `catalog-manifest.json` records every derived file
hash and the native completeness counts. Provider-specific names and Foundry
suggestions use this embedded snapshot without network access.

Names are suggestions, never proof that a key can use a model. Azure deployment
aliases, SageMaker endpoints and custom models require the customer's actual
configured identity. Static public prices are estimates at the source date;
they do not establish private contract rates, current billing, deployment alias
pricing, or a strict cost cap. Native request accounting remains separate.

`pricing_currency` is USD. `pricing_units` keeps each source unit explicit:
`USD/token` is per token, not per million tokens; image/second/character/query
and cache/tier/tool prices retain their units. Missing or null prices remain
absent, never zero. An explicit source zero remains an explicit zero. Conflicting
aliases cannot qualify a token rate. API token estimates use exact-provider,
exact-model input/output rates; media prices never become token prices.

The native Bifrost files are `bifrost-pricing.json` and
`bifrost-model-parameters.json`. They use its native `provider` datasheet field
and canonical map keys. Duplicate names are resolved deterministically, while
conflicting or incomplete token pricing records are omitted so an unknown rate
cannot become native zero-priced usage. Static metadata remains available for
those names. Regional/image-size pricing paths are excluded from model choices.
The engine reads these files at `/app/catalog/` via `file://` URLs, with automatic
live-model and MCP-library background refresh disabled. Neither file contains
provider credentials or claims authenticated model availability.
