# Customer normal API qualification gates — source-only

No live account, provider, grant or runtime writes have been performed by this plan. Run each of the four profiles through its own normal disabled fixture; actual traffic uses separate approved resources/grants. Full browser desktop/mobile qualification remains independent.

| Case | Concrete normal API gate | Pass evidence | Current live boundary |
|---|---|---|---|
| C01 | Admin configuration-check, disabled provider create, provider/configuration GET | Exact UUIDs and redacted wrapper profile/configuration revision, no PSK; no partial creation | Fresh static VPN IDs pending quota; BGP disposable fixture needs root release |
| C02 | Actual member/observer reads and denied create/config-check/intent/rotation/delete; cross-org paths | Normal authenticated roles, 403/404/401 before secret access; immutable provider/config state | Only admin credential currently bound; do not fabricate other roles |
| C03 | Invalid mode/fields/prefix/inside/PSK/tunnel count; BGP ASN/router/limit | 400 coded redacted error, marker absent, connection list unchanged | Validation POST only; no DB writes |
| C04 | Frozen create retry; stale quoted CAS on disabled disposable intent/rotation | No duplicate identity, 409 stale CAS, 400 malformed header; current disabled revision/config unchanged | Never fault existing enabled providers for a CAS test |
| C05 | Real site/gateway eligibility and wrong references | Fresh source-bound native base/BGP capability and correct role/site | Expired capability lifecycle negative remains separate approved runtime gate |
| C06 | Static/BGP public status correlated with native receipts | Static selected slot; BGP selected per prefix, no global active slot; unknown/stale stays honest | No synthetic status POST or DB override |
| C09 | Exact grant plus neighboring port/source/destination and gateway-origin negatives | Independent target health and route, actual DROP/lease evidence; wrong nc exit alone insufficient | Reachable alternate target/source needs its own fixture; no ANY grant |

Normal paths and source tests are recorded in `customer-api-qualification-plan.py`. GET configuration is a separate `/connections/{id}/configuration` wrapper; provider GET omits configuration fields. API requires explicit `ipv4-static` or `ipv4-bgp`; the static-default claim belongs to the browser UI.

If member/observer accounts are absent, use an independently reviewed normal account lifecycle in an isolated test organization, preserving existing passwords and roles. Check invite/email side effects before creation. Never emulate a Principal, manipulate certificates/capabilities, or reset an existing account. O_EXCL intents and GET-only unknown-outcome reconciliation precede any fixture mutation.
