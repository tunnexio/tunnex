# AA-4 local acceptance evidence

Status: **Locally complete on 2026-10-03**. This qualifies the browser transport and dedicated authority boundary. Native app publication and positive app-session authority remain AA-5/AA-6 work. The owned runtime retains drafts and an empty serving-publication table.

The separate `apps/app-proxy` service uses direct TLS 1.3 authority authentication, a distinct hashed/versioned proxy credential, separate public and enrollment-CA gateway certificates, and purpose-bound outbound gateway channels. Every request obtains current authority. Independent lease timers interrupt HTTP reads/writes and hijacked streams when authority expires, including callbacks that ignore cancellation; a late callback cannot alter a reused connection after its response finishes.

Real TLS fixtures exercise the production proxy, outbound mTLS broker and origin transport: forms, assets, ordinary application credentials, bounded uploads, registered-origin cookie/redirect rewriting, SSE, valid RFC6455 multi-frame WebSockets and cancellation. The actual node BrowserPool sustains two open SSE requests while admitting a third form/asset request, and withdraws its channels when assignments disappear. Test-only route/session authority is injected explicitly; these fixtures do not establish native published access.

Final pinned Go 1.26.8 gates passed:

- App-proxy full race suite: 5.504 seconds, including framing refusal, callback/resource bounds and retired-response expiry regression. Independent real authority-client TLS/generated-payload/strict-JSON tests also passed.
- Node App Access/control race suites: 5.066 seconds and cached control results; Linux arm64 node and app-proxy builds passed.
- Shared transport full race suites: 7.282 seconds and origin policy 2.119 seconds. An independent strengthened origin streaming suite passed separately.
- Dedicated authority HTTP/config race suites, actual TLS with the isolated PostgreSQL child database, credential revocation and authenticated gateway withdrawal passed. Full API suite passed after the authority changes; tests requiring separately supplied infrastructure remain subject to their existing skips.
- Web TypeScript check passed against the final generated schema. Toolchain-pin tests and scoped generator regeneration checks passed; existing AA-3 web tests/build and browser origin-check proof remain recorded in their own evidence.

Migration 170 passed empty-publication denial, composite tuple constraints, hash-only credentials, version/revocation and transactional audit rollback. It is frozen after application to the explicitly owned local runtime. No live draft was promoted, and the Community/runtime authority listener remains disabled by default.

The generic denial page was inspected at desktop and 390px mobile widths without horizontal overflow. It discloses no private origin or tenant details. This is template visual evidence; a real browser launch/session journey belongs to AA-5/AA-6.

Compatibility limits are explicit in [the proxy README](../apps/app-proxy/README.md): root-path applications, known-length streamed uploads up to 64 MiB, bounded headers/concurrency, strict same-origin unsafe requests, qualified redirects/cookies, SSE and WebSockets. Chunked request bodies are refused to avoid accepting TE+CL ambiguity hidden by the standard parser. External OAuth redirects and cross-site POSTs require later qualification. No HTML/JavaScript rewriting, capacity benchmark, hard RSS guarantee, allocation fairness or production rollout is claimed. AA-7 owns operational shutdown/load and final revocation qualification.

Development remains uncommitted on `feature/app-access`. No push, PR, deployment or unrelated resource cleanup was performed.
