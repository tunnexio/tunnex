# AI-0 qualification harness

Experimental, not a production endpoint. No control-plane route imports this
module. See [decision paper](../../docs/S-AI-0-decisions.md).

## Local adapter boundary

```sh
cd experiments/ai0
GOWORK=off GOFLAGS=-mod=readonly go test -race ./...
GOWORK=off GOFLAGS=-mod=readonly go vet ./...
```

This runs deterministic HTTP/SSE tests. Native and paid tests explicitly skip
unless enabled; a default green run does not qualify Bifrost or a provider.

The adapter requires an injected trusted authorization function. Its result
must bind tenant, agent, model and a scoped virtual key with an expiry. Test
identities are synthetic and deliberately are not a new enrollment/token
implementation. Supported experimental payload fields are `model`, `messages`,
`stream`, `max_tokens`, `temperature`, `system`; other fields are refused.
Bodies are limited to 256 KiB; upstream requests/streams have a 30-second timeout
or grant expiry, whichever occurs first. Inbound reads/downstream writes do not
yet enforce that bound (held review finding). Only the two tested inference paths are accepted.
Upstream request/response headers are allowlisted, redirects and environment
proxies are disabled. There is no production concurrency admission policy yet.

## Pinned native engine

- Release: `transports/v2.0.0`
- Source: `e4a30d6041c0446603aea615bc5da340dac001b1`
- Official artifact: `https://downloads.getmaxim.ai/bifrost/v2.0.0/darwin/arm64/bifrost-http`
- SHA-256: `31ac451d83706069e580dd1dedf099aa518d1bc47c3c481d20f97203f799275e`
- Embedded Go build metadata matches the source commit, `vcs.modified=false`.

Download explicitly, verify the digest, make executable, then run:

```sh
AI0_BIFROST_BINARY=/absolute/path/to/verified/bifrost-http \
  GOWORK=off GOFLAGS=-mod=readonly go test -race -run TestBifrostNative -v -count=1
```

The native test checks the binary digest, creates a dedicated temporary SQLite
store, launches a loopback engine and a synthetic provider, verifies native
denial/streaming/admin authentication, revokes a virtual key through the admin
API and observes refusal after restart. Active-key controls and exact denial
contracts remain held review findings, so this is not conclusive persistence
proof yet. It does not inherit provider secrets.
Child processes and test-owned temporary files are released when the test ends.
Engine default catalog/pricing initialization can contact public upstream
services; inference targets the instrumented loopback provider only.

## Authorized paid smoke

Only after explicit permission to use the provider credential for these two
requests, supply a private regular credential file (mode `0600`). Never put its
contents into a command, config.json, tracked file or evidence. Provider config
uses an environment reference supplied only to the engine process.

```sh
AI0_ALLOW_PAID_SMOKE=yes \
AI0_OPENROUTER_KEY_FILE=/absolute/path/to/private/credential-file \
AI0_BIFROST_BINARY=/absolute/path/to/verified/bifrost-http \
  GOWORK=off GOFLAGS=-mod=readonly go test -run TestOpenRouterSmoke -v -count=1
```

The test sends one request per supported path through the local adapter and
Bifrost to `openai/gpt-4o-mini`, with 16 output tokens per request. It does not
retry deliberately or assert exact provider billing. It reports status/path
and streaming-request results, not prompts, response bodies or credentials.
Incremental/terminal-event assertions remain a held review finding. Do not run
it repeatedly as a regression suite. Synthetic identity means this is engine
and provider compatibility evidence, not enrolled-agent acceptance.

## Remaining AI-0 acceptance

- Real Tunnex enrollment/identity integration and current policy authorization.
- Measured budget concurrency/overshoot, retries, missing usage and persisted
  accounting across restart. Revocation persistence is not accounting persistence.
- Complete secret rotation/listener bypass matrix and tenant/team accounting.
- Engine selection disposition, independent findings disposition, and final
  repository gates/CI before merge. No production or beta readiness claim.
