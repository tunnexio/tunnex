# Local installed API walkthrough

This zero-spend walkthrough starts the actual Linux ARM64 API executable, pinned
Bifrost image, PostgreSQL and Redis on a new private Docker network. It uses real
administrator login, forced password rotation, human sessions and canonical
agent enrollment/policy APIs. It does not install a gateway or agent binary.

Run from a checked-out repository with Go and Docker available. Build the API
for Linux ARM64 with the repository's normal read-only module settings. Select
an unused explicit project and an output directory that does not exist:

```sh
GOCACHE=/absolute/private/go-cache \
python3 deploy/ai-gateway/installed-walk/run.py \
  --context YOUR_VERIFIED_LOCAL_CONTEXT \
  --project tunnexai-local-unique \
  --api-binary /absolute/private/tunnex-api-linux-arm64 \
  --output-dir /absolute/private/new-walk-results
```

The project name must contain only lowercase letters, digits and hyphens. All planned container, network and volume names must be absent. Existing project
resources are refused; the script never repairs, reuses or deletes them. Before
starting PostgreSQL, it verifies its own container label, network and exact named
volume ownership. It prints the verified database boundary before migrations or
fixture SQL. Cleanup stops only verified immutable IDs created by this run and
retains all named volumes, networks and stopped containers.

Fixture passwords are generated for the run. Private logs, cookie jars and
runtime credentials are not printed; output files use owner-only permissions and
the output directory ignores its contents at creation.
Do not publish or commit retained runtime state. `sign.go` generates an ephemeral
Ed25519 verifier and a signed **fictional, unpublished** release descriptor so
normal bootstrap verification remains active. No release assets are downloaded,
published or installed. One eligible gateway row is seeded into the explicitly
verified new database; all users, organizations, agents, groups, memberships,
AI policies and revocations use the actual API.

The provider responds locally and spends no credits. Its prompt and response
markers allow checking logical and raw SQLite metadata for content omission
across both normal and streamed requests. The script validates complete SSE
frames, text, finish and terminal events, not just a200 response. Monetary proof
is labelled as an observed threshold only when exact pricing is known, policy
revisions are applied and complete scoped observed cost already exceeds it.

This test uses private plaintext HTTP between local containers. It does not
qualify public TLS, a packaged CP image, Helm/CNI deployment, gateway networking,
real providers, crash recovery or cross-version upgrades. The API is an actual
process within a pinned Go container; Docker is not asked to publish host ports.

Safety checks can be exercised without Docker:

```sh
PYTHONPYCACHEPREFIX=/absolute/private/python-cache \
python3 -m unittest discover -s deploy/ai-gateway/installed-walk -p test_isolation.py -v
```
