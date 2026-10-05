# Local qualification evidence, 2026-10-03

Image recipes/static bootstrap source: `5007f70` for all six preserved builds.
Earlier Python-only candidate evidence exists in commit `e8069e5`; the current
manifest supersedes it with the completed shared-layer variants.

Build command per matrix member:
`deploy/sandbox/alpine/build-image.sh <arm64|amd64> tunnex-sandbox-alpine-task3-<minimal|python|node>-<arch> <profile>`.
Exact build logs remain task-owned local `/tmp/tunnex-alpine-build-<profile>-<arch>.log`.

Qualification command per matrix member:
`python3 deploy/sandbox/alpine/verify.py tunnex-sandbox-alpine-task3-<profile>-<arch>`.
All six exited zero. Each manifest member contains the exact tags, index/config/
platform digests, compressed OCI descriptors, package inventory, software versions,
measurements, payload SHA256 and positive/negative checks. Each used generated
fixtures only and removed its own container/volume. The amd64 matrix was emulated;
none of these results qualifies native rootless networking/readiness.

Checks per image: uid1001 SSH, exit37, Unicode/1MiB binary SFTP byte equality,
pinned identity, wrong pin rejection, same host key after restart; entrypoint
rejects root, symlink /run/sshd, world-writable /run/sshd and arguments; static
bootstrap --help executes; installed Python/Node code executes; excluded tools
are absent. Runtime resource caps and measurement methodology are in README.
No image was pushed and no API/org template registered.

Regression commands (all passed):

```
python3 deploy/sandbox/test_entrypoint.py
# apps/cli:
GOFLAGS=-mod=readonly go test ./internal/cli -run 'Sandbox|ManagedRuntime' -count=1
# apps/api, after provider/catalog changes:
GOFLAGS=-mod=readonly go test ./internal/sandboxruntime ./internal/sandboxes -count=1
GOFLAGS=-mod=readonly go test -tags enterprise ./internal/sandboxruntime ./internal/sandboxes -count=1
```

The pure metadata test checks six distinct measured entries, candidate status,
explicit emulation, sensible observed sizes vs evidence bounds, exact digest
lookup, absent metadata for unknown/Ubuntu identities and fresh catalog copies.
The provider regression asserts all existing quarantine/mount/identity controls
and that no runtime argv overrides the immutable image CMD. Ubuntu's recipe and
Python entrypoint are byte-identical to the starting checkout.

No shared OpenAPI/API handler/UI changes: source integration is held for admin
owner coordination. Consequently no frontend typecheck/build or shared-contract
regeneration is claimed. Generator-only Go header drift was restored. Native
Linux integration/DB tests skipped by their existing environment prerequisites
are not native qualification; see the concrete native verification plan.
