# Scoped sandbox readiness diagnostic rollout

Historical diagnostic scope decision. This paper supplies no current activation permission. Its deployed schema181 refers to the historical source checkpoint; the reconciled publication schema is195. Current checks are in S-sandbox-pr-validation.md.

The approved diagnostic bundle uses deployed API baseline `41640584b167e132ec1a7d1cfcdd531e18d22acf` and only commit `81335963a4e753def158231f2d384772a790e141`'s changes to `cmd/server/main.go`, `internal/sandboxes/readiness_policy.go`, `internal/sandboxes/resume.go` and the new `internal/sandboxes/readiness_diagnostics.go`. Their focused regression tests are included for local qualification. Other story-branch runtime changes are excluded.

Build and pin the Linux AMD64 enterprise API offline, qualify the focused checks in both editions, and replace only the existing CP API image. Preserve schema181 and every effective environment, mount, credential, private address and listener setting. Retain the previous cached API image and exact image-only rollback; health must pass within60seconds or restore that compatible image. No runner binary/config/unit changes are needed.

Start the existing actor and transport roles without boot enablement. Parent owns exactly one authenticated UI Create: the existing creator/Mac/key binding, qualified preloaded Minimal image,128MiB/1CPU/64PIDs, empty scope, no skills/delegation and900-second original creation-based expiry. Aggregate224MiB/256tasks/zero-swap and existing IO/storage caps remain. Record typed policy-gate observations and canonical timestamps, with one ordinary private SSH command; no repeated SFTP/Resume/transport matrix. Keep the independent expiry guard active, confirm exact TTL/provider/network/credential/files retirement, then stop roles and verify creation unavailable.

This is diagnosis only. No TTL correction, latency optimization, schema change, policy/account change, new infrastructure, package installation, extra trial, push or merge is included. Unexpected pin/config drift stops the bundle instead of broadening it. The first-Ready lifetime proposal belongs to a later versioned contract.
