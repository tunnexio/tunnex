# K8L-3 — `tunnex k8s` must work with Helm 4

Story branch: `story/kubernetes-launch-fixes`. Found on 2026-11-22: Google Cloud Shell ships
Helm v4.3, and `tunnex k8s install` there stopped before touching the cluster.

## What happened

    error: read Helm release failed: Error: unknown flag: --all

and, once past that, `helm install ... --atomic` fails with `unknown flag: --atomic`. The CLI's
version gate only refuses Helm older than 3.14, so Helm 4 was let through and then broke.

## What changed in Helm 4 (checked against `helm <command> --help` on 4.0.5)

| Used by the CLI | Helm 4 |
| --- | --- |
| `list --all` | removed; every status is listed by default |
| `install --atomic`, `upgrade --atomic` | renamed `--rollback-on-failure`; `install` rejects the old name |
| every other flag the CLI passes to list, install, upgrade, rollback, uninstall, history, pull | unchanged |

## Decision

1. One function, `helmArgsForClient`, rewrites those two flags when the installed client is
   Helm 4 or newer. Call sites keep writing the Helm 3 spelling, so Helm 3 behavior is byte-for-byte
   what it was.
2. The meaning does not change: the gateway install and upgrade are still undone on failure.
3. Helm 4 is supported, not refused. Refusing would turn away Cloud Shell and every workstation
   that installed Helm this year.
4. If the version cannot be read at a call site, the Helm 3 spelling is kept.

## Not in this story

A CI job that runs the chart contract tests on Helm 4. Worth adding before release.

## Proof

- Unit: the rewrite for 3.14, 3.17, 4.0.5, 4.3 and an unreadable version; the caller's slice is
  not modified; `list --all` handling for both majors. Existing CLI suite passes unchanged.
- Live: GKE Standard from Cloud Shell (Helm v4.3) — recorded in `docs/K8L-live-walk.md` when run.
