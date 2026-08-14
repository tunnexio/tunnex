# Upgrading Tunnex

## The contract

**Upgrades are forward-only. There is no downgrade.** If an upgrade goes wrong, the rollback is
**restore from backup** — which requires the master key you custody separately from the database dump (see
[backup-restore.md](backup-restore.md)). Those two sentences belong together: "forward-only" is only a
reasonable policy because restore-from-backup is a real one, and restore-from-backup is only real if you have
both artifacts.

Why not support downgrade: every schema migration would need a tested reverse path and every artifact version
a backward transform, forever — an enormous ongoing tax for a case that, in practice, operators resolve by
restoring a backup. Forward-only is honest about that rather than shipping a downgrade path nobody exercises.

**Agent version support: N and N-1.** A control plane at protocol version *N* works with gateway agents at
*N* and *N-1*. That is what makes a rolling upgrade possible — you do not have to upgrade every gateway before
the control plane.

This is a mechanism, not a promise. Policy artifacts are stamped with the **oldest** protocol version whose
shape covers their content, so an organization using no new-version features keeps receiving an old-version
artifact its older agents apply correctly. A test (`TestNMinusOneAgentsCanStillApply`) fails the build if that
ever stops being true, and `preflight` tells you before a roll whether any gateway is below the window.

**An agent below the window fails closed, not open.** It refuses the artifact entirely rather than partially
rendering it — so it keeps enforcing the policy it last applied and stops receiving updates until upgraded.
Safe, but you will want to know: that is what preflight is for.

## Before you upgrade: preflight

## Verified host upgrade (online or air-gapped)

The read-only upgrade center never executes host commands. Operators can use the
repository's `deploy/upgrade.sh` helper on the deployment host. It refuses to pull
or restart anything until a signed descriptor is verified and the backup/preflight
gates pass. The default is a dry run; `--apply` is an explicit approval.

```sh
./upgrade.sh
./upgrade.sh --apply
```

The installer places `upgrade.sh` next to `tunnex.yml`, records the trusted release
key and a baseline hash for that deployment file in `.env`, and the API image carries
the verifier binary. The helper refuses an edited `tunnex.yml` before it reaches Docker.
Every successful-main installer fetches the immutable signed `release.json`
descriptor for its exact source SHA and mounts it into the API. Online deployments
then fetch only the signed `tunnex-updates` discovery descriptor when the host
helper runs; a missing, altered, or mismatched descriptor is a hard failure, never
an invitation to pull an unverified tag. Set `TUNNEX_RELEASE_UPDATE_CHECK=false`
and supply `--manifest` for air-gapped operation.

The installer baseline currently covers the deployment compose file only. Image
digest and arbitrary source-tree attestation are intentionally not inferred from a
mutable local Compose tag: the release manifest needs an explicit installed-image
mapping (and a defined source-build policy) before the updater can fail closed on
those cases without rejecting legitimate custom or air-gapped deployments.

For an air-gapped host, place pre-pulled OCI archives in a bundle directory and
pass `--airgap BUNDLE`; the helper loads those archives only after descriptor
verification. Keep the backup dump and manifest together for the documented
forward-only restore procedure. Downgrades are refused by the signed sequence
check; there is no silent or browser-triggered upgrade.

`preflight` ships **inside the control-plane image** — it needs `DATABASE_URL`, and an operator running it
before a roll should be reading the database the deployment actually uses, not one named on a laptop:

```bash
docker compose exec -T api preflight                        # Compose
kubectl -n tunnex exec deploy/tunnex-api -- preflight        # Kubernetes
```

It **changes nothing** — every check is a read — and it **refuses** rather than warning, because a warning in
a deploy log is a warning nobody reads. It checks:

| check | why it can strand an upgrade |
|---|---|
| database reachable | an upgrade cannot be assessed, let alone performed |
| migration state clean | a *dirty* state means a previous migration failed part-way: the schema is neither old nor new, and rolling onto it turns a recoverable state into an unrecoverable one |
| agent version window | any gateway below N-1 will refuse its artifact after the upgrade and stop receiving policy updates — the remedy (upgrade those agents first) only exists *beforehand*. This check also **refuses when any gateway's certificate has expired**: such a gateway cannot reconnect at all, so its reported version says nothing about what it can apply, and a fleet containing one is not a fleet to roll onto without knowing. Re-enroll it first |
| rollback plan | forward-only means your only rollback is a verified backup **plus** its master key |

A check that cannot be evaluated is reported as **unknown and refuses** — "I could not tell" and "it is fine"
are different answers, and only one of them may proceed.

The rollback check is an explicit acknowledgement, because preflight cannot see your offsite backup:

```bash
# after taking a backup and verifying it with `backupctl verify`
docker compose exec -T -e TUNNEX_PREFLIGHT_BACKUP_CONFIRMED=yes api preflight
```

## The rolling procedure

**Never a flag day.** In order:

```bash
# 1. Back up, and VERIFY the backup against the master key you hold.
#    backupctl/preflight run IN the control plane — that is where the master key and DATABASE_URL are.
pg_dump --format=custom --no-owner "$DATABASE_URL" > pre-upgrade.dump
docker compose exec -T api backupctl manifest "pre-upgrade" > pre-upgrade.manifest.json
docker compose exec -T api backupctl verify < pre-upgrade.manifest.json   # must pass before you continue

# 2. Preflight.  Refuses if anything would strand the roll.
docker compose exec -T -e TUNNEX_PREFLIGHT_BACKUP_CONFIRMED=yes api preflight

# 3. Migrate the database. Migrations are backward-compatible for one version (enforced by
#    TestMigrationsAreBackwardCompatibleForOneVersion), so the OLD control plane keeps working
#    against the NEW schema while replicas roll.
migrate up

# 4. Roll the control-plane replicas. Any mix of old and new runs correctly during the roll.
#    Scheduler leadership moves on its own: the leader releases its lock as it shuts down and a
#    replica picks it up (see the HA note below).
kubectl -n tunnex set image deploy/tunnex-api api=ghcr.io/tunnexio/tunnex-api:vX.Y.Z
kubectl -n tunnex rollout status deploy/tunnex-api

# 5. Gateways reconcile on their own. No action, no re-enrolment.
#    Upgrade them at your convenience, one at a time — they are within the support window.
```

**Running tunnels are not interrupted by any of this.** Agents forward traffic from their applied state and
reconcile against the control plane periodically; a control plane that is restarting, migrating, or briefly
absent does not touch the data plane. An upgrade is a management-plane event.

### Why step 3 is safe

Migrations must be backward-compatible for one version, and that is a **build-enforced rule**, not a
convention: a census of the shipped migrations found two historical exceptions (a dropped column and a renamed
column), so the property was holding by luck. A guard now fails the build on `DROP COLUMN`, `DROP TABLE`,
`RENAME COLUMN`, `ALTER TABLE … RENAME TO`, narrowing `ALTER COLUMN … TYPE`, and `SET NOT NULL` in any new
migration.

Removing a column therefore takes two releases — **expand, migrate, contract**: drop the last *reader* of the
column in release N, drop the *column* in N+1. If a release ever genuinely must break compatibility, it will
say so here explicitly and require a short maintenance window; the guard exists to force that to be a stated
decision rather than a surprise.

### Control-plane HA during the roll

Request serving runs on **every** replica; only the periodic schedulers (hub failover, CRL rebuild, flow-log
retention) are leader-gated, via a Postgres advisory lock. A follower is fully **ready** — it serves API
traffic and simply does not tick — so a rolling upgrade never removes capacity.

Honest limit, and it is **two different limits** that are easy to merge into one wrong sentence:

- **The leader stops or dies** — clean shutdown, crash, `kill -9`, container removal. Its Postgres connection
  *closes*, so the session ends and the advisory lock frees immediately; another replica acquires within about
  ten seconds. **Verified on a live deployment**, both for a graceful stop and for a SIGKILL. This is the case
  a rolling upgrade actually produces.
- **The leader is network-partitioned while still running.** Its session stays open from Postgres's point of
  view until TCP keepalive expires, so the lock is not released and takeover can take minutes.
  **Not verified — no partition test has been run.**

Nothing ticks during either window — no failover promotion, no CRL refresh — which is safe rather than degraded,
because those are periodic reconcilers and never sit in the request or data path.

## If an upgrade goes wrong

There is no downgrade. Restore:

```bash
# 1. Put the master key that belongs to the backup in place.
# 2. Verify BEFORE writing anything — this refuses on a key mismatch (exit 2).
docker compose exec -T api backupctl verify < pre-upgrade.manifest.json
# 3. Only if step 2 passed:
pg_restore --clean --if-exists --no-owner -d "$DATABASE_URL" pre-upgrade.dump
# 4. Roll the control-plane image back to the previous version.
```

Your gateways reconnect on their own: they hold their own keys and pin the agent CA, which is in the restored
database. No re-enrolment, no new certificates.
