# Backup and restore

A Tunnex control-plane backup is **two artifacts, and you must keep both**:

1. **A PostgreSQL dump** — every organization, policy, device, node, audit row, and the *sealed* secret
   material (the agent CA private key, the OpenVPN CA and profile keys, MFA secrets, SSO client secrets).
2. **The master key** — a 32-byte secret, held *outside* the backup, which is the only thing that can decrypt
   the sealed material in that dump.

**The master key is deliberately NOT inside the backup.** A backup carrying its own key is equivalent to no
encryption at rest for anyone who obtains the file — and backups are the most-copied, least-guarded artifact
in a deployment: offsite storage, object buckets, a laptop. The whole reason the material is sealed is that
possessing the database is not enough.

## What happens if you lose one

Stated plainly, because this is the sentence that decides whether people actually store the key separately:

| lost | consequence |
|---|---|
| **The dump** | Restore from an older one. You lose whatever changed in between — nothing is unrecoverable. |
| **The master key** | **The sealed material is unrecoverable.** The agent CA cannot be read, so no certificate can ever again be issued that your enrolled gateways will trust: **the whole fleet must re-enroll.** Devices must be re-issued. MFA enrolments, SSO client secrets and OpenVPN profiles are all lost. |

Back the key up separately, and to somewhere the database backup does not also live.

## What a backup does *not* contain — and why that is a good property

**Gateway and device private keys are never in the control plane at all.** A gateway generates its own
WireGuard key and keeps it; the CP stores only public keys. Devices are the same — there is deliberately no
private-key column in the schema.

So a CP backup restores the *control plane's* state, not the *fleet's* secrets — and it does not need to,
because the fleet's secrets never left the fleet. The adjacent recovery stories are separate and simple:

- **A lost gateway**: re-enroll it (one pasted command). It generates a fresh key; the CP re-issues its
  certificate. Nothing needs restoring.
- **A lost device**: the user re-enrolls it the same way.

This is why an earlier plan item calling for "node-agent state (WG private keys on each gateway)" in the
backup was struck: a backup cannot carry what the control plane structurally never holds, and promising it
would be a recovery claim the artifact could not honour.

## Taking a backup

`backupctl` ships **inside the control-plane image**, because that is the only place `TUNNEX_MASTER_KEY` and
`DATABASE_URL` are already in the environment — the manifest's whole job is to fingerprint the key this
deployment actually holds, so it must run where that key is.

```bash
# 1. The dump.
pg_dump --format=custom --no-owner "$DATABASE_URL" > tunnex-$(date +%F).dump

# 2. The manifest (records WHICH master key this dump is sealed under — never the key itself).
#    Compose:
docker compose exec -T api backupctl manifest "pre-upgrade" > tunnex-$(date +%F).manifest.json
#    Kubernetes:
kubectl -n tunnex exec deploy/tunnex-api -- backupctl manifest "pre-upgrade" > tunnex-$(date +%F).manifest.json

# 3. The master key — stored SEPARATELY, once. It does not change between backups.
#    In Kubernetes it is the Secret the chart requires you to create (the chart never mints one,
#    precisely so that this is a deliberate act you can back up).
kubectl get secret tunnex-master -o jsonpath='{.data.key}' | base64 -d > tunnex-master.key   # store offline
```

The manifest is small, contains **no secret material**, and carries a *keyed fingerprint* of the master key —
an HMAC, never the key and never reversible to it. Its only job is to answer, at restore time: *is the key
this control plane has the key this backup was sealed under?*

## Restoring

```bash
# 1. Put the master key in place FIRST (the CP will not start without it, and will never mint one).
# 2. Verify BEFORE writing anything — this refuses if the key does not match the backup.
#    Run it in the control plane, against the key that control plane holds. Exit 2 = key mismatch.
docker compose exec -T api backupctl verify < tunnex-2026-07-29.manifest.json
#    Kubernetes: kubectl -n tunnex exec -i deploy/tunnex-api -- backupctl verify < tunnex-2026-07-29.manifest.json
# 3. Only if step 2 passed:
pg_restore --clean --if-exists --no-owner -d "$DATABASE_URL" tunnex-2026-07-29.dump
```

**Verification runs first and refuses loudly on a mismatch, before any data is written.** This is deliberate.
The catastrophic outcome is not a *failed* restore — it is a restore that *succeeds* with the wrong key. That
gives you a control plane which starts, serves traffic, and cannot read its own agent CA: every enrolled
gateway is silently orphaned, and you find out later, from the fleet, with the backup already written over
the evidence. A restore that half-applies and then fails is worse than one that refuses, so it refuses.

If the fingerprints differ, the error names both and tells you what would have happened. Restore the master
key that belongs to that backup and retry.

## After a restore

Your gateways reconnect on their own. They hold their own keys and pin the agent CA — which is in the
restored database, sealed under the key you just verified — so no re-enrolment, no new certificates, and no
manual step. That is the property the whole design protects, and it is the EPIC 11 box-walk's owed proof:
restore a control plane from backup on real hardware, and an existing agent connects unchanged. Until that leg
is recorded in `walk-artifacts/S11/`, treat this paragraph as the design's intent rather than a demonstrated
result.

Running tunnels are not interrupted by a control-plane outage in the first place — agents reconcile against
last-known state and keep forwarding — so a restore is a recovery of management, not of connectivity.
