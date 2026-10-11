# Actual owned GCP HA fault checkpoints on source 0249

Deployed source: 0249f7cf8804a7d6b4e1f82bf4dbf42b887bdfe7. The diagnostic successor and the CNAME query-reuse candidate were not deployed for these observations.

BOTH: actual `077-result.json` completed true. During the two-peer loss, both owned UDP4500 filters registered positive drops (44 and 25); strict HA TCP/UDP denial and separate Classic TCP/UDP allowance passed. After explicit cleanup (`047-fault_event.json`), native recovery, all four full production guard observations, and fresh HA/Classic payloads passed. Pending native observations before the final gates remain included.

ONE: actual retained-flow v5 `093-result.json` completed true. Both holders were ready before their corresponding fault/restoration phases. Existing TCP tuple and same UDP socket checkpoints passed during loss (`056`) and recovery (`089`); fresh HA/Classic payloads and all four full guard observations passed at the accepted phase gates. Positive owned UDP4500 drops and exact cleanup were observed. Holder closures `094` and `095` are retained. Earlier ONE v1–v4 failures remain immutable in ROOT's separate private evidence; they are not superseded into success by this archive.

These are bounded controlled packet-loss, retained-tuple checkpoint, and recovery observations. They do not establish continuous availability, maximum outage duration, host HA, or an SLA. The exact configured API baseline and foreign-state preservation verdicts are distinct evidence, retained in the coordinator phase frames and hash-only foreign projections.

`manifest.json` binds every archived numbered receipt to its original SHA. Most receipts are exact bytes. Native frames are deliberately projected to an explicit public metadata allowlist (source/container/image/connection/boot, phase/contract/delivery/ownership digest, observed interfaces, owned BGP routes, guard metadata, SAD count); their complete original SHA remains recorded. Traffic-control native snapshots retain only selected drop-action tuples and counters with the original SHA. No whole NFT ruleset, journal, raw log, stderr, credential or key material is archived.

The two original private directories are `/private/tmp/gcp-ha-both-peer-actual-0249-20261011-v1` and `/private/tmp/gcp-ha-one-existing-actual-0249-20261011-v5`. UTC and monotonic timestamps in each frame are preserved; they describe observations rather than an inferred continuous outage interval.
