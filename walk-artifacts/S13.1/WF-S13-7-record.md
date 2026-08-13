# WF-S13-7 — CLOSED ON THE ARTIFACT. **NOT ON A WIRE RUN.**

> ⛔ **READ THE BOUNDARY BEFORE THE RESULT.** A later reader must not come away believing a freshly
> UI-enrolled gateway was watched expiring and recovering. **It was not.** Two halves, two instruments,
> and only one of them is a wire proof.

## THE CLAIM

*A gateway installed by the DOCUMENTED PROCEDURE loops forever on expiry, because the UI's emitted enroll
command pins a `ghcr` digest that predates S13.1.* The mechanism can be perfect and the copy-paste still ship
the old one — so the finding is about the ARTIFACT the operator is handed, not about the code.

## WHAT WAS PROVEN, AND BY WHICH INSTRUMENT

| half | instrument | result |
|---|---|---|
| **the UI emits the S13.1 digest** | the founder read the Gateways page and pasted the command **verbatim** | ✅ carries `@sha256:f9d86c1a…` |
| **that digest contains the fix** | `grep -c agent_identity_recovery_at_runtime` **inside the shipped image** | ✅ **1** |
| **the fix recovers an expired cert in place** | **§C′ on the wire** (`Cprime-record.md`), same code | ✅ recovered 18:17:41Z, no restart, mTLS port black throughout |
| **a UI-enrolled gateway observed recovering** | — | ❌ **NOT DONE** |

⛔ **THE COMMAND CAME FROM THE FOUNDER, NOT FROM ME, AND THAT IS THE POINT.** A command reconstructed from
`config.go` or read from `/api/v1/meta` tests the CONFIG VALUE; the subject is the string the SPA renders for
an operator to copy. A locally-sourced command is precisely what hid this through the whole of §A. The server
half was proven separately (`/api/v1/meta` served the digest verbatim); the last hop — the SPA rendering it —
could only be closed by a human reading the page.

## WHY THE WIRE RUN WAS NOT DONE

The enrolment ran on `azure-gw` and **that host is the live `k8s` gateway** — same machine, running the agent
natively rather than in a container, which three container-surface checks failed to reveal (filed in
`laws.md`). Continuing would have applied a fleet-wide 10-minute certificate TTL and a control-plane partition
to a **live gateway that was never in the approved blast radius**.

The run was HALTED, the enrolled container and volume removed, the orphaned node row deleted, and the `k8s`
gateway proven whole afterwards — pid, port binds, control-plane connection, `openvpn`, and its certificate
serial **byte-identical** to the pre-run baseline.

⚠ **The remaining gap is one code path tested twice, not one untested.** §C′ exercised expire-and-recover
against the same `identityWatchLoop` that this image is now proven to contain. What a second run would add is
that the path holds for a gateway whose provenance is the copy-paste — which is a provenance claim, and
provenance is exactly what the grep above establishes.

## HOW TO CLOSE IT FULLY, IF WE EVER WANT THAT

**Provision a genuinely separate host** — not `aws-gw-1` (the §C/§C′ subject, hand-built image), not `aws-gw-2`
(§A leg-3's subject), not `azure-gw`/`k8s` (this one). Enrol from the UI's emitted command, then reuse the §C′
rig: short TTL, partition `:8443`, wait past `not_after`, restore, watch `agent_identity_recovery_at_runtime`
→ `agent_identity_recovered_in_place` with `RestartCount`/`StartedAt`/pid unchanged. **~20 minutes plus a VM.**

**It is not required for the claim as stated.** WF-S13-7 says the documented install ships the fix. It does.
