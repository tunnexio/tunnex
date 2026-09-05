# C5 third-worker entry gateway and HA blocker

Observed 2026-09-05 UTC. Product source remains
`61ecc5fec4e5a971faaf9b1c65ccdc7b3b4cd8c1`; no runtime source patch.

The user approved a separate entry gateway on the existing third worker,
without another EC2 machine. Paper: `6e0ea72`; scoped ingress: `e14c503`.
CloudFormation changeset `controllers-edge-20260905` added exactly five UDP
ingress rules and reached `UPDATE_COMPLETE`: client /32 to 31083, edge /32
to A3/B2 ports 31081/31082, and A3/B2 /32s to edge port 31083. No replacement
or new compute was requested. NLB qualification remains explicitly SKIPPED.

Native CLI plan ran 16:11:27.092–16:11:36.441, exit 0. Native install ran
16:12:22.173–16:13:19.761, exit 0. Release `tunnex-s205-edge` enrolled node
`01a07258-591d-7ef5-aa58-a07b436807fb` at `65.2.179.105:31083` on existing
worker `i-0afe3c3ecd00d1411`. Pod
`tunnex-s205-edge-tunnex-gateway-6f855df64f-cs6xp` was 1/1 Ready with zero
restarts; init host-posture admission reported ready.

Through the dashboard, the edge was bound to the sandbox site outside the
A3/B2 connector pool, then selected as primary hub at approximately 16:15:22.
Hub generation became 2. All three gateway Pods remained Ready at readback.

## Failure, not HA acceptance

The missing-entry-gateway prerequisite was removed, but the pool remained
`bootstrap_pending` / `base_authority_pending`. CP logs repeatedly reported
`Kubernetes ownership base authority does not match the exact desired base`
for `GET /agent/desired-state`, including 16:23:54. A fresh client VIP request
after the primary change timed out after 2 seconds. Historical direct-A3
VIP/FQDN HTTP 200 proof remains recorded separately; it is not a pass for this
new topology. Pod readiness is not ownership or traffic proof.

Read-only authority metadata at approximately 16:24 showed A3/B2 revisions
2, 3, 4 with unchanged per-node base hashes, but base versions advancing by 2
per revision. Latest deliveries were created at 16:19:01.089936 and expired
at 16:25:00. This is diagnostic evidence, not a proven root cause.

No authority was forced, no database row edited, and no networking repair or
remedial restart was used. HA and subsequent dependent legs remain blocked.

## Narrower runtime refusal

A3 logs at 16:27:41.716451457 and 16:28:07.318132099 report
`ownership full-domain readback mismatch: wg_peers` during
`desired_state_push`. B2 acknowledged authority revisions 1, 2, 3 and 5;
A3 had acknowledged none at the corresponding read. This distinguishes the
node's initial apply/readback failure from the subsequent CP version-binding
failure; neither is safely fixed by disabling exact ownership checks.

A read-only kernel peer enumeration showed the current desktop peer with
`10.99.0.2/32` and the edge peer with empty AllowedIPs. No IPv6 pool row exists
in the CP database. A later kernel snapshot alone cannot prove the expected
peer set at the instant of refusal.

Diagnostic boundary: a standalone GET-only executable was copied into
`/tmp/s205-peer-readback-Rsc3W7/peer-readback` in the A3 container. It uses the
existing in-container mTLS credentials without exporting them and prints only
public peer keys/prefixes, version and authority metadata. It does not replace
or alter the Tunnex binary, chart, identity, network state, or database. It is
diagnostic work, not additional acceptance credit. The temporary executable
is retained; no cleanup was performed.

## Confirmed compiler defect and local correction

The GET diagnostic saw only HTTP 500 during its bounded 30-request run. A
second standalone diagnostic invoked the unchanged CP peer compiler against
the existing database with every connection forced read-only. It returned:

- Desktop peer: `10.99.0.2/32`.
- Edge peer contribution from site transit: `10.99.0.0/24`, `172.31.0.0/16`.
- **The same edge key again**, from Kubernetes transit: `10.99.0.0/24`.

Both edge contributions had identical endpoint and keepalive. The second
diagnostic does not configure a policy provider: its evidence is the peer
path, not full policy/hash equivalence. Its temporary executable remains at
`/tmp/s205-cp-peer-readback-Rsc3W7` on the CP host and in its API container;
the running API binary was not changed. No credential value was emitted.

Decision paper `docs/S20.5-shared-topology-peer-correction.md` records the
bounded source fix. Regression tests failed with concatenation and passed
after compatible topology peers were combined into one deterministic union.
Focused API tests passed open and enterprise, plus open race. Focused node
ownership tests passed, including preservation of the ordinary site route
and desktop peer during the pool fence. Independent slice review found no
concrete P1/P2 findings; full compiler/hash execution was not directly tested.

The live CP still runs C5, not this correction. The next live topology must
also use the supported device-move workflow to home the desktop on the edge;
the serving ownership overlap guard must not be relaxed. Exact-final gates,
story-end review, new immutable publication and fresh live proof remain owed.
