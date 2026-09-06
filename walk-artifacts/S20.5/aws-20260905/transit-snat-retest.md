# AWS transit SNAT correction — local qualification

Product source: `dc70c9bc847925f43d19bff59306ebb63ef5c7ec`.
Decision records precede product code in `648c7b0` and `ade26c3`.
Private candidate version: `0.0.1-walk.1.shadc70c9bc847925f43d19bff59306ebb63`.

## Reviewed correction

Journal schema 4 adds a distinct AWS source-tunnel + ingress/egress `wg0`
return receipt and finite authority scope. Schema 3 stays destination-only;
schemas 1/2 stay IP-MASQ-only. Active epochs never migrate in place.
The startup observer accepts the new finite scope. An explicit ordered walk
sequence avoids accidental hash-lexical manager downgrades while preserving
full source provenance and the existing 50-character version boundary.

Self-review and independent reviews found no concrete P1/P2 findings in the
final product slices. Independent review also covered the final startup
fixture correction and its real-store two-advancing-proof regression.
This is slice review, not final story-end multi-finder completion.

## Local results

- Real candidate packaging contract suite PASS with Go 1.25.13 / Helm 3.18.4:
  default deterministic packages, ordered sequences 1/10/999, full provenance,
  four charts and CLI, and invalid sequence/version refusal.
- Linux host-posture package PASS, including old-schema byte preservation,
  schema-4 cleanup, historical cleanup refusal and baseline leftover detection.
- Linux k8snetprep package and scoped fake-runner race suite PASS, including
  partial insertion, duplicates, restart cleanup and expired authority.
- Native host-posture race PASS. Native Darwin `cmd/agent` build is unsupported
  by existing Linux data-plane symbols; that failed invocation is not a pass.
- Real Linux startup tests PASS, including schema-4 correlated two-proof
  admission and continued proof freshness across a slow startup.
- CLI/operator/helper/helper-crosscompile targets PASS on detached `1da06bf`;
  their component trees are unchanged by this correction. These are not
  inherited exact-final whole-story gate results.
- Initial full node/race invocations exposed an outdated test-only schema
  threshold: the fixture mapped schema 3 to IP-MASQ after the current schema
  advanced to 4. Corrected to preserve 1/2, 3 and 4 independently; full target
  rerun and final startup race were started after correction.

## Real Linux packet witness (not AWS acceptance)

`TestAWSTransitKernelPackets` PASS with the actual C7 node image's nft/iptables
tools (iptables-nft-save 1.8.10) in a disposable privileged Docker container,
no network attachment or host network, and a nested isolated network/mount
namespace. A veth called `wg0` models ingress/egress; it does not substitute for
WireGuard cryptographic identity, live AWS CNI or the desktop client.

The production reconciler, native JSON parser and explicit compat readback
were exercised, not hand-written replacement exemption commands:

1. Destination-only legacy scope reproduces failed client-to-Service traffic.
2. New scope preserves source `10.99.0.2` to `100.96.0.3`; receiver source
   filtering makes a successful ping proof of the received source.
3. Reverse initiated Service-to-client traffic retains the Service source.
4. Same-pool source entering on `pod0` still receives AWS SNAT.
5. Client traffic leaving on non-WG egress still receives AWS SNAT.
6. An independent forwarding DROP remains effective with the exemption.
7. Production withdrawal restores source NAT; receiver accepts only SNAT source.

Each ping is a fresh process/flow. No conntrack flush is used. Exact foreign
rules/chain fingerprints, excluding only recognized owned returns and changing
counters, remain unchanged across reconcile and withdrawal.

Test-harness corrections before PASS: namespace sysctls needed a disposable
privileged container; the first fingerprint assertion incorrectly included
expected owned mutations; xt rule deletion matching was replaced with a
source-filtering deny inserted below the one SNAT-source accept. None of these
changed AWS, weakened product parsing, or repaired live networking.

## Live boundary / next transition

AWS identity freshly verified as account `735391218823`, principal
`arn:aws:iam::735391218823:user/aws-cli`, ap-south-1. Exact EKS cluster
`tunnex-s205-aws-20260905a` ACTIVE, VPC `vpc-05cbd22769f527e55`.
Existing A3/B2/edge pods remain Running with zero restarts and unchanged IDs.
No AWS mutation was used for this local proof.

Native transition: retain original PVC/PV and consumed claim identities;
uninstall B2/A3/edge through CLI, explicitly wait for restored old epochs and
idle manager/no owned artifacts, then reuse-install edge/A3/B2 with the new
published manager and gateway candidate. First install upgrades manager through
the native provenance path, subsequent installs reuse it. Verify new epoch =
old + 1, schema 4, unchanged node/WG identities and PVCs. No journal, Secret,
PVC, CNI or Helm-history edits. This entails a deliberate sandbox gateway
outage and is retained reuse evidence, not a fresh empty-cluster baseline.

Live IP/FQDN and HA legs remain pending. NLB remains SKIPPED. No PR, merge,
release, exact-final CI or story-complete claim is made here.
