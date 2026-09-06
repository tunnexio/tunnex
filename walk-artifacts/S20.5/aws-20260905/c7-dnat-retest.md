# C7 DNAT receipt correction and AWS retest

Source: `3081f63a0338ed95a444ba69665ca1e8de1ef42e` (clean immutable worktree).
Version: `0.0.0-walk.sha3081f63a0338ed95a444ba69665ca1e8`.

User approved the P2 test correction and explicitly authorized essential
continuation without routine approval pauses. Same private ECR account
`735391218823`, region `ap-south-1`, prefix `tunnex-s205-aws-20260905a`;
STS verified exact `aws-cli` principal. No new cloud resources or Azure use.

Corrected production-path Linux nft round-trip PASS; egress race PASS;
full final `make test-node` PASS. Independent source re-review closed P2
with no new concrete P1/P2 findings. This is scoped review, not story-end
multi-finder completion. Exact source SHA had zero GitHub check runs.

Six linux/amd64 images (including enterprise API) built and published with
remote digest equality checked, plus four private Helm charts. All four
charts were privately pulled and SHA256 compared with the bundle: PASS.
Private build logs and credentials remain outside Git.

The laptop public IP changed. Exact existing CP operator SSH rule
`sgr-0548dd638d19b896f` was updated from `122.183.45.166/32` to
`223.181.44.79/32`, TCP22 only. SSH recovered; CP HTTPS stayed healthy.
No other firewall rule was changed at this entry.

Effective CP configuration comparison PASS: only API/web/nginx images and
three candidate API metadata values differ from C6; stores and other
services unchanged. Native CP candidate rollout started. Gateway upgrades
and fresh HA/client proof are pending; not a walk PASS or merge-ready claim.

CP native rollout completed exit 0; health returned 200. First A3 attempt
00:50:41.252–00:51:11.738 UTC stopped at Kubernetes API context verification
(timeout), before Helm mutation. Read-only EKS inspection proved its public
endpoint still allowed only the laptop's previous IP. EndpointAccessUpdate
`42823a41-2116-3e05-b6b7-659c1c74d882` changes only that `/32` to
`223.181.44.79/32`, retaining both public and private access. The three
existing laptop-only UDP31081/31082/31083 rules were likewise updated to
the new `/32`; gateway-to-gateway rules and other resources remain unchanged.
This is an operator connectivity correction, not a product fix or HA proof.

Endpoint update succeeded. A3 retry 00:52:19.855–00:52:24.745 UTC then
correctly refused before gateway mutation: shared manager revision 2 had
plain Helm description `Upgrade complete`, not proven zero-touch provenance.
This was caused by the operator's C6 plain-Helm manager upgrade, not the
DNAT correction. It invalidates that manager-upgrade path as zero-touch proof.

Fresh history verified revision 1 has `tunnex-zero-touch/v1`; source diff
confirmed no hostposture code/chart changes between C5 and C7. A normal Helm
rollback to revision 1 was started as an explicit operator fixture repair.
No Helm Secret/history rewriting, forged description, journal/PVC edit, or
provenance-check bypass. This repair must not count as zero-touch acceptance.

Manager rollback completed: revision 3 records `Rollback to 1`, all three
manager instances Ready. Manager is therefore C5 again (its component source
is unchanged), not C7. CP C7 containers `db156daef5d2` API, `75034812ba18`
web and `b93287a32374` nginx are healthy; other CP container IDs unchanged.

A3 native retry 00:53:58.091–00:54:35.613 UTC completed exit 0. Replacement
`tunnex-s205-a3-tunnex-gateway-5bc78d7fdc-b6kgc` Ready 1/1, zero restarts.
B2 native upgrade started next. HA remained bootstrap_pending at the first
post-A3 check; a transient stale ownership tuple refusal was observed, not
the previous DNAT grammar refusal. Fresh fenced/client proof remains pending.

## Fresh fenced activation achieved

B2 native upgrade 00:54:52.676–00:55:29.708 UTC completed exit 0.
CP reported `actual_mode=fenced_ha`, `reason_code=fenced_base_ready`,
`achieved_at=2026-09-06T00:55:14.228073Z`, revision 181, generation 1,
membership epoch 0, active A3. A3 live nft readback contains the two-backend
typed `dnat ip to jhash` rule and receipt digest
`da08ea33fa250d837cd61af68f199839a78ed08e165726d0bc3cf564e73fcf17`.
This clears the DNAT activation blocker on AWS. It is not A→B/B→A failover
acceptance. Edge native upgrade started next. First local HTTP VIP probe
timed out (HTTP000); end-to-end client recovery is still unproven.

Edge native upgrade 00:55:39.267–00:56:16.969 UTC completed exit 0.
All three gateways are now on C7; shared manager remains the explicitly
restored C5 revision. Desktop remains the user-installed C5 build.

Desktop read-only UI shows Connected and tunnel address `10.99.0.2/32`;
local VIP route uses utun6 and the selected profile is managed against the
correct CP. Edge live WireGuard state includes the expected desktop public
key with `10.99.0.2/32`, but its handshake timestamp is zero, while gateway
peers have fresh handshakes. UI Connected alone therefore does not prove
current path connectivity. No desktop credential/config file was decrypted,
replaced or reimported, and no automated VPN disconnect/reconnect performed.
