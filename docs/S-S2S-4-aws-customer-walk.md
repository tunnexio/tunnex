# S2S-4 AWS customer qualification walk

Status: **live AWS qualification in progress; not qualified**. This is the operator procedure for the implemented AWS static IPv4 profile. AWS interoperability and a qualified support label remain pending. Native strongSwan peer tests and synthetic UI previews do not establish AWS compatibility. Required exact-head full CI and native AMD64 recovery/rotation acceptance remain separate gates in [S2S-3 completion](S-S2S-3-completion.md).

## Scope and execution boundary

Use one AWS Site-to-Site VPN attached to a virtual private gateway (VGW), public IPv4 outside addresses, static IPv4 routes, two tunnels, IKEv2 and the fixed AES-256/SHA2-256/DH14 profile. Follow the constraints in [provider profile](S-S2S-2-provider-profile.md); its original proposal text is historical, not evidence that live qualification passed. BGP, transit gateway, Cloud WAN, IPv6, certificates, Azure, Google Cloud and appliance interoperability are outside this walk.

Before any live change, record and approve the exact account, region, resource IDs or proposed resources, owner tags, test window, spend cap, interruption budget and rollback/teardown plan. Run AWS discovery and changes only from the designated control-plane host. A development continuation does not authorize cloud creation, firewall changes, gateway restart or deletion. The initial document preparation performed no cloud mutations; the explicitly approved isolated live walk began on 2026-09-25.

Use an isolated test network and dedicated behind-host endpoints. Preserve management access independently of the VPN. Stop on uncertain ownership, unexpected impact, leaked credentials, plaintext bypass, unexplained deny failure or an exceeded time/spend bound. Restore only captured owned changes; do not improvise production repairs.

## Record the fixture

| Item | Required record, before testing |
| --- | --- |
| Software | Exact source commit, installed gateway/API artifacts and hashes, architecture, OS/kernel, strongSwan version, configuration/recovery capabilities, schema and CI receipts |
| AWS | Account/region, VPN/VGW/VPC IDs, both AWS tunnel endpoints and inside assignments, route tables, subnet/security-group/NACL IDs; label new versus pre-existing resources |
| Tunnex | Organization, Site, gateway, connection and ordered tunnel IDs; current desired/configuration/policy revisions; approved non-overlapping local/remote prefixes |
| Endpoints | Local LAN host A behind the Tunnex gateway and private AWS host B behind the VGW; each host's actual routes, firewall, test listener and clock |
| Boundaries | NAT presence, public customer address, underlay interfaces, chosen probe ports and sizes, test payload marker, capture locations, stop deadline and approved rollback |
| Evidence | UTC timestamps, receipt directory, restricted raw evidence location and redacted report destination; no PSKs or downloaded secret-bearing config in Git, logs or screenshots |

Neither endpoint may be the IPsec gateway itself. Give probes no alternate overlay, public-address or local path to the other endpoint. Record source and destination private addresses and verify the path before accepting traffic evidence. Existing WireGuard/OpenVPN services, routes and connectivity need a before/after control sample if present.

## Configure and review

1. Prepare the approved customer gateway, attached VGW, static-routing VPN and both tunnels. Use the actual downloaded AWS configuration to map each outside endpoint, /30 and customer/AWS inside addresses; never infer inside address ordering. Keep the download private because it can contain PSKs. AWS documents the setup sequence and use of the NAT device's public address when applicable in [VPN setup](https://docs.aws.amazon.com/vpn/latest/s2svpn/SetUpVPNConnections.html).
2. Explicitly restrict both AWS tunnels to the implemented IKEv2 suite. Record both sides' lifetime, startup and DPD settings; do not assume provider defaults match the runtime. Confirm the negotiated suite in sanitized runtime evidence. Do not weaken algorithms to make a test pass.
3. Configure AWS static customer-network prefixes and the test subnet's return route toward the VGW. Allow only the planned endpoint probes through AWS security groups, NACLs and host firewalls. Ensure local hosts route AWS prefixes through the Tunnex gateway. Record the exact route entries that a later failure test will withdraw and restore.
4. In Site-to-site, select the IPsec AWS flow, eligible local Site/gateway, both tunnel assignments and write-only keys. Preflight, review and save disabled. Verify readback of ranges and tunnel identities; cancel/retry must not silently duplicate or enable a connection. Use existing access policies for explicit directions and ports. Broad negotiation selectors are not an allow-all grant.
5. Enable explicitly. Record desired and applied revisions, each tunnel's timestamped Up/Down/Unknown status, Preferred path and independently reported Active path. Wait within a recorded bound; timeout is a failed or blocked case, not evidence of readiness.

## Packet and failure matrix

Start each row from a recorded healthy or explicitly stated baseline. Change one variable, collect timestamped evidence, restore it and rerun the positive control before the next row. Record **pass, fail or blocked**, observed interruption, evidence path and reason for every row. These are required outcomes, not results already obtained.

| Case | Controlled action | Required evidence |
| --- | --- | --- |
| Allowed traffic | Send TCP application payload and UDP request/reply A→B, then independently initiate B→A under corresponding explicit grants | Receiving application observes the marker; matching ESP/NAT-T and per-tunnel counters increase; no marker is visible as plaintext on the underlay. A ping or SA alone is insufficient |
| Policy deny | With AWS/host controls permitting the probes, remove the relevant Tunnex grant or use an explicitly ungranted port/direction; test both initiated directions | Destination receives no forbidden payload; Tunnex enforcement evidence attributes the denial. Restore grant and prove the same probe succeeds so an absent listener or AWS deny cannot satisfy this test |
| Return-path independence | Leave both tunnels available and let AWS choose its egress; observe ingress slot separately from Tunnex's selected outbound slot | Bidirectional payload succeeds without forcing AWS to the same slot. If return traffic on the other slot is refused, record an interoperability blocker; do not change cloud preference to conceal it |
| Wrong PSK | In a maintenance window, disable and wait for acknowledged cleanup; rotate one test key so only that AWS tunnel mismatches, then explicitly enable | A fresh negotiation on the mismatched slot cannot authenticate; no old SA is accepted as proof. Healthy partner behavior is recorded separately. Restore a matching key through maintenance rotation and prove recovery; errors and evidence omit keys |
| Missing return route | Withdraw only the previously recorded AWS test-subnet return route (including any equivalent propagated path); keep tunnel configuration intact | Behind-host request/reply fails while SAs may remain Up. UI does not claim traffic verified from Up. Restore exact route and prove the identical flow succeeds |
| Tunnel 1 failure | With slot 1 initially active, block only its approved underlay peer traffic, including relevant IKE/NAT-T/ESP, without touching management or slot 2 | Timestamp fault, Down evidence, refusal, alternate selection and first successful encrypted payload. No plaintext escape; both directions recover without manually steering AWS return traffic |
| Tunnel 2 failure | First prove slot 2 active using the preceding case; restore slot 1 and verify no automatic failback, then independently fault only slot 2 | Same evidence for recovery to slot 1. Testing an inactive tunnel alone does not qualify reverse-direction failover |
| Both tunnels unavailable | Fault both dedicated endpoints within the approved window; then restore them | No permitted application traffic or fabricated active path during failure; restoration uses fresh authority/observations and encrypted traffic. Unknown telemetry remains Unknown |
| Controller restart | With a healthy active slot, restart only the approved gateway process and record lease/selection observations | Refusal until fresh authority and kernel/daemon proof; saved selection is not saved permission. Independent payload recovers. Label this process restart, not host reboot |
| Host reboot | Only with separate host-restart approval, reboot the isolated gateway host and repeat traffic/ownership checks | Record new boot identity, restored refusal, current authority and successful behind-host payload. If not authorized/executed, leave this case pending |
| Rekey | Observe actual CHILD and IKE renewal over a bounded scheduled soak, identifying each negotiated replacement | New SA identity/timestamps and continued or measured interrupted payload, correct suite and no plaintext. Maintenance PSK rotation is not a substitute for protocol rekey evidence |
| Maintenance rotation | Disable; wait for exact cleanup acknowledgement; replace one key, update AWS, then explicitly enable. Repeat with both keys | Connection remains disabled during remote update; fresh old-key negotiation fails, matching new keys work on both slots, unchanged partner remains intact for the one-key case. Record revisions/audit only, never key material |
| Disable/delete | Preview owned effects; disable and await cleanup, then perform approved deletion/disposition | Both slots' owned SAs/routes are withdrawn, retained prefix refusal remains as required, payload stays denied, exact cleanup acknowledgement recorded; unrelated routes, Sites, policies and cloud resources preserved |

The recovery reducer's three fresh observations spanning ten seconds are an internal switch condition, not a ten-second end-to-end outage guarantee. Detection, AWS convergence, fresh authorization and negotiation add time. Report measured interruption rather than an assumed SLA. See [recovery integration](S-S2S-3-runtime-integration.md) and [maintenance rotation](S-S2S-3-rotation.md).

AWS chooses its egress tunnel independently and can change that choice; VGW does not provide ECMP. Thus two Up tunnels and a locally selected route do not establish usable failover. AWS recommends accommodating asymmetric paths. These facts make the return-path row a release gate, not an optional optimization. [AWS route priority](https://docs.aws.amazon.com/vpn/latest/s2svpn/vpn-route-priority.html).

## MTU and application-sized traffic

Record actual interface MTUs and any existing MSS adjustment on both endpoint paths; this walk does not claim Tunnex automatically configures them. For the selected AES-CBC/SHA2-256 suite, AWS lists MTU/IPv4 MSS ceilings of 1438/1398 without NAT-T and 1422/1382 with NAT-T. The actual path may be lower. AWS VPN does not support Path MTU Discovery. [AWS customer-gateway best practices](https://docs.aws.amazon.com/vpn/latest/s2svpn/cgw-best-practice.html), [AWS gateway requirements](https://docs.aws.amazon.com/vpn/latest/s2svpn/CGRequirements.html).

Test both directions on each selected tunnel: small payload, payload near the measured path limit, and a larger application transfer. Record whether each size is ICMP/UDP payload or complete IPv4 packet length (UDP and ordinary ICMP add 28 bytes of IPv4/protocol headers). Include DF probes and TCP transfer completion with byte count/checksum; a successful small ping cannot pass this case. Record expected oversize failure/fragmentation separately from in-range success. If a lower MTU/MSS is required, obtain the scoped change approval, record its owner and rollback, then retest. Do not silently change unrelated host defaults. Recheck after failover.

## Finish and qualify

Collect redacted setup screenshots, ordered case receipts, application byte/checksum results, packet/counter correlation, actual failover timings, rekey/restart evidence and exact cleanup outcomes. Avoid raw XFRM state dumps that can disclose session keys. Capture only necessary test traffic in restricted storage; publish sanitized observations, not raw downloaded configurations or packet files with customer data.

After Tunnex cleanup, restore captured AWS routes/firewall settings and remove only separately approved disposable resources by exact ID. Check management and unrelated connectivity again. Tunnex deletion does not delete a customer-managed AWS VPN, VGW or VPC. Record outstanding resources and retained refusal/reservations explicitly; no success-by-absence cleanup inference.

A reviewer may propose an AWS support label only after all required cases pass on the named software/profile/platform and exact-head gates are satisfied. Record any blocked or failed case as an open acceptance item. A forced symmetric return route, emulator result, successful tunnel handshake, or synthetic preview cannot close this walk. No result from this procedure implies Azure, GCP, Fortinet/Cisco, gateway-host HA or universal IPsec compatibility.

## Receipt completeness check

Copy [the pending template](../deploy/ipsec/aws-walk-template.json) into the restricted evidence directory and enter the tested 40-character source SHA. Keep schema 1, profile `aws-static-ipv4-v1`, environment `live-aws` and the exact fourteen check keys. Each passing check needs one or more nonempty sanitized artifacts with a path relative to the receipt and its SHA-256. Leave unexecuted or blocked cases `pending`, and observed failures `fail`; do not remove them to obtain a passing checker result.

From the repository root, run `python3 deploy/ipsec/check_aws_walk.py /absolute/path/to/receipt.json`. This command reads local receipt/artifact files only. It checks completeness and matching hashes; it neither runs cloud tests nor proves that a supplied artifact demonstrates the claim. Manual technical review and secret review remain mandatory, even if its exit status is zero.

Record independent AWS return-path/asymmetry proof under `return_path_independence` and correlate it with `behind_host_tcp_udp` and both tunnel-failure receipts. Use `both_tunnels_failure` for simultaneous loss, `restart_recovery` for process restart and `host_reboot` for the separately authorized reboot; absent required reboot evidence leaves that check pending. Record actual protocol rekey in `protocol_rekey`, separately from `maintenance_rotation`. The receipt does not waive any subcases in this walk or the separate S2S-3 acceptance gates. Never place raw PSKs, session keys or secret-bearing downloads in receipt artifacts.

## Live walk checkpoint — 2026-09-25

The approved isolated AWS VGW fixture has two established IKEv2/NAT-T tunnels and
independent private endpoints. Organization enforcement was enabled with explicit
approval, with host-specific TCP/18080 and UDP/18081 resource grants.

Initial TCP traffic exposed asymmetric AWS replies arriving on the other tunnel,
plus strict nftables host-prefix readback and empty reply-set lifecycle defects.
Local fixes passed focused regressions and the full node IPsec suite. Native
nftables lifecycle replay passed. The updated lab passed A→B TCP/UDP echoes,
TCP 32768-byte and UDP 1394-byte payloads, exact-grant deny/restore, and withdrawal
and restoration of the exact AWS return route. Both CHILD rekeys completed and
payload recovered automatically after a measured transient failure.

These results cover subcases only. Independent B→A initiation, complete MTU evidence, PSK rotation, full
failure/recovery coverage, host reboot and final cleanup remain open. Forced IKE
rekeys produced replacement IKE identities on both peers with successful payload.
Single-peer loss recovered A→B traffic in both route directions (approximately
190 and 216 seconds to first sampled success), while the corresponding fault
remained active. Restoring the preferred tunnel did not force failback. A scoped
standby retry fix then restored a terminated standby SA automatically in about
three seconds, with selected duty unchanged. Initial tunnel-loss testing exposed missing periodic DPD;
the local fix enables 10-second probes, while failure detection also includes
strongSwan retransmission time. Single-peer failover retesting passed the above A→B subcases. Simultaneous loss
refused payload with empty guard leases and no active-path UI claim; removal of
the fault restored A→B TCP/UDP automatically. A mislabeled capture taken after
container recreation was identified as LAN ingress and excluded from underlay proof.
Key-mismatch and rotation tests await specific credential-change approval after
automatic approval review rejected the write; no PSK change was submitted.

Container/kernel reset also exposes a separate persisted-ownership restoration
blocker. Supported disable/acknowledged cleanup/re-enable recovers the lab, but
that manual sequence does not qualify automatic restart or host reboot recovery.
No journal bypass or ownership relaxation was used. Evidence and cloud inventories
remain in the restricted lab directory; all new fixes remain local.

Latest checkpoint: both tunnels Up and TCP/UDP positive controls pass. All injected
fault tables removed. Corrected underlay capture showed no plaintext test marker
or private AWS destination packets in its bounded sample. Short-flap recovery
remained delayed by DPD retransmission timeout; do not advertise fast failover.
The [runtime restoration proposal](S-S2S-4-runtime-restoration-decision.md) records
the separate unresolved persisted-state repair. Current work is uncommitted and
has not been pushed or qualified by fresh full CI.


## Post-tuning stability check — 2026-09-25

**PASS (user-observed):** the user reports approximately 50 minutes of the second-Mac SSH/TCP checks running without an observed drop, exceeding the planned 30-minute observation window. Marked pass at the user's request. No additional fault was injected for this observation.

Evidence is the user's report in this session; the full soak output was not supplied or independently analyzed. This does not establish absence of backend flapping, scheduled rekey coverage, or production reliability, and does not close the remaining AWS qualification gates.


## Gateway container restart — 2026-09-25

**FAIL: automatic recovery.** Authorized restart of only `tunnex-s2s-clean-wifi-gateway` started at 14:25:12 UTC. Gateway became healthy and reused its stored identity, but no IKE/CHILD SAs were restored. CP and shared VM were not restarted.

Docker reintroduced an `ip nat` table containing only its inspected loopback DNS rules. The runtime platform census rejects this extra table. Existing direct resolver and CP hosts mapping remained intact. Removing that scoped Docker DNS table restored platform qualification (platform-refused warnings stopped), but runtime reconciliation still refused and tunnels remained absent at the last check. Persisted journal and current namespace metadata matched; a namespace mismatch has NOT been established as the remaining cause. No journal edits, ownership bypass, or termination attestation were performed.

The restarted daemon configuration also lacks the manually applied retransmission tuning; the running lab image predates that source change. This test does not qualify tuned-setting persistence or successful traffic recovery. Client probe output has not yet been collected. Further disruptive test cases are paused pending diagnosis and restoration.

### Gateway restart recovery correction (2026-09-25)
The initial restart failure was corrected for the same-namespace lab container: recovery now independently distinguishes exact surviving owned interfaces from complete absence, requires fresh CP authority and prefix refusal before recreating absent interfaces, and persists new ownership before activation. Mixed/foreign/renamed objects and namespace changes still refuse. Docker's DNS-only NAT reinjection is handled by a strictly scoped lab startup adapter, not by relaxing production census.

A live restart at 14:53:50 UTC recovered both IKE/CHILD SAs automatically around 14:54:20 UTC without disable/enable or journal edits. CP showed both Up, route and bidirectional counters recovered, and tuned retry values persisted. Full native IPsec suite and focused ownership/lease regressions passed. User reports the existing SSH connection did not disconnect; exact TCP probe gap has not been supplied. Approximately 30 seconds is the observed tunnel startup interval, not proven zero application downtime. Host/VM reboot and changed-namespace recovery remain outside this result.

### Dual-tunnel outage with restored build — PASS (2026-09-25)
Both lab peers were blocked for 90 seconds. CP reported both Down; second-Mac TCP22 requests continued while replies stopped. Counter-only observation of the VM external interface showed zero cleartext egress toward the private AWS host. Removing the fault automatically restored both installed tunnels, the route and TCP replies within the next 15-second sample, without manual tunnel/CP action. User confirmed both Up and replies resumed. All temporary fault and counter rules were removed and independently verified absent. Exact client outage duration remains log-dependent; the deliberately imposed 90-second outage is not a failover-detection measurement.

### Second-Mac large TCP transfer — PASS (user output, 2026-09-25)
At 20:43 IST, the personal Mac uploaded 32 MiB over private-IP SSH in 11 seconds and downloaded it in 16 seconds; local, remote and downloaded SHA256 matched. SSH reported original source 192.168.1.33 to AWS 10.204.20.10:22, with the Mac route via 192.168.1.40. Large TCP transfer/content integrity passes. Exact MTU, UDP/DF sizing and AWS-initiated connections are not established by this result.
