# BGP-0 — AWS IPv4 BGP contract

Status: design reviewed and accepted by root, 2026-10-07; runtime/local-network/AWS proof belongs to later stories.

| Decision | Contract |
| --- | --- |
| Profile | New `aws-bgp-ipv4-v1` / `ipv4-bgp`; exactly two AWS inside /30 peers. Existing static behavior and ownership digests remain unchanged. |
| ASN/router ID | Customer ASN: 64512..65534 or 4200000000..4294967294. Remote AWS ASN: these private ranges or AWS default 7224. Reject other values and equal ASNs in this initial bounded profile. Stable canonical IPv4 router ID independent of active tunnel. AWS customer-gateway primary documentation verified before qualification; actual provider-assigned ASN must match configuration. |
| Export | Exact `local_prefixes` only; no connected/kernel/WireGuard/default redistribution. Verify local reachability before originating to avoid invented reachable LANs. |
| Import | `remote_prefixes` is the bounded approved destination list. Initial release accepts exact equality only, with no more-specific acceptance. Reject default/special-use/local/inside/outer conflicts and unrelated route overlap. `bgp.maximum_prefixes` limits accepted routes per peer (1..64), including accepted paths that cannot currently become best. The total selected route union is bounded by the exact approved remote list (at most64), with one selected slot per prefix; disjoint peers may together select more routes than the per-peer limit. Bound daemon response size. |
| Daemon | Managed FRR bgpd with `--no_kernel` and an isolated zebra observer for interface/nexthop state; no staticd/other route protocols and no BGP kernel writes or arbitrary CLI text. Private owned configuration/control socket, deterministic config and actual packaged runtime probe. |
| Kernel writer | Go node controller remains sole writer. Preserve execution namespace/main table254/protocol242 with exact owned interface/metric/destination tuples. Preflight rejects unrelated/other-connection overlaps. No new policy routing tables in initial scope. |
| Selection | One best next hop per prefix; different prefixes may use different tunnels. Both sessions active; FRR best-path result feeds bounded validated node reconciliation. Never invoke static `MoveSelectedRoutes` for BGP. |
| Selectors | BGP-only versioned route-based CHILD with IPv4 0/0 selectors both sides, exact XFRM IDs/reqids and existing strongSwan cryptography. Separate transport selectors from policy prefixes and dynamic installed subset. Broad cryptographic selectors never broaden forwarding permission. |
| Peer transport | Explicit cloud-inside /32 route through each owned XFRM link because existing inside addresses use noprefixroute. Allow TCP/179 only between exact inside peer pair on owned interface, inbound/outbound; deny WAN/other interfaces. |
| Access | Runtime grants, source checks, denial guard and permit lease remain authority. Route learning creates no grant and remote subnet is not authenticated user identity. Asymmetric return enforcement requires real packet proof. |
| Recovery | Journal nonsecret instance/config revision and exact route mutation obligation before mutation. Do not journal PSKs or raw daemon output. Denial precedes session/export stop and route cleanup; verify exact kernel/daemon absence before acknowledgement. Crash replay cannot trust stale BGP observations or remove unrelated routes. |
| Compatibility | Explicit BGP capability/runtime version; fail closed on absent/unknown capability, never static activation fallback. Database downgrade refuses BGP rows instead of deleting/converting them. Preserve static DTO/digest compatibility. |
| UX/status | Extend existing IPsec workspace/theme/review flow. Distinguish IPsec established, BGP established, accepted/installed routes and traffic proof. Per-prefix paths cannot falsely project one global active slot. |

## Code grounding and implementation risks

`config_validation.go` allows only static mode today. `runtime_wire.go` has no ASN/BGP intent. `kernel_apply.go` uses table254/protocol242 and moves every configured prefix between selected slots. It verifies the execution namespace and does not create a namespace per connection; route conflict detection is mandatory.

`daemon.go` derives CHILD selectors from local/remote prefixes and forbids /0. `runtime_material.go`, `runtime_journal.go` and `runtime_proof.go` couple selectors, approved prefixes and installed route inventory. BGP must separate all three in a versioned representation; globally relaxing static validation is unacceptable. Guards continue to use approved policy boundaries, never 0/0 selectors. BGP route proof permits only a validated learned subset, not every approved prefix automatically installed.

Peer /32 routes and application learned routes need separate exact ownership/proof. Daemon restart, stale selection, partial route-add failure, lease expiry and disable/delete must fail closed; unit fixtures alone cannot qualify this behavior. Platform/package availability and AWS path attributes remain acceptance gaps until actually tested.

## Primary references

- [FRR BGP invocation](https://docs.frrouting.org/en/latest/bgp.html): `--no_kernel` is the supported way to suppress BGP installation while retaining zebra interface/nexthop observations. Latest documentation warns against `--no_zebra`; package presence alone is not runtime qualification. Node-owned installation remains required.
- [AWS customer gateway requirements](https://docs.aws.amazon.com/vpn/latest/s2svpn/CGRequirements.html): route-based tunnel and encrypted BGP transport requirements.
- [AWS VPN connection options](https://docs.aws.amazon.com/vpn/latest/s2svpn/modify-vpn-connection-options.html): default local/remote IPv4 traffic selector ranges are 0/0.

These references support the design choice, not a claim of live AWS interoperability.

## Local qualification disposition

BGP-0 design and BGP1–4 CP/ARM64 component gates are accepted locally. Latest full API/IPsec PostgreSQL suite passed without changing the serving parent schema/data. Final native ARM64 session14 and wrongASN2 receipts bind the same qualified binary, with two established encrypted sessions, accepted-count readback, daemon restart, complete kernel-route baseline preservation, no SYS_ADMIN, owned cleanup and foreign socket preservation. Native AMD64 patched production package qualification passed separately; native AMD64 session and wrong-ASN qualification passed as separate component gates. These are component/local receipts, not live AWS support or integrated forwarding proof.

Private/public BGP observations require exact configured prefixes, ordered two-peer slots, explicit nonnull accepted/installed counts, omitted unknown rejected counts and safe-integer monotonic sequence. Observations never create runtime authority. API activation and node full BGP capability remain blocked until learned-route installation, best-path failure/withdrawal and lifecycle recovery gates finish.

Native AMD64 BGP4 receipt: designated-host build `aaeefd3ba1833c1e`, production image `868b425d65ef30b6` prefix, session binary `3213e4c393dcc51c` prefix. `native-session1/result.json` and `native-wrong-asn1/result.json` both report passed and cleanup complete, with observer SYS_ADMIN absent. These receipts use synthetic component lease authority and install no learned routes; they do not prove live AWS VPN or CP activation. Lab retains receipt files under `/home/ubuntu/tunnex-bgp-lab/builds/aaeefd3ba1833c1e/` on the designated host.

Managed bgpd uses `--no_kernel` (`-n`) with observer zebra; the earlier candidate `bgp no-rib` command was removed during actual route-ingestion qualification. BGP5 native route/grant and maximum-RIB component gates are accepted by root; lifecycle integration6–7 remains required before activation.
