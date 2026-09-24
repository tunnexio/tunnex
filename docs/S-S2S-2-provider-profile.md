# Proposed AWS static IPv4 validation profile

Research date: 2026-09-24. Status: research/design proposal only. This document does not approve a runtime, persistence migration, public creation API, cloud operation or provider-support claim. It builds on the approved identity/PSK foundation in [the decision gates](S-S2S-2-decision-gates.md) and [the persistence contract](S-S2S-2-persistence-contract.md). Existing disabled identity reservation still accepts no provider configuration.

## Scope and terminology

Proposed profile identifier: `aws-static-ipv4-v1`. Initial qualification target: a virtual private gateway, public IPv4 outside transport, IPv4 inside networks, static routing, IKEv2, and exactly two tunnel slots. Exclude BGP, transit-gateway/Cloud WAN/concentrator qualification, IPv6, private outside transport, certificate authentication, acceleration and policy-based VPN configuration from this first profile. These are **Tunnex scope choices**, not a claim that AWS lacks those capabilities.

AWS documents two tunnels and one unique inbound/outbound SA pair per tunnel. Do not create a CHILD_SA for every LAN prefix or access rule; routing and access enforcement must remain separate from SA negotiation. The static-routing setup communicates customer-network prefixes to AWS and also needs customer-side routes toward AWS. Sources: [customer gateway requirements](https://docs.aws.amazon.com/vpn/latest/s2svpn/CGRequirements.html), [static versus dynamic routing](https://docs.aws.amazon.com/vpn/latest/s2svpn/vpn-static-dynamic.html).

## Endpoint and inside-address fields

Proposed connection field `customer_outside_ipv4` is the static Internet-facing customer-gateway address. With NAT it is the NAT device's public address, not necessarily an address assigned to the local interface. Each tunnel carries a distinct `aws_outside_ipv4` taken from that connection's actual AWS configuration; neither may equal the customer address. Accept literal canonical IPv4 only, with no URL, hostname, port, zone, mapped IPv6 or surrounding whitespace. AWS publishes outside endpoint addresses in its downloaded configuration. UDP 500, ESP when applicable and UDP 4500 for NAT-T require later firewall qualification. Sources: [customer gateway API](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateCustomerGateway.html), [firewall requirements](https://docs.aws.amazon.com/vpn/latest/s2svpn/FirewallRules.html).

Proposed outside-address predicate: ordinary IPv4 unicast outside **all** ranges below. This deliberately excludes some globally reachable special-purpose anycast assignments; it is a conservative product subset, not an exact test of Internet reachability. A validator cannot establish address ownership or live reachability. Do not use `IsGlobalUnicast` alone.

```
0.0.0.0/8       10.0.0.0/8       100.64.0.0/10    127.0.0.0/8
169.254.0.0/16  172.16.0.0/12    192.0.0.0/24     192.0.2.0/24
192.31.196.0/24 192.52.193.0/24  192.88.99.0/24   192.168.0.0/16
192.175.48.0/24 198.18.0.0/15    198.51.100.0/24  203.0.113.0/24
224.0.0.0/4     240.0.0.0/4
```

The registry distinguishes global reachability, forwardability and protocol reservations; these properties are not interchangeable. Table snapshot checked on the research date; recheck when qualifying a new profile revision. Sources: [IANA IPv4 special-purpose registry](https://www.iana.org/assignments/iana-ipv4-special-registry), [IANA IPv4 address space](https://www.iana.org/assignments/ipv4-address-space).

Each tunnel requires `inside_cidr`, `customer_inside_ipv4`, and `aws_inside_ipv4`. AWS requires a /30 in 169.254.0.0/16, excluding:

```
169.254.0.0/30  169.254.1.0/30  169.254.2.0/30  169.254.3.0/30
169.254.4.0/30  169.254.5.0/30  169.254.169.252/30
```

The two addresses must be the two distinct usable host addresses of their canonical /30; reject network/broadcast addresses. Require the caller to supply the customer/AWS assignment from the downloaded connection configuration. **Do not infer which side is `.1` or `.2`: the sources reviewed do not establish a universal IPv4 assignment rule.** AWS's documented first/second usable address statement on the tunnel-options page concerns IPv6. Per AWS, inside CIDRs must be unique across connections on the same virtual private gateway. A future local conflict check must also reject reuse on the assigned Tunnex gateway; validating just the submitted pair cannot prove either cross-connection condition. Sources: [tunnel options](https://docs.aws.amazon.com/vpn/latest/s2svpn/tunnel-configure.html), [downloadable configuration guidance](https://docs.aws.amazon.com/vpn/latest/s2svpn/cgw-static-routing-examples.html).

## Traffic selectors and routed prefixes are separate

Proposed negotiation selector pair: `0.0.0.0/0` in both directions, one SA pair per tunnel; no user-authored selector matrix. These broad selectors are **not routes and not access grants**. AWS describes its local/remote IPv4 CIDRs as negotiation inputs and route-based forwarding as dependent on routing and security controls. Runtime proof must show ingress identity binding and deny-by-default enforcement before any route can become usable. Source: [AWS tunnel selectors](https://docs.aws.amazon.com/vpn/latest/s2svpn/tunnel-configure.html).

Proposed routed fields `local_prefixes` and `remote_prefixes`: 1–64 canonical IPv4 CIDRs per side, prefix lengths 1–32. Allow ordinary customer-owned public space as well as RFC1918 space; **do not restrict LANs to RFC1918**. The count bound and default-route exclusion are Tunnex validation choices, not an asserted AWS quota. Reject duplicate/overlapping prefixes within a side, local-versus-remote overlap and any prefix intersecting the following deliberately excluded special ranges:

```
0.0.0.0/8       100.64.0.0/10    127.0.0.0/8      169.254.0.0/16
192.0.0.0/24
192.0.2.0/24    192.31.196.0/24  192.52.193.0/24  192.88.99.0/24
192.175.48.0/24 198.18.0.0/15    198.51.100.0/24  203.0.113.0/24
224.0.0.0/4     240.0.0.0/4
```

This permits RFC1918 as the only exception to the special-purpose denylist. It rejects shared 100.64.0.0/10 in this initial conservative profile; that is a Tunnex subset restriction, not an AWS requirement. Ordinary customer-owned public unicast prefixes remain permitted. For exclusions, test whole-prefix intersection, not just the network address. Reject route coverage of any outside peer/customer address to avoid routing the underlay into its own tunnel. Bound lists before overlap comparisons. Do not silently mask host bits, aggregate or reorder semantic priority.

A future persistence/admission boundary must prove local prefixes are authorized approved subnets of the selected Site and remote ranges do not collide with organization WireGuard pools, site networks, existing routes or another assigned connection. Which overlaps can be safely shared across connections remains a routing-ownership decision; pure validation cannot answer it. AWS static return routes must include the selected local networks and VPC route tables/security groups/NACLs must independently allow intended traffic. Source: [AWS setup/routing](https://docs.aws.amazon.com/vpn/latest/s2svpn/SetUpVPNConnections.html).

## PSKs and proposed fixed transforms

AWS PSK constraint: 8–64 characters; ASCII letters, digits, period and underscore; first character cannot be `0`. Validate bytes without trimming or normalization. Existing generic encrypted-envelope bounds remain a storage primitive and are not replaced. PSKs stay write-only; errors never echo them. Source: [EC2 VPN tunnel option API](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_VpnTunnelOptionsSpecification.html).

Proposed single fixed suite, to be confirmed by actual negotiation/rekey tests:

| Setting | Proposed value |
|---|---|
| IKE | IKEv2 only, PSK authentication |
| IKE encryption/integrity | AES-256-CBC / HMAC-SHA2-256 (AWS `AES256`, `SHA2-256`) |
| IKE DH | group 14, MODP 2048 |
| ESP mode/encryption/integrity | tunnel / AES-256-CBC / HMAC-SHA2-256 |
| ESP PFS | group 14 |
| IKE / child lifetimes | 28,800 / 3,600 seconds |

AWS lists these encryption, integrity and group choices and allows those lifetime values. Choosing only these is a Tunnex subset; do not silently negotiate SHA1/DH2 fallback. Exact IKE PRF naming, ESP integrity truncation and engine proposal spelling must be matched to the selected engine and verified against AWS. No strongSwan configuration string is approved here. Source: [EC2 VPN tunnel option API](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_VpnTunnelOptionsSpecification.html).

Do not inherit a DPD default implicitly: the AWS user guide and API reference currently describe different default timeout values. Explicit DPD/restart, startup side, rekey margin/fuzz, replay window, MTU/MSS, asymmetric routing and failover decisions remain runtime work. AWS can change its preferred egress tunnel, and VGW does not support ECMP; two configured tunnels alone do not prove failover. Source: [AWS route priority](https://docs.aws.amazon.com/vpn/latest/s2svpn/vpn-route-priority.html).

## Proposed contract and remaining decisions

A future pure validator may accept the fixed profile ID, one customer outside address, the bounded local/remote prefix lists, and exactly two named slots containing distinct tunnel IDs, AWS outside address, inside CIDR/explicit address pair and write-only PSK. No arbitrary engine text, extra transforms, policy expressions or automatically generated AWS changes. Return static field identifiers/codes only; return no secret-bearing validated struct to logs or ordinary APIs.

Before provider fields are persisted or exposed publicly, disposition is still needed for the proposed scope/subset, profile revision ownership, conflict reservation across connections, exact selectors/algorithms, NAT identity binding and the persisted configuration schema. An in-memory validator can prove syntax and local consistency only. Activation remains blocked on runtime selection, fresh authenticated capability, policy-before-route enforcement, acknowledged withdrawal, real two-tunnel AWS traffic and failure/rekey qualification. No cloud action was performed for this research.

### Pure-helper implementation boundary

The local validation increment is an in-memory helper, not this entire future persisted profile. Its mode discriminator is `ipv4-static`; fields cover a required customer outside address, local/remote prefix lists (1–64 each), and exactly two tunnel inputs with outside/inside addresses and write-only PSKs. Provider profile IDs, persisted tunnel identities, fixed transform selection, traffic-selector delivery and organization-wide ownership/conflict checks are not implemented by that helper. In particular, no successful helper result reserves an address, writes configuration or establishes authority to create/activate a connection.
