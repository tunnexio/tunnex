# Private DNS profiles and site-to-site IPsec

This document describes the local `s2s-hotfix` implementation and its coordinated standalone desktop changes. Local builds and qualification do not establish a published release or production readiness. Record the control-plane, gateway, and desktop build pins used for each live check.

Private DNS profiles either forward a private zone to the customer's DNS server or serve centrally managed A, AAAA, and CNAME records from the Tunnex gateway. Application traffic uses its own routes and access policies. A DNS answer never creates an application grant.

Ordinary DNS forwarding does not require the `fqdn_resources` licence feature. Hostname-based application policy enforcement requires an eligible signed licence on that control-plane deployment and the organization's FQDN opt-in. Trial, Starter, Growth and Scale include this feature; activating a licence on a separate control plane does not activate this deployment.

## Existing office DNS

1. Keep AD DNS, BIND, or the existing office resolver as the client's DNS server.
2. Configure a conditional forwarder for the private zone, for example `apps.example.internal`, to the remote resolver's private endpoint IPs.
3. In AWS, use Route 53 Resolver inbound endpoints in the VPC associated with the private hosted zone. Configure endpoint security groups for UDP and TCP 53 from the actual DNS source address.
4. Include endpoint addresses in the connection's approved remote prefixes and the office DNS source in its local prefixes. Approve UDP/TCP 53 separately in Access Policies.
5. Allow the application's private LB/service address and application ports separately. A successful DNS answer does not create an application grant.

Office client → office DNS conditional forwarder → approved IPsec tunnel → remote DNS resolver → private A/CNAME answer. The subsequent application connection follows its approved application route through IPsec to the private service/LB.

## Enrolled desktop clients with automatic private DNS

Open the connection under **Site-to-site → Connections**, then **DNS records and forwarding**, or open the selected network's **Advanced → DNS records and forwarding** section. Both reuse the same Private DNS profile editor; the connection fixes its Site and Gateway, and the network fixes its Site. The editor is also available under **Access Policies → Resources → Private DNS**. Activate **DNS records** or **Forward to DNS server → site-to-site IPsec**. For an IPsec profile:

- Select the enabled connection.
- Enter an IPv4 DNS source address already assigned to that gateway and included in the connection's local prefixes.
- Add the private zone suffix and the remote resolver's approved private endpoint IPs on port 53. Keep the gateway's upstream DNS transport authorized through that connection.

Enroll the desktop on that same gateway, then grant its user or group both UDP and TCP 53 to the gateway's WireGuard DNS address, for example `10.99.0.1`. An active device and current membership are required. A LAN listener's source allowlist does not grant desktop DNS access. No FQDN application licence or FQDN application resource is required for this DNS entitlement.

The standalone desktop's authenticated configuration poll automatically receives the authorized active profile suffixes and the selected gateway's DNS address. The response includes an exact gateway `/32` route when existing ranges do not cover it. In split-tunnel mode, the desktop installs the routes before adding DNS suffix rules. If route installation fails, it defers DNS additions while still withdrawing obsolete suffixes. Full-tunnel mode uses its existing default route and also applies the scoped DNS rules. These operations use the existing routed-ranges contract and privileged resolver helper; users do not manually add suffix rules in the coordinated desktop build. Generic WireGuard clients still need their own OS suffix configuration or supported split-DNS helper.

Grant application access separately: add an explicit user/group policy to the private IPv4/CIDR resource and required ports within the connection's approved remote prefixes. For the initial desktop IPsec path, use an `aws-bgp-ipv4-v1` connection on that exact gateway. The gateway preserves the enrolled desktop's VPN source `/32` and exports that host return route through BGP; cloud security rules and the VPC return path must permit it. A static or forwarded answer can resolve into that authorized CIDR, but the answer itself grants no application access. Direct desktop authorization to an FQDN application resource is outside this path. See [Desktop access through site-to-site IPsec](desktop-ipsec-transit.md).

Profiles are bound to their active configuration revision; forwarded profiles also bind the selected IPsec connection. The most specific matching zone wins; profiles do not fall back to one another. Disabled, deleted, expired, stale, or unproven tunnel paths deny forwarded private-zone queries. No matching profile means no private query is sent. Unmatched names retain the client's configured DNS behavior: its normal resolver in split mode or configured tunnel resolver in full mode.

The projection requires a fresh capable gateway report. Revoked or blocked devices, removed membership or DNS permission, expired rules, and retired profiles remove their suffixes from subsequent snapshots. DNS caches can retain earlier answers until their TTL expires; application permission remains independently enforced.

Both UDP and TCP 53 are required. Large answers use DNS truncation and TCP retry instead of depending on tunnel fragmentation. Two resolver endpoints provide availability only when both endpoints' routes, policies and remote security rules are configured.

The gateway proxy listens on its WireGuard interface by default. Office LAN serving is an explicit per-profile option described below; no public or wildcard DNS listener is created.

**Configured** confirms stored DNS configuration. Check live tunnel status and perform a DNS query to verify forwarded-zone availability. Tunnex does not discover or import cloud DNS record sets.

## Centrally managed static records

Open **DNS records and forwarding** beside the relevant Site-to-site connection or network. New profiles start with **DNS records**, a name based on the selected network, and a 300-second TTL. Enter a hostname, choose A/AAAA/CNAME, and enter its IP or target hostname. Leaving the first hostname field suggests that exact hostname as the DNS scope when the new draft's scope is empty. Review the visible, editable scope; use a shared suffix for sibling names. Saved scopes are not changed automatically. Activate the profile version to distribute the records to that gateway. No cloud account is required.

For example, a profile for `office.example.com` can contain:

| Name | Type | Value | TTL |
| --- | --- | --- | --- |
| `app.office.example.com` | A | `10.20.1.10` | 300 |
| `app.office.example.com` | AAAA | `fd00::10` | 300 |
| `portal.office.example.com` | CNAME | `app.office.example.com` | 300 |
| `service.office.example.com` | CNAME | `load-balancer.example.net` | 300 |

Use A for a private IPv4 address and AAAA for a private IPv6 address; neither needs an upstream. CNAME aliases within this same profile follow its managed records. For an external target such as a load balancer hostname that normal DNS can resolve, the gateway can complete the alias through explicitly configured normal DNS upstreams. This applies independently of whether the application is in AWS, Azure, Google Cloud, or on-premises. A hostname available only in a cloud private zone still needs a DNS server that serves that zone; a public upstream cannot discover unpublished private records.

For a new static draft, entering an external CNAME target selects visible defaults `1.1.1.1` and `8.8.8.8`. **Advanced target DNS settings** lets the administrator edit or disable them before activation. These are ordinary DNS upstreams, not paid cloud resolver endpoints. Existing saved aliases retain their current behavior when opened or when unrelated fields change. Enable target lookup explicitly to upgrade such a profile. The stored contract reuses the static profile's optional `endpoints` list: at most three distinct public IPv4 addresses, port 53, UDP or TCP. The gateway must reach them on UDP/TCP 53; UDP truncation can require TCP retry. No IPsec resolver binding is used for these target lookups.

With no target upstreams, external CNAMEs remain alias-only, so the client's recursive resolver must complete the target. With target lookup enabled, the gateway follows external targets only when they are outside **every** configured private zone. A chain into another private profile is refused; it is not sent to public DNS. Missing, denied, or failed private records never cause public fallback. Same-profile chains remain supported. The original private name is served locally; only the external target is queried upstream.

Keep a load balancer's hostname in the CNAME value rather than pinning its current addresses. Resolution follows the target's DNS TTL, bounded by the alias chain; a long static TTL does not extend a shorter upstream TTL. DNS completion alone does not make an application policy ready. Use separate IP/CIDR application permissions for the site-to-site path; this feature does not claim external-CNAME FQDN application-resource enforcement.

Each profile supports up to 128 records and each hostname up to 32 combined A/AAAA addresses. TTL is 30–86400 seconds, with a default of 300. Names must be within the profile's declared zones. Wildcards, public IP record values, duplicate records, CNAME cycles, CNAME coexistence with A/AAAA at the same name, and chains over eight aliases are rejected. Records in the same record set use one TTL. A static profile may have the optional normal DNS target upstreams described above, but cannot have an IPsec resolver binding. Separate profiles in the same Site/Gateway context can use different zones and modes; the most-specific zone still wins.

Edit records in the same profile editor, remove individual records or whole profiles, then activate the replacement version. Removing the resolver context retires all its active profiles. Each replacement has immutable provenance and withdraws the preceding configuration; cached client answers can remain until their TTL expires. DNS records do not create routes, IPsec traffic selectors, or permissions. For application traffic across IPsec, add a separate private-IP/CIDR Access Policy. A static profile has no IPsec resolver binding, so static names do not enable FQDN-over-IPsec application authorization. The existing FQDN resource lifecycle still applies to supported application paths.

## Serve private and public DNS to the office LAN

1. Use a managed static profile or an IPsec resolver profile, and enable **Serve this profile to the office LAN**.
2. Enter the gateway's actual private IPv4 LAN address and interface, for example `192.168.1.39` on `eth0`.
3. Enter explicit IPv4 client source CIDRs within that Site's approved subnets. These ranges receive DNS-only permission for this profile on UDP/TCP 53. Application access still needs separate policies.
4. For one office DNS address, enable **Resolve other domains** and enter 1–3 public IPv4 DNS resolvers that the gateway can reach over UDP and TCP 53. This is off by default. Private, reserved, duplicate, local and empty upstream addresses are rejected. Existing private-only profiles remain private-only.
5. Activate the version and check **Office DNS listener**. The UI shows its DNS IP/interface, private zones, allowed client ranges, public upstreams and current version's listener readiness.
6. Before changing DHCP, test a configured private name and a public name from an approved office device through the gateway on both UDP and TCP. For example: `dig @192.168.1.39 app.office.example.com A`, the same command with `+tcp`, then `dig @192.168.1.39 example.com A` and `+tcp`. Confirm both public upstreams are reachable if configuring more than one. Separately test application traffic and verify a client outside the allowlist is refused.
7. After these checks pass, an administrator sets the router or DHCP server's DNS address once to the gateway LAN address. Clients receive it on DHCP lease renewal; the gateway address must remain stable. Tunnex does not automatically change router settings. If the router cannot advertise a DNS server, use an existing managed office DNS server with conditional forwarders for the private zones.

A private-only listener must not be advertised as the office's sole global DNS server. Keep the existing office resolver in DHCP and configure its private-zone conditional forwarders to Tunnex when **Resolve other domains** is off.

The most-specific private zone is selected before public forwarding. Private-name denial, NXDOMAIN, timeout, or unavailable tunnel never triggers public fallback. Only names outside every configured private zone may reach the explicit public upstreams, and only from a profile's explicitly opted-in client ranges. A private-only sibling profile grants no public DNS permission. Profiles sharing the same listener address/interface must agree on the public upstream set when opted in; their private source permissions remain separate. This LAN option does not add general recursion to the gateway WireGuard listener or the control-plane resolver RPC.

The control plane validates listener and client ranges against approved Site subnets. The gateway verifies that it owns the exact address on the named interface and rejects upstreams that point back to itself. Another DNS service using that socket prevents startup. Removing or changing a listener, retiring its profile, or withdrawing an approved subnet withdraws that exposure when the policy is applied. Removing **Resolve other domains** withdraws public forwarding while preserving authorized private DNS.

Listener status confirms a current socket bind for the active profile revision; it does not prove upstream reachability, private cloud DNS, or application authorization. Static and private-only LAN profiles require a fresh gateway policy capability of at least version 12. Public default upstreams require version 13. Static external-CNAME target completion requires version 14. The gateway report must be no more than 90 seconds old; activation on an older or stale gateway is refused before retiring the previous configuration. CNAME target upstreams are separate from **Resolve other domains**: enabling target lookup does not make a private listener suitable as the office's global DNS server. Clientless office devices still need one DHCP or office DNS change; an arbitrary router cannot receive this setup automatically.

## Qualification boundaries

Native source binding, UDP truncation/TCP retry, scoped policy, route/DNS snapshot handling, and fail-closed tests have local evidence. macOS uses the privileged resolver helper and has native helper test evidence. Windows uses NRPT plus exact resolver UDP/TCP 53 permits on the live tunnel interface; its helper and WFP tests cross-compile, and the filter scope has source-review evidence. Native Windows tests and behavior still require qualification. Automatic resolver installation is not implemented by the generic helper on other operating systems.

Desktop application transit is initially limited to AWS BGP, active human devices on the exact gateway, and explicit IPv4/CIDR policies. Static IPsec, Azure, GCP, cross-gateway desktop transit, IPv6 desktop transit, and direct FQDN-resource desktop grants are not qualified by this implementation. AAAA DNS records do not establish IPv6 application transit support.

Live qualification is recorded separately with actual API/node/desktop build pins and packet receipts. It must include a desktop on another network, automatic route and suffix installation, authorized DNS and application traffic, original VPN source observed in the cloud, the AWS return `/32`, and withdrawal after revocation or expiry. Local tests and restored office LAN connectivity do not establish that remote desktop path. Actual private AWS load-balancer connectivity remains dependent on the test account permitting load-balancer creation; DNS A/CNAME tests alone do not establish LB, EKS, ECS or ASG application readiness.
