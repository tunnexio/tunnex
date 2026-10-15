# Desktop access through site-to-site IPsec

An enrolled desktop can receive authorized cloud routes through its existing WireGuard gateway and reach approved resources through that gateway's AWS BGP IPsec connection. The source remains the desktop's assigned IPv4 address. The initial implementation supports `aws-bgp-ipv4-v1`, active human devices on the connection's exact gateway, and explicit user/group policies targeting IPv4/CIDR resources.

## Configure access

1. Use a current gateway that reports `ipsec_desktop_transit_version: 1`. This requires its existing native BGP qualification and the source-preserving egress integration.
2. Keep the existing approved LAN prefixes and remote cloud prefixes on the IPsec connection. Do not add the desktop VPN pool as a LAN subnet or broad authorization rule.
3. Enroll the desktop on that same gateway. Its active membership, assigned address, and enrolled WireGuard public key supply the device identity.
4. Add an Access Policy from the permitted user or group to a private IPv4/CIDR resource within the connection's remote prefixes. Select the required protocol/ports and, if needed, an expiry.
5. Connect the desktop. The existing authenticated routed-ranges poll automatically includes that device's permitted cloud destinations. The standalone desktop already consumes this poll; no separate desktop configuration format is introduced.
6. Configure the cloud security rules for the authorized desktop source `/32` and the service port. The AWS VPC route table must use propagated routes from the intended VPN gateway. Verify the advertised desktop `/32` reaches the applicable AWS return path.

For the local lab, a desktop assigned `10.99.0.7` can be granted TCP 443 to a resource inside `10.180.0.0/16` through the gateway at `192.168.1.39`. The gateway exports `10.99.0.7/32` over BGP; it does not advertise `10.99.0.0/24` automatically. Approved LAN sources continue using their existing routes.

## DNS is a separate entitlement

Configure DNS beside the selected Site-to-site connection under **DNS records and forwarding**. Static A/AAAA records need no upstream. For CNAME targets available through normal DNS, optional public DNS target upstreams let a policy-version-14 gateway complete the answer without a paid cloud resolver. Existing alias-only profiles remain unchanged until explicitly enabled. Targets inside another private profile are refused; unpublished private zones still require their own resolver. These DNS choices do not change the application transit provider limits below. See [Private DNS profiles](private-dns-over-ipsec.md).

A managed static record or forwarded private-zone answer may resolve to the approved resource address. Grant the user or group UDP and TCP 53 access to the selected gateway's WireGuard DNS address separately. The standalone desktop's existing poll automatically installs each authorized active profile suffix through that gateway; other clients need their own split-DNS helper or OS suffix rules. This projection requires a fresh capable gateway report and no FQDN application licence. DNS resolution does not create an application grant. Direct desktop authorization to an FQDN application resource is outside this initial IPsec path: use the explicit CIDR resource policy for application access. LAN DNS permissions do not authorize a WireGuard source, and WireGuard DNS permissions do not enable the LAN listener.

## Identity, routing, and withdrawal

The control plane compiles a separate ephemeral desktop grant containing the enrolled device ID, public key, exact assigned `/32`, destination, service tuple, rule ID, and rule expiry. Literal VPN-CIDR policies cannot create this authority. The grant participates in the ordinary policy hash and finite runtime lease; it does not modify immutable LAN selectors or the owned connection manifest.

Before forwarding, the gateway checks that the enrolled key uniquely owns the exact `/32` in WireGuard AllowedIPs, the interface is up and is WireGuard, and the selected return route uses that interface without another next hop. A peer with an overlapping broader range fails this proof. Guard permits bind the observed WireGuard interface index, authorized source/destination/ports, proven IPsec interface, encryption path, and current finite lease.

The egress manager adds only the exact desktop-source/cloud-destination no-SNAT tuples before its normal masquerade rule. The IPsec owner reads back that exact rule and its ordering before granting forwarding. NAT-status refusal guards remain enabled. Publishing an exemption does not grant forwarding, so initial reconciliation can safely retry after egress has installed the required tuple.

BGP exports only the unique verified desktop hosts plus the existing local exports, with a combined limit of 64 prefixes. The whole runtime policy remains bounded to 128 grants. The controller independently proves host peer/return-route ownership before disabling FRR's kernel-exact-prefix import check; a connected WireGuard pool route therefore does not require installing an artificial kernel `/32` per peer. No default route or redistribution is added.

Material refresh and priority renewal recheck device ownership. A revoked/blocked device, removed membership, disabled/expired rule, missing capability, or disabled connection withdraws desktop routed ranges and invalidates the old policy hash. Existing packet permits remain bounded by the original lease and rule expiry. Refusal commits packet denial before closing a BGP session carrying desktop exports. Changed export sets restart the owned BGP session through its existing durable cleanup path. Cleanup removes the desired no-SNAT tuples. Source NAT is never used as a return-routing workaround.

Static IPsec, Azure, GCP, cross-gateway desktop routing, agents, IPv6 desktop transit, full-tunnel internet routing changes, and direct FQDN-resource desktop authorization are not qualified by this implementation. Unsupported profiles produce no desktop grant or route. Prefix-limit overflow fails closed; it does not truncate the authorized host list.

## Local evidence and live acceptance

Local tests cover explicit identity and membership, source spoof/overlap denial, provider gating, prefix bounds, policy-hash revocation, expiry-bound leases, route withdrawal, exact WireGuard ingress and reply egress, no-SNAT ordering, and BGP export withdrawal. The PostgreSQL integration test exercises real runtime material/leases and the routed-ranges service in a disposable child database.

The optional `TestDesktopExportNativeConfig`, run with `TUNNEX_TEST_BGPD=/opt/tunnex-bgp/bgpd` inside a network-disabled container, loads the rendered configuration into FRR and reads its actual local RIB. FRR 10.6.1 accepted the configuration and originated the exact desktop `/32`; there was no pool advertisement. This component proof does not establish an AWS peer exchange or real desktop application traffic.

The broader existing `TestPriorityActiveRenewalCallerContinuity` intermittently refuses its virtual 20-second renewal scenario. The same failure was reproduced on an unchanged baseline source archive; it is tracked separately from desktop acceptance. Do not weaken the existing lease or reserve to hide that failure.

Live acceptance still requires a desktop on another network: record its assigned VPN source, automatic destination route, successful authorized service connection, original source observed in the cloud, AWS return `/32`, and denial of an unauthorized source/service. Then revoke the rule/device and confirm route withdrawal, finite packet denial, and return-export withdrawal. Record build pins and these traffic receipts separately from local unit/component tests.
