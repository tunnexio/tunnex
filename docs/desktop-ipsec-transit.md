# Desktop access through site-to-site IPsec

An enrolled desktop can receive authorized cloud routes through its existing WireGuard gateway and reach approved resources through that gateway's AWS BGP or static IPsec connection. The source remains the desktop's assigned IPv4 address. This path supports `aws-bgp-ipv4-v1` and `aws-static-ipv4-v1`, active human devices on the connection's exact gateway, and explicit user/group policies targeting IPv4/CIDR resources or the managed-CNAME hostname resources described below. VGW versus TGW changes the AWS return routing, not the Tunnex profile.

## Configure access

1. Use a current gateway that reports `ipsec_desktop_transit_version: 1`. AWS static desktop access additionally requires `ipsec_desktop_static_version: 1`; an older gateway's BGP desktop capability does not authorize static transit. Keep the source-preserving egress integration enabled.
2. Keep the existing approved LAN prefixes and remote cloud prefixes on the IPsec connection. Do not add the desktop VPN pool as a LAN subnet or broad authorization rule.
3. Enroll the desktop on that same gateway. Its active membership, assigned address, and enrolled WireGuard public key supply the device identity.
4. Add an Access Policy from the permitted user or group to a private IPv4/CIDR resource within the connection's remote prefixes. Select the required protocol/ports and, if needed, an expiry.
5. Connect the desktop. The existing authenticated routed-ranges poll automatically includes that device's permitted cloud destinations. The standalone desktop already consumes this poll; no separate desktop configuration format is introduced.
6. Configure cloud security rules for the authorized desktop source `/32` and service port. With BGP, verify the exact advertised desktop `/32` reaches the applicable VPN and VPC return path. With static routing, configure the return routes below before testing; Tunnex does not change AWS routes.

For the local lab, a desktop assigned `10.99.0.7` can be granted TCP 443 to a resource inside `10.180.0.0/16` through the gateway at `192.168.1.39`. The gateway exports `10.99.0.7/32` over BGP; it does not advertise `10.99.0.0/24` automatically. Approved LAN sources continue using their existing routes.

### AWS static return routes

Find the desktop's current assigned VPN address in **Devices**. Configure that exact address as a `/32` once for the selected path, and update it if the device is assigned a different address or the VPN attachment changes. Do not substitute the gateway's public IP or the desktop's Internet IP.

- **VGW:** add the desktop `/32` to the AWS VPN connection's static routes, and route that `/32` through the VGW from the application's VPC subnet route table.
- **TGW:** route the desktop `/32` from the application's VPC subnet to the TGW, then to the intended static VPN attachment in the TGW route table associated with return traffic from that VPC.
- Allow the same desktop `/32` and required service ports in application security groups and ensure network ACLs permit the return traffic. Keep the existing cloud destination routes and approved LAN routes intact.

The gateway preserves the desktop source, verifies its WireGuard ownership and applies finite packet permissions. Static mode does not advertise the desktop address using BGP. A cloud return route does not grant application access; Tunnex policy remains independently required. A changing load-balancer target address does not change the desktop's return `/32`.

## DNS is a separate entitlement

Configure DNS beside the selected Site-to-site connection under **DNS records and forwarding**. Static A/AAAA records need no upstream. For CNAME targets available through normal DNS, optional public DNS target upstreams let a policy-version-14 gateway complete the answer without a paid cloud resolver. Existing alias-only profiles remain unchanged until explicitly enabled. Targets inside another private profile are refused; unpublished private zones still require their own resolver. These DNS choices do not change the application transit provider limits below. See [Private DNS profiles](private-dns-over-ipsec.md).

A managed static record or forwarded private-zone answer may resolve to the approved resource address. For independent DNS access, grant the user or group UDP and TCP 53 access to the selected gateway's WireGuard DNS address. The standalone desktop's existing poll automatically installs each authorized active profile suffix through that gateway; other clients need their own split-DNS helper or OS suffix rules. This projection requires a fresh capable gateway report and no FQDN application licence. DNS resolution does not create an application grant. LAN DNS permissions do not authorize a WireGuard source, and WireGuard DNS permissions do not enable the LAN listener.

## Access a changing service by hostname

For an ECS service behind an internal load balancer, keep the load balancer's DNS name as the CNAME target. Task or load-balancer IP changes then do not require editing the user's policy.

1. Open the AWS BGP or static connection and choose **Add hostname access** beside its DNS settings. For an existing managed CNAME, choose **Grant access** on that record. Static connections show the VGW/TGW return-route requirements in the connection details and the same access drawer.
2. Enter the private hostname and target hostname. Select the service port (TCP 443 by default) and the users or groups who need access. The selected connection, site and gateway are already filled in.
3. If requested, review the organization's FQDN and enforcement prerequisites in the same drawer. These switches are not silently enabled by saving a record.
4. Save. This creates or reuses the DNS record, application-bound FQDN resource and explicit access rules. A partial save reports the confirmed stage; it does not claim that traffic already works.
5. Wait for fresh DNS answers and gateway policy application. Connect an authorized desktop and test the hostname with normal certificate verification. The desktop receives the exact application routes and required private DNS suffix through its existing authenticated configuration poll.

This flow requires the organization's FQDN feature entitlement and opt-in, enforcement enabled, and a fresh gateway reporting `ipsec_desktop_fqdn_version: 1` in addition to desktop transit and FQDN policy v2 support. AWS static also requires `ipsec_desktop_static_version: 1`; the UI checks the separate static hostname eligibility before saving DNS. The flow accepts managed CNAME records with configured target upstreams, AWS BGP or static, IPv4 application addresses inside the connection's approved remote ranges, and human devices on that gateway. Ordinary A/AAAA record editing and independent DNS permissions remain available separately.

The gateway resolves the configured external CNAME target, and the control plane binds that authenticated answer to a finite generation. The selected user/group's application permission supplies a scoped DNS dependency; no broad DNS or subnet policy is silently created. When the answer changes, fresh addresses replace the prior generation. Failed refreshes cannot extend the old permission beyond its original validity. Resource, rule, device or connection withdrawal invalidates the corresponding authority. Cached client DNS may outlast a withdrawn application permission and does not reopen access.

The DNS transport and application connection are separate: a normal DNS lookup for a load-balancer target does not require an IPsec resolver binding or a paid cloud resolver endpoint. Names published only in a private cloud DNS zone still need a reachable resolver for that zone. Cloud security rules and the AWS return route for the desktop source are still required.

**Network permission is to resolved IP addresses and the selected port.** Hostnames sharing one load-balancer address and port share this network access. This feature does not provide HTTP hostname or TLS SNI isolation; use application-layer authorization when that separation is required.

## Identity, routing, and withdrawal

The control plane compiles a separate ephemeral desktop grant containing the enrolled device ID, public key, exact assigned `/32`, destination, service tuple, rule ID, and rule expiry. Literal VPN-CIDR policies cannot create this authority. The grant participates in the ordinary policy hash and finite runtime lease; it does not modify immutable LAN selectors or the owned connection manifest.

Before forwarding, the gateway checks that the enrolled key uniquely owns the exact `/32` in WireGuard AllowedIPs, the interface is up and is WireGuard, and the selected return route uses that interface without another next hop. A peer with an overlapping broader range fails this proof. Guard permits bind the observed WireGuard interface index, authorized source/destination/ports, proven IPsec interface, encryption path, and current finite lease.

The egress manager adds only the exact desktop-source/cloud-destination no-SNAT tuples before its normal masquerade rule. The IPsec owner reads back that exact rule and its ordering before granting forwarding. NAT-status refusal guards remain enabled. Publishing an exemption does not grant forwarding, so initial reconciliation can safely retry after egress has installed the required tuple.

BGP exports only the unique verified desktop hosts plus the existing local exports, with a combined limit of 64 prefixes. The whole runtime policy remains bounded to 128 grants. The controller independently proves host peer/return-route ownership before disabling FRR's kernel-exact-prefix import check; a connected WireGuard pool route therefore does not require installing an artificial kernel `/32` per peer. No default route or redistribution is added.

Material refresh and priority renewal recheck device ownership. A revoked/blocked device, removed membership, disabled/expired rule, missing capability, or disabled connection withdraws desktop routed ranges and invalidates the old policy hash. Existing packet permits remain bounded by the original lease and rule expiry. Refusal commits packet denial before closing a BGP session carrying desktop exports. Changed export sets restart the owned BGP session through its existing durable cleanup path. Cleanup removes the desired no-SNAT tuples. Source NAT is never used as a return-routing workaround.

Azure, GCP, cross-gateway desktop routing, agents, IPv6 desktop transit and full-tunnel internet routing changes remain outside this implementation. Desktop FQDN grants are limited to the managed-CNAME path above. Unsupported profiles or missing static capability produce no desktop grant or route. Prefix-limit overflow fails closed; it does not truncate the authorized host list.

## Local evidence and live acceptance

Local tests cover explicit identity and membership, source spoof/overlap denial, provider gating, prefix bounds, policy-hash revocation, expiry-bound leases, route withdrawal, exact WireGuard ingress and reply egress, no-SNAT ordering, and BGP export withdrawal. The PostgreSQL integration test exercises real runtime material/leases and the routed-ranges service in a disposable child database.

The optional `TestDesktopExportNativeConfig`, run with `TUNNEX_TEST_BGPD=/opt/tunnex-bgp/bgpd` inside a network-disabled container, loads the rendered configuration into FRR and reads its actual local RIB. FRR 10.6.1 accepted the configuration and originated the exact desktop `/32`; there was no pool advertisement. This component proof does not establish an AWS peer exchange or real desktop application traffic.

The broader existing `TestPriorityActiveRenewalCallerContinuity` intermittently refuses its virtual 20-second renewal scenario. The same failure was reproduced on an unchanged baseline source archive; it is tracked separately from desktop acceptance. Do not weaken the existing lease or reserve to hide that failure.

Live acceptance still requires a desktop on another network for each claimed VGW/TGW and static/BGP combination: record its assigned VPN source, automatic destination route, successful authorized service connection, original source observed in the cloud, AWS return `/32`, and denial of an unauthorized source/service. Then revoke the rule/device and confirm route withdrawal and finite packet denial; BGP must also withdraw its dynamic desktop export. Static AWS return routes are administrator-managed and do not themselves authorize traffic. Static desktop implementation and UI tests are not evidence of completed AWS or Rajan-Mac qualification. Record build pins and traffic receipts separately from local unit/component tests.
