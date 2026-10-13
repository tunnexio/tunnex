# Private DNS across site-to-site IPsec

Private DNS names resolve through the customer's DNS server. Application traffic then uses the resolved private address across the tunnel and its own access policy.

Ordinary DNS forwarding does not require the `fqdn_resources` licence feature. Hostname-based application policy enforcement requires an eligible signed licence on that control-plane deployment and the organization's FQDN opt-in. Trial, Starter, Growth and Scale include this feature; activating a licence on a separate control plane does not activate this deployment.

## Existing office DNS

1. Keep AD DNS, BIND, or the existing office resolver as the client's DNS server.
2. Configure a conditional forwarder for the private zone, for example `apps.example.internal`, to the remote resolver's private endpoint IPs.
3. In AWS, use Route 53 Resolver inbound endpoints in the VPC associated with the private hosted zone. Configure endpoint security groups for UDP and TCP 53 from the actual DNS source address.
4. Include endpoint addresses in the connection's approved remote prefixes and the office DNS source in its local prefixes. Approve UDP/TCP 53 separately in Access Policies.
5. Allow the application's private LB/service address and application ports separately. A successful DNS answer does not create an application grant.

Office client → office DNS conditional forwarder → approved IPsec tunnel → remote DNS resolver → private A/CNAME answer. The subsequent application connection follows its approved application route through IPsec to the private service/LB.

## WireGuard clients with explicit split DNS

Select the Site and Gateway in **Private DNS resolvers**, then add a profile:

- Choose **Site-to-site IPsec** and the enabled connection.
- Enter an IPv4 DNS source address already assigned to that gateway and included in the connection's local prefixes.
- Add the private zone suffix and the remote resolver's approved private endpoint IPs on port 53.
- Configure the client OS or an existing supported split-DNS helper explicitly for that suffix and the gateway's WireGuard DNS address. This release does not automatically install OS suffix rules.
- Add explicit DNS access policies for the permitted clients. Configure application access separately.

Profiles are bound to the selected connection and configuration revision. The most specific matching zone wins; profiles do not fall back to one another. Disabled, deleted, expired, stale, or unproven tunnel paths deny private-zone queries. No matching profile means no private query is sent. Public DNS remains on the client's normal resolver.

Both UDP and TCP 53 are required. Large answers use DNS truncation and TCP retry instead of depending on tunnel fragmentation. Two resolver endpoints provide availability only when both endpoints' routes, policies and remote security rules are configured.

The gateway proxy listens on its WireGuard interface. Office LAN clients use their existing DNS forwarder. Do not point office clients at a gateway LAN/public address for this proxy.

**Configured** confirms stored DNS configuration; check live tunnel status and perform a DNS query to verify availability. This feature does not host a replacement DNS zone or copy AWS record sets into Tunnex.

## Qualification boundaries

Native source binding, UDP truncation/TCP retry, scoped policy, and fail-closed tests have accepted local evidence. Live qualification is recorded separately with actual API/node build pins and packet receipts. Actual private AWS load-balancer connectivity remains dependent on the test account permitting load-balancer creation; DNS A/CNAME tests alone do not establish LB, EKS, ECS or ASG application readiness.
