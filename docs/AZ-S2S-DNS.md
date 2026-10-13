# Azure site-to-site DNS and application qualification

Qualification status reviewed 2026-10-13: basic owned office DNS, genuine FQDN entitlement and disconnected native FQDN expiry have evidence. Sustained DNS readiness and encrypted FQDN application allow/revoke/expiry/recovery/failover/negative acceptance remain open. Receipt-checker fixtures do not establish Azure live acceptance. See the [current story status](evidence/azure-s2s-20261010/azure-story-wise-status-20261012.json).

## Reuse and Azure contract

Reuse the existing private DNS resolver profiles, most-specific suffix selection, IPsec connection/revision/source binding, policy evaluation, TCP/UDP transport, lease guards, mailbox freshness and FQDN answer generation. The existing `azure` provider hint is presentation metadata; it does not create an Azure resolver or authorize traffic. Keep ordinary DNS and application permissions separate.

## Customer setup and readiness

Follow the [customer setup guide](azure-provider-contract.md#reach-azure-private-dns) with the customer's actual network values:

- Select the intended Site, Gateway and enabled IPsec connection. Approve the private zone suffixes, resolver endpoint ranges and the gateway or office resolver's actual source address, including the return route.
- Authorize that source to the inbound resolver on both UDP and TCP port 53. Authorize application TCP/UDP ports separately. FQDN enforcement also requires its feature and a genuine eligible licence or trial.
- Verify fresh DNS answers and actual application traffic independently. A configured resolver, successful DNS query or established tunnel does not prove current application permission. When an allowed answer's address lease expires, access fails closed; recovery requires a fresh permitted answer under the current connection and policy.

The fixed suffixes, addresses and commands in the office-resolver section below describe the owned lab fixture. Substitute independently verified customer values for customer setup.

The latest owned sustained DNS window recorded 43/61 Ready reads, 18 original-cutoff refusals and one of three required new answer generations. The scheduler repair passed local qualification, but its effect on that live failure remains unproved. Basic DNS success and local tests do not establish uninterrupted private-name application access. See the [recorded cutoff result](evidence/azure-s2s-20261010/azure-static-909-enabled18-dns-original-cutoff-confirmed.json).

For customer-to-Azure private resolution, configure conditional forwarding for each approved private namespace to the Azure DNS Private Resolver **inbound endpoint private IP**. Link the private zone to the resolver's VNet and provide an approved VPN route and return path. Do not target Azure's platform IP `168.63.129.16` from outside Azure. A custom forwarder inside Azure is a separate customer configuration, not evidence of managed Private Resolver acceptance.

Inbound endpoints require a dedicated subnet delegated to `Microsoft.Network/dnsResolvers`; Microsoft recommends at least /28. Do not place customer workloads in that subnet. A stable inbound endpoint IP can be allocated statically. An outbound endpoint plus forwarding ruleset is needed when Azure must resolve customer namespaces; it is not required solely for customer-to-Azure private resolution. Resolve private service/LB names at runtime and apply the returned approved private addresses; do not copy managed service IPs into static configuration.

Sources checked 2026-10-10:

- [Custom IKE/IPsec policy combinations and supported SKUs](https://learn.microsoft.com/en-us/azure/vpn-gateway/ipsec-ike-policy-howto)
- [DNS Private Resolver overview](https://learn.microsoft.com/en-us/azure/dns/dns-private-resolver-overview)
- [Endpoints and rulesets](https://learn.microsoft.com/en-us/azure/dns/private-resolver-endpoints-rulesets)
- [Hybrid DNS deployment guidance](https://learn.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-best-practices/dns-for-on-premises-and-azure-resources)
- [Hybrid DNS troubleshooting, including the outside-VNet platform-IP constraint](https://learn.microsoft.com/en-us/troubleshoot/azure/dns/troubleshoot-azure-dns-private-resolver-hybrid-resolution-failure)

## Owned live topology and evidence

The lead provisions and inventories the smallest owned test lab through the designated Azure bastion. Record subscription/tenant, resource group, location, resource IDs and ownership tags in sanitized evidence. Run no Azure CLI locally. Preserve bastion access and unrelated resources. The lab should include a linked private zone, inbound endpoint, private application endpoint and explicit approved prefixes for the resolver and application. If a managed private LB/private service cannot be afforded or authorized, record that specific acceptance case as blocked rather than substituting a hosts-file entry or public DNS.

Record the tested source commit, binary hashes, runtime image, profile, tunnel topology, current CP configuration revision, Azure public/BGP peer identities, exact resolver IPs/private suffixes and approved routes. Evidence must contain timestamps and actual observed packets/results, with keys, tokens and PSKs removed. A receipt checker only verifies coverage names and artifact hashes; technical and secret review are still required.

## Qualification matrix

| Check | Required observed behavior |
|---|---|
| DNS UDP and TCP 53 | Allowed client/source resolves the approved private zone over the selected VPN path; UDP and TCP return packets traverse that path. |
| A, CNAME, NXDOMAIN | Private A answer is within approved prefixes; CNAME chain resolves using the approved namespace rules; nonexistent name returns genuine NXDOMAIN. |
| Large and truncated answers | Demonstrate real large/truncated UDP response and successful TCP retry across the tunnel, including lower-MTU conditions. Fixture-only proof remains local. |
| Resolver failover | With two owned reachable inbound resolver IPs in one profile, fail the selected endpoint and observe the permitted second endpoint; no cross-profile/public fallback. Record capability/resource limitations if only one endpoint is available. |
| Lease expiry and tunnel loss | DNS and both fresh/existing application flows lose access on enforced expiry/unavailable transport. No protected-zone request or response reaches WAN/public DNS. Recovery requires current valid ownership/configuration. |
| Security negatives | Unauthorized source, unapproved suffix, resolver outside approved ranges, stale configuration revision, disabled/deleted tunnel and denied application port fail closed. |
| Application flow | Query the actual customer private service/LB FQDN, then establish fresh TCP/UDP application traffic by that name. Re-resolve changed DNS without copying managed LB addresses. Record DNS success separately from application success. |
| Ordinary LAN option | Existing office resolver forwards the private suffix directly to inbound endpoint through the approved route; authorize that resolver source on DNS and application policies. Gateway WireGuard DNS listener does not imply a LAN-facing listener. |
| Azure-to-customer DNS option | When included, use outbound endpoint + forwarding ruleset for the customer namespace and verify the VPN return route and customer resolver ACLs. |

Some response semantics, such as controlled truncation, may require an owned custom authoritative server in addition to the managed resolver. Its coverage must be identified separately; it does not prove that Azure Private Resolver produced the same response.

## Ordinary office resolver fixture

Use the standard dnsmasq template `deploy/ipsec/azure-office-forwarder.conf.template` inside the already owned LAN peer namespace. This is an isolated office resolver fixture, not a second product DNS transport. Substitute only the two inventoried Azure inbound IPv4 addresses. The upstream socket source is explicitly `10.233.10.2`; the namespace must own that address and already route both inbound endpoints through the approved VPN. The resolver listens only on namespace loopback. No resolv.conf, hosts file, cache, global upstream, or static application address is used. Only `azure-s2s.test` and its subdomains have upstreams; unrelated suffixes cannot fall back to public DNS. dnsmasq supports conditional upstream selection and both DNS transports; see its [official manual](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html).

The lead executes these commands through the designated bastion, after inspecting the actual namespace and rendered configuration. `PEER_NAMESPACE`, `FORWARDER_CONF` and `FORWARDER_PID` denote owned resources; retain the foreground process handle or exact PID and terminate only that process at cleanup. Do not replace host/system resolver configuration or restart an existing resolver.

Current owned lab values reported by the lead are namespace `azure-s2s-client`, inbound endpoints `10.231.2.4` and `10.231.2.20`, source `10.233.10.2`, service CNAME `service.azure-s2s.test` to `app.azure-s2s.test`, and separately granted application TCP 8080 / UDP 8081. Render these resolver addresses into the template; the application answer remains obtained from DNS, never inserted into the forwarder configuration. The fixture was executed through the designated bastion on the owned peer namespace. dnsmasq syntax passed; ordinary loopback queries passed UDP/TCP CNAME resolution, genuine NXDOMAIN, and a 3,000-byte TXT answer with UDP-to-TCP fallback. The unrelated suffix returned REFUSED. Receipt: `evidence/azure-s2s-20261010/office-dns-observations.json`. Genuine entitlement and disconnected native FQDN expiry were separately qualified. Sustained DNS, hostname-to-application access, connected revoke/expiry/recovery, upstream failover and negative application cases remain pending.

```sh
ip netns exec "$PEER_NAMESPACE" ip -4 address show
ip netns exec "$PEER_NAMESPACE" ip route get "$INBOUND_1" from 10.233.10.2
ip netns exec "$PEER_NAMESPACE" ip route get "$INBOUND_2" from 10.233.10.2
ip netns exec "$PEER_NAMESPACE" dnsmasq --test --conf-file="$FORWARDER_CONF"
ip netns exec "$PEER_NAMESPACE" dnsmasq --keep-in-foreground --conf-file="$FORWARDER_CONF" --pid-file="$FORWARDER_PID"
```

From another bastion session, query the office resolver by explicit namespace-loopback server. Test A/CNAME, genuine NXDOMAIN, large TXT, TCP, and UDP truncation with TCP retry; retain actual query output and namespace packet captures. Replace the sample names with the actual inventoried records, without copying their answers into configuration.

```sh
ip netns exec "$PEER_NAMESPACE" dig @127.0.0.1 service.azure-s2s.test A +time=3 +tries=1
ip netns exec "$PEER_NAMESPACE" dig @127.0.0.1 service.azure-s2s.test A +tcp +time=3 +tries=1
ip netns exec "$PEER_NAMESPACE" dig @127.0.0.1 missing-owned.azure-s2s.test A +time=3 +tries=1
ip netns exec "$PEER_NAMESPACE" dig @127.0.0.1 large.azure-s2s.test TXT +bufsize=512 +time=3 +tries=1
ip netns exec "$PEER_NAMESPACE" dig @127.0.0.1 unrelated.example A +time=3 +tries=1
```

For name-to-application proof, use an application client that resolves through this resolver at runtime. For HTTP TCP, curl supports `--dns-servers 127.0.0.1` only when built with c-ares; check `curl -V` before using it. Otherwise use an existing standard client/library with an explicit resolver option, or a process-scoped libc resolver configuration in a disposable mount namespace. Do not use `--resolve`, hosts entries, or static service-IP configuration. Authorize application traffic separately for source `10.233.10.2`; a successful DNS query must not grant its application port.

For upstream failover, identify the actually selected endpoint from packet capture, then apply the existing owned fault mechanism only to that endpoint on UDP and TCP 53. With cache disabled, repeat both queries and observe source `10.233.10.2` reach the remaining approved endpoint. Record observed delay; server preference is not a fixed primary/secondary promise. Fail both endpoints, repeat the private query, and prove no other DNS destination receives it. Remove only the owned fault and terminate only the fixture resolver. These are recipe steps until real captures and results are recorded; they do not imply live acceptance or bypass the product FQDN entitlement gate.

## Profile-specific receipt gate

Use `python3 deploy/ipsec/check_azure_walk.py RECEIPT.json`. Four pending templates cover active-active/active-standby and static/BGP profiles. All require `live-azure`; AWS/GCP/emulator receipts are rejected. Standby coverage does not certify two-peer failover. BGP coverage additionally requires exact import/export/default/subprefix/prefix-limit selection and APIPA initiation evidence; static coverage requires exact route/selector and return-path proof. Never replace pending checks with pass based on a successful JSON/hash check.
