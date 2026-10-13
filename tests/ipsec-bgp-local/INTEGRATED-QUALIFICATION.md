# Integrated BGP qualification gates

Keep all Git work local. AWS CLI runs exclusively through SSH on the designated bastion `ubuntu@16.170.207.192`. Credentials, bootstrap logs, AWS VPN configuration/PSKs and authentication cookies stay in private ignored/runtime files. Do not serialize provider create bodies in evidence.

## Acceptance boundary

Package and synthetic component session proof do not activate the serving product. Root must accept stories 5–7 before enabling a real CP-authorized BGP connection. Current cloud control plane/gateway baseline remains healthy and inactive. Preserve immutable source/image/binary receipts when refreshing an owned runtime.

## Local integrated fixture

Use the existing local control plane and normal synthetic owner authentication from `.runtime/ui-accounts.env`. Its approved local prefix is `10.10.0.0/24`. Create only distinctly owned LAN client/peer/target namespaces and retain the existing site-to-site browser fixture. An encrypted peer component cannot substitute for real CP enrollment, material, policy compiler, leased authority, acknowledgements and cleanup.

Before activation capture schema version, gateway identity/certificate, source and immutable image digests. Start with no application rule: both BGP peers may establish and the accepted remote route may exist, but forwarded client traffic must fail. Then create a narrow rule using the actual policy API, set enforcing mode and verify fresh policy/lease delivery. Confirm forwarded traffic passes and ciphertext/CHILD counters increase. Remove the rule, wait for actual policy convergence and prove traffic stops again while BGP reachability remains. Exercise independent peer loss, stale authority, daemon restart and exact cleanup without manipulating runtime journals.

## AWS VGW fixture

The customer VPC is `10.84.0.0/16`; source instance is `10.84.2.10`. The isolated target VPC is `10.85.0.0/16`; private target is `10.85.1.10:8080`. Customer ASN is 65000 and VGW ASN is 64512. Customer gateway public EIP is `13.63.169.255`; the actual node runs inside the owned Docker namespace. Its host has a scoped route toward the container; target return routing must remain exclusively through the VGW. There is no VPC peering or internet path to the target. The recorded pre-activation TCP negative proves topology separation only.

Prepare a normal synthetic owner and bind only the enrolled `bgp-cloud-gateway` to a new lab site through the actual APIs. Advertise and approve exactly `10.84.2.0/24`, opt in IPsec and check existing reservations before creating any provider identity. Parse both AWS tunnel inside addresses, outside peers and PSKs only on the designated bastion from its private VPN JSON. Submit the write-only BGP provider body through normal authenticated CP APIs; retain only returned nonsecret identities/revisions. Configuration creation is disabled by default; do not enable until the root activation gate.

Use normal policy resource/rule APIs: a remote CIDR resource `10.85.1.10/32` and a site or exact CIDR source `10.84.2.0/24`, TCP port8080 only, in enforcing mode. The CP runtime compiler supports site/cidr sources and site/resource destinations and intersects grants with the connection local/remote prefix boundaries. Learned routes, BGP ASN/session state and caller-provided grants cannot confer application authority.

Run the initial forwarded TCP denial from the independent source EC2 before creating the application rule. After the narrow rule converges, prove actual source→target application response, two BGP sessions, accepted/installed prefix status, Go-owned proto242 routes, XFRM CHILD byte changes and fresh authenticated CP status. AWS tunnel metadata is supplemental: an Up tunnel alone is insufficient. Withdraw the rule and independently verify forwarding denial before disable/delete lifecycle tests. Preserve exact delivery/cleanup acknowledgements and old identities.

The fresh gateway keeps normal Docker firewall behavior. Only scoped owned bridge forwarding and exact SG prefixes/ports are permitted. Do not disable host firewalls, change global reverse-path settings, or broaden product failclosed checks to accommodate the environment.

## TGW retained-ownership boundary

Migration160 retains cleanup identity, local and remote prefix guards. In the same organization, `ipsec_provider_check_range` rejects any overlap with `ipsec_retained_remote_prefixes` even after successful cleanup. Do not delete retained rows, reset journals or replay old connection/gateway identity to force reuse.

After VGW acceptance, evaluate the replacement request through actual APIs. Preferred reuse is a new target prefix `10.86.0.0/16` and customer source `10.84.3.0/24`, with fresh AWS VPN inside ranges and legal API reservations on the existing owned CP/gateway. Evaluate all retained guards through actual APIs before assuming reuse succeeds. A fallback uses the same fresh physical gateway with a new owned namespace, fresh CP organization/site/enrollment and independently scoped authorization; retain the original CP and cleanup receipts. New prefixes alone do not excuse other retained site/gateway identity restrictions. Provision TGW only after selecting a legal case and keep old VGW evidence intact.

## Evidence

Bind each receipt to source manifest, test binary, harness and immutable image SHA, native architecture, exact container/network IDs and CP identity/revisions. Record live cloud baseline container identities before and after each component run. Include negative and positive forwarding observations separately. Store all raw potentially sensitive evidence privately; summaries contain only nonsecret IDs, readiness, pass/fail and cleanup results.

## Normal API fixture client

`api-fixture.py --private-config <mode0600.json> --state <private-state.json> <action>` supports `inspect`, `topology`, `resource`, `provider-disabled`, `grant` and `withdraw`. There is deliberately no connection enable operation. Supply base_url, organization_id, gateway_id, fixture_name, local_prefix, target_prefix (exact /32), port, email and password privately. Optional site_id reuses only an explicitly named legal site. provider_config_file points at a separate mode0600 write-only provider JSON. allow_enforcing_mode_change must be true to change organization policy mode.

Use a dedicated synthetic fixture account with normal login; the client never creates users or changes credentials. State pins owned identities, refuses ambiguous resource/site collisions and records a pending connection UUID before submission so uncertain outcomes cannot silently create another connection. Error output excludes response bodies and provider material. These helpers remain unactivated until the accepted runtime gates.

## Inactive physical setup receipt

`prepare-integrated-topology.py` prepares project `tunnexs2sbgpintegrated1007` under separate exact owner labels. Three internal bridges separate outer `198.19.241.0/24`, customer LAN `10.10.0.0/24` and target LAN `10.20.0.0/24`. The enrolled serving gateway stays on its existing CP network and gains outer eth1 and customer LAN eth2. The standalone peer, client and target have recorded exact container IDs. Only the TCP echo target runs; no IPsec/BGP daemon or forwarding grant starts during preparation.

The production public-endpoint validator correctly refuses benchmark IPv4 underlay addresses in a provider body. `prepare-public-aliases.py` preserves that validator by assigning virtual public /32 aliases inside the isolated namespaces: customer `13.63.169.255`, peer `13.50.7.159` and `51.20.220.141`. Exact namespace routes force all three aliases onto the internal Docker bridge with assigned source addresses. These values simulate the owned cloud lab endpoints locally; this is separate from real AWS evidence, and its synthetic PSKs are independently generated. Both routeget directions and distinct namespaces are captured in `.runtime/integrated-public-aliases.json`.

`probe-integrated.py deny` proves that the independent source `10.10.0.2` cannot reach real echo target `10.20.0.2:18080` before activation. `.runtime/integrated-probe-deny.json` records probe binary SHA and actual container identities. A policy resource for this exact /32 and TCP18080 can be prepared normally without an allow rule.

Normal disabled provider creation may still refuse `unsupported` until the original gateway's qualified image/code and typed capabilities are refreshed after story7. Preserve this refusal; never inject a database capability or bypass the controller. `resolve-provider` resolves a pending exact UUID through normal GET, retaining refused IDs and preventing duplicate identity creation. `prepare-peer-config.py` deliberately requires an actual disabled provider identity before generating its private flipped standalone-peer configuration.

Capture before-refresh identities using `gateway-refresh-proof.py capture` once. After the accepted image replacement, `gateway-refresh-proof.py rebind --expected-image sha256:...` accepts only a fresh container with the exact same recorded state volume, CP organization/node/certificate and runtime configuration, with the old container absent. Reconnect owned topology and reapply its isolated aliases separately. The old proof remains retained; no enrollment UUID or runtime journal is reset.

## Baseline platform refusal diagnosis

The overlay-only `platform_diagnostic_linux_test.go` reads and validates the existing managed charon process/namespace/config, then calls the actual product probe steps and exported `ProbeRuntimePlatform`. It starts no daemon, installs no NFT rules, attaches no qualification receipt and advertises no capability. The test can be crosscompiled with a Go overlay mapping its file into `apps/node/internal/ipsec`, leaving production source unchanged.

On the enrolled baseline gateway, package/privilege/daemon/kernel/XFRM/nft-check stages passed; environment census failed. IPv4 policy rules were exactly default. Docker's standard embedded DNS adds an `ip nat` table with OUTPUT DNAT and POSTROUTING SNAT for exact loopback `127.0.0.11` TCP/UDP DNS; the existing strict foreign-table census rejects it before examining those constraints. The fresh cloud gateway has the same shape with different ephemeral reply source ports. This requires narrowly reviewed product compatibility qualification; it does not justify deleting firewall rules, allowing arbitrary Docker NAT or changing host forwarding. Exact observations stay in `.runtime/platform-docker-dns.json` and the privately bound diagnostic receipt. The copied diagnostic binary is removed after observation.
