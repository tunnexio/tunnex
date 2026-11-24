# K8N-3 — kubectl and cluster API access through Tunnex

Story branch: `story/kubernetes-next`. Item 4 of `docs/EPIC-kubernetes-next.md`. Written 2026-11-23.
This is a decision paper. It changes no product code. Facts about Tunnex come from the code at this
branch; facts about managed control planes come from the provider pages listed under Sources, read
on the same day. Anything not read in code or in a cited page is marked **unconfirmed** and listed
again near the end.

## The question

Customers want to run `kubectl` against a cluster whose API server is not reachable from the
internet, through Tunnex, without a second VPN or a bastion.

## What is true today

Tunnex reaches Services inside a cluster. It does not offer the cluster's API.

- An administrator registers a cluster against a site and an in-cluster gateway, with an address
  range for exposed Services and a DNS zone (`apps/api/internal/k8s/service.go`, `registerCluster`).
- Exposing a Service port allocates one address (VIP) from that range and gives it the name
  `<service>.<namespace>.svc.<cluster>.<zone>` (`ExposeService`, `FQDN`).
- A rule (`dst_kind='k8s_service'`) names a person, group, site, range or agent and one exposed
  Service. The compiler turns it into an allow entry for the Service's current VIP and port, plus
  DNS on the cluster's DNS address, on the device's gateway and on the cluster's gateway
  (`apps/api/internal/policy/compiler.go`). No rule, no path.
- The gateway does not forward to the ClusterIP. It watches Services and EndpointSlices and rewrites
  VIP:port straight to a ready endpoint address and its target port
  (`apps/node/internal/egress/k8swatch_linux.go`, `dnat_linux.go`). The forward chain matches the
  address the client dialled (`ct original ip daddr`), so the rule still applies after the rewrite.
- Device traffic leaving the gateway node on a non-tunnel interface is masqueraded to the node's
  address (`egress_linux.go`, `ip saddr <pool> oifname != <tunnels> masquerade`). The destination
  sees the gateway's node, not the device.
- The gateway's ServiceAccount may `get`, `list` and `watch` Services and EndpointSlices, cluster
  wide, and nothing else (`deploy/helm/tunnex-gateway/templates/rbac.yaml`). It runs on the host
  network with `NET_ADMIN`.

### "Kubernetes scopes" is not API access

The dashboard's Kubernetes scopes (`apps/api/internal/k8s/scope_activation.go`, migrations 0086 and
0123, `AccessKubernetesScopes.tsx`) is a rule whose destination is a cluster and whose members are
individual exposed Service ports. Each member is approved or rejected by a person with
`k8s_scope:approve`; a Service exposed later joins as pending. It is unlocked by edition and off by
default per organization. Migration 0086 says in its header that a scope "grants no namespace, Pod,
Node, VPC, or Kubernetes API entitlement". It is a way to grant many Services at once. It must stay
that.

### The API server can already be exposed by accident

Nothing in the control plane or the gateway treats the `kubernetes` Service in `default` specially.

- `ExposeService` accepts any namespace and name with one port. `default/kubernetes` on TCP 443
  passes.
- The gateway's inventory reports every Service with a TCP or UDP port (`ServiceInventory`), so
  `default/kubernetes` is offered as a candidate like any other, including to a scope.
- The operator exposes whatever a `TunnexExposedService` names; K8L-8 already records that anyone
  allowed to create that resource can expose a Service in any namespace.

So today an administrator can expose the control plane as "a Service", and the rule, the audit entry
and the scope candidate look the same as for a web app. Whether the traffic then arrives is
**unconfirmed** (see "Can the existing mechanism reach the API server"). Either way this needs
closing: API reach must be a named thing.

### What Tunnex already does for privileged sessions

Server Access (`apps/api/internal/serveraccess`) brokers browser SSH. It is the precedent for
Tunnex holding a credential on purpose: the control plane keeps one SSH user CA per organization,
sealed (`server_access_settings.ca_private_sealed`); the customer installs that CA's public key on
each server; a session is admitted only with fresh MFA (60 to 900 seconds, per organization), is
bound to the person's login and a grant, has a lease the gateway must renew, is ended on revoke, and
is written to the audit log, with optional recording. Nothing comparable exists for Kubernetes.

## What a customer needs

1. **A network path to a private API endpoint.** EKS with public access disabled, an AKS private
   cluster, a GKE cluster with only the internal endpoint, or a self-managed cluster on a private
   network.
2. **A kubeconfig that still verifies the server.** A kubeconfig holds three things: the server
   URL, the CA that signed the API server's certificate, and the user's credential. The credential
   is usually a plugin that fetches a short-lived token: `aws eks get-token` on EKS [S2],
   `kubelogin` on AKS [S5], `gke-gcloud-auth-plugin` on GKE [S8]. `kubectl` runs such plugins
   itself [S10].
3. **Streaming commands.** `kubectl exec`, `attach`, `cp` and `port-forward` upgrade the HTTP
   connection. Before Kubernetes 1.31 the upgrade was SPDY/3.1; from 1.31 `kubectl` uses WebSocket
   by default, and "many modern proxies, gateways, and load balancers no longer support" SPDY [S13].
   `kubectl logs -f` and `get --watch` are long-lived plain responses. Anything in the path that is
   not a plain TCP forwarder must handle all of these.
4. **People and pipelines.** A person has a device, a browser and MFA. A pipeline has none of them:
   it uses a non-interactive credential (for example `kubelogin`'s workload identity mode [S5]) and
   needs a path that does not depend on someone being signed in.
5. **An answer to "who did what".** The cluster's own audit log answers it for the cluster
   identity. Security teams also ask it of the access product.

## TLS: what the kubeconfig may point at

The API server presents one certificate. `kubectl` checks it against the host in `server:` unless
`tls-server-name` is set: "TLSServerName is used to check server certificate. If TLSServerName is
empty, the hostname used to contact the server is used." [S9]

- On a kubeadm cluster the certificate covers the node's hostname and addresses, any load balancer
  name or address the administrator added, and `kubernetes`, `kubernetes.default`,
  `kubernetes.default.svc`, `kubernetes.default.svc.cluster`,
  `kubernetes.default.svc.cluster.local` [S12]. k3s adds names with `--tls-san` [S14].
- On a managed cluster the customer cannot add names. The certificate certainly covers whatever
  host the provider's own kubeconfig uses, because that kubeconfig verifies against it. Whether it
  also covers the `kubernetes.default.svc` names on EKS, AKS and GKE is **unconfirmed**.
- A Tunnex name such as `kubernetes.default.svc.<cluster>.<zone>` and a Tunnex VIP are in no API
  server certificate, and on managed clusters never can be.

Consequence. If the kubeconfig points at a Tunnex name or VIP, it must also set `tls-server-name`
to a name the certificate does cover. The safe choice is the host from the original `server:` line,
which is covered by construction. If the kubeconfig keeps pointing at the provider's own endpoint
and Tunnex only carries the packets, nothing in it changes.

`insecure-skip-tls-verify` is never the answer and Tunnex must never print it.

## Can the existing mechanism reach the API server

Read from the code; not yet run.

- **The Service is watched.** The watcher lists all Services and EndpointSlices.
  `default/kubernetes` exists on every cluster with port 443 (EKS shows it in its own example
  output [S2]). Expected: its endpoints are the API server's addresses, in an EndpointSlice labelled
  `kubernetes.io/service-name=kubernetes` with a port named `https` and `ready: true`. The watcher
  needs exactly that label and that condition (`parseSlice`); a missing `ready` is treated as not
  ready. The real shape on each platform is **unconfirmed**.
- **A managed control plane is outside the pod network, and that is fine.** The rewrite targets an
  address, not a pod. The gateway is on the host network, so it reaches what its node reaches, and
  the node already talks to the API server. The packet leaves masqueraded as the node. Expected to
  work; **unconfirmed** live.
- **A gateway on a control-plane node cannot use this path.** `classify` drops any endpoint that is
  one of the gateway's own addresses, because a rewrite to a local address is delivered to the host
  itself and skips the forward chain where rules are enforced. On a single-node k3s cluster, or a
  kubeadm cluster with the gateway on its only control-plane node, the mapping is refused with
  `no_ready_endpoints`. With three control-plane nodes the local one is dropped and the others
  serve.
- **The certificate does not match.** As above: `tls-server-name` is required.

## The designs

### A — network only

Tunnex carries TCP to the API server and decides who may open that connection. The user
authenticates to the cluster with the credential they already have. TLS runs from `kubectl` to the
API server; Tunnex forwards ciphertext.

Two ways to carry it.

**A1, through a VIP.** The cluster API becomes one more address in the cluster's range, mapped to
`default/kubernetes`. The kubeconfig changes two lines:

    server: https://<tunnex name for the cluster API>
    tls-server-name: <host from the original server line>

**A2, to the provider's own endpoint.** The private endpoint's address is already inside the
cluster's network. If that network is an approved subnet of the gateway's site, a resource (an
address and port) or an FQDN resource (a hostname, resolved in the site's context) with a rule on
TCP 443 or 6443 carries it. The kubeconfig is the one the provider's CLI wrote. This needs no new
code, and no one has walked it.

Gives:
- `kubectl` against a private cluster with one connection, default deny, per person or group.
- Every `kubectl` feature, including exec, logs, port-forward and watch, because nothing between
  the client and the API server interprets the stream.
- Works with every credential type and every client (`helm`, `k9s`, Terraform), unchanged.

Costs:
- Tunnex does not know the Kubernetes identity, the verb or the resource. Its record is "this
  device opened TCP 443 to this cluster's API at this time, allowed by this rule".
- The cluster's audit log shows the gateway node's address as the client, for every Tunnex user.
- A1 needs a kubeconfig edit that provider CLIs overwrite when they regenerate the file.
- A2 differs per platform and depends on the cluster's network being routed as a site.

Security:
- Tunnex holds no cluster credential and stores none. Two independent locks: a Tunnex rule to reach
  the API server, and a cluster credential to use it. Tunnex can only take access away.
- A person with the rule and no credential reaches whatever the API server offers anonymously.
  That is a smaller audience than a public endpoint, and larger than none.
- A compromised Tunnex control plane can give any enrolled device a path to the API server. It
  cannot authenticate, and it cannot read or change the traffic without the API server's key.
- Source-address controls on the cluster side stop distinguishing users: they all arrive as the
  gateway node.

### B — Tunnex authenticates

Tunnex decides the Kubernetes identity as well as the path.

**B1, an in-cluster proxy that impersonates.** A proxy inside the cluster ends the user's TLS,
establishes who they are in Tunnex, and repeats the request to the API server with its own
ServiceAccount and the headers `Impersonate-User` and `Impersonate-Group` [S11]. The customer binds
Kubernetes roles to those users and groups. The cluster's audit log records both the proxy and the
`impersonatedUser` [S11]. The proxy can log every request.

The credential: the proxy's ServiceAccount needs the `impersonate` verb. Granted on all users and
groups, that is cluster-admin by another name. It can be limited to listed names with
`resourceNames` [S11], so the blast radius is exactly the union of what the listed users and groups
are bound to, readable in one ClusterRole. From Kubernetes 1.36, constrained impersonation (beta)
can also limit which actions may be taken while impersonating [S11].

**B2, an in-cluster proxy that mints tokens.** The proxy asks the API server for a ten-minute token
for one of a few ServiceAccounts the customer created (`tunnex-view`, `tunnex-deploy`) and uses it
for the request. The cluster's audit log shows the ServiceAccount, not the person; only Tunnex knows
the person. The blast radius is the listed ServiceAccounts. That the token permission can be limited
to named ServiceAccounts is **unconfirmed** here.

**B3, no proxy: Tunnex as an OIDC issuer.** The cluster trusts tokens signed by Tunnex. A `kubectl`
plugin fetches a short-lived token after MFA; the path stays as in A. The cluster's own audit log
names the person. Tunnex logs issuance, not verbs. Tunnex's control plane holds a signing key:
whoever has it can be any Tunnex-prefixed user or group on every cluster that trusts it. Platform
limits: EKS requires the issuer to be "publicly accessible" and refuses self-signed certificates
[S3]; on AKS the feature is a preview, needs public discovery endpoints and prefixes every name with
`aks:jwt:` [S6]; a self-managed cluster can be configured without public discovery [S10]; GKE is
**unconfirmed**. A self-hosted Tunnex that is not on the internet cannot serve EKS or AKS this way.

**Client certificates are refused in every variant.** A certificate cannot be revoked before it
expires.

Gives (B1, B2): one identity for access and for the cluster; per-request audit in Tunnex; MFA at
the moment of use; a kubeconfig that needs no cloud CLI; off-boarding in one place.

Costs:
- A proxy that reads HTTP: it must pass SPDY and WebSocket upgrades, watches, large responses and
  aggregated APIs, across the `kubectl` versions customers run. This is the bulk of the work.
- The proxy sees everything in clear, including Secrets that users read and exec streams.
- A second certificate to manage: the proxy's, with its CA in a Tunnex-issued kubeconfig.
- Customer work: writing RBAC for the Tunnex users and groups, and listing them for the proxy.
- A user-supplied `Impersonate-*` header must be rejected by the proxy, or any user becomes any
  listed identity.

Security:
- Tunnex is now trusted with authority inside the cluster. The credential stays in the cluster (a
  projected ServiceAccount token in the proxy pod), but the control plane tells the proxy who each
  device is. A compromised control plane can therefore act as any listed identity on every cluster
  using the feature.
- It must not live in the gateway pod. That pod is root on the host network; EPIC item 3 exists to
  reduce it.

### C — staged

A first, as an explicit and separately permitted destination. B later, per cluster, opt-in, as its
own story. The two do not conflict: A is the path B's users would still travel.

## Recommendation

Do A now, do it explicitly, and decide B separately.

**Before any code: a one-day walk with what exists.** On EKS and GKE Standard test clusters, and on
a self-managed cluster with the gateway on a worker node, expose `default/kubernetes` 443 as an
ordinary Service, grant it, and run `kubectl` with the two-line kubeconfig change. On EKS also try
A2 with an FQDN resource and an untouched kubeconfig. This settles every **unconfirmed** item that
decides between A1 and A2. Remove the exposure afterwards.

### Stage 1 — the cluster API as a named destination

Assuming the walk confirms A1:

1. A registered cluster gains "API access", off by default. Turning it on needs a new permission,
   `k8s_api:manage`, separate from `k8s:manage`, and writes an audit entry.
2. Turning it on allocates one address from the cluster's range and adds a mapping to
   `default/kubernetes` on port 443. The name is the one the mechanism already produces,
   `kubernetes.default.svc.<cluster>.<zone>`, so the gateway's forwarding and DNS are the ones
   Services use. A shorter alias can come later; it would need a gateway DNS change.
3. A rule with a new destination kind, `k8s_api`, grants a person or a group TCP 443 to that
   address. Default deny. Expiring grants work as for any rule.
4. `default/kubernetes` is refused as an ordinary exposure (`ExposeService`, the operator) with a
   message pointing at API access, and is left out of inventory candidates and scopes.
5. The cluster page shows the two kubeconfig lines and says in one sentence that the user's own
   cluster credential still decides what they may do.
6. "Test access" understands the destination (below).
7. The gateway reports a distinct reason when every API endpoint was dropped as its own address,
   so "gateway is on the control-plane node" is not shown as "no ready endpoints".

If the walk shows A1 does not hold on a platform, that platform uses A2 with the same destination
kind in the rule model, pointing at the provider endpoint. The rule model, permission, audit and
"Test access" work are the same either way.

About one week including the walks.

**Deliberately not in stage 1:**
- No Kubernetes identity. Tunnex does not issue, store, proxy or see any cluster credential.
- No record of verbs, resources or exec content.
- No MFA at the moment of use. The device's connection is the only Tunnex check.
- No kubeconfig generation and no CLI helper. Two lines, shown on screen.
- No grants to sites, address ranges or agents (founder decision 3).
- No GitOps resource for API access. The operator only gains the refusal.
- No support for a gateway on a control-plane node, and none for GKE Autopilot (no gateway runs
  there today).

### Stage 2 — identity, as its own paper (K8N-4)

An opt-in, per-cluster, in-cluster proxy in its own unprivileged pod, B1 unless that paper finds
otherwise: fresh MFA and a short-lived Tunnex token to open a session, as Server Access does;
impersonation limited to names the customer lists; per-request records. Stage 1's destination stays
the path. Several weeks; needs founder decisions 6 and 9 first.

### What Tunnex is trusted with

| | Stored credential | Can it act in the cluster | Sees API traffic | If the control plane is compromised |
| --- | --- | --- | --- | --- |
| Today | Gateway ServiceAccount: read Services and EndpointSlices | No | No | Service reach can be granted |
| Stage 1 | The same. Nothing added | No | No (TLS end to end) | API reach can be granted; no cluster identity comes with it |
| Stage 2 (B1) | Proxy ServiceAccount in the cluster, `impersonate` on listed names only | Yes, as any listed user or group | Yes, in clear | It can act as any listed identity. Never `system:masters`, never an unlisted name |

Tunnex never holds cluster-admin, and never holds any cluster credential that is not named in a
ClusterRole the customer can read.

## Access control and audit

**A new destination kind, not `k8s_service`.**

- A scope's members are Service rows. If the API were one, it would be a scope candidate and could
  be approved in a batch. Migration 0086 promises scopes carry no API entitlement.
- The rule list, the audit log and "Test access" must say "Kubernetes API of cluster X". It is a
  different class of risk from a web app.
- A separate permission means someone who may expose Services may not expose the control plane.
- Agent access, agent templates and just-in-time requests already handle `k8s_service`
  (`agentaccess`, `agenttemplates`, `agent_access_requests.sql`). A new kind keeps the API out of
  all of them until someone decides otherwise.

Shape: a row per cluster for the API endpoint (cluster, address, enabled), a rule column referencing
it, and `dst_kind='k8s_api'` added to the two checks on `policy_rules`. The compiler emits what it
emits for a Service: the address on TCP 443 and the cluster's DNS address, on the device's gateway
and the cluster's gateway. No artifact version change, so older gateways still serve it.

**Default deny** is unchanged. With enforcement on, no rule means the SYN is dropped. With
enforcement off (open mesh), an enabled API endpoint is reachable by every device, as every exposed
Service is. The enable dialog must say so.

**"Test access"** (`docs/UIX-1-device-access-test.md`) with the cluster API's name or address and
TCP 443 runs its existing checks. Additions:

- Destination: `k8s_api_not_enabled` when API access is off for that cluster.
- Rule: `no_matching_grant` reads "no rule lets this device reach the Kubernetes API of <cluster>".
- A new check, endpoint: `k8s_api_endpoint_unavailable` with the gateway's reason, including the
  "gateway is on the control-plane node" case.
- On `allowed`, a fixed sentence: "Tunnex allows the connection. The cluster still decides what you
  may do: a 401 or 403 from kubectl is the cluster's answer, not Tunnex's."

A Tunnex refusal looks like a timeout to `kubectl`. A cluster refusal is an HTTP status after a
successful TLS handshake. The docs should say how to tell them apart.

**Logged in stage 1:**
- Audit log: API access enabled or disabled (who, which cluster); rule created, disabled, expired,
  deleted, with the destination named.
- Access events: each allowed, denied and terminated flow, with device, person, rule, time and
  port. Whether Service flows are labelled with their Service today, and so whether API flows need
  new labelling, is **unconfirmed**.
- Not logged, because not visible: the Kubernetes user, verbs, resources, exec content.

Removing a rule ends open connections, including a running `exec`, while the gateway agent is up
(`conntrack_linux.go`). The known gap stands: a rule removed while the agent is down leaves open
flows until they end.

## Per platform

**EKS.** With public access off, "any `kubectl` commands must come from within the VPC or a
connected network", and "the cluster's API server endpoint is resolved by public DNS servers to a
private IP address from the VPC" [S1]. The cluster security group controls the private endpoint, and
a connected network must be allowed on port 443 [S1]. Through Tunnex the client is the gateway node,
which the cluster must already allow for the node itself to work. A2 fits well: the device resolves
the endpoint name itself, the certificate matches, the kubeconfig is untouched. The endpoint's
addresses can change, so an FQDN resource rather than fixed addresses. Without Tunnex, AWS offers
CloudShell in a VPC environment [S2]: that is the break-glass path.

**AKS.** The API server sits behind a private endpoint in the node subnet, and AKS "might recreate
the private endpoint in a different subnet" on stop and start [S4]. By default there is a private
DNS zone linked only to the cluster's network and also a publicly resolvable name for the same
private endpoint; the public name can be turned off, and it "doesn't create a public API endpoint"
[S4]. With it on, the device resolves the name itself; with it off, the name must be resolved
inside the network. Authorized IP ranges do not apply to the
private endpoint [S4]. `az aks command invoke` reaches a private cluster through the Azure API, is
"not for programmatic access", and returns text only [S7]: break-glass, not a substitute. AKS has
never been walked live with Tunnex at all. Clusters using API Server VNet Integration were not
examined.

**GKE.** There are IP endpoints and a DNS endpoint [S8]. The DNS endpoint is "accessible from any
network reachable by Google Cloud APIs, including on-premises or other cloud networks", is
authorized by IAM (`container.clusters.connect`), and removes the need for "a bastion host or proxy
nodes" [S8]. A customer who enables it does not need Tunnex to reach the API, and Tunnex should say
so. Service account tokens and client certificates are off by default on that endpoint [S8]. For
the internal IP endpoint with authorized networks on, "only the IP addresses that you defined in
the Add authorized networks list can access" it [S8]; whether the gateway node's address is always
admitted is **unconfirmed**.
Only GKE Standard is supported by the gateway.

**Self-managed.** The API server listens on the control-plane nodes (6443 by default on k3s [S14])
or behind the customer's load balancer. The customer controls the certificate's names [S12] [S14],
so a Tunnex name could even be added and `tls-server-name` dropped. A1 is refused when the gateway
is on the only control-plane node. A2 to a node address works only when that address is not the
gateway's own; traffic to the gateway's own address is not judged by the forward chain at all (the
`tunnex` table has forward and NAT chains only), and what happens to it is **unconfirmed** and must
be checked before anyone is told to do it.

Only on some: untouched kubeconfig (A2: EKS, AKS with the public name, GKE internal IP,
self-managed); a path that needs no Tunnex (GKE DNS endpoint); adding a Tunnex name to the
certificate (self-managed); OIDC trust without a public issuer (self-managed).

## Risks

- **Locking yourself out.** If the gateway is down, `kubectl` through Tunnex is down, and the
  gateway runs in the cluster it gives access to. A cluster has one gateway; a second is a preview.
  Customers must keep a path that does not use Tunnex. The docs must say so on the first screen.
- **Mistaken for identity.** "kubectl access" will be read as "Tunnex controls what people do in
  the cluster". Stage 1 does not. The enable dialog, the docs and the sales language must say
  "network path".
- **Wider anonymous reach.** Everyone with the rule can reach the API server's unauthenticated
  surface. A cluster with careless anonymous bindings is more exposed than before.
- **One client address.** All Tunnex users appear to the cluster as the gateway node. Cluster-side
  source filters and audit by address stop being useful for them.
- **Open mesh.** With enforcement off, enabling API access opens it to every device.
- **Throughput.** A device on another gateway travels through the hub (K8L-7). Large `kubectl cp`
  and log streams follow that path.
- **Existing exposures.** An organization may already have exposed `default/kubernetes`. The
  refusal must not silently break it (founder decision 8).

## What stays refused

- Storing a kubeconfig, a token, a certificate or a cloud credential for a cluster, in stage 1.
- Issuing client certificates, ever.
- Any credential with `cluster-admin`, `system:masters`, or unrestricted `impersonate`.
- `insecure-skip-tls-verify`, in anything Tunnex prints.
- The API as a scope member, or as an ordinary exposed Service.
- Reach to kubelets, etcd or nodes. This is the API server's port only.
- A SOCKS proxy as the transport: Kubernetes documents that it does not carry exec, attach or
  port-forward over SPDY [S9].

## Tests

- Compiler: a `k8s_api` rule yields the address on TCP 443 and DNS, on both gateways; nothing when
  API access is off; nothing for a deleted cluster.
- Control plane, against a database: enable and disable need `k8s_api:manage`; a rule needs
  `policy:manage`; another organization's cluster is 404; `default/kubernetes` is refused by
  `ExposeService`; it is absent from scope candidates; migration up and down.
- Gateway: EndpointSlice fixtures for `default/kubernetes` captured from each platform in the walk;
  an endpoint equal to a gateway address is dropped and reported with the new reason.
- Operator: a `TunnexExposedService` for `default/kubernetes` is `Ready=False` with the reason.
- "Test access": each new code, and the fixed sentence on `allowed`.
- Dashboard: the toggle, the kubeconfig lines, the rule builder, the open-mesh warning.
- Every existing Service, scope and rule test passes unchanged.

## Live walk

Before code (decides A1 or A2), per platform:

1. `kubectl get endpointslices -n default -l kubernetes.io/service-name=kubernetes -o yaml`: record
   addresses, port name, ready condition.
2. Read the API server certificate's names with `openssl s_client`.
3. Expose `default/kubernetes` 443, grant it, check the gateway log for `k8s_vip_resolved`.
4. With the two-line kubeconfig change: `get`, `apply`, `logs -f` for ten minutes, `exec -it`,
   `port-forward`, `cp`, `get --watch` past five minutes. Once with `tls-server-name` set to an IP
   address where the original server line was an IP.
5. Remove the rule during an `exec`: the session ends; a new command times out.
6. Repeat step 4 from a device on a different gateway.
7. Read the cluster's audit log for the client address.
8. Single-node k3s: confirm the refusal; then try the node's own address on 6443 with no rule.
9. EKS: A2 with an FQDN resource and an untouched kubeconfig.
10. AKS: the first walk of any kind.

After code: the same matrix through the named destination, plus "Test access" for allowed, no rule,
not enabled and endpoint unavailable; the scope and operator refusals; open-mesh behaviour.

## Not confirmed

1. The shape and `ready` condition of the `kubernetes` EndpointSlice on EKS, AKS, GKE and k3s, and
   what address it holds on each.
2. That a rewrite to a managed control plane's address, masqueraded as the node, is accepted on
   EKS, AKS and GKE.
3. Whether managed API server certificates cover the `kubernetes.default.svc` names.
4. That `tls-server-name` may be an IP address.
5. Whether any managed endpoint routes on the TLS server name in a way the change would upset.
6. Whether GKE always admits the cluster's own nodes to the internal endpoint when authorized
   networks are on.
7. What happens to device traffic addressed to the gateway node's own address.
8. That A2 works through an in-cluster gateway with an FQDN resource for a provider endpoint.
9. Whether access events label Service flows with their Service today.
10. For stage 2: that `resourceNames` cannot match by prefix; that token creation can be limited to
    named ServiceAccounts; GKE's support for a customer OIDC issuer; AKS with API Server VNet
    Integration; that Kubernetes offers no way to revoke a client certificate.
11. That no organization has already exposed `default/kubernetes`.

## Decisions for the founder

1. Ship stage 1 as "kubectl access" knowing Tunnex will not know who did what in the cluster, or
   hold the feature until identity exists?
2. Which edition: everyone, or unlocked like scopes?
3. Who may be granted API reach: people and groups only (recommended), or also sites and address
   ranges (how a pipeline would get it) and AI agents?
4. A separate permission `k8s_api:manage` (recommended), or reuse `k8s:manage`?
5. Is "no MFA at the moment of use" acceptable for stage 1?
6. For stage 2, which trust to ask of customers: a proxy inside their cluster that reads traffic
   and may impersonate listed identities, or a signing key in the Tunnex control plane that their
   clusters trust, with no per-request record in Tunnex?
7. May Tunnex ever generate a kubeconfig that contains a credential? Recommended: no.
8. If an organization has already exposed `default/kubernetes`: leave it and refuse new ones, or
   flag it for the administrator to convert?
9. In stage 2, are exec command lines logged (they can contain secrets), and are streams recorded?
10. May the docs tell GKE customers that the DNS endpoint needs no Tunnex?
11. Priority against items 2 and 3 of the epic. Stage 1 is about a week; stage 2 is several.

## Rollback

Stage 1 is additive: one table, one destination kind, one permission, two refusals. Turning API
access off for a cluster removes its address and compiles its rules to nothing. Removing the
feature leaves Services, scopes and rules as they are. The refusal of `default/kubernetes` as an
ordinary Service should stay even if the rest is removed.

## Sources

Read 2026-11-23.

- [S1] Amazon EKS, Cluster API server endpoint:
  https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html
- [S2] Amazon EKS, Connect kubectl to an EKS cluster by creating a kubeconfig file:
  https://docs.aws.amazon.com/eks/latest/userguide/create-kubeconfig.html
- [S3] Amazon EKS, Grant users access to Kubernetes with an external OIDC provider:
  https://docs.aws.amazon.com/eks/latest/userguide/authenticate-oidc-identity-provider.html
- [S4] Azure AKS, Create a private AKS cluster:
  https://learn.microsoft.com/en-us/azure/aks/private-clusters
- [S5] Azure AKS, Use kubelogin to authenticate:
  https://learn.microsoft.com/en-us/azure/aks/kubelogin-authentication
- [S6] Azure AKS, External identity providers with structured authentication (preview):
  https://learn.microsoft.com/en-us/azure/aks/external-identity-provider-authentication-overview
- [S7] Azure AKS, Access a private cluster using command invoke:
  https://learn.microsoft.com/en-us/azure/aks/access-private-cluster
- [S8] Google GKE, About network isolation; Customize your network isolation; Install kubectl and
  configure cluster access:
  https://docs.cloud.google.com/kubernetes-engine/docs/concepts/network-isolation
  https://docs.cloud.google.com/kubernetes-engine/docs/how-to/latest/network-isolation
  https://docs.cloud.google.com/kubernetes-engine/docs/how-to/cluster-access-for-kubectl
- [S9] Kubernetes, kubeconfig (v1) reference:
  https://kubernetes.io/docs/reference/config-api/kubeconfig.v1/
- [S10] Kubernetes, Authenticating:
  https://kubernetes.io/docs/reference/access-authn-authz/authentication/
- [S11] Kubernetes, User impersonation:
  https://kubernetes.io/docs/reference/access-authn-authz/user-impersonation/
- [S12] Kubernetes, PKI certificates and requirements:
  https://kubernetes.io/docs/setup/best-practices/certificates/
- [S13] Kubernetes blog, Streaming transitions from SPDY to WebSockets (1.31):
  https://kubernetes.io/blog/2024/08/20/websockets-transition/
- [S14] k3s, server CLI reference: https://docs.k3s.io/cli/server

## Founder ruling, 2026-11-23

"Do the recommended." Recorded against the decisions above, where the paper made a recommendation:

- Stage 1 (network reach only, no cluster identity held by Tunnex) goes ahead as written.
- Grants are for people and groups only. Sites, address ranges and AI agents are not grantable in
  stage 1.
- A separate `k8s_api:manage` permission, not `k8s:manage`.
- Tunnex never generates a kubeconfig that contains a credential.
- New exposures of `default/kubernetes` as an ordinary Service are refused; existing ones are left in
  place and not converted.

Still open, because the paper made no recommendation and only the founder can decide: which edition
carries the feature, whether "no MFA at the moment of use" is acceptable for stage 1, the stage 2
trust model, and priority against the other items. The one-day manual walk on real clusters comes
before any stage 1 code, as the paper says.

Naming: the identity-mapping paper this document calls "K8N-4" will be K8N-5. K8N-4 is
`docs/K8N-4-expose-by-namespace.md`.

## As built — stage 1, 2026-11-23

Branch `k8n/kubectl-stage1`, from `story/kubernetes-next`. Stage 1 is built as scoped above. Where the
paper and the code disagreed, or the paper was silent, the smallest correct choice was taken; each one
is listed here.

**Built before the walk.** The ruling says the one-day walk on real clusters comes before any stage 1
code. This code was written first, on instruction. Nothing in it has run against a cluster. Every item
under "Not confirmed" is still not confirmed, and the choice of A1 over A2 is still an assumption.
Substitute, not satisfied: unit tests and database-backed tests with seeded gateway reports. Trigger for
the real proof: the next live Kubernetes walk on `story/kubernetes-next`, with the matrix under "Live
walk".

What is built, and where it differs:

1. **Shape.** Table `k8s_api_endpoints` (one row per cluster: enabled, address) and column
   `policy_rules.dst_k8s_api_endpoint_id`, migration `0239`. The rule points at the endpoint row; the API
   takes and returns the cluster (`dst_k8s_api_cluster_id`), because that is what a person names.
   The endpoint is never a `k8s_services` row. That is what keeps it out of scopes, agent access
   requests and agent templates: all three key on `k8s_services` and have their own destination checks,
   which do not know the kind.
2. **Off keeps the rules, and on brings them back.** Turning API access off gives the address back and
   keeps the endpoint row, so its rules stay and compile to nothing, as the paper says. It follows that
   turning it on again makes those rules effective again. The response carries `rule_count`, and the
   enable and disable dialogs say how many rules are affected. Deregistering the cluster removes the
   endpoint and its rules by cascade; the deregistration audit entry counts them.
3. **An existing `default/kubernetes` exposure blocks enabling.** Existing exposures are left in place
   and not converted. With one in place, API access cannot be turned on for that cluster (409
   `k8s_api_ordinary_exposure_exists`): two addresses would answer to one name. The administrator
   unexposes it first. Whether it should instead be converted is the founder's decision 8, ruled "not
   converted".
4. **Not available with a connector pool.** A pool's handoff plan is built from `k8s_services` alone, so
   the API's address would not follow a handoff. API access is refused for a cluster served by a pool
   (409 `k8s_api_connector_pool_unsupported`), and a pool cannot be configured while API access is on
   (409 `k8s_api_access_enabled`). The paper only says a second gateway is a preview.
5. **A human turns it on.** `k8s_api:manage` is held by owner and admin. The machine operator role does
   not hold it, and a machine credential is refused even with the permission. This is "no GitOps
   resource for API access" made unreachable rather than merely unbuilt.
6. **People and groups only, in three places.** The API refuses any other source (400
   `k8s_api_source_not_allowed`), the database refuses it (check `policy_rules_k8s_api_people_only`),
   and the compiler emits nothing for it. One step further than the paper: a rule that grants a person
   does not reach an AI agent that person owns. Other destination kinds do reach it; this one does not.
7. **The gateway's reason is general.** `classify` reports `endpoints_on_gateway_node` for any Service
   whose ready endpoints are all the gateway's own addresses, not only for the API. One existing
   assertion in `dnat_linux_test.go` changed from `no_ready_endpoints` to the new reason; it was
   asserting exactly the wording this item replaces. The reason is only logged and reported; nothing
   keys on it.
8. **The gateway reports one new field.** Per-address refusals were never sent to the control plane,
   only logged. "Test access" could not have shown the gateway's reason. The gateway now reports
   `k8s_api_endpoint` (`ready`, a refusal reason, or nothing) with its usual status. The control plane
   keeps only known values. A gateway older than this reports nothing, and "Test access" then says so
   (`k8s_api_endpoint_not_observed`, inconclusive) instead of guessing.
9. **"Test access" codes.** As specified: `k8s_api_not_enabled`, `k8s_api_endpoint_unavailable` with the
   reason, the cluster named in `no_matching_grant`, and the fixed sentence, returned in a new `note`
   field. Added because three states cannot be said with two codes: `k8s_api_destination` (the
   destination was recognised), `k8s_api_endpoint_ready`, `k8s_api_endpoint_not_observed`. The cluster's
   API is recognised by its tunnel name or by its address. Only the device diagnostic has it; agents
   cannot be granted the API.
10. **Refusal of `default/kubernetes`.** `ExposeService`, the inventory exposure path, the shared insert
    path, the namespace rule's planner and the operator all refuse it (400
    `k8s_api_server_not_a_service`; operator `Ready=False` with that reason). It is left out of the
    inventory listing and of a new scope's candidates. The gateway still reports it; the filter is in
    the control plane, so an older gateway is covered. Existing rows are untouched: an exposure a
    namespace rule already owns is still read as reported and is never withdrawn for this reason; an
    existing scope membership is read as it was.
11. **Audit names the destination.** `k8s.api_access_enabled` and `k8s.api_access_disabled` name the
    person and the cluster. For a rule whose destination is a cluster's API, the created, deleted,
    enabled, disabled and expired entries carry the cluster. Other rules' entries are unchanged.
12. **Address allocation.** Every allocation in a cluster now takes the cluster row lock, including
    `ExposeService`, which did not before, and works around the API's address. Two database triggers
    are the backstop: the API's address must be in the range and not the DNS or a Service address, and a
    Service is never given the API's address.
13. **Older schemas.** This repository runs today's code against earlier schema versions in its tests.
    The policy snapshot, the gateway topology, address allocation and the client resolver push
    therefore ask whether the `0239` table exists before reading it (`internal/k8sapiaccess`). The
    existing queries they already ran are unchanged.
14. **No edition gate.** Which edition carries the feature is still open. Nothing was added: the switch
    is available wherever cluster registration is, and a rule is subject to what the policy API
    already requires.
15. **A device on another gateway.** The rule is placed where a Service rule is placed: on the device's
    gateway and on the cluster's gateway. A device whose home gateway has no route to the cluster's
    range is told so by the existing route check. Nothing new was built for that path.

Not built, as the paper says: any cluster identity; issuing, storing or proxying a credential; records
of verbs; MFA at the moment of use; kubeconfig generation; a CLI helper; a GitOps resource for API
access; support for a gateway on a control-plane node (it is refused and now said plainly).

Also still open from "Not confirmed": item 9, whether access events label Service flows with their
Service. Nothing was changed there, so API flows are recorded as any allowed or denied flow is, with
device, person, rule, time and port.

## Return path for the API server — decision, 2026-11-23

Found on the first live walk (GKE Standard, in-cluster gateway on the host network, node 10.70.0.6).
Stage 1 as built does not work on a managed cluster: the API server's reply never comes back.

**Observed.**

- API access is on. The tunnel address 100.65.0.4:443 is mapped to `default/kubernetes`, whose
  EndpointSlice holds the managed control plane's address, 10.70.0.3:443. That address is not a node.
- The gateway rendered `ip daddr 100.65.0.4 tcp dport 443 dnat to 10.70.0.3:443` and the access rule
  `ip saddr 10.99.0.2 ct original ip daddr 100.65.0.4 ... accept`. The access rule's counter rose while
  a connected device (tunnel address 10.99.0.2) called `https://100.65.0.4/version`: the device's
  packets arrive, are accepted and are forwarded.
- From inside the gateway container, `https://10.70.0.3/version` answered 401: the node reaches the API
  server.
- The device's call times out. The only source-NAT rule in `ip tunnex postrouting` was
  `ip saddr 100.65.0.2 oifname != "wg0" masquerade`, and 100.65.0.2 is the gateway's own tunnel
  address. The device is connected to another gateway and arrives through the hub (K8L-7), so its
  address is outside that range and the forwarded flow leaves the node with source 10.99.0.2.
- A Service's pods answer such a device, because every node carries a return route to the tunnel
  range (host posture). The managed API server is not a node and has no such route. Its reply is lost.

This corrects two sentences above. "Device traffic leaving the gateway node on a non-tunnel interface
is masqueraded to the node's address" is true only for a source inside the gateway's own tunnel range.
"The packet leaves masqueraded as the node" was therefore wrong for a device on another gateway. It
was item 2 of "Not confirmed", and it is the assumption that failed. Item 1 is settled for GKE Standard
only: one ready endpoint, the control plane's address, port 443.

**Decision.** The gateway source-NATs exactly the flows it forwards to the API server, one rule per
mapped address, in `ip tunnex postrouting`:

    ct original ip daddr <API address> oifname != <tunnel interfaces> masquerade comment "tunnex_k8s_api_return"

- *Why the original destination.* After the rewrite the packet is addressed to the API server, which
  the node and every pod also talk to natively; matching that would translate traffic that is not
  Tunnex's. The source cannot be used: this gateway does not know the ranges of devices that belong to
  other gateways. The address the client dialled is a Tunnex address, the forward chain already
  decides on it (`ct original ip daddr`), and no native traffic has it as its original destination.
  The match is therefore the forwarded API flows and nothing else. A Service has a different address,
  so Service flows keep the device's source, as today.
- *Why this is not new behaviour to the customer.* This paper already states that the cluster sees
  every Tunnex user as the gateway node (design A, "Costs"; "Risks", "One client address"). The rule
  makes that statement true for every device instead of only for devices in the gateway's own range.
- *Why the invariant holds.* "Tunnex never source-NATs traffic bound for the tunnel" is what the
  ownership check protects (K8L-2, K8N-1): a translated tunnel-bound packet breaks the return half of
  every forwarded flow. The new rule carries the same `oifname != <tunnel interfaces>` exclusion as the
  device-pool rule, and the check refuses the rule without it. A packet leaving by `wg0`, or by the
  OpenVPN interface when one is co-terminated, never matches. Replies are not evaluated by NAT rules at
  all; conntrack reverses the binding made by the first packet.
- *When it is rendered.* From the same resolved mapping as the rewrite itself, in the same atomic
  replacement of the table: only for a mapping whose Service is `default/kubernetes`, only when that
  mapping has a ready endpoint that is not the gateway's own address (so only next to its `dnat`
  rule), only for a valid IPv4 address.

**How the startup check recognises the rule.** `validateTunnexPostrouting`
(`apps/node/internal/k8snetprep/aws_linux.go`) reads the live `nft -j -a list ruleset` on every pass
and required every rule in `ip tunnex postrouting` to be the device-pool rule. The first attempt
(`fc2c4786`, reverted by `ad59275f`) rendered the new rule and did not teach the check. The gateway
then refused its own ruleset on every pass. In the running loop that is a warning and "not ready"; in
the startup ownership pass (`ownership_startup_withdraw`, OpenVPN stage, which re-applies the table) it
is fatal, so the pod crash-looped with `Tunnex source-NAT CIDR differs from current tunnel`. Unit tests
of the renderer alone could not see it.

The check now accepts exactly two shapes and still refuses everything else:

1. The device-pool rule, unchanged: no comment; `ip saddr` equal to the current tunnel range;
   `oifname !=` the WireGuard interface or a set that contains it; `masquerade`.
2. The API return rule: the comment is exactly `tunnex_k8s_api_return`; exactly three statements; the
   first is `ct original ip daddr ==` one IPv4 address in canonical form; the second is the same tunnel
   exclusion as in shape 1; the third is a bare `masquerade`. The same address twice is refused.

Refused, among others: the marker on any other shape; this shape without the marker or with another
comment; `ip saddr`, `ip daddr`, `ct original ip saddr` or `ct reply ip daddr` in place of the original
destination; `!=`; a prefix, a set or a range instead of one address; an IPv6 address (nft itself
refuses `ct original ip6 daddr` in an `ip` table); a missing or different interface exclusion; `snat`,
or `masquerade` with flags or ports; any further statement; any other rule in the chain.

*What the check cannot know.* It is given the WireGuard interface, the tunnel range and the kernel's
listing. Which address is mapped to `default/kubernetes` exists only in the policy the control plane
sent, held in memory by the egress manager; after a restart the check runs before that is known again.
So the check binds the shape and the marker, not the address. The address is bound by the renderer:
the whole `ip tunnex` table is replaced from the current mapping on every pass (every 30 seconds by
default, and at once on a policy or endpoint change), so a rule for any other address does not outlive
one pass.

*Residual risk.* Whoever is root on the node can write a rule with this marker for another address,
and the check accepts it until the next pass replaces the table. Such a rule translates flows whose
original destination is that one address and that leave by a non-tunnel interface. It cannot touch
tunnel-bound traffic, which is what the check exists for, and root on the node can already do more.
The check also does not prove that the matching `dnat` rule exists; the two are rendered together and
replaced together.

**A leftover rule.**

- *API access turned off, the mapping removed, or no ready endpoint.* The next pass renders the table
  without the rule. The atomic replacement removes it together with the rewrite. Nothing is deleted
  rule by rule.
- *Gateway stopped normally.* Shutdown already flushes both `tunnex` tables and writes back only the
  ownership marker. The rule goes with every other rule.
- *Emergency withdrawal* (`EmergencyWithdrawK8s`) flushes the rewrite chain only. The return rule stays
  until the next full pass. Without its rewrite nothing is forwarded to the API server, so the rule
  grants nothing; the check still accepts it.
- *Gateway killed.* The rule is left in the kernel until the next gateway process replaces the table.
- *Downgrade to a build that does not know the rule.* An older check refuses the rule wherever it
  reads it. In the code before this change every fatal check sits inside `Manager.Reconcile`, after
  that build has replaced the table with its own rendering, which has no such rule. The single read of
  a leftover table before the first replacement (`ResolveK8sVIPs`) only logs
  `k8s_netprep_reconcile_failed`. So an older build removes a leftover rule on its first pass and does
  not crash-loop on it. This was run, once, by hand: the code at `ad59275f`, in a container, over a
  kernel that held the table of the new build with API access still on. Its check refused the table
  (`unknown Tunnex source-NAT rule`, not ready), its first pass replaced the table, the OpenVPN stage of
  the startup pass succeeded, and it was ready with only the device-pool rule left. The crash loop of
  the first attempt was a build refusing the rule it rendered itself, which is a different thing.
- *Before a downgrade:* turn API access off for the cluster. Not because of the leftover rule, but
  because an older gateway still receives the mapping (no artifact version change) and forwards to the
  API server with no return path: `kubectl` times out for every device outside the gateway's own range
  while "Test access" says allowed. The build of the first attempt must not be deployed at all.

**Not changed, and adjacent.** The check still refuses every other rule in that chain. That includes
two rules this agent can render on a gateway that is not in a cluster: the site-LAN masquerade
(`tunnex_site_lan_masquerade`, SSI-8) and the IPsec desktop exemption (`tunnex_ipsec_desktop_no_snat`).
A site that turns on the site-LAN option and also has an in-cluster gateway with remote routes would
meet the same refusal as the first attempt did. That is a separate defect and is not fixed here. In the
other direction, the IPsec desktop recipe (`ipsec/runtime_desktop_nat_pending.go`) accepts only its own
exemptions followed by the device-pool rule, so it refuses a chain that also holds an API return rule.

Seen while verifying, not caused by this change and not touched: after a normal stop the flushed
`ip tunnex` table keeps its chains, and one of them is `forward`, hooked, with policy drop and no rule.
In a container (nft 1.1.6) a router that forwarded between two plain interfaces before and with the
gateway's table dropped that traffic after the marker-only table was loaded. If a node behaves the
same, pod traffic through a node is dropped from the moment its gateway stops until a gateway loads
the table again or the table is removed. Not looked into further.

**As built, and what was run.** Substitute, not satisfied: no cluster.

- Renderer: `k8sAPIReturnRules` in `egress/egress_linux.go`, from the resolved mappings flagged as the
  API's (`dnat_linux.go`). Check: `validateTunnexPostrouting` in `k8snetprep/aws_linux.go`. The marker
  is one constant, `k8snetprep.APIReturnRuleComment`, used by both.
- The check's fixtures (`k8snetprep/testdata/k8n3-api-return*.nft-ruleset.json`) are a kernel's own
  listing of the renderer's own output, saved next to that output (`*.rendered.nft`). A test in the
  egress package fails if the NAT chain is ever rendered differently from what the check was proved on.
- `TestK8sAPIReturnPathKernel` (egress package, opt-in, privileged container, own network namespaces)
  runs the real manager, real `nft`, the real check on that kernel's JSON, and real packets. Without the
  rule the request reaches a control plane that has no route to the device and the call times out; with
  it the answer returns and the control plane sees the node's address; a Service next to it still sees
  the device's address. A second gateway process over the first one's table passes the check before
  loading anything and passes the startup order that crash-looped the first attempt. Four foreign rules
  written into the live chain are each refused with the expected reason. With an OpenVPN interface the
  set form is accepted. With API access off the rule is gone and the address no longer answers.
- What that is not: wg0 is a veth, the control plane is a TCP listener, the node has no CNI rules, there
  is no TLS, no `kubectl` and no control plane of ours. The startup order is the manager's calls in the
  order `cmd/agent` makes them, not the agent binary.

**Still not confirmed.** Nothing here has run on GKE or any other cluster. To walk: the device's call
returns the API server's answer; `kubectl get`, `exec`, `logs -f`; the same after a gateway restart
and after a kill; the rule is gone after API access is turned off; the cluster's audit log shows the
node's address. Items 3 to 11 of "Not confirmed" stand.

## First live result on GKE — 2026-11-24

Demo control plane on `story/kubernetes-next`; GKE Standard cluster `gke` (zone
australia-southeast1-b); gateway and host posture on a build with the return-path rule above (image
tag `k8n3`). API access on for the cluster; one rule, a person → the cluster's Kubernetes API.
A connected laptop on another gateway (device address 10.99.0.2).

Confirmed:

- The return path works on a managed control plane. Through
  `https://kubernetes.default.svc.gke.k8s.corp.internal` (address 100.65.0.4, mapped to the
  `default/kubernetes` endpoint 10.70.0.3:443): `/version` answered `401 Unauthorized` from the API
  server in about 1 s, and `/healthz` answered 200 five times out of five. Before the rule the same
  call timed out (2026-11-23).
- The gateway restarted onto this build cleanly (no crash loop; ready within seconds), and existing
  Services kept working (`orders` on GKE and `web` on the on-prem cluster answered 200).
- Only TCP 443 is granted: port 80 on the same address does not answer.

The API server certificate on this cluster names (SAN): `kubernetes`, `kubernetes.default`,
`kubernetes.default.svc`, `kubernetes.default.svc.cluster.local`, and the addresses
35.201.21.105 (the public endpoint; subject CN), 34.118.224.1 (the `kubernetes` ClusterIP),
10.70.0.3 (the endpoint) and 34.151.107.213. The Tunnex name is not among them, as expected, so
`tls-server-name` is required. Two values are candidates: the host of the original `server:` line
(an IP on GKE) and `kubernetes.default.svc`, which kube-apiserver certificates carry by convention.
Which one to print in the dashboard waits until both are walked with kubectl and EKS/AKS
certificates are checked.

### kubectl walk, same day

The founder's own GKE credential (gcloud on the laptop, `gke-gcloud-auth-plugin`), in a separate
kubeconfig whose only change was `server: https://kubernetes.default.svc.gke.k8s.corp.internal` plus
`tls-server-name`:

- `kubectl get namespaces` worked with `tls-server-name` set to the original host (the IP
  35.201.21.105) and with `kubernetes.default.svc`. Both values verify against this certificate, so
  "tls-server-name may be an IP" is confirmed for kubectl on GKE.
- `get pods`, `logs`, `logs -f`, `exec` and `port-forward` (HTTP 200 through the forward) all worked.
- Service flows keep the device's source: the Service's access log shows 10.99.0.2.
- **Negative control.** With the access rule disabled at 00:34:27 UTC, a new `kubectl get` failed
  with "context deadline exceeded" and a raw `/healthz` timed out. The same kubeconfig therefore goes
  through Tunnex and does not fall back to the public endpoint. Re-enabling the rule restored kubectl
  within 13 s.
- **A running exec when the rule is disabled.** A streaming `exec` printing every 2 s stopped
  receiving output at once (last line 00:34:23); the client did not exit by itself and reported
  `i/o timeout` about 60 s later. Access ends immediately; the client notices late. The dashboard's
  "Traffic matching this rule stops immediately" is accurate for the data; a customer may see a
  hanging terminal for up to a minute.

Still not confirmed: a gateway restart while a rule and an open connection exist; API access turned
off (address withdrawn) with a session open; the node's address appearing in the cluster's audit
log; EKS, AKS and self-managed clusters; the dashboard's single suggested `tls-server-name` value
across providers.
