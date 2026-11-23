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
