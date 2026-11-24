# K8N-7 — devices reach the gateway node's own services (no input hook)

Story branch: `k8n/input-chain` (from `story/kubernetes-next`). Written 2026-11-24.
This paper comes first. Facts about Tunnex come from the code at this branch, from `origin/main`
(60aae74f) and from the `v0.1.44` tag (9ca22bc8) where stated. Nothing here was run on a cluster.
Packet results come from privileged containers with their own network namespaces and real `nft`.
Anything else is marked **unconfirmed**.

## The finding

Confirmed live on the demo on 2026-11-24. A laptop connected through the GKE in-cluster gateway, with
no access rule for the gateway's node, reached the node's kubelet:

- `https://100.65.0.2:10250/healthz` (the gateway's tunnel address) answered 401;
- `https://10.70.0.6:10250/healthz` (the node's own address) answered 401.

A 401 is the kubelet refusing an anonymous request. The TCP and TLS handshakes completed, so the port
is open to every connected device.

### Why

The gateway runs on the node's host network (`hostNetwork: true`). A packet from a device arrives on
`wg0`. If its destination is an address of the node, the kernel delivers it locally. It goes through
the netfilter **input** hook, not the **forward** hook.

Tunnex enforces access only in `chain forward` of `ip tunnex` and `ip6 tunnex` (`rulesetWith`,
`apps/node/internal/egress/egress_linux.go`). That chain is `policy drop`. The table has no chain on
the input hook. So every packet a device addresses to the node itself skips the access rules. That
includes the gateway's own tunnel address, the node's primary address and any other local address.
It meets only whatever host firewall the node has. A GKE node accepts kubelet traffic on its own
addresses.

What a device can reach this way is every TCP or UDP service that listens on a node address or on the
wildcard address:

- the kubelet (10250);
- the kube-proxy and kubelet health and metrics ports;
- the CNI agent's ports;
- node-exporter and other DaemonSet `hostNetwork` listeners;
- NodePorts that kube-proxy delivers to a `hostNetwork` endpoint on this node;
- the gateway's own health endpoint (`:9091`, `/healthz`, `/readyz`).

### Is `main` affected? Yes

`origin/main` (60aae74f) and `v0.1.44` (9ca22bc8) render the same two chains with a hook,
`postrouting` and `forward` (plus `prerouting` while a VIP is mapped). `git grep "hook input"` finds
nothing in `apps/node/internal/egress` on either. Both run the agent on the host network in
Kubernetes mode, as K8N-5 item 1 records. The live probe above was against the released gateway.

**How a customer can check.**

1. On the gateway's node, `nft list table ip tunnex` (and `ip6 tunnex`) shows no chain with
   `hook input`.
2. From a connected device with no rule for the node, `curl -k https://<gateway tunnel
   address>:10250/healthz` and the same against the node's own address answer (401 from the
   kubelet) instead of timing out.

After this change, step 1 shows `chain input { type filter hook input priority filter; policy
accept; ... }`, and step 2 times out.

## Scope: Kubernetes mode only (founder ruling)

The change applies only to a gateway in Kubernetes mode (`SetKubernetesMode(true)`, set by
`TUNNEX_K8S_MODE=true`, which only the gateway chart sets).

**Out of scope, unchanged: VM and site gateways.** Their tables keep no input chain. Administrators
may reach a VM or site gateway's host over the VPN, as they can today. That includes SSH on its
tunnel address and any other service on the host. That is the founder's ruling, recorded here so
nobody reads the Kubernetes rule as a gap on VMs. `Teardown`'s VM path, `delete table ip tunnex;
delete table ip6 tunnex`, is also unchanged.

## Inventory: what devices legitimately need on the node

Every listener in `apps/node` was found with
`grep -rn 'net.Listen\|ListenPacket\|ListenUDP\|ListenTCP\|ListenAndServe\|http.Server{\|ListenConfig'`.
Each one was read for its address, interface and port. Child processes the agent starts (OpenVPN,
the IPsec and BGP daemons) are listed too.

| # | listener | address / interface | proto, port | serves devices over the tunnel? | Kubernetes mode |
|---|---|---|---|---|---|
| 1 | DNS forwarder, tunnel side (`dnsforward`, `ReconcileK8sBinds` → `reconcileBinds` / `reconcileTCPBinds`) | every address on `wg0`: the gateway's tunnel address (v4 and v6) **and** each cluster DNS VIP, which `ReconcileDNSVIPs*` assigns to `wg0` as a `/32`; `SO_BINDTODEVICE wg0` | UDP 53, TCP 53 | **yes**. Devices resolve exposed-Service names on the cluster's DNS VIP. The compiler grants DNS on the device's gateway and on the cluster's gateway. A device on another gateway arrives over the site link, also on `wg0`. | **needed** |
| 2 | AI VPN inference listener (`aivpn.Runtime`, `HTTPPort`) | the gateway's private IPv4 tunnel address, `SO_BINDTODEVICE wg0`, `tcp4` | TCP 8083 | **yes**, when enabled. The control plane points devices at `http://<gateway address>:8083/...` (`apps/api/internal/aigateway/vpn_auto.go`). | **needed when `aiVPN.enabled`** (chart → `TUNNEX_AI_VPN_AUTO`). Otherwise no socket exists. |
| 3 | DNS forwarder, LAN listeners (`reconcileLANBinds`) | an administrator-named non-tunnel interface; refused on `wg0` | UDP/TCP 53 | no. They serve the LAN, not the tunnel. | not tunnel side; untouched |
| 4 | agent health (`serveHealth`, `TUNNEX_AGENT_HEALTH_ADDR`, default `:9091`) | wildcard | TCP 9091 | no. The kubelet probes it on the node address, from the node. | **not needed from the tunnel**. It is reachable today, and will be dropped. |
| 5 | WireGuard (`wg0` listen port, chart `hostPort` 51820) | the uplink (node address), UDP | UDP 51820 | the encrypted packets arrive on the uplink, never on `wg0` | not tunnel side; untouched |
| 6 | ICE relay (`relay.Runtime`) | outbound sockets bridged to the local WireGuard port | — | no listener on the tunnel | untouched |
| 7 | app access / browser access (`appaccess`) | outbound connections to the app proxy (`oneListener` over a dialled connection) | — | no listener | untouched |
| 8 | Server Access (`serveraccess`) | outbound to the control plane | — | no listener | untouched |
| 9 | sandbox network RPC (`sandboxnetwork`) | a Unix socket | — | no | untouched |
| 10 | OpenVPN server (child process, opt-in per gateway) | its own port on the uplink; clients arrive on `tun0` | UDP/TCP (OpenVPN) | the control channel arrives on the uplink. Inside the tunnel it pushes the cluster DNS VIP as a resolver. That VIP lives on `wg0`, and the forwarder's sockets are bound to `wg0`, so a query that arrives on `tun0` is not delivered to them today (see "OpenVPN" below). | the OpenVPN listener is untouched; `tun0` joins the tunnel set |
| 11 | IPsec / BGP daemons (`ipsec`, `bgp`) | — | — | — | IPsec is refused on an in-cluster gateway (K8N-5 item 4, `validateHookCoverage`) |
| 12 | DHCP | none | — | — | none |

ICMP:

- **PMTU and errors for the node's own flows.** An ICMP error (fragmentation needed, packet too big,
  unreachable) that a device sends about a connection the node opened is conntrack `related` in the
  reply direction. The reply rule below accepts it. ICMP errors about forwarded flows go through
  `forward`, as today.
- **Echo to the gateway.** Nothing in the agent, the API or the desktop client pings the gateway's
  tunnel address (grep for `icmp` and `ping` in `apps/` and in the desktop client). It is **not**
  allowed. A person who pings the gateway's tunnel address to troubleshoot sees a timeout. A decision
  for the founder, below.
- **IPv6 neighbour discovery.** `wg0` is a layer-3 interface with no neighbour discovery and no
  link-local address, so there is nothing to allow.

Not inventory, already on `forward`:

- **Exposed Services.** The gateway DNATs `VIP:port` to an endpoint in prerouting. `classify` drops
  any endpoint that is one of the gateway's own addresses (K8N-3, "A gateway on a control-plane node
  cannot use this path"). So a mapped flow always leaves through `forward`, never `input`.
- **The API return path** (K8N-3) and the **site-LAN masquerade** (K8N-5 item 4) are NAT on
  forwarded flows. A masqueraded device flow's reply comes back to the node's address on a
  non-tunnel interface, and conntrack reverses the NAT in prerouting. It then goes through `forward`.
  Neither touches `input`.

## The rule

In Kubernetes mode, a packet that arrives on a tunnel interface (`iifname` in the tunnel set: `wg0`,
plus the OpenVPN `tun` when active) and is delivered to the node itself is dropped, except:

1. **Replies to connections the node opened:** `ct direction reply` and `ct state
   established,related`. A reply to a device's own connection is in the *original* direction and is
   not covered. That is deliberate: a device's connection to a node port that was open before the
   upgrade does not survive the first pass.
2. **Exactly the listeners above:** DNS (UDP and TCP 53) and, when the AI VPN runtime is configured,
   TCP 8083 in IPv4. Each is limited to:
   - packets that arrive on the WireGuard interface itself (`iifname "wg0"`), because both sockets
     are bound to it with `SO_BINDTODEVICE`;
   - a destination address that is configured **on that interface** (`fib daddr . iif type local`).
     That covers the tunnel address and every DNS VIP as they come and go, with no re-render. It
     does not cover the node's other addresses: a device that sends to the node's primary address
     on port 53 is dropped. A host DNS cache that listens on the wildcard address, or on a dummy
     interface (NodeLocal DNSCache), is not reachable from the tunnel.

Node traffic on any other interface meets no Tunnex rule here: the chain is `policy accept`, and
every rule is limited to the tunnel set. The accept verdicts end only this chain. A drop by the
node's own firewall in another chain on the same hook still applies.

The DNS forwarder still decides, per source, whom it answers (`allow`). The input rule opens the port
to the tunnel. It does not replace that check.

### As rendered (running), IPv4

```
  chain input {
    type filter hook input priority filter; policy accept;
    iifname "wg0" ct direction reply ct state established,related counter accept comment "tunnex_input_reply"
    iifname "wg0" fib daddr . iif type local udp dport 53 counter accept comment "tunnex_input_dns"
    iifname "wg0" fib daddr . iif type local tcp dport 53 counter accept comment "tunnex_input_dns"
    iifname "wg0" fib daddr . iif type local tcp dport 8083 counter accept comment "tunnex_input_ai_vpn"
    iifname "wg0" counter drop comment "tunnex_input_tunnel_drop"
  }
```

The `8083` line is present only when the AI VPN runtime is configured on this gateway. With OpenVPN
active, the first and last lines match `iifname { "wg0", "tun0" }`. The listener lines keep
`iifname "wg0"`.

### IPv6

The same chain in `ip6 tunnex`, without the `8083` line: the AI VPN listener is IPv4 only (`tcp4`).
DNS binds every address on `wg0`, the IPv6 tunnel address included. IPv6 `fib daddr . iif type
local` is true only for an address configured on `wg0`.

### Every running state is the same

The input chain does not depend on the policy. Cold start (no policy yet), an unsupported artifact
version, a nil policy, an enforcing policy and an explicit `Mesh: true` artifact all render it
byte for byte the same:

- **Cold start and emergency (deny).** The forward chain is deny-all (K8N-5 item 3). The input chain
  is the rule above: the tunnel reaches only DNS, and the AI VPN when configured. Before the first
  policy the forwarder's table is empty, so it answers nothing.
- **No rule opens the node.** An access rule whose destination covers the gateway node's own address
  (a range rule over the node network) still does not reach it. Other nodes in that range stay
  reachable through `forward`, as granted. This follows from the ruling: on an in-cluster gateway the
  node is not a destination.
- **Mesh.** With Zero Trust off (`Mesh: true`) devices reach every address the node routes to
  through `forward`, other nodes' kubelets included. The gateway's own node stays closed. A decision
  for the founder, below.

## Stop, kill, emergency, restart

**Stop** (`Teardown` → `reduceToHostPostureMarkers` → `hostPostureStoppedRuleset`). The stopped state
keeps the tunnel side of the input hook closed. While `wg0` is drained, and if the drain fails
(`agent_backend_shutdown_blocked`), a device that still has a session must not reach the node. Per
family, in the same transaction, next to the forward guard of K8N-5:

```
add chain ip tunnex input
delete chain ip tunnex input
add chain ip tunnex input { type filter hook input priority filter; policy accept; }
add rule ip tunnex input iifname "wg0" counter drop comment "tunnex_stopped_tunnel_drop"
```

- **No listener accepts in the stopped state.** The agent's DNS and AI VPN sockets close with the
  process. Another program on the node may bind the same port.
- **No reply accept.** The forward guard of K8N-5 drops both directions on the tunnel. The input guard
  drops everything that arrives on it.
- **`add chain` + `delete chain`** removes a leftover input chain whatever it held, as K8N-5 does for
  `forward`. That includes a hand-made one and none at all (a table from v0.1.44).
- **The chain name and hook stay the same.** The next start's `flush table` + re-declaration replaces
  the guard in place.
- Ordinary node traffic meets no Tunnex rule after a stop: only `iifname <tunnel>` drops.

**Kill** (SIGKILL, OOM). The full running table stays, input chain included. The node stays closed to
the tunnel, and DNS and replies keep working.

**Emergency withdraw** (`EmergencyWithdrawK8s`). It flushes only `prerouting`. The input chain is
untouched. The next pass renders it unchanged (K8N-5 item 3: cold-start deny on `forward`).

**Restart over a leftover table.** The running ruleset is `add table` + `flush table` + the full
table, in one transaction. `flush table` keeps chains. Re-declaring `input` with the same type, hook
and priority replaces its rules and sets its policy. That holds over any leftover:
- the stopped guard;
- a previous running chain;
- no chain at all, as left by v0.1.44 or by the manager's marker-only table.

The priority is always `filter` (0). A leftover input chain at another priority cannot be re-declared
in place. Only a hand-made one could have another priority, and the apply then fails as a whole
(the previous table stays in force) and the gateway is not ready. That is the fail-closed side.

**Downgrade to v0.1.44.** Its ruleset does `add table` + `flush table` and does not declare `input`.
The chain stays, empty, with `policy accept`: harmless, and open again as released. The manager's
last-owner cleanup deletes the whole table.

## What reads the table, and what changes

| check | what it reads | change |
|---|---|---|
| `k8snetprep` `validateHookCoverage` (every Kubernetes-mode pass, fatal at startup) | `nft -j list ruleset`; it refuses an unknown IPv4/inet **postrouting** hook and proves `ip tunnex postrouting` (`validateTunnexPostrouting`) | **new `validateTunnexInput`**, called from it. In `ip tunnex` and `ip6 tunnex`, every chain on the input hook must be the one chain `input`: `filter`, priority 0, `policy accept`, holding exactly the running rule list (reply, DNS, DNS, optional AI VPN in IPv4 only, drop) or exactly the stopped drop. Anything else under the tunnex tables' input hook is refused, as is any tunnex chain on a hook the renderer never declares (`output`, for example) and a hook-less chain named `input`, with near-miss tests. **Absence, or an empty chain, is accepted.** A table from the manager's `Prepare` (marker only), a v0.1.44 leftover and the K8N-3, K8N-5 and K8N-6 kernel fixtures have no input chain. A v0.1.44 process that runs over this table (a downgrade) leaves the chain empty with `policy accept`, which can neither drop nor accept. Presence is proved by the egress readback below. |
| egress `ReadAppliedOVPNTunnel` (the ownership surface's kernel readback of the tunnel set) | `nft list table ip/ip6 tunnex`, the native-forward passthrough line | in Kubernetes mode it also requires the input chain's `tunnex_input_tunnel_drop` line, naming exactly the same tunnel set, in both families. So a table without the input drop, or one that leaves `tun0` open, fails the ownership readback. |
| `hostposture.ValidateNFTMarkerChain` and the manager's `Prepare`, `Enforce`, `RestoreAndCleanup`, gateway `Teardown` | `nft -a list chain <family> tunnex tunnex_posture_owner` only | none. They read only the marker chain, which is unchanged. Tests run them over a table that holds the input chain, running and stopped. |
| `hostposture` `CaptureBaseline` ("ambiguous pre-Tunnex nft table") | the table's presence | none |
| egress `parseK8sDNATReceipts` | DNAT lines with the VIP receipt comment | none; the input lines carry no receipt comment |
| `ipsec` `runtimeEnvironment` baseline check | hooks of `ip/ip6 tunnex`: only forward (drop, 0) and postrouting (nat, 99) | none. IPsec is already refused on an in-cluster gateway (K8N-5 item 4). The prerouting chain of a mapped VIP is refused here too. On VM gateways the table has no input chain, so nothing changes there. |

## Tests

- **Renderer:**
  - the Kubernetes running ruleset has the input chain in both families, with exactly the inventory
    and in that order;
  - the AI VPN line is present only when configured, and in IPv4 only;
  - with OpenVPN the reply and drop lines are a set, and the listener lines stay on `wg0`;
  - the chain is identical in cold start, refused version, nil, enforcing and mesh;
  - VM mode has no input chain (VM nil, enforcing and mesh text unchanged);
  - `nft -c` syntax where `nft` exists.
- **Stop ruleset:** the exact new text; the guard drops only on the tunnel set; the only input rule is
  the stopped drop.
- **Validator:**
  - accepts the running chain (with and without AI VPN, single interface and set) and the stopped
    chain;
  - accepts a table with no input chain;
  - near-miss refusals, each over the K8N-5 fixture with the chain added:
    - another priority, policy drop, a second input-hook chain, another name;
    - a missing or extra rule, rules out of order;
    - a listener on another port, or without the `fib` match or the `wg0` match;
    - a reply accept without `ct direction reply`;
    - a drop that does not cover `wg0`;
    - AI VPN in IPv6, a duplicate rule, the stopped drop beside running rules, an unknown comment.
- **Startup and ownership path over a ruleset with the chain:**
  - a restart check over the real kernel's listing (fixtures re-captured by the witnesses);
  - the manager's marker validation and the gateway's stop over a table with the chain.
- **Kernel witness** `TestGatewayInputChainKernel` (opt in, privileged container, own namespaces, real
  `nft`). A device namespace sits behind `wg0`. A stand-in kubelet listens on `0.0.0.0:10250` on the
  gateway node, and a stand-in DNS on the tunnel address and a DNS VIP, UDP and TCP 53, bound to
  `wg0`. Checked after a first start, after a stop and after a restart over the leftover table:
  - the device cannot reach 10250 on the tunnel address or on the node's primary address, in IPv4
    and IPv6;
  - the device reaches DNS on the tunnel address and on the DNS VIP;
  - a node-opened connection to the device gets its reply;
  - a host on the node network reaches 10250 (untouched);
  - after the stop the device reaches nothing on the node, and the node network still does.
  - The released table (no input chain) is replayed as the control: the device reaches 10250.
- Existing witnesses re-run, each in its own container: stop state, API return, site-LAN, Cilium
  Service reach.

## Decisions for the founder

1. **ICMP echo to the gateway** is dropped from the tunnel. Nothing in the product relies on it. A
   person pinging the gateway's tunnel address sees a timeout. Allowing `icmp type echo-request`
   (and `icmpv6`) to the tunnel address would be one more line; it is left out because the ruling is
   "exactly the listeners".
2. **Mesh (Zero Trust off)** keeps the gateway's own node closed, although every other node is
   reachable through `forward`. The other reading is that mesh opens the node too. That would make
   the node's kubelet reachable whenever an org turns Zero Trust off.
3. **A rule covering the node's address does not open the node.** On an in-cluster gateway there is
   no way to grant a device the gateway's own node. A customer who wants node access uses another
   node, or a VM gateway.
4. **The AI VPN line is rendered only when the runtime is configured.** The alternative, always
   rendering 8083, exposes any other program that listens on the wildcard address at 8083 to the
   tunnel when AI VPN is off.

## Not confirmed

- No cluster. The real kubelet, the real DNS forwarder on a real gateway, GKE's node firewall and the
  AI VPN listener were not exercised; stand-ins in namespaces were.
- `fib` support in every supported node kernel (GKE COS, EKS AL2023, AKS Ubuntu, k3s hosts). The `fib`
  expression has been in Linux since 4.10, and kube-proxy's nftables mode depends on it. Without it
  the whole atomic apply fails, and the gateway is not ready (fail closed, visible). Not checked per
  provider.
- Whether a CNI's eBPF host datapath (Cilium host routing, Calico eBPF) can deliver a packet from
  `wg0` to a local socket without the netfilter input hook. Neither attaches to `wg0` as far as read,
  but that was not checked on a live node.
- The OpenVPN DNS observation (row 10). It is read from `SO_BINDTODEVICE` semantics, not run.

## As built and verified (2026-11-24)

Rebased onto `story/kubernetes-next` at 85b89323 (the Cilium host-routing commits).

### Functions changed

- `apps/node/internal/egress/egress_linux.go`:
  - `rulesetWith`: two new slots, one per family, for the input chain. VM mode renders them empty,
    so its text is byte for byte as before.
  - new `k8sInputChain`;
  - `hostPostureStoppedRuleset`: also removes `input` and re-declares it as the stopped guard;
  - `stoppedTunnelDropComment`: now the shared `k8snetprep.StoppedTunnelDropRuleComment`, same
    text;
  - `ReadAppliedOVPNTunnel`: in Kubernetes mode it also requires the input drop over exactly the
    tunnel set;
  - new `parseInputTunnelDropInterfaces` and `inputTunnelDropReadbackRE`;
  - new `SetAIVPNListener` and the `aiVPNInput` field.
- `apps/node/internal/egress/egress_other.go`: the `SetAIVPNListener` stub.
- `apps/node/cmd/agent/main.go`: `egressMgr.SetAIVPNListener(aiVPN != nil)` after the AI VPN runtime
  is configured.
- `apps/node/internal/k8snetprep/types.go`: the rule markers and ports, shared by the renderer and
  the check.
- `apps/node/internal/k8snetprep/aws_linux.go`: `validateHookCoverage` calls `validateTunnexInput`
  first.
- `apps/node/internal/k8snetprep/tunnex_input_linux.go` (new):
  - `validateTunnexInput` and `validateTunnexInputRules`;
  - `tunnexInputReply`, `tunnexInputListener`, `tunnexInputDrop` and `tunnexInputIngress`;
  - `knownTunnexHooks`.
- Unchanged:
  - `hostposture`: every one of its checks reads only the marker chain;
  - `ipsec`;
  - `dnat_linux.go`: the emergency path flushes only `prerouting`.

### Tests

- `egress/input_chain_k8s_linux_test.go`:
  - the exact chain in both families;
  - the AI VPN line only when configured, IPv4 only, and its port equal to `aivpn.HTTPPort`;
  - the OpenVPN set;
  - the same chain in the cold start, nil, refused-version, enforcing (with a grant over the node
    network), mesh and emergency states;
  - VM mode: no input chain, and the rest of the text identical to Kubernetes mode;
  - `nft -c` of the running table, and of the stop over it;
  - the readback: absent, leaves `tun0` open, two drops, an extra statement, and a VM;
  - drift against the captured rendering.
- `egress/stop_ruleset_linux_test.go`: the exact stop text with the input guard, and the set form.
- `k8snetprep/tunnex_input_linux_test.go`:
  - an accept table: none, empty, running, AI VPN, the OpenVPN set, stopped;
  - 36 near-misses through `Reconcile`;
  - a restart over the three real-kernel captures, each read twice with no mutation, plus a
    `tun0`-open refusal over the same listing.
- `k8snetprep/testdata/k8n7-input{,-openvpn,-stopped}.nft-ruleset.json` and
  `k8n7-input.rendered.nft`: the listings from nft 1.1.6, written by the witness.
- `TestGatewayInputChainKernel` (opt in with `TUNNEX_TEST_INPUT_CHAIN_KERNEL=1`, privileged). The
  shell's proof lines, all present:
  - `RELEASED_DEVICE_REACHES_KUBELET_VIA_TUNNEL_ADDRESS`, `…_VIA_NODE_ADDRESS`: the control;
  - `FIRST_START_READY`, over the released table;
  - `RUNNING_NODE_CLOSED_TO_DEVICE`: 10250 on the tunnel address, on the node address and on their
    IPv6 twins, and the node-address DNS on TCP 53, all time out;
  - `RUNNING_DNS_OPEN_TO_DEVICE`: UDP and TCP 53 on the tunnel address, the DNS VIP and the IPv6
    tunnel address answer, with the device's own source;
  - `RUNNING_NODE_OPENED_CONNECTION_GETS_REPLY`, IPv4 and IPv6;
  - `RUNNING_NODE_NETWORK_UNTOUCHED`;
  - `RUNNING_INPUT_DROP_COUNTED` (`counter packets 6` in IPv4, `4` in IPv6);
  - `STOPPED_NODE_CLOSED_TO_DEVICE`, `STOPPED_DNS_CLOSED_TO_DEVICE`, `STOPPED_NODE_NETWORK_UNTOUCHED`;
  - after a restart over the stopped table: `RESTART_OVER_STOPPED_TABLE_ACCEPTED` (the check before
    anything is loaded), `RESTART_NODE_CLOSED_TO_DEVICE`, `RESTART_DNS_OPEN_TO_DEVICE`,
    `RESTART_NODE_OPENED_CONNECTION_GETS_REPLY`, `RESTART_NODE_NETWORK_UNTOUCHED`;
  - `RESTART_OVER_RUNNING_TABLE_ACCEPTED`;
  - `RESTART_OVER_RELEASED_TABLE_ACCEPTED`: a released process over our table (empty input chain),
    then a new start;
  - `NEAR_MISSES_STILL_REFUSED`: five rules or chains written into the live tables, each refused,
    each removed by the next pass;
  - `OPENVPN_SET_FORM_ACCEPTED`, `OPENVPN_NODE_CLOSED_TO_DEVICE`;
  - `KILL_LEAVES_NODE_CLOSED`;
  - `MANAGER_DELETE_IS_THE_CONTROL`: after the manager's table delete the kubelet answers again.

  The manager's `ValidateNFTMarkerChain` passed on the real kernel's marker after the start, the
  stop and every restart.

### Run

All runs were in `golang:1.26.11-alpine` on Docker's Linux kernel, with nftables 1.1.6.

- With `--cap-add=NET_ADMIN`, in `apps/node`:
  - `gofmt -l .`: empty;
  - `go vet ./...` and `GOOS=linux go vet ./internal/egress/`: clean. This also compiles
    `cilium_service_reach_kernel_linux_test.go` with `TestCiliumHostRoutingGrantKernel`;
  - `go build ./...`: clean;
  - `go test ./internal/egress/... ./internal/k8snetprep/... ./internal/hostposture/...
    ./internal/ownershiplease/... ./cmd/agent/... -count=1`: all `ok`.
- With `--privileged`, one container each:
  - `TestGatewayInputChainKernel` PASS (60 s);
  - `TestGatewayStopStateKernel` PASS;
  - `TestK8sAPIReturnPathKernel` PASS;
  - `TestSiteLANMasqueradeKernel` PASS;
  - `TestK8sDNATKernelPrinterRoundTrip` PASS. It needs `--privileged` for `unshare`; under
    NET_ADMIN alone it fails at `unshare`, before and after this change.
- Not run: `TestCiliumServiceReachKernel` and `TestCiliumHostRoutingGrantKernel`. They are written
  for a kind node, and kind was not used. They compile.

## Founder ruling, 2026-11-24

Accepted as recommended: ping to an in-cluster gateway is dropped; the gateway's own node stays closed
to devices even with Zero Trust off; no access rule can open the gateway's own node; the AI VPN port
(TCP 8083) is opened only while AI VPN is configured. VM and site gateways are unchanged; deciding an
input chain for them is a separate, later decision.
