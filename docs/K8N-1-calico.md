# K8N-1 — run the in-cluster gateway on Calico

Story branch: `story/kubernetes-next`. First item of `docs/EPIC-kubernetes-next.md`. Cilium is a
separate paper (K8N-2): it needs a different proof and must not share this one's assumptions.

## What happens today

On a cluster whose network plugin is Calico, the host-posture check reports not-ready and names the
NAT chain it could not read. The gateway never becomes ready, so no Service is reachable.

The check exists to prove one thing before the gateway carries traffic: **no rule on the node can
rewrite the source address of a packet bound for the tunnel range.** If a node masqueraded such a
packet, the device would see the node's address instead of the Service's, and the reply path and the
access decision would both be wrong.

`k8snetprep/observed.go` walks every rule reachable from `ip nat POSTROUTING` in the nft JSON and
accepts a source-NAT rule only when the rule itself limits the source to a range outside the tunnel
(pod traffic, which a network plugin may masquerade). Anything it cannot read is an error.

Calico's masquerade rule is, in `iptables-save` form:

    -A cali-nat-outgoing -m set --match-set cali40masq-ipam-pools src
                         -m set ! --match-set cali40all-ipam-pools dst
                         -j MASQUERADE --random-fully

In nft JSON both `set` matches appear as an opaque `{"xt": {"type": "match", "name": "set"}}`: the
set's name, its direction and its negation are not there. The walk therefore sees "a masquerade
behind conditions I cannot read" and refuses, correctly.

## What is needed to prove it

The rule is safe when the first set, matched on **source**, contains no address inside the tunnel
range. Then only pod-sourced traffic can reach the MASQUERADE, which is the case the walk already
allows. The second match only narrows the rule further and needs no proof.

Two facts are missing from the nft JSON and must be read from elsewhere:

1. **Which set, which direction, negated or not.** `iptables-nft-save -t nat` prints exactly this.
   The gateway image already ships that binary and `realIPTablesRunner` already runs it, read-only,
   for the EKS adapter.
2. **What the set contains.** Kernel ipsets are not nft sets; `nft` cannot list them. This needs the
   `ipset` tool (`ipset save <name>`), which the image does not ship today.

## Decision

Extend the observed proof; do not add a Calico "adapter" that edits anything. Tunnex still changes
nothing in Calico's chains.

1. **Read set matches from `iptables-nft-save -t nat`.** For every rule whose nft form contains an
   opaque `set` match, find the same rule in the saved text (same chain, same position) and read each
   `--match-set <name> <src|dst>` with its negation. A rule that cannot be paired is unreadable, as
   today.

   *As built.* The saved text is read only when the walk meets a source-NAT rule behind a `set`
   match that nothing else already excuses; a node whose rules need no set proof runs no new
   command. A chain is paired as a whole: it must have the same number of rules in both readings,
   and rule N of both must have the same number of `set` matches and end in the same target
   (`MASQUERADE`, `RETURN`, a chain name, ...). Position alone would let two rules that each carry
   one set match swap places unnoticed; the target check catches that. The saved text must also be
   one complete `*nat ... COMMIT` block with no warning lines.
2. **Read membership with `ipset save <name>`**, read-only, bounded in size, for exactly the sets
   named by NAT rules reachable from POSTROUTING. Accept only `hash:net` and `hash:ip` IPv4 sets;
   any other type is unreadable.

   *As built.* "Named by NAT rules reachable from POSTROUTING" is taken at its narrowest: the sets
   of non-negated, source-only matches on source-NAT rules that tunnel-bound traffic can reach.
   Those are the only sets whose members can decide anything, so Calico's second (negated,
   destination) set is never read. At most 16 sets, 256 KiB and 4096 members each, 5 s per read.
   A set name must match `[A-Za-z0-9_.:-]`, be at most 31 bytes and not start with `-` (ipset would
   read that as an option); any other name is refused. A set that does not exist, cannot be read,
   or has another type refuses the node.
3. **Proof rule.** A source-NAT rule is accepted when it carries a non-negated `set ... src` match
   whose every member is disjoint from the tunnel range. That sets `sourceLimited`, the existing
   concept. A negated source match, a destination-only match, or a set overlapping the tunnel range
   proves nothing and the rule is refused.
4. **Two readings must agree.** The nft JSON and the saved text are read at different instants. Read
   JSON, then text and sets, then JSON again; if the two JSON readings differ, report "rules changed
   during observation" and retry on the next cycle, as the existing semantic-observation guard does.

   *As built.* This is the existing guard itself (`observeRegisteredMechanisms`): the saved text
   and the sets are read between its two JSON listings, and its message is unchanged, "CNI rules
   changed across semantic observation". The guard compares rules, not set members: a pool added
   after the set was read is seen on the next cycle, like any later rule change.
5. **Image:** add the `ipset` package to `deploy/docker/node.Dockerfile` and verify it at build time
   the way `iptables-nft-save -V` is verified.

   *As built.* The build runs `ipset help`, not `ipset version`: the version command asks the
   kernel over netlink and exits 1 in an unprivileged image build.
6. **Report:** the adapter stays `observed_cni`. Its reason names the sets that carried the proof, so
   an operator can see why the node was accepted.

   *As built.* `node NAT rules cannot rewrite traffic to the tunnel range; masquerade sources are
   limited by sets outside it: cali40masq-ipam-pools` (at most three names, then "and N more",
   240 bytes in all). Without a set proof the reason is the unchanged first clause.

7. **Added after the live capture: the masquerade on the overlay interface.** A real node has a
   second masquerade the paper did not know (see *State*): `-o tunl0 ... -j MASQUERADE` in IPIP mode,
   `-o vxlan.calico ...` in VXLAN mode. No set limits it. It is excused by its output interface: the
   walk is now told the WireGuard interface, and a source-NAT rule that requires another **exact**
   output interface (`oifname == "tunl0"` in the nft JSON, no wildcard, not negated, not a set of
   names) cannot apply to traffic that leaves through the WireGuard interface.

   This states the protected traffic more precisely than before: traffic for the tunnel range
   **that leaves through the WireGuard interface**. It is the scope the rules Tunnex owns already
   use (`ip daddr TUNNEL oifname wg0 return`, and its own masquerade excludes `oifname wg0`). A
   packet for the tunnel range that leaves through any other interface is not entering the tunnel
   on this node. Without a known WireGuard interface the condition excuses nothing.
8. **Added after the live capture: Calico's mangle hook.** Calico hooks `ip mangle POSTROUTING`.
   Any postrouting hook other than `ip nat POSTROUTING` was refused outright, because a chain that
   runs before NAT could set a Kubernetes mark (0x2000, 0x4000, 0x8000) and so select a masquerade
   the NAT proof believes unreachable. The hook is now accepted only when every rule reachable from
   it is proved unable to change one of those bits: conditions, `RETURN`/`ACCEPT`/`DROP`, jumps to
   known chains, and `MARK`, whose value is read from `iptables-nft-save -t mangle` (paired by
   chain, position and target, like the set matches) and must leave the three bits alone in both
   value and mask. Calico's is `--set-xmark 0x0/0x1b0000`. Any other target (`DSCP`, `CONNMARK`,
   ...), a native nft statement, or text that does not pair is refused. Only the iptables mangle
   hook (`ip mangle POSTROUTING`, type filter, priority -150, policy accept) is read this way.

9. **Added after the founder's ruling: the host-posture manager reads what the gateway cannot.**
   The gateway keeps its capabilities (`NET_ADMIN`, `NET_BIND_SERVICE`, and `NET_RAW` only with VPN
   inference). It no longer runs `iptables-nft-save -t nat|-t mangle` or `ipset` for this proof.
   The privileged manager reads, publishes the facts, and the gateway decides, as K8N-2 does for
   Cilium. The manager never learns the tunnel range and never publishes a verdict.

   *What the manager reads*, each pass in which a gateway owns the node, before it takes the
   operation lock (like its API read):

   - `iptables-nft-save -t mangle`, and `iptables-nft-save -t nat` only when the kernel has at
     least one ipset (`/sys/module/ip_set` present and `ipset list -n` not empty). Without an
     ipset no rule can carry a `set` match, so a Flannel, GKE or EKS node pays for no NAT save.
   - From each text, only the chains a proof can need: NAT chains with a `set` match, mangle
     chains with a `MARK` target. Their rule lines are carried word for word, in order. The whole
     text must first be one complete table with no warning, as before.
   - `ipset save NAME` for exactly the sets named by a non-negated, source-only match on a
     `MASQUERADE` or `SNAT` rule of those chains. This does not depend on the tunnel range, so it
     is the smallest list that covers every range; Calico's negated destination set is still
     never read.
   - For every carried chain, `nft -j -a list tables` and `nft -j -a list chain ip TABLE CHAIN`
     before and after the reads. The two listings must be equal; their SHA-256 (the table's
     handle, the chain, and its rules with their handles, counters removed) is carried as the
     chain's *listing digest*. The manager never lists the whole ruleset.

   *The receipt.* `host-facts.json` in the shared state directory
   (`/var/lib/tunnex/host-posture/v1`), mode 0644, replaced atomically under the operation lock
   together with the heartbeat and the CNI authority receipt. Strict JSON:

       schema_version 1, contract "tunnex-host-posture-facts/v1"
       node_name, manager_uid, manager_boot_id, sequence   (those of the heartbeat it was written with)
       observed_at                                         (when the manager began reading)
       netfilter:
         nat, mangle: state read | not_needed | unreadable, reason,
                      chains [ { name, listing, rules [ "-A ..." ] } ]
         sets [ { name, state, reason, saved } ]           (saved = what `ipset save NAME` printed)
       digest                                              (SHA-256 of all of the above)

   It holds rule text and set members only. K8N-2 adds its own section beside `netfilter` under
   the same identity, freshness and digest.

   *Bounds.* 256 KiB for the file and 192 KiB for the text in it; 64 chains per table; 1024 rules
   per chain; 4096 bytes per rule; 16 sets; 240 bytes per reason; 3 s for one read. Facts that do
   not fit are published as `unreadable` with the reason, never cut. A chain name the manager
   could not pass to `nft` unquoted (`[A-Za-z_.][A-Za-z0-9_.-]*`, 64 bytes) is `unreadable` too.

   *How the gateway uses it.* Inside the existing guard, with the operation lock held: nft JSON,
   then the receipt, then nft JSON again; the two listings must still be equal ("CNI rules changed
   across semantic observation"). The receipt is taken only if

   - the heartbeat is fresh, active and for this node, and the receipt carries the same node,
     manager, manager boot and sequence: a receipt of another node, of an earlier manager process
     or of an earlier pass is refused;
   - `observed_at` is not in the future and not older than the heartbeat freshness window (10 s);
   - the digest and every bound hold;
   - every carried chain has, in the gateway's own first listing, the listing digest the manager
     recorded, and every chain of that listing that has a `set` match (NAT) or a `MARK` target
     (mangle) is carried.

   The last point is what keeps Decision 4 true across two processes. The manager proved the
   chain did not change while its text was read; the gateway proves its two listings show that
   same chain, handles included. A rule replaced between the manager's read and the gateway's
   listing gets a new handle, the digests differ, and the node is refused until the next pass.
   A table that is deleted and built again repeats its chain and rule handles (seen with
   nft 1.1.6), but gets a new table handle, which is why that handle is in the digest.
   Unrelated churn (kube-proxy's Service chains, the gateway's own tables) does not enter the
   digest. Set members are as old as the receipt: a pool added after the read is seen on the next
   pass, as before.

   The gateway then runs the unchanged parsers and the unchanged pure proofs on the carried text.

   *Failure is a refusal with its reason.* No receipt, an unreadable or oversized one, a wrong
   node, manager, boot or sequence, a stale one, a wrong digest, a chain that changed, a chain or
   set that was not read, or a manager-side read error: each leaves the gateway not ready and says
   which. Nothing is assumed, and there is no fall-back to reading directly.

   *What it does not protect against.* The digest detects damage, not forgery: whoever can write
   the state directory is root on the node and could change the rules themselves. The directory
   stays writable by the manager only and read-only in the gateway, as for the heartbeat.

   *Scope.* Only the two reads of this paper move. The manager's own baseline and cleanup, and the
   EKS adapter's `iptables-nft-save -t nat` cross-check, run as before. Outside Kubernetes nothing
   changes.

   *Charts.* No change: the gateway already mounts the state directory read-only and the manager
   read-write, and the manager is privileged. The manager's memory limit (128Mi) now also covers
   one `iptables-nft-save -t nat` per pass on nodes that have ipsets; see *Not known yet*.

   *Versions.* A gateway from before this decision ignores the file. A gateway with it next to a
   manager without it finds no receipt and stays not ready on Calico, as it was. The digest is
   computed from each side's own `nft` output, so a manager and a gateway whose `nft` versions
   print a chain differently refuse each other until both run the same image.

### Why not trust the set's name

`cali40masq-ipam-pools` is Calico's name for its pools today. A name is not a proof: a pool that
overlaps the device range is a real misconfiguration, and it is exactly the case in which
masquerade would rewrite tunnel traffic. Membership is what decides.

### What stays refused

- Calico in eBPF dataplane mode (no iptables NAT rules to read) — same class as Cilium, K8N-2.
- A pool that overlaps the organisation's device range. The reason says which pool; the fix is on
  the customer's side (move the device pool or the IP pool).
- IPv6 pools: the tunnel range is IPv4 only today.

## Tests

- Unit: fixtures captured from a real Calico node (nft JSON, `iptables-nft-save`, `ipset save`) for
  the accepted case; then mutations of it: overlapping pool, negated source match, destination-only
  match, unknown set type, missing set, rule order differing between the two readings, text that
  does not pair with the JSON.

  *State.* Every case above is covered (`observed_calico_test.go`, `observed_calico_linux_test.go`)
  on rules modelled on Calico's documented masquerade rule, and **now also on captures from a real
  node** (`observed_calico_live_linux_test.go`, `testdata/calico-v3.31.2-kind.*`, provenance in
  `testdata/README.md`): Calico v3.31.2, unchanged manifest, iptables dataplane on the nft backend,
  default pool 192.168.0.0/16 with IPIP and natOutgoing, on a one-node kind cluster, read with the
  gateway image's tool versions (nft 1.1.6, iptables-nft-save 1.8.13, ipset 7.24).

  What the live capture showed:

  - **The modelled rule was right.** The real `cali-nat-outgoing` rule is the modelled one word for
    word (comment, `set ... src`, `set ! ... dst`, `MASQUERADE --random-fully`); in nft JSON it is
    comment, two opaque `set` matches and an opaque `MASQUERADE` target. All 29 chains of the real
    nat table pair with the saved text. `ipset save` printed `hash:net family inet` and one member.
    With the other rules of the node out of the way the proof accepted 100.96.0.0/24, naming
    `cali40masq-ipam-pools`, and refused ranges inside the pool.
  - **The node as a whole was still refused, for two reasons the model did not have**, both fixed
    here (Decision 7 and 8): a second masquerade on the overlay interface, and the `ip mangle
    POSTROUTING` hook, which stopped the check before the NAT walk began.
  - **The gateway container cannot read the saved text.** `iptables-nft-save` opens a raw socket to
    resolve a `set` match's name. With the gateway's capabilities (`NET_ADMIN`,
    `NET_BIND_SERVICE`) it prints `Can't open socket to ipset.`, exits 1 and stops inside the
    masquerade rule, for `-t nat` and `-t mangle` alike. With `NET_RAW` added, or privileged (the
    host-posture container), it works. `ipset save` works with `NET_ADMIN` alone. So the check is
    ready on a Calico node only where `NET_RAW` is held: today the host-posture container, and the
    gateway only with VPN inference on. The refusal is closed (the command fails, and the cut text
    is refused on its own), but **the gateway on Calico is not ready until this is decided**:
    grant the gateway `NET_RAW` on such clusters, or have it rely on the host-posture reading.
    Decided and built since: Decision 9, and *Live check of Decision 9* below.
  - No iptables-legacy table existed on the node; Calico wrote through the nft backend. (Running
    any `iptables-legacy*` command on a node creates one, after which `iptables-nft-save` prints a
    warning on stderr that the reader refuses.)
  - kube-proxy's rules did not interfere: `KUBE-POSTROUTING` returns on the unset mark, as on the
    other fixtures. kind's own `DOCKER_POSTROUTING` SNAT is limited to source 127.0.0.11.

  With both fixes, the code's own observation (two nft listings around the reads, real runners) was
  run on the live node from a pod with the host-posture security context and from one with the
  gateway's plus `NET_RAW`: 100.96.0.0/24 accepted with the reason naming the set, 192.168.7.0/24
  refused naming the set. The same held after switching the pool to VXLAN (`-o vxlan.calico`).
- Decision 9: the reader, the receipt and the gateway's use of it each have unit tests on the
  captured node (`k8snetprep/hostfacts_linux_test.go`, `hostposture/host_facts_test.go`): what is
  carried and what is never read, and a refusal for a missing, stale, truncated, edited,
  oversized, wrong-node, wrong-manager and wrong-pass receipt, for a chain or table that changed
  after the read, and for text that no longer pairs. `k8snetprep/hostfacts_e2e_linux_test.go`
  runs the real manager and a real gateway reconciler over one state directory with the captured
  node between them; the gateway's own `iptables-nft-save` and `ipset` fail there as they do
  without `NET_RAW` and are never tried.
- *Live check of Decision 9* (2026-11-23, one-node kind v0.31.0, Kubernetes v1.35.0, kernel 6.8,
  Calico v3.31.2 from its unchanged `calico.yaml`; tools nft 1.1.6, iptables-nft-save 1.8.13,
  ipset 7.24). The package's test binary ran in two `hostNetwork` pods sharing
  `/var/lib/tunnex/host-posture/v1` as the charts mount it:

  - one with the manager's security context (privileged, root, read-only root filesystem,
    128Mi limit): the real manager loop with the real reader and the real commands. Only the
    Kubernetes API read and the kernel mutations were replaced, so nothing on the node changed
    but the state directory. One pass took 60 to 70 ms and the container used 8 to 17 MB; the
    receipt was 1.9 KiB: `cali-nat-outgoing` (one rule), `cali-POSTROUTING` of the mangle table
    (five rules) and the one set.
  - one with the gateway's security context without VPN inference (root, drop ALL, add
    `NET_ADMIN` and `NET_BIND_SERVICE`; effective capabilities `0x1400`), the directory mounted
    read-only: `iptables-nft-save -t nat` and `-t mangle` exit 1 there, and the real reconciler
    with the real authority guard and the real facts source became ready for 100.96.0.0/24 and
    10.200.0.0/16, naming `cali40masq-ipam-pools`, and was refused for 192.168.7.0/24 and
    192.168.0.0/16, naming the set and the range.
  - A second IP pool 100.96.0.0/16 with `natOutgoing` was then added: within one pass
    100.96.0.0/24 was refused ("masquerades sources in set cali40masq-ipam-pools, which overlaps
    the tunnel range 100.96.0.0/24") while 10.200.0.0/16 stayed ready.
  - With the manager stopped, the gateway was refused after the freshness window ("host-posture
    heartbeat is stale"), although the last receipt was still in the directory.

  The check was repeated with the Cilium guard of K8N-2 in the binary; it does not trip on a
  Calico node (devices `lo`, `eth0`, `tunl0`, `cali*`).

  Not part of this check: the `rp_filter` read-back of `wg0` (the node had no `wg0`; the test
  points that one read at a file), the manager's own Kubernetes and kernel work, and the real
  images and charts.
- *Live install of the real image and the real chart* (2026-11-23, branch `k8n/live-install`;
  one-node kind v0.31.0, Kubernetes v1.35.0, kernel 6.8.0-117 arm64, containerd 2.2.0, Calico
  v3.31.2 from its unchanged `calico.yaml`, pool 192.168.0.0/16 with IPIP and natOutgoing,
  kube-proxy present; a Docker VM with 2 CPUs and 3.8 GiB shared with other work). No control
  plane was involved.

  - **Image.** `deploy/docker/node.Dockerfile` built from this tree: 433 MB as Docker reports it
    (119 MB compressed, 298 MB of files). The build took 43 s, but 20 of its steps came from the
    build cache, so this is not a cold build time.
  - **Manager: the chart itself, installed by Helm.** `helm upgrade --install tunnex-host-posture
    ... --namespace tunnex-system --atomic --wait` with the values `tunnex k8s install` sets
    (`acknowledgePrivileged`, `rolloutRevision`, the fixed placement values) and the image
    pointed at the loaded one. Ready 3 s after the install; `Running`, 0 restarts, no OOM, for
    the six minutes the cluster lived. Root filesystem read-only (`touch /x` refused), no seccomp
    filter (privileged), the projected token read. Its whole log was three lines: started; one
    `k8s_host_posture_facts` (`nat=read chains=1; mangle=read chains=1; sets=1`); one blocked
    pass (below).
  - **An idle manager publishes no receipt.** With no gateway pod on the node the state
    directory held `heartbeat.json` (296 bytes, `state: idle`, `owners: null`),
    `cni-authority.json` (`state: revoked`) and two lock files; no `host-facts.json`. The reader
    runs only when a gateway may own the node. Nothing was written by hand to change that.
  - **Gateway side: the gateway chart's pod, with the reconciler's test binary in it.** The real
    binary reaches the CNI check only after enrollment, so it has no step that can be run without
    a control plane. Instead `helm template` of `tunnex-gateway` (the installer's values, a
    control-plane address that does not exist) gave the Deployment's pod template, and that
    template was created as a Pod unchanged: labels, annotations, the init container, the
    gateway container's security context, environment, mounts and volumes. Only three things
    differ: the gateway container runs `k8snetprep.test -test.run TestLiveCiliumGateway` (the
    real reconciler, the real authority guard and both real facts sources, once a second)
    instead of `tunnex-node`; its HTTP probes are removed; the state volume is an `emptyDir`.
  - **The real manager adopted that pod through the Kubernetes API** (its shape passes
    `validateGatewayAuthority`), wrote `journal.json` (1276 bytes, schema 4, `active`, epoch 1),
    created `wg0` (type `wireguard`, alias `tunnex-host-posture/v1`, down, `rp_filter` 0),
    granted authority (`scope: ip_masq_and_aws_transit`) and published `host-facts.json`: 1868
    bytes, contract `tunnex-host-posture-facts/v1`, `netfilter.nat` with `cali-nat-outgoing`
    (one rule), `netfilter.mangle` with `cali-POSTROUTING` (five rules), the one set
    `cali40masq-ipam-pools`, a digest, and no `cilium` member. The same content as the earlier
    check.
  - **The real init container admitted it**: `tunnex-node k8s-host-posture-check --wait` as user
    65532 with every capability dropped and a read-only root printed `"status":"ready"` and
    exited 0 two seconds after it started.
  - **Decisions**, first one 7 s after the pod was created: ready for 100.96.0.0/24 and
    10.200.0.0/16 (`... masquerade sources are limited by sets outside it:
    cali40masq-ipam-pools`), refused for 192.168.7.0/24 and 192.168.0.0/16 (`NAT chain
    cali-nat-outgoing masquerades sources in set cali40masq-ipam-pools, which overlaps the
    tunnel range ...`). A second pool 100.96.0.0/16 with `natOutgoing` turned 100.96.0.0/24 to
    refused within about two seconds, and deleting it turned it ready again within about three.
  - **Differs from the earlier check: by default the gateway holds `NET_RAW`.** The chart's
    `aiVPN.enabled` is `true` by default and the installer does not set it, so the rendered
    gateway container adds `NET_ADMIN`, `NET_BIND_SERVICE` and `NET_RAW` (effective `0x3400`,
    seccomp filter on). There `iptables-nft-save -t nat` exits 0. The earlier check used the
    profile without VPN inference; that was repeated here with `aiVPN.enabled=false` (`0x1400`,
    `iptables-nft-save` exits 1 with `Can't open socket to ipset.`). The four decisions were the
    same in both.
  - **When the pod was deleted** the manager removed `wg0`, set the journal to `restored`, the
    heartbeat to `idle` and the authority to `revoked` within the next five seconds. The last
    `host-facts.json` stays in the directory; it belongs to an older heartbeat.
  - **Cost of the manager with one gateway on the node**, read from its cgroup on the node: 26
    to 27 MB charged (8 MB of it anonymous, 18 MB the page cache of the binary), peak 35 MB,
    against the 128Mi limit; resident set 15 MB; 2.96 s of CPU in 120 s, that is 25 millicores,
    more than the chart's 20m request. That figure includes the two exec probes, which start
    the 15 MB binary every 2 s and every 10 s.
  - **Seen once, cause not established.** About a minute in, one manager pass failed with
    `acquire host-posture CNI transition lock: wait for CNI operation lock: context deadline
    exceeded` (the 5 s bound), and the kubelet recorded two readiness and one liveness failure
    with `host-posture heartbeat is stale or from the future`; a `kubectl` call from outside got
    a TLS handshake timeout from the API server in the same seconds, so the whole VM probably
    stalled. Two probe runs had also timed out (2 s) at the moment the first gateway pod was
    adopted. No restart followed. See K8N-2, "Live install", on the exec probes under load.

  Not part of this check, because it needs a control plane: enrollment, the real `tunnex-node`
  agent running its own reconcile loop and `/readyz`, WireGuard up with a peer, a Service
  reached from a device, and `tunnex k8s install` itself (its plan, its Helm calls for the
  gateway release, the preflight hook). Also not run: more than one node.
- Existing Flannel, kube-proxy, GKE and EKS fixtures must still pass unchanged.
- Live walk on a cluster running Calico (iptables dataplane): gateway ready, a Service reached by
  address and by name from a connected device, and the readiness reason naming the sets. Then a
  deliberately overlapping pool, to see the refusal and its message.

## Not known yet

- ~~Whether `ipset save` needs a capability the host-posture container does not already hold.~~
  Answered on the live node: `ipset save` needs only `NET_ADMIN`; it is `iptables-nft-save` that
  needs `NET_RAW` whenever a rule has a `set` match (see *State*).
- The exact rule text across Calico versions. Fixtures are from v3.31.2 only; the parser pairs by
  structure, not by Calico's chain names, so a renamed chain does not break it, but a new match type
  would be refused rather than misread. Other versions may install a different mangle hook or
  none.
- ~~Whether the gateway should hold `NET_RAW` on Calico clusters.~~ Ruled: it does not;
  Decision 9.
- What Decision 9 costs the manager on a large node. Where ipsets exist it saves the whole NAT
  table every pass (2 s) inside a 128Mi limit, where before only the gateway (256Mi) would have.
  That includes nodes that have ipsets for another reason (Calico for policy only, kube-proxy in
  IPVS mode) and carry no set match in NAT. Measured only on the one-node capture above. If it is
  too much, the text of an unchanged chain can be kept between passes, since its listing digest
  says when it changed; not built.
- Decision 9 across a version skew of `nft` between the manager and the gateway image, and on a
  multi-node cluster.
- Calico features that add rules: egress DSCP fills `cali-egress-dscp` in the mangle table with a
  `DSCP` target, which the mark proof refuses; host endpoints and floating IPs fill chains that were
  empty in the capture. None was exercised.
- Still owed from the live walk, and all of it needs a control plane: the gateway itself
  enrolled and installed by `tunnex k8s install` on a Calico cluster, its own `/readyz`, WireGuard
  up, a Service reached from a device. Also a multi-node cluster (every check so far is one
  node). The real image, the real host-posture chart installed by Helm, the manager's own
  Kubernetes and kernel work, the real admission init and the gateway chart's pod profile are
  no longer on this list: see *Live install of the real image and the real chart* above.
- Whether the manager's 20m CPU request and its 2 s exec probes are right. Measured once: 25
  millicores with one gateway, and probe runs that timed out when the node was busy.

## Rollback

The change only widens what the proof can read. Removing it returns Calico clusters to "not ready,
chain unreadable". No stored data changes.
