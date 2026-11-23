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
   - For every carried chain, `nft -j -a list chain ip TABLE CHAIN` before and after the reads.
     The two listings must be equal; their SHA-256 (chain and rules with handles, counters
     removed) is carried as the chain's *listing digest*.

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

   *Bounds.* 256 KiB for the file; 64 chains per table; 4096 bytes per rule; 16 sets; 240 bytes
   per reason; 3 s for one read. Facts that do not fit are published as `unreadable` with the
   reason, never cut.

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
   read-write, and the manager is privileged.

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
    Not changed here.
  - No iptables-legacy table existed on the node; Calico wrote through the nft backend. (Running
    any `iptables-legacy*` command on a node creates one, after which `iptables-nft-save` prints a
    warning on stderr that the reader refuses.)
  - kube-proxy's rules did not interfere: `KUBE-POSTROUTING` returns on the unset mark, as on the
    other fixtures. kind's own `DOCKER_POSTROUTING` SNAT is limited to source 127.0.0.11.

  With both fixes, the code's own observation (two nft listings around the reads, real runners) was
  run on the live node from a pod with the host-posture security context and from one with the
  gateway's plus `NET_RAW`: 100.96.0.0/24 accepted with the reason naming the set, 192.168.7.0/24
  refused naming the set. The same held after switching the pool to VXLAN (`-o vxlan.calico`).
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
- Whether the gateway should hold `NET_RAW` on Calico clusters (see *State*).
- Calico features that add rules: egress DSCP fills `cali-egress-dscp` in the mangle table with a
  `DSCP` target, which the mark proof refuses; host endpoints and floating IPs fill chains that were
  empty in the capture. None was exercised.
- Still owed from the live walk: the gateway itself installed on a Calico cluster, a Service
  reached from a device, and a multi-node cluster (the capture is one node).

## Rollback

The change only widens what the proof can read. Removing it returns Calico clusters to "not ready,
chain unreadable". No stored data changes.
