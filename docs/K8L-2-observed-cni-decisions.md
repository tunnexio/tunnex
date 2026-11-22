# K8L-2 — a gateway on a cluster with no registered CNI mechanism

Story branch: `story/kubernetes-launch-fixes`. Found on 2026-11-22 on a one-node k3s cluster
(Flannel, kube-proxy, Kubernetes 1.37) after K8L-1 let the gateway pod start.

## What happened

The gateway enrolled, then crash-looped:

    k8s_netprep_state host_state=blocked host_reason="unknown NAT POSTROUTING rule coverage"

and `tunnex k8s install` timed out. The same would happen on kubeadm with Flannel and on GKE
Standard, whose nodes also have none of the chains the gateway knows.

## Why the gateway looks at the node's NAT rules at all

Traffic the gateway sends out of `wg0` to the tunnel range (to devices and to other gateways) must
keep its source address: WireGuard drops a packet whose source is not in the peer's allowed
addresses. Some clusters masquerade everything that leaves a node to a non-cluster destination
(AKS `ip-masq-agent`, the AWS VPC CNI). There the gateway inserts one owned "do not masquerade the
tunnel range" rule into the CNI's chain. Until now it knew only those two chains, and treated every
other shape as blocked — including clusters where no such rule is needed.

## Decision

1. When neither registered chain is present, the gateway proves the property instead of editing
   anything. It walks every rule reachable from `ip nat POSTROUTING` and is ready only if no
   source-NAT statement can apply to a packet whose destination is inside the tunnel range. It owns
   no rule in that case. The adapter is reported as `observed_cni`.
2. The walk (`apps/node/internal/k8snetprep/observed.go`) understands a small closed set:
   - conditions: `ip saddr/daddr ==/!= prefix`, the Kubernetes-reserved packet marks (kube-proxy
     0x4000 and 0x8000, CNI portmap 0x2000), an `xt` comment, any other typed `xt` match (treated
     as "may or may not match"), and other native matches (same);
   - statements: return, accept, drop, jump, goto, masquerade/snat (native or `xt` target), and
     mark-setting.
   Anything else — an unknown statement, an untyped `xt` expression, a jump to a missing chain, a
   loop — is a refusal. It never assumes.
3. A source-NAT rule that might apply to tunnel-bound traffic is accepted in exactly one case: the
   rule is positively limited to a source range that does not overlap the tunnel range. That is how
   a CNI masquerades pod-originated traffic (Flannel: `ip saddr <pod network>`). Consequence, to
   be documented: a connection a pod opens towards a device is seen from the gateway's tunnel
   address, not the pod's. Device-to-Service traffic, which is the product feature, is unaffected.
4. Nothing changes where a registered mechanism exists:
   - AWS VPC CNI nodes keep the exact rule-by-rule validation they were qualified with;
   - on an `IP-MASQ-AGENT` node the owned rule is still inserted and read back; other rules in
     `POSTROUTING` (kube-proxy) now go through the walk instead of being refused outright.
5. A mechanism that was being reconciled and then disappears is still a refusal
   (`registered CNI mechanism disappeared`) for the life of the process: that is a controller
   restart in progress, not a cluster without one.
6. Refusals name the chain, for example `NAT chain IP-MASQ can rewrite the source of traffic to the
   tunnel range 172.20.0.0/24`, so the operator knows which range to exclude.

## What this covers

| Cluster | Result |
| --- | --- |
| k3s / kubeadm with Flannel + kube-proxy | ready (proved live, below) |
| GKE Standard, default dataplane | `IP-MASQ` returns for 10/8, 172.16/12, 192.168/16, 100.64/10 and others before masquerading; ready when the tunnel range is inside one of them, refused with the chain name otherwise. Rule shape taken from a live GKE 1.36 node; live gateway run still to do. |
| AKS (`IP-MASQ-AGENT`) | unchanged owned rule; kube-proxy's chain no longer blocks. Not yet run live. |
| EKS (AWS VPC CNI) | unchanged. |
| Calico (ipset matches), Cilium iptables mode | still refused, now with a reason naming the chain. Later story if customers need it. |

## Not in this story

- The coverage fingerprint spans the whole ruleset, so an unrelated kube-proxy change between the
  two reads gives a one-pass `CNI rules changed across semantic observation`. Seen once at start on
  k3s; it cleared on the next pass. Narrowing the fingerprint is K8L-4.
- Install failure messages (K8L-3).

## Proof

- Unit (run on any OS): real k3s ruleset fixture, GKE shape, 12 refusal shapes, 7 acceptance shapes.
- Existing Linux suites for `k8snetprep`, `egress`, `hostposture` pass; one expectation changed on
  purpose (a node with no mechanism at all is now ready as observed).
- Live, 2026-11-22, k3s 1.37 one node: `adapter=observed_cni adapter_state=ready`, `agent_ready`,
  `/readyz` = `{"status":"ready"}`, and `tunnex k8s install` printed `Gateway "gw-a" is ready`.
