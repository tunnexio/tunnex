# K8L-9 — a Kubernetes API outage must not be a Tunnex outage, and a gateway must be able to restart

Story branch: `story/kubernetes-launch-fixes`. Founder ruling 2026-11-22: do it. Walked live on a
one-node k3s 1.37 cluster with the laptop connected through the gateway in another network.

## 1. The Kubernetes API stops answering

### Before

The in-cluster gateway learns which pods back a Service from the Kubernetes API. On the first failed
read it cleared its whole view: every exposed Service lost its rules at once, and the gateway reported
not-ready. Separately, the host-posture manager on the node stopped vouching for the gateway the
moment its own API read failed, which also made the gateway not-ready.

An API server restart, an etcd leader change or a managed control-plane upgrade lasts seconds and
does not move a single pod. So an event the workloads never noticed took every exposed Service down,
and behind a cloud load balancer took the gateway out of rotation.

### Decision

Both keep the last complete, verified state for **60 seconds** after the API was last read
successfully, then fail closed exactly as before.

- Gateway (`egress.apiOutageGrace`): a view that was fully synced stays readable and keeps backing
  the Service rules; readiness holds. The clock starts at the first loss and is not extended by later
  failures. A view that was never complete has no grace.
- Host-posture manager (`hostposture.apiFaultGrace`): after re-enforcing the retained ownership it
  keeps issuing an active heartbeat for the owner set it last read. A manager that has not read the
  owners since it started has no grace. Its heartbeat is stamped when written, because the failed
  read may have waited its full timeout.
- Not changed: the Service inventory report to the control plane still stops during the outage (the
  dashboard then shows the inventory as stale, which is true).

### The trade

For up to 60 seconds traffic may go to a pod address that no longer belongs to that Service, if the
pod died and its address was reused in that window. kube-proxy keeps its last rules indefinitely in
the same situation; this is bounded. Access rules are unaffected: they apply to the Service address
before it is translated.

### Proof

- Unit: the view is kept inside the grace and cleared after it, for a lost watch, an early stream
  close, a decode error and a failing list; a repeated failure does not move the start; a restored
  watch resets it. The manager stays active inside the grace, blocks after it, never cleans up, and
  has no grace with no successful read.
- Live: `systemctl stop k3s` for 43 seconds while probing every 2 seconds.

  | | Before | After |
  | --- | --- | --- |
  | Service from the laptop | rules withdrawn on the first failed read | 36 of 36 answered 200 |
  | Gateway `/readyz` during the outage | `not_ready` | `ready` at every 5-second sample |

## 2. A gateway serving a multi-port Service could not start again

### Found

Rolling the gateway to the new build put it in a crash loop:

    ownership_startup_reconcile_failed: withdraw Kubernetes ownership: ownership full-domain readback mismatch

The previous build did the same, so it was not the new code. The error named nothing. With the
difference added to the message it read `...readback mismatch: dns_answers`.

### Cause

A Service exposed on two ports is two address mappings with the same name and address. The expected
state listed that DNS answer twice; the resolver holds one answer per name. Every readback therefore
differed, and startup refuses to continue on a readback difference. Any gateway holding a multi-port
Service — made from the dashboard's "Expose selected ports" or from two operator resources — would
fail on its next restart: a node reboot, an upgrade, an eviction.

### Decision

- Expected DNS answers are de-duplicated; both port mappings remain.
- The startup failure now names the part of the state that differs.

### Proof

- Unit: two ports of one Service give one expected answer equal to what the resolver reports; two
  different Services keep two.
- Live: the gateway serving `shop/web` on ports 80 and 8080 restarted cleanly, zero restarts, ready.

## Still open

Readiness can drop for one pass with `CNI rules changed across semantic observation` when kube-proxy
rewrites its chains between the two reads of the NAT rules. Seen once at each start; it clears on the
next pass. Narrowing what is compared is its own change.
