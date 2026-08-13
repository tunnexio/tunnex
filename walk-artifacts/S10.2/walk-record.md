# S10.2 GitOps operator — box-walk record (EXECUTED 2026-07-29)

Rig: **azure-cp** (enterprise CP, docker-compose, rebuilt from `story/S10.2-operator`) · **azure-gw** (k3s +
in-cluster gateway `tunnex-gw`, org Nykaa `019f8e44…`, site `k8s-site`) · **laptop** (macOS, WireGuard dev
tunnel, device `10.99.0.4`). Operator image `tunnex-operator:a9d781d`, hostNetwork (gateway-node egress).

## Verdict: DISCHARGED — every leg green. The decisive teeth proven on the wire.

| Leg | Result | Evidence |
|---|---|---|
| 0 deploy + provenance | ✓ | operator log `version=a9d781d`; 3 controllers + workers up |
| 1 cluster from YAML | ✓ | `ready=True clusterId=ea6ded6c… dnsVip=100.64.0.2` |
| 2 service from YAML + DNAT | ✓ | `ready=True vip=100.64.0.3 fqdn=hello.default.svc.prod.k8s.local`; gateway `dnat to 10.42.0.15:80` (= live pod IP) |
| **3 DENY (no grant)** | ✓ | laptop `curl 100.64.0.3 → exit 28`; `tunnex_default_drop` counter 0→**2** |
| **4 ALLOW via `kubectl apply`** | ✓ | grant `ready=True ruleId=019fad8d…`; gateway accepts for `saddr 10.99.0.2/.3/.4 ct original ip daddr 100.64.0.3`; laptop `curl → 200` (nginx body) |
| **6 REVOKE via `kubectl delete`** | ✓ | accepts **gone**; laptop `curl → exit 28`; audit `policy.rule_deleted`: `actor_system=operator:gitops`, `cause=tunnexgrant:default/eng-to-hello` |
| 7 cascade audit | ✓ | `kubectl delete tunnexcluster` → audit `k8s.cluster_deregistered`: `actor_system=operator:gitops`, `cause=tunnexcluster:default/prod-cluster`, `services_deleted=1` |
| 8 drift heal | ✓ | out-of-band `deleted_at` → operator recreated (`serviceId 01757958…→e0b6a785…`). Drift condition transient → **WF-OP-3** |
| 9 honest status | ✓ | incidental — `403` (WF-OP-1), `conflict: an identical rule already exists`, `Ready=False` all rendered the CP's verbatim verdict |
| 5 ownership surface | ✓ | dashboard: `prod` cluster badged **"Managed by GitOps"**, Deregister → **"edit the CR"** (`leg5-ownership-surface.png`) |

## The decisive sequence (WF-K6 standard)
**deny → allow → deny, SAME flow (`http://100.64.0.3/`), flipped by `kubectl apply`/`delete` of a
TunnexGrant — never the dashboard**, with counter evidence at the drop (default_drop 0→2) and the audit at
the revoke (CR as cause). GitOps governs the wire, honestly attributed.

## The walk earned its keep — findings + fold-validation

- **WF-OP-1 (FOUND + FOLDED mid-walk):** `RoleOperator` lacked `member:list` → a user-subject `TunnexGrant`
  reported `Ready` but 403'd on `GET /members` → the flow never opened. Fix `RoleOperator += PermMemberList`
  (read-only) committed `d3f45a1`, CP rebuilt, re-proven: the grant then resolved `nykaa@in` → 3 device
  accepts → curl 200. **A feature that didn't work, found on the wire — exactly what the walk exists to catch.**
- **WF-OP-3 (REGISTERED):** drift healing proven (serviceId changed); the `Drift` condition self-clears next
  reconcile so a status snapshot misses it — observability gap, not correctness. Durable fix = a k8s Event on
  drift-heal (fold-later).
- **Fold validated on the wire:** **M1b** (grant-delete audit CR-cause, Leg 6 — would have failed pre-fold) ·
  **C1** (operator authorized at all, Leg-0 provenance `version=a9d781d`) · **keep-last/fail-static** (the
  CP-unreachable retry left status untouched + backed off, incidental).

## Walk-time notes (rig, not S10.2 defects)
- Operator on a **full-tunnel gateway node** needs `hostNetwork` (the node's kill-switch drops pod egress to
  the CP). Deploy consideration, registered.
- `src_cidr` grants place on the containing **site's** gateway; a **device-pool** IP has no containing site —
  so a device is granted via its **user**, never a raw pool CIDR (compiler by-design; my walk mis-choice).
- Client dev-run (`pnpm start`) is refused by the helper's caller-auth (by design); the walk client used
  `scripts/macos-dev-install.sh` (trusts the dev Electron dir) — a legitimate `iifname wg0` peer.
