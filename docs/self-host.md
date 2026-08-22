# Self-hosting Tunnex

Everything needed to stand up a control plane, connect a gateway, and run it unattended. Written for someone
who has never seen this product.

**A note on the procedures below.** Each is marked with whether *we* have actually executed it:

- ✅ **verified** — run end to end, in this form, by us.
- 🔶 **partially verified** — the artifact is exercised, but not the whole procedure as written; what is and
  isn't covered is stated inline.
- ⚠️ **untested** — plausible and derived from the code, but nobody has run it. Treat with suspicion.

A quickstart nobody executed is documentation that looks like a guarantee, so the marks are the honest part.

---

## 0. Public one-command installer 🔶 locally verified

For a fresh Linux or macOS host with a public DNS name or IP:

```bash
curl -fsSL https://get.tunnex.io | sh
```

For Windows, open Administrator PowerShell:

```powershell
irm https://get.tunnex.io/install.ps1 | iex
```

The terminal guide shows the Tunnex wordmark and slogan, checks the host, selects the latest signed
semantic release, collects the public URL/TLS/admin/email choices, and presents one final review. Only
after confirmation does it install or start a compatible Docker runtime and Compose v2, generate secrets,
pull digest-pinned images, and verify the running stack. A working existing runtime is reused. Linux uses
the host package manager, macOS reuses Docker Desktop or prepares Homebrew + Colima, and Windows prepares
Docker Desktop + Git Bash through Windows Package Manager before entering the same canonical flow.

On Linux, that flow runs the control plane and its co-located WireGuard gateway. On macOS and Windows,
it runs a portable control plane and keeps the Linux-only `node-agent` container disabled; the final
screen tells you to enroll the gateway on a separate Linux host. This is a runtime boundary, not a missing
installer feature: the gateway requires `/dev/net/tun`, `NET_ADMIN`, IP forwarding, and host networking.

*What is verified:* the complete installer ran locally against a clean Ubuntu host simulation, including
Docker/Compose bootstrap, signed-release hand-off, generated configuration, safe rerun, and a root-only
Docker socket. The native Windows launcher contract also proves existing-runtime reuse and fresh Docker
Desktop preparation before canonical hand-off, plus the portable-control-plane handoff. *What is not yet verified:* this exact new flow on live
fresh Linux, macOS, and Windows hosts. Those live-wire proofs are required before changing
`get.tunnex.io`.

## 1. Quickstart — Docker Compose ✅ verified

Single host, everything on one machine. Good for evaluation and small deployments.

```bash
git clone https://github.com/tunnexio/tunnex.git && cd tunnex
cp .env.example .env          # review it; the defaults are development values
make up                       # open edition   (make up-enterprise for Zero Trust policy)
make migrate                  # apply the schema
make seed                     # create a demo org + owner (skip for a real deployment)
```

Then open `http://localhost`. `curl localhost/api/v1/meta` reports the edition and protocol version.

*Verified from a clean slate (`make reset` first) on 2026-07-30: `up` → `migrate` → `seed` → `HTTP 200` and
`protocol_version: 7`.*

**Before production on this path:** change every credential in `.env`, put TLS in front of it, and read
§2 about the master key.

## 2. The master key — decide this now, not later ✅ verified (the mechanism)

Tunnex encrypts its most important secrets at rest under a **master key**: the agent CA private key, the
OpenVPN CA and profile keys, MFA/TOTP secrets, SSO client secrets.

**The agent CA is the one that matters most.** Every enrolled gateway *pins* it. If the master key is lost,
that CA cannot be read, no certificate can ever again be issued that your gateways will trust, and **the whole
fleet must re-enrol.**

So, at the moment you create it:

1. **Back it up separately from your database backups.** Not in the same bucket, not in the same archive.
2. **Never let anything regenerate it.** Tunnex refuses to: a mis-set or malformed key fails startup loudly,
   and the Helm chart will not mint one for you (it *requires* you to create the Secret first, precisely so
   that this is a deliberate act you can back up).

```bash
# Kubernetes: create it once, then back up the value offline.
kubectl -n tunnex create secret generic tunnex-master \
  --from-literal=key="$(head -c 32 /dev/urandom | base64)"
```

Full detail, including what a backup does and does not contain: **[backup-restore.md](backup-restore.md)**.

## 3. Kubernetes with Helm 🔶 partially verified

```bash
helm install tunnex deploy/helm/tunnex-cp \
  --namespace tunnex --create-namespace \
  --set publicBaseURL=https://vpn.example.com \
  --set appBaseURL=https://vpn.example.com \
  --set database.url='postgres://…' \
  --set redis.url='redis://…' \
  --set masterKey.existingSecret=tunnex-master
```

The chart runs **no bundled Postgres or Redis** — you supply managed ones, because a database inside the
release is a database that gets deleted with it.

*What is verified:* the chart renders cleanly with these values, and every required value fails loudly when
missing (we walked all five refusals, including the master-key one). The chart was installed to a live k3s
cluster during the S10.1 and S10.3 box walks. *What is not:* this exact command sequence, on a managed
Kubernetes service, with managed Postgres/Redis, has not been executed by us end to end.

**Known unsupported:** GKE Autopilot — the gateway needs `hostNetwork` and `NET_ADMIN`, which Autopilot
forbids. Use a standard node pool.

**The agent port must not be TLS-terminated.** Gateways dial `:8443` with a *pinned* certificate; an Ingress
that terminates TLS presents its own certificate and breaks enrolment in a way that looks like a network fault.
The chart exposes it as a raw L4 Service for this reason.

## 4. First gateway ✅ verified

A gateway is where traffic actually flows. In the UI: **Sites → add a site → enroll a gateway**. You get a
single command to paste on the host — it carries a one-time join token, and the agent generates its own
WireGuard key locally.

**The gateway's private key never leaves the gateway.** The control plane stores only public keys. This is why
a control-plane backup cannot (and need not) contain fleet secrets — see §7.

*Verified on live Azure and AWS hosts across the S8.x–S10.x box walks, including the in-cluster gateway on k3s.*

**Reachability requirement, stated plainly:** Tunnex runs **no relay fleet**. A gateway needs to be reachable
by its clients — a public IP, a port-forward, or a private network they share. Clients behind CGNAT may fail
to connect directly, and there is no hosted fallback to rescue them. If you need one, Tunnex is the wrong
choice today.

## 5. First device ✅ verified

**Devices → add device** issues a WireGuard configuration **shown exactly once** (the private key is generated
for you and never stored server-side; if it is lost, revoke and re-issue). Import it into the Tunnex desktop
app or the official WireGuard client.

*Verified on macOS with both the desktop client and WireGuard.app.*

## 6. Honest limits — read these once, up front

Every one of these was written down honestly when it was found. Collected here so you meet them before they
meet you.

| Limit | What it means for you |
|---|---|
| **No relay fleet** | Gateways need reachability; CGNAT clients may not connect. No hosted fallback. |
| **Per-cloud fabric routes** | Cross-site traffic needs a route in your cloud's route table (AWS route table / Azure UDR) pointing the remote range at the gateway's interface. One console visit per side; the UI names the steps. |
| **OpenVPN revocation timing** | A revoked OpenVPN client is cut at the next renegotiation, not instantly. WireGuard revocation is immediate (peer removal). |
| **OpenVPN failover timing** | Re-homing an OVPN client is bounded by connect-timeout × number of dead remotes before it reaches a live one. |
| **GKE Autopilot unsupported** | The gateway needs `hostNetwork` + `NET_ADMIN`. Use a standard node pool. |
| **Revoked-while-agent-down** | If a gateway is offline when you revoke access, flows already established there persist until they end. New flows are blocked as soon as it reconciles. |
| **Windows full-tunnel re-home** | A Windows client in *full-tunnel* mode refuses to re-home to a new gateway (honestly, with a named error) rather than half-doing it. Split-tunnel re-homes normally. |
| **Cross-site DNS to cluster zones** | Resolving another site's Kubernetes zone across a site link is not implemented; same-site resolution works. |
| **Leader takeover window** | A leader that **stops or dies** — clean shutdown, crash, `kill -9`, container removal — releases the lock at once, and another replica takes over within ~10s (verified). A leader that is **network-partitioned** while still running is the slow case: its Postgres session stays open until TCP keepalive expires, so takeover can take minutes (**not verified — no partition test has been run**). Nothing ticks meanwhile; **running tunnels are unaffected** either way. |
| **A gateway offline >48h must be re-enrolled** | Agent certificates last 48 hours and renew automatically **while the agent is running**. A gateway offline for longer cannot renew — the renewal endpoint requires the certificate that expired — so it never reconnects on its own. The control plane reports it as `cert_expired_cannot_reconnect` and `preflight` refuses to call the fleet ready. **Re-enrolling now works without wiping anything:** restart the agent with `TUNNEX_JOIN_TOKEN` set and it replaces the dead certificate, saying so in its log. **But it comes back as a NEW node** — a new id, so its site binding must be re-applied, and **its devices stay revoked and must be re-issued**. Same-identity recovery and device restore are the remaining work (EPIC 13). |
| **Posture checks are self-reported** | OS version, disk encryption and EDR checks are reported by the device. A compromised device can lie. Treat posture as defense-in-depth, never attestation. |
| **No third-party security audit yet** | Stated in [SECURITY.md](../SECURITY.md), and it will say so until one has happened. |

## 7. Running it unattended

### What to watch

The control plane exposes Prometheus metrics and readiness on a **separate port, bound to loopback by
default** (`TUNNEX_METRICS_ADDR` to change it — see §8). ✅ *verified by scraping a live control plane.*

`tunnex_gateway_policy_health{kind="…"}` counts gateways per health kind. These are the product's own health
vocabulary — the same states the dashboard shows:

| kind | meaning | remedy |
|---|---|---|
| `healthy` | in sync | — |
| `apply_failing` | the gateway is failing to apply policy | check the gateway's logs |
| `stuck_enforcing` | enforcing a policy it cannot swap out | check the gateway |
| `converging` | a push is settling (normal, brief) | wait |
| `silent_desync` | pushed ≠ applied and not settling | investigate the gateway |
| `desync_unknown` | cannot determine — **not** healthy | check reachability/reporting |
| `unsupported_policy_version` | the agent refused a too-new artifact | **upgrade that agent** |
| `site_hub_down` / `site_link_down` | a site link has no fresh handshake | fix the hub / that spoke |
| `site_subnet_unreachable` | the gateway advertises a subnet it isn't on | fix its host networking |
| `conntrack_flush_unavailable` | expired-grant flush failing | restore `CAP_NET_ADMIN` |
| `k8s_endpoints_unavailable` | no endpoint view from the K8s API | check the gateway's API reachability + RBAC |
| `hub_forwarding_not_reconciling` | wire fresh but the agent is stale (a zombie hub) | restart the agent |
| `cert_expired_cannot_reconnect` | the agent's certificate expired while it was unreachable — it **cannot** get a new one | **re-enroll that gateway**; waiting will not fix it |

**Alert on:** `cert_expired_cannot_reconnect > 0` **first** — that gateway is not coming back without you;
`unsupported_policy_version > 0` (an agent has stopped receiving updates); `apply_failing` or `silent_desync`
sustained over minutes; and `desync_unknown` sustained — it means you cannot see the truth, which is its own
problem. The metric answers *how many*; the dashboard answers *which*.

### `/readyz`

| response | meaning |
|---|---|
| `200 ok leader` | ready, and running the periodic schedulers |
| `200 ok follower` | ready, serving traffic, not ticking — **a normal, healthy state** |
| `503 not ready: …` | a dependency is down; the reason is named |

A follower is **ready on purpose**: it serves API traffic. Treating it as unhealthy would remove capacity for
no reason.

### What degrades vs what breaks ✅ verified

**The control plane degrades; tunnels survive.** With Postgres stopped, the control plane keeps running,
`/healthz` still answers, `/readyz` returns 503 naming the reason, and leadership is released; when Postgres
returns, leadership is re-acquired **without a restart**. Meanwhile gateways keep forwarding traffic from their
applied state — they reconcile *against* the control plane and never *through* it.

Redis holds sessions only: losing it breaks API sign-in, not tunnels, and not the mTLS agent channel.

*Verified by stopping and restarting Postgres under a live control plane.*

### Two recovery stories — don't confuse them

| Lost | Recovery |
|---|---|
| **The control plane** | Restore from backup: verify the master key first, then restore the dump. Gateways reconnect on their own — no re-enrolment. See [backup-restore.md](backup-restore.md). |
| **A gateway** | Re-enrol it: restart the agent with `TUNNEX_JOIN_TOKEN` set. It generates a fresh key, the control plane issues a new certificate, and a dead stored identity is replaced automatically (it will not silently keep one it cannot use). **Two caveats until EPIC 13 lands:** the gateway returns as a *new node*, so re-apply its site binding; and revoking a gateway revokes the devices homed on it, so those users need new configs. |
| **A device** | Re-enrol it. Nothing to restore: a fresh key is generated and the config is re-issued (shown once). |

A control-plane restore recovers the *control plane's* state, not the fleet's secrets — and doesn't need to,
because the fleet's secrets never left the fleet.

### Upgrades

Forward-only, with restore-from-backup as the rollback. Run `preflight` first — it refuses rather than warns.
Full procedure: **[upgrade.md](upgrade.md)**. ✅ *`preflight` verified against a live database.*

## 8. Security posture

- **Secrets at rest** — AES-GCM under the master key: agent CA, OpenVPN CA and profile keys, MFA secrets, SSO
  client secrets. A stolen database dump is not enough to read any of them.
- **Agent channel** — mutual TLS. A gateway is authorised by its *client certificate*, never by anything in a
  request body.
- **Secrets shown once** — device configs, join tokens, `.ovpn` profiles, machine credentials. Lost means
  revoke-and-reissue, never retrieve. What remains visible is a *keyed* fingerprint, which proves which secret
  is stored without revealing it.
- **Privileged surfaces, and why each is needed** — the gateway agent runs with `hostNetwork` and `NET_ADMIN`
  because it programs WireGuard and firewall rules; the desktop privilege helper runs as root behind a typed
  protocol with caller authentication; the GitOps operator holds **no** data-plane privilege and reaches
  Tunnex only over HTTPS as a machine credential; the in-cluster gateway's Kubernetes RBAC is read-only on
  `services` and `endpointslices` — it cannot read Secrets, cannot write, cannot escalate.
- **Metrics** — separate port, **loopback by default**, unauthenticated. An endpoint that cannot be reached
  cannot have its authentication be wrong. Remote scraping is opt-in configuration; a wildcard bind is
  permitted but logged.
- **Supply chain** — every merge runs `govulncheck` and CodeQL with high/critical findings **blocking**;
  releases publish an SBOM and a keyless cosign signature.

Reporting a vulnerability, our response targets, and what is in and out of scope: **[SECURITY.md](../SECURITY.md)**.
