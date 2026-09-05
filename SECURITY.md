# Security Policy

Tunnex is a self-hosted VPN and Zero Trust access control plane. It sits directly in the network path of the
systems that deploy it, and it holds the key material that authenticates a fleet. We treat vulnerability
reports accordingly.

## Reporting a vulnerability

**Email: `security@tunnex.io`** — or open a
[GitHub private security advisory](https://github.com/tunnexio/tunnex/security/advisories/new), which is
preferred because it keeps the report, the fix, and the CVE assignment in one place.

**Do not open a public issue for a suspected vulnerability.** Public issues are fine for everything else.

Useful in a report: affected version or commit, deployment shape (self-hosted compose, Helm, edition), a
reproduction or proof-of-concept, and the impact you believe it has. A partial report is still worth sending —
we would rather triage an uncertain report than never receive it.

### What to expect

| Stage | Target |
|---|---|
| Acknowledgement that a human has read it | **2 business days** |
| Initial assessment (severity, affected versions, whether we can reproduce) | **5 business days** |
| Fix or documented mitigation for **critical / high** | **30 days** from confirmation |
| Fix or documented mitigation for **medium / low** | next scheduled release |
| Public advisory + credit (if you want it) | at release, coordinated with you |

These are targets for a small team, stated honestly rather than aspirationally. If we are going to miss one,
we will tell you before the deadline rather than after it.

We support **coordinated disclosure**: we ask for a reasonable embargo while a fix ships, we will not threaten
or take legal action over good-faith research, and we will credit you in the advisory unless you prefer
otherwise. We do not currently operate a paid bug-bounty program.

## Supported versions

Tunnex is **pre-1.0 and in active development.** Security fixes land on the **latest release and `main`**.
There are **no long-term-support branches and no backports to older tags** — the upgrade path is
**forward-only** by design (see `docs/S11-decisions.md` D1), and the supported remediation for any release is
to move forward to the fixed one.

| Version | Supported |
|---|---|
| latest release + `main` | ✅ |
| any earlier tag | ❌ — upgrade to the latest release |

## What is in scope

The things an attacker would actually go after, and where we will act on a report:

- **The control-plane API** (`apps/api`) — authentication, session handling, RBAC and permission gating,
  tenant isolation (cross-organization access of any kind), the audit trail's integrity.
- **The policy engine** — any path that lets traffic through that policy should deny, or that lets a
  principal reach a resource they hold no grant for.
- **The data-plane agent** (`apps/node`) — the WireGuard/OpenVPN configuration it renders and the firewall
  rules it programs, including any bypass of the enforcement chain.
- **The privilege helper** ([tunnex-client/apps/helper](https://github.com/tunnexio/tunnex-client/tree/main/apps/helper)) — it runs as root. Caller authentication, the typed protocol, the
  kill-switches (macOS pf, Windows WFP), and any local privilege escalation through it.
- **Key and secret handling** — the sealed master key, the certificate authorities, device and machine
  credentials, one-time-secret ceremonies, anything that leaks a secret into a log, an API response, or a
  backup that should not carry it.
- **The GitOps operator** (`apps/operator`) and the machine-credential principal.
- **The desktop client** ([tunnex-client/apps/client](https://github.com/tunnexio/tunnex-client/tree/main/apps/client)) — token handling, the preload boundary, navigation and CSP locks.

## What is out of scope

Not because these do not matter, but because a report will not lead to a fix here:

- **Findings that require an already-compromised host.** A root-level attacker on a gateway can subvert its
  data plane; that is the trust model, not a vulnerability.
- **Client-reported device posture.** Posture checks (OS version, disk encryption, EDR) are self-reported and
  **spoofable by a compromised device** — stated plainly in the product. Treat posture as defense-in-depth,
  never as attestation. A demonstration that a compromised device can misreport is a known property.
- **Denial of service through resource exhaustion** on a self-hosted deployment the reporter controls.
- **Missing hardening headers or TLS configuration on a deployment's own reverse proxy** where the operator
  controls that configuration. (Defaults we ship *are* in scope.)
- **Vulnerabilities in a base image with no upstream fix available.** We scan for these and track them
  (advisory tier), but we cannot fix what upstream has not.
- **Social engineering, physical access, or attacks against Tunnex's own project infrastructure** rather than
  the shipped software.
- **Automated scanner output with no demonstrated impact.** We read these, but a report with a reproduction
  moves far faster.

## Exposure model — what listens, and to whom

Every network surface Tunnex opens, and the default that governs it. Defaults are chosen so that the unsafe
configuration requires a deliberate act, not so that the safe one requires reading documentation.

| Surface | Default bind | Auth | Notes |
|---|---|---|---|
| Control-plane API | `:8080` (behind your TLS terminator) | session cookie or bearer; RBAC per org | The public surface. |
| Agent control channel | `:8443` | **mutual TLS** — the client certificate identifies the node | Authorizes by certificate, never by anything in the request body. |
| **Metrics + readiness** | **`127.0.0.1:9090`** | **none — the bind address is the control** | See below. |
| Gateway (node agent) | WireGuard `:51820/udp`, OpenVPN if enabled | cryptographic peer identity | No management surface is exposed by the agent. |

**Metrics (`/metrics`, `/readyz`) bind to loopback by default and are not authenticated.** This is the
Prometheus convention, and the reasoning is worth stating: an authenticated public endpoint depends on the
auth being right, whereas an endpoint that is not reachable cannot be wrong. On a VM, a metrics listener bound
to `0.0.0.0` is internet-reachable the moment a security group is loose — so remote scraping is **opt-in by
explicit configuration** (`TUNNEX_METRICS_ADDR`), pointed at a private interface, or at `0.0.0.0` inside a
Kubernetes pod whose Service is deliberately not exposed. A wildcard bind is permitted but never silent: the
control plane logs `metrics_listener_wildcard_bind` naming the exposure. The metric set is fleet-level counts
by health kind — it answers *how many* gateways are degraded, never *which*, and carries no org, node, user
or device labels.

**The in-cluster gateway's Kubernetes RBAC** is the same principle on the other side: its ServiceAccount is
granted read-only `get/list/watch` on `services` and `endpointslices` and nothing else — it reads Service
endpoints to program its DNAT, and **cannot read Secrets, cannot write, and cannot escalate**. The GitOps
operator is narrower still: it holds no data-plane privilege at all and reaches Tunnex only over HTTPS with a
machine credential, so every invariant it depends on is enforced by the control-plane handlers rather than
trusted to the operator.

## How we build

Context for what a reporter can assume about the code, not a security claim in itself:

- Every merge runs `govulncheck` across all Go modules and CodeQL over Go and TypeScript; **high and critical
  findings block the merge.** Base-image scanning (Trivy) and OpenSSF Scorecard run advisory.
- Release tags publish an **SBOM (SPDX)** and a **keyless cosign signature** for the source tree and the
  service images.
- Security-relevant behavior is proven on real hardware, not only in unit tests: the kill-switches, the
  enforcement chain, and revocation are verified on the wire in per-story box walks recorded under `docs/`.

An **independent third-party security assessment has not yet been performed.** We will publish the result when
one has been, and we will say so plainly here until then.
