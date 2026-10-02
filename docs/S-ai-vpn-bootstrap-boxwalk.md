# Automatic VPN AI bootstrap: sandbox wire walk

Date: 2026-10-02. Branch: `codex/vpn-ai-bootstrap`.
Decision record: [S-ai-vpn-bootstrap-decisions.md](S-ai-vpn-bootstrap-decisions.md).
Sanitized observations and build provenance: [verification.json](../walk-artifacts/vpn-ai-bootstrap-20261002/verification.json).

## Scope and deployed candidate

The authorized sandbox runs the control plane and enrolled gateway on the same
VM. The review deployment replaced API, node and web images after backup. A later
API-only update supplied the short private inference URL for a user with one
active organization. These are review overlays on signed v0.1.37, not a newly
published release or proof that a new signed installer already contains the fix.
The paper commit alone does not identify the deployed code; the evidence records
both review source hashes and the replacement binary hashes.

At the final API-only comparison, the other eight containers and their images,
all service mounts, managed installation files, existing settings, transport
policy, provider state and model/grant inventory matched the recorded baselines.
The existing login session and Playground document both returned HTTP 200.
The separately authorized test-agent enrollment creates a new agent identity; it
is not part of that unchanged-inventory assertion.

## Wire observations

| Check | Observed result | Boundary |
| --- | --- | --- |
| Human VPN inference | The private short `/ai/v1` endpoint returned HTTP 200 with a chat completion. The user's existing Python script later exited 0 with an assistant response after the alias update. | Real connected human device and existing model grant; no new application or provider credential. |
| Force ordinary network interface | A request to the same private endpoint, explicitly bound to the laptop's non-VPN interface, timed out with curl status `000` and zero completed TCP connections. | This was an interface-bound refusal test; the desktop VPN was not physically disconnected. |
| Public identity forgery | Public AI request returned HTTP 401 `unauthenticated`. Post-alias anonymous admin and forged public AI/model/provider checks also returned 401. | Public paths did not accept supplied VPN identity headers. |
| Gateway restart | The recorded restart recovered. All nine project services ran; all eight configured health checks were healthy. | The edge service has no health check. This is recovery evidence, not a claim of zero downtime. |
| Isolated real WireGuard ingress | Kernel WireGuard test passed with IPv4 and IPv6 peers and a 288 KiB response. Ordinary and spoofed-source underlay ingress were denied; interface loss withdrew the listener. | An isolated network-namespace proof, not a live dual-stack cloud deployment. |
| Fresh managed AI Agent | Signed runtime bootstrap enrolled the new agent device; its system service was active and applied/WireGuard revisions converged to 1. | AI Agents is the nonhuman managed-runtime feature, separate from the human VPN inference listener. |
| Agent restart and model denial | Runtime restarted successfully with its WireGuard identity preserved. AI credential issuance without an agent model grant returned HTTP 403. | Enrollment did not create model access. Successful agent model inference was not exercised. |

The human inference and non-VPN-interface observations were captured by the
parent walk. The committed evidence retains their sanitized results, not the
user's script, completion body, host addresses or authentication material.

## Managed-agent bootstrap prerequisites

The test VM used WireGuard tools, curl, jq and CA certificates, plus its existing
`resolvconf` compatibility link to `resolvectl`. The requested `openresolv` package
was unavailable on Ubuntu 24.04, so that cloud-init package step failed. Enrollment
and runtime operation subsequently succeeded with the available resolver
compatibility; this is not a clean cloud-init result. The generated enrollment
command also requires `releaseverify`; it does not install these host
prerequisites itself.

The release verifier is not a standalone published release asset. For this walk,
only that binary was built from the original signed source with pinned Go 1.26.8
and copied to the test host. Its provenance is recorded separately from the review
API/node/web binaries. This preparation means the walk does **not** prove a
zero-prerequisite fresh-host installation.

The actual v0.1.37 manifest signature was verified against the installer-pinned
public key and expected source. The public manifest, both managed-runtime
architectures and the systemd unit returned HTTP 200; all three asset hashes
matched the signed manifest. No provider credential was copied to the agent.
An application using managed-agent AI access still needs an explicit agent-group
assignment and the existing runtime-credential exchange; a human group grant is
not an agent grant. Installing the Tunnex runtime does not install an AI
application or language framework.

## Outstanding acceptance

- **Private CP browser HTTPS remains unresolved.** TCP and small packets reach
  the private CP with working return-path NAT. Packet captures and size sweeps
  show size-dependent loss that stalls TLS. The exact failing outer component
  and a corrected effective MTU have not been proved. The edge also serves a
  public-address certificate and redirects HTTP to the public origin; packet
  sizing alone cannot supply a matching private-address certificate.
- **Separate CP/gateway and Kubernetes layouts still need live qualification.**
  Their packaging/contracts and isolated tests substitute for those wire walks.
  Trigger: acceptance of each layout before declaring universal bootstrap
  support. Same-host success is not evidence that co-location caused the original
  defect or that every other layout has passed.
- **Fresh-host agent dependencies need a supported delivery path.** Trigger:
  managed-agent bootstrap acceptance on a clean supported host, without an
  operator-built verifier or manually staged dependencies.
- **Physical VPN disconnect and live policy-revocation negatives remain distinct.**
  The interface-bound and isolated ingress tests substitute for those exact live
  cases. Trigger: final VPN AI release acceptance, including saved HTTP-policy
  refusal, withdrawn grants and revoked identities.
- **Positive managed-agent model access is still pending.** Trigger: an explicitly
  approved test model/group assignment, followed by inference and withdrawal.
- **Signed publication and upgrade acceptance are pending.** Trigger: the release
  containing this candidate, followed by an unmodified fresh install and upgrade.

Private CP transport diagnostics made no route, firewall, certificate or MTU
change. Working private AI inference does not establish private browser HTTPS.
