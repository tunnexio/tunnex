# Non-human enrollment: competitor source review

Research date: 2026-09-09. This is a source review and design recommendation,
not a deployment test or a claim of full competitor parity.

The resulting Tunnex proposal is in
[Workload identity decisions](S-AI-workload-identity-decisions.md).

## Conclusion

Use the familiar **scoped enrollment key → independent instance identity →
centrally assigned policy** pattern. Offer single-use keys for individual installs
and reusable keys for deployments that create replacements. Bind each key to one
stable Tunnex workload; every replica inherits that workload's current AI policy.
OIDC/federation is an optional automation path, not a prerequisite for autoscaling.

The key is an introduction credential, not the credential sent with model calls.
Existing instances authenticate independently after enrollment. This makes host
replacement a new instance joining the same policy target, rather than an attempt
to resurrect a deleted machine identity.

## Source pins and inspection boundary

These are the exact repository HEADs fetched for this review. Links use immutable
commit IDs; do not interpret a snapshot of `main` as a released-version promise.

| Project | Inspected commit | Scope |
| --- | --- | --- |
| NetBird | `d2e62e358a07333462fa1e60587ef2964af85b1f` | Setup-key model, creation, peer enrollment/login and ephemeral lifecycle in the management server. |
| Tailscale | `3945b82f8a9550b54c33e61d4ed2227862d53e8a` | CLI/client, wire types, OAuth auth-key creation and optional identity-token acquisition. Hosted control-service behavior is supported by official docs, not an inspection of its private server implementation. |
| Headscale | `38722e5eebe401b61cfed89a99773e4a5ece4440` | Independent open-source coordination server: pre-auth-key persistence, atomic consumption, registration ownership and ephemeral cleanup. It is not Tailscale's hosted backend. |

Public source was cloned into temporary research directories. No competitor
service was started, account connected, production key created or source vendored
into Tunnex. Tunnex baseline: `ai-improvement` at `db683fa5`, with the pre-existing
uncommitted MCP work inspected but preserved.

## NetBird: setup keys and automatic grouping

The [`SetupKey` type and generator](https://github.com/netbirdio/netbird/blob/d2e62e358a07333462fa1e60587ef2964af85b1f/management/server/types/setupkey.go#L17-L54)
contain reusable/single-use type, expiry, revoked state, usage count/limit,
auto-assigned group IDs and ephemeral enrollment. Generation stores a SHA-256
digest and masked identifier while returning the secret at creation.

[`handleSetupKeyAddedPeer`](https://github.com/netbirdio/netbird/blob/d2e62e358a07333462fa1e60587ef2964af85b1f/management/server/peer.go#L708-L734)
resolves the account, groups and ephemeral setting from the server's key record.
[`AddPeer`](https://github.com/netbirdio/netbird/blob/d2e62e358a07333462fa1e60587ef2964af85b1f/management/server/peer.go#L886-L945)
adds group membership and rechecks key validity under a database update lock before
incrementing use. That transaction is the useful pattern for concurrent scale-out;
an earlier validation alone would not protect a usage limit.

[`LoginPeer`](https://github.com/netbirdio/netbird/blob/d2e62e358a07333462fa1e60587ef2964af85b1f/management/server/peer.go#L1138-L1177)
first finds the peer by its public key; an unknown peer takes the introduction
path. The [ephemeral manager](https://github.com/netbirdio/netbird/blob/d2e62e358a07333462fa1e60587ef2964af85b1f/management/internals/modules/peers/ephemeral/manager/ephemeral.go)
tracks disconnect deadlines, cancels pending cleanup on connection, and reloads
tracked peers on startup.

Official documentation confirms that expired/revoked setup keys stop new
enrollment while existing peers remain connected; auto-groups apply to new joins.
Its documented ephemeral offline interval is ten minutes. Those are NetBird
semantics, not timing defaults to import into an HTTP gateway.
[Setup-key documentation](https://docs.netbird.io/manage/peers/register-machines-using-setup-keys)

**Apply to Tunnex:** workload-scoped keys, atomic use accounting, automatic policy
binding, separate enrollment and runtime lifecycles. Keep the workload association
immutable on an issued key; policy changes affect the stable workload directly.

## Tailscale: tags, independent node keys and automated auth keys

The [key capability types](https://github.com/tailscale/tailscale/blob/3945b82f8a9550b54c33e61d4ed2227862d53e8a/client/tailscale/keys.go#L23-L39)
express reusable, ephemeral, preauthorization and tag settings. The
[`up` command](https://github.com/tailscale/tailscale/blob/3945b82f8a9550b54c33e61d4ed2227862d53e8a/cmd/tailscale/cli/up.go#L99-L106)
accepts file-backed credentials. The
[control client](https://github.com/tailscale/tailscale/blob/3945b82f8a9550b54c33e61d4ed2227862d53e8a/control/controlclient/direct.go#L692-L770)
generates/preserves a private node key and sends its public key separately from
the supplied auth key in registration.

The [OAuth-key feature](https://github.com/tailscale/tailscale/blob/3945b82f8a9550b54c33e61d4ed2227862d53e8a/feature/oauthkey/oauthkey.go#L23-L86)
recognizes an OAuth client credential, obtains API access and creates a fresh
non-reusable auth key with requested tags. Tags are required by this client path;
the server-side scope restriction is documented in
[OAuth client registration](https://tailscale.com/docs/features/oauth-clients).
This separates the bootstrap automation credential from the generated join key.

Official [auth-key documentation](https://tailscale.com/docs/features/access-control/auth-keys)
distinguishes one-off/reusable keys and auth-key expiry from node-key expiry.
An auth key expiring does not itself disconnect enrolled nodes. Tagged-device
expiry defaults are a Tailscale product choice; Tunnex need not copy them.

The inspected CLI also has an
[optional federation hook](https://github.com/tailscale/tailscale/blob/3945b82f8a9550b54c33e61d4ed2227862d53e8a/cmd/tailscale/cli/up.go#L668-L688)
and [provider-token helpers](https://github.com/tailscale/tailscale/blob/3945b82f8a9550b54c33e61d4ed2227862d53e8a/wif/wif.go).
These demonstrate an advanced path alongside ordinary auth keys; they do not
justify making a specific cloud's metadata service mandatory in Tunnex.

**Apply to Tunnex:** protected file input, server-assigned workload binding,
independent per-instance keys, and optional automated short-lived enrollment.
Do not copy the WireGuard/Noise dataplane into model authentication.

## Headscale: server-side ownership and concurrency evidence

The [pre-auth-key record](https://github.com/juanfont/headscale/blob/38722e5eebe401b61cfed89a99773e4a5ece4440/hscontrol/types/preauth_key.go#L39-L78)
separates tagged identity from its human creator. Its validation distinguishes
revoked, expired, reusable and consumed keys. The
[database implementation](https://github.com/juanfont/headscale/blob/38722e5eebe401b61cfed89a99773e4a5ece4440/hscontrol/db/preauth_keys.go)
stores a prefix and password hash for newly created keys and uses a conditional
update when consuming a single-use key.

[New-node registration](https://github.com/juanfont/headscale/blob/38722e5eebe401b61cfed89a99773e4a5ece4440/hscontrol/state/state.go#L1928-L1965)
copies key-owned tags; it does not permit that path to substitute client-requested
tags. [Creation and key consumption](https://github.com/juanfont/headscale/blob/38722e5eebe401b61cfed89a99773e4a5ece4440/hscontrol/state/state.go#L2023-L2041)
share a transaction. Existing authenticated state has a
[separate registration path](https://github.com/juanfont/headscale/blob/38722e5eebe401b61cfed89a99773e4a5ece4440/hscontrol/auth.go#L77-L100);
the more detailed [pre-auth path](https://github.com/juanfont/headscale/blob/38722e5eebe401b61cfed89a99773e4a5ece4440/hscontrol/state/state.go#L2458-L2557)
distinguishes restart, expiry, rotation and ownership changes.

The [ephemeral collector](https://github.com/juanfont/headscale/blob/38722e5eebe401b61cfed89a99773e4a5ece4440/hscontrol/db/node.go#L512-L536)
uses a generation check to discard stale scheduled deletion after reconnection.
For Tunnex, that check must be tied to shared durable state across gateway/API
replicas; a process-local timer is not the complete distributed implementation.

**Apply to Tunnex:** retain creator for audit, attach authority to the workload;
never accept arbitrary group/tag claims from the runtime. Include lost-response,
same-key retry, concurrent consumption and cleanup-versus-renewal tests.

## Supporting comparisons

- [LiteLLM service accounts](https://docs.litellm.ai/docs/proxy/service_accounts)
  support the product concept of production credentials independent of an
  individual user. Tunnex additionally needs replaceable instance attribution.
- [Teleport Machine ID](https://goteleport.com/docs/reference/architecture/machine-id-architecture/)
  supports separating permanent bot identity from runtime instances and joining
  from renewal. Its broader platform is not required for Tunnex's first slice.
- [Vault AppRole introduction](https://developer.hashicorp.com/vault/docs/auth/approle/approle-pattern)
  is a useful optional deployer-delivered bootstrap pattern. It is not mandatory
  infrastructure for a reusable-key deployment.
- [OAuth security guidance](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.5)
  supports asymmetric client authentication after enrollment. This is a Tunnex
  protocol recommendation, not a claim that the three networking products use
  OAuth client assertions for their dataplane identities.

## What the simplified Tunnex contract should be

| Event | Intended Tunnex behavior |
| --- | --- |
| First replica starts | Valid enrollment key creates an independent instance under its fixed workload. |
| Ten replicas start together | Reusable key accepts separate instances, within configured limits; all receive the same current workload policy. |
| Process restarts with its own state | Use its existing instance credential; do not spend another enrollment use. |
| Machine is replaced | New keypair/instance, same workload and policy. Never bake instance state into an image. |
| Enrollment key expires or is revoked | Refuse new instances; existing instance authentication remains separate. Rotate deployment bootstrap before expiry. |
| One instance is revoked | That credential loses access. A retained reusable enrollment key could still create a different instance; containment must also revoke the compromised enrollment key or disable the workload. |
| Workload disabled | Refuse new enrollment, token issuance and gateway admissions for all its instances. |
| Instance goes quiet | Observe authenticated renewals, not just model traffic; retire ephemeral instances using a documented grace interval and a renewal-safe transaction. |

A scoped reusable key is intentionally a bootstrap secret. Possession permits
new instances of that workload until expiry/revocation/limits. It is not secretless
attestation, and a rotation process is required for uninterrupted future joins.
Where an organization already operates a trusted issuer, federation can remove
this shared bootstrap secret from application deployments.

## Reuse and licensing boundary

This proposal adopts behavior and documents provenance; it copies no competitor
implementation. NetBird's [root license](https://github.com/netbirdio/netbird/blob/d2e62e358a07333462fa1e60587ef2964af85b1f/LICENSE)
explicitly places `management/` under AGPLv3. Tailscale and Headscale's inspected
root licenses are BSD-3-Clause. Any later literal reuse needs a file-level license
and notice check; implement the core pattern within Tunnex's own contracts rather
than importing an entire competitor's identity or networking service.
