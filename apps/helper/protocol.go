// Package helper is the Tunnex privileged tunnel helper (S6.3).
//
// It is a SEPARATE privileged process (not Electron, not Node) that owns the one
// operation the desktop app cannot do unprivileged: bring a WireGuard tunnel
// up/down and configure its interface. The app (Electron main) drives it over a
// local IPC channel using the typed protocol in this file — a fixed verb set, no
// generic passthrough (same allowlist posture as the S6.1 preload). The verb set
// IS the privileged attack surface; keep it minimal.
package helper

// ProtocolVersion is bumped on any wire-incompatible change. Both sides send it on
// every message so a mismatched app/helper pair fails fast and loud rather than
// misparsing. It is intentionally independent of the app version.
const ProtocolVersion = 1

// AuthMode is how the helper authenticates that its caller is the REAL Tunnex app
// and not another local process. It rides on every request FROM DAY ONE so that
// the S6.5b hardening (crypto code-signing identity pinning) is a negotiated MODE
// UPGRADE on this same protocol, never a breaking change.
type AuthMode string

const (
	// AuthModePathCheck is the INTERIM mode for unsigned builds: verify the
	// caller's executable lives inside the app's install dir. Weaker than pinning
	// (see auth.go for the threat model). Retire trigger = S6.5b.
	AuthModePathCheck AuthMode = "path_check"
	// AuthModeCodeSigning is the S6.5b mode: pin the caller's code-signing identity
	// (macOS XPC peer requirement / Windows Authenticode). Not yet compiled in.
	AuthModeCodeSigning AuthMode = "code_signing"
)

// authRank orders modes by strength. 0 = unknown/unsupported.
func authRank(m AuthMode) int {
	switch m {
	case AuthModePathCheck:
		return 1
	case AuthModeCodeSigning:
		return 2
	default:
		return 0
	}
}

// Negotiate returns the auth mode the helper will ENFORCE for this connection, or
// an error if the client cannot meet the helper's enforced minimum.
//
// The helper enforces exactly the mode it has a verifier compiled for (`enforced`)
// — today path_check, at S6.5b code_signing. `clientMax` is the strongest mode the
// app supports. If the app is too weak for the helper's enforced mode we REFUSE
// (no silent downgrade): once the helper is signed and enforces code_signing, a
// stale path_check-only app is rejected and must update. That one-way ratchet is
// the whole point of carrying auth_mode from day one.
// NegotiateVersion checks wire-protocol compatibility and, on mismatch, names WHICH
// side is stale so the app can act. The helper is the long-lived root daemon; the app
// upgrades it (a new app version installs its bundled helper via the lifecycle —
// SMAppService / the Windows service). So:
//   - client > helper → the installed helper is OLD (app upgraded, helper didn't):
//     "helper_outdated" — the app should (re)install its bundled helper via the
//     lifecycle, then retry. This is the NORMAL upgrade path.
//   - client < helper → the app is OLD relative to a newer helper: "client_outdated" —
//     REFUSE (a stale app must not drive a newer helper; a downgrade-refused ratchet,
//     mirroring the auth-mode ratchet in Negotiate). Update the app.
//
// v1 is the only version today; this is the framework the first bump uses.
func NegotiateVersion(client, helper int) error {
	switch {
	case client == helper:
		return nil
	case client > helper:
		return &ProtocolError{Code: "helper_outdated", Msg: "the Tunnex helper is older than this app — reinstall to upgrade it"}
	default:
		return &ProtocolError{Code: "client_outdated", Msg: "this app is older than the installed Tunnex helper — update the app"}
	}
}

func Negotiate(clientMax, enforced AuthMode) (AuthMode, error) {
	if authRank(enforced) == 0 {
		return "", &ProtocolError{Code: "auth_mode_unsupported", Msg: "helper enforced auth mode is unknown"}
	}
	if authRank(clientMax) == 0 {
		return "", &ProtocolError{Code: "auth_mode_unsupported", Msg: "client auth mode is unknown"}
	}
	if authRank(clientMax) < authRank(enforced) {
		return "", &ProtocolError{Code: "auth_downgrade_refused", Msg: "client cannot meet the helper's required auth mode"}
	}
	return enforced, nil
}

// Verb is the closed set of operations the helper exposes. No arbitrary command,
// no config-file path, no "run this binary".
type Verb string

const (
	VerbTunnelUp   Verb = "tunnel_up"   // bring the tunnel up from a validated config
	VerbTunnelDown Verb = "tunnel_down" // tear the tunnel down (idempotent)
	VerbStatus     Verb = "status"      // read-only handshake/transfer stats
	// VerbPostureStatus (S7.5.3) reads device posture facts the app cannot read
	// unprivileged (FileVault/BitLocker state). STRICTLY READ-ONLY: no config, no
	// state change, no ownership — the privileged surface grows by reads only.
	// ADDITIVE at ProtocolVersion 1: an older helper answers unknown_verb and the
	// app degrades to reporting the fact ABSENT (never guessed) — a version bump
	// would instead refuse ALL verbs from a paired old helper, including tunnel_up.
	VerbPostureStatus Verb = "posture_status"
	// VerbSetResolvers (S8.4) installs domain-scoped resolvers so cross-site names
	// resolve to a remote site's internal DNS over the tunnel. The Resolvers list is
	// the COMPLETE desired set (full-sweep): the helper reconciles its OWNED resolver
	// files to match exactly — writes/updates the desired, removes owned-but-absent,
	// and NEVER touches foreign resolver files. An empty/nil list clears all owned
	// resolvers (the inert steady state). ADDITIVE at ProtocolVersion 1 like posture:
	// an old helper answers unknown_verb and the app fail-STATIC (tunnel stays up,
	// cross-site names just don't resolve) — DNS forwarding is never load-bearing for
	// the tunnel. macOS-only in v1 (/etc/resolver); Windows NRPT is S8.4b.
	VerbSetResolvers Verb = "set_resolvers"
	// VerbSetAllowedIPs (S8.5) LIVE-updates the tunnel peer's AllowedIPs to a COMPLETE desired set
	// (baked-stable ∪ current-declared-ranges, computed client-side) — the open-edition routed-subnets
	// push. Applied via a wireguard-go uapi update (update_only + replace_allowed_ips: the peer's keys +
	// endpoint are UNTOUCHED, no handshake reset, no tunnel bounce) plus an OS-route full-sweep. STATE-
	// CHANGING but NOT tunnel-owning (same class as set_resolvers): it never touches tunnel state, the
	// owner connection, or the kill-switch. Split-tunnel ONLY by structure — the kill-switch exists only
	// in full-tunnel, and a full-tunnel base (0.0.0.0/0) already subsumes every range, so the verb no-ops
	// there. ADDITIVE at ProtocolVersion 1 like posture/set_resolvers: an old helper answers unknown_verb
	// and the client fail-STATIC (routes just don't push).
	VerbSetAllowedIPs Verb = "set_allowed_ips"
	// VerbSetGatewayPeer (WF-A re-homing) LIVE-swaps the tunnel's gateway peer to a new active hub —
	// public key + endpoint — WITHOUT a bounce. A re-home is a peer SWAP (WG keys a peer by pubkey, and
	// the active hub's key differs from a standby's), so the helper adds the new peer with the CURRENT
	// peer's allowed_ips (routing preserved) and removes the old — the DEVICE IDENTITY (own key, address,
	// enrollment) and the kill-switch are UNTOUCHED. The dial is a routing FACT about the network, never
	// device identity — it rides the volatile channel, the never-re-fetch identity invariant holds. STATE-
	// CHANGING but NOT tunnel-owning (same class as set_allowed_ips): never touches the owner connection.
	// SPLIT-TUNNEL ONLY in v1: a full tunnel's endpoint host-route + kill-switch pass rule must move WITH
	// the peer, which is the D-WFA-4 carve-out (a separate slice) — the Supervisor refuses full-tunnel here.
	// ADDITIVE at ProtocolVersion 1 like posture/set_resolvers/set_allowed_ips: an old helper answers
	// unknown_verb and the client fail-STATIC (keeps its current peer; the re-home just doesn't apply).
	VerbSetGatewayPeer Verb = "set_gateway_peer"
)

func validVerb(v Verb) bool {
	return v == VerbTunnelUp || v == VerbTunnelDown || v == VerbStatus || v == VerbPostureStatus || v == VerbSetResolvers || v == VerbSetAllowedIPs || v == VerbSetGatewayPeer
}

// Request is one app→helper message. Config is REQUIRED for tunnel_up and must be
// nil otherwise (a config on a down/status request is rejected — no smuggling).
type Request struct {
	Version  int           `json:"version"`
	AuthMode AuthMode      `json:"auth_mode"`
	Verb     Verb          `json:"verb"`
	Config   *TunnelConfig `json:"config,omitempty"`
	// Resolvers is the full-sweep desired set for VerbSetResolvers only (nil elsewhere).
	Resolvers []ResolverForward `json:"resolvers,omitempty"`
	// AllowedIPs is the COMPLETE desired peer AllowedIPs set for VerbSetAllowedIPs only (nil elsewhere) —
	// the full baked-stable ∪ declared-ranges set, applied as a full-sweep (replace_allowed_ips).
	AllowedIPs []string `json:"allowed_ips,omitempty"`
	// GatewayPeer is the new active-hub peer for VerbSetGatewayPeer only (nil elsewhere) — the re-home
	// target (WF-A). The helper preserves the current peer's allowed_ips onto it; identity is untouched.
	GatewayPeer *GatewayPeer `json:"gateway_peer,omitempty"`
}

// GatewayPeer names a gateway to re-home onto (WF-A): its WireGuard public key and host:port endpoint.
// It carries NO key material of the device's own — only the peer's PUBLIC routing facts.
type GatewayPeer struct {
	PeerPublicKey string `json:"peer_public_key"`
	Endpoint      string `json:"endpoint"`
}

// ResolverForward is one domain-scoped resolver: names under Domain resolve via
// ResolverIP (a remote site's internal DNS, reachable over the tunnel). S8.4.
type ResolverForward struct {
	Domain     string `json:"domain"`
	ResolverIP string `json:"resolver_ip"`
}

// Response is one helper→app reply. Status is set only for a successful status/up;
// Posture only for a successful posture_status.
type Response struct {
	Version int            `json:"version"`
	OK      bool           `json:"ok"`
	Code    string         `json:"code,omitempty"`  // stable machine code on failure
	Error   string         `json:"error,omitempty"` // human message on failure
	Status  *TunnelStatus  `json:"status,omitempty"`
	Posture *PostureStatus `json:"posture,omitempty"`
}

// TunnelStatus is read-only live state (no secrets — never echoes keys).
type TunnelStatus struct {
	State            string `json:"state"` // "down" | "up" | "failed"
	Interface        string `json:"interface,omitempty"`
	LastHandshakeSec int64  `json:"last_handshake_sec,omitempty"` // unix seconds, 0 = never
	RxBytes          uint64 `json:"rx_bytes,omitempty"`
	TxBytes          uint64 `json:"tx_bytes,omitempty"`
}

// PostureStatus is read-only, locally-read device posture (S7.5.3). No secrets.
// A nil field means the helper COULD NOT DETERMINE that fact (query failed /
// unparseable output): it is reported absent upstream, never guessed — the
// server's absence-never-blocks taxonomy depends on this honesty.
type PostureStatus struct {
	DiskEncrypted *bool `json:"disk_encrypted"` // FileVault (macOS) / BitLocker system drive (Windows)
}

// ProtocolError is a typed helper error carrying a stable machine code.
type ProtocolError struct {
	Code string
	Msg  string
}

func (e *ProtocolError) Error() string { return e.Code + ": " + e.Msg }

// ValidateRequest checks the envelope BEFORE any privileged work: version match,
// known auth mode + verb, and the config-presence rule. Field-level config
// validation is TunnelConfig.Validate (called by the up path). Returns a
// ProtocolError so the caller can surface a stable code.
func ValidateRequest(r *Request) error {
	if r == nil {
		return &ProtocolError{Code: "empty_request", Msg: "request is nil"}
	}
	if err := NegotiateVersion(r.Version, ProtocolVersion); err != nil {
		return err
	}
	if authRank(r.AuthMode) == 0 {
		return &ProtocolError{Code: "auth_mode_unsupported", Msg: "unknown auth mode"}
	}
	if !validVerb(r.Verb) {
		return &ProtocolError{Code: "unknown_verb", Msg: "unknown verb"}
	}
	if r.Verb == VerbTunnelUp && r.Config == nil {
		return &ProtocolError{Code: "config_required", Msg: "tunnel_up requires a config"}
	}
	if r.Verb != VerbTunnelUp && r.Config != nil {
		return &ProtocolError{Code: "unexpected_config", Msg: "config is only valid on tunnel_up"}
	}
	// Resolvers ride ONLY on set_resolvers — no smuggling a resolver write onto another
	// verb. An empty list on set_resolvers is legal (it means sweep to zero).
	if r.Verb != VerbSetResolvers && r.Resolvers != nil {
		return &ProtocolError{Code: "unexpected_resolvers", Msg: "resolvers are only valid on set_resolvers"}
	}
	// AllowedIPs ride ONLY on set_allowed_ips — no smuggling a routing change onto another verb.
	if r.Verb != VerbSetAllowedIPs && r.AllowedIPs != nil {
		return &ProtocolError{Code: "unexpected_allowed_ips", Msg: "allowed_ips are only valid on set_allowed_ips"}
	}
	// GatewayPeer rides ONLY on set_gateway_peer — no smuggling a peer swap onto another verb; and it is
	// REQUIRED there (a re-home with no target is nonsense). Its fields are validated as strictly as a
	// tunnel_up peer: a base64/32-byte key and a safe host:port (validEndpoint bars loopback/link-local/
	// metacharacters), so a typo can never steer the root helper's dial.
	if r.Verb != VerbSetGatewayPeer && r.GatewayPeer != nil {
		return &ProtocolError{Code: "unexpected_gateway_peer", Msg: "gateway_peer is only valid on set_gateway_peer"}
	}
	if r.Verb == VerbSetGatewayPeer {
		if r.GatewayPeer == nil {
			return &ProtocolError{Code: "gateway_peer_required", Msg: "set_gateway_peer requires a gateway_peer"}
		}
		if err := validKey(r.GatewayPeer.PeerPublicKey); err != nil {
			return &ProtocolError{Code: "bad_peer_key", Msg: err.Error()}
		}
		if !validEndpoint(r.GatewayPeer.Endpoint) {
			return &ProtocolError{Code: "bad_endpoint", Msg: "endpoint must be host:port"}
		}
	}
	return nil
}
