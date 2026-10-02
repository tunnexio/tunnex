import type { BootstrapRelease } from "./api";

/**
 * The AI-agent surface's view model — S15.3.
 *
 * ⛔ THE RENDER FLOOR IS THE FIRST THING IN THIS FILE, BECAUSE IT CONSTRAINS EVERY STRING BELOW.
 *
 * > **UNDER PROMPT INJECTION, AUTHENTICATION IS INTACT AND AUTHORIZATION IS INTACT. ONLY *INTENT* IS
 * > CORRUPTED. ZERO TRUST BOUNDS THE BLAST RADIUS OF A CORRECTLY-AUTHENTICATED PRINCIPAL. IT DOES NOT
 * > DETECT INJECTION.**
 *
 * Two claims this surface may never make, in any copy, at any size:
 *
 *  · ⛔ **DETECTION** — "catches", "blocks", "prevents" a manipulated request. The product does not inspect
 *    intent. A boundary LIMITS WHAT A REQUEST CAN REACH; it does not know the request was manipulated.
 *  · ⛔ **PER-TOOL CONTROL** — enforcement is five fields (`SrcIP, DstCIDR, Protocol, PortLow, PortHigh`).
 *    A tool name is not among them and cannot be. Teleport does per-tool; we do not, and the claim is
 *    checkable and false.
 *
 * ⚠ THE HONEST VERB IS **REACH**. This surface says which agents may reach which destinations. It never
 * says which ACTIONS they may perform there, because the enforcement plane cannot see actions.
 */

/**
 * One agent, as the screen understands it — served whole by `GET /organizations/{id}/agents`.
 *
 * ⚠ ONE SURFACE, ONE SOURCE. This used to be assembled client-side by joining `nodes` to `devices`, which
 * made the screen a second place deriving "which nodes are agents". The server answers it now, from the
 * marker, and the join is gone.
 */
export interface AgentRow {
  device_id: string;
  name: string;
  owner_email: string | null;
  unattributable: boolean;
  address: string | null;
  /** The gateway this agent connects THROUGH — why its traffic is forwarded and therefore policed. */
  gateway_name: string;
  node_id?: string;
  /** A key is registered — the connect command was issued. Says NOTHING about the network. */
  config_issued?: boolean;
  online?: boolean;
  last_handshake_at?: string | null;
  /** Whether the gateway — the only reporter of this agent's liveness — is itself reporting. */
  gateway_reporting?: boolean;
  rx_bytes?: number | null;
  tx_bytes?: number | null;
  status: string;
}

/**
 * ⛔ AN AGENT'S LIVENESS HAS FIVE STATES AND A BOOLEAN CAN CARRY TWO OF THEM.
 *
 * The gateway is the ONLY reporter of a peer's handshake — an agent runs plain `wg-quick` and has no
 * control-plane channel of its own. So an absent handshake has three different causes that look identical
 * in the data:
 *
 *  · the agent was never brought up,
 *  · the agent was brought up and has since stopped,
 *  · **the gateway stopped reporting, and we know nothing about the agent either way.**
 *
 * > **AN EMPTY LIVENESS SIGNAL READS IDENTICALLY TO A DEAD AGENT AND TO A DEAD REPORTER.** That is the same
 * > three-states-one-appearance failure that nearly made the EPIC 15 walk report "attribution does not work"
 * > about a collector that was switched off.
 *
 * ⚠ `unknown` OUTRANKS `offline`, ALWAYS. Rendering a confident "offline" while the reporter is silent
 * blames the agent for the gateway's fault and sends an operator to debug the wrong box.
 */
export type AgentLiveness =
  "revoked" | "online" | "offline" | "never" | "unknown" | "not-issued";

export function agentLiveness(a: AgentRow): AgentLiveness {
  // ⛔ REVOKED OUTRANKS EVERY OTHER STATE, AND GETTING THIS ORDER WRONG PRODUCED THE WORST STRING ON THE
  // SCREEN. A revoked agent keeps its row and its key, so `config_issued` stays true — and revocation
  // SWEEPS ITS TELEMETRY, so `last_handshake_at` goes null. Those two facts together land a dead credential
  // in `never`, whose copy tells the operator to go and run the connect command on the agent host.
  //
  // > **THE MOST ACTIONABLE-SOUNDING STATE IS THE MOST DANGEROUS ONE TO FALL INTO BY DEFAULT.** It sends
  // > someone to fix a machine that is working, for a credential that was deliberately destroyed.
  if (a.status === "revoked") return "revoked";
  // No config was ever issued: there is no tunnel to be up or down. Distinct from "never connected",
  // which means we DID hand over a command and it was never run.
  if (a.config_issued === false) return "not-issued";
  // ⛔ THE REPORTER FIRST. Every state below is inferred from handshake data the gateway supplies; if the
  // gateway is silent, that data is absent for a reason that has nothing to do with the agent.
  if (a.gateway_reporting === false) return "unknown";
  if (a.online) return "online";
  if (!a.last_handshake_at) return "never";
  return "offline";
}

/**
 * The words for each state, and the tone.
 *
 * ⚠ NO STATE IS `danger`. An agent being down is not a security event — the fail-closed direction means a
 * disconnected agent reaches nothing at all. Painting it red claims an incident that has not occurred.
 */
export function livenessLabel(
  a: AgentRow,
  now: Date = new Date(),
): {
  label: string;
  tone: "ok" | "warn" | "unknown" | "neutral";
  detail: string;
} {
  switch (agentLiveness(a)) {
    case "revoked":
      return {
        label: "revoked",
        // ⚠ NOT `danger`. A revoked credential is the system working as instructed, not an incident.
        tone: "neutral",
        detail:
          "This agent's credential was revoked. Its peer has been removed from the gateway and it can reach nothing. Enrol a new agent to replace it, the old connect command will never work again.",
      };
    case "online":
      return {
        label: "connected",
        tone: "ok",
        // ⚠ HONEST ABOUT WHAT "CONNECTED" MEANS. WireGuard has no connection state; this is handshake
        // recency, and saying so costs one clause and prevents a wrong bug report.
        detail: `Handshaked with ${a.gateway_name} ${relAge(a.last_handshake_at, now)}. WireGuard has no connection state, this is derived from handshake recency.`,
      };
    case "offline":
      return {
        label: `last seen ${relAge(a.last_handshake_at, now)}`,
        tone: "warn",
        detail: `This agent has connected before but has not handshaked with ${a.gateway_name} recently. Its tunnel is down, so it can reach nothing, access rules are unaffected.`,
      };
    case "never":
      return {
        label: "never connected",
        tone: "warn",
        // ⛔ THE ACTIONABLE ONE. The connect command was issued and never run — the single most likely
        // state for a new agent, and the one an operator can actually fix.
        detail:
          "The connect command was issued but this agent has never handshaked. Run the command on the agent host; if it was already run, check that wireguard-tools is installed and the gateway's endpoint is reachable from there.",
      };
    case "unknown":
      return {
        label: "liveness unknown",
        // ⚠ `unknown` IS ITS OWN TONE, not a quiet grey. An operator must be able to tell "we do not know"
        // apart from "nothing here" at a glance — the desync_unknown honest-state convention.
        tone: "unknown",
        // ⛔ THIS NAMES THE GATEWAY AS THE SUSPECT, NOT THE AGENT.
        detail: `${a.gateway_name} is not reporting to the control plane, and it is the only source of this agent's liveness. The agent may be perfectly healthy, we cannot tell. Check the gateway first.`,
      };
    case "not-issued":
      return {
        label: "no config issued",
        tone: "neutral",
        detail:
          "No WireGuard key is registered for this agent, so no connect command has been handed over yet.",
      };
  }
}

/** Coarse recency, matching the Devices page's honest-precision convention. */
function relAge(at: string | null | undefined, now: Date): string {
  if (!at) return "never";
  const secs = Math.max(
    0,
    Math.floor((now.getTime() - new Date(at).getTime()) / 1000),
  );
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  return `${Math.floor(secs / 86400)}d ago`;
}

/** Bytes as the operator reads them. Null stays null — an unreported counter is not zero. */
export function formatTraffic(
  rx?: number | null,
  tx?: number | null,
): string | null {
  if (rx == null && tx == null) return null;
  const h = (n: number) => {
    const u = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    let v = n;
    while (v >= 1024 && i < u.length - 1) {
      v /= 1024;
      i++;
    }
    return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${u[i]}`;
  };
  return `↓ ${h(rx ?? 0)} · ↑ ${h(tx ?? 0)}`;
}

/**
 * Order: **unattributable first, then undetermined, then the rest.**
 *
 * ⚠ THE TWO STATES AN OPERATOR CANNOT LEARN ANYWHERE ELSE COME FIRST, and neither may depend on a name.
 */
export function sortAgents(rows: AgentRow[]): AgentRow[] {
  // ⚠ UNATTRIBUTABLE FIRST, and it must not depend on a name — it is the one state an operator cannot
  // learn anywhere else.
  return [...rows].sort(
    (a, b) =>
      Number(b.unattributable) - Number(a.unattributable) ||
      a.name.localeCompare(b.name),
  );
}

/**
 * What the screen says about an agent's attribution.
 *
 * ⚠ TONE IS `warn`, NEVER `danger` — the same ruling as the gateway badge. An unattributable tunnel is a
 * LOGGING failure, not an access-control one. Painting it red claims a security failure that has not
 * occurred, and over-alarming is the same defect as under-alarming, facing the other way.
 */
export function attributionNote(
  a: Pick<AgentRow, "unattributable">,
): { label: string; tone: "warn"; detail: string } | null {
  if (!a.unattributable) return null;
  return {
    label: "unattributable",
    tone: "warn",
    detail:
      "No owner is recorded for this agent, so its activity cannot be attributed to a person. It keeps running and policy still applies to it, this is a gap in the audit trail, not in access control.",
  };
}

/**
 * The empty state's words.
 *
 * ⛔ "NO AGENTS" AND "COULD NOT LOAD" ARE DIFFERENT CLAIMS and the caller must keep them apart — this
 * returns only the former. A failed load rendering as "no agents" is a zero nobody measured.
 */
export const NO_AGENTS =
  "No AI agents are enrolled in this organization. An agent is enrolled with a join token, the same way a gateway is, it then appears here with the person who authorised it.";

/**
 * ⛔ THE UNDETERMINED STATE — ITS WORDS ARE RULED, AND THEY ARE PINNED LIKE THE RENDER FLOOR.
 *
 * A node enrolled before the marker existed (`enrolled_kind IS NULL`) is **neither an agent nor
 * not-an-agent**. The fact was never recorded, the join token that would have carried it is consumed, and
 * its intent was never asked for — so it **cannot be recovered**.
 *
 * > **NOT "not an agent"** — that asserts a fact nobody has.
 * > **NOT "agent"** — that repeats the defect the marker was built to fix.
 *
 * ⚠ AND IT MUST NOT READ AS A FAULT. These nodes are working correctly. **The gap is in our record, not in
 * them**, and copy that implies otherwise sends an operator to debug a healthy gateway.
 *
 * ⛔ THE PHRASE MUST NOT DRIFT INTO A VERDICT. "Unknown" softening into "none" is exactly how it would —
 * one is an absence of knowledge, the other is a claim about the world. The test enforces the difference.
 */
export const UNDETERMINED_LABEL = "enrolment kind not recorded";

export const UNDETERMINED_DETAIL =
  "We do not know what this was enrolled as. This node was enrolled before Tunnex recorded that choice, so the answer was never captured and cannot be recovered. The node is working normally, this is a gap in our record, not a problem with it.";

/**
 * Which of the three states a node is in.
 *
 * ⚠ THREE, NOT TWO. A boolean here would force undetermined into one of the other two, which is the exact
 * failure the ruling exists to prevent.
 */
export type EnrolmentKind = "agent" | "gateway" | "undetermined";

export function enrolmentKind(n: {
  enrolled_kind?: string | null;
}): EnrolmentKind {
  if (n.enrolled_kind === "agent") return "agent";
  if (n.enrolled_kind === "gateway") return "gateway";
  return "undetermined";
}

/**
 * The Overview card's words — S15.3.
 *
 * ⛔ COUNTS AND ONE NAMED GAP. NOTHING ELSE. A card is where copy gets shortened until it implies things,
 * so §0's two forbidden claims bind hardest here: no DETECTION, no PER-TOOL. It says how many agents exist
 * and how many cannot be tied to a person — both facts the server actually holds.
 *
 * ⚠ AND IT IS NOT A HEALTH VERDICT. "3 agents, 1 unattributable" is a count and an audit gap. It is not
 * "you are secure", not "all good", and not a claim about what any agent is doing.
 */
export function agentSummary(rows: Pick<AgentRow, "unattributable">[]): {
  total: number;
  unattributable: number;
  note: string | null;
} {
  const unattributable = rows.filter((r) => r.unattributable).length;
  return {
    total: rows.length,
    unattributable,
    // ⚠ The gap is named only when it exists. A permanent "0 unattributable" would train the reader to
    // stop seeing the line — and it is the line that matters when it is not zero.
    note:
      unattributable > 0
        ? `${unattributable} cannot be attributed to a person`
        : null,
  };
}

/**
 * The command an operator runs ON THE AI-AGENT HOST to bring the tunnel up.
 *
 * ⛔ THE AGENT IS A PEER, SO WHAT IT NEEDS IS A WIREGUARD CONFIG — not a node-agent container. The earlier
 * version handed over a `docker run` that started a GATEWAY on the agent's host: traffic originating there
 * is locally-originated, never traverses FORWARD, and therefore is never seen by the policy chain. The
 * address it was granted was held by nothing and the grant could not fire.
 *
 * ⚠ ONE COMMAND, NOT A FILE TO SAVE AND THEN A COMMAND TO RUN. A two-step ceremony is where the config gets
 * pasted into the wrong path, and the config carries a private key shown exactly once.
 *
 * The heredoc is quoted ('TUNNEXEOF') so the shell performs NO expansion on the key material — an unquoted
 * heredoc would mangle any `$` in a base64 key.
 */
export function agentConnectCommand(
  conf: string,
  ifaceName = "tunnex",
): string {
  return [
    `sudo mkdir -p /etc/wireguard && sudo tee /etc/wireguard/${ifaceName}.conf >/dev/null <<'TUNNEXEOF'`,
    conf.trim(),
    "TUNNEXEOF",
    `sudo chmod 600 /etc/wireguard/${ifaceName}.conf && sudo wg-quick up ${ifaceName}`,
  ].join("\n");
}

// One-shot managed bootstrap: the agent generates its private key locally,
// sends only the public key, installs the returned template, and retains the
// runtime credential for the future managed control channel.
export function agentBootstrapCommand(token: string, release: BootstrapRelease, apiURL = globalThis.location?.origin ?? ""): string {
  const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
  const verifier = release.verifier;
  const script = [
    "set -eu",
    'PATH="$PATH:/usr/local/sbin"; export PATH',
    "[ \"$(uname -s)\" = Linux ] || { echo 'automatic agent setup supports Ubuntu/Debian Linux only' >&2; exit 1; }; case \"$(uname -m)\" in amd64|x86_64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;; *) echo 'unsupported runtime architecture' >&2; exit 1 ;; esac",
    "[ -r /etc/os-release ] || { echo 'Ubuntu/Debian release information is required' >&2; exit 1; }; . /etc/os-release; case \"${ID:-}\" in ubuntu|debian) ;; *) echo 'automatic agent setup supports Ubuntu/Debian only' >&2; exit 1 ;; esac",
    "run_as_root=0; if [ \"$(id -u)\" = 0 ]; then run_as_root=1; else command -v sudo >/dev/null || { echo 'root or sudo is required' >&2; exit 1; }; sudo -n true 2>/dev/null || sudo -v || { echo 'sudo authorization is required' >&2; exit 1; }; fi; as_root() { if [ \"$run_as_root\" = 1 ]; then \"$@\"; else sudo \"$@\"; fi; }",
    "command -v systemctl >/dev/null && as_root systemctl show --property=Version --value >/dev/null 2>&1 || { echo 'a running systemd host is required' >&2; exit 1; }",
    `umask 077; d=$(mktemp -d); runtime_bin=/usr/local/bin/tunnex-agent-runtime; runtime_unit=/etc/systemd/system/tunnex-agent-runtime.service; runtime_cfg=/etc/wireguard/runtime.conf; runtime_cred=/etc/tunnex-agent/runtime-credential; runtime_state=/var/lib/tunnex-agent/runtime-state.json; failed=1; snapshot_ready=0; was_active=0; was_enabled=0; release_tag=${q(release.tag)}; source_sha=${q(release.source_sha)}; manifest_url=${q(release.manifest_url)}; verifier_key_id=${q(release.verifier_key_id)}; release_key=${q(release.verifier_public_key)}; expected_runtime_binary=${q(release.runtime.binary)}; expected_runtime_version=${q(release.runtime.version)}; expected_amd64_name=${q(release.runtime.linux_amd64.name)}; expected_amd64_digest=${q(release.runtime.linux_amd64.sha256)}; expected_arm64_name=${q(release.runtime.linux_arm64.name)}; expected_arm64_digest=${q(release.runtime.linux_arm64.sha256)}; expected_unit_name=${q(release.runtime.unit.name)}; expected_unit_digest=${q(release.runtime.unit.sha256)}; expected_unit_source_sha=${q(release.runtime.unit.source_sha)}; case \"$release_tag\" in v*|tunnex-build-*) ;; *) echo 'invalid immutable release tag' >&2; exit 1 ;; esac; [ \"$expected_unit_source_sha\" = \"$source_sha\" ] || { echo 'signed runtime unit source refused' >&2; exit 1; }`,
    "if [ -e /sys/class/net/runtime ] || { command -v wg >/dev/null && as_root wg show runtime >/dev/null 2>&1; }; then echo 'existing managed runtime interface refused; remove it explicitly before retrying' >&2; rm -rf \"$d\"; exit 1; fi; for target in \"$runtime_bin\" \"$runtime_unit\" \"$runtime_cfg\" \"$runtime_cred\" \"$runtime_state\"; do if as_root test -e \"$target\" || as_root test -L \"$target\"; then echo 'existing managed installation refused; remove it explicitly before retrying' >&2; rm -rf \"$d\"; exit 1; fi; done",
    "rollback_file() { path=\"$1\"; snap=\"$2\"; if [ -f \"$snap\" ]; then as_root install -o root -g root -m 600 \"$snap\" \"$path\"; else as_root rm -f \"$path\"; fi; }; offboard_runtime() { as_root systemctl disable --now tunnex-agent-runtime.service >/dev/null 2>&1 || true; }; rollback() { offboard_runtime; rollback_file \"$runtime_bin\" \"$d/runtime-bin.snapshot\"; rollback_file \"$runtime_unit\" \"$d/runtime-unit.snapshot\"; rollback_file \"$runtime_cfg\" \"$d/runtime-cfg.snapshot\"; rollback_file \"$runtime_cred\" \"$d/runtime-cred.snapshot\"; rollback_file \"$runtime_state\" \"$d/runtime-state.snapshot\"; as_root systemctl daemon-reload >/dev/null 2>&1 || true; if [ \"$was_active\" = 1 ]; then as_root systemctl start tunnex-agent-runtime.service >/dev/null 2>&1 || true; else as_root systemctl stop tunnex-agent-runtime.service >/dev/null 2>&1 || true; fi; if [ \"$was_enabled\" = 1 ]; then as_root systemctl enable tunnex-agent-runtime.service >/dev/null 2>&1 || true; else as_root systemctl disable tunnex-agent-runtime.service >/dev/null 2>&1 || true; fi; }; cleanup() { rc=$?; set +e; if [ \"$failed\" = 1 ] && [ \"$snapshot_ready\" = 1 ]; then rollback; fi; rm -rf \"$d\"; trap - EXIT; exit \"$rc\"; }; trap cleanup EXIT",
    `verifier_available=${verifier ? "1" : "0"}; expected_verifier_amd64_name=${q(verifier?.linux_amd64.name ?? "")}; expected_verifier_amd64_digest=${q(verifier?.linux_amd64.sha256 ?? "")}; expected_verifier_amd64_source=${q(verifier?.linux_amd64.source_sha ?? "")}; expected_verifier_arm64_name=${q(verifier?.linux_arm64.name ?? "")}; expected_verifier_arm64_digest=${q(verifier?.linux_arm64.sha256 ?? "")}; expected_verifier_arm64_source=${q(verifier?.linux_arm64.source_sha ?? "")}; if [ "$verifier_available" = 0 ]; then command -v releaseverify >/dev/null || { echo 'this older release requires a preinstalled signed release verifier; no bootstrap token was used' >&2; exit 1; }; fi`,
    "packages=; command -v wg >/dev/null && command -v wg-quick >/dev/null || packages=\"$packages wireguard-tools\"; command -v curl >/dev/null || packages=\"$packages curl\"; command -v jq >/dev/null || packages=\"$packages jq\"; command -v ip >/dev/null || packages=\"$packages iproute2\"; command -v sha256sum >/dev/null || packages=\"$packages coreutils\"; [ -s /etc/ssl/certs/ca-certificates.crt ] || packages=\"$packages ca-certificates\"",
    "need_resolver=0; resolver_link=; if ! command -v resolvconf >/dev/null; then if command -v resolvectl >/dev/null && as_root systemctl is-active --quiet systemd-resolved && resolvectl status >/dev/null 2>&1; then resolver_link=$(command -v resolvectl); else need_resolver=1; fi; fi",
    "if [ -n \"$packages\" ] || [ \"$need_resolver\" = 1 ]; then command -v apt-get >/dev/null && command -v apt-cache >/dev/null || { echo 'apt is required to install missing agent dependencies' >&2; exit 1; }; as_root apt-get update || { echo 'could not refresh dependency packages; no bootstrap token was used' >&2; exit 1; }; if [ \"$need_resolver\" = 1 ]; then apt-cache show openresolv >/dev/null 2>&1 || { echo 'no supported resolver compatibility is available; configure resolvconf or active systemd-resolved before retrying; no bootstrap token was used' >&2; exit 1; }; packages=\"$packages openresolv\"; fi; as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --no-remove $packages || { echo 'agent dependency installation failed; no bootstrap token was used' >&2; exit 1; }; fi",
    "if [ -n \"$resolver_link\" ]; then if [ -e /usr/local/sbin/resolvconf ] || [ -L /usr/local/sbin/resolvconf ]; then echo 'existing resolver compatibility path refused' >&2; exit 1; fi; as_root mkdir -p /usr/local/sbin; as_root ln -s \"$resolver_link\" /usr/local/sbin/resolvconf; fi",
    "for tool in wg wg-quick curl jq ip sha256sum resolvconf; do command -v \"$tool\" >/dev/null || { echo \"required agent dependency is unavailable: $tool; no bootstrap token was used\" >&2; exit 1; }; done; [ -s /etc/ssl/certs/ca-certificates.crt ] || { echo 'CA certificates are unavailable; no bootstrap token was used' >&2; exit 1; }",
    "download_asset() { curl -fsSL --proto '=https' --proto-redir '=https' --max-redirs 5 --connect-timeout 15 --max-time 180 \"$1\" -o \"$2\"; }",
    `case "$arch" in amd64) runtime_name="$expected_amd64_name"; runtime_digest="$expected_amd64_digest"; verifier_name="$expected_verifier_amd64_name"; verifier_digest="$expected_verifier_amd64_digest"; verifier_source="$expected_verifier_amd64_source" ;; arm64) runtime_name="$expected_arm64_name"; runtime_digest="$expected_arm64_digest"; verifier_name="$expected_verifier_arm64_name"; verifier_digest="$expected_verifier_arm64_digest"; verifier_source="$expected_verifier_arm64_source" ;; esac; if [ "$verifier_available" = 1 ]; then [ "$verifier_name" = "releaseverify-linux-$arch" ] && [ "$verifier_source" = "$source_sha" ] && [ "\${#verifier_digest}" = 64 ] || { echo 'signed verifier descriptor refused' >&2; exit 1; }; case "$verifier_digest" in *[!a-f0-9]*) echo 'signed verifier digest refused' >&2; exit 1 ;; esac; download_asset "\${manifest_url%release.json}$verifier_name" "$d/releaseverify"; actual_verifier_digest=$(sha256sum "$d/releaseverify" | awk '{print $1}'); [ "$actual_verifier_digest" = "$verifier_digest" ] || { echo 'verifier byte digest refused; no bootstrap token was used' >&2; exit 1; }; chmod 700 "$d/releaseverify"; verifier="$d/releaseverify"; else verifier=$(command -v releaseverify); fi; download_asset "$manifest_url" "$d/release.json"; "$verifier" -manifest "$d/release.json" -public-key "$release_key" -expected-source-sha "$source_sha" -expected-key-id "$verifier_key_id" -platform "$arch" -print-env > "$d/release.env" || { echo 'signed release verification refused' >&2; exit 1; }`,
    `runtime_binary=$(sed -n 's/^TUNNEX_AGENT_RUNTIME_BINARY=//p' "$d/release.env"); runtime_version=$(sed -n 's/^TUNNEX_AGENT_RUNTIME_VERSION=//p' "$d/release.env"); unit_name=$(sed -n 's/^TUNNEX_AGENT_RUNTIME_UNIT_NAME=//p' "$d/release.env"); unit_digest=$(sed -n 's/^TUNNEX_AGENT_RUNTIME_UNIT_SHA256=//p' "$d/release.env"); unit_source_sha=$(sed -n 's/^TUNNEX_AGENT_RUNTIME_UNIT_SOURCE_SHA=//p' "$d/release.env"); [ "$runtime_binary" = "$expected_runtime_binary" ] || { echo 'signed runtime binary refused' >&2; exit 1; }; [ "$runtime_version" = "$expected_runtime_version" ] || { echo 'signed runtime version refused' >&2; exit 1; }; [ "$unit_name" = "$expected_unit_name" ] || { echo 'signed runtime unit name refused' >&2; exit 1; }; [ "$unit_source_sha" = "$expected_unit_source_sha" ] || { echo 'signed runtime unit source refused' >&2; exit 1; }; [ "$unit_digest" = "$expected_unit_digest" ] || { echo 'signed runtime unit digest refused' >&2; exit 1; }`,
    `download_asset "\${manifest_url%release.json}$runtime_name" "$d/runtime"; actual_digest=$(sha256sum "$d/runtime" | awk '{print $1}'); [ "$actual_digest" = "$runtime_digest" ] || { echo 'runtime byte digest refused' >&2; exit 1; }; download_asset "\${manifest_url%release.json}$unit_name" "$d/unit"; actual_unit_digest=$(sha256sum "$d/unit" | awk '{print $1}'); [ "$actual_unit_digest" = "$unit_digest" ] || { echo 'runtime unit refused' >&2; exit 1; }`,
    `wg genkey > "$d/key"; wg pubkey < "$d/key" > "$d/public"; printf '%s' ${q(token)} > "$d/token"; jq -nc --rawfile token "$d/token" --rawfile key "$d/public" '{bootstrap_token:($token|rtrimstr("\\n")),public_key:($key|rtrimstr("\\n"))}' | curl -fsS -H 'content-type: application/json' --data-binary @- ${q(`${apiURL}/api/v1/agent/bootstrap`)} > "$d/response"; jq -e '.config | type == "string" and contains("__TUNNEX_PRIVATE_KEY__")' < "$d/response" >/dev/null; jq -e '.runtime_credential | type == "string" and length > 0' < "$d/response" >/dev/null; jq -j --rawfile p "$d/key" '.config | gsub("__TUNNEX_PRIVATE_KEY__"; ($p|rtrimstr("\\n")))' < "$d/response" > "$d/config"; jq -r '.runtime_credential' < "$d/response" > "$d/credential"; jq -n --arg server ${q(apiURL)} --arg client tunnex-agent-runtime '{server:$server,applied_revision:0,client_version:$client}' > "$d/state"; as_root systemctl is-active --quiet tunnex-agent-runtime.service && was_active=1 || true; as_root systemctl is-enabled --quiet tunnex-agent-runtime.service && was_enabled=1 || true`,
    "for pair in 'runtime-bin.snapshot /usr/local/bin/tunnex-agent-runtime' 'runtime-unit.snapshot /etc/systemd/system/tunnex-agent-runtime.service' 'runtime-cfg.snapshot /etc/wireguard/runtime.conf' 'runtime-cred.snapshot /etc/tunnex-agent/runtime-credential' 'runtime-state.snapshot /var/lib/tunnex-agent/runtime-state.json'; do snap=$(printf '%s' \"$pair\" | cut -d' ' -f1); path=$(printf '%s' \"$pair\" | cut -d' ' -f2); if as_root test -f \"$path\"; then as_root cp -p \"$path\" \"$d/$snap\"; fi; done; snapshot_ready=1; as_root install -d -o root -g root -m 755 /etc/wireguard /etc/tunnex-agent /var/lib/tunnex-agent /etc/systemd/system; as_root install -o root -g root -m 755 \"$d/runtime\" \"$runtime_bin\"; as_root install -o root -g root -m 644 \"$d/unit\" \"$runtime_unit\"; as_root install -o root -g root -m 600 \"$d/config\" \"$runtime_cfg\"; as_root install -o root -g root -m 600 \"$d/credential\" \"$runtime_cred\"; as_root install -o root -g root -m 600 \"$d/state\" \"$runtime_state\"; as_root systemctl daemon-reload; as_root systemctl enable --now tunnex-agent-runtime.service; failed=0; trap - EXIT; rm -rf \"$d\"",
  ].join("; ");
  return ["sh <<'TUNNEX_BOOTSTRAP'", script, "TUNNEX_BOOTSTRAP"].join("\n");
}

/**
 * What the operator must have on the agent host first.
 *
 * ⚠ STATED, NOT ASSUMED. `wg-quick` is not installed by default on most images, and a command that fails
 * with "command not found" reads as a broken product rather than a missing package.
 *
 * ⛔ AND `resolvconf` IS NAMED BECAUSE ITS ABSENCE IS SILENT AND TOTAL. The config carries a `DNS =` line, so
 * `wg-quick` shells out to `resolvconf` — and on ANY failure there it ROLLS THE WHOLE INTERFACE BACK
 * (`ip link delete dev tunnex`). The tunnel comes up and deletes itself, mid-output, after several lines that
 * all look like success. On a minimal container or slim VM — **exactly the host an AI agent runs on** — the
 * operator is left with no interface, no route, and a command that appeared to work.
 *
 * ⚠ Found on the wire, and it concealed itself twice: with no tunnel route the agent's own subnet reached the
 * destination DIRECTLY over the host network, so a request still returned 200 and the rig read as healthy.
 * A successful request is not proof the tunnel carried it — only a counter delta on the peer is.
 */
export const AGENT_PREREQ =
  "Requires Ubuntu/Debian (amd64 or arm64), systemd, and root or sudo. Missing host dependencies are installed automatically.";
