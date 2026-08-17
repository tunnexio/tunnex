import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { accessSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { readGeneratedFile } from "./support/source";
import { join } from "node:path";
import {
  agentConnectCommand,
  agentSummary,
  attributionNote,
  NO_AGENTS,
  sortAgents,
  agentLiveness,
  livenessLabel,
  formatTraffic,
  agentBootstrapCommand as buildAgentBootstrapCommand,
  type AgentRow,
} from "../src/lib/agentview";
import type { BootstrapRelease } from "../src/lib/api";

const release: BootstrapRelease = {
  tag: "v0.4.0",
  source_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  manifest_url: "https://github.com/tunnexio/tunnex/releases/download/v0.4.0/release.json",
  verifier_key_id: "release-2026-01",
  runtime: {
    binary: "tunnex-agent-runtime",
    version: "v0.4.0",
    linux_amd64: { name: "tunnex-agent-runtime-linux-amd64", sha256: "3".repeat(64), source_sha: "a".repeat(40) },
    linux_arm64: { name: "tunnex-agent-runtime-linux-arm64", sha256: "4".repeat(64), source_sha: "a".repeat(40) },
    unit: { name: "tunnex-agent-runtime.service", sha256: "5".repeat(64), source_sha: "a".repeat(40) },
  },
};

const agentBootstrapCommand = (token: string, apiURL = "https://cp.example") =>
  buildAgentBootstrapCommand(token, release, apiURL);

describe("the agent surface — S15.3", () => {
  const row = (o: Partial<AgentRow> = {}): AgentRow => ({
    device_id: o.device_id ?? "d1",
    name: o.name ?? "agent-a",
    owner_email:
      "owner_email" in o ? (o.owner_email ?? null) : "owner@demo.tunnex.local",
    unattributable: o.unattributable ?? false,
    address: "address" in o ? (o.address ?? null) : "10.99.0.4",
    gateway_name: o.gateway_name ?? "gw-1",
    status: o.status ?? "active",
  });

  it("⛔ UNATTRIBUTABLE SORTS FIRST — the one state found nowhere else", () => {
    const sorted = sortAgents([
      row({ device_id: "d1", name: "aaa-normal" }),
      row({ device_id: "d2", name: "zzz-normal" }),
      row({
        device_id: "d3",
        name: "mmm-orphan",
        unattributable: true,
        owner_email: null,
      }),
    ]);
    // ⚠ Must not depend on a name: alphabetically this order would be aaa, mmm, zzz.
    expect(sorted.map((r) => r.name)).toEqual([
      "mmm-orphan",
      "aaa-normal",
      "zzz-normal",
    ]);
  });

  it("⛔ THE ABSENCES ARE FIRST-CLASS — no owner and no address stay null, never a guess", () => {
    const [r] = sortAgents([
      row({ owner_email: null, address: null, unattributable: true }),
    ]);
    expect(r.owner_email).toBeNull();
    expect(r.address).toBeNull();
  });

  describe("the attribution note", () => {
    it("names the gap and says the agent KEEPS RUNNING", () => {
      const n = attributionNote({ unattributable: true })!;
      expect(n.label).toMatch(/unattributable/i);
      expect(n.detail).toMatch(/keeps running/i);
      expect(n.detail).toMatch(/audit trail, not in access control/i);
    });

    it("⚠ TONE IS warn, NEVER danger — a logging gap is not an access-control failure", () => {
      expect(attributionNote({ unattributable: true })!.tone).toBe("warn");
    });

    it("is absent for an attributable agent — without this the note could be a constant", () => {
      expect(attributionNote({ unattributable: false })).toBeNull();
    });
  });

  // ⛔ THE RENDER FLOOR, ENFORCED ON THE COPY ITSELF. These are the two claims the product cannot keep.
  it("⛔ NO DETECTION AND NO PER-TOOL LANGUAGE anywhere in the surface's copy", () => {
    const copy = [
      NO_AGENTS,
      attributionNote({ unattributable: true })!.label,
      attributionNote({ unattributable: true })!.detail,
    ].join(" ");
    for (const forbidden of [
      /\bdetect\w*/i,
      /\bblocks?\b/i,
      /\bprevent\w*/i,
      /\bprompt injection\b/i,
      /\btool\b/i,
      /\bper-tool\b/i,
      /\bsecure\b/i,
      /\bprotected\b/i,
    ]) {
      expect(copy).not.toMatch(forbidden);
    }
  });
});

// ⛔ THE UNDETERMINED STATE'S WORDS ARE PINNED THE WAY THE RENDER FLOOR IS PINNED.
//
// The ruling: undetermined means *we do not know what this was enrolled as, because the fact was not
// recorded at the time and cannot be recovered*. It is NOT "not an agent" (a fact nobody has), NOT "agent"
// (the defect the marker fixed), and NOT a fault (these nodes work correctly).
//
// > **"UNKNOWN" SOFTENING INTO "NONE" IS EXACTLY HOW THE PHRASE WOULD DRIFT INTO A VERDICT** — one is an
// > absence of knowledge, the other is a claim about the world.
describe("the Overview card — S15.3", () => {
  const r = (u: boolean) => ({ unattributable: u });

  it("counts, and names the gap only when it exists", () => {
    expect(agentSummary([r(false), r(false)])).toMatchObject({
      total: 2,
      unattributable: 0,
      note: null,
    });
    const s = agentSummary([r(true), r(false), r(true)]);
    expect(s).toMatchObject({ total: 3, unattributable: 2 });
    expect(s.note).toMatch(/cannot be attributed to a person/i);
  });

  // ⛔ §0 BINDS HARDEST AT CARD SIZE — this is where copy gets shortened until it implies things.
  it("⛔ the card's copy makes no detection, per-tool or health claim", () => {
    const copy = agentSummary([r(true)]).note ?? "";
    for (const forbidden of [
      /\bdetect\w*/i,
      /\bblocks?\b/i,
      /\bprevent\w*/i,
      /\btool\b/i,
      /\bsecure\b/i,
      /\bprotected\b/i,
      /\ball good\b/i,
      /\bhealthy\b/i,
    ]) {
      expect(copy).not.toMatch(forbidden);
    }
  });
});

describe("the connect command — S15.3", () => {
  const conf =
    "[Interface]\nPrivateKey = k+ey/with$dollar=\nAddress = 10.99.0.7/32\n";

  it("⛔ ONE COMMAND, not a file to save and then a command to run", () => {
    const c = agentConnectCommand(conf);
    expect(c).toMatch(/tee \/etc\/wireguard\/tunnex\.conf/);
    expect(c).toMatch(/wg-quick up tunnex/);
  });

  it("⛔ THE HEREDOC IS QUOTED — an unquoted one would let the shell mangle a key containing $", () => {
    const c = agentConnectCommand(conf);
    expect(c).toContain("<<'TUNNEXEOF'");
    // the key survives verbatim
    expect(c).toContain("k+ey/with$dollar=");
  });

  it("⚠ the config is chmod 600 — a private key must not be world-readable", () => {
    expect(agentConnectCommand(conf)).toMatch(/chmod 600/);
  });
});

describe("the managed bootstrap command — F03", () => {
  it("shell-quotes token and API URL and never embeds a private key", () => {
    const cmd = agentBootstrapCommand("tok'$danger", "https://cp.example/one path");
    expect(cmd).toContain("--rawfile token");
    expect(cmd).toContain("'\\''");
    expect(cmd).toContain("https://cp.example/one path/api/v1/agent/bootstrap");
    expect(cmd).toContain("wg genkey");
    expect(cmd).not.toContain("PrivateKey =");
    expect(cmd).not.toContain("private_key");
  });

  it("validates before installation, uses atomic temp files, and cleans failures", () => {
    const cmd = agentBootstrapCommand("TKN", "https://cp.example");
    expect(cmd).toContain("command -v resolvconf");
    expect(cmd).toContain("mktemp -d");
    expect(cmd).toContain("jq -e");
    expect(cmd).toContain('runtime_credential | type == "string" and length > 0');
    expect(cmd).toMatch(/install -o root -g root -m 600/);
    expect(cmd).toContain("trap cleanup EXIT");
    expect(cmd).toContain("systemctl disable --now tunnex-agent-runtime.service");
    expect(cmd).not.toContain("/etc/wireguard/tunnex.conf");
    expect(cmd).not.toContain("/etc/tunnex-agent-credential");
  });

  it("executes the generated command and substitutes a valid config byte-for-byte", () => {
    const dir = mkdtempSync(join(tmpdir(), "tunnex-bootstrap-exec-"));
    const bin = join(dir, "bin");
    const captured = join(dir, "captured");
    const ephemeral = join(dir, "ephemeral");
    const runtime = join(dir, "runtime");
    const unit = join(dir, "tunnex-agent-runtime.service");
    const response = join(dir, "response.json");
    const manifest = join(dir, "release.json");
    const curlArgs = join(dir, "curl.args");
    const systemctlCalls = join(dir, "systemctl.calls");
    const privateKey = "private+key/keeps$dollar=";
    const runtimeCredential = "tnx_runtime_test_secret";
    const config = [
      "[Interface]",
      "PrivateKey = __TUNNEX_PRIVATE_KEY__",
      "Address = 10.99.0.7/32",
      "",
    ].join("\n");
    const sha = (value: string) => createHash("sha256").update(value).digest("hex");
    const runtimeBytes = "runtime-bytes\n";
    const unitBytes = "[Service]\nExecStart=/usr/local/bin/tunnex-agent-runtime\n";
    const executable = (name: string, body: string) =>
      writeFileSync(join(bin, name), `#!/bin/sh\nset -eu\n${body}\n`, { mode: 0o700 });

    mkdirSync(bin);
    mkdirSync(join(captured, "usr/local/bin"), { recursive: true });
    symlinkSync(execFileSync("which", ["jq"]).toString().trim(), join(bin, "jq"));
    writeFileSync(runtime, runtimeBytes);
    writeFileSync(unit, unitBytes);
    writeFileSync(manifest, "{}\n");
    writeFileSync(response, JSON.stringify({ config, runtime_credential: runtimeCredential }));

    executable("mktemp", `mkdir -p "$MOCK_EPHEMERAL"; printf '%s\\n' "$MOCK_EPHEMERAL"`);
    executable("wg", `
case "\${1:-}" in
  show) exit 1 ;;
  genkey) printf '%s\\n' "$MOCK_PRIVATE_KEY" ;;
  pubkey) cat >/dev/null; printf '%s\\n' 'public-key=' ;;
esac`);
    executable("wg-quick", "exit 0");
    executable("resolvconf", "exit 0");
    executable("uname", "printf '%s\\n' x86_64");
    executable("systemctl", `printf '%s\n' "$*" >> "$MOCK_SYSTEMCTL_CALLS"
case "\${1:-}" in
  is-active|is-enabled) exit 1 ;;
  enable) [ "\${MOCK_START_FAIL:-0}" = 1 ] && exit 42 || exit 0 ;;
  *) exit 0 ;;
esac`);
    executable("releaseverify", `
printf '%s\\n' \\
  'TUNNEX_AGENT_RUNTIME_BINARY=tunnex-agent-runtime' \\
  'TUNNEX_AGENT_RUNTIME_VERSION=v0.4.0' \\
  'TUNNEX_AGENT_RUNTIME_UNIT_NAME=tunnex-agent-runtime.service' \\
  "TUNNEX_AGENT_RUNTIME_UNIT_SHA256=$MOCK_UNIT_SHA" \\
  'TUNNEX_AGENT_RUNTIME_UNIT_SOURCE_SHA=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'`);
    executable("curl", `
printf '%s\n' "$*" >> "$MOCK_CURL_ARGS"
out=; url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2 ;;
    -H|--data-binary) shift 2 ;;
    -*) shift ;;
    *) url=$1; shift ;;
  esac
done
case "$url" in
  */api/v1/agent/bootstrap) cat >/dev/null; cat "$MOCK_RESPONSE" ;;
  */release.json) [ "$out" = /dev/null ] || cp "$MOCK_MANIFEST" "$out" ;;
  *tunnex-agent-runtime-linux-amd64) cp "$MOCK_RUNTIME" "$out" ;;
  *tunnex-agent-runtime.service) cp "$MOCK_UNIT" "$out" ;;
  *) exit 64 ;;
esac`);
    executable("sudo", `
cmd=$1; shift
map_path() { case "$1" in /etc|/etc/*|/usr/local|/usr/local/*|/var/lib/tunnex-agent|/var/lib/tunnex-agent/*) printf '%s%s' "$MOCK_CAPTURE" "$1" ;; *) printf '%s' "$1" ;; esac; }
case "$cmd" in
  wg|wg-quick|systemctl) exec "$cmd" "$@" ;;
  test)
    op=$1; path=$(map_path "$2"); exec test "$op" "$path" ;;
  rm)
    args=; for arg in "$@"; do case "$arg" in -*) args="$args $arg" ;; *) args="$args $(map_path "$arg")" ;; esac; done
    exec sh -c "rm $args" ;;
  install)
    args=; skip=0
    for arg in "$@"; do
      if [ "$skip" = 1 ]; then skip=0; continue; fi
      case "$arg" in -o|-g) skip=1 ;; /*) args="$args $(map_path "$arg")" ;; *) args="$args $arg" ;; esac
    done
    exec sh -c "install $args" ;;
  cp) exec cp "$@" ;;
  *) exec "$cmd" "$@" ;;
esac`);

    const executableRelease: BootstrapRelease = {
      ...release,
      runtime: {
        ...release.runtime,
        linux_amd64: { ...release.runtime.linux_amd64, sha256: sha(runtimeBytes) },
        unit: { ...release.runtime.unit, sha256: sha(unitBytes) },
      },
    };

    try {
      const generated = buildAgentBootstrapCommand("TKN", executableRelease, "https://cp.example");
      expect(generated).toMatch(/^sh <<'TUNNEX_BOOTSTRAP'/);
      expect(generated).not.toContain("sh -c");
      const execute = (startFails: boolean) =>
        execFileSync("/bin/sh", [], {
          input: generated,
          env: {
          ...process.env,
          PATH: `${bin}:${process.env.PATH ?? ""}`,
          MOCK_CAPTURE: captured,
          MOCK_CURL_ARGS: curlArgs,
          MOCK_EPHEMERAL: ephemeral,
          MOCK_MANIFEST: manifest,
          MOCK_PRIVATE_KEY: privateKey,
          MOCK_RESPONSE: response,
          MOCK_RUNTIME: runtime,
          MOCK_START_FAIL: startFails ? "1" : "0",
          MOCK_SYSTEMCTL_CALLS: systemctlCalls,
          MOCK_UNIT: unit,
          MOCK_UNIT_SHA: sha(unitBytes),
          TUNNEX_RELEASE_PUBLIC_KEY: "trusted-public-key",
          },
          stdio: ["pipe", "pipe", "pipe"],
        }).toString();

      expect(() => execute(true)).toThrow();
      expect(() => accessSync(join(captured, "etc/wireguard/runtime.conf"))).toThrow();
      expect(() => accessSync(join(captured, "etc/tunnex-agent/runtime-credential"))).toThrow();
      expect(() => accessSync(ephemeral)).toThrow();
      expect(readGeneratedFile(systemctlCalls, dir)).toContain("daemon-reload");

      const stdout = execute(false);

      expect(readGeneratedFile(join(captured, "etc/wireguard/runtime.conf"), captured)).toBe(
        config.replace("__TUNNEX_PRIVATE_KEY__", privateKey),
      );
      expect(readGeneratedFile(join(captured, "etc/tunnex-agent/runtime-credential"), captured)).toBe(`${runtimeCredential}\n`);
      expect(stdout).not.toContain(privateKey);
      expect(stdout).not.toContain(runtimeCredential);
      expect(readGeneratedFile(curlArgs, dir)).not.toContain("TKN");
      expect(() => readGeneratedFile(join(process.cwd(), "src/lib/agentview.ts"), dir)).toThrow(/escaped/);
      expect(() => accessSync(ephemeral)).toThrow();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses a missing resolver before key generation, redemption, or file writes", () => {
    const dir = mkdtempSync(join(tmpdir(), "tunnex-bootstrap-prereq-"));
    const calls = join(dir, "calls");
    try {
      symlinkSync("/bin/sh", join(dir, "sh"));
      for (const name of ["wg", "wg-quick", "curl", "jq"]) {
        writeFileSync(join(dir, name), `#!/bin/sh\nprintf '%s\\n' "$0 $*" >> ${JSON.stringify(calls)}\nexit 99\n`, { mode: 0o700 });
      }
      const cmd = agentBootstrapCommand("TKN", "https://cp.example");
      let failure: { stderr?: Buffer } | undefined;
      try {
        execFileSync("/bin/sh", ["-c", cmd], {
          env: { PATH: dir, CALLS: calls },
          stdio: ["ignore", "pipe", "pipe"],
        });
      } catch (err) {
        failure = err as { stderr?: Buffer };
      }
      expect(failure).toBeTruthy();
      expect(failure?.stderr?.toString()).toMatch(/resolvconf\/openresolv is required/);
      expect(() => accessSync(calls)).toThrow();
      expect(cmd.indexOf("command -v resolvconf")).toBeLessThan(cmd.indexOf("umask 077"));
      expect(cmd.indexOf("command -v resolvconf")).toBeLessThan(cmd.indexOf("wg genkey"));
      expect(cmd.indexOf("command -v resolvconf")).toBeLessThan(cmd.indexOf("/api/v1/agent/bootstrap"));
      expect(cmd.indexOf("command -v resolvconf")).toBeLessThan(cmd.indexOf("install -o root -g root -m 600"));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("installs the pinned same-release managed runtime service contract", () => {
    const cmd = agentBootstrapCommand("TKN", "https://cp.example");
    // F04's approved package contract is asserted here so F03 cannot invent a
    // second runtime binary, unit, or state layout.
    expect(cmd).toContain("tunnex-agent-runtime");
    expect(cmd).toContain("tunnex-agent-runtime.service");
    expect(cmd).toMatch(/TUNNEX_(RELEASE|VERSION)|release\.json/i);
    expect(cmd).toContain("/etc/wireguard/runtime.conf");
    expect(cmd).not.toContain("/etc/tunnex-agent/runtime.conf");
    expect(cmd).toContain("/etc/tunnex-agent/runtime-credential");
    expect(cmd).toContain("/var/lib/tunnex-agent/runtime-state.json");
    expect(cmd).toMatch(/install[^;]*(?:-o root|-u root)[^;]*(?:-g root|-g 0)[^;]*-m 600/i);
  });

  it("installs root-owned 0600 runtime files for the approved root service", () => {
    const cmd = agentBootstrapCommand("TKN", "https://cp.example");
    const rootOwned0600 = cmd.match(/install -o root -g root -m 600[^;]+\$runtime_(?:cfg|cred|state)/g) ?? [];
    expect(rootOwned0600.length).toBe(3);
  });

  it("keeps bootstrap/runtime secrets and private keys out of process args and command output", () => {
    const cmd = agentBootstrapCommand("TKN", "https://cp.example");
    // The approved hygiene boundary keeps secrets in temporary files and rawfile
    // inputs rather than process arguments or command output.
    expect(cmd).not.toMatch(/--arg\s+token\b/i);
    expect(cmd).not.toMatch(/--arg\s+p\b/i);
    expect(cmd).not.toMatch(/(?:echo|printf)[^;]*(?:runtime_credential|private_key|token_hash)/i);
    expect(cmd).not.toMatch(/(?:echo|printf)[^;]*\$r\b/i);
  });

  it("atomically hands off startup and revoke/offboarding to the service", () => {
    const cmd = agentBootstrapCommand("TKN", "https://cp.example");
    expect(cmd).toMatch(/mktemp -d/);
    expect(cmd).toMatch(/trap/);
    expect(cmd).toMatch(/systemctl\s+(?:enable\s+--now|start)\s+tunnex-agent-runtime\.service/);
    expect(cmd).toMatch(/systemctl\s+(?:disable\s+--now|stop)\s+tunnex-agent-runtime\.service/);
    expect(cmd).toMatch(/(?:revoke|offboard)/i);
    expect(cmd).toMatch(/runtime-(?:credential|state)/);
  });

  it("requires the signed runtime descriptor and binds the selected asset to its source release", () => {
    const cmd = agentBootstrapCommand("TKN", "https://cp.example");
    expect(cmd).toContain("releaseverify");
    expect(cmd).toMatch(/-manifest\s+[^ ]*release\.json/);
    expect(cmd).toMatch(/-public-key/);
    expect(cmd).toMatch(/-expected-source-sha/);
    expect(cmd).toMatch(/-platform/);
    expect(cmd).toContain(release.tag);
    expect(cmd).toContain(release.source_sha);
    expect(cmd).toContain(release.manifest_url);
    expect(cmd).toContain(release.verifier_key_id);
    expect(cmd).toContain(release.runtime.linux_amd64.name);
    expect(cmd).toContain(release.runtime.linux_amd64.sha256);
    expect(cmd).toContain(release.runtime.linux_arm64.name);
    expect(cmd).toContain(release.runtime.linux_arm64.sha256);
    expect(cmd).toContain(release.runtime.unit.name);
    expect(cmd).toContain(release.runtime.unit.sha256);
    expect(cmd).toContain('runtime_name="$expected_amd64_name"');
  });

  it("verifies runtime bytes before install and rejects unsigned or mutable fallbacks", () => {
    const cmd = agentBootstrapCommand("TKN", "https://cp.example");
    expect(cmd).toMatch(/sha256sum/);
    expect(cmd).toContain("expected_amd64_digest");
    expect(cmd).toContain("expected_arm64_digest");
    expect(cmd).toMatch(/\[\s+"\$actual_digest"\s+=\s+"\$runtime_digest"\s+\]/);
    expect(cmd).toMatch(/sha256sum[^;]*[\s\S]*install/);
    expect(cmd).not.toMatch(/(?:latest|docker\s+(?:pull|run)|Tunnex-Agent-Runtime-SHA256SUMS)/i);
  });

  it("requires the systemd unit to be a signed, digest-verified runtime asset", () => {
    const cmd = agentBootstrapCommand("TKN", "https://cp.example");
    expect(cmd).toContain("TUNNEX_AGENT_RUNTIME_UNIT_NAME");
    expect(cmd).toContain("TUNNEX_AGENT_RUNTIME_UNIT_SHA256");
    expect(cmd).toContain("TUNNEX_AGENT_RUNTIME_UNIT_SOURCE_SHA");
    expect(cmd).toContain("unit_source_sha");
    expect(cmd).toMatch(/releaseverify[\s\S]*TUNNEX_AGENT_RUNTIME_UNIT_NAME/);
    expect(cmd).toMatch(/unit_name.*tunnex-agent-runtime\.service/);
    expect(cmd).toMatch(/sha256sum[^;]*unit[\s\S]*actual_unit_digest/);
    expect(cmd).toMatch(/\[\s+\"\$actual_unit_digest\"\s+=\s+\"\$unit_digest\"\s+\]/);
    expect(cmd).toMatch(/unit_name[\s\S]*curl[^;]*\$unit_name/);
    expect(cmd).toMatch(/(?:unit|signature)[\s\S]*(?:refused|invalid|missing)/i);
    expect(cmd.indexOf("actual_unit_digest")).toBeLessThan(cmd.indexOf('install -o root -g root -m 644 "$d/unit"'));
    expect(cmd).toContain("{server:$server,applied_revision:0,client_version:$client}");
    expect(cmd).not.toMatch(/jq -n --arg server[^;]*--rawfile credential/);
    expect(cmd).not.toMatch(/jq -n --arg server[^;]*runtime_credential/);
  });

  it("fails closed on malformed signatures, missing architectures, and unsupported hosts", () => {
    const cmd = agentBootstrapCommand("TKN", "https://cp.example");
    expect(cmd).toMatch(/set -e/);
    expect(cmd).toMatch(/(?:amd64|x86_64)/);
    expect(cmd).toMatch(/(?:arm64|aarch64)/);
    expect(cmd).toMatch(/unsupported|refus|invalid|missing/i);
    expect(cmd).toMatch(/releaseverify[\s\S]*(?:\|\||exit|return)/i);
  });

  it("preserves runtime files and service state when verification or startup fails", () => {
    const cmd = agentBootstrapCommand("TKN", "https://cp.example");
    expect(cmd).toMatch(/(?:runtime|agent-runtime)/i);
    expect(cmd).toMatch(/(?:backup|restore|preserve|already exists|\.bak|snapshot)/i);
    expect(cmd).toMatch(/(?:systemctl\s+is-active|was-active|service state|restore.*service)/i);
    expect(cmd).toMatch(/trap[\s\S]*(?:rm -rf|cleanup)/i);
    expect(cmd).toMatch(/(?:verify|sha256sum|releaseverify)[\s\S]*install/);
  });

  it("refuses existing managed targets before changing config or credential bytes", () => {
    const cmd = agentBootstrapCommand("TKN", "https://cp.example");
    // Refusal occurs before token redemption, key generation, download, writes,
    // service mutation, or cleanup of an existing managed installation.
    expect(cmd).toMatch(/existing managed (?:runtime interface|installation) refused/i);
    expect(cmd).toContain('for target in "$runtime_bin" "$runtime_unit"');
    expect(cmd.indexOf('for target in "$runtime_bin"')).toBeLessThan(cmd.indexOf("trap cleanup EXIT"));
    expect(cmd).toContain("wg show runtime");
    expect(cmd.indexOf("wg show runtime")).toBeLessThan(cmd.indexOf("trap cleanup EXIT"));
    expect(cmd).not.toContain("wg show tunnex");
    expect(cmd).not.toContain("wg-quick up tunnex");
    expect(cmd).not.toContain("/etc/wireguard/tunnex.conf");
    expect(cmd).not.toContain("/etc/tunnex-agent-credential");
  });
});

/**
 * ⛔ AGENT LIVENESS — the five states, and the precedence between two of them.
 *
 * The whole point of this block is the ONE ordering rule: `unknown` outranks `offline`. Everything else is
 * a straightforward mapping; that rule is the one a refactor silently breaks, and breaking it produces a
 * screen that confidently blames an agent for its gateway's silence.
 */
describe("agent liveness — S15.3", () => {
  const now = new Date("2026-08-05T12:00:00Z");
  const ago = (s: number) => new Date(now.getTime() - s * 1000).toISOString();
  const live = (o: Partial<AgentRow> = {}): AgentRow => ({
    device_id: "d1",
    name: "agent-a",
    owner_email: "o@x.com",
    unattributable: false,
    address: "10.99.0.2",
    gateway_name: "gw-1",
    status: "active",
    config_issued: true,
    gateway_reporting: true,
    ...o,
  });

  it("⭐ REVOKED OUTRANKS EVERYTHING — a dead credential must never be told to reconnect", () => {
    // ⛔ THE EXACT ROW THE LIVE RIG PRODUCED. Revocation keeps the row and the key (config_issued stays
    // true) and SWEEPS the telemetry (last_handshake_at goes null) — which lands a revoked agent in
    // `never`, whose copy sends the operator to run the connect command on a machine that is fine, for a
    // credential that was deliberately destroyed.
    const a = live({
      status: "revoked",
      online: false,
      last_handshake_at: null,
    });
    expect(agentLiveness(a)).toBe("revoked");
    expect(livenessLabel(a, now).label).toBe("revoked");
    expect(livenessLabel(a, now).detail).not.toMatch(/Run the command/);
    // ⚠ And it outranks the reporter check too: a revoked agent on a silent gateway is still revoked,
    // not unknown — that fact does not depend on anyone reporting.
    expect(
      agentLiveness(live({ status: "revoked", gateway_reporting: false })),
    ).toBe("revoked");
    // ⚠ NOT `danger`. A revoked credential is the system doing what it was told.
    expect(livenessLabel(a, now).tone).not.toBe("danger");
  });

  it("an ACTIVE agent with the same shape still reads never-connected — revoked is doing the work", () => {
    // Without this, the assertion above would pass on a function that returned "revoked" for everything.
    expect(
      agentLiveness(
        live({ status: "active", online: false, last_handshake_at: null }),
      ),
    ).toBe("never");
  });

  it("online when the gateway reports a recent handshake", () => {
    const a = live({ online: true, last_handshake_at: ago(20) });
    expect(agentLiveness(a)).toBe("online");
    expect(livenessLabel(a, now).label).toBe("connected");
    expect(livenessLabel(a, now).tone).toBe("ok");
  });

  it("⛔ NEVER-CONNECTED IS NOT OFFLINE — a command issued and never run is a different fact", () => {
    const a = live({ online: false, last_handshake_at: null });
    expect(agentLiveness(a)).toBe("never");
    expect(livenessLabel(a, now).label).toBe("never connected");
    // ⚠ And it must be ACTIONABLE. This is the most likely state for a new agent, so the detail has to
    // tell the operator what to do rather than merely restate the badge.
    expect(livenessLabel(a, now).detail).toMatch(
      /Run the command on the agent host/,
    );
  });

  it("offline, with honest recency rather than a bare word", () => {
    const a = live({ online: false, last_handshake_at: ago(600) });
    expect(agentLiveness(a)).toBe("offline");
    expect(livenessLabel(a, now).label).toBe("last seen 10m ago");
  });

  it("⭐ UNKNOWN OUTRANKS OFFLINE — a silent gateway must never be reported as a dead agent", () => {
    // Same row as the offline case in every respect EXCEPT the reporter's own liveness. If the precedence
    // were reversed this would read "last seen 10m ago" — a confident claim about an agent nobody has
    // heard from OR about, sending an operator to debug the wrong machine.
    const a = live({
      online: false,
      last_handshake_at: ago(600),
      gateway_reporting: false,
    });
    expect(agentLiveness(a)).toBe("unknown");
    expect(livenessLabel(a, now).label).toBe("liveness unknown");
    // ⛔ AND IT NAMES THE GATEWAY AS THE SUSPECT.
    expect(livenessLabel(a, now).detail).toContain("gw-1");
    expect(livenessLabel(a, now).detail).toMatch(/Check the gateway first/);
  });

  it("⛔ AND UNKNOWN OUTRANKS ONLINE-LOOKING DATA TOO — a stale `online` must not survive a dead reporter", () => {
    // The server derives `online` from a handshake it may have recorded before the gateway went quiet.
    // If the reporter is silent, that derivation is stale by construction and must not be rendered as fact.
    const a = live({
      online: true,
      last_handshake_at: ago(10),
      gateway_reporting: false,
    });
    expect(agentLiveness(a)).toBe("unknown");
  });

  it("no config issued is distinct from never connected", () => {
    // ⚠ Nothing was handed over, so there is no command to re-run — the "never connected" advice would be
    // wrong here, which is why these are two states and not one.
    const a = live({ config_issued: false });
    expect(agentLiveness(a)).toBe("not-issued");
    expect(livenessLabel(a, now).label).toBe("no config issued");
  });

  it("⛔ NO LIVENESS STATE IS `danger` — a down agent is not a security event", () => {
    // Fail-closed means a disconnected agent reaches NOTHING. Painting it red claims an incident that has
    // not occurred, and over-alarming is the same defect as under-alarming, facing the other way.
    for (const a of [
      live({ online: true, last_handshake_at: ago(5) }),
      live({ online: false, last_handshake_at: null }),
      live({ online: false, last_handshake_at: ago(9999) }),
      live({ gateway_reporting: false }),
      live({ config_issued: false }),
    ]) {
      expect(livenessLabel(a, now).tone).not.toBe("danger");
    }
  });

  it("traffic: an unreported counter renders as absent, never as zero", () => {
    // ⛔ A device the gateway has never reported has NULL counters. Rendering "0 B" would claim we measured
    // no traffic, when in fact we measured nothing at all.
    expect(formatTraffic(null, null)).toBeNull();
    expect(formatTraffic(undefined, undefined)).toBeNull();
    expect(formatTraffic(0, 0)).toBe("↓ 0 B · ↑ 0 B");
    expect(formatTraffic(2048, 1048576)).toBe("↓ 2.0 KB · ↑ 1.0 MB");
    expect(formatTraffic(15_728_640, 0)).toBe("↓ 15 MB · ↑ 0 B");
  });
});
