import { afterEach, describe, expect, it } from "vitest";
import { spawnSync, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readlinkSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { agentBootstrapCommand, agentRuntimeUpdateCommand, INSTALL_ON_ENROLLED_HOST } from "../src/lib/agentview";
import { readGeneratedFile } from "./support/source";
import type { BootstrapRelease } from "../src/lib/api";

// Execute the actual generated POSIX shell in an isolated filesystem/PATH. Only
// privileged host operations, package delivery, and network responses are fakes.
// SHA-256, jq, shell control flow, artifact bytes, file modes and cleanup are real.
// This is not a replacement for the clean supported VM wire walk.
const fixtures: string[] = [];
afterEach(() => { for (const path of fixtures.splice(0)) rmSync(path, { recursive: true, force: true }); });
const sha = (bytes: string) => createHash("sha256").update(bytes).digest("hex");
const source = "a".repeat(40);
const token = "tnx_agent_fixture-only_TOKEN";
// `typed` is what the operator enters at the hidden prompt; null means the
// host has no terminal at all. stty and the terminal device are fakes; the
// prompt, trimming and validation are the real generated shell.
function harness(options: { missing?: string[]; resolver?: "existing" | "resolved" | "package" | "unavailable"; legacy?: boolean; arch?: string; root?: boolean; typed?: string | null; enrolled?: boolean } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "tunnex-agent-host-"));
  fixtures.push(dir);
  const bin = join(dir, "bin");
  const available = join(dir, "available");
  const root = join(dir, "root");
  const assets = join(dir, "assets");
  const log = join(dir, "calls");
  const ephemeral = join(dir, "ephemeral");
  for (const path of [bin, available, root, assets, join(root, "usr/local/bin"), join(root, "usr/local/sbin"), join(root, "etc/ssl/certs")]) mkdirSync(path, { recursive: true });
  const executable = (name: string, body: string, directory = bin) => writeFileSync(join(directory, name), `#!/bin/sh\nset -eu\n${body}\n`, { mode: 0o700 });
  for (const name of ["sh", "cat", "cp", "rm", "mkdir", "ln", "chmod", "sed", "awk", "cut", "wc", "env", "test", "tr", "mv"]) symlinkSync(execFileSync("which", [name]).toString().trim(), join(bin, name));
  const realInstall = execFileSync("which", ["install"]).toString().trim();
  executable("install", `# Production installs use root:root; the fixture runs unprivileged.\nif [ "$1" = -d ]; then shift; directory=1; else directory=0; fi\n[ "$1" = -o ] && shift 2\n[ "$1" = -g ] && shift 2\nif [ "$directory" = 1 ]; then exec '${realInstall}' -d "$@"; else exec '${realInstall}' "$@"; fi`);
  executable("mktemp", 'mkdir -p "$FIXTURE_EPHEMERAL"; echo "$FIXTURE_EPHEMERAL"');
  executable("sleep", 'echo "sleep $*" >> "$FIXTURE_LOG"');
  executable("stty", 'echo "stty $*" >> "$FIXTURE_LOG"; case "${1:-}" in -g) echo fixture-tty-state ;; esac');
  const tty = join(dir, "tty");
  if (options.typed !== null) writeFileSync(tty, options.typed ?? `${token}\n`);
  executable("uname", 'case "$1" in -s) echo Linux ;; *) echo "$FIXTURE_ARCH" ;; esac');
  executable("id", `echo ${options.root === false ? "1000" : "0"}`);
  executable("sudo", `echo "sudo $*" >> "$FIXTURE_LOG"
case "$1" in
  -n) [ "\${FIXTURE_SUDO_NONINTERACTIVE:-1}" = 1 ]; exit $? ;;
  -v) [ "\${FIXTURE_SUDO_VALIDATE:-1}" = 1 ]; exit $? ;;
esac
exec "$@"`);
  executable("systemctl", `echo "systemctl $*" >> "$FIXTURE_LOG"
case "$1" in
  show) [ "\${FIXTURE_SYSTEMD_FAIL:-0}" = 0 ] ;;
  is-active) case "\${3:-}" in systemd-resolved) [ "\${FIXTURE_RESOLVED:-0}" = 1 ] ;; tunnex-agent-runtime.service) [ "\${FIXTURE_RUNTIME_ACTIVE:-0}" = 1 ] ;; *) exit 1 ;; esac ;;
  is-enabled) exit 1 ;;
  enable) [ "\${FIXTURE_START_FAIL:-0}" = 0 ] ;;
  # Only the first restart can be made to fail: the one after it is the restored runtime.
  restart) echo restart >> "$FIXTURE_DIR/restarts"; [ "\${FIXTURE_RESTART_FAIL:-0}" = 0 ] || [ "$(wc -l < "$FIXTURE_DIR/restarts")" -gt 1 ] ;;
esac`);
  executable("sha256sum", `exec "$FIXTURE_NODE" -e 'const fs=require("node:fs");const c=require("node:crypto");console.log(c.createHash("sha256").update(fs.readFileSync(process.argv[1])).digest("hex")+"  "+process.argv[1]);' "$@"`);
  executable("wg", `echo "wg $*" >> "$FIXTURE_LOG"
case "$1" in
  show) exit 1 ;;
  genkey) echo 'private+fixture/key=' ;;
  pubkey) cat >/dev/null; echo 'public-fixture-key=' ;;
esac`, available);
  executable("wg-quick", "exit 0", available);
  executable("ip", "exit 0", available);
  executable("resolvconf", "exit 0", available);
  executable("resolvectl", 'exit 0', available);
  symlinkSync(execFileSync("which", ["jq"]).toString().trim(), join(available, "jq"));
  executable("curl", `echo "curl $*" >> "$FIXTURE_LOG"
out=; url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2 ;;
    -H|--data-binary|--proto|--proto-redir|--max-redirs|--connect-timeout|--max-time) shift 2 ;;
    -*) shift ;;
    *) url=$1; shift ;;
  esac
done
case "$url" in
  */api/v1/agent/bootstrap) cat > "$FIXTURE_DIR/redeemed.json"; cat "$FIXTURE_DIR/response.json" ;;
  *) name=\${url##*/}; cp "$FIXTURE_ASSETS/$name" "$out" ;;
esac`, available);
  executable("apt-cache", `echo "apt-cache $*" >> "$FIXTURE_LOG"; [ "\${FIXTURE_PACKAGE_AVAILABLE:-1}" = 1 ]`);
  executable("apt-get", `echo "apt-get $*" >> "$FIXTURE_LOG"
[ "\${FIXTURE_APT_FAIL:-0}" = 0 ] || exit 99
[ "$1" = install ] || exit 0
for package in "$@"; do
  case "$package" in
    wireguard-tools) cp "$FIXTURE_AVAILABLE/wg" "$FIXTURE_BIN/wg"; cp "$FIXTURE_AVAILABLE/wg-quick" "$FIXTURE_BIN/wg-quick" ;;
    curl|jq) ln -s "$FIXTURE_AVAILABLE/$package" "$FIXTURE_BIN/$package" ;;
    iproute2) cp "$FIXTURE_AVAILABLE/ip" "$FIXTURE_BIN/ip" ;;
    openresolv) cp "$FIXTURE_AVAILABLE/resolvconf" "$FIXTURE_BIN/resolvconf" ;;
    ca-certificates) echo installed-ca > "$FIXTURE_ROOT/etc/ssl/certs/ca-certificates.crt" ;;
  esac
done`);
  const missing = options.missing ?? [];
  for (const name of ["wg", "wg-quick", "ip", "jq", "curl"]) if (!missing.includes(name)) symlinkSync(join(available, name), join(bin, name));
  const resolver = options.resolver ?? "existing";
  if (resolver === "existing") symlinkSync(join(available, "resolvconf"), join(bin, "resolvconf"));
  if (resolver === "resolved") symlinkSync(join(available, "resolvectl"), join(bin, "resolvectl"));
  writeFileSync(join(root, "etc/os-release"), "ID=ubuntu\n");
  writeFileSync(join(root, "etc/resolv.conf"), "nameserver 127.0.0.53\n");
  if (!missing.includes("ca-certificates")) writeFileSync(join(root, "etc/ssl/certs/ca-certificates.crt"), "fixture-ca\n");
  const runtime = "fixture-runtime-binary\n";
  const unit = "[Service]\nExecStart=/usr/local/bin/tunnex-agent-runtime\n";
  const verifier = `#!/bin/sh
set -eu
echo "verifier $*" >> "$FIXTURE_LOG"
[ "\${FIXTURE_VERIFY_FAIL:-0}" = 0 ] || exit 99
printf '%s\\n' 'TUNNEX_AGENT_RUNTIME_BINARY=tunnex-agent-runtime' 'TUNNEX_AGENT_RUNTIME_VERSION=v0.4.0' 'TUNNEX_AGENT_RUNTIME_UNIT_NAME=tunnex-agent-runtime.service' 'TUNNEX_AGENT_RUNTIME_UNIT_SHA256=${sha(unit)}' 'TUNNEX_AGENT_RUNTIME_UNIT_SOURCE_SHA=${source}'
`;
  const asset = (name: string, bytes: string) => { writeFileSync(join(assets, name), bytes); return { name, sha256: sha(bytes), source_sha: source }; };
  const release: BootstrapRelease = {
    tag: "v0.4.0", source_sha: source,
    manifest_url: "https://release.example/immutable/v0.4.0/release.json",
    verifier_key_id: "fixture-key", verifier_public_key: "fixture-public-key",
    runtime: { binary: "tunnex-agent-runtime", version: "v0.4.0", linux_amd64: asset("tunnex-agent-runtime-linux-amd64", runtime), linux_arm64: asset("tunnex-agent-runtime-linux-arm64", runtime), unit: asset("tunnex-agent-runtime.service", unit) },
    verifier: { linux_amd64: asset("releaseverify-linux-amd64", verifier), linux_arm64: asset("releaseverify-linux-arm64", verifier) },
  };
  if (options.legacy) { delete release.verifier; writeFileSync(join(bin, "releaseverify"), verifier, { mode: 0o700 }); }
  writeFileSync(join(assets, "release.json"), "{}\n");
  writeFileSync(join(dir, "response.json"), JSON.stringify({ config: "[Interface]\nPrivateKey = __TUNNEX_PRIVATE_KEY__\nAddress = 10.99.0.7/32\n", runtime_credential: "tnx_fixture_runtime_secret" }));
  // An enrolled host: the files a completed install leaves behind, with bytes
  // that differ from the release so a replacement is observable.
  const installed = {
    bin: join(root, "usr/local/bin/tunnex-agent-runtime"), unit: join(root, "etc/systemd/system/tunnex-agent-runtime.service"),
    cfg: join(root, "etc/wireguard/runtime.conf"), cred: join(root, "etc/tunnex-agent/runtime-credential"), state: join(root, "var/lib/tunnex-agent/runtime-state.json"),
  };
  const previous = { bin: "previous-runtime-binary\n", unit: "[Service]\nExecStart=/usr/local/bin/tunnex-agent-runtime --previous\n", cfg: "[Interface]\nPrivateKey = enrolled+private/key=\n", cred: "tnx_enrolled_runtime_secret\n", state: '{"applied_revision":7}\n' };
  if (options.enrolled) {
    for (const path of ["etc/systemd/system", "etc/wireguard", "etc/tunnex-agent", "var/lib/tunnex-agent"]) mkdirSync(join(root, path), { recursive: true });
    writeFileSync(installed.bin, previous.bin, { mode: 0o755 }); writeFileSync(installed.unit, previous.unit, { mode: 0o644 });
    for (const name of ["cfg", "cred", "state"] as const) writeFileSync(installed[name], previous[name], { mode: 0o600 });
  }
  const execute = (built: string, extra: Record<string, string>) => {
      // No path rewrites exist in production. Remap only fixed host locations so
      // root mode can be executed without touching the developer's machine.
      let command = built;
      expect(command).not.toContain(token);
      command = command.replace(/\/(?:etc|usr\/local|var\/lib\/tunnex-agent|sys\/class\/net)(?=[/;"\s])/g, (path) => root + path);
      command = command.split("/dev/tty").join(tty);
      return spawnSync("/bin/sh", [], { input: command, encoding: "utf8", timeout: 30_000, env: {
        PATH: bin, FIXTURE_NODE: process.execPath, FIXTURE_DIR: dir, FIXTURE_BIN: bin, FIXTURE_ROOT: root,
        FIXTURE_AVAILABLE: available, FIXTURE_ASSETS: assets, FIXTURE_LOG: log, FIXTURE_EPHEMERAL: ephemeral,
        FIXTURE_ARCH: options.arch ?? "x86_64", FIXTURE_RESOLVED: resolver === "resolved" ? "1" : "0",
        FIXTURE_PACKAGE_AVAILABLE: resolver === "unavailable" ? "0" : "1", ...extra,
      } });
  };
  return {
    dir, bin, root, assets, release, log, ephemeral, installed, previous, runtime, unit,
    calls: () => existsSync(log) ? readGeneratedFile(log, dir) : "",
    run: (extra: Record<string, string> = {}) => execute(agentBootstrapCommand(release, "https://cp.example"), extra),
    runUpdate: (extra: Record<string, string> = {}) => execute(agentRuntimeUpdateCommand(release), { FIXTURE_RUNTIME_ACTIVE: "1", ...extra }),
  };
}
function deniedBeforeRedeem(f: ReturnType<typeof harness>, message: RegExp, extra?: Record<string, string>) {
  const result = f.run(extra);
  expect(result.error).toBeUndefined();
  expect(result.status, result.stderr).not.toBe(0);
  expect(result.stderr).toMatch(message);
  expect(existsSync(join(f.dir, "redeemed.json"))).toBe(false);
  expect(f.calls()).not.toContain("wg genkey");
  return result;
}
const installOnEnrolledHost = INSTALL_ON_ENROLLED_HOST;
const nothingChanged = "Tunnex agent runtime update stopped: nothing was changed on this host.";
// Bytes, mode and modification time of every installed file, plus the directory
// listings that would reveal a leftover temporary file.
function snapshot(f: ReturnType<typeof harness>) {
  const files = Object.fromEntries(Object.entries(f.installed).map(([name, path]) => {
    if (!existsSync(path)) return [name, null];
    const stat = statSync(path);
    return [name, { bytes: readGeneratedFile(path, f.dir), mode: stat.mode & 0o777, mtimeMs: stat.mtimeMs }];
  }));
  const listing = (path: string) => existsSync(join(f.root, path)) ? readdirSync(join(f.root, path)).sort() : null;
  return { files, bin: listing("usr/local/bin"), units: listing("etc/systemd/system"), credentials: listing("etc/tunnex-agent"), wireguard: listing("etc/wireguard"), state: listing("var/lib/tunnex-agent") };
}
function updateRefused(f: ReturnType<typeof harness>, message: RegExp, extra?: Record<string, string>) {
  const before = snapshot(f);
  const result = f.runUpdate(extra);
  expect(result.error).toBeUndefined();
  expect(result.status, result.stderr).not.toBe(0);
  expect(result.stderr).toMatch(message);
  expect(result.stderr.trim().split("\n").at(-1)).toBe(nothingChanged);
  expect(snapshot(f)).toEqual(before);
  const calls = f.calls();
  for (const untouched of ["systemctl daemon-reload", "systemctl restart", "systemctl enable", "systemctl disable", "systemctl stop", "apt-get", "stty", "wg "]) expect(calls).not.toContain(untouched);
  expect(existsSync(f.ephemeral)).toBe(false);
  return result;
}

describe("in-place runtime update on an enrolled host (executed shell)", { timeout: 45_000 }, () => {
  it("contains no token, prompt, enrolment call or key handling", () => {
    const command = agentRuntimeUpdateCommand(harness().release);
    for (const absent of ["/dev/tty", "stty", "bootstrap_token", "tnx_agent_", "install token", "/api/v1/", "wg genkey", "wg pubkey", "wg-quick", "wg show", "runtime-credential.snapshot", "runtime-cred.snapshot", "apt-get", "systemctl disable", "systemctl enable"]) expect(command, absent).not.toContain(absent);
    expect(command).toContain("fixture-public-key");
    expect(command.split("\n")[0]).toBe("sh <<'TUNNEX_RUNTIME_UPDATE'");
  });
  it.each([["as root", true], ["through sudo", false]])("replaces the runtime and its unit %s, restarts the service and keeps the agent's credential, tunnel and state", (_label, root) => {
    // No terminal exists on this host at all: the update must not need one.
    const f = harness({ enrolled: true, typed: null, root });
    const before = snapshot(f);
    const result = f.runUpdate();
    expect(result.status, result.stderr).toBe(0);
    const after = snapshot(f);
    expect(after.files.bin).toMatchObject({ bytes: f.runtime, mode: 0o755 });
    expect(after.files.unit).toMatchObject({ bytes: f.unit, mode: 0o644 });
    for (const name of ["cred", "cfg", "state"] as const) expect(after.files[name], name).toEqual(before.files[name]);
    for (const name of ["bin", "units", "credentials", "wireguard", "state"] as const) expect(after[name], name).toEqual(before[name]);
    const calls = f.calls();
    expect(calls.indexOf("verifier -manifest")).toBeGreaterThan(-1);
    expect(calls.indexOf("verifier -manifest")).toBeLessThan(calls.indexOf("systemctl daemon-reload"));
    expect(calls.indexOf("systemctl daemon-reload")).toBeLessThan(calls.indexOf("systemctl restart tunnex-agent-runtime.service"));
    expect(calls.match(/^systemctl restart/gm)).toHaveLength(1);
    expect(calls).toContain("-public-key fixture-public-key -expected-source-sha " + source + " -expected-key-id fixture-key -platform amd64");
    for (const absent of ["stty", "wg ", "apt-get", "/api/v1/", "runtime.conf", "runtime-state", "systemctl enable", "systemctl disable", "systemctl stop"]) expect(calls, absent).not.toContain(absent);
    // The only thing ever done with the credential is an existence test.
    for (const line of calls.split("\n").filter((entry) => entry.includes("runtime-credential"))) expect(line).toMatch(/^sudo test -[Lf] \S+runtime-credential$/);
    expect(existsSync(join(f.dir, "redeemed.json"))).toBe(false);
    expect(result.stdout.trim()).toBe("Tunnex agent runtime updated to v0.4.0 and restarted. The agent's identity, credential, tunnel and settings were not changed.");
    expect(result.stdout + result.stderr).not.toMatch(/tnx_enrolled_runtime_secret|enrolled\+private|install token|Paste/);
    expect(existsSync(f.ephemeral)).toBe(false);
  });
  it("accepts the release the control plane serves when the same runtime is already installed", () => {
    const f = harness({ enrolled: true });
    writeFileSync(f.installed.bin, f.runtime, { mode: 0o755 });
    const result = f.runUpdate();
    expect(result.status, result.stderr).toBe(0);
    expect(f.calls()).toContain("systemctl restart tunnex-agent-runtime.service");
  });
  it.each([["no managed runtime at all", []], ["a runtime without a credential", ["bin", "unit", "cfg", "state"]], ["a credential without a runtime", ["cred", "cfg", "state"]], ["a runtime that is a link", ["link", "unit", "cred"]]] as const)("refuses a host with %s and points at the install command", (_label, present) => {
    const f = harness({ enrolled: true });
    for (const [name, path] of Object.entries(f.installed)) if (!(present as readonly string[]).includes(name)) rmSync(path);
    if ((present as readonly string[]).includes("link")) symlinkSync("/missing-owned-runtime", f.installed.bin);
    const result = updateRefused(f, /This host is not enrolled as a Tunnex agent\. Use the install command from Add agent in Tunnex instead\./);
    expect(f.calls()).not.toContain("curl");
    expect(result.stderr.trim().split("\n")).toHaveLength(2);
  });
  it("changes nothing when the release signature is refused", () => {
    const f = harness({ enrolled: true });
    updateRefused(f, /signed release verification refused/, { FIXTURE_VERIFY_FAIL: "1" });
    expect(f.calls()).not.toContain("/tunnex-agent-runtime-linux-");
  });
  it("changes nothing when the verifier bytes were altered, and never runs them", () => {
    const f = harness({ enrolled: true });
    writeFileSync(join(f.assets, "releaseverify-linux-amd64"), "#!/bin/sh\necho unsafe-verifier-executed\n");
    const result = updateRefused(f, /verifier byte digest refused/);
    expect(f.calls()).not.toContain("verifier -manifest");
    expect(result.stdout).not.toContain("unsafe-verifier-executed");
    expect(result.stderr).not.toContain("bootstrap token");
  });
  it.each([["runtime binary", "tunnex-agent-runtime-linux-amd64", /runtime byte digest refused/], ["unit", "tunnex-agent-runtime.service", /runtime unit refused/]])("changes nothing when the downloaded %s does not match the signed digest", (_label, name, message) => {
    const f = harness({ enrolled: true });
    writeFileSync(join(f.assets, name), "tampered-bytes\n");
    updateRefused(f, message);
  });
  it("changes nothing when a download fails", () => {
    const f = harness({ enrolled: true });
    rmSync(join(f.assets, "tunnex-agent-runtime.service"));
    updateRefused(f, /update stopped/);
  });
  it.each(["os", "architecture", "systemd", "privileges"])("refuses unsupported %s and changes nothing", (kind) => {
    const f = harness({ enrolled: true, arch: kind === "architecture" ? "riscv64" : undefined, root: kind !== "privileges" });
    if (kind === "os") writeFileSync(join(f.root, "etc/os-release"), "ID=fedora\n");
    if (kind === "privileges") rmSync(join(f.bin, "sudo"));
    updateRefused(f, /Ubuntu\/Debian|unsupported runtime architecture|running systemd|root or sudo/, kind === "systemd" ? { FIXTURE_SYSTEMD_FAIL: "1" } : undefined);
    expect(f.calls()).not.toContain("curl");
  });
  it.each([["the restart fails", { FIXTURE_RESTART_FAIL: "1" }], ["the new runtime does not stay running", { FIXTURE_RUNTIME_ACTIVE: "0" }]])("restores the previous runtime and unit when %s, and says so", (_label, extra) => {
    const f = harness({ enrolled: true });
    const before = snapshot(f);
    const result = f.runUpdate(extra);
    expect(result.status, result.stderr).not.toBe(0);
    const after = snapshot(f);
    expect(after.files.bin).toMatchObject({ bytes: f.previous.bin, mode: 0o755 });
    expect(after.files.unit).toMatchObject({ bytes: f.previous.unit, mode: 0o644 });
    for (const name of ["cred", "cfg", "state"] as const) expect(after.files[name], name).toEqual(before.files[name]);
    for (const name of ["bin", "units", "credentials", "wireguard", "state"] as const) expect(after[name], name).toEqual(before[name]);
    const calls = f.calls();
    expect(calls.match(/^systemctl daemon-reload/gm)).toHaveLength(2);
    expect(calls.match(/^systemctl restart tunnex-agent-runtime.service/gm)).toHaveLength(2);
    const lines = result.stderr.trim().split("\n");
    expect(lines[0]).toBe("The updated runtime did not start.");
    expect(lines.at(-1)).toBe("Tunnex agent runtime update stopped: the previous runtime and unit were restored and the service was restarted. The agent's credential, tunnel and settings were not changed.");
    expect(result.stdout).not.toContain("updated to");
    expect(existsSync(f.ephemeral)).toBe(false);
  });
  it("uses a preinstalled verifier for an old release, and refuses when it is missing", () => {
    const f = harness({ enrolled: true, legacy: true });
    expect(f.runUpdate().status).toBe(0);
    expect(f.calls()).not.toContain("/releaseverify-linux-");
    const g = harness({ enrolled: true, legacy: true });
    rmSync(join(g.bin, "releaseverify"));
    updateRefused(g, /older release requires a preinstalled signed release verifier/);
    expect(g.calls()).not.toContain("curl");
  });
});

describe("automatic managed-agent host preparation (executed shell)", { timeout: 45_000 }, () => {
  it("prepares a host with missing tools and downloads a verified executable before redeeming", () => {
    const f = harness({ missing: ["wg", "wg-quick", "curl", "jq", "ip", "ca-certificates"] });
    const result = f.run();
    expect(result.status, result.stderr).toBe(0);
    const calls = f.calls();
    expect(calls).toContain("apt-get install -y --no-install-recommends --no-remove wireguard-tools curl jq iproute2 ca-certificates");
    expect(calls.indexOf("apt-get install")).toBeLessThan(calls.indexOf("curl"));
    expect(calls.indexOf("verifier -manifest")).toBeLessThan(calls.indexOf("wg genkey"));
    expect(JSON.parse(readGeneratedFile(join(f.dir, "redeemed.json"), f.dir))).toEqual({ bootstrap_token: token, public_key: "public-fixture-key=" });
    expect(readGeneratedFile(join(f.root, "etc/wireguard/runtime.conf"), f.dir)).toContain("PrivateKey = private+fixture/key=");
    expect(statSync(join(f.root, "etc/tunnex-agent/runtime-credential")).mode & 0o777).toBe(0o600);
    expect(statSync(join(f.root, "usr/local/bin/tunnex-agent-runtime")).mode & 0o777).toBe(0o755);
    expect(calls).toContain("systemctl enable --now tunnex-agent-runtime.service");
    expect(calls).not.toContain(token);
    expect(result.stdout + result.stderr).not.toMatch(/private\+fixture|tnx_fixture_runtime/);
    expect(existsSync(f.ephemeral)).toBe(false);
  });
  it("asks for the install token on the terminal with echo off, after host checks and before any change", () => {
    const f = harness({ missing: ["wg", "wg-quick"] });
    const result = f.run();
    expect(result.status, result.stderr).toBe(0);
    const calls = f.calls();
    expect(calls.indexOf("systemctl show")).toBeLessThan(calls.indexOf("stty -g"));
    expect(calls.indexOf("stty -g")).toBeLessThan(calls.indexOf("stty -echo"));
    expect(calls.indexOf("stty -echo")).toBeLessThan(calls.indexOf("stty fixture-tty-state"));
    expect(calls.indexOf("stty fixture-tty-state")).toBeLessThan(calls.indexOf("apt-get"));
    expect(calls.match(/^stty /gm)).toHaveLength(3);
    expect(result.stderr).toContain("Paste the install token");
    expect(result.stdout + result.stderr).not.toContain(token);
    expect(calls).not.toContain(token);
    expect(JSON.parse(readGeneratedFile(join(f.dir, "redeemed.json"), f.dir)).bootstrap_token).toBe(token);
  });
  it("accepts a token pasted with stray spaces or a Windows line ending", () => {
    const f = harness({ typed: `  ${token} \r\n` });
    const result = f.run();
    expect(result.status, result.stderr).toBe(0);
    expect(JSON.parse(readGeneratedFile(join(f.dir, "redeemed.json"), f.dir)).bootstrap_token).toBe(token);
  });
  it("stops without a terminal before packages, downloads or redemption", () => {
    const f = harness({ typed: null, missing: ["wg", "wg-quick"] });
    deniedBeforeRedeem(f, /a terminal is required to enter the install token.*no bootstrap token was used/);
    expect(f.calls()).not.toContain("apt-get");
    expect(f.calls()).not.toContain("curl");
    expect(f.calls()).not.toContain("stty -echo");
    expect(existsSync(f.ephemeral)).toBe(false);
  });
  it.each([["an empty entry", "\n"], ["something that is not a token", "sh <<'TUNNEX_BOOTSTRAP'\n"], ["a token with unexpected characters", "tnx_agent_abc$(id)\n"]])("refuses %s, restores the terminal, and never repeats what was typed", (_label, typed) => {
    const f = harness({ typed, missing: ["wg", "wg-quick"] });
    const result = deniedBeforeRedeem(f, /not an install token.*no bootstrap token was used/);
    expect(f.calls()).toContain("stty fixture-tty-state");
    expect(f.calls()).not.toContain("apt-get");
    expect(f.calls()).not.toContain("curl");
    if (typed.trim()) expect(result.stdout + result.stderr).not.toContain(typed.trim());
    expect(existsSync(f.ephemeral)).toBe(false);
  });
  it.each(["x86_64", "aarch64"])("uses the selected architecture %s and leaves existing dependencies/resolver alone", (arch) => {
    const f = harness({ arch, root: false });
    const result = f.run();
    expect(result.status, result.stderr).toBe(0);
    expect(f.calls()).not.toContain("apt-get");
    expect(f.calls()).toContain(`releaseverify-linux-${arch === "x86_64" ? "amd64" : "arm64"}`);
    expect(f.calls()).toContain("sudo -n true");
    expect(readGeneratedFile(join(f.root, "etc/resolv.conf"), f.dir)).toBe("nameserver 127.0.0.53\n");
    expect(existsSync(join(f.root, "usr/local/sbin/resolvconf"))).toBe(false);
  });
  it("uses a working passwordless command when sudo validation would request a password", () => {
    const f = harness({ root: false });
    const result = f.run({ FIXTURE_SUDO_VALIDATE: "0" });
    expect(result.status, result.stderr).toBe(0);
    expect(f.calls()).toContain("sudo -n true");
    expect(f.calls()).not.toContain("sudo -v");
  });
  it("falls back to interactive sudo validation when a password is required", () => {
    const f = harness({ root: false });
    const result = f.run({ FIXTURE_SUDO_NONINTERACTIVE: "0" });
    expect(result.status, result.stderr).toBe(0);
    expect(f.calls()).toContain("sudo -v");
  });
  it("refuses failed sudo authorization before packages and redemption", () => {
    const f = harness({ root: false, missing: ["wg", "wg-quick"] });
    deniedBeforeRedeem(f, /sudo authorization is required/, { FIXTURE_SUDO_NONINTERACTIVE: "0", FIXTURE_SUDO_VALIDATE: "0" });
    expect(f.calls()).not.toContain("apt-get");
    expect(f.calls()).not.toContain("curl");
  });
  it("adds only the missing compatibility link for an active working systemd resolver", () => {
    const f = harness({ resolver: "resolved" });
    const result = f.run();
    expect(result.status, result.stderr).toBe(0);
    expect(readlinkSync(join(f.root, "usr/local/sbin/resolvconf"))).toBe(join(f.bin, "resolvectl"));
    expect(readGeneratedFile(join(f.root, "etc/resolv.conf"), f.dir)).toBe("nameserver 127.0.0.53\n");
    expect(f.calls()).not.toContain("apt-get");
    expect(f.calls()).not.toContain("systemctl enable --now systemd-resolved");
  });
  it("installs available resolver compatibility without package removals", () => {
    const f = harness({ resolver: "package" });
    const result = f.run();
    expect(result.status, result.stderr).toBe(0);
    expect(f.calls()).toContain("apt-get install -y --no-install-recommends --no-remove openresolv");
    expect(readGeneratedFile(join(f.root, "etc/resolv.conf"), f.dir)).toBe("nameserver 127.0.0.53\n");
  });
  it("stops if resolver compatibility is unavailable before installing packages or redeeming", () => {
    const f = harness({ resolver: "unavailable", missing: ["wg", "wg-quick"] });
    deniedBeforeRedeem(f, /no supported resolver compatibility/);
    expect(f.calls()).not.toContain("apt-get install");
    expect(f.calls()).not.toContain("curl");
  });
  it("stops on dependency failure before downloads or redemption", () => {
    const f = harness({ missing: ["wg", "wg-quick"] });
    deniedBeforeRedeem(f, /could not refresh dependency packages/, { FIXTURE_APT_FAIL: "1" });
    expect(f.calls()).not.toContain("curl");
  });
  it("refuses altered verifier bytes before executing them", () => {
    const f = harness();
    writeFileSync(join(f.assets, "releaseverify-linux-amd64"), "#!/bin/sh\necho unsafe-verifier-executed\n");
    const result = deniedBeforeRedeem(f, /verifier byte digest refused/);
    expect(f.calls()).not.toContain("verifier -manifest");
    expect(result.stdout).not.toContain("unsafe-verifier-executed");
    expect(existsSync(f.ephemeral)).toBe(false);
  });
  it("refuses a failed runtime signature check before downloading or executing the runtime", () => {
    const f = harness();
    deniedBeforeRedeem(f, /signed release verification refused/, { FIXTURE_VERIFY_FAIL: "1" });
    expect(f.calls()).not.toContain("/tunnex-agent-runtime-linux-");
  });
  it.each(["file", "dangling link", "interface"])("refuses an existing %s before package changes", (kind) => {
    const f = harness({ missing: ["wg", "wg-quick"] });
    const path = join(f.root, kind === "interface" ? "sys/class/net/runtime" : "usr/local/bin/tunnex-agent-runtime");
    if (kind === "interface") mkdirSync(path, { recursive: true });
    else if (kind === "dangling link") symlinkSync("/missing-owned-runtime", path);
    else writeFileSync(path, "existing-runtime");
    // A leftover is not an enrolled agent: "Update runtime" would refuse it, so it is named instead.
    const result = deniedBeforeRedeem(f, /Part of an earlier Tunnex agent installation is still on this host: .*(tunnex-agent-runtime|the runtime network interface)\. Nothing was changed and the install token was not used\. Remove it, then run this command again\./);
    expect(result.stderr).not.toContain("Update runtime");
    expect(f.calls()).not.toContain("apt-get");
    expect(f.calls()).not.toContain("curl");
    expect(f.calls()).not.toContain("stty");
    expect(result.stderr).not.toContain("Paste the install token");
    if (kind === "file") expect(readGeneratedFile(path, f.dir)).toBe("existing-runtime");
  });
  it("on an enrolled host, points at Update runtime, asks for no token and changes nothing", () => {
    const f = harness({ enrolled: true });
    const before = snapshot(f);
    const result = deniedBeforeRedeem(f, /This host already runs a Tunnex agent/);
    expect(result.stderr.trim()).toBe(installOnEnrolledHost);
    expect(snapshot(f)).toEqual(before);
    const calls = f.calls();
    for (const untouched of ["stty", "curl", "apt-get", "systemctl daemon-reload", "systemctl enable", "systemctl restart", "systemctl disable"]) expect(calls).not.toContain(untouched);
    expect(existsSync(f.ephemeral)).toBe(false);
  });
  it.each(["os", "architecture", "systemd", "privileges"])("refuses unsupported %s before any host mutation", (kind) => {
    const f = harness({ missing: ["wg", "wg-quick"], arch: kind === "architecture" ? "riscv64" : undefined, root: kind !== "privileges" });
    if (kind === "os") writeFileSync(join(f.root, "etc/os-release"), "ID=fedora\n");
    if (kind === "privileges") rmSync(join(f.bin, "sudo"));
    deniedBeforeRedeem(f, /Ubuntu\/Debian|unsupported runtime architecture|running systemd|root or sudo/, kind === "systemd" ? { FIXTURE_SYSTEMD_FAIL: "1" } : undefined);
    expect(f.calls()).not.toContain("apt-get");
    expect(f.calls()).not.toContain("curl");
  });
  it("preserves the preinstalled-verifier path for old releases", () => {
    const f = harness({ legacy: true });
    const result = f.run();
    expect(result.status, result.stderr).toBe(0);
    expect(f.calls()).toContain("verifier -manifest");
    expect(f.calls()).not.toContain("/releaseverify-linux-");
  });
  it("explains the legacy requirement and stops before package changes when its verifier is missing", () => {
    const f = harness({ legacy: true, missing: ["wg", "wg-quick"] });
    rmSync(join(f.bin, "releaseverify"));
    deniedBeforeRedeem(f, /older release requires a preinstalled signed release verifier/);
    expect(f.calls()).not.toContain("apt-get");
    expect(f.calls()).not.toContain("curl");
  });
});
