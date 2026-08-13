import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";

// S6.5a — the in-app privileged helper install (the "zero terminal" step). On macOS
// the packaged, UNSIGNED app can't use SMAppService (needs Developer ID → S6.5b), so
// on first connect it installs the bundled helper as a LaunchDaemon via ONE GUI admin
// prompt (osascript's `with administrator privileges`). This is the FALLBACK for a
// non-.pkg install (dragged .app); the .pkg postinstall is the primary path. Windows
// registers its SCM service at NSIS install time, so this is a no-op there.

const LABEL = "io.tunnex.helper";
const PLIST = `/Library/LaunchDaemons/${LABEL}.plist`;
const INSTALL_DIR = "/usr/local/tunnex"; // no spaces — keeps the root shell script simple
const HELPER_DEST = `${INSTALL_DIR}/tunnex-helper`;
const SOCKET = "/var/run/tunnex/helper.sock";
// Root daemon log lives in a ROOT-OWNED dir, never world-writable /tmp (a predictable
// /tmp path for a root O_CREAT|O_APPEND is a symlink-clobber vector — review #8).
const HELPER_LOG = "/var/run/tunnex/helper.log";

// helperInstalled is the cheap presence check (the daemon plist exists). Connect uses
// it to decide whether to run the one-time install before dialing the helper socket.
export function helperInstalled(platform: NodeJS.Platform = process.platform): boolean {
  if (platform !== "darwin") return true; // windows: installed by NSIS; nothing to do here
  return fs.existsSync(PLIST);
}

// macOS's launchd plist is the source of truth for which Electron executable the
// root helper will accept.  An unsigned/dev Electron app can move when its runtime
// is reinstalled, so a plist merely existing is not enough: the helper would then
// reject the caller after Connect and leave the user with a confusing retry path.
// Keep this parser deliberately narrow: we only read our own scalar environment
// value, never execute or trust any plist content.
function xmlUnescape(value: string): string {
  return value
    .replace(/&apos;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&gt;/g, ">")
    .replace(/&lt;/g, "<")
    .replace(/&amp;/g, "&");
}

function installDirsFromPlist(plist: string): string[] {
  const match = plist.match(/<key>TUNNEX_INSTALL_DIR<\/key>\s*<string>([\s\S]*?)<\/string>/);
  if (!match) return [];
  // This value is written and consumed by the macOS LaunchDaemon, whose path
  // separator is always `:`. Unit tests also run on Windows, where
  // path.delimiter is `;`; using the host delimiter there incorrectly treats
  // multiple trusted macOS paths as a single entry.
  return xmlUnescape(match[1]).split(":").filter(Boolean);
}

function canonicalPath(value: string): string {
  try {
    return fs.realpathSync.native(value);
  } catch {
    return path.resolve(value);
  }
}

function trustedInstallDirsContain(executable: string, installDirs: string[]): boolean {
  const exe = canonicalPath(executable).toLowerCase();
  return installDirs.some((dir) => {
    const trusted = canonicalPath(dir).toLowerCase();
    return exe === trusted || exe.startsWith(`${trusted}${path.sep}`);
  });
}

function helperTrustsCurrentCaller(executable = process.execPath): boolean {
  try {
    return trustedInstallDirsContain(executable, installDirsFromPlist(fs.readFileSync(PLIST, "utf8")));
  } catch {
    // A missing/unreadable plist is repaired by the existing one-time installer.
    return false;
  }
}

// A plist only proves that *some* helper was installed. It does not prove that
// the root LaunchDaemon is running the helper bundled with this app release.
// On an app upgrade that left the existing plist in place, treating presence as
// freshness stranded the old helper and silently skipped new privileged fixes.
// Compare bytes, rather than a separately maintained helper version, so the
// installed daemon is repaired exactly when its bundled helper changes.
function helperBinaryMatchesStaged(staged: string, installed = HELPER_DEST): boolean {
  try {
    const digest = (file: string) => createHash("sha256").update(fs.readFileSync(file)).digest("hex");
    return digest(staged) === digest(installed);
  } catch {
    return false;
  }
}

// stagedHelperPath is the bundled helper inside the app's resources (universal binary).
// process.resourcesPath is an Electron augmentation — cast so the module also compiles
// under plain node (the unit tests run via ts-node without electron's ambient types).
function stagedHelperPath(): string {
  const resourcesPath = (process as unknown as { resourcesPath?: string }).resourcesPath ?? "";
  return path.join(resourcesPath, "helper", "tunnex-helper");
}

// callerTrustDir is the directory the helper must trust as the caller: the packaged
// app's main executable dir (…/Tunnex.app/Contents/MacOS).
function callerTrustDir(): string {
  return path.dirname(process.execPath);
}

// shq POSIX-single-quotes a value for safe embedding in the shell script — escapes an
// embedded quote as '\'' (review #1: a path with an apostrophe would otherwise break
// the quoting and inject into the ROOT shell).
function shq(s: string): string {
  return `'${s.replace(/'/g, "'\\''")}'`;
}

// installScript is the root shell script run under the single admin prompt. It is a
// PLAIN shell script written to a file (runPrivileged executes the file path, NOT an
// inlined body), so nothing here is double-escaped — the pf-anchor line uses ordinary
// quoting (review #0). Dynamic paths go through shq().
function installScript(staged: string, trustDir: string): string {
  return [
    "#!/bin/sh",
    "set -e",
    `mkdir -p ${shq(INSTALL_DIR)} ${shq("/var/run/tunnex")}`,
    `cp ${shq(staged)} ${shq(HELPER_DEST)}`,
    `chown root:wheel ${shq(HELPER_DEST)}`,
    `chmod 755 ${shq(HELPER_DEST)}`,
    `codesign --force --sign - ${shq(HELPER_DEST)}`,
    // pf anchor reference — mirrors the dev-install so the kill-switch anchor is live.
    // Plain quoting (the script is a file, not an AppleScript-escaped string).
    `if ! grep -q 'anchor "tunnex"' /etc/pf.conf; then cp /etc/pf.conf /etc/pf.conf.tunnex-bak; printf '%s\\n' 'anchor "tunnex"' >> /etc/pf.conf; pfctl -f /etc/pf.conf 2>/dev/null || true; fi`,
    `cat > ${shq(PLIST)} <<'PL'`,
    `<?xml version="1.0" encoding="UTF-8"?>`,
    `<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">`,
    `<plist version="1.0"><dict>`,
    `  <key>Label</key><string>${LABEL}</string>`,
    `  <key>ProgramArguments</key><array><string>${HELPER_DEST}</string></array>`,
    `  <key>EnvironmentVariables</key><dict>`,
    `    <key>TUNNEX_INSTALL_DIR</key><string>${trustDir}</string>`,
    `    <key>TUNNEX_HELPER_SOCKET</key><string>${SOCKET}</string>`,
    `  </dict>`,
    `  <key>RunAtLoad</key><true/>`,
    `  <key>KeepAlive</key><true/>`,
    `  <key>StandardErrorPath</key><string>${HELPER_LOG}</string>`,
    `</dict></plist>`,
    `PL`,
    `chown root:wheel ${shq(PLIST)}`,
    `chmod 644 ${shq(PLIST)}`,
    `launchctl bootout system ${shq(PLIST)} 2>/dev/null || true`,
    `launchctl bootstrap system ${shq(PLIST)}`,
  ].join("\n");
}

// appleQuote escapes a value for an AppleScript string literal. Only the (fixed,
// controlled) temp-script PATH and the prompt cross this layer — never the script body.
function appleQuote(s: string): string {
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

// runPrivileged writes the script to a USER-PRIVATE temp file (os.tmpdir is per-user,
// mode-0700 on macOS — no cross-user TOCTOU) and runs it as root via ONE GUI admin
// prompt. osascript executes the FILE PATH, so the script body isn't AppleScript-escaped.
function runPrivileged(script: string, prompt: string): Promise<void> {
  const tmp = path.join(os.tmpdir(), `tunnex-install-${process.pid}-${process.hrtime.bigint()}.sh`);
  fs.writeFileSync(tmp, `${script}\n`, { mode: 0o700 });
  const osa = `do shell script ${appleQuote(`/bin/sh ${tmp}`)} with administrator privileges with prompt ${appleQuote(prompt)}`;
  return new Promise((resolve, reject) => {
    execFile("/usr/bin/osascript", ["-e", osa], (err, _stdout, stderr) => {
      try {
        fs.unlinkSync(tmp);
      } catch {
        /* best-effort cleanup */
      }
      if (err) {
        const canceled = /-128|User canceled/i.test(stderr || String(err)); // -128 = user cancelled
        reject(new Error(canceled ? "helper_install_canceled" : `helper_install_failed: ${stderr || err.message}`));
        return;
      }
      resolve();
    });
  });
}

// waitForSocket polls for the helper's socket after a fresh install — `launchctl
// bootstrap` returns before the RunAtLoad daemon binds its socket, so the very Connect
// that installed the helper would otherwise race and fail (review #9). Best-effort:
// returns on appearance or timeout; a still-absent socket surfaces via the connect error.
async function waitForSocket(sock: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(sock)) return;
    await new Promise((r) => setTimeout(r, 150));
  }
}

// isTranslocated reports whether macOS is running the app from a randomized read-only
// App Translocation mount (unsigned + quarantined app launched from outside /Applications).
// The exec path there is EPHEMERAL, so installing a helper that trusts it produces
// caller_untrusted next launch. Guard: refuse with an actionable error.
function isTranslocated(): boolean {
  return process.platform === "darwin" && process.execPath.includes("/AppTranslocation/");
}

// ensureHelperInstalled installs the privileged helper if it isn't already. Idempotent,
// no-op off macOS (and after the .pkg postinstall already installed it). Throws
// app_translocated / helper_install_canceled / helper_install_failed / helper_asset_missing.
export async function ensureHelperInstalled(): Promise<void> {
  if (process.platform !== "darwin") return;
  // A matching plist means the helper will accept THIS app's executable, so a
  // normal quit/reopen never asks again. A stale dev/unsigned install is repaired
  // once with the current app path instead of failing later as caller_untrusted.
  if (isTranslocated()) throw new Error("app_translocated"); // move to /Applications, reopen
  const staged = stagedHelperPath();
  if (!fs.existsSync(staged)) throw new Error("helper_asset_missing");
  // Existing installs must match the helper inside THIS app release. A caller
  // trust match alone is insufficient: it leaves a stale root daemon running
  // after a desktop update. Re-running the idempotent installer atomically
  // replaces the helper and reboots only the LaunchDaemon.
  if (helperInstalled() && helperTrustsCurrentCaller() && helperBinaryMatchesStaged(staged)) return;
  await runPrivileged(installScript(staged, callerTrustDir()), "Tunnex needs to install its VPN helper.");
  await waitForSocket(SOCKET, 5000); // don't race the RunAtLoad daemon's socket bind
}

// installScriptForTest exposes the generated script for unit assertions (escaping is the
// bug class the review caught — pin it).
export const __test = { installScript, shq, installDirsFromPlist, trustedInstallDirsContain, helperBinaryMatchesStaged };
