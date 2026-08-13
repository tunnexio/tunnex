import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { __test } from "../src/main/helperinstall";

const { installScript, shq, installDirsFromPlist, trustedInstallDirsContain, helperBinaryMatchesStaged } = __test;

// These pin the two CONFIRMED security-critical review findings so they can't regress:
//   #0 — the pf-anchor line was double-escaped, silently disarming the kill-switch.
//   #1 — an app path with an apostrophe injected into the ROOT shell.

test("shq POSIX-single-quotes and escapes embedded apostrophes", () => {
  assert.equal(shq("/usr/local/tunnex"), "'/usr/local/tunnex'");
  // An apostrophe must close-escape-reopen: O'Brien → 'O'\''Brien'
  assert.equal(shq("/Users/O'Brien/Tunnex.app"), "'/Users/O'\\''Brien/Tunnex.app'");
});

test("installScript emits a CORRECT pf-anchor line (not double-escaped)", () => {
  const s = installScript("/tmp/staged/tunnex-helper", "/Applications/Tunnex.app/Contents/MacOS");
  // The anchor test + append must be the real pf token `anchor "tunnex"` — NOT a
  // backslash-mangled `anchor \"tunnex\"` that never matches and corrupts pf.conf.
  assert.match(s, /grep -q 'anchor "tunnex"' \/etc\/pf\.conf/);
  assert.match(s, /printf '%s\\n' 'anchor "tunnex"' >> \/etc\/pf\.conf/);
  assert.doesNotMatch(s, /anchor \\"tunnex\\"/); // the buggy form must not appear
});

test("installScript shell-quotes an apostrophe path safely (no root injection)", () => {
  const s = installScript("/Users/O'Brien/Tunnex.app/Contents/Resources/helper/tunnex-helper", "/Users/O'Brien/Tunnex.app/Contents/MacOS");
  // The staged path must be single-quoted with the apostrophe escaped — never a bare
  // `cp '/Users/O'Brien/...'` that breaks quoting.
  assert.match(s, /cp '\/Users\/O'\\''Brien\/.*tunnex-helper'/);
});

test("installScript logs to a root-owned dir, not world-writable /tmp", () => {
  const s = installScript("/tmp/staged/tunnex-helper", "/Applications/Tunnex.app/Contents/MacOS");
  assert.match(s, /StandardErrorPath<\/key><string>\/var\/run\/tunnex\/helper\.log/);
  assert.doesNotMatch(s, /\/tmp\/tunnex-helper\.log/);
});

test("a matching trusted caller skips the repair prompt after reopen", () => {
  const dirs = installDirsFromPlist(`<?xml version="1.0"?><plist><dict>
    <key>TUNNEX_INSTALL_DIR</key><string>/Applications/Tunnex.app/Contents/MacOS</string>
  </dict></plist>`);
  assert.deepEqual(dirs, ["/Applications/Tunnex.app/Contents/MacOS"]);
  assert.equal(trustedInstallDirsContain("/Applications/Tunnex.app/Contents/MacOS/Tunnex", dirs), true);
});

test("a stale trusted path is repaired once instead of failing caller authentication", () => {
  const dirs = installDirsFromPlist(`<key>TUNNEX_INSTALL_DIR</key><string>/old/Electron.app/Contents/MacOS:/usr/local/tunnex</string>`);
  assert.equal(trustedInstallDirsContain("/new/Electron.app/Contents/MacOS/Electron", dirs), false);
  assert.equal(trustedInstallDirsContain("/usr/local/tunnex/tunnelctl", dirs), true);
});

test("a stale installed helper is not treated as current after a desktop upgrade", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tunnex-helperinstall-"));
  try {
    const staged = path.join(dir, "staged-helper");
    const installed = path.join(dir, "installed-helper");
    fs.writeFileSync(staged, "rc29-helper");
    fs.writeFileSync(installed, "rc28-helper");
    assert.equal(helperBinaryMatchesStaged(staged, installed), false);
    fs.writeFileSync(installed, "rc29-helper");
    assert.equal(helperBinaryMatchesStaged(staged, installed), true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
