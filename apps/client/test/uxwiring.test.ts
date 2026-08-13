import { test } from "node:test";
import assert from "node:assert/strict";

import { messageFor, postureCheckSummary } from "../src/main/notifyview";
import { trayIconAssetNamesFor, trayIconSizeFor, trayIconSvg, trayIconVariantFor, trayMenuModel, trayStateFor } from "../src/main/trayview";

// The PURE view-models live in electron-free modules (notifyview / trayview) so they
// import cleanly in CI, where ELECTRON_SKIP_BINARY_DOWNLOAD makes require("electron")
// throw. The Electron wiring (notify.ts / tray.ts) is live-verified at S6.5a packaging.

test("notify: every tunnel event has non-empty, distinct copy", () => {
  const events = ["connected", "disconnected", "failed", "revoked", "pending", "approved", "migrated", "migrate_retry", "posture_warning", "posture_blocked"] as const;
  const titles = new Set<string>();
  for (const ev of events) {
    const { title, body } = messageFor(ev);
    assert.ok(title.length > 0 && body.length > 0, `${ev} has copy`);
    titles.add(title);
  }
  assert.equal(titles.size, events.length); // no two events share a title
  // The revoked message must actually say "revoked" — a revoked device disconnects
  // LOUDLY (watch-item #1), not with a generic "disconnected".
  assert.match(messageFor("revoked").body, /revoked/i);
  assert.match(messageFor("failed").body, /kill-switch/i);
});

test("notify: posture messages name the server-evaluated failed checks", () => {
  const checks = [
    { kind: "disk_encryption", mode: "require" },
    { kind: "os_version", mode: "warn" },
  ];
  assert.match(postureCheckSummary(checks), /disk encryption/i);
  assert.match(postureCheckSummary(checks), /operating system/i);
  assert.match(messageFor("posture_blocked", checks).body, /disk encryption/i);
  assert.match(messageFor("posture_warning", checks).body, /minimum version/i);
});

test("tray: menu model offers the right actions per state", () => {
  // Connected → only Disconnect.
  assert.deepEqual(trayMenuModel("connected"), { statusLabel: "Connected", showConnect: false, showDisconnect: true });
  // Disconnected → only Connect.
  assert.equal(trayMenuModel("disconnected").showConnect, true);
  assert.equal(trayMenuModel("disconnected").showDisconnect, false);
  // Failed (kill-switch active) → BOTH: reconnect or tear the kill-switch down.
  const failed = trayMenuModel("failed");
  assert.ok(failed.showConnect && failed.showDisconnect);
  assert.match(failed.statusLabel, /kill-switch/i);
  // Revoked → reconnect only (the dead config was already cleared).
  const revoked = trayMenuModel("revoked");
  assert.ok(revoked.showConnect && !revoked.showDisconnect);
  assert.match(revoked.statusLabel, /revoked/i);
  // Connecting → only Disconnect (cancel), never a spurious Connect.
  const connecting = trayMenuModel("connecting");
  assert.equal(connecting.showConnect, false);
  assert.equal(connecting.showDisconnect, true);
});

test("tray: brand badge is compact, circle-free, and state-aware", () => {
  assert.equal(trayIconVariantFor("connected"), "connected");
  assert.equal(trayIconVariantFor("posture_warning"), "connected");
  assert.equal(trayIconVariantFor("disconnected"), "idle");
  assert.equal(trayIconSizeFor("darwin"), 16);
  assert.equal(trayIconSizeFor("win32"), 20);
  assert.deepEqual(trayIconAssetNamesFor("darwin", "connected"), { normal: "connected.png", retina: "connected@2x.png" });
  assert.deepEqual(trayIconAssetNamesFor("win32", "idle"), { normal: "idle-win.png", retina: "idle-win@2x.png" });

  const connected = trayIconSvg("connected");
  assert.match(connected, /width="16" height="16"/);
  assert.match(connected, /#ee1d36/); // connected Tunnex red
  assert.match(connected, /M14\.25 11h1\.6/); // thin left-shifted brand cut
  assert.doesNotMatch(connected, /<circle cx="16" cy="16" r=/); // no outer circular badge

  const idle = trayIconSvg("idle");
  assert.match(idle, /#d7d7da/);
  assert.match(idle, /fill="#171719"/); // compact black backing badge remains
});

test("tray: trayStateFor mirrors the renderer's handshake-liveness (no drift)", () => {
  const now = Math.floor(Date.now() / 1000);
  // up + FRESH handshake → connected.
  assert.equal(trayStateFor({ state: "up", last_handshake_sec: now - 5 }), "connected");
  // up but STALE / no handshake → connecting (matches the renderer's amber state, not
  // a premature "Connected").
  assert.equal(trayStateFor({ state: "up", last_handshake_sec: now - 600 }), "connecting");
  assert.equal(trayStateFor({ state: "up" }), "connecting");
  assert.equal(trayStateFor({ state: "failed" }), "failed");
  assert.equal(trayStateFor({ state: "revoked" }), "revoked");
  // S7.3: a failed legacy-config replacement surfaces a DISTINCT state (not bare
  // "disconnected"), so a stuck migration is legible in the tray/window even with OS
  // notifications off — mirrors the revoked synth-state.
  assert.equal(trayStateFor({ state: "migrate_failed" }), "migrate_retry");
  const mr = trayMenuModel("migrate_retry");
  assert.ok(mr.showConnect && !mr.showDisconnect); // reconnect retries; nothing to disconnect
  assert.match(mr.statusLabel, /replace device|retry/i);
  // S7.5.3 [2]: a server-side require-mode block surfaces as a DISTINCT state — the
  // interface is up but the gateway dropped the peer, so the tray must NOT read
  // "connected". Reconnect wouldn't help (still non-compliant); it auto-reconnects on
  // the next compliant report, so offer disconnect only.
  assert.equal(trayStateFor({ state: "posture_blocked" }), "posture_blocked");
  const pb = trayMenuModel("posture_blocked");
  assert.ok(!pb.showConnect && pb.showDisconnect);
  assert.match(pb.statusLabel, /posture/i);
  assert.match(messageFor("posture_blocked").body, /posture|encryption|update/i);
  assert.equal(trayStateFor({ state: "posture_warning" }), "posture_warning");
  const pw = trayMenuModel("posture_warning");
  assert.ok(!pw.showConnect && pw.showDisconnect);
  assert.match(messageFor("posture_warning").body, /recommended|access/i);
  assert.equal(trayStateFor({ state: "down" }), "disconnected");
});
