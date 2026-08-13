import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { bearerFor } from "../src/main/session";
import { cspFor } from "../src/main/csp";
import { looksLikeAsset, contained, resolveBundlePath } from "../src/main/bundle";
import { AUTOUPDATE_ENABLED } from "../src/main/flags";
import { StoredCredential } from "../src/main/credential";

const origin = "https://api.example";
const live: StoredCredential = { server: origin, token: "tnx_live", fingerprint: "fp", expiresAt: "2999-01-01T00:00:00Z" };

// ---- bearer injection: the never-cross-servers invariant, enforced locally ---
test("bearerFor attaches ONLY to the exact minting server + origin, unexpired", () => {
  const now = new Date("2026-01-01");
  // Happy path.
  assert.equal(bearerFor(origin + "/api/v1/organizations", origin, live, now), "Bearer tnx_live");
  // No credential / no origin.
  assert.equal(bearerFor(origin + "/x", origin, null, now), null);
  assert.equal(bearerFor(origin + "/x", "", live, now), null);
  // CROSS-SERVER: config origin differs from where the credential was minted.
  assert.equal(bearerFor("https://other.example/x", "https://other.example", live, now), null);
  // Sub-origin / userinfo tricks must not match origin+"/".
  assert.equal(bearerFor("https://api.example.evil.com/x", origin, live, now), null);
  assert.equal(bearerFor("https://api.example@evil.com/x", origin, live, now), null);
  // Expired → not attached (local expiry, no server oracle).
  assert.equal(bearerFor(origin + "/x", origin, { ...live, expiresAt: "2000-01-01T00:00:00Z" }, now), null);
});

// ---- CSP present + origin-scoped connect-src ---------------------------------
test("cspFor is strict and scopes connect-src to the configured server", () => {
  const csp = cspFor(origin);
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /script-src 'self'/);
  assert.match(csp, new RegExp(`connect-src 'self' ${origin.replace(/\./g, "\\.")}`));
  assert.match(csp, /frame-ancestors 'none'/);
  // Unset server → only 'self' in connect-src.
  assert.match(cspFor(""), /connect-src 'self'(;|$)/);
});

// ---- asset vs document fallback (no 404-masking) -----------------------------
test("looksLikeAsset distinguishes files from navigation paths", () => {
  for (const a of ["/assets/app.js", "/x/y.css", "/favicon.ico", "/logo.svg"]) assert.equal(looksLikeAsset(a), true, a);
  for (const d of ["/", "/dashboard", "/devices", "/create-org"]) assert.equal(looksLikeAsset(d), false, d);
});

// ---- symlink escape: lexical resolve passes, realpath containment catches it -
test("contained + realpath catches a symlink planted inside the bundle", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "bundle-"));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "outside-"));
  fs.writeFileSync(path.join(outside, "secret"), "SECRET");
  const link = path.join(root, "leak.js");
  try {
    fs.symlinkSync(path.join(outside, "secret"), link);
    // Lexical resolve PASSES (the link path is under root)...
    const lex = resolveBundlePath(root, "/leak.js");
    assert.equal(lex, link);
    // ...but the realpath is OUTSIDE root, so contained() rejects it.
    const real = fs.realpathSync(link);
    assert.equal(contained(fs.realpathSync(root), real), false);
    // A genuine in-bundle file is contained.
    fs.writeFileSync(path.join(root, "app.js"), "ok");
    assert.equal(contained(fs.realpathSync(root), fs.realpathSync(path.join(root, "app.js"))), true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

// ---- updater inert (pinned) --------------------------------------------------
test("AUTOUPDATE_ENABLED is false (updater inert until S6.5 signing)", () => {
  assert.equal(AUTOUPDATE_ENABLED, false);
});
