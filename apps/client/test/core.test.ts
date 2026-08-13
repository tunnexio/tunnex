import { test } from "node:test";
import assert from "node:assert/strict";
import * as path from "node:path";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

import { resolveBundlePath } from "../src/main/bundle";
import { normalizeServerUrl, validateServer, serverChangeRequiresRelogin } from "../src/main/serverurl";
import { CredentialStore, InsecureStorageError, StoredCredential, SafeStorageLike, Persistence } from "../src/main/credential";
import { evalCallback, generatePkce } from "../src/main/loopback";
import { consentUrl, exchangeCode } from "../src/main/exchange";
import * as crypto from "node:crypto";

// ---- app:// path escape-rejection (the security core of the protocol) --------
test("resolveBundlePath serves in-bundle files and REJECTS escapes", () => {
  // Resolve the fixture root for the host platform (Windows prefixes a drive) so
  // expectations match resolveBundlePath's own absolute resolution — the function
  // is correct cross-platform; only a POSIX-literal fixture broke on Windows CI.
  const root = path.resolve("/app/bundle");
  assert.equal(resolveBundlePath(root, "/"), path.join(root, "index.html"));
  assert.equal(resolveBundlePath(root, "/index.html"), path.join(root, "index.html"));
  assert.equal(resolveBundlePath(root, "/assets/app.js"), path.join(root, "assets/app.js"));
  // Escapes → null.
  for (const bad of [
    "/../etc/passwd",
    "/../../secret",
    "/assets/../../etc/passwd",
    "/%2e%2e/%2e%2e/etc/passwd", // encoded traversal
    "/foo\0bar",
    "/foo\\bar", // backslash
  ]) {
    assert.equal(resolveBundlePath(root, bad), null, `must reject ${bad}`);
  }
  // The /root-evil prefix trap: a sibling dir sharing the prefix is NOT inside.
  assert.equal(resolveBundlePath(root, "/../bundle-evil/x"), null);
});

// ---- server URL: shape + /healthz validation + relogin-on-change -------------
test("normalizeServerUrl accepts base URLs only", () => {
  assert.equal(normalizeServerUrl("https://tunnex.example"), "https://tunnex.example");
  assert.equal(normalizeServerUrl(" http://10.0.0.1:8080 "), "http://10.0.0.1:8080");
  for (const bad of ["ftp://x", "https://x/path", "https://x?q=1", "not a url", "https://x#f"]) {
    assert.throws(() => normalizeServerUrl(bad), /.*/, `must reject ${bad}`);
  }
});

test("validateServer requires a live /healthz", async () => {
  const ok = await validateServer("https://good.example", async (u) => {
    assert.equal(u, "https://good.example/healthz");
    return { ok: true, status: 200 };
  });
  assert.equal(ok, "https://good.example");
  await assert.rejects(validateServer("https://bad.example", async () => ({ ok: false, status: 502 })));
  await assert.rejects(
    validateServer("https://dead.example", async () => {
      throw new Error("ECONNREFUSED");
    }),
  );
});

test("serverChangeRequiresRelogin: credential must never cross servers", () => {
  assert.equal(serverChangeRequiresRelogin("", "https://a.example", true), false); // first set
  assert.equal(serverChangeRequiresRelogin("https://a.example", "https://a.example", true), false); // same
  assert.equal(serverChangeRequiresRelogin("https://a.example", "https://b.example", true), true); // changed
  assert.equal(serverChangeRequiresRelogin("https://a.example", "https://b.example", false), false); // no cred
});

// ---- credential store: keychain vs REFUSE-by-default -------------------------
function fakePersist(): Persistence & { buf: Buffer | null } {
  return {
    buf: null,
    read() {
      return this.buf;
    },
    write(b: Buffer) {
      this.buf = b;
    },
    clear() {
      this.buf = null;
    },
  };
}
const cred: StoredCredential = { server: "https://x", token: "tnx_secret", fingerprint: "abc", expiresAt: "2999-01-01T00:00:00Z" };

test("with a keychain, the credential round-trips encrypted (never plaintext on disk)", () => {
  // A fake that actually OBSCURES (base64) so "no plaintext on disk" is a real
  // assertion, not a tautology against a passthrough.
  const safe: SafeStorageLike = {
    isEncryptionAvailable: () => true,
    encryptString: (s) => Buffer.from("ENC:" + Buffer.from(s).toString("base64")),
    decryptString: (b) => Buffer.from(b.toString("utf8").slice(4), "base64").toString("utf8"),
  };
  const p = fakePersist();
  const store = new CredentialStore(safe, p, false);
  store.save(cred);
  const onDisk = p.buf!.toString("utf8");
  assert.ok(onDisk.startsWith("ENC:"), "stored via safeStorage");
  assert.ok(!onDisk.includes("tnx_secret"), "raw token must NOT appear on disk");
  assert.deepEqual(store.load(), cred);
  store.clear();
  assert.equal(store.load(), null);
});

test("NO keychain + no opt-in → REFUSE (InsecureStorageError), disk stays empty", () => {
  const safe: SafeStorageLike = { isEncryptionAvailable: () => false, encryptString: () => Buffer.from(""), decryptString: () => "" };
  const p = fakePersist();
  const store = new CredentialStore(safe, p, false);
  assert.throws(() => store.save(cred), InsecureStorageError);
  assert.equal(p.buf, null, "nothing written on refusal");
  assert.equal(store.available(), false);
});

test("NO keychain + explicit opt-in → plaintext with a visible marker, loadable", () => {
  const safe: SafeStorageLike = { isEncryptionAvailable: () => false, encryptString: () => Buffer.from(""), decryptString: () => "" };
  const p = fakePersist();
  const store = new CredentialStore(safe, p, true);
  store.save(cred);
  assert.ok(p.buf!.toString("utf8").startsWith("PLAINTEXT:"));
  assert.deepEqual(store.load(), cred);
  assert.equal(store.available(), true);
});

test("isExpired reads local expiry (no server oracle)", () => {
  assert.equal(CredentialStore.isExpired({ ...cred, expiresAt: "2000-01-01T00:00:00Z" }, new Date("2026-01-01")), true);
  assert.equal(CredentialStore.isExpired(cred, new Date("2026-01-01")), false);
});

// ---- loopback callback: state-first, single-shot -----------------------------
test("evalCallback checks state BEFORE the code (mismatch never reads it)", () => {
  const bad = evalCallback("good", new URLSearchParams("code=stolen&state=WRONG"));
  assert.equal(bad.status, 403);
  assert.equal(bad.result.code, undefined);
  assert.match(bad.result.error!, /state mismatch/);

  const noCode = evalCallback("s", new URLSearchParams("state=s"));
  assert.equal(noCode.status, 400);

  const ok = evalCallback("s", new URLSearchParams("state=s&code=one-time"));
  assert.equal(ok.status, 200);
  assert.equal(ok.result.code, "one-time");
});

test("PKCE challenge is base64url(sha256(verifier))", () => {
  const { verifier, challenge } = generatePkce();
  const want = crypto.createHash("sha256").update(verifier).digest("base64url");
  assert.equal(challenge, want);
  assert.equal(challenge.length, 43);
});

// ---- exchange + consent URL --------------------------------------------------
test("consentUrl points at /cli-auth with the loopback redirect + challenge + state", () => {
  const u = new URL(consentUrl("https://x", "http://127.0.0.1:5555/callback", "chal", "st"));
  assert.equal(u.pathname, "/cli-auth");
  assert.equal(u.searchParams.get("redirect_uri"), "http://127.0.0.1:5555/callback");
  assert.equal(u.searchParams.get("code_challenge"), "chal");
  assert.equal(u.searchParams.get("state"), "st");
});

test("exchangeCode returns the credential on 200 and throws the server message otherwise", async () => {
  const good = await exchangeCode("https://x", "c", "v", "http://127.0.0.1:1/callback", async (_u, _b) => ({
    ok: true,
    status: 200,
    json: async () => ({ token: "tnx_t", fingerprint: "fp", expires_at: "2999-01-01T00:00:00Z" }),
  }));
  assert.equal(good.token, "tnx_t");
  await assert.rejects(
    exchangeCode("https://x", "c", "v", "http://127.0.0.1:1/callback", async () => ({
      ok: false,
      status: 400,
      json: async () => ({ error: { code: "invalid_grant", message: "the authorization code is invalid" } }),
    })),
    /invalid/,
  );
});

// ⛔ THE TEST SCRIPT ENUMERATES ITS FILES, SO A NEW TEST FILE IS SILENTLY NEVER RUN.
//
// `package.json`'s `test` lists every file by name (node --test does not glob here). A file added to
// `test/` and left off that list exists, typechecks, passes locally when invoked directly, and
// contributes NOTHING to CI — and the total test count barely moves, so nobody notices.
//
// Found the moment `entry.test.ts` was added: the count stayed at 102. **A test that is not RUN is
// indistinguishable from a test that does not exist**, which is the same class as the unreachable
// branch that file was written to cover.
test("every test file is listed in the test script — an unlisted test never runs", () => {
  const pkg = JSON.parse(
    readFileSync(join(__dirname, "..", "package.json"), "utf8"),
  ) as { scripts: { test: string } };
  const listed = new Set(
    [...pkg.scripts.test.matchAll(/test\/([A-Za-z0-9._-]+\.test\.ts)/g)].map((m) => m[1]),
  );
  const present = readdirSync(join(__dirname)).filter((f) => f.endsWith(".test.ts"));
  assert.ok(present.length >= 12, `vacuity floor: found only ${present.length} test files`);
  const missing = present.filter((f) => !listed.has(f));
  assert.deepEqual(missing, [], `these test files are never run: ${missing.join(", ")}`);
});
