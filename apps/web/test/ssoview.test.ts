import { describe, expect, it } from "vitest";
import {
  enabledLabel,
  secretPlaceholder,
  toggleReflectsServer,
} from "../src/lib/ssoview";

// ⛔ A CONTROL WHOSE DEFAULT READS AS A FACT.
//
// Google SSO rendered "Enabled" CHECKED and a dotted secret field on a provider the server answers
// `404 sso_not_configured` for. Microsoft rendered the identical box and identical dots — and IS
// configured. Visually indistinguishable, and one of them false.
//
// MEASURED: `useState(true)` checks the box before any load, and an unconfigured provider never
// calls `setEnabled`, so it stays checked; and `placeholder="••••••••"` rendered unconditionally.
// An admin concluded Google SSO was enabled with a stored secret. Neither was true.
//
// ⛔ EVERY TEST HERE ASSERTS **BOTH ARMS**. That is the whole point: a checkbox that is always
// checked cannot be told from one that is correctly checked, and a test that only exercises the
// configured arm would pass against the defect.
describe("enabledLabel — the toggle means different things per arm", () => {
  it("⛔ does NOT say 'Enabled' on an unconfigured provider", () => {
    // Nothing is stored, so the control can only express INTENT about the config being created.
    expect(enabledLabel(false)).toBe("Enable when saved");
    expect(enabledLabel(false)).not.toBe("Enabled");
  });

  it("says 'Enabled' on a configured provider, where it reflects stored state", () => {
    // The NEGATIVE arm alone would be satisfied by never saying "Enabled" at all.
    expect(enabledLabel(true)).toBe("Enabled");
  });

  it("the two arms are never the same string", () => {
    expect(enabledLabel(true)).not.toBe(enabledLabel(false));
  });
});

describe("secretPlaceholder — dots are a claim that a secret is stored", () => {
  it("⛔ renders NO dots when nothing is stored", () => {
    // On the configured arm the dots sit above a real secret_fingerprint — proof of storage. On the
    // unconfigured arm they sat above nothing and looked identical.
    expect(secretPlaceholder(false)).toBe("");
  });

  it("renders the dots when a secret IS stored", () => {
    expect(secretPlaceholder(true)).toBe("••••••••");
  });

  it("the two arms are never the same string", () => {
    expect(secretPlaceholder(true)).not.toBe(secretPlaceholder(false));
  });
});

describe("toggleReflectsServer", () => {
  it("⛔ is FALSE when unconfigured — the assertion that matters is the negative one", () => {
    // A boolean that is always true cannot be told from one that is correctly true, so this is
    // pinned in both directions rather than only where it is on.
    expect(toggleReflectsServer(false)).toBe(false);
    expect(toggleReflectsServer(true)).toBe(true);
  });
});
