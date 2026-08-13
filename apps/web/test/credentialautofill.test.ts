import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { stripJsComments } from "./support/source";

// ⛔ THE BROWSER TREATED AN OAuth CREDENTIAL FORM AS A LOGIN FORM.
//
// Found on the enterprise review stack: the Google client-ID box was prefilled with the
// signed-in admin's EMAIL and the secret box with a SAVED PASSWORD, both in autofill-blue —
// one un-noticed Save away from writing them into a live IdP config.
//
// ⛔ AND THE CAUSE WAS ORDER, NOT MARKUP. `SsoProvider` renders once per provider from ONE
// component, so Google's and Microsoft's fields were byte-identical. Chrome fills the FIRST
// text+password pair on a page as a login form, and `google` is first in PROVIDERS. Microsoft
// looked immune only because Chrome fills one pair per page.
//
//   FIXING ONLY THE PROVIDER THAT VISIBLY MISBEHAVED WOULD HAVE MOVED THE BUG, NOT REMOVED IT
//   — reordering PROVIDERS would have handed it straight to Microsoft.
//
// So the guard is a CENSUS, not a case: every password input in the app must declare what it
// is, and a new one cannot ship silently. The census found FIVE password inputs and ZERO
// autocomplete attributes — the OAuth secret was the one being exploited, but none of them
// were telling the browser anything.
const SRC = join(__dirname, "..", "src");

/** ⛔ Every read goes through the stripper — a COMMENTED-OUT `<input type="password">` is not a
 *  password input, and counting one would let a real unlabelled input hide behind the vacuity floor. */
function read(f: string): string {
  return stripJsComments(readFileSync(f, "utf8"));
}

function tsxFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((e) => {
    const p = join(dir, e);
    return statSync(p).isDirectory()
      ? tsxFiles(p)
      : p.endsWith(".tsx")
        ? [p]
        : [];
  });
}

/**
 * One `<Input .../>` or `<input .../>` element's attribute text.
 *
 * NOT `[^>]*?` — JSX attributes contain `>` inside arrow functions
 * (`onChange={(e) => …}`), so an exclusion class matches nothing at all. The vacuity floor
 * below caught exactly that on the first run: 0 password inputs found in a tree with 5.
 * Non-greedy to the first `/>` instead; `=>` cannot contain `/>`.
 */
function inputElements(src: string): string[] {
  return [...src.matchAll(/<[Ii]nput\b([\s\S]*?)\/>/g)].map((m) => m[1]);
}

const files = tsxFiles(SRC);

describe("every password input declares what it is to the browser", () => {
  it("finds the password inputs at all (vacuity floor)", () => {
    // If this drops to zero the census is measuring nothing and every assertion below
    // passes for free — the failure mode this repo has filed four times.
    const total = files
      .flatMap((f) => inputElements(read(f)))
      .filter((a) => /type=["']password["']/.test(a));
    expect(total.length).toBeGreaterThanOrEqual(5);
  });

  it("⛔ no password input is left without an autoComplete", () => {
    const offenders: string[] = [];
    for (const f of files) {
      for (const attrs of inputElements(read(f))) {
        if (!/type=["']password["']/.test(attrs)) continue;
        if (!/autoComplete=/.test(attrs)) {
          offenders.push(f.replace(SRC, "src"));
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it("⛔ a NON-login secret never claims to be a password the browser may fill", () => {
    // `current-password` on an OAuth client secret is what invites the saved-password fill.
    // `new-password` is the value Chrome actually honours to suppress it — `off` is widely
    // ignored on password inputs, which is why it is not accepted here either.
    const settings = read(join(SRC, "pages", "Settings.tsx"));
    const secrets = inputElements(settings).filter((a) =>
      /type=["']password["']/.test(a),
    );
    expect(secrets.length).toBeGreaterThan(0);
    for (const attrs of secrets) {
      expect(attrs).toMatch(/autoComplete="new-password"/);
      expect(attrs).not.toMatch(/autoComplete="current-password"/);
    }
  });

  it("⛔ the OAuth client ID is not offered as a username", () => {
    // This is the field that was being filled with the admin's email address.
    const settings = read(join(SRC, "pages", "Settings.tsx"));
    const clientId = inputElements(settings).filter((a) =>
      /oauth-client-id/.test(a),
    );
    expect(clientId.length).toBe(1);
    expect(clientId[0]).toMatch(/autoComplete="off"/);
    expect(clientId[0]).not.toMatch(/autoComplete="(username|email)"/);
  });

  it("only the real sign-in form claims current-password", () => {
    // Signup / ResetPassword / AcceptInvite all CREATE a password; `new-password` stops a
    // manager filling the OLD one into a "choose a password" box.
    const current: string[] = [];
    for (const f of files) {
      for (const attrs of inputElements(read(f))) {
        if (/autoComplete="current-password"/.test(attrs)) {
          current.push(f.replace(SRC, "src"));
        }
      }
    }
    // ⭐ TWO FORMS LEGITIMATELY ASK FOR A CURRENT PASSWORD, and the second one is the forced first-login
    // change. `current-password` is the CORRECT token there per the HTML spec — the field genuinely is the
    // existing credential, and a password manager offering to fill it is helping rather than leaking.
    //
    // ⚠ THE GUARD STAYS AN ALLOW-LIST, not a rule that says "only Login". What it exists to catch is a
    // form that claims to be a sign-in when it is not — an invite-accept or a reset screen mislabelled
    // that way trains the browser to offer a credential on a page that should be minting a new one.
    expect(current.sort()).toEqual([
      "src/pages/ChangePassword.tsx",
      "src/pages/Login.tsx",
    ]);
  });
});
