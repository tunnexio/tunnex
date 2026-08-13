# Tunnex desktop client

Electron shell + the privileged helper. The renderer is served over `app://` from a bundled SPA build.

---

## ⛔ ONE CLONE. THESE INSTRUCTIONS ASSUME `~/tunnex`.

**Two clones caused two separate confusions in a single day** — a stale served bundle, then a "SIGKILL" that
was a ten-story-old branch with no client work in it. **The rule is one clone, one state.** If you keep
another, rename it `tunnex-OLD` so a stray terminal cannot be mistaken for the real one.

The compose stacks, seeded databases and the `localhost` / `:8081` review URLs all belong to **this** clone.
Running `make up-enterprise` from a second one collides on those ports.

## STEP 0 — verify the tree, before anything else

```bash
ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"
echo "clone:  ${ROOT:-NOT A GIT REPO}"
echo "branch: $(git rev-parse --abbrev-ref HEAD 2>/dev/null)"
echo "head:   $(git rev-parse --short HEAD 2>/dev/null)"
for f in apps/client/package.json apps/web/client.html apps/web/src/client/ClientApp.tsx; do
  [ -f "$ROOT/$f" ] && echo "  yes  $f" || echo "  NO   $f"
done
```

Every line must say `yes`. **`NO apps/web/client.html` means you are on a branch without the client work** —
that is a wrong-branch problem, not an app problem.

## STEP 1 — verify Electron, and know the THREE states

⛔ **THE MIDDLE STATE IS THE ONE THAT COSTS HOURS: `dist/` exists but holds only a licence and a version file.
Every other check calls that "installed".** `path.txt` is written, the package directory is there, `dist` is
there — and there is no binary. Electron then dies with `Killed: 9` and no stack trace, which reads exactly
like a code-signing problem and is not.

```bash
ROOT="$(git rev-parse --show-toplevel)"
D="$ROOT/node_modules/.pnpm/electron@31.7.7/node_modules/electron/dist"
if [ ! -d "$D" ]; then
  echo "STATE 1 — NO dist. Electron was never installed."
else
  SZ=$(du -sm "$D" | cut -f1)
  if [ "$SZ" -lt 50 ]; then
    echo "STATE 2 — dist is ${SZ}MB. BROKEN: the binary was never downloaded."
  else
    echo "STATE 3 — dist is ${SZ}MB. Looks real."
  fi
fi
```

| state | `dist` size | meaning |
|---|---|---|
| 1 | absent | never installed |
| 2 | **~9 MB** | ⛔ **broken — licence + version only, no binary.** Passes every naive check. |
| 3 | **~234 MB** | genuinely installed |

**Then confirm the version — and run it from `apps/client`, never the repo root:**

```bash
cd "$ROOT/apps/client" && npx electron --version   # must print v31.7.7
```

⛔ **`npx electron --version` FROM THE REPO ROOT IS NOT A VALID CHECK.** There is no `electron` dependency at
the root, so npx resolves a FOREIGN package and will **download electron@43.2.0** to answer you. It prints a
version, so it looks like it worked — while telling you nothing about the client's Electron and quietly
installing a different one. **If it prints anything other than `v31.7.7`, treat it as a failed check**, not as
a version mismatch.

## STEP 2 — the fix for state 1 or 2

```bash
ROOT="$(git rev-parse --show-toplevel)"
rm -rf "$ROOT/node_modules/.pnpm/electron@31.7.7"
pnpm install
```

**What does NOT work, both confirmed:**

- **`pnpm rebuild electron`** — does nothing here.
- **plain `pnpm install`** — prints *"Lockfile is up to date, resolution step is skipped"* and exits in under a
  second. **That message means the install was a NO-OP**, so a broken `dist` stays broken. Deleting the
  `.pnpm` entry is what forces the postinstall to run again.

**Also check your shell**, because it produces exactly state 2 — a completed postinstall with no download:

```bash
echo "${ELECTRON_SKIP_BINARY_DOWNLOAD:-unset}"
```

Anything but `unset` means it is in your profile and will break **every** install in **every** clone.

## Resetting app data

```bash
rm -rf ~/Library/Application\ Support/@tunnex/client
```

⛔ **THE DIRECTORY IS NAMED FOR THE npm SCOPE, NOT THE PRODUCT.** `package.json` has
`name: "@tunnex/client"` and **no `productName`**, so in DEV Electron uses `@tunnex/client`. The PACKAGED app
uses `Tunnex`, because `productName: Tunnex` lives in `electron-builder.yml` and applies only to the build.
**Two different paths for the same app**, and neither is the one you would guess.

**`rm -rf` on the wrong path SUCCEEDS SILENTLY** — so a reset that removed nothing looks exactly like a reset
that worked, and you go on to debug a state you believed you had cleared. **Verify instead of assuming:**

```bash
ls -la ~/Library/Application\ Support/ | grep -i tunnex
```

## First run — what you will see

**There is no dev flag to skip the setup screen.** `index.ts` shows it whenever `config.getServerUrl()` is
empty, and nothing reads an environment variable for it. On a fresh profile you get:

1. **The setup screen** — enter your server URL (e.g. `http://localhost`). It is validated against a live
   `/healthz` before it is stored.
2. **Then the client surface** — status head, connection stats, the primary verb, split tunnel. **Not a
   dashboard**: no sidebar, no nav, no login page. If you see those, Electron is loading the OLD entry and
   step 3 has not been applied.
3. **Sign-in opens your BROWSER.** By design: *"MFA touches the client only via browser re-auth — never an
   in-app password field."* There is no password field in the client and there should never be one.

To pre-seed the server URL and skip step 1, write the store directly **before first launch**:

```bash
mkdir -p ~/Library/Application\ Support/@tunnex/client
echo '{"serverUrl":"http://localhost"}' > ~/Library/Application\ Support/@tunnex/client/tunnex.json
```

⚠ Unverified — the store is `electron-store` with `name: "tunnex"`, so that is the file it reads, but this
shortcut has not been tested end to end. **The setup screen is the supported path.**

---

## Run it

```bash
COMPOSE_PROJECT_NAME=tunnex-s141 make up-enterprise   # a stack to point at
pnpm --filter @tunnex/web build                        # the renderer the client loads
pnpm --filter @tunnex/client build                     # main + preload (tsc → dist)
pnpm --filter @tunnex/client start                     # electron .
```

⚠ **`pnpm --filter @tunnex/client build` is `tsc -b`, which is INCREMENTAL.** A green local build means
"whatever tsc chose to re-check is green", not "the build is green" — a clean CI container can fail on the
same tree. Delete `*.tsbuildinfo` if you need the real answer.

## Test / typecheck

```bash
pnpm --filter @tunnex/client typecheck
pnpm --filter @tunnex/client test    # node --test; imports NO electron at runtime
```

Client tests must never `require("electron")` at runtime — CI sets `ELECTRON_SKIP_BINARY_DOWNLOAD`, so the
import throws. Pure view-models live in Electron-free modules (`trayview.ts`, `notifyview.ts`).

## Package

```bash
bash apps/client/scripts/pack.sh [mac|win]
# 1 web build → 2 tsc → 3 stage-helper → 4 electron-builder → 5 SHA256SUMS
```

**Unsigned and un-notarized.** macOS: Gatekeeper will warn (curl without quarantine, or
Settings → Open Anyway). Windows: SmartScreen will warn. Both are the registered signing gate, not a defect
in the build.
