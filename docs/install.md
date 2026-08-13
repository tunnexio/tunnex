# Installing Tunnex (desktop)

The S6.5a builds are **unsigned** — no Apple Developer ID, no Windows code-signing
certificate yet (that's a later milestone). The apps are safe, but macOS Gatekeeper and
Windows SmartScreen will warn on first launch because they can't verify a signature.
Here's how to install past those warnings, and how to verify you got the real file.

---

## 1. Verify your download (both platforms)

Every release ships a `SHA256SUMS` file. Check the installer you downloaded matches the
hash published on the release page (this is how you trust an unsigned build):

- **macOS:** `shasum -a 256 Tunnex-<version>-universal.dmg`
- **Windows (PowerShell):** `Get-FileHash .\Tunnex-Setup-<version>.exe -Algorithm SHA256`

Compare the output to the matching line in `SHA256SUMS`. If it doesn't match, don't run it.

---

## 2. macOS — install the `.pkg`

Tunnex ships as a **`.pkg` installer**. It installs the app to **/Applications** and sets up
the privileged helper during install (one admin prompt) — so you are NOT prompted on first
Connect, and the app runs from a fixed path (no "caller not trusted" issues).

1. Open **`Tunnex-<version>.pkg`**. Unsigned, so Gatekeeper warns:
   - **macOS 14 and earlier:** right-click the `.pkg` → **Open** → **Open**.
   - **macOS 15 (Sequoia)+:** try to open it once (blocked), then **System Settings →
     Privacy & Security** → **"Tunnex… was blocked"** → **Open Anyway**.
   - **No-warning path:** download the `.pkg` with `curl -LO "<url>"` (curl downloads aren't
     quarantined), then `open Tunnex-<version>.pkg`.
2. Step through the installer. It asks for your **password once** — that's Tunnex installing
   its VPN helper (a small root component that manages the WireGuard tunnel + kill-switch).
3. Launch **Tunnex** from **/Applications**.

> Always install with the `.pkg` and run from /Applications. Running the `.app` from
> Downloads/Desktop can trigger macOS App Translocation (a random read-only path), which
> breaks the helper's caller check — the app will tell you to move it to Applications.

---

## 3. Windows — get past SmartScreen

Running the unsigned `.exe` shows **"Windows protected your PC."** Click **More info** →
**Run anyway**. (SmartScreen warns on any installer without an established signing
reputation; that goes away once the app is signed in a later release.) The installer is
elevated (UAC) and registers the Tunnex helper service during install.

---

## 4. Connect

Launch Tunnex → enter your organization's server URL → sign in → **Connect**. A successful
tunnel shows **Connected** with your assigned IP; traffic for your org network now routes
through Tunnex. Use the **tray/menu-bar icon** to connect/disconnect without the window.

---

## 5. Uninstall (clean removal)

- **macOS:** quit Tunnex and drag **Tunnex.app** to the Trash — that's it. The helper
  notices its app is gone and **removes itself within ~90 seconds** (releases the
  kill-switch, restores `pf.conf`, deletes its files, unloads the daemon). No script.
  - Immediate removal (optional): `sudo bash scripts/macos-uninstall.sh` (from the repo).
- **Windows:** Settings → Apps → **Tunnex** → Uninstall. The uninstaller stops and removes
  the helper service.

---

## Why unsigned?

Signing (Apple notarization + a Windows EV certificate) is a later milestone tied to public
distribution. Until then these steps are the trade-off for an early build. A signed release
will install with no warnings and enable automatic updates.

## First sign-in — the bootstrap admin

⛔ **There is no public signup.** A self-hosted control plane is owned by one company: everyone inside
arrives by invitation, and an invitation has to be sent by somebody. That somebody is the CP admin, and the
control plane creates it for you on first start.

**Watch the startup logs.** On a deployment that has never had a user, the API mints one account and prints
its credential — once:

```
WARN bootstrap_admin_created
  email=admin@tunnex.local
  password=<24 random bytes, base64url>
  action="SIGN IN NOW AND CHANGE THIS PASSWORD — you will be forced to"
```

`docker compose logs api | grep bootstrap_admin_created`

⚠ **It is stored only as an argon2id hash.** Never in `.env`, never in a file, never in the database in
plaintext. That one log line is the only moment the plaintext exists.

**First login forces a password change**, and it is a wall rather than a screen: until the password is
changed the account may authenticate and do *nothing else* — `403 password_change_required` on every route
except `POST /api/v1/auth/password`. The credential was printed into logs that get shipped, aggregated and
searched, so it is treated as compromised from the moment it works.

Then the CP admin creates the first organization and invites everyone else.

### ⛔ If you lose that credential before signing in

**There is no recovery. Reset the deployment:** `docker compose down -v && make up`.

⚠ **Said plainly here so nobody discovers it at 2am.** It cannot be reprinted — only the hash is stored —
and there is no second admin to reset it from, and no signup to create a replacement.

⭐ **That is the deliberate trade.** The alternative — a password in `.env`, a file on disk, or a fixed
default — is a credential that lives forever and is identical on every install. One that exists for a single
log line and then only as a hash is one an attacker cannot find later.

⚠ **Once you have signed in and changed it**, the account is an ordinary user: normal password reset applies.

### Restarting is safe

The condition is *"has this deployment ever had a user"*, counting soft-deleted rows. A restart — crash,
redeploy, host reboot — mints nothing and prints nothing. ⛔ **A restart must not be a security event**: a
second admin would be a privilege escalation with no actor behind it, and reprinting the first one's
password would republish a live credential into log aggregation.
