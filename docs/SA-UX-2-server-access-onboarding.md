# SA-UX-2: Server Access (and App Access) onboarding UX

2026-11-25; local branch `story/sa-ux-2`, base `origin/main` a7a931a0 (v0.1.46). Not pushed.

## Why

A live walk of the v0.1.46 demo by the founder hit eleven Server Access onboarding problems, from a raw
`ssh_unreachable` after a "successful" setup to a dashboard tab running the previous release's bundle. A follow-up
scope addition applies the same audit to App Access (section "App Access" below). Product principles that bound
every decision: no user confusion (every state and message is clear and actionable), security never weakens for
convenience, one-click upgrades keep working, and App Access and Server Access stay independent (shared UI helpers
only — no shared toggle, setting or runtime dependency).

## Server Access

### 1. Gateway → server reachability (TCP 2222) is never stated

**Problem.** Automatic setup reported success, then every account check failed with a raw `ssh_unreachable`: the
cloud firewall blocked the gateway from the browser-SSH listener (`tunnex-browser-sshd`, TCP 2222 by default). The
register form and the setup panel never said the gateway must reach the server on that port. The only hint was a
paragraph shown after setup succeeded.

**Decision.**
- The register form and the setup panel state the requirement before anything runs: "The gateway *name* (address
  as Tunnex knows it: *IP*) must reach *server IP*:*management port* (setup) and *server IP*:*SSH port* (browser
  terminal) over TCP." The address is the gateway's address as the control plane knows it (its reported/public
  address); the panel says so, because NAT can change the source address the server sees.
- When an account check, a setup run or a session fails with `ssh_unreachable`, the UI shows a plain sentence and a
  "Can't reach the server?" disclosure with copy-ready firewall rules parameterized with the gateway address and
  the port: GCP firewall rule, AWS security group, Azure NSG, `ufw`, `firewalld`.
- **No new probe RPC.** The account check already *is* the gateway's TCP probe: the gateway dials the server and
  `classifyResult` maps a dial error (`net.OpError`) to `ssh_unreachable`. Adding a second probe would duplicate that
  path without new information. The setup run's own dial failure maps to the same code. What changes is the
  explanation, not the detection.
- `ssh_unreachable` is never rendered raw (see item 8).

**Security.** Display only. The gateway address shown is already visible to administrators on the Gateways page.
The firewall examples restrict the source to the gateway address (`/32`), never `0.0.0.0/0`.

**Tests.** Web: the register form and setup panel render the requirement with the gateway address and ports; a check
failing with `ssh_unreachable` renders the human sentence and firewall examples containing the gateway IP and the
SSH port, and the raw code is absent.

### 2. Manual "Verified management SSH fingerprint" paste

**Problem.** Setup required the administrator to obtain the management sshd's SHA256 host-key fingerprint from a
trusted session on the server and paste it. Painful, and easy to get wrong.

**Why the field exists.** The gateway connects to the server's management sshd with a temporary key that the
one-time authorization command adds to `authorized_keys`, then sends the reviewed installer and trusts the result it
reads back (accounts, and the host fingerprint of the browser-SSH listener on 2222, which is pinned for every later
terminal session). Without a pinned management host key, an attacker on the network path between gateway and server
could terminate the SSH connection with its own host key, receive the installer, and return a forged result that
pins *the attacker's* 2222 host key — turning every later browser terminal into a man-in-the-middle.

**Rejected: trust-on-first-use from the network path.** `ssh-keyscan` from the gateway, or "accept whatever host key
the gateway sees", makes the attacker's position the trust source. Not acceptable.

**Decision: host-key attestation bound to the one-time authorization (the manual field becomes optional).**
The administrator already runs the one-time authorization command as root on the server through a trusted channel
(their own SSH session, console, IAP, SSM — see item 11). That channel can carry a secret, and the root process on
the real server can read the real host keys. So:

1. When the gateway reports its temporary public key, the control plane generates a fresh 256-bit random
   *attestation key* `K` for that job and embeds it only in the one-time authorization command (`SETUP`). `K` is
   **never** sent to the gateway (it is not in `bootstrap.Job` or anything `EnrollmentDesired` returns).
2. The authorization command (root, on the real server, at authorization time) reads the server's ed25519 host
   public keys (the `HostKey` entries from `sshd -T`, falling back to `/etc/ssh/ssh_host_ed25519_key.pub`), computes
   their SHA256 fingerprints, and stores `K` and that list in the root-only (0700) launcher.
3. When the gateway's temporary key runs the forced command, the launcher first prints one attestation line:
   the fingerprint list and `HMAC-SHA256(K, "tunnex-enroll-host-keys-v1\n" + job_id + "\n" + sorted fingerprints)`.
4. The gateway, with no pinned fingerprint, accepts only an ed25519 host key during the handshake, records the
   fingerprint it actually saw, and reports it together with the attestation line.
5. The control plane recomputes the HMAC with `K`, checks the job id, and requires the fingerprint the gateway saw
   to be in the attested list. Any mismatch fails the job (`ssh_host_key_unverified`) and **nothing is saved**.

The "Verified management SSH fingerprint" input stays as an optional **"Advanced: verify the host key
independently"** field. When it is filled, the gateway pins it strictly exactly as before, *and* the attestation is
still verified.

**Threat model.**
- *Network attacker between gateway and server (the threat the field addressed).* To pass, the attacker must either
  (a) relay the gateway's login to the real server — impossible: SSH public-key authentication signs the session
  identifier, which is bound to the attacker's own key exchange, so the real server rejects it; or (b) forge the
  attestation for its own host key — impossible without `K`, which travelled only browser (HTTPS) → administrator →
  trusted channel → root on the real server. Replaying an attestation from an earlier job fails: `K` and the job id
  are per job. Defeated.
- *Attacker who reads the dashboard/control-plane database.* Can learn `K` while the job is active (the command is
  stored in the job until it ends, then cleared, as today). With `K` *and* a network position they could forge an
  attestation. Such an attacker already controls far more (they can prepare jobs, read sealed material with the
  key ring, change trust configuration); this does not widen their reach.
- *Local unprivileged user on the target.* `K` is in the authorization command's argv (visible in `ps` for the
  instant the command runs) and possibly in the administrator's shell history. To exploit it they also need a
  network position between gateway and server during the ≤15-minute window and the job must still be active. The
  launcher holding `K` is root-only and deleted at use or expiry. Accepted, documented, bounded (single use,
  ≤15 minutes). Administrators who consider this unacceptable use the advanced field (strict pin, as before).
- *Root on the target.* Trusted by definition (it is the machine being enrolled).
- *Compromised gateway.* Already holds the temporary key and sees the session; it gains nothing new (it never
  receives `K`; it could only report a wrong fingerprint, which the attestation rejects).
- *Non-default host keys.* If sshd serves an ed25519 key the command cannot find, or only non-ed25519 keys, the
  attestation fails closed with a clear message pointing to the advanced field. Nothing is trusted silently.

**Upgrade and version skew (one-click upgrades).**
- New control plane, old gateway: the control plane advertises `host_key_attestation: true` in the job; an old
  gateway ignores the unknown field and reports its public key without the capability. If no manual fingerprint was
  given, the control plane fails the job at once with "This gateway needs an update for automatic host-key
  verification. Update the gateway, or use Advanced: verify the host key independently." — never an unexplained
  `ssh_host_key_mismatch`. With a manual fingerprint, old gateways work exactly as before.
- Old control plane, new gateway: the job lacks the capability flag, so the gateway sends no new fields (the
  control plane decodes agent reports strictly) and requires the pinned fingerprint as before.
- The authorization command and launcher are generated per job, so no target-side upgrade is involved.

**Tests.**
- API (unit): attestation verifies; wrong `K`, wrong job id, seen fingerprint not in the list, malformed line,
  missing line when attestation required, and an empty list are each refused; a manual fingerprint that differs
  from the seen one is refused; input validation accepts an empty fingerprint.
- Python/Go round trip: the launcher's attestation line (produced by the real `authorize.py` code paths in a test
  harness) verifies with the Go verifier.
- Node: with no pinned fingerprint and attestation on, the host key callback records an ed25519 key and refuses
  others; without attestation, an empty fingerprint is refused as invalid material; the attestation line is parsed
  from bounded output; new report fields are sent only when the job advertises the capability.

### 3. MFA requirement appears only after "Prepare automatic setup"

**Problem.** The control plane refused with `mfa_required` after the click; the administrator had no MFA enrolled.

**Decision.** The Server Access workspace (for managers) and the setup panel show the requirement up front: "Setting
up a server needs two-factor verification." If the account has no confirmed factor, an inline "Set up two-factor"
path (the existing `MfaSettings` ceremony) is offered before the Prepare button is enabled; if it has one, the panel
says verification will be asked when needed (the existing inline step-up). The API rule is unchanged.

**Security.** Unchanged: the server still enforces fresh MFA; the UI only explains it earlier.

**Tests.** Web: without an enrolled factor the setup panel shows the requirement and the setup path and disables
Prepare; with a factor, Prepare is enabled and the notice says verification happens on the next step.

### 4. Administrator without a grant hits a dead end on Connect

**Problem.** Connect returned `account_not_granted`: "You do not have current access to this account on this server.
Ask an administrator for a grant." — shown to the administrator themself.

**Decision.** When the caller can manage grants (`can_manage`/grant permission in the workspace), the refusal shows
an inline "Grant myself access" form: account (pre-selected), duration (default 1 hour; choices up to the existing
7-day maximum), and a button that calls the existing `createServerAccessGrant` with the caller's own user id, then
retries Connect. Others see "Ask an organization administrator (owner or admin) to grant you access to *account* on
*server*."

**Security.** No new endpoint and no new authority: anyone with the grant permission can already grant themselves
through the grant form. Same validation, same 7-day cap, same audit (`server_access.grant_created`, actor = target
user). The session itself still requires fresh MFA exactly as for any grant. We do not add an extra step for
self-grants because it would be bypassable through the normal form.

**Tests.** Web: a manager seeing `account_not_granted` gets the inline form, which posts a grant for their own user
with a 1-hour window and retries; a non-manager sees the "ask an administrator" text and no form.

### 5. Installation-off state without the link to the setting

**Problem.** Features → Server Access showed "Terminal capability is disabled on this installation" and "Reload
Server Access setting", without the link. The installation-off branch only covered the *initial read*; a refusal
that arrived on a later read or on a save (the installation was turned off after the page loaded, or a read raced
the change) fell through to the generic error.

**Decision.** Any `server_access_disabled` answer — initial read, reload, or save — switches the row to the
installation-off state. Server administrators always get the link to Settings → Server Access; others are told to ask
a server administrator. The same rule applies on the Server Access workspace page.

**Tests.** Web: a save refused with `server_access_disabled` shows the installation-off row and the link for a server
administrator; a non-administrator gets the ask text.

### 6. Two toggles in two places

**Problem.** A server administrator turns the installation on in Settings → Server Access, then must find Features to
turn it on for the organization.

**Decision.** The installation toggle, when turning *on*, offers "Also turn on Server Access for *organization*"
(checked by default when the administrator can manage Server Access in the current organization). After the
installation save succeeds, the dashboard turns the organization on with the existing organization endpoint; the
result of each step is shown separately ("Turned on for this installation. Also turned on for Acme." or "...but
turning it on for Acme failed: reason — use Settings → Features"). Org administrators who are not server
administrators keep using Features.

**Why two calls, not one combined endpoint.** The installation action keeps its own re-authentication and audit;
the organization step is the normal organization setting with its own permission check and audit. A combined
endpoint would let one authority write the other's setting. Two calls keep each check where it already is; the
dashboard sequences them behind one confirmed click.

**Security.** No new authority. The organization step runs only if the installation step succeeded and only with
the administrator's own organization permission; a refusal is shown, not hidden.

**Tests.** Web: turning on with the box checked calls the installation PATCH then the organization PUT and reports
both; unchecked calls only the installation PATCH; the box is absent when the user cannot manage the organization.

### 7. Old dashboard bundle after an upgrade

**Problem.** After the control-plane upgrade an open tab kept running the old bundle until a hard reload.

**Decision.** The dashboard periodically (every 5 minutes and when the tab becomes visible) fetches its own
`/index.html` with `cache: "no-store"` and compares the module script it references with the one the page loaded.
When they differ it shows a non-blocking banner: "A new version of Tunnex is available. Reload". It never reloads
automatically (a live terminal or an unsaved form may be open). Skipped in the Vite dev server.

**Security / privacy.** Same-origin request to the control plane that served the page; no phone-home, no new
endpoint, no data sent. `deploy/nginx/spa.conf` already serves `index.html` with `no-cache`.

**Tests.** Web: the banner appears when the fetched index references a different module script, not when it is the
same, not when the fetch fails; Reload calls `location.reload`.

### 8. Raw reason codes in the UI

**Decision.** `serverAccessReasons.ts` maps every Server Access code — session end reasons, connect/check refusal
codes from `deny_messages.go`, enrollment failure codes, and gateway result codes — to a sentence plus a next step.
Unknown codes render a generic sentence ("Server Access could not complete this action.") rather than a humanized
code. The list of codes is checked in (`serverAccessReasonCodes`) and a Go test asserts every code the API and gateway
can emit is in that list, so the web test ("no raw code renders, for every known code") covers the real set.

**Tests.** Web: for every known code the rendered text contains neither the code nor an underscore; unknown codes
render the generic sentence. Go: `deny_messages.go` keys, enrollment failure codes and gateway `classifyResult`
outcomes are all present in the web list.

### 9. Session recording silently off

**Problem.** The terminal showed "Recording off" without explanation, and registration did not explain the choice.

**Decision.** Registration keeps the "Record terminal sessions" switch with its default (off, unchanged), and explains
it: what is recorded (terminal output and resize, not keystrokes typed into hidden prompts), who can replay it, the
retention setting, and that it can be changed later per server. The terminal header shows "Recording on/off" and, for
users who can manage the server, a "Change" link to the server's settings. Existing servers are not changed (no
migration).

**Tests.** Web: the registration form shows the explanation; the terminal header shows the state and the change link
only for managers.

### 10. Person pickers show name in one place and email in another

**Decision.** One helper formats a person as "Name (email)" (or just email when there is no name, or when the name
equals the email) and is used by the grant picker and the grant list.

**Tests.** Web: the picker option and the list row for the same member show the same "Name (email)".

### 11. Running the one-time authorization without direct SSH

**Decision.** A docs section in `docs/EPIC-server-access.md` (and an in-app "Can't run commands on the server?"
disclosure in the setup panel) covers: the gateway as a jump host (`ssh -J`), GCP IAP TCP forwarding (requires a
firewall rule allowing `35.235.240.0/20` on tcp:22 to the VM), AWS Systems Manager Session Manager, Azure Bastion /
Run Command, and cloud-init/user-data for new VMs. Note for cloud-init: the authorization command expires in 15
minutes and is per job, so cloud-init is suitable only when the VM is created within that window; the snippet says so.

**Security.** The trusted-channel assumption of item 2 holds for each of these (the administrator authenticates to the
cloud provider or jump host). Copying the command into a cloud "user data" field stores it in the cloud provider's
metadata; the note says to prefer interactive channels and that the command expires and is single use.

## App Access

Scope addition (founder, 2026-11-25): the same onboarding audit for App Access, in the same branch. App Access and
Server Access stay independent; only presentation helpers (firewall examples, person label, new-version banner) are
shared.

### AA-1. Allowed-range requirement surfaces late

**Problem.** An app whose origin was a private address outside the app's allowed ranges saved and published; the
refusal appeared only at check/open time (`target_refused`). The guidance (`suggestedOriginRange`, "Allow
10.0.0.5/32") existed but only after a failed check.

**Decision.** The Connection step evaluates the origin as it is typed: for a private IP-literal origin not covered by
the allowed ranges it shows, before save, "The gateway *name* will refuse *address*: private origins need their range
allowed" with the same one-click "Allow *address*/32" (fills the draft; the admin still saves). For a hostname origin
it says the gateway resolves the name when it connects and that a private result needs its range listed. It names the
gateway that will dial the origin (the app's selected gateway — there is no gateway selection logic to explain).

**Security.** Advisory only. The gateway's policy check (`originpolicy.Validate`) remains the enforcement point and
nothing is widened automatically; the existing server-side validation of ranges is unchanged.

**Tests.** Web: a private IP origin outside the ranges shows the warning and the Allow action before any check; a
covered origin shows none; a hostname shows the resolution note.

### AA-2. Gateway → origin reachability

**Decision.** `connect_failed` and `deadline_exceeded` check results add the same "Can't reach the origin?" disclosure
as Server Access item 1, with firewall examples parameterized with the gateway's address (as Tunnex knows it) and the
origin host:port. Shared helper, separate call sites.

**Tests.** Web: a `connect_failed` check renders the examples with the origin port; the raw code is absent.

### AA-3. Gateway → app-proxy listener (8444) status — deferred to Phase 1b

The gateway does not report proxy-listener reachability today (`getAppAccessGatewayStatus` returns only capability
status). Building `proxy_reachable | tls_failed | unreachable` needs a new gateway probe, a new report field and
storage — exactly the AA-EN-1 Phase 1b work (`docs/AA-EN-1-phase-1a.md`), including the "gateway in another network
handed an unreachable proxy address" case (demo: onprem-gw-a delivered 10.70.0.2:8444). Showing a guess from data the
gateway does not report would violate "no user confusion". **Not in this slice.**

### AA-4. Administrator with no grant

**Problem/constraint.** The app-proxy's refusal page is deliberately uniform — "a missing grant, an unpublished app
and an unknown host look alike" (`apps/app-proxy/internal/proxy/unavailable.go`). That is an anti-enumeration
property for the public hostname and must not change.

**Decision.** The fix lives in the dashboard: on the application's Access step, a manager (`app_access:grant`) who has
no grant of their own sees "You do not have access to this application yet" with "Grant myself access" (duration
default 1 hour), which calls the existing grant endpoint with the caller as subject. No new endpoint or authority —
the same person can already grant themselves through the form; the grant is audited as any other.

### AA-5. Feature-off states

**Decision.** "Applications is off for this organization" / "setup is not complete" messages give organization
administrators the link to the right setting (Settings → Features, Settings → Application domains for server
administrators) and others "ask an administrator".

### AA-6. Reason codes

**Decision.** The existing local maps already cover the check codes, with a generic fallback. A test asserts that for
every App Access check, publication and event reason code the rendered text contains no raw code.

### AA-7. Person labels

**Decision.** The App Access subject picker uses the same "Name (email)" helper as Server Access.

### AA-8. New-version banner

The banner (item 7) is mounted in the app shell, so it covers App Access pages too.

## Outcome (2026-11-25)

Server Access
- 1: done. Register form and setup panel state the gateway → server ports (management SSH for setup, browser
  terminal afterwards) with firewall examples; `last_error` renders as a sentence plus firewall rules on the
  Connection and Accounts steps. No new probe RPC (the account check is the probe).
- 2: done as decided. Host-key attestation in `authorize.py` (launcher prints the HMAC line), gateway records the key
  it saw (`setupHostKeyCallback`), control plane verifies (`verifyHostKeyAttestation`); fingerprint optional in the
  API and UI. Python ↔ Go round trip tested with the real `authorize.py` code.
- 3: done in the setup panel (requirement and inline two-factor setup before Prepare). The Servers landing itself is
  unchanged; the panel is where the requirement applies.
- 4: done (`SelfGrant`, existing grant endpoint, 1 hour default, up to the existing 7-day cap).
- 5: done (save and reload refusals switch to the installation-off row).
- 6: done (checkbox, two sequenced calls, separate results).
- 7: done (`NewVersionBanner` in the app shell).
- 8: done (`serverAccessReasons.ts` + `TestEveryServerAccessCodeHasWebText`).
- 9: done for new servers and the terminal header; no migration.
- 10: done for Server Access (picker and list) and the App Access picker. The App Access grant list shows the
  server-stored `subject_label` (name, or email when there is no name), captured when the grant was created; changing
  that snapshot is an API/data change left out of this slice.
- 11: done (`docs/EPIC-server-access.md` operator guide + in-app "Can't run commands on the server?").

App Access
- AA-1, AA-2, AA-4, AA-5, AA-6 (check codes and event reasons), AA-7, AA-8: done as decided above.
- AA-3: deferred to Phase 1b (needs a new gateway probe and report).

Not run here: the `tests/server-access-local` harness walk (real gateway + OpenSSH target) for the attestation path;
the unit and round-trip tests cover the protocol, but a live walk on a real target should precede release.

## Rollback

No migrations. Item 2 adds optional fields to the agent wire (`bootstrap.Job.HostKeyAttestation`, report fields) that
older peers ignore or never receive; rolling the control plane back makes the fingerprint required again (the old
web bundle requires it too). All other items are web-only.
