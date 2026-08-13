# Device posture checks (Enterprise)

Tunnex can evaluate device **posture** — OS version and disk encryption — on every
device self-report and warn on, or disconnect, non-compliant devices.

> **What posture checks are (and are not).** Posture checks deter honest
> non-compliance and give you an audit trail. They are client-reported, not
> hardware-attested — a compromised device can misreport. Treat posture as
> defense-in-depth, not a guarantee.

## How it works

- The desktop client self-reports facts every ~10 minutes while connected:
  OS version, and disk-encryption state (FileVault on macOS, BitLocker on
  Windows, read by the privileged helper).
- The server evaluates each report against your org's configured checks —
  evaluation is continuous, so a device that **drifts** non-compliant mid-session
  is caught within one report cycle.
- **warn** mode surfaces a warning (dashboard + audit); access continues.
- **require** mode disconnects a non-compliant device from every gateway within
  seconds of its report, and re-admits it the same way once a later report is
  compliant.

## Configuration (Access policies → Device posture checks)

Checks are **per-check, org-level opt-in, default off** — nothing is enforced
until you turn a check on.

| Check | Param | Notes |
|---|---|---|
| Disk encryption | — | FileVault / BitLocker, as reported by the device. |
| Minimum OS version | per-platform minimums | e.g. macOS `14.0`, Windows `10.0.22631`. **A platform you leave empty is not constrained** — the UI shows exactly which platforms a check covers. Version floors are per-platform because version numbers are not comparable across OS schemes. |

> **Windows version numbers — a foot-gun.** Windows 11 reports its OS version as
> **`10.0.22000`** (major `10`, not `11`) — Microsoft never bumped the major.
> To require Windows 11, enter `10.0.22000`, **not** `11.0`. Entering `11.0`
> compares numerically greater than every real Windows build and would block your
> entire Windows fleet, including Windows 11. Use the **build number**
> (`winver` shows it): Win 10 21H2 = `10.0.19044`, Win 11 22H2 = `10.0.22621`,
> Win 11 23H2 = `10.0.22631`.

RBAC: configuring checks requires the `device_health:manage` permission
(owners + admins). Reporting is done by each device's owner automatically.

## What "unknown" means — absence is not compliance

A device shows **posture unknown** when it has never reported, its last report
has gone stale (> 30 minutes), or a specific fact could not be read on the
device (reported absent, never guessed). Unknown devices are **not blocked** —
only a fresh, positive non-compliant report gates — but unknown is **not a
pass**: treat unreporting fleets as unverified, not compliant. Devices that
cannot report (CLI-only, mobile WireGuard, old desktop clients) always show
unknown.

Three input classes, precisely:

1. **A positive report** is evaluated — including a garbled one (an unparseable
   OS version under a require-mode floor **blocks**; garbage is not absence).
2. **Absence** (no report, or a single unreadable fact) never blocks and is
   surfaced as unknown.
3. **Staleness is absence**: a block whose backing report has gone quiet past
   the TTL is automatically cleared. A device that goes silent to evade shows
   as unknown — which is also why blocking on absence would add no security: a
   client malicious enough to go silent can just as easily lie.

## Enabling a check on an existing fleet

Turning a check on never disconnects anything by itself: a device's gate only
changes when **its own next report** is evaluated. The save response tells you
how many devices' *last* report would fail the new check (best-effort) — those
get blocked (require) or warned (warn) at their next report, within ~10 minutes.
Devices that never report are unaffected (unknown, not blocked).
