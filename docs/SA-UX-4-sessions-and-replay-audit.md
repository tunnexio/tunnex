# SA-UX-4: Sessions "Started" column and replay audit spam

2026-11-25; local branch `story/sa-ux-4`, base `origin/main` 43d021a9. Not pushed.

Two Server Access bugs found on the live v0.1.47 demo. Product principles that bound every decision: no user
confusion, security and audit guarantees never weaken, one-click upgrades keep working, no feature-to-feature
dependencies.

## Bug 1: the Sessions "Started" column is a blank, 40px-wide column

### Problem

Server Access → Sessions shows the start time wrapped 2–3 characters per line ("25/11/2026, 12:32:02" down a
~140px-tall row) under an empty header.

Root cause is CSS, not the formatter. `server-access-workspace.css` sized the grants table and the sessions table with
the same `th:nth-child(2..5)` rules. They were written when both tables had five columns, the fifth being an actions
column: `th:nth-child(5) { width:40px; font-size:0 }`. SA-UX-2 added Recording and Started to the sessions table,
which now has seven columns (Server, User, Status, Recording, Started, Duration or expiry, Actions). The fifth column
is now **Started**: its header text is hidden by `font-size:0` and the column is 40px wide. `td { overflow-wrap:anywhere }`
then breaks the date at every character boundary that fits. The header text was always in the DOM; only the style
hid it.

### Decisions

1. **The sessions table gets its own column widths.** The shared grants/sessions rules are split. The grants table
   keeps exactly its current rules. The sessions table sizes every column explicitly (Server takes the remainder):
   User 17%, Status 96px, Recording 170px, Started 150px, Duration or expiry 180px, Actions 128px. Its Actions header
   stays visible ("Actions"): `font-size:0` is not used on any session column. At a ~1100px table (a 1440–1500px
   window minus navigation) every column fits on one line.
2. **Time cells never wrap.** Started, Duration or expiry, and the Details time values render inside a
   `.sa-time` element with `white-space:nowrap`, which overrides the cell's `overflow-wrap:anywhere`. Below 1000px the table keeps a
   1000px minimum width and scrolls horizontally inside `.tnx-table-scroll` instead of squeezing columns. A rare
   long value (a date in another year) is cut with an ellipsis rather than drawn over the next column; the full
   time is in the tooltip. A time is never broken mid-number.
3. **Compact absolute time, full time in the tooltip.** A new `compactDateTime(iso, now)` in `lib/format.ts` uses
   `Intl.DateTimeFormat(undefined, …)` so the viewer's locale decides order, separators and 12/24-hour clock, as
   the other tables (`toLocaleString()`) do:
   - same calendar day: time only (`12:32` / `12:32 PM`);
   - same year: day, short month and time (`25 Nov, 12:32` / `Nov 25, 12:32 PM`);
   - otherwise: with the year.
   No seconds. The element is a `<time dateTime=…>` with `title` set to the full `toLocaleString()` value, so the
   exact second is one hover away and machine-readable.
   Relative time ("12 min ago") was rejected: the sessions list re-renders only on refresh, so a relative label
   goes stale while the page is open and silently lies. An absolute label never does.
4. **Duration or expiry uses the same formatter.** A live session shows `Expires <compact time>`; an ended one shows
   the duration ("12 min"). Same nowrap element.
5. **Details drawer.** The drawer's `dl` is a wide two-column fact list and did not have the bug, but it now uses
   the same element (full `toLocaleString()` text there, since space is not tight) for consistency.

### Tests (web)

- The rendered table has a `Started` and a `Duration or expiry` column header, and the Started cell shows the
  compact time with the full time in `title` and `dateTime` set to the ISO value.
- `compactDateTime` returns time-only, no-year and with-year forms; expected strings are computed with the same
  `Intl` options so the test is locale/TZ independent.
- A stylesheet guard reads `server-access-workspace.css` and fails if any `.sa-session-table` rule sets
  `font-size:0`, or if the grants rules again select session-table columns. jsdom applies no stylesheet, so this is
  the only test that would have caught the original bug.

## Bug 2: an open replay writes an audit row every 5 seconds

### Problem

While a replay is open, the audit log gains `server_access.recording_access_checked` every ~5 seconds for the same
actor and session.

`TerminalReplay.tsx` does a full read on open and then calls
`GET …/sessions/{sessionId}/recording?metadata_only=true` every 5 s. That poll is not cosmetic: the SA-0 authority
contract (`docs/SA-0-authority-contract.md`, Replay) requires "metadata-only rechecks every five seconds in the
mounted player; loss of authority clears its terminal content". The server (`serveraccess/recording.go`,
`Recording`, metadata-only branch) re-runs the full authority check — current parent login, user status and auth
epoch, logout tombstone, same-org membership, replay permission, own-session or session-management authority —
and then writes `recording_access_checked`. The metadata branch returns no events: status, archive status, archive
error/retry time and expiry only.

### Options

- **(a) Metadata polls do not audit; content reads do.** Already the shape of the API: `metadata_only=true` exists
  and never reads chunks. Only the audit write in that branch is removed.
- **(b) Server-side de-duplication per actor+session within a window.** Keeps a row per window. Needs a read of
  `audit_logs` (or a new table) inside every poll, a window to justify, and still produces a row every window for a
  long replay. It also makes the audit log's meaning time-dependent ("an access within the last N minutes may not be
  recorded"), which is exactly the kind of guarantee erosion to avoid.
- **(c) Stop polling when the recording is complete.** Taken alone this breaks the SA-0 contract: a finished
  recording would stay on screen after the viewer's authority is revoked. It also does not fix a live capture,
  which polls for its whole duration.

### Decision: (a), plus a tighter polling lifecycle

1. **Server.** The metadata-only branch of `Recording` keeps every authority check, but no longer writes
   `recording_access_checked`. No other path changes. No OpenAPI change, no migration, no generated code.
2. **Every content read is still audited, exactly.** The content paths and their audit rows are unchanged:
   - full read (opening the replay, "Load latest output"): `recording_read` with owner and event count;
   - full read of an expired/failed recording: `recording_read` with `events: 0`;
   - download: `recording_download`; encrypted package download: `recording_package_download`; import:
     `recording_import`; S3 export request: `recording_archive_requested`.
   Each audit insert is in the same transaction as the read and a failed insert fails the request, as before.
   So one replay now produces one `recording_read` when it is opened, plus one per explicit "Load latest output".
3. **Client polling lifecycle.**
   - The authority recheck runs while the player is mounted **and the tab is visible**, every 5 s, whatever the
     recording status — this is the SA-0 revocation mechanism and is kept.
   - When the tab becomes hidden the timer is cleared: no requests from a background tab. When it becomes visible
     again the player rechecks immediately, before anything else, then resumes the 5 s cadence. A revocation that
     happened while hidden therefore clears the content the moment the viewer can see it again.
   - Polling stops when the player unmounts (Close recording, navigating away).
   - Polling stops once the recording reaches a terminal content-free state (`expired`, `failed`, `disabled`):
     the player has already cleared its content for those, so there is nothing left to protect and nothing
     further to learn.
   - **Deliberate deviation from the brief.** The brief asked for polling "only while a recording is still
     capturing". That would remove the SA-0 revocation guarantee for finished recordings, so it is not done. With
     the audit row gone a poll is a cheap authorized read that leaves no trace in the audit log, which removes the
     reason to restrict it. Status refresh during capture is a by-product of the same call.

### Security and audit analysis

- **What the removed row recorded.** That an already-authorized viewer was re-authorized, plus the recording status.
  It never recorded access to content. The content access that preceded it (opening the replay) is still recorded
  by `recording_read`, with the same actor, session and owner.
- **What a metadata poll discloses without an audit row.** Status, archive status, archive error code (a fixed code such as
  `archive_storage_unavailable`, never free text), archive retry time and expiry, to a caller who passes the same authority checks as a content read. That is session-level state of the
  same kind as the unaudited Sessions list, which already shows whether each session is recorded. No output, no keystrokes, no resize events.
- **Authority checks are unchanged.** Every poll still runs the full `recordingAudience` check; denial still returns
  403 and the player still clears its content and cancels queued rendering on denial or network loss.
- **Denials.** Neither the old nor the new code audits a denied metadata poll; that is unchanged.
- **Hidden tab.** Pausing while hidden does not widen exposure: content already delivered to the browser cannot be
  recalled in either design (SA-0 states this), and the immediate recheck on becoming visible clears the screen
  before the viewer can see it, exactly as a 5 s poll would have at worst 5 s later.
- **Existing rows.** Historical `recording_access_checked` rows stay in the audit log; nothing renames or deletes
  them. The web audit view humanizes action names generically, so they keep rendering.
- **Version skew.** An old web client against the new API: polls stop producing rows (the goal). A new web client
  against an old API: the old API still writes a row per visible poll, but none while hidden or after the replay
  closes. No contract change in either direction.

### Tests

- API (`testpostgres` + miniredis, both editions): a recorded terminal session; N metadata-only reads add zero audit
  rows of any kind and return no events; each full read adds exactly one `recording_read`; after the viewer's
  membership is revoked a metadata read is denied and still writes nothing.
- Web: the poll stops on unmount; no poll requests while the tab is hidden; an immediate recheck when it becomes
  visible again; a denied recheck still clears content (existing tests kept); polling stops on an expired recording.

## Deferred

- The grants table still uses positional `nth-child` widths. Column-keyed widths would need a `className` on
  `DataTable` columns (`ui.tsx`), a shared-component change outside this story.
