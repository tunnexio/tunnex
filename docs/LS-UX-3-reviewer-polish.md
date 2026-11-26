# LS-UX-3 — Local Sharing reviewer page polish

Branch `story/ls-ux-3` from `origin/main` (includes LS-UX-2, PR #137). Local only until the
founder says otherwise. Internal code name **Beam**; customers see **Local Sharing**.

Trigger: live walk on v0.1.50 of the share page (`/beam/shares/:id`) as an invited reviewer
in an organization whose Local Sharing policy requires MFA. Follows
`docs/LS-UX-2-reviewer-and-member-experience.md`. Security rules are unchanged: the server
still enforces the 5-minute MFA freshness on launch, feedback and Sharing updates
(`internal/beam/authority.go` `parent`); this story only changes how the console presents it.

Read for this paper: `apps/web/src/pages/Beam.tsx` (share detail, `ReviewerLaunch`),
`components/BeamFeedback.tsx` (feedback + Sharing updates), `components/BeamShareMobile.tsx`,
`components/InlineTerminalMfa.tsx`, `components/ui.tsx`, `components/ui/button.tsx`,
`beam-workspace.css`, API `internal/beam/{authority,feedback,notifications,browser}.go`.

## Decisions

| # | Page / state / role | Finding | Decision |
|---|---|---|---|
| U1 | Share detail, Review feedback, any viewer, policy requires MFA and the session has no MFA in the last 5 minutes | The feedback read is refused with `mfa_step_up_required`. The console put the server message in red (*"Verify MFA to open this share"*) and then the fallback *"Feedback can be added while this share is available to your account."* Red reads as an error; the second sentence explains nothing; there is no way forward on the page. | **Fix.** No red text. A neutral line says why: *"Your organization requires a recent MFA check to read and send review feedback."* plus a **Verify MFA** button (primary: it is the next step in that section). The button opens the console's existing inline step-up (`InlineTerminalMfa`, same as Server Access / upgrades) with `freshnessSeconds=300` to match the server. On success the feedback reloads in place and the form appears, no page reload. Cancel returns to the button. Copy is viewer-neutral (publisher and managers pass the same gate). |
| U2 | Share detail, Review feedback, MFA lapses while writing (draft open > 5 minutes) | Submit was refused, the draft was marked "uncertain" and the red server message said to open the share. | **Fix.** An MFA refusal on submit is not an uncertain write (the server refuses before writing). The draft is kept, the inline step-up opens straight away, and after verification the feedback is sent. |
| U3 | Sharing updates panel (lists), policy requires MFA | Same server gate (`notifications.go`), so the panel showed the red *"Verify MFA to open this share"* (wrong noun: no share is being opened) and a **Retry** that cannot help. | **Fix.** Same neutral line + **Verify MFA** + inline step-up as U1; the updates load after verification. |
| U4 | Open shared app (`/beam/launch`), policy requires MFA | After *Continue*, a code box appears with no reason given. | **Fix.** Same neutral sentence above the existing code box (*"Your organization requires a recent MFA check before you open shared apps."*). Flow and button name unchanged. |
| U5 | Share detail, Shared app / Share settings card footer, all viewers | *Open app >* is a small 12 px bordered link; *Open on phone* and *Copy link* are standard 36 px outline buttons; *Review feedback* is plain text. Four different looks in one row. | **Fix.** One button group: **Open app** is the primary button (filled), *Open on phone*, *Copy link* and *Review feedback* are secondary (outline). Review feedback stays a link to `#beam-review-feedback` (keyboard and no-JS friendly) styled as a button; it scrolls to the section and moves focus to the first form control, or to the Verify MFA button, or to the section. The list rows keep the compact *Open app* link (unchanged; different density). |
| U6 | Share detail, Manage sharing card, publisher / manager | *Pause share* rendered as the filled primary next to *Stop share*: pausing is not the main action of the card and the filled style draws the eye to it. | **Fix.** *Pause share* is secondary (outline). *Resume share* (the next step when paused) stays primary. *Stop share* keeps its danger style: it is a real destructive action. |
| U7 | Share detail and Open shared app, share not available to this account (LS-UX-2 L9) | The uniform *"This shared app isn't available to your account…"* sentence is informational but is rendered red with `role="alert"`. | **Fix.** Rendered as the neutral status hint (same box as the other status sentences). Real failures (copy failed, could not be checked, mutation refused) stay red. |
| U8 | Status pill *Local app unavailable* / *Unavailable* | Danger tone. | **Kept.** The app really cannot be opened; this is the one state where the colour is meant to alarm. *Publisher offline*, *Reconnecting*, *Starting*, *Refresh required* stay amber, *Paused / Expired / Stopped / Revoked* neutral. |
| U9 | Open app unavailable text (*Access is not currently granted*), reviewers card, diagnostics, events | Grey or neutral already; no red outside real errors. | **Kept.** |
| U10 | Share detail, *Open on phone*, policy requires MFA | The QR code carries only the public share URL; the phone signs in and lands on the same *Open shared app* page. | **Kept.** U4's sentence covers the phone as well; nothing phone-specific to change. |
| U11 | Earlier feedback, *View screenshot* link, MFA lapses after the list loaded | The screenshot opens in a new tab through the same server gate, so after 5 minutes that tab shows the API refusal. | **Kept / known.** Out of scope for this polish story; reloading the feedback (which now offers Verify MFA) is the recovery. Candidate for a later story. |

## Not changed

- Server: no API, policy or freshness change. `check:beam` (OpenAPI drift) must stay clean.
- `InlineTerminalMfa` itself (shared with Server Access, upgrades, editor auth) is reused as is.
- Vault and navigation files (owned by `story/vault-ux-1`).

## Tests

`apps/web/test/lsux3beam.test.tsx`: U1 (no red text, Verify MFA → inline step-up → form appears
without reload, feedback re-read), U2 (MFA on submit keeps the draft, verifies and sends), U3,
U4, U5 (button classes and focus), U6, U7. Existing LS-UX-2 tests keep passing.
