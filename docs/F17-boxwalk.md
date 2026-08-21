# F17 — final CSS and UX polish box-walk

Status: **live control-plane UI proof complete (2026-08-21); review and CI
pending**.

## Local proof

The complete web suite passed after the shared modal fix: **85 test files,
1,117 tests**. Focused coverage proves the modal enters the dialog, traps Tab,
handles Escape, and restores the opener even when a child field uses
`autoFocus`. It also proves narrow-drawer focus movement and announced retry
errors.

## Live control-plane UI proof

The F17 source was staged on CP `54.79.53.95` and the web service alone was
rebuilt and recreated. The previous source is retained at
`/home/ubuntu/tunnex/.f17-walk-backup-20260821T125249Z`. API, Caddy, nginx,
node-agent, PostgreSQL, and Redis remained running; the rebuilt web service
reported healthy. No API mutation, policy change, agent change, or form
submission was made during this walk.

| Leg | Expected outcome | Result |
|---|---|---|
| Narrow navigation starts closed | `aria-expanded=false`; drawer is hidden | PASS at 375px |
| Keyboard navigation | Enter opens the drawer and moves focus to Overview | PASS |
| Drawer dismissal | Escape closes it and returns focus to Menu | PASS |
| Create-site dialog entry | Focus reaches the auto-focused Site name field | PASS |
| Dialog keyboard loop | Shift+Tab from Site name reaches Cancel; Tab returns to Site name | PASS |
| Dialog dismissal | Escape closes the dialog and returns focus to Add site | PASS |
| Rendered shared controls | Add site minimum height is 44px; Sites table scroll region uses horizontal overflow | PASS |

The first live modal leg exposed a real focus-return defect: a child
`autoFocus` field was captured as the apparent opener, so dismissal fell back
to the document body. F17 now captures the opener during modal render, before
the child autofocus commit, and adds a regression test. The repaired CP build
repeated the same live leg successfully.
