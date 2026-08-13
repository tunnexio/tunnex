# S7.5.5 — founder-driven UI walk (Pawan clicks; the six slice-3 features rendered)

Backend proven on the wire (grandfather / bearer-exempt / downgrade / audited mutations). This walk
proves the SPA renders: self-enroll ceremony, challenged login, legible failure/cap, enforce toggle +
D8 honesty copy, forced-enrollment (grandfather) page, admin-reset modal + notification.

TOTP codes come from a REAL authenticator app on Pawan's phone (scan the QR) — the customer path.
Each enrollment shows a NEW QR = a new entry; after any disable/reset, the OLD entry is dead — always
use the NEWEST QR. Owner and member are separate authenticator entries.

Users (both password `tunnex-demo-password`):
- owner@demo.tunnex.local (owner) · member@demo.tunnex.local (member) · org slug `demo`
Dashboard: http://<BOX>/  · Mailpit: http://<BOX>:8025/   (<BOX> = however Pawan reaches the VM)

Prep leaves: enterprise build, enforce OFF, member+owner unenrolled, Mailpit empty.

## Steps (findings are WALK FINDINGS — held, dispositioned, same protocol)

A. Self-enroll (open half): member login (no gate, enforce off) → Settings → Set up 2FA → QR + manual
   key shown ONCE → scan → enter code → confirm → recovery-codes modal (once) → note count (10).
B. Challenged login: member logout → login → password → 2FA step → WRONG code (legible error) →
   right code → in. Then logout/login again → use a RECOVERY CODE instead of TOTP → in.
C. Cap: at the 2FA step, enter wrong codes 5× → capped state renders + routes back to password login.
D. Enforce ON (owner): owner login → Settings → owner enrolls own 2FA first (admin complies too) →
   org enforce section → D8 honesty copy visible verbatim → toggle ON.
E. Grandfather: member → Settings → turn OFF 2FA → next navigation → forced-enrollment page ("set up
   2FA to continue", nothing else reachable, sign-out escape) → complete enrollment → proceeds.
F. Admin-reset: owner → Users → Reset 2FA on member → confirm modal names the target + "notified by
   email" → confirm → Mailpit has the notification → member next login = password then forced enroll.
G. Downgrade glance (optional): rebuild open → owner sees no enforce toggle (edition-gated); a member
   with TOTP is still challenged at login.

Verdict + Pawan's findings recorded here after the walk.
