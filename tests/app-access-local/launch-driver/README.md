# Owned launch driver

This nonshipping helper uses its own cookie jar and a normal local password login.
It neither imports browser cookies nor modifies the review browser's session. Run
only after the orchestrator confirms the owned payroll publication is active.

It verifies public and console TLS 1.3 with the retained fixture CA, real hostname
and SNI, fixed loopback dialing and no environment proxy or automatic redirects.
The pending nonce is created by the actual proxy before the console launch POST;
the helper checks the configured internal console return, one redemption and a
refused replay, then GET/assets/form/redirect/cookie behavior over the real channel.
This is safe-return compatibility evidence, not an actual IdP or rendered SSO login.

Build using the pinned Go toolchain with `GO111MODULE=off`. Run with the exact
`APP_ACCESS_OWNED_PROJECT` and `APP_ACCESS_OWNED_CHECKOUT` guards used by the stream
driver. `--account-file` accepts an existing mode-0600 account env in the owned
`.runtime` directory, with `AA1_UI_EMAIL` and `AA1_UI_PASSWORD`. Default is the
separately seeded UI account; the mutation matrix should supply its own synthetic
account file to preserve that account's grants and browser sessions.

`--session-file` and `--control-file` must be new direct children of `.runtime`.
They are exclusively created with mode 0600. The session file contains only the
app token for the five-protocol driver. The control file contains CP cookies and
exact user/org/app/app-session IDs for the separately authorized scoped mutation
orchestrator. Never print, attach, or pass their contents on a command line.
The helper's stdout contains only nonsensitive IDs and proof labels. Transient
code/nonce redirect URLs are never persisted or printed. No revoke or publication
mutation is performed by this helper.

`--login-only` creates only the independent native CP cookie artifact and stops
before pending registration, launch or application traffic. The scoped mutation
orchestrator can use it for a separately logged-in owner without borrowing any
review browser cookies.

`--baseline-root-only` explicitly qualifies only pending/launch/redemption/replay,
root GET, strict public/console TLS and session metadata. Its output marks
assets/form/redirect/cookie compatibility **unqualified**. Use this against the
old minimal origin, then run a fresh full qualification after the orchestrator's
reviewed compatibility origin upgrade. The replay probe re-sends the original
valid browser nonce with the consumed code, reaching the actual single-use guard.
