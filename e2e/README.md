# Tunnex e2e harness

One command runs everything against a real stack:

```bash
make e2e     # brings the stack up healthy, then runs API integration + browser e2e
```

What it does:
1. `docker compose up -d --wait` — starts the stack and waits for every service healthy (reuses a running stack; never wipes data).
2. **API integration tests** — `go test ./...` with `TUNNEX_TEST_DATABASE_URL` set, so DB-backed tests run (incl. the `set_updated_at` trigger schema check).
3. **Playwright** — drives the SPA through the edge nginx and asserts the
   `SPA → API` correlation chain (`X-Request-Id` well-formed and matching the
   response body), not just that pages load.

## Seed data

```bash
make seed    # idempotent, non-destructive; no-ops until domain tables exist (S1.1)
```

The demo dataset uses **fixed, documented IDs** (see
`apps/api/internal/seeddata/seeddata.go`) so tests reference them without
querying — notably `DemoOrgID = 01900000-0000-7000-8000-000000000001`.

## Notes

- Playwright pins `@playwright/test@1.48.2` to match the
  `mcr.microsoft.com/playwright:v1.48.2-jammy` runner image (browsers must match).
- Tests must stay green on the **open build with local auth only** — no
  enterprise/SSO dependency — so the open edition is always fully testable.
