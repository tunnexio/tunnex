# Provider API URL entry validation

Decision paper: `S-AI-endpoint-entry-decisions.md` (51873d54).

New Custom and SageMaker forms accept an API base URL beside an approved-endpoint
shortcut and display the actual chat request URL. Test Connect stays visible in
the drawer footer. Native providers retain their standard origins.

## Results

- Full web suite: 1,353 tests across 118 files passed; TypeScript and production
  Vite build passed. Vite retains the existing large-chunk warning.
- Focused provider suite: 21 tests passed, including typed URL normalization,
  canonical probe/create payloads, refusal of unapproved URLs and credentials in
  URLs, and invalidation after endpoint edits.
- Independent read-only review found no actionable endpoint approval, stale
  result or immutable-connection issues. Self-review included final footer placement.
- Actual local CP browser walk: typed `http://fixture:8091/v1`, selected the
  synthetic `private-demo` model, and pressed Test Connect. The authenticated
  CP/LiteLLM/egress fixture path returned success; the UI displayed
  "Test succeeded for private-demo" and enabled Create connection.
- Changed that URL to `https://not-approved.example/v1`: the key and successful
  result cleared, approval explanation appeared, and Test/Create were disabled.
- Rendered SageMaker URL entry with `http://fixture:8200/v1` and its derived test
  URL. This is a private LiteLLM bridge URL, not a direct AWS runtime URL.

No connection was saved, policy changed or paid inference requested in this walk.
Screenshots: `walk-artifacts/ai-gateway-20260907/custom-api-url-test-local.jpg`
and `walk-artifacts/ai-gateway-20260907/sagemaker-api-url-entry-local.jpg`.

This UI validation does not satisfy SageMaker AWS qualification. User designated
local CP and ap-south; ap-south-1 was assumed from the previously named region.
Read-only local STS returned account 132613841543 for both available profiles,
which differs from the previously authorized sandbox 735391218823. No SageMaker
inventory or invocation followed. Confirm the intended account and existing
endpoint/IAM binding before cloud qualification. Earlier composite-gate capacity,
image-build, remote-CI and full LiteLLM parity limitations remain unchanged.
