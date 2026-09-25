# S2S-3: per-tunnel troubleshooting increment

## Scope

Continue development as requested while retaining the failed full-CI gate for final verification. Native AMD64 qualification passed at fce82b1f; that result does not replace full CI or qualify customer AWS deployment.

Reuse the existing IPsecTunnelHealth component and read-only status endpoint. Each tunnel has an initially collapsed, keyboard-accessible troubleshooting disclosure. Derive guidance from the same freshness-validated status that controls its badge. Keep existing theme and two-column desktop layout; no additional setup wizard or always-visible explanation block.

- Up: encrypted tunnel established; review access policy and remote return routes if applications remain unreachable. Do not claim verified application traffic.
- Down: suggest checking the remote endpoint, IKE reachability and matching authentication/proposals. These are checks, not diagnosed causes.
- Unknown: refresh the report and check gateway/control-plane connectivity. Stale Up must never retain success-specific guidance.

Opening guidance performs no write, reconnect, key read/export, route change or failover. Do not render server failure bodies or credentials. No schema, permission, API or lifecycle changes are required.

## Acceptance

Focused tests cover independent Up/Down guidance, Unknown after stale/failed observations, initially collapsed disclosures and read-only interaction. Inspect the rendered synthetic preview and run the relevant existing workspace/security tests plus frontend typecheck. Live gateway state remains untouched.

## Remaining S2S-3 work

This increment is diagnostics guidance only. Measured two-tunnel recovery/failover and PSK rotation require their own explicit state-transition and rollback contract plus native packet evidence. Full CI failure remains an unresolved final gate, not a completed or waived check.

## Local verification — 2026-09-25

Implemented the collapsed status-specific guidance using existing theme tokens. Focused tunnel-health, workspace and security suites pass: 32 tests across 3 files. Frontend TypeScript check passes. Synthetic browser preview confirmed both disclosures initially closed, Enter expands Tunnel 1, click independently expands Tunnel 2, and the existing two-column dark theme is preserved. Stale/unknown/invalid reports select Unknown guidance in tests; disclosure interaction performs no API writes. Changes remain local, with no CI rerun or publication in this increment.
