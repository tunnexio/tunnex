# F07 instrument-first and default-deny proof

- Disposable reporter: `f07-reporter-20260816T0615Z`, node `01a00933-4b37-7ac3-9104-793b1dc4dade`.
- Disposable managed agent: `f07-agent-20260816T0618Z`, device `01a00937-8187-702a-845a-dc1a9ff6561f`, address `10.99.0.7`.
- Reporter health was ready; `flowlog_started` was observed; access-log health reported `retention_failed=false` and `dropped=0`. The agent-filtered baseline was empty only after those instrument checks.
- The approved agent reached runtime revisions `desired/attempted/applied=1/1/1`, `connected`, `ready`, `stale=false`, with a real reporter/runtime WireGuard handshake.
- With zero grants, a TCP attempt to `10.99.0.200:18080` failed and produced an attributed deny from the applied subject map:
  - source agent `01a00937-8187-702a-845a-dc1a9ff6561f`
  - gateway `01a00933-4b37-7ac3-9104-793b1dc4dade`
  - observed route `10.99.0.7 -> 10.99.0.200`, TCP/18080
  - `decision=deny`, `decision_reason=no_matching_grant`, `rule_id=null`
  - applied policy hash `d67bad673369`, policy protocol version `4`, agent configuration revision `1`
- No human or workflow trigger was inferred or rendered.
