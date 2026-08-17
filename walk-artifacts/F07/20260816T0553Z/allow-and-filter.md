# F07 matched-grant and server-filter proof

- Disposable resource `01a00940-8139-791f-abe8-e03a4094bb20` described only `10.99.0.200/32`, TCP/18080.
- Disposable rule `01a00940-817c-7d93-af8e-6a461c2cfbf2` granted the F07 agent access to that resource.
- After the reporter applied the policy, the same URL returned HTTP 200 and both WireGuard peers transferred traffic.
- Access event `01a00941-20b0-7358-9516-898d94ccd9d7` preserved:
  - the exact source agent and gateway IDs above
  - the exact route tuple and rule ID
  - `decision=allow`, `decision_reason=matched_grant`
  - applied policy hash `315c0e233f55`, policy protocol version `4`, configuration revision `1`
- Server-side filters passed: agent attribution, `denies_only` excluding allow, agent plus deny across two one-row keyset pages, and an unrelated UUID returning HTTP 200 with an empty page and no identity oracle.
