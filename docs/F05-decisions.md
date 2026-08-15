# F05 — Runtime bearer and WireGuard rotation decisions

Status: **In progress**. F05.1 covers the runtime bearer. F05.2 reuses the same
operator action and runtime channel to rotate the managed agent's WireGuard key.

## Essential contract

- An owner/admin holding `agent_credential:rotate` requests one rotation for an
  active managed agent. Plain members receive the same 403 and the released
  route does not request or render rotation status for them.
- The agent generates `tnx_runtime_` successor plaintext locally. The control
  plane accepts and stores only its 32-byte SHA-256 hash while the current
  bearer authenticates the request. API/UI projections contain only revision,
  state, and the one-hour deadline.
- PostgreSQL permits one current and at most one candidate. Repeating the same
  requested revision/hash is idempotent. The first successful poll/report with
  the candidate atomically promotes it and makes the old bearer return the
  uniform 401 response.
- The runtime writes candidate, previous, and live credential files atomically
  with mode 0600. A definite candidate 401 restores the old bearer. An unknown
  response preserves the candidate plus previous credential so restart can
  prove the outcome. Credential-only rotation never applies or restarts the
  WireGuard tunnel.
- Suspension cancels request/candidate state while retaining the proven current
  bearer for resume. Revocation/deletion invalidates current and candidate rows
  in the same device lifecycle transaction; F04 performs the existing clean
  tunnel offboard on the next uniform 401.
- Migration 0094 backfills legacy credentials as revision 1/current. Down is
  allowed only for pristine legacy state and refuses before deleting rows or
  hashes after any rotation request/history exists.

No generic credential framework, plaintext delivery endpoint, credential hash
projection, scheduler, bootstrap-token rotation, or gateway certificate
rotation is in F05.

## F05.2 WireGuard key state machine

The single operator **Rotate credential** request opens the bearer request above
and a WireGuard request with the same one-hour deadline. Only one current public
key (`devices.public_key`) and one candidate public key may exist for an agent.
The candidate private key is generated on the managed Linux runtime and never
crosses the machine boundary.

1. `requested`: the runtime poll exposes only the requested WG revision and
   deadline. The runtime creates a mode-0600 candidate private-key file, derives
   its public key, and prepares that public key through the authenticated runtime
   channel. Repeating the same revision/public key is idempotent; a different
   key for that revision is refused.
2. `prepared`: gateway desired state contains the current peer with its assigned
   `/32` (and `/128`, when present), plus the candidate peer with **no
   AllowedIPs**. This warm peer is sufficient to receive a WireGuard initiation,
   but cannot own or route the agent address. Therefore the gateway never has
   duplicate or ambiguous AllowedIPs.
3. `staged`: a real gateway status report containing the candidate public key
   proves that the warm peer was installed. Only then does runtime poll
   acknowledge staging. The runtime atomically preserves its last-good config,
   replaces only `PrivateKey`, and applies the local interface; it does not
   change address, gateway peer, routes, DNS, or service process.
4. `cutover`: the candidate initiates WireGuard. A nonzero candidate handshake
   reported by the agent's assigned gateway is the sole commit signal. In that
   report transaction the control plane replaces `devices.public_key` with the
   candidate and marks the rotation complete. The next desired state gives the
   `/32` solely to the new current peer and omits the old peer, retiring it.
5. `current`: runtime poll confirms the committed revision; the runtime deletes
   its previous-key/config recovery files. The released UI shows only revision,
   state, and deadline after refetch; no current/candidate public key is added to
   the rotation wire projection or DOM.

An expired/cancelled request before local switch removes the warm candidate and
leaves the current tunnel untouched. A definitive cancellation after switch
causes the runtime to atomically restore the last-good private key/config. An
unknown or lost response preserves both candidate and last-good files so restart
can re-poll and finish or restore without inventing an outcome. Suspend cancels
the WG candidate/request and preserves `devices.public_key`; revoke/delete
invalidates both and reuses F04's clean offboard. Expiry is evaluated on existing
request, poll, and gateway-report traffic; F05 adds no scheduler.

## Combined AWS DEV live checklist (not yet executed)

1. Deploy exact content commit to the authorized development CP only; verify
   schema 94 clean and keep the previous API/web/runtime images recorded.
2. On the Ubuntu agent VM, record active service/PID, mode-0600 credential and
   config files, current WireGuard public key/interface, and a real
   gateway-reported handshake. Preserve the exact last-good config/key for
   bounded rollback inspection; never print either private credential.
3. In the released Agents route, request rotation as owner; refetch must show
   requested revision/deadline and no bearer/hash in network payload or DOM.
4. Observe the same runtime PID generate/prepare/switch the bearer, then refetch
   its current revision. Old bearer must return uniform 401; successor poll and
   report succeed; service and WireGuard interface remain active with no WG
   apply churn during this bearer leg.
5. On the gateway, prove desired state has old peer owning the agent `/32` and
   candidate peer with empty AllowedIPs. Its zero-handshake status report must
   move UI/API to `staged` without changing `devices.public_key`.
6. Observe the Ubuntu runtime hot `wg set` key switch with the same PID,
   interface, address, gateway peer, routes, and DNS. A real nonzero candidate
   handshake from the assigned gateway must atomically commit the canonical
   public key/revision; the next desired state must contain only the new peer
   owning the `/32` and omit the old peer.
7. Repeat once with an interrupted prepare response and runtime restart. The
   same bearer hash and WG public candidate are retried, every scratch file is
   0600, and the last-good tunnel remains recoverable. Exercise timeout after
   local key switch and prove atomic restoration of the previous config/key.
8. Request another rotation, suspend before commit, and prove both candidates
   cancel while the current bearer/key survive resume. Then revoke and prove
   current+candidate bearer refusal, both WG peers absent, and F04 clean
   inactive offboard.
9. Run exact-head default+enterprise API, CLI, web, generation, migration
   rollback, diff, and secret scans. Clean only disposable F05 resources.
