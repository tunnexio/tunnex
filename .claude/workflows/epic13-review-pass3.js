export const meta = {
  name: 'epic13-review-pass3',
  description: 'EPIC 13 review pass 3 — the agent recovery loop, adversarially verified',
  phases: [
    { title: 'Find', detail: '7 finder angles over apps/node' },
    { title: 'Verify', detail: 'two adversarial lenses per finding' },
    { title: 'Critic', detail: 'what the finders could not have found' },
    { title: 'Synthesize', detail: 'rank the survivors' },
  ],
}

const SCOPE = `
REPO: /Users/pawangupta/tunnex  BRANCH: story/S13.1-gateway-recovery (a1ae128)  BASE: f9b2dfd0 (main)
Diff with: git diff f9b2dfd0...HEAD -- apps/node

THE SURFACE UNDER REVIEW (pass 3 of 3) — THE AGENT RECOVERY LOOP, apps/node only:
  apps/node/cmd/agent/main.go            attemptRekey + its retry loop, saveCreds, loadOrCreatePendingKey,
                                         enrollWithToken, renewLoop, the boot sequence around identity.Decide
  apps/node/internal/identity/decide.go  Decide(), the precedence order, EffectiveName, StoredSerial
  apps/node/internal/control/rekey.go    Rekey(), rekeyChallenge, Identifier, KeyFingerprintFromPEM,
                                         GenerateKey, csrForKey, error mapping, retryAfter
  apps/node/internal/control/client.go   GenerateKeyAndCSR, Enroll, Renew, the TLS/RootCAs construction
  tests: cmd/agent/main_test.go, internal/identity/decide_test.go,
         internal/control/rekey_test.go, internal/control/fingerprint_test.go

WHAT THIS CODE IS FOR. A gateway whose 48h certificate expired cannot authenticate to the mTLS agent channel,
and /agent/renew lives behind that channel. So the agent recovers by proving possession of the keypair the
control plane recorded, over the PUBLIC api listener. If that fails it falls back to an operator-minted join
token, which creates a NEW node (site binding lost, devices need re-issuing) — so it is the LAST resort, never
the first. The agent must never exit on a condition the control plane could resolve.

TWO PRIORS FROM REVIEW PASS 1, CARRIED IN ADVERSARIALLY. Both are confirmed defect SHAPES in this exact code,
so assume more instances exist and go looking:

  ROOT 2 — INPUTS DECIDED ONCE, BEFORE A LOOP THAT NEVER REVISITS THEM. attemptRekey samples
  pendingWasOnDisk at entry, builds its identities slice before the loop, never receives HaveToken at all, and
  the only loop exits are success and ctx-cancel. Three separate pass-1 findings were instances of this one
  shape. FIND THE REST: for every value read before a loop, ask what changes it while the loop runs, and what
  the loop would do differently if it re-read it.

  ROOT 7 — GUARDS AND COMMENTS VOUCHING FOR PROPERTIES THE CODE DOES NOT HAVE. Five instances in pass 1,
  including a test whose expectation is derived from the artifact under test. TREAT EVERY COMMENT THAT ASSERTS
  A SAFETY PROPERTY AS A CLAIM TO BE FALSIFIED, NOT AS CONTEXT. This codebase writes long explanatory comments;
  several of them are wrong, and the wrong ones are load-bearing precisely because they read as authoritative.
  When you find a comment asserting a property, construct the input that violates it before believing it.

ALREADY FOUND IN PASS 1 — do NOT re-report these; report only NEW defects or a materially different mechanism:
  - main.go:861 saveCreds writes the ca_pem from the unauthenticated re-key response, replacing the trust anchor
  - main.go:852 the retry loop has no exit on persistent refusal, so the join token is never reached
  - main.go:837 pendingWasOnDisk sampled before the loop, so the lost-response case never tries the fingerprint
  - control/rekey.go:193 every non-200/429 and every transport error maps to a permanent refusal
  - main.go:441 saveCreds can leave a new cert beside an old key; no boot-time pair check

ANSWER IN DEFECTS, NOT IMPRESSIONS. Every finding names a concrete failing sequence: starting state (which files
exist on disk with what contents, what the server answers, what the clock says), the step-by-step path through
the code with file:line, and the wrong outcome. "This could race" is not a finding; "the renew goroutine writes
key.pem at line N while attemptRekey is between its rename calls at line M, leaving X" is.

DO NOT report: style, naming, comment density, missing tests for code you found no defect in, or speculative
hardening with no failing sequence.
`

const FINDING_SCHEMA = {
  type: 'object', additionalProperties: false, required: ['findings'],
  properties: { findings: { type: 'array', items: {
    type: 'object', additionalProperties: false,
    required: ['title', 'file', 'line', 'severity', 'category', 'failure_sequence', 'why_it_matters'],
    properties: {
      title: { type: 'string' }, file: { type: 'string' }, line: { type: 'integer' },
      severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
      category: { type: 'string' }, failure_sequence: { type: 'string' },
      why_it_matters: { type: 'string' }, suggested_direction: { type: 'string' },
    } } } },
}

const VERDICT_SCHEMA = {
  type: 'object', additionalProperties: false, required: ['refuted', 'confidence', 'reasoning'],
  properties: {
    refuted: { type: 'boolean' }, confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
    reasoning: { type: 'string' }, correction: { type: 'string' },
  },
}

const FINDERS = [
  { key: 'loop', prompt: `${SCOPE}

YOUR ANGLE: ROOT 2 SYSTEMATICALLY — every value decided once, and the loop that never revisits it.

Enumerate, for attemptRekey AND for every other loop in apps/node's recovery path (renewLoop, the reconcile
loop, reportKeyLoop, any monitor goroutine): what is read before the loop, what can change it while the loop
runs, and what the loop would do differently if it re-read it.

Ask specifically:
 - The identities slice, the pending key, the node name, the stored serial, the certificate itself. Which of
   these can change on disk or on the server while attemptRekey is looping? What if an operator drops a join
   token into the environment, or restores the node server-side, or the pending key is deleted?
 - The backoff: does it ever reset on a change of condition? A gateway that has backed off to the 1h ceiling —
   what wakes it sooner when the control plane recovers?
 - Does anything re-read the CLOCK in a way that matters (a cert that expires mid-loop, a clock jump)?
 - renewLoop and attemptRekey: can they run concurrently, and what do they do to the same three files?
 - Is there any loop whose exit condition can never be satisfied from inside it?` },

  { key: 'comments', prompt: `${SCOPE}

YOUR ANGLE: ROOT 7 SYSTEMATICALLY — every comment that asserts a safety property, falsified.

Walk apps/node and collect EVERY comment claiming a property: atomicity, ordering, "cannot", "never", "always",
"by construction", "structurally", "so a crash mid-X leaves Y". For each, construct the input or interleaving
that violates it, or confirm it holds and say what makes it hold.

Known starting points (find more):
 - saveCreds "a crash mid-save leaves either the old set or the new set, never a mixture" — three renames.
 - loadOrCreatePendingKey "a crash mid-write cannot leave a truncated key".
 - identity.Decide "takes NO network argument ... a failed handshake CANNOT trigger re-key" — is that true of
   every caller, or only of Decide itself?
 - the pending-key comments claiming it "cannot become an identity by accident — only saveCreds can promote it".
 - control/rekey.go's claims about convergence and about the signed message matching the server's construction.
Report each falsified claim as its own finding, with the violating sequence. A comment that is merely imprecise
is not a finding; a comment that would lead the next engineer to skip a check IS.` },

  { key: 'state', prompt: `${SCOPE}

YOUR ANGLE: THE ON-DISK CREDENTIAL STATE MACHINE, exhaustively.

The state dir holds cert.pem, key.pem, ca.pem, rekey-pending-key.pem, wg.key, plus *.tmp files mid-write.

Enumerate the reachable combinations and what the agent does with each at BOOT and mid-run:
 - cert present + key absent · cert absent + key present · cert and key present but MISMATCHED (different
   keypairs) · pending present alongside a valid identity · pending present and unreadable · *.tmp left behind
   by a crash · ca.pem absent or corrupt · every file present but ca.pem is a DIFFERENT CA than the cert chains
   to · zero-length files (disk full) · files owned by the wrong user or wrong mode.
 - Which of these does identity.Decide classify correctly, which does it misclassify, and which does the agent
   never check at all? Is there a boot-time check that cert.pem and key.pem are the SAME keypair?
 - What happens on a disk-full or read-only filesystem at each write point?
 - Trace what the agent does after a partial saveCreds — at the NEXT boot, not just in the moment.
 - Does anything ever delete or overwrite a WORKING credential set?` },

  { key: 'errors', prompt: `${SCOPE}

YOUR ANGLE: ERROR MAPPING, BACKOFF, AND WHAT THE AGENT TELLS THE OPERATOR.

The control plane's refusals are uniform BY DESIGN and carry no reason, so the agent's local diagnosis is the
only thing an operator can act on. That makes its correctness a product property, not a nicety.

Ask specifically:
 - Enumerate every server response the agent can receive on both re-key round trips (2xx with a valid body, 2xx
   with a truncated/garbage body, 3xx, 400, 401, 403, 404, 413, 429 with and without Retry-After, 5xx, a hung
   connection, a TLS error, a DNS failure, a connection reset mid-body) and state what the agent DOES and what
   it LOGS for each. Which of those are wrong or misleading?
 - retryAfter: what does it do with an HTTP-date, a negative value, a huge value, a malformed one?
 - The backoff floor/ceiling arithmetic: overflow, reset conditions, and whether the throttle path can starve.
 - Does any log line print material that should not be logged (a key, a token, a CSR, a signature)?
 - Does the agent ever exit, panic, or become permanently non-ready on a condition the CP could resolve?
 - Is a 429 from an intermediary (a proxy, not the CP) distinguishable from the CP's own throttle?` },

  { key: 'precedence', prompt: `${SCOPE}

YOUR ANGLE: identity.Decide's PRECEDENCE, as a truth table.

Build the complete truth table of Decide's inputs (certPEM present/absent/corrupt, loadErr set or not, cert
expired or not, requestedName matching or not matching the stored CN, haveToken true/false, now vs notBefore
and notAfter) and check the verdict for EVERY row against what the recovery story requires.

Ask specifically:
 - Which rows return Recover, UseToken, UseStored, Idle — and is any row's verdict WRONG for the situation?
 - The crash-loop this precedence was written to fix: Helm injects TUNNEX_JOIN_TOKEN on every pod start, so an
   expired gateway used to take UseToken and 409 against its own row. Is the fix complete, or are there rows
   where a token still wins over a recoverable identity?
 - notBefore: a certificate not yet valid (clock skew backwards) — what does Decide say, and is it right?
 - A cert that is expired AND whose CN does not match the requested name.
 - What does the CALLER do with each verdict? Decide taking no network argument is a structural claim about the
   caller too — verify the caller cannot reach re-key from a network failure by another route.
 - Does any verdict lead to an unrecoverable state that a control-plane change could not fix?` },

  { key: 'wire', prompt: `${SCOPE}

YOUR ANGLE: WHAT ELSE DOES THE AGENT ACCEPT FROM THE WIRE WITHOUT VALIDATING IT?

Pass 1 found the agent writing the trust anchor from an unauthenticated re-key response. That is one instance of
a class: material arriving over the wire and being persisted or acted on without validation. Find the others.

Ask specifically:
 - Every response body the agent parses (enroll, renew, re-key, challenge, routed-ranges/dial, desired state /
   policy artifact, anything else): what is validated before it is used or written to disk?
 - The dial channel (dial_endpoint, dial_pubkey): what does the agent do with a hostile value — does a
   gateway public key or endpoint from a response get applied to the data plane?
 - Does the agent validate that a certificate it receives actually matches the key it just generated?
 - Size limits, content-type checks, and what happens on a multi-gigabyte or slow-loris response body.
 - Which of these paths run over plain HTTP (apiURL) versus the CA-pinned mTLS channel (agentURL)? List them.
 - Is there anywhere the agent trusts a server-supplied NAME, PATH, or COMMAND?` },

  { key: 'lifecycle', prompt: `${SCOPE}

YOUR ANGLE: GOROUTINES, SHUTDOWN, AND CONCURRENT WRITERS.

Ask specifically:
 - Enumerate every goroutine the agent starts and what state each touches. Which of them write the credential
   files, the WG key, or the data plane?
 - Can renewLoop, attemptRekey, the reconcile loop and any monitor write the same file concurrently? Construct
   the interleaving and say what lands on disk.
 - Context cancellation: on shutdown, can a write be interrupted between renames? Is there any cleanup?
 - Does recovery start before or after the data plane is brought up, and can a half-recovered agent push a
   partial or stale desired state to WireGuard?
 - Readiness/liveness: is there any state where the process reports ready while holding an unusable identity, or
   reports not-ready forever when it is fine?
 - Restart semantics: what does a SIGKILL at each interesting point leave behind, and does the next boot recover
   from it without an operator?` },
]

phase('Find')

const perFinder = await pipeline(
  FINDERS,
  (f) => agent(f.prompt, { label: `find:${f.key}`, phase: 'Find', schema: FINDING_SCHEMA })
    .then((r) => ({ key: f.key, findings: (r && r.findings) || [] })),
  (r) => {
    if (!r || !r.findings.length) return { key: r ? r.key : '?', verified: [] }
    const rank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
    const ordered = r.findings.slice().sort((a, b) => rank[a.severity] - rank[b.severity])
    const take = ordered.slice(0, 6)
    if (ordered.length > take.length) {
      log(`CAP: ${r.key} reported ${ordered.length}; verifying top ${take.length}. Dropped: ${ordered.slice(6).map(f => f.title).join(' | ')}`)
    }
    return parallel(take.map((f) => () =>
      parallel([
        () => agent(`${SCOPE}

You are REFUTING a review finding. Default to refuted=true unless you confirm the failing sequence by READING
THE CODE. Verify by construction, not by plausibility.

LENS: CORRECTNESS. Does the sequence actually occur? Read every function on the path; check whether some guard,
type, file ordering, caller precondition or goroutine structure already prevents it. Quote the deciding lines.
If it is directionally right but the mechanism is wrong, set refuted=false and give the CORRECTION.

FINDING
title: ${f.title}
file: ${f.file}:${f.line}
sequence: ${f.failure_sequence}`,
          { label: `v:correct:${f.title.slice(0, 26)}`, phase: 'Verify', schema: VERDICT_SCHEMA }),
        () => agent(`${SCOPE}

You are REFUTING a review finding. Default to refuted=true unless you confirm it by reading the code.

LENS: OPERATIONAL CONSEQUENCE. Assume the mechanism is real. Does it actually reach an OPERATOR-VISIBLE bad
outcome — a gateway that stays down, an identity lost, a wrong diagnosis acted on, a data-plane effect? Work out
what must be true for it to fire (a specific crash point? a hostile server? a race window measured in
microseconds?), how likely that is in the shipped topology, and whether the agent self-heals on the next tick or
the next boot. A defect that heals unattended on the next reconcile is NOT the finding it claims to be — say so.
Also state whether an EXISTING test would have caught it, naming the test.

FINDING
title: ${f.title}
file: ${f.file}:${f.line}
sequence: ${f.failure_sequence}`,
          { label: `v:oper:${f.title.slice(0, 26)}`, phase: 'Verify', schema: VERDICT_SCHEMA }),
      ]).then((vs) => {
        const votes = (vs || []).filter(Boolean)
        const refuted = votes.filter((v) => v.refuted).length
        return { ...f, finder: r.key, survived: votes.length > 0 && refuted < votes.length,
                 unanimous: votes.length > 0 && refuted === 0, verdicts: votes }
      })
    )).then((v) => ({ key: r.key, verified: (v || []).filter(Boolean) }))
  }
)

const all = perFinder.filter(Boolean).flatMap((r) => r.verified || [])
const survivors = all.filter((f) => f.survived)
log(`${all.length} verified; ${survivors.length} survived (${all.filter(f => f.unanimous).length} unanimous).`)

phase('Critic')

const critic = await agent(`${SCOPE}

You are the COMPLETENESS CRITIC for this pass. Seven angles ran: decided-once loop inputs, comments-as-claims,
the on-disk credential state machine, error mapping and backoff, Decide's precedence truth table, what the agent
accepts from the wire unvalidated, and goroutine lifecycle.

SURVIVED verification:
${JSON.stringify(survivors.map((f) => ({ title: f.title, file: f.file, line: f.line, severity: f.severity })), null, 2)}

REFUTED (do not resurrect without new evidence):
${JSON.stringify(all.filter((f) => !f.survived).map((f) => ({ title: f.title, why: (f.verdicts[0] || {}).reasoning })), null, 2)}

YOUR JOB: name what this pass could NOT have found, then go find the most important one or two.
Consider: a property of the recovery STORY that no single file owns; an interaction between two angles neither
owned; the agent and control plane disagreeing about the protocol with no test spanning both (they are separate
Go modules that cannot import each other); a test in apps/node whose expectation is derived from the artifact
under test (ask "could this check have failed?" of every new test in cmd/agent/main_test.go and
internal/control/rekey_test.go); and the sequence an operator ACTUALLY performs during an outage, end to end,
which no test covers because each step is tested alone.

Report real defects in the same schema. Empty list if none — do not pad.`,
  { phase: 'Critic', schema: FINDING_SCHEMA })

const criticFindings = ((critic && critic.findings) || []).map((f) => ({ ...f, finder: 'critic', survived: true, unanimous: false, verdicts: [] }))

phase('Synthesize')

const final = await agent(`Write the final report for EPIC 13 review pass 3 (the agent recovery loop).

SURVIVING FINDINGS (two adversarial lenses each):
${JSON.stringify(survivors, null, 2)}

COMPLETENESS-CRITIC FINDINGS (unverified — mark them):
${JSON.stringify(criticFindings, null, 2)}

One ranked list, most severe first. MERGE duplicates that are the same root defect found by different angles and
say so — several findings sharing one root is the most useful thing a review can report. Keep each failing
sequence intact; do not soften it into a suggestion. Also return the shared roots, and for each root say which
finding numbers belong to it.

Return JSON only.`,
  { phase: 'Synthesize', schema: {
    type: 'object', additionalProperties: false, required: ['ranked', 'roots'],
    properties: {
      ranked: { type: 'array', items: {
        type: 'object', additionalProperties: false,
        required: ['title', 'file', 'line', 'severity', 'failure_sequence', 'why_it_matters', 'confidence'],
        properties: {
          title: { type: 'string' }, file: { type: 'string' }, line: { type: 'integer' },
          severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] },
          category: { type: 'string' }, failure_sequence: { type: 'string' },
          why_it_matters: { type: 'string' }, suggested_direction: { type: 'string' },
          confidence: { type: 'string', enum: ['both-lenses-agreed', 'one-lens', 'critic-unverified'] },
        } } },
      roots: { type: 'array', items: { type: 'string' } },
    } } })

return { ranked: (final && final.ranked) || [], roots: (final && final.roots) || [],
         counts: { raised: all.length, survived: survivors.length, critic: criticFindings.length } }
