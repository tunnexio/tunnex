# Tunnex engineering laws (central registry)

Laws minted across stories, previously scattered in `docs/S*-decisions.md`. New laws land here; existing ones get lifted over time. A law is a rule the review probes for and the build must not regress.

# ⭐ A CORRECT CAVEAT DOES NOT MAKE AN INADEQUATE CHECK ADEQUATE. IT ONLY MAKES THE INADEQUACY HONEST.

**(2026-08-01, S14.4 — the sharpest finding of the day, and it leads this file for that reason.)**

**THE FOUNDER COMMISSIONED A CHECK FOR A SPECIFIC QUESTION:** a shared `Card` primitive had changed, twelve
screens consume it, *"is any of them now visibly broken — overlapping, unreadable, or losing content?"*

**THE CHECK WAS RUN.** Nine screens rendered through their existing wiring tests with content asserted; the
other three got a smoke mount. **It reported "nothing is broken", and it carried an accurate caveat:**

> *"This gates crashes and content loss. It CANNOT see overlap, truncation or unreadable contrast, because
> jsdom has no layout engine."*

**AND `backdrop-filter` HAD ALREADY BROKEN FIVE MODALS ACROSS FOUR SCREENS** — by making `Card` the containing
block for `position: fixed`, so every nested overlay was clipped to the card with the card's own body over its
buttons. **Playwright found it. The commissioned check could not have.**

## THE HEDGE IS NOT THE FAILURE

**The caveat was correct, specific, and written into the test file itself.** It named the exact limitation that
mattered. **Both the author and the founder read the hedged green as reassurance anyway** — because a green
result answers *some* question, and under time pressure the question it answers silently becomes the question
that was asked.

> **THE FAILURE IS TREATING THE CHECK AS AN ANSWER TO THE QUESTION IT WAS COMMISSIONED FOR, WHEN ITS OWN
> CAVEAT SAYS IT IS NOT.**

**SO THE RULE HAS A PROCEDURAL HALF: WHEN A CHECK CANNOT ANSWER THE QUESTION IT WAS ASKED, THE REPORT LEADS
WITH THAT — NOT WITH THE RESULT.** *"I cannot answer this; here is what I could measure"* is a different
message from *"nothing is broken (caveat)"*, and only the first survives being skimmed.


## ZERO-TOUCH GATEWAY LAW (founder-ratified 2026-07-18) — S8.2c acceptance bar
**A gateway is brought online by pasting the ONE install command the dashboard emits — and nothing else.** Sites, subnets, enforcing mode, the site→site grant, and a genuinely-separate host *behind* the gateway reaching a far site are ALL achieved by clicking in the dashboard — never by SSH'ing the gateway to add networking. **Any manual networking step on the gateway is a DEFECT, not a runbook line:** no hand-added `--network host`, no `TUNNEX_WG_BACKEND` flag, no `src`-hint on a route, no forward rule, no `ip route` edit. The cross-cloud demo (`walk-artifacts/cross-cloud-demo/`) re-runs clean under this bar — fresh org, two cloud VMs, the only terminal action a pasted join command — and THAT re-run is S8.2c's box-walk.
**BOUNDARY CLAUSE (S8.2c D3):** the law's boundary is the **gateway VM itself** — zero SSH to the gateway after join stands. The **cloud console gets ONE named, guided visit per side** (Azure UDR, AWS route-table + src/dst-check) — un-codeable fabric routing that the site/subnet UI SURFACES as detected/declared, copy-paste snippets + doc links. Guided ≠ manual-gateway-touch; the boundary holds.

## Fixture-fidelity law — TOPOLOGY SIBLING (minted 2026-07-18, cross-cloud demo)
**A site-to-site fixture MUST include a genuinely separate, FORWARDED host behind the gateway — not an interface inside the gateway's own netns.** S8.2's walk used dummy LANs *inside* the gateway container (`10.1.0.1` on a dummy interface); that traffic was **locally-originated, never forwarded**, so the forward chain's LAN→tunnel asymmetry (finding #5) was **invisible** — it survived a full box-walk. Locally-originated ≠ forwarded. A fixture that only originates locally cannot exercise the forward path; the first genuinely-separate behind-gateway host (the CP in the cross-cloud demo) exposed the gap immediately. (Sibling of the [[fixture-fidelity law]]: a test double must not out-capability the substrate; here, a test topology must not under-exercise the path.)

## REPORTED ≢ STORED law — FIXTURE-FIDELITY FAMILY (minted 2026-07-19, S8.5 Slice 5)
**A ruling that assumes plumbing exists must cite the WRITE PATH, not the wire.** S8.5's L1 ruling said "existing plumbing extended, not new telemetry" — true of the *wire* (the agent reports every peer's bytes/handshake) but FALSE of *storage*: `UpsertDeviceStatus` maps a peer pubkey to the active DEVICE on the node, so a site-link peer's pubkey (a remote GATEWAY's wg key, no device row) is a silent no-op — reported, never stored. The verify-before-build instinct (trace the upsert, not the report) caught it at ruling-premise depth; the halt-and-surface followed. Data that crosses the wire is not data at rest — before building on "the CP already has X," find the SELECT that reads X back out, or the column that holds it. (Sibling of the [[fixture-fidelity law]] and [[reported ≢ stored law]] itself: the map is not the territory — a report is not a row.)

## ONE-TRUTH law (lifted to registry 2026-07-18, S8.2c) — a consumer never re-derives a fact its authority already owns
**React-tier corollary (S8.5 Slice 5):** two components each holding a copy of one server list is the one-truth violation in UI form — a mutation in one leaves the other's copy (and everything derived from it, e.g. a button's enabled state) stale. Fix by INVALIDATING the copy (a parent-owned revision signal the mutator bumps and the reader re-loads on) or LIFTING the state — never by patching the stale-fed symptom, which leaves every other consumer of the copy still stale.
**When the control plane owns a fact authoritatively, every other layer CONSUMES it — never computes a second, independent derivation.** A second derivation agrees in the easy case and quietly diverges in exactly the hard cases the feature exists to make safe. Confirmed instances (each a review probe; a new derivation of an owned fact is a finding):
1. **Backend site-hub election** (S8.3) — the web reads the backend-elected `is_site_hub` (`electSiteHub`), never re-elects in TS.
2. **`meta.protocol_version` ceiling** (S8.3) — the CW-confirm reads the server's version ceiling, no TS hardcode.
3. **D2 `LocalSubnets`** (S8.2c) — the agent uses the CP-sent subnet for its route src-hint; it does NOT guess its own site address (egress probe / interface heuristic diverges on-prem WAN≠LAN / multi-homed).
4. **`meta.public_base_url`** (S8.2c, instance #5 of the pattern) — the gateway-enroll command derives the CP's REST/agent URLs from the CP's OWN configured public base URL, NOT `window.location`: the browser URL is whatever alias/tunnel/bare-IP the admin opened, which would bake an unreachable endpoint into the pasted zero-touch command. (Numbered #5 in the running tally though listed 4th here — instance #4 was the S8.1 D2-topology backend-hub overrule, folded into row 1's lineage.)

## SHARED-TERRITORY OWNERSHIP law (founder-ratified 2026-07-19, S8.4) — mark, touch-only-own, refuse-on-collision, AND sweep on every exit
**When the agent (or helper) writes into shared system territory it does not exclusively own — kernel routes, another daemon's firewall chain, the OS resolver directory — it MARKS what it owns, TOUCHES ONLY what it marked, and REFUSES on a collision with a foreign entry rather than clobbering it. AND ownership includes CLEANUP on every exit — graceful, crash, and next-start: a discipline that marks and refuses but cannot sweep its own residue after an unclean exit is HALF a discipline.** A stranded owned entry after a crash is as much an ownership failure as clobbering a foreign one. Confirmed instances (each a review probe; writing into shared territory without the mark/own/refuse/sweep quartet is a finding):
1. **Foreign routes logged** (S3.7/egress) — the agent's route reconcile logs, never blindly deletes, a route it didn't install.
2. **DOCKER-USER chain comment-marked** (S8.2c WF-4) — the agent's forward-accept rules carry a `tunnex-site-fwd` comment; the full-sweep keys on that marker, so a foreign rule in Docker's chain is never removed.
3. **`/etc/resolver` owned-marker + refuse-on-collision** (S8.4) — resolver files carry a `# tunnex-managed` first line; a desired domain colliding with a foreign resolver file is REFUSED (`resolver_domain_conflict`), never overwritten.
4. **Resolver sweep — startup ONLY in S8.4; crash/owner-loss sweep DEFERRED to S8.4b/S8.5** (the F6 → rider → removal arc, terminal form). S8.4 keeps ONLY `CleanStaleResolvers` at helper startup (race-free, `SelfHeal`-precedented). The crash/owner-loss sweep was attempted twice — an eager per-exit sweep (diverged from the kill-switch grace, raced a reconnect) and a release-rider parasitic on the kill-switch (moved FS I/O under the Supervisor lock, left a StateDown persistence gap, added an unsynchronized callback) — **three defect rounds in one component before the terminal move: REMOVE it.** The machinery was dormant — the client resolver path is inert until S8.5 (no resolver files are installed in S8.4), so there was never any crash residue to sweep. It is deferred to S8.4b/S8.5 where it is exercisable, red-able, and walk-provable, with a NAMED ORDERING PRECONDITION: the sweep must land BEFORE the client resolver path activates. **DORMANT-MACHINERY ADDENDUM (the arc's one-sentence law):** build lifecycle machinery only for code paths that are LIVE in the story that builds them — dormant machinery cannot be walk-proven, and unproven lifecycle code is where defect clusters breed (instances: Windows NRPT staging, the resolver release-rider; the S8.2-#5 forward-chain gap as the original demonstration). A sweep that is a *decision-maker* is the smell; a sweep that *rides a decision* is better; a sweep built for code that isn't live yet is the disease.

## DORMANT-MACHINERY — INSTANCE 2 (EPIC 13, WF-S13-6, founder-ruled 2026-07-31): the epic that minted the law shipped a case of it

**S8.4 minted the law; EPIC 13 is its second instance, and a more dangerous shape.** In S8.4 the dormant code was
a *sweep* for residue that could not exist yet. Here the dormant code is **the feature itself** — gateway
recovery — in the case the epic was opened to fix.

**The caller/trigger analysis, stated the way the law now requires:**

| | |
|---|---|
| **the machinery** | `attemptRekey` — proof-of-possession recovery |
| **its only caller** | `main()`, `apps/node/cmd/agent/main.go:77`, via `identity.Decide` on credentials read at boot |
| **the trigger it must serve** | a certificate expiring at **runtime**, under a process that is already up |
| **can caller and trigger co-occur?** | **NO.** `main()` runs once, before the trigger exists. Nothing re-enters it |

Recovery is therefore **reachable only by restarting the process** — and the epic's headline claim is that a
gateway comes back *by itself*.

**The epic WROTE THE BUG DOWN AS A SAFETY PROPERTY.** `docs/S13.1-decisions.md:1277`, from Batch B:

> *"There is no path from the in-loop clock check to starting a recovery, so a clock that jumps the other way
> cannot…"*

That sentence is **correct about NTP** — a backward clock jump must not trigger a recovery — and it is **also an
exact description of the defect**. The same absent edge that makes a clock jump safe makes runtime expiry
unrecoverable. It was reasoned about, written down, and shipped, because it was only ever examined from the
direction where it is a virtue.

**What this adds to the law:** when you record that *no path exists* from X to Y as a safety property, **state
what else that missing path was carrying.** An absent edge is a guarantee in one direction and a gap in the
other, and the note that proves the guarantee is the natural place to notice the gap. See also
`tunnex-unit-tests-prove-behaviour-not-reachability` — name the trigger, then check the caller can co-occur with
it.

## THE VACUITY DETECTOR (founder-ratified 2026-08-01) — read this BEFORE the five mechanisms below

**WHEN A CHECK REPORTS THE SAME VALUE FOR EVERY INPUT, VERIFY ONE INPUT INDEPENDENTLY.** A check that cannot
distinguish its cases reports agreement — and agreement reads as success.

The five mechanisms below name distinct ways a green result can mean nothing. **This is the PROCEDURE that
catches all five**, and it is cheaper than diagnosing which one you are in:

- a **half-fold** — every row reports "closed"
- a **tautological guard** — every input satisfies the assertion
- a **fixture that restates production** — every run agrees with itself
- **true-by-structure** — every mutation of the fix leaves it green
- **absence-means-permit** — every unset value reads as allowed

**How to apply it, in one line: name a case whose answer you already know by other means, and check the check
against that case.** If the check cannot tell that case apart from the others, it is measuring nothing.

**TWO INSTANCES ON ONE DAY, both inside an audit that existed to detect vacuity:**

1. **`git show` failing into `2>/dev/null`** so `grep -c` counted an empty stream. It returned `0` for every
   commit — **including one whose true value was independently known to be `1`.** The uniform result across a
   case with a different real answer was the entire tell; the tally itself looked like a clean audit.
2. **zsh's `:a` history modifier ate a path** — `"$c:apps/..."` expands to `${c:a}` + `"pps/..."`. Caught ONLY by
   a deliberate **injected-duplicate probe**: feed the check a case that must produce a different answer and
   require it to. The probe proved the counting method sound while the path construction was broken.

3. **`ok … [no tests to run]`** — a green with NOTHING EXECUTED, byte-indistinguishable in a scrollback from a
   green with everything passing. Produced by running a `//go:build enterprise` test file without the tag.

**CAN A GATE PRODUCE THAT SHAPE? Checked, and the answer is a qualified YES — which makes it a gate hole, not
just a local footgun.**

- If **every** file in a package is excluded by a build tag, `go test` reports **`FAIL … [setup failed]`**. Loud,
  and safe.
- But if **some** files are excluded and others are not, the package runs the survivors and prints **`ok`**. The
  excluded tests are invisible, and nothing in the output distinguishes "these tests passed" from "these tests
  were never compiled."

**Live instance in this repo:** `apps/api/internal/devices/restore.go` is **untagged** — it ships in BOTH
editions — while its only test file, `restore_integration_test.go`, is `//go:build enterprise`. So
`make test-editions`' open pass compiles the restore path, tests none of it, and reports `ok` for the package.
Registered as a finding in `docs/S13.1-pass3-triage.md`.

**Instance 2 is the form to copy.** Do not merely inspect a check; **feed it a case it must fail on.** A check
that has never once produced a different answer has not been shown to be capable of one.

## TRUE-BY-STRUCTURE — the FOURTH way a green check means nothing (EPIC 13, 2026-08-01)

**The assertion is guaranteed by code the fix never touched, so no mutation of the fix can break it.** The red is
about a real property, the property genuinely holds, and the test says nothing whatever about the change it was
written for.

**Four mechanisms now, and they are distinct:**

| mechanism | what fails |
|---|---|
| **half-fold** | the remedy addresses the defect's NEIGHBOURHOOD, not the defect |
| **tautological guard** | the expectation DERIVES from the artifact under test |
| **fixture restates production** | the DOUBLE stands in for the thing being tested |
| **TRUE-BY-STRUCTURE** | the assertion is held up by code the fix never touched |

**THE DIAGNOSTIC: if you cannot describe an INPUT that would make the assertion false, it is not a test of the
fix.** Not "can I imagine the code being wrong" — name the input. If the only way to falsify the assertion is to
edit a different function than the one under test, the red belongs to that other function, or to nothing.

**THE INSTANCE.** A red asserted that sustained throttling never reaches the join token. It PASSED with
`refusals++` injected directly into the throttle branch — because the exhaustion check lives inside the
`ErrRekeyRefused` case and the throttle branch returns before reaching it. **A throttle cannot spend the token
regardless of any fix**, so the assertion was unfalsifiable by construction.

**THE PROCEDURAL CAUSE, AND THE RULE IT MAKES: ONE MUTATION AT A TIME. Not a preference — the rule.** This
surfaced only because the two mutations were run SEPARATELY. Combined, the package would have shown ONE `FAIL`
and one failing test name, and that reads as success for both reds — the passing one hidden behind the failing
one. A combined mutation run can prove *at least one* red works; it can never prove that each does.

### FIFTH MECHANISM — SAMPLED-SLOWER-THAN-THE-EVENT (EPIC 13 box-walk, 2026-08-01)

**The observation window is coarser than the state it observes, so the check reports the steady state and
never the transition.** The property may well hold; the check could not have seen it either way.

| mechanism | what fails |
|---|---|
| **SAMPLED-SLOWER-THAN-THE-EVENT** | the observer's interval exceeds the state's lifetime |

**THE INSTANCE.** §B's B2 asserts that `nodes.cert_delivered` flips `f` → `t` across a re-key. The walk polled
it **twelve times at ~7-second intervals and read `t` every time**, including 3 seconds after the recovery. The
window is bounded by the code: `RekeyNode` clears the marker in the same statement that rotates the serial
(`nodes.sql:319-326`), and `nodes.sql:49` sets it back on the agent's first authenticated call — here
`06:22:17.246` → `06:22:19.262`, **about two seconds.** A 7-second poll against a 2-second window **cannot
fail.** Twelve green samples, zero information.

**It passes the TRUE-BY-STRUCTURE diagnostic and fails anyway**, which is why it is a separate mechanism: an
input that falsifies the assertion is easy to name (a re-key that never re-delivers). The defect is not in the
assertion — **it is in the sampling rate**, and no amount of reasoning about the assertion surfaces it.

**THE DIAGNOSTIC: state the event's LIFETIME and the observer's INTERVAL as two numbers, and compare them.** If
the interval is not comfortably smaller than the lifetime, the check is decorative. For a transition bounded by
two code paths, read the lifetime out of the code rather than estimating it.

**Recorded as NOT OBSERVED, never as passed.** The distinction is the whole point: a walk that logs "B2 green"
on twelve blind samples has manufactured evidence.

### SIXTH MECHANISM — ASSERTS-A-DIFFERENT-EVENT-THAN-IT-WAITS-ON (EPIC 13, 2026-08-01). THE MIRROR OF THE OTHER FIVE.

**The check waits for event A and asserts property B, where B happens strictly after A and nothing synchronises
them. It fails for a reason unrelated to its subject.**

| mechanism | what fails |
|---|---|
| **ASSERTS-A-DIFFERENT-EVENT-THAN-IT-WAITS-ON** | the wait and the assertion are about different moments |

**THIS ONE INVERTS THE FAMILY.** The other five all answer *"could this check have failed for the RIGHT
reason?"* — they are green when they should be silent. This one is the mirror: it goes **red for the WRONG
reason.** And the consequence is symmetric, which is the part worth internalising: **a check that can fail
spuriously is exactly as uninformative as one that cannot fail at all.** In both cases the colour carries no
information about the subject.

**THE INSTANCE.** `TestExpiryWhileRUNNINGRecoversWithoutARestart` — `identityWatchLoop`'s acceptance red, and
EPIC 13's **first merge precondition**. It waited on `issued`, a counter incremented inside the fake control
plane's HANDLER (*"the CP produced a response"*), then called `cancel()`, then asserted the AGENT'S DISK
(*"the recovery was promoted"*). The disk write happens strictly after the response. A fast machine won the
race; a contended CI runner lost it — and did, on the very first CI run this branch ever received.

**WHY IT MATTERS MORE ON A GATE.** On merge day a red here is indistinguishable from a real regression, and a
green proves only that the runner was fast. **A flaky acceptance test cannot carry a merge precondition** — it
converts the gate into a coin toss whose outcome gets argued about rather than trusted.

**THE DIAGNOSTIC: name the event the test WAITS for and the property it ASSERTS, in that order, and check they
are the same moment.** If the assertion is downstream of the wait, the test is racing its own subject. **The fix
is never "wait longer" — it is to wait for the asserted property itself.**

**PROVEN BY TWO MUTATIONS, because "wait longer" and "wait for the right thing" are indistinguishable from a
single green:**

| mutation | expected | observed |
|---|---|---|
| promotion silently skipped (`saveCredsFn` → no-op returning nil) | FAIL | **FAIL at 15.11s**, `issued=749`, disk still expired |
| write delayed 3s then genuine | PASS | **PASS at 3.18s** |

The first proves the longer wait still bites on a real non-recovery; the second is the case the old wait lost.
**One mutation would have proven neither.**

## THE TOOLS WRITTEN TO CATCH VACUITY WERE THEMSELVES VACUOUS — TWICE, IN ONE DAY, SILENTLY (2026-08-01)

**A SCRIPT'S OWN EXECUTION IS AN UNCHECKED ASSUMPTION.** A tool that has only ever been INVOKED cannot be
distinguished from one that WORKS. Both "ran"; only one did anything.

**Two instances, and the second was introduced by the fix for the first:**

1. **`mutate.sh` printed `Restoring.` and did not restore** (`3c9c16f`). Every run left the mutated file in the
   tree while announcing a restoration it had not performed. *The tool built to prevent false claims was making
   one about itself.*
2. **The fix for (1) added a DIRTY-FILE REFUSAL that referenced `$file` above the line assigning it.** Under
   `set -euo pipefail` that is an unbound-variable abort, so the script **exited before any work, on every
   invocation, from the moment the safety feature landed** — and the same block was copy-pasted into
   `prove-fix.sh`, killing both. Neither announced it; the caller saw a non-zero exit indistinguishable from a
   tool that ran and disagreed.

**NEITHER FAILURE ANNOUNCED ITSELF, and that is the whole pattern.** A vacuous CHECK is green when it should be
silent; a vacuous TOOL is silent when it should be either. Both are read as "we verified this."

**THE GUARD THIS EARNED — `scripts/toolselftest.sh`, wired as `--self-test` on both scripts.** Each tool is run
against a **known-good** and a **known-bad** case and the verdict is asserted:

| tool | known-good | known-bad |
|---|---|---|
| `mutate.sh` | a red that goes RED under the mutation → accepted | a test passing regardless of the mutation → refused · a non-matching anchor → refused |
| `prove-fix.sh` | red fails before the edit, passes after → accepted | an ALREADY-GREEN red → refused |
| both | the target is byte-restored afterwards | |

**The self-test caught its own author on the first run** — the initial `mutate.sh` known-good asserted the
MUTATED token, which passes under the mutation, and the tool correctly refused it. That is the argument for
having one in the sentence.

**WHAT IS AND IS NOT INVALIDATED, stated plainly.** Mutations run after `3c9c16f` were performed **by hand** —
which is how they were performed before the script existed. **So no mutation proof is void. But none was
protected either**, and the difference matters only in what can be claimed: those proofs rest on the operator
having done the three assertions manually, not on a tool having enforced them.

**RULE: a tool that enforces a verification discipline must itself be verified against a case whose answer is
known in advance, and that self-test must be runnable in one command.**

## ANY CHANGE TO GENERATED CODE OR A SHARED TYPE RUNS THE FULL GATE SET, NEVER A SUBSET (2026-08-01)

**THE INSTANCE.** Adding `x-go-name: RestoreDevicesResult` renamed a generated type. `make generate-check` and
`make test-node` were run and treated as sufficient; **`make build-editions` and `make test-editions` were
skipped.** `apps/api/internal/http/node_handlers.go:156` still constructed the old name, so `apps/api` stopped
compiling and CI went red across `gates`, `e2e`, `e2e-enterprise`, `govulncheck(apps/api)`, `gofmt + vet parity`
and the Trivy image build — **while the fix's own target, `govulncheck(apps/cli)`, went green.**

**A rename is the change whose blast radius a single-package check cannot see, by definition.** The gate that
would have caught it existed and was listed in CLAUDE.md; running a subset was a choice, not an oversight in the
tooling.

**THE RULE: generated code, shared types, and anything crossing a module boundary run the FULL gate set.** For
this repo that is `generate-check` · `migrate` · `test-editions` · `build-editions` · `test-node` ·
`test-helper` · `helper-crosscompile` · the web trio. Not the two that seem related.

**AND THE STRUCTURAL FIX IS THE SAME ONE WF-S13-11 REGISTERED:** CI on story branches makes this impossible to
get wrong, because the full set runs whether or not the author remembered it. Every argument for that change
gained an instance here.

## DOES THE REMEDY ADDRESS THE DEFECT, OR ITS NEIGHBOURHOOD? (founder-ratified 2026-08-01, EPIC 13, three instances in one epic)

**A fold is not closed because an edit landed near the defect. Ask of every remedy: does this make the NAMED
DEFECT impossible — or does it fix something ADJACENT to it?** Adjacent fixes are made in good faith, pass their
reds, survive marker sweeps, and read as complete.

**An earlier version of this law said multi-claim fold rows were the risky shape. That was wrong** — it was
inferred from two instances and refuted by the third. **Claim count is a SYMPTOM, not the mechanism.**

| instance | the defect | what the remedy did instead | claims in the row |
|---|---|---|---|
| claims 2/4/13/20 | nothing ENTERS the recovery loop at runtime | re-read the premise **inside** the loop — correct for 4/13/20, silent on 2 | 4 |
| claims 9/10/14 | the throttled branch has no exit or escalation | honoured `Retry-After` — the interval, not the exit | 3 |
| **#11** | an interrupted promotion leaves a mismatched pair | made the seam **injectable** and the failure **survivable** — the pair itself neither prevented nor detected | **1** |
| (Batch A, found earlier by this same question) | re-key must refuse a node the CP cannot verify is GONE | authorized any caller **proving the current key** — a live-node takeover | 1 |

**Two of four are single-claim rows.** The mechanism is that a defect has a NEIGHBOURHOOD — its consequences, its
testability, its survivability, its adjacent parameters — and every one of those is a satisfying thing to fix.
The fix is real, the red passes, the row gets ticked, and the defect is untouched.

**What binds now:** state the remedy as a sentence that makes the defect impossible, and check that sentence
against the defect's own words. *"The premise is re-read each pass"* does not contain *"something enters the
loop."* *"The seam is injectable"* does not contain *"the pair matches."* If the remedy's sentence and the
defect's sentence are about different subjects, the fold is open however good the code is.

**The corollary that cost this epic three instances:** a marker sweep asks *did the edit land?* — a question all
three passed. It cannot ask this one. **Sweeps verify presence; only reading the defect beside the remedy
verifies closure.**

## ONE-TRUTH — 6th instance (EPIC 13, 2026-08-01): TWO CLIENTS, ONE SERVER TRUTH, NEITHER CONSUMING IT

**The server computes the correct predicate. Both clients independently reimplement a WRONG one and neither
consumes the server's.** This is not a UI gap and the fix is not a dropdown.

| layer | the predicate |
|---|---|
| **API — the truth** | a gateway is usable iff `endpoint != "" && wg_public_key != ""` (`devices/service.go:72`), enforced with `409 node_not_ready`. `Create` accepts `in.NodeID`, so choosing has ALWAYS been supported |
| **web** | `nodepick.ts:30` — `selectableNodes(nodes)[0]`, filtering on `status == "active"` |
| **CLI** | `device.go:43-52` — iterate, take the first `status == "active"`, `break`. **No flag exposes the choice** |

**Two independent reimplementations of the same wrong test.** `status='active'` is a liveness claim; usability is
`endpoint AND key`. A gateway can be active and unusable — `azure-gw` was, for six days — and both clients
routed every device creation to it, producing `node_not_ready`, an error naming the OPERATOR'S agent
configuration for a defect in client selection.

**THE FIX IS TO EXPOSE THE API'S PREDICATE AND CONSUME IT**, not to add a picker to one surface. A picker over the
same wrong list still offers a dead gateway; consuming the server's predicate fixes both clients and the default.

**WHY NO TEST ON EITHER SIDE COULD CATCH IT.** Each client is INTERNALLY CONSISTENT — the web's tests pass against
the web's rule, the CLI's against the CLI's, and the server's against the server's. **The defect exists only in
the relationship between them**, which is precisely what a duplication hides. Note the surface: `apps/cli` had NO
CI job at all until S11 slice 1, and this is that same surface producing a second defect — but **this one is not
a coverage gap.** More tests on either client would have confirmed the wrong rule faster.

**Generalised:** when a server enforces a predicate and clients must anticipate it, the predicate is a SHARED
TRUTH and belongs in the contract (a field, or the generated types), never re-derived per client. Two
re-derivations agreeing by luck is not a property; two re-derivations agreeing WRONGLY is what shipped.

## Prior laws (lifted from decision docs — pointers)
- **Fixture-fidelity law** (S8.2): a test double must not be more capable than the real substrate (the fake stripped `SiteLink` on read). Contrapositive (S8.3): when the kernel genuinely reports a field, PARSE and COMPARE it (keepalive), so convergence is real not fixtured.
- **Four-word reconcile model** (S8.2): {atomic fetch, fail-static, full-sweep, keep-last-value} — any deviation is a finding.
- **DesiredState-atomic law** (S8.2): a multi-section artifact assembly error fails the WHOLE fetch; the agent holds last-good.
- **Swallowed-audit law** (S8.1): an in-tx `InsertAuditLog` error must PROPAGATE (return), else a mystery commit-rollback.
- **Validator-input-filtering law** (S8.1): never filter the disjointness validator's comparison set to exempt a collision; its value is that it can't be bypassed. **UI corollary** (S8.3): no client-side re-check — one validator, never a second copy in JS.
- **Reassuring-comment law / reassuring-empty law** (S7.x/S8.3): a load failure must never render as a reassuring empty/healthy state; the loudest line on a page must never lie in the reassuring direction (`rulesSummary` failed-state).
- **Render-floor law** (S8.3): render only wire-truth (no decorative telemetry); applies to DERIVED truth too — the UI reads the backend-elected hub, never re-elects (`electSiteHub` one-election).
- **Unlock-then-opt-in** (founder): enterprise features unlock a capability; they never turn enforcement on.

## GATE-REPORT-NEEDS-SHA law (founder-ratified 2026-07-20, S8.6 protocol finding) — a gate report describes committed, pushed state; the sha is in the report, or it is a plan not a gate
**A gate report (build/test/review "passed", "walk-ready", "green") describes COMMITTED, PUSHED state. It leads with the commit sha the gate ran against, or it is a PLAN — a description of intended work — not a gate. A reader accepting a gate demands the sha as a HARD FIELD; a sha-less gate report is void on its face.** The failure this closes: a review disposition, a "walk-ready close", or a slice "accept" can be produced for work that was PAPERED but never built — the report reads identically to a real gate. This stayed invisible precisely because MOST reports already led with a sha (`bb844f6`, `2df19df`, …); the ones that lacked one read the same as the ones that had one, so a paper-only "S8.6 walk-ready" and a real "S8.6 reduce gated (`6d94b79`)" were indistinguishable in prose. The producer side: every gate report leads with its sha. The acceptor side: no gate is passed until the sha is shown and the commit is real (`git log` confirms it, not a summary). Rulings (design dispositions — warn-not-refuse, an approach chosen) STAND independently of code; a GATE (state proven) does not exist without the commit. Confirmed instance: the S8.6 reduce — dispositioned + papered (`fba643c`, `440be19`) and accepted as "walk-ready close" while the #1 enterprise-enforcing cross-site blackhole was live in-branch and the reduce unbuilt; corrected by building + gating it with shas (`6d94b79`/`1bf1e47`/`599409e`), and by voiding every sha-less acceptance in the S8.6/S8.7 train.

## WRITER-OWNERSHIP law — CLAUSE (S8.6 re-review, 2026-07-20): two writers to one field are legal iff both write the SAME pure derivation
The writer-ownership law (a persisted authority with multiple writers must PARTITION its fields by writer) gains a bounded exception: **two writers MAY write the same field iff both write the output of the SAME pure function of the same inputs — convergent by construction, so a race resolves to the same value and the next pass re-derives it.** S8.6 instance: after the failover-tick corrector reduce, BOTH `ReconcileHubSet` (on a bind/unbind/pin/revoke event) and the failover tick write `org_hub_set.configured`, each = `electSiteHubSet`'s output. Legal — a racing stale write self-heals the next tick; the per-field atomic `IS DISTINCT FROM` generation bump stays monotonic. This is NOT a license for two writers with two different derivations (the original clobber class); the guard is *same pure function, same inputs*. The demoted field stays single-writer (the controller); the partition holds where the derivations differ.

## KILL-SWITCH-NO-UNBOUNDED-I/O law (founder-ratified 2026-07-23, WF-A slice-3 review finding #1) — the fail-closed enforcement path must never queue behind latency an attacker or a bad network can set
**No network call, no filesystem stall, nothing whose latency is not locally bounded, may hold a lock that the fail-closed (kill-switch) enforcement path needs to acquire.** The failure this closes: the helper's `SetGatewayPeer` resolved a re-home endpoint (a DNS lookup) *while holding `b.mu`* — the same mutex the dead-man's `FailClosed` takes via the Supervisor. A slow/timing-out resolve would then delay kill-switch enforcement, and it does so during a FAILOVER — precisely the moment a device re-homes AND precisely the moment the kill-switch matters most. Fix (trivial): resolve BEFORE taking the lock; the lock guards only local state mutation. This is the **RR2 lesson** (bounded route syscalls / FS I/O must run OUTSIDE the Supervisor lock — S8.5 crash-sweep) recurring at the DNS tier: same law, new I/O class. Stating it as a rule means the next helper feature that adds a privileged verb meets it at design time, not at review. **REGISTERED companion:** `darwinBackend.Up` / `windowsBackend.Up` resolve the WG endpoint (and now the CP endpoint) under `b.mu` too — the same stall applies, but on a path WF-A did not create; TRIGGER to fix = *the next helper session touching Up's endpoint-resolve path* (out of WF-A scope, not a silent drop).

## NEVER-TRIAGE-FROM-A-TRUNCATED-READ probe (founder-ratified 2026-07-29, EPIC 11 slice 1) — cite the complete output, or state that it is partial

Reading a FRAGMENT and reporting it as the WHOLE. Three instances, all self-caught, all in the same fortnight:

1. **S10.2 merge-time e2e claim.** The e2e job failed in 2m22s on the first run and again later; the DURATION
   matched, so it was reported as "the same pre-existing failure" — without reading the log. It was neither
   pre-existing nor the same: it was a regression that S10.2 itself introduced. A signal that RESEMBLES a
   known state is not evidence of that state.
2. **The S11 govulncheck triage.** CI logs were grepped with `head -8`, which cut the output after the first
   vulnerability per module. "One dependency, two modules" was reported; the complete scan showed **five**
   vulnerabilities across chi, pgx and x/net — three core-dependency bumps that had been invisible.
3. **The gofmt count** (caught before it mattered): an UNPINNED host toolchain flagged ~120 files; the pinned
   one flagged 31. Reporting the first number would have described a defect that did not exist.

**THE PROBE:** never triage from a truncated read. Cite the COMPLETE output, or state explicitly that the read
is partial and what was cut. `head`, `tail`, `grep -m`, and a scrolled terminal all truncate — and a truncated
read of a scanner, a log, or a test run yields a confident, specific, wrong conclusion. The corollary, from
instance 1: **an attribution to a pre-existing cause must cite a GREEN RUN AT A SPECIFIC SHA**, not a
resemblance. (Companion to the census law, which says the same thing about artifacts: only reading it proves
it.)

## CENSUS-THE-MIRROR-SURFACE law (founder-ratified 2026-07-29, S11-6) — on a guard-not-mirrored finding, measure the surface before fixing the instance

**GUARD-NOT-MIRRORED** has now appeared five times across three epics: WF-OVPN-10's keyless peer · the
identity-binding invariant across three consumers · the e2e fixture drift · M1b's two audit helpers ·
S11-5's four unguarded 500 paths on the agent channel. Every instance was found by tripping over it.

**S11-6 is the first time the width of a mirror surface was measured BEFORE it failed.** M1b was diagnosed as
"two audit helpers, one taught the machine branch and one not"; a census run for an unrelated reason (D3.5's
vocabulary question) found **fourteen**, across nine packages — a seven-fold sizing error in the ledger, and
enough to change the item's disposition from a slice to its own story.

**THE LAW: when a guard-not-mirrored instance is found, CENSUS THE MIRROR SURFACE — do not merely fix the
site that failed.** The instance is one member of a set; the fix's real size is the SET'S COUNT, not the
instance. A census costs minutes and answers three things a point-fix cannot: how many siblings exist,
whether the correct fix is "mirror it" or "collapse them", and whether the work is a slice or a story.
Sizing a mirrored-guard item from the instance systematically under-estimates it.

**Corollary — the trigger gets specific.** A censused surface yields a NAMED trigger ("the next change to
audit behaviour", because that change is what must be mirrored N times) rather than a vague one ("someday
unify these"). The next person is forced into the work anyway; the ledger should say so.

**Corollary — CHECK THE REMEDY, NOT ONLY THE CLAIM (founder-ratified 2026-07-30, S13.1 Slice 6).** A census of
user-facing strings must ask what each one PRESCRIBES as well as what it asserts. Slice 6's census graded three
`needs_reexport` consumers on whether they named a *cause*, and passed the badge label `re-export needed` as
"cause-neutral ✅" — while the widening made it visible to MANAGED devices, for which there is no export path at
all. The tooltip was caught because it named the wrong cause; the label was missed because it named no cause and
nobody asked whether it named a possible ACTION. **A label can lie through the remedy it prescribes, and a
census that only grades claims will pass it.** Every censused string gets both questions: is what it says still
true, and is what it tells the user to do still possible.

## PROVE-A-GUARD-REJECTS law (founder-ratified 2026-07-29, EPIC 11) — a new guard is not accepted until it has failed on a planted violation

**A guard that has only ever passed is indistinguishable from a guard that does nothing.** Green is the state
a correct guard and an inert guard share; only a REJECTION distinguishes them. So a new gate, census, red or
scanner is not accepted on "it runs and passes" — it is accepted when it has been shown to FAIL on a
deliberate violation, and then to pass again once the violation is removed.

Instances that made the case, all in EPIC 11 slice 1–2:
- **govulncheck** — its first honest run exited 3 on `GO-2026-5856`, a reachable `crypto/tls` flaw in the
  pinned toolchain that builds every shipped binary. It rejected because REALITY demanded it, which is
  stronger evidence than a planted vuln would have been.
- **The advisory-job guard** — built after a 3-second Trivy no-op reported green, it then caught the very
  next instance of its own bug (the corrected pin was still wrong) and failed VISIBLY.
- **The toolchain-pin agreement check** — partial bump → exit 1, agreement → exit 0.
- **The 500-path census** (S11-5) — a planted `http.Error(..., 500)` fails with its file:line; removed, passes.
- **The health-kind census** (D3.1) — a planted 14th kind fails by name with the reason; reverted, passes.

**COROLLARY (S11-7) — prove it rejects the HARDEST instance of what it claims to cover, not the easiest.**
A guard that enforces a SUBSET of its own ruling is worse than no guard: it manufactures confidence in
coverage that does not exist. The D3.5 audit census is the measurement. Version one inspected call ARGUMENTS
and found 51 actions — and would have passed while **sixteen branch-selected literals** (`action :=
"x.disabled"; if c { action = "x.enabled" }`) survived untouched, because those are assignments, not
arguments. Extending it to assignments took the count to **68**. Had it shipped at version one, the registry
would have looked complete, the red would have been green, and a quarter of the vocabulary would still have
been bare literals. So: enumerate the SHAPES the defect can take, and plant the awkward one.

**THE LAW:** when you add a guard, plant the violation it exists to catch, watch it fail, then revert and
watch it pass. Record both outcomes. The cost is a minute; the alternative is a green check that has never
once done its job and will not do it the first time it matters. (Companion to ARTIFACT-EXISTS ≠
ARTIFACT-WORKS: this is that law applied to the gates themselves.)

---

## A WITNESS MUST PROVE IT WAS ALIVE ACROSS THE WINDOW IT CERTIFIES

*Minted: EPIC 11 box-walk, Leg 5. A corollary of PROVE-A-GUARD-REJECTS, pointed at evidence-gathering rather
than at guards.*

**A silent witness is indistinguishable from a clean witness, and it fails toward "pass."**

The measurement: Leg 5's first attempt certified "no data-path loss across the roll" from a `ping` log whose
last line was timestamped **nine minutes before the roll began**. The process had died. Its `icmp_seq` gap
detector returned **clean** — a spotless bill of health for a window it never observed. The check could not have
failed, so its passing carried no information at all.

That is the same defect PROVE-A-GUARD-REJECTS exists to catch, one level up. There, the question is whether a
guard can reject a violation. Here it is whether an *instrument* can register the event it is aimed at. A gap
detector over a dead log, a metric scraped before its collector runs, an audit query over a table the code
never wrote to — each returns a confident, meaningless pass.

**THE LAW:** evidence of continuity requires evidence the instrument was running. Three checks, never fewer:

1. **Before** the leg — confirm the witness is replying *now*, with fresh timestamps.
2. **After** the leg — check its timestamp bounds against the leg's own start and end. `head -1` and `tail -1`
   must straddle the window.
3. **Then** the continuity check, grepping **the window explicitly** rather than trusting an aggregate over the
   whole file.

The generalisation beyond witnesses: before believing any negative result — no gaps, no errors, no findings,
zero rows — establish that the thing producing it was in a position to produce a positive one. "Nothing was
observed" and "nothing happened" are different claims, and only one of them is evidence.

---

## COULD THIS CHECK HAVE FAILED? — the censuses need censusing

*Minted: EPIC 11 box-walk. PROVE-A-GUARD-REJECTS generalized from guards to **evidence**.*

**The epic that built five censuses also demonstrated that the censuses needed censusing.**

Three checks in one session could not fail. Every one was green. Every one was vacuous:

1. **A witness dead nine minutes before the leg it certified.** The `ping` log ended before the roll began, and
   its `icmp_seq` gap detector returned **clean** — a spotless bill of health for a window it never observed.
   Accepted, it would have recorded "no data-path loss across the roll" from evidence predating the roll.
2. **A red asserting a tautology.** `degradedKind(KindInput{CertExpired: false})` does not return the
   cert-expired kind — true by construction. The production fix was removed and **everything still passed**. The
   decision under test was never the projection; it was *which rows count as expired*, and that lived in an
   untestable inline expression.
3. **A provenance census verifying the commit but not the product.** Leg 0 asserted the sha and the toolchain on
   an **open-core** codebase and never the edition, so four rebuilds silently swapped the open image for the
   enterprise one — `go build -tags ""` printed in every log, read every time, noticed never. The walk drew
   conclusions from the wrong product for several legs.

None was caught by running it again. Each was caught by one question:

> **Could this check have failed?**

Not *did it pass*. A check that cannot fail is worse than a missing one, because a missing check is visibly
absent while a vacuous check is visibly **green** — and green is what people act on.

**THE LAW:** before believing any negative or confirming result — no gaps, no errors, no findings, zero rows,
"all N are fine" — establish that the thing producing it was in a position to produce the opposite. Concretely:

- **Guards:** remove the fix, watch the guard fail, restore it. (PROVE-A-GUARD-REJECTS, and its S11-7 corollary:
  plant the *hardest* instance, not the easiest.)
- **Instruments:** prove the instrument was running across the window it reports on, with timestamp bounds
  straddling the event. (A WITNESS MUST PROVE IT WAS ALIVE.)
- **Censuses:** census the census. Ask what it enumerates over and name what it therefore cannot see. A census
  of *lookups* said nothing about *pickers*. A census that a health kind **reaches** each surface said nothing
  about whether each surface **decides correctly** about it. A pattern of `[a-z_]+` silently dropped
  `k8s_endpoints_unavailable` because the name contains a digit — the same incomplete-pattern bug the census was
  hunting, inside the census.
- **Provenance:** name every dimension of "the thing under test", not just the convenient one. A commit is not a
  build; a build is not an edition; an edition is not a configuration.

**A check written in the same breath as its fix encodes the author's belief about the fix rather than the
behaviour of the system.** Separating them costs a minute. Not separating them costs the first incident the
check was supposed to prevent.

### INSTANCE COUNT — the law is NOT BINDING (founder-ratified 2026-07-31, EPIC 13 review pass 1)

**Six prior instances, and then THREE MORE IN A SINGLE REVIEW PASS — on the story that was supposed to satisfy
this law.** Counted here rather than given a new law, because a second law would be a way of not noticing that
the first one is not working.

The class is narrower than the law's general form and worth naming precisely: **a guard whose expectation is
derived from the artifact under test** (first papered at S7.5.5 as the tautological-guard finding). Pass 1's
three:

| # | guard | what it derives from the artifact | what it therefore cannot catch |
|---|---|---|---|
| 3 | `rekey_integration_test.go:195-198` | hand-applies the `UPDATE` that pushes `cert_not_after` back into the past | that a lost re-key commit *advances* the very column the gone-gate reads, so real fingerprint recovery is refused for a full 48h TTL. The test fabricates the state that makes it pass |
| 19 | `rekeyquery_test.go:61` | asserts the presence of a substring of the query it is guarding | a `WHERE` clause that re-keys **every active node** still passes |
| 20 | `migrationcompat_test.go:33-41` | a line-level regex over migration text, with no notion of which tables the previous version had | that it fires on a `RENAME` inside a table created in the **same release** — forcing an expand/contract shim onto a version that cannot exist, which was then documented as protecting it |

**Three in one pass means the law is being read and not applied.** #20 is the sharpest: the guard's verdict was
taken as authority and a compatibility shim was built to satisfy it, without anyone asking whether the table
existed one version ago. *The law was invoked to justify the work that the law would have prevented.*

### FURTHER INSTANCES (2026-07-31, EPIC 13 fold)

**Instance 6 — and the procedure is now MECHANIZED rather than remembered.** A third mutation reported `ok`
because a Python syntax error inside the heredoc meant the patch never applied. Three false proofs in one session,
all the same shape: **the outcome was verified and the APPLICATION was not.**

`scripts/mutate.sh` now asserts, before any test runs: the anchor exists (and exactly once), the file actually
changed on disk, and the result still compiles. Anchor and replacement are read from FILES, never argv, so no
shell escaping can corrupt them. A mutation that matches nothing now exits with a message saying so, instead of a
green test.

**The generalisation, since it cost three instances to learn:** when a check's setup can silently fail, the check
verifies nothing and reports success. Verify the setup, not just the result.

**A false proof through mangled tooling — instance 4 of this class.** A mutation round was run through a shell
function whose `\&` escaping silently corrupted every patch: two mutations produced BUILD failures (already known
to be indistinguishable from a pass) and one reported **`ok`** — a mutation that never applied, read as "the fix
is unnecessary". The rule that now binds: **mutation rounds are applied through a heredoc with an anchor
assertion** (`assert old in s`) so a patch that does not match fails loudly instead of passing quietly. Re-running
the same round correctly produced four clean FAILs.

**Fixture fidelity — two more instances, both caught by the reds themselves.** A cascade helper that recorded
LESS than the production sweep it mirrored, so a restored device looked like a pre-migration row and the red
failed for the wrong reason. And a fixture using fixed certificate serials against a globally unique column: it
passed once and then failed on a constraint forever — **a fixture whose first green is its only green**, caught by
`make test-editions` rather than by the direct run that wrote it. Both are the fixture-fidelity law: a fixture
that cannot express the production state tests a different system.

**What binds, from now on, when a guard is written or trusted:** state, in one sentence beside it, **what the
guard reads and where that value comes from.** If the answer is "from the thing it is checking", it is not a
guard — it is a restatement. Applies equally to trusting an EXISTING guard's verdict: #20 was a failure to ask
that question of a guard someone else wrote.


---

## A DETERMINATION OF "GONE" MUST PROVE THE CREDENTIAL CANNOT WORK

*Minted: EPIC 13 / S13.1, from a ruling that was wrong as literally written — and whose counterexample was in the
walk that produced it.*

Recovery mechanisms need to decide when an existing credential may be **replaced**. The condition ruled for
WF-S11-11 listed three determinations of "unusable": **expired**, **unreadable**, and **name mismatch**. The first
two are proofs the credential *cannot function*. The third is a proof that *configuration disagrees* — which is
not the same thing, and treating it as equivalent is destructive.

**The counterexample is in the walk that produced the ruling.** The enrolment command was pasted on the wrong
host: `azure-gw`, holding `azure-gw`'s **valid** certificate, with `TUNNEX_NODE_NAME=aws-gw-1`. Under a
mismatch-authorizes rule the agent would have abandoned a live gateway's identity and enrolled that host as a
different node — a working gateway made to look dead while a second node took its name. That is precisely the
S8.2c WF-2 disaster the stored-identity preference exists to prevent, **reproduced by the guard meant to help**.

**THE LAW:** a determination that the original is *gone* must rest on evidence the credential **cannot work** —
expired, revoked, cryptographically unusable. Evidence that configuration merely **disagrees** — a mismatched
name, an unexpected host, a surprising label — is a **loud ERROR and never an authorization**. When the two kinds
of evidence conflict, the fail-toward-the-existing-identity clause governs.

The same shape governs the CP side (S13.1 D3): `revoked` or `cert_not_after < now()` may authorize a re-key;
`last_seen_at` stale may not. Silence is not proof that something cannot work — it is only proof that we have not
heard from it.

---

## MUTATION-TESTING COROLLARY — A MUTATION MUST COMPILE

*Minted: EPIC 13 / S13.1. COULD THIS CHECK HAVE FAILED?, applied to the thing checking the checks.*

Mutation testing is a habit in this repo now: break the fix, watch the guard fail, restore. The trap is one level
up again.

A mutation that replaced `if expired {` with `if false {` **orphaned a variable and failed to build**. The harness
grepped for test-failure patterns, matched nothing, and printed nothing — **identical output to a mutation that
passed silently**. For a moment the core fix of an entire slice appeared to be unguarded.

**THE COROLLARY:** a mutation must **compile**. A build failure is not a passing test and it is not a failing one;
it is a mutation that never ran. So:

- Prefer mutations that keep every symbol used — `expired := false` rather than `if false {`.
- **THE DISCRIMINATOR — when a build failure IS the rejection.** A build failure is a **valid** rejection when the
  guard *is* the type signature: adding a `lastHandshakeFailed bool` to a decision function that must not see the
  network fails with `not enough arguments in call to Decide`, and that is precisely the guard working — the
  compiler is enforcing the constraint, and the author is sent back to the reasoning. It is an **invalid** mutation
  when the guard is *behavioural* and the build failure merely prevented the behaviour from running: neutralising
  `if expired {` orphaned a variable, so nothing executed and the output was indistinguishable from a pass. Ask
  which kind of guard you are testing before reading the outcome.
- Have the harness distinguish **build failure**, **test failure**, and **pass** as three outcomes, never two.
  Grepping for `FAIL:` alone conflates the first with the third.
- The pass you must see is the *named assertion message*, not merely the absence of output. Absence of output is
  the failure mode.

---

## A CENSUS MUST ASSERT THE PROPERTY, NEVER A COINCIDENCE OF THE CURRENT TEXT

*Minted: EPIC 13 / S13.1 Slice 4. A corollary of COULD THIS CHECK HAVE FAILED?, pointed at the guards' matching.*

Censuses in this repo read source text — Dockerfiles, `.sql` files, enum blocks, renderers. That is their strength
and their trap: it is easy to match something that is *true of the text today* rather than the *property being
guarded*.

Three instances, all this epic:

- A guard asserted `strings.Contains(queries, "cert_not_after)")` — the closing paren of an INSERT column list. It
  was pinning the column's **position at the end of the list**. Appending a new column after it was a completely
  legitimate change and it **broke the guard**, which teaches the next author to weaken the guard rather than trust
  it.
- A kind census matched `[a-z_]+` and silently dropped `k8s_endpoints_unavailable`, because the name contains a
  digit. The pattern encoded an assumption about naming that the names did not honour.
- A shipping census guessed binary names from package names, and `./cmd/server` builds `tunnex-api`. It both
  false-passed and false-failed until it parsed the `-o` flag instead.

**THE LAW:** assert the property, scoped. **Position, ordering, adjacency and formatting are coincidences**;
presence *within a named scope* is the property. Concretely:

- Extract the region first (this query, this const block, this build stage), then assert **within** it — so a match
  elsewhere in the file cannot vouch for it.
- Match identifiers, not punctuation. `cert_not_after` inside `CreateNode`, not `cert_not_after)` anywhere.
- Derive the expected set from the source of truth (`AllKinds()`, the `-o` flag) rather than restating it.
- When a guard fails on a change you believe is correct, the first question is whether the guard is pinned to a
  coincidence — not whether the change is wrong.

### Companion: BENIGN vs INERT — what a non-rejecting mutation actually means

A mutation that produces no failure has two very different explanations, and conflating them is how a guard is
wrongly trusted or wrongly deleted:

- **BENIGN** — the property is genuinely still enforced, by another path. Neutralising an empty-key check left the
  case refused by a later parse failure: **defence in depth**, so the mutation revealed redundancy, not absence.
- **INERT** — nothing enforces the property, and the guard never did. A red asserting
  `degradedKind(CertExpired: false)` is not the cert-expired kind passed with its own fix removed.

Tell them apart by asking *what refused, and why* — then mutate **that** instead. If nothing refuses, the guard is
inert and the property is unprotected.

---

## EXPIRY IS AN ABSENCE OF ACTION; REVOCATION IS THE PRESENCE OF A DECISION

*Minted: EPIC 13 / S13.1, from a ruling that was wrong and an attack chain that proved it.*

A recovery mechanism authenticated by **proof of possession** asks "do you still hold the key?" It cannot ask "are
you the person who should hold it." That distinction decides what such a proof may overturn.

**A cryptographic proof may overturn an absence of action. It must never overturn a decision.**

The attack that established this: an attacker steals a gateway's state volume — its private key. The operator
notices and **revokes** the gateway, which is the product's answer to a stolen credential. The attacker then proves
possession of the stolen key and, under a gate that accepted `revoked` as authorizing, receives a fresh certificate
for that node — active, same identity, same policy. **Revocation defeated by the exact credential it was invoked
against.**

`revoked` had been listed as the *strongest* authorizing evidence, on the reasoning that it is the strongest
evidence the node is **gone**. It is. That was the wrong question: strength-of-evidence-that-it-is-gone is not
validity-of-authorization-to-**return**.

**THE LAW:**

- **Expiry, lapse, timeout, absence of a heartbeat** — nobody decided anything. A proof of possession may recover
  from these, because no intent is being overridden.
- **Revocation, suspension, deliberate disablement, an explicit deny** — a human decided. Only another human act may
  undo it. A credential must never be able to reverse the decision made *about that credential*.

Undoing a decision requires an act of the same kind: an operator-minted token, an authenticated administrative call,
a signed approval. Never a proof that the holder is still the holder — that is precisely what was doubted.

**And prefer construction to convention when enforcing it.** The statement that performs recovery does not
*carefully avoid* resurrecting a revoked row; it does not reference `status` or `revoked_at` at all, so no future
call path can reintroduce it. The gate that authorizes takes no liveness parameter, so staleness cannot be passed in
by mistake. A rule that cannot be expressed is stronger than a rule that is merely followed.

### Corollary — WHEN A RED'S ASSERTION INVERTS, SAY WHICH BEHAVIOUR WAS WRONG

A test whose expectation reverses is recording a **decision**, not applying a fix. Quietly editing it is how the
reasoning is lost and the decision gets re-litigated by someone who only sees the current line.

So: the commit states which behaviour was wrong and why, and the test carries the reasoning — for a security
inversion, **the attack chain itself**, not just the rule. A future reader who finds `revoked → refuse` with no
explanation will eventually decide it is an inconvenience worth relaxing.

---

## A FORWARD REFERENCE NAMES AN INTENTION, NEVER A CAPABILITY

*Minted: EPIC 13 / S13.1. A comment citing a story is not a citation of code.*

`auth/service.go:177` read:

```go
// (Per-caller email throttling is a separate concern — S11.3 rate limiting.)
```

Accurate when written, and it reads like a pointer to a mechanism. It is a pointer to a **plan**. S11.3 was scoped,
listed as UNBUILT in EPIC 11's own verify pass, and never shipped — Slice 1 delivered the security-CI tier instead.
Two epics later that comment was read as evidence the throttle existed, and a ruling was made on it: *"rate-limit it
(S11.3 shipped the machinery)."* The machinery did not exist.

This is the same shape as EPIC 11's advisory CI job that never ran, and as a runbook naming a binary the image did
not contain: **an artifact that reads like evidence of a thing rather than evidence of a plan for the thing.**

**THE LAW:** a comment, doc, or ticket that cites a story name is naming an intention. Before relying on it:

- **Grep for the code, not the citation.** "Where is this implemented" is a different question from "where is this
  mentioned", and the second is much easier to answer accidentally.
- **Write forward references so they cannot be misread** — *"there is no rate limiting today; S11.3 would add it"*
  rather than *"S11.3 rate limiting"*. The tense is the whole difference.
- **When a plan item is descoped, sweep its forward references.** A citation outliving its story is how a plan
  becomes a phantom capability that someone later builds a ruling on.

Corollary of ARTIFACT-EXISTS ≠ ARTIFACT-WORKS, one step earlier: here the artifact does not exist at all, and the
*reference* is what exists.

---

## A GUARD MUST BE EXERCISED THROUGH THE STACK IT RUNS IN

*Minted: EPIC 13 / S13.1, from a review finding on a guard written in the same slice as the law it violated.*

A test that calls the function directly tests **the function**. It does not test **the protection** — because the
protection is the function *plus everything the request passes through before reaching it*.

The instance: a per-endpoint throttle read `r.RemoteAddr` and deliberately ignored `X-Forwarded-For`, on the
reasoning that a header the caller controls is not an identity. Three tests asserted exactly that, including one
that rotated a forged `X-Forwarded-For` across four requests and proved the budget still bound. All three passed.

**And the throttle was defeated in production**, because `middleware.RealIP` was registered *above* it and had
already overwritten `r.RemoteAddr` with the client-supplied header value. The tests built bare `httptest` requests
and never ran that middleware, so they proved a property of the function that the deployed path did not have. The
guard was inert and was reported as proven.

**THE LAW:** when a guard's correctness depends on its position in a pipeline — middleware order, interceptor
chains, decorator stacks, hook ordering, SQL executed through a wrapper — the test must either run the real
pipeline or assert the position itself. Concretely:

- **Assert the position.** `TestThrottleIsRegisteredBeforeRealIP` reads the router and fails if the registration
  order changes. Blunt, and it catches the actual defect where a unit test cannot.
- **Or exercise the composed handler**, not the leaf — build the router and send a request through it.
- **Ask what runs before this.** The question that would have found this in seconds is not "does my function
  ignore the header" but "**is `RemoteAddr` still the peer address by the time my function reads it?**"
- **Suspect any guard whose input is mutated upstream.** Anything that rewrites request fields — proxy middleware,
  body decoders, auth context injectors, path rewriters — turns "I read X" into "I read whatever the chain left in
  X".

This is COULD THIS CHECK HAVE FAILED? narrowed to a specific mechanism: the check *could* have failed on a wrong
function, and *could not* have failed on a wrong pipeline — which was the way it was actually wrong.

## A FIXTURE THAT RESTATES PRODUCTION TESTS THE RESTATEMENT (founder-ratified 2026-07-31, WF-S13-3)

**Fixture-fidelity, in the direction nobody watches for.** The known form is a fixture that records LESS than
production, so a red fails for the wrong reason — annoying, and self-announcing. This is the mirror: a fixture
that records MORE, so a red **passes** for the wrong reason. Nothing draws attention to a pass.

**The instance.** EPIC 13's fold for finding #8 added `revoked_prev_status` to the restore's READ side and, via a
bare `s.replace` whose anchor missed by one space, never added it to the production sweep. The same fold "fixed"
the test fixture to set the column by hand. So the red asserted against a fixture **simulating a production
change that did not exist** — and passed. So did a mutation round. Four gates, a review pass and a mutation round
all missed it; the box-walk found it in one query.

**THE RULE:** a fixture must **CALL** the production path it depends on, never restate it. Where restating is
unavoidable, the red is not evidence about production and must say so in its own comment.

**THE COROLLARY, and it amends a claim made earlier in the same epic:** *per-fix reds substitute for a review pass
ONLY where the fixture calls production.* Where a fixture restates it, the red proves the restatement and the
review remains owed. That claim was endorsed on the strength of a mutation round catching two vacuous guards —
and WF-S13-3 is the case it does not cover, because the mutation round passed too.

**Mechanically enforced, in the half that was missing:** `scripts/prove-fix.sh` requires the red to **FAIL BEFORE
the edit**, then proves the anchor matched exactly once, the file changed, it compiles, and the red passes after.
Assertion 1 is the one this incident needed — the fixture's simulation made the red green *before* the edit, and
that gate would have stopped it.

---

## A UNIT TEST PROVES BEHAVIOUR, NEVER REACHABILITY (founder-ratified 2026-07-30, S13.1)

**For every mechanism: name the caller, and prove the trigger can CO-OCCUR with the gate.**

EPIC 13 shipped `RestoreCascadeRevokedDevices` with reds that all passed. It has one caller (`Rekey`); devices are
cascade-revoked in one place (`Revoke`); and `Rekey` refuses a revoked node (D3). So the only trigger that creates
the work puts the node into the one state that can never reach the code that does it — **correct code wired to a
trigger it cannot fire from.** The reds proved the restore does the right thing *when called*. Nothing proved it is
ever called, and nothing in the build or the story-end review asked.

It surfaced while a WALK LEG was being drafted, because writing a leg forces the sequence to be stated end to end —
which is a reason to draft walk legs early, not only before a walk.

**This is the [who-reads-this probe](#) one layer up.** That probe catches a PRODUCER with no consumer (a channel
field nothing reads); this catches a CONSUMER with no reachable producer. Same defect class, opposite end, and both
land on the dormant-machinery law.

**The check, and it is cheap:** grep the callers of the new function AND the callers of whatever produces the state
it consumes, then ask whether both sets of preconditions can be true **at the same time**. Cheapest at design time,
still cheap while drafting a walk leg, expensive after it ships as code that never runs.

---

## ABSENCE MUST BE THE CLOSED STATE (founder-ratified 2026-07-31, S13.1 D3)

**A column whose ABSENT value means PERMIT is a fail-open waiting for the first writer that does not know about
it. Choose the encoding so absence is the CLOSED state.**

This is a by-construction rule, not a check. A check asks every future writer to remember; an encoding cannot be
forgotten, because the database supplies the safe value to anyone who says nothing.

**Three instances, all inside one ruling, which is why it is a law and not a note:**

1. **Existing rows.** `nodes.cert_delivered_at` shipped as a nullable timestamp where NULL meant *undelivered* —
   the state that OPENS the re-key redelivery carve-out. A new nullable column reads NULL for the entire fleet, so
   deploying it would have opened the carve-out for every node in the field on day one: **a fail-open introduced
   by the fix for a fail-open.** Caught before merge and closed by a backfill (0063).
2. **New rows.** The backfill fixed the rows that existed and did nothing for the ones created afterwards.
   `CreateNode` names six columns and not the marker, so **every freshly enrolled node** read undelivered while
   holding a valid certificate — on every replica, not only an older one mid-roll. The backfill answered
   "what about the fleet?" and nobody asked "what about tomorrow's fleet?" (0064).
3. **The encoding that looks right and is not.** `NOT NULL DEFAULT now()` was the obvious repair and cannot work:
   re-key must still express *never delivered*, and NOT NULL forbids the value that meant it. The shape that
   satisfies both halves is a **boolean `NOT NULL DEFAULT true`** — absence lands CLOSED, and only the one
   statement that legitimately opens the state says so explicitly.

**The test that distinguishes a real application of this law from a restatement:** write the INSERT that an
unaware writer produces — naming exactly the columns today's code names, and nothing else — and assert the
resulting row is in the refusing state. If that test cannot fail, the encoding is not doing the work.

**Related:** this is the schema-level sibling of *a determination of "gone" must prove the credential cannot work*
and of the fail-closed direction in KILL-SWITCH-NO-UNBOUNDED-I/O. Same instinct, moved from code into DDL, where
it cannot be refactored away.

### SIBLING — A RECOVERY MECHANISM MUST NOT DESTROY ITS OWN INPUT (founder-ratified 2026-08-01, WF-S13-8)

**A recovery path must not delete the record it needs, on the path where recovery is what failed. Discard the
input only after the recovery it feeds has demonstrably succeeded.**

ABSENCE MUST BE THE CLOSED STATE governs the value an unaware writer *supplies*. This governs the value a
recovery path *destroys*. Both fail the same way — the safe state has to survive somebody not thinking about it —
and both are by-construction, not checks.

**The instance.** `restoreDNS` (`apps/helper/backend_darwin.go:672`) puts every macOS network service's DNS back
from `/var/run/tunnex/dns.json` after a full tunnel hijacked it. Each restore is `_ = run("networksetup", …)` —
the error discarded — and `os.Remove(dnsBackupPath)` then runs **unconditionally**, outside any success test. So
a single failed restore strands that service on the tunnel resolver **and deletes the only record of what it
should have been.** The startup `CleanStale` retry that exists for exactly this case becomes a permanent no-op,
because its input is gone. **Total failure (no DNS), self-concealing (the tunnel is visibly down, so nobody
inspects resolver settings), and self-destroying.**

**The shape, stated so it is recognisable away from DNS:** *cleanup that runs unconditionally after a
best-effort apply.* The apply swallows its errors, the cleanup does not read them, and the retry downstream is
starved. Every teardown that persists state to undo itself has this shape available to it — the kill-switch pf
token, the route belief, any owned-marker sweep.

**The test that distinguishes application from restatement:** make the underlying command fail for ONE subject,
then assert the record survives AND the next retry still repairs it. A test that only checks the happy path
cannot fail in the direction this law protects.

**Sibling of** ABSENCE MUST BE THE CLOSED STATE (above) and of the KEEP-LAST direction in the reconcile model:
when the new value cannot be established, keep the old one — do not land on empty.
## A CORRECT ASSERTION, SILENTLY INVERTED BY A PREVIOUS TEST'S STATE (minted 2026-08-01, web component tier slice 1)

**Belongs to the [[COULD THIS CHECK HAVE FAILED?]] family, and it is DISTINCT from every member of it.** The
others are bad assertions — they cannot fail, or they fail for the wrong reason. **This one is a CORRECT
assertion, correctly written, whose verdict is inverted by state left behind by a test that already ran.**

**THE INSTANCE.** `apps/web/vitest.config.ts` sets no `globals: true` and no setup file, so
`@testing-library/react`'s automatic `afterEach` cleanup **never registers**. Renders accumulate in one
document across every test in a file. The existing foothold never hit it because it renders exactly once; the
first multi-render file hit it immediately.

**And the direction it failed in is the whole point:**

```
it("offers no revoke control on an already-revoked gateway", …)
  →  Found multiple elements with the role "button" and name "Revoke"
```

**An assertion about a button's ABSENCE became a false PRESENCE** — because a *previous* test's revoke button
was still in the document. Reverse the leak and the same mechanism turns a genuine presence into a false
absence. **Either way the test reports on a document nobody wrote.**

**WHY IT IS INFRASTRUCTURE AND NOT AN AUTHORING ERROR: it cannot be caught by reading any single test.** Every
test in the file is individually correct. The defect lives in what the harness does *between* them, which no
amount of care inside one test can see. That is what distinguishes it from the rest of the family — those are
found by reading the check and asking whether it can fail; this one is found only by running two checks in one
file, or by knowing the harness.

**THE GUARD: an explicit `afterEach(cleanup)` with its REASON INLINE**, not as boilerplate. Boilerplate gets
deleted by whoever is tidying imports; a line that says why it exists does not. **A tier convention, adopted
before the second screen was written rather than after a false green shipped.**

**THE ASYNC FORM (added 2026-08-01):** the same defect arrives without any leak when a test asserts against a
tree it has **not finished waiting for**. Sites' first test waited on the PENDING chip and asserted the APPROVED
one, which renders later; its sibling test, over the SAME two elements, passed only because it happened to wait
on the later one. **Two tests over the same elements disagreeing is the tell.** Both forms are one sentence: **a
correct assertion made against a tree that is not yet — or no longer — the tree it describes.** Guard: a
`waitFor` must cover EVERY element the assertions touch (tier query rule 5).

**GENERALISED, past React:** any harness where one case can leave state the next case reads — a shared temp
dir, a package-level fixture, a module-level cache, a database not rolled back — has this shape available to
it. **The question is not "is my assertion right" but "what did the previous test leave behind that my
assertion can read?"**

*(The six other mechanisms in this family — half-fold, tautological guard, fixture-restates-production,
TRUE-BY-STRUCTURE, SAMPLED-SLOWER-THAN-THE-EVENT, ASSERTS-A-DIFFERENT-EVENT-THAN-IT-WAITS-ON — were minted
during EPIC 13 and arrive on `main` with that epic's merge. This entry is written self-contained so it reads
correctly before and after.)*

### TWO MORE INSTANCES, BOTH FOUND BY USING THE TOOL RATHER THAN READING IT (2026-08-01, web tier slice 2)

**INSTANCE — fixture-restates-production, written INSIDE the check guarding against it.** D4's sibling
assertion exists to prove three surfaces agree about revoked-row suppression. Its first draft covered the third
surface with a three-line `DeviceRowProbe` that re-encoded the production guard
(`status !== "revoked" && <badge>`) in the test file. **It would have passed forever even if `Devices.tsx` lost
its guard**, because the assertion would have been reading the test's own copy of the rule. **Caught
pre-commit** and replaced with the real page; **the near-miss is recorded in the test file itself**, not just in
the commit, because the next author to reach for a probe will read the file and not the history.

**INSTANCE — the SIXTH mechanism applied to the TOOL.** `mutate.sh` asserted *"the test failed"* and concluded
*"the guard rejects the mutation."* A **broken test command fails identically.** It happened: invoked from the
repo root as `vitest run --root apps/web test/x.test.tsx`, the relative path in `vi.mock("../src/lib/api")`
stopped resolving, nothing was mocked, and **all four tests failed — including two the mutation cannot affect.**
The script printed *"test failed under the mutation, as required."*

That is **ASSERTS-A-DIFFERENT-EVENT-THAN-IT-WAITS-ON** with the tool as subject: it waits on *exited non-zero*
and asserts *the guard bit*.

**THE FIX: re-run the command UNMUTATED and refuse if it also fails.** `prove-fix.sh` has always had the mirror
of this — *"the red must FAIL before the edit"* — and **`mutate.sh` never had it.** Now it does, proven to bite
with a deliberately broken command.

**THE PATTERN ACROSS BOTH TOOL DEFECTS THIS WEEK:** the `set -u` abort and this false verdict were **both found
by USING the tool, neither by reading it.** A self-test proves a tool runs; **only a real subject proves it
concludes correctly.** Keep the self-tests, and keep distrusting a green verdict whose baseline nobody checked.

## APPLY THE DETECTOR TO THE MEASUREMENT (minted 2026-08-01, EPIC 13 + web tier)

**A MEASUREMENT ERROR THAT PRODUCES A PLAUSIBLE FINDING IS MORE DANGEROUS THAN ONE THAT PRODUCES NONSENSE.**
Nonsense gets re-run. **A plausible finding gets written down and acted on.**

**Two instances in one day, and BOTH failed in the dangerous direction — plausibly:**

1. **`grep -c` on a 2.9 MB file of 405 lines**, counting `<div`. It counts **LINES containing a match**, not
   occurrences, so it undercounts by orders of magnitude — **uniformly**, which is what makes it dangerous.
   Nothing looks anomalous; every figure is simply small. The correct measure (`grep -o … | wc -l`) returned
   **1,018**.
2. **`grep -o 'case "[a-z_]*"'` excluding DIGITS**, so `k8s_endpoints_unavailable` did not match. The conclusion
   available from that output was *"WF-S11-7's kind is unrendered on main"* — **a live regression of a
   named, famous finding.** It is handled (`healthview.ts:44`). **The pattern was wrong, and the wrong answer
   was the interesting one.**

**THE DIAGNOSTIC: before reporting anything a grep found, verify the PATTERN against an input whose answer is
already known.** The detector this repo applies to checks applies to measurements: *could this measurement have
produced a different answer for a reason unrelated to its subject?*

**Neither instance reached a claim.** Both were caught by re-measuring before writing — instance 1 by asking why
a 2.9 MB file would hold so few divs, instance 2 by reading the source at the line the count implied was empty.
**Recorded because they were caught, not because they were harmless: the same error one step later is a false
finding in a walk record.**

**THE POSITIVE FORM, from the same session:** the responsive audit counted **`min-width:0` = 104
SEPARATELY** — a number taken **deliberately so it could not be misread as responsiveness** (it is the flexbox
min-content idiom). **Measuring the thing that would produce a wrong reading, in order to exclude it, is the
same care in its constructive direction.**

### POSITIVE INSTANCES — two seams where fixture-restates-production was AVOIDED (web tier slice 3)

**1. THE MIRROR CENSUS AS A DELIBERATE LITERAL.** `test/kuberneteswiring.test.tsx` lists every
`policy_degraded_kind` the contract allows **as a hand-maintained literal**, and asserts each reaches a
renderer. **Deriving that list from the generated type would prove nothing** — it would compare the source to
itself and pass by construction. **Two lists, maintained separately, shown to agree.** Same family as D10's
golden vector and the twin canonical-hash goldens: *the coupling is asserted, not assumed.*

**2. THE REAL `AuthProvider`, NOT A STUB.** The Kubernetes screen reads `useAuth()` for its role gate. Stubbing
the context would put **the test's copy of the gate** under assertion instead of **the product's** — 
fixture-restates-production **at the seam where it is easiest to fall into**, because stubbing a context is the
obvious move and the test still goes green.

## A GUARD ENFORCED BY TYPES BEATS ONE ENFORCED BY DISCIPLINE (minted 2026-08-01, web tier slice 4)

**Discovered by trying to break it, which is the only way this is ever discovered.**

The `loadOne` law says a failed load must never render as an empty or a defaulted value. On the Access screen
that would be *"0 rules — ALL traffic denied."* on a load that never returned — **an authorization claim
invented by the client.**

**The naive mutation for it DOES NOT COMPILE.** `Loaded<T>` is a discriminated union:

```ts
export type Loaded<T> = { ok: true; data: T } | { ok: false; error: string };
```

**`.data` is unreachable without narrowing `.ok`.** Dropping the `!rulesResult.ok` check does not produce a
wrong render — **it produces a type error.** The mutation had to attack the failed branch's *output* instead.

**THE FINDING IS THE STRENGTH, NOT THE INCONVENIENCE.** The law is enforced **by construction** on this path:
a future author cannot reintroduce the defect by forgetting a check, because the compiler will not let them
read the value they forgot to check for.

**THE STANDARD, AND THE REGRESSION RISK: `Loaded<T>` MUST NOT BE LOOSENED.** Widening it to
`{ ok: boolean; data?: T; error?: string }` — the shape a hurried refactor reaches for, because it is easier to
construct — **would silently convert a compile-time guarantee into a discipline nobody is auditing.** Nothing
would fail. No test would go red. The guard would simply stop existing.

**BINDING ON THE REDESIGN.** A re-architecture touches every screen's load path. **`Loaded<T>`'s discriminated
shape is a thing the redesign must not regress**, and it is exactly the kind of guard that disappears without
anyone noticing, because its absence looks like ordinary code.

**GENERALISED:** when a law can be encoded in a type, encode it there. A rule enforced by review is enforced
until the reviewer is busy; a rule enforced by the compiler is enforced at 3am by someone who never read the law.

## A COMMAND THAT PRODUCES OUTPUT BUT NOT ITS EFFECT READS AS GREEN IN EVERY LOG (minted 2026-08-01)

**TWO TOOLS, SAME SHAPE: each ANNOUNCED SUCCESS WITHOUT DOING ITS WORK, and each was believed.**

1. **`mutate.sh` printed `Restoring.` and did not restore** (`3c9c16f`). Every run left the mutated file in the
   tree while claiming it had been put back.
2. **`npx tsc --noEmit` run from the REPO ROOT** resolved to a different package, which prints
   *"This is not the tsc command you are looking for"* and exits. **Four slices were reported "typecheck
   clean" on that output.** Nothing was checked. Nothing said so.

**THE SHARED SHAPE: output is not effect.** A log line proves a command RAN. It proves nothing about what it
DID, and a human scanning for red sees neither.

**THE DIAGNOSTIC: RUN THE COMMAND THE GATE RUNS, FROM WHERE THE GATE RUNS IT — never a convenient equivalent.**
`npx tsc` from the repo root is not `pnpm --filter @tunnex/web typecheck`. `vitest --root apps/web` from the
root is not `vitest` from `apps/web` — that one broke a relative mock path and produced a **false mutation
verdict** the same day. The convenient equivalent is where the difference hides.

### THIRD INSTANCE OF THE MEASUREMENT CLASS — and it compounds with the first two

With `grep -c` on a 405-line file and `grep -o '[a-z_]*'` excluding digits, this makes **three measurement
errors in one session**, all of which produced a **plausible** answer. See *APPLY THE DETECTOR TO THE
MEASUREMENT* above: nonsense gets re-run; a plausible answer gets written down.

### THE SHARPEST INSTANCE — the near-miss that found all of it

**`tsconfig.json` included only `src`.** So `tsc --noEmit` — the gate behind
`pnpm --filter @tunnex/web typecheck` — **had never typechecked a single file in the component test tier.**
Five slices were written and reported green against a check that never looked at them.

**It was found by asking WHERE THE ASSERTION WOULD ACTUALLY RUN, not by reading anything.** The `Loaded<T>`
contract was about to be placed in `test/`, where it would have been **a check that cannot fail — inside the
artifact written to prevent checks that cannot fail.** One question ("does the gate see this directory?")
caught the contract's placement, the tier's missing type coverage, and the vacuous `tsc` invocation together.

**WHAT THE FIX FOUND, stated plainly rather than assumed:** scoping `test/` in and running the gate's own
command surfaced **exactly two errors, neither in the new tier** — a duplicate `import { ruleRow }` in
`test/policyview.test.ts` re-importing a symbol already imported at the top of the same file. **Behaviourally
benign** (both bindings resolved to production), **genuinely a TS2300**, and **invisible to every gate for as
long as it has existed.** The five slices were **clean once scoped correctly — which is a different statement
from "assumed clean", and only one of them was ever true.**

### FOURTH INSTANCE — A SUITE PASSING ON A PHANTOM DEPENDENCY (2026-08-01)

`@testing-library/react` and `jsdom` were **not in `apps/web/package.json` and not in `pnpm-lock.yaml`**. They
existed only physically in one machine's `node_modules`, installed while on a different branch. **Five slices of
the component tier ran green on them.** On a clean checkout — or on CI — nothing would have resolved.

**THE SHAPE ACROSS ALL FOUR, and it is one reading, not four:**

| # | mechanism | the output |
|---|---|---|
| 1 | `mutate.sh` printed `Restoring.` and did not restore | a success line |
| 2 | `npx tsc` from the repo root resolved to a different package | a banner, then exit |
| 3 | `vitest --root apps/web` from the root broke the relative mock path | a red that meant nothing |
| 4 | the suite resolved deps present on **one machine only** | 217 passing tests |

**THE CHECK RAN. IT PRODUCED OUTPUT. THE OUTPUT DID NOT MEAN WHAT IT APPEARED TO MEAN.** Four different
mechanisms, one reading — and in three of the four the output was *green*, which is the direction nobody
re-examines.

**THIS IS A REPEAT OF THIS REPO'S OWN HISTORY.** S6.0b: an unanchored `secrets/` in `.gitignore` kept
`apps/api/internal/secrets` **out of git** — built fine locally, **broke every fresh clone**. Same class,
already learned once, rediscovered here in a different costume. **A lesson learned in one toolchain does not
transfer to another by itself; it has to be re-earned or encoded.**

**THE RULE THIS EARNS: A SLICE IS NOT GREEN UNTIL THE GATE PASSES — the gate AS CI RUNS IT, not a local
equivalent, and EVERY slice, not once at the end.** For this tier that is `make web-gate` (typecheck + test +
build, Node 20 container). `vitest` passing in a developer shell is a useful signal and is **not** evidence.

**THE SHARPEST FRAMING:** the tier exists to catch defects a surface's own tests cannot see — **and its first
five slices carried a defect its own gate could not see.** That is not irony. It is the evidence that *"the gate
is the authority"* has to mean **the gate as CI runs it, on every slice.**

## A DRIFT GUARD PROTECTS THE SOURCE↔ARTIFACT RELATIONSHIP, NOT THE ARTIFACT FROM TAMPERING (2026-08-01, S14.1)

**`make generate-check` depends on `make generate`.** So it REGENERATES before it diffs — and a hand-edit of an
emitted artifact is **silently overwritten**, leaving a clean tree and a **green** check.

```
hand-edit the emitted file  →  generate-check  →  generate overwrites it  →  diff clean  →  GREEN
```

**A HAND-EDIT IS SELF-HEALING, NOT DETECTED.**

**What the guard DOES catch is a STALE COMMIT:** source changed, artifact not regenerated. Proven by editing
`packages/shared/src/tokens.ts` without regenerating — the guard printed the before/after lines and failed.

**THIS IS TRUE OF EVERY GENERATED ARTIFACT IN THIS REPO** — `api.d.ts`, `rbac-policy.json`, the sqlc output,
the RBAC mirror. The property is the same for all of them because the target is the same shape.

**Why it matters even though it is arguably fine:** the edit cannot survive the next `make generate`, and CI
runs the check on every PR, so tampering never reaches `main`. **But "the artifact is guarded" and "the artifact
matches its source" are different claims**, and only the second is true. Anyone reasoning about what the drift
guard protects should be reasoning about the second.

**NOT FIXED — registered as a repo-wide property. TRIGGER: the next change to `make generate-check`, or a
finding that depends on artifact tampering being detected.**

## INTERNAL USE AND REDISTRIBUTION ARE DIFFERENT LICENCE QUESTIONS — AND A SELF-HOSTED PRODUCT IS ALWAYS THE SECOND (2026-08-01, EPIC 14)

**"Free for commercial use" answers the wrong question for this product.**

**Tunnex SHIPS A BUILT BUNDLE to customers who run it themselves.** That is **redistribution** of every
dependency's compiled code — not internal use on a site we operate. The two permissions are granted separately
and a licence may grant one without the other.

**THE INSTANCE.** GSAP 3.15.0 is genuinely free for commercial use. Its licence field is
`"Standard 'no charge' license: https://gsap.com/standard-license"` — **a custom URL, neither SPDX nor
OSI-approved** — and it forbids reverse-engineering and altering notices. **The open edition is Apache-2.0 with
a NOTICE file, and Apache-2.0 grants modification.** A recipient of an Apache-2.0 artifact would not receive,
for the GSAP portion, the freedoms the surrounding licence advertises. **Not adopted. Motion (MIT) instead.**

**THE QUESTION TO ASK OF EVERY DEPENDENCY, in this order:** may we USE it · may we REDISTRIBUTE it · is its
licence COMPATIBLE with the licence of the artifact we redistribute it inside · does NOTICE need an entry.
**Answering only the first is how a licence conflict ships.**

*(Repo precedent: S6.3 pinned wireguard-go as MIT and recorded Wintun's redistribution terms in NOTICE — the
second and fourth questions, asked at the time.)*

## INVISIBLE IS NOT ABSENT — THIRD INSTANCE, NOW IN RESPONSIVE (2026-08-01, S14.2)

**`display:none` leaves an element FOCUSABLE, ANNOUNCED and SUBMITTABLE.** It is gone to a sighted mouse user
and present to everyone else.

**Three instances of one shape, now across three mechanisms:**

| mechanism | the failure |
|---|---|
| **edition gating by style** | an enterprise control coloured away is still in the DOM — a licence boundary that fails open |
| **responsive hiding** | the **access-rule builder** hidden below `compose` is still keyboard-reachable — **a security surface where a mis-tap grants access**, decided by viewport |
| **nav hiding** | a destination hidden by CSS is a navigation surface that exists for some users and not others, **decided by VIEWPORT rather than by PERMISSION** |

**THE RULE: PERMISSION IS A RENDER DECISION. WIDTH NEVER IS.**

- **Composition below `compose` is ABSENT**, not hidden — `ComposeGate` does not render the editor at all.
- **Nav may RE-ARRANGE, never REMOVE** — every destination is in the DOM at every width; only presentation
  collapses.

**AND THE TEST MUST ASSERT ABSENCE BY ROLE**, which is what makes a `display:none` implementation **fail**
rather than pass: `queryByRole` finds a hidden element, so an assertion written against roles distinguishes
*hidden* from *absent* where a visual check cannot.

### DETECTOR'S FOURTH PROSPECTIVE CATCH — jsdom HAS NO LAYOUT ENGINE

**A "responsive test" written in vitest would assert NOTHING and pass at EVERY width.** jsdom does not evaluate
media queries, compute widths, or lay anything out. **That is not a query-rule-4 violation — it is a check that
CANNOT FAIL**, and it was caught **before the test was written**.

| # | instance | when caught |
|---|---|---|
| 1 | B2's 7-second poller vs a 272 ms window | after twelve green samples |
| 2 | the acceptance test waiting on `issued` | after CI went red |
| 3 | the restore-window poller for an event `restore.go` cannot produce | **before it was written** |
| **4** | **a jsdom "responsive" test at five widths** | **before it was written** |
| **5** | **a `prefers-reduced-motion` test in jsdom** — `window.matchMedia` **is not implemented**, so the test would throw or silently no-op | **before the motion gate was written** |

**The three-layer answer is right precisely because it never asks jsdom a question jsdom cannot answer:** a
**pure** `layoutIntent(width)` unit-tested at boundaries · a component tier that stays **width-blind** (and *a
test that needs a viewport to pass IS the finding*) · a responsive contract asserting **absence by role** with
capability **injected, never measured**.

**CATCH 5 IS THE SAME SHAPE ONE MEDIA QUERY OVER, and it is why the shape is worth naming rather than the
instance.** `prefers-reduced-motion` is a **gate, not a courtesy** — so a test of it that quietly no-ops is a
gate that certifies an accessibility property nobody checked. **Found before the motion gate was written, not
after it silently passed**, and answered the same way: a **pure `motionAllowed(prefersReducedMotion)`**
decision, the preference read **once at the app edge**, and the CSS half emitted **unconditionally** as
`@media (prefers-reduced-motion: reduce)` zeroing every duration token — **so a component that forgets to check
still animates for zero milliseconds.**

**THREE OF THE FIVE WERE CAUGHT BEFORE THE CHECK WAS WRITTEN.** That is the detector paying for itself: the
first two cost a green run each; the last three cost a question.

## A COMMENT THAT ASSERTS A LIBRARY'S BEHAVIOUR IS A GUESS UNTIL A MUTATION CONFIRMS IT (2026-08-01, S14.2)

**THE SESSION'S RESULT. Filed at the top of the [[COULD THIS CHECK HAVE FAILED?]] family because of what it
nearly cost, not because of what it was.**

**THE INSTANCE.** The responsive contract's central assertion — the one the entire compose gate exists for —
was written as:

```tsx
// `queryByRole` finds an element hidden with `display:none`, so a display:none implementation FAILS this.
expect(screen.queryByRole("button", { name: /add rule/i })).toBeNull();
```

**The comment is wrong.** testing-library defaults to `hidden: false` and runs `isInaccessible`, which jsdom
evaluates against inline styles. A `display:none` element is **excluded** from the query — so `queryByRole`
returns `null` and the assertion **passes**. Mutation 1 (reimplement the gate as `display:none`) **PASSED**.

**The assertion checked "not in the ACCESSIBLE TREE"; the comment claimed "not in the DOM".** Those two differ
on *exactly* the failure mode being guarded against. A member of the
[[ASSERTS-A-DIFFERENT-EVENT-THAN-IT-WAITS-ON]] family, and the sharpest so far, because **the false claim was
written INSIDE the comment explaining why the assertion was rigorous.**

## ⚠ WHAT IT NEARLY COST — the near miss is the point, and it is worth stating plainly

**Had `ComposeGate` shipped as `display:none`, the access-rule builder below 768px would have been
KEYBOARD-REACHABLE and SCREEN-READER-ANNOUNCED while invisible — and this test would have CERTIFIED IT
ABSENT.**

A control that grants access, present to a keyboard and gone only to a sighted mouse user, is
[[INVISIBLE IS NOT ABSENT]] — the law this epic had already minted twice. **So the near miss happened inside
the guard written to prevent it.** The guard was not weak; it was *aimed one layer off*, and the comment made
the misaim read as rigour.

**THE RULE. A CLAIM ABOUT A LIBRARY'S SEMANTICS IS A HYPOTHESIS. THE MUTATION IS THE EXPERIMENT.** Where an
assertion's rigour depends on what a matcher *includes* — visibility, disabled state, `aria-hidden`, shadow
roots, portals — **write the mutation the claim says would be caught, and run it.** Prose confidence about a
third-party default is not evidence, and it reads exactly like evidence.

**THE COROLLARY, which is the transferable part: THE MORE CONFIDENT THE COMMENT, THE MORE IT NEEDS THE
MUTATION.** A hedged comment invites scrutiny. A comment that explains why an assertion is rigorous *suppresses*
it — from the author first, then from every reviewer after.

**The fix is a flag, not a rewrite:** `{ hidden: true }` searches the whole DOM regardless of visibility, and
the same mutation then goes red. **The cost of finding this was one mutation. The cost of not finding it was a
security-adjacent gate that passed while not gating.**

## VERIFY THE SCAN, NOT THE BADGE — AND ESPECIALLY ON A SLICE WHOSE OWN FINDING WAS A PASSING NON-ASSERTION (2026-08-01, S14.2)

**A green check is a CLAIM ABOUT a scan. The alert list IS the scan.** When a security check flips from red to
green after a fix, read the finding list at the ref — not the check's colour.

```
gh api "repos/<o>/<r>/code-scanning/alerts?ref=refs/pull/<n>/merge&state=open&tool_name=CodeQL"
```

**THE INSTANCE.** The wireframe rename was verified by that query returning **zero** where it had returned
five, before the aggregate check was believed. Which was lucky in the order it happened: the aggregate passed
through `failure` → **`neutral`** → `pass` as analyses re-ran, and `neutral` reads as "not red" to anyone
skimming. **Two of those three states would have been mis-read as success by colour alone.**

**WHY IT BINDS HERE IN PARTICULAR, and this is the transferable part.** This same slice's finding was
[[A COMMENT THAT ASSERTS A LIBRARY'S BEHAVIOUR IS A GUESS UNTIL A MUTATION CONFIRMS IT]] — **an assertion that
PASSED while asserting nothing.** Trusting a check's colour after finding that would have been **the identical
mistake one layer up**: accepting a summarised verdict in place of the thing it summarises.

**THE RULE. A SESSION THAT HAS JUST FOUND A VACUOUS CHECK MUST ASSUME ITS OTHER CHECKS ARE VACUOUS UNTIL READ.**
The finding is not a one-off to be logged and moved past — **it is evidence about the reliability of every
summarised signal in the same session**, and the cheapest response is to open the underlying data once.

## A PAPER THAT CLAIMS COVERAGE IS AN ASSERTION, AND IT NEEDS A GATE LIKE ANY OTHER (2026-08-01, S14.1 → S14.3)

**THE INSTANCE.** S14.1's commit-one claimed five covered token groups. The emitted artifact carried **thirteen
variables, all colour**. Typography scale, spacing, radius, elevation and motion were **claimed and never
emitted**, and the slice shipped CI-green.

**Its gates were not weak — the promise had NO gate.** Theme completeness compared each theme to the names that
existed. Contrast compared colours to colours. The reservation scan compared source to a rule. **Every gate was
aimed at what was there; none at what was promised.**

**THE RULE. A COVERAGE CLAIM IS DATA, AND A CENSUS COMPARES IT TO THE ARTIFACT.** The claim is hand-authored to
mirror the paper; the artifact is generated; **adding a claimed category without emitting it goes red.**
Derive the claim from the implementation and it compares the system to itself and passes by construction —
[[fixture-restates-production]], applied to a design system.

**THE FAMILY THIS JOINS.** It is the [[A COMMENT THAT ASSERTS A LIBRARY'S BEHAVIOUR IS A GUESS]] shape one level
up: **a comment vouching for absent code, and a paper vouching for an absent property, fail identically** — both
read as evidence, both are unchecked prose, and **both are most convincing exactly where they are wrong.**

**A promise with no gate reads exactly like a promise that is kept**, because everything it is measured against
agrees with it.

## THE RENDER-FLOOR AUDIT MUST READ THE SPEC'S SEMANTICS, NOT JUST CONFIRM AN ENDPOINT EXISTS (2026-08-01, S14.3)

**The "Site-Link Throughput" chart is not merely unbacked. `openapi.yaml` describes the field it would draw as:**

> *"Raw gauge since the last handshake **(display only, never summed as monotonic)**."*

**The endpoint EXISTS. The field EXISTS. The spec FORBIDS the use.** A render-floor audit that asks only *"does
an endpoint supply this?"* returns **yes** and lets the chart through.

**THE RULE. THREE QUESTIONS, NOT ONE:** does the data exist · **does its own description permit this reading** ·
and does the render survive absence (a failed load must show the retry, **never an empty axis**; zero data must
say *"no data"*, **never a flat line at zero**).

**THE UNBACKED CASE IS THE EASY ONE.** Nothing to point at, so the audit catches it. **The hard case is a real
field used in a way its definition rules out** — the audit's own evidence argues *for* the chart. That is why
both known violations in this repo are charts, and why `VizSource` is a REQUIRED PROP: **a chart that does not
name its source does not typecheck**, which moves the question from "did anyone check?" to "does it build?".

## A MISSING PRIMITIVE COUPLES **EVERY** TEST LAYER TO MARKUP — AND LIFTING THE WORKAROUND IN ONE LAYER LEAVES THE OTHERS (2026-08-01, S14.3; widened after shipping)

**Measured: ZERO `<table>` elements in the entire web app. Thirty-seven `.map()` calls rendered `<div>` rows.**

**THE SHARED ROOT: with no `<table>` anywhere, there was NO ROLE TO ASK FOR.** Query rule 1 binds the project
to role + accessible name, and `role="table"` / `row` / `cell` did not exist. So **every** layer that needed to
identify a row invented its own workaround — **independently, and none of them could see the others doing it.**

| layer | the workaround it invented | why it looked fine |
|---|---|---|
| **unit tier** (vitest) | `getByText("old-laptop")` — matching row content as **free text** | passes; reads like a normal query |
| **e2e specs** (Playwright) | `page.locator("main ul > li")`, `locator("li", { hasText })` — **DOM structure** | passes; reads like a normal locator |

**THE PART THAT WAS LEARNED BY SHIPPING.** This law was first minted from the unit tier alone. Slice A
converted three screens, re-pointed the unit tier at roles, ran `make web-gate` **green** — **and CI's `e2e`
job went red**, because the Playwright specs were coupled for the *same* reason and had not been touched.
**Lifting the workaround in one layer left the other, and the one left behind was the one the local gate does
not run.**

### THE DIAGNOSTIC — enumerate, do not read

> **WHEN A PRIMITIVE LANDS, ENUMERATE EVERY CONSUMER ACROSS EVERY TEST TIER BEFORE DECLARING IT LANDED.**

**Reading is not enough, and the reason is precise:**

- **reading one tier** shows queries that **work** — they pass, so nothing draws the eye;
- **reading the components** shows markup that **renders** — it looks correct, because it is;
- **only the ENUMERATION** shows the workaround — because a workaround is only visible as *the gap between what
  a layer asks for and what it could have asked for*, and that gap exists in neither artifact alone.

**A primitive that ships while ANY consumer keeps the workaround has only half landed** — and the half left
behind is invisible from both of the places you would naturally look.

## ⑦ THE SEVENTH VACUITY MECHANISM — **AN UNCHECKED CLAIM** (minted 2026-08-01, S14.1 → S14.3)

> ## **A PROMISE WITH NO GATE READS EXACTLY LIKE A PROMISE THAT IS KEPT, BECAUSE EVERYTHING IT IS MEASURED AGAINST AGREES WITH IT.**

**THE OTHER SIX ASK WHETHER A CHECK COULD FAIL. THIS ONE ASKS WHETHER A CLAIM IS CHECKED AT ALL** — and that
is why none of the other six can see it. Every existing member starts from a check and interrogates it. **Here
there is no check to interrogate.** The claim lives in a paper, a README, a coverage table, an interface
comment; the gates that exist are all sound; and the claim is simply **outside the set of things anything
compares.**

**THE INSTANCE.** S14.1's commit-one claimed five covered token groups — colour, typography, spacing,
radius/elevation, motion. The artifact carried **thirteen variables, all colour**. The slice shipped CI-green
with three gates, **all of them correct**:

| gate | what it compared | why it could not see the defect |
|---|---|---|
| theme completeness | each theme → `TOKEN_NAMES` | **compares themes to the names that EXIST** |
| contrast floor | colour pairs → WCAG ratios | **compares colours to colours** |
| `ok` reservation scan | source use-sites → a rule | **compares source to a rule** |

**Every gate internally consistent. Every gate aimed at what was there. None at what was promised.**

### THE DIAGNOSTIC — the question to ask of a paper, and it is one line

> **For every claim a paper makes ABOUT AN ARTIFACT, name the check that would FAIL if the claim became false.**
> **If there is none, the claim is prose.**

Prose is not worthless — but it must be **read as prose**, and a coverage table read as a guarantee is the
whole failure. **The tell is that nothing has to change for the claim to become false**: a promise nothing
measures cannot be broken, only discovered.

### THE FIX'S LOAD-BEARING PROPERTY: **`CLAIMED_COVERAGE` IS HAND-AUTHORED, NOT DERIVED**

**This is the part that does the work, and it looks like duplication.** `CLAIMED_COVERAGE` mirrors the paper by
hand. Deriving it from the scales it describes would make the census **compare the token set to itself** — it
would pass for every possible token set, including the thirteen-colour one. **That is exactly how the original
claim survived: everything that looked at it was downstream of it.**

**SAME FAMILY AS TWO EXISTING RULINGS, and the family is worth naming:** the **mirror census as a deliberate
literal** and the **D10 golden vector**. In all three, **an INDEPENDENT restatement is the mechanism** — and in
all three the instinct to "just derive it, so it can't drift" would destroy the only property that matters.
**A check must be able to DISAGREE with the thing it checks. Derivation removes that ability while looking
like rigour.**

## THE `?raw` ESCAPE WAS LUCK, NOT DESIGN — AND RECORDING IT AS DESIGN WOULD TEACH THE WRONG LESSON (2026-08-01, S14.3)

**`import css from "…/tokens.css?raw"` returns an EMPTY STRING under vitest** — CSS processing is off by
default and the raw query is swallowed with it. The coverage census read `""` and went red.

**IT WENT RED ONLY BECAUSE EVERY COVERAGE ASSERTION IS A LOWER BOUND** (`0 >= 13` is false). **Had one been an
"and nothing unexpected" check — a set difference, a "no extra variables", an exact-match — an empty string
would have satisfied it PERFECTLY**, and the census would have certified an artifact it never read.

**THAT WAS LUCK.** The assertions were written as lower bounds because lower bounds fit the question, not
because anyone had considered an empty artifact. **The guard that asserts the artifact is non-trivial is what
converts the luck into a property** — after it, the direction of the assertions stops mattering.

**THE RULE, and it is about the write-up as much as the code: A LUCKY ESCAPE RECORDED AS A DESIGNED ONE TEACHES
THE WRONG LESSON.** It says *"our assertions are robust"* when the truth is *"our assertions happened to point
the safe way this time."* The first invites the next author to rely on a property nobody built. **Name which
one it was.**

**GENERALLY: AN EMPTY FIXTURE SATISFIES EVERY UNIVERSAL CLAIM.** `every`, `all`, set-difference, "none of these
appear", exact-match against an empty expectation — **all pass on nothing.** Any check reading an external
artifact needs a **non-triviality assertion on the artifact itself**, and it belongs beside the check, not in
the author's head.

## NAME A GATE WITH ITS COMPOSITION, ALWAYS — A PHRASE MUST NOT CARRY MORE WEIGHT THAN ITS TARGET (2026-08-01, founder-ruled)

> ## **`make web-gate` (typecheck + vitest + build — NOT Playwright; e2e runs in CI only)**

**That parenthetical is MANDATORY wherever the target is named**, in papers, commit messages and reports, and
it was **applied retroactively** to the S14.1 / S14.2 / S14.3 papers rather than only going forward.

**THE INSTANCE.** Slice A was reported as *"`make web-gate` GREEN"* — true — and was **broken**, because
`e2e` is not in it. Three Playwright specs selected rows by DOM structure and died the moment the lists became
tables. **The claim was accurate and the sentence was not**, because "the gate" sounds total and the target is
partial.

**THIS PROJECT HAS A DOCUMENTED HISTORY OF EXACTLY THIS CLASS, and the members should be read together:**

| phrase | what it sounds like | what it actually is |
|---|---|---|
| *"CI is green"* | everything ran and passed | **[[CI GREEN BY ABSENCE]]** — a job that never fired reports nothing, and nothing looks like success |
| *"`generate-check` guards the artifacts"* | tampering is detected | **it protects the SOURCE↔ARTIFACT RELATIONSHIP** — a hand-edit is regenerated away and the check goes green |
| *"`mutate.sh` printed `Restoring`"* | the file is back | **restoration is from the BACKUP**, and only the target file — a generated artifact stays mutated |
| *"`make web-gate` passed"* | the web surface is gated | **typecheck + vitest + build. NOT Playwright.** |

**THE RULE. A GATE'S NAME IS A CLAIM ABOUT COVERAGE, AND AN UNQUALIFIED NAME OVERSTATES IT** — not through
dishonesty but through **compression**: the short form survives into summaries, handoffs and re-entry, while
the composition stays behind in the Makefile. **The parenthetical travels; the Makefile does not.**

**AND THE COST IS ASYMMETRIC.** Overstating coverage produces confident wrong decisions — *"the gate passed,
ship it"*. Stating it precisely costs eight words.

## AN OFF-BY-ONE THAT RESEMBLES A PLAUSIBLE PRODUCT DEFECT COSTS MORE TO DIAGNOSE THAN ONE THAT LOOKS ABSURD (2026-08-01, S14.3)

**THE INSTANCE.** Re-pointing `audit.spec.ts` from `main ul > li` to `getByRole("row")` changed what "a row"
means: **`role="row"` INCLUDES THE HEADER.** Both counts needed `+1` (50 → 51, 53 → 54).

**The second one was nearly missed — and it would have failed IN THE SAFE-LOOKING DIRECTION.** That spec
asserts keyset paging stitches 53 events with **no overlap and no gap**. A count of 53-where-54-is-expected
does not read as *"the test counts the header now"*. **It reads as a re-served or dropped row — a paging bug**,
which is a real defect this suite exists to catch, in a subsystem where such bugs genuinely occur.

**THE RULE. THE DANGEROUS FAILURE IS THE ONE THAT LOOKS LIKE A BUG YOU BELIEVE IN.** An absurd red (`expected
54, got 0`) is diagnosed in seconds. A **plausible** red sends someone into the paging logic — the code that is
correct — and the longer they look, the more likely they are to "fix" it there.

**SIBLING OF THE MEASUREMENT-ERROR LAW: a plausible finding is more dangerous than nonsense.** Same shape, one
domain over: **nonsense is self-announcing; plausibility is camouflage.** So when a query's *semantics* change
under a refactor — what counts as a row, a cell, a match — **state the new convention IN the assertion**, so
the next red is read as a convention question rather than a product one.

# ⑨ ONE-SIDED OBSERVATION (minted 2026-08-02, S14.5 — founder-filed as the family's cleanest form)

> ## **A TEST THAT ONLY EVER OBSERVES ONE VALUE OF A TWO-VALUED THING CANNOT TELL THE VARIABLE FROM THE CONSTANT.**

**IT IS NOT WRONG. IT IS HALF-WRITTEN — which is why it survives review and why it survived a mutation round.**

## The instance

`NodeLink` gained a selection with `aria-pressed={isSel}`. The test rendered a node, asserted
`aria-pressed === "false"`, clicked it, and asserted the handler fired. **Green, and it looked complete.**

**MUTATION: hard-code the attribute to `false`** — deleting the selection state from the announcement
entirely, so no assistive technology could ever learn which node is selected.

**THE TEST PASSED.** `false` is exactly what it expected. It had never once observed `true`, so the constant
and the variable were indistinguishable to it.

## ⛔ THE DIAGNOSTIC

> **FOR EVERY BOOLEAN OR ENUM ASSERTION: DOES THE TEST OBSERVE *BOTH* STATES? IF IT ONLY EVER SEES ONE, IT IS
> ASSERTING A CONSTANT.**

**EXPECT THIS ON THE REMAINING SCREENS.** One-sided observation is the DEFAULT SHAPE when a test is written
from a happy path: you render the common case, assert what it shows, and the other branch is never
instantiated. It takes a deliberate second render to make the assertion mean anything.

## ⚠ AND THE PART THAT MAKES IT WORSE THAN IT LOOKS

**IT CAUGHT ITSELF ONLY BECAUSE THE MUTATION HAPPENED TO TARGET THE CONSTANT SIDE.**

A mutation that changed the **true** branch — `aria-pressed={isSel ? undefined : false}`, or inverting to
`aria-pressed={!isSel}` — **would ALSO have passed**, for the same reason. So the mutation round did not
demonstrate that the technique finds this class. **It demonstrated one lucky hit.** A one-sided test has a
one-sided blind spot, and a single mutation samples one side of it.

**COROLLARY, and the reason this is filed rather than fixed-and-forgotten: MUTATION TESTING INHERITS THE
TEST'S BLIND SPOT.** Mutating a branch that the test never instantiates cannot fail. **"The mutation was
caught" is evidence about the mutation, not about the test's coverage of the other state.**

# ⑧ THE SUBJECT AND ITS CHECK VANISHING TOGETHER (minted 2026-08-01, EPIC 14 merge)

> ## **THE OTHER SEVEN MECHANISMS ALL ASSUME THE SUBJECT IS PRESENT. THIS ONE IS THE SUBJECT AND ITS GUARD DISAPPEARING IN THE SAME MOVE, SO NOTHING REMAINS TO DISAGREE.**

**FILED ABOVE THE REST OF ITS FAMILY. It is the sharpest instance this project has produced.**

**THE INSTANCE.** Rebuilding `story/S14.2-layout-shell` on the new `main` meant cherry-picking its own commits.
The sequence **reported success**. **The commit count agreed.** A repo-wide conflict-marker scan was **clean**.
Every exit code was **0**.

**And 400+ lines of S14.2's product code were missing** — `ComposeGate.tsx`, `layout.ts`, the grouped `AppShell`
nav, the `Access`/`main` wiring. They had originally landed inside `1843df9`, a **merge commit that also
carried uncommitted working-tree files**; replaying only non-merge commits dropped the payload.

## WHY THIS IS NOT MERELY A VACUOUS CHECK

**Had it shipped, CI WOULD LIKELY HAVE PASSED** — because `responsivecontract.test.tsx` and `layout.test.ts`
were dropped **in the same payload**. The feature and its evidence were one commit.

**A vacuous check is a guard pointed at the wrong thing while the subject is still there to be examined.**
Every one of the other seven has that structure — a poller that samples too slowly, an assertion that waits on
a different event, a claim nothing compares, a fixture restating production. **In all of them the subject
exists and something could, in principle, notice.**

**Here there was nothing left to notice with.** The suite would have gone green over a smaller universe and
reported the same word. **Green is a statement about what ran, and a shrinking denominator is invisible in it.**

## THE DIAGNOSTIC THAT CAUGHT IT

> ### **COMPARE THE RESULT TO THE INTENT — NEVER THE PROCESS TO ITS EXIT CODE.**

`git diff --stat backup/S14.2-prerebase HEAD`. **That is what found it.** Commit counts, exit codes and marker
scans **all agreed with each other and all described the process**, not the outcome. Only an artifact-to-artifact
comparison against a known-good reference could see a hole, because **a hole has no representation in any
process signal.**

## PROCEDURAL, NOT ADVISORY

> **ANY REBASE OR REBUILD OF A BRANCH WHOSE CI IS ALREADY GREEN MUST END WITH A TREE DIFF AGAINST THE
> CI-VERIFIED TIP, ASSERTED EMPTY. TAKE THE BACKUP REF BEFORE STARTING. ALWAYS.**

```bash
git branch -f backup/<branch>-prerebase <branch>     # BEFORE anything
…                                                     # rebase / rebuild
git diff --stat backup/<branch>-prerebase HEAD        # MUST be empty
```

**The backup ref costs nothing and is the only thing that makes the assertion possible.** Without it there is
no known-good reference, and the rebuild can only be compared to itself.

## A COMMAND THAT STOPS FOR INPUT IS NOT A COMMAND THAT FAILED — AND `&&` CANNOT TELL THEM APART

**`git rebase` EXITS 0 WHEN IT STOPS ON A CONFLICT.** So `git rebase … && git push --force-with-lease …`
**pushed a branch with 1 of 6 commits replayed.**

**RECORDED AS LUCK, NOT DESIGN:** the truncated state was never consumed. Nothing read it, `main` was
untouched, and the completed rebase restored all six. **That is an outcome, not a safeguard**, and a lucky
escape written up as a designed one teaches the wrong lesson.

**REBASES RUN UNCHAINED FROM THEIR PUSH. PERMANENTLY.**

**AND NOTE THE PAIR, ONE SESSION APART AND ONE LAYER APART:**

| command | exits `0` while… |
|---|---|
| `git rebase` | **incomplete** — stopped mid-sequence awaiting a human |
| `git cherry-pick <list>` | **dropping a payload** — a merge commit's content silently skipped |

**Both are "success" by exit code. Both are only visible by comparing the RESULT to the INTENT.**

# THE FAST-FORWARD PUSH IS THE STANDARD MERGE ROUTE, AND THE REASON IS A PROPERTY WORTH KEEPING (2026-08-01)

**GitHub REFUSES the merge-commit route under `required_linear_history`:**

```
GraphQL: Merge commits are not allowed on this repository. (mergePullRequest)
```

**`gh pr merge --rebase` would work — and it REWRITES the shas**, server-side, producing commits **CI has never
seen**. The recorded green sha and the merged sha would then be different objects, and every *"CI green at
`X`"* line in every paper would refer to something that is not what landed.

**A TRUE FAST-FORWARD PUSH PRESERVES THE EXACT SHAS CI VERIFIED:**

```bash
git push origin origin/story/<branch>:main     # ff only; refused if not a descendant
```

**THE PROPERTY: the sha in the paper, the sha CI checked, and the sha on `main` are ONE OBJECT.** That is what
makes `GATE-REPORT-NEEDS-SHA` mean anything after the merge rather than only before it — and it is what let
this session detect that #44's recorded green had gone stale, because the recorded sha was still findable.

**It also cannot silently succeed on the wrong thing:** a non-descendant is **refused by git**, which is how
#45 and #46 were caught needing a rebase rather than being quietly rewritten onto the new base. **GitHub closes
the PR as MERGED on its own once the head sha becomes an ancestor of `main`.**

## A COMMENT THAT **BECAME CODE** — THE COMMENT-VOUCHING FAMILY, INVERTED (2026-08-01, S14.3 slice B)

**THE INSTANCE.** A `@ts-expect-error` directive was removed because it was unused (`TS2578`). The removal was
explained in a `//` comment that **named the directive**. **`tsc` reported `TS2578` again — on the comment.**

**TypeScript reads the TOKEN, not the sentence around it.** Writing the literal text of a suppression directive
in a line comment **creates a suppression directive**, regardless of the prose wrapped around it.

### WHY THIS IS A NEW MEMBER RATHER THAN ANOTHER INSTANCE — THE MECHANISM IS INVERTED

| | the usual shape | **this one** |
|---|---|---|
| the comment | makes a **FALSE CLAIM** about code | **BECAME code** |
| the claim | asserted by a human, unchecked | **REAL, and asserted by nobody** |
| discovered by | a mutation, or an incident | **the compiler, immediately** |

[[A COMMENT THAT ASSERTS A LIBRARY'S BEHAVIOUR IS A GUESS UNTIL A MUTATION CONFIRMS IT]] and
[[⑦ THE SEVENTH VACUITY MECHANISM]] both describe **prose that says something untrue about the system**. Here
the prose **entered the system** and said something **true that nobody meant to say**. It is the same seam —
the boundary between commentary and code — **crossed in the opposite direction.**

### THE DURABLE HALF, WHICH IS ABOUT SUPPRESSIONS GENERALLY

> ## **A STALE SUPPRESSION IS A STANDING ASSERTION THAT A TYPE ERROR EXISTS — AND IT GOES STALE IN SILENCE.**

`@ts-expect-error` claims *"the next line does not compile."* **When the underlying error is fixed, NOTHING
FAILS** in most configurations — the directive simply outlives its reason, **indefinitely**, and the next
reader takes it as evidence of a problem that no longer exists. TypeScript's `TS2578` is unusually good
behaviour here precisely *because* it makes the stale case loud; **most suppression mechanisms
(`eslint-disable`, `//nolint`, `# type: ignore`) do not.**

### THE PRACTICAL RULE

> **NEVER WRITE A DIRECTIVE'S LITERAL TEXT IN PROSE. REFER TO IT BY DESCRIPTION.**

*"the suppression directive that used to sit here"* — not the token. **A block comment is not a fix; it is a
workaround for one language's lexer.** The rule is general because the failure is: **any tool that scans
comments for magic tokens cannot distinguish an instruction from a discussion of that instruction.**

## THE GATE IS **THREE LEGS**, AND EACH ANSWERS A QUESTION THE OTHERS STRUCTURALLY CANNOT (2026-08-01, S14.3)

**`make web-gate` = `typecheck` + `vitest` + `build`. NOT Playwright; e2e runs in CI only.**

**THE `typecheck` LEG IS NOT REDUNDANT WITH THE `vitest` LEG, and this story produced THREE proofs in a row:**

| # | what `tsc` caught | what `vitest` said |
|---|---|---|
| 1 | `TS6133` — an unused import in the **primitive census** | **13 tests green**, watched pass |
| 2 | `TS2578` — the comment that **became a directive** | **347 tests green** |
| 3 | `TS6133` — an unused `vi` import | **347 tests green** |

**THE REASON IS STRUCTURAL, not a configuration accident: VITEST TRANSPILES PER FILE AND NEVER TYPECHECKS.**
esbuild strips types without checking them, so a test file can be **type-incoherent and behaviourally correct
at the same time** — and the suite reports the second while saying nothing about the first.

**AND THE CONVERSE HOLDS:** `tsc` cannot tell whether a correct-typed assertion asserts anything at all — that
is what the mutation proofs are for. **Three legs, three questions:**

- **`typecheck`** — *is it coherent?*
- **`vitest`** — *does it behave?*
- **`build`** — *does it assemble?* (and `e2e`, **in CI only** — *does it work end to end?*)

> **NAMING A COMPOSITE GATE AS ONE THING IS WHAT LET *"the gate is green"* MEAN LESS THAN IT SOUNDED.**

**Filed beside the `NOT Playwright` rule because it is the same failure one level down:** the first said the
gate omits a leg people assume is there; **this says the legs it DOES have are not interchangeable, so "some of
it passed" is not "it passed."**

## A CORRECTNESS IMPROVEMENT CAN BREAK A TEST THAT DEPENDED ON THE DEFECT (2026-08-01, S14.3 slice C)

**THE INSTANCE.** `Donut`'s `<svg>` gained an accessible `<title>` — a strict improvement, since a graphic with
no name is unannounced. **`getByLabelText("Gateway liveness")` immediately failed: *"Found multiple elements."***

**The test had been passing BECAUSE THE ACCESSIBLE NAMING WAS ABSENT.** One element carried that name only
because the other one did not carry it yet. **The query was never specific — it was unique by accident**, and
the accident was the missing accessibility.

**THE RULE.** When adding semantics breaks a query:

> ## **THE BREAK IS A SIGNAL THE QUERY WAS WEAK — NOT THAT THE IMPROVEMENT WAS WRONG.**

The reflex is to narrow the *fix* (add a `data-testid`, scope to a container, take `[0]`). **All three preserve
the weak query and discard the signal.** The right move is the one the rules already require: **query by ROLE +
accessible name** (`getByRole("figure", { name })`), which is unambiguous precisely *because* it engages the
semantics that just improved.

**WHY THIS MATTERS FOR THE WHOLE EPIC, and it is the reason this is filed rather than fixed and forgotten:**
**S14.4+ adds semantics to THIRTEEN more screens.** Every one of these breaks will look like a regression and
be **evidence of a pre-existing weak assertion**. **Expect them, welcome them, and fix the QUERY.**

**A test that breaks when the product gets more correct was testing the wrong thing** — and it was green the
entire time it was wrong, which is why nothing found it earlier.

## DORMANT MACHINERY IN OUR OWN NEW CODE, ONE SLICE AFTER MINTING THE LAW (2026-08-01, S14.2 → S14.4)

**S14.2 shipped `LayoutCapability.columns` — a 1/2/3/4 budget derived from viewport width, unit-tested,
mutation-proven, and published to the DOM as `data-columns`.**

**NOTHING CONSUMED IT.** Every screen stayed inside `max-w-3xl` — a 768px cap — so there was never any width
for a second column. **The capability was computed, asserted, and ignored.**

**THE UNCOMFORTABLE PART: this epic had already ruled on dormant machinery** (S8.4's round-3 HALT ripped out a
dormant resolver rider), **re-stated it for the viz primitives**, and **wrote it into the EPIC 14 paper as an
enforceable obligation** — and then produced a fresh instance two slices later, in code written by the same
hand that wrote the rule.

**WHY THE TESTS DID NOT CATCH IT, and this is the transferable part: the tests asserted the DECISION, and the
decision was correct.** `capabilityFor("wide").columns === 4` is true and always was. **No assertion asked
whether anything READ it.** A value can be perfectly computed and perfectly tested while being perfectly
inert.

> ## **A PRODUCER-WITHOUT-A-CONSUMER PASSES EVERY TEST OF THE PRODUCER.**

**The repo already has the standing probe for exactly this** — *"for every new channel field, name its consumer
and cite the reading line"* — minted after three producer-without-consumer instances in one epic.
**IT WAS NOT APPLIED TO UI STATE, only to the agent channel.** It applies to any value crossing any seam:
**name the consumer, cite the line, or do not ship the producer.**

## AN EDITION-GATED CAPABILITY IS A FOURTH STATE, AND FOLDING IT INTO `failed` SHOWS AN ERROR FOR A FEATURE NEVER SOLD (2026-08-01, S14.4)

**THE INSTANCE.** The Overview's *Pending approvals* card reads **`— unavailable`** in red on the **open**
edition. `/devices/pending` is enterprise-only, so it answers `403 edition_required`, `loadOne` reports a
failure, and the card renders the failure treatment.

**S14.4 carefully separated three states — `loading` / `failed` / `ok` — and then folded a FOURTH into
`failed`:**

> ### **THIS CAPABILITY DOES NOT EXIST FOR YOUR EDITION.**

**That is not a failure to learn something. It is a correct, successful answer** — and the product renders it
as breakage to the exact users who were never sold the feature.

**EPIC 14 ALREADY RULED THIS: edition gating is a RENDER decision — the surface is ABSENT, not styled away,
not degraded, and NEVER AN ERROR.** It routes through the one gating seam. The rule existed; the fourth state
was simply not noticed while building the other three.

**THE GENERAL SHAPE:** when a design carefully enumerates states, **the danger moves to the state that was not
enumerated** — and it will be absorbed by whichever existing state is nearest, which is almost never the
harmless one. **`403 edition_required` is nearest to "error" in shape and furthest from it in meaning.**

**THE CHECK: for every load, ask what a SUCCESSFUL REFUSAL looks like** — 403 by edition, 403 by permission,
404 by scope. **Each is a real answer. None of them is a failure.**

## A GATE SUITE CAN BE COMPLETE, GREEN, AND BLIND TO THE ONLY QUESTION THAT MATTERED (2026-08-01, EPIC 14, founder-ruled)

**THE INSTANCE.** Four slices of a UI redesign shipped with **388 passing tests, green CI, mutation proofs that
found three real defects, a contrast gate, a coverage census, and a drift guard** — and **did not look like the
design.**

**Every gate asked a question and answered it correctly.** *Is this correct? Is it honest? Could this check
have failed? Does the claim have a check?* **All yes.** Not one of them could ask:

> ## **DOES THIS LOOK LIKE THE THING WE ARE TRYING TO BUILD?**

**THE RULE. WHEN A DELIVERABLE HAS A PROPERTY NO AUTOMATED CHECK CAN EVALUATE, THE HUMAN REVIEW IS NOT A
COURTESY — IT IS THE GATE FOR THAT PROPERTY, AND IT IS REQUIRED.** Naming it as optional is how it gets skipped
under time pressure, and the skip is invisible because everything else is green.

**AND THE SHARPER HALF: A COMPREHENSIVE GREEN SUITE MAKES THIS FAILURE MORE LIKELY, NOT LESS.** The more gates
that pass, the more confident the report, and the more the unmeasured dimension looks like it must have been
covered by *something*. **Rigour on the measurable dimensions is not evidence about the unmeasurable ones — but
it reads exactly like it.**

**RELATED, AND THE ROOT CAUSE HERE: A SESSION-SCOPED INSTRUCTION THAT IS NEVER LIFTED BECOMES A PERMANENT ONE.**
The prohibition on reading the design file was correct for the session it was written in and wrong for every
session after. **Nothing expires an instruction; it has to be revisited.** When a later ruling *implies* an
earlier constraint should lift, **say so and ask** — a contradiction between two instructions is a fork, and
forks halt and surface.

# ⭐ AN ABSENCE FOUND BY ONE ENCODING IS NOT AN ABSENCE (2026-08-01, EPIC 14 — founder-ranked the best finding of this stretch)

**THE INSTANCE.** A design file was scanned for colours with `#[0-9a-fA-F]{6}` and the report read: **"there is
no violet anywhere."** The design's accent is `#7C5CFC`, and the founder was about to rule a correction —
re-pointing the entire token set — on the strength of that sentence.

**Two things were true and neither was what the report said:** the prototype ships **two palettes** with
**mono as the default**, so the rendered file genuinely contains no violet; and the accent, where it *is* used,
appears as **`rgba(124,92,252,…)`** — an **rgb() form a hex scan cannot match.**

**THE REPORT WAS ACCURATE ABOUT THE FILE AND WRONG AS A CLAIM ABOUT THE DESIGN.** The gap between those two is
where the damage was.

**THE RULE. AN ABSENCE FOUND BY ONE ENCODING IS NOT AN ABSENCE.** Colours are `#rgb`, `#rrggbb`, `rgb()`,
`rgba()`, `hsl()`, and named. Paths are absolute, relative, and symlinked. Versions are `v1.2.3` and `1.2.3`.
**Before reporting "X is not present", enumerate the ways X could be spelled and search for each — or report
"not found as <encoding>", which is a different and honest claim.**

**AND THE SHARPER HALF, because it is what nearly caused the damage: A NEGATIVE FINDING DRIVES BIGGER
DECISIONS THAN A POSITIVE ONE.** *"The accent is X"* invites a look. *"There is no accent"* invites a rewrite.
**Absence claims should therefore carry MORE evidence than presence claims, and habitually carry less** —
because there is nothing to point at, so there is nothing to check.

**WHAT CAUGHT IT: a second, independent artifact** — the designer's README — **saying something different.**
Not a better search. **When a measurement drives a large decision, seek a source that could DISAGREE with it**;
re-running the same query more carefully cannot.

**SECOND TIME THIS SESSION A CLAIM OF MINE WAS REFUTED BY MEASUREMENT RATHER THAN ARGUMENT** — the first was
the cherry-pick that reported success while dropping 400 lines, caught by a tree diff. **Founder-recorded as
the process working, not a setback.** Both were caught the same way: **an artifact that could disagree**, not a
more careful re-reading of the one already trusted.

## EAGER OR LAZY IS DECIDED BY WHETHER THE ABSENCE IS VISIBLE MID-RENDER — NOT BY PRECEDENT (2026-08-01, EPIC 14)

**TWO ASSET DECISIONS, ONE WEEK APART, SAME QUESTION, OPPOSITE ANSWERS:**

| asset | ruling | why |
|---|---|---|
| **Motion** (animation) | **LAZY, never critical path** | **a missing animation is INVISIBLE.** Nothing renders wrong; the page is simply still. |
| **Lucide icons** (nav) | **EAGER, must be in the initial bundle** | **a nav that renders iconless and then REFLOWS is worse than one that never had them.** The absence is visible, and then the arrival moves the page under the reader. |

> ## **THE DISCRIMINATOR: IS THE ABSENCE VISIBLE MID-RENDER?**
> **If yes, ship it eagerly. If no, defer it.**

**STATED AS A RULE SO THE NEXT ASSET IS NOT DECIDED BY PRECEDENT.** *"We lazy-loaded the last one"* is not an
argument — **the two rulings above would be inconsistent under any precedent-based reading, and they are both
correct.** Ask the question, not the history.

## A VERIFIED FACT AND A CORRECTLY TRANSCRIBED FACT ARE TWO DIFFERENT CLAIMS (2026-08-01)

**THE INSTANCE.** A Makefile override was verified with `make -n seed NET=tunnex-s141_default` — **correct, and
the output proved it.** The instruction was then written as `NET=tunnex-s141_default make seed`.

**Those are not the same command.** `NET=x make …` sets an **environment variable**, and a Makefile's
`NET := …` **overrides the environment**. `make … NET=x` is a **command-line variable**, which **overrides the
Makefile**. Opposite precedence, decided purely by which side of `make` the assignment sits on — and the wrong
form fails **silently**, using the default.

**THE VERIFICATION WAS SOUND. THE HANDOFF WAS NOT.** The check happened; its result was then restated in a form
the check never covered. **Nothing about "I verified it" is false, and the instruction was still wrong.**

**THE RULE. VERIFY THE ARTIFACT YOU ARE ABOUT TO HAND OVER, NOT THE ONE YOU HAPPENED TO RUN.** Where a command
is being given to someone else, **paste the exact string that was executed** — do not retype it, do not
normalise it, do not move a flag for readability. **The gap between "what I ran" and "what I wrote" is
invisible to every gate**, because the gate only ever saw the first one.

**SIBLING OF `APPLY-THE-DETECTOR-TO-THE-MEASUREMENT`:** there, the measurement needed checking as much as the
thing measured. **Here, the TRANSCRIPTION needs checking as much as the measurement** — it is one more link in
the chain, and it is the only link no tool observes.

## ⛔ VERIFYING IS NOT DELIVERING — AND THIS SESSION PRODUCED THREE INSTANCES (2026-08-01)

**THE THIRD AND WORST INSTANCE.** The S14.4 redesign was built, `make web-gate` ran green at **401 tests**, the
drift guard passed — **and the eight commits were never pushed.** The founder was told to review it on
localhost, pulled, and got *"Already up to date"* — **truthfully**. Docker reported
`CACHED [web build 10/10]` — **correctly**, because nothing in their clone had changed.

> ## **EVERY SIGNAL IN THE CHAIN WAS HONEST. THE ONLY FALSE STATEMENT WAS "GO AND LOOK AT IT."**

### THE FAMILY, IN ONE SESSION

| # | what was VERIFIED | what was DELIVERED | caught by |
|---|---|---|---|
| 1 | `git rebase` exited 0 | a branch with **1 of 6** commits replayed | a later tree diff |
| 2 | `make -n seed NET=…` proved the override works | the instruction written in the form that **silently ignores it** | the founder's failed run |
| 3 | **401 tests green locally** | **nothing — the commits never left the machine** | **the founder losing twenty minutes** |

**THE PROGRESSION IS THE POINT: each was caught later and cost more, and each time the verification itself was
sound.** A green gate says something true about a working tree. **It says NOTHING about whether that working
tree is reachable by anyone else.**

### THE RULE

> **BEFORE TELLING ANYONE TO LOOK AT SOMETHING, VERIFY IT FROM WHERE THEY WILL LOOK.**

Not "did it build" — **"is it where they will fetch it from"**:

```bash
git fetch origin && git rev-parse HEAD && git rev-parse origin/<branch>   # must be equal
```

**A HANDOFF IS AN ACT, NOT A CONSEQUENCE.** Building, testing, committing and pushing are four separate
things, and only the fourth makes the other three visible. **The gate cannot notice the missing one, because
the gate runs on the side where the work already is.**

## EXTENDING A FRAMEWORK'S SCALE WITH ITS OWN KEY NAMES REDEFINES EVERY EXISTING USE (2026-08-01, S14.4)

**THE INSTANCE.** The design specifies spacing in **px** — 4 · 6 · 7 · 8 · 9 · 10 · 12 · 14 · 16 · 20 · 24 —
so the token set was emitted with those numbers as keys and fed to `theme.extend.spacing`.

**Tailwind's scale is keyed in QUARTER-REMS: `4` means `1rem` (16px), `24` means `6rem` (96px).** The extension
did not ADD a scale. **It redefined the existing one**, across **128 use sites in 17 screens**:

| class | was | became |
|---|---|---|
| `p-4` | 16px | **4px** |
| `gap-12` | 48px | **12px** |
| `h-24` | 96px | **24px** |

**NOTHING FAILED.** Every class still resolved, every page still rendered, the type-checker was silent, and
**415 tests stayed green** — because no test asserts a computed size, and jsdom has no layout engine to assert
one with.

### HOW IT SURFACED — and the symptom pointed away from the cause

**A donut "was wired" and did not appear.** It was rendering at `h-24 w-24` = **24×24px instead of 96×96** —
present, correct, and a quarter the size of its own legend text. **The reported fact ("wired") and the observed
fact ("no donut") were both true**, and the gap between them was a unit.

**THE RULE. WHEN EXTENDING A DESIGN-SYSTEM SCALE, CHECK WHETHER THE KEYS COLLIDE WITH THE FRAMEWORK'S OWN.**
If they do, one of three things must happen: **namespace the new scale**, **express the design in the
framework's existing keys** (12px = `3`, 16px = `4`, 24px = `6`), or **migrate every existing use in the same
change**. Silently redefining is the only option that looks like it worked.

**AND THE DEEPER POINT: A UNIT CHANGE IS INVISIBLE TO EVERY GATE WE HAVE.** Types check names, not magnitudes.
Tests assert decisions, not pixels. The drift guard compares artifacts, not meanings.

> ## ⭐ THE STRONGEST ARGUMENT YET FOR THE HUMAN GATE, AND IT IS WORTH STATING AS ONE.
>
> **128 use sites across 17 screens silently changed magnitude. A donut rendered at a QUARTER SIZE. And:**
>
> | gate | verdict it gave |
> |---|---|
> | `tsc --noEmit` | **clean** — every class name still valid |
> | 415 vitest assertions | **green** — every decision still correct |
> | `make generate-check` | **clean** — every artifact matched its source |
> | contrast gate, coverage census, `ok`-reservation scan | **green** |
> | CI, e2e included | **green** |
>
> **Every instrument we own reported success, and the page was wrong.** The defect was found by a founder
> looking at a screenshot and saying *"the donuts are missing."*

**THIS IS NOT AN ARGUMENT FOR FEWER GATES — it is an argument about what gates are FOR.** Ours answer *is this
correct, honest, and non-vacuous?* **None of them can answer *does this look right?*, and no amount of rigour
on the first question produces evidence about the second.** The founder's localhost review is therefore a
**required gate for a dimension nothing else measures** (see the SECTION PROTOCOL), and calling it a courtesy
is how it gets skipped under time pressure — invisibly, because everything else is green.

### ⛔ AND THE SHARPER HALF — **THE EYE GATES ONLY WHAT SOMEONE HAPPENS TO LOOK AT**

**All 17 screens were mis-rendered while the override was live. ONE was being reviewed.**

**Overview had coverage because it was the section in flight. The other sixteen had NONE** — and would have
had none until their own section arrived, **possibly weeks later, by which time the cause would be buried
under dozens of unrelated commits.** The bug would then present as *"Sites has always looked a bit off"*, with
no path back to a spacing key changed in a different story.

> ## **A HUMAN GATE IS A SPOTLIGHT, NOT A FLOODLIGHT. IT PROVES THE SCREEN THAT WAS LOOKED AT AND SAYS NOTHING
> ## ABOUT THE REST — AND ITS SILENCE ABOUT THE REST IS INDISTINGUISHABLE FROM APPROVAL.**

**THIS IS THE ARGUMENT FOR THE PLAYWRIGHT VIEWPORT LEG IN ITS STRONGEST FORM.** A screenshot diff across every
screen at every breakpoint is **the only instrument that could have caught this without a human standing in
front of all seventeen.** Not types, not unit tests, not the drift guard — and not the founder, who can only
be in one place.

> ### **REGISTERED AND UNBUILT. TRIGGER ALREADY FIRED (the first screen slice, S14.4). OWED BEFORE THE EPIC
> ### CLOSES.**

**CONFINEMENT, CHECKED:** the override never reached `main` (`f9b2dfd`), so no other branch or session was
affected — the blast radius was one branch and one reviewer's time.

## `backdrop-filter` MAKES AN ANCESTOR THE CONTAINING BLOCK FOR `position: fixed` — AND jsdom CANNOT SEE IT (2026-08-01, S14.4)

**THE INSTANCE.** `Card` gained the design's glass recipe, which includes `backdrop-filter: blur(24px)`.
**Five modals across four screens render inside a `Card`.** Every one of them silently stopped being
viewport-positioned: `position: fixed` resolves against the nearest ancestor with `filter`, `transform`,
`perspective`, `will-change` **or `backdrop-filter`** — so the overlay was clipped to the card, and the card's
own body sat on top of the modal's buttons. **Clicks never landed.**

### HOW EACH LAYER OF THE GATE ANSWERED

| gate | verdict |
|---|---|
| `tsc` | **clean** |
| 422 component tests | **green** |
| a deliberate click-through of all 12 `Card` consumers | **"nothing is broken"** |
| Playwright `e2e` | ⛔ **ONE click timed out**, with a `Card` named as the intercepting element |

**THE CLICK-THROUGH WAS RUN SPECIFICALLY TO CATCH THIS, AND IT COULD NOT.** It rendered every screen and
asserted content — **jsdom has no layout engine, so a containing-block change is invisible there.** The report
was hedged correctly (*"this gates crashes and content loss; it cannot see overlap"*) and was still, in
substance, reassuring about something it had not measured.

> ## **A CORRECT CAVEAT DOES NOT MAKE AN INADEQUATE CHECK ADEQUATE. IT ONLY MAKES THE INADEQUACY HONEST.**

### THE RULE

**AN OVERLAY'S POSITION MUST NEVER DEPEND ON WHERE IN THE TREE IT IS RENDERED.** `Modal` and
`OneTimeSecretModal` now `createPortal(…, document.body)`. That is the correct fix **independently of the
cause** — the containing-block trap is one of several ways a nested overlay breaks, and the portal closes all
of them at once rather than treating this instance.

**AND THE PROPERTY WORTH REMEMBERING: ADDING A VISUAL EFFECT CHANGED A LAYOUT CONTRACT.** `backdrop-filter`
reads as decoration and behaves as positioning. **The same is true of `transform`, `filter`, `perspective` and
`will-change`** — every one of them is reached for as a visual tweak and every one silently re-parents fixed
descendants. **When adding any of them to a SHARED component, enumerate the fixed-position elements that could
end up inside it.**

## ⛔ DURING VISUAL ITERATION, REPORT CI STATE ON EVERY PUSH — EVEN WHEN IT IS "STILL RUNNING" (2026-08-01, founder-ruled)

**THE INSTANCE, AND IT IS WORSE THAN THE BUG IT HID.** Four consecutive pushes were reported as
*"`make web-gate` green, IN SYNC"* while **CI had been RED since `1307948` at 16:08Z.** The branch stayed red
for four rounds and would have been merged on the founder's word had the word not arrived with a re-check
attached.

**THE GATE-COMPOSITION RULE WAS MINTED THE SAME MORNING** — *"`make web-gate` = typecheck + vitest + build,
NOT Playwright; e2e runs in CI only"* — **and stopped being applied during the screenshot iteration.**

**WHICH IS PRECISELY WHEN IT MATTERED MOST.** Design changes break exactly what Playwright sees and the local
gate cannot: **nav labels, DOM order, click targets, containing blocks.** Of the four e2e failures, **all four**
were caused by the visual work — renamed nav links, a reordered stat card, and a modal re-parented by
`backdrop-filter`. **The local gate was green for every one of them.**

> ### **A PUSH WITH NO CI LINE IS A PUSH WITH AN UNKNOWN STATE, AND A STRING OF THEM IS HOW A BRANCH STAYS RED
> ### FOR FOUR ROUNDS.**

**THE RULE:**

- **Every push during visual iteration carries a CI line** — `green at <sha>` · `running` · `RED: <job>`.
- **If CI is red, that is the FIRST line of the report**, before anything about what was built. A red branch
  is the most important fact on the page and it must not sit under a description of new panels.
- **"Still running" is a valid and required answer.** The failure mode is silence, not uncertainty.

## THE THIRD TIME ADDING SEMANTICS BROKE A PASSING QUERY — AND IT IS NOT A COINCIDENCE (2026-08-01, EPIC 14)

| # | what was added | what broke |
|---|---|---|
| 1 | real `<table>`/`role="row"` on three screens | unit tier matching row content as **free text**; e2e selecting rows via `main ul > li` |
| 2 | an accessible `<title>` on the donut SVG | `getByLabelText` matching **two** elements |
| 3 | `role="group"` + `aria-label` on the stat card | e2e reading a value via **`xpath=preceding-sibling`** |

> ## **THE TESTS WERE COUPLED TO INCIDENTAL STRUCTURE BECAUSE THE PRODUCT HAD NO SEMANTIC STRUCTURE TO COUPLE
> ## TO.**

**Every one of those queries was the best available at the time it was written.** There was no `role="table"`
to ask for, no accessible name on the graphic, no named group around the stat — **so each test reached for
position, text, or DOM shape, and each was correct until the product acquired the thing it should have been
asking for all along.**

**THE CONSEQUENCE FOR THE TWELVE REMAINING SCREENS: EXPECT THIS EVERY TIME, AND WELCOME IT.** A query that
breaks when the product becomes more semantic **was testing the wrong thing and was green the entire time it
was wrong.** Fix the query, never the semantics — and never by narrowing to a test-id.

## ADDING A VISUAL EFFECT CAN CHANGE A LAYOUT CONTRACT (2026-08-01, S14.4)

**`backdrop-filter`, `transform`, `filter`, `perspective` and `will-change` ALL READ AS DECORATION AND BEHAVE
AS POSITIONING.** Each makes its element the containing block for `position: fixed` descendants.

**BEFORE ADDING ANY OF THEM TO A SHARED COMPONENT, ENUMERATE THE FIXED-POSITION ELEMENTS THAT COULD END UP
INSIDE IT.** For `Card` the answer was **five modals across four screens**, and nothing in the type system, the
component tier, or a deliberate click-through could see it.

**AND THE STRUCTURAL FIX BEATS THE INSTANCE FIX: AN OVERLAY'S POSITION MUST NEVER DEPEND ON WHERE IN THE TREE
IT RENDERS.** `createPortal(…, document.body)` closes the containing-block trap and every other nesting trap at
once, rather than treating the one that happened to be found.

## ⭐ THE STRONGEST FORM OF PROVE-A-GUARD-REJECTS: A GUARD THAT FIRES ON ITS OWN AUTHOR, ON LIVE INPUT (2026-08-01, S14 viewport leg)

**`PROVE-A-GUARD-REJECTS` normally means "break it deliberately and watch it go red".** That is good and it is
the weaker form: **the input is chosen by the person who already knows the answer.**

**THE STRONGER FORM HAPPENED HERE, UNPROMPTED.** `VisualGallery.tsx` was added, and the screen census failed
**by name** in the same session it was written:

```
unaccounted screens (add a wiring+failure test, or a PENDING/EXEMPT entry WITH A REASON): VisualGallery.tsx
```

**Nobody set that up.** The census caught a file its author had not yet thought about — **a real omission, on
live input, from the person who wrote the guard.** A mutation proves a guard *can* fire. **This proves it
fires when nobody is watching for it**, which is the only condition that matters in six months.

**AND THE EXEMPTION IT FORCED IS THE POINT, NOT A FORMALITY.** The census refuses a bare name; it demands a
reason, inline, as data:

> *"test fixture, build-flagged off; gated by the viewport leg and by the unshipped-route assertion"* —
> **a fixture makes no decision, so a wiring test would assert that a fixture equals itself.**

**Without the reason requirement the correct move (exempt) and the lazy move (exempt) are the same keystroke.**
The reason is what makes the two distinguishable to a reader who was not there.

## BASELINES ARE GENERATED WHERE THEY WILL BE COMPARED (2026-08-01, S14 viewport leg)

**THE TEMPTATION IS OBVIOUS: a machine is right there, and `--update-snapshots` runs in seconds.**

**THE PINNED PLAYWRIGHT IMAGE IS `linux/amd64`. EMULATED ON AN arm64 HOST, FONT RASTERISATION DIFFERS** — the
same page, the same browser build, subtly different glyph edges. A baseline rendered on the host is red in CI
on its first comparison.

> ## ⛔ **THE DANGER IS NOT THE MISMATCH. IT IS THE ESCAPE.**
>
> **A red suite nobody can explain leaves exactly one exit: widen the threshold.** And a widened threshold is a
> visual suite that has stopped meaning anything — it now passes the very class of change it was built to
> catch, and reports green while doing so.

**So the rule is about WHERE, not about care:** generate baselines in the same image, on the same architecture,
against the same stack that CI will use. Here that meant **bootstrapping them from a deliberately-failed first
CI run** and committing the artifacts, rather than producing them locally in one command.

**SAME FAMILY AS *"run the command the gate runs, from where the gate runs it."*** Both say: a check's answer
is a property of its ENVIRONMENT as much as its logic, and a result obtained somewhere else is a result about
somewhere else.

## A BUILD-TIME FLAG DELIVERED AT RUNTIME ARRIVES AFTER THE DECISION (2026-08-01, S14 viewport leg)

**THE INSTANCE.** The visual gallery is gated by `import.meta.env.VITE_VISUAL_GALLERY`. The CI job set it in
`.env` — which reaches **compose** and the **running container**, and never reaches the **image build**.

**Vite bakes `import.meta.env` into the bundle at BUILD time.** The route was dead-code-eliminated before the
variable existed. The container then started with the flag set, serving a bundle that had never contained the
route.

**IT FAILED IN THE MOST MISLEADING WAY AVAILABLE:** `toBeVisible` timed out on an element that had never been
compiled in. **Nothing said "the flag did not apply."** The symptom was a missing element, which reads as a
rendering bug, a timing bug, or a bad selector — three wrong places to look.

**THE FIX IS STRUCTURAL: a build-time flag travels as a BUILD ARG**, declared in the Dockerfile and passed
through compose, so the value is present when the decision is made.

> ## **THE RULE: FOR ANY FLAG, ASK *WHEN IS THE DECISION TAKEN?* AND DELIVER IT BEFORE THAT MOMENT.**
> **Build-time, boot-time and request-time flags look identical in a config file and are not interchangeable.**

**AND THE PROCESS POINT THAT CAUGHT IT: THE JOB WAS EXPECTED TO FAIL, AND THE FAILURE WAS STILL READ.** The
first run was *designed* to fail with *"snapshot doesn't exist"* so the baselines could be harvested. **Two of
the five failures were that. Two were this.** Had the log been skimmed for "did it fail? yes, as planned",
the broken gallery specs would have shipped with baselines harvested from a page that never rendered.

**AN EXPECTED FAILURE IS STILL A FAILURE THAT MUST BE READ.** *"It failed as predicted"* is a claim about the
REASON, not the outcome — and the reason is the only part that was predicted.

## `min-width: auto` IS WHY FLEX ROWS OVERFLOW, AND THE SYMPTOM POINTS AT THE WRONG ELEMENT (2026-08-01, S14 viewport leg)

**Flex items default to `min-width: auto`** — they refuse to shrink below their content. A single long string in
a row (an email address, a hostname, a UUID) therefore pushes the row past the viewport, and **the whole PAGE
scrolls sideways**.

**THE INSTANCE, AND THE DIAGNOSTIC ERROR IT PRODUCED.** Overview measured **65px wider than a 390px viewport**.
The first hypothesis was the panel grid — plausible: a `col-span-4` panel at 390px is ~100px and holds a 120px
donut. **The grid was collapsed responsively and the overflow stayed at EXACTLY 65px.**

> **A FIX THAT CHANGES THE NUMBER BY ZERO DID NOT ADDRESS THE CAUSE. THE CONSTANT IS THE EVIDENCE.**

The real source was the **shell header** — an untruncated email in a flex row. It was identifiable in one step
from a fact already in hand: **the gallery passed at 390 and renders OUTSIDE `AppShell`; Overview failed and
renders inside it.** The difference between the passing and failing surface was the shell, not the page.

**THE RULE, PRACTICAL:** any flex row containing user-supplied text needs **`min-w-0` on the shrinking child
and `truncate` on the text**. Absent both, the row's width is set by its longest content forever, and nothing
in the styling says so.

**AND THE DIAGNOSTIC RULE, WHICH IS THE TRANSFERABLE PART: WHEN A FIX LEAVES A MEASURED NUMBER UNCHANGED,
THE HYPOTHESIS IS WRONG — NOT INSUFFICIENT.** The temptation is to add a second fix on top of the first. **The
measurement was already telling us the first fix addressed nothing.**

## FREEZING THE CLOCK FIXES A VARIABLE *NOW*. IT DOES NOTHING ABOUT VARIABLE *DATA*. (2026-08-01, S14 viewport leg)

**THE INSTANCE.** The viewport leg's determinism plan named `relativeAge` — *"3s ago" / "12m ago"* — as the
largest source of false diffs, and prescribed **freezing the browser clock**. That was implemented, and the
Overview snapshot still diverged by **118 pixels** on the next run.

**BECAUSE THE VARIABLE WAS NEVER `Date.now()`. IT WAS `created_at`.** The seed writes its audit rows at SEED
time, which differs every CI run. `frozen_now − varying_created_at` varies, so *"2m ago"* becomes *"5m ago"*
and the image diverges forever.

> ## **A RELATIVE VALUE HAS TWO OPERANDS. PINNING ONE PINS NOTHING.**

**THE FIX AND THE ANTI-FIX, because the wrong one is easier and looks reasonable:**

| | |
|---|---|
| ❌ **`maxDiffPixelRatio: 0.01`** | passes this diff **and every real regression smaller than it**. A threshold is how a visual suite stops meaning anything, and it is the move a red-nobody-can-explain always invites. |
| ✅ **`mask: [page.locator("[data-volatile]")]`** | excludes a **named** region. The snapshot covers LAYOUT; the timestamp VALUE is unit-tested in `relativeAge`. |

**THE DISTINCTION THAT MATTERS: A MASK IS DECLARED IN THE MARKUP AND VISIBLE IN THE IMAGE; A THRESHOLD IS A
NUMBER IN A CONFIG THAT SILENTLY COVERS EVERYTHING.** One says *"this region is not asserted"*; the other says
*"some unspecified amount of anything may change"*. **Both reduce coverage. Only one tells you where.**

**GENERALLY: BEFORE ADDING TOLERANCE, ASK WHAT IS ACTUALLY VARYING AND EXCLUDE THAT.** Tolerance is what gets
reached for when the answer is unknown — and the cost of not knowing is paid by every future regression that
fits under the number.

## MASK WHAT CANNOT BE DETERMINISTIC. **WAIT** FOR WHAT HAS MERELY NOT SETTLED. (2026-08-02, S14 viewport leg)

**TWO VISUAL DIFFS, ONE AFTER THE OTHER, THAT LOOKED IDENTICAL AND NEEDED OPPOSITE FIXES.**

| diff | cause | correct fix |
|---|---|---|
| 118 px, scattered | `relativeAge` over a `created_at` written at SEED time — **varies every run, forever** | **MASK** — it cannot be made deterministic |
| 621 px, one 40px band | `HealthStatus` renders `checking…` then `operational` when `/healthz` answers — **the shot raced the transition** | **WAIT** — the settled state is perfectly deterministic |

**HAD THE SECOND BEEN MASKED — the reflex, since the first one was — A REAL SURFACE WOULD HAVE BEEN EXCLUDED
FROM THE SNAPSHOT PERMANENTLY**, and the control-plane health indicator would never again have been visually
asserted. **The suite would have kept its green and quietly stopped covering a thing it was built to cover.**

> ## **A COMPONENT THAT *CHANGES* IS NOT A COMPONENT THAT IS *VOLATILE*.**

**THE DIAGNOSTIC THAT SEPARATED THEM: LOCALISE THE DIFF BEFORE EXPLAINING IT.** Decoding the diff PNG and
counting changed pixels per row put the entire 621 in `y 921–960` — one band, one component. **A scattered
diff and a banded diff have different causes, and the pixel positions say which** before any hypothesis is
formed. Guessing from "it changed again" would have produced a second mask.

**AND THE COST ASYMMETRY IS WHY THE DEFAULT MUST BE `WAIT`:** an unnecessary wait costs milliseconds; an
unnecessary mask costs a permanently unasserted region that nothing will ever flag.

## ⚠ CORRECTION TO THE ROW ABOVE (2026-08-02) — THE WAIT DID NOT FIX THE 621

**The table claims `WAIT` was the correct fix for the 621 px band. IT WAS NOT, and the entry is left standing
with this correction rather than quietly edited, because the correction is the more useful artifact.**

The wait was added. **The next run diffed by 621 pixels again — the same number.** By the law two sections
down (*when a fix leaves a measured number unchanged, the hypothesis is wrong*), the race was never the
cause. Confirmed by isolating the variable: the app was **byte-identical** between the run the baseline was
harvested from and the run that rejected it. **Only docs and `.png` files moved. So it was run-to-run
variance in rendering, not a transition being caught mid-flight.**

**WHAT SURVIVES OF THE LAW:** the mask-versus-wait *distinction* is sound and the diagnostic (*localise the
diff before explaining it*) is what produced every correct call in this arc. **WHAT DOES NOT SURVIVE:** the
claim that the 621 was diagnosed and fixed. It was diagnosed twice, plausibly, and wrongly both times.

> **A LAW MINTED FROM A FIX THAT WAS NEVER RE-MEASURED IS A HYPOTHESIS WEARING A LAW'S TYPOGRAPHY.**

**The disposition was to remove the subject, not to keep explaining it** — see the law below.

# ⭐ A VISUAL SUITE'S SUBJECT SHOULD BE THE SURFACE WHOSE OUTPUT IS DETERMINED BY CODE, NOT BY DATA

**(2026-08-02, EPIC 14 viewport leg — founder-ruled after seven rounds, and the leg's most durable output.)**

**THE GALLERY RENDERS FIXTURES. A SCREEN RENDERS A LIVE CONTROL PLANE:** panels that resolve in whatever
order the API answers, rows stamped at seed time, health that arrives when `/healthz` arrives. **That is
where the product is interesting and where a pixel diff is LEAST able to say anything.**

Measured, over seven rounds of the same instrument:

| subject | behaviour |
|---|---|
| `gallery-1440` / `gallery-390` (fixtures) | **stable across all 7 rounds** |
| `overview-1440` (live control plane) | **621 px different across runs of IDENTICAL app code** |
| `overview-390` (same code path) | passed twice — **luck, not a property** |

**Keeping the 390 baseline because it happened to pass was considered and REJECTED.** It is the same code
path that flakes at 1440. **Two passes is an absence of evidence of flake, not evidence of determinism** —
the same shape as the absence law near the top of this file.

## ⛔ THE COROLLARY, WHICH IS THE PART THAT ACTUALLY DECIDED IT

**A suite earns its subjects. Count what each instrument has PAID.**

| instrument | pre-existing `main` defects found |
|---|---|
| geometric assertion (`scrollWidth` vs `clientWidth`) | **1** — a 65px header overflow at 390, on every screen since S14.2 |
| a human reading a harvested image | **1** — the drawer `Menu` button sitting on top of the page `<h1>` |
| a strict-mode locator violation | **1** — the control-plane health indicator rendering twice on Overview |
| **the full-page pixel diff of a live screen** | **0, in six rounds** |

> ## **SCOPE THE SUITE TO WHAT HAS PAID, NOT TO WHAT LOOKS COMPREHENSIVE.**

**The honest answer to persistent variance is often a SMALLER SUBJECT, not more determinism work.** Every
round spent chasing the 621 was a round not spent on the screens the instrument had already proven it could
protect — and the three findings above all arrived by other means while the pixel diff was being debugged.

**⚠ AND THE COST OF THE REDUCTION, STATED RATHER THAN GLOSSED:** the `Menu`-over-`<h1>` overlap had been
**committed into the `overview-390` baseline** — frozen, visible, written down. Dropping that baseline means
**the defect is now registered in prose only, and no artifact holds it.** Reducing scope removed real
coverage. That is the correct trade here, and it is not a free one.

# ⭐ A GUARD CAN CONTAIN THE CLASS IT GUARDS AGAINST (2026-08-02, S14.5 — the sweep's headline)

**THE ABSENCE-BY-ONE-ENCODING LAW, APPLIED TO A GUARD RATHER THAN TO A SEARCH.**

`ENTERPRISE_PATHS` exists because the edition-vs-failure defect was fixed at one call site and was still live
two cards over. The lesson taken was *only an enumeration finds the rest*, and a census was built to hold the
enumeration to the spec. **That census then walked past three genuinely enterprise-gated endpoints for a
regex detail:**

```
/summary:.*\(enterprise\)/i          ← the word ALONE inside its parentheses
```

```
"Approve a pending device (peer + grants land org-wide within seconds, enterprise)"
"Reject a pending device (revoked, tunnel address freed, enterprise)"
"Self-report device posture facts (owner only; server evaluates, enterprise)"
```

All three call `deviceApprovalEditionRequired()` or gate on `deviceHealthEnabled`. **The gate existed on the
server. The client did not know about it, and the instrument whose entire job was to notice reported clean.**

> ## **THE INSTRUMENT BUILT TO STOP THE CLASS HAD THE CLASS INSIDE IT.**

## ⛔ THE TRADE, AND WHY IT IS NOT SYMMETRIC

Widening to `\benterprise\b` admits false positives — a path named that is not really gated.

| error | what it costs |
|---|---|
| **false positive** | a RED naming a path. **Visible, cheap, and self-correcting** — someone reads the name and removes it. |
| **false negative** | **nothing at all.** The census stays green, the endpoint stays unregistered, and the defect ships. |

> ## **A GUARD TUNED FOR PRECISION OVER RECALL IS TUNED FOR SILENCE.**

**So a census's regex is a SAFETY setting, not a style choice.** When in doubt, match more: the noise is
reviewable and the silence is not.

# ⭐ AN ASSERTION DERIVED FROM THE IMPLEMENTATION — *fixture-restates-production, one level up* (2026-08-02, S14.5)

> ## **A TEST IS ONLY EVIDENCE ABOUT THE PRODUCT WHEN THE RULE IT ENCODES CAME FROM THE PRODUCT. THIS ONE CAME FROM THE PAGE IT WAS TESTING.**

**THE KNOWN MECHANISM is a FIXTURE that restates production, so the test compares production to itself. This
is one level up: THE ASSERTION ITSELF is derived from the implementation.**

`sitesview.test.ts` asserted:

```ts
const g = siteGate({ role: "owner", emailVerified: true, edition: "open" });
expect(g.canView).toBe(false);          // ← the client-invented rule, pinned
```

The server says the site model is **all-editions core (D11)**, three times, and gates none of it. **So the
suite was not missing a test. It was holding the WRONG RULE IN PLACE, confidently, with a green tick.**

## ⛔ WHY THIS IS WORSE THAN NO TEST AT ALL

**AN ABSENT TEST INVITES SCRUTINY. A WRONG-BUT-CONFIDENT TEST FORECLOSES IT.**

Anyone who opened that file to ask *"is the upsell intentional?"* found an explicit, named, passing assertion
saying yes. **The test did not merely fail to catch the defect — it actively defended it**, and it would have
gone on doing so through every future review of that screen.

**THE DIAGNOSTIC: FOR ANY ASSERTION ABOUT A RULE, NAME THE RULE'S SOURCE.** A spec line, a handler, a
migration, a founder ruling. **If the only place the rule exists is the code under test, the test is a mirror.**

# ⭐ THE INVERSE PAIR — the diagnostic for every remaining screen (2026-08-02, S14.5)

**TWO DEFECTS, ONE ROOT, OPPOSITE SIGNS. Both were found in the same sweep and neither was findable alone.**

| | direction | symptom |
|---|---|---|
| **Sites** | the client **INVENTED** a boundary the server does not have | an **upsell** for a shipped capability |
| **`ENTERPRISE_PATHS`** | the client **MISSED** a boundary the server does have | a `403` rendered as a **failure** |

> ## **NEITHER DIRECTION IS FINDABLE FROM INSIDE THE CLIENT ALONE.**

A client-side edition branch looks equally deliberate whether or not a server gate stands behind it. **The
only way to tell is to read the other side** — which is why this sweep had to open `site_handlers.go` and
`device_posture_handlers.go`, not merely grep for `edition ===`.

**COROLLARY: the census cannot see either.** A hand-written branch never passes through the seam, so the
enumeration that guards the seam is structurally blind to it. **`grep` for the branches; read the handlers
for the truth; the census only keeps the registered set honest.**

# ⭐ THE MORE A VIEW EXISTS TO SURFACE A PROBLEM, THE MORE DANGEROUS ITS EMPTY STATE IS (2026-08-02, S14.5)

**Founder-filed as `loadOne`'s sharpest instance since the SSO panel.**

The cross-site DNS view exists for ONE reason: to show that a zone resolves differently depending on the
site (`409 dns_domain_conflict` — one zone maps to one resolver ORG-WIDE). It is built from an **N+1**, one
`listSiteDNSForwards` per site.

**A SINGLE FAILED FETCH SHORTENS THE LIST. AND A SHORT LIST ON A CONFLICT VIEW READS AS "NO CONFLICT."**

The failure lands as reassurance **aimed precisely at the thing the view was built to reveal** — and the
missing site is exactly where the other half of a conflicting pair would live.

## ⛔ THE SHAPE, WHICH GENERALISES

> ## **AN EMPTY STATE IS READ AS AN ANSWER TO THE VIEW'S PURPOSE. THE STRONGER THAT PURPOSE, THE MORE
> ## CONFIDENTLY A FAILURE GETS READ AS GOOD NEWS.**

An empty **device list** reads as "no devices" — mildly wrong. An empty **conflict list**, an empty
**pending-approvals queue**, an empty **needs-attention panel**, an empty **failed-login log** all read as
**"you are fine"**. Same defect, escalating consequence, and the escalation tracks how much the operator
WANTS the empty answer.

**THE MECHANISM: `mergeOrgForwards` returns `conflictsAreComplete`, and the panel may not print a clean
verdict while it is false.** Two claims, kept apart by construction:

| claim | when |
|---|---|
| **nothing was found** | always sayable |
| **nothing is there** | only when every source answered |

**AND THE BANNER RENDERS ABOVE THE ROWS IT QUALIFIES, NOT BELOW.** Beneath them it is read after the list
has already been believed.

**THE DIAGNOSTIC, for every remaining screen: ASK WHAT THIS PANEL'S EMPTY STATE WOULD MEAN TO SOMEONE WHO
WANTS GOOD NEWS. If the answer is "all clear", the empty and the failed states must be visibly different,
and partial reads must say so.**

## SIBLING, and the reason both are worth stating together

**`DataTable`'s required `failed` prop** solves this for ONE source: empty and failed cannot be conflated
because the type will not let you. **This is the N-source version** — every source individually succeeded or
failed, and the aggregate needs its own honesty field, because no single call's `failed` flag describes the
whole.

# ⭐ ABSENCE OF A RELATIONSHIP IS DRAWN AS ABSENCE OF AN EDGE — the render-floor rule, applied to a GRAPH (2026-08-02, S14.5)

> ## **A DRAWN EDGE IN A FAILURE COLOUR CLAIMS A LINK WAS ATTEMPTED AND FAILED.**
> ## **THAT IS A DIFFERENT FACT FROM NO LINK EXISTING, AND ONLY ONE OF THEM IS A FAULT.**

The site mesh draws one node per site. A site with **no gateway bound** has no site-link at all — nothing has
been attempted, nothing is broken, the operator simply has not bound a gateway yet.

**THE TEMPTING RENDERING IS A RED OR DASHED EDGE**, because it is the more informative-looking one: it fills
the diagram, it distinguishes that site from a healthy one, and it *looks* like the UI is telling you
something. **It is telling you something false.** It puts an unconfigured site in the same visual class as a
site whose tunnel is down, and sends an operator to debug a link that was never created.

**THE HONEST RENDERING OF ABSENCE IS ABSENCE.** No edge.

## ⛔ WHY THIS WILL RECUR, AND IN WHICH DIRECTION

**EVERY REMAINING DIAGRAM FACES THE SAME CHOICE**, and the failure tone is *always* the more informative-looking
option:

| diagram | the absence | the tempting lie |
|---|---|---|
| access-flow (source → destination) | no rule connects them | a red "denied" edge |
| address-space map | a range nobody has claimed | a "free" cell styled like a rejected one |
| device fabric | a device that never enrolled | an offline spoke |
| K8s service graph | a service with no backing endpoints | an unhealthy link |

**In every row the honest rendering is quieter, and quiet reads as "the diagram is incomplete".** That
pressure is the whole reason this needs to be a law rather than a preference.

**THE DIAGNOSTIC: FOR EVERY EDGE YOU ARE ABOUT TO DRAW, ASK WHETHER THE SYSTEM EVER TRIED.** If it never
tried, there is nothing to colour.

**SIBLING:** the gap bin in `Histogram` — a window the agent did not observe is drawn as a GAP, never as a
zero-height bar. Same rule, one dimension down: *we did not see* and *there were none* draw identically
unless you make them not.

# ⚠ WHEN ONE RULE REQUIRES REWRITING THE EXPRESSION OF ANOTHER (2026-08-02, S14.5 — one line, but the only case so far)

**THE EM-DASH SWEEP HIT THE BANNED GLYPH ITSELF.** `hubsetview` rendered `"—"` as the placeholder for an
absent metric — deliberately, under the honesty rule (*a member that is NOT reporting shows absent, NEVER
`0`*). The COPY rule bans the em-dash as a placeholder glyph outright. **Both rules were right and they
collided inside a single character.**

**RESOLVED TO `n/a`, and the second reason is the better one:** an em-dash is not *read* as "we have no value"
by anyone who has not been told that it means that. It reads as a dash, as a minus, or as **nothing at all**
to a screen reader. **The honesty rule was not weakened by the copy rule — it was expressed better because of
it.**

**Recorded because it is the only instance so far where following one rule required rewriting how another one
was expressed**, and the reflex in that moment is to claim an exemption for the older rule.

# ⭐ AN APPROVAL PROVES WHAT WAS LOOKED AT, UNDER THE CONDITIONS IT WAS LOOKED AT (2026-08-02, S14.5 — founder-filed on his own approval)

**`--tnx-ink-600` DOES NOT EXIST.** The Donut's `neutral` slice referenced it, so **every neutral slice has
rendered BLACK since S14.3** — on **Overview**, a screen the founder reviewed on localhost and passed.

**THE HUMAN GATE HAS THE SAME SHAPE OF BLIND SPOT AS THE AUTOMATED ONES.** A black arc segment on a
near-black panel is **not distinguishable by eye from a deliberate dark tone**. There was nothing to notice:
no error, no gap, no obviously-wrong colour — just a slice quieter than intended, on a palette full of
quiet things.

> ## **THE FOUNDER'S REVIEW IS NECESSARY AND IT IS NOT OMNISCIENT. IT PROVES WHAT WAS VISIBLE UNDER THE
> ## CONDITIONS OF LOOKING — NOT THAT THE SCREEN IS CORRECT.**

**THIS DOES NOT WEAKEN THE SECTION PROTOCOL. IT BOUNDS IT.** The human gate catches what no test can (*"it
does not look like the design"*). It cannot catch a value that is wrong in a direction the eye reads as a
choice. **The two gates fail differently, which is the whole argument for having both** — and it means a
passed review is not a reason to stop building mechanical guards for the same screen.

**MECHANISM MINTED: `test/tokenrefs.test.ts`** enumerates every `var(--tnx-*)` in `src` against the generated
token set. CSS does not error on an undefined custom property — `var()` with no fallback resolves to the
INITIAL value — so this class is silent by construction and needs an enumeration, not an eye.

# ⭐ A COMPONENT CONSTRAINED BY ITS HARNESS IS NOT A COMPONENT THAT HAS BEEN TESTED AT SIZE (2026-08-02, S14.5)

**FIXTURE-FIDELITY APPLIED TO A HARNESS — and the failure runs the OPPOSITE way from the known one.**

The known trap is a double that **OUT-capabilities** the substrate: a fake that answers what the real thing
refuses, so the test passes and production fails. **This is the inverse: the harness UNDER-capabilities it.**

Every gallery specimen renders inside `w-80` — 320px. `NodeLink` has `viewBox 200x120` and `w-full`, so its
height derives from its width:

| context | rendered height |
|---|---|
| gallery, `w-80` | **192px — tidy, correct-looking** |
| Sites, 8fr column at 1440 | **~750px, with two enormous discs floating in it** |

**AND THE DIFFERENCE IS INVISIBLE BECAUSE BOTH LOOK CORRECT.** The gallery image was not subtly wrong; it was
right, at a width no screen gives that component.

> ## **A HARNESS THAT CONSTRAINS ITS SPECIMENS TESTS THE HARNESS.**

**THE GENERAL FORM: ANY PROPERTY DERIVED FROM AVAILABLE SPACE IS UNTESTED BY A FIXED-WIDTH HARNESS** —
aspect-ratio heights, wrap points, truncation, column counts, `min-width:auto` overflow. All of them are
**functions of the container**, and a harness that pins the container pins the function's only input.

# ⭐ RECESSION IS THE HONEST ENCODING FOR A DEGRADED STATE — every diagram, from here (2026-08-02, S14.5, founder-ruled)

**I DREW THE MESH'S LINK STATES AS GREEN / AMBER / RED. THE DESIGN IS NEAR-MONOCHROME** — `linked` is light
grey, `degraded` and `down` are progressively DARKER greys separated by a dash pattern, and **only the status
dot carries a hue**. The founder's rendering was right and mine was the reflex.

> ## **A FIVE-NODE MESH WITH THREE RED EDGES READS AS AN EMERGENCY EVEN WHEN ONE SPOKE IS MERELY UNREACHABLE.**

**A failure tone SHOUTS, and shouting does not scale with the number of things in the picture.** Three reds
in a five-node diagram is a crisis; three reds in a fifty-node diagram is Tuesday — but the eye cannot tell
which it is looking at, because red does not encode proportion.

**RECESSION DOES.** A degraded edge that RETREATS stays legible at any node count: the healthy structure
remains readable, and the faults are the gaps in it. **The words in the list below carry the actual claim**,
which is where a claim belongs.

## ⛔ AND THE REASON THIS NEEDS TO BE A LAW RATHER THAN A PREFERENCE

**THE FAILURE TONE WILL ALWAYS LOOK MORE INFORMATIVE WHILE YOU ARE BUILDING IT.** A grey diagram looks
under-built; a red one looks like the UI is working hard. That pressure is constant and it points the wrong
way every time.

**SPEND COLOUR WHERE IT IS SCARCE.** One hue, on one element, means something. Three hues on every edge mean
the diagram has a palette.

**SIBLING:** *absence of a relationship is drawn as absence of an edge.* Same family — both are cases where
the quieter rendering is the true one and the louder one is a claim nobody measured.

## ⛔ COROLLARY, founder-ruled 2026-08-02: THE HARNESS IS PART OF THE SPECIMEN

**KEEP BOTH WIDTHS. THAT IS THE FINDING, NOT A COMPROMISE.**

The instinct after the 750px discovery is to *move* the gallery to full width — swapping one pinned container
for another. **`w-80` is a real context too**: it is what a card, a modal body and a right-hand rail give a
component, and defects live there as well.

> ## **NEITHER WIDTH ALONE IS THE COMPONENT. A SPECIMEN IS A COMPONENT *PLUS* THE SPACE IT WAS GIVEN.**

**MECHANISM (S14.5):** a `[data-wide-specimens]` section renders the width-sensitive primitives unconstrained,
captured as its OWN baseline — `gallery-wide-1440.png`, census 2 → 3.

**SEPARATE RATHER THAN APPENDED, and the reason is the suite's whole purpose:** appending doubles the page and
spreads any change over more pixels, **making a real regression harder to see in the image a human is meant to
read.** Every image must earn its place; one isolating the container-derived-geometry class earns it.

**1440 ONLY.** At 390 there is no wide column, so a wide specimen is the narrow one again — **it would test
nothing while costing a baseline and a re-harvest on every change.** The reason is written into the census's
expectation list itself, where someone reaching to add the 390 counterpart for symmetry will read it.

# ⭐ A LAYOUT DERIVED FROM A POPULATED EXAMPLE MUST BE CHECKED AT N=1 (2026-08-02, S14.5, founder-ruled)

**A DESIGN SHOWS EVERY DIAGRAM AT ITS MOST INTERESTING SIZE — WHICH IS THE SIZE IT WILL ALMOST NEVER HAVE ON
A CUSTOMER'S FIRST DAY.**

The wireframe's network map places **five spokes at fixed coordinates in a 600×320 frame**, and it reads
beautifully because five spokes FILL that frame. I took the frame and the ring radius verbatim.

**WITH ONE SITE IT RENDERED AS A COLUMN OF TWO CIRCLES WITH THE LEFT TWO-THIRDS OF THE PANEL EMPTY** —
because a lone spoke at −90° sits directly above the hub. **It read as a BROKEN diagram, not a sparse one**,
and that distinction is the whole finding: sparse is a fact about the customer, broken is a claim about us.

## ⛔ THE FIX IS STRUCTURAL, NOT A SPECIAL CASE

Not `if (n === 1) …`. **The frame follows the content:**

- radii **shrink** with the count (one spoke needs distance, not an orbit; two want opposite sides)
- the first spoke goes **RIGHT**, because a relationship reads left-to-right — **straight up reads as a stack**
- the **viewBox is FITTED to what was actually placed**, padded for the labels drawn beneath each ring

**So the content stops rattling inside a frame sized for a different dataset.**

## THE GENERAL FORM

> ## **EVERY LAYOUT TAKEN FROM A DESIGN IS A LAYOUT TUNED FOR THE DESIGNER'S SAMPLE DATA. THE SAMPLE IS
> ## ALWAYS THE FLATTERING CASE.**

**CHECK EVERY BORROWED LAYOUT AT: ZERO · ONE · TWO · AND FAR MORE THAN THE SAMPLE.** The design shows you
exactly one of those four, and it is never the one a new customer sees.

**SIBLING:** *the harness is part of the specimen.* Both are the same error — **reasoning about a component
from a single instance of its context** — one in width, one in cardinality.

# ⭐ WHEN A CONTROL IS MEANINGLESS AT CURRENT SCALE (2026-08-02, S14.5, founder-ruled for every screen)

> ## **RENDER THE PANEL WITH AN EMPTY STATE THAT NAMES THE PRECONDITION AND THE ACTION THAT CROSSES IT.**
> ## **NEVER THE CONTROL. NEVER DISABLED-WITHOUT-REASON. NEVER ABSENT.**

**THE INSTANCE.** *Hub high-availability* offered **`pin as primary`** beside a **single** gateway, under copy
about failing transit over to a standby if the primary goes stale. **There is nothing to fail over to.** A
control for multi-gateway transit, offered on a one-gateway stack.

## Why each alternative is wrong, in order of temptation

**NOT ABSENT.** **Scale is a state the operator MOVES THROUGH; an edition boundary is a purchase.** That is
the distinction from the four-way panel test, which says *absent* for capabilities that do not exist. HA
exists and is **one gateway away** — hiding it means they never learn it is there nor what unlocks it.

**NOT DISABLED.** A greyed control states that something is unavailable **without saying why or what to do**.
The reassuring-empty shape, in control form.

**NOT OFFERED-WITH-EXPLANATION** — which is what shipped, and it is the expensive one, because it looks the
most helpful. **It cost a real question from the founder: *"when will connectivity start?"***

## ⛔ AND THE BOUNDARY CONDITION THAT IS EASY TO GET WRONG

**AN ALREADY-CONFIGURED SET STILL RENDERS IN FULL, EVEN BELOW THE THRESHOLD.** If an org drops from two
gateways to one (a revoke), the panel must show **the hub set that is still configured** — not hide it behind
a precondition notice. **The precondition governs OFFERING the capability, never DISCLOSING existing state.**
Suppressing real configuration because a count dipped is how an operator loses track of what is live.

# ⭐ A SCREENSHOT SHOWS WHAT IS WRONG. ONLY THE SOURCE SAYS WHAT IS RIGHT. (2026-08-02, S14.5, founder-ruled)

**MEASURED COST: FOUR ROUNDS ON ONE PANEL**, plus two more after it, all on the Sites network map.

| round | what I did | outcome |
|---|---|---|
| 1 | built from the handoff markup, took its five-spoke coordinates verbatim | N=1 rendered as a column, panel two-thirds empty |
| 2 | **corrected from a screenshot** — fitted the viewBox to the nodes | whitespace gone, everything MAGNIFIED to 150px rings |
| 3 | **corrected from a screenshot** — pinned `viewBox 0 0 600 320` | scale right, 320px of near-empty panel |
| 4 | **re-opened the file**: `height: 320px` + fitted box together | correct |
| 5 | founder asked twice more; **re-opened the file** | node rows were never in the design (`sc-for extraSites`) |
| 6 | founder asked why the link does not flow; **re-opened the file** | `.tnx-edge` animation never implemented, never flagged |

**EVERY CORRECTION MADE FROM AN IMAGE WAS WRONG OR HALF-RIGHT. EVERY CORRECTION MADE FROM THE FILE WAS
RIGHT.** The source was on disk the entire time.

## Why an image cannot answer the question

**A screenshot is evidence of a DEFECT and evidence of nothing else.** It shows a symptom — too big, too
empty, missing — and every symptom has several plausible causes. Choosing among them from the picture is
guessing, and a plausible guess produces a fix that changes the symptom without touching the cause. **That is
how round 2 turned a spacing failure into a scaling failure.**

The source states the CONTRACT: `viewBox 0 0 600 320` at `height: 320px` means one user unit is one pixel.
**No amount of looking at a rendering recovers that**, because a wrong scale looks exactly like a right scale
when every shape moves together.

## ⛔ THE STANDING CORRECTION — now part of the section protocol

> **OPEN THE HANDOFF BLOCK AND DIFF IT STRUCTURALLY BEFORE WRITING THE COMPONENT — AND AGAIN BEFORE ANY
> CORRECTION. NEVER AFTER A SCREENSHOT SAYS SOMETHING IS OFF.**

**IT IS THE SAME ERROR AS BUILDING FOUR SLICES FROM A SUMMARY OF THE WIREFRAME**, one scale down: working
from a derived artifact when the original is available. The first cost four slices; this cost six rounds.

## ⚠ AND THE PART THAT IS NOT A CRITICISM OF THE LOOP (founder-ruled: keep both stories)

**THE ROUNDS FOUND REAL DEFECTS, AND THEY NEEDED FINDING:**

- **`--tnx-ink-600` does not exist** — every Donut neutral slice black since S14.3, live on `main`, on a
  screen already reviewed and passed
- **N=1 geometry** — a layout inherited from a populated example
- **the scale contract** — understood only by reading the source
- **a node wearing a `down` pill with no edge** — the map making the same claim I had told the founder the
  card was wrong to make

**THE LOOP WAS PRODUCTIVE AND THE METHOD WAS WRONG. Both are true, and recording only one of them would
teach the wrong lesson** — the fix is not to iterate less, it is to iterate against the source.

# ⭐ A LIST IS A TABLE. A DETAIL IS ONE PANEL. SELECTION IS THE LINK. (2026-08-02, S14.5 — founder-caught)

**THE DEFECT: EVERY SITE RENDERED AS A FULL CARD** — name, gateway, health, subnet chips, two collapsed
teaching accordions, four buttons. **~320px each.**

| sites | page height |
|---|---|
| 5 | 1,600px |
| 10 | 3,200px |
| 50 | unusable |

**AND THE TWO ACCORDIONS WERE STATIC TEACHING TEXT, IDENTICAL ON EVERY CARD.** *N* sites meant *N* copies
of the same paragraph.

> ## **THE PAGE'S HEIGHT GREW WITH THE NETWORK WHILE THE INFORMATION IN IT DID NOT.**

## ⛔ THE DIAGNOSTIC, AND IT IS ONE QUESTION

> **WHAT DOES THIS SCREEN LOOK LIKE AT 10× THE CURRENT DATA? AT 100×?**

**A design reviewed on a demo dataset answers it by accident and usually wrongly**, because the mock has
three rows and three rows look fine as anything. **This is the cardinality sibling of *check every borrowed
layout at N=1*** — that one catches the empty end, this one catches the full end, and a design hands you a
flattering sample in the middle so you check neither.

## THE SHAPE THAT SCALES

**ONE ROW PER ITEM, CONSTANT HEIGHT** — carrying only what you compare ACROSS items (state, owner, ranges).
**ONE DETAIL PANEL** — carrying what you only need for ONE (forms, actions, teaching text). **SELECTION is
the link**, and it is the SAME selection the diagram uses, so there is one notion of "the current site" with
two ways in.

**THE TEST FOR WHERE SOMETHING BELONGS: IS IT THE SAME ON EVERY ROW?** If yes it renders ONCE, at the panel,
never per item. Repeating identical text per row is not redundancy — **it is a page that costs more to read
the more successful the customer is.**

# ⭐ A SEMANTIC NAME SURVIVES A PALETTE SWAP; THE CONTRAST IT ASSUMED DOES NOT (2026-08-02, S14.5, founder-caught)

**EVERY PRIMARY BUTTON IN THE PRODUCT WAS WHITE TEXT ON LIGHT GREY.**

```
primary: "bg-accent-500 text-white"     // unchanged since before S14.1
--tnx-accent: #7C5CFC                   // violet — white text is fine
--tnx-accent: #C9C9C4                   // mono, S14.1 — white text is INVISIBLE
```

**The class names never changed. The token they resolve to did.** `accent` kept meaning *"the accent"*
faithfully, and the thing it pointed at moved from dark-enough-for-white-text to far too light.

> ## **A COLOUR TOKEN CARRIES A NAME AND A VALUE. RE-POINTING THE VALUE KEEPS EVERY NAME HONEST AND BREAKS
> ## EVERY PAIRING THAT DEPENDED ON THE OLD LUMINANCE.**

## ⛔ WHY NOTHING CAUGHT IT

- **`tsc`** — the class string is valid either way
- **445 tests** — jsdom resolves no custom properties, and none asserts contrast
- **the build** — Tailwind emits the class; luminance is not its concern
- **the drift guard** — the token file is generated correctly, and correctly generated is the problem
- **the gallery** — it renders the button, and a low-contrast button is still a rendered button
- **the founder's review of S14.1, S14.3 and S14.4** — a wash of light grey with faint text reads as a
  *disabled* button, which is a plausible design choice rather than an obvious fault

**IT SURVIVED A PALETTE MIGRATION, A PRIMITIVES STORY AND THREE HUMAN REVIEWS**, which is what a defect looks
like when every gate is asking a different question from the one that matters.

## THE FIX IS THE DESIGN'S OWN RECIPE, AND ITS SHAPE IS THE LESSON

`background rgba(255,255,255,.16)` · `border rgba(255,255,255,.4)` · `blur(10px)` · `color #F5F5F5`

**THE DESIGN USES A TRANSLUCENT FILL RATHER THAN A SOLID ONE PRECISELY SO THIS CANNOT HAPPEN:** a wash
composited over whatever is behind it keeps a fixed RELATIONSHIP to that backdrop, so it stays legible on the
page, on a glass panel, and on a modal. **A solid fill fixes a colour and hopes the text still works.**

**THE STANDING CHECK: WHEN A TOKEN'S VALUE MOVES, ENUMERATE EVERY FOREGROUND PAIRED WITH IT.** The pairing
lives at the call site, the value lives in the token, and nothing connects the two — so the enumeration has
to be deliberate. **Ours found exactly one text pairing (`Button`); the other two `bg-accent` uses are a logo
square and a histogram bar, and neither carries text.**


## ⛔ HUMAN GATE LIMIT LAW (founder-ratified 2026-08-02, Overview S14.5 audit) — A human gate can only catch what the data makes visible

**A HUMAN GATE CAN ONLY CATCH WHAT THE DATA MAKES VISIBLE. A DEFECT ON A CODE PATH THE REVIEW STACK NEVER RENDERS IS INVISIBLE TO ANY AMOUNT OF LOOKING.**

Neither defect on Overview was invisible because it was state-branching rather than visual. The `--tnx-ink-600` black neutral slice was a visual defect — invisible because the founder's review stack had zero devices (rendering the empty state instead of the neutral arc). `· hs n/a` required an un-reporting hub member in the fixture seed. Both were **fixture-coverage failures**, not review-modality failures.

**Actionable Precondition**: The review stack (`make seed-fixtures`) must exercise every state each redesigned screen can produce (N=0, N=1, N=many, degraded, un-reporting, pending). Pre-flight 2 applies to fixtures as a strict precondition for the human review gate: a screen review is not valid unless seed fixtures reach all states the screen can render.

## ⛔ EVIDENCE COLLECTED WITHOUT COMPARISON TO AUTHORITATIVE SOURCE (founder-ratified 2026-08-02, S14.6 audit) — Nav-audit defect shape recurrence 3

**An audit table listed a state (`ovpn_ok`) the API cannot produce, and the subsequent diagnostic turn treated the table entry as empirical evidence about the codebase without checking the source code.**

This is the nav-audit defect shape for the third time: evidence collected, not compared against authoritative source. The phantom `ovpn_ok` finding was retracted. Authoritative OpenAPI audit confirms `ovpn_health` is absent on the wire (`{}`) when healthy and normalized at the boundary via `?? null`.


## ⛔ COROLLARY — AN UNDER-CAPABILITIED DOUBLE IS DANGEROUS ONLY IF THE MISSING CAPABILITY FAILS *SILENTLY*

**Founder-raised 2026-08-02 as the harness sibling of fixture-fidelity. Measured, and the measurement
sharpens it rather than confirming it.**

Nine test suites render a page component with **no Router context**. The concern: *anything
routing-dependent was untested by construction and green.*

**MEASURED: 0 of 7 pages use `useNavigate`, `<Link>`, `useLocation`, `useParams` or `useSearchParams`.**
Nothing was being skipped. **And when the first `<Link>` was added (Devices, S14.6), five tests CRASHED
immediately** — `Cannot destructure property 'basename' of useContext(...) as it is null`.

> ## **A MISSING CAPABILITY THAT *THROWS* IS SELF-ANNOUNCING. ONE THAT SILENTLY NO-OPS IS THE TRAP.**
> ## **THE HARNESS GAP IS NOT THE RISK — THE FAILURE MODE OF THE GAP IS.**

**AND THE SILENT INSTANCE ALREADY EXISTS IN THIS REPO, one file over.** `lib/motion.ts` says it outright:
jsdom does not implement `matchMedia`, so a test asking whether reduced motion is honoured would **throw, or
— worse, if someone stubbed it carelessly — silently no-op and pass at every setting.** That is why the motion
gate is a **pure function** with the platform read at the app edge: it converts a silent-failure capability
into a value a test can pass in.

**THE DIAGNOSTIC: for every capability the harness does not provide, ask WHAT HAPPENS WHEN CODE USES IT.**
Throws → the gap is loud and self-correcting. Returns `undefined`/no-ops → **the gap is a permanent green over
untested behaviour**, and the capability must be lifted out of the component into a value.

---

## ⛔ STRENGTHENING A GUARD IS A CHANGE TO GUARD COVERAGE — three instances in ONE session (S14.8)

*Moved here from `docs/CUT-REGISTER.md`, founder-corrected. That file answers "is this in scope?" one line per
cut; the deferral register answers "when does this happen?". THIS IS A FAILURE CLASS, and the other failure
classes live here. A register that absorbs a fourth kind of entry stops being greppable, which is the reason
it was created — **the same mistake this law describes, one level up: I strengthened the record-keeping and
blinded the thing that made it work.***

> ### **STRENGTHENING A GUARD IS A CHANGE TO GUARD COVERAGE.**
> ### **AFTER CHANGING ONE, RE-MEASURE WHAT ELSE WAS WATCHING THE SAME FAILURE.**

Every instance below is a change made to make a check STRONGER that reduced coverage somewhere else. **All
three were caught by the author mid-change. None by a gate.** They are not three anecdotes; the shape repeats
because a guard's *subject* and a guard's *detection mechanism* are different things, and improving the first
can silently break the second.

| # | the strengthening | what went blind | how it was caught |
|---|---|---|---|
| 1 | `switch` + `default` → `Record<NonHealthyPolicyDegradedKind, HealthBadge>` (compile-time exhaustiveness) | **the RUNTIME fallback.** A kind the SERVER has and our generated union lacks now yielded `undefined` — **no badge at all while `policy_degraded` is true**, i.e. LESS ALARMED THAN THE BOOL | a component test asserting forward-compat |
| 2 | the SAME edit | **`TestEveryHealthKindReachesItsMirrorSurfaces`.** It detects a rendered kind by the literal `case "<kind>":`; the `Record` removed that string, so **all thirteen kinds read as unrendered** and the cross-surface census went red-then-nearly-dismissed | running the Go suite, then NOT accepting "pre-existing" |
| 3 | adding the wedge regression test | **the test itself.** A hand-built `&Service{}` left `failovers` nil, so it panicked and failed **identically with and without the fix** — a red that proved nothing | re-running the proof both ways instead of stopping at the first red |

**AND THE TWO GUARDS IN #1 AND #2 ARE BOTH NECESSARY** — the reason the class is subtle is that the
replacement really is stronger, just not at the same seam:

| guard | catches |
|---|---|
| the `Record` | a kind IN the spec with no badge — at **TS compile** time |
| the runtime `??` | a kind the **server** has that our generated union does not |
| the mirror census | a kind in the **GO ENUM** that never reached the spec at all — the compiler cannot see across that gap |

**THE CHECK, AND IT IS CHEAP:** after changing a guard, **run the other guards that name the same subject and
confirm they still REJECT — not merely that they pass.** The census passed green while reading every kind as
unrendered; **a passing guard and a blind guard are indistinguishable without a rejection probe.** This is
`PROVE-A-GUARD-REJECTS` applied to the guards you did **not** edit.


---

## CHECK THE MATCHER BEFORE THE SUBJECT, WHEN A RESULT SURPRISES YOU BY BEING CLEAN

**A LINE, NOT A LAW — but the third instance of the same sub-pattern, which is what makes it worth naming.**

S14.8: proving the verifier's arms, my filter was `grep -E "^FAIL|arm 4"`. **Arm 3 reported nothing and I read
that as "it did not fire."** It had fired — the `FAIL` prefix carries ANSI colour codes, so `^FAIL` never
matched. **A proof that reported success because its matcher missed the output.**

Same family as the magenta baseline (a fully-magenta screenshot every count agreed with) and the phantom
`ovpn_ok`: **evidence collected, not compared.** It self-corrected inside the same step, so it is a line rather
than a finding — but it is the **third time this engagement that the PROOF was wrong rather than the code**
(with A1e's false red and the narrow docker mount).

> ### **WHEN A CHECK COMES BACK CLEANER THAN EXPECTED, SUSPECT THE MATCHER BEFORE THE SUBJECT.**
> ### **A silent filter and a passing subject are the same output.**

---

## A GLOBAL WITH THE SAME NAME MAKES A MISSING IMPORT LOOK LIKE A WRONG FIELD

**S14.8.** `Kubernetes.tsx` used `Node` as a type without importing it, so TypeScript resolved it to **the DOM's
global `Node`** and reported:

```
Property 'site_id' does not exist on type 'Node'
Property 'policy_degraded_kind' does not exist on type 'Node'
```

**Both errors are TRUE, about a REAL type, and completely misleading.** Nothing in the message says a
*different* `Node` was found. The natural reading is *"our Node schema is missing those fields"* — which sends
you to the spec, the generated types and the API, all of which are correct.

> ### **THE CHECK RAN, IT MATCHED SOMETHING, AND THE SOMETHING WAS WRONG.**

Same family as the ANSI-swallowed `^FAIL` grep and the magenta baseline: **evidence collected, not compared.**
Distinct enough to name because the collision is with a GLOBAL, so there is no import to be missing from a
diff and no red anywhere — the code compiles the moment the field access is removed.

**THE COLLIDING NAMES IN THIS CODEBASE:** `Node` (schema vs DOM), `Event`, `Response`, `Request`, `Location`,
`Screen` — `Event` is the one to watch, since `AccessEvent` and audit entries live beside it.

**⚠ MEASURED, AND THE GUARD DOES NOT EXIST TO BE ADDED:** the repo has **no ESLint** (`grep -c eslint
package.json` → 0), so `no-restricted-globals` has nowhere to live. **A censused sweep of `apps/web/src` found
ZERO other instances** — every other use of these names imports its type. So this was a single occurrence, not
a pattern, and the finding is recorded rather than tooled.

**IF ESLINT IS EVER ADOPTED, THIS RULE IS THE FIRST ENTRY.** Until then the check is the sweep above, which is
cheap to re-run and is what proved the instance was isolated.

---

## A SYMPTOM HAS AXES. FIXING ONE AND REPORTING THE SYMPTOM CLOSED IS A CLAIM ABOUT THE OTHERS.

**S14.8, and the founder saw the same defect twice.** He reported *"button alignment is not correct."* I found
the action column lacked `numeric`, right-aligned it, screenshotted, and reported it fixed. It was not: the
buttons were **~36px tall against a ~20px row line under `align-top`**, so their labels still sat visibly below
the row's own text. Horizontal was one axis of two.

> ### **THE SECOND REPORT WAS AS CONFIDENT AS THE FIRST.**

**THE MECHANISM IS IN THE SECOND LOOK, NOT THE FIRST FIX.** I did screenshot after the change — and compared
it against **the edit I had made** (are the buttons right-aligned? yes) instead of against **the complaint**
(does this look aligned?). The screenshot was taken, examined, and asked the wrong question.

**THE CHECK, AND IT IS ALREADY IN USE ELSEWHERE:** after a visual fix, compare the screenshot **against the
words of the complaint**, not against the diff. That is exactly how the duplicated DNS VIP was caught one
commit earlier — that look asked *"does this read right?"* rather than *"did my edit land?"*, and it found a
defect the edit had not introduced.

**Related:** ALL-X-WITHOUT-A-DENOMINATOR and PROVE-A-GUARD-REJECTS. Same family: a check that ran, matched
something, and was asked a narrower question than the one that mattered.

---

## A DEPLOY IS CONFIRMED BY THE ARTIFACT CHANGING, NOT BY THE COMMAND EXITING ZERO

**S14.8 — the fifth "silently didn't apply", and it was caught by luck.** A deploy step ran
`make up-enterprise` from `apps/web`, which has **no Makefile**. Nothing built, nothing deployed, **no error**,
and the next screenshot would have been of the previous bundle. It was caught only because the bundle hash in
the served HTML was **unchanged from the line before**.

**THE GENERAL DEFENCE CANNOT BE A REPO FIX.** `make` walking up from a directory without a Makefile — or not,
depending on the shell and the tree — is a property of the environment, not of this codebase. There is no
`ON CONFLICT` to change and no variable to derive.

> ### **SO THE RULE IS TO VERIFY THE ARTIFACT, NOT THE COMMAND:**
> ### **A DEPLOY IS CONFIRMED BY THE SERVED BUNDLE HASH CHANGING. A COMMAND EXITING 0 CONFIRMS NOTHING.**

```bash
curl -s http://localhost/ | grep -o '/assets/index-[A-Za-z0-9_-]*\.js'   # must DIFFER from the last one
```

**`scripts/k3s-demo.sh verify` IS THE SAME PRINCIPLE, ALREADY BUILT:** it does not report success because
`docker run` exited 0 — it asks the cluster for Ready nodes and the control plane for its Service list, and
fails by name when either disagrees. **Both are instances of one rule: check the state you claim to have
produced, never the instruction you issued.**

The five instances: `NET := tunnex_default` · the never-run `round2-walk` spec · `ON CONFLICT DO NOTHING` ·
the three skipped pre-merge checks · `make` from the wrong directory.

---

## ANY DESTRUCTIVE WRITE AGAINST A SHARED DATABASE IS ORG-SCOPED OR IT DOES NOT RUN

**S14.10, twice in one session, and the second time after being told.**

```sql
DELETE FROM device_health WHERE device_id NOT IN (…);   -- scoped
UPDATE devices SET health_blocked = false;              -- ⛔ NO WHERE org_id. 124 rows, EVERY tenant.
```

**THE PATTERN IS SPECIFIC AND WORTH NAMING: THE `DELETE` GETS SCOPED AND THE `UPDATE` BESIDE IT DOES NOT.**
The delete *looks* dangerous, so it gets a predicate. The update reads as cleanup, so it gets none.

> ### **"THEY WERE ALL TEST-DEBRIS ORGS SO NOTHING OF VALUE MOVED" IS TRUE TODAY AND IS NOT THE PROPERTY**
> ### **THAT MATTERS. THE SAME COMMAND ON A PRODUCTION-SHAPED DATABASE CLEARS EVERY DEVICE'S ENFORCEMENT**
> ### **FLAG IN EVERY TENANT. THE BLAST RADIUS WAS BOUNDED BY LUCK, NOT BY THE COMMAND.**

**THE RULE:** `WHERE org_id = <the demo org>` on **every** `UPDATE` and `DELETE`, no exceptions, **including the
ones that look like cleanup.** A statement that cannot name its org does not run.

**AND BOTH RAN WITH NO APPROVAL STEP.** The broadened Bash rules — granted on *"take all required permission at
once"* — removed the confirmation prompt that would have caught an unscoped predicate. `allow_auto_merge` is
`false` and is a red herring here: it governs merges, not shell. **The Bash grant is the consequential
environment mutation, and unlike the visual job and auto-merge it has NO re-arm trigger.** Registered as such.

**The self-check, and it is one question:** before running an `UPDATE` or `DELETE`, read the `WHERE` clause
aloud. If it does not contain an org id, the statement is wrong even when its effect is harmless.

---

## A TEST CAN PIN A LABEL PRODUCTION CAN NEVER PRODUCE. ONLY THE SCREEN SAYS OTHERWISE.

**S14.10. FIVE unit reds were green against a state the schema forbids.**

I built a third posture label for a cause the spec named, wrote five assertions covering it — including one that
required all three labels be distinct — and every one passed. The label was **unreachable in production**:
`device_health.evaluated_state` is `NOT NULL` with `CHECK IN ('compliant','noncompliant')`, and the evaluator
skips an absent fact (`if f.DiskEncrypted == nil { continue }` — *"absence never blocks"*), so the state the
label described cannot be stored.

> ### **THIS IS THE FIXTURE-FIDELITY LAW INVERTED. Fixture-fidelity says a double must not be MORE capable**
> ### **than production. Here the DOUBLE WAS MORE PERMISSIVE THAN THE SUBSTRATE: a hand-built object literal**
> ### **can hold field combinations a `CHECK` constraint forbids, and unit tests never touch the constraint.**

**SECOND INSTANCE THIS SECTION.** The first was `work-laptop` — a device in the wiring mock with no seeded
counterpart, which is how 522 tests passed while the POSTURE column rendered blank.

**HOW IT WAS CAUGHT, AND IT IS THE ONLY THING THAT CAUGHT IT:** a reachability assertion on the RENDERED PAGE.

```
RENDERS      posture blocked  (1)
** ABSENT ** posture reported, fact unavailable  (0)
```

The unit tests passed. The API payload looked right. **The count of zero on the screen was the only disagreement
in the system.**

**THE CHECK:** for any NEW rendered state, assert it appears on the rendered page against seeded data BEFORE
believing the unit test. A state that cannot be produced is a state that cannot be reviewed — and under the
Human Gate Limit Law, cannot be accepted.

**AND THE CHEAPER PRIOR CHECK:** when a label's precondition is a field being ABSENT, read that column's
nullability and CHECK constraint first. `os_version NOT NULL` alone would have killed my first discriminator
before a single test was written.

---

## AN INSTRUMENT CAN BE CONFIDENTLY WRONG ABOUT ITS OWN SUBJECT — three instances

**Not "the check failed". The check RAN, MATCHED SOMETHING, and reported on the wrong thing.**

| # | instrument | what it reported | what was true |
|---|---|---|---|
| 1 | `grep -E "^FAIL\|arm 4"` over a verifier's output | arm 3 "did not fire" | it HAD fired — the `FAIL` prefix carries ANSI colour codes, so `^FAIL` never matched |
| 2 | `grep -c FAIL` over a decision table | 2 failures | zero failures. It matched the words **"FAIL-CLOSED"** and **"FAILS CLOSED"** in my own labels |
| 3 | a CI monitor labelled `373c679` | `ALL THREE REQUIRED PASS on 373c679` | that run was **CANCELLED as superseded.** The loop printed `git log -1` — the LOCAL head — not the sha it was watching |

**#3 IS THE WORST OF THE THREE**, because a pass on a cancelled run is a green light for a merge. It was caught
only because the merge was verified by a direct query instead of by the watcher that existed to answer it.

> ### **AN INSTRUMENT MUST NAME ITS SUBJECT FROM THE SAME PLACE IT READS ITS RESULT.**
> ### **A LABEL COMPOSED SEPARATELY FROM THE MEASUREMENT CAN DISAGREE WITH IT AND STILL LOOK RIGHT.**

**THE CHECKS, all cheap:**
- Strip formatting before matching (`sed 's/\x1b\[[0-9;]*m//g'`), or match a marker that cannot appear in prose.
- Never match a word that also appears in your own labels — assert on a delimiter (`** FAIL **`), not a word.
- **A watcher must echo the identifier it QUERIED**, never one it re-derived locally.
- **And verify a merge-gating result by direct query regardless.** A watcher is a convenience; the gate is a fact.

Related: A SYMPTOM HAS AXES · CHECK THE MATCHER BEFORE THE SUBJECT · A TEST CAN PIN A LABEL PRODUCTION CAN
NEVER PRODUCE. Same family — the evidence was collected and not compared against the authoritative source.

---

## BEFORE RECORDING AN ABSENCE, NAME THE TABLE. A DTO IS A PROJECTION; A SCHEMA IS THE PRODUCT.

**SECOND INSTANCE, and the property that matters is that NEITHER was caught by the person who made the call.**

| # | the call | what was actually there | who caught it |
|---|---|---|---|
| 1 | S14.5 — *"the Site schema has no hub fields, so the capability is missing"* | the hub set was **its own endpoint and its own schema** all along | the founder |
| 2 | S14.11 — *"`Member` has no auth source / device count / MFA state, so the product doesn't hold them"* | `users.password_hash`, `Device.user_id` + an admin-scoped `listDevices`, and `user_totp.confirmed` — **all persisted** | review |

**FOUR OF FIVE VERDICTS WERE WRONG IN INSTANCE 2**, all in the same direction: **under-building the screen.**
`N devices` was a client-side group-by over a call the audience already makes. MFA was a projection, not a
roadmap. AUTH was half-derivable. `idp-sync` was reachable through the group tables.

> ### **THE STANDING QUESTION, ASKED BEFORE THE WORD "ABSENT" IS WRITTEN:**
> ### **WHICH TABLE DID I LOOK IN? IF THE ANSWER IS A DTO, I HAVE NOT LOOKED YET.**

**WHY IT NEEDS A QUESTION AND NOT A CAUTION: THIS CLASS DOES NOT SELF-DETECT.** A grep over one response
returns a clean, confident, *true* answer — the field really is not on that response — and nothing in the
result hints that a different place holds it. Both instances required an outside reader. A caution
("be careful about DTOs") does not fire, because nothing feels uncertain at the moment of the mistake.

**THE FOUR PLACES TO NAME, IN ORDER:** the **table** (`information_schema` / `\d`), the **handler** (what it
scopes and to whom), the **other endpoint** (a capability often has its own), and the **gate**
(permission / edition — see ABSENCE OF PERMISSION IS NOT ABSENCE OF DATA).

Related: VERIFY AGAINST THE SWITCH, NOT AGAINST THE NAME · A TEST CAN PIN A LABEL PRODUCTION CAN NEVER
PRODUCE · ABSENCE OF PERMISSION IS NOT ABSENCE OF DATA. Every one of them is the same failure at a different
layer: **the evidence was collected somewhere other than where the truth lives.**


### ⛔ SECOND INSTANCE (S14.12) — AND IT WAS INVERTED, WHICH IS WORSE THAN MISSING

I enumerated what `ci.yml` and `security.yml` duplicate, and reported: *"`security.yml` pins nothing, so its
jobs take the runner default"* — naming the security workflow as the drift risk. **Measured:**

```
security.yml:82,175   go-version-file: <module>/go.mod   <- DERIVED. Cannot drift.
ci.yml:176            go-version: '1.25'                 <- hardcoded. The actual risk.
all five modules      go 1.25.12
```

**My regex matched `go-version:` and missed `go-version-file:`.** Same cause as the first instance: an absence
established through ONE encoding of the thing, when the thing had two.

> ### **A WRONG DIRECTION IS WORSE THAN NOT HAVING LOOKED, BECAUSE IT SENDS THE FIX TO THE WRONG FILE.**
> ### **A missing finding costs nothing until someone looks. AN INVERTED ONE SPENDS EFFORT HARDENING THE**
> ### **SIDE THAT WAS ALREADY CORRECT AND LEAVES THE REAL ONE ALONE — and it does so with the confidence**
> ### **of a measurement.**

**AND THE FIX FOLLOWED THE CORRECTED DIRECTION:** `ci.yml` now uses `go-version-file: apps/api/go.mod`,
**removing the hand-maintained copy rather than adding a second one.**

> ### **TWO DERIVED VALUES CANNOT DISAGREE. TWO PINNED VALUES CAN.**
---

## RE-READ THE SURROUNDINGS, NOT THE EDIT — AND IN A DOCUMENT THE STALE HALF IS READ AS TRUTH

**S14.11.** I corrected §0's headline after measuring that four of five "absences" were wrong — and left the
paragraph **immediately beneath it** still asserting *"the columns below are absent because the fields do not
exist."* **The exact claim the correction disproved, sitting directly under the correction.**

**This is the duplicated-DNS-VIP shape** (S14.8: I added a DNS VIP line and left the pre-existing one, so one
address rendered twice) **— same cause, different medium: I verified my edit and not its neighbourhood.**

> ### **THE COST DIFFERS BY MEDIUM, AND THE DOCUMENT VERSION IS WORSE.**
> ### **A duplicated indicator on a screen is VISIBLE — the founder caught the DNS VIP in one look.**
> ### **A stale paragraph in a decisions doc is READ BY A FUTURE SESSION AS TRUTH.**

This epic has already had **two documents contradict each other** — the S14.5 HALT, and PLAN vs the epic doc —
so the failure mode is not hypothetical here.

**THE CHECK IS THE ONE THAT CAUGHT THE DNS VIP:** after correcting a claim, **re-read what surrounds it**, not
the diff. A correction that leaves its own premise standing has not landed; it has only been added to.

**AND IN A DOC, LEAVE THE CORRECTION VISIBLE.** Both the headline and the paragraph now say what they used to
say and why it was wrong — a future reader needs to know the claim was tested, or they will re-derive the
original from the wireframe.

---

## A MUTATION SURVIVOR IS NOT AUTOMATICALLY A MISSING TEST — IT MAY BE A WRONG BEHAVIOUR

**S14.11.** A mutation that swapped the two gate lines in `groupAccessState` **survived**. I read the survivor
the way a survivor is normally read — *my code is right, my test is thin* — and wrote a new test asserting the
order I had written. **The order was the thing that was wrong.**

Measured afterwards, `ListGroups` runs `authorize(PermPolicyView)` and **only then** `if s.policy == nil`, so an
open-edition member's real response is `403 forbidden`. My edition-first version told that member *"Groups are a
Tunnex Enterprise feature"* — **an upsell to someone whose role would not let them see groups after buying
them.** The S14.5 halt shape, forward, in the function whose own comment warns against its reverse.

> ### **HARDENING A TEST AROUND A SURVIVOR PINS THE BUG. The new test is then a second, LOUDER assertion**
> ### **that the defect is correct — and it will outlive the reasoning that produced it.**

**THE CHECK:** a survivor says *"no test distinguishes these two behaviours."* Before writing the test, decide
**which behaviour is right, from the substrate** — the handler, the schema, the wire. Only then pin it. The
survivor tells you where the ambiguity is; it does not tell you which side of it you are on.

**COROLLARY — A MUTATION MUST BE EQUIVALENT TO THE DEFECT IT NAMES.** My first "edition-first" page mutation
swapped only the *condition* and left the branch strings, so for the one caller under test both conditions were
true and it emitted **identical output**. It "survived" by not being the bug. **A mutation that cannot produce
the defect proves nothing about the defect** — and it reads in a report exactly like a real survivor.

---

## A FIXTURE LESS REPRESENTATIVE THAN A TEST DOUBLE HIDES DEFECTS THE DOUBLE FINDS

**S14.11.** `users.name` is `NOT NULL DEFAULT ''` and `acceptInvitation`'s `name` is optional, so **144 of 241
users in the review database have an empty name.** Every seeded demo member had one. The roster cell rendered
`{m.name || m.email}` **and** `{m.email}` unconditionally, printing the address twice for a nameless member —
and **nobody ever saw it**, because the only members ever rendered had names.

It surfaced because a test **mock omitted `name`**, and the first thing I did was try to fix the *test*.

> ### **S14.10's TRAP WAS THE DOUBLE BEING MORE PERMISSIVE THAN THE SUBSTRATE (a label pinned that production**
> ### **cannot produce). THIS IS THE SAME LESSON FROM THE OTHER SIDE — and it is the worse side, because**
> ### **ONLY THE FIXTURE IS REVIEWABLE ON A SCREEN. A founder cannot see what the fixture never produces.**

**THE CHECK:** for each column, ask *what does this field look like for the users who never filled it in?* —
then seed that. Optional-on-write plus `DEFAULT ''` is the signature: a field the SCHEMA calls required and the
POPULATION mostly leaves blank. And when a double disagrees with the fixture, **ask which one production
resembles** before fixing either.

---

## A HARNESS THAT MUTATES SOURCE MUST RESTORE IN A `finally`

**S14.11.** My mutation harness restored the original file on its last line. An assert threw mid-run, so it
**left the source mutated** — and because I ran it twice in one command, the second run took its backup **from
the corrupted file**, destroying the only clean copy of an untracked file.

Damage was one line, and it was named precisely before repair rather than guessed at. But the shape is general:

> ### **A TOOL THAT EDITS THE WORKING TREE AND CLEANS UP ON THE HAPPY PATH IS NOT A TOOL, IT IS A WAGER.**

**AND THE SECOND HALF, WHICH IS THE ONE THAT LIES:** the harness matched each mutation by a text anchor. When an
anchor went stale (the function had been deleted), `str.count() != 1` — so the mutation **never ran**, and a
naive harness counts a never-run mutation as *no failure*, i.e. **as a survivor or, worse, as a pass.**

**THE CHECK:** restore in `finally`; refuse to start if a stale backup exists; and report a stale anchor as
**NEVER APPLIED**, never as a result. *A mutation whose anchor no longer matches is not a mutation that passed.*
Print `applied: N of M` so the count and the list cannot disagree.

---

## A COUNT USED AS A GUARD MUST COUNT WHAT IT GUARDS AGAINST

**S14.11.** `guardLastOwner` protects an org from losing its last owner. Its input:

```sql
SELECT count(*) FROM memberships WHERE org_id = $1 AND role = 'owner';   -- no join to users
```

It counts **owner ROWS**. What it guards against is **an org with nobody who can sign in and administer it** —
and a deactivated user is refused at login (`403 account_deactivated`). The two are not the same set, so the
guard permits exactly the outcome it exists to prevent.

**PROVEN REACHABLE, not read off the code** (`docs/probes/lockout_probe_test.go.txt`): deactivate owner A
(allowed — two owner rows), then deactivate owner B (allowed — still two owner rows). **Two owner rows satisfy
the invariant on paper; zero accounts can sign in and act. Recovery requires direct database access.**

> ### **THIS IS THE DORMANT-MACHINERY LAW INVERTED. That law removes code that is CORRECT AND UNREACHABLE.**
> ### **This is a guard that is REACHABLE AND PERMISSIVE — worse, because it reports success while doing**
> ### **nothing, and every review that sees `guardLastOwner` in the call path reads the invariant as held.**

**THE CHECK:** for every count that gates a decision, write the sentence *"this protects against X"* and then
ask whether the query's row set is X. A guard counting rows while protecting against a capability is the
signature. Ask it of `WHERE role = …` especially: a role is an entitlement on paper, and entitlement is not
the same as ability.

**AND CENSUS THE SHAPE, NOT THE INSTANCE.** Three queries here count over a privilege-bearing role; two are
guards with no status filter, one is a display count that documents why it includes deactivated. The display
count being correct-by-intent is exactly why the census must read each one's PURPOSE — the same SQL shape is a
bug in a guard and correct in a tally.

---

## WRITING A RULE CREATES THE FEELING OF HAVING COMPLIED WITH IT

**S14.11.** §2.6 of this story's own decisions doc reads: *"ADDITIONS GET THE SAME DISCIPLINE AS CUTS — a
silent addition is as hard to audit later as a silent removal."* I wrote that sentence, registered
`email_verified` under it as a deliberate addition — **and then added a `Groups` stat tile that is nowhere in
the wireframe, with no register row, in the same document, in the same story.**

This is the fourth PROSE-VERSUS-BEHAVIOUR instance of the slice and **the sharpest**, because the other three
are a stale summary of someone else's artifact. This one is my own rule about my own code.

> ### **THE RULE IS SALIENT, SO THE MIND SUPPLIES THE COMPLIANCE. Having just articulated the principle**
> ### **feels like having applied it — and the author is the ONE PERSON who cannot read their own rule fresh.**
> ### **A reviewer reading §2.6 cold would have asked "which additions?" and found the tile in one pass.**

**THIS IS WHY THE STANDING QUESTION IS A QUESTION.** *"What in this change is asserted only in prose?"* can be
asked of yourself and returns an answer. *"Follow your own rules"* cannot — **it is already believed**, and a
belief cannot be used as a check on itself.

**THE PRACTICAL FORM:** after writing a rule, apply it to the change containing the rule — the diff that
introduces a discipline is the first place the discipline is unenforced, because it did not exist when the
rest of the diff was written.

---

## AN INFLATED FINDING COSTS THE NEXT ONE ITS CREDIBILITY

**S14.11.** The `CountOwners` probe had two branches. Branch 1 (deactivate one owner, then DEMOTE the other)
ends with zero owners who can sign in — and reads like a lockout. It is not: the demoted owner is now an admin
who still holds `member:manage` and can reactivate the first. **A capability outage with a path back.**

Only branch 2 (deactivate BOTH) is unrecoverable: two owner rows satisfy the invariant on paper, zero accounts
can sign in and act, and recovery requires direct database access.

> ### **REPORTING BRANCH 1 AS A LOCKOUT WOULD HAVE MADE THE FINDING BIGGER AND THE REPORT WORSE. The reader**
> ### **who checks branch 1 and finds a path back now discounts branch 2 — and branch 2 is the real one.**

**THE CHECK:** when a proof has several routes to the same headline, run each to the end and ask *is there a
path back?* Report the narrowest claim the evidence supports, and say explicitly which routes did NOT qualify —
the exclusions are what make the remaining claim load-bearing.

---

## A FALLBACK NEVER EXERCISED DELIBERATELY IS A FALLBACK ALWAYS EXERCISED ACCIDENTALLY

**S14.11.** The Audit Log's actor cell is `{a.actor_id ? actorName(members, a.actor_id) : "system"}`. Its
wiring mock sent **`actor_user_id`** — a field the spec does not have and, being `additionalProperties: false`,
one the server can never send. So `a.actor_id` was `undefined` in **every** audit-log test, **every** row
rendered `"system"`, and the suite was green.

**No assertion ever looked at the actor column.** The ternary had two branches and the tests only ever ran one
— the wrong one — for the entire life of the screen.

> ### **THE MOCK AND THE PAGE DISAGREED, THE TEST PASSED, AND THE PASSING BRANCH WAS THE ONE NOBODY WANTED.**
> ### **A fallback is the branch you expect NOT to take; if no test takes the other one on purpose, the**
> ### **fallback silently becomes the only behaviour you have ever observed.**

**THE CHECK:** for every `?:`, `??`, `||`, and `default:` on a rendering path, name the test that exercises the
**non**-fallback branch. If you cannot, the fallback is your actual UI. This is sharpest on surfaces where the
fallback is *plausible* — `"system"`, `"unknown"`, `"—"` — because a plausible fallback never looks like a bug.

**AND IT COMPOUNDS WITH AN UNFAITHFUL DOUBLE.** The mock was wrong in BOTH directions at once (invented
`actor_user_id`, omitted `actor_id`), which is exactly the pair that produces a green suite: the invented field
is ignored by the page, and the omitted one makes the page take the branch nobody checked.

**MEASURE BEFORE BLAMING THE PAGE.** The live endpoint served a populated `actor_id` on 34 of 78 rows — so the
page was right and only the fixture was wrong. Reading the code alone would have supported either conclusion.

---

## A PER-SCREEN OBLIGATION THAT NOBODY DISCHARGES PER SCREEN IS PROSE

**S14.11, founder-ruled.** *"Each section clears its own em-dashes"* was written down and carried across
sections. **It is not what cleared anything.** The 163→19 burn-down happened in **one global sweep in S14.6**,
while the per-screen passes **preserved** em-dashes because tests asserted on them.

> ### **THE OBLIGATION EXISTED, WAS WRITTEN DOWN, AND WAS NOT THE MECHANISM. Every section reported its**
> ### **pass complete without discharging it, and no check noticed — because the obligation's only**
> ### **enforcement was the sentence stating it.**

Reclassified to a **single global sweep plus an ESLint/CI rule at EPIC 14 close** — the honest form, because a
lint rule is discharged by machinery rather than by intent.

**THE DIAGNOSTIC, and it generalises past em-dashes:** for any standing per-unit obligation, ask **what
actually discharged it last time**. If the answer is "a batch pass someone ran once", it was never per-unit —
it is a global task wearing a per-unit costume, and leaving it in the per-unit definition of done means every
unit reports done while the debt accrues.

**AND NOTE WHICH RULE THIS DOES *NOT* COVER.** The em-dash as a **placeholder glyph** is a separate, already
resolved rule (S14.5: `"—"` → `"n/a"`), and it does **not** wait for the global prose sweep. Collapsing the two
would let a resolved rule ride on an unresolved one's schedule — which is how `Kubernetes.tsx:403` shipped a
regression with a written exemption.

**This is a sibling of the prose-versus-behaviour class:** there the prose asserted a fact the code did not
implement; here the prose asserted a *process* nobody performed. Same failure, one level up.

---

## A GATE CONDITIONED DIFFERENTLY FROM ITS OWN INPUT FAILS ON ABSENCE, NOT ON FINDINGS

**S14.11 follow-up (PR #59).** The CodeQL `go` leg is filtered per-leg: on a diff with no Go files,
`init` / `autobuild` / `analyze` skip. **The step that COUNTS the findings carried no condition at all**, so it
ran anyway and died on `jq: error: Could not open file codeql-results/*.sarif`.

It reported as **`CodeQL (blocking on high/critical) (go): failure`** — which reads exactly like a real
security finding. **That is the worst possible disguise for a plumbing bug**: the one check whose red nobody
argues with.

> ### **IT STAYED INVISIBLE BECAUSE EVERY PR BETWEEN THE SPLIT AND #59 TOUCHED GO. The filter was never**
> ### **exercised on the branch it now takes — the same shape as the audit log's `"system"` fallback, one**
> ### **layer down: a conditional whose other side no run had ever taken.**

**THE CHECK, and it is mechanical:** for every step gated by an `if:`, list the steps that consume its output
and confirm they carry **the same** condition. A producer skipped without its consumer is a guaranteed failure
on the first diff that takes that branch.

**AND DO NOT FIX IT BY MAKING ABSENCE PASS.** The repair adds the condition **and** a real guard: when the
analysis DID run, a missing SARIF now fails loudly (*"CodeQL ran but produced NO SARIF"*). Otherwise the fix
converts a false red into a silent green, which is the trade this project refuses everywhere else — a skip
that reports success is worse than a failure that reports honestly.

**THE COST OF FINDING IT LATE:** this was the FIRST non-Go diff since the `gates` split. Arm 2 of the split
proof was still uncollected — and the moment a genuinely non-Go diff finally arrived, it did not prove the
split worked; **it found a defect the split introduced.** A proof deferred is a defect deferred with it.

---

## A PROOF DEFERRED IS A DEFECT DEFERRED WITH IT

**S14.11 (founder-ruled).** Arm 2 of the `gates`-split proof — *"a web-only diff skips the Go steps"* — was
uncollectable for **four consecutive PRs**, each time for a correct reason: every diff touched Go, so the
non-Go branch was never taken and could not be observed.

**The first diff that finally could take it did not prove the split worked. It found a defect the split had
introduced** — the CodeQL findings-gate reading a SARIF that was never produced.

> ### **THE DEFECT SAT LIVE FOR THE ENTIRE PERIOD THE PROOF WAS PENDING, AND THE TWO WERE THE SAME FACT**
> ### **WEARING DIFFERENT WORDS. "We cannot test this path yet" and "this path is broken" are**
> ### **INDISTINGUISHABLE FROM THE OUTSIDE — by construction, because the only thing that would tell them**
> ### **apart is the test that cannot run.**

**THE CHECK:** when a proof is deferred for lack of a triggering condition, write down **what would be true if
the untested path were already broken** — and notice that the answer is *exactly what you currently observe*.
That is not a reason to panic; it is a reason to stop treating "not yet provable" as "probably fine", and to
weight the eventual collection as **defect-hunting** rather than confirmation.

**A cheap partial substitute exists and was not used here:** the branch could have been *forced* — a scratch
branch touching only a doc, pushed to a throwaway PR, would have taken the non-Go path in minutes. **Waiting
for the condition to arrive naturally is what let four PRs pass.**

---

## A FALSE RED ON A SECURITY CHECK IS WORSE THAN A FALSE RED ANYWHERE ELSE

**S14.11 (founder-ruled).** The plumbing bug above surfaced as
**`CodeQL (blocking on high/critical) (go): failure`** — the exact presentation of a real high-severity
finding. Nothing in the check's name, status, or summary distinguished a missing file from a vulnerability.

> ### **THE FIRST REFLEX IS TO TRUST A SECURITY RED. THE SECOND REFLEX, AFTER IT HAS BEEN WRONG ONCE, IS TO**
> ### **STOP READING IT.** A security check is the one gate whose red nobody argues with — which is exactly
> ### **why a false one there costs more than a false one anywhere else. It spends credibility that the next,**
> ### **real finding needs.

**AND THE REPAIR MUST NOT CONVERT A FALSE RED INTO A SILENT GREEN.** The obvious fix — make a missing SARIF
pass — would have removed the noise by removing the check. The fix applied instead:

1. the counting step now carries **the same condition as the analysis producing its input**, so on a non-Go
   diff it is **skipped**, not passed; and
2. when the analysis **did** run and produced nothing, it fails **loudly** — *"CodeQL ran but produced NO
   SARIF"* — because a scan that analysed nothing is a real failure.

**Skipped and passed must never render alike** — the classifier's own notice says it (`false = the Go steps
below are SKIPPED, not passed`), and this is that rule applied to the check's own internals.

---

## ANY SCRIPT VALIDATED ONLY AGAINST ACCUMULATED STATE IS VALIDATED AGAINST SOMETHING NO NEW CUSTOMER HAS

**S14.12 (founder-ruled; the open-edition stack's strongest justification, and it was NOT predicted).**

Building the open-edition review stack produced a **fresh database** for the first time in months. `make
seed-open` failed immediately:

```
insert or update on table "policy_rules" violates foreign key constraint
"policy_rules_src_user_fk" (SQLSTATE 23503)
```

`policy_rules` is inserted at line 341 of `fixtures.sql`; the users those rules reference are inserted at line
384. **The ordering has been wrong for as long as those rules have existed.** It never failed because the
primary database is months old and the referenced users were already there from earlier seeds.

> ### **THE PRIMARY STACK VALIDATED THE SEED AGAINST STATE THE SEED ITSELF DID NOT CREATE. A FIRST-RUN**
> ### **CUSTOMER GETS THE FRESH PATH — AND THE FRESH PATH WAS BROKEN.**

**GENERALISE PAST FIXTURES.** Migrations are covered: CI runs them forward from empty every time, so an
ordering defect there fails immediately. **Nothing else in this repo has that property by default** — seeds,
backfills, and any ordering-sensitive script may only ever have run against a database that already contains
what they assume.

**THE DIAGNOSTIC:** for any script that writes, ask *when did this last run against an EMPTY target?* If the
answer is "never" or "not since it was written", it has been tested against its own side effects.

**REGISTERED, NOT CHASED:** *what else here has only ever run against an accumulated database?*
Trigger — **the next data-path story** (`docs/DEFERRAL-REGISTER.md`).

**AND NOTE WHICH FINDING THIS OUTRANKS.** The same stack also confirmed the predicted `accessView` gate-order
bug. **That one was a code reading first and a measurement second; this one nobody predicted at all.** A tool
that only confirms what you already suspected has not yet earned its cost.

---

## TWO DATABASES THAT DIFFER ARE DRIFTED OR CORRECTLY DIFFERENT, AND ONLY A WRITTEN NOTE DECIDES WHICH

**S14.12 (founder-ruled).** The enterprise and open review stacks seed from one `fixtures.sql` through one
seeder binary, and they still differ: `health_blocked` is **1** on enterprise and **0** on open, because the
seeder registers posture **through the product** and device-health reporting is edition-gated.

**That difference is correct.** But *correct* and *drifted* look identical in a diff — a number that does not
match, with no property of the data itself saying which it is.

> ### **THE ONLY THING THAT DISTINGUISHES A LEGITIMATE DIFFERENCE FROM DRIFT IS THAT SOMEONE WROTE DOWN**
> ### **WHICH ONE IT IS, BEFORE ANYONE HAD TO ASK.**

**THE PRACTICE:** when standing up a second environment, enumerate the expected differences **at creation**
and put them where the comparison happens — here, in the `seed-open` target itself. An unexplained difference
found later is investigated from zero; an explained one is checked against its explanation in seconds. And a
difference nobody wrote down eventually gets "fixed" by someone making the two match, which is how an edition
gate quietly stops being tested.

---

## THE ARTIFACT OUTLIVES THE SOURCE THAT PRODUCED IT — AND KEEPS ANSWERING

**S14.12 (founder-ruled). THIRD instance of one family, now named.**

`make up-open-review` was committed on a branch **after that branch merged**, so the target existed on no
branch anyone would check out. The `:8081` containers kept running the whole time — so the open-edition stack
**looked present and healthy** while its definition was gone from every tree, and the bundle it served
predated a day of work.

**THE SIBLINGS, and they are the same failure:**

| instance | the artifact | what it outlived |
|---|---|---|
| S14.11 | the **served bundle** | eight commits that were never deployed |
| S14.11 | **"CI green"** | the sha it was green on, superseded by a push |
| S14.12 | a **running container** | the Makefile target that defines it |

> ### **AN ARTIFACT KEEPS ANSWERING AFTER THE THING THAT DEFINES IT HAS MOVED OR VANISHED, AND THE ANSWER**
> ### **LOOKS CURRENT PRECISELY BECAUSE THE ARTIFACT IS STILL RUNNING. Health is not freshness. A green**
> ### **check, a serving port and a healthy container all report on a PAST state with a PRESENT voice.**

**THE DIAGNOSTIC, cheap enough to always run:** *before trusting a running thing, confirm its DEFINITION is on
the branch you are on.* `grep` the target in the checked-out `Makefile`; diff the served bundle hash after a
deploy; re-read check-runs for **the exact sha** rather than the PR. **All three instances would have been
caught by that one question**, and each was instead caught by luck or by a later failure.

---

## A CONSEQUENCE ASSERTED WITHOUT ITS PRECONDITION

**S14.12 (founder-ruled — and the finding of the slice, though it is not what was ruled).**

The empty rule list rendered: *"No rules — under Enforcing, all device-to-device traffic is denied."*
**Unconditionally.** The demo org's mode is `off`, and with enforcement off an empty rule set denies
**nothing**. The sentence was true of a state the screen was not in.

**It was invisible because the fixture had rules**, so the branch never rendered. **One deletion away, the
screen makes a false claim about enforcement** — on the surface whose entire job is stating the enforcement
posture.

> ### **THE SENTENCE NAMED A CONSEQUENCE ("all traffic is denied") AND OMITTED ITS PRECONDITION ("while**
> ### **enforcing"). A conditional truth rendered unconditionally is FALSE HALF THE TIME, and the half it is**
> ### **false in is invisible whenever the fixture keeps you out of it.**

**HOW IT WAS FOUND, and this is the transferable part: by being asked a DIFFERENT question.** The ruling was
about two empty states — *failed* vs *zero-while-enforcing*. Building that distinction properly forced reading
the mode, and the third claim fell out. **Neither the founder nor I was looking for it.**

**THE CHECK:** for every rendered sentence asserting a consequence, name the state that makes it true and ask
whether the render is conditioned on that state. If the copy contains *"under X"*, *"while X"*, *"since X"* —
X must be in the branch condition, not only in the prose.

---

## A GUARD THAT VALIDATES ONE COPY OF A DUPLICATED RULE CERTIFIES THE COPY, NOT THE RULE

**S14.12 (founder-ruled — the session's result). IT COMPOUNDS THREE WAYS, and each alone would have been
survivable.**

**1 — THE RULE WAS DUPLICATED WITH NOTHING LINKING THE COPIES.** The diff classifier lives in `ci.yml` **and**
in `security.yml`. Adding `\.sql$` to one left the other behind; nothing in the repo related them.

**2 — THE GUARD BUILT TO PREVENT EXACTLY THIS CLASS READ ONLY ONE COPY, AND PASSED.**
`TestClassifierPatternMatchesTheWorkflow` was written *because* a transcribed pattern can drift from the
workflow. It opened `ci.yml`, found agreement, and reported green — **certifying the artifact I had already
fixed while the divergent one went unexamined.**

**3 — THE FAILURE MODE WAS `skipped`, NOT `failed`.** Three security jobs — **`govulncheck` ×5 modules,
`gofmt + vet parity`, `Trivy`** — did not run on a diff containing a Go compile input. **Every badge was
green.** A skipped security job is indistinguishable at a glance from "not applicable to this diff", which is
the *normal* reason a job skips.

> ### **A GREEN BOARD WITH THREE ABSENT SECURITY JOBS LOOKS EXACTLY LIKE A GREEN BOARD.**

**THE FIX ASSERTS THE RULE, NOT A COPY:** both workflows must carry the **identical** pattern, and the guard
loops over both files. **Proven to fire on the sibling** — reverting `security.yml` alone reds it by name.

**THE GENERAL CHECK:** when a guard validates a duplicated value, its assertion must range over **every**
instance, and the loop must be **derived** (a list of files) rather than written once per instance — because a
guard extended by hand acquires the same drift it exists to prevent.

**AND THE SHAPE THAT HID IT — the third `skipped`-vs-`passed` instance this epic.** The classifier's own
notice says it (`false = the Go steps below are SKIPPED, not passed`); CodeQL's counting step said it; and now
a whole job set. **Every time, the thing that made it invisible was that skipping is also the correct
behaviour most of the time.**

---

## A COMPOSITE RESULT REPORTED BY ITS MOST FAVOURABLE COMPONENT

**S14.12 (founder-ruled). TWO INSTANCES IN ONE SESSION, one in each direction.**

**A GATE READ SELECTIVELY IS NOT A GATE.** I ran the web gate, read *"597 tests passed"*, and pushed. Two
lines above it sat **`typecheck: 2`**. The gate is typecheck + tests + build; I reported the leg that agreed
with me.

**THE SIBLING, same session, same shape:** CI's board showed every badge green while `govulncheck` ×5,
`gofmt + vet parity` and `Trivy` **never ran** — a green *badge* hiding absent jobs, where the other was a
green *test count* hiding a failing leg.

> ### **BOTH TIMES THE UNFAVOURABLE PART WAS VISIBLE, ADJACENT, AND UNREAD. Nothing was hidden; the**
> ### **aggregate was simply allowed to speak for its parts, and an aggregate always speaks in the voice of**
> ### **whichever part you looked at.**

**THE CHECK:** for any composite gate, report **every leg by name and value** — never the aggregate, never the
one leg you happened to read.

> ### **"make web-gate green" IS NOT A REPORT. "typecheck 0, 597 tests, build clean" IS.**

Same for CI: not *"CI green"* but **`gates: success` (14/14 steps), `client (macos)`: success, `client
(windows)`: success, `govulncheck` ×5: RAN and passed** — because *ran* and *passed* are different claims and
a skip reports as neither.

---

## THE RUNNING IS THE RESULT; THE GREEN IS INCIDENTAL

**S14.12 (founder-ruled).** The classifier fix was proven not by a passing board but by a **transition**:

```
sha 8522614   govulncheck x5, gofmt+vet parity, Trivy   ->  SKIPPED
sha 129e784   the same seven jobs, same class of diff   ->  SUCCESS
```

> ### **A JOB THAT PASSES PROVES SOMETHING ABOUT THE CODE. A JOB THAT RUNS WHERE IT PREVIOUSLY SKIPPED**
> ### **PROVES SOMETHING ABOUT THE GATE — AND THE GATE WAS THE THING UNDER TEST.**

Had those seven jobs simply been green on both shas, nothing would have been demonstrated: green is what a
skipped job's absence looks like on a board. **The evidence was the change in `conclusion`, not its value.**

**THE CHECK:** when the thing you fixed is a GATE, state the before and after **per job by name**. "CI is
green" is compatible with the gate being broken in exactly the way you were fixing — which is how the defect
survived four PRs in the first place.

**SIBLING:** *a composite result reported by its most favourable component*. Same session, same root: an
aggregate cannot report on whether its parts ran.

---

## A VIEW-MODEL WITH GREEN TESTS AND NO CALLER IS INVISIBLE TO EVERY GATE WE OWN

**S14.12 (founder-ruled). SECOND dormant-machinery catch this epic, and the two were found differently — which
is the point.**

**FIRST (S14.11):** the founder asked why a primitive had no consumer. **A person noticed.**
**SECOND (S14.12):** `flowGraphState` / `flowGraphNote` were built, tested, and **mutation-proven** — 4 tests,
4 mutations, zero survivors — and referenced **nowhere**. I found it by grepping the SERVED ARTIFACT for
`"Too many rules to draw legibly"` and getting **0**.

> ### **EVERY GATE WE OWN TESTS THE VIEW-MODEL. So a view-model that is correct, covered and uncalled passes**
> ### **all of them — unit tests, mutations, typecheck, build. There is no gate whose subject is "is this**
> ### **reachable from the page", because reachability is exactly what the tests supply themselves.**

**THE CHECK, and it is cheap:** after building a view-model, **grep the ARTIFACT for a string only its
consumer can produce.**

> ### **TREE-SHAKING IS THE TELL — IF THE BUNDLER DROPPED IT, NOTHING CALLS IT.** The bundler already performs
> ### the reachability analysis no test performs; read its output instead of duplicating it.

**AND WHY WIRING IT IMMEDIATELY MATTERS:** an unwired view-model *between slices* is how dormant machinery
becomes permanent. **It passes its tests, so nothing ever complains** — the debt has no failing signal and no
deadline. The catch is only worth having if the wiring follows in the same slice.

### ⛔ THIRD INSTANCE (S14.12) — GSAP, AGAIN, AND I ARGUED THE WRONG REASON

Asked to "use gsap animation", I answered with **bundle size, motion-gate coverage, and reduced-motion
ergonomics** — all correct, and **none of them the reason.** GSAP was ruled out on **2026-08-01 on LICENCE**:
`docs/EPIC-14-ui-redesign.md:96` — a custom *"no charge"* licence, **neither SPDX nor OSI**, and Tunnex
**redistributes a built bundle to self-hosters**, so embedding a non-OSI dependency inside an Apache-2.0
artifact denies the recipient, for that portion, the freedoms the surrounding licence advertises. The ruled
alternative is **Motion (MIT)**.

**The heading literally says `GSAP IS NOT ADOPTED`. One grep.**

**INSTANCE COUNT THIS EPIC: THREE** — Fleet risk, GSAP, and GSAP again.

> ### **BEING RIGHT FOR A WEAKER REASON IS HOW A RULING GETS RE-OPENED A FOURTH TIME. A licence finding**
> ### **closes the question permanently; a bundle-size argument invites "but it's only 70kB" — and the**
> ### **next person to ask will get my weaker answer, not the founder's stronger one, because mine is the**
> ### **one now written in the conversation.**

**AND NOTE WHAT MADE IT FEEL UNNECESSARY:** I *had* the correct conclusion (don't add it) and a confident
argument for it. **The grep feels redundant precisely when you already agree with the ruling** — which is
exactly when it is load-bearing, because agreeing is not the same as knowing why.

---

## A THRESHOLD SHOULD MEASURE THE PROPERTY THAT MATTERS, NOT A PROXY FOR IT

**S14.12 (founder-ruled — and the founder's own question was the proxy).**

The question asked was *"at what rule count does the flow panel stop saying anything?"* **N was the wrong
variable.** Degree-ranking's usefulness depends on the **degree distribution**, not the count:

| same N | top-4 covers | verdict |
|---|---|---|
| 900 rules hub-and-spoke through 4 gateways | nearly everything | **a good summary** |
| 900 rules across 900 distinct pairs | ~2% | **decoration** |

**A fixed second count would have withheld from a well-summarised org for a property it does not have, and
kept drawing for a badly-summarised one until somebody noticed.** So the threshold measures **coverage** —
withhold when the drawn share falls below half — because coverage *is* the property, and count merely
correlates with it in the cases that first come to mind.

> ### **THE PROOF SHAPE IS THE SHARPEST PART: SAME N, OPPOSITE VERDICT.** Twenty rules hub-and-spoke draws;
> ### **twenty rules fully distinct withholds. A test that VARIES THE THING THE THRESHOLD CLAIMS TO MEASURE**
> ### **while HOLDING THE THING IT DOES NOT** is the only test that distinguishes a real threshold from a
> ### proxy — and it fails loudly the day someone "simplifies" it back to a count.

**THE CHECK:** for any threshold, write the sentence *"this withholds when X"* and ask whether the quantity in
the code **is** X or merely tracks it. If it tracks it, find the input where they diverge — that input is your
test, and it is usually easy to construct once you look for it.

**THE SIBLING, one level down:** the class-token regex in the same slice. `max-w-full` **contains** `w-full`,
so matching the substring reported correct code as broken. **Same error at a smaller scale: the thing measured
was a proxy (does the string appear) for the thing that mattered (is the class token present).**

### ⛔ AND THE DIRECTION IS WHAT COSTS — SECOND INSTANCE OF A RULE ALREADY FILED

`docs/laws.md` already records *a wrong direction is worse than not having looked, because it sends the fix to
the wrong file* (the `go-version` inversion). **This is its second instance, and it names the cheaper half:**

> ### **A MATCHER THAT IS WRONG IN THE FALSE-POSITIVE DIRECTION SENDS YOU TO FIX SOMETHING THAT IS NOT**
> ### **BROKEN.** A false negative costs you a finding. A **false positive costs you a change** — and the
> ### change lands on correct code, with a test now pinning the damage.

Here it would have removed `max-w-full`, which is the very thing keeping the panel from overflowing a narrow
viewport. **The "fix" would have introduced the defect the assertion exists to prevent.**

**BOTH INSTANCES WERE CAUGHT THE SAME WAY: by checking the finding instead of acting on it.** The `go-version`
inversion was caught by reading the file the claim was about; this one by reading the class string the regex
had judged. **Neither was caught by a gate, and neither would have been** — a matcher that is confidently
wrong produces a clean, specific, actionable red.

**THE CHECK:** when an assertion goes red on code you did not just change, read the subject before you read
the fix. The first question is *"is this red correct?"*, not *"how do I make it green?"*

---

## AN ANIMATION AND A SEMANTIC ENCODING MUST NOT SHARE A PROPERTY

**S14.12 (founder-found on screen).** The flow panel encodes *temporary grant* as **`stroke-dasharray: "5 6"`**
and its legend says `- - - temporary`. The entry animation drew each edge with
`stroke-dasharray: 1600; animation: tnxDraw …` on the same element.

**A CSS declaration beats an SVG PRESENTATION ATTRIBUTE.** So the animation's dasharray silently overrode the
semantic one and **every temporary edge rendered SOLID, while the legend promised a dash.**

> ### **WHICHEVER THE CASCADE FAVOURS WINS, AND THE LOSER FAILS SILENTLY. The edge still drew, at the right**
> ### **width, in the right colour, along the right path — just carrying the wrong meaning. Nothing looked**
> ### **broken, which is why it survived a review pass that caught a wrong type tag.**

**THE FIX IS NOT PRECEDENCE, IT IS SEPARATION.** The reveal now uses **`clip-path`**, which nothing on this
panel encodes, applied to the edge `<g>` so the flow wipes in once. Dash is free to mean what the legend says.

**THE CHECK:** before animating an SVG or CSS property, ask **what else on this surface reads that property as
meaning**. `stroke-dasharray`, `opacity`, `stroke-width` and colour are all commonly BOTH decorative and
semantic — and an animation is written in CSS while the meaning is usually written as an attribute, so the
animation wins by default.

**SIBLING — the same defect one layer up:** the epic already rules that **a gate must be a RENDER decision,
never a style**, because a column hidden by `opacity` is still in the DOM. Here a *meaning* was hidden by an
animation. **Both are: a presentational mechanism silently overriding a semantic one.**

---

## RUN A SWEEP AGAINST A CASE YOU ALREADY KNOW THE ANSWER TO

**S14.12 (founder-ruled — the most reusable thing in that report).**

The first "which mutating endpoints have no web call site" sweep reported **6**. `addGroupMember` — which I had
*already measured* as uncalled ten minutes earlier — **was not in the list.** That absence is what caught it.

**THE PROXY, and it is the worst kind:** the sweep asked *"does this path string appear anywhere in
`apps/web/src`?"* But `edition.ts` is a **PATH MANIFEST** — it lists every enterprise-gated path so the
reactive-403 layer can classify them.

> ### **SO THE PROXY WAS CORRECT-BY-CONSTRUCTION FOR THE WRONG QUESTION. Every enterprise path was**
> ### **guaranteed to match, called or not. A proxy that fails randomly gets noticed; one that is**
> ### **structurally guaranteed to agree looks like a clean result.**

Re-run against **actual call sites** (`api.POST|PUT|PATCH|DELETE("…")`, manifest excluded): **19 of 80**, and
the known case was present.

> ### **THE FLOOR: SEED EVERY ENUMERATION WITH A CASE WHOSE ANSWER YOU ALREADY KNOW. If the known case is**
> ### **MISSING FROM THE OUTPUT, THE SWEEP IS MEASURING SOMETHING ELSE — and you learn that in one glance,**
> ### **before the number reaches anyone.**

This is the **vacuity floor for enumerations**, the sibling of the count floors already on the census tests
(`gated < 40`, `files > 50`, `found < 2`). Those catch a scan that broke; **this catches a scan that works
perfectly on the wrong question.**

---

## THE WHO-READS-THIS PROBE, FAILING ON A **VERB**

**S14.12 (founder-ruled).** Every prior instance was a served **FIELD** nobody rendered — `actor_system`, the
peer count, `Histogram`. This one is **three shipped ENDPOINTS with one consumer**, since S7.5.2:
`listGroupMembers` is called; **`addGroupMember` and `removeGroupMember` never have been.**

> ### **A FIELD WITH NO READER SHOWS NOTHING. A VERB WITH NO CALLER MEANS A CAPABILITY THE PRODUCT HAS AND**
> ### **THE OPERATOR CANNOT REACH — an incomplete view versus an unusable feature.**

And it compounds: the Access screen lets an admin create a group and write rules that *use* it as a source,
while the surface to put anyone in it does not exist. **The form creates an object nobody can populate, above
rules that depend on it being populated.**

**THE DIAGNOSTIC:** for every mutating endpoint in the spec, **name its call site.** An endpoint with no
caller is either **dead** or **missing a surface**, and nothing distinguishes those without asking — so the
question has to be asked per endpoint, not inferred from the count.

**MEASURED SIZE (S14.12): 19 of 80 mutating operations have no web call site; 12 are genuinely unreachable
capability.** Registered as its own story, not folded.

---

## A MUTATION THAT FAILS TO APPLY PROVES NOTHING — AND LOOKS EXACTLY LIKE ONE THAT WAS CAUGHT

**S14.12 (founder-filed on my own output).** Proving the new `empty_group_members` census, I twice inserted a
row to break the state, re-seeded, and read the verdict. Both proofs "passed."

**Both inserts had failed.** `group_members.org_id` is `NOT NULL` and I omitted it:

```
ERROR: null value in column "org_id" of relation "group_members" violates not-null constraint
```

**The state was never broken, so the census never saw a non-zero.** I had proved that a guard reports success
when nothing is wrong — which is not a property worth having.

> ### **A FAILED MUTATION AND A CAUGHT MUTATION PRODUCE THE SAME FINAL READING. The guard says "fine" either**
> ### **way, and the error scrolls past above it — in my case printed on the very line before the result I**
> ### **then reported.**

**THE CHECK, and it is one extra read:** after applying a mutation and before reading the guard's verdict,
**confirm the mutation actually changed the subject.** Count the rows. Diff the file. Assert the broken state
exists. Only then ask the guard.

Re-run with `org_id` supplied: the insert took (`INSERT 0 1`, members `1`), the seed **restored** it to `0`,
and with the restore removed the census **rejected** — `seed_fixtures_incomplete`, `interns_members: 1`,
`will NOT render`. **That is the proof; the first two were theatre.**

**SIBLING:** the S14.11 wedge test that failed identically with and without the fix (a nil map, not the
defect). Same family — *a red for the wrong reason* and *a green for the wrong reason* are the same error with
opposite signs, and both are caught by asking what the test's subject was actually in.

### ⛔ AND IT IS THE COMPOSITE-BY-FAVOURABLE-COMPONENT LAW, IN **TIME** RATHER THAN IN SPACE

The typecheck slip put `typecheck: 2` two lines **above** the test count I reported. Here the discriminating
evidence — the `null value in column "org_id"` error — was one **scroll back**, printed on the line
immediately before the verdict I read.

> ### **SAME LAW, DIFFERENT AXIS. There the unfavourable part was ADJACENT IN THE OUTPUT; here it was**
> ### **ADJACENT IN TIME AND ALREADY GONE FROM ATTENTION. Both times nothing was hidden, and both times the**
> ### **aggregate was allowed to speak for a part it had not checked.**

**THE MECHANICAL CHECK — and it is not "did the command run":**

> ### **BEFORE READING A GUARD'S VERDICT, CONFIRM THE MUTATION CHANGED THE SUBJECT.**

Not that the command exited. Not that it printed. **That the subject is now in the state the guard is supposed
to catch.** Count the rows, diff the file, re-read the value.

**FOURTH INSTANCE OF A CHECK REPORTING ON A STATE IT NEVER REACHED**, and the family is now worth stating
whole: *run the command the gate runs* (not one that resembles it) · *output is not effect* (a command that
prints is not a command that changed something) · *a mutation whose anchor no longer matches never ran* ·
and now *a mutation that failed to apply proves nothing.* **Every one is a proof about a subject the proof
never touched.**

---

# ⛔ A CORRECTLY-RUN CHECK AIMED AT THE WRONG SUBJECT

**S14.13. A NEW VARIANT, and the sharper half of the stale-stack finding.**

The panels were built, committed, CI-green — and invisible on both review stacks. The cause was mundane
(containers built 08:34, branch point 08:59, first story commit 09:21; the rebuild was never run). **What
matters is why it survived a check that was specifically supposed to catch it.**

The artifact law was obeyed. The grep ran. It searched `apps/web/dist/assets/index-*.js` for five strings only
the new consumers can produce, found all five, and was reported as proof the panels reach the artifact.

**It was proof they reach AN artifact. The one nobody was looking at.**

> ## **THE THREE PRIOR INSTANCES WERE CHECKS THAT COULD NOT SEE. THIS ONE SAW PERFECTLY, AND THE SUBJECT WAS**
> ## **WRONG. Different failure, same family — and strictly more dangerous, because a check that cannot see**
> ## **often looks wrong, while a correctly-run check aimed at the wrong subject LOOKS LIKE EVIDENCE. That is**
> ## **exactly why it survives review: nothing about it is malformed.**

**AND THE FIX IS NOT TO STOP RUNNING IT.** The `dist` grep still does its real job — tree-shaking and
no-caller detection, the "view-model with green tests and no caller" law. It was simply never capable of
answering *can the reviewer see it*. **The repair is to say WHICH QUESTION EACH GREP ANSWERS**, because both
greps are correct and they answer different things:

| check | subject | question it answers |
|---|---|---|
| **hash changed** | the port | **DEPLOY** — is the served artifact new at all? |
| **strings present in the SERVED bundle** | the port | **REACH** — did this code get into what is being served? |
| strings present in `dist` | the local build | **LINKAGE** — does this code have a caller, or did tree-shaking drop it? |

**THE MECHANICAL RULE — added to the handoff:**

> ## **BEFORE A REVIEW, GREP THE SERVED BUNDLE, NOT `dist`.**
> The hash changing is the **deploy** proof; the served strings are the **reach** proof. Two different checks,
> both against the same artifact — **the one on the port.**

**Generalized, this is the family's fifth member and it names the axis the others share:** *run the command
the gate runs* · *output is not effect* · *an unmatched anchor never ran* · *a mutation that failed to apply
proves nothing* · **and now: a check is only as good as the subject it was pointed at.** Every one is a proof
about a subject the proof never touched — but this is the first where the proof itself was flawless.

---

# ⛔ A DIFFERENCE IN SYMPTOM DOES NOT IMPLY A DIFFERENCE IN CAUSE

**S14.13, from the founder's review stack.** Google's OAuth client-ID field was prefilled with the signed-in
admin's **email** and the secret field with a **saved password**, both in autofill-blue, on a credential
surface. Microsoft's fields, on the same screen, were clean.

**The reasonable inference — and it was wrong:** *the two must be marked up differently; find the difference.*

**MEASURED: the fields are BYTE-IDENTICAL.** `SsoProvider` renders once per provider from ONE component, so
there is no markup difference to find. Chrome fills the **first** text+password pair on a page as a login form
and fills **one pair per page**; `google` is first in `PROVIDERS`. **Microsoft looked immune because it was
second.**

> ## **TWO INSTANCES OF ONE COMPONENT BEHAVED DIFFERENTLY BECAUSE OF POSITION — AND POSITION IS INVISIBLE**
> ## **FROM THE MARKUP.** The variable was not in either instance; it was in the ORDER OF THE LIST that
> ## **renders them, one file away.**

**AND THE COST OF THE WRONG INFERENCE IS NOT A WASTED HOUR — IT IS A FIX THAT MOVES THE BUG.** Annotating only
the provider that visibly misbehaved would have left the defect intact and handed it to Microsoft the first
time anyone reordered `PROVIDERS`. **The symptom would have relocated and the diff would have looked like a
fix.**

**THE MECHANICAL CHECK:**

> ### **WHEN TWO INSTANCES OF THE SAME COMPONENT BEHAVE DIFFERENTLY, DIFF THE INSTANCES FIRST. IF THEY ARE**
> ### **IDENTICAL, THE CAUSE IS THEIR CONTEXT — ORDER, POSITION, WHAT RENDERED BEFORE THEM — NOT THEIR CODE.**

**And one instance is not a scope.** The founder reported one field on one provider; the CENSUS turned that
into the real finding — **five password inputs across the app, ZERO `autocomplete` attributes.** The reported
symptom was the least of it.

## ⛔ AND THE VACUITY FLOOR EARNED ITSELF ON ITS FIRST RUN

The census matcher used `<Input\b([^>]*?)\/>` and found **ZERO password inputs in a tree containing five** —
because **JSX arrow functions contain `>`** (`onChange={(e) => …}`), so the exclusion class stopped at the
first `=>`.

> ### **A CENSUS WHOSE MATCHER IS DEFEATED BY THE LANGUAGE IT SCANS REPORTS A CLEAN TREE.**

Without the floor (`expect(total).toBeGreaterThanOrEqual(5)`) every assertion below it would have passed
against an empty set, and the credential guard would have shipped green and blind.

---

# ⛔ MUTATIONS DETECT VACUOUS TEST *RUNS*, NOT ONLY WEAK ASSERTIONS

**S14.13.** A new Go test was written, run, and reported `ok`. **It had SKIPPED** —
`set TUNNEX_TEST_DATABASE_URL to run this integration test` — and `go test` reports a skipped package as `ok`.

Nothing in the output was false. Nothing was hidden. **It was caught only because ALL FIVE Go mutations
survived**, which is impossible for a test that is actually asserting.

> ## **THE MUTATION SWEEP WAS THE INSTRUMENT, NOT A CAREFUL READING OF THE OUTPUT.** *Ran and passed are
> ## **different claims* was already law; this is the instance where the sweep — not vigilance — is what
> ## separated them.

**So the sweep has a second job, and it is the more valuable one:** a weak assertion lets *some* mutations
survive; **a test that never executed lets ALL of them survive.** A 100% survival rate is not a verdict about
the assertions — **it is a verdict about whether the test ran at all**, and it should be read that way before
a single assertion is blamed.

**Corollary for the harness:** report survivors as a RATE, not a list. `5 of 5 survived` is a different
diagnosis from `2 of 5 survived`, and only the first one means *go check that the test executes*.

---

# ⛔ THE SPEC DESCRIBES THE SHAPE OF A REQUEST, NOT THE EXISTENCE OF A CAPABILITY

**S14.14.** Every idp-sync path enumerates `provider: [microsoft, google]`; the server answers Google with
`400 provider_not_supported`, deliberately, at config time. **The spec, the handler signature and the
generated schema all read as though Google works — only the served payload disagreed.** Build the arm for
what the server ANSWERS, not for what the contract permits you to ask.

---

# ⛔ A CUMULATIVE DIFF MAKES ANY CLASSIFIER STICKY

**S14.15.** CI classified `BASE...HEAD` — the whole PR — so **the first commit that trips a rule trips it for
every commit after it.** One edit to `fixtures.sql` pinned `go=true` for the rest of the branch: across 18
runs, 17 were `go=true` and 16 of those were that one file, including 10 commits that were docs-only. **The
classifier existed and was a constant.**

**The shape will recur wherever a per-push decision is computed from a cumulative range** — cost gates, path
filters, "did anything security-relevant change". Ask *what is the earliest commit that can trip this, and
does it then trip forever?*

**TWO THINGS THAT ARE NOT THE FIX, recorded so they are not tried:**

- **Do NOT switch to a per-commit diff.** The PR as a whole is what gets merged, so per-commit classification
  would skip a leg for a change that IS in the merge. Cumulative is correct; stickiness is its cost.
- **Do NOT read the skip as a bigger win than it is.** `docs_only` cannot fire on a story branch that already
  contains code — so end-of-story documentation pushes are covered by the narrowed `go=false` path, **not** by
  the docs-only skip. Stating that plainly is the difference between a measured result and a claim.

**And `e2e` stays on every push.** It is parallel, sits under the post-fix floor, and deferring integration
proof to merge time finds breaks at the most expensive moment.

---

# ⛔ WHEN RE-TESTING AN OLD FAILURE, PIN THE TREE IT WAS WRITTEN AGAINST

**S14.15.** Two reds written at S14.13 were re-measured at S14.15 and appeared to reproduce in isolation,
refuting three sessions of "it is cumulative". **The refutation was false.** The tree had since gained
S14.14's directory-sync panel, which renders *"status unknown"* once per provider — so a singular query now
matched **twice** and threw. **A different failure, with a different message, standing exactly where the old
one had been.**

Suppressing only the new panel restored the truth: alone it **passes**, in the full file it **fails with the
original errors**. Cumulative after all.

> ## **CHANGING THE SUBJECT AND THE INSTRUMENT IN THE SAME STEP IS NOT RE-MEASURING. A failure re-tested on a**
> ## **tree that has moved is a NEW experiment wearing the old one's name — and it is most convincing exactly**
> ## **when the new symptom lands in the same place as the old.**

**The cost was not the wasted measurement.** The false refutation was used to argue an ORDERING decision to
the founder. *A wrong direction is worse than not having looked* — with a decision attached to it.

**MECHANICAL:** before re-running an old red, either check out the commit it was written against, or suppress
everything that has landed on that surface since. Then compare the ERROR TEXT, not just pass/fail: a changed
message means a changed defect.

---

# ⛔ `needs:` FOR AN OUTPUT IS ALSO A GATE ON SUCCESS

**S14.15.** `e2e`, `e2e-enterprise` and `visual` were given `needs: gates` **solely to read
`needs.gates.outputs.docs_only`**. That silently added a success condition: when `gates` went red, all three
reported **`skipped`** — so the integration signal disappeared **exactly when something was broken**, which is
when it is worth most. Observed live, not predicted.

> ### **WHEN YOU WANT THE VALUE AND NOT THE CONDITION, WRITE `if: always() && …`.**

**Same family as *a skipped job reads as not-applicable*:** a check that reported **nothing** looked like a
check that **found** nothing. The earlier instance was a security job skipped by a classifier; this one is a
dependency added for an unrelated reason. **Both times the absence of a result was mistaken for a result.**

## ⛔ A COMPILE ERROR IS A MUTATION THAT NEVER APPLIED, WEARING A PASS'S CLOTHING

A mutation that swapped a recorded count to `0` orphaned a variable, so the package failed to **compile** and
the harness scored it *caught*. It proved nothing. **Re-run with the variable kept alive, it caught on the
assertion.** Belongs with *a mutation that failed to apply proves nothing* — the new part is that a BUILD
failure is one of the disguises, and it is the most convincing one because the exit code is identical.

## ⛔ AND MY MATCHERS KEEP ASSUMING A CANONICAL RENDERING THE PRODUCER NEVER PROMISED

**Second instance in two stories.** First: `<Input\b([^>]*?)\/>` found ZERO inputs in a tree of five, because
JSX arrow functions contain `>`. Second: `"members_removed":2` failed against a correct row, because postgres
renders jsonb **with a space after the colon**.

> ### **A MATCHER OVER A FORMATTED ARTIFACT IS A GUESS ABOUT THE FORMATTER.** Query the STRUCTURE — parse the
> ### JSON, read the attribute, ask the database — rather than pattern-matching its printed form.

Both were caught only because the surrounding check had a floor or a known-answer case. **A matcher with
neither would have reported a clean tree and been believed.**

---

# ⛔ A NUMBER QUOTED FROM AN OLD REGISTRATION OUTLIVES THE THING IT COUNTED

**EPIC 14, found 2026-08-03.** "EPIC 14's remaining **eight** screens" was carried in instructions and in
`PLAN.md` for several stories after it stopped being true. The figure came from the **S14.2 registration** and
was never decremented as stories shipped. **Ten had shipped; two remained.**

> ## **A COUNT WRITTEN ONCE BECOMES A FACT BY REPETITION. Nobody re-derives a number that is already written**
> ## **down — it gets quoted, and each quotation makes it look better attested.**

**Neither of us noticed**, and it was caught only because a screen census was run for a different reason.

**MECHANICAL:** a count in a plan is a **derived** value. Either re-derive it at the point of use (`ls` the
screens, run the census) or write it as *"N as of <story>"* so its age is visible. **A bare number carries no
expiry date and therefore never appears stale.**

**Same family as the sticky-classifier and stale-artifact laws:** something computed once kept being trusted
long after the thing it described had moved.

---

# ⛔ A FALLBACK THAT REUSES A MEANINGFUL TERM HIDES THE CASE IT FALLS BACK FROM

**S14.16.** The Audit Log rendered `actor_id ? name : "system"`. But **"system" was already the correct word
for a NAMED subsystem** — 26 of 100 rows carried `actor_system`. So the fallback for *we do not know who* was
the same token as *we know exactly who, and it is a machine*.

> ## **THE GAP WAS NOT MERELY UNFIXED — IT WAS INVISIBLE, because every unattributed row rendered as a**
> ## **legitimate, well-understood category.** Nobody reports a bug that reads like a correct answer.

**GENERALISES PAST THIS SCREEN:** an `else` branch, a `default:` case, a `?? "unknown"`, a placeholder — **if
its value is a term that means something specific elsewhere in the same view, the two states merge and only
the meaningful one is ever seen.**

**MECHANICAL:** for every fallback, ask *does this token already carry meaning in this view?* If it does, the
fallback needs its own word — and usually its own visual weight, because a genuine gap is not metadata.
**Related, and the reason this one survived so long:** the same defect made the count wrong too, so even a
tally of "system rows" would have agreed with itself.

---

# ⛔ A VALUE THE CLIENT INVENTED, SITTING WHERE A SERVER FACT BELONGS

**Two instances, same class, OPPOSITE DIRECTIONS — which is why the second one was not recognised as the
first.**

| | what happened | direction |
|---|---|---|
| **S14.11** | a **failed read** rendered as **NOT CONFIGURED** | invents absence |
| **S14.16** | a **form default** (`useState(true)` + an unconditional `••••••••`) rendered as **CONFIGURED** | invents presence |

> ## **THE SHARED DEFECT IS NOT "WRONG DEFAULT" — IT IS THAT A CLIENT-SIDE VALUE OCCUPIED THE POSITION WHERE**
> ## **A READER EXPECTS A SERVER FACT.** Looking for the first shape does not find the second, because the
> ## symptom is inverted while the mechanism is identical.

**MECHANICAL:** for every control rendered before or without a successful read, ask *what does a reader
conclude from this, and did the server say it?* A checkbox, a placeholder and an empty string all make claims.

## ⛔ AND PIN BOTH ARMS — A TEST THAT ONLY PINS THE FIX PASSES A WRONG IMPLEMENTATION

Of the five mutations on this fix, **two were OVER-CORRECTIONS** — always-intent, never-dots — not the
original bug. Both are wrong in the *other* direction, and **both look careful.**

> ## **A CHECKBOX THAT IS ALWAYS CHECKED CANNOT BE TOLD FROM ONE THAT IS CORRECTLY CHECKED — and neither**
> ## **can one that is never checked. A test asserting only the arm you just fixed certifies the direction**
> ## **of your last edit, not the behaviour.**

Assert the positive AND the negative arm, and assert that **the two differ** — that third assertion is the one
that survives both over-corrections.

## SAME GLYPH, DIFFERENT CLAIM — AND THE COPY IS WHAT DECIDES

The directory-sync credential form shows the **same `••••••••`** and was correctly left alone: its own copy
says *"the fields below always start empty even when a credential is stored"*, so the dots assert nothing
there. **The glyph is not the claim; the glyph PLUS the surrounding text is.** A sweep for the character would
have "fixed" a correct panel.

---

# ⛔ A LEDGER SEES ONLY THE SHAPE IT IS KEYED ON

**S14.17.** Two censuses, two shapes, and the collapsible sidebar escaped **both**: `screencensus` is keyed on
**pages**, `wireframecensus` on **screen banners**, and a shell component is neither.

> ## **AND THE GAP IS NOT CLOSED — IT IS NARROWED. Anything that is neither a page nor a banner still has no**
> ## **ledger:** a modal, a toast rule, an empty state, a keyboard binding, a notification policy. Saying "the
> ## census now covers the design" would be the same over-claim the census was built to catch.

**MECHANICAL:** when a ledger misses something, ask *what SHAPE was it keyed on, and what shape was the thing?*
Adding a row rarely fixes it; adding a **second key** sometimes does; and the honest close is to name what
neither key can see.

## ⛔ CHECK EVERY OCCURRENCE, NOT THE FIRST

The sidebar spec's **first** `228px` sits inside the DESKTOP CLIENT block — which would have scoped it as
desktop-only and made S14.18 part of S14.20. Every occurrence shows it in the **shared preamble** as well, so
it is a shell component.

**Same discipline as reading the whole error rather than the last line, and the same failure mode as a
first-match `grep` standing in for a census.** A first hit answers *does this exist*; it never answers *where
does this belong*.

---

# ⛔ THE RENDER FLOOR REACHES A LEGAL CLAIM MADE TO A STRANGER

**S14.17, and this is the furthest the rule has travelled.** It began as *a chart must name the endpoint it
draws from*. It now governs **"SOC 2 Type II certified"** on the login page — a **compliance claim with zero
backing anywhere in the repository**, shown to every visitor **before they authenticate**.

> ## **SAME MECHANISM, DIFFERENT BLAST RADIUS. The chart misleads an OPERATOR, who can check. The badge**
> ## **misleads a BUYER, who cannot — and who is being asked to rely on it.**

Alongside it, **"SSO + SCIM enterprise ready"**: SSO ships, SCIM is explicitly OUT of v1 and deferred to
S7.5.2b. **The badge is half true and the false half is the specific standard named** — the half a buyer
checks.

**NEITHER IS DELETED. BOTH ARE GATED ON THE THING THAT WOULD MAKE THEM TRUE** — see the register. A cut claim
with no return condition is just a claim someone re-adds later with no argument to defeat.

## ⛔ THE CENSUS WORKED ON ITS AUTHOR, ONE STORY AFTER HE WROTE IT

`wireframecensus` requires a `built` disposition to name a route that exists — written specifically so a
disposition could not be aspirational. **One story later it refused MY OWN claim** that AUTH SCREENS was done:
the block also specifies a forced-enrollment modal that cannot be dismissed by click-away or Esc, and
`MfaSettings` has no such handling.

**That is the strongest evidence the mechanism has teeth** — a guard that has only ever caught other people's
work is untested.

## ⛔ AN EXEMPTION LIST IS HOW A CENSUS QUIETLY BECOMES THE CODEBASE

The forbidden-claim census first caught the comment **explaining the cut**. The instinct was a second file
exemption. **Refused:** it strips comments and keeps every file in scope instead — a claim in a comment is not
rendered and is not a claim; a claim in a string is.

**Every exemption is a place the census stops looking, and the reason is always good at the time.**

## ⛔ AND THE VACUITY FAMILY HAS A TIME AXIS

`main` went red on a **sync assertion against async content**: `queryAllByText` ran before the card it looked
for had rendered, and the `waitFor` above it waited on a **different element**. It passed locally twice and in
isolation — **the same sha that failed on CI.**

**Reproduced rather than theorised:** a 25ms delay on every mocked GET fails the old form with CI's exact
message and passes the new one, same file, one line apart.

> ## **THE EARLIER INSTANCES REPORTED ON A STATE THEY NEVER REACHED. THIS ONE REPORTED ON A STATE THAT HAD**
> ## **NOT ARRIVED YET.**

**AND THE ASSERTION ORDER IS HALF THE FIX:** await what must APPEAR, then assert what must be ABSENT.
**Absence-first passes trivially before anything renders at all** — a green that means *too early to tell*,
which is indistinguishable from a green that means *correct*.

---

# ⛔ THE WIREFRAME IS RELIABLE ABOUT LAYOUT AND UNRELIABLE ABOUT ANYTHING THE SERVER COMPUTES

**Third instance, S14.19 — and the mechanism is now clear enough to predict the next one.**

| story | the design drew | the server actually does |
|---|---|---|
| S14.12 | `polFlow` — 4 sources, 4 destinations, 5 hand-authored edges | a rule table the picture never reads; the derivation is OURS to design |
| S14.14 | `_tunnex-verify.acme.io TXT "tnx-domain-…"` | resolves the **APEX**, compares `tunnex-verify=<token>` by exact equality |
| S14.19 | four verdict chips: allow · deny · deny_aggregate · terminated | **FIVE** decisions — the fifth, `gap`, means **THE LOG IS INCOMPLETE** |

> ## **ITS AUTHOR COULD ONLY DRAW WHAT THEY COULD SEE. Layout, hierarchy, density and tone are**
> ## **VISIBLE and the design is authoritative about them. A derivation, a comparison, an enum's**
> ## **fifth member and a refused inference are INVISIBLE — and the picture is silent, not wrong,**
> ## **which is why building to it faithfully still produces a defect.**

**The S14.19 case is the sharpest:** building the four chips the design drew would have rendered a
**tamper-evidence marker as an ordinary row, or dropped it** — presenting an incomplete security log as a
complete one.

**MECHANICAL, and it is cheap:** for every screen, diff the design's ENUMERATIONS against the schema's —
chips, tabs, states, badges, columns. Where the design has fewer, ask what the extra one MEANS before deciding
it is unimportant. **A missing state is usually the failure state**, because a designer drawing a healthy
product has nothing to look at when drawing it.

## ⛔ AND A REFUSED INFERENCE IS NOT MISSING DATA

`device/user are DEFERRED (nil) — never derived from a racy src_ip lookup`. The design paired a name with the
address; the server declines to guess one, because an address maps to a device only through a lease that may
since have moved.

> ### **A WRONG NAME IN A SECURITY LOG IS WORSE THAN NO NAME.** Render what was attributed, and say why the
> ### rest is absent — the same family as *"could not check" is not "empty"*.

---

# ⛔ A DELIMITER WITH NO TERMINATOR MAKES THE LAST ITEM ABSORB EVERYTHING TO EOF

**S14.20.** The banner census measures each screen block as **start-to-next-start**. For the FINAL banner
there is no next start, so `DESKTOP CLIENT` was measured as **167,263 chars — "the largest block by 5×"**.

**It is 11,966.** The other 155k is four app-wide overlay specs (⌘K palette, detail drawer, bulk action bar,
onboarding checklist) that merely sit after it in the file.

> ## **THE NUMBER WAS COMPUTED, WHICH IS EXACTLY WHY NEITHER OF US DOUBTED IT. A measured figure carries an**
> ## **authority a guess does not — and this one measured the wrong EXTENT, not the wrong thing.**

**AND IT INVERTED THE CONCLUSION.** "Largest block by 5×" framed the desktop client as the biggest remaining
build. **It is the SMALLEST screen spec in the file** — which is what the founder had been saying about the
client all along, against a number that appeared to contradict him.

**MECHANICAL:** when a census measures RANGES, the last range is unbounded unless something terminates it.
Either give the delimiter an end marker, or **treat the final element's extent as unmeasured** rather than as
measured-and-large. Same family as the vacuity floor: the check ran, the arithmetic was right, and the
subject was wrong.

## ⛔ AND `find(1)` LISTS THE WORKING TREE, NOT THE INDEX

In the same pass I reported that **`apps/client/release/` was committed to git — "a full built .app in
version control"**. It was not. **Zero tracked files, and `.gitignore:60` already covers it.** It is 1.0G of
local build output that `find` listed because `find` does not know what git is.

**The founder ruled on that premise** — remove and gitignore — and the ruling was already satisfied before it
was made. **A wrong premise that produces a plausible instruction is worse than an obvious error**, because
the instruction gets carried out.

**MECHANICAL:** never report repository state from a filesystem walk. `git ls-files` for what is tracked,
`git log -- <path>` for what ever was, `git check-ignore -v` for why not. All three are one line.

---

# ⛔ A CAUSE INFERRED FROM A SYMPTOM'S NAME IS NOT A DIAGNOSIS

**S14.20.** A SIGKILL was reported launching Electron. *"SIGKILL on an unsigned Electron binary"* is a real,
well-known macOS failure — so Gatekeeper **fitted**, and a README section was written with working commands
to fix it.

**It never reproduced.** The report came from a **different clone on a branch ten stories old** with no client
work and **no `Electron.app` installed at all**. The binary was ABSENT, not blocked.

> ## **AND THE FIX'S COMMANDS WERE REAL, WHICH IS WHAT MADE IT DANGEROUS. `xattr -cr` and an ad-hoc re-sign**
> ## **both run, both do something, and neither confirms the cause. REAL COMMANDS AROUND AN UNCONFIRMED**
> ## **CAUSE READ AS EVIDENCE** — and once written down they become the next person's starting assumption.

⛔ **The tell was present and ignored: I wrote "I could not reproduce it" IN THE SAME COMMIT that shipped the
remedy.** Stating the doubt is not the same as acting on it. A cause you could not reproduce is a
**hypothesis**, and a hypothesis in a README is indistinguishable from a finding.

**MECHANICAL:**
- **Reproduce, or label it a lead.** Documentation may carry "if X, check Y" — it must not carry "X is caused
  by Y" without a reproduction.
- **Verify the TREE before diagnosing the CODE.** Clone, branch, head, files present, deps installed. Two
  clones caused two separate confusions in this epic — a stale served bundle, then this.
- **A missing artefact and a blocked artefact fail differently.** `NO Electron.app` and `Killed: 9` are not
  the same sentence, and the first was never checked.

## ⛔ THE STRONGEST INSTANCE YET — AND IT CAME ONE DAY AFTER FILING THIS LAW

**2026-08-04.** A host was needed for the WF-S13-7 enrolment. `azure-gw` was checked and reported **bare**:

```
docker ps -a          -> no containers
docker volume ls      -> no tunnex volumes
wg show interfaces    -> none
```

**All three answers were correct.** The host was nonetheless running a live gateway — `/usr/local/bin/tunnex-node`,
pid 48233, up 7 days, holding `:53` on two addresses and an established control-plane connection, alongside an
`openvpn` server. **`azure-gw` the SSH alias and `k8s` the node are the same machine**, and it was the gateway the
founder's own laptop had been homed on.

> ## **"NO CONTAINERS, NO VOLUMES, NO WG INTERFACES" WAS A COMPLETE AND CORRECT ANSWER TO A QUESTION**
> ## **NOBODY ASKED.** Three container-surface checks on a host that runs the agent NATIVELY.

The cost: a second agent was enrolled into one network namespace — an unapproved state — and the planned run
would have taken a fleet-wide 10-minute certificate TTL and a control-plane partition across a **live**
gateway that was never in the approved blast radius.

**MECHANICAL — BEFORE CALLING A HOST BARE, CHECK `ps` AND `ss`, NOT JUST `docker`. A PROCESS IS NOT A
CONTAINER.**
- `ps aux | grep <product>` and `ss -tulpn` answer "is anything running", which is the actual question.
- `docker ps` answers "is anything running **the way I expect it to be run**" — a narrower question that looks
  like the same one.
- An SSH alias is not an inventory. Confirm which node row a host owns before treating it as free.

---

# ⛔ ANY CENSUS OVER SOURCE STRIPS COMMENTS FIRST — AS THE STARTING SHAPE

**S14.20, ruled by the founder after the THIRD instance in one epic.** A census searches source for a string.
**A comment is the most likely place in a file for the exact string the census hunts for** — the code does the
thing once, and the prose ABOUT the thing quotes it, explains it, and names the alternative it rejected. A
search over raw source is therefore biased toward finding the *explanation* rather than the *implementation*,
and **the better-documented the file, the more reliably the census lies.**

The three:
1. `placeholderglyph` banned an em-dash as a rendered value and caught **its own comment about em-dashes**.
2. A `@ts-expect-error` written inside a comment *to describe one* became a live directive.
3. The `client.html` entry check passed **with the flip reverted**, because the comment explaining the flip
   contains `client.html`.

⛔ **The direction of the lie is FALSE GREEN.** The census reports the thing present when only its description
is present — so unlike a false red, nothing ever surfaces it.

> ## **AND THE SHARPEST CASE WAS FOUND BY THE RETROFIT, NOT BY A FAILURE.** `visualgallery.test.ts` asserts
> ## `it("the route is guarded by an env flag, NOT BY A COMMENT")` — and read `App.tsx` **raw**. Mutation:
> ## replace the guard with `true /* was: import.meta.env.VITE_VISUAL_GALLERY === "1" */`. **Pre-retrofit:
> ## PASSED. Post-retrofit: FAILED.** The visual gallery could have shipped ALWAYS-ON with its guard green.

**A TEST THAT NAMES A HAZARD IN ITS OWN TITLE IS NOT DEFENDED AGAINST IT.** Same shape as writing "I could not
reproduce this" in the commit that ships the remedy — stating the doubt is not acting on it.

**MECHANICAL:**
- Strip **before** the search, in `apps/web/test/support/source.ts`. Never re-derive it inline; three copies
  had already diverged (one stripped `//` mid-line and would have eaten every URL in the tree).
- **The stripper must match the LANGUAGE.** There is no universal comment syntax, and the JS stripper on a
  YAML file removes nothing while looking like it worked — a green check that never ran. One function per
  syntax (`js` · `css` · `xml` · `yaml`), chosen at the call site.
- `//` and `#` strip at **line start only**. A mid-line strip eats `"https://…"` and trades a false green for
  a false red.
- Enforced by `censuscensus.test.ts`: any test calling `readFileSync` imports a stripper or is **registered**
  with a reason. The register is checked against the stripped body of the test itself — a test that merely
  *mentions* `support/source` in a comment has not imported it. **The rule applied to its own enforcement.**

---

# ⛔ A VERIFICATION ARGUMENT YOU CONSTRUCTED IS NOT A VERIFICATION

**S13.1 merge, 2026-08-04.** The merge command carried `--match-head-commit`, an integrity check whose whole
purpose is to refuse if the branch moved since it was inspected. The sha passed to it was **fabricated**: the
short form `ceea882e` was padded out with **32 invented hexadecimal characters** to look like a full one.

```
passed:  ceea882e6bd7f1bfa4a0b0b31e0bbf6f3f3ec9e9   <- invented
actual:  ceea882ea3d057fc1c4f0c0d0253efbb89c87878
```

GitHub refused: *"Head branch was modified."* **The check was real. The input was fiction. From the command
line the two are indistinguishable** — a well-formed 40-character hex string is exactly what a correct
invocation looks like, and nothing about the shape of the argument reveals that it was assembled rather than
read.

> ## **THE INSTRUMENT WAS SOUND AND THE SUBJECT WAS MADE UP.** Same family as the artifact `grep` aimed at
> ## `dist/` instead of the tracked tree, and the census that matched its own explanatory comment: in each
> ## case the check would have passed its own review, because the defect is in what it was pointed at.

⛔ **AND NOTE WHAT SAVED IT: A FLAG THAT COULD HAVE BEEN OMITTED.** `gh pr merge --squash` without
`--match-head-commit` merges whatever is at head, silently, including a head that moved after CI went green.
The safety here was not diligence at the moment of the error — it was a habit adopted earlier.

**MECHANICAL:**
- **`--match-head-commit` is MANDATORY on every merge.** Not a nicety, not usually — every one.
- **Never type a sha. Read it.** `gh pr view <n> --json headRefOid -q .headRefOid`, or `git rev-parse <short>`.
  A sha that was not produced by a command is not a sha.
- **Never expand a short sha by hand.** `git rev-parse` exists precisely so the expansion is done by something
  that can fail.
- The same rule covers any identifier used AS a check: digests, content hashes, run ids. If it is being used to
  prove that two things are the same thing, it must have been read from one of them.

---

# ⛔ A LONG-LIVED BRANCH CAN HOLD A FIX `main` NEVER GOT — AND A REWRITE CAN MULTIPLY THE BUG IT INHERITED

**S13.1 merge, 2026-08-04.** S13.1 fixed device creation homing on a **REVOKED** gateway: `nodes[0]` indexes a
list that includes revoked rows ordered by `created_at`, so on any deployment whose oldest gateway had been
revoked, **every new device was homed on a dead one and handed a one-time config that could never connect** —
and a one-time secret cannot be re-issued.

The branch forked at EPIC 11 and sat for weeks. In that time:

1. **`main` never received the fix.** It was still calling `nodes[0]` on the day of the merge.
2. **EPIC 14's rewrite of `Devices.tsx` ADDED A THIRD CALL SITE.** The fix had been written against two.

> **A CONFLICT RESOLUTION THAT TAKES EITHER SIDE WHOLESALE WOULD HAVE DROPPED IT SILENTLY** — `--ours` keeps
> the bug and loses the rewrite; `--theirs` keeps the rewrite and loses the fix. Neither produces a failing
> test, because the test lives on the branch and the bug lives on `main`.

**MECHANICAL:**
- On any long-lived branch merge, list the files changed on BOTH sides and read what each side changed — the
  overlap is where fixes go to die. (Here: 123 files changed by the branch, **19** also touched on `main`.)
- **Re-apply, then MUTATION-PROVE the re-application.** Reverting the re-applied fix must fail a test. Without
  that step "I re-applied it" is a claim about intent, not about behaviour.
- Expect call sites to have MULTIPLIED, not merely moved. Count them on both sides before resolving.

---

# ⛔ A VALUE THAT EXISTS ONLY IN A SHELL INVOCATION IS NOT CONFIGURATION

**2026-08-04, found while scoping the `azure-cp` deploy — before the rebuild, not after.**

The API's open-core edition is chosen by a Docker build arg:

```yaml
args:
  TUNNEX_BUILD_TAGS: ${TUNNEX_BUILD_TAGS:-}   # empty builds the OPEN image
```

`make up-enterprise` supplies it **on the command line** and does not persist it. So a host running
as enterprise carries that fact in **shell history**, and `.env` — the file every operator would read
to learn how the host is configured — says nothing about it.

> ## **A PLAIN `docker compose up -d --build` WOULD HAVE SILENTLY REBUILT THE ENTERPRISE CONTROL**
> ## **PLANE AS OPEN.** Policy, device posture, MFA enforcement and IdP sync begin returning
> ## `403 edition_required` — and **nothing about the deploy looks like it failed.** Every container
> ## comes up healthy, `--wait` is satisfied, and the capability is simply gone.

**This is the third instance of one shape this week**, and the shape is what matters more than the
instance:

| where the value lived | what it did quietly |
|---|---|
| a digest pinned in `.env`, never forwarded to the container | the pin no-op'd; the emitted enroll command shipped a stale image (WF-S13-7) |
| `nodes[0]` indexing a list that includes REVOKED rows | every new device homed on a dead gateway, holding a one-time config that can never connect |
| an edition selector living in shell history | a rebuild downgrades the control plane and reports success |

**A VALUE LIVING SOMEWHERE NOBODY CHECKS, DOING THE WRONG THING QUIETLY.** In all three the system
is behaving exactly as written; what is missing is anywhere to *look* that would say so.

⛔ **PERSISTING IT IS THE FIX, NOT A PRECAUTION.** Writing `TUNNEX_BUILD_TAGS=enterprise` into `.env`
does not merely reduce the chance of the mistake — it moves the value into the file that defines the
host, where a later reader and a later rebuild both find the same answer.

**MECHANICAL:**
- **If a build produces a materially different artifact depending on an argument, that argument
  belongs in the environment file, not in a Makefile target.** A convenience target may still pass
  it; it must not be the only place it exists.
- **Verify the CAPABILITY after a deploy, not the container state.** `docker compose ps` said healthy
  in the failure case too. `/api/v1/meta` reporting `"edition":"enterprise"` is the check that would
  have caught it — read the property back out of the running system.
- **Ask of any deploy: what is true about this host that is written down nowhere?** The answer is
  usually short, and usually the thing that breaks.

---

# ⛔ A GUARD MADE THE CALLER'S RESPONSIBILITY IS INHERITED BY EVERY NEW CALLER

**2026-08-04, found on the first deployed dashboard.** A revoked gateway was rendering the literal word
**"healthy"**, in green, on the Dashboard's Gateway Health panel. `revoked` IS the state; a health verdict
beside it describes a machine that is no longer meant to work.

**This is the THIRD time the same defect has been fixed** — `Gateways.tsx` at EPIC 11, `sitesview.ts` at
S13.1 — and S13.1's own comment explains why it recurred: *"that fix was component-local, which is why this
one lives in the view-model."* That reasoning was right and **still landed in a view-model that turned out to
be one of several.**

## The census is the finding, not the instance

Seven places form a health verdict about a gateway. **Four guard `revoked`. Three do not.**

| guarded | site |
|---|---|
| ✅ | `components/Gateways.tsx` — `n.status !== "revoked" &&` |
| ✅ | `lib/sitesview.ts` — `n.status === "revoked" ? null : policyHealthBadge(n)` |
| ✅ | `lib/gatewaysview.ts` — **the same line, copy-pasted** |
| ❌ | `pages/Dashboard.tsx` Gateway Health — renders "healthy" for a revoked node |
| ❌ | `pages/Dashboard.tsx` Needs Attention — a revoked node can be listed as needing attention |
| ❌ | `pages/Dashboard.tsx` the degraded COUNT — a revoked node inflates it |
| ❌ | `pages/Kubernetes.tsx` — filters on `policy_degraded_kind`, no status check |

> ## **THE THREE CORRECT SITES CARRY THE SAME LINE COPY-PASTED. THAT IS THE TELL.**
> ## **A rule that must be RESTATED at each site is not enforced — it is remembered.**

And two of the three broken sites **never call the badge function at all**; they read `policy_degraded`
directly. **So fixing the function would have been the fourth instance of the same mistake and would not
have reached them.**

## The type made the omission not merely possible but MANDATORY

```ts
policyHealthBadge(node: Pick<Node, "policy_degraded" | "policy_degraded_kind">)
```

This does not fail to check `status` — it makes checking **impossible**. A caller cannot pass status; the
compiler is satisfied by an object that does not have one. **The function is structurally forbidden from
forming the verdict it is named for**, which is precisely why the guard ended up outside it.

**MECHANICAL — the difference between FIXED and IMPOSSIBLE:**
- **Widen the parameter so a caller that forgets does not compile.** Requiring the whole `Node` moves the
  guard inside, once, where the verdict is formed; the copy-pasted guards become redundant.
- **When a guard appears verbatim at more than one call site, that is a defect report about the callee**,
  not a sign of diligence at the callers.
- **Census by the INPUT, not by the function name.** Two of the three broken sites were invisible to a
  search for callers, and visible immediately to a search for `policy_degraded`.
- ⚠ **A raw field read can bypass any function.** The degraded COUNT is
  `.filter(n => n.policy_degraded).length`; a widened signature ENABLES correct sourcing but cannot FORCE
  it. Say so rather than reporting the class closed.

## ⛔ AND THE SAME SHAPE ONE LEVEL UP: A SAFETY CLAUSE REUSED WITHOUT RE-DERIVING WHAT IT PROTECTS

**2026-08-04, two deletes an hour apart.** The first removed revoked walk rows and carried
`AND status = 'revoked'` as a belt — so a mistyped id could not reach a live gateway. The second removed an
orphaned node created by an aborted enrolment, and the row to remove **was the active one**, so the correct
belt was `AND status = 'active'` — the exact inverse.

> **A COPIED PREDICATE WOULD HAVE PROTECTED THE WRONG THING.** The guard that was correct an hour earlier
> was, by then, precisely backwards: it would have excluded the only row the statement was meant to touch
> while leaving the rows that must never be touched eligible.

It is the caller-inherited guard one level up. There, a rule restated at each call site was remembered rather
than enforced. Here, a rule **restated in each statement** is worse — it looks identical, so re-derivation
feels redundant exactly when it is load-bearing.

**MECHANICAL:** a safety predicate is derived from *what this statement must not touch*, never copied from the
last one that worked. State the protected set out loud before writing the clause.

---

# ⛔ A FIXTURE THAT ENCODES THE ANSWER IN THE NAME MAKES DISAMBIGUATION UNNECESSARY

**2026-08-04, from the first look at real data.** The deployed dashboard listed `aws-gw-1` **three times** and
`aws-gw-2` **twice** — same names, different ids, contradictory states. Nothing in the panel distinguished
them.

The panel is served `id · name · status · agent_version · enrolled_at · last_seen_at · policy_degraded ·
site_id · max_policy_version · ovpn_health · is_site_hub · policy_degraded_kind`. **It renders `name` and a
badge.** `id` is used as a React key and then discarded; `status` and `enrolled_at` are received and dropped.

Our fixtures name gateways **`gw-active`** and **`gw-revoked`**.

> ## **THE FIXTURE DOES NOT MERELY AVOID THE AMBIGUOUS CASE — IT MAKES DISAMBIGUATION UNNECESSARY.**
> ## The name alone tells you the state, so a panel that renders ONLY the name looks complete.

Every screen reviewed in EPIC 14 was reviewed against data of that shape. **No screen has ever been shown two
rows sharing a name.** Real deployments produce them routinely: a gateway is decommissioned and the host is
re-enrolled under the same hostname.

**MECHANICAL:**
- **The corrected fixture is two rows, ONE name, different states** — e.g. two `edge-gw` rows, one `active`
  and one `revoked`, differing `enrolled_at`, one with a `site_id` and one without.
- **Expect it to turn several reviewed screens red.** That is the point: a fixture change that breaks nothing
  has not added a case.
- **A fixture whose names carry semantics is testing the reader, not the renderer.** Name rows for what they
  ARE (`edge-gw`), never for what they are FOR (`gw-revoked`).

---

# ⛔ WE RULED ON A DELETE WITHOUT ASKING WHAT CASCADES

**2026-08-04, rig cleanup.** A delete of three `nodes` rows was proposed and approved. `devices.node_id` is
**`ON DELETE CASCADE`**, so the statement would have removed **10 devices** it does not mention. It was caught
only because the FK graph was read before writing the SQL.

## THE RULE THAT CAUGHT IT IS ONE WE WROTE FOR THE PRODUCT AND DID NOT APPLY TO OURSELVES

S14.12's second absence question, verbatim: *"What happens after each destructive verb, and is the operator
told? Read the FK actions and the handler's response body."* It found `ON DELETE CASCADE` on three columns —
deleting a group silently deleted every rule referencing it, and the 204 said nothing.

> ## **WE APPLIED THAT QUESTION TO OUR HANDLERS AND NOT TO OUR OWN `psql` SESSION.** A rule filed as a
> ## product standard is not a personal habit until it is exercised where WE are the operator.

**Two further things the incident produced, both of which nearly went unasked:**

⛔ **THE DELETE LIST QUIETLY GREW TO MATCH A SENTENCE.** "The three from 07-30/07-31" described two rows; a
third was from 07-23 and got swept in to make the count work. Corrected to two. **A destructive set that
expands to fit a description is the wrong shape** — the description should be corrected, not the set.
⚠ And removing that row changed the cascade by **zero**: it had no devices. A change made for tidiness
altered nothing about the blast radius, which is worth knowing before assuming a smaller list is a safer one.

⛔ **THERE WAS NO BACKUP.** No dump files, no cron, no systemd timer — the only `backup` unit on the host was
Debian's `dpkg-db-backup`, which is the package database. **The rig held walk evidence that exists nowhere
else, with no backup**, while its rows were being cited as "the only surviving evidence" in an argument for
keeping them.

**MECHANICAL:**
- **Before any destructive statement, query the FK graph** — `information_schema.referential_constraints`
  joined to the referencing tables — and **enumerate the rows each cascade takes**, not just the count.
- **Back up first, and VERIFY THE BACKUP BY RESTORING IT.** `pg_restore -l` proves the dump lists a table; it
  does not prove the table has rows. Restore to a scratch database and compare counts against live.
  (Here: 7 nodes / 43 devices in both.)
- **A backup that lives only on the box it protects survives a bad `DELETE` and not a lost host.** Say which
  of the two you have.
- **Wrap it in a transaction, verify before `COMMIT`.** Add a predicate that makes the catastrophic case
  impossible rather than unlikely — `status = 'revoked'` alongside the id list, so a mistyped id cannot reach
  a live gateway.

---

# ⛔ THE SAFE STATE MUST NOT DEPEND ON REMEMBERING A REGISTRY — AND WHEN IT DOESN'T, THE ESCAPE IS THE HAZARD

**S15.1, 2026-08-04.** A brand-new `PUT` endpoint answered a **sessionless** request with
`400 validation_failed` instead of `401`. The OpenAPI request validator rejected the required body **before
the auth layer ran**, so an unauthenticated caller learned the endpoint exists and what shape it expects.

> ## **A NO-ORACLE VIOLATION ON AN ENDPOINT THAT WAS HOURS OLD, AND THE AUTHOR DID NOT FIND IT.**
> ## `TestSessionlessRequestsAre401` did, on CI, doing exactly what it was built for.

## THE GOOD HALF — the guard fails CLOSED, which is why this is not the usual entry

Any new operation with a **required body** has this defect by default until it is registered in the walk's
body map. **The obvious worry is that a new op can silently forget the registry.** Measured: **it cannot.**
The walk enumerates every operation in the spec and skips only those the SPEC marks public
(`security: []` — `authwalk_test.go:101-104`). **There is no exemption list and no opt-out.** Forgetting the
entry produces a **failing test**, not a silent pass.

**That is the shape we want and it should be said out loud, because this repo more often records the
opposite:** the registry is the FIX, not the GUARD. Missing it is loud.

## ⛔ AND THAT IS EXACTLY WHY THE ESCAPE IS THE HAZARD

The red says *"sessionless status = 400, want 401"*. **There are two ways to make it green:**

| fix | effect |
|---|---|
| register a valid body — the request reaches auth, and the 401 is the AUTH layer's answer | ✅ correct |
| ⛔ **mark the op `security: []` in the spec** | the walk **skips it entirely**, the red disappears, **and the endpoint is now genuinely public** |

**Both turn the test green. One of them ships an unauthenticated endpoint.** The second is *one line*, it is in
a different file from the test, and its diff reads like a spec tidy-up rather than a security change.

**MECHANICAL:**
- **A red that can be cleared by widening the thing under test is not a red, it is a prompt.** When a guard
  fails, enumerate the ways to make it green BEFORE picking one — and check whether any of them removes the
  subject rather than fixing it.
- **`security: []` in `openapi.yaml` deserves review attention proportional to what it disables**, because it
  is simultaneously the way to declare a genuinely public endpoint and the way to delete a test.
- A required body on a gated op is a **standing** shape, not a one-off: every future one starts defective and
  is caught. **Keep it caught — never make the walk's skip list data-driven from anything but `security`.**

---

# ⚠ REGISTERED, NOT SOLVED — A LOCAL GATE THAT FAILS WHERE CI DOES NOT

**S15.1, 2026-08-04.** `make test-editions` failed locally in `internal/agentca` (4 tests). The same tree
passes `go test ./internal/agentca/`, and CI's `gates` log shows those tests **not failing at all** — only
the 401-walk, which was a real defect.

⛔ **FOUR IRRELEVANT LOCAL FAILURES MASKED THE ONE THAT MATTERED.** The real defect was found by reading the
CI log, not the local run.

> **A LOCAL GATE THAT PRODUCES FAILURES CI DOES NOT IS A GATE PEOPLE WILL LEARN TO IGNORE** — and the cost is
> not the noise, it is the signal that arrives wearing the same colour.

**NOT CHASED, DELIBERATELY.** Recording it beats a guess about docker/alpine/`-mod=readonly` differences.
**TRIGGER: the next time `make test-editions` disagrees with CI on the same sha** — at that point there are
two data points and the difference is worth naming.

---

## CORE-FIRST: A NON-BLOCKING FINDING IS COLLECTED, NOT CHASED — FIRST RECORDED INSTANCE

**S15.1 close, 2026-08-04.** Setting up the D14 restore wire-proof, the local stack stopped answering on
`:80` and a `curl` timed out at two minutes. **It was collected in one line and not investigated.**

⛔ **THAT WAS THE RIGHT CALL AND IT IS WORTH A RECORDED INSTANCE, BECAUSE THE INSTINCT RUNS THE OTHER WAY.**
The stack is a local rig; nothing about it bears on `main`, on the merge, or on the proof that was owed —
and the proof itself turned out to be un-runnable for an unrelated and more important reason (no live
machine credential exists). Chasing the hang would have spent the turn on the least consequential of the
three facts in front of it.

**The distinction, stated per finding, in one line:** *does the current core deliverable depend on this
answer?* If yes it halts; if no it is written down and the core continues. ⚠ **Blocking still halts** — in
the same session, a query-lint failure that WAS mine and WAS in the gate path stopped the work until fixed.

---

## A CENSUS'S INPUT MUST BE THE SUBJECT, NOT A NAME THE CODEBASE SHARES

**S15.2 slice 4, 2026-08-04 — caught before it shipped, by running the gate it belonged to.**

D24 ruled that a second agent-principal constructor required the census to be **re-run as a merge gate**.
The first implementation censused assignments to the field name **`NodeID`** — and fired on access-log
events (`accesslog/ingest.go`, `store.go`) and device params (`devices/service.go`, `restore.go`), none of
which build a principal at all.

⛔ **IT WOULD HAVE SHIPPED PERMANENTLY RED.**

> ## **A GATE THAT CRIES WOLF GETS SUPPRESSED, AND THE SUPPRESSION OUTLIVES THE REASON.** A census that
> ## cannot distinguish its subject from a name the codebase happens to share is not a strict gate — it is a
> ## gate on its way to being deleted, and it takes the guarantee with it.

**The fix was to scope the match to the `Principal` composite literal**, so `NodeID` means the agent
identity field only where it is one.

⚠ **AND THE LESSON IS THE OLD LESSON, ONE LEVEL DOWN.** `policyHealthBadge` taught *census by INPUT, not by
function* — because two of seven sites never called the function. This adds: **the input has to be the
subject.** Censusing by input is not enough if the input is a token rather than a thing.

**Two properties every census gate needs, both now in `agent_principal_census_test.go`:**

- **a vacuity floor** — if it finds *zero* known sites it fails as broken, rather than passing forever
  because a package moved or a pattern rotted;
- **a proof it can fail** — a deliberately planted second construction site was caught by file and line,
  and removing it went green. *A gate that has only ever passed is indistinguishable from one that does
  nothing.*

---

## A GUARD WRITTEN FOR A HAZARD IS NOT A GUARD AGAINST THE HAZARD

**S15.2 / EPIC 15 walk Leg 4, 2026-08-04 — found on a live wire, not in review.**

`ListActiveWireGuardPeersForNode` has filtered `public_key <> ''` since S9.1, and **its own comment names
the general hazard**: *"a keyless row would make `wg syncconf` reject the ENTIRE config — one OpenVPN client
bricking the WG fleet."* An agent device row carrying `pending-agent-<uuid>` is **non-empty**, passed the
guard, and did exactly that: **zero peers configured on the gateway, including every human device.**

> ## **`<> ''` ASKS *IS THERE A KEY*. THE PARSER ASKS *IS THIS A KEY*.** Emptiness is a **special case** of
> ## malformedness, so a guard that tests the special case is **silent on the general one** — while its
> ## comment names the general hazard, **which is what makes it read as covered.**

⚠ **The comment is the trap, not the code.** A predicate with no explanation invites scrutiny. A predicate
whose comment names the full hazard has already answered the reviewer's question, wrongly, and nobody asks
twice.

### ⛔ THE SHAPE, SO IT CAN BE LOOKED FOR

> ## **ANY GUARD WHOSE PREDICATE IS CHEAPER THAN THE CONSUMER'S PARSE IS ONE PREDICATE TOO NARROW.**

Presence (`<> ''`, `IS NOT NULL`) is the cheapest possible predicate; parsing is the most expensive. Wherever
those two sit on the same value, the gap between them is unguarded — and it stays invisible while every
writer happens to produce well-formed values. **`public_key` was fine for years because everything writing it
produced real keys. The defect arrived with the first writer that did not.**

### CENSUS OF THE CLASS — measured 2026-08-04, filed, NOT fixed

**5 presence-only guards on values a downstream consumer parses:**

| value | guards | what parses it | status |
| --- | --- | --- | --- |
| `public_key` | 2 | `wg syncconf` / wgctrl key parser | ⛔ **FIXED** — now format-checked (`^[A-Za-z0-9+/]{43}=$`) at the peer-set source, with the complement query reporting exclusions |
| **`assigned_ip`** | **3** — `ListActiveDeviceAllocations`, `ListActiveOVPNDevicesForNode`, `ListActiveDevicesForOrg` | `netip` and WireGuard `AllowedIPs` | ⚠ **OPEN.** Presence-only |

⚠ **`assigned_ip` is the same shape and is currently safe for the same reason `public_key` was:** every
writer today is `ipalloc.Allocate`, which produces well-formed addresses. **That is a property of the
writers, not of the guard** — and it is exactly the property that stopped holding the day something wrote a
placeholder.

⛔ **Not fixed here** — measured and filed, per the founder's instruction. Checked and found to have **no**
presence-only guards: `cidr`, `pool_cidr`, `vip_range`, `endpoint`, `cert_serial`, `cert_public_key`.

---

## ⚠ gofmt REWRITES DOC-COMMENT CONTENT, AND IT CAN MAKE A TRUE COMMENT FALSE

**S15.2 / EPIC 15 walk, 2026-08-04 — caught by CI, then by reading the diff rather than re-running the tool.**

A comment explaining the peer-key guard said the old predicate was ``public_key <> ''``. **gofmt's doc-comment
reflow (Go 1.19+) converted the two single quotes into a typographic `”`** — so a comment *about SQL* came to
read `public_key <> ”`, which is not a thing.

> ## **A FORMATTER THAT REFLOWS PROSE IS EDITING CONTENT, NOT LAYOUT.** `gofmt -w` is normally safe to apply
> ## blind because it moves whitespace. In doc comments it also normalises quotes and backticks — so
> ## "just run gofmt" can silently change what a comment CLAIMS.

⚠ **And CI cannot catch the resulting falsehood** — the file is *correctly formatted* afterwards. The only
signal is reading the diff, and the temptation after a `gofmt` red is to run `gofmt -w` and move on.

**Practice:** avoid raw `''`, `""` and paired backticks inside Go doc comments when they are *technical
content*; write the meaning in words ("an is-not-empty check") or move the snippet into code. ⛔ And after any
`gofmt -w` on a commented file, **read the diff** — it is the only place the change is visible.

---

## ⛔ A GUARD CAN BE ARMED AND STILL NOT BE REACHED — CITE THE CALLER, NOT THE DEFINITION

**S15.2 / EPIC 15, 2026-08-04. The epic's last law, and its most transferable finding.**

The enrolment refusal was **written, tested in both directions, mutation-proven, and shipped unarmed on
purpose** so that arming it later would be a boolean flip over a known-good implementation. When the D14
restore proof was discharged, the constant was flipped —

> ## **AND NOTHING CHANGED, BECAUSE `RefuseUnownedEnrolment` HAD ZERO CALL SITES.**

The rule was correct. The tests were green. The mutation evidence was real. **The enrolment path never
consulted it.**

⚠ **THE WHO-READS-THIS PROBE WAS MINTED FOR SERVED FIELDS AND CHANNEL VALUES. THIS IS ITS FIRST INSTANCE ON
A GUARD** — and guards are where it hides best, because a guard's test suite *looks* like proof of
enforcement while proving only that the predicate computes.

### ⛔ AND THE ARMING COMMIT IS EXACTLY WHERE IT HIDES

An arming commit is small, deliberate, and reviewed for **whether the guard should be on** — never for
**whether the guard is wired**. Everyone reads the constant and the tests; nobody greps for the call. The
smaller and more careful the commit, the more completely the question goes unasked.

> ## **THE CHECK, NAMED: FOR EVERY GUARD, CITE THE LINE THAT CALLS IT — NOT THE LINE THAT DEFINES IT.**

**And make it executable where it matters.** `enrolment_refusal_test.go` now reads the enrolment path's
source and fails if the call disappears — including a check that it is **inside `Enroll`**, since a call on
an unrelated path would satisfy a naive grep.

⚠ **Related but distinct from the too-narrow-predicate law.** That one is *a guard that runs and does not
catch enough*. This one is *a guard that never runs at all* — and the second is invisible to every test the
first would fail.

---

## ⛔ A LOCAL COMMAND THAT RAN IS NOT A LOCAL COMMAND THAT CHECKED — TWO INSTANCES, ONE SESSION

**⚠ THIRD INSTANCE (S12.1, 2026-08-06) — AND THE TELL WAS THAT THE NUMBER GOT BETTER.** A failing-package
sweep reported **1** where every prior run reported **5**. The grep matched the bare `FAIL` summary line as
well as the `FAIL<TAB>package` lines, so `awk '{print $2}'` emitted an empty field — a parsing artifact
that looked like four packages had been FIXED. Caught only by refusing to accept a number that had no
explanation. **A result that moves in your favour is the one nobody re-checks**, which makes it the most
dangerous form of an uninterrogated measurement: a worse number gets investigated by reflex, a better one
gets reported.

**2026-08-04. Both times a command ran, produced output, and the output did not mean what it appeared to
mean.** The class is more useful than either instance.

### Instance 1 — `ok` from four SKIPS

`go test ./internal/agentca/` printed **`ok`** while **skipping four tests** for want of
`TUNNEX_TEST_DATABASE_URL`. That `ok` was then compared against a `test-editions` run that *supplied* the
variable and actually executed them — **a pass and a skip, read as two comparable results.**

### Instance 2 — `build-editions` standing in for `test-editions`

`make build-editions` passed, `go build ./...` passed, and an untagged fresh-DB suite passed — while **four
stale call sites sat in an enterprise-tagged TEST file.**

| check | why it could not see them |
| --- | --- |
| `make build-editions` | compiles **packages, not test files** |
| `go build ./...` | never compiles **enterprise-tagged** test files |
| an untagged `go test ./...` | never compiles them either |

⚠ **A signature change is precisely the break that lives only in test files** — and every local gate was
blind to it in a different way.

### ⛔ THE RULE, STATED SO IT BINDS

> ## **`build-editions` DOES NOT IMPLY `test-editions`, AND NEITHER IMPLIES THE OTHER.**
> ## **REPORT EVERY LEG BY NAME AND VALUE. DO NOT LET ONE STAND IN FOR ANOTHER.**

**And run the gate as CI runs it** — already law here; this is its next instance. The composite is composite
*because* the legs answer different questions, and treating the cheap one as evidence for the expensive one
is how a green local turns into a red CI.

⚠ **The tell both times was available and unremarkable:** `ok` on a package with a skip count, and a build
gate that never mentions tests. **Neither looked like a problem, which is the whole difficulty** — an output
that is *wrong* gets read; an output that is merely *narrower than assumed* gets counted.

**The check:** before treating a local result as evidence, ask **what would this command have to see in order
to fail?** ⛔ If the answer excludes the thing you changed, the command is not evidence about it.

---

## ⛔ "DOWNGRADE RELEASES ENFORCEMENT" IS A LAW ABOUT **RESTRICTIONS**. A REVOCATION MECHANISM RELEASED THE SAME WAY IS A FAIL-OPEN

**Found while designing S12.1's IdP-sync downgrade (D1), against a precedent that was cited to me as the
model to follow — and the precedent is correct, and copying it produces the hole.**

`devices/health.go:260` — `ReleaseAllHealthBlocks` frees every posture-blocked device on downgrade, audited
as `health_blocks_released_on_downgrade`. It is right, and it is the convention this codebase reaches for
whenever an enterprise capability lapses.

Apply it to IdP directory sync and you get: **stop reconciling.** Membership then freezes at the last
successful sync, the compiler keeps compiling those grants, the gateways keep enforcing them, and **a person
removed from the customer's directory keeps working access indefinitely.**

The two look identical — both are "the paid feature stops" and both end up **more permissive** — and they
are opposite:

| | posture | IdP sync |
| --- | --- | --- |
| what the paid feature **does** | a **RESTRICTION** — it blocks devices | a **REVOCATION MECHANISM** — it removes access |
| release it | devices unblock → more permissive → **safe** | removals stop → more permissive → **the hole** |

> ## **RELEASING A RESTRICTION RETURNS THE SYSTEM TO ITS DEFAULT. RELEASING A REVOCATION MECHANISM STRANDS
> ## THE SYSTEM AT A PAST STATE OF THE WORLD, AND CALLS IT CURRENT.**

### ⭐ THE TEST — and it is the operational part, not the epigram

> ## **ASK WHAT THE CAPABILITY'S *ABSENCE* MEANS, NOT WHAT ITS *RELEASE* DOES.**

Absent posture
enforcement, nothing was ever blocked — a clean default. Absent sync, membership means *"true as of the last
poll"* while every surface renders it as *"true"*.

> ## ⛔ **STALENESS INDISTINGUISHABLE FROM CURRENCY IS THE DEFECT — AND "RELEASE THE ENFORCEMENT" IS THE
> ## PHRASING THAT HIDES IT.**

The phrase is doing the damage: it describes an action taken on OUR side and says nothing about the state
the world is left in. Every downgrade path should be described by **what a reader of the data will now
wrongly believe**, and if the answer is "nothing — it reads as a clean default", release is safe.

⭐ **THE RULING THAT FOLLOWS, AND IT IS THE DURABLE PART:**

> # **A LICENCE MAY STOP GRANTING ACCESS. IT MUST NEVER STOP REMOVING IT.**

Implemented as the additive/subtractive split in `idpsync/reconciler.go` — the licence gates the Adds block
and there is deliberately **no seam at all** through which it could reach Removes or Deprovision. The way to
be certain a licence can never stop a revocation is that there is nowhere to put the check.

### ⚠ WHY THIS ONE IS FILED, WHEN THE CODE ALREADY ENCODES IT

**It fires on the person following precedent CORRECTLY.** Every other failure in this file is someone
missing a rule; this is someone applying one, from the right place, and landing on a security hole. The
instruction that set this work going **named the posture precedent as the model to follow** — the analogy
was in the brief, not invented by the implementer. An engineer who reads `ReleaseAllHealthBlocks`, copies
its shape, and writes "release on downgrade" will have done everything the codebase asked of them.

**A convention that is safe in every instance so far is not a law — it is an unexamined sample.** The class
this belongs to is the one where the guard exists, the reasoning is sound, and the SUBJECT is different in a
way the phrasing cannot express. Same shape as *A GUARD WRITTEN FOR A HAZARD IS NOT A GUARD AGAINST THE
HAZARD*, one level up: here the guard is not even wrong, it is **wrong for this noun**.

⛔ **So the question to ask of any downgrade path is not "what does release mean here" but "is this thing a
restriction or a revocation".** Only the first releases.

---

## ⛔ WHEN A PRODUCT'S CORE PROMISE IS THE **ABSENCE OF A CHANNEL**, EVERY CONTROL THAT WOULD HAVE USED THAT CHANNEL IS UNAVAILABLE — AND THE COST LANDS SOMEWHERE THAT LOOKS UNRELATED

**Found in S12.4, designing the licence signing key's compromise-recovery plan. The finding is not about
keys.**

Tunnex verifies licences **offline**. Customer deployments never call home. That is the differentiator a
sovereignty buyer pays for, and it is stated as a feature — *"no SaaS in the trust path."*

Follow it to its consequences and it stops being only a feature:

- **No revocation.** A key that leaves is alive until its expiry.
- **No usage signal.** We cannot see which deployments run which keys.
- ⛔ **AND THEREFORE NO DETECTION OF A FORGED KEY.** If the signing key leaked, an attacker could mint valid
  licences indefinitely and **nothing would ever indicate it had happened** — because the telemetry that
  would show it is exactly what the product promises not to have.

> ## ⛔ **THE RECOVERY PLAN CAN NEVER BE TRIGGERED BY EVIDENCE, ONLY BY SUSPICION.**

The plan itself is fine — rotate, ship a binary trusting a new key, re-issue. **Every step is executable and
none of them will ever be prompted**, because the event that should start them is unobservable. A response
plan whose trigger cannot fire is not a response plan; it is a document.

### ⭐ THE GENERAL FORM

**Every product promise of the shape "we do not collect / we do not connect / we do not see" is also a
promise that a class of CONTROL is unavailable.** The controls are usually not enumerated when the promise
is made, because the promise is made in marketing terms and the controls are discovered later, one at a
time, by whoever needs one.

**The pattern is that the cost lands somewhere that looks unrelated to the promise.** Nobody choosing
offline verification is thinking about signing-key compromise; they are thinking about customer trust. The
bill arrives in an incident-response document years later.

> ## ⭐ **SOVEREIGNTY IS NOT FREE. IT MOVES THE BURDEN TO PREVENTION AND MAKES RESPONSE A RUMOUR-DRIVEN
> ## ACT.**

### WHAT TO DO WITH IT

⛔ **When a promise removes a channel, enumerate the controls that channel would have carried — at the time
the promise is made, not when one is needed.** Then decide, per control, whether:

1. **prevention absorbs it** (the S12.4 answer: the key exists in plaintext nowhere, and the account
   boundary is the real control), or
2. **a different channel can carry it** (a customer-initiated check, an out-of-band signal), or
3. ⚠ **it is genuinely accepted as absent** — which is a legitimate answer and must be *written down*, or
   it will be rediscovered as a defect by someone who assumes it was overlooked.

⚠ **And the asymmetry to watch: detection and response degrade together.** Losing detection quietly makes
every response plan downstream of it unrunnable, and those plans keep looking complete on paper. **Check
whether a plan's TRIGGER still exists, not only whether its STEPS do.**

---

## ⛔ A PROPERTY THAT DEPENDS ON A HUMAN PROCEDURE CANNOT BE TESTED OR MUTATION-PROVEN — AND A SENTENCE DESCRIBING IT WILL READ AS A GUARANTEE UNLESS IT SAYS OTHERWISE

**Found in S12.4, writing the operator README for the licence signing key.**

The decisions paper claimed the private key is *"generated inside the Worker and never exists in plaintext
anywhere else — not on a laptop, not in a password manager, not in a repo."* Confident, specific, and it
survived four gates of review.

**It is not achievable.** To place a key into a Cloudflare Worker secret you must first hold it as text. So:

> ## ⛔ **THE PRIVATE KEY EXISTS IN PLAINTEXT EXACTLY ONCE, ON THE MACHINE THAT GENERATES IT. THAT IS THE
> ## ONLY MOMENT THE COMMERCIAL MODEL IS COPYABLE, AND NO CODE CHANGE MOVES IT.**

Everything *after* that moment is enforceable and was enforced — `wrangler secret put` is write-only, and
the Worker imports the key as **non-extractable** so the runtime, not a convention, prevents export. **The
one uncoverable instant is the first one.**

### THE CLASS

Some properties are **procedural**: they hold because a person follows steps, not because a system
constrains them. Shell history off. Nothing pasted into a note. Scrollback cleared.

**There is no test for that, and there is no mutation that proves the test.** The repo's strongest habit —
*a guard that has only ever passed is indistinguishable from one that does nothing* — **cannot be applied
here at all**, because there is nothing to mutate.

⛔ **The danger is not the gap. It is that a sentence about a procedural property is indistinguishable in
tone from a sentence about an enforced one.** *"The key never exists in plaintext"* and *"the key is
imported non-extractable"* read identically as assurances. One is checked by a runtime; the other is
checked by whoever last did it, at speed, possibly at night.

### WHAT TO DO

1. **Say which kind it is, in the sentence itself.** A procedural property must be labelled procedural
   where it is claimed, not only where it is performed.
2. **Put the steps where the person is** — an operator README, as a ceremony with an order — never as prose
   in a decisions paper the performer will not be reading.
3. **Do not let it sit beside enforced properties unmarked.** Adjacency launders it: a procedural claim in
   a list of mutation-proven ones inherits their credibility.

### ⚠ AND HOW IT SURFACED IS ITS OWN FINDING

**The operator-facing README disproved the decisions paper.** Not a review, not a test, not the four
rulings the paper had already passed through — *writing down how a person would actually do the thing.*

> ## ⭐ **A DOC WRITTEN FOR SOMEONE ELSE IS A DIFFERENT CHECK FROM A DOC WRITTEN FOR THE RECORD.**

A decisions paper is read by people reconstructing *why*; it can hold a claim that is directionally right
for years because nobody has to act on it. An operator doc has to be **executable by a stranger**, and the
first step that cannot be written is a claim that was never true. **That is a cheap check and it is
available for any claim about a system's operation: try writing the instructions.**

---

## ⛔ WHEN A HAZARD IS A **SEAM**, CENSUS THE CALLERS BEFORE FIXING THE FILE THAT NAMED IT

**Found in S12.4, moving licence issuance into `tunnex-web`.**

A comment in `src/pages/api/trial/verify.ts` read:

> *"The one-line issuer swap point: when the product's real signer ships, replace `placeholderKeyIssuer()`
> with it — nothing else changes."*

That comment **instructs the next person to create the defect**, and taking it looks like following
instructions: offline verification means no revocation, so an automated mint is a mistake that cannot be
taken back. Bad enough on its own.

⛔ **But the comment names ONE caller, and the seam has TWO.** `onTrialApproved` is also called by
`lifecycle.ts`'s promote leg, driven by the **daily cron at 03:17 UTC, unattended, in a loop over every
parked trial.**

> ## ⛔ **FIXING THE FILE THAT CARRIES THE INVITATION LEAVES THE CALLER NOBODY THINKS TO CHECK — AND THAT
> ## ONE RUNS WITH NO HUMAN PRESENT.**

### ⭐ THE ASYMMETRY THAT MAKES THIS GENERAL

**The file with the warning is the SAFE one.** Someone was thoughtful enough to write a comment there — so
that is where attention has already been paid, where reviewers look, and where a fix gets proposed.

**The dangerous caller is the one where nobody wrote anything**, because nobody was thinking about the
hazard when they wrote it. Its silence is not evidence of safety; it is evidence that the hazard was never
considered there.

> ## ⭐ **A WARNING MARKS WHERE SOMEONE WAS PAYING ATTENTION, NOT WHERE THE RISK IS CONCENTRATED. THE
> ## UNMARKED CALLER IS THE ONE TO FIND.**

### WHAT TO DO

⛔ **Before fixing a file that names a hazard, enumerate every caller of the seam it names.** Then put the
guard **at the seam**, not at the call site — so new callers inherit it, and the fix does not depend on
anyone remembering how many there were.

Here that meant: the human gate lives in the `Issuer` implementation, not in `verify.ts`; and the guard
(`issuance-gate.test.ts`) **harvests issuer names from source and checks every glue file**, rather than
asserting something about the one file that happened to carry the comment.

⚠ **And the corollary, which cost a red test to learn:** a ruling may be recorded in more than one place.
The same reversal touched a comment **and** a test asserting `src/` contained no Ed25519. Only the test
objected. **Grep for the ruling, not just for the file you were told about.**

---

## ⛔ WHEN REVERSING A RULING, CENSUS WHAT **ENFORCES** IT — NOT ONLY WHAT **STATES** IT

**Found in S12.4, moving licence issuance into `tunnex-web`.**

The destination repo carried a ruling in a file header: *"The site NEVER holds signing keys… no key
material in this repo."* The founder reversed it. The obvious work was to rewrite that header, and I did.

⛔ **The ruling was not only a comment. It was a TEST** — `trial-issuance.test.ts`, asserting *"src/
contains no Ed25519 usage or embedded private keys"*, walking the tree and matching on `ed25519`, PEM
blocks and `signingKey`. **It went red the instant the signer landed.**

> ## ⛔ **REWRITING THE HEADER ALONE WOULD HAVE LEFT A RED TEST WITH NO EXPLANATION — AND THE NEXT PERSON
> ## WOULD HAVE DELETED THE TEST TO MAKE THE BUILD PASS.**

That is the whole hazard, and it is quiet: the deletion would look like housekeeping. A guard removed to
make a build green takes its invariant with it, and **nothing afterwards records that the invariant ever
existed** — the header now says the opposite, so there is not even a contradiction left to notice.

### ⭐ THE GENERAL FORM

**A ruling worth writing down was often worth guarding, and the guard is where the reversal actually costs
something.** Prose states an intention; a test *enforces* one, and only the enforcement will object when
you contradict it. So the census is not "where is this ruling described" but **"what would fail if I did
the opposite"**:

1. **tests** naming the invariant (they fail loudly — the best case)
2. **schema constraints** — CHECKs, UNIQUEs, NOT NULLs encoding the old rule
3. **lint rules, CI steps, censuses** that enumerate or forbid
4. **types** whose shape only makes sense under the old ruling

⚠ **And the right move on the objecting guard is REWRITE, NOT DELETE.** The reversal narrows an invariant;
it rarely abolishes one. Here *"no key material in this repo"* became **"Ed25519 lives in exactly one
module, and no private key is ever a literal"** — still mechanical, still failing on the real hazard, and
now aimed at what the new ruling actually forbids.

> ## ⭐ **A REVERSED RULING SHOULD LEAVE A NARROWER GUARD BEHIND IT, NOT AN ABSENCE.**

⚠ Corollary to *when a hazard is a seam, census the callers*: **grep for the ruling, not for the file you
were told about.** Here the ruling lived in a header, a test, and the shape of an interface — and only the
test objected.

---

## ⛔ A CENSUS NAMES A **SUBJECT**. A SUBJECT CHOSEN BY SHAPE RATHER THAN BY CAPABILITY DRIFTS OUT FROM UNDER IT — SILENTLY

**Found in S12.4, building the admin signing surface in `tunnex-web`.**

⚠ **THIS ENTRY INVERTS THE USUAL SHAPE IN THIS FILE.** Every other one is a guard that fired wrongly, or a
check that passed vacuously over an empty input set. **This is a guard that stayed SILENT while the exact
hazard it exists for walked straight past it — with a non-empty input set, asserting truthfully, on a
subject that had quietly stopped being the right one.**

`issuance-gate.test.ts` existed to enforce one rule: **no unattended path may mint a licence.** It harvested
`Issuer` factories from source, demanded a disposition for each, and checked the glue files. It was
mutation-proven three ways. It was a good guard.

Then the admin signing surface was built, and it **calls `signLicence` directly** rather than being an
`Issuer`. So:

> ## ⛔ **THE ONE PLACE IN THE CODEBASE THAT ACTUALLY MINTS WAS COVERED BY NOTHING — AND EVERY TEST STAYED
> ## GREEN.**

No red. No warning. The census kept passing **because it was still censusing issuer factories correctly**;
there simply were no longer any interesting ones.

### ⭐ THE TRANSFERABLE HALF

**"Issuer factories" was a PROXY for "things that mint."** The proxy was exact when written — every mint
went through a factory — and it stopped being exact the moment minting moved out of one. **Nothing
announced the change, because a proxy failing does not look like a failure. It looks like a pass.**

> ## ⭐ **ASK WHAT THE HAZARD *IS*, NOT WHERE IT CURRENTLY LIVES.**

The hazard is *"a signature can be produced here."* The capability that expresses it is `signLicence`, and
**importing that function IS the minting capability** — a subject that cannot drift, because it is the
thing itself rather than a container the thing happened to sit in at the time.

Subjects that are shapes and will drift: *files matching a name pattern · things in a directory · a
particular interface · a naming convention · handlers with a given signature.* Subjects that are
capabilities and will not: *callers of the dangerous function · holders of the dangerous permission ·
writers to the dangerous table.*

⚠ **The tell is a census whose subject is described in terms of CODE ORGANISATION** rather than in terms of
what can go wrong. Organisation is a thing engineers change casually; risk is not.

### ⚠ AND HOW IT WAS FOUND IS PART OF THE LAW

**By building the very thing the guard exists to watch.**

Nothing else would have. Reviewing the guard would have found it correct. Re-running it would have found it
green. Mutating it would have found it sensitive — **to the subject it had, which is exactly the assertion
being tested and not the choice being tested.**

> ## ⛔ **MUTATION-TESTING PROVES THE ASSERTION. ONLY EXERCISING THE HAZARD PROVES THE SUBJECT.**

So when a guard protects a rule you are about to build something under: **build it, and check the guard
notices.** A guard that stays silent through the addition it was written for is not passing — it is
absent, and it will keep reporting that everything is fine.

---

## ⛔ A CROSS-RUNTIME BOUNDARY TESTED ON ONE SIDE ONLY IS UNTESTED — AND IT FAILS LOOKING LIKE A DEPLOYMENT PROBLEM

**S12.4's first live issuance attempt. 144 tests passed. The key it produced could not be used.**

The ceremony generated an Ed25519 signing key with Node's WebCrypto and exported it as a JWK. Node emits
`alg: "Ed25519"`. **workerd — the runtime that actually signs — refuses it:**

```
DataError: JSON Web Key Algorithm parameter "alg" ("Ed25519") does not match requested Ed25519 curve.
```

It requires `"EdDSA"`, the JWA registered name (RFC 8037). **Every test ran on Node, where the key works.
The runtime that rejects it was never tested against.**

> ## ⛔ **A SUITE THAT RUNS ONLY ON THE PRODUCING SIDE OF A BOUNDARY PROVES THE PRODUCER AGREES WITH
> ## ITSELF.**

### ⚠ AND THE FAILURE MODE IS WHAT MADE IT EXPENSIVE

**It presents as a deployment problem, not a code problem.** The operator pasted a secret and got a
failure. Everything on the code side was green, so the search started at the paste, the shell, the prompt,
the secret store — the entire surface where a human could plausibly have erred. The suspect list was
ordered by *what a person might have done wrong*, and the answer was in a place nobody was looking:
**the generator emitted something correct-looking that one of two runtimes accepts.**

⚠ **Crypto is the sharpest case, because "the key is fine" is a claim both runtimes appear to support** —
one imports it, one refuses it, and the JWK is byte-identical.

### WHERE THESE BOUNDARIES ARE

Any place where **one runtime produces an artefact another consumes**, and the artefact is described by a
format rather than shared code:

- **Two languages** — a Go verifier reading a TypeScript signer's output *(closed here by the twin golden
  vector; that boundary was tested and this one was not, which is the whole comparison)*
- **Two JavaScript runtimes** — Node tooling producing values a Worker consumes ← **this one**
- **Build vs runtime** — a value baked at compile time read by a different engine
- **A CLI vs the server** — an operator's local tool generating something the deployment must parse

### WHAT TO DO

⛔ **Test on the CONSUMING side, with the artefact the PRODUCING side actually emits.** Not a hand-authored
fixture that looks like it — the first reproduction here used a hand-written JWK, **it passed**, and it
proved nothing, because the fields Node adds (`alg`, `key_ops`, `ext`) were exactly what was missing.

⭐ **And derive the fixture from the producer, not from a copy.** The test that closes this extracts the
generator **out of the README** and runs it, so the documentation and the runtime cannot drift apart again.
A copied fixture passes while the instructions rot — and the instructions are what the operator follows.

### ⚠ THE WIDER RESULT FROM THAT WALK, WHICH IS THE REAL ARGUMENT FOR WALKING

**Eight findings. None came from the suite.** The alg mismatch · a verification email landing in Junk with
links disabled · a page promising a key that was actually queued for review · a secret travelling in a URL ·
an internal status string shown to a human deciding · two names for one tier · a mail scanner issuing HEAD
against a single-use link.

**Every one required a person doing the whole thing once, on the real system.** A suite proves the parts
agree with the assumptions they were written under; a walk is what tests the assumptions.

---

## ⛔ WHEN A LIMIT IS ENFORCED ONLY AT CREATION, A TEMPORARY GRANT OF THAT LIMIT IS A PERMANENT GRANT OF EVERYTHING CREATED UNDER IT

**Ruled by the founder while setting the trial band, S12.4.**

Tunnex's gateway limit is checked at **enrolment only** — a running gateway is never stopped, deliberately,
because stopping one disconnects people who did nothing. That rule is right and it is load-bearing.

Now issue a **trial** on the Scale band:

> ## ⛔ **SOMEONE ENROLS 1,000 GATEWAYS, LETS THE TRIAL LAPSE, AND KEEPS ALL 1,000 — FOREVER.**

They can reconfigure and use them indefinitely. **That is not a trial. It is a permanent Scale licence that
activates the moment the trial ends.** And Growth does not fix it — it makes the number 20 instead of 1,000.

### ⭐ THE QUESTION TO ASK

> ## **FOR EVERY TRIAL OR TEMPORARY ELEVATION: WHAT SURVIVES WHEN IT ENDS?**

The grant expires. **The things created under it do not.** Anywhere a limit is checked at create-time —
seats, gateways, projects, keys, integrations, storage — the temporary tier is really a permanent
entitlement to whatever was provisioned while it was active. The expiry closes the *door*, not the *room*.

**The trial ceiling is therefore not "enough to be useful". It is the number you are content to leave
running forever**, because that is what you are granting. Two gateways is what a customer needs to see
site-to-site, HA and cross-site DNS work, and two is a ceiling worth conceding permanently. Both halves have
to be true at once.

### ⚠ AND THIS IS TWO CORRECT RULINGS COLLIDING, WHICH IS WHY IT WAS EASY TO MISS

- *"A trial should show the customer everything the product can do."* — correct.
- *"Nothing running is ever stopped."* — correct.

**They are individually right and jointly produce a permanent free Scale licence.** Neither is wrong; the
combination is.

⛔ **The second wins, and the reason generalises: it is OLDER and MORE LOAD-BEARING.** It protects people
who did nothing wrong from being disconnected, and it is depended on by every other degradation rule in the
model. The trial-generosity ruling was proposed later and **without being checked against it.**

> ## ⭐ **A NEW RULING MUST BE CHECKED AGAINST THE STANDING ONES IT INTERACTS WITH — AND WHEN TWO COLLIDE,
> ## THE OLDER, MORE DEPENDED-UPON ONE WINS UNLESS THERE IS A REASON TO REOPEN IT.**

⚠ The tell is that the conflict lives in **neither ruling's own words**. Each reads as obviously right in
isolation; the defect only appears when you ask what state the system is in *after* one of them fires.

---

## ⛔ A LAW PROPOSED FROM A SUMMARY IS A LAW PROPOSED FROM NOTHING — GREP FOR THE THING BEFORE WRITING ABOUT IT

**Near-miss, S12.1. Two entries were proposed for this file and neither had a referent.**

1. *"The `TrialGatewayCap` constant that must never be read."* **No such constant exists.** `grep -rn
   TrialGatewayCap apps/ docs/` returns nothing. The trial ceiling is an ordinary map entry that IS read.
2. *"Ed25519 vs EdDSA again, in the Go verifier — second instance."* **It never recurred.** The Go verifier
   has no JWK path at all: `TrustedKeys` holds base64url of raw 32-byte public keys. There is no `alg`
   field to disagree about. **One instance, in `tunnex-web`, already fixed and already filed.**

Both were plausible. Both fit the shape of things that HAD happened. Both were describable in a sentence
that reads exactly like the fifty true entries above them.

> ## ⛔ **A FABRICATED PATTERN IN THIS FILE IS WORSE THAN A MISSING ONE. Every future session reads it as
> ## MEASURED — that is the file's entire value, and one invented entry spends it.**

A missing law costs a rediscovery. **A false one costs trust in all of them**, and there is no way for a
later reader to tell which entry was checked and which was recalled: they are the same prose.

### ⚠ WHERE THEY CAME FROM, WHICH IS THE USEFUL PART

**Not from source. From a summary of the session** — a description of work, at one remove, where "the
constant that must never be read" and "the second Ed25519 instance" are both things that *could* have been
concluded from what was nearby. Long sessions compress, and compression invents structure: two adjacent
true facts acquire a connective that was never there.

⛔ **The hazard is specific to writing DOWN what a session learned, and it peaks exactly when the material
is richest** — at the end, when there is most to record and least context left to check it against.

### THE CHECK, AND IT IS CHEAP

> ## ⭐ **BEFORE WRITING A LAW ABOUT AN ARTEFACT, GREP FOR THE ARTEFACT.**

`grep -rn TrialGatewayCap` · `grep -rn alg internal/licence/`. **Two commands, both instant, both
conclusive.** Neither requires remembering anything — which is the point, because memory is what failed.

⚠ **And the same check applies to the count.** "Second instance" is a claim about the world, not a summary
of it: it asserts that a search WAS performed and returned two. If no search ran, the number is invented
even when the first instance is real.

⚠ **Corollary, and it is the harder half:** this near-miss was caught because the two claims arrived as an
INSTRUCTION to write them down, which forced a look. **A law drafted unprompted gets no such trigger** —
nobody asks it to prove its referent. The discipline has to be self-imposed at the moment of writing.

### ⛔ SECOND INSTANCE, SAME SESSION, SAME TRIGGER — AND THIS TIME THE FABRICATION WAS A MEASUREMENT

**S12.1, hours after the entries above.** The claim, stated as fact and handed over to be recorded:

> *"e2e has been red on main for 68 days, 47 runs, zero green."*

**Measured instead of written.** Every non-cancelled main CI run was pulled and each one's `e2e` job
conclusion read from the API:

| | |
|---|---|
| Runs of history that exist at all | **54, reaching back to 2026-07-18 — 19 days, not 68** |
| Green | **37** |
| Red | 17, in clusters (2026-07-18/19/23/24/25/29), **not continuously** |
| The run before the break | **32 consecutive green, 2026-08-01 → 2026-08-04** |

Every number was wrong, including the direction: the suite was **overwhelmingly green**, and the red being
investigated was **19 hours old and one merge deep** (`f5f84a8a`, PR #91).

⚠ **AND THE UNDERLYING FINDING SURVIVED THE CORRECTION INTACT** — which is the reason this is a near-miss
and not merely an error. PR #91 *did* merge green on all three required checks while `e2e` was correctly
reporting breakage. **The shape was right at 19 hours exactly as it would have been at ten weeks.** That is
precisely what makes a fabricated figure dangerous: it attaches to a true finding and inherits its
credibility, and no later reader can separate them.

> ## ⛔ **A NUMBER IS A CLAIM THAT A COUNT WAS PERFORMED. INHERITING IT FROM A TRUE STORY DOES NOT PERFORM IT.**

### ⭐ THE TRIGGER WAS IDENTICAL BOTH TIMES, AND THAT IS THE TRANSFERABLE PART

`TrialGatewayCap` and *"68 days, 47 runs"* were both caught **because someone asked for them to be written
down.** Being asked to record a thing is what forced the look; neither would have survived a `grep` or an
API query, and neither got one until the writing-down demanded it.

⛔ **So the corollary above is now measured rather than predicted: the request to record IS the check.**
Two for two. The failure mode is not bad memory — it is a claim that never had a moment where anyone had
to produce its referent.

⭐ **Which means the discipline is cheap and specific: treat "write this down" as "verify this now", and
treat every figure inside it as a separate referent needing its own command.** The finding and its count
are two claims, and the true one does not vouch for the other.

---

## ⛔ A CHECK THAT NOTICES AND CANNOT BLOCK IS A CHECK THAT GETS MERGED PAST

**S12.1, measured.** `e2e` is `continue-on-error` and is not one of the three required checks. PR #91
removed the Overview liveness card, the activity feed, and moved device creation into a modal. `e2e` caught
all of it — six failures, correctly aimed, with accurate locators — **and PR #91 merged green**, because the
only checks that gate a merge are `gates` + `client (macos-latest)` + `client (windows-latest)`.

The breakage then sat on `main` until the next PR's author read a red log that was not theirs.

> ## ⛔ **AN ADVISORY CHECK DOES NOT DEGRADE GRACEFULLY INTO A WARNING. IT DEGRADES INTO A LOG NOBODY OPENS.**

⚠ **AND THE HONEST COST OF FIXING IT IS WHY THIS IS HELD, NOT RULED.** `e2e` is the slowest leg and has
**17 red runs in the 19 days of history that exist**. Making it required today blocks every merge on
whatever produced the July clusters — which nobody has diagnosed. **Requiring a flaky check is how a team
learns to bypass required checks**, which is strictly worse than the gap it closes.

**REGISTERED, TWO ITEMS, BOTH FOR FOUNDER DISPOSITION:**
1. **Should `e2e` become required?** Cost named above. Not answerable before item 2.
2. **The July `e2e` red clusters** (2026-07-18/19/23/24/25/29, 17 runs). Never diagnosed. **Prerequisite for
   item 1** — and independently worth knowing, because a suite red for six days at a stretch was reporting
   something.

## ⛔ A TEMPORARY MARKER NAMING A SUCCESSOR IS NOT A HANDOFF — IT IS A GAP WEARING A PLAN'S CLOTHES

**S12.1 → the edition defect, measured.** `enterprise/edition.go` carried this, written by the slice that
created the problem:

```go
// Name is what `/meta` reports as the edition.
//
// ⚠ TEMPORARY, AND IT IS THE UNLICENSED DEFAULT. With one binary the edition is a property of the
// LICENCE, not the build, so this becomes a licence read in the LicenseManager slice. Until then it
// reports the tier a deployment with no key is entitled to.
const Name = "open"
```

**Everything in it is true.** It identifies the gap, explains why the gap exists, names the successor that
must close it, and states the interim behaviour. It is a better comment than most.

⛔ **The LicenseManager slice arrived, built a LicenseManager, and did not close it.** Nothing checked.
`const Name = "open"` shipped to `main` as the only definition of the edition, so **every deployment
reported itself as open under any licence** — and eleven web files gate on that value, so a customer with a
valid Growth key got their capabilities from the API and upsell cards from the UI.

> ## ⛔ **THE COMMENT READ AS A PLAN. IT WAS A GAP. NOTHING DISTINGUISHES THE TWO IN PROSE — AND THE
> ## SUCCESSOR NEVER READS THE FILE IT IS SUPPOSED TO FIX.**

⚠ **THAT LAST CLAUSE IS THE MECHANISM, AND IT IS OBVIOUS ONLY AFTERWARDS.** A deferral comment lives in the
file that has the problem. The slice that must fix it is working somewhere else entirely — it opens
`licence/manager.go`, not `enterprise/edition.go`. **The note is filed where the successor will not be.**

### THE RULE

> ## ⭐ **IF A SUCCESSOR MUST DO SOMETHING, IT BELONGS IN THAT SLICE'S DEFINITION OF DONE — NOT IN A
> ## COMMENT THE SUCCESSOR NEVER OPENS.**

A `TEMPORARY` marker is a fine *explanation* and a worthless *mechanism*. Pair it with something that
fails: a decide-item in the successor's commit-one, a test the successor must delete to pass, a census that
names the constant. **Anything that makes the successor's build red until it has looked.**

⚠ **AND THE COST IS NOT THE DEFECT — IT IS THE DIAGNOSIS.** `make up-enterprise` still passed
`TUNNEX_BUILD_TAGS=enterprise` and still printed `# -> enterprise`, so a review session spent its opening
on stale images and compose drift. **A build target promising a state it can no longer produce is the same
failure as the comment, one layer out: a description that outlived what it described.**

⭐ **This is the dormant-machinery law's twin, and the inverse of it.** Dormant machinery is code that runs
and does nothing. This is prose that does nothing and reads as if it will.

## ⛔ WHEN A MIGRATION BACKFILLS, CHECK WHAT THE SEED DOES FOR THE SAME COLUMN — ONLY ONE OF THEM RUNS ON A FRESH INSTALL

**S12.5, and a human caught it, not a test.** Migration `0073` added `users.can_create_orgs DEFAULT false`
and grandfathered existing owners, which is correct and necessary — a deployment upgrading into it must not
lose the ability to administer itself. **The seed's `UpsertUser` never mentioned the column**, so it took
the default.

| | order | result |
|---|---|---|
| **Developer's rig** | data already exists → migrate | backfill matches the demo owner → **granted** → works |
| **Fresh install** | migrate → seed | backfill matches **nothing** → seed inserts at default → **not granted** |

> ## ⛔ **THE BACKFILL DOES NOT FIX THE SEED. IT HIDES THAT THE SEED IS BROKEN, ON EXACTLY THE MACHINE THE
> ## AUTHOR IS LOOKING AT.**

Everyone who ran it locally saw it work. Every fresh rig — every new reviewer, every clean CI volume, every
customer install — got a demo owner who could not create an organization and could not run the walk.

### ⭐ THE CHECK CANNOT BE A DATABASE TEST

A test that queried the database would have **passed on the machine whose state caused the blindness**. The
guard reads the **SEED SOURCE** and asserts the column is stated for every account it creates — including
the ones that must NOT have it.

⚠ **Silence is the bug.** An unstated column is not neutral: it is a vote for the default, cast invisibly,
and readable only where a migration has already voted the other way.

> ## ⭐ **A MIGRATION THAT BACKFILLS AND A SEED THAT INSERTS ARE TWO ANSWERS TO ONE QUESTION. THEY MUST
> ## AGREE — AND SINCE ONLY THE SEED RUNS ON A FRESH INSTALL, THE SEED IS THE ONE THAT DECIDES.**

⚠ **AND KEEP THE FIXTURE REPRESENTATIVE.** The seed grants the capability to exactly ONE account and
explicitly withholds it from the rest, because signup now creates an account and never an organization — so
*cannot create* is the MAJORITY case a real deployment produces. A fixture where everybody holds a
capability gives the boundary nothing to be seen against.

⛔ **A fixture value inherited from a migration clause is how a fixture stops representing anything**: the
no-org onboarding account read `true` on old rigs purely because an e2e run had once given it an org and the
backfill then caught it.


## ⛔ A LAYOUT DECISION CAN SILENTLY DELETE A CAPABILITY (sixth instance)

`POST /nodes/{nodeId}/revoke` shipped in S11 with a two-step confirm, inside `EnrolCeremony`'s own list.
The Gateways page renders that component with **`renderList={false}`** — it owns the list itself — so the
ACTION went off with the list, and the tables that replaced it never grew one.

**Nothing went red.** The component still existed, its own tests still passed, the endpoint stayed wired,
and the RBAC mirror still granted the permission. What broke was REACHABILITY, which no component-scoped
test asks about.

⚠ **And the cost landed at the worst moment:** the gateway-ceiling notice tells an operator to *"revoke a
gateway you no longer use"* — a remedy that is TRUE (`CountLiveNodes` counts `revoked_at IS NULL`, so
revoking really does free a slot) — while the button did not exist. A refusal naming a remedy the UI does
not offer sends the operator hunting for a control that was never built, at the moment they would
otherwise have paid.

⭐ **THE GUARD MUST BE ABOUT THE ACTION BEING REACHABLE, NOT ABOUT A COMPONENT EXISTING** — the component
existing is exactly what was true the whole time the control was gone. `gatewayrevokereach.test.ts` reads
the PAGE for the endpoint call, so it survives whatever `renderList` does.

⚠ **And that guard nearly lied too:** a census-of-censuses caught it reading source WITHOUT stripping
comments — its own doc comment contains the endpoint path, so it would have matched its own prose and
passed with the button deleted. Source censuses strip first, always.


## ⛔ A GUARD READ IN ISOLATION CANNOT SHOW WHAT TWO GUARDS DO TO EACH OTHER

Both of the day's defects were COMPOSITIONAL: the 400-before-401 sat in front of a correct handler, and the
invitation defect sits between correct redirects. Each guard is right alone; a loop exists only in their
composition — and the spec that DRIVES the flow finds what reading the guards does not.

⚠ **AND THE COROLLARY, WHICH THIS STORY IS THE EVIDENCE FOR: READING CANNOT EXONERATE EITHER.** A handoff
named `RequireSetupIncomplete` as the guard that bounced a membershipless user to `/login`. That guard does
not exist in this codebase. The two real guards were then measured end to end:

- `RequireOrg` (App.tsx) sends 0-membership to `/create-org`, or `/verify-pending` when unverified.
- `RequireNoOrg` bounces to `/dashboard` — never `/login` — and only when `status === "has"`.
- `CreateOrg` renders the **Invitation required** card for any authed non-`cp_admin`, so the funnel TERMINATES.
- Server side: create returns 202 with the raw token (`delivered:false` when SMTP is unset), accept does
  `CreateUser` + `MarkEmailVerified` + `UpsertMembership`, and `ListOrganizations` is membership-scoped.

**Five legs, five passes, no loop found by reading — which is exactly the result a reading pass is entitled
to produce and NOT entitled to conclude from.** The only instrument that can settle it is one that drives a
REAL invitation: create it, take the token from the RESPONSE (never from mail), accept, sign in, and assert
the org renders.

⛔ **AND A SPEC THAT ASSERTS ONLY THE FIRST DESTINATION PASSES ON A PRODUCT WHERE INVITATIONS NEVER WORK.**
`onboarding.spec.ts` already pinned membershipless → the invitation card against a real backend, and it was
green throughout. Two states, two destinations, BOTH asserted, or the green half hides the broken half.


## ⛔ A COUNT FROM ONE SOURCE AND ITS ROWS FROM ANOTHER ARE TWO TRUTHS ABOUT ONE SET

Gateways, Devices and Sites each fetched their own rows while the badge beside the nav label came from a
shared hook (`useNavCounts`). **Three pages made the same mistake independently** — which is what makes it a
class and not a bug.

⚠ **THEY AGREE RIGHT UP UNTIL A FILTER DIFFERS, AND THEN THEY DISAGREE SILENTLY.** Nothing errors. Both
numbers are correctly computed from correctly fetched data; they are simply answers to two different
questions wearing one label. The page counts what the page filtered, the badge counts what the hook
filtered, and the operator reads them side by side as one fact.

⛔ **THE SAME SHAPE ALREADY SHIPPED A MEASURED DEFECT:** the nav badge built its fraction from the CURRENT
ORG's gateway list over the DEPLOYMENT's ceiling, so a newly created organization read `0 / 5` on a box that
was already full and refusing the next enrolment. **A fraction whose halves answer different questions does
not fail to inform — it actively misinforms**, and most confidently in the newest org. The fix was to serve
the numerator from the same place the ceiling is enforced (`gateways_in_use`, `licence_handlers.go`).

⭐ **THE RULE: ONE SET, ONE SOURCE.** A count rendered beside rows is DERIVED FROM THOSE ROWS, or it comes
from a seam that both the count and the rows read. Never a second independent fetch — the second fetch is
where the drift lives, and no test that checks either number alone can see it.

⚠ **AND IT IS INVISIBLE TO PER-SURFACE TESTS BY CONSTRUCTION.** Both sides pass their own tests, because
each is right about its own question. The guard has to compare them, or assert they share a source.
