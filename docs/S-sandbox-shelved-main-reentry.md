# Sandbox shelving on main

Sandbox development is paused at the user's request. This patch starts from
published main `e6b65cd9b60b96d05344fb2cec770a0dc45e28dd` and shelves the
sandbox implementation already present there. It does not import later local
runner, lifetime, enrollment or release development.

## Decisions before implementation

- Locked: use isolated branch `story/sandbox-shelved-main-20261007`; preserve
  the original development and shelving branches unchanged.
- Locked: make sandbox product availability a source-level off switch. Earlier
  environment settings, stored opt-ins and supplied dependencies must not
  reactivate UI, API, background work or dedicated executable entry points.
- Locked: retain implementation source, generated contracts, migrations and
  existing data. Shared VPN, gateway, site-to-site, SHIELD/browser access,
  identity restrictions and security checks remain active.
- Locked: remove only sandbox-specific work from ordinary CI and releases.
  Preserve shared compile dependencies, full source builds and ordinary check
  names. Historical sandbox matrix contexts may print explicit shelving
  notices without claiming qualification.
- Locked: keep this public checkpoint free of private host identifiers,
  machine access paths, credentials and enrollment/operational details.
- Locked: this work is local preparation only. No push, PR creation, workflow
  dispatch, deployment, live access change or infrastructure cleanup.

## Implementation stories and acceptance

1. **Product entry points.** Add explicit static gates and TODOs at existing
   web, API/server, node and CLI integration seams. Sandbox navigation/settings
   and direct routes cannot expose the product. HTTP refuses before sandbox
   authentication, body parsing or providers; server and executable guards
   refuse before dedicated configuration or credential loading.
2. **Ordinary CI and release paths.** Disable sandbox-only test discovery,
   fixtures, packaging/image producers and their artifact consumers together.
   Keep aggregate dependencies coherent, ordinary release verification and
   shared VPN/security coverage. Failed/invalid/empty package discovery cannot
   silently pass. Do not remove dependencies still required by retained source.
3. **Validation.** Exercise affected acceptance/contract tests, both API
   editions and ordinary UI/build checks as appropriate. Validate workflow
   syntax and the exact diff from the published baseline. Clearly record
   passed, failed and unrun checks; no native/live sandbox qualification.
4. **Re-entry.** Record final source pointers and restoration seams without
   importing private operations history. The final PLAN pointer names the
   content commit, followed by a documentation-only checkpoint commit.

Stories 1 and 2 can proceed independently after this decision record. Story 3
depends on both, and story 4 closes the local checkpoint.

## Preserved local development history

The earlier combined development/shelving branch remains local as
`story/sandbox-shelved-20261007`, checkpoint
`a316ac73607d71bcb7b8178a3034121585a2723c` (content
`30172195114a7a5fb872cecec28434025ca03425`). Its 30 commits include 24 later
implementation commits and six shelving commits. They are not imported into
this main-based patch. Detailed private operational and unfinished-work
checkpoints remain local; obtain that handoff deliberately before any restart.

## Re-entry procedure

1. Confirm an explicit restart instruction and select the intended integration
   base. Review this patch separately from the preserved local development
   branch; do not blindly cherry-pick the entire old history.
2. Review all static product gates together, then restore the existing route,
   server, executable and UI wiring deliberately.
3. Restore sandbox tests, fixtures and the complete CI/release artifact chain
   together. Keep ordinary shared gates and verified dependency requirements.
4. Review the original goals: policy-bound user sandboxes, direct terminal or
   existing local-agent access, selectable templates and configurable skills,
   and a lightweight preloaded runtime with measured startup/resource budgets.
   General multi-user runner architecture remains a re-entry direction, not
   authorization to resume it during this pause.
5. Requalify exact-source builds, generated drift, native operation, cleanup
   and release compatibility before separately authorized publication or use.

## Validation ledger

Decision record committed before implementation. Results and the final content
pointer will be recorded after the bounded main-based changes are complete.
