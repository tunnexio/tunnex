# UPG-2: the upgrade runs the target release's own upgrade script

**Status:** decision paper only, nothing implemented.

- **Branch:** local `story/app-access-enablement-papers`, based on `origin/main` 4d693d12
  (v0.1.45). Not pushed, not run on any host.
- **Origin:** this is the follow-up to UPG-1 decision D3 (founder ruling of 2026-11-24).
  UPG-1 explicitly asked for its own paper and review first, because the change touches
  which code a host executes.
- **Dependency:** implementation depends on UPG-1 (`story/app-access-one-click-upgrade`)
  landing first. Line references below are to `origin/main` unless they say UPG-1.

**Binding principles** (founder, 2026-11-24):

- no user confusion
- security unchanged
- upgrades work in one click
- no feature blocks upgrades

## 1. Summary

Today an installed host upgrades with its **own, old** `upgrade.sh`. When an old script
meets a situation it refuses, the host can only be upgraded by replacing the script by
hand. App Access on v0.1.45 is the first case of this (UPG-1 F5/D3), but not the last: any
guard, ordering or new component added later has the same problem.

**Recommendation:**

1. The installed script becomes a small, stable **trampoline**. It verifies the signed
   release with the installed trusted key and verifier, then refuses downgrade and
   replay.
2. It obtains the target release's host files from the **digest-pinned, signed API
   image**: the files are copied out of the image, nothing in it is run.
3. It then `exec`s the target `upgrade.sh` with a frozen, versioned hand-off interface.
4. The target script does all of the following:
   - re-verifies the release
   - runs its own admission, backup and apply
   - after reaching `healthy`, replaces the installed copies:
     - `<install>/upgrade.sh`
     - `/usr/local/lib/tunnex/upgrade.sh`
     - `/usr/local/lib/tunnex/upgrade-runner.sh`

This also closes two existing gaps:

- **Phase 1:** host files are currently trusted only through raw GitHub at a commit SHA,
  with no signed digest. In Phase 1 the target takes every host file from the extracted,
  signed hand-off directory.
- **Phase 2:** the `--airgap` path is not actually offline.

**First slice:**

- the API image carries the host files
- the trampoline and hand-off in `upgrade.sh`
- a sequence check against the installed signed descriptor

Hosts that already run this script never need a manual script replacement again.

## 2. Facts (from reading `origin/main` and the UPG-1 branch)

| # | Fact | Consequence |
|---|---|---|
| H1 | `upgrade-runner.sh` executes `TUNNEX_UPGRADE_HELPER`, which the systemd unit written by `install.sh` sets to `/usr/local/lib/tunnex/upgrade.sh`. The runner is root, with `PrivateTmp=true` and `NoNewPrivileges=true`. | Whatever script that path holds runs as root with Docker authority. Every byte of a delegated script must be authenticated by the release key. |
| H2 | The self-update (`TUNNEX_UPGRADE_PRIVILEGED=1` only) happens **after** backup and preflight. The new script is installed for the *next* run and never executed in the current one. | A guard in the old script that refuses, or that runs before self-update, cannot be escaped (UPG-1 F5). |
| H3 | Self-update and CLI upgrades fetch `upgrade.sh`, `upgrade-runner.sh`, `tunnex.yml`, `ai-bootstrap.sh` and `config-managed.json` from `raw.githubusercontent.com/tunnexio/tunnex/<SOURCE_SHA>/…`. The only check is `sh -n`. `ai-bootstrap.sh` is **sourced** as root. | The trust in these files is GitHub TLS plus git addressing, not the release signing key. A different trust root from the images, which are pinned by signed digest. |
| H4 | `release.Load` decodes with `DisallowUnknownFields`. The signature covers `json.Marshal` of the known struct. | `release.json` cannot gain a field such as `host_assets` without breaking every installed verifier. `agent-bootstrap-verifier.json` is the existing detached-descriptor precedent, which says so in a code comment. |
| H5 | The API image (`deploy/docker/api.Dockerfile`) ships `releaseverify`, `backupctl`, `preflight` and the API binary. It does not ship the `deploy/` host files. | Host files could be added to the image. Its digest is already bound by the signed descriptor. |
| H6 | With manual CLI upgrades (no `TUNNEX_UPGRADE_PRIVILEGED`), `<install>/upgrade.sh` is **never** refreshed. Non-systemd hosts upgrade forever with the script they were installed with. | Non-systemd and CLI-only hosts are a hidden population for this problem, not only App Access hosts. |
| H7 | `--airgap DIR` loads image tars, but `tunnex.yml` (and the AI files) are still fetched from GitHub. Whether `@sha256` references resolve for `docker load`ed images depends on the Docker image store. The classic store does not keep repository digests. | The offline path is not offline today, and its image-digest binding is unproven. |
| H8 | The host script compares the target only with the request's `--expected-source-sha`/`--expected-sequence`. The API refuses `next.Sequence <= current.Sequence` (`release/manifest.go`) for the dashboard. A CLI `--manifest` pointing to an **older** validly signed release is not refused by the host script. | Downgrade and replay protection exists only on the dashboard path. |
| H9 | On main, `refuse_existing_app_access` runs **before** `verify_release`. UPG-1 moves admission into the classifier, but it still runs before any delegation could happen. | The trampoline must sit before every admission guard and before the backup. |
| H10 | The systemd unit files are written only by `install.sh`. Neither upgrade path rewrites them. | Unit changes are a separate concern. The trampoline must keep working with today's units. |

## 3. Requirements

1. Nothing downloaded is executed, sourced or installed unless the pinned release public
   key in the installation's `.env` authenticates its bytes, through the verified
   descriptor. This has to hold transitively: key, then descriptor, then digest, then
   bytes.
2. Only immutable references are used: content digests and the verified source SHA. No
   mutable tag, branch or catalog URL may decide which code runs.
3. No configuration is read as shell. `.env` is read by `sed` (`dotenv_value`).
   Verifier output is parsed by key, never `eval`ed.
4. No target older than the installed release. Re-running the same release (UPG-1 D2,
   forward fix) is allowed.
5. One hand-off only. The target never delegates again, and nothing loops.
6. The status file and request ID stay continuous across the hand-off. The dashboard sees
   one upgrade, not two.
7. The same mechanism works online, offline (air-gapped), from the CLI and from the
   dashboard runner.
8. No App Access or Server Access logic in the trampoline. Feature logic lives only in the
   target script.

## 4. Options

### 4.1 Where the target host files come from (the trust chain)

**T-a. Status quo: raw GitHub at the verified source SHA.**
- Trust root: GitHub TLS plus git commit addressing (H3), not the release key.
- No offline path.
- **Rejected** as the basis for executing code before backup.

**T-b. A detached signed host-assets descriptor.** `host-assets.json` would carry:
- purpose `tunnex-host-assets`
- version and source SHA
- a sha256 per file

It would be signed by the release key and published as an immutable release asset next
to `release.json` (H4 precedent). Files are fetched from the immutable release assets and
checked against those digests.
- Pros:
  - Works offline: the bundle carries the descriptor and the files.
  - Small.
- Cons:
  - A new CI signing and publication step.
  - The installed verifier does not understand the new descriptor. The first hop has to
    run the target verifier by digest anyway.
  - Two artifacts must stay consistent.

**T-c. Host files inside the signed API image (recommended).**
- The API image gains `/usr/share/tunnex/host/`, holding:
  - `upgrade.sh`
  - `upgrade-runner.sh`
  - `tunnex.yml`
  - `app-access/compose.yml`
  - `app-access/restore.py`
  - `ai-bootstrap.sh`
  - `ai-gateway/config-managed.json`
  - `HOST_ABI`, which holds the hand-off interface version
- The trampoline runs `docker pull <TUNNEX_API_IMAGE from verified env>`, which is
  content-addressed, so the daemon checks the digest. It then runs `docker create`
  (`--pull never`, no start) and `docker cp` of that directory into a private `0700`
  temporary directory, then `docker rm`.
- No code from the target runs to obtain the files.
- Chain: pinned key → descriptor signature (installed verifier) → `api` digest →
  image bytes → files.
- Pros:
  - No new signed artifact and no new CI signing step.
  - One trust root for images and host files.
  - Offline works whenever the images are present.
- Cons:
  - Host-file changes ship only with an image build. They already share a commit, so
    this changes nothing in practice.
  - A few kilobytes are added to the API image.

**T-d. Run the target API image's `releaseverify` to verify a detached descriptor (T-b
with a target verifier).** This combines T-b's extra artifact with T-c's image trust. It
is more moving parts than T-c for the same result. **Rejected.**

### 4.2 When to delegate

**W-a. Immediately after verification, before admission, backup and any mutation
(recommended).** The target alone decides whether it can upgrade this host. Old guards can
never trap a host again.

- The target's own backup runs before its mutations, so "a verified backup exists before
  anything changes" still holds.
- What changes compared with UPG-1's concern: signed target code now runs *before* the
  backup. It is authenticated exactly like the images, which run after the backup and
  with more privilege inside Compose. So this widens no trust boundary.

**W-b. After backup.** The old script's backup would then be taken under old rules. An old
script that refuses before backup, as with App Access, is still trapped. **Rejected.**

**W-c. Delegate in `--apply` only, not in dry runs.** A dry run would then show the old
script's view, which may differ from what applying does. That would confuse operators.
**Rejected:** dry runs delegate too, and the target dry run mutates nothing.

### 4.3 When installed copies are replaced

**R-a. After the target reaches `healthy` (recommended).** A host adopts a new script only
after that script has completed an upgrade on that host. If the target fails, the old copy
remains, and the next attempt delegates again (forward fix). A target whose own script is
broken can never become the installed trampoline.

**R-b. Right after verified extraction.** A failed upgrade would leave a newer, but
unproven, trampoline installed. **Rejected.**

Copies replaced, atomically (`install` to `.next`, then `mv`):

| Copy | Condition |
|---|---|
| `<install>/upgrade.sh` | Always. This closes H6 for CLI and non-systemd hosts. |
| `/usr/local/lib/tunnex/upgrade.sh` and `upgrade-runner.sh` | When privileged (root runner, or root CLI with the root directory present). Owner root, mode 0755. |

Unit files are not rewritten (H10).

### 4.4 Downgrade and replay

The trampoline compares the target with the **installed signed descriptor**
`<install>/release.json`. It verifies that file with the same key. It does not use
`.env`'s `TUNNEX_RELEASE_SEQUENCE`, because that is configuration, not signed state.

| Case | Result |
|---|---|
| target sequence > installed sequence | Proceed. |
| target sequence = installed sequence and same source SHA | Proceed. This is a re-run or forward fix after a failure (UPG-1 D2). |
| target sequence = installed sequence and different SHA | Refuse (`release_conflict`). |
| target sequence < installed sequence | Refuse (`downgrade_refused`). Going back is a restore, never an "upgrade" (AA-7, UPG-1 D2). |
| installed `release.json` missing or unverifiable | Refuse, unless the operator passes `--accept-installed-unknown`. That flag is CLI only and never available from the runner, and it is printed in the status. This covers hosts whose descriptor was lost. |

The dashboard path keeps its existing `expected_source_sha`/`expected_sequence` binding.

The hand-off environment variable `TUNNEX_UPGRADE_HANDOFF=1` makes the target skip
delegation. Without it, the target trampolines into itself: it extracts the same files
and execs once. The variable is harmless if an attacker sets it, because it only *skips*
delegation. The target still verifies everything itself.

### 4.5 Hand-off interface (ABI 1, frozen)

The old trampoline runs
`exec /bin/sh "$HANDOFF_DIR/upgrade.sh" <args>` with:

- **Arguments:** `--manifest "$HANDOFF_DIR/release.json"`, which is the exact bytes
  already verified, so the target does not re-fetch the catalog. Plus the original
  `--apply`, `--expected-source-sha` and `--expected-sequence`, and `--airgap DIR` if it
  was given.
- **Environment, set explicitly:**
  - `TUNNEX_DIR`, which is the install directory; the target must not derive it from its
    own temporary location
  - `TUNNEX_ENV_FILE`
  - `TUNNEX_COMPOSE_FILE`
  - `TUNNEX_UPGRADE_STATUS_FILE`
  - `TUNNEX_UPGRADE_REQUEST_ID`
  - `TUNNEX_UPGRADE_PRIVILEGED`
  - `TUNNEX_UPGRADE_HANDOFF=1`
  - `TUNNEX_UPGRADE_HANDOFF_ABI=1`
  - `TUNNEX_UPGRADE_HANDOFF_DIR`, which the target removes on exit

Other environment is passed through unchanged. The trampoline adds no other variables
and never derives values from the manifest JSON.

**Why `exec`:** the old process is replaced, so its `EXIT` trap cannot overwrite the
target's terminal status. Before `exec`, the trampoline clears its own trap and writes
status `verifying`. The target then owns the status file.

**ABI mismatch:** the target reads `TUNNEX_UPGRADE_HANDOFF_ABI` and refuses an unknown ABI
with `handoff_unsupported`. The trampoline reads `HOST_ABI` from the extracted files and
refuses to exec a target that does not declare an ABI it speaks. The ABI is versioned and
only extended, never broken; a breaking change would need ABI 2 and a two-hop path.

### 4.6 Offline (air-gapped) path

With T-c, everything the host needs is in images. `--airgap DIR` then:

1. Requires `--manifest`. Reaching the catalog is not attempted.
2. Before `docker load`, verifies that each archive is an OCI layout. Its index or
   manifest digest for the host architecture must equal the signed digest. The check
   computes sha256 over the manifest blob inside the tar. No code runs.
3. Loads the archives, then resolves the API image **by the verified digest**. Where the
   daemon's image store cannot address a loaded image by digest (H7), the image ID must
   equal the config digest recorded in the verified OCI manifest.
4. Extracts host files as in 4.1. **No network access at all.** Any `curl` in airgap
   mode is a refusal.

This replaces today's partially online `--airgap` behaviour. The air-gap bundle format
(OCI layout, one archive per image, plus `release.json`) is documented in `docs/upgrade.md`.

### 4.7 Dashboard runner

- **`upgrade-runner.sh` is unchanged in role.** It snapshots and validates the bounded
  request, then calls `TUNNEX_UPGRADE_HELPER --apply --expected-source-sha
  --expected-sequence`. Its interface to `upgrade.sh` stays stable.
- **The installed helper becomes the trampoline.** The target's status lines continue
  the same `request_id`.
- **Runner-specific constraints:**
  - `PrivateTmp`: the hand-off directory sits under the runner's own `$TMPDIR` or
    `<install>/upgrade-state/work` (root, 0700). Files go in with `docker cp` *from* the
    container, so the daemon never needs to read a host temporary path.
  - `NoNewPrivileges` is unaffected, because nothing is setuid.
- **The runner is replaced as a file** by the target after `healthy` (4.3). The systemd
  unit keeps pointing to the same paths.

### 4.8 Failure and rollback

| Failure point | State | Result |
|---|---|---|
| Verification, sequence check, pull, extraction, ABI check | Nothing changed | Status `failed` with `handoff_failed`, `downgrade_refused`, `release_conflict` or `handoff_unsupported`. Fix the cause and re-run. |
| Target refuses during admission (for example UPG-1 App Access identity) | Nothing changed | Target's own message and exit code 13. |
| Target fails after mutation | As in UPG-1 section 8 | Forward fix: re-run, which delegates again to the same target, or move to the next release. Restore stays with `app-access-restore.py` or the documented restore. |
| Target reaches `healthy` but installing its copies fails | Upgrade done, old trampoline remains | Status stays `healthy`, with a warning line. The next upgrade still delegates correctly, because the old trampoline is ABI 1. |

The trampoline never restores and never retries automatically.

## 5. Bootstrapping hosts already on v0.1.45 or older

Their scripts have no trampoline. Three populations:

**1. Systemd-runner hosts without App Access (most installations).**
- One ordinary dashboard upgrade to the first UPG-2 release. The old script applies it,
  then, being privileged, self-updates the root copies and `<install>/upgrade.sh` from
  raw GitHub at the verified SHA (H2/H3). That is the last time raw GitHub supplies
  executable code.
- From then on, every upgrade delegates.
- No operator action is needed.

**2. Hosts with App Access composed on v0.1.45 or older.**
- Their old script refuses before self-update (UPG-1 F5). They need the one-time manual
  replacement ruled in UPG-1 D3: replace both copies with the target's verified script.
- UPG-2 makes this safer and shorter by shipping a documented verify-and-extract
  procedure, which uses only commands already on the host. The release notes print the
  exact text:
  1. Fetch the target `release.json` from its immutable release tag.
  2. Verify it with the **installed** API image's `releaseverify -public-key <.env key>
     -expected-source-sha <sha> -print-env`.
  3. Pull the printed `TUNNEX_API_IMAGE` digest.
  4. Run `docker create` / `docker cp /usr/share/tunnex/host/upgrade.sh`.
  5. Install it as both copies with the modes from UPG-1 D3.
- Then click upgrade.

**3. CLI-only and non-systemd hosts (H6).**
- Their `<install>/upgrade.sh` has never been refreshed. A CLI upgrade with the old script
  applies the release but leaves the old script in place.
- One-time step: the same verify-and-extract procedure, installing `<install>/upgrade.sh`
  only.
- After one UPG-2 upgrade, the target refreshes this copy itself (4.3).

Release notes for the first UPG-2 release name all three populations. An old script
cannot announce anything new about itself, so the notice comes from the dashboard instead.
New scripts report `host_abi=1` in the status file. When that field is absent, the Updates
page shows: "This control plane's upgrade helper predates self-updating upgrades. Run the
one-time step in the release notes, or upgrade once from the dashboard." The wording is
chosen per population, using whether a runner is present and whether App Access is
present.

The API's status parser must accept the new key. Older APIs must ignore it, which needs
checking before Phase 2.

## 6. Threat notes

- **Tampered host files at the source (GitHub or a mirror).** Under T-c, host files come
  from a digest-pinned image whose digest the pinned key signed. A modified file means a
  different image digest, which the descriptor does not list. This is an improvement over
  today (H3).
- **Malicious or older signed release (replay or downgrade).** Refused by the sequence
  rule against the installed signed descriptor (4.4). The dashboard additionally binds the
  approved SHA and sequence.
- **Compromised release signing key.** Out of scope, and the same as today: such a key
  can already sign images that run as the API with the database and master key. UPG-2
  adds no new key and no new trust root, and removes one (GitHub raw).
- **Hand-off environment abuse.** The trampoline sets every hand-off variable
  explicitly. The target trusts none of them as security input: it re-verifies the
  manifest, recomputes the sequence check and re-reads `.env` with `sed`. Only a root
  caller can set `TUNNEX_UPGRADE_HANDOFF`, and it only skips one delegation.
- **TOCTOU on extracted files.** The hand-off directory is created by `mktemp -d` as
  root, mode 0700, inside a root-only parent. Files are copied from the container, never
  from a user-writable path, and executed from that directory immediately.
- **Shell sourcing.** `ai-bootstrap.sh` continues to be sourced, but now only from the
  verified extraction. Configuration files (`.env`, status, request) are never sourced or
  `eval`ed.
- **Mixed versions.** The old trampoline does no feature work. All admission, backup and
  ordering is in one script version, the target's. The "old script, new compose" mix that
  produced UPG-1 F1–F3 cannot occur.
- **Broken target trampoline adopted.** Prevented by R-a: copies are replaced only after
  a successful upgrade.

## 7. Recommendation

Adopt the following:

| Area | Choice |
|---|---|
| Trust chain | T-c, host files from the signed API image |
| When to delegate | W-a, right after verification, in both dry run and apply |
| When copies are replaced | R-a, only after the target is healthy |
| Downgrade and replay | Sequence rule against the installed signed descriptor |
| Hand-off | Frozen ABI 1 with `exec` |
| Air-gap | Fully offline, digest-verified |

Do it in the trampoline-first order, so every host that runs a UPG-2 script is never
trapped again.

## 8. Phased delivery

**Phase 1 (first slice, one release):**

- `api.Dockerfile` copies the host files and `HOST_ABI` to `/usr/share/tunnex/host/`, with
  a test that the files in the image equal the files at the source SHA.
- `upgrade.sh` gains:
  - the trampoline section at the very top, after verification
  - the sequence check
  - extraction and `exec`
  - the hand-off receiver
  - copy replacement after `healthy`, including the `<install>` copy for CLI hosts
  - the target reads every host file from the hand-off directory instead of raw GitHub.
    That covers `tunnex.yml`, `ai-bootstrap.sh`, `config-managed.json`, the App Access
    overlay and `restore.py`, and closes H3 for every host already on UPG-2.
- Fallback, for this first release only: if the target image lacks
  `/usr/share/tunnex/host`, which can only be a pre-UPG-2 target (a downgrade, already
  refused), refuse with `handoff_unsupported`.
- Release notes: the three bootstrap populations, plus the verify-and-extract procedure.

**Phase 2:**

- The offline path per 4.6 (OCI-layout verification, no network).
- Dashboard notice for hosts without the trampoline.
- `install.sh` takes host files from the verified image too, instead of raw GitHub. This
  gives the installer the same trust root.

**Phase 3, optional:**

- Unit-file updates, from signed content and only after `healthy`.
- Delete the remaining raw-GitHub code paths. They are reachable only by pre-UPG-2
  scripts during bootstrap.

## 9. Tests

**Contract tests** (`sh` and `dash`, Docker and verifier fakes, extending
`upgrade_apply_contract_test.sh` and `upgrade_runner_contract_test.sh`):

- **Delegation happens before any guard and before the backup:**
  - an old-style refusing guard placed after the trampoline is never reached
  - no backup file exists when delegation fails
- **Exact `exec` arguments and environment:**
  - the target receives the verified manifest path
  - `TUNNEX_DIR` is the install directory, not the hand-off directory
  - the status file's `request_id` is continuous
  - the old `EXIT` trap does not write after `exec`
- **The target with `TUNNEX_UPGRADE_HANDOFF=1` does not delegate again.** A target
  without it delegates exactly once.
- **Sequence table:** higher proceeds; equal with the same SHA proceeds; equal with a
  different SHA refuses; lower refuses; missing installed descriptor refuses unless the
  CLI flag is given, and the runner cannot pass that flag.
- **Extraction uses the verified digest only:**
  - a mutable tag is refused
  - `--pull never` on create
  - the container is never started
  - files are copied into a 0700 directory
- **ABI:** an unknown `HOST_ABI` refuses, and so does an unknown hand-off ABI.
- **Copy replacement:** happens only after `healthy`, with the right owners, modes and
  paths. The `<install>` copy is refreshed without privilege. A failed target leaves the
  old copies untouched.
- **Air-gap:**
  - any network command fails the test
  - an archive whose manifest digest differs is refused before `docker load`

**Image test:** the files in the built API image under `/usr/share/tunnex/host` are
byte-identical to `deploy/` at the build's source SHA (CI, per architecture).

**Compatibility matrix (CI):** the trampoline of each supported release delegates to the
current target, and the current target accepts a hand-off from each supported release's
trampoline (ABI 1).

**Bootstrap rehearsal** on an isolated test CP:

- a v0.1.45 systemd host goes through one dashboard upgrade and the next upgrade
  delegates
- a v0.1.45 App Access host goes through the documented verify-and-extract procedure,
  then a one-click upgrade
- a CLI-only host goes through the procedure, then `./upgrade.sh --apply`

## 10. Founder decisions (with recommendation)

- **U1. Source and trust of target host files.**
  - **Recommendation:** T-c, the files ship inside the signed, digest-pinned API image
    and are extracted without running it.
  - Rejected alternatives: raw GitHub at the SHA (status quo), and a new detached signed
    descriptor (T-b).
- **U2. When to hand off.**
  - **Recommendation:** right after the signature and source-SHA verification, before
    every admission guard, backup and mutation, in dry runs as well as applies.
  - Signed target code now runs before the backup. The target takes the backup itself
    before it mutates anything.
- **U3. When the installed copies are replaced.**
  - **Recommendation:** only after the target upgrade reaches `healthy`.
  - The `<install>` copy is always replaced. The root copies are replaced when
    privileged. Unit files are not touched.
- **U4. Downgrade and replay rule.**
  - **Recommendation:**
    - Compare against the installed **signed** `release.json`.
    - Allow strictly newer releases, and a re-run of the same release with the same SHA.
    - Refuse everything else.
    - No "allow older" override. Going back is a restore.
- **U5. Missing installed descriptor.**
  - **Recommendation:** refuse by default. Provide a CLI-only
    `--accept-installed-unknown` that is printed in the status and never reachable from
    the dashboard runner.
- **U6. Bootstrap for v0.1.45 and older.**
  - **Recommendation:**
    - Systemd hosts without App Access need nothing: one ordinary dashboard upgrade.
    - App Access hosts, plus CLI-only and non-systemd hosts, need a one-time documented
      verify-and-extract replacement, which supersedes the raw text of UPG-1 D3.
    - The dashboard shows a notice for hosts whose helper predates the hand-off.
- **U7. Air-gapped upgrades.**
  - **Recommendation:**
    - Make `--airgap` truly offline: `--manifest` is required, OCI-layout archives are
      verified against the signed digests before load, host files come from the
      verified image, and no network access is allowed.
    - Ship this in Phase 2, and state in the docs until then that the current air-gap
      path still reaches GitHub.
- **U8. Hand-off interface stability.**
  - **Recommendation:** freeze ABI 1 (the arguments and environment in 4.5), and back it
    with a CI matrix of supported trampolines × current target.
  - Any breaking change requires ABI 2 and a two-hop upgrade.

## Founder rulings, 2026-11-24

The founder accepted every recommendation ("do recommended"), under the standing
principles: no user confusion, security unchanged, one-click upgrades, no feature blocks
upgrades.

- **U1, source of host files:** accepted. They ship inside the signed, digest-pinned API
  image and are extracted without running it.
- **U2, when to hand off:** accepted. Right after signature and source-SHA verification,
  before every admission guard, backup and mutation, in dry runs as well.
- **U3, replacing installed copies:** accepted. Only after the target reaches `healthy`.
  The install-directory copy is always replaced; the root copies when privileged. Unit
  files are not touched.
- **U4, downgrade and replay:** accepted. Strictly newer releases, or a re-run of the same
  release with the same SHA. Everything else is refused, with no override.
- **U5, missing installed descriptor:** accepted. Refused by default. A CLI-only
  `--accept-installed-unknown` that is never reachable from the dashboard runner.
- **U6, bootstrap of v0.1.45 and older:** accepted. Systemd hosts without App Access need
  one ordinary dashboard upgrade. App Access hosts and CLI-only or non-systemd hosts need
  the one-time verify-and-extract step, which supersedes UPG-1 D3.
- **U7, air-gapped upgrades:** accepted. Truly offline in Phase 2. Until then the docs
  say the current path still reaches GitHub.
- **U8, hand-off interface:** accepted. ABI 1 is frozen, backed by a compatibility check.
  A breaking change needs ABI 2 and a two-hop upgrade.
