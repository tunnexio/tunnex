# Private maximum-prefix observation wrapper review

Source-only draft; nothing staged or executed. `prepare-max-prefix-observer.py` writes ONLY a native binding, never an observation/ACK/cleanup receipt. Root supplies genuine fresh inputs. It does not establish that external attestation is true: root independently verifies container/image/node/namespace/journal inputs first, and the native oracle independently rechecks current runtime. No production journal mutation, history truncation or controller construction.

Use existing staged `reviewed-max-prefix-3cc3e9db` for normal API/DNS functions. Install this new reviewed preparation source separately only after review. Layout: existing Ubuntu-owned0700 private root P retains D and M/R; a NEW root-owned0700 observation directory Q contains root0600 copies of normal receipt and immutable lifecycle M/R, independent current runtime attestation, output binding, raw test output and extracted typed result. Copy only reviewed typed/state inputs needed locally; do not export their bodies or credentials. Existing original historical reboot proof/stopped journal remain unchanged and hash pinned. Binary remains separate, exact SHA a55be0165ed8990906457efe0e1714971d7826516a9e579e6feebac329734d6a.

Fresh attestation JSON input: `observed_at`, `container_id`, `image_sha256`, `node_executable_sha256`, `binding`, `journal_cleanup_desired_revision`. Binding contains exact org/site/gateway/connection UUIDs, desired/config revisions, limit1 or8, namespace device/inode and optional original historical_boot pins. Actual independent collection must establish these; this script provides no invented attestation template or producer. It pins current c5 container, image9a49, node7dfb hashes. A replacement requires a separately reviewed source pin change. Do not reuse old revision/history counts. Preserve the whole actual journal (including all24 retained/current history and genuine old-boot entry), whose checksum/history/process/guard checks remain in the unchanged observer. No fixed expected journal count is manufactured here.

Ubuntu: source existing execution-functions.sh; set AZURE_SOURCE_ROOT to staged3cc, AZURE_PRIVATE_ROOT=P, AZURE_DNS_TRANSITION=existing D. `max_prefix_dns read`; `max_prefix_dns revoke` only after reviewed window. Never prepare D. Independently prove withdrawal. New M/R/output paths preserve original state. Native baseline uses fresh `max_prefix_limit read NORMAL`; absence uses real disabled/settled normal read and exact independent journal cleanup revision; post-limit uses `max_prefix_limit restore-read NORMAL` (no runtime inference). For restored baseline use `max_prefix_baseline read NORMAL` and R immutable state.

Root, after installing actual private input copies, runs this preparation only:

```sh
python3 prepare-max-prefix-observer.py --normal "$Q/normal.json" --immutable "$Q/immutable-state.json" --attestation "$Q/runtime-attestation.json" --observer-binary /private/tmp/azure-owned-maxproof-postlimit-dd8cbe12.test --mode baseline --output "$Q/max-prefix-binding.json"
```

Choose absence or post-limit explicitly. All evidence timestamps≤60s; output path absent/private. Absence also requires normal disabled/not_applied/nonpending and equality with actual cleanup journal revision. Post-limit requires limit1 and immutable restore-read, but does NOT require API Applied or infer readiness. Baseline requires normal Applied in addition to independent native proof later. Key-free stdout is a fixed preparation result; failures generic, no raw file content.

Root separately reviews private installation into actual c5 container `/run/tunnex-qualification/max-prefix-binding.json`, unchanged historical evidence and attested binary path. No installation command is automated here. Then run **only** the unchanged observer on that real container:

```sh
docker exec -u 0 -e TUNNEX_AZURE_MAX_PREFIX_NATIVE_PROOF=1 "$VERIFIED_CURRENT_CID" "$VERIFIED_CONTAINER_BINARY" -test.run '^TestAzureOwnedMaxPrefixNativeProof$' -test.v > "$Q/native-test-output.txt"
```

Require zero exit, no skip and exactly one `AZURE_MAX_PREFIX_NATIVE_PROOF ` typed line; keep raw harness output private, extract only that line into a new0600 receipt. No receipt on failure. Recheck actual fresh identity after installation/time delay; preparation success is no freshness extension. Same a55 binary contains counter-aware baseline/absence oracle and reviewed two-frame PfxCt mode; pin exact hash instead of substituting any historical371 artifact. Observer enforces native/process/socket/namespace/whole-guard/journal brackets and genuine reboot pins. No journal slicing/copying or assumed postlimit readiness.

Pre-add capture starts in actual attested owned gateway namespace before one Azure add. Range review/native baseline/normal receipt must remain≤60s at add; recollect on expiry. Restore Azure FIRST with fresh immutable restore-read regardless of PfxCt/runtime refusal. Any preparation/schema/identity/history/native bracket failure stops; no fabricated result or blind mutation retry. This draft intentionally leaves root-only input installation and typed receipt extraction explicit, rather than introducing another cloud/native authority wrapper.
