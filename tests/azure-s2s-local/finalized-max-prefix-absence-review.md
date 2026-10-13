# Finalized prior absence (v4 candidate; source only)

Concrete source gap: original v3 could not refresh absence after finalized delete, because normal projection has no live configuration and normal desired revision may advance beyond retained CleanupDesiredRevision. Source provider.ReadProvider returns surviving profile_id/configuration_revision only when finalized_at exists; HTTP omits configuration. Runtime RetainedRefusal coverage does not advance cleanup revision. No lifecycle has been executed for this source change.

New `finalized-read` normal phase is separate from live `restore-read`. It requires actual deleted/not_applied/nonpending/finalized prior with historical Site/gateway, no live Site/gateway, exact org/UUID, empty actual policies, and GET/configuration having exactly profile_id+configuration_revision. It compares surviving metadata with saved predelete public configuration. Output kind `owned_finalized_prior_authority` explicitly labels the archived saved_prior_contract/hash and actual tombstone revision/timestamps. It contains NO normal_connection, runtime observation or readiness. New normal prepare records prior_configuration (important for R's max1 prior); existing original M may fall back to its original_configuration. Existing baseline R without saved prior_configuration refuses: never infer the deleted max1 config from original baseline8. Prepare R with v4 before its lifecycle.

V4 SOURCE is exclusively `/home/ubuntu/tunnex-azure-lab/reviewed-max-prefix-observer-v4-finalized54`; preserves stagedv3/v2/3cc and M/D. Current54 full CID/image/node/StartedAt pins unchanged. Root must review/stage whole v4 closure separately. The a55 binary is unchanged: no native validation weakening.

After actual original delete/finalization, Ubuntu invokes:

```sh
python3 "$REVIEWED_DISPATCHER" finalized-read
```

Use its actual new private normal receipt with root v4 full observer `--mode absence --state EXISTING_M`. The wrapper calls real finalized-read before/after, checks exact actual tombstone metadata through normal API again, reads the actual whole current journal, derives actual retained cleanup revision and matches saved M.cleanup_revision. Binding desired_revision remains this genuine journal cleanup revision; normal tombstone revision is separately compared and may be larger. No invented enabled/disabled projection or timestamp extension. Complete current/historical/native/socket/process/guard brackets remain the unchanged independent observer. Root installs actual unchanged pinned reboot/stopped evidence. New output native-receipt is generated only by a passing real oracle now, not by the normal finalized-read model.

For disabled predelete absence, existing restore-read mapping remains. New finalized mode is ABSENCE ONLY, never baseline/post-limit authority. Same contract/configrevision/UUID/historicalSite/gateway and absence duties must remain bound. Any changed retained cleanup revision, missing archived config, tombstone config mismatch, extra policies, pending finalization, old receipt or namespace identity refuses. Recovery after arbitrarily long finalization is fresh finalized-read plus fresh complete independent absence; not a forced60s transaction or reused expired receipt. Create still consumes the fresh actual native receipt≤60s and saved cleanup revision. Actual saved max1 prior config is needed in R for later restore lifecycle, even though live tombstone no longer exposes it.

## Exact ownership-copy bridge

Root v4 observer success now reports binding_sha256 alongside actual receipt_sha256/private_run_id. Run only reviewed root helper on tunnex-peer:

```sh
sudo python3 "$V4/tests/azure-s2s-local/copy-max-prefix-absence.py" --run-id "$ACTUAL_MAXPROOF_WINDOW_UUID" --state "$EXISTING_M_OR_R" --receipt-sha256 "$ACTUAL_ROOT_ATTESTED_RECEIPT_SHA" --binding-sha256 "$ACTUAL_ROOT_ATTESTED_BINDING_SHA"
```

It accepts only fixed native-receipt.json/binding.json beneath exact root0700 `PRIVATE/maxproof-window-UUID`, validates their root0600 nonsymlink actual bytes/hashes/freshness/owned prior/setup/saved cleanup revision/zero native objects, and rejects unknown receipt fields. It exclusively creates Ubuntu0600 `PRIVATE/max-prefix-typed-copy-UUID-absence.json` and `-binding.json`. Byte-for-byte copies preserve original hashes/timestamps; console only fixed category/run-ID/hashes. No raw journals, logs, keys, policies or arbitrary path copying. Partial copy refuses without replay/overwrite; root can review exact new private paths. Underlying normal create/delete still independently validates hash/context/freshness. This copy attests no new native fact.

Then explicit fresh discovery/privatePSK plus these typed inputs allow one guarded create. Before post-delete create, root must refresh typed absence/discovery if oldest observation exceeds60s. Same normal finalized state can be freshly reread; it does not extend the native timestamp. Capture-before-add and CLOUD RESTORE FIRST remain unchanged boundaries. D never reprepared. Dispatcher7d7 is a separate unintegrated prerequisite or use final v4 source package with it included; no live dispatcher invocation occurred.

Offline verification:19 maximum-prefix model tests (actual tombstone envelope/correctly distinct cleanup mapping/refusals),11 observer-wrapper tests,4 dispatcher tests,2 exact typed-copy guard tests. Models/fixtures prove source contracts only; no live acceptance. Finalization/schema errors fail closed and require source review, never manually fabricated API envelopes or permissions.
