# Runtime history continuation (journal v8)

This change removes the artificial lifetime limit of sixteen BGP process retirements and sixteen trusted namespace restorations for one delivery. It changes private runtime duty storage; it does not change public configuration, CP leases, forwarding permissions, or the trusted stop/absence proof requirements.

## Durable lineage

The journal retains up to sixteen concrete retired process identities and sixteen concrete trusted restoration epochs. Before the next reservation would exceed that bound, it replaces exactly the oldest previously committed, discharged entry with a continuation `{Count, Digest}`. The digest is a domain-separated SHA-256 chain over the exact canonical identity, the previous digest, and its monotonic ordinal. The atomic journal save/fsync commits the tombstone and the new reservation together. A newly discharged duty cannot be compacted in that same transition; the predecessor must already record its discharge.

A process generation equals the compacted count plus the concrete retired count plus one. A restoration epoch equals the compacted count plus the concrete retired count. Neither counter resets; unsigned overflow refuses. Generation-specific private directories remain distinct and are not reused, adopted, or deleted by compaction. The continuation itself supplies no deletion authority.

Process compaction requires the oldest recorded process stage to be `cleaned`. A committed restoration epoch already binds the trusted runtime termination and the verified absence in the replacement namespace. Epoch compaction additionally refuses any historical retired process with unresolved uncertainty. Unknown artifacts and uncertain process duties are never compacted. An unresolved oldest duty can therefore still block further reservations at the concrete-history bound; the bound is intentional for unresolved work. Historical uncertain snapshots are retained conservatively even if another record later reports remediation.

Successor validation recomputes the exact expected digest from the predecessor. Changing the offset or digest, omitting entries without a tombstone, replaying a generation/epoch, or rewriting retained ownership identities refuses. Ambiguous write/fsync failure poisons the writer, and restart must reload a whole validated journal before continuing.

## Compatibility and rollback

New fields are optional and omitted at zero history offset. Existing journal versions 1 through 7 and their canonical checksum bytes remain supported. The first compaction upgrades the journal to version 8. New readers reject a continuation encoded under an older version, and journal versions cannot decrease.

An older binary cannot safely consume a compacted v8 journal. Rollback requires a binary that understands this continuation contract; deleting the tombstone or rewriting the journal as v7 is not a supported rollback. The restoration receipt tool must be rebuilt from the same v8-aware source before qualifying restoration of such a journal. Public API manifests and their digests are unchanged.

## Local evidence

`runtime_history_continuation_test.go` exercises real journal saves, checksums, locks, reloads, and successor validation through forty process generations, forty CV2/CV3 restoration epochs, and forty combined BGP process/namespace cycles. The identity/termination fixtures are synthetic; these tests do not claim forty native daemon restarts or cloud packet acceptance. Negative cases cover uncertain-duty compaction, forged/replayed lineage, overflow, and ambiguous directory fsync failure.

Go 1.26.8 suites passed: `internal/ipsec`, `internal/bgp`, `internal/control`, and `cmd/ipsec-restoration-receipt`. No cloud worker, provider, kernel state, or journal was modified during this local implementation. A new immutable build and separate native/cloud qualification are required before deployment.

Actual local ARM64 qualification also passed twenty managed FRR generations with live VTY readback, exact tracked-child termination, empty private-directory/fsync recovery, real journal close/reload, and capability readback. The final process was generation 20 with a cleaned-history continuation count of 3 and sixteen concrete retired duties. This fixture used real charon, owned XFRM links and NFT denial, with synthetic configuration and no established peer, application grant, or encrypted packet claim.

Eighteen subsequent replacement namespace allocations passed the original Linux host stop observer, exact Docker SIGKILL, two-pass absence/event proof, the actual v8 receipt CLI, and controller trusted-restoration reservation. The final epoch was 18 with continuation count 2 and sixteen concrete epochs. Each replacement was preallocated while its predecessor was alive and proved different; Linux recycled numerical namespace inode IDs between retired lifetimes. Fresh lease authority was synthetic. Successful owned fixtures were removed; earlier failed fixture receipts remain preserved. Private archived evidence is under `tests/ipsec-bgp-local/.runtime/history-v8-native-qualified`. These local proofs do not establish deployed customer or cloud packet acceptance.

Native Linux AMD64 qualification subsequently passed on the owned test host in a disposable network-none, read-only container using only NET_ADMIN and NET_RAW. The immutable v8 fixture exercised twenty real FRR generations, production controller/journal cleanup, continuation count 3, and actual base/BGP capability 1/1. The test container was removed and the serving worker, certificate, and foreign containers remained unchanged. The fixture contains the v8 product controller code; the production AMD candidate was transferred and hash-verified only, without serving installation. Key-free proof is archived in `tests/ipsec-bgp-local/.runtime/history-v8-native-amd-qualified`. The earlier local emulation refusal is preserved: QEMU lacked required netlink/XFRM operations. This component proof does not claim a v8 serving deployment, encrypted traffic, or CP authority.
