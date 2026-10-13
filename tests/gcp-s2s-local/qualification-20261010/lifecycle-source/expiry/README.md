# Failed expiry cycles and refusal checkpoint

This archive records three attempts against deployed source 4143d866. None
qualified temporary expiry. Helpers and corrected versions are source only;
private original receipts remain unchanged. Receipt projections omit bodies,
credentials, material, full journals and raw native states. Source hashes are
recorded separately from evidence hashes. Coordinator sources retain their
original pinned paths and are not portable or automatically executable here.

V1: the lease helper recorded HTTPError after disabling both original permanent
rules. It recorded no created temporary ID. Both originals and the complete
13-resource/12-policy baseline were restored; fresh native and TCP/UDP payload
checks passed. The server error body/status was not retained in that receipt,
so it does not itself prove the duplicate-index cause. Source inspection showed
site/resource uniqueness is independent of enabled state and expiry; v2 uses a
freshly verified equal singleton Site70 CIDR rather than another site tuple.

V2: the helper recorded TCP temporary ID
01a126c1-82c9-73a5-b0ec-0d1b932137b1, requested expiry
2026-10-10T17:01:08.397790Z. The coordinator separately observed Go's equivalent
2026-10-10T17:01:08.39779Z response and Python3.9 parsing refusal before UDP POST.
That exact five-digit parser failure was independently reproduced offline.
Both originals and all baseline resources/policies were restored; TCP/UDP
payload checks passed. Strict native single-rule allow remained false while
temporary duplicate TCP authority existed, so restoration was not represented
as full native acceptance. Initial cleanup before expiry refused. Coordinator
read-only GET at 17:02:02 UTC found the temporary absent after normal sweep;
the later archived cleanup receipt confirms already_absent and preserved
original baseline. This is normal expiry/sweep observation, not a completed
allow-to-expiry qualification or manual deletion proof.

V3: corrected timestamp parsing was reviewed and nine parser/authority boundary
tests passed on Python3.9 and Python3.14 with optimization enabled. The fresh
preallow capture SHA744c4cbf3e8353576dda2da3122deed0e9fe372b906d9023da02749d31daae5a
refused before any API writes. Offline unmodified production readback and
withdrawal checks both passed at guard revision21401. Expected and actual
HA/Classic permit sets were all empty, with no matching TCP8080/UDP9000 forward
accepts and permanent remote81 refusal intact. The same reviewed observer
passed deny for both protocols. No observer weakening is warranted. The reason
runtime withdrew permission is not proved by this snapshot.

The next cycle requires normal runtime positive state and a fresh native
preallow proof. Shared failure-scope/renewal source fixes and live acceptance
remain separate from these archived observations.
