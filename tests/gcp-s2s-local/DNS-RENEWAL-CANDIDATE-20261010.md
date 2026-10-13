# GCP DNS guard renewal candidate

Base: frozen cloud source `3d0951e84aa58ce78dcc6238bd2ecaf7d3f38fd9`.
This isolated candidate is not integrated or deployed. No actual Google DNS
failure has been attributed to this race.

Shared Azure source review identified an independently published guard renewal
between an immutable owner-view load and its complete native guard read.
GCP Classic contract 4 and HA contract 3 traverse the same read path. Four
provider-shaped initial/final-read regressions passed their stable baseline,
then failed on the unchanged source when the native reader observed a newer
committed template. The narrow adaptation makes those cases pass.

Only a complete native guard read failure can trigger the initial retry. The
final read additionally binds its checked digest. Both stages share one retry
budget. The independently published replacement must have a different digest;
original owner epoch, input identity and both accepted lease deadlines remain
valid before and after its full read. A subsequent digest change refuses.
There is no controller mutation, authority renewal, grant creation, or retry of
malformed namespace/set/required-member inputs.

The tests use real GCP material validation, the real guard renderer/parser and
real accepted lease machinery. SA/source/route inventories are modeled. They
are not native packet, control-plane enrollment or Google qualification proof.
Classic's fixture explicitly keeps its inactive tuple zero and excludes its
inactive interface from readback. Legacy two-slot fixture behavior is retained.

Checks:
- Frozen-source four-case regression: RED after positive baseline.
- Initial/final positive cases and owner/grant/lease/native/cancellation/digest
  churn/shared-budget negatives: race PASS 4.386s.
- Existing owner-view plus GCP renewal suite: race PASS 5.884s.
- Full IPsec suite: PASS 42.956s; fqdnrpc suite: PASS 1.211s.
- Linux AMD64 agent build PASS; artifact SHA256
  `8df008f00d4d4bfeb68f67eb4e540755876ea8b521dc634c4547c88748610961`.

Endpoint concurrency change `ddc26950` was reviewed separately: four complete
endpoint workflows are bounded and results reduce in configured order. It is
not included in this candidate. Shared withdrawal-zero changes are also separate.
