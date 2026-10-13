# Failed GCP9 private-forwarder fixture v8

Actual overall acceptance is false. Seven normal allow cases succeeded. The eighth Classic large-answer case received genuine UDP truncation, established TCP and wrote the DNS question, then timed out before the TCP frame length arrived. The case was not replayed. Policy-removal REFUSED queries were not reached.

All recorded cleanup completed without errors: inverse normal API cleanup, owned client down and resolver/configuration restoration, peer absence, exact temporary firewall deletion and final native/DNS proofs. Cleanup does not turn the failed query or whole fixture into a pass. Cause remains unproved.

This public subset excludes DNS names, answers, tuples, credentials/configuration and their hashes, raw logs/stderr, full NFT and journal. Original private receipts stay immutable.
