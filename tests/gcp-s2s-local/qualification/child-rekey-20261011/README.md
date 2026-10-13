# Controlled Classic CHILD rekey

The approved command executed once with a durable attempt receipt and return code 0. Its immediate recovery check refused the overlapping old DELETED CHILD and new INSTALLED CHILD. That original lifecycle result remains false.

A separate later read-only reconciliation passed: the target IKE identity and SPIs stayed unchanged, CHILD 4 became CHILD 5 with new SPIs, and HA sibling identities stayed exact. Fresh public native proof showed three CHILD SAs, SAD 6, nine policies, two established BGP peers, and both routes. All four full production guard checks and HA/Classic TCP and UDP packets passed. API and normalized foreign state matched the original baseline.

This proves later recovery only. It does not establish recovery within the original 60-second window, uninterrupted traffic, scheduled IKE rekey, or overall production readiness. The JSON contains allowlisted public projections and source receipt hashes; raw NFT, journal, credentials, PSKs, and XFRM keys are excluded.
