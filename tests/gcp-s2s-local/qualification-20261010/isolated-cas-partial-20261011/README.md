# Isolated browser CAS partial checkpoint

Actual first UI Save returned200 at expectedrevision1; stale second Save returned409 with the secret draft cleared. Public desiredrevision2/configrevision1 readback passed. The runner then failed its cleanup gate and overall_accepted:false is preserved. No final cleanup or complete CAS acceptance is claimed until normal read-only reconciliation establishes the exact owned tombstone, configabsence and whole baseline preservation. No replay or second DELETE is implied. Human Chrome/dialogs431fa remain untouched.
