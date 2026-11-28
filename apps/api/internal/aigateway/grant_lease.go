package aigateway

import "time"

// grantLease is how long one authorization lease lasts. An in-flight request
// renews it (Grant.Renew) before it ends; revocation reaches a running request
// within one lease.
var grantLease = 30 * time.Second

// SetGrantLeaseForTests shortens the lease so tests can exercise renewal
// quickly. It returns a function restoring the previous value. Never call it
// outside tests.
func SetGrantLeaseForTests(d time.Duration) func() {
	previous := grantLease
	grantLease = d
	return func() { grantLease = previous }
}
