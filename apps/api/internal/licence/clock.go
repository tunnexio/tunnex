package licence

import (
	"sync"
	"time"
)

// Clock detects a BACKWARD jump in the deployment's wall clock.
//
// ⛔ IT REPORTS. IT NEVER REFUSES.
//
// An expiry is checked against the deployment's own clock, and offline verification means there is no
// second opinion. The clock can lie in both directions: forward makes a live key read as expired, backward
// makes an expired key read as live — and backward is the direction an attacker would choose, trivially,
// on a box they control.
//
// So why not refuse on it? Because a clock going backwards is OVERWHELMINGLY a VM restore, an NTP
// correction, a hardware fault, or a container image with a stale clock. Refusing would take a working VPN
// down over a plausible accident, which violates "a running VPN never stops" — and an attacker who can move
// the clock can also delete the high-water mark.
//
// ⚠ HONEST INSTRUMENTATION, RECORDED AS A SUBSTITUTE AND NOT A DEFENCE. It makes the anomaly visible to an
// operator who is looking, and claims nothing more. The real answer to clock-lying is short-lived keys with
// reissue, which is the revocability question already on the record.
type Clock struct {
	mu        sync.Mutex
	highWater time.Time
}

// Observation is what Observe reports. Zero value means "nothing unusual".
type Observation struct {
	// BackwardJump is true when now is materially behind the highest time ever seen.
	BackwardJump bool
	// By is how far behind. Only meaningful when BackwardJump.
	By time.Duration
	// HighWater is the highest time observed before this call.
	HighWater time.Time
}

// Tolerance is the slack allowed before a backward step is called a jump. NTP nudges a clock by
// milliseconds routinely; reporting those would train an operator to ignore the signal entirely.
const Tolerance = 5 * time.Minute

// Observe records now and reports whether the clock moved backward past Tolerance.
//
// ⚠ The high-water mark only ever ADVANCES. A backward jump is reported and then IGNORED for the purpose of
// the mark — otherwise one bad reading would reset the baseline and the second jump would look normal.
func (c *Clock) Observe(now time.Time) Observation {
	c.mu.Lock()
	defer c.mu.Unlock()
	prev := c.highWater
	if now.After(prev) {
		c.highWater = now
		return Observation{HighWater: prev}
	}
	if behind := prev.Sub(now); behind > Tolerance {
		return Observation{BackwardJump: true, By: behind, HighWater: prev}
	}
	return Observation{HighWater: prev}
}

// HighWater returns the highest time observed so far.
func (c *Clock) HighWater() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.highWater
}
