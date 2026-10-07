// Package sandboxproduct gates the dedicated sandbox executables independently
// of environment, configuration and retained implementation source.
package sandboxproduct

import "errors"

// TODO(sandbox-reentry): restore all product gates together as recorded in
// docs/S-sandbox-shelved-main-reentry.md after an explicit restart decision.
const Available = false

var ErrShelved = errors.New("sandbox development is paused")
