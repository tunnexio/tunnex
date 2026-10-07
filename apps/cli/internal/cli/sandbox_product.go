package cli

import "errors"

// SandboxProductAvailable is a static gate, independent of environment or credentials.
// TODO(sandbox-reentry): restore product wiring together with the gates in
// docs/S-sandbox-shelved-main-reentry.md after an explicit restart decision.
const SandboxProductAvailable = false

var ErrSandboxShelved = errors.New("sandbox development is paused")
