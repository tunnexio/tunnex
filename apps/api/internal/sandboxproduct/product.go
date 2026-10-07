// Package sandboxproduct holds the source-level sandbox shelving boundary.
package sandboxproduct

// TODO(sandbox-reentry): review docs/S-sandbox-shelved-main-reentry.md before
// restoring product wiring. Environment or stored settings cannot override this.
const Shelved = true

const Message = "sandbox_feature_shelved: sandbox development is paused"
