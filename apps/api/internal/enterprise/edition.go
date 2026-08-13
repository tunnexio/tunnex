// Package enterprise is a COMPATIBILITY SHIM, and it is deliberately small.
//
// ⛔ THE BUILD-TAG EDITION SPLIT IS GONE (S12.1). There is one binary. What used to be decided at compile
// time — `edition_open.go` vs `edition_enterprise.go`, selected by `-tags enterprise` — is now decided at
// RUNTIME by a licence, through `internal/licence`.
//
// ⚠ This package survives only so callers that read `Unlimited` / `MaxOrganizations` keep compiling while
// they are migrated to `licence.Has(...)`. It is NOT the entitlement source and must not grow.
//
// ⛔ AND THE LICENSE FILE IN THIS DIRECTORY NO LONGER GOVERNS ANYTHING BUT ITSELF. `idpsync`, `policy` and
// `sso` moved to `internal/` in this story — approximately 1,784 lines relicensed from the proprietary
// source-available terms to Apache-2.0, founder-ruled, and ONE-WAY: once released under Apache-2.0 it
// cannot be withdrawn from anyone who received it.
package enterprise

// Unlimited is retained for callers not yet migrated. ⚠ ALWAYS TRUE NOW — the real answer comes from the
// licence, and a build-time constant cannot express a runtime entitlement.
const Unlimited = true

// MaxOrganizations is meaningless when Unlimited is true; kept for signature compatibility only.
const MaxOrganizations = 0

// Name is what `/meta` reports as the edition.
//
// ⚠ TEMPORARY, AND IT IS THE UNLICENSED DEFAULT. With one binary the edition is a property of the LICENCE,
// not the build, so this becomes a licence read in the LicenseManager slice. Until then it reports the
// tier a deployment with no key is entitled to.
//
// ⛔ The name itself ("open" vs "Community") is an open S12.1 decision — the licensing model calls the free
// tier Community while the site and this enum say "open". Renaming touches the OpenAPI enum, the generated
// clients and the web mirror, so it is a deliberate sweep, not a rename inside a compile fix.
const Name = "open"
