// Package bootstrap holds the reviewed target installer delivered over gateway mTLS.
package bootstrap

import _ "embed"

//go:embed helper.py
var Helper string

//go:embed authorize.py
var Authorize string
