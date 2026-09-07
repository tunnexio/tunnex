// Package testbifrost holds verified native artifacts for optional zero-spend tests.
// It is not imported by product code. Unknown platforms deliberately have no pin.
package testbifrost

import "runtime"

// BinarySHA256 pins the selected v2.0.0 release artifact on this test platform.
// Linux binaries were extracted from the exact OCI index shipped by Compose/Helm.
var BinarySHA256 = map[string]string{
	"darwin/arm64": "31ac451d83706069e580dd1dedf099aa518d1bc47c3c481d20f97203f799275e",
	"linux/amd64":  "e3a59884140ed5ddb29f373c6c76f42de8d453dc150b996f8f834893b2bfed41",
	"linux/arm64":  "85f21483ed660d8c50de5f4313a995cd8ba364de058d2d645966bf13d5ba9222",
}[runtime.GOOS+"/"+runtime.GOARCH]
