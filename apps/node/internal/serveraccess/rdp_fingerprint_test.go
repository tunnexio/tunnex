package serveraccess

import (
	"encoding/base64"
	"testing"
)

func TestGuacCertificateFingerprint(t *testing.T) {
	digest, err := base64.RawStdEncoding.DecodeString("eJACheLLVPjdmcv0POB7UVrSNCdCG8Pp+mwIkO7nT5k")
	if err != nil {
		t.Fatal(err)
	}
	const want = "sha256:78:90:02:85:e2:cb:54:f8:dd:99:cb:f4:3c:e0:7b:51:5a:d2:34:27:42:1b:c3:e9:fa:6c:08:90:ee:e7:4f:99"
	if got := guacCertificateFingerprint(digest); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}
