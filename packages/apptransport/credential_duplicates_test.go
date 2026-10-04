package apptransport

import (
	"net/http"
	"testing"
)

func TestKnownCredentialInLaterAuthorizationIsStripped(t *testing.T) {
	for _, secret := range []string{"AppProxy tnxap_secret", "Bearer tnx_secret", "Bearer tnxm_secret", "Bearer tnxap_secret"} {
		h := http.Header{"Authorization": []string{"Bearer application-token", secret}, "X-Auth-Token": []string{"application-token"}}
		StripCredentials(h)
		if len(h.Values("Authorization")) != 0 {
			t.Fatal("later Tunnex credential forwarded")
		}
		if h.Get("X-Auth-Token") != "application-token" {
			t.Fatal("ordinary application credential removed")
		}
	}
	h := http.Header{"Authorization": []string{"Bearer application-token"}}
	StripCredentials(h)
	if h.Get("Authorization") != "Bearer application-token" {
		t.Fatal("single application auth removed")
	}
}
