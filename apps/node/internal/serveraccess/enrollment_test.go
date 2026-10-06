package serveraccess

import (
	"github.com/tunnexio/tunnex/packages/apptransport/bootstrap"
	"testing"
)

func TestSetupDestinationAndOutputLimits(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "169.254.169.254", "8.8.8.8", "localhost"} {
		if validateSetupJob(bootstrap.Job{IP: ip, Port: 22, Account: "ubuntu", Script: "reviewed"}) == nil {
			t.Fatal("unsafe target accepted", ip)
		}
	}
	if validateSetupJob(bootstrap.Job{IP: "10.2.3.4", Port: 22, Account: "ubuntu", Script: "reviewed"}) != nil {
		t.Fatal("private target refused")
	}
	b := &boundedSetupOutput{}
	if _, e := b.Write(make([]byte, 65537)); e == nil {
		t.Fatal("unbounded output accepted")
	}
}
func TestSetupOutputRequiresStructuredResult(t *testing.T) {
	if _, e := parseSetupOutput([]byte("no result")); e == nil {
		t.Fatal("missing result accepted")
	}
	result, e := parseSetupOutput([]byte("Detected Linux\nBEGIN TUNNEX SSH RESULT\n{\"version\":1,\"accounts\":[\"ubuntu\"]}\nEND TUNNEX SSH RESULT\n"))
	if e != nil || result.Version != 1 {
		t.Fatal(result, e)
	}
}
