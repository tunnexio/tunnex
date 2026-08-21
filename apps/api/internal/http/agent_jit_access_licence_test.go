package http

import (
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/agentaccess"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
)

func TestAgentJITAccessUsesTheScaleLicenceEntitlement(t *testing.T) {
	port := agentaccess.New(nil, nil)
	expires := time.Now().Add(time.Hour)

	if !(apiServer{
		licence:     licence.NewTestManager("scale", expires),
		agentAccess: port,
	}).agentAccessAvailable() {
		t.Fatal("Scale licence must unlock JIT access")
	}

	for _, tier := range []string{"community", "starter", "growth"} {
		if (apiServer{
			licence:     licence.NewTestManager(tier, expires),
			agentAccess: port,
		}).agentAccessAvailable() {
			t.Fatalf("%s licence must not unlock JIT access", tier)
		}
	}
}
