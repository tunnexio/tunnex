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

	if err := (apiServer{
		licence:     licence.NewTestManager("scale", expires),
		agentAccess: port,
	}).requireAgentAccessCapability(); err != nil {
		t.Fatal("Scale licence must unlock JIT access")
	}

	for _, tier := range []string{"community", "starter", "growth"} {
		if err := (apiServer{
			licence:     licence.NewTestManager(tier, expires),
			agentAccess: port,
		}).requireAgentAccessCapability(); !hasCode(err, 403, "feature_required") {
			t.Fatalf("%s licence must not unlock JIT access", tier)
		}
	}
}
