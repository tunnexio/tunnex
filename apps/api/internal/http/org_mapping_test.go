package http

import (
	"testing"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

func TestToAPIOrgPreservesAgentJITAccessEnabled(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		got := toAPIOrg(sqlc.Organization{AgentJitAccessEnabled: enabled})
		if got.AgentJitAccessEnabled != enabled {
			t.Fatalf("agent_jit_access_enabled = %v, want %v", got.AgentJitAccessEnabled, enabled)
		}
	}
}
