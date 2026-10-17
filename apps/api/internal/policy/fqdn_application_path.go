package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
	"strconv"
)

// The optional application binding changes content identity without changing any legacy generation.
func fqdnApplicationGenerationIdentity(base string, p *policyspec.FQDNApplicationIPsecPath) string {
	if p == nil {
		return base
	}
	id, err := uuid.Parse(p.ConnectionID)
	if base == "" || err != nil || id == uuid.Nil || id.String() != p.ConnectionID || p.ConfigurationRevision != 1 {
		return ""
	}
	sum := sha256.Sum256([]byte(base + "\x00application_ipsec_path\x00" + p.ConnectionID + "\x00" + strconv.FormatInt(p.ConfigurationRevision, 10)))
	return hex.EncodeToString(sum[:])
}
