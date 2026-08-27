//go:build linux

package egress

// The FQDN baseline is deliberately local, durable state.  A desired policy only
// contains the next answer generation; after an agent restart it cannot tell which
// concrete answers were removed while it was down unless it retained the last
// successfully applied generation.  The file has a small two-phase shape:
// pending is written before nft, committed only after nft accepted the complete
// policy.  A crash at either boundary is therefore fail-closed on the next boot.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

type fqdnBaselineFile struct {
	State       string                      `json:"state"` // pending | committed
	Generations []nodepolicy.FQDNGeneration `json:"generations"`
	Allow       []nodepolicy.AllowEntry     `json:"allow"`
}

func fqdnAllowBaseline(p *nodepolicy.Compiled) []nodepolicy.AllowEntry {
	if p == nil || len(p.FQDNGenerations) == 0 {
		return nil
	}
	answers := make(map[string]struct{})
	for _, g := range p.FQDNGenerations {
		for _, answer := range g.Answers {
			answers[answer] = struct{}{}
		}
	}
	out := make([]nodepolicy.AllowEntry, 0, len(p.Allow))
	for _, allow := range p.Allow {
		if _, ok := answers[allow.DstCIDR]; ok {
			out = append(out, allow)
		}
	}
	return out
}

func writeFQDNBaseline(path string, state string, p *nodepolicy.Compiled) error {
	if path == "" {
		return nil
	}
	if state != "pending" && state != "committed" {
		return fmt.Errorf("invalid fqdn baseline state %q", state)
	}
	b, err := json.Marshal(fqdnBaselineFile{
		State: state, Generations: p.FQDNGenerations, Allow: fqdnAllowBaseline(p),
	})
	if err != nil {
		return fmt.Errorf("marshal fqdn baseline: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create fqdn baseline directory: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("write fqdn baseline: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("commit fqdn baseline: %w", err)
	}
	return nil
}

func readFQDNBaseline(path string) (fqdnBaselineFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return fqdnBaselineFile{}, err
	}
	var state fqdnBaselineFile
	if err := json.Unmarshal(b, &state); err != nil {
		return fqdnBaselineFile{}, fmt.Errorf("decode fqdn baseline: %w", err)
	}
	if state.State != "committed" {
		return fqdnBaselineFile{}, fmt.Errorf("fqdn baseline is %q", state.State)
	}
	for _, allow := range state.Allow {
		if _, ok := tupleFromAllow(allow); !ok {
			return fqdnBaselineFile{}, fmt.Errorf("fqdn baseline contains malformed tuple")
		}
	}
	return state, nil
}
