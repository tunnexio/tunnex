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
	Format      int                         `json:"format"`
	State       string                      `json:"state"` // pending | committed
	Generations []nodepolicy.FQDNGeneration `json:"generations"`
	Allow       []nodepolicy.AllowEntry     `json:"allow"`
}

// fqdnHistoryFile is deliberately separate from the active tuple baseline.
// It proves that this gateway has previously enforced an S21 FQDN generation
// without attempting to reconstruct retired tuples from corrupt state.
type fqdnHistoryFile struct {
	Format int  `json:"format"`
	Seen   bool `json:"seen"`
}

func fqdnAllowBaseline(p *nodepolicy.Compiled) []nodepolicy.AllowEntry {
	if p == nil || len(p.FQDNGenerations) == 0 {
		return nil
	}
	out := make([]nodepolicy.AllowEntry, 0, len(p.Allow))
	for _, allow := range p.Allow {
		if allow.FQDNManaged {
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
		Format: 1, State: state, Generations: p.FQDNGenerations, Allow: fqdnAllowBaseline(p),
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

func writeFQDNHistory(path string) error {
	if path == "" {
		return nil
	}
	b, err := json.Marshal(fqdnHistoryFile{Format: 1, Seen: true})
	if err != nil {
		return fmt.Errorf("marshal fqdn history: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create fqdn history directory: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("write fqdn history: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("commit fqdn history: %w", err)
	}
	return nil
}

func readFQDNHistory(path string) (seen bool, known bool) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return false, true
	}
	if err != nil {
		return false, false
	}
	var state fqdnHistoryFile
	if json.Unmarshal(b, &state) != nil || state.Format != 1 {
		return false, false
	}
	return state.Seen, true
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
	if state.Format != 1 {
		return fqdnBaselineFile{}, fmt.Errorf("fqdn baseline format %d is unsupported", state.Format)
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

// hasUnversionedFQDNBaseline detects an old-format file that positively proves
// prior FQDN enforcement but carries no ownership-mark provenance. It is not a
// recovery hint: callers must refuse FQDN enforcement until an operator performs
// controlled recovery, rather than guessing or flushing unrelated flows.
func hasUnversionedFQDNBaseline(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var state struct {
		Format      int                         `json:"format"`
		Generations []nodepolicy.FQDNGeneration `json:"generations"`
	}
	return json.Unmarshal(b, &state) == nil && state.Format != 1 && len(state.Generations) > 0
}
