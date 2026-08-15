package db_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestF04RuntimeChannelAcceptanceSpec pins the F04 auth and monotonicity seams
// across the HTTP adapter, runtime service, and SQL source.
func TestF04RuntimeChannelAcceptanceSpec(t *testing.T) {
	roots := []string{filepath.Join("..", "internal", "http"), filepath.Join("..", "internal", "agentruntime")}
	var source strings.Builder
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(root, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			source.Write(b)
		}
	}
	s := source.String()
	handlerRequired := []string{
		"AuthenticateAgentRuntimeCredential",
		"sha256.Sum256",
		"device_id",
		"dev.Kind != \"agent\"",
		"cred.RevokedAt.Valid",
		"runtimeUnauthorized",
	}
	for _, marker := range handlerRequired {
		if !strings.Contains(strings.ToLower(s), strings.ToLower(marker)) {
			t.Errorf("runtime handler auth contract must prove %q", marker)
		}
	}

	queries := ""
	for _, name := range []string{"agent_bootstrap.sql", "agent_runtime.sql"} {
		b, err := os.ReadFile(filepath.Join("queries", name))
		if err != nil {
			t.Fatal(err)
		}
		queries += string(b)
	}
	queryRequired := []string{
		"GREATEST(ars.applied_revision, $3)",
		"GREATEST(ars.last_attempted_revision, $4)",
		"$4 <= ars.desired_revision",
		"$4 >= $3",
		"token_hash",
		"revoked_at IS NULL",
	}
	for _, marker := range queryRequired {
		if !strings.Contains(strings.ToLower(queries), strings.ToLower(marker)) {
			t.Errorf("runtime SQL contract must prove %q", marker)
		}
	}

	// These symbols force the implementation to keep opt-in fail-closed,
	// bounded errors, and secret-free admin status explicit.
	for _, marker := range []string{
		"RuntimeCredentialPrefix",
		"ErrOptInUnavailable",
		"validErrorCode",
		"LastErrorCode",
		"AgentRuntimeStatus",
	} {
		if !strings.Contains(s+queries, marker) {
			t.Errorf("runtime channel acceptance contract must address %q", marker)
		}
	}

	// The response contract must remain secret-free. If a future handler adds a
	// runtime response type, it must not copy bootstrap credentials or private
	// key material into that response.
	for _, forbidden := range []string{"PrivateKey", "RuntimeCredential", "TokenHash"} {
		if strings.Contains(s, "RuntimePoll") && strings.Contains(s, forbidden) {
			t.Errorf("runtime poll response must not expose %q", forbidden)
		}
	}
}
