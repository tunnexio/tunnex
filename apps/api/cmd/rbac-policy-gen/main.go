// Command rbac-policy-gen serializes the authoritative RBAC grant table
// (rbac.Policy) to canonical JSON at the path given as its first argument. It is
// run by `make generate-rbac`; the emitted file is consumed by the web client's
// RBAC mirror (apps/web/src/lib/rbac.ts) so the two can never silently diverge —
// `make generate-check` fails if the committed JSON drifts from the Go table.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: rbac-policy-gen <output-path>")
		os.Exit(2)
	}
	// json.Marshal sorts map keys, and Policy() sorts each permission slice, so
	// the output is deterministic (stable across runs → clean drift diffs).
	b, err := json.MarshalIndent(rbac.Policy(), "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal: %v\n", err)
		os.Exit(1)
	}
	b = append(b, '\n')
	if err := os.WriteFile(os.Args[1], b, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}
