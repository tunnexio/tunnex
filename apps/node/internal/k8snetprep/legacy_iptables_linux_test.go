//go:build linux

package k8snetprep

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Review finding 5. iptables-legacy rules run in the same kernel hooks as
// nf_tables and no nft listing shows them, so a node whose CNI or kube-proxy
// writes with iptables-legacy was ready with nothing read. The node is now
// refused unless the facts say it has no legacy IPv4 table.

// legacyProcNet is a network namespace's proc directory: `dev`, and
// ip_tables_names when listing is given (one argument, the file's content).
func legacyProcNet(t *testing.T, listing ...string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dev"), []byte("Inter-|   Receive\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	for _, content := range listing {
		if err := os.WriteFile(filepath.Join(dir, "ip_tables_names"), []byte(content), 0o440); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestReadLegacyIPTables(t *testing.T) {
	none := LegacyTablesFacts{State: FactsRead}
	for name, tc := range map[string]struct {
		dir  func(*testing.T) string
		want LegacyTablesFacts
		why  string // for an unreadable answer: part of the reason
	}{
		"ip_tables not loaded":     {dir: func(t *testing.T) string { return legacyProcNet(t) }, want: none},
		"loaded, no table":         {dir: func(t *testing.T) string { return legacyProcNet(t, "") }, want: LegacyTablesFacts{State: FactsRead, Tables: []string{}}},
		"tables":                   {dir: func(t *testing.T) string { return legacyProcNet(t, "nat\nfilter\n") }, want: LegacyTablesFacts{State: FactsRead, Tables: []string{"filter", "nat"}}},
		"one table, no newline":    {dir: func(t *testing.T) string { return legacyProcNet(t, "mangle") }, want: LegacyTablesFacts{State: FactsRead, Tables: []string{"mangle"}}},
		"not a proc net directory": {dir: func(t *testing.T) string { return t.TempDir() }, why: "not a network namespace's proc directory"},
		"no directory at all":      {dir: func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") }, why: "not a network namespace's proc directory"},
		"unreadable": {dir: func(t *testing.T) string {
			dir := legacyProcNet(t)
			if err := os.Mkdir(filepath.Join(dir, "ip_tables_names"), 0o755); err != nil {
				t.Fatal(err)
			}
			return dir
		}, why: "read ip_tables_names"},
		"a name that is not a table": {dir: func(t *testing.T) string { return legacyProcNet(t, "nat\n../x\n") }, why: "not understood"},
		"too many names":             {dir: func(t *testing.T) string { return legacyProcNet(t, strings.Repeat("t\n", maxLegacyTables+1)) }, why: "more tables"},
		"too long":                   {dir: func(t *testing.T) string { return legacyProcNet(t, strings.Repeat(" ", maxLegacyNamesBytes+1)) }, why: "exceeds bound"},
	} {
		got := ReadLegacyIPTables(tc.dir(t))
		if tc.why != "" {
			if got.State != FactsUnreadable || !strings.Contains(got.Reason, tc.why) || len(got.Tables) != 0 {
				t.Errorf("%s: %+v, want unreadable with %q", name, got, tc.why)
			}
			if got.LegacyRefusal() == nil {
				t.Errorf("%s: an unreadable answer does not refuse", name)
			}
			continue
		}
		if got.State != tc.want.State || len(got.Tables) != len(tc.want.Tables) || (len(got.Tables) > 0 && !reflect.DeepEqual(got.Tables, tc.want.Tables)) {
			t.Errorf("%s: %+v, want %+v", name, got, tc.want)
		}
		if err := (HostNetFacts{NAT: SavedTableFacts{State: FactsNotNeeded, Reason: "x"}, Mangle: SavedTableFacts{State: FactsRead}, LegacyIPTables: got}).Validate(); err != nil {
			t.Errorf("%s: facts do not validate: %v", name, err)
		}
		if refusal := got.LegacyRefusal(); (refusal == nil) != (len(got.Tables) == 0) {
			t.Errorf("%s: refusal %v", name, refusal)
		}
	}
}

func TestHostNetFactsMustSayWhetherLegacyTablesExist(t *testing.T) {
	base := HostNetFacts{NAT: SavedTableFacts{State: FactsNotNeeded, Reason: "x"}, Mangle: SavedTableFacts{State: FactsRead}}
	for name, tc := range map[string]struct {
		legacy LegacyTablesFacts
		want   string
	}{
		"not said (a manager from before)": {LegacyTablesFacts{}, "do not say whether the node has iptables-legacy tables"},
		"unknown state":                    {LegacyTablesFacts{State: "absent"}, "unknown state"},
		"read with a reason":               {LegacyTablesFacts{State: FactsRead, Reason: "x"}, "inconsistent"},
		"unreadable without a reason":      {LegacyTablesFacts{State: FactsUnreadable}, "inconsistent"},
		"unreadable with tables":           {LegacyTablesFacts{State: FactsUnreadable, Reason: "x", Tables: []string{"nat"}}, "inconsistent"},
		"invalid table name":               {LegacyTablesFacts{State: FactsRead, Tables: []string{"a b"}}, "invalid legacy"},
		"too many tables":                  {LegacyTablesFacts{State: FactsRead, Tables: strings.Fields(strings.Repeat("t ", maxLegacyTables+1))}, "exceed bound"},
	} {
		facts := base
		facts.LegacyIPTables = tc.legacy
		if err := facts.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
	// Facts that could not be read at all say so for legacy tables too.
	if facts := UnreadableHostNetFacts("boom"); facts.Validate() != nil || facts.LegacyIPTables.State != FactsUnreadable {
		t.Fatalf("unreadable facts: %+v", facts)
	}
}

func TestHostFactsReaderPublishesLegacyTables(t *testing.T) {
	f, reader := liveCalicoFactsReader(t)
	if facts := reader.Read(t.Context()); facts.LegacyIPTables.State != FactsRead || len(facts.LegacyIPTables.Tables) != 0 || facts.NAT.State != FactsRead {
		t.Fatalf("node without legacy tables: %+v", facts)
	}
	reader.procNet = legacyProcNet(t, "nat\n")
	if facts := reader.Read(t.Context()); facts.LegacyIPTables.State != FactsRead || !reflect.DeepEqual(facts.LegacyIPTables.Tables, []string{"nat"}) || facts.Validate() != nil {
		t.Fatalf("node with a legacy nat table: %+v", facts)
	}
	// It is read whatever else fails.
	f.version = "iptables v1.8.13 (legacy)"
	if facts := reader.Read(t.Context()); facts.NAT.State != FactsUnreadable || !reflect.DeepEqual(facts.LegacyIPTables.Tables, []string{"nat"}) || facts.Validate() != nil {
		t.Fatalf("legacy save tool: %+v", facts)
	}
	reader.procNet = t.TempDir()
	if facts := reader.Read(t.Context()); facts.LegacyIPTables.State != FactsUnreadable {
		t.Fatalf("no proc net: %+v", facts)
	}
}

// The refusal comes before every proof, on every captured node, through the
// receipt and through the gateway's own read; a node without legacy tables is
// decided exactly as before.
func TestNodeWithLegacyTablesIsNotReady(t *testing.T) {
	const tunnel = "100.96.0.0/24"
	wantRefused := func(t *testing.T, name string, r *Reconciler, want string) {
		t.Helper()
		status, err := r.Reconcile(t.Context(), tunnel)
		if err == nil || !strings.Contains(err.Error(), want) || status.Host.State != StateBlocked {
			t.Errorf("%s: %+v %v, want %q", name, status, err, want)
		}
		for _, adapter := range status.Adapters {
			if adapter.State == StateReady {
				t.Errorf("%s: a refused node reports %+v", name, adapter)
			}
		}
	}
	const present = "node has iptables-legacy tables (filter, nat), whose rules no nft listing shows"

	// Through the receipt: the captured Calico node and the captured Flannel node.
	calicoFacts := liveCalicoHostFacts(t)
	flannelFacts := HostNetFacts{
		NAT:            SavedTableFacts{State: FactsNotNeeded, Reason: "the kernel has no ipset, so no NAT rule can match one"},
		Mangle:         SavedTableFacts{State: FactsRead},
		LegacyIPTables: LegacyTablesFacts{State: FactsRead},
	}
	for node, base := range map[string]HostNetFacts{"Calico": calicoFacts, "Flannel": flannelFacts} {
		gateway := func(facts HostNetFacts) *Reconciler {
			if node == "Calico" {
				_, r := gatewayOnLiveCalico(t, constantFacts(facts))
				return r
			}
			_, r := liveFlannelKernel(t)
			r.UseHostFacts(constantFacts(facts))
			return r
		}
		if status, err := gateway(base).Reconcile(t.Context(), tunnel); err != nil || status.Adapters[0].Name != ObservedAdapterName || status.Adapters[0].State != StateReady {
			t.Fatalf("%s without legacy tables: %+v %v", node, status, err)
		}
		for name, tc := range map[string]struct {
			legacy LegacyTablesFacts
			want   string
		}{
			"tables present":   {LegacyTablesFacts{State: FactsRead, Tables: []string{"filter", "nat"}}, present},
			"not readable":     {LegacyTablesFacts{State: FactsUnreadable, Reason: "read ip_tables_names: permission denied"}, "could not tell whether the node has iptables-legacy tables: read ip_tables_names: permission denied"},
			"not said at all":  {LegacyTablesFacts{}, "host-posture facts: host facts do not say whether the node has iptables-legacy tables"},
			"an unknown state": {LegacyTablesFacts{State: "absent"}, "unknown state"},
		} {
			facts := base
			facts.LegacyIPTables = tc.legacy
			wantRefused(t, node+", "+name, gateway(facts), tc.want)
		}
	}

	// Without a facts source the gateway reads ip_tables_names itself.
	for name, procNet := range map[string]string{
		"tables present":   legacyProcNet(t, "nat\nfilter\n"),
		"not a proc net":   t.TempDir(),
		"names not parsed": legacyProcNet(t, "a/b\n"),
	} {
		_, r := liveFlannelKernel(t)
		r.procNet = procNet
		want := present
		if name != "tables present" {
			want = "could not tell whether the node has iptables-legacy tables"
		}
		wantRefused(t, "direct, "+name, r, want)
	}
	for name, procNet := range map[string]string{"module not loaded": legacyProcNet(t), "no table": legacyProcNet(t, "")} {
		_, r := liveFlannelKernel(t)
		r.procNet = procNet
		if status, err := r.Reconcile(t.Context(), tunnel); err != nil || status.Adapters[0].State != StateReady {
			t.Errorf("direct, %s: %+v %v", name, status, err)
		}
	}
}

// A gateway in Kubernetes takes the receipt on every observation, also on a
// node whose rules need no fact from it: without it nothing says whether the
// node has legacy tables or whether the manager saw Cilium.
func TestGatewayTakesTheReceiptOnEveryObservation(t *testing.T) {
	_, r := liveFlannelKernel(t)
	asked := 0
	r.UseHostFacts(func(context.Context) (HostNetFacts, error) {
		asked++
		return HostNetFacts{}, errors.New("host facts receipt is missing")
	})
	if _, err := r.Reconcile(t.Context(), "100.96.0.0/24"); err == nil || err.Error() != "host-posture facts: host facts receipt is missing" || asked == 0 {
		t.Fatalf("asked %d times: %v", asked, err)
	}
}
