package ipsec

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	bgpengine "github.com/tunnexio/tunnex/apps/node/internal/bgp"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBGPUncertainHistoryStillStopsCurrentAndWithdraws(t *testing.T) {
	c, f, p, denied := bgpControllerFixture(t, true)
	*denied = true // cleanup is invoked only after verified denial.
	entries, _ := c.journal.Entries()
	e := entries[0]
	original := processStateFixture(t).BGPProcess
	original.Namespace = e.Allocation.Namespace
	original.Directory = filepath.Join("/var/lib/tunnex", "bgp-"+e.DeliveryID.String()+"-g1")
	e.BGPProcess = original
	if err := c.journal.Save([]RuntimeJournalEntry{e}); err != nil {
		t.Fatal(err)
	}
	current := *original
	current.Generation = 2
	current.Directory = filepath.Join("/var/lib/tunnex", "bgp-"+e.DeliveryID.String()+"-g2")
	current.DirectoryFile.Inode++
	retired := *original
	retired.Stage = "retired-uncertain"
	e.BGPProcess = &current
	e.BGPProcessRetired = []bgpengine.ProcessIdentity{retired}
	if err := c.journal.Save([]RuntimeJournalEntry{e}); err != nil {
		t.Fatal(err)
	}
	e.Phase = RuntimeCleanupPending
	e.CleanupID = uuid.New()
	e.CleanupDesiredRevision = e.Engines[0].Binding.DesiredRevision + 1
	e.CoveredDeliveryRevision = e.Engines[0].Binding.DesiredRevision
	if err := c.journal.Save([]RuntimeJournalEntry{e}); err != nil {
		t.Fatal(err)
	}
	if err := c.cleanupBGPDuties(context.Background(), e); err == nil {
		t.Fatal("unproved historical cleanup accepted")
	}
	saved, _ := c.journal.Entries()
	if !p.closed || f.routes[0][e.Allocation.Tunnels[0].RemotePrefixes[0].String()] || saved[0].BGPProcessRetired[0].Stage != "retired-uncertain" || saved[0].BGPRoutes.Stage != "completed" || !saved[0].BGPRoutes.Withdrawal {
		t.Fatal("uncertainty stranded current authority or forgotten")
	}
}

func TestBGPQualificationCannotBeFabricated(t *testing.T) {
	c, _, _, _ := bgpControllerFixture(t, false)
	for _, q := range []*bgpengine.PreflightQualification{nil, {}} {
		if c.AttachBGPQualification(q) == nil {
			t.Fatal("unobserved preflight accepted")
		}
	}
	if c.bgpQualification != nil || c.BGPCapability() != 0 {
		t.Fatal("unobserved support advertised")
	}
}

func TestBGPValidateMissingReceiptWithdrawsAuthority(t *testing.T) {
	for _, installed := range []bool{false, true} {
		c, f, p, denied := bgpControllerFixture(t, installed)
		entries, _ := c.journal.Entries()
		if err := c.Validate(context.Background()); err == nil {
			t.Fatal("missing actual BGP receipt accepted")
		}
		after, _ := c.journal.Entries()
		if !*denied || !p.closed || len(c.active) != 0 || f.routes[0][entries[0].Allocation.Tunnels[0].RemotePrefixes[0].String()] || !after[0].BGPRoutes.Withdrawal {
			t.Fatal("invalid BGP qualification retained authority")
		}
	}
}

func TestBGPValidateMissingReceiptPreservesStaticGrant(t *testing.T) {
	c, f, p, denied := bgpControllerFixture(t, true)
	entries, _ := c.journal.Entries()
	m := runtimeMaterialFixture()
	m.Manifest.OrgID = c.config.OrgID
	m.Manifest.NodeID = c.config.GatewayID
	m.Manifest.LocalPrefixes = []string{"10.40.0.0/24"}
	m.Manifest.RemotePrefixes = []string{"10.50.0.0/24"}
	runtimeReseal(&m)
	static, _, err := runtimeMaterialEntry(m, c.config.OrgID, c.config.GatewayID, entries[0].Allocation.Namespace)
	if err != nil {
		t.Fatal(err)
	}
	for i, tunnel := range static.Allocation.Tunnels {
		static.Observed[i] = Ownership{Namespace: static.Allocation.Namespace, InterfaceName: tunnel.Name, InterfaceIndex: 30 + i, XFRMID: tunnel.XFRMID}
	}

	// The fresh MTU proof reads both legitimate allocations, not a BGP-only
	// kernel fixture with invented static journal indices.
	sf := newRecoveryKernelFixture()
	sf.p = static.Allocation
	sf.owned = static.Observed
	for k := range sf.routes {
		sf.routes[k] = map[string]bool{}
	}
	for _, prefix := range static.Allocation.Tunnels[0].RemotePrefixes {
		sf.routes[0][prefix.String()] = true
	}
	c.kernel.run = func(ctx context.Context, args ...string) ([]byte, error) {
		raw, err := f.run(ctx, args...)
		if err != nil {
			return nil, err
		}
		q := strings.Join(args, " ")
		if strings.Contains(q, "link show") || strings.Contains(q, "addr show") || strings.Contains(q, "-4 route show") {
			other, err := sf.run(ctx, args...)
			if err != nil {
				return nil, err
			}
			var a, b []map[string]any
			if json.Unmarshal(raw, &a) != nil || json.Unmarshal(other, &b) != nil {
				return nil, ErrKernelApply
			}
			return json.Marshal(append(a, b...))
		}
		return raw, nil
	}
	for _, phase := range []RuntimePhase{RuntimeReserved, RuntimeApplying, RuntimeApplied} {
		static.Phase = phase
		if err = c.journal.Save(append(entries, static)); err != nil {
			t.Fatal(err)
		}
	}
	authority := NewPermitLeaseAuthority()
	identity := PermitLeaseIdentity{DeliveryID: static.DeliveryID, Binding: static.Engines[0].Binding, PolicyHash: m.Policy.Hash}
	request, err := authority.Begin(identity)
	if err != nil {
		t.Fatal(err)
	}
	if err = authority.Accept(PermitLeaseResponse{PermitLeaseRequest: request, TTLMillis: 60000}); err != nil {
		t.Fatal(err)
	}
	grant := GuardGrant{Source: static.Engines[0].LocalPrefixes[0], Destination: static.Engines[0].RemotePrefixes[0], Protocol: GuardTCP, PortLow: 18080, PortHigh: 18080, HostOrigin: true}
	c.active[static.Allocation.ConnectionID] = runtimeActive{Entry: static, Environment: RuntimeEnvironment{Namespace: static.Allocation.Namespace, Underlays: [2]RuntimeUnderlay{{OuterMTU: 1500}, {OuterMTU: 1500}}}, Identity: identity, Authority: authority, Grants: []GuardGrant{grant}}
	var installed GuardIntent
	c.replace = func(_ context.Context, intent GuardIntent) (GuardManifest, error) {
		installed = intent
		*denied = true
		return GuardManifest{}, nil
	}
	if c.Validate(context.Background()) == nil {
		t.Fatal("invalid BGP qualification accepted")
	}
	var staticGranted, bgpDenied bool
	for _, connection := range installed.Connections {
		if connection.ID == static.Allocation.ConnectionID {
			staticGranted = !connection.PrefixOnly && len(connection.Grants) == 1 && connection.Grants[0] == grant && len(connection.PermittedInterfaceIndices) == 1 && connection.PermittedInterfaceIndices[0] == 30 && connection.PermitFor > 0
		}
		if connection.ID == entries[0].Allocation.ConnectionID {
			bgpDenied = connection.PrefixOnly && len(connection.Grants) == 0
		}
	}
	if !staticGranted || !bgpDenied || !p.closed || f.routes[0][entries[0].Allocation.Tunnels[0].RemotePrefixes[0].String()] || len(c.active) != 1 {
		t.Fatal("BGP qualification loss affected fresh static grant or retained BGP authority")
	}
	if _, err = authority.RemainingForApply(identity, 5*time.Second); err != nil {
		t.Fatal("static lease was lost or renewed incorrectly", err)
	}
}
