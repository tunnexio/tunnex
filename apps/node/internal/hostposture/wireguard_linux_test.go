//go:build linux

package hostposture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const testStagingName = "tnx0123456789ab"

type fakeLinkCommandError string

func (e fakeLinkCommandError) Error() string { return string(e) }
func (fakeLinkCommandError) ExitCode() int   { return 1 }

type stagedLinkHarness struct {
	links          map[string]wireGuardLink
	nextIfIndex    int
	nftPresent     map[string]bool
	mutations      []string
	durablePhase   string
	mutationChecks bool
}

func newStagedLinkHarness(t *testing.T) (*LinuxKernel, *stagedLinkHarness, Journal) {
	t.Helper()
	procSys := t.TempDir()
	for _, receipt := range desiredSysctls() {
		writeSysctlFixture(t, procSys, receipt.Key, receipt.Desired)
	}
	h := &stagedLinkHarness{
		links:        map[string]wireGuardLink{},
		nextIfIndex:  77,
		nftPresent:   map[string]bool{},
		durablePhase: WireGuardPhaseStagingPlanned,
	}
	runner := runnerFunc(func(_ context.Context, name string, input []byte, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		switch {
		case name == "ip" && joined == "-j -d link show":
			rows := make([]map[string]any, 0, len(h.links))
			for _, link := range h.links {
				rows = append(rows, map[string]any{
					"ifindex": link.IfIndex,
					"ifname":  link.Name,
					"ifalias": link.Alias,
					"linkinfo": map[string]any{
						"info_kind": link.Kind,
					},
				})
			}
			body, err := json.Marshal(rows)
			return string(body), err

		case name == "ip" && strings.HasPrefix(joined, "-j -d link show dev "):
			linkName := strings.TrimPrefix(joined, "-j -d link show dev ")
			link, ok := h.links[linkName]
			if !ok {
				return "", fakeLinkCommandError("Device does not exist")
			}
			return fmt.Sprintf(`[{"ifindex":%d,"ifname":%q,"ifalias":%q,"linkinfo":{"info_kind":%q}}]`, link.IfIndex, link.Name, link.Alias, link.Kind), nil

		case name == "ip" && strings.HasPrefix(joined, "link add name "):
			fields := strings.Fields(joined)
			if len(fields) != 6 || fields[0] != "link" || fields[1] != "add" || fields[2] != "name" || fields[4] != "type" || fields[5] != "wireguard" {
				return "", fmt.Errorf("unexpected link create %q", joined)
			}
			if h.mutationChecks && h.durablePhase != WireGuardPhaseStagingPlanned {
				return "", fmt.Errorf("create ran without durable planned phase: %s", h.durablePhase)
			}
			if _, exists := h.links[fields[3]]; exists {
				return "", fmt.Errorf("link already exists")
			}
			h.links[fields[3]] = wireGuardLink{Name: fields[3], Kind: "wireguard", IfIndex: h.nextIfIndex}
			h.nextIfIndex++
			h.mutations = append(h.mutations, "create")
			return "", nil

		case name == "nft" && strings.HasPrefix(joined, "list table "):
			fields := strings.Fields(joined)
			if !h.nftPresent[fields[2]] {
				return "", fakeLinkCommandError("No such file or directory")
			}
			return "table present", nil

		case name == "nft" && joined == "-f -":
			if strings.Contains(string(input), "add table ip6 tunnex") {
				h.nftPresent["ip6"] = true
			} else if strings.Contains(string(input), "add table ip tunnex") {
				h.nftPresent["ip"] = true
			} else {
				return "", fmt.Errorf("unexpected nft input %q", input)
			}
			return "", nil

		case name == "nft" && strings.HasPrefix(joined, "-a list chain "):
			if strings.HasSuffix(joined, " tunnex_posture_owner") {
				return "chain tunnex_posture_owner {\n counter packets 0 bytes 0 comment \"tunnex_host_posture_v1\" # handle 2\n}\n", nil
			}
			return "", fakeLinkCommandError("Error: No such file or directory")

		case name == "ip" && (joined == "-4 route show" || joined == "-4 rule show pref 100" || joined == "-6 route show" || joined == "-6 rule show pref 100"):
			return "", nil

		default:
			return "", fmt.Errorf("unexpected command %s %s", name, joined)
		}
	})
	kernel, err := NewLinuxKernel(procSys, runner)
	if err != nil {
		t.Fatal(err)
	}
	kernel.setLinkAlias = func(_ context.Context, ifIndex int, alias string) error {
		if h.mutationChecks && h.durablePhase != WireGuardPhaseStagingCreated {
			return fmt.Errorf("alias ran without durable created phase: %s", h.durablePhase)
		}
		name, link, ok := h.linkByIndex(ifIndex)
		if !ok {
			return fmt.Errorf("ifindex %d absent", ifIndex)
		}
		link.Alias = alias
		h.links[name] = link
		h.mutations = append(h.mutations, fmt.Sprintf("alias:%d", ifIndex))
		return nil
	}
	kernel.renameLink = func(_ context.Context, ifIndex int, newName string) error {
		if h.mutationChecks && h.durablePhase != WireGuardPhaseStagingMarked {
			return fmt.Errorf("rename ran without durable marked phase: %s", h.durablePhase)
		}
		oldName, link, ok := h.linkByIndex(ifIndex)
		if !ok {
			return fmt.Errorf("ifindex %d absent", ifIndex)
		}
		if _, exists := h.links[newName]; exists {
			return fmt.Errorf("target link exists")
		}
		delete(h.links, oldName)
		link.Name = newName
		h.links[newName] = link
		h.mutations = append(h.mutations, fmt.Sprintf("rename:%d", ifIndex))
		return nil
	}
	kernel.deleteLink = func(_ context.Context, ifIndex int) error {
		name, _, ok := h.linkByIndex(ifIndex)
		if !ok {
			return fmt.Errorf("ifindex %d absent", ifIndex)
		}
		delete(h.links, name)
		h.mutations = append(h.mutations, fmt.Sprintf("delete:%d", ifIndex))
		return nil
	}

	receipts := desiredSysctls()
	for i := range receipts {
		receipts[i].Original = "0"
	}
	journal, err := newJournal("worker-node-a", 1, receipts, []Owner{{UID: "owner-uid", Namespace: "tunnex", Name: "gateway-a"}}, testStagingName, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	return kernel, h, journal
}

func (h *stagedLinkHarness) linkByIndex(ifIndex int) (string, wireGuardLink, bool) {
	for name, link := range h.links {
		if link.IfIndex == ifIndex {
			return name, link, true
		}
	}
	return "", wireGuardLink{}, false
}

func TestPrepareStagedWireGuardCheckpointsBeforeEveryOwnershipMutation(t *testing.T) {
	kernel, h, journal := newStagedLinkHarness(t)
	h.mutationChecks = true
	var checkpoints []string
	checkpoint := func(value *Journal) error {
		h.durablePhase = value.Artifacts.WireGuard.Phase
		checkpoints = append(checkpoints, h.durablePhase)
		return nil
	}
	if err := kernel.Prepare(t.Context(), &journal, checkpoint); err != nil {
		t.Fatal(err)
	}
	wg := journal.Artifacts.WireGuard
	if wg.Phase != WireGuardPhaseCommitted || wg.IfIndex != 77 || wg.StagingIfIndex != 77 {
		t.Fatalf("final receipt=%+v", wg)
	}
	if got := strings.Join(checkpoints, ","); got != "staging_created,staging_marked,committed" {
		t.Fatalf("checkpoints=%s", got)
	}
	if got := strings.Join(h.mutations, ","); got != "create,alias:77,rename:77" {
		t.Fatalf("mutations=%s", got)
	}
	if _, ok := h.links[testStagingName]; ok {
		t.Fatal("staging link remained after publication")
	}
	if final := h.links[DefaultWireGuardIface]; !exactWireGuardLink(final, DefaultWireGuardIface, WireGuardAlias, 77) {
		t.Fatalf("final link=%+v", final)
	}
}

func TestPrepareStagedWireGuardResumesEveryCrashCut(t *testing.T) {
	tests := []struct {
		name          string
		phase         string
		stagingIndex  int
		finalIndex    int
		liveName      string
		liveAlias     string
		wantMutations string
	}{
		{name: "planned before create", phase: WireGuardPhaseStagingPlanned, wantMutations: "create,alias:77,rename:77"},
		{name: "planned after create before checkpoint", phase: WireGuardPhaseStagingPlanned, liveName: testStagingName, wantMutations: "alias:77,rename:77"},
		{name: "created before alias", phase: WireGuardPhaseStagingCreated, stagingIndex: 77, liveName: testStagingName, wantMutations: "alias:77,rename:77"},
		{name: "created after alias before checkpoint", phase: WireGuardPhaseStagingCreated, stagingIndex: 77, liveName: testStagingName, liveAlias: WireGuardAlias, wantMutations: "rename:77"},
		{name: "marked before rename", phase: WireGuardPhaseStagingMarked, stagingIndex: 77, liveName: testStagingName, liveAlias: WireGuardAlias, wantMutations: "rename:77"},
		{name: "marked after rename before checkpoint", phase: WireGuardPhaseStagingMarked, stagingIndex: 77, liveName: DefaultWireGuardIface, liveAlias: WireGuardAlias},
		{name: "final readback", phase: WireGuardPhaseCommitted, stagingIndex: 77, finalIndex: 77, liveName: DefaultWireGuardIface, liveAlias: WireGuardAlias},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kernel, h, journal := newStagedLinkHarness(t)
			journal.Artifacts.WireGuard.Phase = tt.phase
			journal.Artifacts.WireGuard.StagingIfIndex = tt.stagingIndex
			journal.Artifacts.WireGuard.IfIndex = tt.finalIndex
			if tt.liveName != "" {
				h.links[tt.liveName] = wireGuardLink{Name: tt.liveName, Alias: tt.liveAlias, Kind: "wireguard", IfIndex: 77}
			}
			if err := kernel.Prepare(t.Context(), &journal, func(*Journal) error { return nil }); err != nil {
				t.Fatal(err)
			}
			if journal.Artifacts.WireGuard.Phase != WireGuardPhaseCommitted || journal.Artifacts.WireGuard.IfIndex != 77 {
				t.Fatalf("recovered receipt=%+v", journal.Artifacts.WireGuard)
			}
			if got := strings.Join(h.mutations, ","); got != tt.wantMutations {
				t.Fatalf("mutations=%q want=%q", got, tt.wantMutations)
			}
		})
	}
}

func TestPrepareStagedWireGuardRefusesForeignOrAmbiguousLinks(t *testing.T) {
	tests := []struct {
		name  string
		phase string
		setup func(*stagedLinkHarness, *Journal)
	}{
		{name: "alias empty final is never adopted", phase: WireGuardPhaseStagingPlanned, setup: func(h *stagedLinkHarness, _ *Journal) {
			h.links[DefaultWireGuardIface] = wireGuardLink{Name: DefaultWireGuardIface, Kind: "wireguard", IfIndex: 91}
		}},
		{name: "even exact final predating marked phase is foreign", phase: WireGuardPhaseStagingPlanned, setup: func(h *stagedLinkHarness, _ *Journal) {
			h.links[DefaultWireGuardIface] = wireGuardLink{Name: DefaultWireGuardIface, Alias: WireGuardAlias, Kind: "wireguard", IfIndex: 91}
		}},
		{name: "foreign staging alias", phase: WireGuardPhaseStagingPlanned, setup: func(h *stagedLinkHarness, _ *Journal) {
			h.links[testStagingName] = wireGuardLink{Name: testStagingName, Alias: "foreign", Kind: "wireguard", IfIndex: 77}
		}},
		{name: "created ifindex mismatch", phase: WireGuardPhaseStagingCreated, setup: func(h *stagedLinkHarness, journal *Journal) {
			journal.Artifacts.WireGuard.StagingIfIndex = 77
			h.links[testStagingName] = wireGuardLink{Name: testStagingName, Kind: "wireguard", IfIndex: 78}
		}},
		{name: "marked alias empty final", phase: WireGuardPhaseStagingMarked, setup: func(h *stagedLinkHarness, journal *Journal) {
			journal.Artifacts.WireGuard.StagingIfIndex = 77
			h.links[DefaultWireGuardIface] = wireGuardLink{Name: DefaultWireGuardIface, Kind: "wireguard", IfIndex: 77}
		}},
		{name: "final and staging coexist", phase: WireGuardPhaseCommitted, setup: func(h *stagedLinkHarness, journal *Journal) {
			journal.Artifacts.WireGuard.StagingIfIndex = 77
			journal.Artifacts.WireGuard.IfIndex = 77
			h.links[DefaultWireGuardIface] = wireGuardLink{Name: DefaultWireGuardIface, Alias: WireGuardAlias, Kind: "wireguard", IfIndex: 77}
			h.links[testStagingName] = wireGuardLink{Name: testStagingName, Alias: WireGuardAlias, Kind: "wireguard", IfIndex: 78}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kernel, h, journal := newStagedLinkHarness(t)
			journal.Artifacts.WireGuard.Phase = tt.phase
			tt.setup(h, &journal)
			err := kernel.Prepare(t.Context(), &journal, func(*Journal) error { return nil })
			if err == nil {
				t.Fatal("ambiguous link was accepted")
			}
			if len(h.mutations) != 0 {
				t.Fatalf("ambiguous link caused mutation: %v", h.mutations)
			}
		})
	}
}

func TestPrepareRefusesAnyUnjournaledTunnexOwnershipCandidateBeforeMutation(t *testing.T) {
	tests := []wireGuardLink{
		{Name: "tnxabcdef012345", Kind: "wireguard", IfIndex: 88},
		{Name: "foreign0", Alias: WireGuardAlias, Kind: "wireguard", IfIndex: 89},
	}
	for _, candidate := range tests {
		t.Run(candidate.Name, func(t *testing.T) {
			kernel, h, journal := newStagedLinkHarness(t)
			h.links[candidate.Name] = candidate
			err := kernel.Prepare(t.Context(), &journal, func(*Journal) error { return nil })
			if err == nil || !strings.Contains(err.Error(), "WireGuard ownership candidate") {
				t.Fatalf("candidate error=%v", err)
			}
			if len(h.mutations) != 0 {
				t.Fatalf("candidate caused prepare mutation: %v", h.mutations)
			}
		})
	}
}

func TestPrepareRejectsSchemaV1PreparingJournalWithoutMutation(t *testing.T) {
	kernel, h, journal := newStagedLinkHarness(t)
	journal.SchemaVersion = LegacyJournalSchemaVersion
	journal.Artifacts.WireGuard.StagingName = ""
	journal.Artifacts.WireGuard.Phase = ""
	h.links[DefaultWireGuardIface] = wireGuardLink{Name: DefaultWireGuardIface, Alias: WireGuardAlias, Kind: "wireguard", IfIndex: 77}
	if err := kernel.Prepare(t.Context(), &journal, func(*Journal) error { return nil }); err == nil || !strings.Contains(err.Error(), "schema-v1") {
		t.Fatalf("schema-v1 preparing error=%v", err)
	}
	if len(h.mutations) != 0 {
		t.Fatalf("schema-v1 refusal mutated links: %v", h.mutations)
	}
}

func TestPrepareSchemaV1ActiveOnlyValidatesExactFinalLink(t *testing.T) {
	kernel, h, journal := newStagedLinkHarness(t)
	journal.SchemaVersion = LegacyJournalSchemaVersion
	journal.State = StateActive
	journal.Artifacts.WireGuard.StagingName = ""
	journal.Artifacts.WireGuard.Phase = ""
	journal.Artifacts.WireGuard.StagingIfIndex = 0
	journal.Artifacts.WireGuard.IfIndex = 77
	h.links[DefaultWireGuardIface] = wireGuardLink{Name: DefaultWireGuardIface, Alias: WireGuardAlias, Kind: "wireguard", IfIndex: 77}
	if err := kernel.Prepare(t.Context(), &journal, func(*Journal) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(h.mutations) != 0 {
		t.Fatalf("schema-v1 active validation mutated links: %v", h.mutations)
	}
	h.links[DefaultWireGuardIface] = wireGuardLink{Name: DefaultWireGuardIface, Kind: "wireguard", IfIndex: 77}
	if err := kernel.Prepare(t.Context(), &journal, func(*Journal) error { return nil }); err == nil {
		t.Fatal("schema-v1 active alias-empty link was accepted")
	}
}

func TestCaptureBaselineRejectsAnyOrphanStagingPattern(t *testing.T) {
	kernel, h, _ := newStagedLinkHarness(t)
	if _, err := kernel.CaptureBaseline(t.Context(), testStagingName); err != nil {
		t.Fatalf("clean baseline: %v", err)
	}
	orphanName := "tnxabcdef012345"
	h.links[orphanName] = wireGuardLink{Name: orphanName, Kind: "wireguard", IfIndex: 88}
	if _, err := kernel.CaptureBaseline(t.Context(), testStagingName); err == nil || !strings.Contains(err.Error(), orphanName) {
		t.Fatalf("orphan staging baseline error=%v", err)
	}
}

func TestCaptureBaselineRejectsTunnexAliasUnderAnotherName(t *testing.T) {
	kernel, h, _ := newStagedLinkHarness(t)
	h.links["foreign0"] = wireGuardLink{Name: "foreign0", Alias: WireGuardAlias, Kind: "wireguard", IfIndex: 89}
	if _, err := kernel.CaptureBaseline(t.Context(), testStagingName); err == nil || !strings.Contains(err.Error(), "foreign0") {
		t.Fatalf("foreign alias baseline error=%v", err)
	}
}

func TestRestoreStagedWireGuardCleansEveryExactCrashCut(t *testing.T) {
	tests := []struct {
		name         string
		phase        string
		stagingIndex int
		finalIndex   int
		liveName     string
		liveAlias    string
		wantDelete   bool
	}{
		{name: "planned before create", phase: WireGuardPhaseStagingPlanned},
		{name: "planned after create", phase: WireGuardPhaseStagingPlanned, liveName: testStagingName, wantDelete: true},
		{name: "created before alias", phase: WireGuardPhaseStagingCreated, stagingIndex: 77, liveName: testStagingName, wantDelete: true},
		{name: "created after alias", phase: WireGuardPhaseStagingCreated, stagingIndex: 77, liveName: testStagingName, liveAlias: WireGuardAlias, wantDelete: true},
		{name: "marked before rename", phase: WireGuardPhaseStagingMarked, stagingIndex: 77, liveName: testStagingName, liveAlias: WireGuardAlias, wantDelete: true},
		{name: "marked after rename", phase: WireGuardPhaseStagingMarked, stagingIndex: 77, liveName: DefaultWireGuardIface, liveAlias: WireGuardAlias, wantDelete: true},
		{name: "committed", phase: WireGuardPhaseCommitted, stagingIndex: 77, finalIndex: 77, liveName: DefaultWireGuardIface, liveAlias: WireGuardAlias, wantDelete: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kernel, h, journal := newStagedLinkHarness(t)
			journal.Owners = nil
			journal.Artifacts.WireGuard.Phase = tt.phase
			journal.Artifacts.WireGuard.StagingIfIndex = tt.stagingIndex
			journal.Artifacts.WireGuard.IfIndex = tt.finalIndex
			if tt.liveName != "" {
				h.links[tt.liveName] = wireGuardLink{Name: tt.liveName, Alias: tt.liveAlias, Kind: "wireguard", IfIndex: 77}
			}
			if err := kernel.RestoreAndCleanup(t.Context(), &journal); err != nil {
				t.Fatal(err)
			}
			if len(h.links) != 0 {
				t.Fatalf("links remain after cleanup: %+v", h.links)
			}
			deleted := len(h.mutations) == 1 && h.mutations[0] == "delete:77"
			if deleted != tt.wantDelete {
				t.Fatalf("mutations=%v wantDelete=%v", h.mutations, tt.wantDelete)
			}
		})
	}
}

func TestRestoreStagedWireGuardRefusesAliasEmptyFinal(t *testing.T) {
	kernel, h, journal := newStagedLinkHarness(t)
	journal.Owners = nil
	journal.Artifacts.WireGuard.Phase = WireGuardPhaseStagingMarked
	journal.Artifacts.WireGuard.StagingIfIndex = 77
	h.links[DefaultWireGuardIface] = wireGuardLink{Name: DefaultWireGuardIface, Kind: "wireguard", IfIndex: 77}
	if err := kernel.RestoreAndCleanup(t.Context(), &journal); err == nil {
		t.Fatal("alias-empty final link was deleted")
	}
	if len(h.mutations) != 0 {
		t.Fatalf("ambiguous cleanup mutated link: %v", h.mutations)
	}
}

func TestRestoreRefusesAnyUnjournaledTunnexOwnershipCandidateBeforeMutation(t *testing.T) {
	tests := []wireGuardLink{
		{Name: "tnxabcdef012345", Kind: "wireguard", IfIndex: 88},
		{Name: "foreign0", Alias: WireGuardAlias, Kind: "wireguard", IfIndex: 89},
	}
	for _, candidate := range tests {
		t.Run(candidate.Name, func(t *testing.T) {
			kernel, h, journal := newStagedLinkHarness(t)
			journal.Owners = nil
			journal.Artifacts.WireGuard.Phase = WireGuardPhaseCommitted
			journal.Artifacts.WireGuard.StagingIfIndex = 77
			journal.Artifacts.WireGuard.IfIndex = 77
			h.links[DefaultWireGuardIface] = wireGuardLink{Name: DefaultWireGuardIface, Alias: WireGuardAlias, Kind: "wireguard", IfIndex: 77}
			h.links[candidate.Name] = candidate
			err := kernel.RestoreAndCleanup(t.Context(), &journal)
			if err == nil || !strings.Contains(err.Error(), "WireGuard ownership candidate") {
				t.Fatalf("candidate cleanup error=%v", err)
			}
			if len(h.mutations) != 0 {
				t.Fatalf("candidate caused cleanup mutation: %v", h.mutations)
			}
			if len(h.links) != 2 {
				t.Fatalf("candidate refusal changed links: %+v", h.links)
			}
		})
	}
}

func TestRestoreSchemaV1PreparingWithoutRecordedIfIndexAlwaysRefuses(t *testing.T) {
	for _, alias := range []string{WireGuardAlias, ""} {
		t.Run(fmt.Sprintf("alias_%q", alias), func(t *testing.T) {
			kernel, h, journal := newStagedLinkHarness(t)
			journal.SchemaVersion = LegacyJournalSchemaVersion
			journal.Owners = nil
			journal.Artifacts.WireGuard.StagingName = ""
			journal.Artifacts.WireGuard.StagingIfIndex = 0
			journal.Artifacts.WireGuard.Phase = ""
			journal.Artifacts.WireGuard.IfIndex = 0
			h.links[DefaultWireGuardIface] = wireGuardLink{Name: DefaultWireGuardIface, Alias: alias, Kind: "wireguard", IfIndex: 77}
			if err := kernel.RestoreAndCleanup(t.Context(), &journal); err == nil {
				t.Fatal("schema-v1 preparing link without persisted ifindex was deleted")
			}
			if len(h.mutations) != 0 {
				t.Fatalf("schema-v1 refusal mutated link: %v", h.mutations)
			}
		})
	}
}

func TestRestoreSchemaV1WithRecordedIfIndexDeletesOnlyExactFinal(t *testing.T) {
	kernel, h, journal := newStagedLinkHarness(t)
	journal.SchemaVersion = LegacyJournalSchemaVersion
	journal.State = StateActive
	journal.Owners = nil
	journal.Artifacts.WireGuard.StagingName = ""
	journal.Artifacts.WireGuard.StagingIfIndex = 0
	journal.Artifacts.WireGuard.Phase = ""
	journal.Artifacts.WireGuard.IfIndex = 77
	h.links[DefaultWireGuardIface] = wireGuardLink{Name: DefaultWireGuardIface, Alias: WireGuardAlias, Kind: "wireguard", IfIndex: 77}
	if err := kernel.RestoreAndCleanup(t.Context(), &journal); err != nil {
		t.Fatal(err)
	}
	if len(h.links) != 0 || strings.Join(h.mutations, ",") != "delete:77" {
		t.Fatalf("legacy exact cleanup links=%v mutations=%v", h.links, h.mutations)
	}
}

func TestCheckpointFailureLeavesCrashRecoverableDurablePhase(t *testing.T) {
	tests := []struct {
		name      string
		failPhase string
		wantPhase string
		wantName  string
		wantAlias string
	}{
		{name: "after create", failPhase: WireGuardPhaseStagingCreated, wantPhase: WireGuardPhaseStagingPlanned, wantName: testStagingName},
		{name: "after alias", failPhase: WireGuardPhaseStagingMarked, wantPhase: WireGuardPhaseStagingCreated, wantName: testStagingName, wantAlias: WireGuardAlias},
		{name: "after rename", failPhase: WireGuardPhaseCommitted, wantPhase: WireGuardPhaseStagingMarked, wantName: DefaultWireGuardIface, wantAlias: WireGuardAlias},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kernel, h, journal := newStagedLinkHarness(t)
			persisted := journal
			errCrash := errors.New("simulated durable write crash")
			err := kernel.Prepare(t.Context(), &journal, func(current *Journal) error {
				if current.Artifacts.WireGuard.Phase == tt.failPhase {
					return errCrash
				}
				persisted = *current
				return nil
			})
			if !errors.Is(err, errCrash) {
				t.Fatalf("prepare error=%v", err)
			}
			if persisted.Artifacts.WireGuard.Phase != tt.wantPhase {
				t.Fatalf("durable phase=%s want=%s", persisted.Artifacts.WireGuard.Phase, tt.wantPhase)
			}
			link := h.links[tt.wantName]
			if link.Alias != tt.wantAlias {
				t.Fatalf("live link=%+v want alias=%q", link, tt.wantAlias)
			}
			if err := kernel.Prepare(t.Context(), &persisted, func(*Journal) error { return nil }); err != nil {
				t.Fatalf("resume after crash: %v", err)
			}
			if persisted.Artifacts.WireGuard.Phase != WireGuardPhaseCommitted {
				t.Fatalf("resume receipt=%+v", persisted.Artifacts.WireGuard)
			}
		})
	}
}
