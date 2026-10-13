package ipsec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"sort"
	"strings"
	"testing"
	"time"
)

// Configuration comes from the real stage material constructor with a mock
// transport. Neither credential material nor a daemon mutation escapes it.
func azureSchedulerMessages(engines []EngineTunnel) ([]viciMessage, error) {
	out := []viciMessage{}
	for _, engine := range engines {
		if !IsAzureRuntimeProfile(engine.ProfileID) || !validEngineTunnel(engine) {
			return nil, ErrDaemonProtocol
		}
		var connection viciMessage
		mock := &DaemonClient{request: func(_ context.Context, command, _ string, message viciMessage) (viciMessage, []viciMessage, error) {
			switch command {
			case "get-conns":
				return viciMessage{"conns": viciList()}, nil, nil
			case "get-shared":
				return viciMessage{"keys": viciList()}, nil, nil
			case "load-shared":
				return viciMessage{"success": viciText("yes")}, nil, nil
			case "load-conn":
				connection = message
				return viciMessage{"success": viciText("yes")}, nil, nil
			default:
				return nil, nil, ErrDaemonProtocol
			}
		}}
		if mock.stageTunnel(context.Background(), engine, []byte("mock-only-unused")) != nil {
			return nil, ErrDaemonProtocol
		}
		out = append(out, connection)
	}
	return out, nil
}
func azureSchedulerConfig(engines []EngineTunnel) (string, error) {
	messages, err := azureSchedulerMessages(engines)
	if err != nil {
		return "", err
	}
	out := "connections {\n"
	for _, message := range messages {
		text, err := azureSchedulerSection(message, "  ")
		if err != nil {
			return "", err
		}
		out += text
	}
	return out + "}\n", nil
}
func azureSchedulerSection(message viciMessage, indent string) (string, error) {
	keys := make([]string, 0, len(message))
	for key := range message {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out strings.Builder
	for _, key := range keys {
		value := message[key]
		switch value.kind {
		case 1:
			nested, e := azureSchedulerSection(value.section, indent+"  ")
			if e != nil {
				return "", e
			}
			fmt.Fprintf(&out, "%s%s {\n%s%s}\n", indent, key, nested, indent)
		case 3:
			text := string(value.scalar)
			if strings.ContainsAny(text, "\n\r{}#\"\\") {
				return "", ErrDaemonProtocol
			}
			fmt.Fprintf(&out, "%s%s = %s\n", indent, key, text)
		case 4:
			values := []string{}
			for _, item := range value.list {
				text := string(item)
				if strings.ContainsAny(text, "\n\r{}#\"\\,") {
					return "", ErrDaemonProtocol
				}
				values = append(values, text)
			}
			fmt.Fprintf(&out, "%s%s = %s\n", indent, key, strings.Join(values, ", "))
		default:
			return "", ErrDaemonProtocol
		}
	}
	return out.String(), nil
}

func TestAzureSchedulerUsesProviderMaterial(t *testing.T) {
	entry, _, _, _ := runtimeProofFixture()
	for _, profile := range []string{AzureActiveActiveBGPProfile, AzureActiveActiveStaticProfile, AzureActiveStandbyBGPProfile, AzureActiveStandbyStaticProfile} {
		t.Run(profile, func(t *testing.T) {
			count := 2
			if IsSingleTunnelProfile(profile) {
				count = 1
			}
			engines := append([]EngineTunnel(nil), entry.Engines[:count]...)
			for i := range engines {
				engines[i].ProfileID = profile
			}
			config, e := azureSchedulerConfig(engines)
			if e != nil || strings.Count(config, "local_ts = 0.0.0.0/0") != count || strings.Count(config, "remote_ts = 0.0.0.0/0") != count || strings.Count(config, "rekey_time = 28800s") != count || strings.Count(config, "life_time = 3600s") != count || strings.Contains(config, "mock-only") {
				t.Fatal("provider material drift")
			}
		})
	}
}

// Validate every obligation first; select by the fresh normal API identity,
// never by journal position. Retained entries remain part of combined denial.
type azureSchedulerBinding struct {
	OrgID, GatewayID, ConnectionID, SiteID uuid.UUID
	DesiredRevision, ConfigurationRevision int64
	ProfileID                              string
}

func azureSchedulerContract(entry RuntimeJournalEntry) bool {
	if IsAzureBGPProfile(entry.Allocation.ProfileID) {
		return entry.ContractVersion == 3
	}
	if entry.Allocation.ProfileID == AzureActiveStandbyStaticProfile {
		return entry.ContractVersion == 4
	}
	return entry.Allocation.ProfileID == AzureActiveActiveStaticProfile && entry.ContractVersion == 2
}
func azureSchedulerEntry(payload runtimeJournalPayload, expected azureSchedulerBinding) (RuntimeJournalEntry, string, error) {
	if !validJournalPayload(payload) || payload.OwnerID != expected.GatewayID || len(payload.Guards) == 0 || !IsAzureRuntimeProfile(expected.ProfileID) || expected.OrgID == uuid.Nil || expected.ConnectionID == uuid.Nil || expected.SiteID == uuid.Nil || expected.DesiredRevision <= 0 || expected.ConfigurationRevision <= 0 {
		return RuntimeJournalEntry{}, "", ErrRuntimeJournal
	}
	selected := RuntimeJournalEntry{}
	count := 0
	retained := []RuntimeJournalEntry{}
	for _, entry := range payload.Entries {
		binding := entry.Engines[0].Binding
		if binding.OrgID != expected.OrgID || binding.GatewayID != expected.GatewayID || entry.SiteID != expected.SiteID {
			return RuntimeJournalEntry{}, "", ErrRuntimeJournal
		}
		if entry.Phase == RuntimeRetainedRefusal {
			if binding.ConnectionID == expected.ConnectionID && entry.CleanupDesiredRevision >= expected.DesiredRevision {
				return RuntimeJournalEntry{}, "", ErrRuntimeJournal
			}
			retained = append(retained, entry)
			continue
		}
		if entry.Phase != RuntimeApplied || binding.ConnectionID != expected.ConnectionID || binding.DesiredRevision != expected.DesiredRevision || binding.ConfigurationRevision != expected.ConfigurationRevision || entry.Allocation.ProfileID != expected.ProfileID || !azureSchedulerContract(entry) {
			return RuntimeJournalEntry{}, "", ErrRuntimeJournal
		}
		selected = entry
		count++
	}
	if count != 1 {
		return RuntimeJournalEntry{}, "", ErrRuntimeJournal
	}
	sort.Slice(retained, func(i, j int) bool { return retained[i].DeliveryID.String() < retained[j].DeliveryID.String() })
	raw, err := json.Marshal(retained)
	if err != nil {
		return RuntimeJournalEntry{}, "", err
	}
	digest := sha256.Sum256(raw)
	return selected, fmt.Sprintf("%x", digest), nil
}

func azureSchedulerCombinedGuard(guards []runtimeGuardTemplate, ns string, check func(runtimeGuardTemplate) bool) error {
	matches := 0
	for _, guard := range guards {
		if guard.Namespace == ns && check(guard) {
			matches++
		}
	}
	if matches != 1 {
		return ErrRuntimeJournal
	}
	return nil
}
func azureSchedulerHistoryFixture(t *testing.T, profile string) (runtimeJournalPayload, azureSchedulerBinding) {
	t.Helper()
	m := azureMaterialFixture(profile)
	if profile == AzureActiveActiveStaticProfile {
		version := 1
		m.Manifest.RecoveryVersion = &version
	}
	m.DesiredRevision = 42
	m.Manifest.DesiredRevision = 42
	runtimeReseal(&m)
	active, _, err := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, "net:[4026531992]")
	if err != nil {
		t.Fatal(err)
	}
	active.Phase = RuntimeApplied
	p := runtimeJournalPayload{Version: 10, OwnerID: m.Manifest.NodeID, Sequence: 42, Entries: []RuntimeJournalEntry{active}, Guards: []runtimeGuardTemplate{{Namespace: active.Allocation.Namespace, Revision: 42, Digest: strings.Repeat("a", 64), ExpectedJSON: guardExpectedFixture}}}
	for i := 0; i < 19; i++ {
		old := azureMaterialFixture(profile)
		if profile == AzureActiveActiveStaticProfile {
			version := 1
			old.Manifest.RecoveryVersion = &version
		}
		old.Manifest.OrgID = m.Manifest.OrgID
		old.Manifest.NodeID = m.Manifest.NodeID
		old.Manifest.SiteID = m.Manifest.SiteID
		old.Manifest.ConnectionID = m.Manifest.ConnectionID
		old.DesiredRevision = int64(i + 1)
		old.Manifest.DesiredRevision = old.DesiredRevision
		runtimeReseal(&old)
		entry, _, err := runtimeMaterialEntry(old, m.Manifest.OrgID, m.Manifest.NodeID, active.Allocation.Namespace)
		if err != nil {
			t.Fatal(err)
		}
		entry.Phase = RuntimeRetainedRefusal
		entry.CleanupID = uuid.New()
		entry.CleanupDesiredRevision = old.DesiredRevision + 1
		entry.CoveredDeliveryRevision = old.DesiredRevision
		p.Entries = append(p.Entries, entry)
	}
	expected := azureSchedulerBinding{OrgID: m.Manifest.OrgID, GatewayID: m.Manifest.NodeID, ConnectionID: m.Manifest.ConnectionID, SiteID: m.Manifest.SiteID, DesiredRevision: 42, ConfigurationRevision: m.Manifest.ConfigurationRevision, ProfileID: profile}
	if !validJournalPayload(p) {
		t.Fatal("invalid genuine history fixture")
	}
	return p, expected
}
func TestAzureSchedulerSelectsCurrentWithNineteenRetainedObligations(t *testing.T) {
	for _, profile := range []string{AzureActiveActiveBGPProfile, AzureActiveActiveStaticProfile, AzureActiveStandbyBGPProfile, AzureActiveStandbyStaticProfile} {
		t.Run(profile, func(t *testing.T) {
			p, expected := azureSchedulerHistoryFixture(t, profile)
			// Current entry deliberately last; no positional authority assumption.
			p.Entries = append(p.Entries[1:], p.Entries[0])
			entry, digest, err := azureSchedulerEntry(p, expected)
			if err != nil || entry.Engines[0].Binding.DesiredRevision != 42 || !validDigest(digest) {
				t.Fatal("current binding refused")
			}
			p.Sequence++
			_, after, err := azureSchedulerEntry(p, expected)
			if err != nil || after != digest {
				t.Fatal("normal journal sequence refresh changed history identity")
			}
		})
	}
}
func TestAzureSchedulerRefusesCorruptOrUnrelatedHistory(t *testing.T) {
	for name, mutate := range map[string]func(*runtimeJournalPayload){
		"corrupt retained cleanup": func(p *runtimeJournalPayload) { p.Entries[1].CleanupID = uuid.Nil },
		"foreign retained org": func(p *runtimeJournalPayload) {
			for i := range p.Entries[1].Engines {
				p.Entries[1].Engines[i].Binding.OrgID = uuid.New()
			}
		},
		"foreign retained site": func(p *runtimeJournalPayload) { p.Entries[1].SiteID = uuid.New() },
		"pending obligation":    func(p *runtimeJournalPayload) { p.Entries[1].Phase = RuntimeCleanupPending },
		"duplicate active": func(p *runtimeJournalPayload) {
			duplicate := p.Entries[0]
			duplicate.DeliveryID = uuid.New()
			p.Entries = append(p.Entries, duplicate)
		},
		"stale cleanup covers current": func(p *runtimeJournalPayload) { p.Entries[1].CleanupDesiredRevision = 42 },
		"corrupt guard":                func(p *runtimeJournalPayload) { p.Guards[0].ExpectedJSON = "{}" },
	} {
		t.Run(name, func(t *testing.T) {
			p, expected := azureSchedulerHistoryFixture(t, AzureActiveStandbyStaticProfile)
			mutate(&p)
			if _, _, err := azureSchedulerEntry(p, expected); err == nil {
				t.Fatal("unsafe history accepted")
			}
		})
	}
}
func TestAzureSchedulerCombinedGuardRequiresOneFullReadback(t *testing.T) {
	p, _ := azureSchedulerHistoryFixture(t, AzureActiveActiveBGPProfile)
	p.Guards = append(p.Guards, p.Guards[0])
	p.Guards[1].Revision++
	if azureSchedulerCombinedGuard(p.Guards, p.Guards[0].Namespace, func(g runtimeGuardTemplate) bool { return g.Revision == 42 }) != nil {
		t.Fatal("exact current combined guard refused")
	}
	for _, matches := range []bool{false, true} {
		if azureSchedulerCombinedGuard(p.Guards, p.Guards[0].Namespace, func(runtimeGuardTemplate) bool { return matches }) == nil {
			t.Fatal("zero or ambiguous full readback accepted")
		}
	}
}

// This selects only a read-only proof; it never constructs a controller or permit.
func azureSchedulerNativeProof(ctx context.Context, e RuntimeJournalEntry, d DaemonInventory, k KernelInventory, x XFRMInventory, routes *KernelApplier) error {
	if !IsAzureBGPProfile(e.Allocation.ProfileID) {
		return runtimeInventoryMatches(e, d, k, x)
	}
	if e.ContractVersion != 3 || !validJournalBGP(e) || !validBGPRoutes(e) || e.BGPRoutes == nil || e.BGPRoutes.Stage != "completed" || routes == nil || k.Namespace != e.Allocation.Namespace || x.Namespace != e.Allocation.Namespace {
		return ErrKernelApply
	}
	count := e.Allocation.activeTunnelCount()
	if len(d.Connections) != count || len(d.SAs) != count || len(d.SharedKeys) != count {
		return ErrKernelApply
	}
	for i, t := range e.Engines[:count] {
		if runtimeTunnelStatus(t, e.Observed[i], d, k, x) != "up" {
			return ErrKernelApply
		}
		_, child, retired, err := ownedRuntimeChildren(t, d)
		if err != nil {
			return ErrKernelApply
		}
		in, out, err := ownedRuntimeSPIStates(t, child, retired, x)
		if err != nil || in != 1 || out != 1 {
			return ErrKernelApply
		}
	}
	return routes.verifyBGPRoutes(ctx, e.Allocation, e.Observed, bgpRouteUnion(e.BGPRoutes), true)
}

// The host request uses CLOCK_MONOTONIC, shared across these owned namespaces.
// Never grant more than the original 30s native maximum or 420s attempt ceiling.
func azureSchedulerControlBudget(now, ceiling int64) (time.Duration, error) {
	if now <= 0 || ceiling <= now || ceiling-now > int64(420*time.Second) {
		return 0, ErrDaemonProtocol
	}
	return min(time.Duration(ceiling-now), 30*time.Second), nil
}
func azureSchedulerJournalStage(readErr, contextErr error, sameFile bool, before, after []byte) string {
	if readErr != nil {
		return "journal-reread"
	}
	if contextErr != nil {
		return "journal-context"
	}
	if !sameFile {
		return "journal-identity"
	}
	if !bytes.Equal(before, after) {
		return "journal-bytes"
	}
	return ""
}
func TestAzureSchedulerControlBudgetAndJournalStages(t *testing.T) {
	now := int64(time.Hour)
	for _, tc := range []struct {
		delta   time.Duration
		want    time.Duration
		refused bool
	}{
		{420 * time.Second, 30 * time.Second, false}, {10 * time.Second, 10 * time.Second, false},
		{0, 0, true}, {-time.Second, 0, true}, {421 * time.Second, 0, true},
	} {
		got, e := azureSchedulerControlBudget(now, now+int64(tc.delta))
		if (e != nil) != tc.refused || got != tc.want {
			t.Fatal("ceiling classification changed")
		}
	}
	if _, e := azureSchedulerControlBudget(0, int64(time.Second)); e == nil {
		t.Fatal("invalid clock accepted")
	}
	for _, tc := range []struct {
		read, ctx error
		same      bool
		after     []byte
		want      string
	}{
		{ErrDaemonProtocol, context.Canceled, false, nil, "journal-reread"},
		{nil, context.DeadlineExceeded, false, nil, "journal-context"},
		{nil, nil, false, nil, "journal-identity"},
		{nil, nil, true, []byte("changed"), "journal-bytes"},
		{nil, nil, true, []byte("original"), ""},
	} {
		if got := azureSchedulerJournalStage(tc.read, tc.ctx, tc.same, []byte("original"), tc.after); got != tc.want {
			t.Fatal("journal refusal order changed")
		}
	}
}

func azureSchedulerClockBinding(expected, actual, offsets string) bool {
	if _, err := uuid.Parse(expected); err != nil || expected != actual {
		return false
	}
	lines := strings.Split(strings.TrimSpace(offsets), "\n")
	if len(lines) != 2 {
		return false
	}
	seen := map[string]bool{}
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) != 3 || (f[0] != "monotonic" && f[0] != "boottime") || seen[f[0]] || f[1] != "0" || f[2] != "0" {
			return false
		}
		seen[f[0]] = true
	}
	return true
}
func TestAzureSchedulerClockBinding(t *testing.T) {
	boot := "66142c80-1111-4111-8111-111111111111"
	offsets := "monotonic 0 0\nboottime 0 0\n"
	if !azureSchedulerClockBinding(boot, boot, offsets) {
		t.Fatal("same boot zero offsets refused")
	}
	for _, bad := range []string{"", "monotonic 1 0\nboottime 0 0", "monotonic 0 1\nboottime 0 0", "monotonic 0 0\nmonotonic 0 0"} {
		if azureSchedulerClockBinding(boot, boot, bad) {
			t.Fatal("unbound clock accepted")
		}
	}
	if azureSchedulerClockBinding(boot, uuid.NewString(), offsets) || azureSchedulerClockBinding("invalid", "invalid", offsets) {
		t.Fatal("different boot accepted")
	}
}

func azureSchedulerRequestBudget(now, ceiling int64, action string, preflight bool) (time.Duration, error) {
	if preflight && (action != "verify" || ceiling <= now || ceiling-now > int64(30*time.Second)) {
		return 0, ErrDaemonProtocol
	}
	return azureSchedulerControlBudget(now, ceiling)
}
func TestAzureSchedulerReadOnlyRequestCeiling(t *testing.T) {
	now := int64(time.Hour)
	for _, tc := range []struct {
		action    string
		preflight bool
		delta     time.Duration
		refused   bool
	}{
		{"verify", true, 30 * time.Second, false}, {"verify", true, 31 * time.Second, true},
		{"initiate", true, time.Second, true}, {"load-accelerated", true, time.Second, true},
		{"terminate", true, time.Second, true}, {"verify", true, 0, true},
		{"verify", false, 420 * time.Second, false}, {"initiate", false, 0, true},
	} {
		_, err := azureSchedulerRequestBudget(now, now+int64(tc.delta), tc.action, tc.preflight)
		if (err != nil) != tc.refused {
			t.Fatal("read-only ceiling binding changed")
		}
	}
}
