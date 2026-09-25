package ipsec

import (
	"context"
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
)

func TestRuntimeControllerRestartRestoresOnlyPrefixRefusal(t *testing.T) {
	entry := journalFixture()
	j, err := OpenRuntimeJournal(journalDir(t), entry.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err = j.Save([]RuntimeJournalEntry{entry}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	c := &RuntimeController{config: RuntimeControllerConfig{OrgID: entry.Engines[0].Binding.OrgID, GatewayID: entry.Engines[0].Binding.GatewayID}, journal: j, namespace: func() (string, error) { return entry.Allocation.Namespace, nil }, replace: func(_ context.Context, in GuardIntent) (GuardManifest, error) {
		calls++
		if len(in.Connections) != 1 || !in.Connections[0].PrefixOnly || len(in.Connections[0].Grants) != 0 || in.Connections[0].PermitFor != 0 {
			t.Fatal("startup reused authority")
		}
		return RenderGuard(in)
	}}
	if err = c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || c.Capability() != 0 {
		t.Fatal("startup failed to restore refusal or manufactured qualification")
	}
	if err = c.Start(context.Background()); err != nil || calls != 1 {
		t.Fatal("start not idempotent")
	}
}
func TestRuntimeControllerStartupFailureBlocksMaterial(t *testing.T) {
	entry := journalFixture()
	j, err := OpenRuntimeJournal(journalDir(t), entry.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err = j.Save([]RuntimeJournalEntry{entry}); err != nil {
		t.Fatal(err)
	}
	c := &RuntimeController{config: RuntimeControllerConfig{OrgID: entry.Engines[0].Binding.OrgID, GatewayID: entry.Engines[0].Binding.GatewayID}, journal: j, namespace: func() (string, error) { return entry.Allocation.Namespace, nil }, replace: func(context.Context, GuardIntent) (GuardManifest, error) { return GuardManifest{}, ErrGuardReadback }}
	if err = c.Start(context.Background()); err == nil || c.started {
		t.Fatal("failed refusal accepted")
	}
	ack, err := c.Apply(context.Background(), RuntimeMaterial{RuntimeDelivery: RuntimeDelivery{ID: uuid.New()}})
	if err == nil || ack.DeliveryID != uuid.Nil {
		t.Fatal("material acknowledged without startup")
	}
}

func TestRuntimeCombinedGuardPreservesDeadlineAndDropsExpiredConnection(t *testing.T) {
	entry := journalFixture()
	j, err := OpenRuntimeJournal(journalDir(t), entry.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err = j.Save([]RuntimeJournalEntry{entry}); err != nil {
		t.Fatal(err)
	}
	for i, tunnel := range entry.Allocation.Tunnels {
		entry.Observed[i] = Ownership{Namespace: entry.Allocation.Namespace, InterfaceName: tunnel.Name, InterfaceIndex: 10 + i, XFRMID: tunnel.XFRMID}
	}
	elapsed := time.Duration(0)
	authority := NewPermitLeaseAuthority()
	authority.elapsed = func() time.Duration { return elapsed }
	identity := PermitLeaseIdentity{DeliveryID: entry.DeliveryID, Binding: entry.Engines[0].Binding, PolicyHash: strings.Repeat("b", 64)}
	identity.Binding.PolicyRevision = 0
	req, err := authority.Begin(identity)
	if err != nil {
		t.Fatal(err)
	}
	if err = authority.Accept(PermitLeaseResponse{PermitLeaseRequest: req, TTLMillis: 60000}); err != nil {
		t.Fatal(err)
	}
	var intents []GuardIntent
	c := &RuntimeController{config: RuntimeControllerConfig{OrgID: entry.Engines[0].Binding.OrgID, GatewayID: entry.Engines[0].Binding.GatewayID}, journal: j, namespace: func() (string, error) { return entry.Allocation.Namespace, nil }, prove: func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error { return nil }, replace: func(_ context.Context, in GuardIntent) (GuardManifest, error) {
		intents = append(intents, in)
		return GuardManifest{}, nil
	}, qualification: testRuntimeQualification(entry.Allocation.Namespace), active: map[uuid.UUID]runtimeActive{entry.Allocation.ConnectionID: {Entry: entry, Environment: RuntimeEnvironment{Namespace: entry.Allocation.Namespace, Underlays: [2]RuntimeUnderlay{{InterfaceIndex: 2}, {InterfaceIndex: 2}}}, Authority: authority, Identity: identity}}}
	c.recoveryObserve = func(context.Context, RuntimeJournalEntry) [2]string { return [2]string{"up", "up"} }
	elapsed = 10 * time.Second
	if err = c.installActive(context.Background(), []RuntimeJournalEntry{entry}); err != nil {
		t.Fatal(err)
	}
	if got := intents[0].Connections[0].PermitFor; got != 45*time.Second {
		t.Fatalf("renewed old authority: %v", got)
	}
	elapsed = 30 * time.Second
	if err = c.installActive(context.Background(), []RuntimeJournalEntry{entry}); err != nil {
		t.Fatal(err)
	}
	if got := intents[1].Connections[0].PermitFor; got != 25*time.Second {
		t.Fatalf("replacement reset old deadline: %v", got)
	}
	elapsed = 60 * time.Second
	if err = c.installActive(context.Background(), []RuntimeJournalEntry{entry}); err != nil {
		t.Fatal(err)
	}
	if !intents[2].Connections[0].PrefixOnly || len(c.active) != 0 {
		t.Fatal("expired authority retained")
	}
}

func TestRuntimeApplyBudgetStartsBeforeIntentAssembly(t *testing.T) {
	entry := journalFixture()
	j, err := OpenRuntimeJournal(journalDir(t), entry.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err = j.Save([]RuntimeJournalEntry{entry}); err != nil {
		t.Fatal(err)
	}
	authority := NewPermitLeaseAuthority()
	calls := 0
	authority.elapsed = func() time.Duration {
		calls++
		if calls == 4 {
			time.Sleep(5100 * time.Millisecond)
		}
		return 0
	}
	identity := PermitLeaseIdentity{DeliveryID: entry.DeliveryID, Binding: entry.Engines[0].Binding, PolicyHash: strings.Repeat("b", 64)}
	identity.Binding.PolicyRevision = 0
	req, err := authority.Begin(identity)
	if err != nil {
		t.Fatal(err)
	}
	if err = authority.Accept(PermitLeaseResponse{PermitLeaseRequest: req, TTLMillis: 60000}); err != nil {
		t.Fatal(err)
	}
	installed := false
	c := &RuntimeController{config: RuntimeControllerConfig{GatewayID: entry.Engines[0].Binding.GatewayID}, journal: j, namespace: func() (string, error) { return entry.Allocation.Namespace, nil }, prove: func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error { return nil }, replace: func(context.Context, GuardIntent) (GuardManifest, error) {
		installed = true
		return GuardManifest{}, nil
	}, qualification: testRuntimeQualification(entry.Allocation.Namespace), active: map[uuid.UUID]runtimeActive{entry.Allocation.ConnectionID: {Entry: entry, Authority: authority, Identity: identity}}}
	if c.installActive(context.Background(), []RuntimeJournalEntry{entry}) == nil || installed {
		t.Fatal("stalled intent assembly acquired fresh apply budget")
	}
}

func testRuntimeQualification(ns string) *RuntimePlatformQualification {
	return &RuntimePlatformQualification{namespace: ns, baseline: runtimeClock{Boot: time.Second, Monotonic: time.Second}, readNamespace: func() (string, error) { return ns, nil }, readClock: func() (runtimeClock, error) { return runtimeClock{Boot: time.Second, Monotonic: time.Second}, nil }, alive: func() bool { return true }}
}
func TestRuntimeQualificationCannotBeOmittedOrReplaced(t *testing.T) {
	c := &RuntimeController{started: true, namespace: func() (string, error) { return "net:[4026531992]", nil }}
	if c.AttachQualification(nil) == nil {
		t.Fatal("nil qualification accepted")
	}
	q := testRuntimeQualification("net:[4026531992]")
	if c.AttachQualification(q) != nil {
		t.Fatal("current receipt refused")
	}
	if c.AttachQualification(testRuntimeQualification("net:[4026531992]")) == nil {
		t.Fatal("qualification replaced without restart")
	}
	if c.Capability() != 0 {
		t.Fatal("partial probe raised capability")
	}
}

func TestRuntimeSupportedArchitectureBoundary(t *testing.T) {
	for _, tc := range []struct {
		os, arch string
		want     bool
	}{{"linux", "arm64", true}, {"linux", "amd64", true}, {"darwin", "arm64", false}, {"windows", "amd64", false}} {
		if supportedRuntimePlatform(tc.os, tc.arch) != tc.want {
			t.Fatalf("incorrect supported profile %s/%s", tc.os, tc.arch)
		}
	}
}
func TestRuntimeEmptyPollWithdrawsInvalidatedAuthority(t *testing.T) {
	entry := journalFixture()
	j, err := OpenRuntimeJournal(journalDir(t), entry.Engines[0].Binding.GatewayID)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err = j.Save([]RuntimeJournalEntry{entry}); err != nil {
		t.Fatal(err)
	}
	q := testRuntimeQualification(entry.Allocation.Namespace)
	q.invalid = true
	calls := 0
	c := &RuntimeController{started: true, qualification: q, config: RuntimeControllerConfig{OrgID: entry.Engines[0].Binding.OrgID, GatewayID: entry.Engines[0].Binding.GatewayID}, journal: j, namespace: func() (string, error) { return entry.Allocation.Namespace, nil }, replace: func(_ context.Context, in GuardIntent) (GuardManifest, error) {
		calls++
		if !in.Connections[0].PrefixOnly {
			t.Fatal("invalidated authority replayed")
		}
		return GuardManifest{}, nil
	}, active: map[uuid.UUID]runtimeActive{entry.Allocation.ConnectionID: {Entry: entry}}}
	if c.Validate(context.Background()) == nil || calls != 1 || len(c.active) != 0 {
		t.Fatal("empty poll left invalidated authority")
	}
}

func TestRuntimeCapabilityRequiresLiveQualifiedSupportedHost(t *testing.T) {
	alive := true
	ns := "net:[4026531992]"
	c := &RuntimeController{started: true, qualification: testRuntimeQualification(ns), config: RuntimeControllerConfig{Daemon: &DaemonClient{}, DaemonAlive: func() bool { return alive }}}
	if c.capabilityFor("linux", "amd64") != 1 {
		t.Fatal("qualified AMD64 profile did not advertise support")
	}
	if c.capabilityFor("linux", "arm64") != 1 {
		t.Fatal("qualified native profile did not advertise support")
	}
	for _, p := range [][2]string{{"linux", "386"}, {"darwin", "arm64"}, {"windows", "amd64"}} {
		if c.capabilityFor(p[0], p[1]) != 0 {
			t.Fatal("unqualified platform advertised support")
		}
	}
	alive = false
	if c.capabilityFor("linux", "arm64") != 0 {
		t.Fatal("dead daemon advertised support")
	}
	alive = true
	c.qualification.invalid = true
	if c.capabilityFor("linux", "arm64") != 0 {
		t.Fatal("invalidated receipt advertised support")
	}
	c.qualification = testRuntimeQualification(ns)
	c.started = false
	if c.capabilityFor("linux", "arm64") != 0 {
		t.Fatal("unstarted controller advertised support")
	}
	c.started = true
	c.closed = true
	if c.capabilityFor("linux", "arm64") != 0 {
		t.Fatal("closed controller advertised support")
	}
	c.closed = false
	c.config.Daemon = nil
	if c.capabilityFor("linux", "arm64") != 0 {
		t.Fatal("missing daemon advertised support")
	}
	c.config.Daemon = &DaemonClient{}
	c.qualification = nil
	if c.capabilityFor("linux", "arm64") != 0 {
		t.Fatal("missing qualification advertised support")
	}
}
