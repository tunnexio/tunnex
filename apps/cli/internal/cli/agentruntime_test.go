package cli

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

const testWGKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

type fakeAgentSource struct {
	cfg       ManagedAgentConfig
	pollErr   error
	reportErr error
	polls     []int64
	reports   []AgentRuntimeReport
}

func (f *fakeAgentSource) Poll(_ context.Context, applied int64, _ string) (ManagedAgentConfig, error) {
	f.polls = append(f.polls, applied)
	return f.cfg, f.pollErr
}

func (f *fakeAgentSource) Report(_ context.Context, report AgentRuntimeReport) error {
	f.reports = append(f.reports, report)
	return f.reportErr
}

type fakeAgentApplier struct {
	applyErr   error
	disableErr error
	applied    []ManagedAgentConfig
	disabled   int
}

func (f *fakeAgentApplier) Apply(_ context.Context, cfg ManagedAgentConfig) error {
	f.applied = append(f.applied, cfg)
	return f.applyErr
}

func (f *fakeAgentApplier) Disable(context.Context) error {
	f.disabled++
	return f.disableErr
}

func validAgentConfig(revision int64) ManagedAgentConfig {
	return ManagedAgentConfig{
		Revision: revision, DeviceID: "dev-1", OrgID: "org-1",
		Address: "100.64.0.8/32", GatewayEndpoint: "gw.example.com:51820",
		GatewayPublicKey: testWGKey, AllowedIPs: []string{"100.64.0.0/10"},
		DNS: []string{"100.64.0.2"}, PersistentKeepalive: 25,
	}
}

func TestAgentRuntimeColdStartFailsClosed(t *testing.T) {
	source := &fakeAgentSource{pollErr: errors.New("offline")}
	applier := &fakeAgentApplier{}
	runtime, err := NewAgentRuntime(source, applier, "v0.1.1")
	if err != nil {
		t.Fatal(err)
	}

	outcome, err := runtime.CheckOnce(context.Background())
	if outcome != AgentRuntimeInconclusive || err == nil {
		t.Fatalf("outcome=%q err=%v", outcome, err)
	}
	if applier.disabled != 1 || len(applier.applied) != 0 {
		t.Fatalf("cold start must disable without applying: %#v", applier)
	}
}

func TestAgentRuntimeUnauthorizedDisableFailureIsNotCleanOffboard(t *testing.T) {
	disableErr := errors.New("wg disable refused")
	source := &fakeAgentSource{pollErr: ErrRuntimeUnauthorized}
	applier := &fakeAgentApplier{disableErr: disableErr}
	runtime, err := NewAgentRuntime(source, applier, "v0.1.1")
	if err != nil {
		t.Fatal(err)
	}

	outcome, err := runtime.CheckOnce(context.Background())
	if outcome != AgentRuntimeInconclusive || !errors.Is(err, ErrRuntimeUnauthorized) || !errors.Is(err, disableErr) {
		t.Fatalf("outcome=%q err=%v; want unauthorized joined with disable failure", outcome, err)
	}
	if applier.disabled != 1 {
		t.Fatalf("disable attempts=%d, want 1", applier.disabled)
	}
}

func TestAgentRuntimePendingNoConfigWaitsFailClosedWithoutReport(t *testing.T) {
	source := &fakeAgentSource{cfg: ManagedAgentConfig{Revision: 0}}
	applier := &fakeAgentApplier{}
	runtime, err := NewAgentRuntime(source, applier, "v0.1.1")
	if err != nil {
		t.Fatal(err)
	}

	outcome, err := runtime.CheckOnce(context.Background())
	if err != nil || outcome != AgentRuntimeInconclusive {
		t.Fatalf("pending no-config outcome=%q err=%v", outcome, err)
	}
	if applier.disabled != 1 || len(applier.applied) != 0 || len(source.reports) != 0 {
		t.Fatalf("pending no-config must disable without apply/report: applier=%#v reports=%#v", applier, source.reports)
	}
}

func TestAgentRuntimeAppliesThenReportsExactRevision(t *testing.T) {
	source := &fakeAgentSource{cfg: validAgentConfig(3)}
	applier := &fakeAgentApplier{}
	runtime, err := NewAgentRuntime(source, applier, "v0.1.1")
	if err != nil {
		t.Fatal(err)
	}

	outcome, err := runtime.CheckOnce(context.Background())
	if err != nil || outcome != AgentRuntimeApplied {
		t.Fatalf("outcome=%q err=%v", outcome, err)
	}
	if runtime.AppliedRevision() != 3 || len(applier.applied) != 1 || applier.disabled != 0 {
		t.Fatalf("apply state: revision=%d applier=%#v", runtime.AppliedRevision(), applier)
	}
	want := AgentRuntimeReport{AppliedRevision: 3, AttemptedRevision: 3, ClientVersion: "v0.1.1"}
	if !reflect.DeepEqual(source.reports, []AgentRuntimeReport{want}) {
		t.Fatalf("reports=%#v want %#v", source.reports, []AgentRuntimeReport{want})
	}
}

func TestAgentRuntimeSameRevisionIsHeartbeatWithoutChurn(t *testing.T) {
	source := &fakeAgentSource{cfg: validAgentConfig(2)}
	applier := &fakeAgentApplier{}
	runtime, _ := NewAgentRuntime(source, applier, "v0.1.1")
	if _, err := runtime.CheckOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	outcome, err := runtime.CheckOnce(context.Background())
	if err != nil || outcome != AgentRuntimeUnchanged {
		t.Fatalf("outcome=%q err=%v", outcome, err)
	}
	if len(applier.applied) != 1 {
		t.Fatalf("identical revision re-applied %d times", len(applier.applied))
	}
	if !reflect.DeepEqual(source.polls, []int64{0, 2}) {
		t.Fatalf("poll revisions=%v", source.polls)
	}
}

func TestAgentRuntimeHeartbeatUnauthorizedOffboards(t *testing.T) {
	source := &fakeAgentSource{cfg: validAgentConfig(2)}
	applier := &fakeAgentApplier{}
	runtime, _ := NewAgentRuntime(source, applier, "v0.1.1")
	if _, err := runtime.CheckOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	source.reportErr = ErrRuntimeUnauthorized

	outcome, err := runtime.CheckOnce(context.Background())
	if outcome != AgentRuntimeInconclusive || !errors.Is(err, ErrRuntimeUnauthorized) || applier.disabled != 1 {
		t.Fatalf("heartbeat unauthorized outcome=%q err=%v disabled=%d; want terminal offboard", outcome, err, applier.disabled)
	}
	if runtime.AppliedRevision() != 0 {
		t.Fatalf("terminal offboard revision=%d, want 0 for re-enable recovery", runtime.AppliedRevision())
	}
}

func TestAgentRuntimeApplyFailureKeepsLastGoodRevision(t *testing.T) {
	source := &fakeAgentSource{cfg: validAgentConfig(1)}
	applier := &fakeAgentApplier{}
	runtime, _ := NewAgentRuntime(source, applier, "v0.1.1")
	if _, err := runtime.CheckOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	source.cfg = validAgentConfig(2)
	applier.applyErr = errors.New("wg refused")
	outcome, err := runtime.CheckOnce(context.Background())
	if outcome != AgentRuntimeInconclusive || err == nil {
		t.Fatalf("outcome=%q err=%v", outcome, err)
	}
	if runtime.AppliedRevision() != 1 || applier.disabled != 0 {
		t.Fatalf("last-good must remain: revision=%d disabled=%d", runtime.AppliedRevision(), applier.disabled)
	}
	want := AgentRuntimeReport{AppliedRevision: 1, AttemptedRevision: 2, ClientVersion: "v0.1.1", ErrorCode: "apply_failed"}
	if got := source.reports[len(source.reports)-1]; !reflect.DeepEqual(got, want) {
		t.Fatalf("failure report=%#v want %#v", got, want)
	}
}

func TestAgentRuntimeFailureReportUnauthorizedOffboards(t *testing.T) {
	source := &fakeAgentSource{cfg: validAgentConfig(1)}
	applier := &fakeAgentApplier{}
	runtime, _ := NewAgentRuntime(source, applier, "v0.1.1")
	if _, err := runtime.CheckOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	source.cfg = validAgentConfig(2)
	source.reportErr = ErrRuntimeUnauthorized
	applier.applyErr = errors.New("candidate refused")
	outcome, err := runtime.CheckOnce(context.Background())
	if outcome != AgentRuntimeInconclusive || !errors.Is(err, ErrRuntimeUnauthorized) || applier.disabled != 1 {
		t.Fatalf("failure report unauthorized outcome=%q err=%v disabled=%d; want terminal offboard", outcome, err, applier.disabled)
	}
}

func TestAgentRuntimeReportUnauthorizedPreservesDisableFailure(t *testing.T) {
	disableErr := errors.New("wg disable refused")
	source := &fakeAgentSource{cfg: validAgentConfig(1)}
	applier := &fakeAgentApplier{}
	runtime, _ := NewAgentRuntime(source, applier, "v0.1.1")
	if _, err := runtime.CheckOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	source.reportErr = ErrRuntimeUnauthorized
	applier.disableErr = disableErr

	_, err := runtime.CheckOnce(context.Background())
	if !errors.Is(err, ErrRuntimeUnauthorized) || !errors.Is(err, disableErr) || applier.disabled != 1 {
		t.Fatalf("report unauthorized disable failure=%v disabled=%d; want joined terminal refusal", err, applier.disabled)
	}
}

func TestAgentRuntimeInvalidConfigNeverReachesApplier(t *testing.T) {
	cfg := validAgentConfig(1)
	cfg.GatewayPublicKey = "not-a-key"
	source := &fakeAgentSource{cfg: cfg}
	applier := &fakeAgentApplier{}
	runtime, _ := NewAgentRuntime(source, applier, "v0.1.1")

	if _, err := runtime.CheckOnce(context.Background()); err == nil {
		t.Fatal("invalid config accepted")
	}
	if len(applier.applied) != 0 || applier.disabled != 1 {
		t.Fatalf("invalid config must fail closed: %#v", applier)
	}
	if len(source.reports) != 1 || source.reports[0].ErrorCode != "invalid_config" {
		t.Fatalf("reports=%#v", source.reports)
	}
}

func TestAgentRuntimeReportFailureDoesNotRollBackAppliedConfig(t *testing.T) {
	source := &fakeAgentSource{cfg: validAgentConfig(4), reportErr: errors.New("report offline")}
	applier := &fakeAgentApplier{}
	runtime, _ := NewAgentRuntime(source, applier, "v0.1.1")

	outcome, err := runtime.CheckOnce(context.Background())
	if outcome != AgentRuntimeInconclusive || err == nil {
		t.Fatalf("outcome=%q err=%v", outcome, err)
	}
	if runtime.AppliedRevision() != 4 || len(applier.applied) != 1 || applier.disabled != 0 {
		t.Fatalf("applied config was rolled back: revision=%d applier=%#v", runtime.AppliedRevision(), applier)
	}
}
