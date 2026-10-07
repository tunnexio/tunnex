package cli

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	beamtransport "github.com/tunnexio/tunnex/packages/apptransport/beam"
)

var beamTestOrg = "11111111-1111-4111-8111-111111111111"
var beamTestShare = "22222222-2222-4222-8222-222222222222"
var beamTestReviewer = "33333333-3333-4333-8333-333333333333"

type beamFakeAPI struct {
	beforeAction        func()
	issueAdvanceOnError bool
	mu                  sync.Mutex
	policy              beamPolicy
	share               beamShare
	connector           beamConnectorWire
	keys                []string
	actions             []beamAction
	issues              int
	creates             int
	createErrors        int
	beats               int
	beatHook            func(context.Context, beamShare, bool) (beamShare, error)
	issueErr            error
	actionErr           error
}

func (a *beamFakeAPI) Policy(context.Context, string) (beamPolicy, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.policy, nil
}
func (a *beamFakeAPI) Audience(context.Context, string) (beamAudience, error) {
	return beamAudience{}, nil
}
func (a *beamFakeAPI) List(context.Context, string, int) (beamSharePage, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return beamSharePage{Items: []beamShare{a.share}}, nil
}
func (a *beamFakeAPI) Get(context.Context, string, string) (beamShare, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.share, nil
}
func (a *beamFakeAPI) Create(_ context.Context, _ string, i beamCreate) (beamShare, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.creates++
	a.keys = append(a.keys, i.IdempotencyKey)
	if a.createErrors > 0 {
		a.createErrors--
		return beamShare{}, &beamAPIError{503, "private"}
	}
	return a.share, nil
}
func (a *beamFakeAPI) Action(_ context.Context, _, _ string, i beamAction) (beamShare, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.beforeAction != nil {
		a.beforeAction()
	}
	a.actions = append(a.actions, i)
	if a.actionErr != nil {
		return beamShare{}, a.actionErr
	}
	if i.ExpectedVersion != a.share.Version {
		return beamShare{}, &beamAPIError{409, "conflict"}
	}
	a.share.Version++
	if i.Action == "resume" {
		a.share.State = "starting"
	} else if i.Action == "stop" {
		a.share.State = "stopped"
	} else if i.Action == "pause" {
		a.share.State = "paused"
	}
	return a.share, nil
}
func (a *beamFakeAPI) Issue(context.Context, string, string, int64, string) (beamConnectorWire, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.issues++
	if a.issueErr != nil {
		if a.issueAdvanceOnError {
			a.share.Version++
		}
		return beamConnectorWire{}, a.issueErr
	}
	a.share.Version++
	a.share.AuthorityVersion = 2
	a.connector.ShareVersion = a.share.Version
	return a.connector, nil
}
func (a *beamFakeAPI) Heartbeat(ctx context.Context, _, _, _ string, ready bool) (beamShare, error) {
	a.mu.Lock()
	a.beats++
	s := a.share
	hook := a.beatHook
	a.mu.Unlock()
	if hook != nil {
		return hook(ctx, s, ready)
	}
	if ready {
		s.State = "active"
		s.Connectivity = "online"
	}
	return s, nil
}
func (a *beamFakeAPI) snapshot() (int, int, int, []beamAction, []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.creates, a.issues, a.beats, append([]beamAction{}, a.actions...), append([]string{}, a.keys...)
}

type beamFakeRunner struct {
	delay   time.Duration
	ready   atomic.Bool
	stopped chan struct{}
}

func (r *beamFakeRunner) Run(ctx context.Context) error {
	defer close(r.stopped)
	<-ctx.Done()
	time.Sleep(r.delay)
	return ctx.Err()
}
func (r *beamFakeRunner) Ready() bool { return r.ready.Load() }

type beamSafeBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *beamSafeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}
func (b *beamSafeBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.Buffer.String() }
func beamFixture() (*beamFakeAPI, *beamFakeRunner, beamDependencies, *atomic.Pointer[Credential]) {
	expiry := time.Now().Add(time.Hour)
	target := beamTarget{Protocol: "http", Address: "127.0.0.1", Port: 5173}
	a := &beamFakeAPI{policy: beamPolicy{Enabled: true, CanPublish: true, DomainReady: true, ProtocolVersion: 1, MinClientVersion: "0.1.7", MaxDuration: 86400}, share: beamShare{ID: beamTestShare, OrgID: beamTestOrg, Name: "local fixture", Hostname: "p-12345678901234567890123456789012.example.net", URL: "https://p-12345678901234567890123456789012.example.net", State: "starting", Connectivity: "offline", Version: 1, AuthorityVersion: 1, ExpiresAt: expiry, CanManage: true, Target: &target}}
	a.connector.Binding.OrgID = beamTestOrg
	a.connector.Binding.AppID = beamTestShare
	a.connector.Binding.Hostname = a.share.Hostname
	a.connector.Binding.Purpose = "beam_proxy"
	a.connector.Binding.Revision = 1
	a.connector.Binding.AuthorityVersion = 2
	a.connector.Binding.Generation = uuid.NewString()
	a.connector.Binding.GatewayID = uuid.NewString()
	a.connector.Binding.Digest = beamTargetDigest(target)
	a.connector.ServerName = "tunnex-beam-proxy"
	a.connector.ProxyURL = "https://proxy.example.net"
	a.connector.ExpiresAt = expiry
	a.connector.CertificateExpiresAt = expiry
	a.connector.CertificatePEM = "PRIVATE-CERT"
	a.connector.CAPEM = "CA"
	r := &beamFakeRunner{stopped: make(chan struct{})}
	r.ready.Store(true)
	c := &atomic.Pointer[Credential]{}
	c.Store(&Credential{Server: "https://cp.example.net", Token: "PRIVATE-TOKEN", Fingerprint: "current", ExpiresAt: expiry})
	d := beamDependencies{loadCredential: func() (Credential, error) {
		v := c.Load()
		if v == nil {
			return Credential{}, ErrNotLoggedIn
		}
		if !v.ExpiresAt.After(time.Now()) {
			return Credential{}, ErrCredentialExpired
		}
		return *v, nil
	}, newAPI: func(Credential) (beamAPI, error) { return a, nil }, checkTarget: func(context.Context, beamtransport.Target) error { return nil }, newConnector: func(beamtransport.ConnectorOptions) (beamRunner, error) { return r, nil }, makeKey: func() (string, string, error) { return "PRIVATE-KEY", "PUBLIC-CSR", nil }, interval: 5 * time.Millisecond, heartbeatInterval: 20 * time.Millisecond, uncertainty: 100 * time.Millisecond, clock: time.Now}
	return a, r, d, c
}
func beamPublishArgs() []string {
	return []string{"publish", "--org", beamTestOrg, "--port", "5173", "--name", "Local app", "--reviewer-user", beamTestReviewer}
}
func beamAwait(t *testing.T, condition func() bool) {
	t.Helper()
	until := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(until) {
			t.Fatal("timed out waiting for Beam state")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestBeamPublishLiveAndSignalStopsFreshRevision(t *testing.T) {
	a, r, d, _ := beamFixture()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := &beamSafeBuffer{}
	done := make(chan error, 1)
	go func() { done <- runBeam(ctx, beamPublishArgs(), out, "dev", d) }()
	beamAwait(t, func() bool { return strings.Contains(out.String(), "URL: https://") })
	if strings.Contains(out.String(), "PRIVATE") {
		t.Fatal("publication leaked connector/login material")
	}
	cancel()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	select {
	case <-r.stopped:
	default:
		t.Fatal("connector still serving after cancellation")
	}
	_, _, _, actions, _ := a.snapshot()
	if len(actions) != 1 || actions[0].Action != "stop" || actions[0].ExpectedVersion != 2 {
		t.Fatalf("cleanup must Stop using fresh server revision: %+v", actions)
	}
}
func TestBeamDoesNotPrintURLBeforeNativeAndServerReadiness(t *testing.T) {
	a, r, d, _ := beamFixture()
	r.ready.Store(false)
	ctx, cancel := context.WithCancel(context.Background())
	out := &beamSafeBuffer{}
	done := make(chan error, 1)
	go func() { done <- runBeam(ctx, beamPublishArgs(), out, "dev", d) }()
	beamAwait(t, func() bool { _, _, beats, _, _ := a.snapshot(); return beats >= 2 })
	if strings.Contains(out.String(), "https://") {
		t.Fatal("printed URL while channels not admitted")
	}
	r.ready.Store(true)
	beamAwait(t, func() bool { return strings.Contains(out.String(), "URL:") })
	cancel()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
func TestBeamCredentialRemovalChangeAndExpiryTerminateWithoutUsingReplacement(t *testing.T) {
	for _, name := range []string{"remove", "replace", "expire"} {
		t.Run(name, func(t *testing.T) {
			a, r, d, c := beamFixture()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			out := &beamSafeBuffer{}
			done := make(chan error, 1)
			go func() { done <- runBeam(ctx, beamPublishArgs(), out, "dev", d) }()
			beamAwait(t, func() bool { return strings.Contains(out.String(), "URL:") })
			switch name {
			case "remove":
				c.Store(nil)
			case "replace":
				next := *c.Load()
				next.Token = "NEW-PRIVATE-TOKEN"
				c.Store(&next)
			case "expire":
				next := *c.Load()
				next.ExpiresAt = time.Now().Add(-time.Second)
				c.Store(&next)
			}
			select {
			case e := <-done:
				if e == nil || !strings.Contains(e.Error(), "login changed") {
					t.Fatalf("expected current-login fence: %v", e)
				}
			case <-time.After(time.Second):
				t.Fatal("credential fence did not cancel foreground")
			}
			select {
			case <-r.stopped:
			default:
				t.Fatal("channels remained open")
			}
			_, _, _, actions, _ := a.snapshot()
			if len(actions) != 0 {
				t.Fatal("used deleted/replaced credential for cleanup mutation")
			}
		})
	}
}
func TestBeamAuthorityUncertaintyHasIndependentCeiling(t *testing.T) {
	a, r, d, _ := beamFixture()
	a.beatHook = func(ctx context.Context, _ beamShare, _ bool) (beamShare, error) {
		<-ctx.Done()
		return beamShare{}, errBeamNetwork
	}
	start := time.Now()
	e := runBeam(context.Background(), beamPublishArgs(), io.Discard, "dev", d)
	if e == nil || !strings.Contains(e.Error(), "could not be refreshed") {
		t.Fatalf("unexpected %v", e)
	}
	if elapsed := time.Since(start); elapsed > 350*time.Millisecond {
		t.Fatalf("independent authority ceiling exceeded: %s", elapsed)
	}
	select {
	case <-r.stopped:
	default:
		t.Fatal("uncertain authority retained channels")
	}
}
func TestBeamPausedRevokedAndGenerationWithdrawalTerminate(t *testing.T) {
	for _, name := range []string{"paused", "revoked", "generation", "expiry"} {
		t.Run(name, func(t *testing.T) {
			a, r, d, _ := beamFixture()
			a.beatHook = func(_ context.Context, s beamShare, _ bool) (beamShare, error) {
				switch name {
				case "paused", "revoked":
					s.State = name
				case "generation":
					return beamShare{}, &beamAPIError{403, "generation_replaced"}
				case "expiry":
					s.ExpiresAt = time.Now().Add(-time.Second)
				}
				return s, nil
			}
			e := runBeam(context.Background(), beamPublishArgs(), io.Discard, "dev", d)
			if e == nil {
				t.Fatal("withdrew no serving authority")
			}
			select {
			case <-r.stopped:
			default:
				t.Fatal("withdrawal retained connector")
			}
		})
	}
}
func TestBeamCreateRetryKeepsIdempotencyAndFailureCleansOnlyNewShare(t *testing.T) {
	a, _, d, _ := beamFixture()
	a.createErrors = 1
	a.issueErr = &beamAPIError{503, "secret"}
	e := runBeam(context.Background(), beamPublishArgs(), io.Discard, "dev", d)
	if e == nil {
		t.Fatal("issue failure not returned")
	}
	creates, _, _, actions, keys := a.snapshot()
	if creates != 2 || keys[0] == "" || keys[0] != keys[1] {
		t.Fatalf("retry changed publication intent: %v", keys)
	}
	if len(actions) != 1 || actions[0].Action != "stop" {
		t.Fatal("new failed publication not cleaned up")
	}
}
func TestBeamResumeUsesImmutableTargetAndOriginalCredentialBeforeConnector(t *testing.T) {
	a, _, d, _ := beamFixture()
	a.share.State = "paused"
	a.actionErr = &beamAPIError{404, "original_source_required"}
	e := runBeam(context.Background(), []string{"resume", "--org", beamTestOrg, "--share", beamTestShare}, io.Discard, "dev", d)
	if e == nil {
		t.Fatal("other credential resume accepted")
	}
	_, issues, _, actions, _ := a.snapshot()
	if issues != 0 || len(actions) != 1 || actions[0].Action != "resume" {
		t.Fatal("failed source guard issued connector or stopped existing share")
	}
}
func TestBeamResumesSameTargetWithoutExtendingOrRecreating(t *testing.T) {
	a, _, d, _ := beamFixture()
	a.share.State = "paused"
	var captured beamtransport.ConnectorOptions
	factory := d.newConnector
	d.newConnector = func(o beamtransport.ConnectorOptions) (beamRunner, error) { captured = o; return factory(o) }
	ctx, cancel := context.WithCancel(context.Background())
	out := &beamSafeBuffer{}
	done := make(chan error, 1)
	go func() {
		done <- runBeam(ctx, []string{"resume", "--org", beamTestOrg, "--share", beamTestShare}, out, "dev", d)
	}()
	beamAwait(t, func() bool { return strings.Contains(out.String(), "URL:") })
	cancel()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	creates, _, _, actions, _ := a.snapshot()
	if creates != 0 || captured.Target.Port != 5173 || captured.Target.Address != "127.0.0.1" || captured.Binding.AppID != beamTestShare || !captured.ExpiresAt.Equal(a.connector.CertificateExpiresAt) {
		t.Fatal("resume altered target/share/certificate deadline")
	}
	if len(actions) != 2 || actions[0].Action != "resume" || actions[0].ExpiresAt != nil {
		t.Fatalf("resume unexpectedly extended expiry: %v", actions)
	}
}
func TestBeamInvalidPublicationNeverLoadsCredential(t *testing.T) {
	_, _, d, _ := beamFixture()
	d.loadCredential = func() (Credential, error) { t.Fatal("invalid intent accessed credentials"); return Credential{}, nil }
	cases := [][]string{{"publish", "--org", beamTestOrg, "--port", "5173", "--name", "App"}, {"publish", "--org", beamTestOrg, "--port", "5173", "--name", "App", "--reviewer-user", beamTestReviewer, "--address", "192.168.0.1"}, {"publish", "--org", beamTestOrg, "--port", "5173", "--name", "App", "--reviewer-user", beamTestReviewer, "--duration", "25h"}, {"resume", "--org", beamTestOrg, "--share", beamTestShare, "--port", "9999"}}
	for _, args := range cases {
		if e := runBeam(context.Background(), args, io.Discard, "dev", d); e == nil {
			t.Fatalf("accepted invalid publication: %v", args)
		}
	}
}
func TestBeamVersionProtocolAndDevelopmentFloor(t *testing.T) {
	p := beamPolicy{ProtocolVersion: 1, MinClientVersion: "0.1.7"}
	for _, test := range []struct {
		version, min string
		protocol     int
		accepted     bool
	}{{"dev", "0.1.7", 1, true}, {"dev", "0.1.8", 1, false}, {"v0.2.0", "0.1.7", 1, true}, {"v0.1.6", "0.1.7", 1, false}, {"v0.1.7-rc1", "0.1.7", 1, false}, {"dev", "0.1.7", 2, false}, {"unknown", "0.1.7", 1, false}} {
		p.MinClientVersion = test.min
		p.ProtocolVersion = test.protocol
		if got := beamCompatible(p, test.version) == nil; got != test.accepted {
			t.Fatalf("compatibility %+v = %v", test, got)
		}
	}
	_, _, d, _ := beamFixture()
	var help bytes.Buffer
	if e := runBeam(context.Background(), []string{"--help"}, &help, "dev", d); e != nil || !strings.Contains(help.String(), "without a desktop client or VPN") {
		t.Fatalf("help unclear: %v %s", e, help.String())
	}
}
func TestBeamReadProjectionNeverPrintsTargetAndCertificate(t *testing.T) {
	a, _, d, _ := beamFixture()
	a.share.Target.CAPEM = "PRIVATE-ORIGIN-CA"
	var out bytes.Buffer
	if e := runBeam(context.Background(), []string{"get", "--org", beamTestOrg, "--share", beamTestShare}, &out, "dev", d); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(out.String(), "PRIVATE") || strings.Contains(out.String(), "5173") || strings.Contains(out.String(), "127.0.0.1") {
		t.Fatal("read projection exposed connector/origin configuration")
	}
}
func TestBeamResumePreflightAndFailedIssueRollbackExactVersion(t *testing.T) {
	for _, name := range []string{"key", "issue", "lost-issue-reply"} {
		t.Run(name, func(t *testing.T) {
			a, _, d, _ := beamFixture()
			a.share.State = "paused"
			expiry := a.share.ExpiresAt
			switch name {
			case "key":
				d.makeKey = func() (string, string, error) { return "", "", fmt.Errorf("PRIVATE-RNG-ERROR") }
			case "issue":
				a.issueErr = &beamAPIError{403, "issue_denied"}
			case "lost-issue-reply":
				a.issueErr = errBeamNetwork
				a.issueAdvanceOnError = true
			}
			e := runBeam(context.Background(), []string{"resume", "--org", beamTestOrg, "--share", beamTestShare}, io.Discard, "dev", d)
			if e == nil || strings.Contains(e.Error(), "PRIVATE") {
				t.Fatalf("preflight/issue failure missing or raw: %v", e)
			}
			_, issues, _, actions, _ := a.snapshot()
			a.mu.Lock()
			defer a.mu.Unlock()
			if !a.share.ExpiresAt.Equal(expiry) {
				t.Fatal("failed resume changed lifetime")
			}
			if name == "key" {
				if issues != 0 || len(actions) != 0 || a.share.State != "paused" {
					t.Fatal("key failure mutated paused share")
				}
				return
			}
			if len(actions) != 2 || actions[0].Action != "resume" || actions[1].Action != "pause" || actions[1].ExpectedVersion != 2 {
				t.Fatalf("rollback adopted newer revision: %+v", actions)
			}
			if name == "issue" && a.share.State != "paused" {
				t.Fatal("failed issue left original paused share starting")
			}
			if name == "lost-issue-reply" && (a.share.State != "starting" || a.share.Version != 3 || !strings.Contains(e.Error(), "server pause was not confirmed")) {
				t.Fatal("lost issuance reply changed unknown newer generation or hid uncertainty")
			}
		})
	}
}
func TestBeamSignalWaitsForNativeChannelClosureBeforeStop(t *testing.T) {
	a, r, d, _ := beamFixture()
	r.delay = 30 * time.Millisecond
	order := make(chan bool, 1)
	a.beforeAction = func() {
		select {
		case <-r.stopped:
			order <- true
		default:
			order <- false
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	out := &beamSafeBuffer{}
	done := make(chan error, 1)
	go func() { done <- runBeam(ctx, beamPublishArgs(), out, "dev", d) }()
	beamAwait(t, func() bool { return strings.Contains(out.String(), "URL:") })
	cancel()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if !<-order {
		t.Fatal("server Stop preceded native channel/origin shutdown")
	}
}
func TestBeamHeartbeatRenewsShortProofAndAcceptsManagementRevision(t *testing.T) {
	a, _, d, _ := beamFixture()
	a.connector.ExpiresAt = time.Now().Add(50 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := &beamSafeBuffer{}
	done := make(chan error, 1)
	go func() { done <- runBeam(ctx, beamPublishArgs(), out, "dev", d) }()
	beamAwait(t, func() bool { return strings.Contains(out.String(), "URL:") })
	a.mu.Lock()
	a.share.Version++
	a.share.AuthorityVersion++
	a.mu.Unlock()
	time.Sleep(120 * time.Millisecond)
	select {
	case e := <-done:
		t.Fatalf("renewed authority ended at initial proof or management revision: %v", e)
	default:
	}
	cancel()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	_, _, _, actions, _ := a.snapshot()
	if len(actions) != 1 || actions[0].ExpectedVersion != 3 {
		t.Fatal("cleanup did not use last generation-bound heartbeat revision")
	}
}
func TestBeamCleanupConflictDoesNotRefreshIntoAnotherGeneration(t *testing.T) {
	a, _, d, _ := beamFixture()
	ctx, cancel := context.WithCancel(context.Background())
	out := &beamSafeBuffer{}
	done := make(chan error, 1)
	go func() { done <- runBeam(ctx, beamPublishArgs(), out, "dev", d) }()
	beamAwait(t, func() bool { return strings.Contains(out.String(), "URL:") })
	a.mu.Lock()
	a.share.Version = 99
	a.mu.Unlock()
	cancel()
	if e := <-done; e == nil || !strings.Contains(e.Error(), "server stop was not confirmed") {
		t.Fatalf("unconfirmed Stop was hidden: %v", e)
	}
	_, _, _, actions, _ := a.snapshot()
	if len(actions) != 1 || actions[0].ExpectedVersion != 2 {
		t.Fatalf("cleanup adopted a foreign revision: %v", actions)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.share.State == "stopped" || a.share.Version != 99 {
		t.Fatal("cleanup stopped a newer generation")
	}
}
func TestBeamKeyCSRProofAndNoPersistence(t *testing.T) {
	key, csr, e := beamKey()
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(key, "RSA PRIVATE KEY") || !strings.Contains(csr, "CERTIFICATE REQUEST") {
		t.Fatal("not an in-memory RSA CSR")
	}
	keyBlock, _ := pem.Decode([]byte(key))
	csrBlock, _ := pem.Decode([]byte(csr))
	rsaKey, e := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	request, e := x509.ParseCertificateRequest(csrBlock.Bytes)
	if e != nil || request.CheckSignature() != nil {
		t.Fatal("CSR has no valid proof of possession")
	}
	public, ok := request.PublicKey.(*rsa.PublicKey)
	if !ok || public.N.Cmp(rsaKey.N) != 0 || public.E != rsaKey.E {
		t.Fatal("CSR is not bound to generated private key")
	}
}
