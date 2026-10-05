package sandboxes

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Historical, synthetic controller receipts test the complete proof/report
// contract without waiting900seconds or claiming native physical measurements.
// The separate composed fixture tests actual source start/stop/resume/retirement.
func TestRunnerTrialPostgresRealMachineReportRequiresCanonicalProofAndHumanReview(t *testing.T) {
	f, b, ctx, s, leaf, in, enrollmentID := runnerTrialFixture(t)
	id, sandbox := uuid.New(), uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	created := now.Add(-910 * time.Second)
	expires := created.Add(900 * time.Second)
	initial, stopped, resumed, retired := created.Add(time.Second), created.Add(2*time.Second), created.Add(3*time.Second), expires.Add(4*time.Second)
	runtime := strings.Repeat("c", 64)
	er, err := s.read(f.ctx, f.pool, enrollmentID, false)
	if err != nil {
		t.Fatal(err)
	}
	// Explicit fixture-only administrative opt-in permits constructing history;
	// it is reset before report submission and never changed by trial product code.
	devExec(t, f, `UPDATE organizations SET sandboxes_enabled=true WHERE id=$1`, f.org)
	keys, _ := json.Marshal(in.SSHPublicKeys)
	devExec(t, f, `INSERT INTO sandboxes(id,org_id,creator_id,template_id,name,requested_scope,idempotency_key,request_hash,created_at,expires_at,selected_skills,ssh_public_keys,terminal_device_id,local_terminal_gateway_id,desired_state,observed_state,generation) VALUES($1,$2,$3,$4,'historical source fixture','[]',$5,$6,$7,$8,'[]',$9,$10,$11,'deleted','deleted',4)`, sandbox, f.org, f.user, b.Profiles[0].TemplateID, id.String(), make([]byte, 32), created, expires, keys, in.TerminalDeviceID, f.node)
	devExec(t, f, `INSERT INTO sandbox_runtime_bindings(sandbox_id,org_id,spec_hash,image_digest,memory_mib,cpus,pids,runtime_id,worker_retired_at) VALUES($1,$2,$3,$4,128,1,64,$5,$6)`, sandbox, f.org, strings.Repeat("d", 64), b.Profiles[0].ConfigDigest, runtime, retired)
	devExec(t, f, `INSERT INTO sandbox_runner_workloads(sandbox_id,org_id,enrollment_id) VALUES($1,$2,$3)`, sandbox, f.org, enrollmentID)
	devExec(t, f, `INSERT INTO sandbox_runner_qualification_trials(id,org_id,enrollment_id,sandbox_id,creator_id,terminal_device_id,profile_id,template_id,binding_hash,spki_hash,source_sha,image_digest,idempotency_key,request_hash,created_at,expires_at,phase,runtime_id,initial_ready_at,stopped_at,resume_ready_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,'cleanup_pending',$17,$18,$19,$20)`, id, f.org, enrollmentID, sandbox, f.user, in.TerminalDeviceID, s.config.Profile.ID, b.Profiles[0].TemplateID, s.bindingHash, er.keyHash, s.config.Profile.Install.SourceSHA, b.Profiles[0].ConfigDigest, uuid.New(), make([]byte, 32), created, expires, runtime, initial, stopped, resumed)
	devExec(t, f, `UPDATE organizations SET sandboxes_enabled=false WHERE id=$1`, f.org)
	for i, code := range []string{"initial_ready", "stopped", "resume_ready"} {
		raw, _ := json.Marshal(map[string]any{"source_fixture": true, "canonical_transition": code, "generation": i + 1, "ssh_origin": "runner"})
		hash := sha256.Sum256(raw)
		devExec(t, f, `INSERT INTO sandbox_runner_qualification_events(trial_id,code,generation,observed_at,evidence,evidence_hash) VALUES($1,$2,$3,$4,$5,$6)`, id, code, i+1, []time.Time{initial, stopped, resumed}[i], raw, hash[:])
	}
	witness := RunnerQualificationOfflineWitness{Version: 1, TrialID: id, SandboxID: sandbox, RuntimeID: runtime, Generation: 3, BindingSHA256: hex.EncodeToString(s.bindingHash), SourceSHA: s.config.Profile.Install.SourceSHA, CreatedAt: created, ExpiresAt: expires, TransportStoppedAt: expires.Add(-5 * time.Second), ActorExpiredAt: expires.Add(time.Second), StoppedObservedAt: expires.Add(2 * time.Second), TransportResumedAt: expires.Add(3 * time.Second), ImageDigest: b.Profiles[0].ConfigDigest, MemoryMaxBytes: 134217728, PIDsMax: 64, CPUQuotaUS: 100000, CPUPeriodUS: 100000, ObserverSHA256: s.config.Profile.BootstrapScript.SHA256}
	wrong := *leaf
	wrong.RawSubjectPublicKeyInfo = []byte("different key")
	if err = s.SubmitQualificationOfflineWitness(f.ctx, &wrong, id, witness); !errors.Is(err, ErrForbidden) {
		t.Fatal("foreign witness credential", err)
	}
	if err = s.SubmitQualificationOfflineWitness(f.ctx, leaf, id, witness); err != nil {
		t.Fatal("exact witness", err)
	}
	if err = s.SubmitQualificationOfflineWitness(f.ctx, leaf, id, witness); err != nil {
		t.Fatal("idempotent witness", err)
	}
	changed := witness
	changed.StoppedObservedAt = changed.StoppedObservedAt.Add(time.Second)
	if err = s.SubmitQualificationOfflineWitness(f.ctx, leaf, id, changed); !errors.Is(err, ErrConflict) {
		t.Fatal("witness replacement", err)
	}
	if err = s.PumpQualificationTrials(f.ctx); err != nil {
		t.Fatal(err)
	}
	view, err := s.QualificationMachineView(f.ctx, leaf, id)
	if err != nil || view.ProofSHA256 == "" || view.Phase != "complete" {
		t.Fatal("complete canonical proof", view, err)
	}
	report := machineTrialReport(t, s, view)
	if err = s.VerifyRunnerQualification(f.ctx, enrollmentID, report); err != nil {
		t.Fatal("actual producer report interop", err)
	}
	record, err := s.SubmitQualification(f.ctx, leaf, report)
	if err != nil || !record.Approvable || record.Decision != "pending" {
		t.Fatal("reviewable exact report", record.BlockedReasons, err)
	}
	if s.RuntimeReady(f.ctx) {
		t.Fatal("machine report self-approved Ready")
	}
	tampered := report
	tampered.Checks = append([]RunnerQualificationCheck(nil), report.Checks...)
	tampered.Checks[2].Evidence = "host says passed"
	if err = s.VerifyRunnerQualification(f.ctx, enrollmentID, tampered); !errors.Is(err, ErrDisabled) {
		t.Fatal("host boolean bypass", err)
	}
	if _, err = s.ReviewQualification(ctx, f.org, f.user, enrollmentID, RunnerQualificationReview{ExpectedReportSHA256: record.ReportSHA256, Decision: "approve", ReviewNote: "Synthetic contract fixture only; not native qualification"}); err != nil {
		t.Fatal("human exact report review", err)
	}
	c, err := s.AuthorizeCertificate(f.ctx, leaf)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RecordHealth(f.ctx, c, b); err != nil {
		t.Fatal(err)
	}
	if !s.RuntimeReady(f.ctx) {
		t.Fatal("reviewed actual binding did not become available")
	}
	// Source interoperability must preserve ordinary admin opt-in after trial.
	if _, _, err = f.store.Create(f.ctx, f.org, f.user, organizationInput(f, b, in.TerminalDeviceID, "before-optin")); !errors.Is(err, ErrDisabled) {
		t.Fatal("report enabled ordinary org", err)
	}
	devExec(t, f, `UPDATE organizations SET sandboxes_enabled=true WHERE id=$1`, f.org)
	devExec(t, f, `UPDATE sandbox_templates SET enabled=true WHERE id=$1`, b.Profiles[0].TemplateID)
	var otherTerminal uuid.UUID
	if err = f.pool.QueryRow(f.ctx, `SELECT id FROM devices WHERE org_id=$1 AND user_id=$2 AND kind='human'`, f.org, f.other).Scan(&otherTerminal); err != nil {
		t.Fatal(err)
	}
	ordinary, _, err := f.store.Create(f.ctx, f.org, f.other, organizationInput(f, b, otherTerminal, "different-authorized-user"))
	if err != nil || ordinary.Identity.CreatorID != f.other {
		t.Fatal("runner still bound to enrolling admin", err)
	}
}
func machineTrialReport(t *testing.T, s *RunnerQualificationService, view RunnerQualificationMachineView) RunnerQualificationReport {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "deploy", "sandbox", "install", "enroll.py")
	if _, err := os.Stat(path); err != nil {
		t.Fatal("integrated machine producer source required", err)
	}
	input := map[string]any{"cfg": map[string]any{"source_sha": s.config.Profile.Install.SourceSHA, "installation": map[string]any{"state_root": "/synthetic/state", "run_root": "/synthetic/run", "uid": 1001, "gid": 1001}, "images": []map[string]string{{"config_digest": s.binding.Profiles[0].ConfigDigest}}}, "bundle": map[string]string{"enrollment_id": view.EnrollmentID.String(), "profile_id": view.ProfileID.String(), "binding_sha256": view.BindingSHA256}, "view": view}
	raw, _ := json.Marshal(input)
	const script = `import importlib.util,json,sys,types
spec=importlib.util.spec_from_file_location("actual_machine_producer",sys.argv[1]);p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
a=json.load(sys.stdin)
class SyntheticHost:
 def read(self,path):
  assert path=="/etc/os-release";return 'ID=ubuntu\nVERSION_ID="26.04"\n'
 def run(self,args,**kwargs):
  assert args[0]=="/usr/bin/podman" and "inspect" in args and "image" in args
  assert kwargs["user"]==1001 and kwargs["extra_groups"]==[]
  return a["cfg"]["images"][0]["config_digest"]+" amd64 linux\n"
installer=types.SimpleNamespace(check=lambda cfg,host,installed_report:None)
print(json.dumps(p.completed_trial_report(a["cfg"],a["bundle"],installer,SyntheticHost(),a["view"],a["view"]["trial_id"])))`
	cmd := exec.Command("python3", "-c", script, path)
	cmd.Stdin = bytes.NewReader(raw)
	cmd.Env = append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal("real machine report producer", err, string(out))
	}
	var report RunnerQualificationReport
	if json.Unmarshal(out, &report) != nil {
		t.Fatal("real producer report schema")
	}
	return report
}
