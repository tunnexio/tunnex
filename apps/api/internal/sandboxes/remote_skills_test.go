package sandboxes

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/sandboxrunner"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"golang.org/x/crypto/ssh"
)

// This fixture uses real mutually authenticated TLS and the runner polling
// loop. Providers, approved revisions and credentials are disposable local
// fixtures; there is no PostgreSQL, workload execution or live enrollment.
func remoteSkillsTLSFixture(t *testing.T, binding BoundedRuntimeBinding) (*WorkerRPCServer, *WorkerRPCClient, context.Context) {
	t.Helper()
	worker, _, _ := persistentRPCFixture(t, binding)
	enrollment, err := sandboxrunner.Enroll("localhost", "spiffe://tunnex/controller/skills-fixture", "spiffe://tunnex/runner/skills-fixture", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	controller, err := tls.X509KeyPair(enrollment.ControllerCertificate, enrollment.ControllerKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(enrollment.RunnerCertificate, enrollment.RunnerKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(enrollment.CA) {
		t.Fatal("fixture CA invalid")
	}
	broker, err := sandboxrunner.NewBroker("spiffe://tunnex/runner/skills-fixture")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(broker)
	server.TLS, err = sandboxrunner.TLSConfig(controller, roots)
	if err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	runner, err := sandboxrunner.NewClient(server.URL, "localhost", "spiffe://tunnex/controller/skills-fixture", certificate, roots, root)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	done := make(chan error, 1)
	go func() { done <- worker.RunRemoteWorker(ctx, runner, sandboxrunner.LeaseStore{Root: root}) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("fixture remote worker did not stop")
		}
	})
	client := &WorkerRPCClient{client: &http.Client{Transport: brokerTransport{broker}, Timeout: 10 * time.Second}, probe: worker.Identity.PublicKey()}
	return worker, client, ctx
}

func TestRemoteSkillsMaximumValidBundleActualTLS(t *testing.T) {
	if sandboxrunner.PayloadLimit != workerRPCLimit {
		t.Fatalf("remote payload bound differs from existing worker RPC: remote=%d worker=%d", sandboxrunner.PayloadLimit, workerRPCLimit)
	}
	selected := make([]SkillSelection, 0, 16)
	approved := map[string]SkillRevision{}
	for i := range 16 {
		revision := testSkill()
		revision.Name = fmt.Sprintf("Large inert fixture %02d", i)
		revision.Instructions = strings.Repeat("i", 32768)
		hash := sha256.Sum256([]byte(revision.Instructions))
		revision.Digest = hex.EncodeToString(hash[:])
		revision.RequiredScope = []Scope{}
		revision.Fields = nil
		configuration := map[string]string{}
		for field := range 16 {
			key := fmt.Sprintf("field_%02d_", field) + strings.Repeat("x", 31)
			value := strings.Repeat("v", 80)
			revision.Fields = append(revision.Fields, SkillField{Key: key, Label: "Bounded inert fixture field", Choices: []string{value}, Required: true})
			configuration[key] = value
		}
		approved[revision.ID.String()] = revision
		selected = append(selected, SkillSelection{RevisionID: revision.ID, Configuration: configuration})
	}
	files, err := PrepareSkillBundle(selected, approved, nil, nil)
	if err != nil || len(files) != 32 {
		t.Fatalf("maximum valid inert bundle rejected: files=%d error=%v", len(files), err)
	}
	if _, err = PrepareSkillBundle(append(selected, selected[0]), approved, nil, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("16-skill selection bound widened", err)
	}
	binding := persistentTestBinding()
	worker, client, ctx := remoteSkillsTLSFixture(t, binding)
	if err = client.CheckBinding(ctx, binding); err != nil {
		t.Fatal("remote binding", err)
	}
	authorization := testAuthorization(binding, 0)
	if err = client.AuthorizeRuntime(ctx, authorization); err != nil {
		t.Fatal("remote authorization", err)
	}
	specHash, err := sandboxruntime.Fingerprint(authorization.spec())
	if err != nil {
		t.Fatal(err)
	}
	plan := WorkspacePlan{Authorization: &authorization, SandboxID: authorization.SandboxID, OrgID: authorization.OrgID, Generation: 1, SpecHash: specHash, Files: files}
	keys := []string{publicTerminalKey(t)}
	wire, err := json.Marshal(workerRequest{Version: workerRPCVersion, Operation: "materialize", ID: plan.SandboxID, Generation: 1, Plan: &plan, Keys: keys})
	if err != nil || len(wire) <= 64<<10 || len(wire) > sandboxrunner.PayloadLimit {
		t.Fatalf("regression fixture outside intended transport range: bytes=%d limit=%d error=%v", len(wire), sandboxrunner.PayloadLimit, err)
	}
	t.Logf("16 skills, 32768 instruction bytes each, 16 configured fields each, 32 inert files; materialize RPC=%d bytes; limit=%d", len(wire), sandboxrunner.PayloadLimit)
	assets, terminal, err := client.MaterializeCreationAssets(ctx, plan, keys)
	if err != nil {
		t.Fatal("maximum bundle over actual TLS", err)
	}
	canonicalRoot, err := filepath.EvalSymlinks(worker.AssetsRoot.Name())
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(canonicalRoot, plan.SandboxID.String())
	if assets.SandboxID != plan.SandboxID || assets.SpecHash != specHash || assets.Workspace != filepath.Join(base, "workspace") || assets.SSH != filepath.Join(base, "terminal") || filepath.Base(assets.Skills) != "skills" || filepath.Dir(filepath.Dir(assets.Skills)) != base {
		t.Fatal("remote assets escaped the pinned worker/sandbox roots")
	}
	skillDirectory := filepath.Dir(assets.Skills)
	manifest, err := os.ReadFile(filepath.Join(skillDirectory, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifestHash := sha256.Sum256(manifest)
	if filepath.Base(skillDirectory) != "skills-"+hex.EncodeToString(manifestHash[:]) {
		t.Fatal("materialized directory does not bind manifest digest")
	}
	var delivered []deliveredFile
	if err = json.Unmarshal(manifest, &delivered); err != nil || len(delivered) != len(files) {
		t.Fatal("manifest file count mismatch", err)
	}
	wantDigests := map[string]string{}
	for _, file := range files {
		wantDigests[file.Path] = file.Digest
		name := filepath.Join(skillDirectory, filepath.FromSlash(file.Path))
		content, err := os.ReadFile(name)
		if err != nil || !bytes.Equal(content, file.Content) {
			t.Fatalf("skill/config content changed at %s: %v", file.Path, err)
		}
		hash := sha256.Sum256(content)
		if hex.EncodeToString(hash[:]) != file.Digest {
			t.Fatalf("skill/config digest changed at %s", file.Path)
		}
		info, err := os.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatalf("skill/config is not a private inert regular file: %s %v", file.Path, err)
		}
	}
	for _, entry := range delivered {
		if wantDigests[entry.Path] != entry.Digest {
			t.Fatal("manifest contains an unexpected path or digest")
		}
		delete(wantDigests, entry.Path)
	}
	if len(wantDigests) != 0 {
		t.Fatal("manifest omitted a selected skill/config")
	}
	fileCount := 0
	if err = filepath.WalkDir(assets.Skills, func(_ string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			fileCount++
		}
		return nil
	}); err != nil || fileCount != 32 {
		t.Fatal("unexpected files in materialized skill tree", fileCount, err)
	}
	digest, err := sandboxruntime.AssetContentDigest(assets.Skills, assets.SSH)
	if err != nil || digest != assets.Digest {
		t.Fatal("aggregate asset digest does not verify", err)
	}
	verified, err := client.VerifyTerminalAssets(ctx, assets)
	if err != nil || terminal.HostPublicKey != string(ssh.MarshalAuthorizedKey(verified)) {
		t.Fatal("remote public terminal identity verification", err)
	}
	// A separate command replay must retain both content and terminal identity.
	replayed, replayedTerminal, err := client.MaterializeCreationAssets(ctx, plan, keys)
	if err != nil || replayed != assets || !reflect.DeepEqual(replayedTerminal, terminal) {
		t.Fatal("remote materialization retry changed assets or identity", err)
	}
	status, err := client.Inspect(ctx, plan.SandboxID)
	if !errors.Is(err, sandboxruntime.ErrMissing) || status.Exists || status.Running {
		t.Fatal("inert skill delivery launched a provider workload", err)
	}
}
