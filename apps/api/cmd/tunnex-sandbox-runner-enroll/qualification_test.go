package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/sandboxrunner"
)

func reportFixture() (nativeReport, bootstrapBundle, reportConfiguration) {
	var cfg reportConfiguration
	cfg.SourceSHA = strings.Repeat("1", 40)
	cfg.Images = append(cfg.Images, struct {
		TemplateID            string `json:"template_id"`
		Path                  string `json:"path"`
		SHA256                string `json:"sha256"`
		ConfigDigest          string `json:"config_digest"`
		Architecture          string `json:"architecture"`
		QualificationEvidence string `json:"qualification_evidence"`
	}{ConfigDigest: "sha256:" + strings.Repeat("a", 64)})
	bundle := bootstrapBundle{EnrollmentID: "00000000-0000-4000-8000-000000000001", ProfileID: "00000000-0000-4000-8000-000000000002", BindingSHA256: strings.Repeat("b", 64)}
	report := nativeReport{Version: 1, EnrollmentID: bundle.EnrollmentID, ProfileID: bundle.ProfileID, BindingSHA256: bundle.BindingSHA256, SourceSHA: cfg.SourceSHA, StartedAt: time.Now().Add(-time.Second), FinishedAt: time.Now(), ImageConfigDigests: []string{cfg.Images[0].ConfigDigest}}
	report.Platform.OS = "linux"
	report.Platform.Version = "ubuntu 26.04"
	report.Platform.Architecture = "amd64"
	for _, code := range []string{"host-capabilities", "approved-image-load", "bounded-provider-start-stop", "offline-expiry-fence", "private-network-connectivity"} {
		report.Checks = append(report.Checks, nativeCheck{Code: code, Result: "unrun", Evidence: "Synthetic fixture; no native execution."})
	}
	return report, bundle, cfg
}

func TestQualificationReportPreservesUnrunAndBindsExactPublicPins(t *testing.T) {
	report, bundle, cfg := reportFixture()
	if validateNativeReport(report, bundle, cfg) != nil {
		t.Fatal("honest unrun report refused")
	}
	for _, mutate := range []func(*nativeReport){
		func(r *nativeReport) { r.EnrollmentID = "different" },
		func(r *nativeReport) { r.BindingSHA256 = strings.Repeat("c", 64) },
		func(r *nativeReport) { r.SourceSHA = strings.Repeat("2", 40) },
		func(r *nativeReport) { r.Platform.Architecture = "arm64" },
		func(r *nativeReport) { r.Checks[0].Result = "pretend-ready" },
		func(r *nativeReport) { r.Checks[1].Code = r.Checks[0].Code },
		func(r *nativeReport) { r.Checks[0].Evidence = strings.Repeat("x", 1025) },
		func(r *nativeReport) { r.ImageConfigDigests[0] = "sha256:" + strings.Repeat("c", 64) },
		func(r *nativeReport) { r.FinishedAt = r.StartedAt.Add(-time.Second) },
	} {
		candidate := report
		candidate.Checks = append([]nativeCheck(nil), report.Checks...)
		candidate.ImageConfigDigests = append([]string(nil), report.ImageConfigDigests...)
		mutate(&candidate)
		if validateNativeReport(candidate, bundle, cfg) == nil {
			t.Fatal("changed report authority accepted")
		}
	}
}

func TestQualificationUsesRealMTLSAndPinsControllerIdentity(t *testing.T) {
	const controllerURI = "spiffe://tunnex.example/sandbox-controller/fixture"
	const runnerURI = "spiffe://tunnex.example/sandbox-runner/fixture"
	identities, err := sandboxrunner.Enroll("controller.fixture", controllerURI, runnerURI, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	serverCertificate, err := tls.X509KeyPair(identities.ControllerCertificate, identities.ControllerKey)
	if err != nil {
		t.Fatal(err)
	}
	runnerCertificate, err := tls.X509KeyPair(identities.RunnerCertificate, identities.RunnerKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(identities.CA)
	calls := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.String() != "/internal/sandbox-runners/v1/qualification" || r.Header.Get("Content-Type") != "application/json" || r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.TLS.VerifiedChains[0][0].URIs[0].String() != runnerURI {
			t.Error("report lacked exact current mutual TLS boundary")
		}
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "PRIVATE KEY") {
			t.Error("private key in qualification report")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCertificate}, MinVersion: tls.VersionTLS13, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}
	server.StartTLS()
	defer server.Close()
	report, _, cfg := reportFixture()
	cfg.Controller.URL = server.URL
	cfg.Controller.ServerName = "controller.fixture"
	cfg.Controller.URI = controllerURI
	client, origin, err := qualificationClient(cfg, runnerCertificate, roots)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(report)
	if sendQualification(context.Background(), client, origin, raw) != nil || calls != 1 {
		t.Fatal("actual mutual TLS report failed")
	}
	cfg.Controller.URI = "spiffe://tunnex.example/unrelated-controller"
	client, origin, err = qualificationClient(cfg, runnerCertificate, roots)
	if err != nil {
		t.Fatal(err)
	}
	if sendQualification(context.Background(), client, origin, raw) == nil || calls != 1 {
		t.Fatal("different controller URI accepted report")
	}
}

func TestQualificationMetadataAcceptanceDoesNotTrustSuccessBodies(t *testing.T) {
	for _, code := range []int{200, 401, 403, 409, 503} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code); io.WriteString(w, `{"ready":true}`) }))
		err := sendQualification(context.Background(), server.Client(), server.URL, []byte(`{"version":1}`))
		server.Close()
		if err == nil {
			t.Fatal("unexpected status or pretend-ready body accepted")
		}
	}
	if sendQualification(context.Background(), http.DefaultClient, "https://never-contact.example.invalid", make([]byte, reportLimit+1)) == nil {
		t.Fatal("oversized report accepted")
	}
}

func TestTrialStatusAndWitnessUseCurrentMTLSExactPublicBindings(t *testing.T) {
	const controllerURI = "spiffe://tunnex.example/sandbox-controller/trial-fixture"
	const runnerURI = "spiffe://tunnex.example/sandbox-runner/trial-fixture"
	const trialID = "00000000-0000-4000-8000-000000000005"
	identities, err := sandboxrunner.Enroll("controller.fixture", controllerURI, runnerURI, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	serverCertificate, err := tls.X509KeyPair(identities.ControllerCertificate, identities.ControllerKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(identities.CA)
	_, bundle, cfg := reportFixture()
	status := trialStatus{Version: 1, EnrollmentID: bundle.EnrollmentID, ProfileID: bundle.ProfileID, BindingSHA256: bundle.BindingSHA256,
		SourceSHA: cfg.SourceSHA, TrialID: trialID, SandboxID: "00000000-0000-4000-8000-000000000006", RuntimeID: strings.Repeat("a", 64), Generation: 3,
		CreatedAt: time.Now().Add(-500 * time.Second), ExpiresAt: time.Now().Add(40 * time.Second), Phase: "awaiting_expiry"}
	proof := strings.Repeat("d", 64)
	status.ProofSHA256 = &proof
	wrongBinding := false
	witnessCalls := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || r.TLS.VerifiedChains[0][0].URIs[0].String() != runnerURI {
			t.Error("trial endpoint lacked exact mutual TLS identity")
		}
		body, _ := io.ReadAll(r.Body)
		if r.URL.String() == "/internal/sandbox-runners/v1/qualification-trials/"+trialID+"/status" {
			if len(body) != 0 {
				t.Error("status request supplied authority body")
			}
			copy := status
			if wrongBinding {
				copy.BindingSHA256 = strings.Repeat("e", 64)
			}
			json.NewEncoder(w).Encode(copy)
			return
		}
		if r.URL.String() == "/internal/sandbox-runners/v1/qualification-trials/"+trialID+"/witness" {
			if bytes.Contains(body, []byte("PRIVATE KEY")) {
				t.Error("private identity in witness")
			}
			witnessCalls++
			w.WriteHeader(204)
			return
		}
		w.WriteHeader(404)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCertificate}, MinVersion: tls.VersionTLS13, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}
	server.StartTLS()
	defer server.Close()
	root := t.TempDir()
	write := func(name string, raw []byte) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	cfg.Controller.URL, cfg.Controller.ServerName, cfg.Controller.URI = server.URL, "controller.fixture", controllerURI
	cfg.Credentials.Certificate = write("runner-cert.pem", identities.RunnerCertificate)
	cfg.Credentials.Key = write("runner-key.pem", identities.RunnerKey)
	cfg.Credentials.CA = write("runner-ca.pem", identities.CA)
	raw, _ := json.Marshal(cfg)
	configPath := write("configuration.json", raw)
	raw, _ = json.Marshal(bundle)
	write("enrollment.json", raw)
	var output bytes.Buffer
	if trialExchange(trialID, "", configPath, root, &output) != nil {
		t.Fatal("bound authenticated status refused")
	}
	var got trialStatus
	if decodeStrict(output.Bytes(), &got) != nil || got.ProofSHA256 == nil || *got.ProofSHA256 != proof {
		t.Fatal("public proof status lost")
	}
	wrongBinding = true
	if trialExchange(trialID, "", configPath, root, io.Discard) == nil {
		t.Fatal("changed trial binding accepted")
	}
	wrongBinding = false
	witness := write("witness.json", []byte(`{"version":1,"trial_id":"`+trialID+`"}`))
	if trialExchange(trialID, witness, configPath, root, io.Discard) != nil || witnessCalls != 1 {
		t.Fatal("scoped mutual TLS witness transport failed")
	}
	if trialExchange("../../other", witness, configPath, root, io.Discard) == nil {
		t.Fatal("caller path entered trial endpoint")
	}
}
