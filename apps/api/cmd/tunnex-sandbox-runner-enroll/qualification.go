package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

const reportLimit = 16 << 10

var errReport = errors.New("qualification_report_refused")

type nativeCheck struct {
	Code     string `json:"code"`
	Result   string `json:"result"`
	Evidence string `json:"evidence"`
}
type nativeReport struct {
	Version       int    `json:"version"`
	EnrollmentID  string `json:"enrollment_id"`
	ProfileID     string `json:"profile_id"`
	BindingSHA256 string `json:"binding_sha256"`
	SourceSHA     string `json:"source_sha"`
	Platform      struct {
		OS           string `json:"os"`
		Version      string `json:"version"`
		Architecture string `json:"architecture"`
	} `json:"platform"`
	Checks             []nativeCheck `json:"checks"`
	ImageConfigDigests []string      `json:"image_config_digests"`
	StartedAt          time.Time     `json:"started_at"`
	FinishedAt         time.Time     `json:"finished_at"`
}

type reportConfiguration struct {
	EnrollmentID   string          `json:"enrollment_id,omitempty"`
	Version        int             `json:"version"`
	Edition        string          `json:"edition"`
	SourceSHA      string          `json:"source_sha"`
	Bundle         json.RawMessage `json:"bundle"`
	Installation   json.RawMessage `json:"installation"`
	OrgID          string          `json:"org_id"`
	Gateway        json.RawMessage `json:"gateway"`
	ProbePublicKey string          `json:"probe_public_key"`
	Images         []struct {
		TemplateID            string `json:"template_id"`
		Path                  string `json:"path"`
		SHA256                string `json:"sha256"`
		ConfigDigest          string `json:"config_digest"`
		Architecture          string `json:"architecture"`
		QualificationEvidence string `json:"qualification_evidence"`
	} `json:"images"`
	Controller struct {
		URL        string `json:"url"`
		ServerName string `json:"server_name"`
		URI        string `json:"uri"`
		APIURL     string `json:"api_url"`
	} `json:"controller"`
	Credentials struct {
		ProbeKey    string `json:"probe_key"`
		APICA       string `json:"api_ca"`
		Certificate string `json:"runner_certificate"`
		Key         string `json:"runner_key"`
		CA          string `json:"runner_ca"`
	} `json:"credentials"`
}

func lowerHash(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func machineFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errReport
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, errReport
	}
	defer root.Close()
	return privateRead(root, filepath.Base(path))
}

func validateNativeReport(report nativeReport, bundle bootstrapBundle, cfg reportConfiguration) error {
	if report.Version != 1 || report.EnrollmentID != bundle.EnrollmentID || report.ProfileID != bundle.ProfileID || report.BindingSHA256 != bundle.BindingSHA256 || report.SourceSHA != cfg.SourceSHA || !lowerHash(report.SourceSHA, 40) || report.Platform.OS != "linux" || report.Platform.Architecture != "amd64" || report.Platform.Version == "" || len(report.Platform.Version) > 128 || report.StartedAt.IsZero() || report.FinishedAt.Before(report.StartedAt) || report.FinishedAt.After(time.Now().Add(time.Minute)) || report.FinishedAt.Sub(report.StartedAt) > 30*time.Minute || len(report.Checks) != 5 || len(report.ImageConfigDigests) != len(cfg.Images) || len(cfg.Images) < 1 || len(cfg.Images) > 4 {
		return errReport
	}
	required := map[string]bool{"host-capabilities": true, "approved-image-load": true, "bounded-provider-start-stop": true, "offline-expiry-fence": true, "private-network-connectivity": true}
	for _, check := range report.Checks {
		if !required[check.Code] || (check.Result != "passed" && check.Result != "failed" && check.Result != "unrun") || check.Evidence == "" || len(check.Evidence) > 1024 {
			return errReport
		}
		delete(required, check.Code)
	}
	for index, digest := range report.ImageConfigDigests {
		if digest != cfg.Images[index].ConfigDigest {
			return errReport
		}
	}
	return nil
}

func qualificationClient(cfg reportConfiguration, cert tls.Certificate, roots *x509.CertPool) (*http.Client, string, error) {
	origin, err := apiOrigin(cfg.Controller.URL)
	if err != nil || cfg.Controller.ServerName == "" || cfg.Controller.URI == "" || roots == nil || len(cert.Certificate) == 0 {
		return nil, "", errReport
	}
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{MaxResponseHeaderBytes: 8192, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: cfg.Controller.ServerName, RootCAs: roots, Certificates: []tls.Certificate{cert}, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 || len(state.VerifiedChains[0][0].URIs) != 1 || state.VerifiedChains[0][0].URIs[0].String() != cfg.Controller.URI {
			return errReport
		}
		return nil
	}}}}
	return client, origin, nil
}

func sendQualification(ctx context.Context, client *http.Client, origin string, raw []byte) error {
	if len(raw) > reportLimit {
		return errReport
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/internal/sandbox-runners/v1/qualification", bytes.NewReader(raw))
	if err != nil {
		return errReport
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return errReport
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, reportLimit+1))
	if response.StatusCode != http.StatusNoContent {
		return errReport
	}
	return nil
}

func uploadQualification(reportPath, configurationPath, identityPath string) error {
	raw, err := machineFile(reportPath)
	if err != nil || len(raw) > reportLimit {
		return errReport
	}
	configRaw, err := machineFile(configurationPath)
	if err != nil {
		return errReport
	}
	bundleRaw, err := machineFile(filepath.Join(identityPath, "enrollment.json"))
	if err != nil {
		return errReport
	}
	var report nativeReport
	var cfg reportConfiguration
	var bundle bootstrapBundle
	if decodeStrict(raw, &report) != nil || decodeStrict(configRaw, &cfg) != nil || decodeStrict(bundleRaw, &bundle) != nil || validateNativeReport(report, bundle, cfg) != nil {
		return errReport
	}
	certRaw, err := machineFile(cfg.Credentials.Certificate)
	if err != nil {
		return errReport
	}
	keyRaw, err := machineFile(cfg.Credentials.Key)
	if err != nil {
		return errReport
	}
	caRaw, err := machineFile(cfg.Credentials.CA)
	if err != nil {
		return errReport
	}
	certificate, err := tls.X509KeyPair(certRaw, keyRaw)
	if err != nil {
		return errReport
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caRaw) {
		return errReport
	}
	client, origin, err := qualificationClient(cfg, certificate, roots)
	if err != nil {
		return errReport
	}
	return sendQualification(context.Background(), client, origin, raw)
}

type trialStatus struct {
	Version              int        `json:"version"`
	EnrollmentID         string     `json:"enrollment_id"`
	ProfileID            string     `json:"profile_id"`
	BindingSHA256        string     `json:"binding_sha256"`
	SourceSHA            string     `json:"source_sha"`
	TrialID              string     `json:"trial_id"`
	SandboxID            string     `json:"sandbox_id"`
	RuntimeID            string     `json:"runtime_id"`
	Generation           int64      `json:"generation"`
	CreatedAt            time.Time  `json:"created_at"`
	ExpiresAt            time.Time  `json:"expires_at"`
	Phase                string     `json:"phase"`
	InitialReadyAt       *time.Time `json:"initial_ready_at,omitempty"`
	StoppedAt            *time.Time `json:"stopped_at,omitempty"`
	ResumeReadyAt        *time.Time `json:"resume_ready_at,omitempty"`
	RetiredAt            *time.Time `json:"retired_at,omitempty"`
	OfflineWitnessSHA256 *string    `json:"offline_witness_sha256,omitempty"`
	ProofSHA256          *string    `json:"proof_sha256,omitempty"`
}

func trialExchange(trial, witnessPath, configurationPath, identityPath string, output io.Writer) error {
	id, err := uuid.Parse(trial)
	if err != nil || id == uuid.Nil || id.String() != trial {
		return errReport
	}
	configRaw, err := machineFile(configurationPath)
	if err != nil {
		return errReport
	}
	bundleRaw, err := machineFile(filepath.Join(identityPath, "enrollment.json"))
	if err != nil {
		return errReport
	}
	var cfg reportConfiguration
	var bundle bootstrapBundle
	if decodeStrict(configRaw, &cfg) != nil || decodeStrict(bundleRaw, &bundle) != nil {
		return errReport
	}
	certRaw, err := machineFile(cfg.Credentials.Certificate)
	if err != nil {
		return errReport
	}
	keyRaw, err := machineFile(cfg.Credentials.Key)
	if err != nil {
		return errReport
	}
	caRaw, err := machineFile(cfg.Credentials.CA)
	if err != nil {
		return errReport
	}
	certificate, err := tls.X509KeyPair(certRaw, keyRaw)
	if err != nil {
		return errReport
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caRaw) {
		return errReport
	}
	client, origin, err := qualificationClient(cfg, certificate, roots)
	if err != nil {
		return errReport
	}
	operation := "status"
	var payload []byte
	if witnessPath != "" {
		operation = "witness"
		payload, err = machineFile(witnessPath)
		if err != nil || len(payload) > reportLimit || !json.Valid(payload) {
			return errReport
		}
	}
	request, err := http.NewRequest(http.MethodPost, origin+"/internal/sandbox-runners/v1/qualification-trials/"+id.String()+"/"+operation, bytes.NewReader(payload))
	if err != nil {
		return errReport
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return errReport
	}
	defer response.Body.Close()
	if witnessPath != "" {
		if response.StatusCode != http.StatusNoContent {
			return errReport
		}
		return nil
	}
	if response.StatusCode != http.StatusOK {
		return errReport
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, reportLimit+1))
	var status trialStatus
	if err != nil || len(raw) > reportLimit || decodeStrict(raw, &status) != nil || status.Version != 1 || status.TrialID != trial || status.EnrollmentID != bundle.EnrollmentID || status.ProfileID != bundle.ProfileID || status.BindingSHA256 != bundle.BindingSHA256 || status.SourceSHA != cfg.SourceSHA {
		return errReport
	}
	_, err = output.Write(raw)
	return err
}
