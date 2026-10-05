package sandboxes

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/tunnexio/tunnex/apps/api/internal/sandboxrunner"
)

var runnerHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
var runnerSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)
var runnerInterface = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)

func runnerHTTPS(raw string, origin bool) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && len(raw) <= 2048 && (!origin || u.Path == "" || u.Path == "/")
}
func runnerCA(raw string) (*x509.Certificate, error) {
	b, rest := pem.Decode([]byte(raw))
	if b == nil || b.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 || len(raw) > 16384 {
		return nil, ErrInvalid
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil || !c.IsCA {
		return nil, ErrInvalid
	}
	return c, nil
}
func (c RunnerEnrollmentConfig) Validate(b BoundedRuntimeBinding) error {
	if b.Validate() != nil || !b.OrganizationScoped() || !b.Persistent() || c.Profile.ID == [16]byte{} || len(strings.TrimSpace(c.Profile.Name)) == 0 || len(c.Profile.Name) > 80 || c.Profile.Architecture != "amd64" || c.Profile.HostOS != "ubuntu" || c.Profile.HostVersion != "26.04" {
		return ErrInvalid
	}
	if _, err := sandboxrunner.NewBroker(c.RunnerURI); err != nil {
		return ErrInvalid
	}
	if _, err := runnerCA(c.RunnerCA); err != nil {
		return err
	}
	if c.APICA != "" {
		if _, err := runnerCA(c.APICA); err != nil {
			return err
		}
	}
	if c.QualifiedRunnerSPKIHash != "" && (!runnerHash.MatchString(c.QualifiedRunnerSPKIHash) || strings.TrimSpace(c.HostQualificationEvidence) == "" || len(c.HostQualificationEvidence) > 512) {
		return ErrInvalid
	}
	p := c.Profile.Install
	if p.Version != 1 || (p.Edition != "open" && p.Edition != "enterprise") || !runnerSHA.MatchString(p.SourceSHA) || p.OrgID != b.OrgID || p.Gateway.NodeID != b.GatewayID || !runnerHash.MatchString(p.Gateway.ContainerID) || !strings.HasPrefix(p.Gateway.ImageDigest, "sha256:") || !runnerHash.MatchString(strings.TrimPrefix(p.Gateway.ImageDigest, "sha256:")) || !runnerInterface.MatchString(p.Gateway.Interface) {
		return ErrInvalid
	}
	for _, a := range []RunnerArtifact{p.Bundle, c.Profile.BootstrapScript} {
		if !runnerHTTPS(a.URL, false) || !runnerHash.MatchString(a.SHA256) {
			return ErrInvalid
		}
	}
	if !runnerHTTPS(p.Controller.URL, true) || !runnerHTTPS(p.Controller.APIURL, true) || p.Controller.ServerName == "" {
		return ErrInvalid
	}
	if _, err := sandboxrunner.NewBroker(p.Controller.URI); err != nil || p.Controller.URI == c.RunnerURI {
		return ErrInvalid
	}
	if len(p.Images) != len(b.Profiles) {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, im := range p.Images {
		profile, ok := b.profile(im.TemplateID)
		if !ok || profile.PIDs != 64 || seen[im.TemplateID.String()] || im.Architecture != "amd64" || im.ConfigDigest != profile.ConfigDigest || im.QualificationEvidence != profile.QualificationEvidence || !runnerHTTPS(im.URL, false) || !runnerHash.MatchString(im.SHA256) {
			return ErrInvalid
		}
		seen[im.TemplateID.String()] = true
	}
	if b.RemoteTerminal == nil && p.Gateway.Terminal != nil || b.RemoteTerminal != nil && p.Gateway.Terminal == nil {
		return ErrInvalid
	}
	if t := p.Gateway.Terminal; t != nil {
		r := b.RemoteTerminal
		if t.NodeID != r.GatewayID || t.Endpoint != r.GatewayEndpoint || t.RuntimeEndpoint != r.RuntimeGatewayEndpoint {
			return ErrInvalid
		}
		for _, v := range []string{t.Endpoint, t.RuntimeEndpoint} {
			host, _, err := net.SplitHostPort(v)
			ip := net.ParseIP(host)
			if err != nil || ip == nil || !ip.IsPrivate() {
				return ErrInvalid
			}
		}
	}
	return nil
}
func NewRunnerEnrollmentService(store *Store, binding BoundedRuntimeBinding, config RunnerEnrollmentConfig, signer RunnerCSRSigner) (*RunnerEnrollmentService, error) {
	if store == nil || store.pool == nil || signer == nil || config.Validate(binding) != nil {
		return nil, ErrInvalid
	}
	// Snapshot public configuration; caller-owned slices cannot mutate authority.
	raw, err := json.Marshal(config)
	if err != nil {
		return nil, ErrInvalid
	}
	var frozen RunnerEnrollmentConfig
	if json.Unmarshal(raw, &frozen) != nil {
		return nil, ErrInvalid
	}
	frozen.ModuleState = config.ModuleState
	frozen.Profile.TerminalGatewayID = binding.terminalGatewayID()
	br, _ := json.Marshal(binding)
	hash := sha256.Sum256(br)
	var b BoundedRuntimeBinding
	if json.Unmarshal(br, &b) != nil {
		return nil, ErrInvalid
	}
	return &RunnerEnrollmentService{store: store, config: frozen, binding: b, bindingHash: hash[:], signer: signer}, nil
}
func shellRunnerValue(v string) string { return "'" + strings.ReplaceAll(v, "'", "'\"'\"'") + "'" }
func (s *RunnerEnrollmentService) installCommand(id string) string {
	p := s.config.Profile
	// Only public pins and UUIDs are present. The script prompts for the token;
	// it must never be interpolated into a shell command or URL.
	return fmt.Sprintf("d=$(mktemp -d) && curl --fail --silent --show-error --proto '=https' --tlsv1.2 %s -o \"$d/enroll.py\" && printf '%%s  %%s\\n' %s \"$d/enroll.py\" | sha256sum -c - && sudo python3 \"$d/enroll.py\" --enrollment-id %s --api-url %s --bundle-url %s --bundle-sha256 %s --source-sha %s --edition %s", shellRunnerValue(p.BootstrapScript.URL), shellRunnerValue(p.BootstrapScript.SHA256), shellRunnerValue(id), shellRunnerValue(p.Install.Controller.APIURL), shellRunnerValue(p.Install.Bundle.URL), shellRunnerValue(p.Install.Bundle.SHA256), shellRunnerValue(p.Install.SourceSHA), shellRunnerValue(p.Install.Edition))
}
func runnerKeyHash(c *x509.Certificate) []byte {
	h := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return h[:]
}
func (s *RunnerEnrollmentService) qualified(key []byte) bool {
	return s.config.QualifiedRunnerSPKIHash != "" && s.config.QualifiedRunnerSPKIHash == hex.EncodeToString(key) && s.config.HostQualificationEvidence != ""
}
