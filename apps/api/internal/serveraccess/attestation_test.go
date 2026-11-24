package serveraccess

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/packages/apptransport/bootstrap"
	"golang.org/x/crypto/ssh"
)

func testHostKey(t *testing.T) (string, string) {
	t.Helper()
	pub, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	key, e := ssh.NewPublicKey(pub)
	if e != nil {
		t.Fatal(e)
	}
	return ssh.FingerprintSHA256(key), string(ssh.MarshalAuthorizedKey(key))
}

func goAttestation(key, job string, fps []string) string {
	k, _ := base64.StdEncoding.DecodeString(key)
	sorted := append([]string(nil), fps...)
	sort.Strings(sorted)
	raw, _ := json.Marshal(attestationLine{V: 1, Job: job, HostKeys: sorted, MAC: hexMAC(k, job, sorted)})
	return bootstrap.AttestationPrefix + string(raw)
}
func hexMAC(k []byte, job string, fps []string) string {
	const digits = "0123456789abcdef"
	sum := attestationMAC(k, job, fps)
	out := make([]byte, 0, len(sum)*2)
	for _, b := range sum {
		out = append(out, digits[b>>4], digits[b&15])
	}
	return string(out)
}

func TestHostKeyAttestationBindsSeenKeyToJob(t *testing.T) {
	key, _ := newAttestationKey()
	other, _ := newAttestationKey()
	job := uuid.NewString()
	seen, _ := testHostKey(t)
	extra, _ := testHostKey(t)
	good := goAttestation(key, job, []string{seen, extra})
	if e := verifyHostKeyAttestation(key, job, seen, good); e != nil {
		t.Fatal(e)
	}
	attacker, _ := testHostKey(t)
	for name, c := range map[string]struct{ key, job, seen, raw string }{
		"attacker host key not attested": {key, job, attacker, good},
		"wrong attestation key":          {other, job, seen, good},
		"replayed for another job":       {key, uuid.NewString(), seen, good},
		"forged without key":             {key, job, attacker, goAttestation(other, job, []string{attacker})},
		"missing":                        {key, job, seen, ""},
		"malformed":                      {key, job, seen, bootstrap.AttestationPrefix + "{"},
		"empty list":                     {key, job, seen, goAttestation(key, job, nil)},
		"unknown field":                  {key, job, seen, strings.Replace(good, `"v":1`, `"v":1,"x":1`, 1)},
		"invalid seen":                   {key, job, "SHA256:bad", good},
	} {
		if verifyHostKeyAttestation(c.key, c.job, c.seen, c.raw) == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestEnrollmentHostKeyModes(t *testing.T) {
	key, _ := newAttestationKey()
	seen, _ := testHostKey(t)
	pinned, _ := testHostKey(t)
	j := enrollment{View: api.ServerAccessEnrollment{Id: uuid.New()}, AttestationKey: key}
	att := goAttestation(key, j.View.Id.String(), []string{seen})
	if e := verifyEnrollmentHostKey(j, bootstrap.Report{HostKey: seen, Attestation: att}); e != nil {
		t.Fatal(e)
	}
	// A manual pin must match what the gateway saw, and the attestation is still required.
	j.Material.Fingerprint = pinned
	if verifyEnrollmentHostKey(j, bootstrap.Report{HostKey: seen, Attestation: att}) == nil {
		t.Fatal("pin mismatch accepted")
	}
	j.Material.Fingerprint = seen
	if verifyEnrollmentHostKey(j, bootstrap.Report{HostKey: seen}) == nil {
		t.Fatal("attested job accepted without attestation")
	}
	// Gateways without attestation support: only with an administrator pin, exactly as before SA-UX-2.
	legacy := enrollment{Material: bootstrap.Job{Fingerprint: pinned}}
	if e := verifyEnrollmentHostKey(legacy, bootstrap.Report{}); e != nil {
		t.Fatal(e)
	}
	legacy.Material.Fingerprint = ""
	if verifyEnrollmentHostKey(legacy, bootstrap.Report{}) == nil {
		t.Fatal("unpinned, unattested result accepted")
	}
}

func TestAuthorizationCommandCarriesAttestationKeyOnlyWhenAttested(t *testing.T) {
	j := enrollment{View: api.ServerAccessEnrollment{Id: uuid.New()}, Material: bootstrap.Job{Account: "ubuntu", Script: "x"}}
	decode := func(cmd string) string {
		a := strings.Index(cmd, "b64decode('") + len("b64decode('")
		raw, e := base64.StdEncoding.DecodeString(cmd[a : a+strings.Index(cmd[a:], "'")])
		if e != nil {
			t.Fatal(e)
		}
		return string(raw)
	}
	setup := func() map[string]any {
		source := decode(authorizationCommand(j))
		inner := source[strings.Index(source, "SETUP = json.loads"):]
		var out map[string]any
		if e := json.Unmarshal([]byte(decode(inner)), &out); e != nil {
			t.Fatal(e)
		}
		return out
	}
	if _, ok := setup()["attest"]; ok {
		t.Fatal("attestation key in a legacy job command")
	}
	j.AttestationKey, _ = newAttestationKey()
	if setup()["attest"] != j.AttestationKey {
		t.Fatal("attestation key missing from the authorization command")
	}
	// The gateway material never carries the key.
	raw, _ := json.Marshal(j.Material)
	if strings.Contains(string(raw), j.AttestationKey) {
		t.Fatal("attestation key leaked into gateway material")
	}
}

// The real Python launcher code produces lines the Go verifier accepts, and its fingerprints match OpenSSH's.
func TestPythonAttestationRoundTrip(t *testing.T) {
	if _, e := exec.LookPath("python3"); e != nil {
		t.Skip("python3 not available")
	}
	key, _ := newAttestationKey()
	job := uuid.NewString()
	fp1, line1 := testHostKey(t)
	fp2, line2 := testHostKey(t)
	dir := t.TempDir()
	script := filepath.Join(dir, "check.py")
	program := `import json, sys
ns = {'__name__': 'test'}
exec(open(sys.argv[1]).read(), ns)
fps = sorted(ns['host_key_fingerprint'](l) for l in json.loads(sys.argv[2]))
assert ns['host_key_fingerprint']('ssh-rsa AAAA') is None
w = {'__name__': 'test'}
exec(ns['WRAPPER'].replace('JOB = None', 'JOB = ' + repr({'id': sys.argv[3], 'attest': sys.argv[4], 'host_keys': fps})), w)
print(w['attestation_line']())
`
	if e := os.WriteFile(script, []byte(program), 0o600); e != nil {
		t.Fatal(e)
	}
	lines, _ := json.Marshal([]string{line1, line2})
	out, e := exec.Command("python3", "-I", script, filepath.Join("..", "..", "..", "..", "packages", "apptransport", "bootstrap", "authorize.py"), string(lines), job, key).CombinedOutput()
	if e != nil {
		t.Fatalf("%v: %s", e, out)
	}
	for _, seen := range []string{fp1, fp2} {
		if e := verifyHostKeyAttestation(key, job, seen, string(out)); e != nil {
			t.Fatalf("python attestation refused for %s: %s", seen, out)
		}
	}
}
