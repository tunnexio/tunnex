package cli

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	beamtransport "github.com/tunnexio/tunnex/packages/apptransport/beam"
)

const beamUsage = `Usage:
  tunnex beam policy|audience|list --org UUID [--offset N]
  tunnex beam get|pause|stop --org UUID --share UUID
  tunnex beam extend --org UUID --share UUID --expires-at RFC3339
  tunnex beam publish --org UUID --port PORT --name NAME --reviewer-user UUID [--reviewer-group UUID] [--duration 1h]
  tunnex beam resume --org UUID --share UUID

Publish and resume run in the foreground; keep the process and local app running.
Repeat --reviewer-user or --reviewer-group to select permitted reviewers explicitly.
Optional --project UUID links a saved project. Repeat --route /api=8080 to serve another local port under /api (path preserved).
Publish accepts --address 127.0.0.1|::1, --protocol http|https and --origin-ca PEM_FILE.
It uses the existing 'tunnex login' (browser or --device), without a desktop client or VPN.
Ctrl+C ends the connector and attempts a bounded Stop; resume never extends expiry.
`

type beamRunner interface {
	Run(context.Context) error
	Ready() bool
}
type beamDependencies struct {
	loadCredential                           func() (Credential, error)
	newAPI                                   func(Credential) (beamAPI, error)
	checkTarget                              func(context.Context, beamtransport.Target) error
	newConnector                             func(beamtransport.ConnectorOptions) (beamRunner, error)
	makeKey                                  func() (string, string, error)
	interval, heartbeatInterval, uncertainty time.Duration
	clock                                    func() time.Time
}

func defaultBeamDependencies() beamDependencies {
	return beamDependencies{
		loadCredential: LoadActiveCredential, newAPI: newBeamHTTPAPI, checkTarget: beamtransport.CheckTarget,
		newConnector: func(o beamtransport.ConnectorOptions) (beamRunner, error) { return beamtransport.NewConnector(o) },
		makeKey:      beamKey, interval: 250 * time.Millisecond, heartbeatInterval: 2 * time.Second, uncertainty: 4 * time.Second, clock: time.Now,
	}
}

// Beam is a standalone, foreground publisher. It never invokes the desktop or
// persists connector keys/certificates, and never changes the WireGuard tunnel.
func Beam(ctx context.Context, args []string, out io.Writer, buildVersion string) error {
	return runBeam(ctx, args, out, buildVersion, defaultBeamDependencies())
}

type beamRepeated []string

func (f *beamRepeated) String() string     { return strings.Join(*f, ",") }
func (f *beamRepeated) Set(s string) error { *f = append(*f, s); return nil }

type beamCommand struct {
	verb, org, share, name, expires, project string
	target                                   beamTarget
	duration                                 time.Duration
	grants                                   []beamGrant
	offset                                   int
}

func beamUUID(s string) (string, error) {
	u, e := uuid.Parse(s)
	if e != nil || u == uuid.Nil {
		return "", errors.New("a valid UUID is required")
	}
	return u.String(), nil
}
func parseBeam(args []string, out io.Writer) (beamCommand, error) {
	var o beamCommand
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, e := io.WriteString(out, beamUsage)
		return o, e
	}
	o.verb = args[0]
	switch o.verb {
	case "policy", "audience", "list", "get", "publish", "resume", "pause", "stop", "extend":
	default:
		return o, errors.New("unknown Beam command; run 'tunnex beam --help'")
	}
	f := flag.NewFlagSet("beam "+o.verb, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&o.org, "org", "", "organization UUID")
	if o.verb == "list" {
		f.IntVar(&o.offset, "offset", 0, "server pagination offset")
	}
	if o.verb == "get" || o.verb == "resume" || o.verb == "pause" || o.verb == "stop" || o.verb == "extend" {
		f.StringVar(&o.share, "share", "", "share UUID")
	}
	if o.verb == "extend" {
		f.StringVar(&o.expires, "expires-at", "", "new absolute expiry RFC3339")
	}
	var users, groups, routes beamRepeated
	var caPath string
	if o.verb == "publish" {
		f.StringVar(&o.name, "name", "", "share name")
		f.StringVar(&o.project, "project", "", "saved project UUID")
		f.Var(&routes, "route", "local path route, e.g. /api=8080 (repeatable; preserves path)")
		f.IntVar(&o.target.Port, "port", 0, "numeric loopback port")
		f.StringVar(&o.target.Address, "address", "127.0.0.1", "numeric loopback address")
		f.StringVar(&o.target.Protocol, "protocol", "http", "http or verified https")
		f.DurationVar(&o.duration, "duration", time.Hour, "share lifetime")
		f.StringVar(&caPath, "origin-ca", "", "additional trusted origin CA PEM file")
		f.Var(&users, "reviewer-user", "permitted user UUID (repeatable)")
		f.Var(&groups, "reviewer-group", "permitted group UUID (repeatable)")
	}
	if e := f.Parse(args[1:]); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			_, e = io.WriteString(out, beamUsage)
			return beamCommand{}, e
		}
		return o, errors.New("invalid Beam flags; run 'tunnex beam --help'")
	}
	if f.NArg() != 0 {
		return o, errors.New("unexpected Beam arguments; run 'tunnex beam --help'")
	}
	var e error
	o.org, e = beamUUID(o.org)
	if e != nil {
		return o, errors.New("pass --org with a valid organization UUID")
	}
	if o.share != "" {
		o.share, e = beamUUID(o.share)
		if e != nil {
			return o, errors.New("pass --share with a valid share UUID")
		}
	} else if o.verb == "get" || o.verb == "resume" || o.verb == "pause" || o.verb == "stop" || o.verb == "extend" {
		return o, errors.New("--share is required")
	}
	if o.offset < 0 || o.offset > 1000000 {
		return o, errors.New("--offset must be between 0 and 1000000")
	}
	if o.verb == "publish" {
		o.name = strings.TrimSpace(o.name)
		if !utf8.ValidString(o.name) || o.name == "" || utf8.RuneCountInString(o.name) > 100 || strings.ContainsAny(o.name, "\r\n\x00") {
			return o, errors.New("--name must contain 1 to 100 characters without control lines")
		}
		if o.duration < time.Minute || o.duration > 24*time.Hour || o.duration%time.Second != 0 {
			return o, errors.New("--duration must be whole seconds between 1m and 24h")
		}
		if o.target.Port < 1 || o.target.Port > 65535 || (o.target.Address != "127.0.0.1" && o.target.Address != "::1") || (o.target.Protocol != "http" && o.target.Protocol != "https") {
			return o, errors.New("publish requires --port 1..65535, --address 127.0.0.1 or ::1, and --protocol http or https")
		}
		if len(users)+len(groups) == 0 || len(users)+len(groups) > 100 {
			return o, errors.New("select 1 to 100 explicit --reviewer-user or --reviewer-group UUIDs; use 'tunnex beam audience' to see permitted reviewers")
		}
		seen := map[beamGrant]bool{}
		for _, v := range []struct {
			kind string
			ids  beamRepeated
		}{{"user", users}, {"group", groups}} {
			for _, id := range v.ids {
				canonical, e := beamUUID(id)
				if e != nil {
					return o, errors.New("reviewer IDs must be valid nonzero UUIDs")
				}
				g := beamGrant{v.kind, canonical}
				if seen[g] {
					return o, errors.New("duplicate reviewer")
				}
				seen[g] = true
				o.grants = append(o.grants, g)
			}
		}
		if caPath != "" {
			if o.target.Protocol != "https" {
				return o, errors.New("--origin-ca requires --protocol https")
			}
			o.target.CAPEM, e = beamOriginCA(caPath)
			if e != nil {
				return o, e
			}
		}
		if o.project != "" {
			o.project, e = beamUUID(o.project)
			if e != nil {
				return o, errors.New("--project requires a valid project UUID")
			}
		}
		for _, raw := range routes {
			prefix, port, ok := strings.Cut(raw, "=")
			n, err := strconv.Atoi(port)
			if !ok || err != nil || n < 1 || n > 65535 || !beamtransport.ValidPathPrefix(prefix) {
				return o, errors.New("--route requires a literal path prefix and port, e.g. /api=8080")
			}
			routeTarget := o.target
			routeTarget.Routes = nil
			routeTarget.Port = n
			o.target.Routes = append(o.target.Routes, beamRoute{prefix, routeTarget})
		}
		if e := beamtransport.ValidateTarget(o.target.transport()); e != nil {
			return o, e
		}
	}
	if o.verb == "extend" {
		if _, e = time.Parse(time.RFC3339, o.expires); e != nil {
			return o, errors.New("--expires-at must be an absolute RFC3339 timestamp")
		}
	}
	return o, nil
}
func beamOriginCA(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", errors.New("could not read origin CA file")
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() {
		return "", errors.New("origin CA must be a regular PEM certificate file")
	}
	b, e := io.ReadAll(io.LimitReader(f, (16<<10)+1))
	if e != nil || len(b) == 0 || len(b) > 16<<10 {
		return "", errors.New("origin CA must contain at most 16 KiB of CA certificates")
	}
	remaining := b
	count := 0
	for len(strings.TrimSpace(string(remaining))) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" {
			return "", errors.New("origin CA must contain only CA certificate PEM blocks")
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil || !cert.IsCA {
			return "", errors.New("origin CA must contain valid CA certificates")
		}
		count++
		remaining = rest
	}
	if count == 0 {
		return "", errors.New("origin CA has no certificates")
	}
	return string(b), nil
}

func runBeam(ctx context.Context, args []string, out io.Writer, build string, d beamDependencies) error {
	o, e := parseBeam(args, out)
	if e != nil || o.verb == "" {
		return e
	}
	cred, e := d.loadCredential()
	if e != nil {
		return e
	}
	if cred.ExpiresAt.IsZero() || cred.Token == "" || !cred.ExpiresAt.After(d.clock()) {
		return ErrCredentialExpired
	}
	api, e := d.newAPI(cred)
	if e != nil {
		return e
	}
	switch o.verb {
	case "policy":
		v, e := api.Policy(ctx, o.org)
		if e != nil {
			return e
		}
		return beamPrint(out, v)
	case "audience":
		v, e := api.Audience(ctx, o.org)
		if e != nil {
			return e
		}
		return beamPrint(out, v)
	case "list":
		v, e := api.List(ctx, o.org, o.offset)
		if e != nil {
			return e
		}
		items := make([]beamPrintableShare, 0, len(v.Items))
		for _, s := range v.Items {
			items = append(items, beamPrintable(s))
		}
		return beamPrint(out, struct {
			Items  []beamPrintableShare `json:"items"`
			Limit  int                  `json:"limit"`
			Offset int                  `json:"offset"`
			Quota  any                  `json:"quota,omitempty"`
		}{items, v.Limit, v.Offset, v.Quota})
	case "get":
		v, e := api.Get(ctx, o.org, o.share)
		if e != nil {
			return e
		}
		return beamPrint(out, beamPrintable(v))
	case "pause", "stop", "extend":
		s, e := api.Get(ctx, o.org, o.share)
		if e != nil {
			return e
		}
		if e = beamManageable(s, o, d.clock()); e != nil {
			return e
		}
		input := beamAction{Action: o.verb, ExpectedVersion: s.Version}
		if o.verb == "extend" {
			at, _ := time.Parse(time.RFC3339, o.expires)
			if !at.After(s.ExpiresAt) {
				return errors.New("new expiry must extend the current expiry")
			}
			input.ExpiresAt = &at
		}
		s, e = api.Action(ctx, o.org, o.share, input)
		if e != nil {
			return e
		}
		return beamPrint(out, beamPrintable(s))
	}
	policy, e := api.Policy(ctx, o.org)
	if e != nil {
		return e
	}
	if e = beamCompatible(policy, build); e != nil {
		return e
	}
	if !policy.Enabled || !policy.DomainReady || !policy.CanPublish {
		return errors.New("Beam publishing is unavailable under current organization policy or serving-domain readiness")
	}
	if strings.TrimSpace(build) == "dev" {
		if _, e = fmt.Fprintln(out, "Development build: Beam protocol 1; no released CLI version is declared."); e != nil {
			return errors.New("could not write Beam development status")
		}
	}
	key, csr, e := d.makeKey()
	if e != nil {
		return errors.New("could not create the in-memory connector identity")
	}
	if e = beamCheckLogin(d, cred); e != nil {
		return e
	}
	var share beamShare
	created := false
	resumed := false
	if o.verb == "publish" {
		if o.project != "" && !slices.Contains(policy.Capabilities, "saved_projects_v1") {
			return errors.New("server update required: Beam saved projects are unsupported")
		}
		if len(o.target.Routes) > 0 && !slices.Contains(policy.Capabilities, beamtransport.PathRoutesCapability) {
			return errors.New("server update required: Beam path routes are unsupported")
		}
		if int(o.duration/time.Second) > policy.MaxDuration {
			return errors.New("requested duration exceeds the organization sharing policy")
		}
		probe, cancel := context.WithTimeout(ctx, time.Second)
		e = d.checkTarget(probe, o.target.transport())
		cancel()
		if e != nil {
			return errors.New("local app check failed; verify the loopback port and HTTPS trust before publishing")
		}
		in := beamCreate{Name: o.name, Target: o.target, Duration: int(o.duration / time.Second), Grants: o.grants, IdempotencyKey: uuid.NewString(), ProjectID: o.project}
		for attempt := 0; attempt < 3; attempt++ {
			if e = beamCheckLogin(d, cred); e != nil {
				return e
			}
			share, e = api.Create(ctx, o.org, in)
			if e == nil {
				break
			}
			if !beamTransient(e) || attempt == 2 {
				return e
			}
			if e = beamWait(ctx, time.Duration(attempt+1)*200*time.Millisecond); e != nil {
				return e
			}
		}
		created = true
	} else {
		share, e = api.Get(ctx, o.org, o.share)
		if e != nil {
			return e
		}
		if e = beamManageable(share, o, d.clock()); e != nil {
			return e
		}
		if share.Target == nil {
			return errors.New("the original share target is unavailable to this publisher")
		}
		o.target = *share.Target
		if len(o.target.Routes) > 0 && !slices.Contains(policy.Capabilities, beamtransport.PathRoutesCapability) {
			return errors.New("server update required: Beam path routes are unsupported")
		}
		if !beamValidTarget(o.target) {
			return errors.New("the original share target is invalid")
		}
		probe, cancel := context.WithTimeout(ctx, time.Second)
		e = d.checkTarget(probe, o.target.transport())
		cancel()
		if e != nil {
			return errors.New("the original local app is unavailable; start it before resuming")
		}
		if e = beamCheckLogin(d, cred); e != nil {
			return e
		}
		if share.State == "paused" {
			share, e = api.Action(ctx, o.org, o.share, beamAction{Action: "resume", ExpectedVersion: share.Version})
			if e != nil {
				return e
			}
			resumed = true
		} else if share.State != "active" && share.State != "starting" {
			return errors.New("only an eligible nonterminal share can resume")
		}
	}
	if share.ID == "" || share.OrgID != o.org || !share.ExpiresAt.After(d.clock()) {
		return errors.New("invalid Beam share response")
	}
	if e = beamCheckLogin(d, cred); e != nil {
		return e
	}
	rollback := func(version int64) error {
		if created {
			return beamCleanup(api, d, cred, o.org, share.ID, version)
		}
		if resumed {
			return beamCleanupAction(api, d, cred, o.org, share.ID, version, "pause")
		}
		return nil
	}
	if share.Target == nil || beamTargetDigest(*share.Target) != beamTargetDigest(o.target) {
		return errors.Join(errors.New("Beam target authority changed; serving refused"), rollback(share.Version))
	}
	connector, e := api.Issue(ctx, o.org, share.ID, share.Version, csr)
	if e != nil {
		return errors.Join(e, rollback(share.Version))
	}
	if !beamConnectorMatches(connector, share, d.clock()) {
		return errors.Join(errors.New("invalid Beam connector authority response"), rollback(share.Version))
	}
	if e = beamCheckLogin(d, cred); e != nil {
		return e
	}
	runner, e := d.newConnector(beamtransport.ConnectorOptions{ProxyURL: connector.ProxyURL, ServerName: connector.ServerName, Binding: connector.binding(), Target: o.target.transport(), CertificatePEM: connector.CertificatePEM, KeyPEM: key, CAPEM: connector.CAPEM, ExpiresAt: connector.CertificateExpiresAt})
	if e != nil {
		action := "stop"
		if o.verb == "resume" {
			action = "pause"
		}
		return errors.Join(errors.New("could not establish the verified Beam connector"), beamCleanupAction(api, d, cred, o.org, share.ID, connector.ShareVersion, action))
	}
	key = ""
	csr = ""
	return beamForeground(ctx, api, d, cred, o, share, connector, runner, out)
}
func beamValidTarget(t beamTarget) bool {
	return beamtransport.ValidateTarget(t.transport()) == nil && (t.Address == "127.0.0.1" || t.Address == "::1") && net.ParseIP(t.Address) != nil && t.Port > 0 && t.Port <= 65535 && (t.Protocol == "http" || t.Protocol == "https")
}
func beamManageable(s beamShare, o beamCommand, at time.Time) error {
	if s.ID != o.share || s.OrgID != o.org || !s.CanManage {
		return errors.New("this share is unavailable for management by the current login")
	}
	if beamTerminal(s.State) || !s.ExpiresAt.After(at) {
		return errors.New("this share has ended; create a new share instead")
	}
	return nil
}
func beamTerminal(s string) bool { return s == "stopped" || s == "expired" || s == "revoked" }
func beamKey() (string, string, error) {
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		return "", "", e
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "Tunnex Beam connector"}}, key)
	if e != nil {
		return "", "", e
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), nil
}
func beamTargetDigest(t beamTarget) string {
	raw, _ := json.Marshal(t)
	value := sha256.Sum256(raw)
	return hex.EncodeToString(value[:])
}
func beamConnectorMatches(c beamConnectorWire, s beamShare, at time.Time) bool {
	b := c.Binding
	return b.OrgID == s.OrgID && b.AppID == s.ID && b.Hostname == s.Hostname && b.Purpose == "beam_proxy" && b.Revision == 1 && b.AuthorityVersion > 0 && b.Generation != "" && b.GatewayID != "" && s.Target != nil && b.Digest == beamTargetDigest(*s.Target) && c.ShareVersion > s.Version && c.ServerName == "tunnex-beam-proxy" && c.CertificateExpiresAt.After(at) && c.ExpiresAt.After(at)
}
func beamWait(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
func beamPrint(out io.Writer, v any) error {
	e := json.NewEncoder(out)
	e.SetIndent("", "  ")
	return e.Encode(v)
}

type beamPrintableShare struct {
	ID           string      `json:"id"`
	OrgID        string      `json:"org_id"`
	Name         string      `json:"name"`
	Hostname     string      `json:"hostname"`
	State        string      `json:"state"`
	Connectivity string      `json:"connectivity"`
	Version      int64       `json:"version"`
	ExpiresAt    time.Time   `json:"expires_at"`
	Grants       []beamGrant `json:"grants,omitempty"`
}

func beamPrintable(s beamShare) beamPrintableShare {
	return beamPrintableShare{s.ID, s.OrgID, s.Name, s.Hostname, s.State, s.Connectivity, s.Version, s.ExpiresAt, s.Grants}
}
func beamVersion(s string) ([3]int, bool, bool) {
	var v [3]int
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	pre := strings.Contains(s, "-")
	s = strings.SplitN(strings.SplitN(s, "+", 2)[0], "-", 2)[0]
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, false, false
	}
	for i, p := range parts {
		n, e := strconv.Atoi(p)
		if e != nil || n < 0 {
			return v, false, false
		}
		v[i] = n
	}
	return v, pre, true
}
func beamCompatible(p beamPolicy, build string) error {
	if p.ProtocolVersion != 1 {
		return errors.New("unsupported Beam protocol; update the CLI and control plane")
	}
	minimum, _, ok := beamVersion(p.MinClientVersion)
	if !ok {
		return errors.New("invalid Beam client-version policy")
	}
	development := strings.TrimSpace(build) == "dev"
	if development {
		build = "0.1.7"
	}
	actual, pre, ok := beamVersion(build)
	if !ok {
		return errors.New("unknown CLI version; use a supported release or explicit source development build")
	}
	for i := range actual {
		if actual[i] > minimum[i] {
			return nil
		}
		if actual[i] < minimum[i] {
			return errors.New("CLI update required by Beam sharing policy")
		}
	}
	if pre {
		return errors.New("CLI update required by Beam sharing policy")
	}
	return nil
}
func beamCanonicalURL(s beamShare) (string, error) {
	u, e := url.Parse(s.URL)
	if e != nil || u.Scheme != "https" || u.Hostname() != s.Hostname || u.Port() != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("invalid canonical Beam share URL")
	}
	return u.String(), nil
}
