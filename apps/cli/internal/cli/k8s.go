package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/cli/internal/api"
)

const (
	// DefaultK8sGatewayChart is the released OCI distribution surface. A source
	// build has version "dev" and must select a local chart or an explicit chart
	// version; it must never guess which published chart is compatible.
	DefaultK8sGatewayChart      = "oci://ghcr.io/tunnexio/charts/tunnex-gateway"
	DefaultK8sHostPostureChart  = "oci://ghcr.io/tunnexio/charts/tunnex-host-posture"
	defaultK8sNamespace         = "tunnex"
	defaultK8sRelease           = "tunnex-gateway"
	defaultK8sTimeout           = "10m"
	defaultK8sWireGuardPort     = 51820
	defaultNodeImageRegistry    = "ghcr.io/tunnexio"
	defaultNodeImageAgent       = "tunnex-node-agent"
	defaultNodeImagePullPolicy  = "IfNotPresent"
	defaultHostPostureRelease   = "tunnex-host-posture"
	defaultHostPostureNamespace = "tunnex-system"
	commandOutputLimit          = 1 << 20
)

// RunK8s runs the provider-neutral Kubernetes gateway lifecycle. buildVersion
// is injected by cmd/tunnex so released binaries select the matching chart.
func RunK8s(ctx context.Context, args []string, buildVersion string) error {
	return runK8s(ctx, args, k8sDeps{
		runner:                  osK8sRunner{},
		loadCredential:          LoadActiveCredential,
		newControlPlane:         newAPIK8sControlPlane,
		in:                      os.Stdin,
		out:                     os.Stdout,
		errOut:                  os.Stderr,
		buildVersion:            buildVersion,
		defaultChart:            DefaultK8sGatewayChart,
		defaultHostPostureChart: DefaultK8sHostPostureChart,
	})
}

type k8sCommand struct {
	name  string
	args  []string
	stdin []byte
}

type k8sCommandResult struct {
	stdout []byte
	stderr []byte
}

type k8sRunner interface {
	LookPath(string) (string, error)
	Run(context.Context, k8sCommand) (k8sCommandResult, error)
}

type boundedBuffer struct {
	b   bytes.Buffer
	max int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	want := b.max - b.b.Len()
	if want > len(p) {
		want = len(p)
	}
	if want > 0 {
		_, _ = b.b.Write(p[:want])
	}
	return len(p), nil
}

func (b *boundedBuffer) Bytes() []byte { return b.b.Bytes() }

type osK8sRunner struct{}

func (osK8sRunner) LookPath(name string) (string, error) { return exec.LookPath(name) }

func (osK8sRunner) Run(ctx context.Context, c k8sCommand) (k8sCommandResult, error) {
	cmd := exec.CommandContext(ctx, c.name, c.args...)
	if c.stdin != nil {
		cmd.Stdin = bytes.NewReader(c.stdin)
	}
	stdout := &boundedBuffer{max: commandOutputLimit}
	stderr := &boundedBuffer{max: commandOutputLimit}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	return k8sCommandResult{stdout: append([]byte(nil), stdout.Bytes()...), stderr: append([]byte(nil), stderr.Bytes()...)}, err
}

type k8sMeta struct {
	publicBaseURL  string
	gatewayControl string
	nodeAgentImage string
}

type k8sOrganization struct {
	id   string
	name string
	slug string
}

type k8sLifecycleClaimStatus struct {
	claim          string
	state          string
	nodeName       string
	generation     int
	requestID      string
	expiresAt      time.Time
	acknowledgedAt *time.Time
	consumedAt     *time.Time
	abortedAt      *time.Time
	nodeID         string
}

type k8sLifecycleRemintResult struct {
	claim      string
	joinToken  string
	generation int
	requestID  string
	expiresAt  time.Time
}

var errK8sLifecycleClaimNotFound = errors.New("Kubernetes lifecycle claim was not found")

type k8sControlPlane interface {
	GetMeta(context.Context) (k8sMeta, error)
	ListOrganizations(context.Context) ([]k8sOrganization, error)
	GetLifecycleClaimStatus(context.Context, string, string) (k8sLifecycleClaimStatus, error)
	RemintLifecycleClaim(context.Context, string, string, string, int, string) (k8sLifecycleRemintResult, error)
	AcknowledgeLifecycleClaim(context.Context, string, string, int, string) (k8sLifecycleClaimStatus, error)
	AbortLifecycleClaim(context.Context, string, string, int, string) (k8sLifecycleClaimStatus, error)
}

type apiK8sControlPlane struct {
	client         *api.ClientWithResponses
	lifecycleRetry lifecycleRouteRetryPolicy
}

func newAPIK8sControlPlane(cred Credential) (k8sControlPlane, error) {
	if err := validateK8sCredentialServer(cred.Server); err != nil {
		return nil, err
	}
	client, err := newAuthedClientWithTransport(cred, newLifecycleFreshConnectionTransport())
	if err != nil {
		return nil, err
	}
	return &apiK8sControlPlane{client: client, lifecycleRetry: defaultLifecycleRouteRetryPolicy()}, nil
}

func validateK8sCredentialServer(server string) error {
	u, err := url.Parse(strings.TrimSpace(server))
	if err != nil || u.Scheme == "" || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return errors.New("stored control-plane URL is invalid; run 'tunnex login' with an absolute https URL")
	}
	if u.Scheme != "https" && !isLoopbackHost(u.Hostname()) {
		return errors.New("stored control-plane URL must use https; plain http is allowed only for an explicit loopback development endpoint")
	}
	return nil
}

func (c *apiK8sControlPlane) GetMeta(ctx context.Context) (k8sMeta, error) {
	resp, err := c.client.GetMetaWithResponse(ctx)
	if err != nil {
		return k8sMeta{}, err
	}
	if resp.JSON200 == nil {
		return k8sMeta{}, apiErr(resp.StatusCode(), resp.Body, "could not read control-plane metadata")
	}
	meta := k8sMeta{}
	if resp.JSON200.PublicBaseUrl != nil {
		meta.publicBaseURL = strings.TrimSpace(*resp.JSON200.PublicBaseUrl)
	}
	if resp.JSON200.GatewayControlUrl != nil {
		meta.gatewayControl = strings.TrimSpace(*resp.JSON200.GatewayControlUrl)
	}
	if resp.JSON200.NodeAgentImage != nil {
		meta.nodeAgentImage = strings.TrimSpace(*resp.JSON200.NodeAgentImage)
	}
	return meta, nil
}

func (c *apiK8sControlPlane) ListOrganizations(ctx context.Context) ([]k8sOrganization, error) {
	resp, err := c.client.ListOrganizationsWithResponse(ctx)
	if err != nil {
		return nil, err
	}
	if resp.JSON200 == nil {
		return nil, apiErr(resp.StatusCode(), resp.Body, "could not list organizations")
	}
	orgs := make([]k8sOrganization, 0, len(*resp.JSON200))
	for _, org := range *resp.JSON200 {
		orgs = append(orgs, k8sOrganization{id: org.Id.String(), name: org.Name, slug: org.Slug})
	}
	return orgs, nil
}

func parseLifecycleIDs(orgID, claim string) (uuid.UUID, uuid.UUID, error) {
	id, err := uuid.Parse(orgID)
	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("invalid organization id returned by server: %w", err)
	}
	claimID, err := uuid.Parse(claim)
	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("invalid lifecycle claim: %w", err)
	}
	return id, claimID, nil
}

func lifecycleStatusFromAPI(status api.NodeLifecycleClaimStatus) k8sLifecycleClaimStatus {
	result := k8sLifecycleClaimStatus{
		claim: status.Claim.String(), state: string(status.State), nodeName: status.NodeName,
		generation: status.Generation, requestID: status.RequestId.String(), expiresAt: status.ExpiresAt,
		acknowledgedAt: status.AcknowledgedAt, consumedAt: status.ConsumedAt, abortedAt: status.AbortedAt,
	}
	if status.NodeId != nil {
		result.nodeID = status.NodeId.String()
	}
	return result
}

func (c *apiK8sControlPlane) GetLifecycleClaimStatus(ctx context.Context, orgID, claim string) (k8sLifecycleClaimStatus, error) {
	orgUUID, claimUUID, err := parseLifecycleIDs(orgID, claim)
	if err != nil {
		return k8sLifecycleClaimStatus{}, err
	}
	resp, err := retryLifecycleRoute(ctx, c.lifecycleRetry,
		func(attemptCtx context.Context) (*api.GetNodeLifecycleClaimResponse, error) {
			return c.client.GetNodeLifecycleClaimWithResponse(attemptCtx, orgUUID, claimUUID)
		},
		func(response *api.GetNodeLifecycleClaimResponse) (int, []byte) {
			return response.StatusCode(), response.Body
		},
	)
	if err != nil {
		return k8sLifecycleClaimStatus{}, err
	}
	if resp.JSON200 == nil {
		if resp.StatusCode() == http.StatusNotFound {
			var body envelope
			if json.Unmarshal(resp.Body, &body) == nil && body.Error.Code == "lifecycle_claim_not_found" {
				return k8sLifecycleClaimStatus{}, errK8sLifecycleClaimNotFound
			}
		}
		return k8sLifecycleClaimStatus{}, apiErr(resp.StatusCode(), resp.Body, "could not read lifecycle claim status")
	}
	return lifecycleStatusFromAPI(*resp.JSON200), nil
}

func (c *apiK8sControlPlane) RemintLifecycleClaim(ctx context.Context, orgID, claim, nodeName string, expectedGeneration int, requestID string) (k8sLifecycleRemintResult, error) {
	orgUUID, claimUUID, err := parseLifecycleIDs(orgID, claim)
	if err != nil {
		return k8sLifecycleRemintResult{}, err
	}
	requestUUID, err := uuid.Parse(requestID)
	if err != nil {
		return k8sLifecycleRemintResult{}, fmt.Errorf("invalid lifecycle request id: %w", err)
	}
	body := api.RemintNodeLifecycleClaimJSONRequestBody{
		NodeName: nodeName, ExpectedGeneration: expectedGeneration, RequestId: requestUUID,
	}
	resp, err := retryLifecycleRoute(ctx, c.lifecycleRetry,
		func(attemptCtx context.Context) (*api.RemintNodeLifecycleClaimResponse, error) {
			return c.client.RemintNodeLifecycleClaimWithResponse(attemptCtx, orgUUID, claimUUID, body)
		},
		func(response *api.RemintNodeLifecycleClaimResponse) (int, []byte) {
			return response.StatusCode(), response.Body
		},
	)
	if err != nil {
		return k8sLifecycleRemintResult{}, err
	}
	if resp.JSON200 == nil {
		return k8sLifecycleRemintResult{}, apiErr(resp.StatusCode(), resp.Body, "could not mint or recover the lifecycle join token")
	}
	if strings.TrimSpace(resp.JSON200.JoinToken) == "" {
		return k8sLifecycleRemintResult{}, errors.New("the control plane returned an empty lifecycle join token")
	}
	return k8sLifecycleRemintResult{
		claim: resp.JSON200.Claim.String(), joinToken: resp.JSON200.JoinToken, generation: resp.JSON200.Generation,
		requestID: resp.JSON200.RequestId.String(), expiresAt: resp.JSON200.ExpiresAt,
	}, nil
}

func (c *apiK8sControlPlane) AcknowledgeLifecycleClaim(ctx context.Context, orgID, claim string, generation int, requestID string) (k8sLifecycleClaimStatus, error) {
	orgUUID, claimUUID, err := parseLifecycleIDs(orgID, claim)
	if err != nil {
		return k8sLifecycleClaimStatus{}, err
	}
	requestUUID, err := uuid.Parse(requestID)
	if err != nil {
		return k8sLifecycleClaimStatus{}, fmt.Errorf("invalid lifecycle request id: %w", err)
	}
	body := api.AcknowledgeNodeLifecycleClaimJSONRequestBody{
		ExpectedGeneration: generation, RequestId: requestUUID,
	}
	resp, err := retryLifecycleRoute(ctx, c.lifecycleRetry,
		func(attemptCtx context.Context) (*api.AcknowledgeNodeLifecycleClaimResponse, error) {
			return c.client.AcknowledgeNodeLifecycleClaimWithResponse(attemptCtx, orgUUID, claimUUID, body)
		},
		func(response *api.AcknowledgeNodeLifecycleClaimResponse) (int, []byte) {
			return response.StatusCode(), response.Body
		},
	)
	if err != nil {
		return k8sLifecycleClaimStatus{}, err
	}
	if resp.JSON200 == nil {
		return k8sLifecycleClaimStatus{}, apiErr(resp.StatusCode(), resp.Body, "could not acknowledge lifecycle claim persistence")
	}
	return lifecycleStatusFromAPI(*resp.JSON200), nil
}

func (c *apiK8sControlPlane) AbortLifecycleClaim(ctx context.Context, orgID, claim string, generation int, requestID string) (k8sLifecycleClaimStatus, error) {
	return c.abortLifecycleClaim(ctx, orgID, claim, "", generation, requestID)
}

func (c *apiK8sControlPlane) AbortLifecycleClaimBeforeMint(ctx context.Context, orgID, claim, nodeName, requestID string) (k8sLifecycleClaimStatus, error) {
	if strings.TrimSpace(nodeName) == "" {
		return k8sLifecycleClaimStatus{}, errors.New("generation-zero lifecycle abort requires the exact anchored node name")
	}
	return c.abortLifecycleClaim(ctx, orgID, claim, nodeName, 0, requestID)
}

func (c *apiK8sControlPlane) abortLifecycleClaim(ctx context.Context, orgID, claim, nodeName string, generation int, requestID string) (k8sLifecycleClaimStatus, error) {
	orgUUID, claimUUID, err := parseLifecycleIDs(orgID, claim)
	if err != nil {
		return k8sLifecycleClaimStatus{}, err
	}
	requestUUID, err := uuid.Parse(requestID)
	if err != nil {
		return k8sLifecycleClaimStatus{}, fmt.Errorf("invalid lifecycle request id: %w", err)
	}
	body := api.AbortNodeLifecycleClaimJSONRequestBody{
		ExpectedGeneration: generation, RequestId: requestUUID,
	}
	if nodeName != "" {
		body.NodeName = &nodeName
	}
	resp, err := retryLifecycleRoute(ctx, c.lifecycleRetry,
		func(attemptCtx context.Context) (*api.AbortNodeLifecycleClaimResponse, error) {
			return c.client.AbortNodeLifecycleClaimWithResponse(attemptCtx, orgUUID, claimUUID, body)
		},
		func(response *api.AbortNodeLifecycleClaimResponse) (int, []byte) {
			return response.StatusCode(), response.Body
		},
	)
	if err != nil {
		return k8sLifecycleClaimStatus{}, err
	}
	if resp.JSON200 == nil {
		return k8sLifecycleClaimStatus{}, apiErr(resp.StatusCode(), resp.Body, "could not abort lifecycle claim")
	}
	return lifecycleStatusFromAPI(*resp.JSON200), nil
}

type k8sDeps struct {
	runner                  k8sRunner
	loadCredential          func() (Credential, error)
	newControlPlane         func(Credential) (k8sControlPlane, error)
	in                      io.Reader
	out                     io.Writer
	errOut                  io.Writer
	buildVersion            string
	defaultChart            string
	defaultHostPostureChart string
	newClaimID              func() string
	newRequestID            func() string
	now                     func() time.Time
	newOperationID          func() string
	newTicker               func(time.Duration) k8sTicker
	cleanupChartRoot        func(string) error
}

func (d k8sDeps) normalized() k8sDeps {
	if d.in == nil {
		d.in = strings.NewReader("")
	}
	if d.out == nil {
		d.out = io.Discard
	}
	if d.errOut == nil {
		d.errOut = io.Discard
	}
	if strings.TrimSpace(d.defaultChart) == "" {
		d.defaultChart = DefaultK8sGatewayChart
	}
	if strings.TrimSpace(d.defaultHostPostureChart) == "" {
		d.defaultHostPostureChart = DefaultK8sHostPostureChart
	}
	if d.newClaimID == nil {
		d.newClaimID = uuid.NewString
	}
	if d.newRequestID == nil {
		d.newRequestID = uuid.NewString
	}
	if d.now == nil {
		d.now = time.Now
	}
	if d.newOperationID == nil {
		d.newOperationID = uuid.NewString
	}
	if d.newTicker == nil {
		d.newTicker = newRealK8sTicker
	}
	if d.cleanupChartRoot == nil {
		d.cleanupChartRoot = removeChartStagingRoot
	}
	return d
}

func runK8s(ctx context.Context, args []string, deps k8sDeps) error {
	deps = deps.normalized()
	if deps.runner == nil || deps.loadCredential == nil || deps.newControlPlane == nil {
		return errors.New("Kubernetes lifecycle dependencies are incomplete")
	}
	if len(args) == 0 {
		return errors.New(k8sUsage)
	}
	switch args[0] {
	case "plan":
		return runK8sPlan(ctx, args[1:], deps)
	case "install":
		return runK8sInstall(ctx, args[1:], deps)
	case "abort-install":
		return runK8sAbortInstall(ctx, args[1:], deps)
	case "status":
		return runK8sStatus(ctx, args[1:], deps)
	case "upgrade":
		return runK8sUpgrade(ctx, args[1:], deps)
	case "rollback":
		return runK8sRollback(ctx, args[1:], deps)
	case "diagnostics":
		return runK8sDiagnostics(ctx, args[1:], deps)
	case "uninstall":
		return runK8sUninstall(ctx, args[1:], deps)
	case "purge-state":
		return runK8sPurgeState(ctx, args[1:], deps)
	case "help", "-h", "--help":
		_, _ = io.WriteString(deps.out, k8sUsage)
		return nil
	default:
		return fmt.Errorf("unknown k8s command %q\n%s", args[0], k8sUsage)
	}
}

const k8sUsage = `Usage:
  tunnex k8s plan       --node-name NAME [install flags]
  tunnex k8s install    --node-name NAME [install flags] [--yes]
  tunnex k8s abort-install --release NAME --claim UUID [--namespace NAME] [--context NAME] [--confirm "ABORT UUID"]
  tunnex k8s status     [--release NAME] [--namespace NAME]
  tunnex k8s upgrade    [--release NAME] [--chart REF] [--chart-version VERSION] [--yes]
  tunnex k8s rollback   --revision N [--release NAME] [--yes]
  tunnex k8s diagnostics [--release NAME] [--namespace NAME]
  tunnex k8s uninstall  [--release NAME] [--namespace NAME] [--yes]
  tunnex k8s purge-state --release NAME --claim NAME [--confirm "DELETE NAME"]
  tunnex k8s purge-state --release NAME --claim NAME --legacy-without-lifecycle-proof [--confirm "DELETE LEGACY NAME"]

Install flags:
  --org ID|slug|name          required when the login belongs to multiple organizations
  --release NAME              Helm release (default tunnex-gateway)
  --namespace NAME            namespace (default tunnex)
  --mode enroll|reuse         reuse requires a lifecycle-provenant --existing-claim and mints no token
  --service-type LoadBalancer|NodePort
  --endpoint HOST:PORT        optional for LoadBalancer; required for NodePort
  --node-port PORT            selected Service nodePort; required for NodePort
  --load-balancer-ip IP       optional operator-managed static IP for LoadBalancer
  --service-annotation K=V    repeatable provider-neutral Service annotation
  --image-pull-secret NAME    repeatable existing image pull Secret name (body is never read)
  --gateway-node-selector K=V repeatable provider-neutral gateway placement selector
  --gateway-toleration SPEC   repeatable KEY[=VALUE][:EFFECT] gateway toleration
  --storage-class NAME        explicit class; otherwise exactly one default is required
  --chart REF                 OCI chart or local chart path
  --chart-version VERSION     required for OCI from a dev/source CLI build
  --host-posture-chart REF    cluster-singleton host manager chart (advanced/source use)
  --host-posture-chart-version VERSION
  --image REF                 deliberate digest/tag override; implicit server metadata is used only when digest-pinned
  --context NAME              explicit kube context (current context by default)
`

type installOptions struct {
	org                   string
	release               string
	namespace             string
	nodeName              string
	mode                  string
	existingClaim         string
	serviceType           string
	endpoint              string
	nodePort              int
	loadBalancerIP        string
	serviceAnnotations    stringListFlag
	imagePullSecrets      stringListFlag
	gatewaySelectors      stringListFlag
	gatewayTolerationsRaw stringListFlag
	gatewayTolerations    []gatewayToleration
	storageClass          string
	chart                 string
	chartVersion          string
	hostPostureChart      string
	hostPostureVersion    string
	image                 string
	kubeContext           string
	timeout               string
	yes                   bool
}

type stringListFlag []string

func (v *stringListFlag) String() string { return strings.Join(*v, ",") }
func (v *stringListFlag) Set(value string) error {
	*v = append(*v, value)
	return nil
}

func parseInstallOptions(args []string, deps k8sDeps) (installOptions, error) {
	o := installOptions{}
	fs := flag.NewFlagSet("k8s install", flag.ContinueOnError)
	fs.SetOutput(deps.errOut)
	fs.StringVar(&o.org, "org", "", "organization id, slug, or exact name")
	fs.StringVar(&o.release, "release", defaultK8sRelease, "Helm release")
	fs.StringVar(&o.namespace, "namespace", defaultK8sNamespace, "Kubernetes namespace")
	fs.StringVar(&o.nodeName, "node-name", "", "gateway node identity")
	fs.StringVar(&o.mode, "mode", "enroll", "enroll or reuse")
	fs.StringVar(&o.existingClaim, "existing-claim", "", "retained PVC used by reuse mode")
	fs.StringVar(&o.serviceType, "service-type", "LoadBalancer", "LoadBalancer or NodePort")
	fs.StringVar(&o.endpoint, "endpoint", "", "explicit public host:port")
	fs.IntVar(&o.nodePort, "node-port", 0, "selected Kubernetes Service nodePort")
	fs.StringVar(&o.loadBalancerIP, "load-balancer-ip", "", "operator-managed static LoadBalancer IP")
	fs.Var(&o.serviceAnnotations, "service-annotation", "repeatable Kubernetes Service annotation key=value")
	fs.Var(&o.imagePullSecrets, "image-pull-secret", "repeatable existing image pull Secret name")
	fs.Var(&o.gatewaySelectors, "gateway-node-selector", "repeatable provider-neutral gateway node selector key=value")
	fs.Var(&o.gatewayTolerationsRaw, "gateway-toleration", "repeatable gateway toleration KEY[=VALUE][:EFFECT]")
	fs.StringVar(&o.storageClass, "storage-class", "", "explicit StorageClass")
	fs.StringVar(&o.chart, "chart", deps.defaultChart, "gateway chart OCI reference or local path")
	fs.StringVar(&o.chartVersion, "chart-version", "", "gateway chart version")
	fs.StringVar(&o.hostPostureChart, "host-posture-chart", deps.defaultHostPostureChart, "cluster-singleton host posture chart OCI reference or local path")
	fs.StringVar(&o.hostPostureVersion, "host-posture-chart-version", "", "host posture chart version")
	fs.StringVar(&o.image, "image", "", "node-agent image override")
	fs.StringVar(&o.kubeContext, "context", "", "kube context")
	fs.StringVar(&o.timeout, "timeout", defaultK8sTimeout, "Helm wait timeout")
	fs.BoolVar(&o.yes, "yes", false, "approve the printed plan")
	if err := fs.Parse(args); err != nil {
		return installOptions{}, err
	}
	if fs.NArg() != 0 {
		return installOptions{}, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if err := validateInstallOptions(&o, deps.buildVersion); err != nil {
		return installOptions{}, err
	}
	return o, nil
}

var (
	dnsLabelRE       = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
	dnsSubdomainRE   = regexp.MustCompile(`^[a-z0-9](?:[-.a-z0-9]*[a-z0-9])?$`)
	annotationNameRE = regexp.MustCompile(`^[A-Za-z0-9](?:[-_.A-Za-z0-9]*[A-Za-z0-9])?$`)
	versionRE        = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._+-]*$`)
	hexRE            = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

func normalizeServiceAnnotations(values []string) (stringListFlag, error) {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, raw := range values {
		key, value, ok := strings.Cut(raw, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" || len(value) > 4096 || strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return nil, fmt.Errorf("invalid --service-annotation %q; use a Kubernetes annotation key=value without control characters", raw)
		}
		name := key
		if prefix, suffix, hasPrefix := strings.Cut(key, "/"); hasPrefix {
			if len(prefix) > 253 || !dnsSubdomainRE.MatchString(prefix) {
				return nil, fmt.Errorf("invalid --service-annotation key %q", key)
			}
			name = suffix
		}
		if len(name) == 0 || len(name) > 63 || !annotationNameRE.MatchString(name) {
			return nil, fmt.Errorf("invalid --service-annotation key %q", key)
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("duplicate --service-annotation key %q", key)
		}
		seen[key] = struct{}{}
		result = append(result, key+"="+value)
	}
	sort.Strings(result)
	return result, nil
}

func normalizeImagePullSecrets(values []string) (stringListFlag, error) {
	result := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, raw := range values {
		name := strings.TrimSpace(raw)
		if err := validateDNSSubdomain("image pull Secret", name, 253); err != nil {
			return nil, err
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, fmt.Errorf("duplicate --image-pull-secret %q", name)
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	sort.Strings(result)
	return result, nil
}

type gatewayToleration struct {
	Key      string `json:"key"`
	Operator string `json:"operator"`
	Value    string `json:"value,omitempty"`
	Effect   string `json:"effect,omitempty"`
}

func normalizeGatewaySelectors(values []string) (stringListFlag, error) {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		key, value, ok := strings.Cut(strings.TrimSpace(raw), "=")
		if !ok || !validKubernetesLabelKey(key) || !validKubernetesLabelValue(value) {
			return nil, fmt.Errorf("invalid --gateway-node-selector %q; use a Kubernetes label key=value", raw)
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("duplicate --gateway-node-selector key %q", key)
		}
		seen[key] = struct{}{}
		result = append(result, key+"="+value)
	}
	sort.Strings(result)
	return result, nil
}

func normalizeGatewayTolerations(values []string) ([]gatewayToleration, error) {
	result := make([]gatewayToleration, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		effect := ""
		if colon := strings.LastIndex(value, ":"); colon >= 0 {
			effect = value[colon+1:]
			value = value[:colon]
			if effect != "NoSchedule" && effect != "PreferNoSchedule" && effect != "NoExecute" {
				return nil, fmt.Errorf("invalid --gateway-toleration effect %q", effect)
			}
		}
		key, labelValue, hasValue := strings.Cut(value, "=")
		if !validKubernetesLabelKey(key) || (hasValue && !validKubernetesLabelValue(labelValue)) {
			return nil, fmt.Errorf("invalid --gateway-toleration %q; use KEY[=VALUE][:EFFECT]", raw)
		}
		item := gatewayToleration{Key: key, Operator: "Exists", Effect: effect}
		if hasValue {
			item.Operator = "Equal"
			item.Value = labelValue
		}
		canonical := item.Key + "\x00" + item.Operator + "\x00" + item.Value + "\x00" + item.Effect
		if _, duplicate := seen[canonical]; duplicate {
			return nil, fmt.Errorf("duplicate --gateway-toleration %q", raw)
		}
		seen[canonical] = struct{}{}
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool {
		a := result[i].Key + "\x00" + result[i].Operator + "\x00" + result[i].Value + "\x00" + result[i].Effect
		b := result[j].Key + "\x00" + result[j].Operator + "\x00" + result[j].Value + "\x00" + result[j].Effect
		return a < b
	})
	return result, nil
}

func validKubernetesLabelKey(value string) bool {
	if value == "" {
		return false
	}
	name := value
	if prefix, suffix, ok := strings.Cut(value, "/"); ok {
		if len(prefix) > 253 || !dnsSubdomainRE.MatchString(prefix) {
			return false
		}
		name = suffix
	}
	return len(name) > 0 && len(name) <= 63 && annotationNameRE.MatchString(name)
}

func validKubernetesLabelValue(value string) bool {
	return value == "" || (len(value) <= 63 && annotationNameRE.MatchString(value))
}

func gatewaySelectorMap(values []string) map[string]string {
	result := make(map[string]string, len(values))
	for _, item := range values {
		key, value, _ := strings.Cut(item, "=")
		result[key] = value
	}
	return result
}

func serviceAnnotationMap(values []string) map[string]string {
	result := make(map[string]string, len(values))
	for _, item := range values {
		key, value, _ := strings.Cut(item, "=")
		result[key] = value
	}
	return result
}

func validateInstallOptions(o *installOptions, buildVersion string) error {
	o.release = strings.TrimSpace(o.release)
	o.namespace = strings.TrimSpace(o.namespace)
	o.nodeName = strings.TrimSpace(o.nodeName)
	o.mode = strings.ToLower(strings.TrimSpace(o.mode))
	o.serviceType = strings.TrimSpace(o.serviceType)
	o.endpoint = strings.TrimSpace(o.endpoint)
	o.existingClaim = strings.TrimSpace(o.existingClaim)
	o.storageClass = strings.TrimSpace(o.storageClass)
	o.chart = strings.TrimSpace(o.chart)
	o.chartVersion = strings.TrimPrefix(strings.TrimSpace(o.chartVersion), "v")
	o.hostPostureChart = strings.TrimSpace(o.hostPostureChart)
	o.hostPostureVersion = strings.TrimPrefix(strings.TrimSpace(o.hostPostureVersion), "v")
	o.image = strings.TrimSpace(o.image)
	o.loadBalancerIP = strings.TrimSpace(o.loadBalancerIP)
	o.kubeContext = strings.TrimSpace(o.kubeContext)
	if err := validateRelease(o.release); err != nil {
		return err
	}
	if err := validateDNSLabel("namespace", o.namespace, 63); err != nil {
		return err
	}
	containsControl := strings.IndexFunc(o.nodeName, unicode.IsControl) >= 0
	if o.nodeName == "" || len(o.nodeName) > 100 || containsControl {
		return errors.New("--node-name is required, at most 100 characters, and must not contain control characters")
	}
	if o.mode != "enroll" && o.mode != "reuse" {
		return errors.New("--mode must be enroll or reuse")
	}
	if o.mode == "enroll" && o.existingClaim != "" {
		return errors.New("--existing-claim is only valid with --mode reuse")
	}
	if o.mode == "reuse" {
		if o.existingClaim == "" {
			return errors.New("--mode reuse requires --existing-claim")
		}
		if o.storageClass != "" {
			return errors.New("--storage-class is not valid with --mode reuse; the retained claim owns its storage class")
		}
		if err := validateDNSSubdomain("existing claim", o.existingClaim, 253); err != nil {
			return err
		}
	}
	if o.serviceType != "LoadBalancer" && o.serviceType != "NodePort" {
		return errors.New("--service-type must be LoadBalancer or NodePort")
	}
	if o.serviceType == "NodePort" && (o.endpoint == "" || o.nodePort == 0) {
		return errors.New("NodePort requires both --endpoint with a reachable node address and an explicit --node-port")
	}
	if o.serviceType != "NodePort" && o.nodePort != 0 {
		return errors.New("--node-port is only valid with --service-type NodePort")
	}
	if o.loadBalancerIP != "" {
		if o.serviceType != "LoadBalancer" {
			return errors.New("--load-balancer-ip is only valid with --service-type LoadBalancer")
		}
		ip := net.ParseIP(o.loadBalancerIP)
		if ip == nil {
			return errors.New("--load-balancer-ip must be a valid IPv4 or IPv6 address")
		}
		o.loadBalancerIP = ip.String()
	}
	annotations, err := normalizeServiceAnnotations(o.serviceAnnotations)
	if err != nil {
		return err
	}
	o.serviceAnnotations = annotations
	pullSecrets, err := normalizeImagePullSecrets(o.imagePullSecrets)
	if err != nil {
		return err
	}
	o.imagePullSecrets = pullSecrets
	selectors, err := normalizeGatewaySelectors(o.gatewaySelectors)
	if err != nil {
		return err
	}
	o.gatewaySelectors = selectors
	tolerations, err := normalizeGatewayTolerations(o.gatewayTolerationsRaw)
	if err != nil {
		return err
	}
	o.gatewayTolerations = tolerations
	if o.nodePort != 0 && (o.nodePort < 30000 || o.nodePort > 32767) {
		return errors.New("--node-port must be between 30000 and 32767")
	}
	if o.endpoint != "" {
		if err := validateEndpoint(o.endpoint); err != nil {
			return fmt.Errorf("invalid --endpoint: %w", err)
		}
		_, rawPort, _ := net.SplitHostPort(o.endpoint)
		port, _ := strconv.Atoi(rawPort)
		if o.serviceType == "NodePort" {
			if port != o.nodePort {
				return fmt.Errorf("NodePort endpoint public port %d must equal selected --node-port %d", port, o.nodePort)
			}
		} else if port != defaultK8sWireGuardPort {
			return fmt.Errorf("LoadBalancer endpoint public port %d must equal wireguard.port %d, the supported listener and Service port", port, defaultK8sWireGuardPort)
		}
	}
	if o.storageClass != "" {
		if err := validateDNSSubdomain("storage class", o.storageClass, 253); err != nil {
			return err
		}
	}
	if err := validateChartReference(o.chart); err != nil {
		return err
	}
	if strings.HasPrefix(o.chart, "oci://") && o.chartVersion == "" {
		v := strings.TrimPrefix(strings.TrimSpace(buildVersion), "v")
		if v == "" || v == "dev" || v == "devel" || v == "unknown" {
			return errors.New("a dev/source CLI cannot guess an OCI chart version: pass --chart with a local path or --chart-version explicitly")
		}
		o.chartVersion = v
	}
	if o.chartVersion != "" && !versionRE.MatchString(o.chartVersion) {
		return errors.New("--chart-version contains unsupported characters")
	}
	if o.hostPostureChart == DefaultK8sHostPostureChart && !strings.HasPrefix(o.chart, "oci://") {
		o.hostPostureChart = filepath.Clean(filepath.Join(filepath.Dir(o.chart), "tunnex-host-posture"))
	}
	if o.hostPostureChart == DefaultK8sHostPostureChart && o.hostPostureVersion == "" && o.chartVersion != "" {
		// The released gateway and singleton-manager charts are a versioned pair.
		// One explicit version is therefore sufficient for the canonical OCI
		// pair, while a custom manager reference still requires its own version.
		o.hostPostureVersion = o.chartVersion
	}
	if err := validateChartReference(o.hostPostureChart); err != nil {
		return fmt.Errorf("invalid --host-posture-chart: %w", err)
	}
	if strings.HasPrefix(o.hostPostureChart, "oci://") && o.hostPostureVersion == "" {
		v := strings.TrimPrefix(strings.TrimSpace(buildVersion), "v")
		if v == "" || v == "dev" || v == "devel" || v == "unknown" {
			return errors.New("a dev/source CLI cannot guess an OCI host-posture chart version: pass --host-posture-chart with a local path or --host-posture-chart-version explicitly")
		}
		o.hostPostureVersion = v
	}
	if o.hostPostureVersion != "" && !versionRE.MatchString(o.hostPostureVersion) {
		return errors.New("--host-posture-chart-version contains unsupported characters")
	}
	duration, err := time.ParseDuration(o.timeout)
	if err != nil {
		return fmt.Errorf("invalid --timeout: %w", err)
	}
	if duration <= 0 {
		return errors.New("--timeout must be greater than zero")
	}
	if o.image != "" {
		if _, err := parseImageRef(o.image); err != nil {
			return fmt.Errorf("invalid --image: %w", err)
		}
	}
	return nil
}

func validateChartReference(chart string) error {
	if chart == "" || strings.HasPrefix(chart, "-") || strings.ContainsAny(chart, "\r\n\x00") {
		return errors.New("--chart must be a non-empty OCI reference or local path and must not start with '-' or contain control characters")
	}
	if strings.HasPrefix(chart, "oci://") {
		u, err := url.Parse(chart)
		if err != nil || u.Scheme != "oci" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("--chart OCI reference must not contain credentials, query, or fragment")
		}
	}
	return nil
}

func validateRelease(value string) error {
	// The chart appends "-tunnex-gateway-state". Forty-two characters is
	// therefore the largest release that keeps every generated name <=63.
	return validateDNSLabel("release", value, 42)
}

func validateDNSLabel(label, value string, max int) error {
	if value == "" || len(value) > max || !dnsLabelRE.MatchString(value) {
		return fmt.Errorf("%s must be a lowercase DNS label no longer than %d characters", label, max)
	}
	return nil
}

func validateDNSSubdomain(label, value string, max int) error {
	if value == "" || len(value) > max || !dnsSubdomainRE.MatchString(value) {
		return fmt.Errorf("%s must be a lowercase DNS subdomain no longer than %d characters", label, max)
	}
	return nil
}

func validateEndpoint(endpoint string) error {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || strings.TrimSpace(host) == "" {
		return errors.New("use host:port (IPv6 addresses must be bracketed)")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	return nil
}

type storageClassList struct {
	Items []struct {
		Metadata struct {
			Name        string            `json:"name"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
		Provisioner       string `json:"provisioner"`
		VolumeBindingMode string `json:"volumeBindingMode"`
	} `json:"items"`
}

type k8sPreflight struct {
	context            string
	storageClass       string
	storageProvisioner string
	bindingMode        string
}

func resolveInstallStorage(ctx context.Context, deps k8sDeps, o installOptions, state installState) (k8sPreflight, error) {
	if o.mode == "reuse" {
		return k8sPreflight{context: o.kubeContext, storageClass: state.pvcStorageClass, storageProvisioner: "existing bound claim", bindingMode: "already bound"}, nil
	}
	if state.pvcExists {
		return k8sPreflight{context: o.kubeContext, storageClass: state.pvcStorageClass, storageProvisioner: "retained retry claim", bindingMode: "existing " + strings.ToLower(state.pvcPhase)}, nil
	}
	classes, err := runChecked(ctx, deps.runner, "discover StorageClasses", k8sCommand{name: "kubectl", args: kubectlArgs(o.kubeContext, "get", "storageclass", "-o", "json")})
	if err != nil {
		return k8sPreflight{}, err
	}
	selected, provisioner, mode, err := selectStorageClass(classes.stdout, o.storageClass)
	if err != nil {
		return k8sPreflight{}, err
	}
	return k8sPreflight{context: o.kubeContext, storageClass: selected, storageProvisioner: provisioner, bindingMode: mode}, nil
}

func runToolContextPreflight(ctx context.Context, deps k8sDeps, requestedContext string) (string, error) {
	for _, tool := range []string{"kubectl", "helm"} {
		if _, err := deps.runner.LookPath(tool); err != nil {
			return "", fmt.Errorf("%s is required and was not found in PATH", tool)
		}
	}
	if err := verifyHelmClient(ctx, deps.runner); err != nil {
		return "", err
	}
	contextName := strings.TrimSpace(requestedContext)
	if contextName == "" {
		result, err := runChecked(ctx, deps.runner, "read current kube context", k8sCommand{name: "kubectl", args: []string{"config", "current-context"}})
		if err != nil {
			return "", err
		}
		contextName = strings.TrimSpace(string(result.stdout))
	}
	if contextName == "" {
		return "", errors.New("kubectl has no current context; select one or pass --context")
	}
	ready, err := runChecked(ctx, deps.runner, "verify Kubernetes API context", k8sCommand{name: "kubectl", args: kubectlArgs(contextName, "get", "--raw=/readyz")})
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(string(ready.stdout)) != "ok" {
		return "", fmt.Errorf("Kubernetes API context %q did not report ready", contextName)
	}
	return contextName, nil
}

func verifyHelmClient(ctx context.Context, runner k8sRunner) error {
	result, err := runChecked(ctx, runner, "read Helm client version", k8sCommand{name: "helm", args: []string{"version", "--short"}})
	if err != nil {
		return err
	}
	version := strings.TrimSpace(string(result.stdout))
	match := regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)(?:\.[0-9]+)?(?:[-+].*)?$`).FindStringSubmatch(version)
	if len(match) != 3 {
		return fmt.Errorf("could not parse Helm client version %q", version)
	}
	major, _ := strconv.Atoi(match[1])
	minor, _ := strconv.Atoi(match[2])
	if major < 3 || (major == 3 && minor < 14) {
		return fmt.Errorf("Helm 3.14 or newer is required for safe gateway lifecycle value merging; client reported %q", version)
	}
	return nil
}

func selectStorageClass(raw []byte, requested string) (string, string, string, error) {
	var list storageClassList
	if err := json.Unmarshal(raw, &list); err != nil {
		return "", "", "", fmt.Errorf("decode StorageClasses: %w", err)
	}
	type candidate struct{ name, provisioner, mode string }
	var candidates []candidate
	for _, item := range list.Items {
		if requested != "" {
			if item.Metadata.Name == requested {
				candidates = append(candidates, candidate{item.Metadata.Name, item.Provisioner, item.VolumeBindingMode})
			}
			continue
		}
		isDefault := strings.EqualFold(item.Metadata.Annotations["storageclass.kubernetes.io/is-default-class"], "true") ||
			strings.EqualFold(item.Metadata.Annotations["storageclass.beta.kubernetes.io/is-default-class"], "true")
		if isDefault {
			candidates = append(candidates, candidate{item.Metadata.Name, item.Provisioner, item.VolumeBindingMode})
		}
	}
	if len(candidates) == 0 {
		if requested != "" {
			return "", "", "", fmt.Errorf("StorageClass %q does not exist", requested)
		}
		return "", "", "", errors.New("no default StorageClass exists; pass --storage-class explicitly after installing a persistent CSI provisioner")
	}
	if len(candidates) > 1 {
		names := make([]string, 0, len(candidates))
		for _, c := range candidates {
			names = append(names, c.name)
		}
		sort.Strings(names)
		return "", "", "", fmt.Errorf("multiple default StorageClasses are ambiguous (%s); pass --storage-class explicitly", strings.Join(names, ", "))
	}
	c := candidates[0]
	if strings.TrimSpace(c.provisioner) == "" {
		return "", "", "", fmt.Errorf("StorageClass %q has no provisioner", c.name)
	}
	mode := c.mode
	if mode == "" {
		mode = "Immediate"
	}
	if mode != "Immediate" && mode != "WaitForFirstConsumer" {
		return "", "", "", fmt.Errorf("StorageClass %q has unsupported volumeBindingMode %q", c.name, mode)
	}
	return c.name, c.provisioner, mode, nil
}

type controlPlaneEndpoints struct {
	apiURL     string
	agentURL   string
	serverName string
}

func deriveControlPlaneEndpoints(meta k8sMeta, credentialServer string) (controlPlaneEndpoints, error) {
	base := strings.TrimSpace(meta.publicBaseURL)
	if base == "" {
		base = strings.TrimSpace(credentialServer)
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return controlPlaneEndpoints{}, errors.New("control-plane public URL is invalid; configure public_base_url or log in with an absolute http(s) URL")
	}
	if u.Scheme != "https" && !isLoopbackHost(u.Hostname()) {
		return controlPlaneEndpoints{}, errors.New("control-plane API URL must use https; plain http is allowed only for an explicit loopback development endpoint")
	}
	apiURL := (&url.URL{Scheme: u.Scheme, Host: u.Host}).String()
	agentURL := strings.TrimSpace(meta.gatewayControl)
	if agentURL == "" {
		host := net.JoinHostPort(u.Hostname(), "8443")
		agentURL = (&url.URL{Scheme: "https", Host: host}).String()
	} else {
		a, parseErr := url.Parse(agentURL)
		if parseErr != nil || (a.Scheme != "https" && a.Scheme != "http") || a.Hostname() == "" || a.User != nil || (a.Path != "" && a.Path != "/") || a.RawQuery != "" || a.Fragment != "" {
			return controlPlaneEndpoints{}, errors.New("configured gateway control URL must be an absolute https URL with no credentials, path, query, or fragment")
		}
		if a.Scheme != "https" && !isLoopbackHost(a.Hostname()) {
			return controlPlaneEndpoints{}, errors.New("configured gateway control URL must use https; plain http is allowed only for an explicit loopback development endpoint")
		}
		agentURL = a.Scheme + "://" + a.Host
	}
	return controlPlaneEndpoints{apiURL: apiURL, agentURL: agentURL, serverName: "tunnex-control"}, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func resolveOrganization(orgs []k8sOrganization, requested string) (k8sOrganization, error) {
	if len(orgs) == 0 {
		return k8sOrganization{}, errors.New("you are not a member of any organization yet")
	}
	requested = strings.TrimSpace(requested)
	if requested == "" {
		if len(orgs) != 1 {
			return k8sOrganization{}, errors.New("this login belongs to multiple organizations; pass --org with the exact id, slug, or name")
		}
		return orgs[0], nil
	}
	var matches []k8sOrganization
	for _, org := range orgs {
		if requested == org.id || requested == org.slug || requested == org.name {
			matches = append(matches, org)
		}
	}
	if len(matches) == 0 {
		return k8sOrganization{}, fmt.Errorf("organization %q was not found in this login", requested)
	}
	if len(matches) > 1 {
		return k8sOrganization{}, fmt.Errorf("organization selector %q is ambiguous; use the organization id", requested)
	}
	return matches[0], nil
}

type imageValues struct {
	reference string
	registry  string
	agent     string
	digest    string
	tag       string
}

func parseImageRef(ref string) (imageValues, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.ContainsAny(ref, "\r\n\x00") {
		return imageValues{}, errors.New("image reference is empty or contains control characters")
	}
	base := ref
	digest := ""
	if at := strings.LastIndex(ref, "@"); at >= 0 {
		base = ref[:at]
		digest = ref[at+1:]
		if !strings.HasPrefix(digest, "sha256:") || len(strings.TrimPrefix(digest, "sha256:")) != 64 || !hexRE.MatchString(strings.TrimPrefix(digest, "sha256:")) {
			return imageValues{}, errors.New("only a complete sha256 digest is accepted after @")
		}
	}
	slash := strings.LastIndex(base, "/")
	if slash <= 0 || slash == len(base)-1 {
		return imageValues{}, errors.New("image must include a registry/repository and image name")
	}
	registry := base[:slash]
	agentAndTag := base[slash+1:]
	tag := ""
	if colon := strings.LastIndex(agentAndTag, ":"); colon >= 0 {
		tag = agentAndTag[colon+1:]
		agentAndTag = agentAndTag[:colon]
	}
	if agentAndTag == "" || strings.ContainsAny(registry+agentAndTag+tag, " ,\t") {
		return imageValues{}, errors.New("image reference contains unsupported characters")
	}
	if digest == "" && tag == "" {
		return imageValues{}, errors.New("image must be pinned by digest or explicit tag")
	}
	return imageValues{reference: ref, registry: registry, agent: agentAndTag, digest: digest, tag: tag}, nil
}

type lifecyclePlan struct {
	SchemaVersion       int                    `json:"schema_version"`
	Action              string                 `json:"action"`
	InstallIntentDigest string                 `json:"install_intent_digest,omitempty"`
	Kubernetes          lifecycleKubernetes    `json:"kubernetes"`
	Organization        *lifecycleOrganization `json:"organization,omitempty"`
	ControlPlane        *lifecycleControlPlane `json:"control_plane,omitempty"`
	HostPosture         lifecycleHostPosture   `json:"host_posture"`
	Gateway             lifecycleGateway       `json:"gateway"`
	Chart               lifecycleChart         `json:"chart"`
	Storage             lifecycleStorage       `json:"storage"`
	ExistingRelease     *helmReleaseSummary    `json:"existing_release,omitempty"`
	Operations          []string               `json:"operations"`
}

type lifecycleKubernetes struct {
	Context   string `json:"context"`
	Namespace string `json:"namespace"`
	Release   string `json:"release"`
}

type lifecycleOrganization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type lifecycleControlPlane struct {
	APIURL     string `json:"api_url"`
	AgentURL   string `json:"agent_url"`
	ServerName string `json:"server_name"`
}

type lifecycleGateway struct {
	NodeName           string              `json:"node_name"`
	Mode               string              `json:"mode"`
	ServiceType        string              `json:"service_type"`
	Endpoint           string              `json:"endpoint"`
	NodePort           int                 `json:"node_port,omitempty"`
	WireGuardPort      int                 `json:"wireguard_port"`
	LoadBalancerIP     string              `json:"load_balancer_ip,omitempty"`
	ServiceAnnotations map[string]string   `json:"service_annotations,omitempty"`
	ImagePullSecrets   []string            `json:"image_pull_secrets,omitempty"`
	NodeSelector       map[string]string   `json:"node_selector,omitempty"`
	Tolerations        []gatewayToleration `json:"tolerations,omitempty"`
	BootstrapSecret    string              `json:"bootstrap_secret,omitempty"`
	BootstrapState     string              `json:"bootstrap_state,omitempty"`
	TokenTransport     string              `json:"token_transport,omitempty"`
	Image              string              `json:"image"`
	Lifecycle          *lifecycleClaimPlan `json:"lifecycle,omitempty"`
}

type lifecycleClaimPlan struct {
	AnchorName          string `json:"anchor_name"`
	Claim               string `json:"claim"`
	RequestID           string `json:"request_id"`
	ExpectedGeneration  int    `json:"expected_generation"`
	Generation          int    `json:"generation"`
	ExpiresAt           string `json:"expires_at,omitempty"`
	State               string `json:"state"`
	InstallOperationID  string `json:"install_operation_id,omitempty"`
	InstallEpoch        int64  `json:"install_epoch,omitempty"`
	InstallIntentDigest string `json:"install_intent_digest,omitempty"`
	CompletedAt         string `json:"completed_at,omitempty"`
}

type lifecycleChart struct {
	Name            string `json:"name"`
	Reference       string `json:"reference"`
	Version         string `json:"version,omitempty"`
	AppVersion      string `json:"app_version,omitempty"`
	ArtifactSHA256  string `json:"artifact_sha256,omitempty"`
	RolloutRevision string `json:"rollout_revision"`
}

type lifecycleStorage struct {
	Claim           string `json:"claim"`
	State           string `json:"state"`
	Class           string `json:"class"`
	Provisioner     string `json:"provisioner"`
	BindingMode     string `json:"binding_mode"`
	Retention       string `json:"retention"`
	PVCUID          string `json:"pvc_uid,omitempty"`
	VolumeName      string `json:"volume_name,omitempty"`
	ResourceVersion string `json:"resource_version,omitempty"`
}

type preparedInstall struct {
	options             installOptions
	plan                lifecyclePlan
	digest              string
	installIntentDigest string
	canonical           []byte
	org                 k8sOrganization
	cp                  k8sControlPlane
	image               imageValues
	state               installState
	anchor              lifecycleAnchorMetadata
	priorInstallAnchor  *lifecycleAnchorMetadata
	completedReplay     *completedInstallReplay
	hostPosture         hostPostureState
	gatewayChart        chartMetadata
	hostPostureChart    chartMetadata
	chartArtifacts      installChartArtifacts
	gatewayArtifact     chartArtifact
	hostPostureArtifact chartArtifact
}

func recoverLifecycleAnchorWithoutSecret(ctx context.Context, cp k8sControlPlane, org k8sOrganization, state installState, anchor lifecycleAnchorMetadata, newRequestID func() string) (lifecycleAnchorMetadata, error) {
	if !state.anchorExists || state.retrySecret {
		return lifecycleAnchorMetadata{}, errors.New("anchor-only lifecycle recovery requires an owned anchor and no bootstrap Secret")
	}
	if anchor.state == "aborting" {
		return lifecycleAnchorMetadata{}, fmt.Errorf("lifecycle claim %s is fenced as aborting; resume abort-install instead of installation", anchor.lifecycleClaim)
	}
	if anchor.installOperationID != "" {
		return lifecycleAnchorMetadata{}, fmt.Errorf("lifecycle install operation %s has no bootstrap Secret; resume abort-install so the exact control-plane operation is reconciled before any remint", anchor.installOperationID)
	}
	status, err := cp.GetLifecycleClaimStatus(ctx, org.id, anchor.lifecycleClaim)
	if errors.Is(err, errK8sLifecycleClaimNotFound) {
		if anchor.state == "pending" && anchor.expectedGeneration == 0 && anchor.generation == 0 && anchor.expiresAt.IsZero() {
			return anchor, nil
		}
		return lifecycleAnchorMetadata{}, errors.New("owned lifecycle anchor references an absent control-plane claim but is not the exact pre-mint generation-zero state")
	}
	if err != nil {
		return lifecycleAnchorMetadata{}, fmt.Errorf("read lifecycle claim for anchor-only recovery: %w", err)
	}
	if status.claim != anchor.lifecycleClaim || status.nodeName != anchor.nodeName || status.nodeID != "" {
		return lifecycleAnchorMetadata{}, errors.New("control-plane lifecycle claim identity does not match the owned anchor-only recovery state")
	}
	now := time.Now()
	statusExpired := status.state == "expired" && !status.expiresAt.After(now)
	statusIssued := status.state == "issued" && status.expiresAt.After(now)
	rotate := func() (lifecycleAnchorMetadata, error) {
		requestID := newRequestID()
		if _, parseErr := uuid.Parse(requestID); parseErr != nil || requestID == status.requestID || requestID == anchor.requestID {
			return lifecycleAnchorMetadata{}, errors.New("could not allocate a fresh lifecycle request identity for expired anchor recovery")
		}
		anchor.requestID = requestID
		anchor.expectedGeneration = status.generation
		anchor.generation = status.generation
		anchor.state = "pending"
		anchor.expiresAt = status.expiresAt
		return anchor, nil
	}
	switch anchor.state {
	case "pending":
		// Crash after persisting the new request and deleting the old Secret,
		// but before the CP remint. The CP still reports generation N under the
		// prior request while the anchor authorizes N -> N+1.
		if statusExpired && status.generation == anchor.expectedGeneration && status.generation == anchor.generation && status.requestID != anchor.requestID {
			return anchor, nil
		}
		// Crash after CP mint but before response metadata/Secret persistence.
		// The same unexpired request is safely redeliverable. Once it expires,
		// persist a fresh N+1 -> N+2 request before contacting the CP again.
		if status.generation == anchor.expectedGeneration+1 && status.requestID == anchor.requestID {
			if statusIssued {
				return anchor, nil
			}
			if statusExpired {
				return rotate()
			}
		}
	case "issued":
		if status.generation == anchor.generation && status.requestID == anchor.requestID && status.expiresAt.Equal(anchor.expiresAt) {
			if statusIssued {
				return anchor, nil
			}
			if statusExpired {
				return rotate()
			}
		}
	}
	return lifecycleAnchorMetadata{}, fmt.Errorf("owned lifecycle anchor without a Secret is not recoverable from control-plane state %q generation %d", status.state, status.generation)
}

func prepareInstall(ctx context.Context, o installOptions, deps k8sDeps) (prepared preparedInstall, retErr error) {
	contextName, err := runToolContextPreflight(ctx, deps, o.kubeContext)
	if err != nil {
		return preparedInstall{}, err
	}
	o.kubeContext = contextName
	state, err := discoverInstallState(ctx, deps.runner, o)
	if err != nil {
		return preparedInstall{}, err
	}
	if state.anchorExists && state.anchorState == "aborting" {
		return preparedInstall{}, fmt.Errorf("lifecycle claim %s is fenced as aborting; resume 'tunnex k8s abort-install --release %s --namespace %s --context %s --claim %s'", state.anchorLifecycleClaim, o.release, o.namespace, o.kubeContext, state.anchorLifecycleClaim)
	}
	artifacts := installChartArtifacts{}
	keepArtifacts := false
	defer func() {
		if !keepArtifacts {
			retErr = errors.Join(retErr, finalizeChartCleanup(artifacts.root, artifacts.cleanupRoot, false, deps.errOut))
		}
	}()
	gatewayChart := chartMetadata{}
	hostPostureChart := chartMetadata{}
	if state.resumeCleanup || state.completedReplay {
		gatewayChart = chartMetadata{Reference: state.resumeRelease.Chart, Name: "tunnex-gateway", Version: strings.TrimPrefix(state.resumeRelease.Chart, "tunnex-gateway-"), AppVersion: state.resumeRelease.AppVersion}
	} else {
		artifacts, err = materializeInstallChartsWithCleanup(ctx, deps.runner, o.kubeContext, o, deps.cleanupChartRoot)
		if err != nil {
			return preparedInstall{}, err
		}
		gatewayChart = artifacts.gateway.Metadata
		hostPostureChart = artifacts.hostPosture.Metadata
		// Pin both local and OCI chart metadata into the approved options. Local
		// charts do not accept --version, but their exact Chart.yaml version and
		// appVersion are still part of the plan and the post-approval readback.
		o.chartVersion = gatewayChart.Version
		o.hostPostureVersion = hostPostureChart.Version
	}
	preflight, err := resolveInstallStorage(ctx, deps, o, state)
	if err != nil {
		return preparedInstall{}, err
	}
	cred, err := deps.loadCredential()
	if err != nil {
		return preparedInstall{}, err
	}
	cp, err := deps.newControlPlane(cred)
	if err != nil {
		return preparedInstall{}, err
	}
	meta, err := cp.GetMeta(ctx)
	if err != nil {
		return preparedInstall{}, err
	}
	endpoints, err := deriveControlPlaneEndpoints(meta, cred.Server)
	if err != nil {
		return preparedInstall{}, err
	}
	orgs, err := cp.ListOrganizations(ctx)
	if err != nil {
		return preparedInstall{}, err
	}
	orgSelector := o.org
	if state.anchorExists {
		orgSelector = state.anchorOrgID
	} else if state.completedReplay {
		orgSelector = state.pvcOrganizationID
	}
	org, err := resolveOrganization(orgs, orgSelector)
	if err != nil {
		return preparedInstall{}, err
	}
	if state.anchorExists && o.org != "" {
		requestedOrg, resolveErr := resolveOrganization(orgs, o.org)
		if resolveErr != nil {
			return preparedInstall{}, resolveErr
		}
		if requestedOrg.id != state.anchorOrgID {
			return preparedInstall{}, errors.New("owned lifecycle anchor is pinned to a different organization")
		}
	}
	if state.completedReplay && o.org != "" {
		requestedOrg, resolveErr := resolveOrganization(orgs, o.org)
		if resolveErr != nil {
			return preparedInstall{}, resolveErr
		}
		if requestedOrg.id != state.pvcOrganizationID {
			return preparedInstall{}, errors.New("completed-install replay PVC is pinned to a different organization")
		}
	}
	if err := validateRetainedPVCReuseControlPlane(ctx, cp, org, o, &state); err != nil {
		return preparedInstall{}, err
	}
	imageRef := o.image
	if imageRef == "" {
		imageRef = implicitPinnedImage(meta.nodeAgentImage)
	}
	image := imageValues{}
	if imageRef != "" {
		image, err = parseImageRef(imageRef)
		if err != nil {
			return preparedInstall{}, fmt.Errorf("control-plane node-agent image is invalid: %w", err)
		}
	}
	hostPostureState, err := discoverHostPostureState(ctx, deps.runner, o.kubeContext)
	if err != nil {
		return preparedInstall{}, err
	}
	hostPostureOperation := "verify and reuse exact cluster-wide host posture manager"
	var hostPosturePlan lifecycleHostPosture
	if state.resumeCleanup || state.completedReplay {
		hostPosturePlan, hostPostureChart, err = planExistingHostPostureCleanup(hostPostureState)
		if err != nil {
			return preparedInstall{}, err
		}
	} else {
		hostPosturePlan, err = planHostPosture(o, hostPostureState, image, hostPostureChart, artifacts.hostPosture.SHA256)
		if err != nil {
			return preparedInstall{}, err
		}
		if hostPosturePlan.Action != "reuse" {
			hostPostureOperation = hostPosturePlan.Action + " exact cluster-wide host posture manager before gateway enrollment"
		}
	}
	if state.completedReplay {
		replay, replayErr := loadCompletedInstallReplay(ctx, cp, org, o, state)
		if replayErr != nil {
			return preparedInstall{}, replayErr
		}
		completedAt := replay.operation.completedAt.UTC().Format(time.RFC3339Nano)
		expiresAt := replay.claim.expiresAt.UTC().Format(time.RFC3339Nano)
		lifecycle := &lifecycleClaimPlan{
			Claim: replay.claim.claim, RequestID: replay.claim.requestID, Generation: replay.claim.generation,
			ExpiresAt: expiresAt, State: string(replay.operation.state), InstallOperationID: replay.operation.operationID,
			InstallEpoch: replay.operation.epoch, InstallIntentDigest: replay.operation.installIntentDigest, CompletedAt: completedAt,
		}
		plan := lifecyclePlan{
			SchemaVersion:       1,
			Action:              "replay-completed-install",
			InstallIntentDigest: replay.operation.installIntentDigest,
			Kubernetes:          lifecycleKubernetes{Context: preflight.context, Namespace: o.namespace, Release: o.release},
			Organization:        &lifecycleOrganization{ID: org.id, Name: org.name},
			ControlPlane:        &lifecycleControlPlane{APIURL: endpoints.apiURL, AgentURL: endpoints.agentURL, ServerName: endpoints.serverName},
			HostPosture:         hostPosturePlan,
			Gateway: lifecycleGateway{
				NodeName: o.nodeName, Mode: o.mode, ServiceType: o.serviceType, Endpoint: endpointPlanValue(o), NodePort: o.nodePort,
				WireGuardPort: defaultK8sWireGuardPort, LoadBalancerIP: o.loadBalancerIP,
				ServiceAnnotations: serviceAnnotationMap(o.serviceAnnotations), ImagePullSecrets: append([]string(nil), o.imagePullSecrets...),
				NodeSelector: gatewaySelectorMap(o.gatewaySelectors), Tolerations: append([]gatewayToleration(nil), o.gatewayTolerations...),
				BootstrapState: "completed token-blind lifecycle proof; no recovery metadata exists", TokenTransport: "none; read-only completed replay",
				Image: "existing release; unchanged", Lifecycle: lifecycle,
			},
			Chart: lifecycleChart{
				Name: "tunnex-gateway", Reference: state.resumeRelease.Chart, Version: "installed revision " + state.resumeRelease.Revision,
				AppVersion: state.resumeRelease.AppVersion, RolloutRevision: rolloutRevision(replay.operation.installIntentDigest),
			},
			Storage: lifecycleStorage{
				Claim: state.pvcName, State: "verify exact retained completed identity", Class: preflight.storageClass,
				Provisioner: preflight.storageProvisioner, BindingMode: preflight.bindingMode, Retention: "retain on uninstall",
				PVCUID: state.pvcUID, VolumeName: state.pvcVolumeName, ResourceVersion: state.pvcResourceVersion,
			},
			ExistingRelease: &state.resumeRelease,
			Operations: []string{
				"recheck exact release/PVC completed-replay fingerprint", "verify exact completed control-plane install operation",
				"verify exact consumed lifecycle claim and node binding", "verify Deployment, Service, Helm revision, PVC provenance, and rollout readiness",
				"repeat exact control-plane and Kubernetes readback", "return success without mutating Helm, Kubernetes, lifecycle claim, or install operation state",
			},
		}
		canonical, digest, planErr := canonicalPlan(plan)
		if planErr != nil {
			return preparedInstall{}, planErr
		}
		return preparedInstall{
			options: o, plan: plan, digest: digest, canonical: canonical, org: org, cp: cp, image: image, state: state,
			completedReplay: &replay, hostPosture: hostPostureState, gatewayChart: gatewayChart, hostPostureChart: hostPostureChart,
		}, nil
	}
	anchor := lifecycleAnchorMetadata{}
	var priorInstallAnchor *lifecycleAnchorMetadata
	if o.mode == "enroll" {
		anchor = lifecycleAnchorMetadata{
			name: o.release + "-lifecycle", appName: "tunnex-gateway-lifecycle", instance: o.release, managedBy: "tunnex-lifecycle", immutable: true,
			orgID: org.id, nodeName: o.nodeName, lifecycleClaim: deps.newClaimID(), requestID: deps.newRequestID(), expectedGeneration: 0, generation: 0, state: "pending",
		}
		if state.anchorExists {
			anchor = lifecycleAnchorMetadata{
				name: state.anchorName, uid: state.anchorUID, resourceVersion: state.anchorResourceVersion,
				appName: "tunnex-gateway-lifecycle", instance: o.release, managedBy: "tunnex-lifecycle", immutable: true,
				orgID: state.anchorOrgID, nodeName: state.anchorNodeName, lifecycleClaim: state.anchorLifecycleClaim,
				requestID: state.anchorRequestID, expectedGeneration: state.anchorExpectedGen, generation: state.anchorGeneration,
				state: state.anchorState, expiresAt: state.anchorExpiresAt,
				installOperationID: state.anchorInstallOperationID, installOperationEpoch: state.anchorInstallOperationEpoch,
				installOperationDurationSeconds: state.anchorInstallOperationDurationSeconds,
				installOperationNotAfter:        state.anchorInstallOperationNotAfter, installIntentDigest: state.anchorInstallIntentDigest,
				releaseNamespace: state.anchorReleaseNamespace, releaseName: state.anchorReleaseName,
			}
			if anchor.orgID != org.id || anchor.nodeName != o.nodeName {
				return preparedInstall{}, errors.New("owned lifecycle anchor is pinned to a different organization or node name")
			}
			if !state.resumeCleanup && state.retrySecret && !state.secretExpiresAt.After(time.Now()) && anchor.installOperationID != "" {
				persisted := anchor
				priorInstallAnchor = &persisted
				anchor.installOperationID = ""
				anchor.installOperationEpoch = 0
				anchor.installOperationDurationSeconds = 0
				anchor.installOperationNotAfter = time.Time{}
				anchor.installIntentDigest = ""
				anchor.releaseNamespace = ""
				anchor.releaseName = ""
			}
			if !state.resumeCleanup && state.retrySecret && !state.secretExpiresAt.After(time.Now()) && anchor.state != "pending" {
				anchor.requestID = deps.newRequestID()
				anchor.expectedGeneration = state.secretGeneration
				anchor.generation = state.secretGeneration
				anchor.state = "pending"
			}
			if !state.resumeCleanup && !state.retrySecret {
				anchor, err = recoverLifecycleAnchorWithoutSecret(ctx, cp, org, state, anchor, deps.newRequestID)
				if err != nil {
					return preparedInstall{}, err
				}
			}
		}
	}
	if state.resumeCleanup {
		secretName := ""
		bootstrapState := "consumed lifecycle anchor retained after Helm release creation"
		operations := []string{hostPostureOperation, "recheck exact release/claim/anchor fingerprint", "verify existing Helm release is deployed", "verify Deployment and Service readiness", "verify exact state claim UID and bound volume", "verify exact control-plane claim is consumed and node-bound", "delete only the owned lifecycle anchor with UID/resourceVersion preconditions"}
		if state.retrySecret {
			secretName = o.release + "-bootstrap"
			bootstrapState = "owned Secret and lifecycle anchor retained after Helm release creation"
			operations[len(operations)-1] = "delete only the owned bootstrap Secret and lifecycle anchor with UID/resourceVersion preconditions"
		}
		expiresAt := ""
		if !anchor.expiresAt.IsZero() {
			expiresAt = anchor.expiresAt.UTC().Format(time.RFC3339Nano)
		}
		lifecycle := &lifecycleClaimPlan{
			AnchorName: anchor.name, Claim: anchor.lifecycleClaim, RequestID: anchor.requestID,
			ExpectedGeneration: anchor.expectedGeneration, Generation: anchor.generation, ExpiresAt: expiresAt, State: anchor.state,
		}
		plan := lifecyclePlan{
			SchemaVersion: 1,
			Action:        "resume-install-cleanup",
			Kubernetes:    lifecycleKubernetes{Context: preflight.context, Namespace: o.namespace, Release: o.release},
			Organization:  &lifecycleOrganization{ID: org.id, Name: org.name},
			ControlPlane:  &lifecycleControlPlane{APIURL: endpoints.apiURL, AgentURL: endpoints.agentURL, ServerName: endpoints.serverName},
			HostPosture:   hostPosturePlan,
			Gateway: lifecycleGateway{
				NodeName: o.nodeName, Mode: o.mode, ServiceType: o.serviceType, Endpoint: endpointPlanValue(o), NodePort: o.nodePort, WireGuardPort: defaultK8sWireGuardPort,
				LoadBalancerIP: o.loadBalancerIP, ServiceAnnotations: serviceAnnotationMap(o.serviceAnnotations), ImagePullSecrets: append([]string(nil), o.imagePullSecrets...),
				NodeSelector: gatewaySelectorMap(o.gatewaySelectors), Tolerations: append([]gatewayToleration(nil), o.gatewayTolerations...),
				BootstrapSecret: secretName, BootstrapState: bootstrapState,
				TokenTransport: "metadata only; token is never read or reminted", Image: "existing release; unchanged", Lifecycle: lifecycle,
			},
			Chart: lifecycleChart{Name: "tunnex-gateway", Reference: state.resumeRelease.Chart, Version: "installed revision " + state.resumeRelease.Revision, AppVersion: state.resumeRelease.AppVersion, RolloutRevision: "unchanged"},
			Storage: lifecycleStorage{
				Claim: state.pvcName, State: "verify exact Bound identity claim", Class: preflight.storageClass,
				Provisioner: preflight.storageProvisioner, BindingMode: preflight.bindingMode, Retention: "retain on uninstall",
				PVCUID: state.pvcUID, VolumeName: state.pvcVolumeName, ResourceVersion: state.pvcResourceVersion,
			},
			ExistingRelease: &state.resumeRelease,
			Operations:      operations,
		}
		canonical, digest, planErr := canonicalPlan(plan)
		if planErr != nil {
			return preparedInstall{}, planErr
		}
		return preparedInstall{options: o, plan: plan, digest: digest, canonical: canonical, org: org, cp: cp, image: image, state: state, anchor: anchor, hostPosture: hostPostureState, gatewayChart: gatewayChart, hostPostureChart: hostPostureChart, chartArtifacts: artifacts, gatewayArtifact: artifacts.gateway, hostPostureArtifact: artifacts.hostPosture}, nil
	}
	secretName := ""
	bootstrapState := ""
	tokenTransport := ""
	claim := o.existingClaim
	storageState := "existing retained claim with exact consumed lifecycle provenance"
	operations := []string{hostPostureOperation, "recheck release, claim ownership, immutable lifecycle provenance, and bound node UUID", "create namespace only if absent", "Helm atomic install", "verify Deployment readiness", "verify Service endpoint"}
	if o.mode == "enroll" {
		secretName = o.release + "-bootstrap"
		claim = gatewayFullname(o.release) + "-state"
		storageState = "create new retained claim"
		if state.retrySecret {
			if state.secretExpiresAt.After(time.Now()) {
				bootstrapState = "bounded retry using existing Tunnex-owned Secret"
				tokenTransport = "existing Secret metadata only; value is not read"
				operations = []string{hostPostureOperation, "recheck release/Secret/claim/anchor fingerprint", "verify exact control-plane lifecycle claim", "acknowledge existing Secret CAS without reading it", "Helm atomic install", "verify Deployment readiness", "verify Service endpoint", "verify exact enrolled lifecycle identity", "delete consumed bootstrap Secret and lifecycle anchor"}
			} else {
				bootstrapState = "expired owned Secret; CAS remint planned"
				tokenTransport = "token-blind anchor CAS, sealed idempotent remint, create-only Secret stdin"
				operations = []string{hostPostureOperation, "recheck release/Secret/claim/anchor fingerprint", "prove cluster and control-plane retry-safe state", "persist new request identity in lifecycle anchor", "CAS-delete expired immutable Secret", "redeliver or remint exact lifecycle token", "create replacement immutable Secret", "acknowledge Secret CAS", "Helm atomic install", "verify exact enrolled lifecycle identity", "delete consumed bootstrap Secret and lifecycle anchor"}
				if priorInstallAnchor != nil {
					operations = []string{hostPostureOperation, "recheck release/Secret/claim/anchor fingerprint", "refresh exact expired lifecycle install operation", "Release the expired operation only after exact epoch/deadline proof", "prove exact Helm release/workload and PVC mount absence", "CAS-retire old operation metadata while persisting the next lifecycle request", "CAS-delete expired immutable Secret", "redeliver or remint exact lifecycle token", "create replacement immutable Secret", "acknowledge Secret CAS", "Helm atomic install", "verify exact enrolled lifecycle identity", "delete consumed bootstrap Secret and lifecycle anchor"}
				}
			}
			if state.pvcExists {
				storageState = "reuse retained retry claim"
			}
		} else {
			if state.anchorExists {
				bootstrapState = "owned lifecycle anchor recovery with no Secret"
				tokenTransport = "token-blind control-plane status/CAS recovery; Secret stdin only; value redacted"
				operations = []string{hostPostureOperation, "recheck release/claim/anchor fingerprint", "verify exact control-plane lifecycle state", "CAS-persist a new request only when the prior sealed response expired", "redeliver or remint the exact lifecycle token", "stream create-only immutable bootstrap Secret to kubectl stdin", "acknowledge Secret CAS", "Helm atomic install", "verify exact enrolled lifecycle identity", "delete consumed bootstrap Secret and lifecycle anchor"}
			} else {
				bootstrapState = "new create-only lifecycle anchor and Secret"
				tokenTransport = "token-blind anchor before control-plane mint; Secret stdin only; value redacted"
				operations = []string{hostPostureOperation, "recheck release/Secret/claim/anchor fingerprint", "create namespace only if absent", "create token-blind lifecycle anchor", "mint or redeliver exact claim token", "stream create-only immutable bootstrap Secret to kubectl stdin", "acknowledge Secret CAS", "Helm atomic install", "verify Deployment readiness", "verify Service endpoint", "verify exact enrolled lifecycle identity", "delete consumed bootstrap Secret and lifecycle anchor"}
			}
		}
		operations = describeFencedLifecycleInstallOperations(operations)
	}
	var lifecycle *lifecycleClaimPlan
	if o.mode == "enroll" {
		expiresAt := ""
		if !anchor.expiresAt.IsZero() {
			expiresAt = anchor.expiresAt.UTC().Format(time.RFC3339Nano)
		}
		lifecycle = &lifecycleClaimPlan{
			AnchorName: anchor.name, Claim: anchor.lifecycleClaim, RequestID: anchor.requestID,
			ExpectedGeneration: anchor.expectedGeneration, Generation: anchor.generation, ExpiresAt: expiresAt, State: anchor.state,
		}
	}
	plan := lifecyclePlan{
		SchemaVersion: 1,
		Action:        "install",
		Kubernetes:    lifecycleKubernetes{Context: preflight.context, Namespace: o.namespace, Release: o.release},
		Organization:  &lifecycleOrganization{ID: org.id, Name: org.name},
		ControlPlane:  &lifecycleControlPlane{APIURL: endpoints.apiURL, AgentURL: endpoints.agentURL, ServerName: endpoints.serverName},
		HostPosture:   hostPosturePlan,
		Gateway: lifecycleGateway{
			NodeName: o.nodeName, Mode: o.mode, ServiceType: o.serviceType, Endpoint: endpointPlanValue(o),
			NodePort:           o.nodePort,
			WireGuardPort:      defaultK8sWireGuardPort,
			LoadBalancerIP:     o.loadBalancerIP,
			ServiceAnnotations: serviceAnnotationMap(o.serviceAnnotations),
			ImagePullSecrets:   append([]string(nil), o.imagePullSecrets...),
			NodeSelector:       gatewaySelectorMap(o.gatewaySelectors),
			Tolerations:        append([]gatewayToleration(nil), o.gatewayTolerations...),
			BootstrapSecret:    secretName, BootstrapState: bootstrapState, TokenTransport: tokenTransport, Image: plannedImageReference(image, gatewayChart.AppVersion), Lifecycle: lifecycle,
		},
		Chart: lifecycleChart{Name: gatewayChart.Name, Reference: o.chart, Version: gatewayChart.Version, AppVersion: gatewayChart.AppVersion, ArtifactSHA256: artifacts.gateway.SHA256, RolloutRevision: "derived from stable install intent digest"},
		Storage: lifecycleStorage{
			Claim: claim, State: storageState, Class: preflight.storageClass, Provisioner: preflight.storageProvisioner,
			BindingMode: preflight.bindingMode, Retention: "retain on uninstall", PVCUID: state.pvcUID,
			VolumeName: state.pvcVolumeName, ResourceVersion: state.pvcResourceVersion,
		},
		Operations: operations,
	}
	prepared = preparedInstall{
		options: o, plan: plan, org: org, cp: cp, image: image, state: state, anchor: anchor, priorInstallAnchor: priorInstallAnchor, hostPosture: hostPostureState,
		gatewayChart: gatewayChart, hostPostureChart: hostPostureChart, chartArtifacts: artifacts,
		gatewayArtifact: artifacts.gateway, hostPostureArtifact: artifacts.hostPosture,
	}
	if o.mode == "enroll" {
		_, intentDigest, intentErr := computeLifecycleInstallIntent(prepared)
		if intentErr != nil {
			return preparedInstall{}, fmt.Errorf("build stable lifecycle install intent: %w", intentErr)
		}
		plan.InstallIntentDigest = intentDigest
		prepared.plan = plan
		prepared.installIntentDigest = intentDigest
	}
	canonical, digest, err := canonicalPlan(plan)
	if err != nil {
		return preparedInstall{}, err
	}
	prepared.canonical = canonical
	prepared.digest = digest
	keepArtifacts = true
	return prepared, nil
}

func implicitPinnedImage(ref string) string {
	ref = strings.TrimSpace(ref)
	if strings.Contains(ref, "@sha256:") {
		return ref
	}
	return ""
}

func endpointPlanValue(o installOptions) string {
	if o.endpoint != "" {
		return o.endpoint
	}
	return "discover from Service status.loadBalancer.ingress"
}

func canonicalPlan(plan any) ([]byte, string, error) {
	canonical, err := json.Marshal(plan)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(canonical)
	return canonical, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func printPlan(out io.Writer, canonical []byte, digest string) error {
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, canonical, "", "  "); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "%s\nPlan digest: %s\n", pretty.String(), digest); err != nil {
		return err
	}
	return nil
}

func requireApproval(in io.Reader, out io.Writer, digest string, yes bool) error {
	if yes {
		return nil
	}
	if _, err := fmt.Fprintf(out, "Apply plan %s? [y/N]: ", digest); err != nil {
		return err
	}
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	if answer != "y" && answer != "yes" {
		return errors.New("plan was not approved")
	}
	return nil
}

func runK8sPlan(ctx context.Context, args []string, deps k8sDeps) (retErr error) {
	o, err := parseInstallOptions(args, deps)
	if err != nil {
		return err
	}
	prepared, err := prepareInstall(ctx, o, deps)
	if err != nil {
		return err
	}
	defer func() {
		retErr = errors.Join(retErr, finalizeChartCleanup(prepared.chartArtifacts.root, prepared.chartArtifacts.cleanupRoot, false, deps.errOut))
	}()
	return printPlan(deps.out, prepared.canonical, prepared.digest)
}

func runK8sInstall(ctx context.Context, args []string, deps k8sDeps) (retErr error) {
	o, err := parseInstallOptions(args, deps)
	if err != nil {
		return err
	}
	prepared, err := prepareInstall(ctx, o, deps)
	if err != nil {
		return err
	}
	helmMutationConfirmed := false
	defer func() {
		retErr = errors.Join(retErr, finalizeChartCleanup(prepared.chartArtifacts.root, prepared.chartArtifacts.cleanupRoot, helmMutationConfirmed, deps.errOut))
	}()
	if err := printPlan(deps.out, prepared.canonical, prepared.digest); err != nil {
		return err
	}
	if err := requireApproval(deps.in, deps.out, prepared.digest, o.yes); err != nil {
		return err
	}
	// prepareInstall resolves an implicit current-context to one exact context.
	// Pin every post-approval read and mutation to that approved context; the
	// user's ambient current-context may change while the plan is reviewed.
	o = prepared.options
	var reuseFence *retainedStateFence
	var reuseRenewal *retainedStateFenceRenewal
	reuseReady := false
	if o.mode == "reuse" {
		binding, bindingErr := retainedStateFenceBindingForReuse(prepared)
		if bindingErr != nil {
			return bindingErr
		}
		reuseFence, err = acquireRetainedStateFence(ctx, deps, binding, retainedStateFenceOperationReuse, func(reproofCtx context.Context) error {
			return reproveReuseStateFence(reproofCtx, deps, prepared, binding, prepared.state.fingerprint())
		})
		if err != nil {
			return err
		}
		reuseRenewal = startRetainedStateFenceRenewal(ctx, deps, reuseFence)
		ctx = reuseRenewal.ctx
		defer func() {
			safeToRelease := reuseReady
			var safeProofErr error
			if !safeToRelease {
				if cause := context.Cause(reuseRenewal.ctx); cause != nil {
					safeProofErr = cause
				} else {
					safeProofErr = reproveReuseStateFence(reuseRenewal.ctx, deps, prepared, binding, "")
					safeToRelease = safeProofErr == nil
				}
			}
			renewErr := reuseRenewal.stop()
			if renewErr != nil {
				retErr = errors.Join(retErr, renewErr)
				return
			}
			if !safeToRelease {
				retErr = errors.Join(retErr, fmt.Errorf("retained-state Lease remains until its bounded expiry because a safe release/UID/mount reproof failed: %w", safeProofErr))
				return
			}
			cleanupCtx, cancel := retainedStateFenceCleanupContext()
			defer cancel()
			retErr = errors.Join(retErr, reuseFence.release(cleanupCtx))
		}()
	}
	currentState, err := discoverInstallState(ctx, deps.runner, o)
	if err != nil {
		return err
	}
	if err := validateRetainedPVCReuseControlPlane(ctx, prepared.cp, prepared.org, o, &currentState); err != nil {
		return fmt.Errorf("re-prove retained claim control-plane identity after approval: %w", err)
	}
	if currentState.fingerprint() != prepared.state.fingerprint() {
		return errors.New("Kubernetes or control-plane release/Secret/claim identity changed after plan approval; no token was minted and nothing was installed — rerun the command to review a fresh plan")
	}
	if prepared.state.resumeCleanup {
		if err := recheckHealthyHostPosture(ctx, deps.runner, o.kubeContext, prepared.hostPosture); err != nil {
			return fmt.Errorf("cluster-wide host posture manager changed or became unhealthy after cleanup approval: %w", err)
		}
		return resumePostInstallCleanup(ctx, deps, prepared)
	}
	if prepared.state.completedReplay {
		if err := recheckHealthyHostPosture(ctx, deps.runner, o.kubeContext, prepared.hostPosture); err != nil {
			return fmt.Errorf("cluster-wide host posture manager changed or became unhealthy after completed-replay approval: %w", err)
		}
		return runCompletedInstallReplay(ctx, deps, prepared)
	}
	if err := recheckPreparedChartArtifacts(prepared); err != nil {
		return err
	}
	if err := ensureHostPostureManager(ctx, deps, prepared, func() { helmMutationConfirmed = true }); err != nil {
		return fmt.Errorf("cluster-wide host posture manager is not ready; no gateway token was minted: %w", err)
	}
	if err := applyNamespace(ctx, deps.runner, o.kubeContext, o.namespace); err != nil {
		return err
	}
	secretName := prepared.plan.Gateway.BootstrapSecret
	var ownedSecret *bootstrapSecretMetadata
	var ownedAnchor lifecycleAnchorMetadata
	var installAuthority *lifecycleInstallAuthority
	var installMonitor *lifecycleInstallMonitor
	var cancelInstallDeadline context.CancelFunc
	installAuthorityTerminal := false
	installHelmStarted := false
	installHolderStopped := false
	token := ""
	defer func() {
		if installMonitor != nil {
			monitorErr := installMonitor.stop()
			if errors.Is(monitorErr, errLifecycleInstallAbortRequested) || errors.Is(monitorErr, errLifecycleInstallDeadline) {
				installHolderStopped = true
			}
			retErr = errors.Join(retErr, monitorErr)
			installMonitor = nil
		}
		if cancelInstallDeadline != nil {
			cancelInstallDeadline()
			cancelInstallDeadline = nil
		}
		if installAuthority != nil && !installAuthorityTerminal {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()
			retErr = errors.Join(retErr, reconcileLifecycleInstallFailure(cleanupCtx, deps, *installAuthority, prepared, installHelmStarted, installHolderStopped))
		}
	}()
	if o.mode == "enroll" {
		ownedSecret, ownedAnchor, token, err = ensureLifecycleBootstrap(ctx, deps, prepared)
		if err != nil {
			return err
		}
		prepared.anchor = ownedAnchor
		authority, authorityErr := prepareLifecycleInstallAuthority(ctx, deps, prepared, ownedAnchor)
		if authorityErr != nil {
			return authorityErr
		}
		installAuthority = &authority
		ownedAnchor = authority.anchor
		prepared.anchor = authority.anchor
		installMonitor, cancelInstallDeadline = startLifecycleInstallMonitor(ctx, deps, authority)
	}
	helmCommand, commandErr := installHelmCommand(prepared)
	if commandErr != nil {
		return commandErr
	}
	mutationCtx := ctx
	if installMonitor != nil {
		mutationCtx = installMonitor.mutationCtx
		if err := installAuthority.proveAnchor(mutationCtx, deps, prepared); err != nil {
			return fmt.Errorf("final lifecycle install authority proof before Helm: %w", err)
		}
	}
	installHelmStarted = installAuthority != nil
	// Helm owns its ordinary --timeout and --atomic cleanup. The lifecycle
	// mutation context remains authoritative for abort, authority loss, and the
	// separately budgeted hard deadline; an equal-time outer deadline would kill
	// Helm before it can remove a failed pending-install revision.
	_, helmErr := runCheckedSecrets(mutationCtx, deps.runner, "install gateway release", helmCommand, token)
	mutationCause := context.Cause(mutationCtx)
	if helmErr != nil {
		installHolderStopped = errors.Is(mutationCause, errLifecycleInstallAbortRequested) || errors.Is(mutationCause, errLifecycleInstallDeadline)
		if mutationCause != nil {
			helmErr = errors.Join(helmErr, mutationCause)
		}
		if secretName != "" {
			return fmt.Errorf("%w; bootstrap Secret %q was retained for bounded retry", helmErr, secretName)
		}
		return helmErr
	}
	helmMutationConfirmed = true
	if err := verifyGateway(mutationCtx, deps.runner, o.kubeContext, o.namespace, o.release, o.serviceType, o.endpoint, o.nodePort, o.timeout); err != nil {
		if secretName != "" {
			return fmt.Errorf("%w; bootstrap Secret %q was retained because real readiness was not verified", err, secretName)
		}
		return err
	}
	if err := verifyInstalledGatewayState(mutationCtx, deps.runner, prepared); err != nil {
		if secretName != "" {
			return fmt.Errorf("%w; bootstrap Secret %q was retained because the persistent gateway identity was not verified", err, secretName)
		}
		return err
	}
	if o.mode == "reuse" {
		reuseReady = true
	}
	if o.mode == "enroll" {
		if err := verifyLifecycleConsumed(mutationCtx, prepared, ownedAnchor); err != nil {
			return fmt.Errorf("%w; bootstrap Secret %q and lifecycle anchor %q were retained because exact control-plane enrollment was not verified", err, secretName, ownedAnchor.name)
		}
		if monitorErr := installMonitor.stop(); monitorErr != nil {
			installMonitor = nil
			installHolderStopped = errors.Is(monitorErr, errLifecycleInstallAbortRequested) || errors.Is(monitorErr, errLifecycleInstallDeadline)
			return fmt.Errorf("lifecycle install authority was lost before completion: %w", monitorErr)
		}
		installMonitor = nil
		if err := installAuthority.complete(mutationCtx); err != nil {
			// Do not let the generic defer guess after Complete begins. Refresh the
			// exact operation: a lost durable 200 is success, while an exact
			// active/abort-requested authority is explicitly released.
			installAuthorityTerminal = true
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			completed, reconcileErr := reconcileLifecycleInstallCompleteError(cleanupCtx, *installAuthority)
			cancel()
			if !completed {
				return fmt.Errorf("complete exact lifecycle install operation failed; recovery metadata was retained: %w", errors.Join(err, reconcileErr))
			}
		}
		installAuthorityTerminal = true
		if cancelInstallDeadline != nil {
			cancelInstallDeadline()
			cancelInstallDeadline = nil
		}
	}
	if secretName != "" {
		if ownedSecret == nil {
			return fmt.Errorf("gateway is ready, but bootstrap Secret %q ownership metadata is unavailable; refusing an unguarded delete", secretName)
		}
		if err := deleteOwnedBootstrapSecret(ctx, deps.runner, o.kubeContext, o.namespace, o.timeout, secretName, o.release, ownedAnchor, *ownedSecret); err != nil {
			return fmt.Errorf("gateway is ready, but consumed bootstrap Secret %q could not be deleted: %w", secretName, err)
		}
		if err := deleteOwnedLifecycleAnchor(ctx, deps.runner, o.kubeContext, o.namespace, o.timeout, o.release, ownedAnchor); err != nil {
			return fmt.Errorf("gateway is ready and bootstrap Secret was removed, but lifecycle anchor %q cleanup failed: %w", ownedAnchor.name, err)
		}
	}
	_, err = fmt.Fprintf(deps.out, "Gateway %q is ready. State claim %q is retained on uninstall.\n", o.release, prepared.plan.Storage.Claim)
	return err
}

func applyNamespace(ctx context.Context, runner k8sRunner, kubeContext, namespace string) error {
	// Read with --ignore-not-found so an existing customer namespace is never
	// applied, relabelled, or otherwise claimed by Tunnex.
	get := k8sCommand{name: "kubectl", args: kubectlArgs(kubeContext, "get", "namespace", namespace, "--ignore-not-found=true", "--output", "name")}
	result, err := runChecked(ctx, runner, "check gateway namespace", get)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(result.stdout)) != "" {
		return nil
	}
	_, createErr := runChecked(ctx, runner, "create gateway namespace", k8sCommand{name: "kubectl", args: kubectlArgs(kubeContext, "create", "namespace", namespace)})
	if createErr == nil {
		return nil
	}
	// A concurrent creator may win after the empty read. Confirm existence and
	// accept that race; never swallow an authorization or transport failure.
	result, confirmErr := runChecked(ctx, runner, "confirm gateway namespace after create race", get)
	if confirmErr == nil && strings.TrimSpace(string(result.stdout)) != "" {
		return nil
	}
	return createErr
}

func bootstrapSecretManifest(namespace, name, release, token string, anchor lifecycleAnchorMetadata) ([]byte, error) {
	if anchor.name != release+"-lifecycle" || anchor.instance != release || anchor.uid == "" || anchor.lifecycleClaim == "" || anchor.requestID == "" || anchor.generation <= 0 || anchor.expiresAt.IsZero() {
		return nil, errors.New("bootstrap Secret requires an exact lifecycle anchor owner and credential identity")
	}
	return json.Marshal(map[string]any{
		"apiVersion": "v1",
		"immutable":  true,
		"kind":       "Secret",
		"metadata": map[string]any{
			"name":      name,
			"namespace": namespace,
			"annotations": map[string]string{
				"tunnex.io/lifecycle-claim": anchor.lifecycleClaim, "tunnex.io/lifecycle-request-id": anchor.requestID,
				"tunnex.io/lifecycle-generation": strconv.Itoa(anchor.generation), "tunnex.io/lifecycle-expires-at": anchor.expiresAt.UTC().Format(time.RFC3339Nano),
			},
			"labels": map[string]string{
				"app.kubernetes.io/name":       "tunnex-gateway-bootstrap",
				"app.kubernetes.io/instance":   release,
				"app.kubernetes.io/managed-by": "tunnex-lifecycle",
			},
			"ownerReferences": []map[string]any{{
				"apiVersion": "v1", "kind": "ConfigMap", "name": anchor.name, "uid": anchor.uid,
				"controller": false, "blockOwnerDeletion": false,
			}},
		},
		"type": "Opaque",
		"stringData": map[string]string{
			"TUNNEX_JOIN_TOKEN": token,
		},
	})
}

func validateOwnedBootstrapSecret(secret bootstrapSecretMetadata, expectedName, release string) error {
	if secret.name != expectedName || secret.appName != "tunnex-gateway-bootstrap" || secret.instance != release || secret.managedBy != "tunnex-lifecycle" {
		return fmt.Errorf("bootstrap Secret %q is not owned by Tunnex release %q; refusing deletion without reading its value", expectedName, release)
	}
	if secret.uid == "" || secret.resourceVersion == "" {
		return fmt.Errorf("bootstrap Secret %q lacks UID/resourceVersion preconditions; refusing deletion without reading its value", expectedName)
	}
	if !secret.immutable {
		return fmt.Errorf("bootstrap Secret %q is mutable; refusing lifecycle use because its one-time token could change after approval", expectedName)
	}
	if secret.ownerAPIVersion != "v1" || secret.ownerKind != "ConfigMap" || secret.ownerName != release+"-lifecycle" || secret.ownerUID == "" {
		return fmt.Errorf("bootstrap Secret %q lacks the exact lifecycle anchor owner reference", expectedName)
	}
	return nil
}

func validateBootstrapSecretAnchor(secret bootstrapSecretMetadata, anchor lifecycleAnchorMetadata) error {
	if err := validateOwnedBootstrapSecret(secret, anchor.instance+"-bootstrap", anchor.instance); err != nil {
		return err
	}
	if secret.ownerName != anchor.name || secret.ownerUID != anchor.uid {
		return fmt.Errorf("bootstrap Secret %q owner does not match lifecycle anchor %q UID", secret.name, anchor.name)
	}
	return nil
}

func deleteOwnedBootstrapSecret(ctx context.Context, runner k8sRunner, kubeContext, namespace, timeout, expectedName, release string, anchor lifecycleAnchorMetadata, secret bootstrapSecretMetadata) error {
	if err := validateOwnedBootstrapSecret(secret, expectedName, release); err != nil {
		return err
	}
	if err := validateBootstrapSecretAnchor(secret, anchor); err != nil {
		return err
	}
	deleteOptions, err := json.Marshal(map[string]any{
		"apiVersion": "v1",
		"kind":       "DeleteOptions",
		"preconditions": map[string]string{
			"uid":             secret.uid,
			"resourceVersion": secret.resourceVersion,
		},
	})
	if err != nil {
		return fmt.Errorf("encode preconditioned bootstrap Secret deletion: %w", err)
	}
	rawPath := "/api/v1/namespaces/" + namespace + "/secrets/" + secret.name
	if _, err := runChecked(ctx, runner, "delete owned bootstrap Secret with UID/resourceVersion preconditions", k8sCommand{
		name: "kubectl", args: kubectlArgs(kubeContext, "delete", "--raw="+rawPath, "-f", "-"), stdin: deleteOptions,
	}); err != nil {
		return err
	}
	_, err = runChecked(ctx, runner, "wait for bootstrap Secret deletion", k8sCommand{
		name: "kubectl", args: kubectlArgs(kubeContext, "wait", "--for=delete", "secret/"+secret.name, "--namespace", namespace, "--timeout", timeout),
	})
	return err
}

func verifyRecoveredGatewayInstall(ctx context.Context, deps k8sDeps, prepared preparedInstall) (string, error) {
	o := prepared.options
	if err := verifyGateway(ctx, deps.runner, o.kubeContext, o.namespace, o.release, o.serviceType, o.endpoint, o.nodePort, o.timeout); err != nil {
		return "", err
	}
	deployment, err := getDeployment(ctx, deps.runner, o.kubeContext, o.namespace, o.release)
	if err != nil {
		return "", err
	}
	if err := requireLiveZeroTouchContract(deployment.Metadata.Annotations[zeroTouchContractAnnotationKey]); err != nil {
		return "", err
	}
	service, err := getService(ctx, deps.runner, o.kubeContext, o.namespace, o.release)
	if err != nil {
		return "", err
	}
	if err := verifyPlannedGatewayInputs(deployment, service, o, ""); err != nil {
		return "", err
	}
	revision, err := strconv.Atoi(prepared.state.resumeRelease.Revision)
	if err != nil || revision <= 0 {
		return "", fmt.Errorf("current Helm revision %q is invalid", prepared.state.resumeRelease.Revision)
	}
	if err := requireZeroTouchRevision(ctx, deps.runner, releaseOptions{
		release: o.release, namespace: o.namespace, kubeContext: o.kubeContext, timeout: o.timeout,
	}, revision); err != nil {
		return "", err
	}
	expectedClaim := gatewayFullname(o.release) + "-state"
	claim, err := deploymentClaim(deployment)
	if err != nil {
		return "", err
	}
	if claim != expectedClaim || claim != prepared.state.pvcName {
		return "", fmt.Errorf("Deployment mounts state claim %q, expected exact enrollment claim %q", claim, expectedClaim)
	}
	pvc, err := getPVC(ctx, deps.runner, o.kubeContext, o.namespace, claim)
	if err != nil {
		return "", err
	}
	if err := validateGatewayIdentityPVC(pvc, claim, o.release); err != nil {
		return "", err
	}
	if err := validatePVCLifecycleProvenance(pvc, prepared.anchor); err != nil {
		return "", err
	}
	if err := verifyPVCStorageClass(pvc, prepared.plan.Storage.Class); err != nil {
		return "", err
	}
	if pvc.Metadata.UID != prepared.state.pvcUID || pvc.Spec.VolumeName != prepared.state.pvcVolumeName {
		return "", errors.New("state claim UID or bound volume changed after cleanup approval")
	}
	if err := verifyLifecycleConsumed(ctx, prepared, prepared.anchor); err != nil {
		return "", err
	}
	return claim, nil
}

func resumePostInstallCleanup(ctx context.Context, deps k8sDeps, prepared preparedInstall) error {
	o := prepared.options
	secretName := o.release + "-bootstrap"
	resumeFailure := func(err error) error {
		return fmt.Errorf("existing release %q cannot yet complete token-blind enrollment cleanup; owned lifecycle recovery metadata was retained: %w", o.release, err)
	}
	if prepared.state.resumeRelease.Status != "deployed" {
		return resumeFailure(fmt.Errorf("Helm status is %q, not deployed; inspect 'tunnex k8s diagnostics' before retrying", prepared.state.resumeRelease.Status))
	}

	// Refresh the exact operation before any live readiness, provenance, PVC,
	// or consumed-claim read. Active recovery stays under the CP DB-clock hard
	// deadline and heartbeats until the final Complete CAS begins.
	authority, alreadyCompleted, err := refreshRecoveredLifecycleInstallAuthority(ctx, deps, prepared)
	if err != nil {
		return resumeFailure(err)
	}
	verificationCtx := ctx
	var monitor *lifecycleInstallMonitor
	var cancelHard context.CancelFunc
	if !alreadyCompleted {
		monitor, cancelHard = startLifecycleInstallMonitor(ctx, deps, authority)
		verificationCtx = monitor.mutationCtx
		defer cancelHard()
	}
	claim, verifyErr := verifyRecoveredGatewayInstall(verificationCtx, deps, prepared)
	if monitor != nil {
		monitorErr := monitor.stop()
		monitor = nil
		if verifyErr != nil || monitorErr != nil {
			var releaseErr error
			holderStopped := errors.Is(monitorErr, errLifecycleInstallAbortRequested) || errors.Is(monitorErr, errLifecycleInstallDeadline)
			if holderStopped {
				cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
				releaseErr = reconcileLifecycleInstallFailure(cleanupCtx, deps, authority, prepared, true, true)
				cancel()
			}
			return resumeFailure(errors.Join(verifyErr, monitorErr, releaseErr))
		}
	}
	if verifyErr != nil {
		return resumeFailure(verifyErr)
	}
	if !alreadyCompleted {
		if err := completeRecoveredLifecycleInstall(verificationCtx, deps, prepared, authority); err != nil {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			completed, reconcileErr := reconcileLifecycleInstallCompleteError(cleanupCtx, authority)
			cancel()
			if !completed {
				return resumeFailure(errors.Join(err, reconcileErr))
			}
		}
	}
	if prepared.state.retrySecret {
		secret := bootstrapSecretMetadata{
			name: secretName, uid: prepared.state.secretUID, resourceVersion: prepared.state.secretResourceVersion,
			appName: "tunnex-gateway-bootstrap", instance: o.release, managedBy: "tunnex-lifecycle", immutable: true,
			lifecycleClaim: prepared.state.secretLifecycleClaim, requestID: prepared.state.secretRequestID,
			generation: prepared.state.secretGeneration, expiresAt: prepared.state.secretExpiresAt,
			ownerAPIVersion: prepared.state.secretOwnerAPIVersion, ownerKind: prepared.state.secretOwnerKind,
			ownerName: prepared.state.secretOwnerName, ownerUID: prepared.state.secretOwnerUID,
		}
		if err := deleteOwnedBootstrapSecret(ctx, deps.runner, o.kubeContext, o.namespace, o.timeout, secretName, o.release, prepared.anchor, secret); err != nil {
			return fmt.Errorf("gateway release %q and identity claim %q are ready, but owned bootstrap Secret cleanup failed; rerun the same install command to retry deletion without reading or reminting the token: %w", o.release, claim, err)
		}
	}
	if err := deleteOwnedLifecycleAnchor(ctx, deps.runner, o.kubeContext, o.namespace, o.timeout, o.release, prepared.anchor); err != nil {
		return fmt.Errorf("gateway release %q and identity claim %q are ready, but lifecycle anchor cleanup failed; rerun the same install command to retry exact cleanup: %w", o.release, claim, err)
	}
	_, err = fmt.Fprintf(deps.out, "Gateway %q was already ready; owned lifecycle recovery metadata was removed with UID/resourceVersion preconditions. No token was read or minted.\n", o.release)
	return err
}

func installHelmCommand(prepared preparedInstall) (k8sCommand, error) {
	o := prepared.options
	// Install is intentionally create-only. A second exact release appearing
	// after the metadata precheck must make Helm fail, never turn enrollment into
	// an implicit upgrade of another operator's release.
	args := []string{"install", o.release, prepared.gatewayArtifact.Path, "--namespace", o.namespace, "--description", zeroTouchContract, "--atomic", "--wait", "--timeout", o.timeout, "--values", "-"}
	args = appendHelmContext(args, o.kubeContext)
	rolloutDigest := prepared.digest
	if o.mode == "enroll" {
		if prepared.installIntentDigest == "" || prepared.installIntentDigest != prepared.plan.InstallIntentDigest {
			return k8sCommand{}, errors.New("enroll Helm values lack the exact approved install intent digest")
		}
		rolloutDigest = prepared.installIntentDigest
	}
	values, err := gatewayInstallValues(prepared, rolloutRevision(rolloutDigest))
	if err != nil {
		return k8sCommand{}, err
	}
	if o.mode == "enroll" {
		installProof, proofErr := lifecycleInstallHookProofForInstallingAnchor(prepared.anchor, o.namespace, o.release)
		if proofErr != nil {
			return k8sCommand{}, fmt.Errorf("derive lifecycle install proof for the preflight hook: %w", proofErr)
		}
		values["lifecycle"] = map[string]any{"installProof": installProof}
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return k8sCommand{}, err
	}
	return k8sCommand{name: "helm", args: args, stdin: encoded}, nil
}

func appendImageValues(values map[string]any, image imageValues) {
	imageMap, _ := values["image"].(map[string]any)
	if imageMap == nil {
		imageMap = map[string]any{}
	}
	imageMap["registry"] = defaultNodeImageRegistry
	imageMap["agent"] = defaultNodeImageAgent
	imageMap["tag"] = ""
	imageMap["digest"] = ""
	imageMap["pullPolicy"] = defaultNodeImagePullPolicy
	if image.reference != "" && image.reference != "chart-default" {
		imageMap["registry"] = image.registry
		imageMap["agent"] = image.agent
		if image.digest != "" {
			imageMap["digest"] = image.digest
		}
		if image.tag != "" {
			imageMap["tag"] = image.tag
		}
	}
	values["image"] = imageMap
}

func appendGatewayImageValues(values map[string]any, image imageValues) {
	appendImageValues(values, image)
	imageMap := values["image"].(map[string]any)
	// `--reset-then-reuse-values` must not resurrect a historical privileged
	// preflight override when the approved plan selects the gateway image.
	imageMap["preflight"] = ""
}

func resolvedImageReference(image imageValues, appVersion string) string {
	if image.reference != "" && image.reference != "chart-default" {
		return image.reference
	}
	appVersion = strings.TrimSpace(appVersion)
	if appVersion == "" {
		return ""
	}
	return defaultNodeImageRegistry + "/" + defaultNodeImageAgent + ":" + appVersion
}

func plannedImageReference(image imageValues, appVersion string) string {
	if resolved := resolvedImageReference(image, appVersion); resolved != "" {
		return resolved
	}
	return image.reference
}

func rolloutRevision(digest string) string {
	value := strings.TrimPrefix(digest, "sha256:")
	if len(value) > 16 {
		value = value[:16]
	}
	return "plan-" + value
}

func gatewayFullname(release string) string {
	value := release + "-tunnex-gateway"
	if len(value) > 63 {
		value = value[:63]
	}
	return strings.TrimSuffix(value, "-")
}

func kubectlArgs(contextName string, args ...string) []string {
	if contextName == "" {
		return append([]string(nil), args...)
	}
	return append([]string{"--context", contextName}, args...)
}

func appendHelmContext(args []string, contextName string) []string {
	if contextName == "" {
		return args
	}
	return append(args, "--kube-context", contextName)
}

func runChecked(ctx context.Context, runner k8sRunner, label string, command k8sCommand) (k8sCommandResult, error) {
	return runCheckedSecrets(ctx, runner, label, command)
}

func runCheckedSecrets(ctx context.Context, runner k8sRunner, label string, command k8sCommand, secrets ...string) (k8sCommandResult, error) {
	result, err := runner.Run(ctx, command)
	if err == nil {
		return result, nil
	}
	detail := strings.TrimSpace(redactText(string(result.stderr), secrets...))
	if detail == "" {
		detail = strings.TrimSpace(redactText(string(result.stdout), secrets...))
	}
	if detail == "" {
		return result, fmt.Errorf("%s failed", label)
	}
	return result, fmt.Errorf("%s failed: %s", label, detail)
}

var diagnosticRedactors = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(authorization\s*:\s*bearer\s+)[^\s]+`),
	regexp.MustCompile(`(?i)(TUNNEX_JOIN_TOKEN["'=:\s]+)[^\s,"'}]+`),
	regexp.MustCompile(`(?i)("join_token"\s*:\s*")[^"]+`),
	regexp.MustCompile(`(?s)-----BEGIN [^-]+-----.*?-----END [^-]+-----`),
}

func redactText(value string, secrets ...string) string {
	for _, secret := range secrets {
		if secret != "" {
			value = strings.ReplaceAll(value, secret, "<redacted>")
		}
	}
	for _, re := range diagnosticRedactors {
		value = re.ReplaceAllString(value, "${1}<redacted>")
	}
	return value
}
