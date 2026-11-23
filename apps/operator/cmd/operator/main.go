// Command operator is the Tunnex GitOps operator (S10.2). It watches TunnexCluster / TunnexExposedService /
// TunnexGrant custom resources and reconciles them against the control-plane HTTP API — the SAME handlers
// the dashboard calls — so a platform team can declare Tunnex state in git.
//
// THE HARD RULE: this is an API CLIENT, never a DB writer. It holds no data-plane privilege and reaches
// Tunnex only over HTTPS with a machine credential (S10.2 Slice 1); every invariant (Collect/OrgRanges,
// identity-binding, edition gate, audit cascade) is inherited through the CP handlers.
//
// Slice 3: the three reconcilers (CR -> CP verb -> status) are registered here. Delete + drift + the
// dashboard ownership surface land in Slice 4.
package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	tunnexv1 "github.com/tunnexio/tunnex/apps/operator/api/v1alpha1"
	"github.com/tunnexio/tunnex/apps/operator/internal/controllers"
	"github.com/tunnexio/tunnex/apps/operator/internal/cp"
)

var scheme = runtime.NewScheme()

// version is the git sha the binary was built from — stamped at build time via
// -ldflags "-X main.version=$(git rev-parse --short HEAD)". Logged at startup so a walk can CONFIRM the
// running operator is the branch build (a stale image reproduces the C1 email_not_verified symptom — the
// build-provenance census in docs/S10.2-boxwalk.md Leg 0). "dev" means an un-stamped local build.
var version = "dev"

var uuidRE = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(tunnexv1.AddToScheme(scheme))
}

// mustEnv reads a required environment variable, fatal-exiting if unset — the operator refuses to start
// half-configured (no CP URL / token / org means it could reach nothing, or the wrong org).
func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		ctrl.Log.WithName("setup").Error(nil, "missing required environment variable", "var", key)
		os.Exit(1)
	}
	return v
}

func validateControlPlaneConfig(cpURL, orgID string) error {
	u, err := url.ParseRequestURI(cpURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return fmt.Errorf("TUNNEX_CP_URL must be an absolute https:// URL with a host")
	}
	if !uuidRE.MatchString(orgID) {
		return fmt.Errorf("TUNNEX_ORG_ID must be a UUID")
	}
	return nil
}

// controlPlaneReady is the pod's readiness: can it reach the control plane with its credential, for its
// organization. The kubelet only reports "not ready", so the reason is logged here — once when it starts
// failing or changes, and once when it recovers, never every probe. Without this the pod sat not-ready with
// nothing in its log (K8L-8 live walk: a credential with no owner is refused with a bare 401).
func controlPlaneReady(client *cp.Client) healthz.Checker {
	log := ctrl.Log.WithName("readiness")
	var mu sync.Mutex
	last := ""
	return func(_ *http.Request) error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		err := client.CheckAccess(ctx)
		reason := readinessReason(err)
		mu.Lock()
		changed := reason != last
		last = reason
		mu.Unlock()
		if changed && err != nil {
			log.Info("control plane is not usable yet", "reason", reason)
		} else if changed {
			log.Info("control plane is reachable and the credential is accepted")
		}
		return err
	}
}

// readinessReason turns the control plane's answer into something an operator can act on. The control plane
// deliberately does not say WHY a credential is refused, so every cause of a 401 is listed.
func readinessReason(err error) string {
	if err == nil {
		return ""
	}
	if e := cp.AsAPIError(err); e != nil {
		switch e.Status {
		case http.StatusUnauthorized:
			return "the control plane refused the credential (401): the token in the Secret is wrong or incomplete, the credential was revoked, it has no owner assigned yet (Settings, GitOps operator credentials, Assign owner), or its owner is deactivated"
		case http.StatusForbidden, http.StatusNotFound:
			return fmt.Sprintf("the credential is not valid for this organization (%d %s): check controlPlane.organizationID", e.Status, e.Code)
		}
		return fmt.Sprintf("control plane answered %d %s: %s", e.Status, e.Code, e.Message)
	}
	return "cannot reach the control plane: " + err.Error()
}

func main() {
	ctrl.SetLogger(zap.New())
	log := ctrl.Log.WithName("setup")
	log.Info("tunnex-operator starting", "version", version) // build provenance — confirm this matches the branch tip

	// The operator's identity to the CP: its machine credential + the org it manages (D3). THE HARD RULE —
	// this bearer client is the ONLY channel to Tunnex; no DB handle is constructed anywhere in this binary.
	cpURL := mustEnv("TUNNEX_CP_URL")
	orgID := mustEnv("TUNNEX_ORG_ID")
	if err := validateControlPlaneConfig(cpURL, orgID); err != nil {
		log.Error(err, "invalid control-plane configuration")
		os.Exit(1)
	}
	cpClient := cp.New(cpURL, mustEnv("TUNNEX_MACHINE_TOKEN"), orgID)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: ":8081",
	})
	if err != nil {
		log.Error(err, "unable to start manager")
		os.Exit(1)
	}

	rec := mgr.GetEventRecorderFor("tunnex-operator") // H1: Warning events for a blocked teardown
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		log.Error(err, "unable to register health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("control-plane", controlPlaneReady(cpClient)); err != nil {
		log.Error(err, "unable to register readiness check")
		os.Exit(1)
	}
	if err := (&controllers.TunnexClusterReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme(), CP: cpClient, Recorder: rec}).SetupWithManager(mgr); err != nil {
		log.Error(err, "unable to set up controller", "controller", "TunnexCluster")
		os.Exit(1)
	}
	if err := (&controllers.TunnexExposedServiceReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme(), CP: cpClient, Recorder: rec}).SetupWithManager(mgr); err != nil {
		log.Error(err, "unable to set up controller", "controller", "TunnexExposedService")
		os.Exit(1)
	}
	if err := (&controllers.TunnexGrantReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme(), CP: cpClient, Recorder: rec}).SetupWithManager(mgr); err != nil {
		log.Error(err, "unable to set up controller", "controller", "TunnexGrant")
		os.Exit(1)
	}

	if err := (&controllers.TunnexNamespaceExposureReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme(), CP: cpClient, Recorder: rec}).SetupWithManager(mgr); err != nil {
		log.Error(err, "unable to set up controller", "controller", "TunnexNamespaceExposure")
		os.Exit(1)
	}

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Error(err, "manager exited non-zero")
		os.Exit(1)
	}
}
