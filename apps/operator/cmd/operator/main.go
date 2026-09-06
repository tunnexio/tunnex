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

func controlPlaneReady(client *cp.Client) healthz.Checker {
	return func(_ *http.Request) error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return client.CheckAccess(ctx)
	}
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

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Error(err, "manager exited non-zero")
		os.Exit(1)
	}
}
