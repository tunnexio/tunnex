package main

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/k8sendpoint"
)

type reportEndpointSnapshot struct {
	Endpoint   string
	Generation uint64
	Reportable bool
}

type reportEndpointSource func() reportEndpointSnapshot

type endpointEnvironment struct {
	explicitEndpoint string
	auto             *k8sendpoint.Config
	kubernetesMode   bool
}

func endpointEnvironmentFrom(lookup func(string) string) (endpointEnvironment, error) {
	config := endpointEnvironment{}
	switch strings.TrimSpace(lookup("TUNNEX_K8S_MODE")) {
	case "":
		// Compatibility contract: absence means an ordinary VM/site gateway.
	case "false":
		// Explicit false is accepted, but does not enable Kubernetes behavior.
	case "true":
		config.kubernetesMode = true
	default:
		return config, fmt.Errorf("TUNNEX_K8S_MODE must be exactly true or false when set")
	}
	explicit := strings.TrimSpace(lookup("TUNNEX_NODE_ENDPOINT"))
	if explicit != "" {
		config.explicitEndpoint = explicit
		return config, nil
	}
	service := strings.TrimSpace(lookup("TUNNEX_K8S_ENDPOINT_SERVICE"))
	namespace := strings.TrimSpace(lookup("TUNNEX_K8S_ENDPOINT_NAMESPACE"))
	portValue := strings.TrimSpace(lookup("TUNNEX_K8S_ENDPOINT_PORT"))
	if service == "" && namespace == "" && portValue == "" {
		if config.kubernetesMode {
			return config, fmt.Errorf("Kubernetes mode requires an explicit endpoint or complete Service discovery tuple")
		}
		// Legacy VM/dev behavior: reporting an empty endpoint remains allowed when
		// Kubernetes auto-discovery was not requested.
		return config, nil
	}
	if !config.kubernetesMode {
		return config, fmt.Errorf("Kubernetes endpoint discovery requires TUNNEX_K8S_MODE=true")
	}
	if service == "" || namespace == "" || portValue == "" {
		return config, fmt.Errorf("Kubernetes endpoint discovery requires Service, namespace, and port")
	}
	port, err := strconv.Atoi(portValue)
	if err != nil || port < 1 || port > 65535 {
		return config, fmt.Errorf("Kubernetes endpoint discovery port must be between 1 and 65535")
	}
	config.auto = &k8sendpoint.Config{Service: service, Namespace: namespace, Port: port}
	return config, nil
}

func configureEndpointSource(ctx context.Context, lookup func(string) string, reported *atomic.Bool, kick chan<- struct{}, logger *slog.Logger) (reportEndpointSource, bool, error) {
	config, err := endpointEnvironmentFrom(lookup)
	if err != nil {
		return blockedEndpointSource(), config.kubernetesMode, err
	}
	if config.explicitEndpoint != "" {
		return staticEndpointSource(config.explicitEndpoint), config.kubernetesMode, nil
	}
	if config.auto == nil {
		return staticEndpointSource(""), false, nil
	}
	discoverer, err := k8sendpoint.NewInCluster(*config.auto, func(snapshot k8sendpoint.Snapshot) {
		reported.Store(false)
		select {
		case kick <- struct{}{}:
		default:
		}
		if logger != nil {
			logger.Info("k8s_endpoint_discovery_state",
				slog.String("state", string(snapshot.State)),
				slog.String("reason", snapshot.Reason),
				slog.Uint64("generation", snapshot.Generation),
			)
		}
	})
	if err != nil {
		return blockedEndpointSource(), true, err
	}
	go discoverer.Run(ctx, 5*time.Second)
	return func() reportEndpointSnapshot {
		snapshot := discoverer.Snapshot()
		return reportEndpointSnapshot{
			Endpoint:   snapshot.Endpoint,
			Generation: snapshot.Generation,
			Reportable: snapshot.Reportable(),
		}
	}, true, nil
}

func staticEndpointSource(endpoint string) reportEndpointSource {
	return func() reportEndpointSnapshot {
		return reportEndpointSnapshot{Endpoint: endpoint, Generation: 1, Reportable: true}
	}
}

func blockedEndpointSource() reportEndpointSource {
	return func() reportEndpointSnapshot { return reportEndpointSnapshot{Generation: 1} }
}

func endpointReportIsCurrent(source reportEndpointSource, sent reportEndpointSnapshot) bool {
	current := source()
	return current.Reportable && current.Generation == sent.Generation && current.Endpoint == sent.Endpoint
}

// acceptEndpointReport closes the race between Service discovery and a
// successful control-plane report. Discovery may advance immediately before
// the readiness bit is stored; the second generation check then retracts that
// stale success. If discovery advances after the second check, its onChange
// callback performs the retraction instead.
func acceptEndpointReport(source reportEndpointSource, sent reportEndpointSnapshot, reported *atomic.Bool) (bool, bool) {
	if !endpointReportIsCurrent(source, sent) {
		reported.Store(false)
		return false, false
	}
	changed := reported.CompareAndSwap(false, true)
	if !endpointReportIsCurrent(source, sent) {
		reported.Store(false)
		return false, false
	}
	return true, changed
}
