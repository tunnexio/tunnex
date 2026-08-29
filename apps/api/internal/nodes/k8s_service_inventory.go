package nodes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const K8sServiceInventoryVersion = 1

const (
	maxK8sServiceInventoryServices = 500
	maxK8sServiceInventoryPorts    = 32
	maxK8sServiceInventoryBody     = 4 << 20
)

var (
	ErrK8sServiceInventoryInvalid   = errors.New("invalid Kubernetes Service inventory")
	ErrK8sServiceInventoryRetention = errors.New("Kubernetes Service inventory retention failed")
)

type K8sServiceInventoryReport struct {
	Version    int                          `json:"version"`
	Sequence   uint64                       `json:"sequence"`
	ObservedAt time.Time                    `json:"observed_at"`
	Digest     string                       `json:"digest"`
	Services   []K8sServiceInventoryService `json:"services"`
}

type K8sServiceInventoryService struct {
	Namespace string                    `json:"namespace"`
	Service   string                    `json:"service"`
	UID       string                    `json:"uid"`
	Ports     []K8sServiceInventoryPort `json:"ports"`
}

type K8sServiceInventoryPort struct {
	Name     string `json:"name,omitempty"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

type K8sServiceInventoryWriteResult struct {
	Duplicate       bool
	ReportID        uuid.UUID
	PrunedSnapshots int64
}

type K8sServiceInventoryStore interface {
	WriteK8sServiceInventory(context.Context, K8sServiceUIDObservationAgent, K8sServiceInventoryReport, time.Time) (K8sServiceInventoryWriteResult, error)
}

func ValidateK8sServiceInventoryReport(report K8sServiceInventoryReport) (K8sServiceInventoryReport, error) {
	if report.Version != K8sServiceInventoryVersion || report.Sequence == 0 || report.ObservedAt.IsZero() || len(report.Services) > maxK8sServiceInventoryServices {
		return K8sServiceInventoryReport{}, ErrK8sServiceInventoryInvalid
	}
	services := canonicalK8sServiceInventory(report.Services)
	seenServices := map[string]bool{}
	for _, service := range services {
		if !validK8sServiceUIDDNSLabel(service.Namespace) || !validK8sServiceUIDDNSLabel(service.Service) || !validK8sServiceInventoryUID(service.UID) || len(service.Ports) == 0 || len(service.Ports) > maxK8sServiceInventoryPorts {
			return K8sServiceInventoryReport{}, ErrK8sServiceInventoryInvalid
		}
		serviceKey := service.Namespace + "\x00" + service.Service
		if seenServices[serviceKey] {
			return K8sServiceInventoryReport{}, ErrK8sServiceInventoryInvalid
		}
		seenServices[serviceKey] = true
		seenPorts := map[string]bool{}
		for _, port := range service.Ports {
			if (port.Protocol != "tcp" && port.Protocol != "udp") || port.Port < 1 || port.Port > 65535 || !validK8sServiceInventoryPortName(port.Name) {
				return K8sServiceInventoryReport{}, ErrK8sServiceInventoryInvalid
			}
			portKey := port.Protocol + "\x00" + strconv.Itoa(port.Port)
			if seenPorts[portKey] {
				return K8sServiceInventoryReport{}, ErrK8sServiceInventoryInvalid
			}
			seenPorts[portKey] = true
		}
	}
	canonical := K8sServiceInventoryReport{Version: report.Version, Sequence: report.Sequence, ObservedAt: report.ObservedAt.UTC(), Digest: report.Digest, Services: services}
	if report.Digest != K8sServiceInventoryDigest(canonical.Sequence, canonical.ObservedAt, canonical.Services) {
		return K8sServiceInventoryReport{}, ErrK8sServiceInventoryInvalid
	}
	body, err := json.Marshal(canonical)
	if err != nil || len(body) > maxK8sServiceInventoryBody {
		return K8sServiceInventoryReport{}, ErrK8sServiceInventoryInvalid
	}
	return canonical, nil
}

func K8sServiceInventoryDigest(sequence uint64, observedAt time.Time, services []K8sServiceInventoryService) string {
	entries := canonicalK8sServiceInventory(services)
	h := sha256.New()
	_, _ = h.Write([]byte("tunnex.k8s-service-inventory.v1\n"))
	_, _ = h.Write([]byte(strconv.FormatUint(sequence, 10) + "\n"))
	_, _ = h.Write([]byte(observedAt.UTC().Format(time.RFC3339Nano) + "\n"))
	for _, service := range entries {
		_, _ = h.Write([]byte(strconv.Quote(service.Namespace) + "\t" + strconv.Quote(service.Service) + "\t" + strconv.Quote(service.UID) + "\n"))
		for _, port := range service.Ports {
			_, _ = h.Write([]byte("\t" + port.Protocol + "\t" + strconv.Itoa(port.Port) + "\t" + strconv.Quote(port.Name) + "\n"))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func canonicalK8sServiceInventory(services []K8sServiceInventoryService) []K8sServiceInventoryService {
	out := append([]K8sServiceInventoryService(nil), services...)
	for i := range out {
		out[i].Ports = append([]K8sServiceInventoryPort(nil), out[i].Ports...)
		sort.Slice(out[i].Ports, func(a, b int) bool {
			if out[i].Ports[a].Protocol != out[i].Ports[b].Protocol {
				return out[i].Ports[a].Protocol < out[i].Ports[b].Protocol
			}
			if out[i].Ports[a].Port != out[i].Ports[b].Port {
				return out[i].Ports[a].Port < out[i].Ports[b].Port
			}
			return out[i].Ports[a].Name < out[i].Ports[b].Name
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Service < out[j].Service
	})
	return out
}

func validK8sServiceInventoryUID(value string) bool {
	return len(value) >= 1 && len(value) <= maxK8sServiceUIDBytes && utf8.ValidString(value) && !strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

func validK8sServiceInventoryPortName(value string) bool {
	return value == "" || (len(value) <= 63 && utf8.ValidString(value) && !strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }))
}
