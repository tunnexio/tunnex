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

	"github.com/tunnexio/tunnex/apps/api/internal/k8s"
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
	// Version 2 only. LabelsTruncated means the Service has more labels than Labels holds.
	Labels          map[string]string `json:"labels,omitempty"`
	LabelsTruncated bool              `json:"labels_truncated,omitempty"`
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
	if (report.Version != K8sServiceInventoryVersion && report.Version != K8sServiceInventoryVersionLabels) || report.Sequence == 0 || report.ObservedAt.IsZero() || len(report.Services) > maxK8sServiceInventoryServices {
		return K8sServiceInventoryReport{}, ErrK8sServiceInventoryInvalid
	}
	services := canonicalK8sServiceInventory(report.Services)
	seenServices := map[string]bool{}
	for _, service := range services {
		if !validK8sServiceUIDDNSLabel(service.Namespace) || !validK8sServiceUIDDNSLabel(service.Service) || !validK8sServiceInventoryUID(service.UID) || len(service.Ports) == 0 || len(service.Ports) > maxK8sServiceInventoryPorts {
			return K8sServiceInventoryReport{}, ErrK8sServiceInventoryInvalid
		}
		if !validK8sServiceInventoryVersionLabels(report.Version, service) {
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
	if report.Digest != K8sServiceInventoryReportDigest(canonical) {
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

// Version 2 adds each Service's labels so the control plane can match a namespace rule's selector
// (K8N-4 slice B). The bounds are per Service; a Service with more is reported with what fits, in key
// order, and LabelsTruncated set.
const (
	K8sServiceInventoryVersionLabels = 2
	MaxK8sServiceInventoryLabels     = 32
	MaxK8sServiceInventoryLabelBytes = 2048
)

// ValidK8sLabelKey and ValidK8sLabelValue are Kubernetes label syntax, shared with the namespace rule's
// selector so a selector can never name a label the report could not carry.
func ValidK8sLabelKey(key string) bool     { return k8s.ValidLabelKey(key) }
func ValidK8sLabelValue(value string) bool { return k8s.ValidLabelValue(value) }

func validK8sServiceInventoryLabels(labels map[string]string) bool {
	if len(labels) > MaxK8sServiceInventoryLabels {
		return false
	}
	total := 0
	for key, value := range labels {
		if !ValidK8sLabelKey(key) || !ValidK8sLabelValue(value) {
			return false
		}
		total += len(key) + len(value)
	}
	return total <= MaxK8sServiceInventoryLabelBytes
}

func sortedK8sLabelKeys(labels map[string]string) []string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// K8sServiceInventoryDigestV2 is the version 2 digest: the version 1 lines under a new prefix, plus each
// Service's labels in key order and whether they were truncated.
func K8sServiceInventoryDigestV2(sequence uint64, observedAt time.Time, services []K8sServiceInventoryService) string {
	entries := canonicalK8sServiceInventory(services)
	h := sha256.New()
	_, _ = h.Write([]byte("tunnex.k8s-service-inventory.v2\n"))
	_, _ = h.Write([]byte(strconv.FormatUint(sequence, 10) + "\n"))
	_, _ = h.Write([]byte(observedAt.UTC().Format(time.RFC3339Nano) + "\n"))
	for _, service := range entries {
		_, _ = h.Write([]byte(strconv.Quote(service.Namespace) + "\t" + strconv.Quote(service.Service) + "\t" + strconv.Quote(service.UID) + "\n"))
		for _, port := range service.Ports {
			_, _ = h.Write([]byte("\t" + port.Protocol + "\t" + strconv.Itoa(port.Port) + "\t" + strconv.Quote(port.Name) + "\n"))
		}
		for _, key := range sortedK8sLabelKeys(service.Labels) {
			_, _ = h.Write([]byte("\tlabel\t" + strconv.Quote(key) + "\t" + strconv.Quote(service.Labels[key]) + "\n"))
		}
		if service.LabelsTruncated {
			_, _ = h.Write([]byte("\ttruncated\n"))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// K8sServiceInventoryReportDigest is the digest for the report's own version.
func K8sServiceInventoryReportDigest(report K8sServiceInventoryReport) string {
	if report.Version == K8sServiceInventoryVersionLabels {
		return K8sServiceInventoryDigestV2(report.Sequence, report.ObservedAt, report.Services)
	}
	return K8sServiceInventoryDigest(report.Sequence, report.ObservedAt, report.Services)
}

// validK8sServiceInventoryVersionLabels: version 1 carries no labels at all; version 2 carries bounded,
// well-formed ones.
func validK8sServiceInventoryVersionLabels(version int, service K8sServiceInventoryService) bool {
	if version == K8sServiceInventoryVersion {
		return len(service.Labels) == 0 && !service.LabelsTruncated
	}
	return validK8sServiceInventoryLabels(service.Labels)
}
