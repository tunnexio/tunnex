package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const K8sServiceInventoryVersion = 1

const (
	maxK8sServiceInventoryServices = 500
	maxK8sServiceInventoryPorts    = 32
	maxK8sServiceInventoryBody     = 4 << 20
)

// ErrK8sServiceInventoryRefused is the control plane's 400 for a report it will not store.
var ErrK8sServiceInventoryRefused = errors.New("Kubernetes Service inventory refused")

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

func ValidateK8sServiceInventoryReport(report K8sServiceInventoryReport) error {
	if (report.Version != K8sServiceInventoryVersion && report.Version != K8sServiceInventoryVersionLabels) || report.Sequence == 0 || report.ObservedAt.IsZero() || len(report.Services) > maxK8sServiceInventoryServices {
		return fmt.Errorf("invalid Kubernetes Service inventory")
	}
	seenServices := map[string]bool{}
	for _, service := range report.Services {
		if !validK8sServiceUIDDNSLabel(service.Namespace) || !validK8sServiceUIDDNSLabel(service.Service) || !validInventoryUID(service.UID) || len(service.Ports) == 0 || len(service.Ports) > maxK8sServiceInventoryPorts {
			return fmt.Errorf("invalid Kubernetes Service inventory")
		}
		if !validK8sServiceInventoryVersionLabels(report.Version, service) {
			return fmt.Errorf("invalid Kubernetes Service inventory")
		}
		serviceKey := service.Namespace + "\x00" + service.Service
		if seenServices[serviceKey] {
			return fmt.Errorf("invalid Kubernetes Service inventory")
		}
		seenServices[serviceKey] = true
		seenPorts := map[string]bool{}
		for _, port := range service.Ports {
			if (port.Protocol != "tcp" && port.Protocol != "udp") || port.Port < 1 || port.Port > 65535 || !validInventoryPortName(port.Name) {
				return fmt.Errorf("invalid Kubernetes Service inventory")
			}
			portKey := port.Protocol + "\x00" + strconv.Itoa(port.Port)
			if seenPorts[portKey] {
				return fmt.Errorf("invalid Kubernetes Service inventory")
			}
			seenPorts[portKey] = true
		}
	}
	if report.Digest != K8sServiceInventoryReportDigest(report) {
		return fmt.Errorf("invalid Kubernetes Service inventory")
	}
	body, err := json.Marshal(report)
	if err != nil || len(body) > maxK8sServiceInventoryBody {
		return fmt.Errorf("invalid Kubernetes Service inventory")
	}
	return nil
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

func (c *Client) ReportK8sServiceInventory(ctx context.Context, report K8sServiceInventoryReport) error {
	if err := ValidateK8sServiceInventoryReport(report); err != nil {
		return err
	}
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/agent/k8s-service-inventory", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusBadRequest {
		// The control plane gives one answer to every report it refuses, so this may be a control plane
		// from before version 2. The caller decides whether to send version 1 instead.
		return fmt.Errorf("%w: status %d", ErrK8sServiceInventoryRefused, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("Kubernetes Service inventory status %d", resp.StatusCode)
	}
	return nil
}

func validInventoryUID(value string) bool {
	if len(value) == 0 || len(value) > maxK8sServiceUIDBytes || !utf8.ValidString(value) {
		return false
	}
	return !strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

func validInventoryPortName(value string) bool {
	return value == "" || (len(value) <= 63 && utf8.ValidString(value) && !strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f }))
}

// Version 2 adds each Service's labels so the control plane can match a namespace rule's selector
// (K8N-4 slice B). The bounds are per Service; a Service with more is reported with what fits, in key
// order, and LabelsTruncated set.
const (
	K8sServiceInventoryVersionLabels = 2
	MaxK8sServiceInventoryLabels     = 32
	MaxK8sServiceInventoryLabelBytes = 2048
	maxK8sLabelKeyBytes              = 317 // 253-byte prefix, "/", 63-byte name
	maxK8sLabelValueBytes            = 63
)

// ValidK8sLabelKey reports whether key has Kubernetes label-key syntax: an optional DNS-subdomain
// prefix and "/", then a name of at most 63 characters.
func ValidK8sLabelKey(key string) bool {
	if len(key) == 0 || len(key) > maxK8sLabelKeyBytes {
		return false
	}
	name := key
	if i := strings.LastIndexByte(key, '/'); i >= 0 {
		prefix := key[:i]
		name = key[i+1:]
		if len(prefix) == 0 || len(prefix) > 253 {
			return false
		}
		for _, part := range strings.Split(prefix, ".") {
			if !validK8sLabelPart(part, false) {
				return false
			}
		}
	}
	return len(name) > 0 && validK8sLabelPart(name, true)
}

// ValidK8sLabelValue reports whether value has Kubernetes label-value syntax; empty is valid.
func ValidK8sLabelValue(value string) bool {
	return value == "" || validK8sLabelPart(value, true)
}

// validK8sLabelPart: 1-63 characters, alphanumeric at both ends. A name or value may hold upper case,
// "_" and "." inside; a prefix part is a lowercase DNS label.
func validK8sLabelPart(part string, nameSyntax bool) bool {
	if len(part) == 0 || len(part) > 63 {
		return false
	}
	alnum := func(c byte) bool {
		return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (nameSyntax && c >= 'A' && c <= 'Z')
	}
	if !alnum(part[0]) || !alnum(part[len(part)-1]) {
		return false
	}
	for i := 1; i < len(part)-1; i++ {
		c := part[i]
		if !alnum(c) && c != '-' && !(nameSyntax && (c == '_' || c == '.')) {
			return false
		}
	}
	return true
}

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

// BoundK8sServiceInventoryLabels keeps the labels that fit the version 2 bounds, taken in key order, and
// says whether any were left out. A label that is not valid Kubernetes syntax is left out too, so the
// control plane is told the set is incomplete rather than refusing the whole report.
func BoundK8sServiceInventoryLabels(labels map[string]string) (kept map[string]string, truncated bool) {
	kept = map[string]string{}
	total := 0
	for _, key := range sortedK8sLabelKeys(labels) {
		value := labels[key]
		if !ValidK8sLabelKey(key) || !ValidK8sLabelValue(value) {
			truncated = true
			continue
		}
		if len(kept) >= MaxK8sServiceInventoryLabels || total+len(key)+len(value) > MaxK8sServiceInventoryLabelBytes {
			truncated = true
			break
		}
		kept[key] = value
		total += len(key) + len(value)
	}
	return kept, truncated
}
