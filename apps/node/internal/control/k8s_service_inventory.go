package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

func ValidateK8sServiceInventoryReport(report K8sServiceInventoryReport) error {
	if report.Version != K8sServiceInventoryVersion || report.Sequence == 0 || report.ObservedAt.IsZero() || len(report.Services) > maxK8sServiceInventoryServices {
		return fmt.Errorf("invalid Kubernetes Service inventory")
	}
	seenServices := map[string]bool{}
	for _, service := range report.Services {
		if !validK8sServiceUIDDNSLabel(service.Namespace) || !validK8sServiceUIDDNSLabel(service.Service) || !validInventoryUID(service.UID) || len(service.Ports) == 0 || len(service.Ports) > maxK8sServiceInventoryPorts {
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
	if report.Digest != K8sServiceInventoryDigest(report.Sequence, report.ObservedAt, report.Services) {
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
