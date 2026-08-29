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
	"regexp"
	"sort"
	"strconv"
	"unicode/utf8"
)

// K8sServiceUIDObservationVersion mirrors the private AgentChannel contract.
const K8sServiceUIDObservationVersion = 1

const (
	maxK8sServiceUIDObservations = 32
	maxK8sServiceUIDReportBytes  = 4096
	maxK8sServiceUIDBytes        = 253
)

var k8sServiceUIDDNSLabelRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// K8sServiceUIDObservationReport deliberately carries no org, site, cluster,
// connector, endpoint, or address field. The presented mTLS identity remains
// the sole authority from which the server derives scope.
type K8sServiceUIDObservationReport struct {
	Version      int                        `json:"version"`
	Sequence     uint64                     `json:"sequence"`
	Digest       string                     `json:"digest"`
	Observations []K8sServiceUIDObservation `json:"observations"`
}

type K8sServiceUIDObservation struct {
	Namespace string `json:"namespace"`
	Service   string `json:"service"`
	UID       string `json:"uid"`
	State     string `json:"state"`
}

func ValidateK8sServiceUIDObservationReport(report K8sServiceUIDObservationReport) error {
	if report.Version != K8sServiceUIDObservationVersion || report.Sequence == 0 || len(report.Observations) == 0 || len(report.Observations) > maxK8sServiceUIDObservations || reportStringBytes(report) > maxK8sServiceUIDReportBytes {
		return fmt.Errorf("invalid Kubernetes Service UID observation")
	}
	seen := map[string]bool{}
	for _, entry := range report.Observations {
		if !validK8sServiceUIDObservation(entry) {
			return fmt.Errorf("invalid Kubernetes Service UID observation")
		}
		key := entry.Namespace + "\x00" + entry.Service + "\x00" + entry.UID
		if seen[key] {
			return fmt.Errorf("invalid Kubernetes Service UID observation")
		}
		seen[key] = true
	}
	if report.Digest != K8sServiceUIDObservationDigest(report.Sequence, report.Observations) {
		return fmt.Errorf("invalid Kubernetes Service UID observation")
	}
	return nil
}

func K8sServiceUIDObservationDigest(sequence uint64, observations []K8sServiceUIDObservation) string {
	entries := append([]K8sServiceUIDObservation(nil), observations...)
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		if a.UID != b.UID {
			return a.UID < b.UID
		}
		return a.State < b.State
	})
	h := sha256.New()
	_, _ = h.Write([]byte("tunnex.k8s-service-uid-observation.v1\n"))
	_, _ = h.Write([]byte(strconv.FormatUint(sequence, 10) + "\n"))
	for _, entry := range entries {
		_, _ = h.Write([]byte(strconv.Quote(entry.Namespace) + "\t" + strconv.Quote(entry.Service) + "\t" + strconv.Quote(entry.UID) + "\t" + entry.State + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ReportK8sServiceUIDObservations posts one locally validated and bounded
// snapshot through the existing mTLS AgentChannel client.
func (c *Client) ReportK8sServiceUIDObservations(ctx context.Context, report K8sServiceUIDObservationReport) error {
	if err := ValidateK8sServiceUIDObservationReport(report); err != nil {
		return err
	}
	body, err := json.Marshal(report)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/agent/k8s-service-uid-observations", bytes.NewReader(body))
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
		return fmt.Errorf("Kubernetes Service UID observation status %d", resp.StatusCode)
	}
	return nil
}

func validK8sServiceUIDObservation(entry K8sServiceUIDObservation) bool {
	if !validK8sServiceUIDDNSLabel(entry.Namespace) || !validK8sServiceUIDDNSLabel(entry.Service) || (entry.State != "live" && entry.State != "deleted") || len(entry.UID) == 0 || len(entry.UID) > maxK8sServiceUIDBytes || !utf8.ValidString(entry.UID) {
		return false
	}
	for _, r := range entry.UID {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validK8sServiceUIDDNSLabel(value string) bool {
	return len(value) >= 1 && len(value) <= 63 && k8sServiceUIDDNSLabelRE.MatchString(value)
}

func reportStringBytes(report K8sServiceUIDObservationReport) int {
	n := len(report.Digest)
	for _, entry := range report.Observations {
		n += len(entry.Namespace) + len(entry.Service) + len(entry.UID) + len(entry.State)
	}
	return n
}
