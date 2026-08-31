package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

const maxMaterializedChartBytes int64 = 128 << 20

var imageTagRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)

type chartMetadata struct {
	Reference  string
	Name       string
	Version    string
	AppVersion string
}

func (m chartMetadata) fingerprint() string {
	return strings.Join([]string{m.Reference, m.Name, m.Version, m.AppVersion}, "\x00")
}

type chartArtifact struct {
	Metadata chartMetadata
	Path     string
	SHA256   string
}

type installChartArtifacts struct {
	root        string
	cleanupRoot func(string) error
	gateway     chartArtifact
	hostPosture chartArtifact
}

func (a installChartArtifacts) cleanup() error {
	if a.root == "" {
		return nil
	}
	cleanup := a.cleanupRoot
	if cleanup == nil {
		cleanup = removeChartStagingRoot
	}
	return cleanup(a.root)
}

func removeChartStagingRoot(root string) error {
	if root == "" {
		return nil
	}
	// Helm artifacts are made owner-read-only after hashing. Restore owner
	// write permission inside the private root before removal so cleanup also
	// succeeds on Windows, where a read-only file cannot be deleted.
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && info != nil {
			if info.IsDir() {
				_ = os.Chmod(path, 0o700)
			} else if info.Mode().IsRegular() {
				_ = os.Chmod(path, 0o600)
			}
		}
		return nil
	})
	return os.RemoveAll(root)
}

func materializeInstallCharts(ctx context.Context, runner k8sRunner, kubeContext string, o installOptions) (installChartArtifacts, error) {
	return materializeInstallChartsWithCleanup(ctx, runner, kubeContext, o, removeChartStagingRoot)
}

func materializeInstallChartsWithCleanup(ctx context.Context, runner k8sRunner, kubeContext string, o installOptions, cleanup func(string) error) (installChartArtifacts, error) {
	cleanup = normalizedChartCleanup(cleanup)
	root, err := createChartStagingRootWithCleanup(cleanup)
	if err != nil {
		return installChartArtifacts{}, err
	}
	artifacts := installChartArtifacts{root: root, cleanupRoot: cleanup}
	artifacts.gateway, err = materializeChartArtifact(ctx, runner, kubeContext, root, "gateway", o.chart, o.chartVersion, "tunnex-gateway")
	if err != nil {
		return installChartArtifacts{}, joinChartCleanupError(err, root, artifacts.cleanup())
	}
	artifacts.hostPosture, err = materializeChartArtifact(ctx, runner, kubeContext, root, "host-posture", o.hostPostureChart, o.hostPostureVersion, "tunnex-host-posture")
	if err != nil {
		return installChartArtifacts{}, joinChartCleanupError(err, root, artifacts.cleanup())
	}
	return artifacts, nil
}

func materializeUpgradeChart(ctx context.Context, runner k8sRunner, kubeContext, reference, requestedVersion string) (chartArtifact, string, error) {
	return materializeUpgradeChartWithCleanup(ctx, runner, kubeContext, reference, requestedVersion, removeChartStagingRoot)
}

func materializeUpgradeChartWithCleanup(ctx context.Context, runner k8sRunner, kubeContext, reference, requestedVersion string, cleanup func(string) error) (chartArtifact, string, error) {
	cleanup = normalizedChartCleanup(cleanup)
	root, err := createChartStagingRootWithCleanup(cleanup)
	if err != nil {
		return chartArtifact{}, "", err
	}
	artifact, err := materializeChartArtifact(ctx, runner, kubeContext, root, "gateway", reference, requestedVersion, "tunnex-gateway")
	if err != nil {
		return chartArtifact{}, "", joinChartCleanupError(err, root, cleanup(root))
	}
	return artifact, root, nil
}

func createChartStagingRoot() (string, error) {
	return createChartStagingRootWithCleanup(removeChartStagingRoot)
}

func createChartStagingRootWithCleanup(cleanup func(string) error) (string, error) {
	cleanup = normalizedChartCleanup(cleanup)
	root, err := os.MkdirTemp("", "tunnex-k8s-charts-")
	if err != nil {
		return "", fmt.Errorf("create private chart staging directory: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return "", joinChartCleanupError(fmt.Errorf("secure chart staging directory: %w", err), root, cleanup(root))
	}
	return root, nil
}

func normalizedChartCleanup(cleanup func(string) error) func(string) error {
	if cleanup == nil {
		return removeChartStagingRoot
	}
	return cleanup
}

func joinChartCleanupError(operationErr error, root string, cleanupErr error) error {
	if cleanupErr == nil {
		return operationErr
	}
	return errors.Join(operationErr, fmt.Errorf("remove private chart staging directory %q before any Helm mutation: %w", root, cleanupErr))
}

func finalizeChartCleanup(root string, cleanup func(string) error, helmMutationConfirmed bool, errOut io.Writer) error {
	if root == "" {
		return nil
	}
	cleanup = normalizedChartCleanup(cleanup)
	err := cleanup(root)
	if err == nil {
		return nil
	}
	if !helmMutationConfirmed {
		return fmt.Errorf("remove private chart staging directory %q before any Helm mutation: %w", root, err)
	}
	if errOut == nil {
		errOut = io.Discard
	}
	_, _ = fmt.Fprintf(errOut, "Warning: Helm mutation succeeded, but private chart staging directory %q could not be removed: %v. Remove that exact directory manually after confirming no Helm process is using it.\n", root, err)
	return nil
}

func materializeChartArtifact(ctx context.Context, runner k8sRunner, kubeContext, root, label, reference, requestedVersion, expectedName string) (chartArtifact, error) {
	destination := filepath.Join(root, label)
	if err := os.Mkdir(destination, 0o700); err != nil {
		return chartArtifact{}, fmt.Errorf("create private %s chart staging directory: %w", label, err)
	}
	var command k8sCommand
	if strings.HasPrefix(reference, "oci://") {
		if requestedVersion == "" {
			return chartArtifact{}, fmt.Errorf("OCI chart %q requires an exact version before materialization", reference)
		}
		command = k8sCommand{name: "helm", args: []string{"pull", reference, "--version", requestedVersion, "--destination", destination}}
	} else {
		command = k8sCommand{name: "helm", args: []string{"package", reference, "--destination", destination}}
	}
	command.args = appendHelmContext(command.args, kubeContext)
	if _, err := runChecked(ctx, runner, "materialize exact "+label+" Helm chart", command); err != nil {
		return chartArtifact{}, fmt.Errorf("materialize chart %q: %w", reference, err)
	}
	path, err := soleMaterializedChart(destination)
	if err != nil {
		return chartArtifact{}, fmt.Errorf("materialize chart %q: %w", reference, err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		return chartArtifact{}, fmt.Errorf("make materialized chart %q read-only: %w", reference, err)
	}
	before, err := hashChartArtifact(path)
	if err != nil {
		return chartArtifact{}, fmt.Errorf("hash materialized chart %q: %w", reference, err)
	}
	metadata, err := readMaterializedChartMetadata(ctx, runner, kubeContext, path, reference, requestedVersion, expectedName)
	if err != nil {
		return chartArtifact{}, err
	}
	after, err := hashChartArtifact(path)
	if err != nil {
		return chartArtifact{}, fmt.Errorf("rehash materialized chart %q: %w", reference, err)
	}
	if before != after {
		return chartArtifact{}, fmt.Errorf("materialized chart %q changed while its metadata was read", reference)
	}
	return chartArtifact{Metadata: metadata, Path: path, SHA256: after}, nil
}

func soleMaterializedChart(directory string) (string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return "", err
	}
	if len(entries) != 1 {
		return "", fmt.Errorf("Helm produced %d files, expected exactly one .tgz artifact", len(entries))
	}
	entry := entries[0]
	if entry.Type()&os.ModeSymlink != 0 || entry.IsDir() || filepath.Ext(entry.Name()) != ".tgz" {
		return "", errors.New("Helm output is not one regular .tgz artifact")
	}
	path := filepath.Join(directory, entry.Name())
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxMaterializedChartBytes {
		return "", fmt.Errorf("Helm artifact must be a non-empty regular file no larger than %d bytes", maxMaterializedChartBytes)
	}
	return path, nil
}

func hashChartArtifact(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxMaterializedChartBytes {
		return "", errors.New("materialized chart is not the approved bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, maxMaterializedChartBytes+1))
	if err != nil {
		return "", err
	}
	if written != info.Size() || written > maxMaterializedChartBytes {
		return "", errors.New("materialized chart size changed while hashing")
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func verifyChartArtifact(artifact chartArtifact, label string) error {
	actual, err := hashChartArtifact(artifact.Path)
	if err != nil {
		return fmt.Errorf("verify approved %s chart artifact: %w", label, err)
	}
	if actual != artifact.SHA256 {
		return fmt.Errorf("approved %s chart artifact changed after plan approval; no lifecycle token or Helm mutation was allowed", label)
	}
	return nil
}

func readMaterializedChartMetadata(ctx context.Context, runner k8sRunner, kubeContext, artifactPath, originalReference, requestedVersion, expectedName string) (chartMetadata, error) {
	args := appendHelmContext([]string{"show", "chart", artifactPath}, kubeContext)
	result, err := runChecked(ctx, runner, "read exact materialized Helm chart metadata", k8sCommand{name: "helm", args: args})
	if err != nil {
		return chartMetadata{}, fmt.Errorf("prove materialized chart metadata for %q: %w", originalReference, err)
	}
	metadata, err := parseChartMetadata(result.stdout)
	if err != nil {
		return chartMetadata{}, fmt.Errorf("chart metadata for %q is not trustworthy: %w", originalReference, err)
	}
	metadata.Reference = originalReference
	if metadata.Name != expectedName {
		return chartMetadata{}, fmt.Errorf("chart %q reports name %q, expected exact %q", originalReference, metadata.Name, expectedName)
	}
	if requestedVersion != "" && metadata.Version != requestedVersion {
		return chartMetadata{}, fmt.Errorf("chart %q reports version %q, expected requested %q", originalReference, metadata.Version, requestedVersion)
	}
	if !imageTagRE.MatchString(metadata.AppVersion) {
		return chartMetadata{}, fmt.Errorf("chart %q appVersion %q is not an exact OCI image tag", originalReference, metadata.AppVersion)
	}
	image, err := parseImageRef(defaultNodeImageRegistry + "/" + defaultNodeImageAgent + ":" + metadata.AppVersion)
	if err != nil || image.registry != defaultNodeImageRegistry || image.agent != defaultNodeImageAgent || image.tag != metadata.AppVersion || image.digest != "" {
		return chartMetadata{}, fmt.Errorf("chart %q appVersion %q cannot identify the exact default node-agent image", originalReference, metadata.AppVersion)
	}
	return metadata, nil
}

func parseChartMetadata(raw []byte) (chartMetadata, error) {
	if len(raw) == 0 {
		return chartMetadata{}, errors.New("Helm returned empty Chart.yaml")
	}
	for _, r := range string(raw) {
		if unicode.IsControl(r) && r != '\n' && r != '\r' {
			return chartMetadata{}, errors.New("Chart.yaml contains unsupported control characters")
		}
	}
	values := make(map[string]string, 3)
	for lineNumber, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") || len(line) != len(strings.TrimLeft(line, " ")) {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		key = strings.TrimSpace(key)
		if !ok || (key != "name" && key != "version" && key != "appVersion") {
			continue
		}
		if _, duplicate := values[key]; duplicate {
			return chartMetadata{}, fmt.Errorf("duplicate top-level %s at line %d", key, lineNumber+1)
		}
		parsed, err := parseChartScalar(value)
		if err != nil {
			return chartMetadata{}, fmt.Errorf("invalid %s at line %d: %w", key, lineNumber+1, err)
		}
		values[key] = parsed
	}
	for _, key := range []string{"name", "version", "appVersion"} {
		if values[key] == "" {
			return chartMetadata{}, fmt.Errorf("missing non-empty top-level %s", key)
		}
	}
	if !versionRE.MatchString(values["version"]) {
		return chartMetadata{}, fmt.Errorf("version %q contains unsupported characters", values["version"])
	}
	return chartMetadata{Name: values["name"], Version: values["version"], AppVersion: values["appVersion"]}, nil
}

func parseChartScalar(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", errors.New("value is empty")
	}
	if value[0] == '"' {
		parsed, err := strconv.Unquote(value)
		if err != nil {
			return "", errors.New("double-quoted scalar is malformed")
		}
		return validateChartScalar(parsed)
	}
	if value[0] == '\'' {
		if len(value) < 2 || value[len(value)-1] != '\'' {
			return "", errors.New("single-quoted scalar is malformed")
		}
		return validateChartScalar(strings.ReplaceAll(value[1:len(value)-1], "''", "'"))
	}
	if comment := strings.Index(value, " #"); comment >= 0 {
		value = strings.TrimSpace(value[:comment])
	}
	if value == "" || strings.ContainsAny(value, "{}[]&*!|>,") || strings.Contains(value, ": ") {
		return "", errors.New("only one plain or quoted scalar is allowed")
	}
	return validateChartScalar(value)
}

func validateChartScalar(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", errors.New("scalar is empty, padded, or contains control characters")
	}
	return value, nil
}

func recheckPreparedChartArtifacts(prepared preparedInstall) error {
	if err := verifyChartArtifact(prepared.gatewayArtifact, "gateway"); err != nil {
		return err
	}
	return verifyChartArtifact(prepared.hostPostureArtifact, "host posture")
}
