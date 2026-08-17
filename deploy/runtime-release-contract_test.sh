#!/bin/sh
# Source contract for the immutable, tag-bound managed-agent runtime assets.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
CI="$ROOT/.github/workflows/ci.yml"

for arch in amd64 arm64; do
  grep -Fq "GOARCH=\"\$arch\"" "$CI"
  grep -Fq "tunnex-agent-runtime-linux-$arch" "$CI"
done
grep -Fq "CGO_ENABLED=0 GOOS=linux GOARCH=\"\$arch\"" "$CI"
grep -Fq "./cmd/tunnex-agent-runtime" "$CI"
grep -Fq "name: tunnex-linux-agent-runtime" "$CI"
grep -Fq "Tunnex-Agent-Runtime-SHA256SUMS" "$CI"
grep -Fq 'gh release upload "$GITHUB_REF_NAME"' "$CI"
grep -Fq 'if: startsWith(github.ref, '\''refs/tags/v'\'')' "$CI"

MANIFEST="$ROOT/apps/api/internal/release/manifest.go"
VERIFY="$ROOT/apps/api/cmd/releaseverify/main.go"
grep -Fq 'ManagedAgentRuntime' "$MANIFEST"
grep -Fq 'managed_agent_runtime' "$MANIFEST"
grep -Fq 'source_sha' "$MANIFEST"
grep -Fq 'VerifyManagedAgentRuntime' "$MANIFEST"
grep -Fq 'runtime_amd64_sha' "$CI"
grep -Fq 'runtime_arm64_sha' "$CI"
grep -Fq 'TUNNEX_AGENT_RUNTIME_AMD64_SHA256' "$VERIFY"
grep -Fq 'TUNNEX_AGENT_RUNTIME_ARM64_SHA256' "$VERIFY"
grep -Fq 'TUNNEX_AGENT_RUNTIME_UNIT_NAME' "$VERIFY"
grep -Fq 'TUNNEX_AGENT_RUNTIME_UNIT_SHA256' "$VERIFY"
grep -Fq 'TUNNEX_AGENT_RUNTIME_UNIT_SOURCE_SHA' "$VERIFY"
grep -Fq 'runtime_unit_sha' "$CI"
grep -Fq 'tunnex-agent-runtime.service' "$CI"
grep -Fq 'sha256sum "$amd64" "$arm64" "$unit"' "$CI"
grep -Fq 'json:"unit"' "$MANIFEST"
grep -Fq 'expected-source-sha' "$VERIFY"
grep -Fq 'expected-key-id' "$VERIFY"
grep -Fq 'TUNNEX_RELEASE_MANIFEST_URL' "$ROOT/apps/api/internal/config/config.go"

echo 'managed-agent runtime release contract: PASS'
