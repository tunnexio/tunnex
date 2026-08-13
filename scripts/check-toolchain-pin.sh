#!/usr/bin/env bash
# S11 Cluster-A guard — ONE Go toolchain pin, agreed across every site that materializes it.
#
# THE FAILURE THIS CLOSES: the Makefile/Dockerfiles were bumped to 1.25.12 while the go.mod `go`
# directives still said 1.25.0 — and CI's setup-go resolves `go-version-file: <module>/go.mod`. So the
# docker-based gates built on a patched toolchain while the security jobs scanned an UNPATCHED one, and
# govulncheck reported stdlib vulnerabilities (GO-2026-5856 crypto/tls, GO-2026-4971 net) that the
# Makefile pin had already fixed. Two pins that disagree is the one-truth violation at the toolchain tier.
#
# Correcting the drift is not enough — the next partial bump reproduces it. This makes disagreement FAIL.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
declare -a seen

note() { printf '  %-52s %s\n' "$1" "$2"; }
record() { seen+=("$1|$2"); note "$1" "$2"; }

echo "Go toolchain pin — agreement check"

# 1. Every Go module's `go` directive (this is what CI's setup-go resolves via go-version-file).
for mod in apps/*/go.mod; do
  v=$(awk '/^go /{print $2; exit}' "$mod")
  record "$mod (go directive)" "$v"
done

# 2. The Makefile image pin (drives every docker-based gate + codegen).
v=$(awk -F'golang:' '/^GO_IMAGE :=/{split($2,a,"-"); print a[1]; exit}' Makefile)
record "Makefile GO_IMAGE" "$v"

# 3. Every Dockerfile build stage (what actually ships in the images).
for df in deploy/docker/*.Dockerfile apps/*/Dockerfile; do
  [ -f "$df" ] || continue
  grep -q 'FROM golang:' "$df" || continue
  v=$(awk -F'golang:' '/FROM golang:/{split($2,a,"-"); print a[1]; exit}' "$df")
  record "$df" "$v"
done

# 4. The devcontainer (what a developer's local gate runs on — the S11 slice-1 debt repayment).
if [ -f .devcontainer/devcontainer.json ]; then
  v=$(grep -o '"ghcr.io/devcontainers/features/go:1": *{ *"version": *"[^"]*"' .devcontainer/devcontainer.json |
    sed 's/.*"version": *"//; s/"$//')
  record ".devcontainer/devcontainer.json" "$v"
fi

# Agreement: every recorded version must be identical.
expected=""
for e in "${seen[@]}"; do
  v="${e#*|}"
  if [ -z "$expected" ]; then
    expected="$v"
  elif [ "$v" != "$expected" ]; then
    fail=1
  fi
done

echo
if [ "$fail" -ne 0 ]; then
  echo "ERROR: Go toolchain pins DISAGREE (expected every site to be '$expected'):" >&2
  for e in "${seen[@]}"; do
    v="${e#*|}"
    [ "$v" = "$expected" ] || echo "  MISMATCH  ${e%%|*} = $v" >&2
  done
  echo >&2
  echo "Bump ALL of them together: apps/*/go.mod, Makefile GO_IMAGE, every Dockerfile, .devcontainer." >&2
  exit 1
fi
echo "OK — every Go toolchain pin agrees: $expected"
