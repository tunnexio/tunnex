#!/usr/bin/env bash
set -euo pipefail
mkdir -p work/installer
curl -fsSL https://tunnexio.github.io/packages/current.json -o work/installer/current.json
expected=$(python3 -c 'import json,re; v=json.load(open("work/installer/current.json"))["tag"]; assert re.fullmatch(r"v\d+\.\d+\.\d+",v); print(v)')
images=(ubuntu:24.04 debian:12 fedora:42 rockylinux:9 amazonlinux:2023 opensuse/leap:16.0 alpine:3.22)
if [ "$(uname -m)" = x86_64 ]; then images+=(archlinux:base); fi
for image in "${images[@]}"; do
  docker run --rm -e EXPECTED="$expected" -v "$PWD/install.sh:/installer.sh:ro" "$image" sh -ec '
    if command -v apt-get >/dev/null; then apt-get update -qq; apt-get install -y -qq curl ca-certificates;
    elif command -v dnf >/dev/null; then dnf install -y curl-minimal ca-certificates;
    elif command -v zypper >/dev/null; then zypper --non-interactive install curl ca-certificates;
    elif command -v apk >/dev/null; then apk add curl ca-certificates;
    elif command -v pacman >/dev/null; then pacman -Syu --noconfirm curl ca-certificates;
    fi
    sh /installer.sh
    test "$(/usr/bin/tunnex version)" = "$EXPECTED"
    /usr/bin/tunnex help
    sh /installer.sh
    test "$(/usr/bin/tunnex version)" = "$EXPECTED"
  '
done
