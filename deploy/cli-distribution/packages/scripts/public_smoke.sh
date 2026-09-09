#!/usr/bin/env bash
set -euo pipefail
base=https://tunnexio.github.io/packages
mkdir -p work/public
curl --fail --retry 3 "$base/current.json" -o work/public/current.json
expected="$(python3 -c 'import json,re; s=json.load(open("work/public/current.json"))["tag"]; assert re.fullmatch(r"v\d+\.\d+\.\d+",s); print(s)')"
curl --fail --retry 3 "$base/tunnex.asc" -o work/public/tunnex.asc
curl --fail --retry 3 "$base/tunnex.rsa.pub" -o work/public/tunnex.rsa.pub
cmp keys/tunnex.asc work/public/tunnex.asc
cmp keys/tunnex.rsa.pub work/public/tunnex.rsa.pub
docker run --rm -v "$PWD/work/public/tunnex.asc:/usr/share/keyrings/tunnex.asc:ro" -e EXPECTED="$expected" ubuntu:24.04 sh -ec '
  apt-get update -qq; apt-get install -y -qq ca-certificates
  echo "deb [signed-by=/usr/share/keyrings/tunnex.asc] https://tunnexio.github.io/packages/apt stable main" > /etc/apt/sources.list.d/tunnex.list
  apt-get update -qq; apt-get install -y tunnex-cli
  test "$(tunnex version)" = "$EXPECTED"; tunnex help
  apt-get remove -y tunnex-cli; test ! -e /usr/bin/tunnex
'
docker run --rm -e EXPECTED="$expected" rockylinux:9 sh -ec '
  printf "[tunnex]\nname=Tunnex\nbaseurl=https://tunnexio.github.io/packages/rpm\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=https://tunnexio.github.io/packages/tunnex.asc\n" > /etc/yum.repos.d/tunnex.repo
  dnf install -y tunnex-cli
  test "$(tunnex version)" = "$EXPECTED"; tunnex help
  dnf remove -y tunnex-cli; test ! -e /usr/bin/tunnex
'
docker run --rm -v "$PWD/work/public/tunnex.rsa.pub:/etc/apk/keys/tunnex.rsa.pub:ro" -e EXPECTED="$expected" alpine:3.22 sh -ec '
  echo https://tunnexio.github.io/packages/alpine >> /etc/apk/repositories
  apk update; apk add tunnex-cli
  test "$(tunnex version)" = "$EXPECTED"; tunnex help
  apk del tunnex-cli; test ! -e /usr/bin/tunnex
'
if [ "$(uname -m)" = x86_64 ]; then
  docker run --rm -v "$PWD/work/public/tunnex.asc:/tmp/tunnex.asc:ro" -e EXPECTED="$expected" -e KEY_ID="$(cat keys/FINGERPRINT)" archlinux:base bash -ec '
    pacman-key --init
    pacman-key --add /tmp/tunnex.asc; pacman-key --lsign-key "$KEY_ID"
    printf "\n[tunnex]\nSigLevel = Required DatabaseRequired\nServer = https://tunnexio.github.io/packages/arch/\$arch\n" >> /etc/pacman.conf
    pacman -Sy --noconfirm tunnex-cli
    test "$(tunnex version)" = "$EXPECTED"; tunnex help
    pacman -R --noconfirm tunnex-cli; test ! -e /usr/bin/tunnex
  '
fi
