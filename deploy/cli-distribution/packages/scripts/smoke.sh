#!/usr/bin/env bash
set -euo pipefail
expected="$(python3 -c 'import json; print(json.load(open("work/release.json"))["tag"])')"
python3 -m http.server 8765 --directory site > work/http.log 2>&1 &
server_pid=$!
trap 'kill "$server_pid"' EXIT
for attempt in {1..20}; do
  if curl --fail --silent http://127.0.0.1:8765/tunnex.asc >/dev/null; then break; fi
  sleep 1
done
for os in ubuntu:24.04 debian:12; do
  docker run --rm --network host -e EXPECTED="$expected" "$os" sh -ec '
    apt-get update -qq; apt-get install -y -qq ca-certificates curl gnupg
    curl -fsS http://127.0.0.1:8765/tunnex.asc -o /usr/share/keyrings/tunnex.asc
    echo "deb [signed-by=/usr/share/keyrings/tunnex.asc] http://127.0.0.1:8765/apt stable main" > /etc/apt/sources.list.d/tunnex.list
    apt-get update -qq; apt-get install -y tunnex-cli
    test "$(tunnex version)" = "$EXPECTED"; tunnex help
    apt-get remove -y tunnex-cli; test ! -e /usr/bin/tunnex
  '
done
for os in fedora:42 rockylinux:9 amazonlinux:2023; do
  docker run --rm --network host -e EXPECTED="$expected" "$os" sh -ec '
    printf "[tunnex]\nname=Tunnex\nbaseurl=http://127.0.0.1:8765/rpm\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=http://127.0.0.1:8765/tunnex.asc\n" > /etc/yum.repos.d/tunnex.repo
    dnf install -y tunnex-cli
    test "$(tunnex version)" = "$EXPECTED"; tunnex help
    dnf remove -y tunnex-cli; test ! -e /usr/bin/tunnex
  '
done
docker run --rm --network host -v "$PWD/keys/tunnex.asc:/tmp/tunnex.asc:ro" -e EXPECTED="$expected" opensuse/leap:16.0 sh -ec '
  rpm --import /tmp/tunnex.asc
  zypper --non-interactive addrepo --refresh http://127.0.0.1:8765/rpm tunnex
  zypper --non-interactive refresh tunnex
  zypper --non-interactive install --from tunnex tunnex-cli
  test "$(tunnex version)" = "$EXPECTED"; tunnex help
  zypper --non-interactive remove tunnex-cli; test ! -e /usr/bin/tunnex
'
docker run --rm --network host -e EXPECTED="$expected" alpine:3.22 sh -ec '
  wget -q http://127.0.0.1:8765/tunnex.rsa.pub -O /etc/apk/keys/tunnex.rsa.pub
  echo http://127.0.0.1:8765/alpine >> /etc/apk/repositories
  apk update; apk add tunnex-cli
  test "$(tunnex version)" = "$EXPECTED"; tunnex help
  apk del tunnex-cli; test ! -e /usr/bin/tunnex
'
docker run --rm --network host -e EXPECTED="$expected" -e KEY_ID="$PACKAGE_KEY_ID" archlinux:base bash -ec '
  pacman-key --init
  curl -fsS http://127.0.0.1:8765/tunnex.asc -o /tmp/tunnex.asc
  pacman-key --add /tmp/tunnex.asc; pacman-key --lsign-key "$KEY_ID"
  printf "\n[tunnex]\nSigLevel = Required DatabaseRequired\nServer = http://127.0.0.1:8765/arch/\$arch\n" >> /etc/pacman.conf
  pacman -Sy --noconfirm tunnex-cli
  test "$(tunnex version)" = "$EXPECTED"; tunnex help
  pacman -R --noconfirm tunnex-cli; test ! -e /usr/bin/tunnex
'
# Prove altered signed metadata is refused without using insecure install flags.
cp site/apt/dists/stable/Release work/tampered-Release
printf '\nTampered: yes\n' >> work/tampered-Release
if gpg --verify site/apt/dists/stable/Release.gpg work/tampered-Release; then
  echo 'ERROR: tampered metadata accepted' >&2; exit 1
fi
# Arch version-boundary regression: lexical order must not select 0.1.99.
mkdir -p work/arch-boundary
for version in 0.1.100 0.1.99; do
  python3 - "$version" <<'PY'
import json, sys
from pathlib import Path
Path('work/boundary.json').write_text(json.dumps({'name':'tunnex-boundary-test','arch':'amd64','platform':'linux','version':sys.argv[1],'release':'1','maintainer':'Tunnex <iotunnex@gmail.com>','description':'Isolated repository ordering regression','contents':[{'src':'/bin/true','dst':'/usr/bin/tunnex-boundary-test'}]}))
PY
  nfpm package --config work/boundary.json --packager archlinux --target work/arch-boundary/
done
docker run --rm -v "$PWD/work/arch-boundary:/repo" archlinux:base bash -ec '
  cd /repo
  repo-add --prevent-downgrade test.db.tar.gz ./*.pkg.tar.zst
  bsdtar -xOf test.db.tar.gz "*/desc" | grep -A1 "%VERSION%" | grep -Fx "0.1.100-1"
'

# Prove APT itself refuses altered signed metadata (not only gpg verification).
cp site/apt/dists/stable/InRelease work/original-InRelease
sed 's/Origin: Tunnex/Origin: Altered/' work/original-InRelease > site/apt/dists/stable/InRelease
if docker run --rm --network host -v "$PWD/keys/tunnex.asc:/usr/share/keyrings/tunnex.asc:ro" ubuntu:24.04 sh -ec '
  echo "deb [signed-by=/usr/share/keyrings/tunnex.asc] http://127.0.0.1:8765/apt stable main" > /tmp/tunnex.list
  apt-get -o Dir::Etc::sourcelist=/tmp/tunnex.list -o Dir::Etc::sourceparts=- -o APT::Update::Error-Mode=any update
' > work/apt-tamper.log 2>&1; then
  echo 'ERROR: APT accepted altered signed metadata' >&2; exit 1
fi
grep -E 'BADSIG|invalid signature' work/apt-tamper.log
cp work/original-InRelease site/apt/dists/stable/InRelease
