#!/usr/bin/env bash
set -euo pipefail
python3 scripts/index.py
root="$PWD"
for arch in amd64 arm64; do
  mkdir -p "site/apt/dists/stable/main/binary-$arch"
  (cd site/apt && dpkg-scanpackages --arch "$arch" --multiversion pool /dev/null) > "site/apt/dists/stable/main/binary-$arch/Packages"
  gzip -kn "site/apt/dists/stable/main/binary-$arch/Packages"
done
(cd site/apt && apt-ftparchive -o APT::FTPArchive::Release::Origin=Tunnex -o APT::FTPArchive::Release::Label=Tunnex -o APT::FTPArchive::Release::Suite=stable -o APT::FTPArchive::Release::Codename=stable -o APT::FTPArchive::Release::Architectures='amd64 arm64' -o APT::FTPArchive::Release::Components=main release dists/stable) > site/apt/dists/stable/Release
gpg --batch --yes --local-user "$PACKAGE_KEY_ID" --clearsign -o site/apt/dists/stable/InRelease site/apt/dists/stable/Release
gpg --batch --yes --local-user "$PACKAGE_KEY_ID" --armor --detach-sign -o site/apt/dists/stable/Release.gpg site/apt/dists/stable/Release
createrepo_c site/rpm
gpg --batch --yes --local-user "$PACKAGE_KEY_ID" --armor --detach-sign site/rpm/repodata/repomd.xml
for arch in x86_64 aarch64; do
  docker run --rm -v "$root/site/alpine/$arch:/repo" -v "$PACKAGE_APK_KEY:/keys/tunnex.rsa:ro" -v "$root/keys/tunnex.rsa.pub:/etc/apk/keys/tunnex.rsa.pub:ro" alpine:3.22 sh -ec 'apk add --no-cache alpine-sdk; cd /repo; apk index -o APKINDEX.tar.gz ./*.apk; abuild-sign -k /keys/tunnex.rsa APKINDEX.tar.gz'
  docker run --rm -v "$root/site/arch/$arch:/repo" archlinux:base bash -ec 'cd /repo; repo-add --prevent-downgrade tunnex.db.tar.gz ./*.pkg.tar.zst'
  # Serve real files, not symlinks (Pages artifact rejects symlinks).
  rm "site/arch/$arch/tunnex.db" "site/arch/$arch/tunnex.files"
  cp "site/arch/$arch/tunnex.db.tar.gz" "site/arch/$arch/tunnex.db"
  cp "site/arch/$arch/tunnex.files.tar.gz" "site/arch/$arch/tunnex.files"
  gpg --batch --yes --local-user "$PACKAGE_KEY_ID" --detach-sign "site/arch/$arch/tunnex.db"
done
