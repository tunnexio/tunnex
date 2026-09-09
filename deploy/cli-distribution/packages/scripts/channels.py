#!/usr/bin/env python3
"""Generate additional channels from the same verified immutable release bytes."""
import json
from pathlib import Path

from upstream import resolve, download
from channel_guard import validate
info = resolve()
previous = Path('nix/release.json')
validate(info, json.loads(previous.read_text()) if previous.exists() else None)
Path('work').mkdir(exist_ok=True)
Path('work/release.json').write_text(json.dumps(info, indent=2) + '\n')
download(info, 'work/upstream')
version = info['version']
hashes = info['binary_sha256']
Path('nix').mkdir(exist_ok=True)
Path('aur/tunnex-cli-bin').mkdir(parents=True, exist_ok=True)
Path('nix/release.json').write_text(Path('work/release.json').read_text())
Path('nix/package.nix').write_text('''{ stdenvNoCC, fetchurl, lib }:
let
  artifacts = {
    x86_64-linux = { arch = "amd64"; sha256 = "%s"; };
    aarch64-linux = { arch = "arm64"; sha256 = "%s"; };
  };
  artifact = artifacts.${stdenvNoCC.hostPlatform.system};
in stdenvNoCC.mkDerivation {
  pname = "tunnex-cli";
  version = "%s";
  src = fetchurl {
    url = "https://github.com/tunnexio/tunnex/releases/download/v%s/tnx-linux-${artifact.arch}";
    inherit (artifact) sha256;
  };
  dontUnpack = true;
  dontFixup = true;
  installPhase = ''\n    install -Dm755 "$src" "$out/bin/tunnex"\n  '';
  doInstallCheck = stdenvNoCC.buildPlatform.canExecute stdenvNoCC.hostPlatform;
  installCheckPhase = ''\n    test "$("$out/bin/tunnex" version)" = "v%s"\n    "$out/bin/tunnex" help\n  '';
  meta = {
    description = "Tunnex Zero Trust command-line client";
    homepage = "https://tunnex.io";
    license = lib.licenses.asl20;
    platforms = [ "x86_64-linux" "aarch64-linux" ];
    mainProgram = "tunnex";
  };
}
''' % (hashes['tnx-linux-amd64'], hashes['tnx-linux-arm64'], version, version, version))
Path('flake.nix').write_text('''{
  description = "Verified Tunnex CLI packages";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/d6524aaca2ff07876657ae2b323f24be4874944b";
  outputs = { self, nixpkgs }: {
    packages = nixpkgs.lib.genAttrs [ "x86_64-linux" "aarch64-linux" ] (system:
      let pkgs = import nixpkgs { inherit system; };
          cli = pkgs.callPackage ./nix/package.nix {};
      in { tunnex-cli = cli; default = cli; });
  };
}
''')
Path('aur/tunnex-cli-bin/PKGBUILD').write_text('''# Generated from a verified Tunnex release; not an AUR submission.
pkgname=tunnex-cli-bin
pkgver=%s
pkgrel=1
pkgdesc='Tunnex Zero Trust command-line client'
arch=('x86_64' 'aarch64')
url='https://tunnex.io'
license=('Apache-2.0')
provides=('tunnex-cli')
conflicts=('tunnex-cli')
optdepends=('wireguard-tools: tunnel up/down commands')
source_x86_64=("tunnex-${pkgver}-x86_64::https://github.com/tunnexio/tunnex/releases/download/v${pkgver}/tnx-linux-amd64")
source_aarch64=("tunnex-${pkgver}-aarch64::https://github.com/tunnexio/tunnex/releases/download/v${pkgver}/tnx-linux-arm64")
sha256sums_x86_64=('%s')
sha256sums_aarch64=('%s')
package() {
  install -Dm755 "$srcdir/tunnex-${pkgver}-${CARCH}" "$pkgdir/usr/bin/tunnex"
}
''' % (version, hashes['tnx-linux-amd64'], hashes['tnx-linux-arm64']))
