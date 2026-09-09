#!/usr/bin/env python3
import hashlib
from pathlib import Path
import urllib.request
from upstream import resolve

info = resolve()
url = f'https://github.com/tunnexio/tunnex/archive/{info["source_sha"]}.tar.gz'
with urllib.request.urlopen(url, timeout=120) as response:
    digest = hashlib.file_digest(response, 'sha256').hexdigest()
formula = '''class TunnexCli < Formula
  desc "Command-line client for Tunnex Zero Trust networking"
  homepage "https://tunnex.io"
  url "%s"
  version "%s"
  sha256 "%s"
  license "Apache-2.0"

  depends_on "go" => :build

  def install
    cd "apps/cli" do
      system "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
             "-ldflags=-s -w -X main.version=v#{version}",
             "-o", bin/"tunnex", "./cmd/tunnex"
    end
  end

  def caveats
    <<~EOS
      For tunnex up/down, install wireguard-tools and configure a device first.
      Login: tunnex login --server https://YOUR_CONTROL_PLANE
      CLI installation does not enroll a device or start a tunnel.
    EOS
  end

  test do
    assert_equal "v#{version}", shell_output("#{bin}/tunnex version").strip
    assert_match "tunnex login", shell_output("#{bin}/tunnex help 2>&1")
  end
end
''' % (url, info['version'], digest)
Path('Formula').mkdir(exist_ok=True)
Path('Formula/tunnex-cli.rb').write_text(formula)
