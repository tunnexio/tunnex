class TunnexCli < Formula
  desc "Command-line client for Tunnex Zero Trust networking"
  homepage "https://tunnex.io"
  url "https://github.com/tunnexio/tunnex/archive/26a36afc9be657af94127c474e173783c91318c3.tar.gz"
  version "0.1.25"
  sha256 "933e1edf0b2a9b15feccbec897e5df246efd3b8c17384b4c23a35d686133d73b"
  license "Apache-2.0"
  revision 1

  depends_on "go" => :build
  depends_on "wireguard-tools"

  def install
    cd "apps/cli" do
      system "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
             "-ldflags=-s -w -X main.version=v#{version}",
             "-o", bin/"tunnex", "./cmd/tunnex"
    end
  end

  def caveats
    <<~EOS
      WireGuard tools are installed. Configure a device before tunnex up/down.
      Login: tunnex login --server https://YOUR_CONTROL_PLANE
      CLI installation does not enroll a device or start a tunnel.
    EOS
  end

  test do
    assert_equal "v#{version}", shell_output("#{bin}/tunnex version").strip
    assert_match "tunnex login", shell_output("#{bin}/tunnex help 2>&1")
  end
end
