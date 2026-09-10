"""Build the private saved-key probe extension against one immutable upstream tree.

Usage: python3 build.py SOURCE_GIT_DIRECTORY OUTPUT_BINARY
The source checkout is read-only; builds use a fresh temporary archive.
"""
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile

PIN = "9537b2fadf42af90eb34ed47d3d4252e1beff4a0"
source, output = map(pathlib.Path, sys.argv[1:])
extension = pathlib.Path(__file__).resolve().parent
with tempfile.TemporaryDirectory(prefix="tunnex-saved-probe-") as scratch:
    root = pathlib.Path(scratch)
    archive = root / "source.tar"
    subprocess.run(["git", "-C", str(source), "archive", "--format=tar", "-o", str(archive), PIN], check=True)
    with tarfile.open(archive) as tar:
        tar.extractall(root, filter="data")
    handlers = root / "transports/bifrost-http/handlers"
    routes = handlers / "providers.go"
    marker = '\tr.GET("/api/keys", lib.ChainMiddlewares(h.listKeys, middlewares...))'
    text = routes.read_text()
    assert text.count(marker) == 1, "pinned route registration changed"
    routes.write_text(text.replace(marker, '\tr.POST("/api/providers/{provider}/keys/{key_id}/test-connection", lib.ChainMiddlewares(h.tunnexSavedKeyProbe, middlewares...))\n' + marker))
    (handlers / "tunnex_saved_probe.go").write_bytes((extension / "saved_probe.go").read_bytes())
    # The private engine has no customer dashboard; Tunnex supplies its own UI.
    ui = root / "transports/bifrost-http/ui"
    ui.mkdir(exist_ok=True)
    (ui / "index.html").write_text("Private Tunnex AI engine")
    env = dict(os.environ, GOWORK="off", GOFLAGS="-mod=readonly")
    subprocess.run(["go", "build", "-trimpath", "-ldflags=-s -w -X main.Version=v2.0.0-tunnex-saved-probe.1", "-o", str(output.resolve()), "./bifrost-http"], cwd=root / "transports", env=env, check=True)
