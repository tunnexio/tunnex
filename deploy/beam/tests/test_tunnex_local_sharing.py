"""LS-UX-1 E.2: tunnex-local-sharing enable/disable/status against a fake Docker.

Certificates are made with the openssl CLI at test time only. The command must
be dry-run by default, idempotent, restore everything it moved on disable and
never print secret material.
"""
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
TOOL = ROOT / "deploy/beam/tunnex-local-sharing.py"
OPENSSL = shutil.which("openssl")
PIN = "ghcr.io/tunnexio/tunnex-beam-proxy@sha256:" + "a" * 64

FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, os, re, shutil, sys
d = os.environ["FAKE_DIR"]
args = sys.argv[1:]
with open(os.path.join(d, "calls"), "a") as log:
    log.write(os.environ.get("COMPOSE_PROFILES", "") + "|" + " ".join(args) + "\n")
if args[0] == "ps":
    print("\n".join("c%d" % i for i, _ in enumerate(open(os.path.join(d, "participants")).read().split())))
    sys.exit(0)
if args[0] == "inspect":
    rows = open(os.path.join(d, "participants")).read().split()
    service, files = rows[int(args[-1][1:])].split("|")
    print("%s|%s|False" % (service, files))
    sys.exit(0)
assert args[0] == "compose", args
cut = next(i for i, a in enumerate(args) if a in ("exec", "cp", "run", "up", "rm"))
files = [args[i + 1] for i, a in enumerate(args[:cut]) if a == "-f"]
rest = args[cut:]
def out_dir():
    helper = [f for f in files if f.endswith("local-sharing-issue.yml")][0]
    return re.search(r"source: '([^']+)', target: /out", open(helper).read()).group(1)
if rest[0] == "exec":
    if os.environ.get("FAKE_NO_PIN") != "1":
        print("TUNNEX_RELEASE_VERSION=v9.9.9")
        print("TUNNEX_BEAM_PROXY_IMAGE=" + os.environ["FAKE_PIN"])
elif rest[0] == "cp":
    shutil.copy(os.environ["FAKE_OVERLAY"], rest[2])
elif rest[0] == "run" and "app-proxy-issue" in rest:
    assert "local-sharing" in rest[rest.index("--purpose") + 1]
    with open(os.path.join(out_dir(), "authority.token"), "w") as f:
        f.write("tnxap_SHHH-TOKEN-VALUE\n")
    print(json.dumps({"id": "11111111-1111-4111-8111-111111111111", "version": 1, "name": "x", "purpose": "local-sharing"}))
elif rest[0] == "run" and "beam-proxy-certificate" in rest:
    os.makedirs(os.path.join(out_dir(), "connector"))
    for name in ("gateway-cert.pem", "gateway-key.pem", "agent-ca.pem"):
        with open(os.path.join(out_dir(), "connector", name), "w") as f:
            f.write("SHHH-" + name)
elif rest[0] == "run" and "app-proxy-revoke" in rest:
    print("{}")
elif rest[0] == "up" and os.path.exists(os.path.join(d, "fail-up")) and any(f.endswith("local-sharing.yml") for f in files):
    sys.exit("proxy did not become healthy")
elif rest[0] in ("up", "rm"):
    pass
else:
    sys.exit("unexpected docker call: %s" % args)
'''


def openssl(*args, cwd):
    subprocess.run([OPENSSL, *args], cwd=cwd, check=True, capture_output=True)


@unittest.skipUnless(OPENSSL, "openssl CLI makes test certificates")
class LocalSharingCommand(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp)
        pki = self.tmp / "pki"
        pki.mkdir()
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "30", "-subj", "/CN=Test CA", cwd=pki)
        openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "key.pem", "-out", "req.csr", "-subj", "/CN=*.share-example.dev", cwd=pki)
        (pki / "ext").write_text("subjectAltName=DNS:*.share-example.dev\n")
        openssl("x509", "-req", "-in", "req.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "cert.pem", "-days", "30", "-extfile", "ext", cwd=pki)
        self.pki = pki
        self.install = self.tmp / "tunnex"
        self.install.mkdir()
        (self.install / "tunnex.yml").write_text("# installed\n")
        self.env = "APP_BASE_URL=https://cp.example.com\nCOMPOSE_PROJECT_NAME=tunnex\nCOMPOSE_PROFILES=bundled-db\nTUNNEX_TLS_MODE=direct\n"
        (self.install / ".env").write_text(self.env)
        os.chmod(self.install / ".env", 0o600)
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        (bin_dir / "docker").write_text(FAKE_DOCKER)
        os.chmod(bin_dir / "docker", 0o755)
        self.fake = self.tmp / "fake"
        self.participants([("api", ["tunnex.yml"])])
        self.environ = dict(os.environ, PATH="%s:%s" % (bin_dir, os.environ["PATH"]), FAKE_DIR=str(self.fake), FAKE_PIN=PIN,
                            FAKE_OVERLAY=str(ROOT / "deploy/beam/compose.yml"))

    def participants(self, rows):
        (self.tmp / "fake").mkdir(exist_ok=True)
        (self.tmp / "fake" / "participants").write_text("\n".join("%s|%s" % (svc, ",".join(str(self.install / f) for f in files)) for svc, files in rows) + "\n")

    def run_tool(self, *args, extra_env=None):
        env = dict(self.environ, **(extra_env or {}))
        return subprocess.run([sys.executable, str(TOOL), "--directory", str(self.install), *args], capture_output=True, text=True, env=env)

    def enable(self, *more, domain="share-example.dev"):
        more = more + (("--skip-owner-check",) if "--apply" in more else ())
        return self.run_tool("enable", "--domain", domain, "--cert", str(self.pki / "cert.pem"), "--key", str(self.pki / "key.pem"), "--ca-file", str(self.pki / "ca.pem"), *more)

    def calls(self):
        path = self.fake / "calls"
        return path.read_text().splitlines() if path.exists() else []

    def env_values(self):
        return dict(l.split("=", 1) for l in (self.install / ".env").read_text().splitlines() if "=" in l)

    def test_dry_run_changes_nothing(self):
        result = self.enable()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("dry run: nothing was changed", result.stdout)
        self.assertEqual((self.install / ".env").read_text(), self.env)
        self.assertFalse((self.install / "local-sharing.yml").exists())
        self.assertTrue(all(" exec " in c for c in self.calls() if "compose" in c), self.calls())

    def test_enable_edge_then_idempotent_then_disable_restores(self):
        result = self.enable("--apply")
        self.assertEqual(result.returncode, 0, result.stderr)
        env = self.env_values()
        self.assertEqual(env["TUNNEX_BEAM_PROXY_IMAGE"], PIN)
        self.assertEqual(env["TUNNEX_EDGE_HTTPS_PUBLISH"], "127.0.0.1:8446")
        self.assertEqual(env["TUNNEX_EDGE_PROXY_PROTOCOL_FROM"], "172.31.254.2/32")
        self.assertEqual(env["TUNNEX_BEAM_EDGE_DEFAULT"], "172.31.254.3:443")
        self.assertEqual(env["TUNNEX_BEAM_PROXY_URL"], "https://cp.example.com:8447")
        self.assertEqual(env["COMPOSE_PROFILES"], "bundled-db,beam")
        self.assertEqual((self.install / "local-sharing.yml").read_bytes(), (ROOT / "deploy/beam/compose.yml").read_bytes())
        secrets_dir = self.install / "local-sharing/secrets"
        for name in ("authority.token", "gateway-cert.pem", "gateway-key.pem", "agent-ca.pem", "public-cert.pem", "public-key.pem", "edge.token"):
            self.assertEqual(stat.S_IMODE(os.stat(secrets_dir / name).st_mode), 0o400, name)
        self.assertEqual(stat.S_IMODE(os.stat(secrets_dir).st_mode), 0o700)
        printed = result.stdout + result.stderr
        for secret in ("SHHH", (secrets_dir / "edge.token").read_text().strip(), "PRIVATE KEY"):
            self.assertNotIn(secret, printed)
        self.assertIn("*.share-example.dev", printed)
        up = [c for c in self.calls() if "|" in c and c.split("|", 1)[1].split()[-6:-5] == ["up"] or " up -d " in c]
        self.assertTrue(up and "local-sharing.yml" in up[-1] and up[-1].startswith("bundled-db,beam|"), self.calls())
        issued = len([c for c in self.calls() if "app-proxy-issue" in c])
        before = (self.install / ".env").read_text()
        again = self.enable("--apply")
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual((self.install / ".env").read_text(), before)
        self.assertEqual(len([c for c in self.calls() if "app-proxy-issue" in c]), issued)
        off = self.run_tool("disable", "--apply")
        self.assertEqual(off.returncode, 0, off.stderr)
        self.assertEqual(self.env_values(), dict(l.split("=", 1) for l in self.env.splitlines()))
        self.assertFalse((self.install / "local-sharing.yml").exists())
        self.assertTrue(any("app-proxy-revoke" in c and "11111111-1111-4111-8111-111111111111" in c for c in self.calls()))
        self.assertTrue(any(" rm -s -f beam-proxy " in c + " " for c in self.calls()))
        self.assertFalse((secrets_dir / "authority.token").exists())
        self.assertIn("local-sharing.yml", " ".join(c for c in self.calls() if " rm " in c))
        self.assertNotIn("local-sharing.yml", self.calls()[-1])

    def test_app_access_layout_moves_app_proxy_behind_the_edge(self):
        aa_secrets = self.tmp / "aa-secrets"
        aa_secrets.mkdir(mode=0o700)
        (self.install / "app-access.yml").write_text("# managed\n")
        with open(self.install / ".env", "a") as f:
            f.write("TUNNEX_APP_ACCESS_COMPOSE_SHA256=abc\nTUNNEX_APP_ACCESS_BASE_DOMAIN=cp.example.com\nTUNNEX_APP_PROXY_SECRETS_DIR=%s\n"
                    "TUNNEX_APP_PROXY_BIND_IP=0.0.0.0\nTUNNEX_APP_PROXY_CONSOLE_UPSTREAM_URL=https://caddy:443\nTUNNEX_EDGE_HTTPS_PUBLISH=127.0.0.1:8446\n" % aa_secrets)
        original = self.env_values()
        self.participants([("api", ["tunnex.yml", "app-access.yml"]), ("app-proxy", ["tunnex.yml", "app-access.yml"])])
        result = self.enable("--apply")
        self.assertEqual(result.returncode, 0, result.stderr)
        env = self.env_values()
        self.assertEqual(env["TUNNEX_BEAM_EDGE_DEFAULT"], "app-proxy:8443")
        self.assertEqual((env["TUNNEX_APP_PROXY_BIND_IP"], env["TUNNEX_APP_PROXY_PUBLIC_PORT"]), ("127.0.0.1", "8448"))
        self.assertEqual(env["TUNNEX_APP_PROXY_EDGE_TOKEN_FILE"], "/etc/tunnex/app-proxy/edge.token")
        self.assertEqual((aa_secrets / "edge.token").read_bytes(), (self.install / "local-sharing/secrets/edge.token").read_bytes())
        self.assertTrue(all("app-access.yml" in c for c in self.calls() if " up " in c))
        self.assertEqual(env["TUNNEX_BEAM_EDGE_DEFAULT_TOKEN"], "true")
        off = self.run_tool("disable", "--apply")
        self.assertEqual(off.returncode, 0, off.stderr)
        self.assertEqual(self.env_values(), original)

    def test_refusals_change_nothing(self):
        cases = [
            (["enable", "--domain", "x.cp.example.com"], "not under or above the console"),
            (["enable", "--domain", "other.dev"], "not trusted"),
        ]
        for args, expected in cases:
            result = self.run_tool(*args, "--cert", str(self.pki / "cert.pem"), "--key", str(self.pki / "key.pem"), "--apply") if "other.dev" in args else \
                self.run_tool(*args, "--cert", str(self.pki / "cert.pem"), "--key", str(self.pki / "key.pem"), "--ca-file", str(self.pki / "ca.pem"), "--apply")
            self.assertNotEqual(result.returncode, 0, args)
            self.assertIn("Nothing else was changed", result.stderr)
            self.assertIn(expected, result.stderr)
        bad_port = self.enable("--connector-port", "443", "--apply")
        self.assertIn("--connector-port", bad_port.stderr)
        no_pin = self.run_tool("enable", "--domain", "share-example.dev", "--cert", str(self.pki / "cert.pem"), "--key", str(self.pki / "key.pem"), "--ca-file", str(self.pki / "ca.pem"), "--apply", extra_env={"FAKE_NO_PIN": "1"})
        self.assertIn("no signed Local Sharing proxy", no_pin.stderr)
        with open(self.install / ".env", "a") as f:
            f.write("TUNNEX_TLS_MODE=terminated\n")
        (self.install / ".env").write_text(self.env.replace("TUNNEX_TLS_MODE=direct", "TUNNEX_TLS_MODE=terminated"))
        terminated = self.enable("--apply")
        self.assertIn("--layout dedicated", terminated.stderr)
        self.assertEqual((self.install / ".env").read_text(), self.env.replace("TUNNEX_TLS_MODE=direct", "TUNNEX_TLS_MODE=terminated"))
        self.assertFalse((self.install / "local-sharing.yml").exists())

    def test_unmanaged_app_access_and_drifted_stack_refused(self):
        (self.install / "app-access.yml").unlink(missing_ok=True)
        self.participants([("api", ["tunnex.yml", "app-access-demo.yml"]), ("app-proxy", ["tunnex.yml", "app-access-demo.yml"])])
        result = self.enable("--apply")
        self.assertIn("not in the managed layout", result.stderr)
        self.participants([("api", ["tunnex.yml", "extra.yml"])])
        result = self.enable("--apply")
        self.assertIn("converge it with upgrade.sh", result.stderr)
        self.assertEqual((self.install / ".env").read_text(), self.env)
        self.assertFalse((self.install / "local-sharing.yml").exists())
        self.assertFalse(any(" up " in c or "app-proxy-issue" in c for c in self.calls()))

    def test_failed_start_restores_previous_setup(self):
        (self.fake / "fail-up").write_text("1")
        result = self.enable("--apply")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("the previous setup was restored", result.stderr)
        self.assertEqual((self.install / ".env").read_text(), self.env)
        self.assertFalse((self.install / "local-sharing.yml").exists())
        ups = [c for c in self.calls() if " up " in c]
        self.assertTrue(ups and "local-sharing.yml" not in ups[-1], ups)

    def test_apply_requires_root(self):
        if os.geteuid() == 0:
            self.skipTest("running as root")
        result = self.run_tool("enable", "--domain", "share-example.dev", "--cert", str(self.pki / "cert.pem"), "--key", str(self.pki / "key.pem"), "--ca-file", str(self.pki / "ca.pem"), "--apply")
        self.assertIn("run with sudo", result.stderr)

    def test_status(self):
        result = self.run_tool("status")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("not enabled", result.stdout)


if __name__ == "__main__":
    unittest.main()
