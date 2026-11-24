"""AA-EN-1 adopt: the demo's hand-written layout becomes the managed one.

Container inspection is faked (labels, mounts and port bindings only); the
Compose rendering is the real `docker compose config` CLI, which needs no
daemon and starts nothing. Skipped where the Docker CLI is unavailable.
"""
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
TOOL = ROOT / "deploy/app-access/tunnex-app-access.py"
UPGRADE = ROOT / "deploy/upgrade.sh"
REAL_DOCKER = shutil.which("docker")
IMAGE = "ghcr.io/tunnexio/tunnex-app-proxy@sha256:" + "f" * 64

FAKE_DOCKER = r'''#!/usr/bin/env python3
import json, os, sys
d = os.environ["FAKE_DIR"]
args = sys.argv[1:]
with open(os.path.join(d, "calls"), "a") as log:
    log.write(" ".join(args) + "\n")
if args[0] == "compose":
    os.execv(os.environ["REAL_DOCKER"], [os.environ["REAL_DOCKER"], *args])
if args[0] == "ps":
    print("\n".join(json.load(open(os.path.join(d, "containers.json")))))
elif args[0] == "inspect" and "Config.Labels" in args[2]:
    c = json.load(open(os.path.join(d, "containers.json")))[args[-1]]
    print("%s|%s|%s" % (json.dumps(c["labels"]), json.dumps(c["mounts"]), json.dumps(c["ports"])))
elif args[0] == "inspect":
    states = open(os.path.join(d, "health")).read().split("\n")
    print(states.pop(0) if len(states) > 1 else states[0])
    open(os.path.join(d, "health"), "w").write("\n".join(states) if len(states) > 1 else states[0])
elif args[0] == "restart":
    pass
else:
    sys.exit("unexpected docker call: %s" % args)
'''

RENDER_ENV = """APP_BASE_URL=https://cp.tunnex.app
DATABASE_URL=postgres://fixture
POSTGRES_PASSWORD=fixture
TUNNEX_AI_CUSTOM_ENDPOINTS_FILE=/fixture
TUNNEX_AI_CUSTOM_PROXY_PASSWORD=fixture
TUNNEX_AI_CUSTOM_PROXY_URL=http://fixture
TUNNEX_AI_CUSTOM_PROXY_USERNAME=fixture
TUNNEX_AI_ENGINE_ENCRYPTION_KEY=fixture
TUNNEX_AI_ENGINE_IMAGE=fixture@sha256:aa
TUNNEX_AI_GATEWAY_ADMIN_PASSWORD=fixture
TUNNEX_AI_GATEWAY_ADMIN_USER=fixture
TUNNEX_EDGE_LISTEN=https://cp.tunnex.app
TUNNEX_NODE_ENDPOINT=203.0.113.10:51820
COMPOSE_PROFILES=bundled-db,app-access
TUNNEX_APP_ACCESS_BASE_DOMAIN=cp.tunnex.app
TUNNEX_APP_PROXY_IMAGE=%s
""" % IMAGE

DEMO_OVERLAY = """services:
  caddy:
    ports: !override
      - "80:80"
  app-proxy:
    ports: !override
      - "0.0.0.0:443:8443"
      - "10.70.0.2:8444:8444"
    environment:
      TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_URL: https://caddy:443
      TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_SERVER_NAME: cp.tunnex.app
"""


def old_overlay():
    """The demo's app-access.yml: a copy of the overlay before AA-EN-1."""
    lines = (ROOT / "deploy/app-access/compose.yml").read_text().splitlines()
    return "\n".join(l for l in lines if "TUNNEX_APP_PROXY_GATEWAY" not in l and "TUNNEX_APP_ACCESS_LOCKED" not in l) + "\n"


@unittest.skipUnless(REAL_DOCKER, "the Docker CLI renders Compose files")
class Adopt(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.dir = self.tmp / "tunnex"
        self.fake = self.tmp / "fake"
        self.bin = self.tmp / "bin"
        self.secrets = self.tmp / "appaccess-secrets"
        for d in (self.dir, self.fake, self.bin, self.secrets):
            d.mkdir()
        (self.bin / "docker").write_text(FAKE_DOCKER)
        (self.bin / "docker").chmod(0o755)
        shutil.copy(ROOT / "deploy/tunnex.yml", self.dir / "tunnex.yml")
        (self.dir / "app-access.yml").write_text(old_overlay())
        (self.dir / "app-access-demo.yml").write_text(DEMO_OVERLAY)
        (self.dir / ".env").write_text(RENDER_ENV + "TUNNEX_APP_PROXY_SECRETS_DIR=%s\n" % self.secrets)
        self.files = ",".join(str(self.dir / f) for f in ("tunnex.yml", "app-access.yml", "app-access-demo.yml"))
        self.containers({"8443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "443"}], "8444/tcp": [{"HostIp": "10.70.0.2", "HostPort": "8444"}]})

    def containers(self, ports, marker="tunnex_app_restore", secrets=None, files=None):
        files = files or self.files
        def c(service, mounts, p):
            return {"labels": {"com.docker.compose.project": "tunnex", "com.docker.compose.service": service,
                               "com.docker.compose.project.config_files": files,
                               "com.docker.compose.project.working_dir": str(self.dir), "com.docker.compose.oneoff": "False"},
                    "mounts": mounts, "ports": p}
        restore = {"Type": "volume", "Name": marker, "Destination": "/var/lib/tunnex/app-restore"}
        sec = {"Type": "bind", "Source": str(secrets or self.secrets), "Destination": "/etc/tunnex/app-proxy"}
        helper = c("api", [restore], {})
        helper["labels"]["com.docker.compose.oneoff"] = "True"
        (self.fake / "containers.json").write_text(json.dumps({
            "api1": c("api", [restore], {"8443/tcp": [{"HostIp": "", "HostPort": "8443"}]}),
            "proxy1": c("app-proxy", [restore, sec], ports),
            "caddy1": c("caddy", [], {}),
            "oneoff1": helper,
        }))

    def run_tool(self, *args):
        env = dict(os.environ, PATH="%s:%s" % (self.bin, os.environ["PATH"]), FAKE_DIR=str(self.fake), REAL_DOCKER=REAL_DOCKER)
        return subprocess.run([sys.executable, "-B", str(TOOL), "--directory", str(self.dir), "adopt", *args],
                              capture_output=True, text=True, env=env)

    def snapshot(self):
        return {p.name: p.read_bytes() for p in self.dir.iterdir() if p.is_file()}

    def calls(self):
        path = self.fake / "calls"
        return path.read_text() if path.exists() else ""

    def env(self):
        return dict(l.split("=", 1) for l in (self.dir / ".env").read_text().splitlines() if "=" in l)

    def test_dry_run_plans_and_changes_nothing(self):
        before = self.snapshot()
        r = self.run_tool()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("dry run", r.stdout)
        self.assertIn("TUNNEX_EDGE_HTTPS_PUBLISH", r.stdout)
        self.assertIn("terminate-and-forward", r.stdout)
        self.assertEqual(before, self.snapshot())
        self.assertNotRegex(self.calls(), r"(^| )(up|stop|start|restart|rm|create)( |$)")

    def test_apply_writes_managed_layout_records_hashes_and_is_idempotent(self):
        demo_before = (self.dir / "app-access-demo.yml").read_bytes()
        r = self.run_tool("--apply")
        self.assertEqual(r.returncode, 0, r.stderr)
        env = self.env()
        managed = ROOT / "deploy/app-access/compose.yml"
        self.assertEqual((self.dir / "app-access.yml").read_bytes(), managed.read_bytes())
        self.assertEqual(stat.S_IMODE((self.dir / "app-access.yml").stat().st_mode), 0o644)
        import hashlib
        sha = lambda p: hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
        self.assertEqual(env["TUNNEX_APP_ACCESS_COMPOSE_SHA256"], sha(managed))
        self.assertEqual(env["TUNNEX_APP_ACCESS_ADOPTED_CONFIG_FILES"], self.files)
        self.assertEqual(env["TUNNEX_APP_ACCESS_ADOPTED_OVERLAYS_SHA256"], sha(self.dir / "app-access-demo.yml"))
        for key, value in {"TUNNEX_APP_PROXY_BIND_IP": "0.0.0.0", "TUNNEX_APP_PROXY_PUBLIC_PORT": "443",
                           "TUNNEX_APP_PROXY_GATEWAY_BIND_IP": "10.70.0.2", "TUNNEX_APP_PROXY_GATEWAY_PORT": "8444",
                           "TUNNEX_APP_PROXY_GATEWAY_HOST": "10.70.0.2",
                           "TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_URL": "https://caddy:443",
                           "TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_SERVER_NAME": "cp.tunnex.app",
                           "TUNNEX_EDGE_HTTPS_PUBLISH": "127.0.0.1:8446", "COMPOSE_PROFILES": "bundled-db,app-access",
                           "TUNNEX_APP_PROXY_SECRETS_DIR": str(self.secrets), "TUNNEX_APP_PROXY_IMAGE": IMAGE}.items():
            self.assertEqual(env.get(key), value, key)
        self.assertEqual((self.dir / "app-access-demo.yml").read_bytes(), demo_before)
        backups = list(self.dir.glob("app-access-adopt-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(stat.S_IMODE(backups[0].stat().st_mode), 0o700)
        self.assertIn("cp %s" % (backups[0] / ".env"), (backups[0] / "ROLLBACK.txt").read_text())
        self.assertEqual((backups[0] / "app-access.yml").read_text(), old_overlay())
        self.assertNotRegex(self.calls(), r"(^| )(up|stop|start|restart|rm|create)( |$)")
        # The managed files render the same live proxy: same ports, console
        # forwarding and secrets, with only the new endpoint keys added.
        render = lambda files: json.loads(subprocess.run([REAL_DOCKER, "compose", "--project-name", "tunnex", "--project-directory", str(self.dir), "--env-file", str(self.dir / ".env"), *sum((["-f", str(f)] for f in files), []), "config", "--format", "json"], capture_output=True, text=True, check=True, env=dict(os.environ, COMPOSE_PROFILES="bundled-db,app-access")).stdout)
        managed_render = render([self.dir / "tunnex.yml", self.dir / "app-access.yml"])
        proxy = managed_render["services"]["app-proxy"]
        self.assertEqual(sorted((p.get("host_ip"), p["published"], p["target"]) for p in proxy["ports"]),
                         [("0.0.0.0", "443", 8443), ("10.70.0.2", "8444", 8444)])
        self.assertEqual(proxy["environment"]["TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_URL"], "https://caddy:443")
        self.assertEqual(proxy["environment"]["TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_SERVER_NAME"], "cp.tunnex.app")
        self.assertEqual(managed_render["services"]["api"]["environment"]["TUNNEX_APP_PROXY_GATEWAY_HOST"], "10.70.0.2")
        # Running again changes nothing.
        before = self.snapshot()
        r = self.run_tool("--apply")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("already adopted", r.stdout)
        self.assertEqual(before, self.snapshot())
        # And the upgrade's admission predicate accepts exactly this record.
        self.assertEqual(self.upgrade_admits(), 0)
        (self.dir / "app-access-demo.yml").write_text(DEMO_OVERLAY + "# edited\n")
        self.assertNotEqual(self.upgrade_admits(), 0)

    def upgrade_admits(self):
        script = UPGRADE.read_text()
        start = script.index("aa_adopted_composition() {")
        body = script[start:script.index("\n}\n", start) + 3]
        helpers = textwrap.dedent('''
            ENV_FILE=%s
            dotenv_value() { sed -n "s/^${1}=//p" "$ENV_FILE" | head -1; }
            file_sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
            AA_OVERLAY=%s/app-access.yml
            AA_CONFIG_FILES=%s
        ''' % (self.dir / ".env", self.dir, self.files))
        return subprocess.run(["sh", "-c", helpers + body + 'aa_adopted_composition "%s"' % self.dir]).returncode

    def test_unknown_drift_in_hand_written_overlay_is_refused(self):
        for extra, expected in [
            ("  api:\n    environment:\n      TUNNEX_SOMETHING: x\n", "api.environment.TUNNEX_SOMETHING"),
            ("  caddy-extra:\n    image: alpine\n", "caddy-extra"),
            ("", "app-proxy.read_only"),
            ("  node-agent:\n    environment:\n      TUNNEX_APP_PROXY_URL: https://elsewhere:8444\n", "node-agent.environment.TUNNEX_APP_PROXY_URL"),
        ]:
            with self.subTest(expected=expected):
                text = DEMO_OVERLAY.replace("services:\n", "services:\n" + extra, 1)
                if expected == "app-proxy.read_only":
                    text = DEMO_OVERLAY + "    read_only: false\n"
                (self.dir / "app-access-demo.yml").write_text(text)
                before = self.snapshot()
                r = self.run_tool("--apply")
                self.assertEqual(r.returncode, 13, r.stdout)
                self.assertIn(expected, r.stderr)
                self.assertIn("Nothing was changed", r.stderr)
                self.assertEqual(before, self.snapshot())

    def test_console_must_stay_reachable(self):
        (self.dir / "app-access-demo.yml").write_text(DEMO_OVERLAY.split("    environment:")[0])
        r = self.run_tool("--apply")
        self.assertEqual(r.returncode, 13)
        self.assertIn("console would be unreachable", r.stderr)

    def test_identity_drift_is_refused(self):
        cases = [
            (dict(ports={"8443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "443"}], "9000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "9000"}]}), "unexpected ports"),
            (dict(ports={"8443/tcp": [{"HostIp": "", "HostPort": "443"}]}), "explicit address"),
            (dict(ports={"8443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "443"}]}, marker="other_app_restore"), "restore barrier"),
            (dict(ports={"8443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "443"}]}, secrets="/elsewhere"), "TUNNEX_APP_PROXY_SECRETS_DIR"),
            (dict(ports={"8443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "443"}]}, files=self.files.replace("app-access.yml,", "other.yml,")), "unknown composition"),
        ]
        for kwargs, expected in cases:
            with self.subTest(expected=expected):
                self.containers(**kwargs)
                before = self.snapshot()
                r = self.run_tool("--apply")
                self.assertEqual(r.returncode, 13, r.stdout)
                self.assertIn(expected, r.stderr)
                self.assertEqual(before, self.snapshot())

    def test_unpublished_gateway_listener_stays_on_loopback(self):
        (self.dir / "app-access-demo.yml").write_text(DEMO_OVERLAY.replace('      - "10.70.0.2:8444:8444"\n', ""))
        self.containers({"8443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "443"}]})
        r = self.run_tool("--apply")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.env()["TUNNEX_APP_PROXY_GATEWAY_BIND_IP"], "127.0.0.1")
        self.assertIn("stays on loopback", r.stdout)

    def test_already_managed_is_a_no_op(self):
        r = self.run_tool("--apply")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.containers({"8443/tcp": [{"HostIp": "0.0.0.0", "HostPort": "443"}], "8444/tcp": [{"HostIp": "10.70.0.2", "HostPort": "8444"}]},
                        files="%s,%s" % (self.dir / "tunnex.yml", self.dir / "app-access.yml"))
        before = self.snapshot()
        r = self.run_tool("--apply")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("already runs from the managed composition", r.stdout)
        self.assertEqual(before, self.snapshot())


if __name__ == "__main__":
    unittest.main()
