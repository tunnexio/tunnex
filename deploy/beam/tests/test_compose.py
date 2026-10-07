"""Qualify real Compose rendering and reject unsafe opt-in configurations."""
import copy
import json
import os
from pathlib import Path
import runpy
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[3]
VERIFY = runpy.run_path(str(ROOT / "deploy/beam/verify-config.py"))["verify"]


class BeamCompose(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        env = os.environ.copy()
        env.update(
            DATABASE_URL="postgres://fixture:fixture@postgres/fixture",
            REDIS_URL="redis://redis:6379/0",
            APP_BASE_URL="https://console.fixture.org",
            TUNNEX_BEAM_BASE_DOMAIN="beam.fixture.net",
            TUNNEX_BEAM_PROXY_URL="https://connector.fixture.net",
            TUNNEX_BEAM_PROXY_IMAGE="fixture.invalid/beam@sha256:" + "a" * 64,
            TUNNEX_BEAM_PROXY_SECRETS_DIR="/private/beam-fixture",
            TUNNEX_BEAM_PUBLIC_BIND_IP="127.0.0.1",
            TUNNEX_BEAM_CONNECTOR_BIND_IP="127.0.0.2",
        )
        env.pop("TUNNEX_BEAM_DOMAIN_READY", None)
        cli = ["sh", str(ROOT / "tests/beam-local/docker-local.sh"), "compose", "-f", str(ROOT / "docker-compose.yml")]
        cls.base = json.loads(subprocess.check_output(cli + ["config", "--format", "json"], cwd=ROOT, env=env))
        cls.beam = json.loads(subprocess.check_output(cli + ["-f", str(ROOT / "deploy/beam/compose.yml"), "--profile", "beam", "config", "--format", "json"], cwd=ROOT, env=env))

    def test_default_stack_does_not_enable_beam(self):
        self.assertNotIn("beam-proxy", self.base["services"])
        self.assertNotIn("TUNNEX_BEAM_BASE_DOMAIN", self.base["services"]["api"]["environment"])

    def test_rendered_opt_in_is_confined_and_unasserted(self):
        VERIFY(self.beam)
        self.assertEqual(self.beam["services"]["api"]["environment"]["TUNNEX_BEAM_DOMAIN_READY"], "false")

    def test_duplicate_external_port_binding_rejected(self):
        config = copy.deepcopy(self.beam)
        ports = config["services"]["beam-proxy"]["ports"]
        ports[1]["host_ip"] = ports[0]["host_ip"]
        with self.assertRaises(ValueError):
            VERIFY(config)

    def test_operator_or_authority_exposure_rejected(self):
        for name, port in (("beam-proxy", 9093), ("api", 8445)):
            config = copy.deepcopy(self.beam)
            config["services"][name].setdefault("ports", []).append({"target": port, "published": str(port), "host_ip": "127.0.0.1"})
            with self.assertRaises(ValueError):
                VERIFY(config)

    def test_mutable_image_and_writable_serving_mounts_rejected(self):
        config = copy.deepcopy(self.beam)
        config["services"]["beam-proxy"]["image"] = "fixture.invalid/beam:latest"
        with self.assertRaises(ValueError):
            VERIFY(config)
        for name in ("api", "beam-proxy"):
            config = copy.deepcopy(self.beam)
            for mount in config["services"][name]["volumes"]:
                if mount["target"] == "/var/lib/tunnex/app-restore":
                    mount["read_only"] = False
            with self.assertRaises(ValueError):
                VERIFY(config)

    def test_configuration_failure_never_echoes_credentials(self):
        config = copy.deepcopy(self.beam)
        config["services"]["beam-proxy"]["image"] = "fixture-secret-marker"
        process = subprocess.run(["python3", str(ROOT / "deploy/beam/verify-config.py")], input=json.dumps(config), text=True, capture_output=True)
        self.assertNotEqual(process.returncode, 0)
        self.assertNotIn("fixture-secret-marker", process.stdout + process.stderr)
        self.assertNotIn("postgres://", process.stdout + process.stderr)


if __name__ == "__main__":
    unittest.main()
