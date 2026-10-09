"""Isolated safety checks for the opt-in local fixture preparer.

These tests never invoke Docker or read/write the repository's real .env.
"""

import contextlib
import importlib.util
import io
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("local_ui_prepare", Path(__file__).with_name("prepare.py"))
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)


class PrepareSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.env = self.root / ".env"
        self.root_patch = patch.object(prepare, "ROOT", self.root)
        self.env_patch = patch.object(prepare, "ENV", self.env)
        self.root_patch.start()
        self.env_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.addCleanup(self.env_patch.stop)

    def write_env(self, text):
        self.env.write_text(text)
        self.env.chmod(0o640)

    def run_prepare(self, *, docker_code=0, docker_output="", tokens=None):
        output = io.StringIO()
        result = SimpleNamespace(returncode=docker_code, stdout=docker_output, stderr="private-docker-error")
        with patch.object(prepare.subprocess, "run", return_value=result) as docker, \
                patch.object(prepare.secrets, "token_hex", side_effect=tokens or ["new-admin-secret", "new-encryption-secret", "new-provider-secret"]) as secrets, \
                contextlib.redirect_stdout(output):
            prepare.main()
        return output.getvalue(), docker, secrets

    def assert_refused_unchanged(self, text, message, *, docker_code=0, docker_output=""):
        self.write_env(text)
        before = self.env.read_bytes()
        before_mode = stat.S_IMODE(self.env.stat().st_mode)
        output = io.StringIO()
        result = SimpleNamespace(returncode=docker_code, stdout=docker_output, stderr="private-docker-error")
        with patch.object(prepare.subprocess, "run", return_value=result) as docker, \
                patch.object(prepare.secrets, "token_hex") as secrets, \
                contextlib.redirect_stdout(output), \
                self.assertRaisesRegex(SystemExit, message) as failure:
            prepare.main()
        self.assertEqual(self.env.read_bytes(), before)
        self.assertEqual(stat.S_IMODE(self.env.stat().st_mode), before_mode)
        self.assertEqual(list(self.root.iterdir()), [self.env])
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn("preserved-admin-secret", str(failure.exception))
        self.assertNotIn("private-docker-error", str(failure.exception))
        secrets.assert_not_called()
        return docker

    def test_generated_credentials_are_private_and_unrelated_settings_remain(self):
        self.write_env("# Existing local settings\nCOMPOSE_PROFILES=existing-profile\nUNRELATED_SETTING=preserve-me\nTUNNEX_DEV_AI_ENGINE_IMAGE=pinned-engine:local\n")
        output, docker, secrets = self.run_prepare()
        text = self.env.read_text()
        self.assertEqual(stat.S_IMODE(self.env.stat().st_mode), 0o600)
        self.assertIn("COMPOSE_PROFILES=existing-profile\n", text)
        self.assertIn("UNRELATED_SETTING=preserve-me\n", text)
        self.assertIn("TUNNEX_DEV_AI_ENGINE_IMAGE=pinned-engine:local\n", text)
        self.assertIn("TUNNEX_AI_GATEWAY_URL=http://bifrost:8080\n", text)
        self.assertIn("TUNNEX_AI_GATEWAY_ADMIN_PASSWORD=new-admin-secret\n", text)
        self.assertIn("TUNNEX_DEV_AI_FIXTURE_ENCRYPTION_KEY=new-encryption-secret\n", text)
        self.assertIn("TUNNEX_DEV_AI_FIXTURE_PROVIDER_KEY=new-provider-secret\n", text)
        self.assertNotIn("new-admin-secret", output)
        self.assertNotIn("new-encryption-secret", output)
        self.assertNotIn("new-provider-secret", output)
        self.assertIn("credentials remain in private .env", output)
        docker.assert_called_once_with(
            ["docker", "volume", "ls", "--filter", "label=com.docker.compose.volume=ai_ui_fixture_config", "--format", "{{.Name}}"],
            capture_output=True, text=True,
        )
        self.assertEqual(secrets.call_count, 3)

    def test_existing_credentials_and_literal_quoting_are_idempotently_preserved(self):
        original = (
            "COMPOSE_PROFILES=existing-profile\nUNRELATED_SETTING=preserve-me\n"
            "TUNNEX_AI_GATEWAY_URL=http://bifrost:8080\n"
            "TUNNEX_AI_GATEWAY_ADMIN_USER='preserved-admin'\n"
            "TUNNEX_AI_GATEWAY_ADMIN_PASSWORD='preserved-admin-secret'\n"
            "TUNNEX_DEV_AI_FIXTURE_ENCRYPTION_KEY=preserved-encryption-secret\n"
            "TUNNEX_DEV_AI_FIXTURE_PROVIDER_KEY=preserved-provider-secret\n"
        )
        self.write_env(original)
        output, docker, secrets = self.run_prepare()
        prepared = self.env.read_bytes()
        self.assertIn(original, prepared.decode())
        self.assertEqual(stat.S_IMODE(self.env.stat().st_mode), 0o600)
        docker.assert_not_called()
        secrets.assert_not_called()
        for private in ("preserved-admin-secret", "preserved-encryption-secret", "preserved-provider-secret"):
            self.assertNotIn(private, output)
        second_output, second_docker, second_secrets = self.run_prepare()
        self.assertEqual(self.env.read_bytes(), prepared)
        second_docker.assert_not_called()
        second_secrets.assert_not_called()
        self.assertNotIn("preserved-admin-secret", second_output)

    def test_foreign_gateway_is_refused_without_changes(self):
        docker = self.assert_refused_unchanged(
            "TUNNEX_AI_GATEWAY_URL=https://existing.example\nUNRELATED_SETTING=preserve-me\n",
            "An existing AI Gateway is configured",
        )
        docker.assert_not_called()

    def test_incomplete_admin_credentials_are_refused_without_changes(self):
        for credentials in ("TUNNEX_AI_GATEWAY_ADMIN_USER=preserved-admin\n", "TUNNEX_AI_GATEWAY_ADMIN_PASSWORD=preserved-admin-secret\n"):
            with self.subTest(credentials=credentials.split("=", 1)[0]):
                docker = self.assert_refused_unchanged(credentials, "existing AI admin credential is incomplete")
                docker.assert_not_called()

    def test_failed_docker_read_refuses_to_generate_credentials(self):
        self.assert_refused_unchanged("UNRELATED_SETTING=preserve-me\n", "Could not check existing local AI state", docker_code=1)

    def test_any_compose_config_volume_refuses_missing_secrets(self):
        cases = (
            "UNRELATED_SETTING=preserve-me\n",
            "TUNNEX_AI_GATEWAY_ADMIN_USER=preserved-admin\nTUNNEX_AI_GATEWAY_ADMIN_PASSWORD=preserved-admin-secret\nTUNNEX_DEV_AI_FIXTURE_PROVIDER_KEY=preserved-provider-secret\n",
            "TUNNEX_AI_GATEWAY_ADMIN_USER=preserved-admin\nTUNNEX_AI_GATEWAY_ADMIN_PASSWORD=preserved-admin-secret\nTUNNEX_DEV_AI_FIXTURE_ENCRYPTION_KEY=preserved-encryption-secret\n",
        )
        for index, text in enumerate(cases):
            with self.subTest(missing_secret=index):
                docker = self.assert_refused_unchanged(
                    text, "Local AI state already exists but matching credentials are missing",
                    docker_output="another_compose_project_ai_ui_fixture_config\n",
                )
                docker.assert_called_once()


if __name__ == "__main__":
    unittest.main()
