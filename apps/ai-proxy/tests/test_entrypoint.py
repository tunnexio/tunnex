import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlparse, unquote


MODULE_PATH = Path(__file__).resolve().parents[1] / "entrypoint.py"
SPEC = importlib.util.spec_from_file_location("ai_proxy_entrypoint", MODULE_PATH)
entrypoint = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(entrypoint)


class SecretBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.values = {
            "master": "sk-" + "a" * 40,
            "salt": "b" * 48,
            "database": "c:@/%?" + "d" * 40,
        }
        self.paths = {}
        for name, value in self.values.items():
            path = Path(self.directory.name) / name
            path.write_text(value + "\n")
            self.paths[name] = str(path)

    def test_separate_secrets_and_encoded_database_password(self):
        env = entrypoint.runtime_environment(self.paths)
        self.assertEqual(env["LITELLM_MASTER_KEY"], self.values["master"])
        self.assertEqual(env["LITELLM_SALT_KEY"], self.values["salt"])
        dsn = urlparse(env["DATABASE_URL"])
        self.assertEqual(dsn.hostname, "ai-proxy-postgres")
        self.assertEqual(unquote(dsn.password), self.values["database"])
        self.assertEqual(dsn.path, "/litellm")

    def test_reusing_any_secret_is_refused(self):
        for name in ("salt", "database"):
            with self.subTest(name=name):
                Path(self.paths[name]).write_text(self.values["master"])
                with self.assertRaises(ValueError):
                    entrypoint.runtime_environment(self.paths)
                Path(self.paths[name]).write_text(self.values[name])

    def test_invalid_secret_input_is_refused(self):
        for value in ("", "short", "x" * 4097, "x" * 40 + "\nembedded", "x" * 40 + " ", "é" * 40):
            with self.subTest(value_length=len(value)):
                Path(self.paths["salt"]).write_text(value)
                with self.assertRaises(ValueError):
                    entrypoint.runtime_environment(self.paths)

    def test_read_failure_never_prints_secret_or_path(self):
        error = OSError("private/path: " + self.values["master"])
        output = io.StringIO()
        with patch.object(entrypoint.sys, "argv", ["entrypoint.py"]), \
             patch.object(entrypoint, "runtime_environment", side_effect=error), \
             contextlib.redirect_stderr(output):
            self.assertEqual(entrypoint.main(), 2)
        self.assertNotIn(self.values["master"], output.getvalue())
        self.assertNotIn("private/path", output.getvalue())

    def test_unapproved_cli_override_is_refused_before_secret_read(self):
        with patch.object(entrypoint.sys, "argv", ["entrypoint.py", "--debug"]), \
             patch.object(entrypoint, "runtime_environment") as read, \
             contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(entrypoint.main(), 2)
        read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
