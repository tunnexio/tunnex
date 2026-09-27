import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name("build-overlay.py")
spec = importlib.util.spec_from_file_location("overlay", SCRIPT)
overlay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(overlay)
BASE = "registry.example:5000/team/node:v1@sha256:" + "a" * 64


class OverlayTests(unittest.TestCase):
    def test_rejects_unpinned_or_injected_bases(self):
        for base in ["alpine:latest", "sha256:" + "a" * 64, BASE + "\nRUN echo unsafe", BASE + " ", BASE[:-1], BASE.replace("sha256:", "sha512:")]:
            with self.subTest(base=base), self.assertRaises(ValueError):
                overlay.dockerfile("api", base)

    def test_preserves_base_metadata_and_copies_only_component_binaries(self):
        for component, names in overlay.BINARIES.items():
            lines = overlay.dockerfile(component, BASE).splitlines()
            self.assertEqual(lines, [f"FROM {BASE}", *[f"COPY --chmod=755 {name} /usr/local/bin/{name}" for name in names]])

    def test_build_uses_literal_digest_and_no_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "tunnex-api").write_bytes(b"test")
            with patch.object(sys, "argv", [str(SCRIPT), "api", "--base-image", BASE, "--tag", "overlay:test", "--context", directory]), patch.object(overlay.subprocess, "run") as run:
                overlay.main()
                run.assert_called_once_with(["docker", "build", "--pull", "--file", "-", "--tag", "overlay:test", str(Path(directory).resolve())], input=overlay.dockerfile("api", BASE), text=True, check=True)

    def test_invalid_base_fails_before_invoking_docker(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "api", "--base-image", "alpine:latest", "--tag", "test", "--context", "/nonexistent"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("@sha256", result.stderr)


if __name__ == "__main__":
    unittest.main()
