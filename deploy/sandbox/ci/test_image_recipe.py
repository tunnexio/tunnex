"""Exercise offline image assembly with synthetic tools; no image or host action."""

import base64
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "deploy/sandbox/build-image.sh"
SOURCE = "a" * 40
BASE = "approved.local/sandbox-ubuntu@sha256:" + "b" * 64


class UbuntuImageRecipeTests(unittest.TestCase):
    def test_mutable_base_wrong_architecture_and_unowned_tag_are_refused(self):
        for base, arch, tag in (("ubuntu:latest", "amd64", "tunnex-sandbox-test"),
                                (BASE[:-1], "amd64", "tunnex-sandbox-test"),
                                (BASE, "mips", "tunnex-sandbox-test"),
                                (BASE, "arm64", "unrelated-user-image")):
            with self.subTest(base=base, arch=arch, tag=tag):
                result = subprocess.run(["/bin/sh", str(SCRIPT), base, arch, tag],
                                        env={"PATH": "/nonexistent-fixture-tools"},
                                        capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)

    def fixture(self, temporary, *, dirty=False):
        root = Path(temporary)
        tools = root / "tools"
        tools.mkdir()
        scratch = root / "scratch"
        scratch.mkdir()
        assets = {name: (ROOT / name).read_text() for name in (
            "deploy/sandbox/Containerfile", "deploy/sandbox/sandbox-entrypoint.py")}
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as output:
            member = tarfile.TarInfo("apps/cli/go.mod")
            content = b"module public-fixture\n"
            member.size = len(content)
            output.addfile(member, io.BytesIO(content))
        scripts = {
            "git": f"""import base64, json, sys
args=sys.argv[1:]
if args[:1]==['-C']: args=args[2:]
if args[:1]==['diff']: sys.exit({int(dirty)})
if args==['rev-parse','HEAD']: print({SOURCE!r})
elif args[:1]==['show']: sys.stdout.write({assets!r}[args[1].split(':',1)[1]])
elif args[:1]==['archive']: sys.stdout.buffer.write(base64.b64decode({base64.b64encode(archive.getvalue()).decode()!r}))
else: sys.exit(1)
""",
            "go": """import json, os, pathlib, sys
args=sys.argv[1:]
assert args[0]=='build' and args[-1]=='./cmd/tunnex-sandbox-bootstrap'
assert os.environ['GOFLAGS']=='-mod=readonly'
assert os.environ['GOOS']=='linux' and os.environ['CGO_ENABLED']=='0'
pathlib.Path(args[args.index('-o')+1]).write_bytes(b'public compiled fixture')
""",
            "podman": """import hashlib, json, pathlib, sys
args=sys.argv[1:]
assert args[0]=='build'
context=pathlib.Path(args[-1])
files={str(p.relative_to(context)):hashlib.sha256(p.read_bytes()).hexdigest() for p in context.rglob('*') if p.is_file()}
print(json.dumps({'args':args[:-1], 'context_files':files}))
""",
        }
        for name, source in scripts.items():
            path = tools / name
            path.write_text(f"#!{sys.executable}\n" + source)
            path.chmod(0o755)
        return {**os.environ, "PATH": str(tools) + os.pathsep + os.defpath, "TMPDIR": str(scratch)}

    def test_offline_assembly_uses_exact_source_and_minimal_context_for_both_architectures(self):
        for arch in ("amd64", "arm64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as temporary:
                environment = self.fixture(temporary)
                result = subprocess.run(["/bin/sh", str(SCRIPT), BASE, arch, "tunnex-sandbox-fixture"],
                                        env=environment, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                receipt = json.loads(result.stdout)
                self.assertIn("--pull=never", receipt["args"])
                self.assertIn("--network=none", receipt["args"])
                self.assertIn(f"--platform=linux/{arch}", receipt["args"])
                self.assertIn(f"SOURCE_SHA={SOURCE}", receipt["args"])
                self.assertIn(f"BASE_IMAGE={BASE}", receipt["args"])
                self.assertEqual(set(receipt["context_files"]), {
                    "Containerfile", "sandbox-entrypoint.py", "runtime/tunnex-sandbox-bootstrap"})
                self.assertEqual(list((Path(temporary) / "scratch").iterdir()), [])

    def test_dirty_source_stops_before_compilation_and_image_assembly(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run(["/bin/sh", str(SCRIPT), BASE, "amd64", "tunnex-sandbox-fixture"],
                                    env=self.fixture(temporary, dirty=True), capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")
            self.assertEqual(list((Path(temporary) / "scratch").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
