"""Producer wiring fixtures; no actual engine, network, enrollment or provider."""

import hashlib
import io
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import tarfile
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location("sandbox_ci_image", Path(__file__).with_name("image.py"))
image = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(image)
SOURCE = "a" * 40
BASE = "sha256:" + "b" * 64
LOCK = (json.dumps({"base_images": {"amd64": "docker.io/library/ubuntu@" + BASE}}) + "\n").encode()


class ImageWiringTests(unittest.TestCase):
    def test_actual_producer_descriptor_and_archive_format_are_verified_without_an_engine(self):
        lock = (image.PRODUCER / "ubuntu26-amd64.lock.json").read_bytes()
        base = json.loads(lock)["base_images"]["amd64"].split("@", 1)[1]
        lock_pin = hashlib.sha256(lock).hexdigest()
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode="w"):
            pass
        layer_raw = layer.getvalue()
        config = json.dumps({"architecture": "amd64", "os": "linux", "config": {
            "User": "1001:1001", "WorkingDir": "/workspace", "Labels": {
                "io.tunnex.sandbox.source": SOURCE, "io.tunnex.sandbox.ubuntu-lock": lock_pin,
            }}, "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(layer_raw).hexdigest()]}}).encode()
        config_pin = hashlib.sha256(config).hexdigest()
        config_name = config_pin + ".json"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            name = "tunnex-sandbox-ubuntu26-linux-amd64.docker.tar"
            with tarfile.open(root / name, "w") as archive:
                for filename, raw in (("manifest.json", json.dumps([{"Config": config_name, "Layers": ["layer.tar"]}]).encode()),
                                      (config_name, config), ("layer.tar", layer_raw)):
                    member = tarfile.TarInfo(filename)
                    member.size = len(raw)
                    archive.addfile(member, io.BytesIO(raw))
            archive_raw = (root / name).read_bytes()
            descriptor = {"schema_version": 1, "source_sha": SOURCE, "os": "linux", "architecture": "amd64",
                          "dependency_lock_sha256": lock_pin, "base_manifest_digest": base,
                          "archive": {"filename": name, "sha256": hashlib.sha256(archive_raw).hexdigest(), "bytes": len(archive_raw)},
                          "config_digest": "sha256:" + config_pin, "unpacked_image_bytes": len(layer_raw),
                          "native_qualification": False, "services_started": False, "packages_installed_at_launch": False}

            def write_descriptor():
                (root / "workload-image.json").write_text(json.dumps(descriptor) + "\n")
                (root / "SHA256SUMS").write_text("".join(hashlib.sha256((root / filename).read_bytes()).hexdigest()
                                                       + "  " + filename + "\n" for filename in (name, "workload-image.json")))

            write_descriptor()
            with patch.object(image, "run", return_value=lock):
                self.assertEqual(image.verify(root, SOURCE), descriptor)
                descriptor["native_qualification"] = True
                write_descriptor()
                with self.assertRaises(ValueError):
                    image.verify(root, SOURCE)
                descriptor["native_qualification"] = False
                descriptor["unpacked_image_bytes"] += 1
                write_descriptor()
                with self.assertRaises(ValueError):
                    image.verify(root, SOURCE)

    def test_verification_supplies_committed_source_arch_and_lock_to_the_actual_contract(self):
        producer = Mock()
        producer.verify_delivery.return_value = {"base_manifest_digest": BASE, "native_qualification": False}
        with patch.object(image, "run", return_value=LOCK) as run, patch.object(image, "load_producer", return_value=producer):
            result = image.verify(Path("/public/delivery"), SOURCE)
        run.assert_called_once_with(["git", "show", SOURCE + ":" + image.LOCK_SOURCE])
        producer.verify_delivery.assert_called_once_with(Path("/public/delivery"), SOURCE, "amd64", hashlib.sha256(LOCK).hexdigest())
        self.assertFalse(result["native_qualification"])

    def test_wrong_base_and_fabricated_source_are_refused(self):
        producer = Mock()
        producer.verify_delivery.return_value = {"base_manifest_digest": "sha256:" + "c" * 64}
        with patch.object(image, "run", return_value=LOCK), patch.object(image, "load_producer", return_value=producer):
            with self.assertRaisesRegex(ValueError, "base"):
                image.verify(Path("/public/delivery"), SOURCE)
        with patch.object(image, "run") as run, self.assertRaisesRegex(ValueError, "source"):
            image.verify(Path("/public/delivery"), "a" * 7)
        run.assert_not_called()

    def test_clean_source_and_pinned_go_precede_fetch_and_offline_archive_production(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            producer_path = root / "deploy/sandbox/ubuntu-base"
            producer_path.mkdir(parents=True)
            (producer_path / "ubuntu26-amd64.lock.json").write_bytes(LOCK)
            calls = []

            def run(args, *, cwd=image.ROOT, env=None):
                calls.append((args, cwd, env))
                if args == ["git", "rev-parse", "HEAD"]:
                    return SOURCE.encode()
                if args[:2] == ["git", "diff"]:
                    return b""
                if args == ["pinned-go", "version"]:
                    return b"go version go1.26.9 linux/amd64\n"
                if args[:2] == ["git", "show"]:
                    return LOCK
                return b""

            descriptor = {"source_sha": SOURCE, "native_qualification": False}
            with patch.object(image, "ROOT", root), patch.object(image, "PRODUCER", producer_path), \
                 patch.object(image, "run", side_effect=run), patch.object(image, "verify", return_value=descriptor) as verify:
                self.assertEqual(image.build(root / "cache", root / "output", "pinned-go"), descriptor)
            verify.assert_called_once_with(root / "output", SOURCE)
            args = [row[0] for row in calls]
            self.assertEqual(args[:4], [["git", "rev-parse", "HEAD"], ["git", "diff", "--quiet"],
                                        ["git", "diff", "--cached", "--quiet"], ["pinned-go", "version"]])
            populate = next(row for row in calls if row[0] == ["pinned-go", "mod", "download"])
            self.assertEqual(populate[1], root / "apps/cli")
            self.assertEqual(populate[2]["GOFLAGS"], "-mod=readonly")
            self.assertEqual(populate[2]["GOTOOLCHAIN"], "local")
            fetch = next(item for item in args if "fetch" in item)
            preload = next(item for item in args if "preload-base" in item)
            archive = next(item for item in args if str(producer_path / "archive.py") in item)
            self.assertLess(args.index(populate[0]), args.index(fetch))
            self.assertLess(args.index(fetch), args.index(preload))
            self.assertLess(args.index(preload), args.index(archive))
            self.assertEqual(archive[-4:], ["--engine", "docker", "--go", "pinned-go"])
            self.assertFalse(any("resolve" in item or "systemctl" in item or "enroll" in item for item in args))

    def test_dirty_source_stops_before_module_or_image_downloads(self):
        calls = []

        def run(args, **kwargs):
            calls.append(args)
            if args == ["git", "rev-parse", "HEAD"]:
                return SOURCE.encode()
            raise subprocess.CalledProcessError(1, args)

        with patch.object(image, "run", side_effect=run), self.assertRaises(subprocess.CalledProcessError):
            image.build(Path("/unused/cache"), Path("/unused/output"), "go")
        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
