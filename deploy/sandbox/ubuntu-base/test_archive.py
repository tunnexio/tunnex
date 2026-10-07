import hashlib
import io
import json
import subprocess
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import archive
import delivery


SOURCE = "a" * 40
LOCK = "b" * 64


def create_delivery(directory, *, source_label=SOURCE, user="1001:1001", missing_layer=False,
                    unsafe_member=False, bad_layer=False):
    metadata = {"architecture": "amd64", "os": "linux",
                "rootfs": {"type": "layers", "diff_ids": ["sha256:" + delivery.sha256(b"public layer fixture")]},
                "config": {"User": user, "WorkingDir": "/workspace", "Labels": {
                    "io.tunnex.sandbox.source": source_label,
                    "io.tunnex.sandbox.ubuntu-lock": LOCK}}}
    config = json.dumps(metadata).encode()
    digest = delivery.sha256(config)
    files = {digest + ".json": config,
             "manifest.json": json.dumps([{"Config": digest + ".json", "Layers": ["layer/layer.tar"]}]).encode()}
    if not missing_layer:
        files["layer/layer.tar"] = b"altered layer" if bad_layer else b"public layer fixture"
    filename = "tunnex-sandbox-ubuntu26-linux-amd64.docker.tar"
    with tarfile.open(directory / filename, "w") as output:
        for name, raw in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            output.addfile(member, io.BytesIO(raw))
        if unsafe_member:
            member = tarfile.TarInfo("../operator-config")
            member.size = 0
            output.addfile(member, io.BytesIO())
    raw = (directory / filename).read_bytes()
    descriptor = {"schema_version": 1, "source_sha": SOURCE, "os": "linux", "architecture": "amd64",
                  "dependency_lock_sha256": LOCK, "base_manifest_digest": "sha256:" + "c" * 64,
                  "archive": {"filename": filename, "sha256": delivery.sha256(raw), "bytes": len(raw)},
                  "config_digest": "sha256:" + digest, "unpacked_image_bytes": len(b"public layer fixture"),
                  "native_qualification": False, "services_started": False,
                  "packages_installed_at_launch": False}
    write_descriptor(directory, descriptor)
    return descriptor


def write_descriptor(directory, descriptor):
    (directory / "workload-image.json").write_text(json.dumps(descriptor) + "\n")
    (directory / "SHA256SUMS").write_text("".join(
        delivery.sha256((directory / name).read_bytes()) + "  " + name + "\n"
        for name in (descriptor["archive"]["filename"], "workload-image.json")))


class ArchiveTests(unittest.TestCase):
    def test_bootstrap_exports_committed_local_dependency_and_excludes_worktree_data(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, context = root / "repo", root / "context"
            repo.mkdir()
            context.mkdir()
            sources = {
                "apps/cli/go.mod": "module example/cli\nreplace example/transport => ../../packages/apptransport\n",
                "packages/apptransport/go.mod": "module example/transport\n",
                "packages/apptransport/channel.go": "package transport\n",
                "deploy/sandbox/ubuntu-base/Containerfile": "FROM locked-base\n",
                "deploy/sandbox/Containerfile": "ARG BASE_IMAGE\nFROM ${BASE_IMAGE}\n",
                "deploy/sandbox/sandbox-entrypoint.py": "# committed entrypoint\n",
                "apps/api/private-fixture.txt": "must never enter the source export\n",
            }
            for name, content in sources.items():
                path = repo / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test Fixture",
                            "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture"], check=True)
            source = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"]).decode().strip()
            (repo / "packages/apptransport/channel.go").write_text("uncommitted worktree content")
            real_command = archive.command
            compiled = []

            def command(args, **kwargs):
                if args[0] != "fixture-go":
                    return real_command(args, **kwargs)
                source_root = kwargs["cwd"].parents[1]
                self.assertEqual((source_root / "packages/apptransport/channel.go").read_text(),
                                 sources["packages/apptransport/channel.go"])
                self.assertFalse((source_root / "apps/api").exists())
                self.assertEqual(kwargs["env"]["GOPROXY"], "off")
                self.assertEqual(kwargs["env"]["GOFLAGS"], "-mod=readonly")
                self.assertIn("-buildvcs=false", args)
                compiled.append(args)
                return b""

            lock = {"metadata": [], "download_packages": [], "installed_inventory": [], "architecture": "amd64"}
            with patch.object(archive, "ROOT", repo), patch.object(archive, "command", side_effect=command):
                archive.assemble_context(lock, b"{}", root / "cache", source, context, "fixture-go")
            self.assertEqual(len(compiled), 1)

    def test_exact_delivery_identity_and_unqualified_status_verify(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            descriptor = create_delivery(root)
            self.assertEqual(archive.verify_delivery(root, SOURCE, "amd64", LOCK), descriptor)
            self.assertFalse(descriptor["native_qualification"])

    def test_archive_byte_corruption_and_checksum_file_drift_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            descriptor = create_delivery(root)
            target = root / descriptor["archive"]["filename"]
            target.write_bytes(target.read_bytes() + b"corrupt")
            with self.assertRaises(delivery.InvalidInput):
                archive.verify_delivery(root, SOURCE, "amd64", LOCK)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_delivery(root)
            (root / "SHA256SUMS").write_text("altered\n")
            with self.assertRaises(delivery.InvalidInput):
                archive.verify_delivery(root, SOURCE, "amd64", LOCK)

    def test_wrong_source_platform_lock_and_native_promotion_refuse(self):
        for field, value in (("source_sha", "d" * 40), ("architecture", "arm64"),
                             ("dependency_lock_sha256", "e" * 64), ("native_qualification", True),
                             ("services_started", True), ("packages_installed_at_launch", True)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                descriptor = create_delivery(root)
                descriptor[field] = value
                write_descriptor(root, descriptor)
                with self.assertRaises(delivery.InvalidInput):
                    archive.verify_delivery(root, SOURCE, "amd64", LOCK)

    def test_source_label_and_nonroot_identity_enforced_inside_image(self):
        for kwargs in ({"source_label": "f" * 40}, {"user": "0:0"}):
            with self.subTest(kwargs=kwargs), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                create_delivery(root, **kwargs)
                with self.assertRaises(delivery.InvalidInput):
                    archive.verify_delivery(root, SOURCE, "amd64", LOCK)

    def test_missing_layers_and_unsafe_members_refuse(self):
        for kwargs in ({"missing_layer": True}, {"unsafe_member": True}):
            with self.subTest(kwargs=kwargs), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                create_delivery(root, **kwargs)
                with self.assertRaises(delivery.InvalidInput):
                    archive.verify_delivery(root, SOURCE, "amd64", LOCK)

    def test_layer_diff_pin_and_measurement_cannot_be_invented(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            create_delivery(root, bad_layer=True)
            with self.assertRaises(delivery.InvalidInput):
                archive.verify_delivery(root, SOURCE, "amd64", LOCK)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            descriptor = create_delivery(root)
            descriptor["unpacked_image_bytes"] += 1
            write_descriptor(root, descriptor)
            with self.assertRaises(delivery.InvalidInput):
                archive.verify_delivery(root, SOURCE, "amd64", LOCK)

    def test_extra_files_and_nonpublic_descriptor_fields_refuse(self):
        for mutation in (lambda root, data: (root / "operator-config").write_text("synthetic"),
                         lambda root, data: write_descriptor(root, dict(data, credential="synthetic"))):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                descriptor = create_delivery(root)
                mutation(root, descriptor)
                with self.assertRaises(delivery.InvalidInput):
                    archive.verify_delivery(root, SOURCE, "amd64", LOCK)


if __name__ == "__main__":
    unittest.main()
