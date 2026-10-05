import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

import archive
import delivery


SOURCE = "a" * 40
LOCK = "b" * 64


def create_delivery(directory, *, source_label=SOURCE, user="1001:1001", missing_layer=False,
                    unsafe_member=False):
    metadata = {"architecture": "amd64", "os": "linux",
                "config": {"User": user, "WorkingDir": "/workspace", "Labels": {
                    "io.tunnex.sandbox.source": source_label,
                    "io.tunnex.sandbox.ubuntu-lock": LOCK}}}
    config = json.dumps(metadata).encode()
    digest = delivery.sha256(config)
    files = {digest + ".json": config,
             "manifest.json": json.dumps([{"Config": digest + ".json", "Layers": ["layer/layer.tar"]}]).encode()}
    if not missing_layer:
        files["layer/layer.tar"] = b"public layer fixture"
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
                  "config_digest": "sha256:" + digest, "unpacked_image_bytes": len(raw),
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
