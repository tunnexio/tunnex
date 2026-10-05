import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import test_install


SPEC = importlib.util.spec_from_file_location("sandbox_enroll", Path(__file__).with_name("enroll.py"))
enroll = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(enroll)


class Response(io.BytesIO):
    status = 200

    def __init__(self, raw, url):
        super().__init__(raw)
        self.url = url

    def geturl(self):
        return self.url


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tunnex-machine-enrollment-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = "1" * 40
        self.path = self.root / "bundle.tar.gz"
        self.payload = test_install.public_bundle(self.path, self.source)
        self.path.chmod(0o600)
        self.sha = hashlib.sha256(self.path.read_bytes()).hexdigest()
        self.options = SimpleNamespace(enrollment_id="00000000-0000-4000-8000-000000000001",
                                       source_sha=self.source, edition="open", api_url="https://api.example.invalid",
                                       bundle_url="https://artifacts.example.invalid/public.tar.gz", bundle_sha256=self.sha)

    def test_pinned_bundle_verified_before_machine_execution(self):
        payload = enroll.verify_bundle(self.path, self.source, self.sha)
        self.assertEqual(payload, self.payload)
        self.assertEqual(set(enroll.ASSETS), set(test_install.install.ASSETS))
        for source, sha in (("2" * 40, self.sha), (self.source, "2" * 64)):
            with self.assertRaises(enroll.Refused):
                enroll.verify_bundle(self.path, source, sha)

    def test_bundle_foreign_member_architecture_and_symlink_refused(self):
        def cases(payload):
            payload["operator/key.pem"] = b"synthetic public fixture"
        test_install.public_bundle(self.path, self.source, cases)
        self.path.chmod(0o600)
        with self.assertRaises(enroll.Refused):
            enroll.verify_bundle(self.path, self.source, hashlib.sha256(self.path.read_bytes()).hexdigest())
        def arm(payload):
            raw = bytearray(payload["bin/tunnex-sandbox-network-linux-amd64"])
            struct.pack_into("<H", raw, 18, 183)
            payload["bin/tunnex-sandbox-network-linux-amd64"] = bytes(raw)
        test_install.public_bundle(self.path, self.source, arm)
        with self.assertRaises(enroll.Refused):
            enroll.verify_bundle(self.path, self.source, hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.path.rename(self.root / "other.tar.gz")
        self.path.symlink_to(self.root / "other.tar.gz")
        with self.assertRaises(enroll.Refused):
            enroll.verify_bundle(self.path, self.source, self.sha)

    def test_download_public_https_only_exact_pin_and_bounded_retry(self):
        raw = b"synthetic public artifact"
        url = "https://artifacts.example.invalid/public"
        destination = self.root / "download"
        opener = SimpleNamespace(open=lambda request, **kwargs: Response(raw, request.full_url))
        sha = hashlib.sha256(raw).hexdigest()
        enroll.download(url, sha, destination, 256, opener)
        self.assertEqual(destination.read_bytes(), raw)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
        no_network = SimpleNamespace(open=lambda *_args, **_kwargs: self.fail("identical retry downloaded again"))
        enroll.download(url, sha, destination, 256, no_network)
        with self.assertRaises(enroll.Refused):
            enroll.download(url, "f" * 64, destination, 256, no_network)

    def test_failed_download_does_not_publish_partial_or_redirect(self):
        raw = b"synthetic public artifact"
        url = "https://artifacts.example.invalid/public"
        for size, pin, changed_url in ((4, hashlib.sha256(raw).hexdigest(), url), (256, "f" * 64, url),
                                      (256, hashlib.sha256(raw).hexdigest(), "https://other.example.invalid/public")):
            destination = self.root / "download"
            opener = SimpleNamespace(open=lambda *_args, **_kwargs: Response(raw, changed_url))
            with self.assertRaises(enroll.Refused):
                enroll.download(url, pin, destination, size, opener)
            self.assertFalse(destination.exists())
            self.assertFalse(destination.with_name("download.partial").exists())
        with self.assertRaises(enroll.Refused):
            enroll.NoRedirect().redirect_request(None, None, 302, None, None, "https://other.example.invalid")

    def test_unsafe_public_url_token_and_unknown_schema_refused(self):
        for url in ("http://artifacts.example.invalid/file", "https://user:secret@artifacts.example.invalid/file",
                    "https://artifacts.example.invalid/file?token=secret", "https://artifacts.example.invalid/file#fragment",
                    "https://artifacts.example.invalid/file\ntext"):
            with self.assertRaises(enroll.Refused):
                enroll.public_url(url)
        with self.assertRaises(enroll.Refused):
            enroll.strict_json('{"version":1,"version":1}')
        with self.assertRaises(enroll.Refused):
            enroll.keys({"version": 1, "unexpected": True}, ("version",))

    def fake_layout_host(self):
        metadata = {"/etc/passwd": "root:x:0:0:root:/root:/bin/sh\noccupied:x:2401:2401::/home/occupied:/bin/sh\n",
                    "/etc/group": "root:x:0:\noccupied:x:2401:\n", "/etc/subuid": "occupied:65536:65536\n",
                    "/etc/subgid": "occupied:131072:65536\n", "/proc/self/mountinfo": "1 0 8:1 / / rw - ext4 /dev/vda1 rw\n"}
        def info(path):
            if path == "/dev/vda1":
                return SimpleNamespace(st_mode=stat.S_IFBLK | 0o600, st_rdev=os.makedev(8, 1))
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_dev=os.makedev(8, 1))
        return SimpleNamespace(read=lambda path: metadata[path], stat=info), metadata

    def test_layout_selects_unoccupied_host_identity_ranges_and_actual_block_device(self):
        host, _ = self.fake_layout_host()
        layout = enroll.select_layout(self.options.enrollment_id, host)
        self.assertEqual(layout["uid"], 2402)
        self.assertEqual(layout["gid"], 2402)
        self.assertEqual(layout["subuid_start"], 196608)
        self.assertEqual(layout["io_device"], "/dev/vda1")
        self.assertEqual(layout["workspace_mib"], 256)
        self.assertEqual(layout["storage_mib"], 4096)
        self.assertIn(self.options.enrollment_id, layout["state_root"])
        self.assertNotIn("root", layout["service_user"])

    def test_layout_refuses_missing_block_device_or_reserved_identity(self):
        host, metadata = self.fake_layout_host()
        metadata["/proc/self/mountinfo"] = "1 0 0:1 / / rw - overlay overlay rw\n"
        with self.assertRaises(enroll.Refused):
            enroll.select_layout(self.options.enrollment_id, host)
        host, metadata = self.fake_layout_host()
        metadata["/etc/passwd"] += "tnxsb0000000000004000:x:2405:2405::/home/foreign:/bin/sh\n"
        with self.assertRaises(enroll.Refused):
            enroll.select_layout(self.options.enrollment_id, host)

    def plan_fixture(self):
        cfg = json.loads(Path(__file__).with_name("example.json").read_text())
        cfg["source_sha"] = self.source
        cfg["controller"]["api_url"] = self.options.api_url
        cfg["bundle"] = {"url": self.options.bundle_url, "sha256": self.sha}
        cfg["images"][0]["url"] = "https://artifacts.example.invalid/approved.image.tar"
        cfg["images"][0]["qualification_evidence"] = "synthetic-reviewed-native-image"
        del cfg["images"][0]["path"]
        for key in ("credentials", "probe_public_key", "installation"):
            del cfg[key]
        identity = self.root / "identity"
        identity.mkdir(mode=0o700)
        (identity / "identity.json").write_text(json.dumps({"probe_public_key": json.loads(Path(__file__).with_name("example.json").read_text())["probe_public_key"]}))
        (identity / "identity.json").chmod(0o600)
        bundle = {"enrollment_id": self.options.enrollment_id, "certificate": "synthetic public cert",
                  "runner_ca": "synthetic public CA", "api_ca": "synthetic public CA", "install": cfg}
        return bundle

    def test_public_plan_becomes_real_pinned_installer_configuration(self):
        bundle = self.plan_fixture()
        host, _ = self.fake_layout_host()
        layout = enroll.select_layout(self.options.enrollment_id, host)
        cfg = enroll.installer_config(bundle, self.options, self.root, layout)
        test_install.install.validate(cfg)
        self.assertEqual(cfg["gateway"], bundle["install"]["gateway"])
        self.assertEqual(cfg["images"][0]["config_digest"], bundle["install"]["images"][0]["config_digest"])
        self.assertNotIn("url", cfg["images"][0])
        self.assertEqual(cfg["credentials"]["runner_key"], str(self.root / "identity/runner-key.pem"))
        self.assertEqual(cfg["installation"]["uid"], 2402)

    def test_changed_public_enrollment_pins_and_arm64_refused(self):
        bundle = self.plan_fixture()
        host, _ = self.fake_layout_host()
        layout = enroll.select_layout(self.options.enrollment_id, host)
        for mutate in (lambda b: b.update(enrollment_id="00000000-0000-4000-8000-000000000009"),
                       lambda b: b["install"].update(source_sha="2" * 40),
                       lambda b: b["install"]["bundle"].update(sha256="2" * 64),
                       lambda b: b["install"]["controller"].update(api_url="https://other.example.invalid"),
                       lambda b: b["install"]["images"][0].update(architecture="arm64")):
            value = copy.deepcopy(bundle)
            mutate(value)
            with self.assertRaises(enroll.Refused):
                enroll.installer_config(value, self.options, self.root, layout)

    def test_activation_requires_exact_admin_ack_and_does_not_claim_ready(self):
        calls = []
        host = SimpleNamespace(run=lambda args: calls.append(args))
        cfg = {"installation": {"unit_prefix": "syntheticrunner"}}
        for acknowledgment in ("", "activate", "yes"):
            with self.assertRaises(enroll.Refused):
                enroll.activate(cfg, host, acknowledgment)
        self.assertEqual(calls, [])
        result = enroll.activate(cfg, host, "ACTIVATE")
        self.assertEqual(calls, [["/usr/bin/systemctl", "start", "syntheticrunner-network.service", "syntheticrunner-actor.service", "syntheticrunner-transport.service"]])
        self.assertFalse(result["connected"])
        self.assertFalse(result["native_qualification"])
        self.assertFalse(result["services_enabled"])

    def test_private_staging_refuses_links_and_permission_changes(self):
        destination = self.root / "private"
        destination.mkdir(mode=0o700)
        with mock.patch.object(enroll, "private_directory"):
            # File-level checks work in a normal unprivileged test directory.
            file = destination / "key"
            file.write_bytes(b"synthetic local identity")
            file.chmod(0o600)
            self.assertEqual(enroll.file_bytes(file, 1024), b"synthetic local identity")
            file.chmod(0o644)
            with self.assertRaises(enroll.Refused):
                enroll.file_bytes(file, 1024)
            file.unlink()
            file.symlink_to(self.path)
            with self.assertRaises(enroll.Refused):
                enroll.file_bytes(file, 1024)

    def test_hidden_prompt_refuses_echo_fallback(self):
        fake = mock.MagicMock()
        fake.__enter__.return_value = fake
        with mock.patch("builtins.open", return_value=fake), mock.patch.object(enroll.getpass, "getpass", side_effect=enroll.getpass.GetPassWarning("echo fallback")):
            with self.assertRaises(enroll.getpass.GetPassWarning):
                enroll.secret_prompt("Enrollment token: ")

