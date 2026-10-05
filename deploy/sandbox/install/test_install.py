import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("sandbox_install", Path(__file__).with_name("install.py"))
install = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(install)


def archive(path, payload, gz=False):
    with tarfile.open(path, "w:gz" if gz else "w") as output:
        for name, raw in sorted(payload.items()):
            entry = tarfile.TarInfo(name)
            entry.size = len(raw)
            output.addfile(entry, io.BytesIO(raw))


def public_bundle(path, source, mutate=None):
    raw = bytearray(64)
    raw[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", raw, 18, 62)
    names = {f"bin/{command}-{edition}-linux-amd64" for command in install.COMMANDS for edition in ("open", "enterprise")}
    names |= {"bin/tunnex-sandbox-network-linux-amd64", "bin/tunnex-sandbox-bootstrap-linux-amd64"}
    payload = {name: bytes(raw) for name in names}
    payload.update({name: b"public fixture asset\n" for name in install.ASSETS})
    manifest = {"schema_version": 1, "source_sha": source, "os": "linux", "architecture": "amd64",
                "api_editions": ["open", "enterprise"], "native_runtime_qualification": False,
                "workload_images_built": False,
                "files": {name: {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)} for name, raw in payload.items()}}
    payload["manifest.json"] = json.dumps(manifest).encode()
    if mutate:
        mutate(payload)
    payload["SHA256SUMS"] = "".join(f"{hashlib.sha256(raw).hexdigest()}  {name}\n" for name, raw in sorted(payload.items())).encode()
    archive(path, payload, True)
    return payload


class FakeHost:
    def __init__(self, cfg):
        self.cfg = cfg
        self.calls = []
        self.system = ("Linux", "x86_64")
        self.version = "systemd 259\n"
        self.metadata = {
            "/etc/passwd": "root:x:0:0:root:/root:/bin/sh\n",
            "/etc/group": "root:x:0:\n",
            "/etc/subuid": "",
            "/etc/subgid": "",
            "/proc/self/mountinfo": "1 0 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n",
            "/sys/fs/cgroup/cgroup.controllers": "cpu memory pids io\n",
            "/proc/filesystems": "nodev\toverlay\n",
        }
        self.service_state = "UnitFileState=disabled\nActiveState=inactive\n"
        self.tool_mode = stat.S_IFREG | 0o755 | stat.S_ISUID

    def identity(self):
        return self.system

    def read(self, path):
        return self.metadata[path]

    def stat(self, path):
        if path == self.cfg["installation"]["io_device"]:
            return SimpleNamespace(st_mode=stat.S_IFBLK | 0o600, st_uid=0, st_rdev=17)
        return SimpleNamespace(st_mode=self.tool_mode, st_uid=0, st_dev=17)

    def run(self, args, **kwargs):
        self.calls.append(tuple(args))
        if args == ["/usr/bin/systemctl", "--version"]:
            return self.version
        if args[:2] == ["/usr/bin/systemctl", "show"]:
            return self.service_state
        if args[:2] == ["/usr/bin/docker", "inspect"]:
            gateway = self.cfg["gateway"]
            return json.dumps({"id": gateway["container_id"], "image": gateway["image_digest"], "running": True,
                               "namespace": "/var/run/docker/netns/" + "c" * 12})
        return ""


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tunnex-installer-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.cfg = json.loads(Path(__file__).with_name("example.json").read_text())
        self.cfg["images"][0]["qualification_evidence"] = "synthetic-reviewed-native-fixture"
        self.cfg["bundle"]["path"] = str(self.root / "public.tar.gz")
        self.payload = public_bundle(self.cfg["bundle"]["path"], self.cfg["source_sha"])
        self.cfg["bundle"]["sha256"] = install.file_hash(self.cfg["bundle"]["path"], 100 * install.MIB)
        image = self.cfg["images"][0]
        image["path"] = str(self.root / "image.tar")
        raw = json.dumps({"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": []}}).encode()
        image["config_digest"] = "sha256:" + hashlib.sha256(raw).hexdigest()
        archive(image["path"], {"manifest.json": json.dumps([{"Config": "config.json", "Layers": ["layer.tar"]}]).encode(),
                                "config.json": raw, "layer.tar": b"synthetic public layer"})
        image["sha256"] = install.file_hash(image["path"], 512 * install.MIB)

    def test_valid_example_and_custom_identity_render_bounded_services(self):
        install.validate(self.cfg)
        files, runtime, binaries = install.render(self.cfg, self.payload)
        self.assertEqual(runtime["Binding"]["Admission"], "organization")
        self.assertNotIn("CreatorID", runtime["Binding"])
        self.assertNotIn("TerminalDeviceID", runtime["Binding"])
        self.assertEqual(runtime["Supervision"]["ActorUID"], 2401)
        self.assertEqual(runtime["Binding"]["MaxTTLSeconds"], 900)
        self.assertEqual(runtime["Binding"]["Profiles"][0]["PIDs"], 64)
        actor = files["tunnexsandbox-actor.service"]
        self.assertIn("KillMode=control-group", actor)
        self.assertIn("DelegateSubgroup=control", actor)
        self.assertIn("ExecStartPre=/usr/bin/python3", actor)
        self.assertIn("--role=actor", actor)
        self.assertIn("MemoryMax=224M", files["tunnexsandbox.slice"])
        self.assertIn("IOWriteBandwidthMax=/dev/vda 8M", files["tunnexsandbox.slice"])
        self.assertIn("CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN", files["tunnexsandbox-network.service"])
        self.assertIn("--gateway-org-id=" + self.cfg["org_id"], files["tunnexsandbox-network.service"])
        self.assertEqual(len(binaries), 5)
        self.assertNotIn("1101", "".join(files.values()))
        self.assertNotIn("sandbox-qual", "".join(files.values()))

    def test_ui_enrollment_qualification_alias_is_public_and_uses_actual_trusted_root(self):
        cfg = copy.deepcopy(self.cfg)
        cfg["enrollment_id"] = "00000000-0000-4000-8000-000000000009"
        cfg["installation"]["state_root"] = "/srv/custom-runner"
        install.validate(cfg)
        path, raw = install.qualification_alias(cfg)
        self.assertEqual(str(path), "/usr/local/libexec/tunnex-sandbox/enrollments/00000000-0000-4000-8000-000000000009/qualify.py")
        self.assertIn(b"/srv/custom-runner/enroll.py", raw)
        self.assertIn(b"--qualification-trial-id", raw)
        self.assertNotIn(b"2401", raw)
        self.assertNotIn(b"PRIVATE KEY", raw)
        self.assertNotIn(b"shell", raw)
        self.assertEqual(install.qualification_alias(self.cfg), (None, None))
        for enrollment in ("../../other", "00000000-0000-0000-0000-000000000000"):
            cfg["enrollment_id"] = enrollment
            with self.assertRaises(ValueError):
                install.qualification_alias(cfg)

    def test_public_artifact_verification(self):
        install.bundle_payload(self.cfg)
        install.verify_image(self.cfg["images"][0])

    def test_mutated_checksum_or_source_refused(self):
        for field, value in (("bundle", dict(self.cfg["bundle"], sha256="f" * 64)), ("source_sha", "f" * 40)):
            cfg = copy.deepcopy(self.cfg)
            cfg[field] = value
            with self.assertRaises(ValueError):
                install.bundle_payload(cfg)

    def test_private_or_unexpected_bundle_member_refused(self):
        public_bundle(self.cfg["bundle"]["path"], self.cfg["source_sha"], lambda files: files.update({"worker/key.pem": b"fixture"}))
        self.cfg["bundle"]["sha256"] = install.file_hash(self.cfg["bundle"]["path"], 100 * install.MIB)
        with self.assertRaises(ValueError):
            install.bundle_payload(self.cfg)

    def test_changed_image_config_or_architecture_refused(self):
        for field, value in (("config_digest", "sha256:" + "f" * 64), ("architecture", "arm64")):
            cfg = copy.deepcopy(self.cfg)
            cfg["images"][0][field] = value
            with self.assertRaises(ValueError):
                install.verify_image(cfg["images"][0]) if field == "config_digest" else install.validate(cfg)

    def test_paths_shell_text_unbounded_limits_and_ambiguity_refused(self):
        cases = [{"state_root": "/tmp/../other"}, {"state_root": "/"}, {"run_root": "/srv/run"},
                 {"run_root": self.cfg["installation"]["state_root"] + "/run"},
                 {"service_user": "root"}, {"service_user": "runner;id"}, {"unit_prefix": "a%1"},
                 {"uid": 0}, {"uid": True}, {"subuid_count": 65537}, {"workspace_mib": 257},
                 {"storage_mib": 8193}, {"io_device": "/tmp/device"}]
        for fields in cases:
            with self.subTest(fields=fields):
                cfg = copy.deepcopy(self.cfg)
                cfg["installation"].update(fields)
                with self.assertRaises(ValueError):
                    install.validate(cfg)
        with self.assertRaises(ValueError):
            install.strict_json('{"version":1,"version":1}')
        cfg = copy.deepcopy(self.cfg)
        cfg["unrecognized"] = True
        with self.assertRaises(ValueError):
            install.validate(cfg)

    def test_public_identity_cannot_contain_options_or_private_material(self):
        for value in ("command=\"id\" " + self.cfg["probe_public_key"], "-----BEGIN OPENSSH PRIVATE KEY-----", self.cfg["probe_public_key"] * 2):
            with self.assertRaises(ValueError):
                install.public_probe(value)

    def test_identity_and_subordinate_collisions_refused(self):
        changes = [("/etc/passwd", "foreign:x:2401:2401::/home/foreign:/bin/sh\n"),
                   ("/etc/group", "foreign:x:2401:\n"),
                   ("/etc/subuid", "foreign:300001:65536\n"),
                   ("/etc/subgid", "tunnex-sandbox:300000:65535\n")]
        for path, value in changes:
            host = FakeHost(self.cfg)
            host.metadata[path] = value
            with self.assertRaises(ValueError):
                install.check(self.cfg, host)

    def test_capabilities_are_structural_not_new_native_proof(self):
        host = FakeHost(self.cfg)
        result = install.check(self.cfg, host)
        self.assertFalse(result["new_host_native_qualification"])
        self.assertFalse(result["services_started"])
        self.assertFalse(result["services_enabled"])
        self.assertEqual(result["workload_slots"], 1)
        self.assertTrue(all(call[0] in ("/usr/bin/systemctl", "/usr/bin/docker") for call in host.calls))
        self.assertFalse(any(action in call for call in host.calls for action in ("start", "enable", "stop", "restart", "pull", "exec", "run", "load")))

    def test_unsupported_hosts_active_roles_or_missing_controllers_refused(self):
        for change in (lambda h: setattr(h, "system", ("Linux", "aarch64")),
                       lambda h: setattr(h, "version", "systemd 253\n"),
                       lambda h: setattr(h, "tool_mode", stat.S_IFREG | 0o777),
                       lambda h: h.metadata.update({"/sys/fs/cgroup/cgroup.controllers": "cpu memory pids\n"}),
                       lambda h: setattr(h, "service_state", "ActiveState=active\nUnitFileState=disabled\n"),
                       lambda h: setattr(h, "service_state", "ActiveState=inactive\nUnitFileState=enabled\n")):
            host = FakeHost(self.cfg)
            change(host)
            with self.assertRaises(ValueError):
                install.check(self.cfg, host)

    def test_foreign_gateway_metadata_refused(self):
        host = FakeHost(self.cfg)
        original = host.run
        def run(args, **kwargs):
            result = original(args, **kwargs)
            if args[0] == "/usr/bin/docker":
                metadata = json.loads(result)
                metadata["image"] = "sha256:" + "f" * 64
                return json.dumps(metadata)
            return result
        host.run = run
        with self.assertRaises(ValueError):
            install.check(self.cfg, host)

    def test_io_backing_device_and_placeholder_qualification_refused(self):
        host = FakeHost(self.cfg)
        original = host.stat
        def changed(path):
            result = original(path)
            if path == self.cfg["installation"]["io_device"]:
                result.st_rdev = 18
            return result
        host.stat = changed
        with self.assertRaises(ValueError):
            install.check(self.cfg, host)
        cfg = copy.deepcopy(self.cfg)
        cfg["images"][0]["qualification_evidence"] = "REPLACE with proof"
        with self.assertRaises(ValueError):
            install.validate(cfg)

    def test_preload_uses_only_verified_offline_image_and_skips_exact_existing_id(self):
        root = self.root / "preload-state"
        for name in ("images", "workload-assets", "worker/storage"):
            (root / name).mkdir(parents=True, exist_ok=True)
        image = copy.deepcopy(self.cfg["images"][0])
        image["path"] = str(root / "images/image.tar")
        Path(image["path"]).write_bytes(Path(self.cfg["images"][0]["path"]).read_bytes())
        layout = dict(self.cfg["installation"], state_root=str(root))
        config = root / "preload.json"
        config.write_text(json.dumps({"installation": layout, "images": [image]}))
        host = FakeHost(self.cfg)
        calls = []
        def run(args, **kwargs):
            calls.append((args, kwargs))
            if "inspect" in args:
                return image["config_digest"] + " amd64 linux\n"
            raise AssertionError("unexpected preload mutation")
        host.run = run
        original_lstat, original_stat = Path.lstat, Path.stat
        def lstat(path, *args, **kwargs):
            if path == config:
                return SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_size=config.read_bytes().__len__())
            return original_lstat(path, *args, **kwargs)
        def statted(path, *args, **kwargs):
            if path in (root / "workload-assets", root / "worker/storage"):
                return SimpleNamespace(st_uid=2401)
            return original_stat(path, *args, **kwargs)
        with mock.patch.object(install.os, "geteuid", return_value=2401), mock.patch.object(install.os, "getegid", return_value=2401), \
             mock.patch.object(Path, "lstat", autospec=True, side_effect=lstat), mock.patch.object(Path, "stat", autospec=True, side_effect=statted):
            result = install.preload(str(config), host)
        self.assertFalse(result["native_qualification"])
        self.assertEqual(len(calls), 1)
        self.assertIn("inspect", calls[0][0])
        self.assertNotIn("load", calls[0][0])
        self.assertEqual(calls[0][1]["env"]["HOME"], str(root / "worker/home"))

    def test_install_repetition_and_changed_owned_artifact(self):
        cfg = copy.deepcopy(self.cfg)
        cfg["installation"]["state_root"] = str(self.root / "state")
        host = FakeHost(cfg)
        units = self.root / "units"
        units.mkdir()
        subuid, subgid = self.root / "subuid", self.root / "subgid"
        subuid.write_text("")
        subgid.write_text("")
        real_path = Path
        def redirected(value):
            text = str(value)
            for before, after in (("/etc/systemd/system", units), ("/etc/subuid", subuid), ("/etc/subgid", subgid)):
                if text == before or text.startswith(before + "/"):
                    return real_path(str(after) + text[len(before):])
            return real_path(value)
        real_open = open
        def opened(value, *args, **kwargs):
            return real_open(redirected(value), *args, **kwargs)
        with mock.patch.object(install.os, "geteuid", return_value=0), \
             mock.patch.object(install.os, "chown"), mock.patch.object(install.os, "fchown"), \
             mock.patch.object(install, "safe_parents"), mock.patch.object(install, "private_input", return_value=b"synthetic fixture identity"), \
             mock.patch.object(install, "Path", side_effect=redirected), mock.patch("builtins.open", side_effect=opened):
            first = install.install(cfg, self.payload, host)
            second = install.install(cfg, self.payload, host)
            self.assertEqual(first["installation"], "installed-disabled")
            self.assertEqual(second["installation"], "already-installed")
            self.assertTrue((self.root / "state/workload-assets.ext4").stat().st_size == 256 * install.MIB)
            self.assertTrue((self.root / "state/storage.ext4").stat().st_size == 4096 * install.MIB)
            self.assertTrue(any("root_owner=2401:2401" in call for call in host.calls))
            self.assertTrue(any("set_inode_field <2> mode 040700" in call for call in host.calls))
            self.assertFalse(any(action in call for call in host.calls for action in ("enable", "start", "stop", "restart", "pull")))
            binary = self.root / "state/bin/tunnex-sandbox-runtime"
            binary.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                install.install(cfg, self.payload, host)


if __name__ == "__main__":
    unittest.main()
