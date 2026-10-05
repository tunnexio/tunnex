import copy
from datetime import datetime, timedelta, timezone
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
        identity.mkdir(mode=0o700, exist_ok=True)
        (identity / "identity.json").write_text(json.dumps({"probe_public_key": json.loads(Path(__file__).with_name("example.json").read_text())["probe_public_key"]}))
        (identity / "identity.json").chmod(0o600)
        bundle = {"enrollment_id": self.options.enrollment_id, "profile_id": "00000000-0000-4000-8000-000000000003", "binding_sha256": "a" * 64, "certificate": "synthetic public cert",
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

    def report_fixture(self):
        bundle = self.plan_fixture()
        layout_host, _ = self.fake_layout_host()
        cfg = enroll.installer_config(bundle, self.options, self.root, enroll.select_layout(self.options.enrollment_id, layout_host))
        host = test_install.FakeHost(cfg)
        host.metadata["/etc/os-release"] = 'ID=ubuntu\nVERSION_ID="26.04"\n'
        host.service_state = "UnitFileState=disabled\nActiveState=active\n"
        original = host.run
        def run(args, **kwargs):
            if args[0] == "/usr/bin/podman":
                host.calls.append(tuple(args))
                self.assertEqual(kwargs["user"], cfg["installation"]["uid"])
                self.assertEqual(kwargs["extra_groups"], [])
                return cfg["images"][0]["config_digest"] + " amd64 linux\n"
            return original(args, **kwargs)
        host.run = run
        return cfg, bundle, host

    def test_current_host_and_loaded_image_report_does_not_claim_native_checks(self):
        cfg, bundle, host = self.report_fixture()
        report = enroll.qualification_report(cfg, bundle, test_install.install, host, {"installation": "activation-requested"})
        self.assertEqual(report["platform"], {"os": "linux", "version": "ubuntu 26.04", "architecture": "amd64"})
        self.assertEqual([check["result"] for check in report["checks"]], ["passed", "passed", "unrun", "unrun", "unrun"])
        self.assertEqual(report["image_config_digests"], [cfg["images"][0]["config_digest"]])
        self.assertFalse(any(action in call for call in host.calls for action in ("start", "kill", "run", "exec", "pull", "load")))
        self.assertFalse(any(call[:2] == ("/usr/bin/systemctl", "show") for call in host.calls))

    def test_stopped_runner_image_unrun_and_actual_capability_failure_reported(self):
        cfg, bundle, host = self.report_fixture()
        host.metadata["/sys/fs/cgroup/cgroup.controllers"] = "cpu memory\n"
        report = enroll.qualification_report(cfg, bundle, test_install.install, host, {"installation": "installed-disabled"})
        self.assertEqual([check["result"] for check in report["checks"]], ["failed", "unrun", "unrun", "unrun", "unrun"])
        self.assertFalse(any(call[0] == "/usr/bin/podman" for call in host.calls))

    def test_image_observation_failure_cannot_be_reported_passed(self):
        cfg, bundle, host = self.report_fixture()
        original = host.run
        host.run = lambda args, **kwargs: "sha256:" + "f" * 64 + " amd64 linux\n" if args[0] == "/usr/bin/podman" else original(args, **kwargs)
        report = enroll.qualification_report(cfg, bundle, test_install.install, host, {"installation": "activation-requested"})
        self.assertEqual(report["checks"][1]["result"], "failed")
        self.assertEqual([check["result"] for check in report["checks"][-3:]], ["unrun"] * 3)

    def test_os_release_is_data_and_missing_platform_cannot_be_invented(self):
        host = SimpleNamespace(read=lambda _path: 'ID=debian\nVERSION_ID="13"\n')
        self.assertEqual(enroll.host_platform(host)["version"], "debian 13")
        for value in ('ID=ubuntu\n', 'ID="$(id)"\nVERSION_ID=26.04\n'):
            with self.assertRaises(enroll.Refused):
                enroll.host_platform(SimpleNamespace(read=lambda _path: value))

    def native_fixture(self):
        cfg, bundle, _ = self.report_fixture()
        initial = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
        clock = [initial]
        def wire(value):
            return value.isoformat().replace("+00:00", "Z")
        sandbox = "00000000-0000-4000-8000-000000000004"
        status = {"version": 1, "enrollment_id": bundle["enrollment_id"], "profile_id": bundle["profile_id"],
                  "binding_sha256": bundle["binding_sha256"], "source_sha": cfg["source_sha"],
                  "trial_id": "00000000-0000-4000-8000-000000000005", "sandbox_id": sandbox,
                  "runtime_id": "b" * 64, "generation": 3, "phase": "awaiting_expiry",
                  "created_at": wire(initial - timedelta(seconds=500)), "expires_at": wire(initial + timedelta(seconds=40)),
                  "initial_ready_at": wire(initial - timedelta(seconds=400)), "stopped_at": wire(initial - timedelta(seconds=300)),
                  "resume_ready_at": wire(initial - timedelta(seconds=200))}
        lease = {"sandbox_id": sandbox, "generation": 3, "created_at": status["created_at"], "expires_at": status["expires_at"]}
        profile = {"ConfigDigest": cfg["images"][0]["config_digest"], "Architecture": "amd64", "PIDs": 64}
        actor_pin = {"SandboxID": sandbox, "Authorization": {"SandboxID": sandbox, "Generation": 3, "Desired": "started",
                     "CreatedAt": status["created_at"], "ExpiresAt": status["expires_at"], "Profile": profile,
                     "TemplateID": cfg["images"][0]["template_id"]}, "Epoch": {"RuntimeID": status["runtime_id"]}, "EpochGeneration": 3,
                     "Binding": {"Admission": "organization", "Mode": "persistent", "OrgID": cfg["org_id"],
                     "GatewayID": cfg["gateway"]["node_id"], "MemoryMiB": 128, "CPUs": 1, "MaxTTLSeconds": 900}}
        receipt = {"lease": lease, "stopped_at": status["expires_at"]}
        def metadata(path, uid):
            self.assertEqual(uid, cfg["installation"]["uid"])
            if str(path).endswith("api-binding.json"):
                return actor_pin
            if str(path).endswith(".lease.json"):
                return lease
            if str(path).endswith(".expired.json"):
                return receipt
            self.fail("unexpected metadata path")
        scope = enroll.trial_scope(cfg, status)
        spec = {"Architecture": "amd64", "ID": sandbox, "ImageDigest": profile["ConfigDigest"], "MemoryMiB": 128, "CPUs": 1, "PIDs": 64}
        labels = {"io.tunnex.sandbox": sandbox, "io.tunnex.sandbox.spec": hashlib.sha256(json.dumps(spec, separators=(",", ":")).encode()).hexdigest()}
        prefix = cfg["installation"]["unit_prefix"]
        states = {prefix + suffix: "active" for suffix in ("-transport.service", "-actor.service", "-network.service")}
        calls = []
        behavior = {"foreign": False, "never-stop": False, "caps-changed": False, "transport-reconnected": False}
        def run(args, **kwargs):
            calls.append(tuple(args))
            if args[:2] == ["/usr/bin/systemctl", "show"]:
                if behavior["transport-reconnected"] and args[2].endswith("-transport.service") and clock[0] >= initial + timedelta(seconds=20):
                    return "active\n"
                return states[args[2]] + "\n"
            if args[:2] in (["/usr/bin/systemctl", "stop"], ["/usr/bin/systemctl", "start"]):
                self.assertTrue(args[2].endswith("-transport.service"))
                states[args[2]] = "inactive" if args[1] == "stop" else "active"
                return ""
            if args[0] == "/usr/bin/podman":
                self.assertEqual(kwargs["user"], cfg["installation"]["uid"])
                running = behavior["never-stop"] or clock[0] < initial + timedelta(seconds=40)
                return json.dumps({"id": "c" * 64 if behavior["foreign"] and not running else status["runtime_id"],
                                   "image": profile["ConfigDigest"], "labels": labels, "running": running,
                                   "pid": 123 if running else 0, "cgroup_parent": scope})
            self.fail("unexpected native fixture command")
        def read(path):
            if path == "/proc/123/cgroup":
                return "0::" + scope + "/libpod-fixture\n"
            values = {"memory.max": "268435456" if behavior["caps-changed"] else "134217728", "memory.swap.max": "0",
                      "pids.max": "64", "cpu.max": "100000 100000",
                      "cgroup.events": "populated " + ("1" if behavior["never-stop"] or clock[0] < initial + timedelta(seconds=40) else "0") + "\nfrozen 0\n"}
            need_prefix = "/sys/fs/cgroup" + scope + "/"
            self.assertTrue(path.startswith(need_prefix))
            return values[path.removeprefix(need_prefix)]
        host = SimpleNamespace(run=run, read=read)
        return cfg, bundle, status, host, metadata, clock, calls, behavior

    def test_actual_offline_observer_only_pauses_own_transport_and_uses_original_expiry(self):
        cfg, bundle, status, host, metadata, clock, calls, _ = self.native_fixture()
        expires = enroll.validate_trial_view(status, bundle, cfg, status["trial_id"])
        with mock.patch.object(enroll, "owned_metadata", side_effect=metadata):
            witness = enroll.observe_offline_expiry(cfg, status, host, now=lambda: clock[0], pause=lambda seconds: clock.__setitem__(0, clock[0] + timedelta(seconds=seconds)))
        service_changes = [call for call in calls if call[:2] in (("/usr/bin/systemctl", "stop"), ("/usr/bin/systemctl", "start"))]
        prefix = cfg["installation"]["unit_prefix"]
        self.assertEqual(service_changes, [("/usr/bin/systemctl", "stop", prefix + "-transport.service"), ("/usr/bin/systemctl", "start", prefix + "-transport.service")])
        self.assertEqual(witness["runtime_id"], status["runtime_id"])
        self.assertEqual(witness["generation"], 3)
        self.assertEqual(witness["expires_at"], status["expires_at"])
        self.assertGreaterEqual(enroll.timestamp(witness["stopped_observed_at"]), expires)
        self.assertFalse(witness["cgroup_populated"])
        self.assertEqual(witness["memory_max_bytes"], 134217728)
        self.assertFalse(any(action in call for call in calls for action in ("kill", "exec", "pull", "create", "rm")))

    def test_changed_runtime_identity_or_reconnected_transport_cannot_prove_offline(self):
        for behavior_name in ("foreign", "transport-reconnected"):
            cfg, _, status, host, metadata, clock, calls, behavior = self.native_fixture()
            behavior[behavior_name] = True
            with mock.patch.object(enroll, "owned_metadata", side_effect=metadata), self.assertRaises(enroll.Refused):
                enroll.observe_offline_expiry(cfg, status, host, now=lambda: clock[0], pause=lambda seconds: clock.__setitem__(0, clock[0] + timedelta(seconds=seconds)))
            changes = [call for call in calls if call[:2] in (("/usr/bin/systemctl", "stop"), ("/usr/bin/systemctl", "start"))]
            self.assertEqual([call[1] for call in changes], ["stop", "start"])

    def test_offline_timeout_restores_owned_transport_and_never_claims_expiry(self):
        cfg, _, status, host, metadata, clock, calls, behavior = self.native_fixture()
        behavior["never-stop"] = True
        with mock.patch.object(enroll, "owned_metadata", side_effect=metadata), self.assertRaisesRegex(enroll.Refused, "bounded_timeout"):
            enroll.observe_offline_expiry(cfg, status, host, now=lambda: clock[0], pause=lambda seconds: clock.__setitem__(0, clock[0] + timedelta(seconds=seconds)))
        self.assertEqual(calls[-2][1], "start")
        self.assertTrue(calls[-2][2].endswith("-transport.service"))

    def test_unready_wrong_generation_caps_or_extended_trial_refused_before_service_changes(self):
        for mutate in (lambda status, behavior: status.update(phase="starting"),
                       lambda status, behavior: status.update(generation=4),
                       lambda status, behavior: behavior.update({"caps-changed": True}),
                       lambda status, behavior: status.update(expires_at=(enroll.timestamp(status["created_at"]) + timedelta(seconds=901)).isoformat())):
            cfg, bundle, status, host, metadata, clock, calls, behavior = self.native_fixture()
            mutate(status, behavior)
            with mock.patch.object(enroll, "owned_metadata", side_effect=metadata), self.assertRaises(enroll.Refused):
                enroll.validate_trial_view(status, bundle, cfg, status["trial_id"])
                enroll.observe_offline_expiry(cfg, status, host, now=lambda: clock[0], pause=lambda seconds: clock.__setitem__(0, clock[0] + timedelta(seconds=seconds)))
            self.assertFalse(any(call[:2] in (("/usr/bin/systemctl", "stop"), ("/usr/bin/systemctl", "start")) for call in calls))

    def test_native_report_requires_actual_retirement_and_received_witness_proof(self):
        cfg, bundle, host = self.report_fixture()
        status = {"proof_sha256": "a" * 64, "retired_at": "2026-10-05T12:00:00Z", "offline_witness_sha256": "b" * 64}
        report = enroll.completed_trial_report(cfg, bundle, test_install.install, host, status, "00000000-0000-4000-8000-000000000005")
        self.assertEqual([check["result"] for check in report["checks"]], ["passed"] * 5)
        self.assertIn("Runner SSH observations remain runner reported", report["checks"][4]["evidence"])
        for key in ("proof_sha256", "retired_at", "offline_witness_sha256"):
            candidate = dict(status)
            del candidate[key]
            with self.assertRaises(enroll.Refused):
                enroll.completed_trial_report(cfg, bundle, test_install.install, host, candidate, "00000000-0000-4000-8000-000000000005")
