import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("sandbox_profile", Path(__file__).with_name("profile.py"))
profile = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(profile)


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="tunnex-public-profile-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = "1" * 40
        self.descriptor = {"schema_version": 1, "source_sha": self.source, "os": "linux", "architecture": "amd64",
                           "dependency_lock_sha256": "2" * 64, "base_manifest_digest": "sha256:" + "3" * 64,
                           "archive": {"filename": profile.ARCHIVE, "sha256": "4" * 64, "bytes": 71403520},
                           "config_digest": "sha256:" + "5" * 64, "unpacked_image_bytes": 195198976,
                           "native_qualification": False, "services_started": False, "packages_installed_at_launch": False}
        artifact = lambda name, char: {"url": "https://github.com/tunnexio/tunnex/releases/download/tunnex-build-" + self.source + "/" + name,
                                      "sha256": char * 64}
        self.distribution = {"schema_version": 1, "source_sha": self.source, "repository": "tunnexio/tunnex",
                             "release_tag": "tunnex-build-" + self.source, "os": "linux", "api_editions": ["open", "enterprise"],
                             "bootstrap_script": artifact("enroll.py", "6"),
                             "bundles": {"amd64": artifact("tunnex-sandbox-linux-amd64.tar.gz", "7"),
                                         "arm64": artifact("tunnex-sandbox-linux-arm64.tar.gz", "8")},
                             "installer_architectures": ["amd64"], "native_runtime_qualification": False,
                             "workload_images_built": True, "workload_image_delivery": artifact("workload-image.json", "9")}
        self.options = SimpleNamespace(distribution=str(self.root / "distribution.json"), distribution_sha256="",
                                       workload_descriptor=str(self.root / "workload-image.json"), source_sha=self.source, edition="open",
                                       org_id="00000000-0000-4000-8000-000000000001",
                                       gateway_node_id="00000000-0000-4000-8000-000000000002", gateway_container_id="a" * 64,
                                       gateway_image_digest="sha256:" + "b" * 64, gateway_interface="wg0",
                                       controller_listen="10.1.0.3:9443", controller_url="https://10.1.0.3:9443",
                                       controller_server_name="controller.example.invalid", controller_uri="spiffe://tunnex/controller/scoped",
                                       runner_uri="spiffe://tunnex/runner/scoped", api_url="https://api.example.invalid",
                                       controller_certificate_file="/etc/tunnex/controller-cert.pem",
                                       controller_private_key_file="/not-readable/controller-key.pem",
                                       runner_ca_file=str(self.root / "public-ca.pem"), runner_ca_key_file="/not-readable/ca-key.pem",
                                       api_ca_file=None, profile_name="Minimal Ubuntu terminal", terminal_gateway_node_id=None,
                                       terminal_gateway_endpoint=None, runtime_gateway_endpoint=None)
        # Public syntax fixture; API startup owns full X.509 CA validation.
        (self.root / "public-ca.pem").write_text("-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n")
        self.publish()

    def publish(self):
        raw = json.dumps(self.descriptor).encode()
        Path(self.options.workload_descriptor).write_bytes(raw)
        self.distribution["workload_image_delivery"]["sha256"] = hashlib.sha256(raw).hexdigest()
        raw = json.dumps(self.distribution).encode()
        Path(self.options.distribution).write_bytes(raw)
        self.options.distribution_sha256 = hashlib.sha256(raw).hexdigest()

    def test_pins_and_org_scoped_identity_derived_without_reading_private_references(self):
        calls = []
        original = profile.public_bytes
        def read(path, *args):
            calls.append(str(path))
            return original(path, *args)
        with mock.patch.object(profile, "public_bytes", side_effect=read):
            config = profile.assemble(self.options)
        self.assertEqual(calls, [self.options.distribution, self.options.workload_descriptor, self.options.runner_ca_file])
        binding, enrollment = config["Binding"], config["Enrollment"]
        image, runtime_profile = enrollment["Profile"]["install"]["images"][0], binding["Profiles"][0]
        self.assertEqual(runtime_profile["TemplateID"], image["template_id"])
        self.assertEqual(runtime_profile["ConfigDigest"], self.descriptor["config_digest"])
        self.assertEqual(runtime_profile["QualificationEvidence"], image["qualification_evidence"])
        self.assertTrue(image["qualification_evidence"].startswith("pending-native-qualification:"))
        self.assertEqual(image["sha256"], self.descriptor["archive"]["sha256"])
        self.assertTrue(image["url"].endswith("/" + profile.ARCHIVE))
        self.assertEqual(binding["Admission"], "organization")
        self.assertEqual((binding["MemoryMiB"], binding["CPUs"], runtime_profile["PIDs"], binding["MaxTTLSeconds"]), (128, 1, 64, 900))
        for name in ("CreatorID", "TerminalDeviceID", "DevReservation"):
            self.assertNotIn(name, binding)
        for name in ("QualifiedRunnerSPKIHash", "HostQualificationEvidence", "ModuleState", "DistributionFile"):
            self.assertNotIn(name, enrollment)
        self.assertEqual(config["Remote"]["PrivateKeyFile"], self.options.controller_private_key_file)
        self.assertEqual(config, profile.assemble(self.options))

    def test_distribution_and_descriptor_are_independently_hash_source_pinned(self):
        for field, value in (("source_sha", "f" * 40), ("distribution_sha256", "f" * 64)):
            options = copy.copy(self.options)
            setattr(options, field, value)
            with self.assertRaises(profile.Refused):
                profile.assemble(options)
        Path(self.options.workload_descriptor).write_text("{}")
        with self.assertRaises(profile.Refused):
            profile.assemble(self.options)

    def test_generated_public_install_plan_passes_actual_machine_schema(self):
        import test_install
        spec = importlib.util.spec_from_file_location("profile_machine_enroll", Path(__file__).with_name("enroll.py"))
        enroll = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(enroll)
        config = profile.assemble(self.options)
        install = config["Enrollment"]["Profile"]["install"]
        enrollment_id = "00000000-0000-4000-8000-000000000030"
        bundle = {"enrollment_id": enrollment_id, "profile_id": config["Enrollment"]["Profile"]["id"],
                  "binding_sha256": "c" * 64, "certificate": "synthetic public leaf",
                  "runner_ca": config["Enrollment"]["RunnerCA"], "api_ca": "", "install": install}
        staging = self.root / "machine-staging"
        (staging / "identity").mkdir(parents=True)
        identity = staging / "identity/identity.json"
        identity.write_text(json.dumps({"probe_public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB"}))
        identity.chmod(0o600)
        layout = json.loads(Path(__file__).with_name("example.json").read_text())["installation"]
        options = SimpleNamespace(enrollment_id=enrollment_id, edition="open", source_sha=self.source,
                                  api_url=self.options.api_url, bundle_url=install["bundle"]["url"],
                                  bundle_sha256=install["bundle"]["sha256"])
        machine = enroll.installer_config(bundle, options, staging, layout)
        self.assertEqual(test_install.install.validate(machine), machine)
        self.assertEqual(machine["images"][0]["config_digest"], config["Binding"]["Profiles"][0]["ConfigDigest"])

    def test_unsupported_qualifications_architecture_services_sizes_and_extra_fields_refused(self):
        for key, value in (("architecture", "arm64"), ("source_sha", "f" * 40), ("native_qualification", True),
                           ("services_started", True), ("packages_installed_at_launch", True),
                           ("unpacked_image_bytes", 2 << 30), ("unexpected", "value")):
            saved = copy.deepcopy(self.descriptor)
            self.descriptor[key] = value
            self.publish()
            with self.assertRaises(profile.Refused, msg=key):
                profile.assemble(self.options)
            self.descriptor = saved

    def test_duplicate_json_unsafe_permissions_symlink_and_private_pem_refused(self):
        with self.assertRaises(profile.Refused):
            profile.public_json('{"a":1,"a":2}')
        ca = Path(self.options.runner_ca_file)
        ca.chmod(0o666)
        with self.assertRaises(profile.Refused):
            profile.assemble(self.options)
        ca.chmod(0o644)
        ca.write_text("-----BEGIN PRIVATE KEY-----\nsynthetic invalid input\n-----END PRIVATE KEY-----\n")
        with self.assertRaises(profile.Refused):
            profile.assemble(self.options)
        ca.unlink()
        ca.symlink_to(self.options.distribution)
        with self.assertRaises(profile.Refused):
            profile.assemble(self.options)

    def test_controller_public_network_identity_and_partial_terminal_pins_refused(self):
        for key, value in (("controller_listen", "127.0.0.1:9443"), ("controller_listen", "8.8.8.8:9443"),
                           ("controller_listen", "198.18.0.3:9443"), ("controller_server_name", "broken name"),
                           ("controller_url", "https://10.1.0.4:9443"), ("api_url", "https://api.example.invalid?token=secret"),
                           ("runner_uri", self.options.controller_uri), ("controller_private_key_file", "relative/key.pem"),
                           ("terminal_gateway_endpoint", "10.1.0.2:51820")):
            options = copy.copy(self.options)
            setattr(options, key, value)
            with self.assertRaises(profile.Refused, msg=key):
                profile.assemble(options)

    def test_remote_terminal_and_identity_changes_remain_exact(self):
        options = copy.copy(self.options)
        options.terminal_gateway_node_id = "00000000-0000-4000-8000-000000000003"
        options.terminal_gateway_endpoint = "10.1.0.2:51820"
        options.runtime_gateway_endpoint = "10.1.0.4:51820"
        config = profile.assemble(options)
        terminal, public_terminal = config["Binding"]["RemoteTerminal"], config["Enrollment"]["Profile"]["install"]["gateway"]["terminal"]
        self.assertEqual(terminal["GatewayID"], public_terminal["node_id"])
        self.assertEqual(terminal["GatewayEndpoint"], public_terminal["endpoint"])
        options.org_id = "00000000-0000-4000-8000-000000000004"
        changed = profile.assemble(options)
        self.assertNotEqual(config["Binding"]["Profiles"][0]["TemplateID"], changed["Binding"]["Profiles"][0]["TemplateID"])

    def test_output_is_private_collision_and_mutable_parent_refused(self):
        config = profile.assemble(self.options)
        output = self.root / "sandbox-runtime.json"
        profile.write_config(str(output), config)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(output.stat().st_uid, os.geteuid())
        self.assertEqual(json.loads(output.read_bytes()), config)
        with self.assertRaises(OSError):
            profile.write_config(str(output), config)
        output.unlink()
        output.symlink_to(self.options.distribution)
        with self.assertRaises(OSError):
            profile.write_config(str(output), config)
        output.unlink()
        self.root.chmod(0o777)
        with self.assertRaises(profile.Refused):
            profile.write_config(str(output), config)
        self.root.chmod(0o700)


if __name__ == "__main__":
    unittest.main()
