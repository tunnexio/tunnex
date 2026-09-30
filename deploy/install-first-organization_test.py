#!/usr/bin/env python3
"""Exercise installer decisions without Docker, network or host changes."""
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest

source = Path(__file__).with_name("install.sh").read_text()
functions = source.split("# BEGIN FIRST ORGANIZATION AND GATEWAY", 1)[1].split("\n", 1)[1].split("# END FIRST ORGANIZATION AND GATEWAY", 1)[0]
url_functions = source[source.index("public_base_url_ok() {"):source.index("public_base_url_scheme() {")]


class InstallerDecisions(unittest.TestCase):
    def run_choice(self, values=None, saved=None, tail="configure_first_organization_and_gateway\nprintf '%s|%s|%s' \"$GATEWAY_PLACEMENT\" \"$FIRST_ORG_NAME\" \"$EXISTING_INSTALL\""):
        with tempfile.TemporaryDirectory(prefix="tunnex-first-org-") as folder:
            if saved is not None:
                Path(folder, ".env").write_text(saved)
            env = {k: v for k, v in os.environ.items() if not k.startswith("TUNNEX_")}
            env.update(DIR=folder, PORTABLE_CONTROL_PLANE="false", ADDR="vpn.example.com")
            env.update(values or {})
            script = "set -eu\ndie() { printf '%s' \"$*\" >&2; exit 1; }\nhave_tty() { return 1; }\ninfo() { :; }\nwarn() { :; }\n" + url_functions + functions + "\n" + tail
            return subprocess.run(["sh", "-c", script], env=env, capture_output=True, text=True, timeout=5)

    def test_default_is_separate(self):
        result = self.run_choice()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "separate|My organization|false")

    def test_older_release_keeps_manual_setup_without_silently_ignoring_requests(self):
        result = self.run_choice({"FIRST_ORG_SUPPORTED": "false"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "separate|Create in dashboard (selected release)|false")
        self.assertNotEqual(self.run_choice({"FIRST_ORG_SUPPORTED": "false", "TUNNEX_BOOTSTRAP_ORG_NAME": "Acme"}).returncode, 0)
        self.assertNotEqual(self.run_choice({"FIRST_ORG_SUPPORTED": "false", "TUNNEX_GATEWAY_PLACEMENT": "same-host", "TUNNEX_COLOCATED_GATEWAY_CONFIRM": "yes"}).returncode, 0)

    def test_same_host_needs_separate_consent(self):
        result = self.run_choice({"TUNNEX_GATEWAY_PLACEMENT": "same-host", "AUTO_CONFIRM": "true"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("explicit yes", result.stderr)

    def test_consented_same_host_keeps_name(self):
        result = self.run_choice({"TUNNEX_GATEWAY_PLACEMENT": "same-host", "TUNNEX_COLOCATED_GATEWAY_CONFIRM": "yes", "TUNNEX_BOOTSTRAP_ORG_NAME": "O'Reilly $Research"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("same-host|O'Reilly $Research|false", result.stdout)

    def test_portable_refuses_same_host(self):
        result = self.run_choice({"PORTABLE_CONTROL_PLANE": "true", "TUNNEX_GATEWAY_PLACEMENT": "same-host", "TUNNEX_COLOCATED_GATEWAY_CONFIRM": "yes"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("require Linux", result.stderr)

    def test_rerun_preserves_placement(self):
        for saved, expected in [("TUNNEX_GATEWAY_PLACEMENT=separate\n", "separate"), ("POSTGRES_USER=tunnex\n", "same-host"), ("TUNNEX_PORTABLE_CONTROL_PLANE=true\n", "separate")]:
            result = self.run_choice(saved=saved)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, expected + "|Existing organization settings preserved|true")
        self.assertNotEqual(self.run_choice({"TUNNEX_GATEWAY_PLACEMENT": "same-host"}, saved="TUNNEX_GATEWAY_PLACEMENT=separate\n").returncode, 0)
        result = self.run_choice({"TUNNEX_BOOTSTRAP_ORG_NAME": "original name"}, saved="POSTGRES_USER=tunnex\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Existing organization settings preserved", result.stdout)

    def test_name_injection_refused(self):
        for name in ["hello\nINJECTED=yes", "\x1b[2J", " " * 3, "a" * 121]:
            self.assertNotEqual(self.run_choice({"TUNNEX_BOOTSTRAP_ORG_NAME": name}).returncode, 0)

    def test_gateway_address_excludes_ports_and_loopback(self):
        for address, success in [("203.0.113.1", True), ("[2001:db8::1]", True), ("gw.example.com", True), ("gw.example.com:99", False), ("127.0.0.1", False)]:
            result = self.run_choice({"TUNNEX_GATEWAY_PLACEMENT": "same-host", "TUNNEX_COLOCATED_GATEWAY_CONFIRM": "yes", "TUNNEX_GATEWAY_ADDRESS": address})
            self.assertEqual(result.returncode == 0, success, result.stderr)

    @unittest.skipUnless(shutil.which("docker"), "Compose CLI required for dotenv parsing")
    def test_organization_name_survives_compose_parsing(self):
        encoding = next(line.strip() for line in source.splitlines() if line.strip().startswith("FIRST_ORG_DOTENV=$(printf"))
        for name in ["O'Reilly $Research", 'Office \\ LAN', 'Tail\\', 'Quote\\\'test', '"Quoted" organization', 'मेरी संस्था']:
            encoded = subprocess.run(["sh", "-c", encoding + '\nprintf "%s" "$FIRST_ORG_DOTENV"'], env=dict(os.environ, FIRST_ORG_NAME=name), capture_output=True, text=True, check=True).stdout
            with tempfile.TemporaryDirectory(prefix="tunnex-org-quoting-") as folder:
                Path(folder, ".env").write_text('TUNNEX_BOOTSTRAP_ORG_NAME="' + encoded + '"\n')
                Path(folder, "compose.yml").write_text('services:\n  check:\n    image: scratch\n')
                result = subprocess.run(["docker", "compose", "-p", "tunnex_bootstrap_quote_test", "--env-file", folder + "/.env", "-f", folder + "/compose.yml", "config", "--environment"], capture_output=True, text=True, check=True)
                actual = next(line.partition("=")[2] for line in result.stdout.splitlines() if line.startswith("TUNNEX_BOOTSTRAP_ORG_NAME="))
                self.assertEqual(actual, name)

    def test_readiness_retries_and_refuses_liveness_only(self):
        result = self.run_choice(tail="calls=0\ntunnex_compose() { calls=$((calls + 1)); [ \"$calls\" -ge 3 ]; }\nsleep() { :; }\nwait_for_local_gateway\nprintf '%s' \"$calls\"")
        self.assertEqual(result.stdout, "3")
        result = self.run_choice(tail="calls=0\ntunnex_compose() { calls=$((calls + 1)); return 1; }\nsleep() { :; }\nif wait_for_local_gateway; then exit 99; fi\nprintf '%s' \"$calls\"")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "60")


if __name__ == "__main__":
    unittest.main()
