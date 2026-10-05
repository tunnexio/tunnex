"""Mocked OpenSSH boundary tests; never connect to any host."""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("sandbox_scp_roundtrip", Path(__file__).with_name("scp_roundtrip.py"))
scp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scp)
CFG = scp.Config("192.0.2.27", "fixtureuser", "/nonexistent/private/.ssh/known hosts",
                 "/nonexistent/private/.ssh/key", pr_number=123)
REMOTE = "/tmp/tunnex-scp-roundtrip.abcdefghijkl"


class FakeOpenSSH:
    def __init__(self, *, fail=None, timeout=None, remote_output=None, corrupt_hash=False,
                 corrupt_download=False, oversized_download=False, symlink_download=False):
        self.calls = []
        self.upload = b""
        self.fail = fail
        self.timeout = timeout
        self.remote_output = remote_output
        self.corrupt_hash = corrupt_hash
        self.corrupt_download = corrupt_download
        self.oversized_download = oversized_download
        self.symlink_download = symlink_download

    def __call__(self, args, **options):
        self.calls.append((args, options))
        if args[0] == "ssh":
            command = args[-1]
            if "mktemp -d" in command:
                stage, output = "create_directory", self.remote_output if self.remote_output is not None else (REMOTE + "\n").encode()
            elif command.startswith("sha256sum < "):
                stage = "remote_hash"
                checksum = "0" * 64 if self.corrupt_hash else hashlib.sha256(self.upload).hexdigest()
                output = (checksum + "  -\n").encode()
            elif "\nrmdir -- " in command:
                stage, output = "cleanup", b""
            else:
                raise AssertionError("unexpected mocked SSH operation")
        elif args[0] == "scp":
            if "@" in args[-1]:
                stage, output = "upload", b""
                if self.fail != stage and self.timeout != stage:
                    self.upload = Path(args[-2]).read_bytes()
            else:
                stage, output = "download", b""
                if self.fail != stage and self.timeout != stage:
                    target = Path(args[-1])
                    if self.symlink_download:
                        target.symlink_to(CFG.identity)
                    else:
                        raw = b"!" + self.upload[1:] if self.corrupt_download else self.upload
                        target.write_bytes(raw + b"!" if self.oversized_download else raw)
        else:
            raise AssertionError("non-OpenSSH command attempted")
        if self.timeout == stage:
            raise subprocess.TimeoutExpired(args, options["timeout"])
        return SimpleNamespace(returncode=23 if self.fail == stage else 0,
                               stdout=b"private raw log" if self.fail == stage else output)


class ScpRoundtripTests(unittest.TestCase):
    def test_exact_roundtrip_uses_only_synthetic_files_and_existing_key_references(self):
        transport = FakeOpenSSH()
        result = scp.run_roundtrip(CFG, transport)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["uploaded_sha256"], result["payload_sha256"])
        self.assertEqual(result["downloaded_sha256"], result["payload_sha256"])
        self.assertEqual(len(transport.upload), CFG.payload_bytes)
        self.assertEqual(len(transport.calls), 5)
        for args, options in transport.calls:
            self.assertEqual(args[args.index("-F") + 1], "/dev/null")
            self.assertEqual(args[args.index("-i") + 1], CFG.identity)
            for expected in ("StrictHostKeyChecking=yes", 'UserKnownHostsFile="' + CFG.known_hosts + '"',
                             "GlobalKnownHostsFile=/dev/null", "KnownHostsCommand=none", "UpdateHostKeys=no",
                             "BatchMode=yes", "PasswordAuthentication=no", "ForwardAgent=no",
                             "ClearAllForwardings=yes", "ProxyCommand=none", "ProxyJump=none"):
                self.assertIn(expected, args)
            self.assertEqual(options, {"stdin": subprocess.DEVNULL, "stdout": subprocess.PIPE,
                                       "stderr": subprocess.DEVNULL, "timeout": CFG.timeout, "check": False})
        for filename in (transport.calls[1][0][-2], transport.calls[3][0][-1]):
            self.assertFalse(Path(filename).exists(), "local synthetic files retained")
        public = json.dumps(result)
        for private in (CFG.target, CFG.user, CFG.known_hosts, CFG.identity, REMOTE, "private raw log"):
            self.assertNotIn(private, public)

    def test_cleanup_is_only_the_allocated_payload_and_empty_directory(self):
        transport = FakeOpenSSH()
        scp.run_roundtrip(CFG, transport)
        cleanup = transport.calls[-1][0][-1]
        self.assertEqual(cleanup, "set -eu\nrm -f -- " + REMOTE + "/payload.bin\nrmdir -- " + REMOTE)
        self.assertNotIn("rm -r", cleanup)
        self.assertNotIn("*", cleanup)
        self.assertNotIn("sudo", cleanup)

    def test_default_plan_never_opens_credentials_or_invokes_commands(self):
        output = io.StringIO()
        with patch.object(scp.subprocess, "run") as run, patch.object(Path, "read_bytes") as read, \
             patch.object(Path, "stat") as metadata, contextlib.redirect_stdout(output):
            code = scp.main(["--target", CFG.target, "--user", CFG.user, "--known-hosts", CFG.known_hosts,
                             "--identity", CFG.identity])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["status"], "not_run")
        run.assert_not_called()
        read.assert_not_called()
        metadata.assert_not_called()
        self.assertNotIn(CFG.identity, output.getvalue())

    def test_explicit_execution_requires_recorded_existing_pr_before_commands(self):
        transport = FakeOpenSSH()
        with self.assertRaises(scp.Refused):
            scp.run_roundtrip(CFG._replace(pr_number=None), transport)
        self.assertEqual(transport.calls, [])

    def test_identity_is_optional_and_no_file_is_inspected(self):
        with patch.object(Path, "read_bytes") as read, patch.object(Path, "stat") as metadata:
            cfg = scp.validated(CFG._replace(identity=None))
            self.assertNotIn("-i", scp.openssh_options(cfg))
        read.assert_not_called()
        metadata.assert_not_called()

    def test_invalid_arguments_are_refused_before_opening_or_connecting(self):
        variants = [CFG._replace(target="-oProxyCommand=bad"), CFG._replace(target="host; command"),
                    CFG._replace(target="user@host"), CFG._replace(target="::1%interface"),
                    CFG._replace(user="user; command"), CFG._replace(user=None),
                    CFG._replace(known_hosts="relative"), CFG._replace(identity="/key\ncommand"),
                    CFG._replace(known_hosts="/path/%h"), CFG._replace(known_hosts="/path/$VAR"),
                    CFG._replace(identity="/path/../key"), CFG._replace(port=0), CFG._replace(port=65536),
                    CFG._replace(payload_bytes=1023), CFG._replace(payload_bytes=scp.MAX_PAYLOAD + 1),
                    CFG._replace(timeout=31), CFG._replace(timeout=True), CFG._replace(pr_number=0)]
        for cfg in variants:
            with self.subTest(cfg=cfg), self.assertRaises(scp.Refused):
                scp.run_roundtrip(cfg, lambda *_args, **_kwargs: self.fail("command attempted"))

    def test_ipv6_scp_endpoint_is_bracketed(self):
        transport = FakeOpenSSH()
        result = scp.run_roundtrip(CFG._replace(target="2001:db8::27", port=2222), transport)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(transport.calls[1][0][-1], "fixtureuser@[2001:db8::27]:" + REMOTE + "/payload.bin")
        self.assertEqual(transport.calls[1][0][transport.calls[1][0].index("-P") + 1], "2222")

    def test_untrusted_remote_paths_never_reach_scp_or_cleanup(self):
        for output in (b"/tmp/other\n", (REMOTE + "/../other\n").encode(),
                       (REMOTE + "\nsecond-path\n").encode(), (REMOTE + " ;command\n").encode(), b"\xff"):
            with self.subTest(output=output):
                transport = FakeOpenSSH(remote_output=output)
                result = scp.run_roundtrip(CFG, transport)
                self.assertEqual(result["reason"], "untrusted_remote_path")
                self.assertEqual(len(transport.calls), 1)
                self.assertEqual(result["operations"]["cleanup"]["result"], "not_run")

    def test_nonzero_exit_codes_are_preserved_and_allocated_directory_is_cleaned(self):
        for stage in scp.STAGES:
            with self.subTest(stage=stage):
                transport = FakeOpenSSH(fail=stage)
                result = scp.run_roundtrip(CFG, transport)
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["failed_stage"], stage)
                self.assertEqual(result["operations"][stage]["exit_code"], 23)
                if stage != "create_directory":
                    self.assertIn("\nrmdir -- " + REMOTE, transport.calls[-1][0][-1])
                self.assertNotIn("private raw log", json.dumps(result))

    def test_wrong_remote_hash_blocks_download_but_still_cleans(self):
        transport = FakeOpenSSH(corrupt_hash=True)
        result = scp.run_roundtrip(CFG, transport)
        self.assertEqual(result["reason"], "uploaded_hash_mismatch")
        self.assertEqual(result["operations"]["download"]["result"], "not_run")
        self.assertEqual(result["operations"]["cleanup"]["result"], "passed")

    def test_corrupt_or_oversized_download_fails_and_cleans(self):
        for option, reason in (("corrupt_download", "downloaded_hash_mismatch"),
                               ("oversized_download", "downloaded_size_mismatch"),
                               ("symlink_download", "downloaded_size_mismatch")):
            with self.subTest(option=option):
                transport = FakeOpenSSH(**{option: True})
                result = scp.run_roundtrip(CFG, transport)
                self.assertEqual(result["reason"], reason)
                self.assertEqual(result["operations"]["cleanup"]["result"], "passed")

    def test_timeout_preserves_failure_and_cleans_created_files(self):
        transport = FakeOpenSSH(timeout="upload")
        result = scp.run_roundtrip(CFG, transport)
        self.assertEqual(result["reason"], "command_timeout")
        self.assertEqual(result["operations"]["upload"], {"result": "timeout", "exit_code": None})
        self.assertEqual(result["operations"]["cleanup"]["result"], "passed")

    def test_unavailable_ssh_does_not_dump_exception_paths(self):
        with patch.object(scp.subprocess, "run", side_effect=OSError("private identity path")):
            result = scp.run_roundtrip(CFG)
        self.assertEqual(result["reason"], "command_unavailable")
        self.assertNotIn("private identity path", json.dumps(result))

    def test_oversized_control_output_is_refused_without_cleanup_of_unknown_path(self):
        transport = FakeOpenSSH(remote_output=b"x" * 4097)
        result = scp.run_roundtrip(CFG, transport)
        self.assertEqual(result["reason"], "unexpected_command_output")
        self.assertEqual(len(transport.calls), 1)

    def test_public_cli_failure_returns_nonzero(self):
        with patch.object(scp, "run_roundtrip", return_value={"status": "failed", "reason": "mocked"}), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            result = scp.main(["--target", CFG.target, "--user", CFG.user, "--known-hosts", CFG.known_hosts,
                               "--execute", "--pr-number", "123"])
        self.assertEqual(result, 1)
        self.assertEqual(json.loads(output.getvalue())["status"], "failed")


if __name__ == "__main__":
    unittest.main()
