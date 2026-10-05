"""Pure safety/contract tests. No systemd, host, network or root operation."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("supervisor_fixture", HERE / "supervisor-layout-fixture.py")
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)
NONCE = "012345abcdef"
UID = 62001


class Connection:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = b""

    def recv(self, maximum):
        if not self.chunks:
            return b""
        value = self.chunks.pop(0)
        if len(value) > maximum:
            self.chunks.insert(0, value[maximum:])
        return value[:maximum]

    def sendall(self, value):
        self.sent += value


def native_receipt():
    own = fixture.names(NONCE)
    control = "/" + own["slice"] + "/" + own["guard"] + "/control"
    sandbox = "12345678-1234-4321-1234-123456789abc"
    scope = control.removesuffix("/control") + "/sandbox-" + sandbox
    return dict(version=1, status="passed", fixture_nonce=NONCE,
                actor_control_cgroup=control, sandbox_id=sandbox, scope_parent=scope,
                proved_payload_cgroup=scope + "/payload", proved_late_child_cgroup=scope + "/payload",
                caps={"memory.max": "134217728", "memory.swap.max": "0", "pids.max": "64",
                      "cpu.max": "100000 100000"}, blocked_effect_deadline=True,
                same_parent_after_generation=True, late_child_execution_blocked=True,
                provider_network_qualification=False, frozen_parent="1",
                expired_cgroup_events="populated 0\nfrozen 1\n",
                late_child_cgroup_events="populated 1\nfrozen 1\n",
                late_child_pid=123, late_child_membership_observed=True,
                late_child_outcome="observed_frozen_child", late_child_typed_sigkill=False,
                clone_into_cgroup_fd=True, clone_into_cgroup_target=scope + "/payload",
                late_child_marker_absent=True, late_child_no_oom=True,
                oom_before={boundary: {"oom": 0, "oom_kill": 0, "oom_group_kill": 0}
                            for boundary in ("scope", "actor", "aggregate")},
                oom_after={boundary: {"oom": 0, "oom_kill": 0, "oom_group_kill": 0}
                           for boundary in ("scope", "actor", "aggregate")},
                deadline_observation_lag_ms=120)


class FixtureTests(unittest.TestCase):
    def test_names_refuse_noncanonical_nonce_and_have_no_shared_slice_parent(self):
        for nonce in ("", "../x", "0" * 11, "0" * 13, "A" * 12, None):
            with self.subTest(nonce=nonce), self.assertRaises(RuntimeError):
                fixture.names(nonce)
        own = fixture.names(NONCE)
        self.assertNotIn("-", own["slice"])
        self.assertEqual(len(set(own.values())), len(own))
        self.assertEqual(fixture.state_path(NONCE), Path("/run/tunnex-supervisor-fixture-" + NONCE))

    def test_path_boundary_refuses_sibling_prefix_parent_and_dotdot(self):
        self.assertTrue(fixture.within("/owned/unit/payload", "/owned/unit"))
        for path in ("/owned/unit", "/owned/unit-foreign/payload", "/owned/unit/../foreign"):
            self.assertFalse(fixture.within(path, "/owned/unit"))

    def test_unused_virtual_slice_is_admitted_but_services_still_need_not_found(self):
        own = fixture.names(NONCE)
        virtual = dict(LoadState="loaded", ActiveState="inactive", SubState="dead",
                       ControlGroup="", FragmentPath="", DropInPaths="", MemoryMax="infinity", TasksMax="infinity")
        with patch.object(fixture.Path, "exists", return_value=False), \
             patch.object(fixture.Path, "is_symlink", return_value=False), \
             patch.object(fixture, "properties", side_effect=lambda unit: virtual if unit == own["slice"] else {"LoadState": "not-found"}):
            fixture.check_fresh_units(own)
        with patch.object(fixture.Path, "exists", return_value=False), \
             patch.object(fixture.Path, "is_symlink", return_value=False), \
             patch.object(fixture, "properties", return_value=virtual):
            with self.assertRaisesRegex(RuntimeError, "service unit collision"):
                fixture.check_fresh_units(own)

    def test_slice_admission_refuses_active_configured_and_incomplete_virtual_objects(self):
        unit = fixture.names(NONCE)["slice"]
        virtual = dict(LoadState="loaded", ActiveState="inactive", SubState="dead",
                       ControlGroup="", FragmentPath="", DropInPaths="", MemoryMax="infinity", TasksMax="infinity")
        changes = dict(ActiveState="active", SubState="running", ControlGroup="/" + unit,
                       FragmentPath="/etc/systemd/system/" + unit,
                       DropInPaths="/run/systemd/system.control/" + unit + ".d/50-MemoryMax.conf",
                       LoadState="masked", MainPID="123", MemoryMax="234881024",
                       TasksMax="256", CPUQuotaPerSecUSec="100ms")
        with patch.object(fixture.Path, "exists", return_value=False), \
             patch.object(fixture.Path, "is_symlink", return_value=False):
            for key, value in changes.items():
                with self.subTest(key=key), self.assertRaises(RuntimeError):
                    fixture.check_unused_slice(unit, dict(virtual, **{key: value}))
            with self.assertRaises(RuntimeError):
                fixture.check_unused_slice(unit, {"LoadState": "loaded"})

    def test_slice_admission_refuses_actual_cgroup_definition_and_broken_symlink(self):
        unit = fixture.names(NONCE)["slice"]
        virtual = dict(LoadState="loaded", ActiveState="inactive", SubState="dead",
                       ControlGroup="", FragmentPath="", DropInPaths="", MemoryMax="infinity", TasksMax="infinity")
        for collision in (fixture.CGROUP / unit, Path("/run/systemd/transient") / unit,
                          Path("/run/systemd/system.control") / (unit + ".d")):
            with self.subTest(collision=collision), \
                 patch.object(fixture.Path, "exists", autospec=True, side_effect=lambda path: path == collision), \
                 patch.object(fixture.Path, "is_symlink", return_value=False):
                with self.assertRaises(RuntimeError):
                    fixture.check_unused_slice(unit, virtual)
        with patch.object(fixture.Path, "exists", return_value=False), \
             patch.object(fixture.Path, "is_symlink", autospec=True, side_effect=lambda path: path == Path("/etc/systemd/system") / unit):
            with self.assertRaises(RuntimeError):
                fixture.check_unused_slice(unit, virtual)

    def test_binding_has_immutable_original_deadline_and_digest(self):
        lease = fixture.binding(NONCE, "after", 1700000000.25)
        same = fixture.binding(NONCE, "after", 1700000000.25)
        self.assertEqual(lease, same)
        self.assertNotEqual(lease["spec_hash"], fixture.binding(NONCE, "after", 1700000001.25)["spec_hash"])
        for value in (float("nan"), float("inf"), True, "1700000000"):
            with self.assertRaises(RuntimeError):
                fixture.binding(NONCE, "after", value)

    def test_holder_waits_past_root_executor_for_two_stable_unprivileged_sleep_samples(self):
        own = fixture.names(NONCE)
        pin = dict(path="/usr/bin/sleep", sha256="1" * 64)
        final = dict(pid=123, start_ticks=456, uid=UID, gid=UID,
                     cgroup="/" + own["slice"] + "/" + own["holder"], state="S")
        sampled = []
        def polling(predicate, seconds, _description):
            self.assertEqual(seconds, 3)
            for _ in range(4):
                value = predicate()
                sampled.append(value)
                if value:
                    return value
            raise RuntimeError("timed out")
        def entry(args, **kwargs):
            self.assertLessEqual(kwargs["timeout"], 3)
            return 0, own["user"] + (":x:" + str(UID) + ":" + str(UID) + ":/nonexistent:/usr/sbin/nologin\n"
                                      if args[1] == "passwd" else ":x:" + str(UID) + ":\n")
        with patch.object(fixture, "properties", return_value={"ActiveState": "active", "SubState": "running", "MainPID": "123"}), \
             patch.object(fixture, "process_identity", side_effect=[dict(final, uid=0, gid=0), final, dict(final, state="R")]), \
             patch.object(fixture.os, "readlink", side_effect=["/usr/lib/systemd/systemd-executor", "/usr/bin/sleep", "/usr/bin/sleep"]), \
             patch.object(fixture, "digest", return_value=pin["sha256"]), \
             patch.object(fixture, "execute", side_effect=entry), \
             patch.object(fixture, "wait_for", side_effect=polling):
            result = fixture.wait_holder(own, pin)
        self.assertEqual(result["uid"], UID)
        self.assertEqual(sampled[:2], [None, None])
        self.assertIsNotNone(sampled[2])

    def test_holder_invalid_uid_range_is_bounded_and_reports_actual_uid_gid(self):
        own = fixture.names(NONCE)
        bad = dict(pid=123, start_ticks=456, uid=1101, gid=1101,
                   cgroup="/" + own["slice"] + "/" + own["holder"], state="S")
        def timeout_poll(predicate, seconds, _description):
            self.assertEqual(seconds, 3)
            self.assertIsNone(predicate())
            self.assertIsNone(predicate())
            raise RuntimeError("timed out: stable holder")
        with patch.object(fixture, "properties", return_value={"ActiveState": "active", "SubState": "running", "MainPID": "123"}), \
             patch.object(fixture, "process_identity", return_value=bad), \
             patch.object(fixture.os, "readlink", return_value="/usr/bin/sleep"), \
             patch.object(fixture, "execute") as executed, \
             patch.object(fixture, "wait_for", side_effect=timeout_poll):
            with self.assertRaisesRegex(RuntimeError, '"gid":1101.*"uid":1101'):
                fixture.wait_holder(own, dict(path="/usr/bin/sleep", sha256="1" * 64))
            executed.assert_not_called()

    def test_holder_reused_pid_exec_or_foreign_getent_binding_cannot_be_admitted(self):
        own = fixture.names(NONCE)
        final = dict(pid=123, start_ticks=456, uid=UID, gid=UID,
                     cgroup="/" + own["slice"] + "/" + own["holder"], state="S")
        def entry(args, **kwargs):
            return 0, own["user"] + (":x:" + str(UID) + ":" + str(UID) + ":\n"
                                      if args[1] == "passwd" else ":x:" + str(UID) + ":\n")
        def polling(predicate, _seconds, _description):
            self.assertIsNone(predicate())
            self.assertIsNone(predicate())
            self.assertIsNone(predicate())
            raise RuntimeError("timed out")
        with patch.object(fixture, "properties", return_value={"ActiveState": "active", "SubState": "running", "MainPID": "123"}), \
             patch.object(fixture, "process_identity", side_effect=[final, dict(final, start_ticks=457), final]), \
             patch.object(fixture.os, "readlink", return_value="/usr/bin/sleep"), \
             patch.object(fixture, "digest", return_value="1" * 64), \
             patch.object(fixture, "execute", side_effect=entry), \
             patch.object(fixture, "wait_for", side_effect=polling):
            with self.assertRaises(RuntimeError):
                fixture.wait_holder(own, dict(path="/usr/bin/sleep", sha256="1" * 64))
        with patch.object(fixture, "properties", return_value={"ActiveState": "active", "SubState": "running", "MainPID": "123"}), \
             patch.object(fixture, "process_identity", return_value=final), \
             patch.object(fixture.os, "readlink", return_value="/usr/bin/sleep"), \
             patch.object(fixture, "digest", return_value="1" * 64), \
             patch.object(fixture, "execute", return_value=(0, "foreign:x:" + str(UID) + ":" + str(UID) + ":\n")):
            with self.assertRaisesRegex(RuntimeError, "UID/GID collision"):
                fixture.wait_holder(own, dict(path="/usr/bin/sleep", sha256="1" * 64))

    def test_strict_json_refuses_duplicate_and_nonfinite_fields(self):
        for raw in (b'{"version":1,"version":1}', b'{"value":NaN}', b'{"value":Infinity}'):
            with self.assertRaises(RuntimeError):
                fixture.strict_json(raw)

    def test_rpc_framing_handles_fragmentation_and_refuses_extra_truncated_oversize(self):
        self.assertEqual(fixture.read_frame(Connection([b'{"version":', b'1}', b'\n'])), {"version": 1})
        for chunks in ([b'{}\n{}\n'], [b'{}\nextra'], [b'{}'], [b'x' * 1025]):
            with self.subTest(chunks=chunks), self.assertRaises(RuntimeError):
                fixture.read_frame(Connection(chunks), 1024)
        connection = Connection([])
        fixture.send_frame(connection, {"version": 1})
        self.assertEqual(connection.sent, b'{"version":1}\n')
        with self.assertRaises(RuntimeError):
            fixture.send_frame(connection, {"large": "x" * fixture.MAX_FRAME})

    def test_status_request_refuses_bool_version_extra_keys_and_foreign_binding(self):
        manifest = {"nonce": NONCE}
        lease = fixture.binding(NONCE, "after", 1700000000)
        request = dict(version=1, operation="status", nonce=NONCE, runtime_id=lease["runtime_id"])
        self.assertTrue(fixture.status_request(request, manifest, lease))
        for altered in (dict(request, version=True), dict(request, other=1),
                        dict(request, runtime_id="0" * 64), dict(request, nonce="f" * 12)):
            self.assertFalse(fixture.status_request(altered, manifest, lease))

    def test_native_receipt_requires_real_membership_caps_and_frozen_event_proofs(self):
        self.assertEqual(fixture.validate_native_receipt(native_receipt(), NONCE), native_receipt())
        mutations = dict(fixture_nonce="f" * 12, actor_control_cgroup="/other/control",
                         scope_parent="/other", proved_late_child_cgroup="/other/payload",
                         blocked_effect_deadline=False, provider_network_qualification=True,
                         expired_cgroup_events="populated 0\nfrozen 0\n",
                         late_child_cgroup_events="populated 0\nfrozen 1\n",
                         deadline_observation_lag_ms=True)
        for key, value in mutations.items():
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                fixture.validate_native_receipt(dict(native_receipt(), **{key: value}), NONCE)

    def test_native_failure_is_detected_before_receipt_timeout_with_exit_status(self):
        failed = dict(LoadState="loaded", ActiveState="failed", SubState="failed", MainPID="0",
                      Result="exit-code", ExecMainCode="1", ExecMainStatus="1")
        with patch.object(fixture, "properties", return_value=failed), \
             patch.object(fixture.Path, "exists") as inspected:
            with self.assertRaisesRegex(RuntimeError, 'ExecMainStatus.*1'):
                fixture.native_sample(Path("owned"), fixture.names(NONCE))
            inspected.assert_not_called()
        pending = dict(failed, ActiveState="active", SubState="running", MainPID="123", Result="success")
        with patch.object(fixture, "properties", return_value=pending), \
             patch.object(fixture.Path, "exists", return_value=False):
            self.assertIsNone(fixture.native_sample(Path("owned"), fixture.names(NONCE)))
        exited = dict(pending, MainPID="0", SubState="exited")
        with patch.object(fixture, "properties", return_value=exited), \
             patch.object(fixture.Path, "exists", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "without its required receipt"):
                fixture.native_sample(Path("owned"), fixture.names(NONCE))

    def test_native_reaped_sigkill_child_requires_typed_signal_no_marker_and_no_oom(self):
        killed = dict(native_receipt(), late_child_pid=None, late_child_membership_observed=False,
                      late_child_outcome="sigkill_before_marker", proved_late_child_cgroup=None,
                      late_child_typed_sigkill=True,
                      late_child_cgroup_events="populated 0\nfrozen 1\n")
        self.assertEqual(fixture.validate_native_receipt(killed, NONCE), killed)
        for key, value in dict(late_child_typed_sigkill=False, late_child_marker_absent=False,
                               clone_into_cgroup_fd=False, late_child_membership_observed=True,
                               clone_into_cgroup_target="/foreign/payload", late_child_pid=123,
                               proved_late_child_cgroup=native_receipt()["proved_late_child_cgroup"],
                               late_child_outcome="signal: killed",
                               late_child_cgroup_events="populated 1\nfrozen 1\n").items():
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                fixture.validate_native_receipt(dict(killed, **{key: value}), NONCE)
        for boundary in ("scope", "actor", "aggregate"):
            altered = dict(killed, oom_after={key: dict(value) for key, value in killed["oom_after"].items()})
            altered["oom_after"][boundary]["oom_kill"] = 1
            with self.subTest(boundary=boundary), self.assertRaises(RuntimeError):
                fixture.validate_native_receipt(altered, NONCE)

    def test_native_late_child_refuses_missing_or_malformed_oom_and_invented_live_pid(self):
        original = native_receipt()
        for changed in (dict(original, late_child_pid=0),
                        dict(original, late_child_membership_observed=False),
                        dict(original, oom_before={}),
                        dict(original, late_child_marker_absent=False)):
            with self.assertRaises(RuntimeError):
                fixture.validate_native_receipt(changed, NONCE)
        malformed = dict(original, oom_before={key: dict(value) for key, value in original["oom_before"].items()})
        malformed["oom_before"]["scope"]["oom_kill"] = False
        with self.assertRaises(RuntimeError):
            fixture.validate_native_receipt(malformed, NONCE)

    def test_native_diagnostics_capture_only_bounded_tail_even_if_unit_query_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "guard").mkdir()
            raw = b"earlier\n" * 20000 + b"actual failure here\n"
            (root / "guard/native-test-output.txt").write_bytes(raw)
            with patch.object(fixture, "native_unit_state", side_effect=RuntimeError("manager query timed out")):
                result = fixture.native_diagnostics(root, fixture.names(NONCE), os.geteuid())
            self.assertEqual(result["output_size_bytes"], len(raw))
            self.assertEqual(result["tail_size_bytes"], fixture.MAX_FRAME)
            self.assertTrue(result["output_truncated"])
            self.assertEqual(result["stdout_stderr_tail"], raw[-fixture.MAX_FRAME:].decode())
            self.assertIn("manager query timed out", result["unit_query_error"])

    def test_native_diagnostics_missing_log_is_explicit_and_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(fixture, "native_unit_state", return_value={"Result": "exit-code"}):
            root = Path(temporary)
            (root / "guard").mkdir()
            self.assertEqual(fixture.native_diagnostics(root, fixture.names(NONCE), os.geteuid())["output_state"], "absent")
            target = root / "unrelated"
            target.write_bytes(b"unrelated contents")
            (root / "guard/native-test-output.txt").symlink_to(target)
            with self.assertRaises(OSError):
                fixture.native_diagnostics(root, fixture.names(NONCE), os.geteuid())

    def test_guard_only_cli_requires_approved_root_run_role(self):
        for args in (["fixture", "--guard-only"], ["fixture", "--guard-only", "--inspect"]):
            with patch.object(fixture.sys, "argv", args):
                with self.assertRaisesRegex(RuntimeError, "guard-only requires"):
                    fixture.main()

    def test_cgroup_write_refuses_ancestor_other_fields_before_open(self):
        with patch.object(fixture.os, "open") as opened:
            for target, field in (("/else", "cgroup.procs"), ("/owned/../else", "cgroup.kill"),
                                  ("/owned/child", "cgroup.controllers")):
                with self.assertRaises(RuntimeError):
                    fixture.cgroup_write("/owned", target, field, 1)
            opened.assert_not_called()

    def test_actual_aggregate_cpu_memory_swap_and_tasks_are_required(self):
        expected = {"memory.max": str(224 * fixture.MIB), "memory.swap.max": "0",
                    "pids.max": "256", "cpu.max": "10000 100000"}
        with patch.object(fixture, "cgroup_read", side_effect=lambda _path, key: expected[key]):
            self.assertEqual(fixture.aggregate_proof("/owned")["cpu"], "10000 100000")
        for key, wrong in (("cpu.max", "max 100000"), ("memory.max", "max"),
                           ("memory.swap.max", "1"), ("pids.max", "257")):
            altered = dict(expected, **{key: wrong})
            with patch.object(fixture, "cgroup_read", side_effect=lambda _path, item: altered[item]):
                with self.assertRaises((ValueError, RuntimeError)):
                    fixture.aggregate_proof("/owned")

    def test_cleanup_refuses_foreign_cgroup_before_any_mutation(self):
        own = fixture.names(NONCE)
        calls = []
        def props(unit):
            return {"MainPID": "0", "ControlGroup": "/system.slice/foreign.service"
                    if unit == own["actor"] else ""}
        with patch.object(fixture, "properties", side_effect=props), \
             patch.object(fixture, "manager", side_effect=lambda *args, **kw: calls.append(args)):
            with self.assertRaises(RuntimeError):
                fixture.cleanup_nonce(NONCE)
        self.assertEqual(calls, [])

    def test_partial_and_repeated_cleanup_keeps_holder_until_owned_children_gone(self):
        own = fixture.names(NONCE)
        stops, mutations = [], []
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(fixture, "STATE_PARENT", Path(temporary)), \
             patch.object(fixture, "CGROUP", Path(temporary) / "cgroup"), \
             patch.object(fixture, "properties", return_value={"MainPID": "0", "ControlGroup": ""}), \
             patch.object(fixture, "stop_owned_unit", side_effect=lambda unit, _own, **kw: stops.append(unit)), \
             patch.object(fixture, "manager", side_effect=lambda *args, **kw: mutations.append(args)):
            fixture.cleanup_nonce(NONCE)
            fixture.cleanup_nonce(NONCE)
        once = [own[key] for key in ("front", "before", "actor", "crash", "guard", "holder", "watchdog")]
        self.assertEqual(stops, once * 2)
        self.assertTrue(all(args[0] in ("reset-failed", "stop", "revert") for args in mutations))

    def test_failed_child_cleanup_retains_holder_and_watchdog(self):
        own, stops = fixture.names(NONCE), []
        def stop(unit, _own, **kwargs):
            stops.append(unit)
            if unit == own["actor"]:
                raise RuntimeError("retained child")
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(fixture, "STATE_PARENT", Path(temporary)), \
             patch.object(fixture, "properties", return_value={"MainPID": "0", "ControlGroup": ""}), \
             patch.object(fixture, "stop_owned_unit", side_effect=stop), \
             patch.object(fixture, "manager") as manager:
            with self.assertRaisesRegex(RuntimeError, "holder/watchdog retained"):
                fixture.cleanup_nonce(NONCE)
            manager.assert_not_called()
        self.assertNotIn(own["holder"], stops)
        self.assertNotIn(own["watchdog"], stops)

    def test_watchdog_cleanup_retires_children_before_requesting_final_slice_stop(self):
        own, stops, mutations = fixture.names(NONCE), [], []
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(fixture, "STATE_PARENT", Path(temporary)), \
             patch.object(fixture, "properties", return_value={"MainPID": "0", "ControlGroup": ""}), \
             patch.object(fixture, "stop_owned_unit", side_effect=lambda unit, _own, **kw: stops.append(unit)), \
             patch.object(fixture, "manager", side_effect=lambda *args, **kw: mutations.append(args)):
            fixture.cleanup_nonce(NONCE, watchdog=True)
        self.assertNotIn(own["watchdog"], stops)
        self.assertNotIn(("stop", own["slice"]), mutations)
        self.assertEqual(stops[-1], own["holder"])
        self.assertEqual(mutations[-1], ("stop", "--no-block", own["slice"]))

    def test_stale_front_pid_or_reused_identity_cannot_satisfy_restart(self):
        lease = fixture.binding(NONCE, "after", 1700000000)
        identity = dict(pid=123, start_ticks=456, uid=UID, gid=UID,
                        cgroup="/tnxsf" + NONCE + ".slice/front.service", state="S")
        observation = dict(lease, front=identity, observed_at=time.time())
        manifest = dict(names=fixture.names(NONCE), uid=UID, slice_cgroup="/tnxsf" + NONCE + ".slice")
        with patch.object(fixture.Path, "exists", return_value=True), \
             patch.object(fixture, "read_json", return_value=observation), \
             patch.object(fixture, "properties", return_value={"ActiveState": "active", "MainPID": "123"}), \
             patch.object(fixture, "process_identity", return_value=dict(identity, start_ticks=457)), \
             patch.object(fixture, "validate_observation") as validated:
            self.assertIsNone(fixture.fresh_front_sample(Path("observation"), lease, manifest, 123))
            self.assertIsNone(fixture.fresh_front_sample(Path("observation"), lease, manifest, 122))
            validated.assert_not_called()

    def test_exact_native_stdin_receiver_rejects_short_long_or_wrong_digest(self):
        cases = ((b"abc", 3, hashlib.sha256(b"abc").hexdigest(), True),
                 (b"ab", 3, hashlib.sha256(b"abc").hexdigest(), False),
                 (b"abcd", 3, hashlib.sha256(b"abc").hexdigest(), False),
                 (b"abc", 3, "0" * 64, False))
        for raw, size, sha, passed in cases:
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as temporary:
                read_fd, write_fd = os.pipe()
                os.write(write_fd, raw)
                os.close(write_fd)
                with os.fdopen(read_fd, "rb") as stream, \
                     patch.object(fixture.sys, "stdin", stream), \
                     patch.object(fixture, "MUTATION_DEADLINE", time.monotonic() + 60):
                    target = Path(temporary) / "guard.test"
                    if passed:
                        fixture.receive_native(target, dict(size_bytes=size, sha256=sha))
                        self.assertEqual(target.read_bytes(), raw)
                        self.assertEqual(target.stat().st_mode & 0o777, 0o555)
                    else:
                        with self.assertRaises(RuntimeError):
                            fixture.receive_native(target, dict(size_bytes=size, sha256=sha))

    def test_watchdog_is_first_admitted_mutation_and_failure_never_starts_other_resources(self):
        calls = []
        def failed_first(unit, _slice, props, command):
            calls.append((unit, props, command))
            raise RuntimeError("watchdog admission failed")
        pins = dict(tools={}, native_test=dict(sha256="0" * 64, size_bytes=10))
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(fixture, "STATE_PARENT", Path(temporary)), \
             patch.object(fixture.secrets, "token_hex", return_value=NONCE), \
             patch.object(fixture, "verify_pins", return_value=pins), \
             patch.object(fixture, "admission", return_value={"protected": {}}), \
             patch.object(fixture, "properties", return_value={"LoadState": "not-found"}), \
             patch.object(fixture, "execute", return_value=(2, "")), \
             patch.object(fixture, "transient", side_effect=failed_first), \
             patch.object(fixture, "cleanup") as cleanup, \
             patch.object(fixture.sys, "stdout", io.StringIO()):
            with self.assertRaises(RuntimeError):
                fixture.run_fixture(Path("pins.json"), "0" * 64)
            cleanup.assert_called_once_with(NONCE)
            self.assertEqual(list(Path(temporary).iterdir()), [])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], fixture.names(NONCE)["watchdog"])
        self.assertIn("--watchdog", calls[0][2])


if __name__ == "__main__":
    unittest.main()
