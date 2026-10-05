#!/usr/bin/env python3
"""Approved, bounded systemd259 synthetic fixture; never an enrolled sandbox.

Default prints the proposal. --inspect is read-only. --run requires root,
explicit approval and frozen source/native-binary/installed-tool SHA pins.
Internal roles accept only the nonce allowlist and pinned public manifest.
"""
import argparse
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import select
import shutil
import socket
import stat
import struct
import subprocess
import sys
import threading
import time

STATE_PARENT = Path("/run")
CGROUP = Path("/sys/fs/cgroup")
MIB = 1024 * 1024
HARD_SECONDS = 180
WATCHDOG_SECONDS = 140
ACCEPT_SECONDS = 120
PHASES = ("before", "after", "crash", "front", "guard")
PROTECTED = ("tunnex-sandbox-qual-worker.service",
             "tunnex-sandbox-qual-network.service",
             "tunnex-sandbox-gateway.service")
PROPERTIES = ("LoadState", "ActiveState", "SubState", "MainPID", "Result",
              "ExecMainCode", "ExecMainStatus",
              "ControlGroup", "MemoryMax", "MemorySwapMax", "TasksMax",
              "CPUQuotaPerSecUSec", "CPUQuotaPeriodUSec", "Delegate",
              "DelegateSubgroup", "KillMode", "KillSignal", "FragmentPath",
              "DropInPaths")
TOOLS = {"manager": "/usr/bin/systemctl", "run": "/usr/bin/systemd-run",
         "python": "/usr/bin/python3", "sleep": "/usr/bin/sleep",
         "mount": "/usr/bin/mount", "umount": "/usr/bin/umount",
         "getent": "/usr/bin/getent", "ip": "/usr/sbin/ip",
         "journal": "/usr/bin/journalctl"}
AGGREGATE = {"memory": 224 * MIB, "swap": 0, "pids": 256,
             "cpu": "10000 100000", "scratch": 8 * MIB}
PAYLOAD_CAPS = {"memory": 128 * MIB, "pids": 64, "cpu": "100000 100000"}
MAX_FRAME = 65536
MUTATION_DEADLINE = None
CLEANUP_DEADLINE = None


def need(condition, message):
    if not condition:
        raise RuntimeError(message)


def names(nonce):
    need(type(nonce) is str and re.fullmatch(r"[0-9a-f]{12}", nonce) is not None,
         "invalid nonce")
    # No hyphens in the slice stem: no implicit shared ancestor slice.
    stem = "tnxsf" + nonce
    return dict(slice=stem + ".slice", user=stem,
                **{role: stem + "-" + role + ".service" for role in
                   ("holder", "before", "actor", "front", "crash", "guard", "watchdog")})


def state_path(nonce):
    names(nonce)
    return STATE_PARENT / ("tunnex-supervisor-fixture-" + nonce)


def within(path, parent):
    path, parent = Path(path), Path(parent)
    if ".." in path.parts or ".." in parent.parts:
        return False
    try:
        return path != parent and bool(path.relative_to(parent).parts)
    except ValueError:
        return False


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode()


def strict_json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            need(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    def constant(_value):
        raise RuntimeError("nonfinite JSON number")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            value.update(block)
    return value.hexdigest()


def pinned_file(path, *, mode=None, limit=2 * MIB):
    info = os.lstat(path)
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0
         and not info.st_mode & 0o022 and info.st_size <= limit,
         "public pinned file ownership/type/mode/size drift")
    if mode is not None:
        need(stat.S_IMODE(info.st_mode) == mode, "pinned public file mode drift")
    return info


def pinned_directory(path):
    info = os.lstat(path)
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0
         and not info.st_mode & 0o022, "root-pinned directory drift")


def read_json(path, *, trusted=False):
    if trusted:
        pinned_file(path, mode=0o444, limit=MAX_FRAME)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_FRAME,
             "observation is not bounded regular data")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_FRAME + 1)
        need(len(raw) <= MAX_FRAME, "observation exceeds bound")
        return strict_json(raw)
    finally:
        os.close(fd)


def write_json(path, value, mode=0o600):
    path = Path(path)
    raw = canonical(value) + b"\n"
    need(len(raw) <= MAX_FRAME, "fixture output exceeds bound")
    temporary = path.with_name(path.name + "." + secrets.token_hex(6) + ".new")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
        os.replace(temporary, path)
    finally:
        os.close(fd)
        if temporary.exists():
            temporary.unlink()


def execute(args, *, timeout=5, allow_failure=False):
    need(0 < timeout <= 10, "command timeout outside fixture bound")
    if CLEANUP_DEADLINE is not None:
        timeout = min(timeout, CLEANUP_DEADLINE - time.monotonic())
        need(timeout > 0, "owned cleanup deadline elapsed")
    process = subprocess.run([str(value) for value in args], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, timeout=timeout,
                             env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    need(len(process.stdout.encode()) <= MAX_FRAME, "command output exceeded bound")
    if not allow_failure:
        need(process.returncode == 0, "fixture command failed: " + str(args[0]) +
             ": " + process.stdout[-1200:])
    return process.returncode, process.stdout


def manager(*args, **kwargs):
    return execute([TOOLS["manager"], *args], **kwargs)


def mutation_gate():
    need(MUTATION_DEADLINE is not None and time.monotonic() + 10 < MUTATION_DEADLINE,
         "fixture setup/acceptance window closed; only owned cleanup is permitted")


def properties(unit, *, timeout=5):
    _, raw = manager("show", unit, *["--property=" + item for item in PROPERTIES], timeout=timeout)
    return dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)


def check_unused_slice(unit, props):
    # PID1 synthesizes valid slice names as loaded units without a unit file.
    # Accept only that inactive virtual object, never a configured/live slice.
    need(re.fullmatch(r"tnxsf[0-9a-f]{12}\.slice", unit) is not None,
         "refused nonfixture slice admission")
    need(props.get("LoadState") in ("not-found", "loaded")
         and props.get("ActiveState", "inactive") == "inactive"
         and props.get("SubState", "dead") == "dead"
         and props.get("MainPID", "0") in ("", "0")
         and not props.get("ControlGroup", "")
         and not props.get("FragmentPath", "") and not props.get("DropInPaths", ""),
         "fixture slice is active or configured")
    if props["LoadState"] == "loaded":
        need(props.get("ActiveState") == "inactive" and props.get("SubState") == "dead"
             and props.get("MemoryMax") == "infinity" and props.get("TasksMax") == "infinity"
             and props.get("CPUQuotaPerSecUSec", "infinity") == "infinity",
             "loaded slice lacks exact inactive virtual state")
    candidates = [CGROUP / unit]
    for parent in ("/run/systemd/transient", "/run/systemd/system", "/run/systemd/system.control",
                   "/etc/systemd/system", "/etc/systemd/system.control", "/usr/lib/systemd/system"):
        candidates += [Path(parent) / unit, Path(parent) / (unit + ".d")]
    need(not any(path.exists() or path.is_symlink() for path in candidates),
         "fixture slice cgroup/runtime definition collision")


def check_fresh_units(own):
    for key, unit in own.items():
        if key == "slice":
            check_unused_slice(unit, properties(unit))
        elif key != "user":
            need(properties(unit).get("LoadState") == "not-found", "fixture service unit collision")


def protected_snapshot():
    snapshot = {unit: properties(unit) for unit in PROTECTED}
    need(all(item.get("LoadState") == "loaded" for item in snapshot.values()),
         "protected unit absent; refuse to guess its identity")
    need(snapshot[PROTECTED[0]]["ActiveState"] == "inactive"
         and snapshot[PROTECTED[0]]["MainPID"] == "0", "existing worker must remain stopped")
    need(all(snapshot[unit]["ActiveState"] == "active" for unit in PROTECTED[1:]),
         "existing helper/gateway must remain active")
    for unit, props in snapshot.items():
        fragment = Path(props["FragmentPath"])
        need(fragment in [Path(parent) / unit for parent in
                          ("/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system")],
             "protected unit fragment path drift")
        pinned_file(fragment)
        props["fragment_sha256"] = digest(fragment)
        if props["MainPID"] != "0":
            identity = process_identity(int(props["MainPID"]))
            props["process"] = {key: value for key, value in identity.items() if key != "state"}
    return snapshot


def pin_tools():
    result = {}
    for key, path in TOOLS.items():
        resolved = Path(path).resolve(strict=True)
        pinned_file(resolved, limit=128 * MIB)
        result[key] = {"path": str(resolved), "sha256": digest(resolved)}
    return result


def verify_pins(path, source, expected_sha):
    pinned_directory(Path(path).parent)
    pins = read_json(path, trusted=True)
    need(re.fullmatch(r"[0-9a-f]{64}", expected_sha or "") is not None,
         "explicit frozen source SHA required")
    pinned_file(source, mode=0o444)
    pinned_directory(Path(source).parent)
    need(pins.get("version") == 1 and pins.get("source_sha256") == expected_sha
         and digest(source) == expected_sha, "frozen source pin drift")
    need(pins.get("tools") == pin_tools(), "installed tool pins drift")
    native = pins.get("native_test", {})
    need(set(native) == {"sha256", "size_bytes"}
         and re.fullmatch(r"[0-9a-f]{64}", native.get("sha256", "")) is not None
         and type(native.get("size_bytes")) is int and 0 < native["size_bytes"] <= 7 * MIB,
         "bounded frozen native test SHA/size required")
    # One binary streamed directly into tmpfs; no duplicate host staging copy.
    need(native["size_bytes"] + 2 * os.stat(source).st_size + os.stat(path).st_size
         + MIB <= AGGREGATE["scratch"], "total artifact/state allowance exceeds8MiB")
    return pins


def verify_manifest(path):
    path = Path(path)
    manifest = read_json(path, trusted=True)
    need(manifest.get("version") == 2, "manifest version drift")
    expected = names(manifest["nonce"])
    root = state_path(manifest["nonce"])
    need(path == root / "public/manifest.json" and manifest["names"] == expected
         and manifest["state"] == str(root), "manifest unit/path allowlist drift")
    need(manifest["slice_cgroup"] == "/" + expected["slice"]
         and manifest["aggregate"] == AGGREGATE, "fixture cap/cgroup drift")
    need(type(manifest["uid"]) is int and 61184 <= manifest["uid"] <= 65519
         and type(manifest["gid"]) is int and 61184 <= manifest["gid"] <= 65519,
         "synthetic DynamicUser identity drift")
    start, deadline = manifest["started_at"], manifest["hard_deadline"]
    need(type(start) in (int, float) and math.isfinite(start)
         and type(deadline) in (int, float) and deadline == start + HARD_SECONDS,
         "fixture absolute deadline drift")
    for directory in (root, root / "public"):
        pinned_directory(directory)
    script = root / "public/fixture.py"
    pinned_file(script, mode=0o444)
    need(digest(script) == manifest["script_sha256"], "fixture source pin drift")
    need(manifest["tools"] == pin_tools(), "installed tool pin drift")
    native = manifest["native_test"]
    need(native["path"] == str(root / "public/guard.test"), "native test path drift")
    pinned_file(native["path"], mode=0o555, limit=128 * MIB)
    need(os.stat(native["path"]).st_size == native["size_bytes"]
         and digest(native["path"]) == native["sha256"], "native test pin drift")
    return manifest


def process_identity(pid):
    need(type(pid) is int and pid > 1, "invalid process identifier")
    proc = Path("/proc") / str(pid)
    raw = (proc / "stat").read_text()
    after_name = raw[raw.rindex(")") + 2:].split()
    status = (proc / "status").read_text()
    uid = int(re.search(r"^Uid:\s+\d+\s+(\d+)", status, re.M).group(1))
    gid = int(re.search(r"^Gid:\s+\d+\s+(\d+)", status, re.M).group(1))
    unified = [row[3:] for row in (proc / "cgroup").read_text().splitlines()
               if row.startswith("0::")]
    need(len(unified) == 1, "process lacks one unified cgroup")
    return dict(pid=pid, start_ticks=int(after_name[19]), uid=uid, gid=gid,
                cgroup=unified[0], state=after_name[0])


def wait_holder(own, sleep_pin, seconds=3):
    # systemd can publish MainPID while its executor still runs as root. Admit
    # only two consecutive observations of the final unprivileged sleep exec.
    need(0 < seconds <= 3, "holder startup wait outside bounded fixture scope")
    expected_cgroup = "/" + own["slice"] + "/" + own["holder"]
    deadline = time.monotonic() + seconds
    last, previous = {}, None
    def ready():
        nonlocal previous
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        props = properties(own["holder"], timeout=remaining)
        pid = int(props.get("MainPID", "0"))
        last.update(active=props.get("ActiveState"), sub=props.get("SubState"), pid=pid)
        if props.get("ActiveState") != "active" or props.get("SubState") != "running" or pid <= 1:
            previous = None
            return None
        try:
            identity = process_identity(pid)
            executable = os.readlink("/proc/" + str(pid) + "/exe")
        except FileNotFoundError:
            previous = None
            return None
        last.update(uid=identity["uid"], gid=identity["gid"], executable=executable)
        if not (61184 <= identity["uid"] <= 65519 and 61184 <= identity["gid"] <= 65519
                and identity["cgroup"] == expected_cgroup and executable == sleep_pin["path"]
                and identity["state"] not in ("Z", "X")):
            previous = None
            return None
        need(digest(sleep_pin["path"]) == sleep_pin["sha256"], "holder installed sleep pin drift")
        for database, identifier in (("passwd", identity["uid"]), ("group", identity["gid"])):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            code, entry = execute([TOOLS["getent"], database, identifier],
                                  timeout=remaining, allow_failure=True)
            if code != 0:
                previous = None
                return None
            fields = entry.strip().split(":")
            need(len(fields) >= 3 and fields[0] == own["user"] and int(fields[2]) == identifier
                 and (database != "passwd" or len(fields) >= 4 and int(fields[3]) == identity["gid"]),
                 "allocated DynamicUser UID/GID collision")
        current = {key: identity[key] for key in ("pid", "start_ticks", "uid", "gid", "cgroup")}
        confirmed = previous == current
        previous = current
        return identity if confirmed else None
    try:
        return wait_for(ready, seconds, "stable final DynamicUser sleep holder")
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(str(error) + "; bounded holder observation=" + canonical(last).decode()) from error


def gone(identity):
    try:
        current = process_identity(identity["pid"])
        return current["start_ticks"] != identity["start_ticks"] or current["state"] == "Z"
    except FileNotFoundError:
        return True


def binding(nonce, phase, expiry):
    names(nonce)
    need(phase in ("before", "after", "crash") and type(expiry) in (int, float)
         and math.isfinite(expiry), "invalid synthetic lease")
    runtime = hashlib.sha256((nonce + ":" + phase).encode()).hexdigest()
    spec = dict(nonce=nonce, phase=phase, runtime_id=runtime,
                expires_at=expiry, caps=PAYLOAD_CAPS)
    return dict(spec, spec_hash=hashlib.sha256(canonical(spec)).hexdigest())


def validate_observation(observation, lease, uid, slice_cgroup):
    need(type(observation) is dict and all(observation.get(key) == lease[key] for key in lease),
         "runtime/lease/spec binding drift")
    need(type(uid) is int and 61184 <= uid <= 65519, "fixture identity drift")
    for key in ("actor", "payload", "conmon"):
        identity = observation[key]
        need(type(identity.get("pid")) is int and identity["pid"] > 1
             and type(identity.get("start_ticks")) is int and identity["start_ticks"] > 0
             and identity["uid"] == uid and within(identity["cgroup"], slice_cgroup),
             "process identity escaped owned fixture")
    need(observation["effective_caps"] == PAYLOAD_CAPS,
         "synthetic payload resource limits drift")
    need(re.fullmatch(r"[0-9a-f]{64}", observation.get("file_sha256", "")) is not None,
         "synthetic persistence digest missing")


def wait_for(predicate, seconds, description):
    need(0 < seconds <= 60, "poll duration outside fixture bound")
    deadline = time.monotonic() + seconds
    while True:
        result = predicate()
        if result:
            return result
        need(time.monotonic() < deadline, "timed out: " + description)
        time.sleep(0.1)


def transient(unit, slice_name, props, command):
    mutation_gate()
    argv = [TOOLS["run"], "--quiet", "--unit=" + unit, "--slice=" + slice_name,
            "--property=WorkingDirectory=/", "--property=StandardOutput=null",
            "--property=StandardError=null", "--property=Restart=no",
            "--property=TimeoutStopSec=2s", "--property=MemorySwapMax=0"]
    argv += ["--property=" + key + "=" + str(value) for key, value in props.items()]
    execute([*argv, "--", *command])


def cgroup_read(path, field):
    need(Path(path).is_absolute() and ".." not in Path(path).parts, "invalid cgroup path")
    need(field in ("cgroup.procs", "cgroup.subtree_control", "cgroup.controllers",
                   "memory.max", "memory.swap.max", "pids.max", "cpu.max",
                   "cgroup.events", "cgroup.type"), "invalid cgroup field")
    return (CGROUP / path.removeprefix("/") / field).read_text().strip()


def cgroup_write(root, target, field, value):
    need(Path(root).is_absolute() and ".." not in Path(root).parts, "invalid delegated root")
    need(within(target, root) or target == root, "write escaped delegated unit")
    need(field in ("cgroup.subtree_control", "cgroup.procs", "memory.max",
                   "pids.max", "cpu.max", "cgroup.freeze", "cgroup.kill"),
         "invalid mutable cgroup field")
    file = CGROUP / target.removeprefix("/") / field
    fd = os.open(file, os.O_WRONLY | os.O_NOFOLLOW)
    try:
        raw = str(value).encode()
        need(os.write(fd, raw) == len(raw), "short cgroup write")
    finally:
        os.close(fd)


def read_frame(connection, maximum=MAX_FRAME):
    need(0 < maximum <= MAX_FRAME, "invalid RPC frame bound")
    raw = bytearray()
    while True:
        block = connection.recv(min(4096, maximum + 1 - len(raw)))
        need(bool(block), "RPC frame ended before delimiter")
        raw.extend(block)
        need(len(raw) <= maximum, "RPC frame exceeds bound")
        if b"\n" in block:
            need(raw.endswith(b"\n") and raw.count(b"\n") == 1,
                 "RPC frame has trailing/multiple values")
            return strict_json(raw)


def send_frame(connection, value):
    raw = canonical(value) + b"\n"
    need(len(raw) <= MAX_FRAME, "RPC reply exceeds bound")
    connection.sendall(raw)


def status_request(request, manifest, lease):
    return type(request) is dict and type(request.get("version")) is int and request == dict(
        version=1, operation="status", nonce=manifest["nonce"], runtime_id=lease["runtime_id"])


def receive_native(path, pin):
    """Read exactly the frozen bounded artifact directly from SSH stdin."""
    mutation_gate()
    deadline = min(time.monotonic() + 10, MUTATION_DEADLINE - 10)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    hasher, received = hashlib.sha256(), 0
    try:
        while True:
            remaining = deadline - time.monotonic()
            need(remaining > 0, "native artifact receive timed out")
            ready, _, _ = select.select([sys.stdin.fileno()], [], [], remaining)
            need(bool(ready), "native artifact receive timed out")
            block = os.read(sys.stdin.fileno(), min(65536, pin["size_bytes"] + 1 - received))
            if not block:
                break
            received += len(block)
            need(received <= pin["size_bytes"], "native artifact exceeds frozen size")
            hasher.update(block)
            pending = memoryview(block)
            while pending:
                written = os.write(fd, pending)
                need(written > 0, "native artifact write stalled")
                pending = pending[written:]
        need(received == pin["size_bytes"] and hasher.hexdigest() == pin["sha256"],
             "streamed native test SHA/size drift")
        os.fsync(fd)
        os.fchmod(fd, 0o555)
    finally:
        os.close(fd)


def actor(manifest, phase):
    uid = manifest["uid"]
    need(os.geteuid() == uid and os.getegid() == manifest["gid"], "actor identity drift")
    state = Path(manifest["state"])
    lease = read_json(state / ("public/" + phase + ".json"), trusted=True)
    key = "before" if phase == "before" else "actor" if phase == "after" else "crash"
    root = manifest["slice_cgroup"] + "/" + manifest["names"][key]
    own = process_identity(os.getpid())
    need(own["cgroup"] == root + "/control", "actor not in delegated control leaf")
    need(not cgroup_read(root, "cgroup.procs") and cgroup_read(root, "cgroup.type") == "domain",
         "delegated root must be an empty domain")
    ancestor = CGROUP / root.removeprefix("/") / "cgroup.procs"
    need(os.access(ancestor, os.W_OK), "UID cannot write migration common ancestor")
    cgroup_write(root, root, "cgroup.subtree_control", "+cpu +memory +pids")
    enabled = set(cgroup_read(root, "cgroup.subtree_control").split())
    need({"cpu", "memory", "pids"} <= enabled, "required delegated controllers absent")
    child = root + "/runtime-" + lease["runtime_id"][:16]
    (CGROUP / child.removeprefix("/")).mkdir()
    for field, value in (("memory.max", PAYLOAD_CAPS["memory"]),
                         ("pids.max", PAYLOAD_CAPS["pids"]), ("cpu.max", PAYLOAD_CAPS["cpu"])):
        cgroup_write(root, child, field, value)
    remaining = lease["expires_at"] - time.time()
    need(5 < remaining <= 60, "original synthetic lease outside bounds")
    # No self-timed payload: expiry must be caused by the actor-owned guard.
    # Ten seconds after the original lease is a synthetic process failsafe,
    # never the accepted expiry proof (which requires <=five seconds lag).
    failsafe_seconds = str(remaining + 10)
    conmon = subprocess.Popen([TOOLS["sleep"], failsafe_seconds])
    payload = subprocess.Popen([TOOLS["sleep"], failsafe_seconds])
    cgroup_write(root, child, "cgroup.procs", payload.pid)
    work = state / phase
    payload_file = work / "workspace.bin"
    with open(payload_file, "xb") as stream:
        stream.write(hashlib.sha256(lease["runtime_id"].encode()).digest() * 128)
    observation = dict(lease, actor=own, conmon=process_identity(conmon.pid),
                       payload=process_identity(payload.pid), running=True,
                       effective_caps={"memory": int(cgroup_read(child, "memory.max")),
                                       "pids": int(cgroup_read(child, "pids.max")),
                                       "cpu": cgroup_read(child, "cpu.max")},
                       delegated_root=root, root_empty=True, root_type="domain",
                       common_ancestor_writable=True, enabled_controllers=sorted(enabled),
                       file_sha256=digest(payload_file), observed_at=time.time(), rpc_count=0)
    need(observation["payload"]["cgroup"] == child
         and observation["conmon"]["cgroup"] == root + "/control",
         "actual payload/keeper placement drift")
    lock = threading.Lock()
    def expiry_guard():
        time.sleep(max(0, lease["expires_at"] - time.time()))
        attempted = time.time()
        errors = []
        for field in ("cgroup.freeze", "cgroup.kill"):
            try:
                cgroup_write(root, child, field, 1)
            except Exception as error:
                errors.append(str(error))
        # Conmon/namespace keeper is deliberately outside the payload subtree.
        # Explicitly retire it; actor failure separately exercises manager kill.
        if conmon.poll() is None:
            conmon.kill()
        for process in (payload, conmon):
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                errors.append("synthetic child did not stop")
        try:
            wait_for(lambda: "frozen 1" in cgroup_read(child, "cgroup.events")
                     and "populated 0" in cgroup_read(child, "cgroup.events"),
                     2, "asynchronous synthetic child freeze and retirement")
        except Exception as error:
            errors.append(str(error))
        with lock:
            observation.update(running=False, observed_at=time.time(), stopped_at=time.time(),
                               expiry_receipt=True, guard_attempted_at=attempted,
                               guard_errors=errors, child_events=cgroup_read(child, "cgroup.events"))
            write_json(work / "runtime.json", observation)
    threading.Thread(target=expiry_guard, daemon=True).start()
    socket_path = work / "actor.sock"
    need(not socket_path.exists(), "synthetic actor socket occupied")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        server.listen(4)
        server.settimeout(0.1)
        with lock:
            write_json(work / "runtime.json", observation)
        while time.time() < manifest["hard_deadline"]:
            try:
                connection, _ = server.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(1)
                _, peer_uid, _ = struct.unpack("3i", connection.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
                try:
                    request = read_frame(connection, 1024)
                except (ValueError, RuntimeError, TimeoutError):
                    request = None
                if peer_uid != uid or not status_request(request, manifest, lease):
                    send_frame(connection, {"error": "unauthorized"})
                    continue
                with lock:
                    observation["rpc_count"] += 1
                    observation["observed_at"] = time.time()
                    response = dict(observation)
                    write_json(work / "runtime.json", observation)
                send_frame(connection, response)


def front(manifest):
    uid = manifest["uid"]
    need(os.geteuid() == uid and os.getegid() == manifest["gid"], "front identity drift")
    state = Path(manifest["state"])
    lease = read_json(state / "public/after.json", trusted=True)
    expected = read_json(state / "public/front.json", trusted=True)
    while time.time() < lease["expires_at"]:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(1)
            connection.connect(str(state / "after/actor.sock"))
            pid, peer_uid, _ = struct.unpack("3i", connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            need(peer_uid == uid and pid == expected["actor_pid"], "foreign provider actor")
            send_frame(connection, dict(version=1, operation="status", nonce=manifest["nonce"],
                                        runtime_id=lease["runtime_id"]))
            observation = read_frame(connection)
            validate_observation(observation, lease, uid, manifest["slice_cgroup"])
            write_json(state / "front/observation.json",
                       dict(observation, front=process_identity(os.getpid())))
        time.sleep(0.2)


def check_owned_unit(unit, own):
    need(unit in own.values() and unit.endswith(".service"), "cleanup refused unlisted unit")
    props = properties(unit)
    path = props.get("ControlGroup", "")
    if path:
        need(path == "/" + own["slice"] + "/" + unit, "cleanup refused foreign cgroup")
    return props


def stop_owned_unit(unit, own, *, deadline=None):
    props = check_owned_unit(unit, own)
    path = props.get("ControlGroup", "")
    if path:
        manager("kill", "--kill-whom=all", "--signal=SIGKILL", unit, allow_failure=True)
    manager("stop", unit, allow_failure=True)
    seconds = 3 if deadline is None else max(0.2, min(3, deadline - time.monotonic()))
    def retired():
        current = check_owned_unit(unit, own)
        return current.get("MainPID", "0") == "0" and not current.get("ControlGroup", "")
    wait_for(retired, seconds, "owned unit retirement " + unit)
    if path:
        need(not (CGROUP / path.removeprefix("/")).exists(), "owned cgroup retained")


def mount_at(path):
    rows = Path("/proc/self/mountinfo").read_text().splitlines()
    unescape = lambda value: re.sub(r"\\([0-7]{3})", lambda item: chr(int(item[1], 8)), value)
    matches = []
    for row in rows:
        parts = row.split()
        if len(parts) > 7 and unescape(parts[4]) == str(path):
            separator = parts.index("-")
            matches.append(dict(root=unescape(parts[3]), options=parts[5].split(","),
                                fstype=parts[separator + 1], source=parts[separator + 2]))
    need(len(matches) <= 1, "multiple mounts on owned state path")
    return matches[0] if matches else None


def cleanup_nonce(nonce, *, watchdog=False, release_lock=None):
    """Idempotent even before mount/UID/manifest setup; never infer other units."""
    own, root = names(nonce), state_path(nonce)
    deadline = CLEANUP_DEADLINE or time.monotonic() + 35
    errors = []
    # Validate every existing unit before any cleanup mutation. The root-owned
    # bootstrap watchdog supplies the nonce even if manifest setup was partial.
    for key in ("front", "before", "actor", "crash", "guard", "holder", "watchdog"):
        check_owned_unit(own[key], own)
    slice_props = properties(own["slice"])
    need(slice_props.get("ControlGroup", "") in ("", "/" + own["slice"]),
         "cleanup refused foreign slice cgroup")
    if root.exists() or root.is_symlink():
        pinned_directory(root)
        mounted = mount_at(root)
        if mounted:
            need(mounted["fstype"] == "tmpfs" and mounted["root"] == "/"
                 and {"nosuid", "nodev"} <= set(mounted["options"]),
                 "cleanup refused foreign state mount")
    else:
        mounted = None
    for key in ("front", "before", "actor", "crash", "guard"):
        try:
            stop_owned_unit(own[key], own, deadline=deadline)
        except Exception as error:
            errors.append(str(error))
    # Keep both independent watchdog and identity holder until descendants are
    # confirmed gone. A failed cleanup never releases a still-owned UID.
    need(not errors, "owned child cleanup incomplete; holder/watchdog retained: " + "; ".join(errors))
    if root.exists():
        need(shutil.rmtree.avoids_symlink_attacks, "fd-safe directory cleanup unavailable")
        allowed = set(PHASES) | {"public", ".cleanup.lock"}
        need(all(item.name in allowed for item in root.iterdir()), "unexpected state child")
        for phase in PHASES:
            target = root / phase
            if target.exists() or target.is_symlink():
                info = os.lstat(target)
                need(stat.S_ISDIR(info.st_mode) and 61184 <= info.st_uid <= 65519,
                     "cleanup writable fixture path drift")
                shutil.rmtree(target)
    stop_owned_unit(own["holder"], own, deadline=deadline)
    if not watchdog:
        stop_owned_unit(own["watchdog"], own, deadline=deadline)
    reset_keys = ["front", "before", "actor", "crash", "guard", "holder"]
    if not watchdog:
        reset_keys.append("watchdog")
    manager("reset-failed", *[own[key] for key in reset_keys],
            allow_failure=True)
    if not watchdog:
        manager("stop", own["slice"], allow_failure=True)
        manager("revert", own["slice"], allow_failure=True)
    if release_lock:
        # A lock FD on tmpfs itself makes umount busy. UID writers and all
        # non-watchdog children are already confirmed gone before releasing it.
        release_lock()
    if root.exists():
        if mount_at(root):
            execute([TOOLS["umount"], root])
        else:
            # Before mount, only the empty nonce mountpoint may exist. A failed
            # unmount must not become deletion of public files on the host FS.
            need(not list(root.iterdir()), "unmounted state unexpectedly populated")
        need(not list(root.iterdir()), "unmounted nonce mountpoint is not empty")
        root.rmdir()
    if not watchdog:
        need(not (CGROUP / own["slice"]).exists(), "fixture slice retained")
    need(time.monotonic() < deadline, "cleanup exceeded independent watchdog allowance")
    if watchdog:
        # Owned state is gone. Retire the remaining root watchdog and its slice
        # through PID1; no process outside that nonce subtree is signalled.
        manager("revert", own["slice"], allow_failure=True)
        manager("stop", "--no-block", own["slice"])


def cleanup(nonce, *, watchdog=False):
    global CLEANUP_DEADLINE
    CLEANUP_DEADLINE = time.monotonic() + 35
    root = state_path(nonce)
    fd = None
    def release_lock():
        nonlocal fd
        if fd is not None:
            os.close(fd)
            fd = None
    try:
        if not root.exists():
            cleanup_nonce(nonce, watchdog=watchdog)
            return
        pinned_directory(root)
        lock_path = root / ".cleanup.lock"
        fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        info = os.fstat(fd)
        need(info.st_uid == 0 and stat.S_ISREG(info.st_mode)
             and stat.S_IMODE(info.st_mode) == 0o600, "cleanup lock ownership/type/mode drift")
        def locked():
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
            except BlockingIOError:
                return False
        wait_for(locked, 3, "bounded owned cleanup lock")
        cleanup_nonce(nonce, watchdog=watchdog, release_lock=release_lock)
    finally:
        release_lock()
        CLEANUP_DEADLINE = None


def watchdog(nonce, started_at):
    need(os.geteuid() == 0 and math.isfinite(started_at), "watchdog identity/time drift")
    own = names(nonce)
    need(time.time() - HARD_SECONDS <= started_at <= time.time() + 1
         and process_identity(os.getpid())["cgroup"] == "/" + own["slice"] + "/" + own["watchdog"],
         "watchdog nonce placement/original time drift")
    # This first-created root service has its own32MiB/16task/10% caps until the
    # containing slice cap is set. No holder/mount/payload exists before it.
    time.sleep(max(0, started_at + WATCHDOG_SECONDS - time.time()))
    cleanup(nonce, watchdog=True)


def admission():
    need(os.geteuid() == 0, "host fixture requires explicit root authority")
    _, version = manager("--version")
    need(re.match(r"systemd 259 \(259\.5-0ubuntu3\.4\)", version) is not None,
         "fixture requires installed systemd259.5-0ubuntu3.4")
    need((CGROUP / "cgroup.controllers").is_file(), "native cgroupv2 required")
    available = int(re.search(r"^MemAvailable:\s+(\d+)\s+kB",
                             Path("/proc/meminfo").read_text(), re.M).group(1)) * 1024
    need(available >= 736 * MIB, "736MiB MemAvailable admission required")
    _, addresses = execute([TOOLS["ip"], "-j", "address", "show"])
    need(any(row.get("local") == "172.31.7.56" for interface in json.loads(addresses)
             for row in interface.get("addr_info", [])), "not the approved existing bastion")
    return dict(systemd=version.splitlines()[0], mem_available=available,
                protected=protected_snapshot(), tools=pin_tools())


def aggregate_proof(path):
    actual = dict(memory=int(cgroup_read(path, "memory.max")),
                  swap=int(cgroup_read(path, "memory.swap.max")),
                  pids=int(cgroup_read(path, "pids.max")), cpu=cgroup_read(path, "cpu.max"))
    need(actual == {key: AGGREGATE[key] for key in ("memory", "swap", "pids", "cpu")},
         "actual aggregate memory/swap/tasks/CPU10% limits drift")
    return actual


def validate_native_receipt(receipt, nonce):
    own = names(nonce)
    control = "/" + own["slice"] + "/" + own["guard"] + "/control"
    need(type(receipt) is dict and receipt.get("version") == 1
         and receipt.get("status") == "passed" and receipt.get("fixture_nonce") == nonce
         and receipt.get("actor_control_cgroup") == control, "native guard receipt identity drift")
    scope = control.removesuffix("/control") + "/sandbox-" + str(receipt.get("sandbox_id"))
    need(re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}",
                      str(receipt.get("sandbox_id"))) is not None
         and receipt.get("scope_parent") == scope
         and receipt.get("proved_payload_cgroup") == scope + "/payload",
         "native guard scope/membership proof drift")
    need(receipt.get("caps") == {"memory.max": "134217728", "memory.swap.max": "0",
                                 "pids.max": "64", "cpu.max": "100000 100000"},
         "native guard caps drift")
    need(all(receipt.get(field) is True for field in
             ("blocked_effect_deadline", "same_parent_after_generation", "late_child_execution_blocked"))
         and receipt.get("provider_network_qualification") is False
         and receipt.get("frozen_parent") == "1", "native guard proof incomplete")
    events = dict(line.split() for line in receipt.get("expired_cgroup_events", "").splitlines())
    need(events.get("frozen") == "1" and events.get("populated") == "0",
         "native guard original-expiry freeze/retirement proof absent")
    validate_native_late_child(receipt, scope)
    lag = receipt.get("deadline_observation_lag_ms")
    need(type(lag) is int and 0 <= lag <= 5000, "native guard timing observation outside fixture bound")
    return receipt


def validate_native_late_child(receipt, scope):
    need(receipt.get("clone_into_cgroup_fd") is True
         and receipt.get("clone_into_cgroup_target") == scope + "/payload"
         and receipt.get("late_child_marker_absent") is True
         and receipt.get("late_child_no_oom") is True,
         "native late-child clone/marker/OOM proof absent")
    before, after = receipt.get("oom_before"), receipt.get("oom_after")
    for snapshot in (before, after):
        need(type(snapshot) is dict and set(snapshot) == {"scope", "actor", "aggregate"},
             "native OOM observation boundaries incomplete")
        for counters in snapshot.values():
            need(type(counters) is dict and set(counters) == {"oom", "oom_kill", "oom_group_kill"}
                 and all(type(value) is int and value >= 0 for value in counters.values()),
                 "native OOM counter snapshot malformed")
    need(before == after, "native late-child could have been killed by OOM")
    events = dict(line.split() for line in receipt.get("late_child_cgroup_events", "").splitlines())
    need(events.get("frozen") == "1", "native late-child parent not actually frozen")
    pid = receipt.get("late_child_pid")
    outcome = receipt.get("late_child_outcome")
    if outcome == "observed_frozen_child":
        need(receipt.get("late_child_membership_observed") is True and type(pid) is int and pid > 1
             and receipt.get("late_child_typed_sigkill") is False
             and receipt.get("proved_late_child_cgroup") == scope + "/payload"
             and events.get("populated") == "1", "native live frozen-child membership unproven")
    elif outcome == "sigkill_before_marker":
        # A reaped task has no live /proc membership to invent. Accept only the
        # typed wait-status SIGKILL proof from the pinned test, no marker, empty
        # frozen parent and unchanged scope/actor/aggregate OOM counters.
        need(receipt.get("late_child_typed_sigkill") is True
             and receipt.get("late_child_membership_observed") is False
             and "late_child_pid" in receipt and pid is None
             and "proved_late_child_cgroup" in receipt and receipt["proved_late_child_cgroup"] is None
             and events.get("populated") == "0", "native completed-child typed SIGKILL proof absent")
    else:
        raise RuntimeError("native late-child outcome is not one of the two evidenced cases")


def native_unit_state(own):
    props = properties(own["guard"])
    return {key: props.get(key, "") for key in
            ("LoadState", "ActiveState", "SubState", "MainPID", "Result", "ExecMainCode", "ExecMainStatus")}


def native_sample(root, own):
    props = native_unit_state(own)
    need(props["ActiveState"] != "failed" and props["Result"] in ("", "success"),
         "native guard test unit failed: " + canonical(props).decode())
    receipt = root / "guard/native-guard-result.json"
    if receipt.exists():
        return read_json(receipt)
    need(not (props["ActiveState"] == "active" and props["SubState"] == "exited"
              and props["MainPID"] == "0"),
         "native guard exited without its required receipt: " + canonical(props).decode())
    return None


def native_diagnostics(root, own, uid):
    """Only the admitted synthetic unit and its fixed bounded offline log."""
    result = {}
    try:
        result["unit"] = native_unit_state(own)
    except Exception as error:
        # A manager query failure must not suppress an already-written native
        # failure log before the guaranteed cleanup removes its filesystem.
        result["unit_query_error"] = str(error)
    log = root / "guard/native-test-output.txt"
    try:
        fd = os.open(log, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        result["output_state"] = "absent"
        return result
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid in (0, uid)
             and info.st_size <= AGGREGATE["scratch"], "native diagnostic log ownership/type/bound drift")
        offset = max(0, info.st_size - MAX_FRAME)
        os.lseek(fd, offset, os.SEEK_SET)
        raw = os.read(fd, MAX_FRAME)
        result.update(output_size_bytes=info.st_size, tail_size_bytes=len(raw),
                      output_truncated=offset > 0, stdout_stderr_tail=raw.decode("utf-8", errors="replace"))
    finally:
        os.close(fd)
    return result


def fresh_front_sample(path, lease, manifest, old_pid):
    if not path.exists():
        return None
    sample = read_json(path)
    props = properties(manifest["names"]["front"])
    pid = int(props.get("MainPID", "0"))
    if props.get("ActiveState") != "active" or pid <= 1 or pid == old_pid:
        return None
    if sample.get("front", {}).get("pid") != pid or time.time() - sample.get("observed_at", 0) >= 2:
        return None
    current = process_identity(pid)
    if any(current[key] != sample["front"].get(key)
           for key in ("pid", "start_ticks", "uid", "gid", "cgroup")):
        return None
    validate_observation(sample, lease, manifest["uid"], manifest["slice_cgroup"])
    return sample


def run_fixture(pins_path, expected_sha, *, guard_only=False):
    global MUTATION_DEADLINE
    source = Path(__file__).resolve()
    pins = verify_pins(pins_path, source, expected_sha)
    preflight = admission()
    nonce, start = secrets.token_hex(6), time.time()
    own, root = names(nonce), state_path(nonce)
    MUTATION_DEADLINE = time.monotonic() + ACCEPT_SECONDS
    need(not root.exists() and not root.is_symlink(), "fresh fixture path occupied")
    check_fresh_units(own)
    for database in ("passwd", "group"):
        code, entry = execute([TOOLS["getent"], database, own["user"]], allow_failure=True)
        need(code == 2 and not entry.strip(), "fixture user/group name collision")
    manifest = dict(version=2, nonce=nonce, names=own, state=str(root),
                    slice_cgroup="/" + own["slice"], aggregate=AGGREGATE,
                    protected=preflight["protected"], tools=pins["tools"],
                    native_test=dict(pins["native_test"], path=str(root / "public/guard.test")),
                    script_sha256=expected_sha,
                    started_at=start, hard_deadline=start + HARD_SECONDS)
    report = dict(nonce=nonce, topology_only=True, source_sha256=expected_sha,
                  mode="guard-only" if guard_only else "full",
                  tools=pins["tools"], native_test=pins["native_test"],
                  gates={}, unrun=["rootless Podman", "WireGuard", "SSH", "production mTLS/enrollment"])
    armed = False
    native_started = False
    error = None
    try:
        # FIRST mutation: independently armed root watchdog. Its trusted source
        # is outside tmpfs, so partial setup or unmount cannot destroy cleanup.
        transient(own["watchdog"], own["slice"],
                  dict(User="root", MemoryMax="32M", TasksMax=16, CPUQuota="10%",
                       CPUQuotaPeriodSec="100ms", NoNewPrivileges="yes",
                       CapabilityBoundingSet="CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_KILL",
                       RestrictAddressFamilies="AF_UNIX", RuntimeMaxSec="180s",
                       KillMode="control-group", KillSignal="SIGKILL", PrivateMounts="no"),
                  [TOOLS["python"], source, "--watchdog", "--nonce", nonce,
                   "--started-at", str(start), "--pins", pins_path,
                   "--expected-source-sha", expected_sha])
        armed = True
        watch_pid = wait_for(lambda: int(properties(own["watchdog"]).get("MainPID", 0)),
                             3, "independent first watchdog")
        need(process_identity(watch_pid)["uid"] == 0, "watchdog owner drift")
        mutation_gate()
        manager("set-property", "--runtime", own["slice"], "MemoryMax=224M",
                "MemorySwapMax=0", "TasksMax=256", "CPUQuota=10%", "CPUQuotaPeriodSec=100ms")
        report["aggregate"] = aggregate_proof(manifest["slice_cgroup"])
        mutation_gate()
        root.mkdir(mode=0o750)
        execute([TOOLS["mount"], "-t", "tmpfs", "-o",
                 "size=8m,mode=0750,nosuid,nodev", "tmpfs", root])
        need(mount_at(root)["fstype"] == "tmpfs", "private tmpfs absent")
        need(os.statvfs(root).f_blocks * os.statvfs(root).f_frsize == 8 * MIB,
             "actual tmpfs storage cap drift")
        (root / "public").mkdir(mode=0o750)
        script = root / "public/fixture.py"
        shutil.copyfile(source, script)
        script.chmod(0o444)
        receive_native(root / "public/guard.test", pins["native_test"])
        transient(own["holder"], own["slice"],
                  dict(DynamicUser="yes", User=own["user"], MemoryMax="16M", TasksMax=4,
                       PrivateNetwork="yes", RestrictAddressFamilies="AF_UNIX",
                       NoNewPrivileges="yes", CapabilityBoundingSet="",
                       RuntimeMaxSec=str(max(1, int(start + HARD_SECONDS - time.time()))) + "s",
                       KillMode="control-group", KillSignal="SIGKILL"),
                  [TOOLS["sleep"], "180"])
        holder = wait_holder(own, pins["tools"]["sleep"])
        manifest.update(uid=holder["uid"], gid=holder["gid"], holder=holder)
        for directory in (root, root / "public"):
            os.chown(directory, 0, manifest["gid"])
        for phase in PHASES:
            target = root / phase
            target.mkdir(mode=0o700)
            os.chown(target, manifest["uid"], manifest["gid"])
        manifest_file = root / "public/manifest.json"
        write_json(manifest_file, manifest, 0o444)
        common = dict(User=manifest["uid"], Group=manifest["gid"], MemoryMax="224M",
                      TasksMax=256, PrivateNetwork="yes", RestrictAddressFamilies="AF_UNIX",
                      NoNewPrivileges="yes", CapabilityBoundingSet="", RuntimeMaxSec="100s")
        def start_actor(phase):
            mutation_gate()
            lease = binding(nonce, phase, time.time() + 35)
            write_json(root / ("public/" + phase + ".json"), lease, 0o444)
            key = "before" if phase == "before" else "actor" if phase == "after" else "crash"
            props = dict(common, Delegate="yes", DelegateSubgroup="control",
                         KillMode="process" if phase == "before" else "control-group",
                         KillSignal="SIGTERM" if phase == "before" else "SIGKILL")
            transient(own[key], own["slice"], props,
                      [TOOLS["python"], script, "--actor", phase, "--manifest", manifest_file])
            sample = wait_for(lambda: read_json(root / phase / "runtime.json")
                              if (root / phase / "runtime.json").exists() else None,
                              8, "synthetic runtime " + phase)
            validate_observation(sample, lease, manifest["uid"], manifest["slice_cgroup"])
            need(sample["running"] is True, "synthetic payload did not start")
            return lease, sample
        if not guard_only:
            before_lease, before = start_actor("before")
            mutation_gate()
            manager("restart", own["before"], allow_failure=True)
            def before_failed():
                props = properties(own["before"])
                return props if props.get("ActiveState") == "failed" else None
            failed = wait_for(before_failed, 8, "actual systemd259 failure-before")
            need(failed["Result"] == "resources" and failed["MainPID"] == "0",
                 "before layout did not reproduce executor resource failure")
            need(not gone(before["payload"]) and not gone(before["conmon"])
                 and not cgroup_read(before["delegated_root"], "cgroup.procs")
                 and digest(root / "before/workspace.bin") == before["file_sha256"],
                 "baseline retained topology/persistence was not preserved")
            _, journal = execute([TOOLS["journal"], "--unit=" + own["before"], "--no-pager",
                                  "--output=cat", "--lines=20"])
            need("Failed to spawn executor" in journal and "Device or resource busy" in journal,
                 "before layout lacks native executor EBUSY evidence")
            report["gates"]["before"] = dict(result=failed["Result"], executor_ebusy=True,
                                              lease=before_lease, observation=before)
            stop_owned_unit(own["before"], own)
            after_lease, after = start_actor("after")
            write_json(root / "public/front.json", dict(actor_pid=after["actor"]["pid"]), 0o444)
            transient(own["front"], own["slice"],
                      dict(common, Delegate="no", MemoryMax="64M", KillMode="control-group", KillSignal="SIGKILL"),
                      [TOOLS["python"], script, "--front", "--manifest", manifest_file])
            fronts, old_pid = [], 0
            for attempt in range(3):
                sample = wait_for(lambda: fresh_front_sample(root / "front/observation.json",
                                                            after_lease, manifest, old_pid),
                                  8, "fresh UID-authenticated front status")
                need(sample["payload"] == after["payload"] and sample["actor"] == after["actor"]
                     and sample["conmon"] == after["conmon"]
                     and digest(root / "after/workspace.bin") == after["file_sha256"],
                     "front restart replaced retained identity/persistence")
                fronts.append(sample["front"])
                old_pid = sample["front"]["pid"]
                aggregate_proof(manifest["slice_cgroup"])
                if attempt < 2:
                    mutation_gate()
                    manager("restart", own["front"])
            need(len({sample["pid"] for sample in fronts}) == 3, "front did not restart twice")
            mutation_gate()
            manager("stop", own["front"])
            need(not gone(after["payload"]), "transport stop terminated retained payload")
            def expired_sample():
                sample = read_json(root / "after/runtime.json")
                return sample if sample.get("expiry_receipt") else None
            expired = wait_for(expired_sample, max(1, after_lease["expires_at"] - time.time() + 5),
                               "actor-owned original expiry with transport stopped")
            validate_observation(expired, after_lease, manifest["uid"], manifest["slice_cgroup"])
            events = dict(line.split() for line in expired["child_events"].splitlines())
            need(expired["running"] is False and gone(after["payload"]) and gone(after["conmon"])
                 and not expired["guard_errors"] and events.get("populated") == "0"
                 and events.get("frozen") == "1" and after_lease["expires_at"] <= expired["stopped_at"]
                 <= after_lease["expires_at"] + 5, "offline expiry lacks physical stopped/frozen proof")
            report["gates"]["after"] = dict(fronts=fronts, original_lease=after_lease,
                                             observation=after, expiry=expired,
                                             transport_offline_expiry=True,
                                             observed_expiry_lag_seconds=expired["stopped_at"] - after_lease["expires_at"])
            stop_owned_unit(own["actor"], own)
            crash_lease, crash = start_actor("crash")
            mutation_gate()
            manager("kill", "--kill-whom=main", "--signal=SIGKILL", own["crash"])
            wait_for(lambda: gone(crash["actor"]) and gone(crash["payload"]) and gone(crash["conmon"]),
                     8, "actor failure killed payload and control-leaf keeper")
            report["gates"]["actor_crash"] = dict(manager_killed_descendants=True,
                                                   lease=crash_lease, observation=crash)
            stop_owned_unit(own["crash"], own)
        else:
            report["topology"] = dict(status="unrun", reason="guard-only continuation; prior topology proof is a separate parent receipt")
            report["unrun"].append("synthetic restart/transport-expiry/actor-crash topology phases")
        # This standalone native Go test invokes the actual source guard backend;
        # its opt-in contract accepts only this nonce-derived delegated service.
        native_started = True
        transient(own["guard"], own["slice"],
                  dict(common, Delegate="yes", DelegateSubgroup="control",
                       KillMode="control-group", KillSignal="SIGKILL", RuntimeMaxSec="25s",
                       RemainAfterExit="yes",
                       StandardOutput="append:" + str(root / "guard/native-test-output.txt"),
                       StandardError="inherit",
                       Environment="GOMAXPROCS=2 TUNNEX_NATIVE_CGROUP_FIXTURE=1" +
                       " TUNNEX_NATIVE_CGROUP_RECEIPT=" + str(root / "guard/native-guard-result.json")),
                  [manifest["native_test"]["path"], "-test.run=^TestNativeActorCgroupLeaseGuard$",
                   "-test.v", "-test.timeout=15s"])
        native_receipt = wait_for(lambda: native_sample(root, own),
                                 20, "actual source independent cgroup deadline guard")
        validate_native_receipt(native_receipt, nonce)
        def native_complete():
            props = properties(own["guard"])
            need(props.get("ActiveState") != "failed", "native guard test service failed")
            return props.get("MainPID") == "0" and props.get("Result") == "success"
        wait_for(native_complete, 3, "native guard complete successful process exit")
        report["gates"]["native_guard"] = native_receipt
        report["native_diagnostics"] = native_diagnostics(root, own, manifest["uid"])
        stop_owned_unit(own["guard"], own)
        aggregate_proof(manifest["slice_cgroup"])
        need(time.time() < start + ACCEPT_SECONDS, "fixture exceeded acceptance window")
        need(protected_snapshot() == preflight["protected"], "protected services changed")
        report["status"] = "passed"
    except Exception as failure:
        error = failure
        report.update(status="failed", error=str(failure))
        if native_started:
            try:
                # Preserve the diagnostic before finally retires its unit and
                # unmounts the complete scratch filesystem.
                report["native_diagnostics"] = native_diagnostics(root, own, manifest["uid"])
            except Exception as diagnostic_error:
                report["native_diagnostics_error"] = str(diagnostic_error)
    finally:
        if armed:
            try:
                cleanup(nonce)
                report["cleanup"] = dict(owned_slice_absent=not (CGROUP / own["slice"]).exists(),
                                          owned_state_absent=not root.exists(),
                                          protected_unchanged=protected_snapshot() == preflight["protected"])
                need(all(report["cleanup"].values()), "fixture cleanup proof incomplete")
            except Exception as failure:
                report["cleanup_error"] = str(failure)
                if error is None:
                    error = failure
        else:
            # systemd-run may have admitted the watchdog before returning error.
            cleanup(nonce)
    print(json.dumps(report, sort_keys=True, allow_nan=False))
    if error:
        raise RuntimeError("synthetic fixture failed; see bounded public receipt") from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--guard-only", action="store_true")
    parser.add_argument("--inspect", action="store_true")
    parser.add_argument("--approve-synthetic-host-fixture", action="store_true")
    parser.add_argument("--expected-source-sha")
    parser.add_argument("--pins", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--actor", choices=("before", "after", "crash"))
    parser.add_argument("--front", action="store_true")
    parser.add_argument("--watchdog", action="store_true")
    parser.add_argument("--nonce")
    parser.add_argument("--started-at", type=float)
    args = parser.parse_args()
    need(not args.guard_only or args.run, "guard-only requires the approved run role")
    need(sum(bool(item) for item in (args.run, args.inspect, args.actor, args.front, args.watchdog)) <= 1,
         "choose one fixture role")
    if args.watchdog:
        need(args.nonce is not None and args.started_at is not None and args.pins is not None,
             "watchdog requires frozen bootstrap pins and nonce/time")
        verify_pins(args.pins, Path(__file__).resolve(), args.expected_source_sha)
        watchdog(args.nonce, args.started_at)
    elif args.actor or args.front:
        need(args.manifest is not None, "internal role manifest required")
        manifest = verify_manifest(args.manifest)
        if args.actor:
            actor(manifest, args.actor)
        else:
            front(manifest)
    elif args.run:
        need(args.approve_synthetic_host_fixture and args.pins is not None,
             "explicit approval and frozen pins required")
        run_fixture(args.pins, args.expected_source_sha, guard_only=args.guard_only)
    elif args.inspect:
        print(json.dumps(dict(admission(), source_sha256=digest(Path(__file__).resolve())), sort_keys=True))
    else:
        print(json.dumps(dict(proposal="systemd259.5 native cgroupv2 synthetic fixture",
                              host="existing bastion172.31.7.56 only", admission_mib=736,
                              aggregate=AGGREGATE, watchdog_seconds=WATCHDOG_SECONDS,
                              hard_seconds=HARD_SECONDS, source_native_tool_pins_required=True,
                              evidence_boundary="synthetic supervision and real guard backend; no Podman/VPN"),
                         sort_keys=True, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("STOP: " + str(error), file=sys.stderr)
        sys.exit(1)
