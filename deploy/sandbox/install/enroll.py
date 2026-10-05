#!/usr/bin/env python3
"""Enroll and install one scoped sandbox runner. Never install host dependencies."""

import argparse
from datetime import datetime, timedelta, timezone
import fcntl
import getpass
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import signal
import ssl
import stat
import struct
import subprocess
import sys
import time
import tarfile
import urllib.parse
import urllib.request
import uuid
import warnings

MIB = 1024 * 1024
ASSETS = {
    "deploy/sandbox/ci/README.md", "deploy/sandbox/Containerfile",
    "deploy/sandbox/sandbox-entrypoint.py", "deploy/sandbox/build-image.sh",
    "deploy/sandbox/network-plan-contract.json", "deploy/sandbox/alpine/Containerfile",
    "deploy/sandbox/alpine/entrypoint.sh", "deploy/sandbox/alpine/build-image.sh",
    "deploy/sandbox/install/install.py", "deploy/sandbox/install/README.md",
    "deploy/sandbox/install/example.json", "deploy/sandbox/install/enroll.py",
    "deploy/sandbox/ubuntu-base/delivery.py", "deploy/sandbox/ubuntu-base/archive.py",
    "deploy/sandbox/ubuntu-base/Containerfile", "deploy/sandbox/ubuntu-base/public-inputs.json",
    "deploy/sandbox/ubuntu-base/ubuntu26-amd64.lock.json", "deploy/sandbox/ubuntu-base/README.md",
}
COMMANDS = ("tunnex-sandbox-runtime", "tunnex-sandbox-ssh-probe", "tunnex-sandbox-runner-enroll")


class Refused(ValueError):
    pass


def need(condition, code):
    if not condition:
        raise Refused(code)


def strict_json(raw):
    def pairs(entries):
        result = {}
        for key, value in entries:
            need(key not in result, "duplicate_configuration_field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def keys(value, required, optional=()):
    need(isinstance(value, dict) and set(required) <= set(value)
         and set(value) <= set(required) | set(optional), "unsupported_configuration")


def public_url(value, origin=False):
    need(isinstance(value, str), "invalid_public_url")
    url = urllib.parse.urlsplit(value)
    need(url.scheme == "https" and url.hostname and not url.username and not url.password
         and not url.query and not url.fragment and not re.search(r"[\x00-\x20]", value)
         and (not origin or url.path in ("", "/")), "invalid_public_url")
    return value.rstrip("/") if origin else value


def pin(value):
    need(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "invalid_artifact_pin")
    return value


def private_directory(path, create=False):
    path = Path(path)
    need(path.is_absolute() and ".." not in path.parts and path != Path("/"), "unsafe_private_directory")
    for parent in (path, *path.parents):
        if parent.exists() or parent.is_symlink():
            info = parent.lstat()
            need(not stat.S_ISLNK(info.st_mode) and info.st_uid == os.geteuid()
                 and not info.st_mode & 0o022, "unsafe_private_directory")
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
         and stat.S_IMODE(info.st_mode) == 0o700, "unsafe_private_directory")
    return path


def file_bytes(path, maximum):
    info = Path(path).lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
         and not info.st_mode & 0o077 and 0 < info.st_size <= maximum, "unsafe_enrollment_file")
    with open(path, "rb") as stream:
        current = os.fstat(stream.fileno())
        need((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino), "enrollment_file_changed")
        raw = stream.read(maximum + 1)
    need(len(raw) <= maximum, "oversized_enrollment_file")
    return raw


def write_exact(path, raw, mode=0o600):
    path = Path(path)
    if path.exists() or path.is_symlink():
        need(file_bytes(path, max(len(raw), 1)) == raw, "changed_enrollment_file")
        return
    with open(path, "xb") as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def write_latest(path, raw):
    path = Path(path)
    if path.exists() or path.is_symlink():
        file_bytes(path, 32768)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".partial")
    try:
        write_exact(temporary, raw)
        os.replace(temporary, path)
    finally:
        if temporary.exists() and not temporary.is_symlink():
            temporary.unlink()


def completed_installation(cfg, installer):
    marker = Path(cfg["installation"]["state_root"]) / "installation.json"
    info = marker.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
         and info.st_size <= 64 * 1024, "unsafe_installation_marker")
    manifest = strict_json(marker.read_bytes())
    expected = hashlib.sha256(json.dumps(cfg, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    need(manifest.get("config_sha256") == expected and manifest.get("native_qualification") is False,
         "changed_installation_marker")
    need(isinstance(manifest.get("files"), dict) and 1 <= len(manifest["files"]) <= 32, "changed_installation_marker")
    for path, checksum in manifest["files"].items():
        need(installer.file_hash(path, 512 * MIB) == pin(checksum), "installed_public_artifact_changed")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise Refused("artifact_redirect_refused")


def download(url, sha, path, maximum, opener=None):
    public_url(url)
    pin(sha)
    path = Path(path)
    if path.exists() or path.is_symlink():
        raw = file_bytes(path, maximum)
        need(hashlib.sha256(raw).hexdigest() == sha, "artifact_checksum_mismatch")
        return
    opener = opener or urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(url, headers={"Accept": "application/octet-stream"})
    temporary = path.with_name(path.name + ".partial")
    need(not temporary.exists() and not temporary.is_symlink(), "partial_download_requires_inspection")
    result = hashlib.sha256()
    count = 0
    try:
        with opener.open(request, timeout=60) as response, open(temporary, "xb") as output:
            os.fchmod(output.fileno(), 0o600)
            need(response.status == 200 and response.geturl() == url, "artifact_download_refused")
            for block in iter(lambda: response.read(MIB), b""):
                count += len(block)
                need(count <= maximum, "artifact_download_too_large")
                result.update(block)
                output.write(block)
            need(count > 0 and result.hexdigest() == sha, "artifact_checksum_mismatch")
            output.flush()
            os.fsync(output.fileno())
        os.rename(temporary, path)
    finally:
        if temporary.exists() and not temporary.is_symlink():
            temporary.unlink()


def verify_bundle(path, source, sha):
    raw = file_bytes(path, 100 * MIB)
    need(hashlib.sha256(raw).hexdigest() == sha, "artifact_checksum_mismatch")
    names = {f"bin/{command}-{edition}-linux-amd64" for command in COMMANDS for edition in ("open", "enterprise")}
    names |= {"bin/tunnex-sandbox-network-linux-amd64", "bin/tunnex-sandbox-bootstrap-linux-amd64"} | ASSETS
    payload = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        for member in archive:
            need(member.name in names | {"manifest.json", "SHA256SUMS"} and member.name not in payload
                 and member.isfile() and member.size <= 64 * MIB, "unsafe_bundle_inventory")
            payload[member.name] = archive.extractfile(member).read()
            need(sum(map(len, payload.values())) <= 256 * MIB, "oversized_bundle")
    need(set(payload) == names | {"manifest.json", "SHA256SUMS"}, "incomplete_bundle")
    manifest = strict_json(payload["manifest.json"])
    need(manifest.get("schema_version") == 1 and manifest.get("source_sha") == source
         and manifest.get("os") == "linux" and manifest.get("architecture") == "amd64"
         and manifest.get("api_editions") == ["open", "enterprise"]
         and manifest.get("native_runtime_qualification") is False
         and manifest.get("workload_images_built") is False, "bundle_identity_mismatch")
    records = {name: {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)} for name, raw in payload.items() if name in names}
    need(manifest.get("files") == records, "bundle_manifest_mismatch")
    summed = "".join(f"{hashlib.sha256(raw).hexdigest()}  {name}\n" for name, raw in sorted(payload.items()) if name != "SHA256SUMS")
    need(payload["SHA256SUMS"] == summed.encode(), "bundle_checksum_mismatch")
    for name in names:
        if name.startswith("bin/"):
            raw = payload[name]
            need(len(raw) >= 64 and raw[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", raw, 18)[0] == 62, "bundle_architecture_mismatch")
    return payload


def select_layout(enrollment_id, host):
    suffix = uuid.UUID(enrollment_id).hex[:16]
    user = "tnxsb" + suffix
    state = "/var/lib/tunnex-sandbox/" + str(uuid.UUID(enrollment_id))
    run = "/run/tunnex-sandbox/" + str(uuid.UUID(enrollment_id))
    passwd = [row.split(":") for row in host.read("/etc/passwd").splitlines() if row]
    groups = [row.split(":") for row in host.read("/etc/group").splitlines() if row]
    need(all(len(row) == 7 for row in passwd) and all(len(row) == 4 for row in groups), "invalid_local_identity_metadata")
    occupied = {int(row[2]) for row in passwd + groups}
    need(not any(row[0] == user for row in passwd + groups), "local_identity_collision")
    selected = next((value for value in range(2401, 65534) if value not in occupied), None)
    need(selected is not None, "dedicated_identity_unavailable")
    ranges = []
    for path in ("/etc/subuid", "/etc/subgid"):
        for row in host.read(path).splitlines():
            if not row or row.startswith("#"):
                continue
            fields = row.split(":")
            need(len(fields) == 3 and fields[1].isdigit() and fields[2].isdigit(), "invalid_subordinate_identity_metadata")
            start, count = int(fields[1]), int(fields[2])
            need(count > 0, "invalid_subordinate_identity_metadata")
            ranges.append((start, start + count))
    subuid = next((start for start in range(65536, 2**32 - 65536, 65536)
                   if all(start + 65536 <= left or start >= right for left, right in ranges)), None)
    need(subuid is not None, "subordinate_identity_unavailable")
    parent = Path(state).parent
    while not parent.exists():
        parent = parent.parent
    device = host.stat(str(parent)).st_dev
    io_device = None
    for line in host.read("/proc/self/mountinfo").splitlines():
        fields = line.split()
        if "-" not in fields or len(fields) < 10:
            continue
        position = fields.index("-")
        if fields[2] == f"{os.major(device)}:{os.minor(device)}" and position + 2 < len(fields):
            candidate = fields[position + 2]
            if re.fullmatch(r"/dev/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", candidate):
                info = host.stat(candidate)
                if stat.S_ISBLK(info.st_mode) and info.st_rdev == device:
                    io_device = candidate
                    break
    need(io_device is not None, "backing_block_device_unavailable")
    return {"state_root": state, "run_root": run, "service_user": user, "unit_prefix": user,
            "uid": selected, "gid": selected, "subuid_start": subuid, "subuid_count": 65536,
            "workspace_mib": 256, "storage_mib": 4096, "io_device": io_device}


def installer_config(bundle, options, staging, layout):
    keys(bundle, ("enrollment_id", "profile_id", "binding_sha256", "certificate", "runner_ca", "api_ca", "install"))
    need(bundle["enrollment_id"] == options.enrollment_id, "changed_enrollment_identity")
    plan = bundle["install"]
    keys(plan, ("version", "edition", "source_sha", "bundle", "org_id", "gateway", "controller", "images"))
    keys(plan["bundle"], ("url", "sha256"))
    need(plan["version"] == 1 and plan["edition"] == options.edition and plan["source_sha"] == options.source_sha
         and plan["bundle"]["url"] == options.bundle_url and plan["bundle"]["sha256"] == options.bundle_sha256,
         "changed_enrollment_artifact_pins")
    need(public_url(plan["controller"]["api_url"], True) == options.api_url, "changed_api_origin")
    identity = strict_json(file_bytes(staging / "identity" / "identity.json", 256 * 1024))
    cfg = dict(plan)
    cfg["bundle"] = {"path": str(staging / "bundle.tar.gz"), "sha256": options.bundle_sha256}
    cfg["installation"] = layout
    cfg["probe_public_key"] = identity["probe_public_key"]
    cfg["credentials"] = {"probe_key": str(staging / "identity/probe-key"), "api_ca": str(staging / "identity/api-ca.pem"),
                          "runner_certificate": str(staging / "identity/runner-cert.pem"), "runner_key": str(staging / "identity/runner-key.pem"),
                          "runner_ca": str(staging / "identity/runner-ca.pem")}
    need(isinstance(plan["images"], list) and 1 <= len(plan["images"]) <= 4, "unsupported_image_catalog")
    images = []
    for image in plan["images"]:
        keys(image, ("template_id", "url", "sha256", "config_digest", "architecture", "qualification_evidence"))
        public_url(image["url"])
        pin(image["sha256"])
        need(image["architecture"] == "amd64", "unsupported_image_architecture")
        copy = dict(image)
        copy["path"] = str(staging / (pin(image["sha256"]) + ".image.tar"))
        del copy["url"]
        images.append(copy)
    cfg["images"] = images
    return cfg


def secret_prompt(prompt):
    # Fail closed instead of getpass falling back to an echoed pipe or log.
    with open("/dev/tty", "r+") as terminal, warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        return getpass.getpass(prompt, stream=terminal)


def activate(cfg, host, confirmation):
    need(confirmation == "ACTIVATE", "activation_not_confirmed")
    prefix = cfg["installation"]["unit_prefix"]
    # Dependency ordering uses the existing bounded helper/actor/transport roles.
    # No enable, package installation, firewall change or per-workload unit.
    host.run(["/usr/bin/systemctl", "start", prefix + "-network.service", prefix + "-actor.service", prefix + "-transport.service"])
    return {"installation": "activation-requested", "services_enabled": False,
            "native_qualification": False, "connected": False}


def check_host(cfg, installer, host):
    for tool in installer.TOOLS:
        try:
            host.stat(tool)
        except OSError:
            raise Refused("required_host_tool_missing:" + tool) from None
    try:
        return installer.check(cfg, host)
    except ValueError as error:
        messages = {
            "missing or mutable required packaged tool": "required_host_tool_permissions_invalid",
            "existing setuid subordinate mapping helper required": "subordinate_mapping_setuid_required",
            "systemd DelegateSubgroup support required": "systemd_254_or_later_required",
            "unified cgroup v2 required": "unified_cgroup_v2_required",
            "cgroup resource controllers required": "cgroup_cpu_memory_pids_io_required",
            "native overlay filesystem required": "native_overlay_required",
            "owned service must be stopped and disabled": "existing_service_active_or_enabled_requires_inspection",
            "exact local Docker gateway required": "run_on_the_selected_gateway_host_with_exact_gateway_pins",
            "service UID collision": "dedicated_service_uid_collision",
            "service GID collision": "dedicated_service_gid_collision",
            "subordinate range collision": "subordinate_range_collision",
        }
        raise Refused(messages.get(str(error), "host_prerequisites_or_identity_not_supported")) from None


def run(options):
    need(os.geteuid() == 0, "explicit_host_admin_required")
    need(platform.system() == "Linux" and platform.machine() in ("x86_64", "amd64"), "linux_amd64_required_arm64_compile_only")
    options.api_url = public_url(options.api_url, True)
    public_url(options.bundle_url)
    pin(options.bundle_sha256)
    need(re.fullmatch(r"[0-9a-f]{40}", options.source_sha) and options.edition in ("open", "enterprise"), "invalid_public_bundle_identity")
    enrollment = uuid.UUID(options.enrollment_id)
    need(enrollment.int != 0 and str(enrollment) == options.enrollment_id, "invalid_enrollment_identity")
    parent = Path("/var/lib/tunnex-sandbox-enrollment")
    private_directory(parent, True)
    staging = private_directory(parent / options.enrollment_id, True)
    with open(staging / "enrollment.lock", "a+") as lock:
        os.fchmod(lock.fileno(), 0o600)
        need(stat.S_ISREG(os.fstat(lock.fileno()).st_mode), "unsafe_enrollment_lock")
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return run_locked(options, staging)


def run_locked(options, staging):
    print("Verifying pinned public runner bundle; host packages and protections stay unchanged.", flush=True)
    download(options.bundle_url, options.bundle_sha256, staging / "bundle.tar.gz", 100 * MIB)
    payload = verify_bundle(staging / "bundle.tar.gz", options.source_sha, options.bundle_sha256)
    executable = staging / "runner-enroll"
    write_exact(executable, payload[f"bin/tunnex-sandbox-runner-enroll-{options.edition}-linux-amd64"])
    os.chmod(executable, 0o700)
    installer_path = staging / "install.py"
    write_exact(installer_path, payload["deploy/sandbox/install/install.py"])
    spec = importlib.util.spec_from_file_location("tunnex_verified_installer", installer_path)
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    host = installer.Host()
    config_path = staging / "operator.json"
    if config_path.exists():
        cfg = installer.validate(strict_json(file_bytes(config_path, 32768)))
        marker = Path(cfg["installation"]["state_root"]) / "installation.json"
        if marker.exists():
            completed_installation(cfg, installer)
            print("Existing completed installation retained. It does not prove connection or qualification.", flush=True)
            result = activation_ceremony(cfg, host)
            return submit_report(cfg, staging, executable, installer, host, result)
    elif not (staging / "layout.json").exists():
        layout = select_layout(options.enrollment_id, host)
        write_exact(staging / "layout.json", (json.dumps(layout, sort_keys=True) + "\n").encode())
    layout = strict_json(file_bytes(staging / "layout.json", 32768))
    command = [str(executable), "--server=" + options.api_url, "--enrollment=" + options.enrollment_id, "--output=" + str(staging / "identity")]
    if (staging / "identity/enrollment.json").exists():
        print("Verify the original issued machine identity and exact public pins for this retained installation retry.", flush=True)
        command.append("--verify-issued")
        token = ""
    else:
        print("Generate private machine identities locally; paste the separate enrollment token at the hidden prompt.", flush=True)
        token = secret_prompt("Enrollment token: ")
        need(32 <= len(token) <= 4096 and not re.search(r"[\x00-\x20]", token), "invalid_bootstrap_token")
    result = subprocess.run(command, input=(token + "\n").encode(),
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=45)
    token = ""
    if result.returncode != 0:
        if result.stderr.startswith(b"bootstrap_unavailable:"):
            raise Refused("bootstrap_https_connection_unavailable_retry_same_enrollment")
        if result.stderr.startswith(b"machine_identity_refused:"):
            raise Refused("private_machine_identity_changed_or_partial_inspect_staging")
        raise Refused("bootstrap_expired_canceled_revoked_or_identity_changed")
    bundle = strict_json(file_bytes(staging / "identity/enrollment.json", 256 * 1024))
    cfg = installer_config(bundle, options, staging, layout)
    installer.validate(cfg)
    check_host(cfg, installer, host)
    write_exact(config_path, (json.dumps(cfg, sort_keys=True) + "\n").encode())
    # This actual mTLS metadata admission checks current enrollment authority
    # before an issued identity continues installation after token redemption.
    report = qualification_report(cfg, bundle, installer, host, {"installation": "installed-disabled"})
    pending_report = staging / "qualification-preinstall.json"
    write_latest(pending_report, (json.dumps(report, sort_keys=True) + "\n").encode())
    current = subprocess.run([str(executable), "--qualification-report=" + str(pending_report), "--install-config=" + str(config_path), "--output=" + str(staging / "identity")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45)
    need(current.returncode == 0, "current_enrollment_authority_or_controller_unavailable_before_install")
    print("Host structure checked. Downloading exact approved images; this does not qualify a new host.", flush=True)
    for image, public in zip(cfg["images"], bundle["install"]["images"]):
        download(public["url"], image["sha256"], image["path"], 512 * MIB)
        installer.verify_image(image)
    verified = installer.bundle_payload(cfg)
    print("Installing the verified bounded runner with stopped, disabled services.", flush=True)
    installer.install(cfg, verified, host)
    result = activation_ceremony(cfg, host)
    return submit_report(cfg, staging, executable, installer, host, result)


def host_platform(host):
    # os-release is public host metadata. Parse data without invoking a shell.
    values = {}
    for line in host.read("/etc/os-release").splitlines():
        name, separator, value = line.partition("=")
        if separator and name in ("ID", "VERSION_ID"):
            value = value.strip().strip('"').strip("'")
            need(re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", value), "unsupported_os_release_metadata")
            values[name] = value
    need("ID" in values and "VERSION_ID" in values, "missing_actual_host_os_version")
    return {"os": "linux", "version": values["ID"] + " " + values["VERSION_ID"], "architecture": "amd64"}


def inspect_preloaded_images(cfg, host):
    layout = cfg["installation"]
    state, run = layout["state_root"], layout["run_root"]
    environment = {"PATH": "/usr/sbin:/usr/bin:/bin", "HOME": state + "/worker/home", "XDG_RUNTIME_DIR": run + "/worker",
                   "XDG_CONFIG_HOME": state + "/worker/config", "XDG_DATA_HOME": state + "/worker/data", "LC_ALL": "C"}
    command = ["/usr/bin/podman", "--root", state + "/worker/storage", "--runroot", run + "/worker/storage",
               "--storage-driver=overlay", "--cgroup-manager=cgroupfs", "--runtime=/usr/bin/runc"]
    for image in cfg["images"]:
        result = host.run(command + ["image", "inspect", "--format", "{{.Id}} {{.Architecture}} {{.Os}}", image["config_digest"]],
                          env=environment, user=layout["uid"], group=layout["gid"], extra_groups=[]).strip()
        expected = image["config_digest"][7:]
        need(result in (f"{expected} amd64 linux", f"sha256:{expected} amd64 linux"), "approved_preloaded_image_not_observed")


def qualification_report(cfg, bundle, installer, host, activation):
    started = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    need(str(uuid.UUID(bundle["profile_id"])) == bundle["profile_id"], "invalid_qualification_profile")
    pin(bundle["binding_sha256"])
    try:
        installer.check(cfg, host, installed_report=True)
        capabilities = {"code": "host-capabilities", "result": "passed",
                        "evidence": "Actual current installer host/gateway/identity/cgroup structure checks passed; capabilities do not prove native lifecycle or network behavior."}
    except (ValueError, OSError, subprocess.SubprocessError):
        capabilities = {"code": "host-capabilities", "result": "failed", "evidence": "Current host structure or exact gateway prerequisites failed; inspect the retained installation and actual capabilities."}
    image = {"code": "approved-image-load", "result": "unrun", "evidence": "Services are stopped; approved image preload has not been observed."}
    if activation.get("installation") == "activation-requested":
        try:
            inspect_preloaded_images(cfg, host)
            image = {"code": "approved-image-load", "result": "passed", "evidence": "Exact approved AMD64 config IDs were read from the dedicated rootless store after actor ExecStartPre."}
        except (ValueError, OSError, subprocess.SubprocessError):
            image = {"code": "approved-image-load", "result": "failed", "evidence": "Pinned rootless image inspection failed. Inspect the actor preload and local host prerequisites; no pull or fallback occurred."}
    checks = [capabilities, image]
    for code in ("bounded-provider-start-stop", "offline-expiry-fence", "private-network-connectivity"):
        checks.append({"code": code, "result": "unrun", "evidence": "Requires the separate control-plane authorized bounded qualification trial and independent observation; installation does not satisfy this check."})
    return {"version": 1, "enrollment_id": bundle["enrollment_id"], "profile_id": bundle["profile_id"],
            "binding_sha256": bundle["binding_sha256"], "source_sha": cfg["source_sha"], "platform": host_platform(host),
            "checks": checks, "image_config_digests": [image["config_digest"] for image in cfg["images"]],
            "started_at": started, "finished_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}


def submit_report(cfg, staging, executable, installer, host, activation):
    bundle = strict_json(file_bytes(staging / "identity/enrollment.json", 256 * 1024))
    completed_installation(cfg, installer)
    report = qualification_report(cfg, bundle, installer, host, activation)
    raw = (json.dumps(report, sort_keys=True) + "\n").encode()
    need(len(raw) <= 16 * 1024, "qualification_report_too_large")
    path = staging / "qualification-report.json"
    write_latest(path, raw)
    result = subprocess.run([str(executable), "--qualification-report=" + str(path), "--install-config=" + str(staging / "operator.json"),
                             "--output=" + str(staging / "identity")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45)
    print("Actual host/image check metadata " + ("accepted" if result.returncode == 0 else "retained locally; controller upload unavailable")
          + ". Unrun native checks remain blocked pending a controlled trial and administrator review.", flush=True)
    return dict(activation, qualification_report="accepted" if result.returncode == 0 else "upload-unavailable",
                native_qualification=False, connected=False)


def observed_time():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def timestamp(value):
    need(isinstance(value, str), "invalid_trial_timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    need(parsed.tzinfo is not None, "invalid_trial_timestamp")
    return parsed


def owned_metadata(path, uid, maximum=32768):
    info = Path(path).lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == uid and not info.st_mode & 0o077
         and 0 < info.st_size <= maximum, "trial_local_metadata_identity_mismatch")
    with open(path, "rb") as stream:
        current = os.fstat(stream.fileno())
        need((info.st_dev, info.st_ino) == (current.st_dev, current.st_ino), "trial_local_metadata_changed")
        raw = stream.read(maximum + 1)
    need(len(raw) <= maximum, "trial_local_metadata_too_large")
    return strict_json(raw)


def podman_observation(cfg, sandbox_id, host):
    need(str(uuid.UUID(sandbox_id)) == sandbox_id and uuid.UUID(sandbox_id).int != 0, "invalid_trial_sandbox_identity")
    layout = cfg["installation"]
    state, run = layout["state_root"], layout["run_root"]
    environment = {"PATH": "/usr/sbin:/usr/bin:/bin", "HOME": state + "/worker/home", "XDG_RUNTIME_DIR": run + "/worker",
                   "XDG_CONFIG_HOME": state + "/worker/config", "XDG_DATA_HOME": state + "/worker/data", "LC_ALL": "C"}
    projection = '{"id":{{json .Id}},"image":{{json .Image}},"labels":{{json .Config.Labels}},"running":{{json .State.Running}},"pid":{{json .State.Pid}},"cgroup_parent":{{json .HostConfig.CgroupParent}}}'
    command = ["/usr/bin/podman", "--root", state + "/worker/storage", "--runroot", run + "/worker/storage",
               "--storage-driver=overlay", "--cgroup-manager=cgroupfs", "--runtime=/usr/bin/runc",
               "inspect", "--type=container", "--format", projection, "tunnex-sandbox-" + sandbox_id]
    return strict_json(host.run(command, env=environment, user=layout["uid"], group=layout["gid"], extra_groups=[]))


def trial_scope(cfg, status):
    return "/" + cfg["installation"]["unit_prefix"] + ".slice/" + cfg["installation"]["unit_prefix"] + "-actor.service/sandbox-" + status["sandbox_id"]


def exact_trial_observation(cfg, status, host, *, running):
    layout = cfg["installation"]
    pin_record = owned_metadata(Path(layout["state_root"]) / "worker/persistent-control/api-binding.json", layout["uid"])
    authorization, epoch, binding = pin_record.get("Authorization", {}), pin_record.get("Epoch", {}), pin_record.get("Binding", {})
    need(pin_record.get("SandboxID") == status["sandbox_id"] and authorization.get("SandboxID") == status["sandbox_id"]
         and authorization.get("Generation") == status["generation"] == 3 and authorization.get("Desired") == "started"
         and timestamp(authorization.get("CreatedAt")) == timestamp(status["created_at"])
         and timestamp(authorization.get("ExpiresAt")) == timestamp(status["expires_at"])
         and epoch.get("RuntimeID") == status["runtime_id"] and pin_record.get("EpochGeneration") == 3
         and not pin_record.get("Withdrawn", False), "trial_actor_pin_mismatch")
    need(binding.get("Admission") == "organization" and binding.get("Mode") == "persistent"
         and binding.get("OrgID") == cfg["org_id"] and binding.get("GatewayID") == cfg["gateway"]["node_id"]
         and binding.get("MemoryMiB") == 128 and binding.get("CPUs") == 1 and binding.get("MaxTTLSeconds") == 900,
         "trial_actor_binding_mismatch")
    profile = authorization.get("Profile", {})
    need(profile.get("PIDs") == 64 and profile.get("Architecture") == "amd64"
         and any(image["template_id"] == authorization.get("TemplateID") and image["config_digest"] == profile.get("ConfigDigest") for image in cfg["images"]),
         "trial_image_profile_mismatch")
    lease = owned_metadata(Path(layout["state_root"]) / "worker/runner-protocol" / (status["sandbox_id"] + ".lease.json"), layout["uid"])
    need(lease.get("sandbox_id") == status["sandbox_id"] and lease.get("generation") == 3
         and timestamp(lease.get("created_at")) == timestamp(status["created_at"])
         and timestamp(lease.get("expires_at")) == timestamp(status["expires_at"]), "trial_local_original_lease_mismatch")
    observation = podman_observation(cfg, status["sandbox_id"], host)
    keys(observation, ("id", "image", "labels", "running", "pid", "cgroup_parent"))
    spec = {"Architecture": "amd64", "ID": status["sandbox_id"], "ImageDigest": profile["ConfigDigest"], "MemoryMiB": 128, "CPUs": 1, "PIDs": 64}
    spec_sha = hashlib.sha256(json.dumps(spec, separators=(",", ":")).encode()).hexdigest()
    scope = trial_scope(cfg, status)
    need(observation["id"] == pin(status["runtime_id"]) and observation["image"].removeprefix("sha256:") == profile["ConfigDigest"][7:]
         and observation["labels"].get("io.tunnex.sandbox") == status["sandbox_id"]
         and observation["labels"].get("io.tunnex.sandbox.spec") == spec_sha and observation["cgroup_parent"] == scope,
         "trial_provider_identity_mismatch")
    need(observation["running"] is running, "trial_provider_still_running" if not running else "trial_provider_not_running")
    if running:
        need(type(observation["pid"]) is int and 0 < observation["pid"] < 2**31, "trial_provider_pid_invalid")
        cgroups = host.read("/proc/" + str(observation["pid"]) + "/cgroup").splitlines()
        need(any(line.startswith("0::" + scope + "/") for line in cgroups), "trial_provider_cgroup_placement_mismatch")
    expected = {"memory.max": "134217728", "memory.swap.max": "0", "pids.max": "64", "cpu.max": "100000 100000"}
    for name, value in expected.items():
        need(host.read("/sys/fs/cgroup" + scope + "/" + name).strip() == value, "trial_actual_resource_caps_mismatch")
    events = dict(line.split() for line in host.read("/sys/fs/cgroup" + scope + "/cgroup.events").splitlines())
    need(events.get("populated") == ("1" if running else "0"), "trial_actual_cgroup_population_mismatch")
    return observation


def trial_command(cfg, staging, executable, trial_id, witness=None):
    arguments = [str(executable), "--qualification-trial=" + trial_id, "--install-config=" + str(staging / "operator.json"),
                 "--output=" + str(staging / "identity")]
    if witness is not None:
        arguments.append("--trial-witness=" + str(witness))
    result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=45)
    need(result.returncode == 0 and len(result.stdout) <= 16 * 1024, "qualification_trial_controller_unavailable")
    return None if witness else strict_json(result.stdout)


def validate_trial_view(status, bundle, cfg, trial_id):
    keys(status, ("version", "enrollment_id", "profile_id", "binding_sha256", "source_sha", "trial_id", "sandbox_id", "runtime_id", "generation", "created_at", "expires_at", "phase"),
         ("initial_ready_at", "stopped_at", "resume_ready_at", "retired_at", "offline_witness_sha256", "proof_sha256"))
    need(status["version"] == 1 and status["trial_id"] == trial_id and status["enrollment_id"] == bundle["enrollment_id"]
         and status["profile_id"] == bundle["profile_id"] and status["binding_sha256"] == bundle["binding_sha256"]
         and status["source_sha"] == cfg["source_sha"], "qualification_trial_public_binding_mismatch")
    need(str(uuid.UUID(status["sandbox_id"])) == status["sandbox_id"] and uuid.UUID(status["sandbox_id"]).int != 0,
         "invalid_trial_sandbox_identity")
    created, expires = timestamp(status["created_at"]), timestamp(status["expires_at"])
    need(0 < (expires - created).total_seconds() <= 900, "trial_original_ttl_outside_cap")
    return expires


def service_state(host, unit):
    return host.run(["/usr/bin/systemctl", "show", unit, "--property=ActiveState", "--value"]).strip()


def observe_offline_expiry(cfg, status, host, *, now=lambda: datetime.now(timezone.utc), pause=time.sleep):
    prefix = cfg["installation"]["unit_prefix"]
    transport, actor, network = (prefix + suffix for suffix in ("-transport.service", "-actor.service", "-network.service"))
    expires = timestamp(status["expires_at"])
    need(status["phase"] == "awaiting_expiry" and status["generation"] == 3
         and timestamp(status["initial_ready_at"]) <= timestamp(status["stopped_at"]) <= timestamp(status["resume_ready_at"]) < expires
         and 15 <= (expires - now()).total_seconds() <= 900, "trial_not_safe_to_pause_transport")
    exact_trial_observation(cfg, status, host, running=True)
    need(service_state(host, transport) == "active" and service_state(host, actor) == "active" and service_state(host, network) == "active", "owned_trial_services_not_active")
    stopped_at = None
    try:
        host.run(["/usr/bin/systemctl", "stop", transport])
        need(service_state(host, transport) == "inactive" and service_state(host, actor) == "active" and service_state(host, network) == "active", "transport_pause_not_independent")
        stopped_at = now().isoformat().replace("+00:00", "Z")
        need(timestamp(stopped_at) < expires, "transport_pause_missed_original_deadline")
        while now() <= expires + timedelta(seconds=90):
            need(service_state(host, transport) == "inactive" and service_state(host, actor) == "active" and service_state(host, network) == "active", "trial_offline_service_independence_lost")
            if now() >= expires:
                try:
                    observation = exact_trial_observation(cfg, status, host, running=False)
                    receipt = owned_metadata(Path(cfg["installation"]["state_root"]) / "worker/runner-protocol" / (status["sandbox_id"] + ".expired.json"), cfg["installation"]["uid"])
                    lease = receipt.get("lease", {})
                    need(lease.get("sandbox_id") == status["sandbox_id"] and lease.get("generation") == 3
                         and timestamp(lease.get("created_at")) == timestamp(status["created_at"])
                         and timestamp(lease.get("expires_at")) == expires and timestamp(receipt.get("stopped_at")) >= expires,
                         "trial_actor_expiry_receipt_mismatch")
                    return {"version": 1, "trial_id": status["trial_id"], "sandbox_id": status["sandbox_id"], "runtime_id": status["runtime_id"], "generation": 3,
                            "binding_sha256": status["binding_sha256"], "source_sha": status["source_sha"], "created_at": status["created_at"], "expires_at": status["expires_at"],
                            "transport_stopped_at": stopped_at, "stopped_observed_at": now().isoformat().replace("+00:00", "Z"), "actor_expired_at": receipt["stopped_at"],
                            "transport_resumed_at": "pending-finally", "image_digest": observation["image"] if observation["image"].startswith("sha256:") else "sha256:" + observation["image"],
                            "memory_max_bytes": 134217728, "memory_swap_max_bytes": 0, "pids_max": 64, "cpu_quota_us": 100000, "cpu_period_us": 100000,
                            "cgroup_populated": False, "observer_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
                except Refused as error:
                    if str(error) not in ("trial_provider_still_running", "trial_actual_cgroup_population_mismatch"):
                        raise
                except FileNotFoundError:
                    # The actor publishes its bounded receipt after stop; an
                    # absent receipt is not successful proof.
                    pass
            pause(2)
        raise Refused("trial_offline_expiry_not_observed_before_bounded_timeout")
    finally:
        # Restart only the exact owned transport even if observation fails.
        host.run(["/usr/bin/systemctl", "start", transport])
        need(service_state(host, transport) == "active", "owned_transport_restart_failed_requires_inspection")


def completed_trial_report(cfg, bundle, installer, host, status, trial_id):
    need(status.get("proof_sha256") and status.get("retired_at") and status.get("offline_witness_sha256"), "trial_complete_proof_not_observed")
    pin(status["proof_sha256"])
    pin(status["offline_witness_sha256"])
    report = qualification_report(cfg, bundle, installer, host, {"installation": "activation-requested"})
    for check in report["checks"][2:]:
        check["result"] = "passed"
        check["evidence"] = "Actual canonical qualification trial " + trial_id + " proof " + status["proof_sha256"] + "; lifecycle/network ACKs, exact local offline expiry witness and confirmed retirement. Runner SSH observations remain runner reported."
    return report


def finish_trial_report(cfg, bundle, installer, host, status, trial_id, staging, executable):
    output = staging / ("qualification-complete-" + trial_id + ".json")
    if output.exists() or output.is_symlink():
        report = strict_json(file_bytes(output, 16 * 1024))
        need(report.get("enrollment_id") == bundle["enrollment_id"] and report.get("profile_id") == bundle["profile_id"]
             and report.get("binding_sha256") == bundle["binding_sha256"] and report.get("source_sha") == cfg["source_sha"], "retained_trial_report_binding_changed")
    else:
        report = completed_trial_report(cfg, bundle, installer, host, status, trial_id)
        write_exact(output, (json.dumps(report, sort_keys=True) + "\n").encode())
    result = subprocess.run([str(executable), "--qualification-report=" + str(output), "--install-config=" + str(staging / "operator.json"), "--output=" + str(staging / "identity")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45)
    need(result.returncode == 0, "native_report_upload_unavailable_retain_actual_witness")
    return {"trial": "retired-with-proof", "native_qualification": False, "administrator_review_required": True}


def qualification_interrupt(*_args):
    raise InterruptedError("qualification interrupted")


def retained_witness_matches(witness, status):
    need(witness.get("version") == 1 and witness.get("generation") == 3 and witness.get("cgroup_populated") is False,
         "retained_offline_witness_invalid")
    for name in ("trial_id", "sandbox_id", "runtime_id", "binding_sha256", "source_sha", "created_at", "expires_at"):
        need(witness.get(name) == status.get(name), "retained_offline_witness_binding_changed")


def resume_interrupted_transport(cfg, staging, host, trial_id):
    transport = cfg["installation"]["unit_prefix"] + "-transport.service"
    if service_state(host, transport) != "inactive":
        return
    path = staging / ("qualification-pause-" + trial_id + ".json")
    need(path.exists(), "owned_transport_inactive_requires_explicit_install_activation")
    journal = strict_json(file_bytes(path, 32768))
    need(journal.get("trial_id") == trial_id and journal.get("source_sha") == cfg["source_sha"], "qualification_recovery_journal_changed")
    print("A previous authorized qualification pause left this installation's transport stopped. Recovery does not create native proof.", flush=True)
    with open("/dev/tty", "r+") as terminal:
        terminal.write("Type RESUME to restart only this installation's transport and allow bounded cleanup: ")
        terminal.flush()
        need(terminal.readline(32).strip() == "RESUME", "qualification_transport_recovery_not_confirmed")
    host.run(["/usr/bin/systemctl", "start", transport])
    need(service_state(host, transport) == "active", "qualification_transport_recovery_failed")


def await_trial_retirement(cfg, bundle, installer, host, trial_id, staging, executable):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        status = trial_command(cfg, staging, executable, trial_id)
        validate_trial_view(status, bundle, cfg, trial_id)
        if status.get("proof_sha256") and status.get("retired_at"):
            return finish_trial_report(cfg, bundle, installer, host, status, trial_id, staging, executable)
        time.sleep(2)
    raise Refused("trial_cleanup_pending_no_complete_proof_retain_witness")


def run_qualification(trial_id):
    need(os.geteuid() == 0 and platform.system() == "Linux" and platform.machine() in ("x86_64", "amd64"), "explicit_linux_amd64_host_admin_required")
    need(str(uuid.UUID(trial_id)) == trial_id and uuid.UUID(trial_id).int != 0, "invalid_qualification_trial_identity")
    state = Path(__file__).absolute().parent
    cfg = strict_json(file_bytes(state / "enrollment-config.json", 32768))
    need(Path(cfg["installation"]["state_root"]) == state, "qualification_installed_state_root_mismatch")
    enrollment_id = state.name
    need(str(uuid.UUID(enrollment_id)) == enrollment_id, "qualification_requires_ui_enrolled_installation")
    staging = private_directory(Path("/var/lib/tunnex-sandbox-enrollment") / enrollment_id)
    spec = importlib.util.spec_from_file_location("tunnex_qualification_installer", state / "install.py")
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    installer.validate(cfg)
    completed_installation(cfg, installer)
    host = installer.Host()
    executable = state / "bin/tunnex-sandbox-runner-enroll"
    bundle = strict_json(file_bytes(staging / "identity/enrollment.json", 256 * 1024))
    resume_interrupted_transport(cfg, staging, host, trial_id)
    print("Qualification will pause only this installation's transport across the trial's original expiry. The actor/helper and hard expiry guard stay active.", flush=True)
    with open("/dev/tty", "r+") as terminal:
        terminal.write("Type QUALIFY to observe this exact owned trial; Enter cancels before any service change: ")
        terminal.flush()
        need(terminal.readline(32).strip() == "QUALIFY", "qualification_pause_not_confirmed")
    status = trial_command(cfg, staging, executable, trial_id)
    expires = validate_trial_view(status, bundle, cfg, trial_id)
    if status.get("proof_sha256") and status.get("retired_at") and status.get("offline_witness_sha256"):
        return finish_trial_report(cfg, bundle, installer, host, status, trial_id, staging, executable)
    witness_path = staging / ("qualification-witness-" + trial_id + ".json")
    if witness_path.exists() or witness_path.is_symlink():
        retained_witness_matches(strict_json(file_bytes(witness_path, 16 * 1024)), status)
        trial_command(cfg, staging, executable, trial_id, witness_path)
        return await_trial_retirement(cfg, bundle, installer, host, trial_id, staging, executable)
    while status["phase"] != "awaiting_expiry":
        need(not status.get("retired_at") and datetime.now(timezone.utc) < expires and status["phase"] not in ("failed", "canceled", "revoked"), "trial_not_available_for_offline_observation")
        print("Waiting for actual control-plane Ready, stop and resumed Ready observations.", flush=True)
        time.sleep(2)
        status = trial_command(cfg, staging, executable, trial_id)
        validate_trial_view(status, bundle, cfg, trial_id)
    previous = signal.signal(signal.SIGTERM, qualification_interrupt)
    try:
        write_exact(staging / ("qualification-pause-" + trial_id + ".json"), (json.dumps(status, sort_keys=True) + "\n").encode())
        witness = observe_offline_expiry(cfg, status, host)
    finally:
        signal.signal(signal.SIGTERM, previous)
    witness["transport_resumed_at"] = observed_time()
    path = staging / ("qualification-witness-" + trial_id + ".json")
    write_exact(path, (json.dumps(witness, sort_keys=True) + "\n").encode())
    trial_command(cfg, staging, executable, trial_id, path)
    return await_trial_retirement(cfg, bundle, installer, host, trial_id, staging, executable)


def activation_ceremony(cfg, host):
    print("Installation complete. Creation stays blocked until the API observes this runner and trusted native qualification.", flush=True)
    with open("/dev/tty", "r+") as terminal:
        terminal.write("Type ACTIVATE to start the bounded runner now (services remain disabled), or Enter to leave it stopped: ")
        terminal.flush()
        confirmation = terminal.readline(32).strip()
    if confirmation != "ACTIVATE":
        return {"installation": "installed-disabled", "services_started": False, "services_enabled": False,
                "native_qualification": False, "connected": False}
    return activate(cfg, host, confirmation)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("enrollment-id", "api-url", "bundle-url", "bundle-sha256", "source-sha", "edition"):
        parser.add_argument("--" + flag)
    parser.add_argument("--qualification-trial-id")
    options = parser.parse_args()
    try:
        if options.qualification_trial_id:
            need(not any(getattr(options, flag.replace("-", "_")) for flag in ("enrollment-id", "api-url", "bundle-url", "bundle-sha256", "source-sha", "edition")), "qualification_uses_only_installed_public_configuration")
            print(json.dumps(run_qualification(options.qualification_trial_id), sort_keys=True))
        else:
            need(all(getattr(options, flag.replace("-", "_")) for flag in ("enrollment-id", "api-url", "bundle-url", "bundle-sha256", "source-sha", "edition")), "required_public_bootstrap_parameters_missing")
            print(json.dumps(run(options), sort_keys=True))
    except Refused as error:
        print(str(error) + ": inspect the stated host prerequisite or public pin; retain private staging and retry the same enrollment before expiry. Revoke it in the UI to cancel. Partial installs require inspection.", file=sys.stderr)
        raise SystemExit(1)
    except (ValueError, OSError, TypeError, KeyError, tarfile.TarError, subprocess.SubprocessError, getpass.GetPassWarning):
        print("runner_enrollment_refused: inspect host prerequisites and retained private staging; retry the same enrollment before expiry or revoke it in the UI. No packages or protections were changed. A partial install requires inspection.", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
