#!/usr/bin/env python3
"""Enroll and install one scoped sandbox runner. Never install host dependencies."""

import argparse
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
import ssl
import stat
import struct
import subprocess
import sys
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
    keys(bundle, ("enrollment_id", "certificate", "runner_ca", "api_ca", "install"))
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
            return activation_ceremony(cfg, host)
    elif not (staging / "layout.json").exists():
        layout = select_layout(options.enrollment_id, host)
        write_exact(staging / "layout.json", (json.dumps(layout, sort_keys=True) + "\n").encode())
    layout = strict_json(file_bytes(staging / "layout.json", 32768))
    print("Generate private machine identities locally; paste the separate enrollment token at the hidden prompt.", flush=True)
    token = secret_prompt("Enrollment token: ")
    need(32 <= len(token) <= 4096 and not re.search(r"[\x00-\x20]", token), "invalid_bootstrap_token")
    result = subprocess.run([str(executable), "--server=" + options.api_url, "--enrollment=" + options.enrollment_id,
                             "--output=" + str(staging / "identity")], input=(token + "\n").encode(),
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
    print("Host structure checked. Downloading exact approved images; this does not qualify a new host.", flush=True)
    for image, public in zip(cfg["images"], bundle["install"]["images"]):
        download(public["url"], image["sha256"], image["path"], 512 * MIB)
        installer.verify_image(image)
    verified = installer.bundle_payload(cfg)
    write_exact(config_path, (json.dumps(cfg, sort_keys=True) + "\n").encode())
    print("Installing the verified bounded runner with stopped, disabled services.", flush=True)
    installer.install(cfg, verified, host)
    return activation_ceremony(cfg, host)


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
        parser.add_argument("--" + flag, required=True)
    options = parser.parse_args()
    try:
        print(json.dumps(run(options), sort_keys=True))
    except Refused as error:
        print(str(error) + ": inspect the stated host prerequisite or public pin; retain private staging and retry the same enrollment before expiry. Revoke it in the UI to cancel. Partial installs require inspection.", file=sys.stderr)
        raise SystemExit(1)
    except (ValueError, OSError, TypeError, KeyError, tarfile.TarError, subprocess.SubprocessError, getpass.GetPassWarning):
        print("runner_enrollment_refused: inspect host prerequisites and retained private staging; retry the same enrollment before expiry or revoke it in the UI. No packages or protections were changed. A partial install requires inspection.", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
