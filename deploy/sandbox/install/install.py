#!/usr/bin/env python3
"""Offline, operator-configured Linux sandbox installation. Never enable services."""

import argparse
import base64
from contextlib import ExitStack
import fcntl
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import urllib.parse
import uuid


MIB = 1024 * 1024
SHA = re.compile(r"^[0-9a-f]{64}$")
NAME = re.compile(r"^[a-z][a-z0-9_-]{0,30}$")
PATH = re.compile(r"^/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
TOOLS = ("/usr/bin/python3", "/usr/bin/systemctl", "/usr/bin/podman", "/usr/bin/runc",
         "/usr/bin/docker", "/usr/bin/wg", "/usr/sbin/ip", "/usr/sbin/nft",
         "/usr/bin/nsenter", "/usr/bin/newuidmap", "/usr/bin/newgidmap",
         "/usr/sbin/mkfs.ext4", "/usr/sbin/debugfs", "/usr/sbin/useradd", "/usr/sbin/groupadd")
ASSETS = {
    "deploy/sandbox/ci/README.md", "deploy/sandbox/Containerfile",
    "deploy/sandbox/sandbox-entrypoint.py", "deploy/sandbox/build-image.sh",
    "deploy/sandbox/network-plan-contract.json", "deploy/sandbox/alpine/Containerfile",
    "deploy/sandbox/alpine/entrypoint.sh", "deploy/sandbox/alpine/build-image.sh",
    "deploy/sandbox/install/install.py", "deploy/sandbox/install/README.md",
    "deploy/sandbox/install/example.json",
    "deploy/sandbox/install/enroll.py",
    "deploy/sandbox/ubuntu-base/delivery.py", "deploy/sandbox/ubuntu-base/archive.py",
    "deploy/sandbox/ubuntu-base/Containerfile", "deploy/sandbox/ubuntu-base/public-inputs.json",
    "deploy/sandbox/ubuntu-base/ubuntu26-amd64.lock.json", "deploy/sandbox/ubuntu-base/README.md",
}
COMMANDS = ("tunnex-sandbox-runtime", "tunnex-sandbox-ssh-probe", "tunnex-sandbox-runner-enroll")


def need(condition, message):
    if not condition:
        raise ValueError(message)


def keys(value, required, optional=()):
    need(isinstance(value, dict) and set(required) <= set(value)
         and set(value) <= set(required) | set(optional), "unknown or missing configuration field")


def absolute(value):
    need(isinstance(value, str) and PATH.fullmatch(value)
         and str(PurePosixPath(value)) == value and ".." not in PurePosixPath(value).parts,
         "clean absolute path required")
    return value


def identifier(value):
    need(isinstance(value, str), "UUID required")
    parsed = uuid.UUID(value)
    need(parsed.int != 0 and str(parsed) == value, "canonical nonzero UUID required")
    return value


def digest(value):
    need(isinstance(value, str) and SHA.fullmatch(value), "SHA256 pin required")
    return value


def fingerprint(value):
    need(isinstance(value, str) and value.startswith("sha256:"), "immutable config digest required")
    digest(value.removeprefix("sha256:"))
    return value


def strict_json(raw):
    def pairs(entries):
        result = {}
        for key, value in entries:
            need(key not in result, "duplicate JSON field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def file_hash(path, maximum):
    info = Path(path).lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_size <= maximum, "bounded regular input required")
    result = hashlib.sha256()
    with open(path, "rb") as stream:
        need(os.fstat(stream.fileno()).st_ino == info.st_ino, "input changed")
        for block in iter(lambda: stream.read(MIB), b""):
            result.update(block)
    return result.hexdigest()


def public_probe(value):
    need(isinstance(value, str), "public probe identity required")
    parts = value.strip().split()
    need(len(parts) == 2 and parts[0] == "ssh-ed25519", "one canonical public ed25519 key required")
    raw = base64.b64decode(parts[1], validate=True)
    need(len(raw) == 51 and raw[:19] == b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
         and base64.b64encode(raw).decode() == parts[1], "invalid public probe key")
    return " ".join(parts) + "\n"


def mount_unit(value):
    unit = value.strip("/").replace("-", "\\x2d").replace("/", "-") + ".mount"
    need(len(unit) <= 255, "bounded systemd mount unit name required")
    return unit


def https(value):
    need(isinstance(value, str), "HTTPS URL required")
    parsed = urllib.parse.urlsplit(value)
    need(parsed.scheme == "https" and parsed.hostname and not parsed.username
         and not parsed.password and parsed.path in ("", "/")
         and not parsed.query and not parsed.fragment, "explicit HTTPS origin required")
    return value


def validate(cfg):
    keys(cfg, ("version", "edition", "source_sha", "bundle", "installation", "gateway", "controller",
               "org_id", "probe_public_key", "credentials", "images"))
    need(cfg["version"] == 1 and cfg["edition"] in ("open", "enterprise"), "unsupported schema or edition")
    need(isinstance(cfg["source_sha"], str) and re.fullmatch(r"[0-9a-f]{40}", cfg["source_sha"]), "source commit required")
    identifier(cfg["org_id"])
    public_probe(cfg["probe_public_key"])
    keys(cfg["bundle"], ("path", "sha256"))
    absolute(cfg["bundle"]["path"])
    digest(cfg["bundle"]["sha256"])
    layout = cfg["installation"]
    keys(layout, ("state_root", "run_root", "service_user", "uid", "gid", "subuid_start", "subuid_count",
                  "unit_prefix", "workspace_mib", "storage_mib", "io_device"))
    state, run = absolute(layout["state_root"]), absolute(layout["run_root"])
    need(state != run and not state.startswith(run + "/") and not run.startswith(state + "/"), "overlapping roots")
    need(run.startswith("/run/"), "host systemd runtime root must be below /run")
    mount_unit(state + "/workload-assets")
    mount_unit(state + "/worker/storage")
    need(absolute(layout["io_device"]).startswith("/dev/"), "explicit backing IO device required")
    need(isinstance(layout["service_user"], str) and layout["service_user"] != "root"
         and NAME.fullmatch(layout["service_user"]) and re.fullmatch(r"[a-z][a-z0-9]{0,24}", layout["unit_prefix"]), "invalid service identity")
    for name in ("uid", "gid", "subuid_start", "subuid_count", "workspace_mib", "storage_mib"):
        need(type(layout[name]) is int, "integer limit required")
    need(1000 <= layout["uid"] < 65534 and 1000 <= layout["gid"] < 65534, "dedicated nonroot identity required")
    need(layout["subuid_start"] >= 65536 and layout["subuid_count"] == 65536
         and layout["subuid_start"] + 65536 <= 2**32, "bounded subordinate identity required")
    need(layout["workspace_mib"] == 256 and 512 <= layout["storage_mib"] <= 8192, "bounded storage required")
    gateway = cfg["gateway"]
    keys(gateway, ("node_id", "container_id", "image_digest", "interface"), ("terminal" ,))
    identifier(gateway["node_id"])
    digest(gateway["container_id"])
    fingerprint(gateway["image_digest"])
    need(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", gateway["interface"]), "invalid gateway interface")
    if "terminal" in gateway:
        terminal = gateway["terminal"]
        keys(terminal, ("node_id", "endpoint", "runtime_endpoint"))
        identifier(terminal["node_id"])
        need(terminal["node_id"] != gateway["node_id"], "separate terminal gateway required")
        for name in ("endpoint", "runtime_endpoint"):
            host, port = terminal[name].rsplit(":", 1)
            address = ipaddress.IPv4Address(host)
            need(address.is_private and not address.is_loopback and not address.is_link_local
                 and 0 < int(port) < 65536, "private IPv4 gateway endpoint required")
    controller = cfg["controller"]
    keys(controller, ("url", "server_name", "uri", "api_url"))
    https(controller["url"])
    https(controller["api_url"])
    need(isinstance(controller["server_name"], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", controller["server_name"]), "TLS server name required")
    uri = urllib.parse.urlsplit(controller["uri"])
    need(uri.scheme and not uri.query and not uri.fragment and not uri.username, "exact controller URI required")
    keys(cfg["credentials"], ("probe_key", "api_ca", "runner_certificate", "runner_key", "runner_ca"))
    for path in cfg["credentials"].values():
        absolute(path)
    need(isinstance(cfg["images"], list) and 1 <= len(cfg["images"]) <= 4, "one to four qualified profiles required")
    seen = set()
    for image in cfg["images"]:
        keys(image, ("template_id", "path", "sha256", "config_digest", "architecture", "qualification_evidence"))
        identifier(image["template_id"])
        need(image["template_id"] not in seen, "duplicate profile")
        seen.add(image["template_id"])
        absolute(image["path"])
        digest(image["sha256"])
        fingerprint(image["config_digest"])
        need(image["architecture"] == "amd64", "ARM64 is compile-only; native activation unavailable")
        need(isinstance(image["qualification_evidence"], str) and 0 < len(image["qualification_evidence"].strip()) <= 512
             and not image["qualification_evidence"].strip().upper().startswith("REPLACE"),
             "operator native qualification reference required")
    return cfg


def bundle_payload(cfg):
    path = cfg["bundle"]["path"]
    info = Path(path).lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_size <= 100 * MIB, "bounded regular bundle required")
    with open(path, "rb") as stream:
        current = os.fstat(stream.fileno())
        need((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino), "bundle changed")
        raw = stream.read(100 * MIB + 1)
    need(len(raw) <= 100 * MIB and hashlib.sha256(raw).hexdigest() == cfg["bundle"]["sha256"], "bundle checksum mismatch")
    names = {f"bin/{command}-{edition}-linux-amd64" for command in COMMANDS for edition in ("open", "enterprise")}
    names |= {"bin/tunnex-sandbox-network-linux-amd64", "bin/tunnex-sandbox-bootstrap-linux-amd64"} | ASSETS
    payload = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        for member in archive:
            need(member.name in names | {"manifest.json", "SHA256SUMS"} and member.name not in payload
                 and member.isfile() and member.size <= 64 * MIB, "invalid public bundle inventory")
            payload[member.name] = archive.extractfile(member).read()
            need(sum(map(len, payload.values())) <= 256 * MIB, "oversized decompressed bundle")
    need(set(payload) == names | {"manifest.json", "SHA256SUMS"}, "incomplete public bundle")
    manifest = strict_json(payload["manifest.json"])
    need(manifest.get("schema_version") == 1 and manifest.get("source_sha") == cfg["source_sha"]
         and manifest.get("os") == "linux" and manifest.get("architecture") == "amd64"
         and manifest.get("api_editions") == ["open", "enterprise"]
         and manifest.get("native_runtime_qualification") is False
         and manifest.get("workload_images_built") is False, "bundle identity or qualification mismatch")
    records = {name: {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
               for name, raw in payload.items() if name in names}
    need(manifest.get("files") == records, "bundle contents differ from manifest")
    summed = "".join(f"{hashlib.sha256(raw).hexdigest()}  {name}\n" for name, raw in sorted(payload.items()) if name != "SHA256SUMS")
    need(payload["SHA256SUMS"] == summed.encode(), "bundle inner checksums mismatch")
    for name in names:
        if name.startswith("bin/"):
            raw = payload[name]
            need(len(raw) >= 64 and raw[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", raw, 18)[0] == 62, "native AMD64 executable required")
    return payload


def verify_image(image):
    need(file_hash(image["path"], 512 * MIB) == image["sha256"], "image archive checksum mismatch")
    with tarfile.open(image["path"], "r:*") as archive:
        members = archive.getmembers()
        need(len(members) <= 4096, "oversized image inventory")
        entries = {}
        for member in members:
            path = PurePosixPath(member.name)
            need(not path.is_absolute() and ".." not in path.parts and not member.issym()
                 and not member.islnk() and (member.isfile() or member.isdir())
                 and member.name not in entries, "unsafe image archive")
            entries[member.name] = member
        need("manifest.json" in entries and entries["manifest.json"].size <= MIB, "Docker archive manifest required")
        manifest = strict_json(archive.extractfile(entries["manifest.json"]).read())
        need(isinstance(manifest, list) and len(manifest) == 1, "one immutable image per archive required")
        record = manifest[0]
        need(isinstance(record.get("Layers"), list) and record["Layers"]
             and all(layer in entries and entries[layer].isfile() for layer in record["Layers"]), "missing image layers")
        config = entries.get(record.get("Config"))
        need(config is not None and config.isfile() and config.size <= 2 * MIB, "image config required")
        raw = archive.extractfile(config).read()
        need("sha256:" + hashlib.sha256(raw).hexdigest() == image["config_digest"], "image config pin mismatch")
        metadata = strict_json(raw)
        need(metadata.get("architecture") == "amd64" and metadata.get("os") == "linux", "native image platform mismatch")


class Host:
    def read(self, path):
        return Path(path).read_text()

    def stat(self, path):
        resolved = Path(path).resolve(strict=True)
        safe_parents(resolved.parent)
        return resolved.stat()

    def run(self, arguments, **kwargs):
        result = subprocess.run(arguments, check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                timeout=60, **kwargs)
        need(len(result.stdout) <= 2 * MIB, "oversized tool output")
        return result.stdout.decode()

    def identity(self):
        return platform.system(), platform.machine()


def identities(cfg, host):
    layout = cfg["installation"]
    user, uid, gid = layout["service_user"], layout["uid"], layout["gid"]
    passwd = [line.split(":") for line in host.read("/etc/passwd").splitlines() if line]
    groups = [line.split(":") for line in host.read("/etc/group").splitlines() if line]
    home = layout["state_root"] + "/worker/home"
    for row in passwd:
        need(len(row) == 7, "invalid account metadata")
        if row[0] == user or int(row[2]) == uid:
            need(row[0] == user and int(row[2]) == uid and int(row[3]) == gid
                 and row[5] == home and row[6] == "/usr/sbin/nologin", "service UID collision")
    for row in groups:
        need(len(row) == 4, "invalid group metadata")
        if row[0] == user or int(row[2]) == gid:
            need(row[0] == user and int(row[2]) == gid and not row[3], "service GID collision")
    for path in ("/etc/subuid", "/etc/subgid"):
        subordinate_ranges(host.read(path), user, uid, layout["subuid_start"])
    return any(row[0] == user for row in passwd), any(row[0] == user for row in groups)


def subordinate_ranges(text, user, uid, reserved_start):
    owners = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        row = line.split(":")
        need(len(row) == 3 and row[1].isdigit() and row[2].isdigit(), "invalid subordinate metadata")
        owner, start, count = row[0], int(row[1]), int(row[2])
        need(count > 0, "invalid subordinate range")
        if owner in (user, str(uid)):
            need(owner == user and start == reserved_start and count == 65536, "changed subordinate identity")
        else:
            need(start + count <= reserved_start or start >= reserved_start + 65536, "subordinate range collision")
        owners.append(owner)
    need(owners.count(user) <= 1, "duplicate subordinate identity")
    return user in owners


def check(cfg, host, *, installed_report=False):
    need(host.identity() in (("Linux", "x86_64"), ("Linux", "amd64")), "Linux AMD64 native host required; ARM64 compile-only")
    for tool in TOOLS:
        info = host.stat(tool)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o111
             and not info.st_mode & 0o022, "missing or mutable required packaged tool")
    for tool in ("/usr/bin/newuidmap", "/usr/bin/newgidmap"):
        need(host.stat(tool).st_mode & stat.S_ISUID, "existing setuid subordinate mapping helper required")
    version = host.run(["/usr/bin/systemctl", "--version"])
    match = re.match(r"systemd (\d+)\b", version)
    need(match and int(match[1]) >= 254, "systemd DelegateSubgroup support required")
    need(" - cgroup2 " in host.read("/proc/self/mountinfo"), "unified cgroup v2 required")
    need({"cpu", "memory", "pids", "io"} <= set(host.read("/sys/fs/cgroup/cgroup.controllers").split()), "cgroup resource controllers required")
    need("overlay" in host.read("/proc/filesystems").split(), "native overlay filesystem required")
    io_device = host.stat(cfg["installation"]["io_device"])
    need(stat.S_ISBLK(io_device.st_mode) and io_device.st_uid == 0, "configured IO device must be an existing block device")
    parent = Path(cfg["installation"]["state_root"]).parent
    while not parent.exists():
        parent = parent.parent
    need(host.stat(str(parent)).st_dev == io_device.st_rdev, "IO device must back the installation filesystem")
    identities(cfg, host)
    prefix = cfg["installation"]["unit_prefix"]
    for unit in (() if installed_report else (prefix + "-actor.service", prefix + "-transport.service", prefix + "-network.service")):
        # Installation never stops, replaces or adopts an active service.
        state = dict(line.split("=", 1) for line in host.run(["/usr/bin/systemctl", "show", unit, "--property=ActiveState,UnitFileState"]).splitlines())
        need(state.get("ActiveState") in ("inactive", "failed", "") and state.get("UnitFileState", "") in ("disabled", "", "not-found"), "owned service must be stopped and disabled")
    gateway = cfg["gateway"]
    output = host.run(["/usr/bin/docker", "inspect", "--type=container", "--format",
                       '{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"namespace":{{json .NetworkSettings.SandboxKey}}}', gateway["container_id"]])
    metadata = strict_json(output)
    need(metadata.get("id") == gateway["container_id"] and metadata.get("image") == gateway["image_digest"]
         and metadata.get("running") is True and re.fullmatch(r"/var/run/docker/netns/[0-9a-f]{12,64}", metadata.get("namespace", "")), "exact local Docker gateway required")
    return {"capabilities": "supported", "new_host_native_qualification": False,
            "workload_slots": 1, "memory_mib": 128, "cpus": 1, "pids": 64, "max_ttl_seconds": 900,
            "services_started": False, "services_enabled": False}


def render(cfg, payload):
    layout, gateway = cfg["installation"], cfg["gateway"]
    state, run, prefix, user = layout["state_root"], layout["run_root"], layout["unit_prefix"], layout["service_user"]
    actor, transport, network, slice_unit = (prefix + suffix for suffix in ("-actor.service", "-transport.service", "-network.service", ".slice"))
    binding = {"Mode": "persistent", "Admission": "organization", "OrgID": cfg["org_id"], "GatewayID": gateway["node_id"],
               "MemoryMiB": 128, "CPUs": 1, "MaxTTLSeconds": 900,
               "Profiles": [{"TemplateID": image["template_id"], "ConfigDigest": image["config_digest"], "Architecture": "amd64",
                             "PIDs": 64, "QualificationEvidence": image["qualification_evidence"]} for image in cfg["images"]]}
    if "terminal" in gateway:
        terminal = gateway["terminal"]
        binding["RemoteTerminal"] = {"GatewayID": terminal["node_id"], "GatewayEndpoint": terminal["endpoint"], "RuntimeGatewayEndpoint": terminal["runtime_endpoint"]}
    edition = cfg["edition"]
    binaries = {command: payload[f"bin/{command}-{edition}-linux-amd64"] for command in COMMANDS}
    binaries.update({command: payload[f"bin/{command}-linux-amd64"] for command in ("tunnex-sandbox-network", "tunnex-sandbox-bootstrap")})
    remote = {"URL": cfg["controller"]["url"], "ServerName": cfg["controller"]["server_name"], "ControllerURI": cfg["controller"]["uri"],
              "CertificateFile": state + "/worker/identity/runner-cert.pem", "PrivateKeyFile": state + "/worker/identity/runner-key.pem", "CAFile": state + "/worker/identity/runner-ca.pem"}
    runtime_cfg = {"StateRoot": state, "RunRoot": run, "ActorControlCgroup": "/" + slice_unit + "/" + actor + "/control",
                   "Binding": binding, "APIUID": layout["uid"], "Supervision": {"Enabled": True, "ActorUID": layout["uid"], "SupervisorUID": layout["uid"], "ProbePublicKey": public_probe(cfg["probe_public_key"])},
                   "Remote": remote, "Server": cfg["controller"]["api_url"], "BootstrapBinary": state + "/bin/tunnex-sandbox-bootstrap",
                   "BootstrapSHA256": hashlib.sha256(binaries["tunnex-sandbox-bootstrap"]).hexdigest(),
                   "CAFile": state + "/worker/main-api-ca.pem", "ProbeKeyFile": state + "/worker/main-probe-key"}
    mounts = []
    files = {}
    for name, size, destination in (("workload-assets", 256, state + "/workload-assets"), ("storage", layout["storage_mib"], state + "/worker/storage")):
        unit = mount_unit(destination)
        mounts.append(unit)
        files[unit] = f"[Unit]\nDescription=Tunnex bounded {name}\nBefore={actor}\n\n[Mount]\nWhat={state}/{name}.ext4\nWhere={destination}\nType=ext4\nOptions=loop,nodev,nosuid\n\n[Install]\nWantedBy=multi-user.target\n"
    files[slice_unit] = f"[Slice]\nMemoryAccounting=yes\nMemoryMax=224M\nMemorySwapMax=0\nTasksAccounting=yes\nTasksMax=256\nIOAccounting=yes\nIOReadBandwidthMax={layout['io_device']} 32M\nIOWriteBandwidthMax={layout['io_device']} 8M\n"
    files[actor] = f"[Unit]\nDescription=Tunnex sandbox actor and independent absolute expiry guard\nRequires={network} {' '.join(mounts)}\nAfter={network} {' '.join(mounts)}\n\n[Service]\nType=simple\nUser={user}\nGroup={user}\nSlice={slice_unit}\nWorkingDirectory={state}/worker\nExecStartPre=/usr/bin/python3 {state}/install.py preload --config={state}/preload.json\nExecStart={state}/bin/tunnex-sandbox-runtime --config={state}/worker/main-config.json --role=actor\nRestart=on-failure\nRestartSec=2\nKillMode=control-group\nKillSignal=SIGKILL\nSendSIGKILL=yes\nDelegate=yes\nDelegateSubgroup=control\nRuntimeDirectory={run.removeprefix('/run/')}/worker {run.removeprefix('/run/')}/api\nRuntimeDirectoryMode=0700\nRuntimeDirectoryPreserve=yes\nUMask=0077\nEnvironment=GOMAXPROCS=1 GOMEMLIMIT=48MiB\nNoNewPrivileges=no\n\n[Install]\nWantedBy=multi-user.target\n"
    files[transport] = f"[Unit]\nDescription=Tunnex sandbox controller transport\nRequires={actor}\nAfter={actor}\n\n[Service]\nType=simple\nUser={user}\nGroup={user}\nSlice={slice_unit}\nWorkingDirectory={state}/worker\nExecStart={state}/bin/tunnex-sandbox-runtime --config={state}/worker/main-config.json --role=transport\nRestart=on-failure\nRestartSec=2\nKillMode=control-group\nUMask=0077\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nRestrictNamespaces=yes\nProtectControlGroups=yes\nProtectSystem=strict\nProtectHome=yes\nReadWritePaths={state}/worker/runner-protocol\nEnvironment=GOMAXPROCS=1 GOMEMLIMIT=32MiB\n\n[Install]\nWantedBy=multi-user.target\n"
    probe_hash = hashlib.sha256(binaries["tunnex-sandbox-ssh-probe"]).hexdigest()
    flags = f"--socket={run}/helper/control.sock --state={state}/helper/manifests --worker-uid={layout['uid']} --subuid-start={layout['subuid_start']} --subuid-count=65536 --gateway-org-id={cfg['org_id']} --gateway-node-id={gateway['node_id']} --gateway-runtime-id={gateway['container_id']} --gateway-image-digest={gateway['image_digest']} --gateway-interface={gateway['interface']} --probe-binary={state}/bin/tunnex-sandbox-ssh-probe --probe-sha256={probe_hash}"
    files[network] = f"[Unit]\nDescription=Tunnex confined sandbox network helper\nAfter=network.target docker.service\n\n[Service]\nType=simple\nUser=root\nGroup={user}\nExecStart={state}/bin/tunnex-sandbox-network {flags}\nRestart=on-failure\nRestartSec=2\nRuntimeDirectory={run.removeprefix('/run/')}/helper\nRuntimeDirectoryMode=0750\nRuntimeDirectoryPreserve=yes\nUMask=0007\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nReadWritePaths={state}/helper {run}/helper\nMemoryMax=64M\nTasksMax=32\nEnvironment=GOMAXPROCS=1 GOMEMLIMIT=24MiB\n\n[Install]\nWantedBy=multi-user.target\n"
    return files, runtime_cfg, binaries


def safe_parents(path):
    for parent in (Path(path), *Path(path).parents):
        if parent.exists() or parent.is_symlink():
            info = parent.lstat()
            need(not stat.S_ISLNK(info.st_mode), "symlink installation parent")
            need(info.st_uid == 0 and not info.st_mode & 0o022, "mutable installation parent")


def write_new(path, raw, mode, uid=0, gid=0):
    with open(path, "xb") as stream:
        os.fchmod(stream.fileno(), mode)
        os.fchown(stream.fileno(), uid, gid)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def private_input(path, uid):
    info = Path(path).lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid in (0, uid) and not info.st_mode & 0o077
         and 0 < info.st_size <= 32768, "private operator identity unavailable")
    with open(path, "rb") as stream:
        current = os.fstat(stream.fileno())
        need((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino), "private input changed")
        raw = stream.read(32769)
    need(0 < len(raw) <= 32768, "private input changed")
    return raw


def install(cfg, payload, host):
    need(os.geteuid() == 0, "explicit root install required")
    result = check(cfg, host)
    files, runtime_cfg, binaries = render(cfg, payload)
    state = Path(cfg["installation"]["state_root"])
    layout = cfg["installation"]
    uid, gid, user = layout["uid"], layout["gid"], layout["service_user"]
    need(layout["run_root"].startswith("/run/"), "systemd runtime root must be below /run")
    safe_parents(state.parent)
    safe_parents("/etc/systemd/system")
    config_hash = hashlib.sha256(json.dumps(cfg, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    marker = state / "installation.json"
    if state.exists():
        safe_parents(state)
        need(marker.is_file() and not marker.is_symlink(), "existing or incomplete installation refused")
        manifest = strict_json(marker.read_text())
        need(manifest.get("config_sha256") == config_hash, "changed installation configuration refused")
        for path, pin in manifest["files"].items():
            need(file_hash(path, 512 * MIB) == pin, "installed public artifact changed")
        return dict(result, installation="already-installed", native_qualification=False)
    need(not Path(layout["run_root"]).exists() and not Path(layout["run_root"]).is_symlink(), "foreign runtime root refused")
    for unit in files:
        target = Path("/etc/systemd/system") / unit
        need(not target.exists() and not target.is_symlink(), "unit collision")
    # Validate supplied private runtime identities without printing or generating
    # them. They are operator-owned runner/probe material, never a human SSH key.
    secrets = {}
    for name, path in cfg["credentials"].items():
        secrets[name] = private_input(path, uid)
    for image in cfg["images"]:
        verify_image(image)
    exists_user, exists_group = identities(cfg, host)
    if not exists_group:
        host.run(["/usr/sbin/groupadd", "--system", "--gid", str(gid), user])
    if not exists_user:
        # -K suppresses ambient automatic subID allocation; explicit ranges are
        # reserved below only after collision checks.
        host.run(["/usr/sbin/useradd", "--system", "--no-create-home", "--uid", str(uid), "--gid", str(gid),
                  "--home-dir", str(state / "worker/home"), "--shell", "/usr/sbin/nologin", "-K", "SUB_UID_COUNT=0", "-K", "SUB_GID_COUNT=0", user])
    with ExitStack() as stack:
        streams = []
        for path in ("/etc/subuid", "/etc/subgid"):
            safe_parents(path)
            stream = stack.enter_context(open(path, "r+"))
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            streams.append(stream)
        # Recheck both ranges under locks before appending either one.
        absent = [not subordinate_ranges(stream.read(), user, uid, layout["subuid_start"]) for stream in streams]
        for stream, missing in zip(streams, absent):
            if missing:
                stream.seek(0, os.SEEK_END)
                stream.write(f"{user}:{layout['subuid_start']}:65536\n")
                stream.flush()
                os.fsync(stream.fileno())
    state.mkdir(mode=0o755)
    for name in ("bin", "images", "helper", "helper/manifests", "worker", "worker/home", "worker/config", "worker/data", "worker/storage", "worker/main-control", "worker/persistent-control", "worker/runner-protocol", "worker/identity", "workload-assets"):
        path = state / name
        path.mkdir(mode=0o755 if name in ("bin", "images") else 0o700)
        if name.startswith("worker") or name == "workload-assets":
            os.chown(path, uid, gid)
    installed = {}
    def public(path, raw, mode=0o644):
        write_new(path, raw, mode)
        installed[str(path)] = hashlib.sha256(raw).hexdigest()
    for command, raw in binaries.items():
        public(state / "bin" / command, raw, 0o755)
    public(state / "install.py", payload["deploy/sandbox/install/install.py"])
    public(state / "enroll.py", payload["deploy/sandbox/install/enroll.py"])
    # Root-owned replay metadata contains public pins and local credential paths,
    # never private key bodies. The installed qualification command uses it.
    public(state / "enrollment-config.json", (json.dumps(cfg, sort_keys=True) + "\n").encode(), 0o600)
    copied_images = []
    for image in cfg["images"]:
        destination = state / "images" / (image["config_digest"][7:] + ".tar")
        need(not destination.exists(), "duplicate image config")
        with open(image["path"], "rb") as source, open(destination, "xb") as target:
            shutil.copyfileobj(source, target, MIB)
        os.chmod(destination, 0o644)
        need(file_hash(destination, 512 * MIB) == image["sha256"], "copied image archive changed")
        installed[str(destination)] = image["sha256"]
        copied_images.append(dict(image, path=str(destination)))
    public(state / "preload.json", (json.dumps({"installation": layout, "images": copied_images}, sort_keys=True) + "\n").encode())
    credential_paths = {"probe_key": "worker/main-probe-key", "api_ca": "worker/main-api-ca.pem", "runner_certificate": "worker/identity/runner-cert.pem", "runner_key": "worker/identity/runner-key.pem", "runner_ca": "worker/identity/runner-ca.pem"}
    for name, raw in secrets.items():
        write_new(state / credential_paths[name], raw, 0o600, uid, gid)
    runtime_raw = (json.dumps(runtime_cfg, sort_keys=True) + "\n").encode()
    write_new(state / "worker/main-config.json", runtime_raw, 0o600, uid, gid)
    installed[str(state / "worker/main-config.json")] = hashlib.sha256(runtime_raw).hexdigest()
    for name, size in (("workload-assets", 256), ("storage", layout["storage_mib"])):
        path = state / (name + ".ext4")
        with open(path, "xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.truncate(size * MIB)
        host.run(["/usr/sbin/mkfs.ext4", "-q", "-m", "0", "-F", "-E", f"root_owner={uid}:{gid}", str(path)])
        host.run(["/usr/sbin/debugfs", "-w", "-R", "set_inode_field <2> mode 040700", str(path)])
    for unit, body in files.items():
        public(Path("/etc/systemd/system") / unit, body.encode())
    public(marker, (json.dumps({"version": 1, "config_sha256": config_hash, "files": installed,
                                "native_qualification": False}, sort_keys=True) + "\n").encode())
    host.run(["/usr/bin/systemctl", "daemon-reload"])
    return dict(result, installation="installed-disabled", native_qualification=False)


def preload(path, host):
    # Called as ExecStartPre inside the actor service, before control dispatch.
    info = Path(path).lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022 and info.st_size <= 16384,
         "root-owned preload configuration required")
    cfg = strict_json(Path(path).read_bytes())
    keys(cfg, ("installation", "images"))
    layout = cfg["installation"]
    need(os.geteuid() == layout["uid"] and os.getegid() == layout["gid"], "dedicated preload identity required")
    state, run = absolute(layout["state_root"]), absolute(layout["run_root"])
    need(host.identity() in (("Linux", "x86_64"), ("Linux", "amd64")), "native AMD64 preload required")
    environment = {"PATH": "/usr/sbin:/usr/bin:/bin", "HOME": state + "/worker/home", "XDG_RUNTIME_DIR": run + "/worker",
                   "XDG_CONFIG_HOME": state + "/worker/config", "XDG_DATA_HOME": state + "/worker/data", "LC_ALL": "C"}
    command = ["/usr/bin/podman", "--root", state + "/worker/storage", "--runroot", run + "/worker/storage",
               "--storage-driver=overlay", "--cgroup-manager=cgroupfs", "--runtime=/usr/bin/runc"]
    for image in cfg["images"]:
        fingerprint(image["config_digest"])
        need(image["architecture"] == "amd64" and absolute(image["path"]).startswith(state + "/images/"), "foreign preload image")
        verify_image(image)
        try:
            output = host.run(command + ["image", "inspect", "--format", "{{.Id}} {{.Architecture}} {{.Os}}", image["config_digest"]], env=environment).strip()
        except subprocess.CalledProcessError:
            host.run(command + ["load", "--input", image["path"]], env=environment)
            output = host.run(command + ["image", "inspect", "--format", "{{.Id}} {{.Architecture}} {{.Os}}", image["config_digest"]], env=environment).strip()
        expected = image["config_digest"][7:]
        need(output in (f"{expected} amd64 linux", f"sha256:{expected} amd64 linux"), "actual preloaded image differs")
    # Mount units bound byte capacity; chown only their empty filesystem root.
    for name in ("workload-assets", "worker/storage"):
        owned = Path(state) / name
        need(owned.stat().st_uid == layout["uid"], "quota filesystem must be provisioned for worker ownership")
    return {"images": "preloaded-offline", "services_started": False, "native_qualification": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "check", "install", "preload"))
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    try:
        if args.action == "preload":
            result = preload(args.config, Host())
        else:
            absolute(args.config)
            need(Path(args.config).stat().st_size <= 32768, "bounded operator config required")
            cfg = validate(strict_json(Path(args.config).read_bytes()))
            payload = bundle_payload(cfg)
            for image in cfg["images"]:
                verify_image(image)
            if args.action == "plan":
                files, runtime_cfg, _ = render(cfg, payload)
                result = {"units": files, "runtime": runtime_cfg, "new_host_native_qualification": False,
                          "services_started": False, "services_enabled": False}
            elif args.action == "check":
                result = check(cfg, Host())
            else:
                result = install(cfg, payload, Host())
        print(json.dumps(result, sort_keys=True))
    except (ValueError, OSError, TypeError, KeyError, tarfile.TarError, subprocess.SubprocessError):
        parser.exit(1, "sandbox installation refused; services were not enabled or started; inspect any partial owned installation\n")


if __name__ == "__main__":
    main()
