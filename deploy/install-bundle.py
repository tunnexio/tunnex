#!/usr/bin/env python3
"""Verify an explicitly trusted, platform-specific local installation bundle.

This is an operator-selected private bundle, not a published release. The
installer and this verifier are operator-trusted entrypoints, obtained and
checked independently. No other bundle payload is executed before signature
and content verification. The public key is supplied outside the bundle.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile

KIND = "tunnex-local-install-bundle"
ROLES = {"api", "web", "nginx", "node-agent", "ai-engine", "postgres", "redis", "caddy"}
PRODUCT_ROLES = {"api", "web", "nginx", "node-agent"}
PAYLOAD = {
    "deploy/install.sh", "deploy/install-bundle.py", "deploy/tunnex.yml",
    "deploy/upgrade.sh", "deploy/upgrade-runner.sh", "deploy/ai-bootstrap.sh",
    "deploy/ai-gateway/config-managed.json",
}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def require(value, message):
    if not value:
        raise ValueError(message)


def fields(value, expected, label):
    require(isinstance(value, dict) and set(value) == set(expected), f"invalid {label} fields")


def unique_object(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(data)
    return h.hexdigest()


def bundle_file(root, name):
    require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9._/-]+", name), "invalid bundle path")
    relative = PurePosixPath(name)
    require(not relative.is_absolute() and str(relative) == name and all(x not in (".", "..") for x in relative.parts), "unsafe bundle path")
    path = root
    for part in relative.parts:
        path = path / part
        require(not path.is_symlink(), "symlink in bundle path")
    require(path.is_file() and path.resolve().is_relative_to(root), "missing bundle file")
    return path


def read_manifest(root, public_key, expected_sha256=None):
    key = Path(public_key).resolve(strict=True)
    require(key.is_file() and not key.is_relative_to(root), "supply the trusted public key independently, outside the bundle")
    path = bundle_file(root, "bundle.json")
    signature = bundle_file(root, "bundle.json.sig")
    require(path.stat().st_size <= 1024 * 1024 and signature.stat().st_size == 64, "invalid descriptor size")
    data = path.read_bytes()
    signature_bytes = signature.read_bytes()
    if expected_sha256 is not None:
        require(HEX64.fullmatch(expected_sha256) and hashlib.sha256(data).hexdigest() == expected_sha256, "bundle changed after initial verification")
    key_bytes = key.read_bytes()
    # Verify the same immutable bytes that are parsed, not a second path read.
    with tempfile.TemporaryDirectory(prefix="tunnex-bundle-signature-") as tmp:
        payload = Path(tmp, "bundle.json")
        sig = Path(tmp, "bundle.sig")
        trusted = Path(tmp, "trusted.pem")
        trusted.write_bytes(key_bytes)
        der = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(trusted), "-pubout", "-outform", "DER"], check=True, capture_output=True, timeout=15).stdout
        require(len(der) == 44 and der[:12].hex() == "302a300506032b6570032100", "trusted key must be Ed25519")
        payload.write_bytes(data)
        sig.write_bytes(signature_bytes)
        verify = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-rawin", "-inkey", str(trusted), "-in", str(payload), "-sigfile", str(sig)], capture_output=True, timeout=15)
        require(verify.returncode == 0, "local bundle signature verification failed")
    m = json.loads(data, object_pairs_hook=unique_object)
    fields(m, {"schema_version", "kind", "platform", "source_sha", "version", "files", "images", "client"}, "bundle")
    require(type(m["schema_version"]) is int and m["schema_version"] == 1 and m["kind"] == KIND, "unsupported local bundle schema")
    require(m["platform"] == "linux/amd64", "local bundles currently support linux/amd64 only")
    require(isinstance(m["source_sha"], str) and SHA.fullmatch(m["source_sha"]), "invalid exact source commit")
    require(isinstance(m["version"], str) and VERSION.fullmatch(m["version"]), "invalid local version")
    require(isinstance(m["files"], dict) and PAYLOAD <= set(m["files"]), "required installer payload missing")
    for name, item in m["files"].items():
        fields(item, {"sha256", "bytes"}, "file")
        require(isinstance(item["sha256"], str) and HEX64.fullmatch(item["sha256"]), "invalid file SHA-256")
        require(type(item["bytes"]) is int and item["bytes"] > 0, "invalid file length")
        file = bundle_file(root, name)
        require(file.stat().st_size == item["bytes"] and digest(file) == item["sha256"], f"bundle checksum mismatch: {name}")
    require(isinstance(m["images"], dict) and set(m["images"]) == ROLES, "bundle must bind every Compose image role")
    archives = set()
    for role, item in m["images"].items():
        fields(item, {"archive", "image_id", "os", "architecture", "source_sha"}, "image")
        require(item["archive"] in m["files"] and item["archive"] not in archives, "missing or duplicated image archive")
        archives.add(item["archive"])
        require(isinstance(item["image_id"], str) and re.fullmatch(r"sha256:[0-9a-f]{64}", item["image_id"]), "invalid immutable Docker image ID")
        require(item["os"] == "linux" and item["architecture"] == "amd64", "image platform differs from bundle")
        if role in PRODUCT_ROLES:
            require(item["source_sha"] == m["source_sha"], "product image source differs from bundle")
        else:
            require(item["source_sha"] is None or (isinstance(item["source_sha"], str) and SHA.fullmatch(item["source_sha"])), "invalid dependency source")
    client = m["client"]
    fields(client, {"path", "source_sha", "version", "platform"}, "client")
    require(client["path"] in m["files"] and client["path"].endswith(".pkg"), "signed client package missing")
    require(isinstance(client["source_sha"], str) and SHA.fullmatch(client["source_sha"]), "client source commit missing")
    require(isinstance(client["version"], str) and VERSION.fullmatch(client["version"]), "invalid client version")
    require(client["platform"] == "darwin/universal", "unsupported client package platform")
    # A local bundle cannot swap the canonical verifier/installer after it starts.
    for name, running in (("deploy/install-bundle.py", Path(__file__).resolve()), ("deploy/install.sh", Path(__file__).resolve().with_name("install.sh"))):
        require(running.is_file() and digest(running) == m["files"][name]["sha256"], "running installer differs from signed bundle")
    return m, data, signature_bytes, key_bytes


def write_verified(root, stage, m, data, signature, key):
    stage.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not stage.is_symlink() and not any(stage.iterdir()), "verification stage must be a new empty directory")
    for name in sorted(PAYLOAD | {m["client"]["path"]}):
        src = bundle_file(root, name)
        dst = stage / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        require(dst.stat().st_size == m["files"][name]["bytes"] and digest(dst) == m["files"][name]["sha256"], "file changed during staging")
        dst.chmod(0o644)
    (stage / "bundle.json").write_bytes(data)
    (stage / "bundle.json.sig").write_bytes(signature)
    (stage / "trusted-public-key.pem").write_bytes(key)
    env = {"TUNNEX_VERSION": m["version"], "TUNNEX_SOURCE_REF": m["source_sha"], "TUNNEX_RELEASE_VERSION": m["version"], "TUNNEX_RELEASE_SOURCE_SHA": m["source_sha"], "TUNNEX_CLIENT_PACKAGE_PATH": m["client"]["path"]}
    for role, item in m["images"].items():
        env["TUNNEX_" + role.upper().replace("-", "_") + "_IMAGE"] = item["image_id"]
    # All values have been constrained above; consumers read individual keys,
    # never evaluate or source this file as shell input.
    (stage / "bundle.env").write_text("".join(f"{k}={v}\n" for k, v in sorted(env.items())))
    return {"result": "VERIFIED_LOCAL_BUNDLE", "bundle_sha256": hashlib.sha256(data).hexdigest(), "source_sha": m["source_sha"], "platform": m["platform"], "client": m["client"]}


def load_images(root, m, gateway_only=False, docker_sudo=False):
    docker = ["sudo", "docker"] if docker_sudo else ["docker"]
    info = subprocess.run(docker + ["info", "--format", "{{.OSType}}/{{.Architecture}}"], check=True, capture_output=True, text=True, timeout=30).stdout.strip()
    require(info in ("linux/amd64", "linux/x86_64"), "Docker server platform differs from bundle")
    loaded = {}
    for role in sorted({"node-agent"} if gateway_only else ROLES):
        item = m["images"][role]
        archive = bundle_file(root, item["archive"])
        expected = m["files"][item["archive"]]
        with archive.open("rb") as stream:
            require(os.fstat(stream.fileno()).st_size == expected["bytes"] and hashlib.file_digest(stream, "sha256").hexdigest() == expected["sha256"], "archive changed before load")
            stream.seek(0)
            subprocess.run(docker + ["image", "load"], stdin=stream, check=True, stdout=subprocess.DEVNULL, timeout=900)
        inspect = json.loads(subprocess.run(docker + ["image", "inspect", item["image_id"]], check=True, capture_output=True, text=True, timeout=30).stdout)
        require(isinstance(inspect, list) and len(inspect) == 1, "invalid loaded image inspection")
        observed = inspect[0]
        require(observed.get("Id") == item["image_id"] and observed.get("Os") == item["os"] and observed.get("Architecture") == item["architecture"], "loaded image identity/platform mismatch")
        loaded[role] = item["image_id"]
    return {"result": "LOADED_VERIFIED_LOCAL_IMAGES", "platform": m["platform"], "images": loaded, "source_sha": m["source_sha"]}


def check_compose(m, path, docker_sudo=False):
    config = json.loads(Path(path).read_text(), object_pairs_hook=unique_object)
    roles = {"api": "api", "web": "web", "nginx": "nginx", "node-agent": "node-agent", "bifrost": "ai-engine", "ai-egress": "api", "postgres": "postgres", "redis": "redis", "caddy": "caddy"}
    services = config.get("services")
    require(isinstance(services, dict) and set(services) <= set(roles) and {"api", "web", "nginx", "node-agent", "bifrost", "ai-egress", "redis", "caddy"} <= set(services), "unexpected local Compose services")
    for service, value in services.items():
        require(value.get("image") == m["images"][roles[service]]["image_id"], f"resolved Compose image differs from signed bundle: {service}")
    api_env = services["api"].get("environment", {})
    require(api_env.get("TUNNEX_NODE_AGENT_IMAGE") == m["images"]["node-agent"]["image_id"], "CP advertised gateway image differs from signed bundle")
    require(api_env.get("TUNNEX_RELEASE_UPDATE_CHECK") == "false" and api_env.get("TUNNEX_RELEASE_MANIFEST_PATH") == "" and api_env.get("TUNNEX_RELEASE_CATALOG_URL") == "", "local bundle must not enable the public release channel")
    docker = ["sudo", "docker"] if docker_sudo else ["docker"]
    inventory = subprocess.run(docker + ["volume", "ls", "--format", "{{json .Name}}"], check=True, capture_output=True, text=True, timeout=30).stdout
    existing = set()
    for line in inventory.splitlines():
        name = json.loads(line)
        require(isinstance(name, str) and name, "invalid Docker volume inventory")
        existing.add(name)
    volumes = config.get("volumes", {})
    require(isinstance(volumes, dict), "invalid Compose volumes")
    for volume in volumes.values():
        require(isinstance(volume, dict) and isinstance(volume.get("name"), str) and volume["name"], "Compose did not resolve a volume name")
        require(volume["name"] not in existing, "resolved Compose data volume already exists; retained data was preserved")
    return {"result": "VERIFIED_FRESH_LOCAL_COMPOSE", "images_checked": len(services), "volumes_checked": len(volumes)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["verify", "load", "gateway-load", "check-compose"])
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--stage")
    parser.add_argument("--compose-json")
    parser.add_argument("--expected-sha256")
    parser.add_argument("--docker-sudo", action="store_true")
    args = parser.parse_args()
    root = Path(args.bundle).resolve(strict=True)
    require(root.is_dir(), "bundle directory missing")
    m, data, signature, key = read_manifest(root, args.public_key, args.expected_sha256)
    if args.action == "verify":
        require(args.stage, "verification requires a private staging directory")
        receipt = write_verified(root, Path(args.stage).absolute(), m, data, signature, key)
    elif args.action == "check-compose":
        require(args.compose_json, "resolved Compose JSON is required")
        receipt = check_compose(m, args.compose_json, args.docker_sudo)
    else:
        receipt = load_images(root, m, args.action == "gateway-load", args.docker_sudo)
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError) as error:
        print(f"Local bundle refused: {error}", file=sys.stderr)
        sys.exit(1)
