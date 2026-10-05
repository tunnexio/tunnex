#!/usr/bin/env python3
"""Lock/fetch/build public Ubuntu image inputs. Never enroll or start a runner."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import urllib.parse
import urllib.request


HERE = Path(__file__).resolve().parent
MIB = 1024 * 1024
MAX_INPUT_BYTES = 512 * MIB
DIGEST = re.compile(r"[0-9a-f]{64}")
BASE = re.compile(r"docker\.io/library/ubuntu@sha256:[0-9a-f]{64}")
SNAPSHOT = re.compile(r"20[0-9]{6}T[0-9]{6}Z")
PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]+")
REQUIRED = {"bash", "coreutils", "iproute2", "nftables", "openssh-server",
            "passwd", "python3", "systemd-resolved", "util-linux", "wireguard-tools"}


class InvalidInput(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise InvalidInput(message)


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        need(name not in result, "duplicate JSON field")
        result[name] = value
    return result


def read_json(path):
    raw = Path(path).read_bytes()
    need(len(raw) <= 4 * MIB, "oversized JSON input")
    return json.loads(raw, object_pairs_hook=unique_object)


def write_json(path, value):
    raw = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    with open(path, "xb") as output:
        output.write(raw)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_relative(path):
    need(isinstance(path, str), "invalid input path")
    p = PurePosixPath(path)
    need(path == str(p) and not p.is_absolute()
         and ".." not in p.parts and bool(p.parts), "unsafe input path")
    return path


def public_url(url, snapshot):
    parsed = urllib.parse.urlsplit(url)
    prefix = f"/ubuntu/{snapshot}/"
    need(parsed.scheme == "https" and parsed.hostname == "snapshot.ubuntu.com"
         and parsed.netloc == "snapshot.ubuntu.com" and parsed.path.startswith(prefix)
         and not parsed.query and not parsed.fragment and not parsed.username,
         "only the pinned official Ubuntu HTTPS snapshot is allowed")
    safe_relative(parsed.path[len(prefix):])
    return url


def regular(path):
    need(path.is_file() and not path.is_symlink(), "missing or symlinked input")


def verify(path, record):
    regular(path)
    need(path.stat().st_size == record["size"] and sha256(path.read_bytes()) == record["sha256"],
         "input size or checksum mismatch: " + path.name)


def download(url, target, expected=None, maximum=128 * MIB):
    need(not target.is_symlink(), "symlinked input destination")
    if target.exists():
        need(expected is not None, "refuse existing unverified metadata")
        verify(target, expected)
        return target.read_bytes()
    target.parent.mkdir(parents=True, exist_ok=True)
    for ancestor in (target.parent, *target.parent.parents):
        need(not ancestor.is_symlink(), "symlinked cache path")
    raw = bytearray()
    with urllib.request.urlopen(url, timeout=60) as response:
        # Redirects cannot move package downloads outside the approved archive.
        need(urllib.parse.urlsplit(response.url).netloc == "snapshot.ubuntu.com",
             "unexpected archive redirect")
        while block := response.read(64 * 1024):
            raw.extend(block)
            need(len(raw) <= maximum, "oversized public input")
    result = bytes(raw)
    if expected:
        need(len(result) == expected["size"] and sha256(result) == expected["sha256"],
             "download size or checksum mismatch")
    with open(target, "xb") as output:
        output.write(result)
    return result


def validate_seed(seed, arch):
    need(isinstance(seed, dict), "input object required")
    need(seed.get("version") == 1 and seed.get("ubuntu_release") == "26.04"
         and seed.get("suite") == "resolute", "unsupported Ubuntu input version")
    need(arch in ("amd64", "arm64") and SNAPSHOT.fullmatch(seed.get("snapshot", "")),
         "unsupported architecture or snapshot")
    need(BASE.fullmatch(seed.get("base_images", {}).get(arch, "")), "mutable or invalid Ubuntu base")
    need(set(seed.get("packages", [])) == REQUIRED and len(seed["packages"]) == len(REQUIRED),
         "essential package set must match the supported image")


def validate_lock(lock):
    need(isinstance(lock, dict), "lock object required")
    arch = lock.get("architecture")
    validate_seed(lock, arch)
    need(isinstance(lock.get("metadata"), list) and len(lock["metadata"]) == 9,
         "all three signed pockets and both package components required")
    required_metadata = {"repository/dists/" + suite + "/" + path
                         for suite in ("resolute", "resolute-updates", "resolute-security")
                         for path in ("InRelease", f"main/binary-{arch}/Packages.xz",
                                      f"universe/binary-{arch}/Packages.xz")}
    need({record.get("path") for record in lock["metadata"]} == required_metadata,
         "missing or unexpected signed metadata input")
    need(isinstance(lock.get("download_packages"), list) and 1 <= len(lock["download_packages"]) <= 256,
         "bounded complete package closure required")
    seen = set()
    total = 0
    for record in lock["metadata"] + lock["download_packages"]:
        need(isinstance(record, dict) and DIGEST.fullmatch(record.get("sha256", ""))
             and type(record.get("size")) is int and 0 < record["size"] <= 128 * MIB,
             "invalid public input hash/size")
        public_url(record.get("url", ""), lock["snapshot"])
        path = safe_relative(record.get("path", ""))
        need(path not in seen, "duplicate input path")
        seen.add(path)
        total += record["size"]
    need(total <= MAX_INPUT_BYTES, "input closure exceeds build budget")
    inventory = lock.get("installed_inventory")
    need(isinstance(inventory, list) and 1 <= len(inventory) <= 512
         and inventory == sorted(set(inventory)), "invalid installed inventory")
    inventory_names = set()
    for row in inventory:
        pieces = row.split("\t")
        need(len(pieces) == 3 and PACKAGE.fullmatch(pieces[0].split(":")[0])
             and 0 < len(pieces[1]) <= 128 and pieces[2] in (arch, "all"), "invalid inventory row")
        inventory_names.add(pieces[0].split(":")[0])
    need(REQUIRED <= inventory_names, "essential dependencies absent from inventory")
    package_names = set()
    for record in lock["download_packages"]:
        need(PACKAGE.fullmatch(record.get("name", "")) and record.get("architecture") in (arch, "all")
             and re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,128}", record.get("version", ""))
             and record["path"] == "packages/" + record["sha256"] + ".deb",
             "invalid package closure entry")
        need(record["name"] not in package_names and record["name"] in inventory_names,
             "duplicate package or package outside locked installed inventory")
        package_names.add(record["name"])
        row = next(row for row in inventory if row.split("\t")[0].split(":")[0] == record["name"])
        need(row.split("\t")[1:] == [record["version"], record["architecture"]],
             "package version differs from expected inventory")
    need(lock.get("native_qualification") is False, "package lock cannot confer native qualification")
    return arch


def release_checksums(raw):
    text = raw.decode("utf-8")
    need("Origin: Ubuntu\n" in text and "Codename: resolute\n" in text,
         "wrong Ubuntu signed archive")
    result = {}
    match = re.search(r"\nSHA256:\n((?: [0-9a-f]{64} +[0-9]+ +[^\n]+\n)+)", text)
    need(match is not None, "signed release has no SHA256 inventory")
    for line in match[1].splitlines():
        digest, size, path = line.split()
        result[path] = (digest, int(size))
    return result


def package_entries(raw):
    result = {}
    for block in lzma.decompress(raw).decode().split("\n\n"):
        fields = {}
        for line in block.splitlines():
            if line and not line[0].isspace() and ": " in line:
                key, value = line.split(": ", 1)
                fields[key] = value
        if {"Package", "Version", "Architecture", "Filename", "Size", "SHA256"} <= fields.keys():
            result[fields["Filename"]] = fields
    return result


def run(args, **kwargs):
    # Public producer inputs never require a saved registry account. This also
    # prevents BuildKit from consulting a user's credential helper for FROM.
    if args[0] in ("docker", "podman") and args[1] in ("pull", "build"):
        with tempfile.TemporaryDirectory(prefix="tunnex-public-registry-") as registry:
            auth = Path(registry, "config.json")
            auth.write_text('{"auths":{}}\n')
            if args[0] == "docker":
                args = [args[0], "--config", registry] + args[1:]
            else:
                args = args[:2] + ["--authfile", str(auth)] + args[2:]
            return subprocess.run(args, check=True, text=True, **kwargs)
    return subprocess.run(args, check=True, text=True, **kwargs)


def resolve(seed_path, arch, cache, output, engine):
    seed = read_json(seed_path)
    validate_seed(seed, arch)
    need(not output.exists(), "lock output already exists")
    base = seed["base_images"][arch]
    root = f"https://snapshot.ubuntu.com/ubuntu/{seed['snapshot']}/"
    metadata, available = [], {}
    for suite in ("resolute", "resolute-updates", "resolute-security"):
        rel = f"dists/{suite}/InRelease"
        existing = cache / "repository" / rel
        if existing.exists():
            # Interrupted resolution may resume cached signed metadata. APT
            # must authenticate all pockets before a lock can be written.
            regular(existing)
            need(existing.stat().st_size <= 2 * MIB, "oversized signed metadata")
            raw = existing.read_bytes()
        else:
            raw = download(root + rel, existing)
        metadata.append({"path": "repository/" + rel, "url": root + rel,
                         "sha256": sha256(raw), "size": len(raw)})
        checksums = release_checksums(raw)
        for component in ("main", "universe"):
            name = f"{component}/binary-{arch}/Packages.xz"
            digest, size = checksums[name]
            rel = f"dists/{suite}/{name}"
            record = {"path": "repository/" + rel, "url": root + rel,
                      "sha256": digest, "size": size}
            raw = download(root + rel, cache / record["path"], record)
            metadata.append(record)
            available.update(package_entries(raw))
    # Signature validation and dependency selection use the official pinned
    # base's Ubuntu keyring/APT. The resolver has no network or host privileges.
    sources = cache / "sources.list"
    sources.write_text("".join(f"deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] file:/input/repository {suite} main universe\n"
                              for suite in ("resolute", "resolute-updates", "resolute-security")))
    run([engine, "pull", "--platform=linux/" + arch, base], timeout=300)
    command = """set -eu
opts='-o Dir::Etc::sourcelist=/input/sources.list -o Dir::Etc::sourceparts=- -o Acquire::Check-Valid-Until=false -o APT::Sandbox::User=root'
apt-get $opts update >&2
printf 'TUNNEX_BASE_INVENTORY\\n'
dpkg-query -W -f='${binary:Package}\\t${Version}\\t${Architecture}\\n'
printf 'TUNNEX_DOWNLOAD_URIS\\n'
apt-get $opts -o Acquire::ForceHash=SHA256 --no-install-recommends --print-uris -y install """ + " ".join(seed["packages"])
    response = run([engine, "run", "--rm", "--network=none", "--cap-drop=ALL",
                    "--security-opt=no-new-privileges", "--platform=linux/" + arch,
                    "--mount", f"type=bind,src={cache.resolve()},dst=/input,readonly",
                    base, "/bin/sh", "-c", command], stdout=subprocess.PIPE).stdout
    need(response.startswith("TUNNEX_BASE_INVENTORY\n") and "\nTUNNEX_DOWNLOAD_URIS\n" in response,
         "unexpected APT resolver response")
    inventory, uris = response[len("TUNNEX_BASE_INVENTORY\n"):].split("\nTUNNEX_DOWNLOAD_URIS\n", 1)
    packages = []
    installed = {row.split("\t")[0].split(":")[0]: row for row in inventory.splitlines()}
    for line in uris.splitlines():
        if not line.startswith("'file:"):
            continue
        fields = line.split()
        path = urllib.parse.unquote(fields[0].strip("'").split("/repository/", 1)[1])
        info = available[path]
        need(fields[2] == info["Size"] and fields[3] == "SHA256:" + info["SHA256"],
             "APT package differs from signed package index")
        record = {"name": info["Package"], "version": info["Version"],
                  "architecture": info["Architecture"], "sha256": info["SHA256"],
                  "size": int(info["Size"]), "url": root + path,
                  "path": "packages/" + info["SHA256"] + ".deb"}
        packages.append(record)
        # dpkg-query includes :arch only for Multi-Arch:same packages.
        binary_name = info["Package"] + (":" + arch if info.get("Multi-Arch") == "same" else "")
        installed[info["Package"]] = "\t".join((binary_name, info["Version"], info["Architecture"]))
    lock = dict(seed, architecture=arch, metadata=metadata,
                download_packages=sorted(packages, key=lambda p: p["name"]),
                installed_inventory=sorted(installed.values()),
                native_qualification=False)
    validate_lock(lock)
    write_json(output, lock)
    return {"lock": str(output), "architecture": arch, "package_downloads": len(packages),
            "native_qualification": False}


def fetch(lock_path, cache):
    lock = read_json(lock_path)
    validate_lock(lock)
    def fetch_record(record):
        download(record["url"], cache / record["path"], record)
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(fetch_record, lock["metadata"] + lock["download_packages"]))
    return {"input_status": "verified", "package_downloads": len(lock["download_packages"])}


def build_base(lock_path, cache, tag, engine):
    lock = read_json(lock_path)
    arch = validate_lock(lock)
    need(re.fullmatch(r"tunnex-sandbox-[a-z0-9][a-z0-9_.-]{0,100}", tag), "task-owned output image tag required")
    for record in lock["metadata"] + lock["download_packages"]:
        verify(cache / record["path"], record)
    base = lock["base_images"][arch]
    metadata = json.loads(run([engine, "image", "inspect", base], stdout=subprocess.PIPE).stdout)
    need(len(metadata) == 1 and metadata[0].get("Architecture") == arch
         and metadata[0].get("Os") == "linux", "pinned preloaded base platform mismatch")
    with tempfile.TemporaryDirectory(prefix="tunnex-ubuntu-base-") as directory:
        context = Path(directory)
        (context / "packages").mkdir()
        for record in lock["download_packages"]:
            shutil.copyfile(cache / record["path"], context / "packages" / Path(record["path"]).name)
        shutil.copyfile(HERE / "Containerfile", context / "Containerfile")
        (context / "expected-inventory.tsv").write_text("\n".join(lock["installed_inventory"]) + "\n")
        run([engine, "build", "--pull=false" if engine == "docker" else "--pull=never",
             "--network=none", "--platform=linux/" + arch, "--build-arg", "BASE_IMAGE=" + base,
             "--build-arg", "LOCK_SHA256=" + sha256(Path(lock_path).read_bytes()),
             "--tag", tag, str(context)])
    images = json.loads(run([engine, "image", "inspect", tag], stdout=subprocess.PIPE).stdout)
    need(len(images) == 1 and images[0].get("Architecture") == arch and images[0].get("Os") == "linux",
         "built dependency image platform mismatch")
    return {"config_digest": images[0]["Id"], "architecture": arch, "tag": tag,
            "native_qualification": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("resolve", "fetch", "check", "preload-base", "build-base"))
    parser.add_argument("--lock", type=Path)
    parser.add_argument("--inputs", type=Path, default=HERE / "public-inputs.json")
    parser.add_argument("--architecture", choices=("amd64", "arm64"))
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--tag")
    parser.add_argument("--engine", choices=("docker", "podman"), default="podman")
    args = parser.parse_args()
    # Normalize the explicitly selected cache root (macOS /tmp is a symlink).
    # Child paths still refuse symlinks and checksum mismatches.
    args.cache = args.cache.resolve()
    try:
        if args.action == "resolve":
            need(args.architecture and args.output, "resolve requires architecture and output")
            result = resolve(args.inputs, args.architecture, args.cache, args.output, args.engine)
        else:
            need(args.lock is not None, "lock required")
            if args.action == "fetch":
                result = fetch(args.lock, args.cache)
            elif args.action == "preload-base":
                lock = read_json(args.lock)
                arch = validate_lock(lock)
                run([args.engine, "pull", "--platform=linux/" + arch,
                     lock["base_images"][arch]], timeout=300)
                result = {"base_status": "preloaded", "native_qualification": False}
            elif args.action == "check":
                lock = read_json(args.lock)
                validate_lock(lock)
                for record in lock["metadata"] + lock["download_packages"]:
                    verify(args.cache / record["path"], record)
                result = {"input_status": "verified", "network": False}
            else:
                result = build_base(args.lock, args.cache, args.tag or "", args.engine)
        print(json.dumps(result, sort_keys=True))
    except (InvalidInput, OSError, subprocess.CalledProcessError, ValueError, KeyError) as error:
        parser.exit(1, "Ubuntu delivery failed: " + str(error) + "\n")


if __name__ == "__main__":
    main()
