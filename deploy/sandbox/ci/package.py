#!/usr/bin/env python3
"""Compile and package public sandbox artifacts; never activate a runtime."""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[3]
ARCHITECTURES = {"amd64": 62, "arm64": 183}
API_COMMANDS = ("tunnex-sandbox-runtime", "tunnex-sandbox-ssh-probe", "tunnex-sandbox-runner-enroll")
# Only public source recipes enter a bundle. Qualification units, host receipts,
# operator configuration, private keys, and working directories are excluded.
ASSETS = (
    "deploy/sandbox/ci/README.md",
    "deploy/sandbox/Containerfile",
    "deploy/sandbox/sandbox-entrypoint.py",
    "deploy/sandbox/build-image.sh",
    "deploy/sandbox/network-plan-contract.json",
    "deploy/sandbox/alpine/Containerfile",
    "deploy/sandbox/alpine/entrypoint.sh",
    "deploy/sandbox/alpine/build-image.sh",
    "deploy/sandbox/install/install.py",
    "deploy/sandbox/install/README.md",
    "deploy/sandbox/install/example.json",
)


def run(arguments, *, cwd=ROOT, env=None):
    return subprocess.run(arguments, cwd=cwd, env=env, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=600).stdout


def binary_names(arch):
    return tuple(f"bin/{command}-{edition}-linux-{arch}"
                 for command in API_COMMANDS for edition in ("open", "enterprise")) + (
        f"bin/tunnex-sandbox-network-linux-{arch}",
        f"bin/tunnex-sandbox-bootstrap-linux-{arch}",
    )


def elf_matches(raw, arch):
    return (len(raw) >= 64 and raw[:6] == b"\x7fELF\x02\x01"
            and struct.unpack_from("<H", raw, 18)[0] == ARCHITECTURES[arch])


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def file_records(files):
    return {name: {"sha256": digest(raw), "bytes": len(raw)}
            for name, raw in sorted(files.items())}


def make_bundle(files, source, arch, go_version):
    if arch not in ARCHITECTURES or not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("invalid architecture/source")
    expected = set(binary_names(arch)) | set(ASSETS)
    if set(files) != expected:
        raise ValueError("bundle inventory differs from the public allowlist")
    for name in binary_names(arch):
        if not elf_matches(files[name], arch):
            raise ValueError("binary architecture does not match bundle")
    manifest = {
        "schema_version": 1,
        "source_sha": source,
        "os": "linux",
        "architecture": arch,
        "api_editions": ["open", "enterprise"],
        "go_version": go_version,
        "purpose": "operator-reviewed artifacts; packaging performs no installation or activation",
        "native_runtime_qualification": False,
        "workload_images_built": False,
        "workload_image_recipes": {
            "ubuntu": "requires an independently approved preloaded base digest",
            "alpine_minimal_python_node": "candidate recipes; registration requires native qualification",
        },
        "files": file_records(files),
    }
    payload = dict(files)
    payload["manifest.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    payload["SHA256SUMS"] = "".join(f"{digest(raw)}  {name}\n"
                                        for name, raw in sorted(payload.items())).encode()
    output = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, raw in sorted(payload.items()):
                member = tarfile.TarInfo(name)
                member.size = len(raw)
                member.mode = 0o755 if name.startswith("bin/") else 0o644
                member.mtime = 0
                archive.addfile(member, io.BytesIO(raw))
    return output.getvalue()


def inspect_bundle(raw, expected_source, arch):
    if arch not in ARCHITECTURES or not re.fullmatch(r"[0-9a-f]{40}", expected_source):
        raise ValueError("invalid expected architecture/source")
    if len(raw) > 100 * 1024 * 1024:
        raise ValueError("oversized bundle")
    files = {}
    expected = set(binary_names(arch)) | set(ASSETS) | {"manifest.json", "SHA256SUMS"}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) != len(expected):
            raise ValueError("unexpected bundle inventory")
        for member in members:
            if (member.name not in expected or member.name in files or not member.isfile()
                    or member.size > 64 * 1024 * 1024):
                raise ValueError("non-public, duplicate or invalid archive member")
            files[member.name] = archive.extractfile(member).read()
    manifest = json.loads(files["manifest.json"])
    payload = {name: raw for name, raw in files.items() if name not in ("manifest.json", "SHA256SUMS")}
    if (manifest.get("schema_version") != 1 or manifest.get("source_sha") != expected_source
            or manifest.get("os") != "linux" or manifest.get("architecture") != arch
            or manifest.get("api_editions") != ["open", "enterprise"]
            or manifest.get("native_runtime_qualification") is not False
            or manifest.get("workload_images_built") is not False
            or manifest.get("files") != file_records(payload)):
        raise ValueError("bundle identity/content/qualification mismatch")
    summed = {name: raw for name, raw in files.items() if name != "SHA256SUMS"}
    sums = "".join(f"{digest(raw)}  {name}\n" for name, raw in sorted(summed.items())).encode()
    if files["SHA256SUMS"] != sums:
        raise ValueError("bundle checksum mismatch")
    for name in binary_names(arch):
        if not elf_matches(files[name], arch):
            raise ValueError("binary architecture mismatch")
    return manifest


def build(arch, output):
    if arch not in ARCHITECTURES:
        raise ValueError("unsupported architecture")
    source = run(["git", "rev-parse", "HEAD"]).decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("invalid source identity")
    run(["git", "diff", "--quiet"])
    run(["git", "diff", "--cached", "--quiet"])
    go_version = run(["go", "version"]).decode().strip()
    if not re.match(r"^go version go1\.26\.8 ", go_version):
        raise ValueError("pinned Go 1.26.8 required")
    output = Path(output)
    if not output.is_absolute() or ".." in output.parts:
        raise ValueError("new absolute output directory required")
    for parent in (output, *output.parents):
        if parent.is_symlink():
            raise ValueError("symlink output refused")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir()  # Never overwrite an existing artifact directory.
    environment = dict(os.environ, GOOS="linux", GOARCH=arch, CGO_ENABLED="0",
                       GOFLAGS="-mod=readonly", GOTOOLCHAIN="local", GOTELEMETRY="off", GOWORK="off")
    files = {}
    # Compile an archive of committed modules, never ambient ignored/untracked
    # Go files, developer credentials, node_modules, or operational evidence.
    source_archive = run(["git", "archive", source, "apps/api", "apps/node",
                          "apps/cli", "packages/apptransport"])
    with tempfile.TemporaryDirectory(prefix="tunnex-sandbox-source-") as temporary:
        source_root = Path(temporary) / "source"
        source_root.mkdir()
        with tarfile.open(fileobj=io.BytesIO(source_archive), mode="r:") as archive:
            for member in archive.getmembers():
                path = Path(member.name)
                if path.is_absolute() or ".." in path.parts or not (member.isfile() or member.isdir()):
                    raise ValueError("non-source archive member")
                if member.isdir():
                    (source_root / path).mkdir(parents=True, exist_ok=True)
                else:
                    destination = source_root / path
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(archive.extractfile(member).read())
        if arch == "arm64":
            # Existing API gates already compile/test both editions on AMD64.
            # Cover edition/architecture rot without shipping extra server or
            # fixture binaries or claiming native ARM64 activation support.
            for edition in ("open", "enterprise"):
                args = ["go", "build", "-trimpath", "-buildvcs=false"]
                if edition == "enterprise":
                    args += ["-tags", "enterprise"]
                run(args + ["./..."], cwd=source_root / "apps/api", env=environment)
        for command in API_COMMANDS:
            for edition in ("open", "enterprise"):
                name = f"bin/{command}-{edition}-linux-{arch}"
                destination = Path(temporary) / Path(name).name
                args = ["go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w"]
                if edition == "enterprise":
                    args += ["-tags", "enterprise"]
                run(args + ["-o", str(destination), f"./cmd/{command}"],
                    cwd=source_root / "apps/api", env=environment)
                files[name] = destination.read_bytes()
                destination.unlink()
        for module, command in (("node", "tunnex-sandbox-network"), ("cli", "tunnex-sandbox-bootstrap")):
            name = f"bin/{command}-linux-{arch}"
            destination = Path(temporary) / Path(name).name
            run(["go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w",
                 "-o", str(destination), f"./cmd/{command}"],
                cwd=source_root / f"apps/{module}", env=environment)
            files[name] = destination.read_bytes()
            destination.unlink()
    for asset in ASSETS:
        # Read committed bytes only; ignored/untracked operator files never enter.
        files[asset] = run(["git", "show", f"{source}:{asset}"])
    bundle = make_bundle(files, source, arch, go_version)
    inspect_bundle(bundle, source, arch)
    name = f"tunnex-sandbox-linux-{arch}.tar.gz"
    (output / name).write_bytes(bundle)
    (output / (name + ".sha256")).write_text(f"{digest(bundle)}  {name}\n")
    print(json.dumps({"source_sha": source, "architecture": arch, "bundle": name,
                      "sha256": digest(bundle), "native_runtime_qualification": False}))


def verify_directory(directory, source):
    directory = Path(directory)
    expected = {f"{arch}/tunnex-sandbox-linux-{arch}.tar.gz{suffix}"
                for arch in ARCHITECTURES for suffix in ("", ".sha256")}
    found = {str(p.relative_to(directory)) for p in directory.rglob("*") if p.is_file() or p.is_symlink()}
    if found != expected:
        raise ValueError("artifact directory inventory differs from public allowlist")
    for arch in ARCHITECTURES:
        name = f"tunnex-sandbox-linux-{arch}.tar.gz"
        bundle = directory / arch / name
        sidecar = directory / arch / (name + ".sha256")
        if bundle.is_symlink() or sidecar.is_symlink():
            raise ValueError("symlink artifact refused")
        raw = bundle.read_bytes()
        if sidecar.read_text() != f"{digest(raw)}  {name}\n":
            raise ValueError("outer checksum mismatch")
        inspect_bundle(raw, source, arch)
    print("Both Linux architecture bundles match source, public inventory and checksums; build evidence only.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    builder = actions.add_parser("build")
    builder.add_argument("--arch", choices=ARCHITECTURES, required=True)
    builder.add_argument("--output", required=True)
    verifier = actions.add_parser("verify")
    verifier.add_argument("--directory", required=True)
    verifier.add_argument("--source", required=True)
    args = parser.parse_args()
    try:
        if args.action == "build":
            build(args.arch, args.output)
        else:
            verify_directory(args.directory, args.source)
    except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError):
        parser.exit(1, "sandbox source artifact packaging refused; no runtime was activated\n")


if __name__ == "__main__":
    main()
