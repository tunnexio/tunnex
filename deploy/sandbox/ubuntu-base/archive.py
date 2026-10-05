#!/usr/bin/env python3
"""Build a source-pinned offline Ubuntu workload image and public archive descriptor."""

import argparse
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile

import delivery


ROOT = Path(__file__).resolve().parents[3]


def command(args, **kwargs):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, **kwargs).stdout


def inspect_archive(path, expected_config, arch):
    """Check output against the installer's immutable Docker archive contract."""
    delivery.regular(path)
    delivery.need(path.stat().st_size <= 512 * delivery.MIB, "image archive exceeds install limit")
    with tarfile.open(path, "r:*") as archive:
        entries = {}
        members = archive.getmembers()
        delivery.need(len(members) <= 4096, "oversized archive inventory")
        for member in members:
            name = PurePosixPath(member.name)
            delivery.need(not name.is_absolute() and ".." not in name.parts
                          and (member.isfile() or member.isdir()) and not member.issym()
                          and member.name not in entries, "unsafe or duplicate image archive entry")
            entries[member.name] = member
        delivery.need("manifest.json" in entries and entries["manifest.json"].size <= delivery.MIB,
                      "Docker archive manifest required")
        manifest = json.loads(archive.extractfile(entries["manifest.json"]).read(),
                              object_pairs_hook=delivery.unique_object)
        delivery.need(isinstance(manifest, list) and len(manifest) == 1,
                      "single workload image required")
        record = manifest[0]
        config = entries.get(record.get("Config"))
        delivery.need(config is not None and config.isfile() and config.size <= 2 * delivery.MIB,
                      "bounded config metadata required")
        raw = archive.extractfile(config).read()
        delivery.need("sha256:" + delivery.sha256(raw) == expected_config, "image config differs from output pin")
        metadata = json.loads(raw, object_pairs_hook=delivery.unique_object)
        delivery.need(metadata.get("architecture") == arch and metadata.get("os") == "linux",
                      "image archive architecture mismatch")
        delivery.need(metadata.get("config", {}).get("User") == "1001:1001"
                      and metadata.get("config", {}).get("WorkingDir") == "/workspace",
                      "unprivileged workload identity required")
        layers = record.get("Layers")
        delivery.need(isinstance(layers, list) and layers and len(layers) <= 64
                      and all(name in entries and entries[name].isfile() for name in layers),
                      "missing image layers")
    return metadata


def committed(path, source):
    return command(["git", "-C", str(ROOT), "show", source + ":" + path])


def verify_delivery(directory, expected_source, expected_architecture, expected_lock_sha256):
    """Reusable release guard. Verification never promotes native qualification."""
    delivery.need(re.fullmatch(r"[0-9a-f]{40}", expected_source)
                  and expected_architecture in ("amd64", "arm64")
                  and delivery.DIGEST.fullmatch(expected_lock_sha256), "invalid expected provenance")
    directory = Path(directory)
    delivery.need(directory.is_dir() and not directory.is_symlink(), "delivery directory required")
    descriptor = delivery.read_json(directory / "workload-image.json")
    delivery.need(isinstance(descriptor, dict) and set(descriptor) == {
        "schema_version", "source_sha", "os", "architecture", "dependency_lock_sha256",
        "base_manifest_digest", "archive", "config_digest", "unpacked_image_bytes",
        "native_qualification", "services_started", "packages_installed_at_launch"},
        "unexpected public descriptor fields")
    filename = f"tunnex-sandbox-ubuntu26-linux-{expected_architecture}.docker.tar"
    delivery.need({path.name for path in directory.iterdir()} == {filename, "workload-image.json", "SHA256SUMS"},
                  "unexpected image delivery inventory")
    delivery.need(descriptor.get("schema_version") == 1 and descriptor.get("source_sha") == expected_source
                  and descriptor.get("architecture") == expected_architecture and descriptor.get("os") == "linux"
                  and descriptor.get("dependency_lock_sha256") == expected_lock_sha256
                  and descriptor.get("native_qualification") is False and descriptor.get("services_started") is False
                  and descriptor.get("packages_installed_at_launch") is False, "image delivery provenance mismatch")
    config = descriptor.get("config_digest", "")
    delivery.need(config.startswith("sha256:") and delivery.DIGEST.fullmatch(config[7:]), "invalid config pin")
    base = descriptor.get("base_manifest_digest", "")
    delivery.need(base.startswith("sha256:") and delivery.DIGEST.fullmatch(base[7:]), "invalid base manifest pin")
    record = descriptor.get("archive", {})
    delivery.need(isinstance(record, dict) and set(record) == {"filename", "sha256", "bytes"}
                  and record.get("filename") == filename, "unexpected image archive fields or filename")
    archive = directory / filename
    delivery.need(delivery.DIGEST.fullmatch(record.get("sha256", "")) and type(record.get("bytes")) is int
                  and 0 < record["bytes"] <= 512 * delivery.MIB, "invalid image archive identity")
    delivery.verify(archive, dict(size=record["bytes"], sha256=record["sha256"]))
    metadata = inspect_archive(archive, config, expected_architecture)
    labels = metadata.get("config", {}).get("Labels", {})
    delivery.need(labels.get("io.tunnex.sandbox.source") == expected_source
                  and labels.get("io.tunnex.sandbox.ubuntu-lock") == expected_lock_sha256,
                  "image labels differ from source/lock provenance")
    delivery.need(type(descriptor.get("unpacked_image_bytes")) is int
                  and 0 < descriptor["unpacked_image_bytes"] <= 512 * delivery.MIB, "invalid measured image size")
    expected_sums = "".join(delivery.sha256((directory / name).read_bytes()) + "  " + name + "\n"
                            for name in (filename, "workload-image.json"))
    sums = directory / "SHA256SUMS"
    delivery.regular(sums)
    delivery.need(sums.read_text() == expected_sums, "image delivery checksum file mismatch")
    return descriptor


def assemble_context(lock, lock_raw, cache, source, context, go):
    """Only allowlisted committed source, locked packages and compiled bootstrap."""
    (context / "packages").mkdir()
    (context / "runtime").mkdir()
    for record in lock["metadata"] + lock["download_packages"]:
        delivery.verify(cache / record["path"], record)
    for record in lock["download_packages"]:
        shutil.copyfile(cache / record["path"], context / "packages" / delivery.package_filename(record))
    base_recipe = committed("deploy/sandbox/ubuntu-base/Containerfile", source).decode()
    final_recipe = committed("deploy/sandbox/Containerfile", source).decode()
    delivery.need(final_recipe.count("FROM ${BASE_IMAGE}\n") == 1
                  and final_recipe.count("ARG BASE_IMAGE\n") == 1, "unexpected final-layer recipe")
    final_recipe = final_recipe.replace("ARG BASE_IMAGE\n", "").replace("FROM ${BASE_IMAGE}\n", "")
    (context / "Containerfile").write_text(base_recipe + "\n" + final_recipe)
    (context / "expected-inventory.tsv").write_text("\n".join(lock["installed_inventory"]) + "\n")
    (context / "sandbox-entrypoint.py").write_bytes(committed("deploy/sandbox/sandbox-entrypoint.py", source))
    cli_archive = command(["git", "-C", str(ROOT), "archive", source, "apps/cli"])
    with tempfile.TemporaryDirectory(prefix="tunnex-ubuntu-bootstrap-") as directory:
        source_root = Path(directory)
        with tarfile.open(fileobj=io.BytesIO(cli_archive), mode="r:") as archive:
            for member in archive:
                name = PurePosixPath(member.name)
                delivery.need(not name.is_absolute() and ".." not in name.parts
                              and (member.isfile() or member.isdir()), "non-source archive member")
                destination = source_root / str(name)
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(archive.extractfile(member).read())
        environment = dict(os.environ, GOOS="linux", GOARCH=lock["architecture"], CGO_ENABLED="0",
                           GOFLAGS="-mod=readonly", GOTOOLCHAIN="local", GOTELEMETRY="off", GOWORK="off",
                           GOPROXY="off", GOSUMDB="off")
        command([go, "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o",
                 str(context / "runtime/tunnex-sandbox-bootstrap"), "./cmd/tunnex-sandbox-bootstrap"],
                cwd=source_root / "apps/cli", env=environment)


def build(lock_path, cache, output, engine, go):
    command(["git", "-C", str(ROOT), "diff", "--quiet"])
    command(["git", "-C", str(ROOT), "diff", "--cached", "--quiet"])
    source = command(["git", "-C", str(ROOT), "rev-parse", "HEAD"]).decode().strip()
    delivery.need(re.fullmatch(r"[0-9a-f]{40}", source), "committed source identity required")
    version = command([go, "version"]).decode().strip()
    delivery.need(version.startswith("go version go1.26.8 "), "pinned Go1.26.8 required")
    lock_raw = Path(lock_path).read_bytes()
    lock = delivery.read_json(lock_path)
    arch = delivery.validate_lock(lock)
    delivery.need(lock_raw == committed(f"deploy/sandbox/ubuntu-base/ubuntu26-{arch}.lock.json", source),
                  "image lock must match committed reviewed inputs")
    base = lock["base_images"][arch]
    metadata = json.loads(command([engine, "image", "inspect", base]))
    delivery.need(len(metadata) == 1 and metadata[0].get("Architecture") == arch
                  and metadata[0].get("Os") == "linux", "pinned preloaded base platform mismatch")
    for record in lock["metadata"] + lock["download_packages"]:
        delivery.verify(cache / record["path"], record)
    delivery.need(output.is_absolute() and not output.exists(), "new absolute output directory required")
    output.parent.mkdir(parents=True, exist_ok=True)
    for parent in (output, *output.parents):
        delivery.need(not parent.is_symlink(), "symlinked output directory")
    output.mkdir()
    tag = f"tunnex-sandbox-ubuntu26-{source[:12]}-{arch}"
    with tempfile.TemporaryDirectory(prefix="tunnex-ubuntu-image-") as directory:
        context = Path(directory)
        assemble_context(lock, lock_raw, cache, source, context, go)
        delivery.run([engine, "build", "--pull=false" if engine == "docker" else "--pull=never",
                      "--network=none", "--file", str(context / "Containerfile"), "--platform=linux/" + arch,
                      "--build-arg", "BASE_IMAGE=" + base,
                      "--build-arg", "LOCK_SHA256=" + delivery.sha256(lock_raw), "--build-arg",
                      "SOURCE_SHA=" + source, "--tag", tag, str(context)])
    images = json.loads(command([engine, "image", "inspect", tag]))
    delivery.need(len(images) == 1 and images[0].get("Architecture") == arch
                  and images[0].get("Os") == "linux", "built image platform mismatch")
    config_digest = images[0]["Id"]
    delivery.need(config_digest.startswith("sha256:") and delivery.DIGEST.fullmatch(config_digest[7:]),
                  "invalid output config identity")
    archive = output / f"tunnex-sandbox-ubuntu26-linux-{arch}.docker.tar"
    command([engine, "save", "--output", str(archive), tag])
    inspect_archive(archive, config_digest, arch)
    descriptor = {"schema_version": 1, "source_sha": source, "os": "linux", "architecture": arch,
                  "dependency_lock_sha256": delivery.sha256(lock_raw),
                  "base_manifest_digest": base.split("@", 1)[1],
                  "archive": {"filename": archive.name, "sha256": delivery.sha256(archive.read_bytes()),
                              "bytes": archive.stat().st_size},
                  "config_digest": config_digest, "unpacked_image_bytes": images[0]["Size"],
                  "native_qualification": False, "services_started": False,
                  "packages_installed_at_launch": False}
    delivery.write_json(output / "workload-image.json", descriptor)
    with open(output / "SHA256SUMS", "x") as sums:
        for path in (archive, output / "workload-image.json"):
            sums.write(delivery.sha256(path.read_bytes()) + "  " + path.name + "\n")
    return descriptor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--engine", choices=("podman", "docker"), default="podman")
    parser.add_argument("--go", default="go")
    args = parser.parse_args()
    try:
        result = build(args.lock, args.cache.resolve(), args.output.resolve(), args.engine, args.go)
        print(json.dumps(result, sort_keys=True))
    except (delivery.InvalidInput, OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, "Ubuntu archive build failed: " + str(error) + "\n")


if __name__ == "__main__":
    main()
