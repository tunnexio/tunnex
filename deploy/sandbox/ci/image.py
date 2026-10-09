#!/usr/bin/env python3
"""Build or verify public image delivery; never enroll or qualify a host."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[3]
PRODUCER = ROOT / "deploy/sandbox/ubuntu-base"
LOCK_SOURCE = "deploy/sandbox/ubuntu-base/ubuntu26-amd64.lock.json"


def run(args, *, cwd=ROOT, env=None):
    return subprocess.run(args, cwd=cwd, env=env, check=True,
                          stdout=subprocess.PIPE, timeout=1200).stdout


def load_producer():
    # Imports are restricted to the source-controlled producer, not host tools.
    for name, path in (("delivery", PRODUCER / "delivery.py"),
                       ("sandbox_image_archive", PRODUCER / "archive.py")):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return module


def verify(directory, source):
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("exact source commit required")
    lock_raw = run(["git", "show", source + ":" + LOCK_SOURCE])
    lock = json.loads(lock_raw)
    descriptor = load_producer().verify_delivery(
        Path(directory), source, "amd64", hashlib.sha256(lock_raw).hexdigest())
    if descriptor["base_manifest_digest"] != lock["base_images"]["amd64"].split("@", 1)[1]:
        raise ValueError("image base differs from committed dependency lock")
    return descriptor


def build(cache, output, go):
    source = run(["git", "rev-parse", "HEAD"]).decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}", source):
        raise ValueError("exact source commit required")
    run(["git", "diff", "--quiet"])
    run(["git", "diff", "--cached", "--quiet"])
    if not run([go, "version"]).decode().startswith("go version go1.26.9 "):
        raise ValueError("pinned Go 1.26.9 required")
    lock = PRODUCER / "ubuntu26-amd64.lock.json"
    if lock.read_bytes() != run(["git", "show", source + ":" + LOCK_SOURCE]):
        raise ValueError("committed dependency lock required")
    # Download only locked build dependencies before the final offline compile.
    environment = dict(os.environ, GOFLAGS="-mod=readonly", GOTOOLCHAIN="local",
                       GOTELEMETRY="off", GOWORK="off")
    run([go, "mod", "download"], cwd=ROOT / "apps/cli", env=environment)
    run([sys.executable, "-B", str(PRODUCER / "delivery.py"), "fetch",
         "--lock", str(lock), "--cache", str(cache)])
    run([sys.executable, "-B", str(PRODUCER / "delivery.py"), "preload-base",
         "--lock", str(lock), "--cache", str(cache), "--engine", "docker"])
    run([sys.executable, "-B", str(PRODUCER / "archive.py"), "--lock", str(lock),
         "--cache", str(cache), "--output", str(output), "--engine", "docker", "--go", go])
    return verify(output, source)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    builder = actions.add_parser("build")
    builder.add_argument("--cache", required=True, type=Path)
    builder.add_argument("--output", required=True, type=Path)
    builder.add_argument("--go", default="go")
    verifier = actions.add_parser("verify")
    verifier.add_argument("--directory", required=True, type=Path)
    verifier.add_argument("--source", required=True)
    args = parser.parse_args()
    try:
        if args.action == "build":
            result = build(args.cache, args.output, args.go)
        else:
            result = verify(args.directory, args.source)
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        parser.exit(1, "sandbox image delivery refused; no host was enrolled or qualified\n")


if __name__ == "__main__":
    main()
