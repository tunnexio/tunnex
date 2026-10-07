#!/usr/bin/env python3
"""Fingerprint uncommitted feature sources without collecting private runtime data."""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import subprocess


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args])


def fingerprint(root):
    changed = set(git(root, "diff", "--name-only", "HEAD", "-z").split(b"\0"))
    changed.update(git(root, "ls-files", "--others", "--exclude-standard", "-z").split(b"\0"))
    files = []
    for raw in sorted(changed - {b""}):
        name = raw.decode("utf-8")
        path = root / name
        if ".runtime" in path.parts:
            raise SystemExit("Private runtime data is unexpectedly visible to Git; refusing manifest")
        if path.is_symlink():
            kind, data = "symlink", path.readlink().as_posix().encode()
        elif path.is_file():
            kind, data = "file", path.read_bytes()
        elif not path.exists():
            kind, data = "deleted", b""
        else:
            raise SystemExit("Unexpected source path type; refusing manifest")
        files.append({"path": name, "kind": kind, "sha256": hashlib.sha256(data).hexdigest()})
    encoded = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return {"root": str(root), "branch": git(root, "branch", "--show-current").decode().strip(),
            "baseline_head": git(root, "rev-parse", "HEAD").decode().strip(),
            "uncommitted": bool(files), "source_fingerprint_sha256": hashlib.sha256(encoded).hexdigest(),
            "files": files}


parser = argparse.ArgumentParser()
parser.add_argument("--core", type=Path, required=True)
parser.add_argument("--client", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
result = {"recorded_at": datetime.now(timezone.utc).isoformat(),
          "scope": "Local uncommitted sources; baseline HEAD alone is not the feature snapshot",
          "core": fingerprint(args.core.resolve()), "client": fingerprint(args.client.resolve())}
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(json.dumps(result, indent=2) + "\n")
args.output.chmod(0o600)
print("Local source fingerprints recorded; private runtime material excluded.")
