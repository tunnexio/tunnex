#!/usr/bin/env python3
"""Build a binary overlay on an explicitly digest-pinned deployment image."""
import argparse
from pathlib import Path
import re
import subprocess


# No whitespace, Dockerfile syntax, or floating tags without a digest. Docker
# verifies this content digest when pulling the base; no registry lookup races.
IMAGE = re.compile(r"[a-z0-9][a-z0-9._:/-]*@sha256:[0-9a-f]{64}", re.ASCII)
BINARIES = {
    "api": ("tunnex-api",),
    "node": ("tunnex-node", "tunnex-ai-vpn-relay"),
}


def dockerfile(component: str, base_image: str) -> str:
    if not IMAGE.fullmatch(base_image):
        raise ValueError("base image must be a repository reference ending in @sha256:<64 lowercase hex digits>")
    copies = [f"COPY --chmod=755 {name} /usr/local/bin/{name}" for name in BINARIES[component]]
    return "\n".join([f"FROM {base_image}", *copies, ""])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", choices=BINARIES)
    parser.add_argument("--base-image", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--context", type=Path, required=True)
    args = parser.parse_args()
    try:
        recipe = dockerfile(args.component, args.base_image)
    except ValueError as error:
        parser.error(str(error))
    context = args.context.resolve(strict=True)
    for name in BINARIES[args.component]:
        binary = context / name
        if not binary.is_file() or binary.is_symlink():
            parser.error(f"context must contain a regular, non-symlink {name} file")
    # Supply literal FROM via stdin, with no build-arg override or shell parsing.
    subprocess.run(
        ["docker", "build", "--pull", "--file", "-", "--tag", args.tag, str(context)],
        input=recipe, text=True, check=True,
    )


if __name__ == "__main__":
    main()
