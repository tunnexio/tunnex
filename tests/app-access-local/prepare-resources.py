#!/usr/bin/env python3
"""Create first-run resources only after exact-name ownership validation."""
from pathlib import Path
import subprocess
from ownership import check, PROJECT, OwnershipError


def prepare(root, call=None, create=None):
    # check() refuses every missing resource already recorded in the marker.
    missing = check(root, call)
    create = create or (lambda kind, name: subprocess.run(
        [str(root / 'docker-local.sh'), kind, 'create',
         '--label', 'com.docker.compose.project=' + PROJECT,
         '--label', 'app-access.checkout=' + str(root.resolve()), name],
        check=True, stdout=subprocess.DEVNULL))
    for kind, name in missing:
        create(kind, name)
    check(root, call)

if __name__ == '__main__':
    try:
        prepare(Path(__file__).resolve().parent)
    except OwnershipError as error:
        raise SystemExit('App Access ownership refusal: ' + str(error))
