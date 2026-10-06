#!/bin/sh
set -eu
cd "$(dirname "$0")"
# Independent control of this exact owned target is the fixture trust channel.
./run.sh exec -T ssh-target cat /ssh-state/host.pub > .runtime/ssh/target-host.pub
python3 - <<'PY'
from pathlib import Path
p=Path('.runtime/ssh'); key=(p/'target-host.pub').read_text().split()
(Path('.runtime/ssh-client')/'known_hosts').write_text('[ssh-target]:2222 '+key[0]+' '+key[1]+'\n')
PY
