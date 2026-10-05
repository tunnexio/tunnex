#!/usr/bin/env python3
"""Project measured manifests into API metadata; no registration or activation."""
import json
from pathlib import Path

root = Path(__file__).resolve().parents[3]
manifest = json.loads((Path(__file__).with_name('manifest.json')).read_text())
base_tools = ['Bash', 'OpenSSH/SFTP', 'coreutils', 'WireGuard', 'iproute2', 'nftables', 'openresolv', 'setpriv', 'CA certificates', 'Tunnex static bootstrap']
catalog = []
for measured in manifest['profiles']:
    variant = measured['profile']
    tools = base_tools + ([measured['versions']['python']] if variant == 'python' else [f"Node.js {measured['versions']['node']}", f"npm {measured['versions']['npm']}"] if variant == 'node' else [])
    context = 'Docker Desktop Linux/arm64; ' + ('amd64 emulation; memory includes emulator overhead and does not predict native amd64 RAM' if measured['emulated'] else 'native arm64 container; does not predict native rootless RAM')
    catalog.append(dict(name={'minimal':'Minimal Alpine', 'python':'Alpine Python', 'node':'Alpine Node.js'}[variant], distro='Alpine 3.23 (musl)', architecture=measured['architecture'], image_digest=measured['platform_manifest_digest'], config_digest=measured['config_digest'], compressed_image_bytes=measured['compressed_layer_download_bytes'], unpacked_image_bytes=measured['unpacked_filesystem_allocated_bytes'], idle_memory_bytes=measured['idle_cgroup_bytes'], evidence_context=context, measured_at=manifest['measured_at'], included_tools=tools, excluded_tools=measured['excluded_tools'], compatibility='musl; arbitrary glibc binaries unsupported. Use local Codex/Claude over private SSH.', qualification='candidate', emulated=measured['emulated'], measurement_memory_cap_bytes=measured['memory_cap_bytes'], measurement_workspace_cap_bytes=measured['workspace_tmpfs_cap_bytes']))
(root / 'apps/api/internal/sandboxes/image_profiles.json').write_text(json.dumps(catalog, indent=2) + '\n')
