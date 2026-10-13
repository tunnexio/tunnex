#!/usr/bin/env python3
# Actual managed IKE component only; no CP authority or traffic grant.
import subprocess, json, time, os, hashlib
from pathlib import Path
image = os.environ['GCP_COMPONENT_IMAGE']
if not image.startswith('sha256:') or len(image) != 71:
    raise ValueError('exact image ID required')
network = os.environ.get('GCP_COMPONENT_NETWORK', 'tunnex-gcp-component-runtime')
mount = str(Path(os.environ['GCP_COMPONENT_TEST_BINARY']).resolve())
receipt_dir = Path(os.environ['GCP_COMPONENT_RECEIPT_DIR']).resolve()
receipt_dir.mkdir(mode=448, parents=True, exist_ok=False)
log = []
source = os.environ['GCP_COMPONENT_SOURCE_COMMIT']
profiles = ['gcp-ha-bgp-ipv4-v1', 'gcp-classic-static-ipv4-v1']
containers = []
created = False

def run(args, input=None):
    r = subprocess.run(args, input=input, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=65)
    if r.returncode:
        log.append(r.stdout)
        raise RuntimeError(' '.join(args[:4]) + ' ' + r.stdout)
    return r.stdout
try:
    run(['docker', 'network', 'create', '--internal', '--subnet', '198.18.222.0/24', '--label', 'tunnex.test.owner=gcp-s2s-runtime', network])
    created = True
    for profile, count in [('gcp-ha-bgp-ipv4-v1', 2), ('gcp-classic-static-ipv4-v1', 1)]:
        names = {role: network + '-' + role for role in ['gateway', 'peer']}
        for role, addr in [('gateway', '198.18.222.10'), ('peer', '198.18.222.20')]:
            name = names[role]
            run(['docker', 'run', '-d', '--name', name, '--network', network, '--ip', addr, '--cap-add', 'NET_ADMIN', '--label', 'tunnex.test.owner=gcp-s2s-runtime', '--mount', 'type=bind,source=' + mount + ',target=/test/ipsec.test,readonly', '--entrypoint', '/test/ipsec.test', '-e', 'TUNNEX_GCP_DAEMON_COMPONENT_LAB=1', image, '-test.run', '^TestGCPDaemonComponentServe$', '-test.v'])
            containers.append(name)
            for _ in range(30):
                logs = run(['docker', 'logs', name])
                if 'GCP_COMPONENT_DAEMON_READY' in logs:
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError(logs)
            if role == 'peer' and count == 2:
                run(['docker', 'exec', name, 'ip', 'addr', 'add', '198.18.222.21/24', 'dev', 'eth0'])
            for i in range(count):
                run(['docker', 'exec', name, 'ip', 'link', 'add', 'gcp' + str(i), 'type', 'xfrm', 'if_id', str((701 if role == 'gateway' else 801) + i)])

        def phase(role, action, wrong=False):
            req = {'ProfileID': profile, 'Role': role, 'Phase': action, 'PSKs': ['synthetic-GCP-component-secret-A-2026', 'synthetic-GCP-component-secret-B-2026' if count == 2 else '']}
            if wrong:
                req['PSKs'] = ['synthetic-wrong-component-secret-2026', 'synthetic-wrong-component-secret-2026' if count == 2 else '']
            out = run(['docker', 'exec', '-i', '-e', 'TUNNEX_GCP_DAEMON_COMPONENT_LAB=1', names[role], '/test/ipsec.test', '-test.run', '^TestGCPDaemonComponentPhase$', '-test.v'], json.dumps(req))
            log.append(out)
            print(out, flush=True)
        phase('peer', 'stage')
        phase('gateway', 'stage')
        phase('gateway', 'initiate')
        phase('peer', 'observe')
        phase('gateway', 'rekey')
        phase('peer', 'observe')
        phase('gateway', 'cleanup')
        phase('peer', 'cleanup')
        phase('peer', 'stage')
        phase('gateway', 'stage', True)
        phase('gateway', 'refused')
        phase('gateway', 'cleanup')
        phase('peer', 'cleanup')
        phase('peer', 'stage-bad-proposal')
        phase('gateway', 'stage')
        phase('gateway', 'refused')
        phase('gateway', 'cleanup')
        phase('peer', 'cleanup')
        for name in list(containers):
            run(['docker', 'rm', '-f', name])
            containers.remove(name)
    receipt = {'source_commit': source, 'test_binary_sha256': hashlib.sha256(Path(mount).read_bytes()).hexdigest(), 'fixture_sha256': hashlib.sha256((Path(__file__).resolve().parents[2] / 'apps/node/internal/ipsec/daemon_gcp_linux_test.go').read_bytes()).hexdigest(), 'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'image_id': image, 'profiles': profiles, 'result': 'PASS', 'scope': 'managed IKE component; no CP authority or GCP cloud proof', 'cases': ['one/two actual IKE and CHILD cardinality', 'route-based selectors and kernel binding', 'rekey SPI replacement', 'wrong-key refusal zero kernel states/policies', 'incompatible IKE proposal refusal', 'exact cleanup/recreate'], 'native_state_count_per_tunnel': 2, 'native_policy_count_per_tunnel': 3}
    (receipt_dir / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
finally:
    (receipt_dir / 'run.log').write_text(''.join(log))
    for name in containers:
        subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL)
    if created:
        subprocess.run(['docker', 'network', 'rm', network], stdout=subprocess.DEVNULL)
