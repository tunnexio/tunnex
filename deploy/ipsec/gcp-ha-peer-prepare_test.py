#!/usr/bin/env python3
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('prepare', Path(__file__).with_name('gcp-ha-peer-prepare.py'))
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)
ROOT = Path(__file__).resolve().parents[2]

class PrepareTest(unittest.TestCase):
    def setUp(self):
        golden = json.loads((ROOT / 'apps/node/internal/ipsec/testdata/api_gcp_runtime_manifest_golden.json').read_text())[0]
        self.material = dict(kind='apply', delivery_id='00000000-0000-4000-8000-000000000099', desired_revision=golden['manifest']['desired_revision'], manifest=golden['manifest'], ownership_digest=golden['sha256'], secrets=[dict(tunnel_id=t['id'], revision=t['secret_revision'], psk='0-synthetic-test-only') for t in golden['manifest']['tunnels']])
        # Wire golden uses illustrative allocations; model genuine CP kernel allocation.
        for t in self.material['manifest']['tunnels']:
            digest = prepare.hashlib.sha256(prepare.uuid.UUID(t['id']).bytes).digest()
            t['link_name'] = 'tx' + digest[:6].hex()
            t['xfrm_id'] = t['reqid'] = int.from_bytes(digest[:4], 'big') | 0x80000000
        self.material['ownership_digest'] = prepare.hashlib.sha256(json.dumps(self.material['manifest'], separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()
        self.args = ('00000000-0000-4000-8000-000000000088', '00000000-0000-4000-8000-000000000077', str(prepare.ipaddress.IPv4Network(self.material['manifest']['remote_prefixes'][0]).network_address + 10), str(prepare.ipaddress.IPv4Network(self.material['manifest']['local_prefixes'][0]).network_address + 10))
    def config(self, value):
        return prepare.peer_config(value, *self.args)
    def test_api_golden_reverse_exact_bindings(self):
        c = self.config(self.material)
        self.assertEqual(len(c['CustomTunnels']), 2)
        self.assertEqual(c['BGPConfig']['LocalASN'], self.material['manifest']['bgp']['remote_asn'])
        self.assertFalse(c['ActivationPerformed'])
        for tunnel, peer in zip(self.material['manifest']['tunnels'], c['CustomTunnels']):
            self.assertEqual(peer['RemoteAddress'], self.material['manifest']['customer_outside_address'])
            self.assertEqual(peer['LocalAddress'], tunnel['outside_address'])
            self.assertEqual(peer['TunnelID'], tunnel['id'])
    def test_digest_secret_profile_and_binding_refused(self):
        for change in [lambda m: m.update(ownership_digest='0'*64), lambda m: m['secrets'][0].update(revision=999), lambda m: m['secrets'][0].update(psk='bad\nsecret'), lambda m: m['manifest'].update(profile_id='gcp-classic-static-ipv4-v1')]:
            m = copy.deepcopy(self.material)
            change(m)
            with self.assertRaises(ValueError): self.config(m)
    def test_key_free_projection_uses_only_owned_creation_keys(self):
        projection = copy.deepcopy(self.material); del projection['secrets']
        config = projection['manifest']
        creation = dict(id=config['connection_id'], tunnel_ids=[t['id'] for t in config['tunnels']], configuration={field:copy.deepcopy(config[field]) for field in ['profile_id','customer_outside_address','local_prefixes','remote_prefixes','bgp']})
        creation['configuration']['tunnels'] = [{**{field:t[field] for field in ['outside_address','inside_cidr','customer_inside_address','cloud_inside_address']}, 'psk':'0-owned-local-create-only'} for t in config['tunnels']]
        result = prepare.attach_creation_secrets(projection, creation)
        self.assertEqual(result['secrets'][0]['psk'], '0-owned-local-create-only')
        self.assertNotIn('secrets', projection)
        with self.assertRaises(ValueError): prepare.attach_creation_secrets(self.material, creation)
        projection['manifest']['tunnels'][0]['secret_revision'] = 2
        with self.assertRaises(ValueError): prepare.attach_creation_secrets(projection, creation)
    def test_private_input_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'material.json'
            path.write_text(json.dumps(self.material)); path.chmod(0o600)
            self.assertEqual(prepare.read_private(path)['kind'], 'apply')
            path.chmod(0o644)
            with self.assertRaises(ValueError): prepare.read_private(path)
            link = Path(directory)/'link'; link.symlink_to(path)
            with self.assertRaises(OSError): prepare.read_private(link)
        with self.assertRaises(ValueError): prepare.unique_object([('psk','first'),('psk','second')])

if __name__ == '__main__': unittest.main()
