import contextlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('fault', Path(__file__).with_name('owned-tunnel-fault.py'))
fault = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fault)


class FaultTests(unittest.TestCase):
    def test_single_peer_host_scope_and_finally_cleanup(self):
        commands = []
        def run(argv, data=None, allow_absent=False):
            commands.append((argv, data))
            if argv[0] == 'docker' and 'Labels' in argv[3]:
                return 0, fault.OWNER.encode()
            if argv[0] == 'docker':
                return 0, json.dumps({fault.NETWORK: {'IPAddress': '172.22.0.5'}}).encode()
            return 0, b''
        inventories = iter([None, {'owned': True}])
        with patch.object(fault.socket, 'gethostname', return_value='tunnex-peer'), patch.object(fault, 'run', run), patch.object(fault, 'fault_inventory', lambda *_: next(inventories)), patch.object(fault.os, 'geteuid', return_value=0), patch.object(fault.signal, 'signal'), patch.object(fault.time, 'sleep', side_effect=KeyboardInterrupt), patch('sys.argv', ['fault', 'block', '--container', 'owned', '--slot', '1']), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                fault.main()
        script = next(data for argv, data in commands if argv == ['nft', '-f', '-']).decode()
        self.assertIn('172.22.0.5', script)
        self.assertIn('52.140.60.21', script)
        self.assertNotIn('20.219.125.34', script)
        self.assertIn('hook forward', script)
        self.assertFalse(any(argv[:2] == ['docker', 'exec'] for argv, _ in commands))
        self.assertIn((['nft', 'delete', 'table', 'inet', fault.TABLE], None), commands)

    def test_both_mode_targets_only_exact_two_peers_and_bridge(self):
        commands = []
        def run(argv, data=None, allow_absent=False):
            commands.append((argv, data))
            if argv[0] == 'docker' and 'Labels' in argv[3]:
                return 0, fault.OWNER.encode()
            if argv[0] == 'docker':
                return 0, json.dumps({fault.NETWORK: {'IPAddress': '172.22.0.5'}}).encode()
            return 0, b''
        inventories = iter([None, {'owned': True}])
        with patch.object(fault.socket, 'gethostname', return_value='tunnex-peer'), patch.object(fault, 'run', run), patch.object(fault, 'fault_inventory', lambda *_: next(inventories)), patch.object(fault.os, 'geteuid', return_value=0), patch.object(fault.signal, 'signal'), patch.object(fault.time, 'sleep'), patch('sys.argv', ['fault', 'block', '--container', 'owned', '--slot', 'both', '--seconds', '45']), contextlib.redirect_stdout(io.StringIO()) as output:
            fault.main()
        script = next(data for argv, data in commands if argv == ['nft', '-f', '-']).decode()
        self.assertEqual(script.count(' counter drop'), 8)
        for peer in fault.PEERS.values():
            self.assertEqual(script.count(peer), 4)
        self.assertEqual(script.count('172.22.0.5'), 8)
        self.assertFalse(any(argv[:2] == ['docker', 'exec'] for argv, _ in commands))
        self.assertEqual(json.loads(output.getvalue().splitlines()[0])['slots'], [1, 2])
        self.assertIn((['nft', 'delete', 'table', 'inet', fault.TABLE], None), commands)

    def test_actual_nft_102_missing_json_comment_requires_full_attestation(self):
        fixture = Path(__file__).with_name('testdata')
        raw = (fixture / 'fault-nft-1.0.2.json').read_bytes()
        text = (fixture / 'fault-nft-1.0.2.txt').read_bytes()
        with patch.object(fault, 'run', side_effect=[(0, raw), (0, text)]):
            self.assertIsNotNone(fault.fault_inventory('172.18.0.5'))
        for mutation in ['wrong_owner', 'wrong_bridge', 'wrong_peer', 'extra_text_rule', 'wrong_json_peer', 'extra_json_expression', 'foreign_chain', 'negative_counter']:
            with self.subTest(mutation=mutation):
                doc = json.loads(raw)
                changed = text.decode()
                if mutation == 'wrong_owner': changed = changed.replace(fault.OWNER, 'foreign')
                if mutation == 'wrong_bridge': changed = changed.replace('172.18.0.5', '172.18.0.6')
                if mutation == 'wrong_peer': changed = changed.replace('52.140.60.21', '1.1.1.1')
                if mutation == 'extra_text_rule': changed += '\n accept\n'
                if mutation == 'wrong_json_peer': doc['nftables'][3]['rule']['expr'][1]['match']['right'] = '1.1.1.1'
                if mutation == 'extra_json_expression': doc['nftables'][3]['rule']['expr'].append({'accept': None})
                if mutation == 'foreign_chain': doc['nftables'][2]['chain']['prio'] = 0
                if mutation == 'negative_counter': doc['nftables'][3]['rule']['expr'][3]['counter']['packets'] = -1
                with self.assertRaises(ValueError):
                    fault.attest_fault_text(doc, changed, '172.18.0.5')

    def test_failed_table_observation_is_not_absence(self):
        inventory = json.dumps({'nftables': [{'table': {'family': 'inet', 'name': fault.TABLE}}]}).encode()
        with patch.object(fault, 'run', side_effect=[(1, b''), (0, inventory)]):
            with self.assertRaises(ValueError):
                fault.fault_inventory('172.18.0.5')
        with patch.object(fault, 'run', side_effect=ValueError('observation unavailable')):
            with self.assertRaises(ValueError):
                fault.clear('172.18.0.5')

    def test_wrong_hostname_refuses_all_operations(self):
        with patch.object(fault.socket, 'gethostname', return_value='foreign-host'), patch.object(fault, 'run') as run, patch('sys.argv', ['fault', 'clear']):
            with self.assertRaises(ValueError):
                fault.main()
            run.assert_not_called()

    def test_foreign_table_cannot_be_cleared(self):
        raw = json.dumps({'nftables': [{'table': {'family': 'inet', 'name': fault.TABLE, 'comment': 'foreign'}}]}).encode()
        with patch.object(fault, 'run', return_value=(0, raw)) as run:
            with self.assertRaises(ValueError):
                fault.clear()
            self.assertFalse(any(call.args[0][1:2] == ['delete'] for call in run.call_args_list))


if __name__ == '__main__':
    unittest.main()
