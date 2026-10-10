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
        with patch.object(fault.socket, 'gethostname', return_value='tunnex-peer'), patch.object(fault, 'run', run), patch.object(fault, 'fault_inventory', lambda: next(inventories)), patch.object(fault.os, 'geteuid', return_value=0), patch.object(fault.signal, 'signal'), patch.object(fault.time, 'sleep', side_effect=KeyboardInterrupt), patch('sys.argv', ['fault', 'block', '--container', 'owned', '--slot', '1']), contextlib.redirect_stdout(io.StringIO()):
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
        with patch.object(fault.socket, 'gethostname', return_value='tunnex-peer'), patch.object(fault, 'run', run), patch.object(fault, 'fault_inventory', lambda: next(inventories)), patch.object(fault.os, 'geteuid', return_value=0), patch.object(fault.signal, 'signal'), patch.object(fault.time, 'sleep'), patch('sys.argv', ['fault', 'block', '--container', 'owned', '--slot', 'both', '--seconds', '45']), contextlib.redirect_stdout(io.StringIO()) as output:
            fault.main()
        script = next(data for argv, data in commands if argv == ['nft', '-f', '-']).decode()
        self.assertEqual(script.count(' counter drop'), 8)
        for peer in fault.PEERS.values():
            self.assertEqual(script.count(peer), 4)
        self.assertEqual(script.count('172.22.0.5'), 8)
        self.assertFalse(any(argv[:2] == ['docker', 'exec'] for argv, _ in commands))
        self.assertEqual(json.loads(output.getvalue().splitlines()[0])['slots'], [1, 2])
        self.assertIn((['nft', 'delete', 'table', 'inet', fault.TABLE], None), commands)

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
            self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
