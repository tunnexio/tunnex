import copy
import hashlib
import json
import unittest

import runtime_restore_runner as runner


class RestorationAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.before = {'DeliveryID': 'delivery', 'Phase': 'applied', 'Allocation': {'Namespace': 'net:[1]', 'Generation': 'old'}, 'Restoration': {'Epoch': 1}, 'Recovery': {'Stage': 'completed', 'SelectedSlot': 2, 'Sequence': 4}}
        self.after = {'DeliveryID': 'delivery', 'Phase': 'applied', 'Allocation': {'Namespace': 'net:[2]', 'Generation': 'new'}, 'Restoration': {'Epoch': 2}, 'Observed': [{'Namespace': 'net:[2]', 'InterfaceIndex': 7}, {'Namespace': 'net:[2]', 'InterfaceIndex': 8}], 'Recovery': {'Stage': 'completed', 'SelectedSlot': 2, 'Sequence': 4, 'PendingFrom': 0, 'PendingTo': 0}}

    def test_reserved_epoch_alone_not_success(self):
        self.assertTrue(runner.restored(self.before, self.after, 'net:[2]'))
        for key, value in [('Observed', [{'Namespace': '', 'InterfaceIndex': 0}] * 2), ('Recovery', {'Stage': 'pending', 'SelectedSlot': 2}), ('Restoration', {'Epoch': 1})]:
            after = copy.deepcopy(self.after)
            after[key] = value
            self.assertFalse(runner.restored(self.before, after, 'net:[2]'))

    def test_old_generation_and_namespace_refused(self):
        for key, value in [('Namespace', 'net:[1]'), ('Generation', 'old')]:
            after = copy.deepcopy(self.after)
            after['Allocation'][key] = value
            self.assertFalse(runner.restored(self.before, after, 'net:[2]'))

    def test_route_duty_and_sequence_preserved(self):
        after = copy.deepcopy(self.after)
        after['Recovery']['SelectedSlot'] = 1
        self.assertFalse(runner.restored(self.before, after, 'net:[2]'))
        after = copy.deepcopy(self.after)
        after['Recovery']['Sequence'] = 5
        self.assertFalse(runner.restored(self.before, after, 'net:[2]'))
        pending = copy.deepcopy(self.before)
        pending['Recovery'].update(Stage='pending', SelectedSlot=1, PendingTo=2)
        self.assertTrue(runner.restored(pending, self.after, 'net:[2]'))

    def test_exact_previous_receipt_only(self):
        raw = json.dumps({'DeliveryID': 'delivery', 'Namespace': 'net:[2]'}).encode()
        entry = copy.deepcopy(self.after)
        entry['Restoration']['Retired'] = [{'EvidenceDigest': hashlib.sha256(raw).hexdigest()}]
        runner.validate_previous_receipt(entry, raw)
        with self.assertRaises(ValueError):
            runner.validate_previous_receipt(entry, raw + b' ')
        entry['Allocation']['Namespace'] = 'net:[3]'
        with self.assertRaises(ValueError):
            runner.validate_previous_receipt(entry, raw)

    def test_both_exact_sessions_required(self):
        entry = {'Engines': [{'TunnelID': 'one', 'SecretRevision': 2, 'Binding': {'DesiredRevision': 3, 'ConfigurationRevision': 4}}, {'TunnelID': 'two', 'SecretRevision': 2, 'Binding': {'DesiredRevision': 3, 'ConfigurationRevision': 4}}]}
        text = '\n'.join('tnx-ipsec-%s-d3-c4-s2: #1, ESTABLISHED, IKEv2\n  tnx-ipsec-%s-d3-c4-s2: #1, reqid 7, INSTALLED, TUNNEL' % (name, name) for name in ('one', 'two'))
        self.assertTrue(runner.tunnels_installed(text, entry))
        self.assertFalse(runner.tunnels_installed(text.replace('two-d3-c4-s2', 'two-d3-c4-s1'), entry))
        self.assertFalse(runner.tunnels_installed(text.replace('INSTALLED', 'INSTALLING'), entry))

    def test_observed_kernel_link_ownership_required(self):
        entry = {'Allocation': {'Tunnels': [{'Name': 'x1', 'Alias': 'owned1', 'XFRMID': 1}, {'Name': 'x2', 'Alias': 'owned2', 'XFRMID': 2}]}, 'Observed': [{'InterfaceIndex': 11}, {'InterfaceIndex': 12}]}
        links = [{'ifname': 'x%d' % i, 'ifalias': 'owned%d' % i, 'ifindex': 10+i, 'linkinfo': {'info_kind': 'xfrm', 'info_data': {'if_id': i}}} for i in (1, 2)]
        self.assertTrue(runner.links_owned(links, entry))
        links[0]['linkinfo']['info_data']['if_id'] = '0x1'
        self.assertTrue(runner.links_owned(links, entry))
        links[0]['ifalias'] = 'foreign'
        self.assertFalse(runner.links_owned(links, entry))

class OrchestrationTests(unittest.TestCase):
    def test_proof_failure_restarts_exact_container_without_receipt(self):
        import os
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'restore-delivery.json'
            lock = os.open(Path(tmp) / 'lock', os.O_CREAT | os.O_RDWR, 0o600)
            args = SimpleNamespace(evidence_dir=tmp, journal=str(Path(tmp) / 'journal.json'), stop_timeout=2)
            calls = []
            with patch.object(runner, 'preflight', return_value=({'id': 'exact-id'}, {}, target, None, lock)), \
                 patch.object(runner.proof, 'snapshot', return_value={'scope': 'exact'}), \
                 patch.object(runner.proof, 'command', side_effect=lambda *a: calls.append(a) or ''), \
                 patch.object(runner.proof, 'prove', side_effect=ValueError('holder survived')):
                with self.assertRaisesRegex(ValueError, 'holder survived'):
                    runner.run(args)
            self.assertEqual(calls, [('docker', 'stop', '--time', '2', 'exact-id'), ('docker', 'start', 'exact-id')])
            self.assertFalse(target.exists())
            failure = json.loads(next(Path(tmp).glob('run-*/failure.json')).read_text())
            self.assertFalse(failure['receipt_installed'])
            self.assertTrue(failure['startup_gate_present'])
            self.assertTrue((Path(tmp) / 'restoration-startup-gate').exists())


    def test_gate_release_rejects_replacement_and_wrong_content(self):
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import patch
        expected = SimpleNamespace(st_dev=1, st_ino=2)
        good = SimpleNamespace(st_dev=1, st_ino=2, st_uid=0, st_mode=0o100600)
        replacement = SimpleNamespace(st_dev=1, st_ino=3, st_uid=0, st_mode=0o100600)
        for observed, contents in [(replacement, b'gate'), (good, b'foreign')]:
            with patch.object(Path, 'lstat', return_value=observed), \
                 patch.object(runner.proof, 'private_bytes', return_value=contents), \
                 patch.object(runner.os, 'unlink') as unlink:
                with self.assertRaises(ValueError):
                    runner.release_gate('/gate', b'gate', expected)
                unlink.assert_not_called()
        with patch.object(Path, 'lstat', return_value=good), \
             patch.object(runner.proof, 'private_bytes', return_value=b'gate'), \
             patch.object(runner.os, 'unlink') as unlink, \
             patch.object(runner, 'sync_directory'):
            runner.release_gate('/gate', b'gate', expected)
            unlink.assert_called_once_with('/gate')

    def test_same_inode_controlled_sequence_releases_gate_only_after_receipt(self):
        import os
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import patch
        fixture = RestorationAcceptanceTests()
        fixture.setUp()
        fixture.before['Allocation']['Namespace'] = 'net:[2]'
        after = fixture.after
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'restore-delivery.json'
            journal = Path(tmp) / 'journal.json'
            journal.write_text('{}')
            lock = os.open(Path(tmp) / 'lock', os.O_CREAT | os.O_RDWR, 0o600)
            args = SimpleNamespace(evidence_dir=tmp, journal=str(journal), stop_timeout=2, timeout=10,
                                   receipt_helper='/helper', strongswan_conf='/conf', swanctl='/swanctl', vici='unix:///vici')
            calls = []
            def command(*a):
                calls.append(a)
                if a[0] == '/helper':
                    Path(a[a.index('-out') + 1]).write_text('{"valid":"receipt"}')
                return '[]' if 'ip' in a else ''
            current = {'state': {'Running': True, 'Pid': 99, 'StartedAt': 'new'}}
            before = {'namespace': {'inode': 2}, 'boot': 'same-boot', 'started': 'old'}
            evidence = {'stopped_journal_raw_sha256': hashlib.sha256(b'{}').hexdigest()}
            def release_gate(path, raw, identity):
                self.assertTrue(target.exists(), 'receipt must be durable before gate release')
                self.assertEqual(Path(path).read_bytes(), raw)
                Path(path).unlink()
            with patch.object(runner, 'release_gate', side_effect=release_gate), \
                 patch.object(runner, 'preflight', return_value=({'id': 'exact-id'}, fixture.before, target, None, lock)), \
                 patch.object(runner.proof, 'snapshot', return_value=before), \
                 patch.object(runner.proof, 'prove', return_value=evidence), \
                 patch.object(runner.proof, 'command', side_effect=command), \
                 patch.object(runner.proof, 'inspect', return_value=current), \
                 patch.object(runner.proof, 'boot', return_value='same-boot'), \
                 patch.object(runner.proof, 'state_mount'), \
                 patch.object(runner.proof, 'private_bytes', side_effect=lambda p: Path(p).read_bytes()), \
                 patch.object(runner.proof, 'private_read', return_value={'Payload': {'Entries': [dict(after, ContractVersion=2)]}}), \
                 patch.object(runner.os, 'readlink', return_value='net:[2]'), \
                 patch.object(runner, 'tunnels_installed', return_value=True), \
                 patch.object(runner, 'links_owned', return_value=True):
                result = runner.run(args)
            self.assertEqual(result['status'], 'controller-and-tunnels-restored')
            self.assertFalse(result['payload_verified'])
            self.assertTrue(target.exists())
            self.assertFalse((Path(tmp) / 'restoration-startup-gate').exists())
            self.assertEqual(calls[0][:2], ('docker', 'stop'))
            self.assertEqual(calls[1][:2], ('docker', 'start'))
            self.assertEqual(calls[2][0], '/helper')


if __name__ == '__main__':
    unittest.main()
