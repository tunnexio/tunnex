import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import runtime_stop_proof as proof


class StopProofTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        (Path(self.tmp.name) / 'ipsec').mkdir()
        self.journal = Path(self.tmp.name) / 'ipsec/journal.json'
        self.document = {'Payload': {'OwnerID': 'test-owner', 'Entries': [], 'Sequence': 1}}
        self.journal.write_text(json.dumps(self.document))
        self.before = {
            'version': 1, 'container': 'a' * 64, 'boot': 'prior-boot',
            'started': 'original-start', 'observed_ns': 10000000000,
            'namespace': {'device': 1, 'inode': 2},
            'cgroup': '/sys/fs/cgroup/docker/' + 'a' * 64,
            'journal': str(self.journal),
            'state_mount': {'source': self.tmp.name, 'destination': '/var/lib/tunnex-node', 'type': 'bind'},
            'journal_entries_sha256': proof.journal_entries_digest(self.document),
            'journal_raw_sha256': hashlib.sha256(b'{}').hexdigest(),
        }
        self.stopped = {'id': 'a' * 64, 'mounts': [{'Source': self.tmp.name, 'Destination': '/var/lib/tunnex-node', 'Type': 'bind', 'RW': True}], 'state': {
            'Running': False, 'Pid': 0, 'Restarting': False,
            'StartedAt': 'original-start', 'FinishedAt': 'finished'}}
        self.event = json.dumps({'Actor': {'ID': 'a' * 64}, 'Action': 'die', 'timeNano': 11000000000})

    def run_proof(self, identity=None, holders=None, event=None, journal=None):
        with patch.object(proof, 'inspect', return_value=identity or self.stopped), \
             patch.object(proof, 'boot', return_value='prior-boot'), \
             patch.object(proof, 'namespace_holders', return_value=holders or []), \
             patch.object(proof, 'command', return_value=self.event if event is None else event), \
             patch.object(proof, 'private_bytes', return_value=json.dumps(self.document if journal is None else journal).encode()):
            return proof.prove(self.before)

    def snapshot_for_cgroup(self, cgroup):
        running = copy.deepcopy(self.stopped)
        running['state'].update(Running=True, Pid=123)
        running['sandbox'] = '/var/run/docker/netns/test'
        ns = type('NamespaceStat', (), {'st_dev': 1, 'st_ino': 2})()
        with patch.object(proof, 'inspect', return_value=running), \
             patch.object(proof, 'boot', return_value='prior-boot'), \
             patch.object(proof, 'private_bytes', return_value=json.dumps(self.document).encode()), \
             patch.object(proof.os, 'stat', return_value=ns), \
             patch.object(Path, 'read_text', return_value=cgroup):
            return proof.snapshot(running['id'], str(self.journal))

    def test_snapshot_accepts_only_exact_docker_cgroup_layouts(self):
        for path in proof.docker_cgroup_paths(self.before['container']):
            with self.subTest(path=path):
                value = self.snapshot_for_cgroup('0::' + path + '\n')
                self.assertEqual(value['cgroup'], '/sys/fs/cgroup' + path)
                self.assertEqual(value['container'], self.before['container'])
                self.assertEqual(value['journal_entries_sha256'], self.before['journal_entries_sha256'])

    def invalid_cgroup_paths(self):
        own, other = 'a' * 64, 'b' * 64
        return [
            '/docker/' + other,
            '/system.slice/docker-' + other + '.scope',
            '/system.slice/tunnex.service',
            '/system.slice/docker-' + own + '.service',
            '/system.slice/docker-' + own[:12] + '.scope',
            '/system.slice/docker-' + own + '.scope/child',
            '/docker/' + own + '/../' + other,
            '/docker/../system.slice/docker-' + own + '.scope',
            '//docker/' + own,
            '/docker/' + own + '/',
            '/docker/' + own + '\n0::/system.slice/docker-' + other + '.scope',
        ]

    def test_snapshot_rejects_foreign_escaped_and_mixed_cgroups(self):
        for path in self.invalid_cgroup_paths():
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'unsupported cgroup'):
                self.snapshot_for_cgroup('0::' + path)
        with self.assertRaisesRegex(ValueError, 'unsupported cgroup'):
            self.snapshot_for_cgroup('1:cpu:/docker/' + self.before['container'])

    def test_proof_accepts_both_layouts_and_requires_two_empty_passes(self):
        for path in proof.docker_cgroup_paths(self.before['container']):
            with self.subTest(path=path):
                self.before['cgroup'] = '/sys/fs/cgroup' + path
                with patch.object(Path, 'exists', return_value=True), \
                     patch.object(Path, 'read_text', autospec=True, return_value='populated 0\n') as reads:
                    self.run_proof()
                    self.assertEqual(reads.call_count, 2)
                    self.assertTrue(all(str(call.args[0]) == self.before['cgroup'] + '/cgroup.events'
                                        for call in reads.call_args_list))
                with patch.object(Path, 'exists', return_value=True), \
                     patch.object(Path, 'read_text', side_effect=['populated 0\n', 'populated 1\n']):
                    with self.assertRaisesRegex(ValueError, 'still populated'):
                        self.run_proof()

    def test_systemd_proof_rejects_namespace_holder_on_second_pass(self):
        self.before['cgroup'] = '/sys/fs/cgroup' + proof.docker_cgroup_paths(self.before['container'])[1]
        with patch.object(proof, 'inspect', return_value=self.stopped), \
             patch.object(proof, 'boot', return_value='prior-boot'), \
             patch.object(proof, 'private_bytes', return_value=json.dumps(self.document).encode()), \
             patch.object(Path, 'exists', return_value=False), \
             patch.object(proof, 'namespace_holders', side_effect=[[], ['/proc/other/ns/net']]):
            with self.assertRaisesRegex(ValueError, 'still referenced'):
                proof.prove(self.before)

    def test_proof_rejects_foreign_escaped_and_mixed_cgroup_paths(self):
        for path in self.invalid_cgroup_paths():
            with self.subTest(path=path):
                self.before['cgroup'] = '/sys/fs/cgroup' + path
                with self.assertRaisesRegex(ValueError, 'foreign cgroup'):
                    self.run_proof()

    def test_exact_stop_requires_all_proofs(self):
        result = self.run_proof()
        self.assertEqual(result['kind'], 'supervisor-confirmed-runtime-stop')
        self.assertEqual(result['snapshot'], self.before)
        self.assertEqual(result['termination']['time_ns'], 11000000000)

    def test_running_restarted_pid_or_foreign_container_refused(self):
        mutations = [
            ('Running', True), ('Pid', 999), ('Restarting', True),
            ('StartedAt', 'later-start'), ('FinishedAt', '0001-01-01')]
        for field, value in mutations:
            with self.subTest(field=field):
                identity = copy.deepcopy(self.stopped)
                identity['state'][field] = value
                with self.assertRaises(ValueError):
                    self.run_proof(identity=identity)
        identity = copy.deepcopy(self.stopped)
        identity['id'] = 'b' * 64
        with self.assertRaises(ValueError):
            self.run_proof(identity=identity)

    def test_any_old_namespace_reference_refused(self):
        with self.assertRaisesRegex(ValueError, 'still referenced'):
            self.run_proof(holders=['/proc/other/ns/net'])

    def test_absence_without_retained_lifecycle_event_refused(self):
        for event in ['', self.event + '\n' + self.event,
                      self.event.replace('11000000000', '9000000000'),
                      self.event.replace('a' * 64, 'b' * 64)]:
            with self.subTest(event=event):
                with self.assertRaisesRegex(ValueError, 'die event'):
                    self.run_proof(event=event)

    def test_changed_journal_refused(self):
        with self.assertRaisesRegex(ValueError, 'journal entries changed'):
            self.run_proof(journal={'Payload': {'OwnerID': 'test-owner', 'Entries': [{'changed': True}]}})

    def test_guard_sequence_changes_preserve_exact_entries_binding(self):
        changed = copy.deepcopy(self.document)
        changed['Payload']['Sequence'] = 2
        changed['Payload']['Guards'] = [{'changed': True}]
        result = self.run_proof(journal=changed)
        self.assertEqual(result['stopped_journal_raw_sha256'], hashlib.sha256(json.dumps(changed).encode()).hexdigest())

    def test_boot_change_not_treated_as_same_boot_docker_stop(self):
        with self.assertRaises(ValueError):
            proof.validate_stopped(self.before, self.stopped, 'new-boot')

    def test_unsafe_evidence_file_refused(self):
        self.journal.chmod(0o644)
        with self.assertRaises(ValueError):
            proof.private_read(self.journal)
        link = Path(self.tmp.name) / 'link'
        link.symlink_to(self.journal)
        with self.assertRaises(OSError):
            proof.private_read(link)

    def test_foreign_journal_mount_refused(self):
        identity = copy.deepcopy(self.stopped)
        identity['mounts'][0]['Source'] = '/different/container/state'
        with self.assertRaisesRegex(ValueError, 'does not belong'):
            self.run_proof(identity=identity)

    def test_mount_escape_decoding(self):
        self.assertEqual(proof.unescape_mount('/a\\040b/\\134x'), '/a b/\\x')


if __name__ == '__main__':
    unittest.main()
