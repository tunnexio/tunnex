"""Mock-only isolation regressions; no Docker resources are created or removed."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from ownership import check, EXPECTED, PROJECT, OwnershipError, MissingResource

spec = importlib.util.spec_from_file_location('prepare_resources', Path(__file__).with_name('prepare-resources.py'))
prepare_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare_module)

class OwnershipTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.items = {}
        for kind, suffix in EXPECTED:
            name = PROJECT + '_' + suffix
            item = {'Name': name, 'Labels': {'com.docker.compose.project': PROJECT, 'app-access.checkout': str(self.root)}}
            if kind == 'network':
                item['Id'] = 'network-original'
            else:
                item['CreatedAt'] = '2026-10-03T00:00:00Z'
            self.items[kind, name] = item
        self.calls = []
        self.created = []

    def call(self, *args):
        self.calls.append(args)
        if args[0] == 'ps':
            return ''
        key = (args[0], args[2])
        if key not in self.items:
            raise MissingResource(args[2])
        return json.dumps([self.items[key]])

    def create(self, kind, name):
        self.created.append((kind, name))
        self.items[kind, name] = {'Name': name, 'CreatedAt': 'new', 'Labels': {'com.docker.compose.project': PROJECT, 'app-access.checkout': str(self.root)}}

    def test_every_expected_name_inspected_without_project_filter(self):
        check(self.root, self.call)
        for kind, suffix in EXPECTED:
            self.assertIn((kind, 'inspect', PROJECT + '_' + suffix), self.calls)
        self.assertFalse(any(args[:2] in [('network', 'ls'), ('volume', 'ls')] for args in self.calls))

    def test_foreign_or_unlabelled_exact_name_rejected_before_create(self):
        for label in ('another-project', None):
            with self.subTest(label=label):
                self.items['volume', PROJECT + '_postgres_data']['Labels']['com.docker.compose.project'] = label
                with self.assertRaises(OwnershipError):
                    prepare_module.prepare(self.root, self.call, self.create)
                self.assertEqual(self.created, [])

    def test_unknown_checkout_rejected(self):
        self.items['network', PROJECT + '_default']['Labels']['app-access.checkout'] = 'another-checkout'
        with self.assertRaises(OwnershipError):
            check(self.root, self.call)

    def test_retained_recorded_legacy_resources_permitted(self):
        check(self.root, self.call)
        for item in self.items.values():
            item['Labels'].pop('app-access.checkout')
        self.assertEqual(check(self.root, self.call), [])

    def test_recorded_resource_foreign_checkout_label_rejected(self):
        check(self.root, self.call)
        self.items['network', PROJECT + '_default']['Labels']['app-access.checkout'] = 'another-checkout'
        with self.assertRaises(OwnershipError):
            check(self.root, self.call)

    def test_recorded_missing_volume_not_recreated(self):
        check(self.root, self.call)
        del self.items['volume', PROJECT + '_postgres_data']
        with self.assertRaisesRegex(OwnershipError, 'missing'):
            prepare_module.prepare(self.root, self.call, self.create)
        self.assertEqual(self.created, [])

    def test_replaced_same_labelled_resource_rejected(self):
        check(self.root, self.call)
        self.items['volume', PROJECT + '_gateway_state']['CreatedAt'] = 'replacement'
        with self.assertRaisesRegex(OwnershipError, 'identity changed'):
            check(self.root, self.call)

    def test_fresh_missing_resource_can_be_created(self):
        del self.items['volume', PROJECT + '_postgres_data']
        prepare_module.prepare(self.root, self.call, self.create)
        self.assertEqual(self.created, [('volume', PROJECT + '_postgres_data')])

    def test_marker_copied_from_another_checkout_rejected(self):
        check(self.root, self.call)
        marker = self.root / '.runtime' / 'ownership.json'
        state = json.loads(marker.read_text()); state['checkout'] = 'another-checkout'
        marker.write_text(json.dumps(state))
        with self.assertRaises(OwnershipError):
            check(self.root, self.call)

if __name__ == '__main__':
    unittest.main()
