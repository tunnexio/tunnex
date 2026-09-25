"""Preflight refusal checks; never invokes Docker or creates lab resources."""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock
from qualification_helpers import remove_lab_gateway_dns_table

SCRIPT = pathlib.Path(__file__).with_name('qualify_coexistence.py')


class QualificationPreflightTests(unittest.TestCase):
    def run_preflight(self, *arguments):
        return subprocess.run(
            [sys.executable, str(SCRIPT), '--binary', '/nonexistent-s2s-binary',
             '--binary-sha256', '0' * 64, *arguments],
            capture_output=True, text=True, timeout=5,
        )

    def test_rejects_unsafe_coordinates_before_binary_or_docker_access(self):
        for arguments in (
            ('--project', 'default'),
            ('--rotation',),
            ('--candidate-image', 'candidate:latest'),
            ('--tools-image', 'tools:latest'),
            ('--native-arch', 'x86_64'),
            ('--binary-sha256', 'invalid'),
        ):
            with self.subTest(arguments=arguments):
                result = self.run_preflight(*arguments)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('error:', result.stderr)
                self.assertNotIn('FileNotFoundError', result.stderr)

    def test_refuses_existing_evidence_without_overwriting_it(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = pathlib.Path(directory) / 'result.json'
            marker.write_text('previous evidence')
            result = self.run_preflight('--evidence-dir', directory)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('FileExistsError', result.stderr)
            self.assertEqual(marker.read_text(), 'previous evidence')


class GatewayDNSTableTests(unittest.TestCase):
    def census(self, entries):
        return Mock(return_value=subprocess.CompletedProcess(
            [], 0, stdout=json.dumps({'nftables': entries}).encode()))

    def test_removes_only_exact_optional_ipv4_nat_table(self):
        run = self.census([{'table': {'family': 'ip', 'name': 'nat'}}])
        remove_lab_gateway_dns_table(run)
        self.assertEqual(run.call_count, 2)
        run.assert_called_with('gateway', ['nft', 'delete', 'table', 'ip', 'nat'])

    def test_absent_or_other_tables_are_preserved(self):
        for entries in ([], [{'table': {'family': 'ip6', 'name': 'nat'}}],
                        [{'table': {'family': 'ip', 'name': 'filter'}}]):
            with self.subTest(entries=entries):
                run = self.census(entries)
                remove_lab_gateway_dns_table(run)
                run.assert_called_once_with('gateway', ['nft', '-j', 'list', 'tables'], capture_output=True)

    def test_census_failure_never_deletes(self):
        run = Mock(side_effect=subprocess.CalledProcessError(1, ['nft']))
        with self.assertRaises(subprocess.CalledProcessError):
            remove_lab_gateway_dns_table(run)
        self.assertEqual(run.call_count, 1)


if __name__ == '__main__':
    unittest.main()
