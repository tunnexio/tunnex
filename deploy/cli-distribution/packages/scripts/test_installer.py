"""Refusal paths must not reach privilege or package commands."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'install.sh'


class InstallerTests(unittest.TestCase):
    def run_script(self, args=(), os_name='Linux', arch='x86_64', corrupt=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def stub(name, body):
                path = root / name
                path.write_text('#!/bin/sh\n' + body + '\n')
                path.chmod(0o755)
            stub('uname', f'if [ "$1" = -s ]; then echo {os_name}; else echo {arch}; fi')
            stub('id', 'echo 0')
            stub('apt-get', 'echo MUTATION; exit 99')
            stub('install', 'echo MUTATION; exit 99')
            stub('sudo', 'echo MUTATION; exit 99')
            if corrupt:
                stub('curl', 'while [ "$#" -gt 0 ]; do if [ "$1" = -o ]; then shift; echo corrupt > "$1"; exit; fi; shift; done; exit 1')
            result = subprocess.run(['sh', str(SCRIPT), *args], text=True, capture_output=True,
                                    env={**os.environ, 'PATH': directory + ':' + os.environ['PATH']})
            self.assertNotIn('MUTATION', result.stdout + result.stderr)
            return result

    def test_help_is_offline(self):
        self.assertEqual(self.run_script(('--help',)).returncode, 0)

    def test_bad_argument_refused(self):
        self.assertNotEqual(self.run_script(('--unknown',)).returncode, 0)

    def test_unsupported_os_refused(self):
        result = self.run_script(os_name='FreeBSD')
        self.assertIn('Unsupported OS', result.stderr)

    def test_unsupported_arch_refused(self):
        result = self.run_script(arch='riscv64')
        self.assertIn('Supported Linux architectures', result.stderr)

    @unittest.skipUnless(Path('/etc/os-release').exists(), 'Linux prerequisite')
    def test_corrupt_key_refused_before_repository_writes(self):
        result = self.run_script(corrupt=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('key checksum mismatch', result.stderr)


if __name__ == '__main__':
    unittest.main()
