import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('private_ui', Path(__file__).with_name('deploy-private-ui.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class OwnedLayoutTest(unittest.TestCase):
    def row(self):
        return {'Id': 'owned-container', 'Name': '/' + m.NAME,
                'State': {'Running': True},
                'Config': {'Labels': {'tunnex.owner': m.OWNER}, 'User': '101:101',
                           'Entrypoint': ['nginx'], 'Cmd': ['-c', m.CONFIG_DEST, '-g', 'daemon off;']},
                'HostConfig': {'NetworkMode': 'host', 'CapDrop': ['ALL']}}

    def inspect(self, row):
        with patch.object(m.subprocess, 'run', return_value=SimpleNamespace(stdout=json.dumps([row]).encode())):
            return m.inspect()

    def test_exact_owned_custom_config_command(self):
        self.assertEqual(self.inspect(self.row())['Id'], 'owned-container')
        for field, value in [('Cmd', ['-c', '/etc/nginx/nginx.conf']), ('Entrypoint', ['sh']), ('User', '0')]:
            row = self.row()
            row['Config'][field] = value
            with self.assertRaises(ValueError):
                self.inspect(row)

    def test_wrong_owner_refused(self):
        row = self.row()
        row['Config']['Labels']['tunnex.owner'] = 'unrelated'
        with self.assertRaises(ValueError):
            self.inspect(row)


if __name__ == '__main__':
    unittest.main()
