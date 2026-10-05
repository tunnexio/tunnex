import importlib.util
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

source = Path(__file__).with_name("sandbox-entrypoint.py")
spec = importlib.util.spec_from_file_location("sandbox_entrypoint", source)
entrypoint = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entrypoint)


class EntrypointTest(unittest.TestCase):
    def run_entrypoint(self, uid=1001, directory_mode=stat.S_IFDIR | 0o755):
        parent = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=1001)
        directory = SimpleNamespace(st_mode=directory_mode, st_uid=1001)
        with (patch.object(entrypoint.sys, "argv", [str(source)]),
              patch.object(entrypoint.os, "geteuid", return_value=uid),
              patch.object(entrypoint.os, "getegid", return_value=1001),
              patch.object(entrypoint.os, "lstat", side_effect=[parent, directory]),
              patch.object(entrypoint.os, "mkdir"),
              patch.object(entrypoint.os, "execv") as execute):
            if uid != 1001 or not stat.S_ISDIR(directory_mode):
                with self.assertRaises(RuntimeError):
                    entrypoint.main()
                execute.assert_not_called()
            else:
                entrypoint.main()
                executable, argv = execute.call_args.args
                self.assertEqual(executable, "/usr/sbin/sshd")
                self.assertEqual(argv[0], executable)  # OpenSSH re-exec requires absolute argv0
                self.assertIn("-D", argv)

    def test_absolute_foreground_exec(self):
        self.run_entrypoint()

    def test_root_identity_refused(self):
        self.run_entrypoint(uid=0)

    def test_symlink_runtime_directory_refused(self):
        self.run_entrypoint(directory_mode=stat.S_IFLNK | 0o777)


if __name__ == "__main__":
    unittest.main()
