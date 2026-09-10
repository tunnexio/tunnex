import json
import unittest
from isolation import ensure_absent, verify_container, verify_volume

class IsolationTest(unittest.TestCase):
    def test_exact_name_foreign_or_unlabelled_collision_refuses_before_creation(self):
        for kind in ['container', 'volume', 'network']:
            calls=[]
            def docker(*args):
                calls.append(args)
                self.assertEqual(args[1], 'ls', 'mutation before collision refusal')
                return 'tunnexfixture_resource\n' if args[0] == kind else ''
            with self.assertRaises(RuntimeError):
                ensure_absent(docker, {k: ['tunnexfixture_resource'] for k in ['container','volume','network']})
            self.assertTrue(calls)

    def test_foreign_volume_cannot_pass_owned_container_check(self):
        def docker(*args):
            if args[:2] == ('volume','inspect'):
                return json.dumps([{'Name':'tunnexfixture_pg','Labels':{'com.docker.compose.project':'foreign'}}])
            return json.dumps([{'Config':{'Labels':{'com.docker.compose.project':'tunnexfixture'}},'NetworkSettings':{'Networks':{'tunnexfixture_engine':{}}},'Mounts':[{'Type':'volume','Destination':'/var/lib/postgresql/data','Name':'tunnexfixture_pg'}]}])
        with self.assertRaises(RuntimeError):
            verify_container(docker,'immutable-id','tunnexfixture','tunnexfixture_engine',{'/var/lib/postgresql/data':'tunnexfixture_pg'})

    def test_unexpected_mount_source_refuses_before_start(self):
        def docker(*args):
            self.assertEqual(args[0],'inspect')
            return json.dumps([{'Config':{'Labels':{'com.docker.compose.project':'tunnexfixture'}},'NetworkSettings':{'Networks':{'tunnexfixture_engine':{}}},'Mounts':[{'Type':'volume','Destination':'/var/lib/postgresql/data','Name':'foreign_pg'}]}])
        with self.assertRaises(RuntimeError):
            verify_container(docker,'immutable-id','tunnexfixture','tunnexfixture_engine',{'/var/lib/postgresql/data':'tunnexfixture_pg'})

if __name__ == '__main__':
    unittest.main()
