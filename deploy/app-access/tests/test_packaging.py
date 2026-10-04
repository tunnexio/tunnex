"""Local render-only contracts. Never deploys or reads real credential files."""
import pathlib
import subprocess
import unittest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[3]
BASE = ['--set', 'database.url=postgres://fixture/db', '--set', 'redis.url=redis://fixture/0', '--set', 'masterKey.existingSecret=fixture', '--set', 'appBaseURL=https://console.example.com']
ENABLED = ['--set', 'appAccess.enabled=true', '--set', 'appAccess.baseDomain=apps.example.net', '--set', 'appAccess.proxy.image=example/proxy@sha256:' + 'a'*64, '--set', 'appAccess.restore.existingClaim=restore', '--set', 'appAccess.proxy.credentialSecret=credential', '--set', 'appAccess.proxy.publicTLSSecret=public', '--set', 'appAccess.proxy.gatewayTLSSecret=gateway', '--set', 'appAccess.proxy.agentCASecret=ca']

def render(args):
    return subprocess.run(['helm','template','fixture',str(ROOT/'deploy/helm/tunnex-cp'),*BASE,*args], capture_output=True, text=True)

class Packaging(unittest.TestCase):
    def test_default_has_no_proxy(self):
        result=render([])
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertNotIn('name: app-proxy\n',result.stdout)
        self.assertNotIn('TUNNEX_APP_PROXY_AUTHORITY_ADDR',result.stdout)

    def test_opt_in_exact_private_composition(self):
        result=render(ENABLED)
        self.assertEqual(result.returncode,0,result.stderr)
        docs=[x for x in yaml.safe_load_all(result.stdout) if x]
        proxy=next(x for x in docs if x['kind']=='Deployment' and x['metadata']['name']=='app-proxy')
        spec=proxy['spec']['template']['spec']
        self.assertEqual(proxy['spec']['replicas'],1)
        self.assertEqual(spec['securityContext']['fsGroupChangePolicy'],'OnRootMismatch')
        self.assertEqual(spec['containers'][0]['volumeMounts'][-1]['subPath'],'app-restore')
        self.assertIn('chmod 0400',spec['initContainers'][0]['args'][0])
        services={x['metadata']['name']:x for x in docs if x['kind']=='Service'}
        self.assertEqual(services['app-authority']['spec']['type'],'ClusterIP')
        self.assertEqual([p['port'] for p in services['app-proxy']['spec']['ports']],[443])
        self.assertNotIn('operator',str(services))

    def test_missing_trust_mutable_image_and_ha_refused(self):
        for args in [['--set','appAccess.enabled=true'], ENABLED+['--set','appAccess.proxy.image=example/proxy:latest'], ENABLED+['--set','api.replicas=2']]:
            self.assertNotEqual(render(args).returncode,0)

    def test_compose_opt_in_and_retained_marker(self):
        doc=yaml.safe_load((ROOT/'deploy/app-access/compose.yml').read_text())
        proxy=doc['services']['app-proxy']
        self.assertEqual(proxy['profiles'],['app-access'])
        self.assertEqual(len(proxy['ports']),1)
        self.assertEqual(proxy['environment']['TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_URL'], '${TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_URL:-}')
        self.assertEqual(proxy['environment']['TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_SERVER_NAME'], '${TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_SERVER_NAME:-}')
        self.assertEqual(proxy['environment']['TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_CA_FILE'], '${TUNNEX_APP_PROXY_CONSOLE_UPSTREAM_CA_FILE:-}')
        self.assertIn('app_restore',doc['volumes'])
        for name in ['api','app-proxy']:
            self.assertIn('app_restore:/var/lib/tunnex/app-restore:ro',doc['services'][name]['volumes'])

if __name__=='__main__': unittest.main()
