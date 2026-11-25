"""Execute only the extracted read-only App Access guard/classifier with a fake Docker CLI."""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]

class InstalledGuard(unittest.TestCase):
    """install.sh reinstall keeps refusing an existing App Access composition."""
    def run_guard(self,rows='',failure='',project='owned'):
        source=(ROOT/'deploy/install.sh').read_text()
        guard=source.split('# BEGIN APP ACCESS REINSTALL GUARD\n',1)[1].split('# END APP ACCESS REINSTALL GUARD',1)[0]
        with tempfile.TemporaryDirectory() as directory:
            file=Path(directory)/'guard.sh'
            fake=f'''docker_cli() {{
case "$1" in
ps) [ "$2" = -a ] && [ "$3" = --filter ] || return 1; case "$4" in label=com.docker.compose.project=owned|label=com.docker.compose.project.working_dir=/owned) ;; *) return 1 ;; esac; [ "{failure}" != ps ] || return 1; printf '%s\\n' '{"fixture" if rows else ""}' ;;
inspect) [ "{failure}" != inspect ] || return 1; printf '%s\\n' '{rows}' ;;
esac
}}
'''
            file.write_text(fake+guard+f'\nrefuse_existing_app_access \"{project}\" /owned\n')
            return subprocess.run(['sh',str(file)],capture_output=True,text=True)
    def test_default_legacy_unchanged(self):
        for row in ['', 'owned|/owned|api|']:
            self.assertEqual(self.run_guard(row).returncode,0)
    def test_stopped_proxy_and_api_marker_refuse(self):
        for row in ['owned|/owned|app-proxy|','owned|/owned|api|marker']:
            result=self.run_guard(row)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('separately reviewed opt-in',result.stderr)
    def test_foreign_project_or_checkout_does_not_block(self):
        for row in ['foreign|/owned|app-proxy|','owned|/foreign|api|marker']:
            self.assertEqual(self.run_guard(row).returncode,0)
    def test_inspection_failure_refuses_without_secret_output(self):
        for failure in ['ps','inspect']:
            result=self.run_guard('owned|/owned|api|',failure)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('inspection failed',result.stderr)
    def test_malformed_inspection_refuses(self):
        result=self.run_guard('malformed-inspection')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('inspection failed',result.stderr)
    def test_top_level_name_without_saved_project_detected(self):
        result=self.run_guard('tunnex|/owned|app-proxy|',project='')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('separately reviewed opt-in',result.stderr)
        self.assertEqual(self.run_guard('tunnex|/owned|api|',project='').returncode,0)
        self.assertEqual(self.run_guard('tunnex|/foreign|app-proxy|',project='').returncode,0)
    def test_invocation_precedes_replacement(self):
        install=(ROOT/'deploy/install.sh').read_text()
        self.assertLess(install.index('refuse_existing_app_access "$INSTALL_COMPOSE_PROJECT"'),install.index('STAGE_DIR=$(mktemp'))


class UpgradeClassifier(unittest.TestCase):
    """upgrade.sh classifies (labels/mounts/ports only); admission decides."""
    SCRIPT=(ROOT/'deploy/upgrade.sh').read_text()
    BLOCK=SCRIPT.split('# BEGIN APP ACCESS COMPOSITION CLASSIFIER\n',1)[1].split('# END APP ACCESS COMPOSITION CLASSIFIER',1)[0]
    def classify(self,rows,failure='',project='owned'):
        with tempfile.TemporaryDirectory() as directory:
            fixtures=Path(directory)
            for index,row in enumerate(rows):(fixtures/str(index)).write_text(row+'\n')
            ids=' '.join(str(i) for i in range(len(rows)))
            fake=f'''docker() {{
case "$1" in
ps) [ "{failure}" != ps ] || return 1; case "$4" in label=com.docker.compose.project=owned|label=com.docker.compose.project.working_dir=/owned) printf '%s\\n' {ids} ;; *) return 1 ;; esac ;;
inspect) [ "{failure}" != inspect ] || return 1; for last in "$@"; do :; done; cat "{directory}/$last" ;;
esac
}}
'''
            file=fixtures/'classify.sh'
            file.write_text(fake+self.BLOCK+f'classify_existing_app_access "{project}" /owned || exit $?\n'
                            'printf "%s|%s|%s|%s|%s|%s|%s|%s\\n" "$AA_API_COUNT" "$AA_PROXY_COUNT" "$AA_PROJECT_FOUND" "$AA_API_MARKER" "$AA_PROXY_SECRETS" "$AA_PROXY_PORTS" "$AA_CONFIG_FILES" "$AA_CONFIG_CONFLICT"\n')
            return subprocess.run(['sh',str(file)],capture_output=True,text=True)
    # Row shapes observed from a real Docker/Compose v5 inspect of this template.
    API='owned|/owned|api|volume:owned_app_restore;||8443/tcp=:8443;|/owned/tunnex.yml,/owned/app-access.yml|False'
    PROXY='owned|/owned|app-proxy|volume:owned_app_restore;|/srv/s;|8443/tcp=127.0.0.1:443;|/owned/tunnex.yml,/owned/app-access.yml|False'
    def test_local_sharing_overlay_is_not_app_access_composition(self):
        # LS-UX-1 D.2: the managed Local Sharing overlay is stripped from the
        # App Access view; its proxy is never counted as an App Access proxy.
        ls=',/owned/local-sharing.yml'
        result=self.classify([self.API, 'owned|/owned|beam-proxy|volume:owned_app_restore;|/srv/b;|8443/tcp=10.0.0.3:443;|/owned/tunnex.yml,/owned/app-access.yml'+ls+'|False',
                              self.API.replace('app-access.yml|','app-access.yml'+ls+'|')])
        self.assertEqual(result.returncode,0,result.stderr)
        fields=result.stdout.strip().split('|')
        self.assertEqual(fields[1],'0')
        self.assertEqual(fields[6],'/owned/tunnex.yml,/owned/app-access.yml')
        self.assertEqual(fields[7],'false')
    def test_plain_install_has_no_participants(self):
        result=self.classify(['owned|/owned|api|||8443/tcp=:8443;|/owned/tunnex.yml|False','owned|/owned|postgres||||/owned/tunnex.yml|False'])
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(result.stdout.startswith('0|0||'))
    def test_participants_identity_reported(self):
        result=self.classify([self.API,self.PROXY])
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.strip(),'1|1|owned|volume:owned_app_restore;|/srv/s;|8443/tcp=127.0.0.1:443;|/owned/tunnex.yml,/owned/app-access.yml|false')
    def test_oneoff_helpers_and_foreign_participants_ignored(self):
        rows=[self.API,self.PROXY,self.API[:-len('False')]+'True','foreign|/owned|app-proxy|x|||y|','owned|/foreign|api|x|||y|']
        result=self.classify(rows)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(result.stdout.startswith('1|1|'))
    def test_multiple_and_conflicting_participants_reported(self):
        result=self.classify([self.API,self.API.replace('app-access.yml','other.yml')])
        self.assertTrue(result.stdout.startswith('2|0|'))
        self.assertTrue(result.stdout.strip().endswith('|true'))
    def test_api_and_proxy_file_split_is_reported_not_a_conflict(self):
        # AA-EN-1: the caller admits only the hash-bound adopted case.
        result=self.classify([self.API,self.PROXY.replace('app-access.yml','app-access.yml,/owned/demo.yml')])
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(result.stdout.strip().endswith('|/owned/tunnex.yml,/owned/app-access.yml|false'))
    def test_inspection_failure_and_malformed_rows_refuse(self):
        for failure in ['ps','inspect']:
            result=self.classify([self.API],failure)
            self.assertNotEqual(result.returncode,0);self.assertIn('inspection failed',result.stderr)
        for row in ['malformed','owned|/owned|api|',self.API+'|extra']:
            result=self.classify([row])
            self.assertNotEqual(result.returncode,0);self.assertIn('inspection failed',result.stderr)
    def test_never_reads_container_environment(self):
        self.assertNotIn('Config.Env',self.BLOCK)
        self.assertNotIn('.Env',self.BLOCK)
    def test_admission_precedes_temporary_state_and_mutation(self):
        self.assertLess(self.SCRIPT.index('admit_app_access "$_aa_upgrade_directory"'),self.SCRIPT.index('TMPDIR=$(mktemp'))
        # UPG-2 U2: the installed helper hands off to the target release's
        # script before any admission guard, so no old guard can trap a host.
        self.assertLess(self.SCRIPT.index('# BEGIN UPG-2 TARGET HAND-OFF'),self.SCRIPT.index('admit_app_access "$_aa_upgrade_directory"'))
        self.assertIn('$(dirname -- "$COMPOSE")',self.SCRIPT)
        self.assertNotIn('separately reviewed opt-in',self.SCRIPT)
    def test_custom_compose_path_proxy_without_barrier_refused_before_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve()
            install=root/'installation';install.mkdir()
            outside=root/'composition';outside.mkdir()
            binary=root/'bin';binary.mkdir()
            compose=outside/'custom.yml';compose.write_text('name: tunnex\nservices: {}\n')
            envfile=install/'.env';envfile.write_text('TUNNEX_RELEASE_PUBLIC_KEY=fixture-public-key\n')
            docker=binary/'docker'
            docker.write_text('#!/bin/sh\ncase "$1" in\nps) printf fixture ;;\ninspect) printf "tunnex|'+str(outside)+'|app-proxy|volume:tunnex_app_restore;|/s;|8443/tcp=127.0.0.1:443;|'+str(compose)+','+str(outside)+'/aa.yml|" ;;\nesac\n')
            docker.chmod(0o755)
            env=os.environ.copy()
            env.update(PATH=str(binary)+':'+env['PATH'],TUNNEX_DIR=str(install),TUNNEX_COMPOSE_FILE=str(compose))
            # Run as the target of a UPG-2 hand-off: admission is the target's.
            host=root/'handoff'/'host'
            (host/'app-access').mkdir(parents=True);(host/'ai-gateway').mkdir();(host/'beam').mkdir()
            (host/'HOST_ABI').write_text((ROOT/'deploy/HOST_ABI').read_text())
            for name in re.search(r"^HOST_FILE_LIST='(.*)'$",self.SCRIPT,re.M).group(1).split():
                (host/name).write_bytes((ROOT/'deploy'/name).read_bytes())
            manifest=root/'handoff'/'release.json';manifest.write_text('{}\n')
            env.update(TUNNEX_UPGRADE_HANDOFF='1',TUNNEX_UPGRADE_HANDOFF_ABI='1',TUNNEX_UPGRADE_HANDOFF_DIR=str(root/'handoff'))
            env.pop('COMPOSE_PROJECT_NAME',None);env.pop('TUNNEX_COMPOSE_PROJECT',None)
            result=subprocess.run(['sh',str(ROOT/'deploy/upgrade.sh'),'--apply','--manifest',str(manifest)],env=env,capture_output=True,text=True)
            self.assertEqual(result.returncode,13,result.stderr)
            self.assertIn('does not mount the external restore barrier',result.stderr)
            self.assertIn('Nothing was changed',result.stderr)
            self.assertEqual(compose.read_text(),'name: tunnex\nservices: {}\n')
            self.assertFalse((install/'backups').exists())
            self.assertFalse((install/'app-access.yml').exists())


if __name__=='__main__':unittest.main()
