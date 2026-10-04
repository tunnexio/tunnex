"""Execute only the extracted read-only guard with a fake Docker CLI."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]

class InstalledGuard(unittest.TestCase):
    def run_guard(self,script,rows='',failure='',project='owned'):
        source=(ROOT/'deploy'/script).read_text()
        guard=source.split('# BEGIN APP ACCESS REINSTALL GUARD\n',1)[1].split('# END APP ACCESS REINSTALL GUARD',1)[0]
        with tempfile.TemporaryDirectory() as directory:
            file=Path(directory)/'guard.sh'
            cli='docker_cli' if script=='install.sh' else 'docker'
            fake=f'''{cli}() {{
case "$1" in
ps) [ "$2" = -a ] && [ "$3" = --filter ] || return 1; case "$4" in label=com.docker.compose.project=owned|label=com.docker.compose.project.working_dir=/owned) ;; *) return 1 ;; esac; [ "{failure}" != ps ] || return 1; printf '%s\\n' '{"fixture" if rows else ""}' ;;
inspect) [ "{failure}" != inspect ] || return 1; printf '%s\\n' '{rows}' ;;
esac
}}
'''
            file.write_text(fake+guard+f'\nrefuse_existing_app_access \"{project}\" /owned\n')
            return subprocess.run(['sh',str(file)],capture_output=True,text=True)
    def test_default_legacy_unchanged(self):
        for script in ['install.sh','upgrade.sh']:
            for row in ['', 'owned|/owned|api|']:
                self.assertEqual(self.run_guard(script,row).returncode,0)
    def test_stopped_proxy_and_api_marker_refuse(self):
        for script in ['install.sh','upgrade.sh']:
            for row in ['owned|/owned|app-proxy|','owned|/owned|api|marker']:
                result=self.run_guard(script,row)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('separately reviewed opt-in',result.stderr)
    def test_foreign_project_or_checkout_does_not_block(self):
        for script in ['install.sh','upgrade.sh']:
            for row in ['foreign|/owned|app-proxy|','owned|/foreign|api|marker']:
                self.assertEqual(self.run_guard(script,row).returncode,0)
    def test_inspection_failure_refuses_without_secret_output(self):
        for script in ['install.sh','upgrade.sh']:
            for failure in ['ps','inspect']:
                result=self.run_guard(script,'owned|/owned|api|',failure)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('inspection failed',result.stderr)
                self.assertNotIn('Config.Env',(ROOT/'deploy'/script).read_text().split('# BEGIN APP ACCESS REINSTALL GUARD',1)[1].split('# END APP ACCESS REINSTALL GUARD',1)[0])
    def test_malformed_inspection_refuses(self):
        for script in ['install.sh','upgrade.sh']:
            result=self.run_guard(script,'malformed-inspection')
            self.assertNotEqual(result.returncode,0)
            self.assertIn('inspection failed',result.stderr)
    def test_top_level_name_without_saved_project_detected(self):
        for script in ['install.sh','upgrade.sh']:
            result=self.run_guard(script,'tunnex|/owned|app-proxy|',project='')
            self.assertNotEqual(result.returncode,0)
            self.assertIn('separately reviewed opt-in',result.stderr)
            self.assertEqual(self.run_guard(script,'tunnex|/owned|api|',project='').returncode,0)
            self.assertEqual(self.run_guard(script,'tunnex|/foreign|app-proxy|',project='').returncode,0)
    def test_upgrade_uses_first_compose_file_directory(self):
        source=(ROOT/'deploy/upgrade.sh').read_text()
        self.assertIn('$(dirname -- "$COMPOSE")',source)
        self.assertNotIn('_aa_guard_project=',source)
    def test_custom_compose_path_refused_before_managed_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve()
            install=root/'installation';install.mkdir()
            outside=root/'composition';outside.mkdir()
            binary=root/'bin';binary.mkdir()
            compose=outside/'custom.yml';compose.write_text('name: tunnex\nservices: {}\n')
            envfile=install/'.env';envfile.write_text('TUNNEX_RELEASE_PUBLIC_KEY=fixture-public-key\n')
            docker=binary/'docker'
            docker.write_text('#!/bin/sh\ncase "$1" in\nps) printf fixture ;;\ninspect) printf "tunnex|'+str(outside)+'|app-proxy|" ;;\nesac\n')
            docker.chmod(0o755)
            env=os.environ.copy()
            env.update(PATH=str(binary)+':'+env['PATH'],TUNNEX_DIR=str(install),TUNNEX_COMPOSE_FILE=str(compose))
            env.pop('COMPOSE_PROJECT_NAME',None);env.pop('TUNNEX_COMPOSE_PROJECT',None)
            result=subprocess.run(['sh',str(ROOT/'deploy/upgrade.sh'),'--apply'],env=env,capture_output=True,text=True)
            self.assertEqual(result.returncode,13,result.stderr)
            self.assertIn('separately reviewed opt-in',result.stderr)
            self.assertEqual(compose.read_text(),'name: tunnex\nservices: {}\n')
            self.assertFalse((install/'backups').exists())
    def test_invocation_precedes_replacement_and_stop(self):
        upgrade=(ROOT/'deploy/upgrade.sh').read_text()
        self.assertLess(upgrade.index('refuse_existing_app_access "$PROJECT"'),upgrade.index('TMPDIR=$(mktemp'))
        install=(ROOT/'deploy/install.sh').read_text()
        self.assertLess(install.index('refuse_existing_app_access "$INSTALL_COMPOSE_PROJECT"'),install.index('STAGE_DIR=$(mktemp'))

if __name__=='__main__':unittest.main()
