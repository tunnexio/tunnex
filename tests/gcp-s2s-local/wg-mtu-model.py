#!/usr/bin/env python3
"""Run mocked Linux owner code locally; no kernel/network/cloud operations.

The RED run uses the exact old backend from --baseline with the same new test
expectation. Overlay-only Linux sources allow macOS to execute command mocks.
"""
import argparse,json,os,pathlib,subprocess,tempfile

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--baseline',default='f9a7733cf3bf624c3a896a7d29a560ae51afda91')
    args=parser.parse_args()
    root=pathlib.Path(__file__).resolve().parents[2]
    package=root/'apps/node/internal/reconcile'
    with tempfile.TemporaryDirectory(prefix='tunnex-wg-mtu-model-') as directory:
        directory=pathlib.Path(directory)
        empty=directory/'empty.go';empty.write_text('package reconcile\n')
        replacements={str(package/'wgctrl_other.go'):str(empty)}
        for name in ('wgctrl_linux.go','wg_mtu_linux.go','wg_mtu_linux_test.go','wgctrl_linux_test.go','wgctrl_routes_test.go','wgctrl_readback_test.go'):
            output=directory/name
            output.write_text((package/name).read_text().replace('//go:build linux\n','',1))
            replacements[str(package/('mtu_model_'+name.replace('_linux','')))]=str(output)
        overlay=directory/'candidate.json';overlay.write_text(json.dumps({'Replace':replacements}))
        command=['go','test','-overlay',str(overlay),'./internal/reconcile','-count=1']
        green=subprocess.run(command,cwd=root/'apps/node',capture_output=True,text=True)
        if green.returncode:
            print(green.stdout+green.stderr);raise SystemExit('candidate model failed')
        old=directory/'old.go'
        old.write_text(subprocess.check_output(['git','show',args.baseline+':apps/node/internal/reconcile/wgctrl_linux.go'],cwd=root,text=True).replace('//go:build linux\n','',1))
        test=(package/'wg_mtu_linux_test.go').read_text()
        function=test[test.index('func TestConfigureApplies'):]
        function=function[:function.index('\n\tdrift = true')]
        function=function.replace(' || b.AppliedMTU() != x.want','').replace(', b.AppliedMTU()','').replace(' reported%d','')+'\n}\n'
        oldtest=directory/'old_test.go';oldtest.write_text('package reconcile\nimport("context";"fmt";"strings";"testing")\n'+function)
        redoverlay=directory/'red.json';redoverlay.write_text(json.dumps({'Replace':{str(package/'wgctrl_other.go'):str(empty),str(package/'mtu_model_old.go'):str(old),str(package/'mtu_model_old_test.go'):str(oldtest)}}))
        red=subprocess.run(['go','test','-overlay',str(redoverlay),'./internal/reconcile','-run','TestConfigureApplies','-count=1'],cwd=root/'apps/node',capture_output=True,text=True)
        if red.returncode==0 or 'physical1460 current1420' not in red.stdout:
            print(red.stdout+red.stderr);raise SystemExit('baseline did not fail the expected geometry')
        print(json.dumps({'baseline_red':True,'candidate_green':True,'kernel_wireguard_executed':False,'cloud_operations':0,'requested_mtu_unchanged':1420,'model_1460_effective':1380,'model_1500_effective':1420},sort_keys=True))
if __name__=='__main__':main()
