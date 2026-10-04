#!/usr/bin/env python3
"""Separate owned no-port certificate lifecycle; never operate the main project."""
import json
import hashlib
import os
from pathlib import Path
import subprocess
import time

ROOT = Path('/Users/pawangupta/tunnex/tests/app-access-local')
CHILD = ROOT / '.runtime/aa8-cert'
PROJECT = 'tunnex-app-access-aa8-cert-1003'
IMAGE = 'tunnex-aa8-restore-proxy-qualification:local'
DOCKER = [str(ROOT / 'docker-local.sh')]
COMPOSE = DOCKER + ['compose', '--project-name', PROJECT, '--project-directory', str(CHILD), '-f', str(CHILD / 'compose.json')]

def call(args, expected=0):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=45)
    if result.returncode != expected:
        raise RuntimeError('isolated certificate operation failed')
    return result.stdout.strip()

def probe(mode, expected=0):
    return call(DOCKER + ['run', '--rm', '--pull', 'never', '--network', PROJECT+'_default',
        '--user', '10001', '--entrypoint', '/helper', '-v', str(CHILD/'certificate-helper')+':/helper:ro',
        '-v', PROJECT+'_proxy_secrets:/cert:ro', IMAGE, '-mode', mode, '-directory', '/cert'], expected)

def replace(script):
    call(DOCKER + ['run', '--rm', '--pull', 'never', '--network', 'none', '--user', '0',
        '--entrypoint', 'sh', '-v', PROJECT+'_proxy_secrets:/out', '-v', str(CHILD/'tls')+':/in:ro',
        IMAGE, '-c', script+'; chown -R 10001:10001 /out; chmod 600 /out/*'])

def main():
    if ROOT.resolve() != ROOT or not CHILD.is_dir():
        raise RuntimeError('owned checkout refused')
    name=PROJECT+'-app-proxy-1'
    item=json.loads(call(DOCKER+['inspect',name]))[0]
    labels=item['Config']['Labels']
    if labels.get('com.docker.compose.project')!=PROJECT or labels.get('com.docker.compose.project.working_dir')!=str(CHILD) or item['HostConfig'].get('PortBindings'):
        raise RuntimeError('isolated participant ownership refused')
    out={'project':PROJECT,'shipping_binary':True,'unsigned_local_image':True,'main_trust_modified':False,'phases':[],
         'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
         'helper_sha256':hashlib.sha256((CHILD/'certificate-helper').read_bytes()).hexdigest(),
         'image_id':item['Image']}
    def require(condition):
        if not condition:
            raise RuntimeError('certificate lifecycle expectation failed')
    def record(name,result):
        out['phases'].append({'phase':name,'result':result,'observed_at_unix':time.time()})
    try:
        require(probe('public')=='certificate_expired_refused')
        record('expired_public_leaf','strict certificate expiry refusal')
        result=probe('gateway',1)
        require('TLS peer refused' in result)
        record('expired_gateway_client','TLS peer refused expired child client; no HTTP response')
        replace('cp /in/renewed.pem /out/public.pem; cp /in/renewed-key.pem /out/public-key.pem')
        require(probe('public')=='certificate_expired_refused')
        record('replace_without_restart','process still serves old expired in-memory leaf')
        call(COMPOSE+['restart','--timeout','10','app-proxy'])
        require(probe('public')=='strict_tls_generic_403')
        record('restart_same_ca_renewed_public','strict TLS accepted; generic HTTP403, no positive authority claim')
        replace('cp /in/client-renewed.pem /out/client.pem; cp /in/client-renewed-key.pem /out/client-key.pem')
        require(probe('gateway')=='strict_tls_generic_403')
        record('renewed_gateway_client','same child CA accepted renewed client without server restart; genericHTTP403')
        call(['/private/tmp/aa8-certificate-helper','-mode','short','-directory',str(CHILD/'tls')])
        replace('cp /in/short.pem /out/public.pem; cp /in/short-key.pem /out/public-key.pem')
        call(COMPOSE+['restart','--timeout','10','app-proxy'])
        require(probe('public')=='strict_tls_generic_403')
        record('short_leaf_before_expiry','strict TLS accepted')
        deadline=time.monotonic()+40
        while time.monotonic()<deadline:
            if probe('public')=='certificate_expired_refused':
                record('short_leaf_after_actual_expiry','strict TLS rejected unchanged running server leaf')
                break
            time.sleep(1)
        else:
            raise RuntimeError('certificate expiry transition not observed')
        out['passed']=True
    finally:
        call(COMPOSE+['stop','--timeout','10','app-proxy'])
        out['final_child_proxy_stopped']=True
        out['limitations']=['No positive published authority/session or production enrolled identity rotation',
            'Fresh test CA only; no global trust or main identity reuse',
            'Cached unsigned local image; not production signed artifact or HA qualification',
            'Client credential callback reload seam exercised by independent fresh probes; not a live enrolled-node renewal loop']
        file=CHILD/('evidence-'+str(time.time_ns())+'.json')
        with open(file,'x',opener=lambda p,f:os.open(p,f,0o600)) as stream:
            json.dump(out,stream,indent=2)
        print(json.dumps({'passed':out.get('passed',False),'evidence_file':str(file)}))

if __name__=='__main__':
    main()
