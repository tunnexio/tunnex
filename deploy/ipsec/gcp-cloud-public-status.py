#!/usr/bin/env python3
"""One-shot key-free normal public API evidence collection; never mutate."""
import argparse
import datetime
import importlib.util
import json
import os
import pathlib
import stat
import sys
import urllib.request
import uuid

spec = importlib.util.spec_from_file_location('private_api', pathlib.Path(__file__).with_name('gcp-private-api-runner.py'))
private = importlib.util.module_from_spec(spec)
spec.loader.exec_module(private)


def selected(record, fields):
    return {k: record[k] for k in fields if k in record}


def project(connection, status):
    out = {'connection': selected(connection, ['id', 'site_id', 'gateway_node_id', 'desired_revision', 'desired_intent', 'cleanup_state', 'application_state', 'finalized_at']),
           'status': selected(status, ['observed_at', 'active_slot', 'selection_sequence', 'recovery_version'])}
    out['status']['tunnels'] = [selected(t, ['id', 'slot', 'selected', 'status']) for t in status.get('tunnels', [])]
    if isinstance(status.get('bgp'), dict):
        b = status['bgp']; out['status']['bgp'] = selected(b, ['version', 'sequence'])
        out['status']['bgp']['peers'] = [selected(t, ['slot', 'state', 'accepted_prefixes', 'installed_prefixes', 'rejected_prefixes']) for t in b.get('peers', [])]
        out['status']['bgp']['routes'] = [selected(t, ['slot', 'prefix']) for t in b.get('routes', [])]
    return out


def collect(cookie, connection_id):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):return None
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    base='http://127.0.0.1:38083/api/v1/organizations/'+private.ORG+'/ipsec/connections/'+connection_id
    def read(suffix):
        request=urllib.request.Request(base+suffix, headers={'Cookie':cookie})
        with opener.open(request,timeout=10) as response:
            raw=response.read(128*1024+1)
            if response.status!=200 or len(raw)>128*1024:raise ValueError('bounded public API refused')
            return json.loads(raw,object_pairs_hook=private.unique)
    before=read('');status=read('/status');after=read('')
    out=project(after,status)
    out['revision_stable_during_collection']=before.get('desired_revision')==after.get('desired_revision')
    out['collected_at_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    out['scope']='public API receipt only; native SA/route/guard and payload evidence collected separately'
    return out


def main():
    p=argparse.ArgumentParser();p.add_argument('--cookie-file',required=True);p.add_argument('--connection-id',required=True);p.add_argument('--out',required=True);a=p.parse_args()
    private.nonzero_id(a.connection_id)
    target=pathlib.Path(a.out);s=os.lstat(target.parent)
    if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('owned private evidence directory required')
    data=collect(private.cookie_header(private.private_read(a.cookie_file)),str(uuid.UUID(a.connection_id)))
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:json.dump(data,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
    print(json.dumps({'collected':True,'revision_stable':data['revision_stable_during_collection']}))

if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt):print('Public GCP collection refused; private responses withheld.',file=sys.stderr);sys.exit(1)
