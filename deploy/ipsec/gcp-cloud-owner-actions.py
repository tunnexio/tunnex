#!/usr/bin/env python3
"""Explicit one-shot owned normal API actions; preparation does not execute writes."""
import argparse, importlib.util, json, os, pathlib, stat, sys, urllib.request
spec=importlib.util.spec_from_file_location('private',pathlib.Path(__file__).with_name('gcp-private-api-runner.py'))
private=importlib.util.module_from_spec(spec);spec.loader.exec_module(private)
SITE='01a12500-95ae-7728-b901-54f20df98cc1'
NODE='01a125fa-32f3-762b-83d4-d368447bf6ed'
BASE='http://127.0.0.1:38083/api/v1/organizations/'+private.ORG

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

def enable_preflight(connection,eligibility,revision,profile):
    if type(revision) is not int or revision<1:raise ValueError('positive revision required')
    if connection.get('site_id')!=SITE or connection.get('gateway_node_id')!=NODE or connection.get('desired_intent')!='disabled' or connection.get('desired_revision')!=revision or connection.get('deleted_at') is not None or connection.get('cleanup_state') not in ('not_required','retained_guard'):raise ValueError('current exact disabled object required')
    gates=['gcp_ha','bgp'] if profile=='ha' else ['gcp_classic']
    if eligibility.get('eligible') is not True or any(eligibility.get(k,{}).get('eligible') is not True for k in gates):raise ValueError('fresh qualification required')
    return {'If-Match':'"'+str(revision)+'"'},{'intent':'enabled'}

def main():
    p=argparse.ArgumentParser();p.add_argument('--cookie-file',required=True);p.add_argument('--action',choices=['enable','resource','grant'],required=True);p.add_argument('--profile',choices=['ha','classic'],required=True);p.add_argument('--connection-id');p.add_argument('--revision',type=int);p.add_argument('--resource-name');p.add_argument('--resource-id');p.add_argument('--receipt',required=True);a=p.parse_args()
    cookie=private.cookie_header(private.private_read(a.cookie_file))
    # Reserve evidence before any write. A failed/partial operation cannot silently replay.
    directory=os.lstat(pathlib.Path(a.receipt).parent)
    if not stat.S_ISDIR(directory.st_mode) or directory.st_uid!=os.getuid() or stat.S_IMODE(directory.st_mode)!=0o700:raise ValueError('owned private receipt directory required')
    fd=os.open(a.receipt,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as receipt:
        def record(data):receipt.write(json.dumps(data)+'\n');receipt.flush();os.fsync(receipt.fileno())
        record({'action':a.action,'profile':a.profile,'started':True,'scope':'normal owner API only; no native readiness claim'})
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        def request(path,method='GET',body=None,headers=None):
            h={'Cookie':cookie,'X-Tunnex-CSRF':'1','Content-Type':'application/json'};h.update(headers or {})
            r=urllib.request.Request(BASE+path,data=None if body is None else json.dumps(body).encode(),headers=h,method=method)
            with opener.open(r,timeout=15) as response:
                raw=response.read(128*1024+1)
                if len(raw)>128*1024:raise ValueError('bounded response required')
                return json.loads(raw,object_pairs_hook=private.unique)
        if a.action=='enable':
            private.nonzero_id(a.connection_id)
            c=request('/ipsec/connections/'+a.connection_id)
            config=request('/ipsec/connections/'+a.connection_id+'/configuration')
            expected='gcp-ha-bgp-ipv4-v1' if a.profile=='ha' else 'gcp-classic-static-ipv4-v1'
            if config.get('profile_id')!=expected or not config.get('configuration'):raise ValueError('exact live provider configuration required')
            e=request('/ipsec/eligibility?site_id='+SITE+'&gateway_node_id='+NODE)
            h,b=enable_preflight(c,e,a.revision,a.profile)
            result=request('/ipsec/connections/'+a.connection_id+'/intent','PUT',b,h)
            record({k:result[k] for k in ['id','desired_revision','desired_intent','application_state','cleanup_state'] if k in result})
        else:
            templates=pathlib.Path(__file__).parents[2]/'tests/gcp-s2s-local/GCP-CLOUD-KEYFREE-GRANT-TEMPLATES-20261010.json'
            items=json.loads(templates.read_text())['items']
            candidates=[i for i in items if i['profile']==a.profile and i['resource_body']['name']==a.resource_name]
            if len(candidates)!=1:raise ValueError('exact owned resource required')
            item=candidates[0]
            if a.action=='resource':
                if any(r.get('name')==a.resource_name for r in request('/resources')):raise ValueError('resource name already exists; no replay')
                result=request('/resources','POST',item['resource_body'])
            else:
                private.nonzero_id(a.resource_id)
                matches=[r for r in request('/resources') if r.get('id')==a.resource_id]
                if len(matches)!=1:raise ValueError('exact current resource required')
                current=matches[0]
                if any(current.get(k)!=v for k,v in item['resource_body'].items()):raise ValueError('exact returned resource required')
                body=dict(item['grant_body']);body['dst_resource_id']=a.resource_id
                result=request('/policies','POST',body)
            private.nonzero_id(result.get('id'));record({'created_id':result['id'],'resource_name':a.resource_name})
        record({'completed':True})
    print(json.dumps({'completed':True,'action':a.action}))

if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt):print('Owned GCP action refused; private API responses withheld. Inspect key-free partial receipt; do not replay.',file=sys.stderr);sys.exit(1)
