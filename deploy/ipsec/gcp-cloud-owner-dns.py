#!/usr/bin/env python3
"""One-shot normal owner resolver replacement. No grants/resources/licence writes."""
import argparse,copy,datetime,importlib.util,json,os,pathlib,stat,sys,urllib.error,urllib.request
spec=importlib.util.spec_from_file_location('private',pathlib.Path(__file__).with_name('gcp-private-api-runner.py'))
private=importlib.util.module_from_spec(spec);spec.loader.exec_module(private)
SITE='01a12500-95ae-7728-b901-54f20df98cc1';NODE='01a125fa-32f3-762b-83d4-d368447bf6ed'
FIELDS=('name','provider_hint','zone_suffixes','endpoints','ipsec_path')
PROFILES={'ha':('gcp-ha-bgp-ipv4-v1','ha.gcp.s2s-qa.tunnex.app','10.80.0.2',2),'classic':('gcp-classic-static-ipv4-v1','classic.gcp.s2s-qa.tunnex.app','10.81.0.2',1)}
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'))
def build(baseline,manifest):
    existing=[] if baseline is None else baseline['profiles']
    if any(p.get('legacy_default') for p in existing):raise ValueError('legacy baseline cannot be losslessly roundtripped')
    profiles=[{k:copy.deepcopy(p[k]) for k in FIELDS if k in p} for p in existing]
    if not 1<=len(manifest)<=2 or len({p['profile'] for p in manifest})!=len(manifest):raise ValueError('unique scoped profiles required')
    for item in manifest:
        profile,zone,ip,count=PROFILES[item['profile']];private.nonzero_id(item['connection_id'])
        if type(item['configuration_revision']) is not int or item['configuration_revision']<1:raise ValueError('actual configuration revision required')
        name='GCP cloud QA '+item['profile']
        if any(p['name']==name or any(s==zone or s.endswith('.'+zone) or zone.endswith('.'+s) for s in p['zone_suffixes']) for p in profiles):raise ValueError('existing profile/suffix collision; no replay')
        profiles.append({'name':name,'provider_hint':'google_cloud','zone_suffixes':[zone],'endpoints':[{'address':ip,'port':53,'transport':t} for t in ('tcp','udp')],'ipsec_path':{'connection_id':item['connection_id'],'configuration_revision':item['configuration_revision'],'source_address':'10.70.0.2'}})
    if len(profiles)>16:raise ValueError('profile limit')
    return {'profiles':profiles}
def verify_live(item,connection,configuration,status,eligibility,now):
    profile,zone,ip,count=PROFILES[item['profile']]
    if connection.get('site_id')!=SITE or connection.get('gateway_node_id')!=NODE or connection.get('desired_intent')!='enabled' or connection.get('application_state')!='applied' or connection.get('deleted_at') is not None:raise ValueError('actual enabled applied binding required')
    if configuration.get('profile_id')!=profile or configuration.get('configuration_revision')!=item['configuration_revision']:raise ValueError('current configuration revision required')
    gates=['gcp_ha','bgp'] if item['profile']=='ha' else ['gcp_classic']
    if eligibility.get('eligible') is not True or any(eligibility.get(k,{}).get('eligible') is not True for k in gates):raise ValueError('fresh native eligibility required')
    observed=datetime.datetime.fromisoformat(status['observed_at'].replace('Z','+00:00'))
    if not 0<=(now-observed).total_seconds()<=90 or len(status['tunnels'])!=count or any(t['status']!='up' for t in status['tunnels']):raise ValueError('fresh actual tunnel status required')
    if item['profile']=='ha':
        bgp=status.get('bgp',{})
        if bgp.get('version')!=1 or len(bgp.get('peers',[]))!=2 or any(p.get('state')!='established' for p in bgp['peers']) or not any(r.get('prefix')=='10.80.0.0/24' for r in bgp.get('routes',[])):raise ValueError('actual HA BGP route required')
def main():
    p=argparse.ArgumentParser();p.add_argument('--cookie-file',required=True);p.add_argument('--manifest',required=True);p.add_argument('--receipt',required=True);p.add_argument('--apply',action='store_true');a=p.parse_args()
    cookie=private.cookie_header(private.private_read(a.cookie_file));m=json.loads(private.private_read(a.manifest),object_pairs_hook=private.unique)
    directory=os.lstat(pathlib.Path(a.receipt).parent)
    if not stat.S_ISDIR(directory.st_mode) or directory.st_uid!=os.getuid() or stat.S_IMODE(directory.st_mode)!=0o700:raise ValueError('private receipt directory required')
    fd=os.open(a.receipt,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as receipt:
        def record(value):receipt.write(json.dumps(value)+'\n');receipt.flush();os.fsync(receipt.fileno())
        record({'started':True,'apply':a.apply,'scope':'normal resolver API only; local baseline check is not atomic CAS'})
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args,**kwargs):return None
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        def request(path,method='GET',body=None,missing=False):
            r=urllib.request.Request('http://127.0.0.1:38083/api/v1'+path,method=method,data=None if body is None else json.dumps(body).encode(),headers={'Cookie':cookie,'X-Tunnex-CSRF':'1','Content-Type':'application/json'})
            try:
                with opener.open(r,timeout=15) as response:
                    raw=response.read(128*1024+1)
                    if len(raw)>128*1024:raise ValueError('bounded response required')
                    return json.loads(raw,object_pairs_hook=private.unique)
            except urllib.error.HTTPError as e:
                if missing and e.code==404:return None
                raise ValueError('normal API refused') from None
        licence=request('/license');assert licence['state']=='valid' and 'fqdn_resources' in licence['features']
        prefix='/organizations/'+private.ORG
        assert request(prefix+'/fqdn-resources/setting')['enabled']
        path=prefix+'/fqdn-resolver-contexts/'+SITE+'/'+NODE
        before=request(path,missing=True);body=build(before,m['profiles'])
        def live():
            e=request(prefix+'/ipsec/eligibility?site_id='+SITE+'&gateway_node_id='+NODE)
            for item in m['profiles']:
                c=prefix+'/ipsec/connections/'+item['connection_id']
                verify_live(item,request(c),request(c+'/configuration'),request(c+'/status'),e,datetime.datetime.now(datetime.timezone.utc))
        live();record({'baseline':before,'prepared':body,'atomic_cas':False})
        if a.apply:
            if canonical(request(path,missing=True))!=canonical(before):raise ValueError('baseline changed; no write')
            live();result=request(path,'PUT',body);record({'write_accepted':True,'version':result.get('version')})
            after=request(path)
            actual=[{k:p[k] for k in FIELDS if k in p} for p in after['profiles']]
            if canonical(actual)!=canonical(body['profiles']):raise ValueError('saved profile readback mismatch; no retry')
            record({'verified':True,'version':after.get('version')})
        record({'completed':True})
if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt):print('Owned DNS action refused; inspect private key-free partial receipt. No automatic retry.',file=sys.stderr);sys.exit(1)
