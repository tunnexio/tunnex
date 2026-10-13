#!/usr/bin/env python3
"""Private real API/managed VICI/route snapshots, never material or kernel keys."""
import argparse,datetime,http.cookiejar,json,os,pathlib,subprocess,urllib.request
os.umask(0o077);p=argparse.ArgumentParser();p.add_argument('name');a=p.parse_args();assert a.name.isalnum()or all(x.isalnum()or x=='-'for x in a.name)
r=pathlib.Path(__file__).resolve().parent;rt=r/'.runtime';c=json.loads((rt/'integrated-local-api.json').read_text());s=json.loads((rt/'integrated-local-api-state.json').read_text());top=json.loads((rt/'integrated-topology.json').read_text());b=c['base_url'];cl=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def api(path,body=None):
 with cl.open(urllib.request.Request(b+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json','Origin':b,'X-Tunnex-CSRF':'1'}),timeout=15)as f:return json.loads(f.read())
api('/api/v1/auth/login',{'email':c['email'],'password':c['password']});path='/api/v1/organizations/'+c['organization_id']+'/ipsec/connections/'+s['connection_id'];proof={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'connection':api(path),'status':api(path+'/status'),'namespaces':{},'routes':{},'sas':{}};d=[str(r/'docker-local.sh')]
for role,cid in [('gateway',top['gateway_id']),('peer',top['containers']['peer'])]:
 def out(*args):return subprocess.check_output(d+['exec',cid]+list(args),text=True)
 proof['namespaces'][role]=out('readlink','/proc/1/ns/net').strip();proof['routes'][role]=json.loads(out('ip','-j','-4','route','show','table','main'));proof['sas'][role]=out('env','STRONGSWAN_CONF=/run/tunnex-ipsec/strongswan.conf','/opt/tunnex-ipsec/sbin/swanctl','--list-sas','--uri','unix:///run/tunnex-ipsec/charon.vici')
(rt/('integrated-observation-'+a.name+'.json')).write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps({'at':proof['at'],'status':proof['status'],'remote_routes':[x for x in proof['routes']['gateway']if x['dst']=='10.20.0.0/24']},indent=2))
