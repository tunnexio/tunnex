#!/usr/bin/env python3
import subprocess,time,json,sys,os,uuid,http.cookiejar,urllib.request,urllib.parse,datetime
from pathlib import Path
# Explicit local lab only. Cookie is read privately and never printed.
base=os.environ['GCP_HA_API_BASE'].rstrip('/')
parsed=urllib.parse.urlsplit(base)
if parsed.scheme!='http' or parsed.hostname not in ['127.0.0.1','localhost'] or parsed.username or parsed.password:
 raise SystemExit('loopback control-plane lab required')
jar=http.cookiejar.MozillaCookieJar(os.environ['GCP_HA_COOKIE_FILE']);jar.load(ignore_discard=True,ignore_expires=True)
opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
def status_read():
 req=urllib.request.Request(base+'/ipsec/connections/'+CID+'/status')
 with opener.open(req,timeout=10) as response:return json.load(response)
receipt=Path(os.environ['GCP_HA_RECEIPT_DIR'])
if not receipt.is_dir():raise SystemExit('existing owned receipt directory required')
started=datetime.datetime.now(datetime.timezone.utc).isoformat()
PEER=os.environ['GCP_HA_PEER'];CLIENT=os.environ['GCP_HA_CLIENT'];CID=str(uuid.UUID(os.environ['GCP_HA_CONNECTION_ID']))
def run(args,text=None):
 r=subprocess.run(args,input=text,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
 if r.returncode:raise RuntimeError('owned operation refused')
 return r.stdout
owner=run(['docker','inspect',PEER,'--format','{{index .Config.Labels "tunnex.test.owner"}}']).strip()
if owner!='gcp-s2s-runtime':raise SystemExit('owned peer required')
action=sys.argv[1]
if action=='clear':
 run(['docker','exec',PEER,'nft','delete','table','inet','tunnex_ha_owned_fault']);print('Owned outer fault cleared')
else:
 addresses=['33.0.0.30'] if action=='one' else ['33.0.0.30','33.0.0.31'] if action=='both' else []
 if not addresses:raise SystemExit('explicit one/both/clear required')
 text='table inet tunnex_ha_owned_fault {\n chain ingress {\n type filter hook prerouting priority -400; policy accept;\n '+''.join('ip daddr '+a+' counter drop\n' for a in addresses)+'}\n chain egress {\n type filter hook postrouting priority 300; policy accept;\n '+''.join('ip saddr '+a+' counter drop\n' for a in addresses)+'}\n}\n'
 # The both transition changes only this dedicated owned fault table.
 if action=='both':run(['docker','exec',PEER,'nft','delete','table','inet','tunnex_ha_owned_fault'])
 run(['docker','exec','-i',PEER,'nft','-f','-'],text);print('Owned outer fault set',action)
for attempt in range(18):
 status=status_read()
 if 'bgp' not in status:
  time.sleep(2);continue
 states=[p['state'] for p in status['bgp']['peers']];routes=status['bgp']['routes']
 expected=(action=='one' and states[0]!='established' and states[1]=='established' and routes==[{'prefix':'10.74.0.0/24','slot':2}]) or (action=='both' and all(s!='established' for s in states) and not routes) or (action=='clear' and states==['established','established'] and len(routes)==1)
 if expected:
  (receipt/('fault-'+action+'-status.json')).write_text(json.dumps(status,indent=2)+'\n');print('HA convergence PASS',action,states,routes);break
 time.sleep(2)
else:raise SystemExit('HA convergence not confirmed within bounded observation')
r=subprocess.run(['docker','exec',CLIENT,'python3','-c','import urllib.request\ntry:\n r=urllib.request.urlopen("http://10.74.0.10:18080",timeout=3);print(r.read().decode().strip())\nexcept (TimeoutError,urllib.error.URLError):print("DENIED")'],text=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=8)
expected='DENIED' if action=='both' else 'GCP_HA_OWNED_MARKER'
if r.returncode or r.stdout.strip()!=expected:raise SystemExit('HA packet expectation not confirmed')
print('HA packet PASS',action,expected)

(receipt/('fault-'+action+'-receipt.json')).write_text(json.dumps({'action':action,'started_at':started,'completed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'connection_id':CID,'peer':PEER,'status':'PASS','packet':expected,'scope':'owned local HA emulator underlay fault; no cloud proof'},indent=2)+'\n')
