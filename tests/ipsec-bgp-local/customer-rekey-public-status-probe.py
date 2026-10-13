"""Source-only owned13 normal-cookie GET status probe; never prints credentials/cookies."""
import argparse,hashlib,http.cookiejar,json,os,pathlib,stat,urllib.request
ORG='01a1161a-906c-7074-9e80-dd318fc2c1eb'
IDS=['9d9f98e2-cd96-456d-b020-a5a79f688040','8856b1c4-ae98-418b-bfd5-664cde5210c3']
def main():
 p=argparse.ArgumentParser();p.add_argument('--execute',action='store_true');a=p.parse_args()
 if not a.execute:print('{"source_only":true}');return
 path=pathlib.Path('/home/ubuntu/tunnex-bgp-lab/normal-api/credentials.json');s=path.lstat();assert os.getuid()==0 and s.st_uid==0 and stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o600 and not path.is_symlink()
 c=json.loads(path.read_bytes());base=c['base_url'];assert base in ['http://127.0.0.1:18383','http://127.0.0.1:8080','http://127.0.0.1:8081']
 client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
 def api(path,body=None):
  req=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),headers={'Content-Type':'application/json','Origin':base,'X-Tunnex-CSRF':'1'})
  with client.open(req,timeout=5)as response:
   raw=response.read(262145);assert len(raw)<=262144;return json.loads(raw)
 login=api('/api/v1/auth/login',{'email':c['email'],'password':c['password']});assert not login.get('mfa_required')
 result=[]
 for cid in IDS:
  root='/api/v1/organizations/'+ORG+'/ipsec/connections/'+cid
  provider=api(root);assert provider['id']==cid and provider['gateway_node_id']=='01a1161a-9529-7478-b62f-a27f25222aa0'
  result.append({'provider_id':cid,'desired_revision':provider['desired_revision'],'desired_intent':provider['desired_intent'],'status':api(root+'/status')})
 print(json.dumps({'read_only':True,'organization_id':ORG,'connections':result}))
if __name__=='__main__':main()
