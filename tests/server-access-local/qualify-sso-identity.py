#!/usr/bin/env python3
"""Owned signed-OIDC callback proof. Never prints cookies or transient SSO URLs."""
import argparse, http.cookiejar, json, re, urllib.parse, urllib.request, urllib.error
from pathlib import Path
API='http://127.0.0.1:18183'
LOGIN='http://127.0.0.1:15189'
ORG='01a109d9-382b-7bc1-82c9-2b0bf036139c'
EXPECTED='11111111-1111-4111-8111-111111111182'
class Identity:
 def __init__(self):
  self.jar=http.cookiejar.CookieJar()
  self.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
 def login(self,mode):
  with self.opener.open(LOGIN+'/api/v1/auth/sso/google/start?org=first-organization&next=%2Fbrowser-access%2Fterminal',timeout=8) as response:
   start=json.load(response)
  with self.opener.open(start['redirect_url'],timeout=8) as response:
   html=response.read().decode()
  values=dict(re.findall(r'name="(state|nonce|challenge)" value="([^"]+)"',html))
  assert len(values)==3,'Normal IdP form missing'
  values['mode']=mode
  request=urllib.request.Request('http://127.0.0.1:15187/approve',urllib.parse.urlencode(values).encode(),method='POST')
  with self.opener.open(request,timeout=8) as response:
   landing=response.url
   response.read()
  return landing
 def rpc(self,method,path,body=None):
  request=urllib.request.Request(API+path,None if body is None else json.dumps(body).encode(),headers={'Origin':API,'X-Tunnex-CSRF':'1','Content-Type':'application/json'},method=method)
  try:
   with self.opener.open(request,timeout=8) as response:
    raw=response.read();return response.status,json.loads(raw) if raw else {}
  except urllib.error.HTTPError as error:return error.code,json.load(error)
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--admission',action='store_true',help='Requires primary gateway capacity free; successful sessions immediately revoked');args=parser.parse_args()
 results=[]
 for mode in ['fresh','absent','stale','future','wrongnonce','wrongaudience','badsignature']:
  client=Identity();landing=client.login(mode)
  status,me=client.rpc('GET','/api/v1/auth/me')
  if mode in ['wrongnonce','wrongaudience','badsignature']:
   assert status==401,'Unverified OIDC identity reached authenticated session'
   assert urllib.parse.parse_qs(urllib.parse.urlsplit(landing).query).get('sso_error')==['sso_failed'],'Rejected token did not expose safe failure landing'
   results.append({'mode':mode,'verified_callback_rejected':True});continue
  assert status==200 and me['id']==EXPECTED,'SSO mapped to wrong member'
  item={'mode':mode,'normal_callback_session':True}
  if args.admission:
   status,workspace=client.rpc('GET','/api/v1/organizations/'+ORG+'/server-access')
   assert status==200
   server=next(v for v in workspace['servers'] if v['name']=='Local Linux fixture')
   status,session=client.rpc('POST','/api/v1/organizations/'+ORG+'/server-access/sessions',{'server_id':server['id'],'account':'fixture'})
   if mode=='fresh':
    assert status==200,'Fresh verified IdP MFA did not admit terminal'
    closed,_=client.rpc('DELETE','/api/v1/organizations/'+ORG+'/server-access/sessions/'+session['id']);assert closed==200
    item['fresh_sso_terminal_admitted']=True
   else:
    assert status==403 and session['error']['code']=='mfa_required','Unknown/stale/future MFA bypassed terminal admission'
    item['terminal_denied_mfa_required']=True
  client.rpc('POST','/api/v1/auth/logout',{})
  results.append(item)
 destination=Path(__file__).resolve().parent/'.runtime'/'sso-identity-results.json';destination.write_text(json.dumps(results,indent=2))
 print('Signed OIDC callback/session qualification PASS; '+('terminal MFA admission negatives verified' if args.admission else 'no terminal capacity consumed'))
if __name__=='__main__':main()
