if not __debug__:
 raise RuntimeError('Qualification requires Python assertions enabled')
import urllib.request,urllib.error,http.cookiejar,json,re,os,time,base64,uuid,sys
base='http://cp-api:8080';jar=http.cookiejar.MozillaCookieJar('/tmp/cookies.txt')
try:jar.load(ignore_discard=True,ignore_expires=True)
except FileNotFoundError:pass
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(jar))
def request(method,path,body=None,want=200,bearer=None):
 headers={'Content-Type':'application/json','X-Tunnex-CSRF':'walk','Origin':base}
 if bearer:headers['Authorization']='Bearer '+bearer
 r=urllib.request.Request(base+path,data=json.dumps(body).encode() if body is not None else None,headers=headers,method=method)
 client=urllib.request.build_opener(urllib.request.ProxyHandler({})) if bearer else opener
 try:res=client.open(r,timeout=30);status=res.status;raw=res.read()
 except urllib.error.HTTPError as e:status=e.code;raw=e.read()
 if status!=want:
  try:code=json.loads(raw).get('error',{}).get('code')
  except:code='non-json'
  raise AssertionError('%s %s returned %s expected %s code=%s'%(method,path,status,want,code))
 jar.save(ignore_discard=True,ignore_expires=True);os.chmod('/tmp/cookies.txt',0o600)
 try:decoded=json.loads(raw)
 except ValueError:
  if path=='/ai/v1/chat/completions' and want==200 and not (body or {}).get('stream'):
   raise AssertionError('successful nonstream inference returned invalid JSON')
  return raw
 if path=='/ai/v1/chat/completions' and want==200 and not (body or {}).get('stream'):
  assert not decoded.get('error') and decoded['choices'][0]['message']['content']=='PRIVATE_RESPONSE_LINUX_WALK'
 return decoded

def save(s):
 with open('/tmp/walk-state.json','w') as f:json.dump(s,f)
 os.chmod('/tmp/walk-state.json',0o600)
if sys.argv[1]=='human':
 raw=open('/tmp/bootstrap-private.log').read();password=re.search(r'^  password  (.+)$',raw,re.M).group(1)
 request('POST','/api/v1/auth/login',{'email':'admin@tunnex.local','password':password})
 request('POST','/api/v1/auth/password',{'current_password':password,'new_password':'Local-Fixture-Only-'+uuid.uuid4().hex},want=204)
 org=request('POST','/api/v1/organizations',{'name':'AI installed fixture','slug':'ai-installed-fixture'},want=201)
 s={'org':org['id']};save(s);print('PASS actual bootstrap admin login and required password rotation; organization='+s['org'])
if sys.argv[1]=='enroll':
 s=json.load(open('/tmp/walk-state.json'));root='/api/v1/organizations/'+s['org'];s['agents']=[]
 for n in [31,32]:
  bootstrap=request('POST',root+'/agents/bootstrap-token',{'name':'installed-'+str(n),'gateway_id':s['node']},want=201)
  agent=request('POST','/api/v1/agent/bootstrap',{'bootstrap_token':bootstrap['bootstrap_token'],'public_key':base64.b64encode(bytes([n])*32).decode()})
  s['agents'].append({'id':agent['device']['id'],'runtime':agent['runtime_credential']})
 save(s);print('PASS canonical HTTP bootstrap-token issuance and agent enrollment twice under real human session')
 request('PUT',root+'/agent-policy-template-settings',{'enabled':True})
 group=request('POST',root+'/agent-groups',{'name':'installed-team'},want=201);s['team']=group['id'];save(s)
 for agent in s['agents']:request('POST',root+'/agent-groups/'+s['team']+'/members',{'device_id':agent['id']},want=204)
 print('PASS canonical group opt-in, creation and memberships')

if sys.argv[1]=='policy':
 s=json.load(open('/tmp/walk-state.json'));root='/api/v1/organizations/'+s['org']+'/ai-gateway'
 setting=request('GET',root);assert setting['enabled']==False and setting['available']==True
 request('POST','/api/v1/agent/runtime/ai-credential',want=401,bearer=s['agents'][0]['runtime'])
 request('PUT',root,{'enabled':True})
 request('POST','/api/v1/agent/runtime/ai-credential',want=403,bearer=s['agents'][0]['runtime'])
 request('PUT',root+'/teams/'+s['team'],{'models':['openrouter/openai/gpt-4o-mini'],'key_ids':['openrouter-primary'],'expected_revision':0})
 for agent in s['agents']:
  applied=request('PUT',root+'/agents/'+agent['id'],{'team_id':s['team'],'enabled':True,'models_override':[],'expected_revision':0})
  assert applied['status']=='applied'
  credential=request('POST','/api/v1/agent/runtime/ai-credential',want=201,bearer=agent['runtime'])
  assert credential['audience']=='tunnex-ai';agent['token']=credential['token']
 save(s)
 body={'model':'openrouter/openai/gpt-4o-mini','messages':[{'role':'user','content':'PRIVATE_PROMPT_LINUX_WALK'}],'max_tokens':16}
 for agent in s['agents']:
  out=request('POST','/ai/v1/chat/completions',body,bearer=agent['token']);assert out['choices'][0]['message']['content']=='PRIVATE_RESPONSE_LINUX_WALK'
 request('POST','/ai/v1/chat/completions',{**body,'model':'openrouter/forbidden'},want=403,bearer=s['agents'][0]['token'])
 for _ in range(100):
  usage=request('GET',root+'/usage?team_id='+s['team'])
  if usage['total_tokens']==14:break
  time.sleep(.1)
 else:raise AssertionError('scoped usage did not converge')
 print('PASS Community defaultoff and unapplied refusal; canonical team+assignment apply; scoped credentials and2synthetic completions; forbidden model403;14tokens scoped public usage')
 request('POST','/api/v1/organizations/'+s['org']+'/devices/'+s['agents'][0]['id']+'/revoke',want=204)
 request('POST','/ai/v1/chat/completions',body,want=401,bearer=s['agents'][0]['token'])
 out=request('POST','/ai/v1/chat/completions',body,bearer=s['agents'][1]['token']);assert out['choices'][0]['message']['content']=='PRIVATE_RESPONSE_LINUX_WALK'
 print('PASS canonical device revocation refused existing AI bearer401 while independent healthy identity remained200')
if sys.argv[1]=='restart':
 s=json.load(open('/tmp/walk-state.json'));root='/api/v1/organizations/'+s['org']+'/ai-gateway'
 assert request('GET',root)['enabled']==True
 body={'model':'openrouter/openai/gpt-4o-mini','messages':[{'role':'user','content':'PRIVATE_PROMPT_LINUX_WALK'}],'max_tokens':16}
 request('POST','/ai/v1/chat/completions',body,want=401,bearer=s['agents'][0]['token'])
 request('POST','/api/v1/agent/runtime/ai-credential',want=401,bearer=s['agents'][0]['runtime'])
 healthy=request('POST','/api/v1/agent/runtime/ai-credential',want=201,bearer=s['agents'][1]['runtime'])
 out=request('POST','/ai/v1/chat/completions',body,bearer=healthy['token']);assert out['choices'][0]['message']['content']=='PRIVATE_RESPONSE_LINUX_WALK'
 print('PASS actual API process restart retained human Redis session, revoked identity refusal and healthy runtime credential exchange/inference')

def strict_stream(raw):
 text=finish=terminal=False
 frames=raw.decode().replace('\r\n','\n').split('\n\n')
 for i,frame in enumerate(frames):
  lines=frame.split('\n');assert 'event: error' not in lines
  data='\n'.join(line[5:].strip() for line in lines if line.startswith('data:'))
  if not data:continue
  assert i<len(frames)-1 and not terminal,'truncated or post-terminal frame'
  if data=='[DONE]':assert text and finish;terminal=True;continue
  event=json.loads(data);assert not event.get('error')
  for choice in event.get('choices',[]):
   text |= bool(choice.get('delta',{}).get('content'))
   finish |= bool(choice.get('finish_reason'))
 assert terminal

if sys.argv[1]=='extended':
 s=json.load(open('/tmp/walk-state.json'));orgroot='/api/v1/organizations/'+s['org'];root=orgroot+'/ai-gateway'
 a=s['agents'][1];a['token']=request('POST','/api/v1/agent/runtime/ai-credential',want=201,bearer=a['runtime'])['token']
 bootstrap=request('POST',orgroot+'/agents/bootstrap-token',{'name':'installed-teamB','gateway_id':s['node']},want=201)
 enrolled=request('POST','/api/v1/agent/bootstrap',{'bootstrap_token':bootstrap['bootstrap_token'],'public_key':base64.b64encode(bytes([33])*32).decode()})
 b={'id':enrolled['device']['id'],'runtime':enrolled['runtime_credential']}
 team=request('POST',orgroot+'/agent-groups',{'name':'installed-teamB'},want=201)['id']
 request('POST',orgroot+'/agent-groups/'+team+'/members',{'device_id':b['id']},want=204)
 request('PUT',root+'/teams/'+team,{'models':['openrouter/openai/gpt-4o'],'key_ids':['openrouter-primary'],'expected_revision':0})
 applied=request('PUT',root+'/agents/'+b['id'],{'team_id':team,'enabled':True,'models_override':[],'expected_revision':0});assert applied['status']=='applied'
 b['token']=request('POST','/api/v1/agent/runtime/ai-credential',want=201,bearer=b['runtime'])['token']
 body={'model':'openrouter/openai/gpt-4o-mini','messages':[{'role':'user','content':'PRIVATE_PROMPT_LINUX_WALK'}],'max_tokens':16}
 arrivals=lambda:len(open('/arrivals').readlines())
 before=arrivals()
 request('POST','/ai/v1/chat/completions',{**body,'model':'openrouter/openai/gpt-4o'},want=403,bearer=a['token'])
 request('POST','/ai/v1/chat/completions',body,want=403,bearer=b['token']);assert arrivals()==before
 stream=request('POST','/ai/v1/chat/completions',{**body,'model':'openrouter/openai/gpt-4o','stream':True},bearer=b['token']);strict_stream(stream)
 print('PASS distinct-team model isolation denies before provider; real installed SSE has complete text/finish/terminal frames and no errors')
 password=json.load(open('/tmp/engine-auth.json'))['password']
 auth='Basic '+base64.b64encode(('fixture-admin:'+password).encode()).decode()
 req=urllib.request.Request('http://bifrost:8080/api/models/details?provider=openrouter&query=openai%2Fgpt-4o-mini&limit=100&offset=0',headers={'Authorization':auth})
 with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=5) as res:catalog=json.load(res)
 prices=[r for r in catalog['models'] if r.get('name')=='openai/gpt-4o-mini' and r.get('provider')=='openrouter']
 known=len(prices)==1 and prices[0].get('input_cost_per_token') is not None and prices[0].get('output_cost_per_token') is not None and not prices[0].get('pricing_override_ids') and not prices[0].get('overridden_pricing')
 print('Exact native pricing known='+str(known))
 request('PUT',root+'/teams/'+s['team'],{'models':['openrouter/openai/gpt-4o-mini'],'key_ids':['openrouter-primary'],'daily_cost_limit':0.000000000001,'expected_revision':1})
 applied=request('POST',root+'/agents/'+a['id']+'/reconcile')
 assert applied['status']=='applied' and applied['applied_revision']==applied['revision'] and applied['applied_team_revision']==2
 if known:
  observed=request('GET',root+'/usage?team_id='+s['team'])
  assert observed['uncosted_requests']==0 and observed['total_cost']>=0.000000000001,'cannot qualify priced threshold without complete positive observed cost'
 before=arrivals();request('POST','/ai/v1/chat/completions',body,want=403,bearer=a['token']);assert arrivals()==before
 request('POST','/ai/v1/chat/completions',{**body,'model':'openrouter/openai/gpt-4o'},bearer=b['token'])
 print('PASS '+('observed priced soft threshold' if known else 'unknown-price monetary policy')+' refusal before provider while independent team allows')
 request('PUT',root,{'enabled':False});before=arrivals()
 request('POST','/ai/v1/chat/completions',{**body,'model':'openrouter/openai/gpt-4o'},want=401,bearer=b['token']);assert arrivals()==before
 request('PUT',root,{'enabled':True})
 reapplied=request('POST',root+'/agents/'+b['id']+'/reconcile');assert reapplied['status']=='applied'
 request('POST','/ai/v1/chat/completions',{**body,'model':'openrouter/openai/gpt-4o'},bearer=b['token'])
 fresh=request('POST','/api/v1/agent/runtime/ai-credential',want=201,bearer=b['runtime'])['token']
 request('POST','/ai/v1/chat/completions',{**body,'model':'openrouter/openai/gpt-4o'},bearer=fresh)
 print('PASS organization disable refuses existing token; explicit reenable/reconcile permits still-valid token and fresh scoped exchange')
