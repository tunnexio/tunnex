import json,urllib.request,urllib.parse,urllib.error,datetime
from pathlib import Path
endpoint='https://bindings.mcp.cloudflare.com/mcp'
state=json.loads(Path('/var/lib/tunnex-agent/runtime-state.json').read_text())
credential=Path('/etc/tunnex-agent/runtime-credential').read_text().strip()
url=state['server'].rstrip('/')+'/api/v1/agent/runtime/mcp-oauth-lease?'+urllib.parse.urlencode({'endpoint':endpoint})
try:
 req=urllib.request.Request(url,headers={'Authorization':'Bearer '+credential,'User-Agent':'Go-http-client/1.1'})
 with urllib.request.urlopen(req,timeout=25) as r: lease=json.load(r); status=r.status
 print(json.dumps({'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),'lease_http':status,'expires_at':lease.get('expires_at')}))
 for ident,method,params in [(1,'initialize',{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'refresh-walk','version':'1'}}),(2,'tools/list',{})]:
  req=urllib.request.Request(endpoint,data=json.dumps({'jsonrpc':'2.0','id':ident,'method':method,'params':params}).encode(),headers={'Authorization':'Bearer '+lease['access_token'],'User-Agent':'Go-http-client/1.1','Content-Type':'application/json','Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2025-03-26'})
  with urllib.request.urlopen(req,timeout=25) as r: raw=r.read().decode(); status=r.status
  try: obj=json.loads(raw)
  except ValueError: obj=json.loads([l[5:].strip() for l in raw.splitlines() if l.startswith('data:')][-1])
  result=obj.get('result',{})
  print(json.dumps({'method':method,'http':status,'has_error':bool(obj.get('error')),'tools_count':len(result.get('tools',[])),'server':result.get('serverInfo')}))
except urllib.error.HTTPError as e:
 print(json.dumps({'http_error':e.code})); raise SystemExit(1)
