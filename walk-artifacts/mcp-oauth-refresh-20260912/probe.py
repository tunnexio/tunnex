import json,datetime,urllib.request,urllib.error
url='http://127.0.0.1:17100/mcp'
for ident,method,params in [(1,'initialize',{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'refresh-walk','version':'1'}}),(2,'tools/list',{})]:
 body=json.dumps({'jsonrpc':'2.0','id':ident,'method':method,'params':params}).encode()
 req=urllib.request.Request(url,data=body,headers={'Content-Type':'application/json','User-Agent':'Go-http-client/1.1','Accept':'application/json, text/event-stream','MCP-Protocol-Version':'2025-03-26'})
 try:
  with urllib.request.urlopen(req,timeout=25) as r: status=r.status; raw=r.read().decode()
 except urllib.error.HTTPError as e: status=e.code; raw=e.read().decode()
 try:
  payload=json.loads(raw)
 except ValueError:
  data=[line[5:].strip() for line in raw.splitlines() if line.startswith('data:')]
  payload=json.loads(data[-1]) if data else {}
 result=payload.get('result',{})
 print(json.dumps({'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),'method':method,'http':status,'error':payload.get('error'),'server':result.get('serverInfo'),'tools_count':len(result.get('tools',[])),'isError':result.get('isError')}))
