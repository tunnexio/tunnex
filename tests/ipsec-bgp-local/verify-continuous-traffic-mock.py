import json,pathlib,tempfile,sys,subprocess,types,ast
source=pathlib.Path('tests/ipsec-bgp-local/vgw-continuous-traffic-v3.py').read_text()
with tempfile.TemporaryDirectory()as temp:
 source=source.replace("base=pathlib.Path('/home/ubuntu/tunnex-bgp-vgw-eic-20261008')",'base=pathlib.Path('+repr(temp)+')').replace("assert pathlib.Path('/home/ubuntu').is_dir() and base.is_dir()","assert base.is_dir()")
 ns={'__name__':'__main__'};calls=[]
 def mock(cmd,**kwargs):
  assert cmd[0]=='ssh';command=cmd[-1];calls.append(command)
  if 'systemctl' in command:
   out=json.dumps({'pid':1353,'start':'123','exe':'/usr/bin/python3.12','cmdline':'\x00'.join(['/usr/bin/python3','-m','http.server','8080','--bind','0.0.0.0','']),'cwd':'/opt/tunnex-bgp-lab'},sort_keys=True)
  elif 'sha256sum /proc/1/exe' in command:out='stable worker identity\n'
  elif 'base64.b64decode' in command:
   if cmd[-2]=='ubuntu@10.85.1.10':out=json.dumps({'fixtures':len(ns['fixtures'])})
   else:
    rows=[]
    for i,r in enumerate(ns['fixtures']):
     success=i not in [3,4];rows.append({'index':i,'nonce':r['nonce'],'started':float(i),'ended':i+(.1 if success else 2),'wall':100+i,'schedule_lag':0,'exit':0 if success else 28,'stdout':r['body']+'HTTP=200\n'if success else 'HTTP=000\n','stderr':'','success':success})
    out=json.dumps({'client_result_path':'mock-only','rows':rows})
  elif command.startswith('curl'):out=ns['fixtures'][0]['body']
  elif 'swanctl' in command:out=ns['a'].gateway_container+' true\n{}\nmock CHILD metadata\n'
  elif 'journalctl' in command:out='\n'.join('10.84.2.10 - "GET '+r['uri']+' HTTP/1.1" 200'for i,r in enumerate(ns['fixtures'])if i not in [3,4])
  else:raise AssertionError(command)
  return types.SimpleNamespace(returncode=0,stdout=out.encode(),stderr=b'')
 old=subprocess.run;argv=sys.argv;subprocess.run=mock;sys.argv=['v3','--execute','--samples','10','--gateway-container','a'*64]
 try:exec(compile(source,'offline-mock','exec'),ns)
 finally:subprocess.run=old;sys.argv=argv
 result=json.loads(next(pathlib.Path(temp).glob('*-result.json')).read_text());assert result['baseline_successes']==3 and result['maximum_consecutive_timeouts']==2 and len(result['recovered_windows'])==1 and not result['right_censored'] and result['uncertain_samples']==[]
 assert len(calls)==10
 for key in ['fixture_code','client_code']:compile(ns[key],key,'exec')
 print('OFFLINE_FULL_FLOW_PASS: 10 mocked SSH calls, baseline3 timeout2 recovery1, embedded snippets compile; no real subprocess/network')
