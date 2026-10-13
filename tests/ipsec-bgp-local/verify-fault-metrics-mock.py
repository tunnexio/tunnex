import tempfile,pathlib,json,subprocess
with tempfile.TemporaryDirectory()as t:
 p=pathlib.Path(t);pin={'root_reviewed':True,'gateway_id':'c'*64,'namespace':'net:[99]','node_sha256':'a'*64,'image':'sha256:'+('b'*64),'cert_sha256':'d'*64,'maximum_verified_clock_skew_seconds':0.1,'clock_skew_evidence_sha256':'e'*64};identity={k:pin[k]for k in ['namespace','node_sha256']};identity['container']=pin['gateway_id'];worker={'exit':0,'stdout':pin['gateway_id']+' '+pin['image']+' 123 2026-10-08T00:00:00Z\n'+pin['namespace']+'\n'+pin['node_sha256']+'  /proc/1/exe\n'+pin['cert_sha256']+'  /state/cert.pem\n'}
 rows=[{'index':i,'wall':i,'started':i,'ended':i+0.2,'success':i not in [3,4,5],'confirmed_timeout':i in [3,4,5],'exit':28 if i in [3,4,5]else 0,'stdout':'HTTP=000\n'if i in [3,4,5]else 'bodyHTTP=200\n','target_matches':0 if i in [3,4,5]else 1}for i in range(8)]
 for r in rows:r['nonce']=format(r['index'],'064x')
 rows[3].update(exit=7,confirmed_timeout=False)
 measurement={'measurement':{'rows':rows,'client_result_path':'/home/ubuntu/mock-client-receipt'},'before':{'exit':0,'stdout':pin['gateway_id']+' true\n'},'after':{'exit':0,'stdout':pin['gateway_id']+' true\n'}}
 files={'fixture-control':{'control':{'exit':0,'stdout':'body'},'fixtures':[{'nonce':r['nonce'],'body':'body'}for r in rows]},'pins':pin,'worker-before':worker,'worker-after':worker,'measurement':measurement,'fault-begin':{'at':'1970-01-01T00:00:02Z','identity':identity},'fault-restore':{'at':'1970-01-01T00:00:05Z','identity':identity,'foreign_rules_preserved':True,'owned_fault_rules_absent':True}}
 argv=['python3','tests/ipsec-bgp-local/vgw-traffic-fault-metrics.py']
 for key,obj in files.items():f=p/(key+'.json');f.write_text(json.dumps(obj));argv+=['--'+key,str(f)]
 output=p/'result.json';subprocess.run(argv+['--output',str(output)],check=True);r=json.loads(output.read_text());assert r['first_failed_request']==3 and r['first_failure_class']=='curl_connect_failure' and r['fault_connect_failures']==1 and r['fault_timeouts']==1
 assert r['survivor_failover_censored'] and r['first_healthy_during_full_fault']is None and r['fault_sustained_successes']==0 and r['first_healthy_after_restore']==6 and not r['steady_baseline_qualified']
 print('OFFLINE CAUSAL PASS: curl7 then only-after-restore success does not qualify failover; short baseline unqualified')
