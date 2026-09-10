#!/usr/bin/env python3
"""Zero-spend, isolated Linux-image provider secret rotation. Retains all resources."""
import base64,json,os,pathlib,subprocess,tempfile,time,urllib.request,urllib.error
if not __debug__:
    raise RuntimeError("refuse python -O: safety checks require normal execution")
PROJECT='tunnexairotate0907'
LABEL='com.tunnex.ai-proof'
CONTEXT='colima-tunnex-sso-review'
IMAGE='maximhq/bifrost:v2.0.0@sha256:cf71be9fad4e0749b6e26cbb774c687413dad9a0970b83f4e1dadb6f503ea208'
ROOT=pathlib.Path(__file__).resolve().parents[3]
OUT=pathlib.Path('/private/tmp/tunnexairotate0907-results')
NET=PROJECT+'_default'
VOLUMES=[PROJECT+'_config',PROJECT+'_logs']
NAMES=[PROJECT+'-provider-1',PROJECT+'-engine-before-1',PROJECT+'-engine-after-1']
BASE=['docker','--context',CONTEXT]
def run(*args):
    return subprocess.check_output(BASE+list(args),text=True,stderr=subprocess.PIPE).strip()
def check(ok,message):
    if not ok:raise RuntimeError(message)
def labels():return ['--label','com.docker.compose.project='+PROJECT,'--label',LABEL+'=rotation']
def inspect(kind,name):return json.loads(run(kind,'inspect',name))[0]
def owned(kind,name):
    obj=inspect(kind,name);lab=obj.get('Labels',obj.get('Config',{}).get('Labels',{}))
    check(lab.get('com.docker.compose.project')==PROJECT and lab.get(LABEL)=='rotation','resource ownership mismatch')
    return obj
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def request(url,body=None,auth=None,method=None):
    data=None if body is None else json.dumps(body).encode()
    headers={'Content-Type':'application/json'}
    if auth:headers.update(auth)
    req=urllib.request.Request(url,data=data,headers=headers,method=method)
    try:
        with opener.open(req,timeout=15) as res:return res.status,json.load(res)
    except urllib.error.HTTPError as error:return error.code,{}
def baseurl(cid,port):
    obj=owned('container',cid)
    check(NET in obj['NetworkSettings']['Networks'],'container network mismatch')
    binding=obj['NetworkSettings']['Ports'][str(port)+'/tcp'][0]
    check(binding['HostIp']=='127.0.0.1','fixture listener not loopback')
    return 'http://127.0.0.1:'+binding['HostPort']
def ready(url):
    for _ in range(150):
        try:
            if request(url)[0]==200:return
        except Exception:pass
        time.sleep(.2)
    raise RuntimeError('fixture readiness failed')
# Every name and project ownership is checked before the first mutation.
for kind,names in [('network',[NET]),('volume',VOLUMES),('container',NAMES)]:
    for name in names:
        p=subprocess.run(BASE+[kind,'inspect',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        check(p.returncode!=0,'refuse existing '+kind+' '+name)
check(not run('ps','-aq','--filter','label=com.docker.compose.project='+PROJECT),'project already owns containers')
engine_image=inspect('image',IMAGE)
go_image=inspect('image','golang:1.25.13-alpine')
check(engine_image['Architecture']==go_image['Architecture'],'fixture/engine architecture mismatch')
check(not OUT.exists(),'proof output already exists')
print('COMPOSE_PROJECT_NAME='+PROJECT+' context='+CONTEXT+' network='+NET+' checked absent planned names',flush=True)
created=[]
try:
    run('network','create',*labels(),NET);owned('network',NET)
    for name in VOLUMES:run('volume','create',*labels(),name);owned('volume',name)
    with tempfile.TemporaryDirectory(prefix=PROJECT+'-') as scratch:
        scratch=pathlib.Path(scratch)
        env=dict(os.environ,GOOS='linux',GOARCH=engine_image['Architecture'],CGO_ENABLED='0',GOWORK='off',GOFLAGS='-mod=readonly',GOCACHE='/private/tmp/tunnex-airotate-go-cache')
        subprocess.run(['go','build','-o',str(scratch/'provider'),str(pathlib.Path(__file__).with_name('provider.go'))],env=env,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        provider=run('create',*labels(),'--name',NAMES[0],'--network',NET,'--network-alias','provider','--publish','127.0.0.1::8081',go_image['Id'],'/tmp/provider')
        created.append(provider);owned('container',provider)
        run('cp',str(scratch/'provider'),provider+':/tmp/provider');run('start',provider)
        provider_url=baseurl(provider,8081);ready(provider_url+'/control')
        config=json.loads((ROOT/'deploy/ai-gateway/config.json').read_text())
        config['providers']['openrouter']['network_config'].update(base_url='http://provider:8081',allow_private_network=True,max_retries=0)
        config['governance']['virtual_keys']=[{'id':'rotation-agent','name':'rotation-agent','value':'sk-bf-rotation-agent-fixture','is_active':True,'provider_configs':[{'provider':'openrouter','allowed_models':['openai/gpt-4o-mini'],'key_ids':['openrouter-primary'],'weight':1}]}]
        (scratch/'config.json').write_text(json.dumps(config))
        admin={'Authorization':'Basic '+base64.b64encode(b'rotation-admin:rotation-admin-fixture').decode()}
        def engine(name,secret,copy_config):
            for v in VOLUMES:owned('volume',v)
            cid=run('create',*labels(),'--name',name,'--network',NET,'--publish','127.0.0.1::8080','--mount','type=volume,src='+VOLUMES[0]+',dst=/app/data','--mount','type=volume,src='+VOLUMES[1]+',dst=/app/data/logs','--env','BIFROST_ADMIN_USER=rotation-admin','--env','BIFROST_ADMIN_PASSWORD=rotation-admin-fixture','--env','OPENROUTER_API_KEY='+secret,'--env','BIFROST_ENCRYPTION_KEY=rotation-durable-encryption-fixture','--env','LOG_LEVEL=error',IMAGE)
            created.append(cid);obj=owned('container',cid)
            mounts={v['Destination']:v.get('Name') for v in obj['Mounts']}
            check(mounts.get('/app/data')==VOLUMES[0] and mounts.get('/app/data/logs')==VOLUMES[1],'volume mount ownership mismatch')
            if copy_config:run('cp',str(scratch/'config.json'),cid+':/app/data/config.json')
            run('start',cid);url=baseurl(cid,8080);ready(url+'/health');return cid,url
        def infer(url):
            status,result=request(url+'/v1/chat/completions',{'model':'openrouter/openai/gpt-4o-mini','messages':[{'role':'user','content':'Reply OK'}],'max_tokens':16},{'X-Bf-Vk':'sk-bf-rotation-agent-fixture'})
            check(status==200 and result.get('choices',[{}])[0].get('message',{}).get('content')=='OK','engine inference failed (response withheld)')
        def stats(url,count):
            for _ in range(150):
                status,result=request(url+'/api/logs/stats?virtual_key_ids=rotation-agent',auth=admin)
                if status==200 and result.get('total_requests')==count and result.get('total_tokens')==count*5:return result
                time.sleep(.2)
            raise RuntimeError('scoped accounting history did not persist')
        before,before_url=engine(NAMES[1],'fixture-provider-before',True)
        infer(before_url);stats(before_url,1)
        status,key_before=request(before_url+'/api/governance/virtual-keys/rotation-agent',auth=admin)
        check(status==200,'initial scoped key readback failed')
        owned('container',before);run('stop',before)
        request(provider_url+'/control',{'secret':'fixture-provider-after'},method='PUT')
        status,_=request(provider_url+'/v1/chat/completions',{}, {'Authorization':'Bearer fixture-provider-before'})
        check(status==401,'old provider secret still accepted')
        after,after_url=engine(NAMES[2],'fixture-provider-after',False)
        infer(after_url);usage=stats(after_url,2)
        status,key_after=request(after_url+'/api/governance/virtual-keys/rotation-agent',auth=admin)
        check(status==200 and key_before==key_after,'native scoped key identity/config changed during provider rotation')
        status,counters=request(provider_url+'/control')
        check(status==200 and counters=={'accepted':2,'rejected':1},'provider arrival/secret checks failed')
        OUT.mkdir(mode=0o700)
        result={'project':PROJECT,'image':IMAGE,'architecture':engine_image['Architecture'],'provider_accepted':2,'old_secret_rejected':1,'scoped_key_unchanged':True,'same_config_and_log_volumes':True,'total_requests':usage['total_requests'],'total_tokens':usage['total_tokens'],'provider_spend':0,'containers':created,'volumes':VOLUMES,'network':NET}
        (OUT/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        print('PASS: provider secret rotated; old rejected; same scoped key/config/log history retained; 2 actual authenticated provider arrivals; zero spend',flush=True)
finally:
    for cid in reversed(created):
        owned('container',cid)
        run('stop',cid)
    print('Stopped only owned container IDs; retained owned containers, volumes and network',flush=True)
