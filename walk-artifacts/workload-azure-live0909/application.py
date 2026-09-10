import json, os, sys, time, urllib.request, urllib.error, fcntl
from pathlib import Path
MODEL = 'custom-fd5043c6-3863-4073-80be-f4af3bceefc2/gpt-5'
BASE = os.environ['OPENAI_BASE_URL'].rstrip('/')
LOCAL_CREDENTIAL = os.environ['OPENAI_API_KEY']

def request(path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, headers={
        'Authorization': 'Bearer ' + LOCAL_CREDENTIAL, 'Content-Type':'application/json'
    })
    try:
        with urllib.request.urlopen(req, timeout=40) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        payload = error.read()
        try: value=json.loads(payload)
        except ValueError: value={}
        return error.code, {'error': {'code': value.get('error',{}).get('code','unspecified')}}

def models():
    status, result = request('/models')
    assert status == 200, ('model_list_http',status)
    assert MODEL in [m.get('id') for m in result.get('data',[])], 'Azure model missing from workload list'
    print(json.dumps({'check':'authorized_model_list','http_status':status}),flush=True)

def chat():
    counter = Path(__file__).with_name('paid-call-budget')
    fd = os.open(counter, os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(fd, 'r+') as budget:
        fcntl.flock(budget.fileno(), fcntl.LOCK_EX)
        count = int(budget.read() or '0')
        assert count < 3, 'Approved three-call limit reached'
        budget.seek(0)
        budget.write(str(count + 1))
        budget.truncate()
        budget.flush()
        os.fsync(budget.fileno())
    status, result=request('/chat/completions',{
        'model':MODEL, 'messages':[{'role':'user','content':'Reply with exactly: tunnex-workload-live-ok'}],
        'max_tokens':256, 'stream':False
    })
    if status!=200:
        print(json.dumps({'check':'azure_inference','http_status':status,'error_code':result.get('error',{}).get('code')}),flush=True)
        raise SystemExit(1)
    content=result.get('choices',[{}])[0].get('message',{}).get('content','')
    print(json.dumps({'check':'azure_inference','http_status':status,'model':result.get('model'),
        'expected_marker_received':'tunnex-workload-live-ok' in str(content),
        'usage':result.get('usage',{}),'response_id':result.get('id')}),flush=True)
    assert content, 'Empty Azure inference response'

mode=sys.argv[1] if len(sys.argv)>1 else 'once'
models()
if mode=='once': chat()
elif mode=='renewal':
    chat()
    started=time.monotonic()
    while time.monotonic()-started<330:
        time.sleep(20)
        models()
    print(json.dumps({'check':'access_beyond_original_five_minute_token','elapsed_seconds':int(time.monotonic()-started)}),flush=True)
elif mode=='deny':
    status,result=request('/chat/completions',{'model':'openrouter/openai/gpt-4o','messages':[{'role':'user','content':'Hello'}]})
    assert status==403, ('ungranted_model_status',status)
    print(json.dumps({'check':'ungranted_model_refusal','http_status':status}),flush=True)
elif mode=='list': pass
else: raise SystemExit('Unknown test mode')
