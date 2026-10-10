#!/usr/bin/env python3
"""Client-only reviewed CAS/reset/public-serial recovery. Run on designated bastion."""
import argparse,base64,hashlib,json,os,pathlib,stat,subprocess,sys,time,urllib.request,uuid
PROJECT='project-0048836f-6ba1-4a14-8da';ZONE='asia-south2-b';NAME='tn-gcps2s-20261010-local-client';ID='4751969643435150303';IP='10.70.0.10'
BASE='https://compute.googleapis.com/compute/v1/projects/'+PROJECT
INSTANCE='/zones/'+ZONE+'/instances/'+NAME
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('duplicate JSON field')
        result[key]=value
    return result

def cas_body(expected,current,items):
    if current!=expected:raise ValueError('metadata changed before CAS')
    return {'fingerprint':current['fingerprint'],'items':items}

def serial_lines(carry,chunk):
    lines=(carry+chunk).split('\n');tail=lines.pop()
    if len(tail)>16384:raise ValueError('bounded serial marker framing required')
    return lines,tail

def parse_marker(line,attempt):
    marker=json.loads(line,object_pairs_hook=unique)
    if set(marker)!={'marker','instance_id','attempt','boot_id','public_key','fingerprint'} or marker['marker']!='TUNNEX_OWNED_PUBLIC_HOSTKEY_V1' or marker['instance_id']!=ID or marker['attempt']!=attempt:raise ValueError('exact authenticated marker required')
    uuid.UUID(marker['boot_id'])
    kind,encoded=marker['public_key'].split();raw=base64.b64decode(encoded,validate=True)
    if kind!='ssh-ed25519' or len(raw)!=51 or raw[:19]!=b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20':raise ValueError('exact public wire key required')
    fingerprint='SHA256:'+base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')
    if marker['fingerprint']!=fingerprint:raise ValueError('public fingerprint mismatch')
    return marker

def metadata_items(metadata):
    items=metadata.get('items',[])
    if not isinstance(items,list) or any(set(i)!={'key','value'} or not isinstance(i['key'],str) or not isinstance(i['value'],str) for i in items):raise ValueError('exact metadata items required')
    if len({i['key'] for i in items})!=len(items):raise ValueError('duplicate metadata key')
    return items

def startup(items,publisher,attempt):
    values={i['key']:i['value'] for i in items}
    if 'startup-script-url' in values or 'startup-script' not in values:raise ValueError('inline original startup script required')
    original=values['startup-script']
    if not original.startswith(('#!/bin/sh\n','#!/bin/bash\n','#!/usr/bin/env bash\n')):raise ValueError('reviewed shell fixture startup only')
    interpreter=['/bin/sh'] if original.startswith('#!/bin/sh\n') else ['/bin/bash'] if original.startswith('#!/bin/bash\n') else ['/usr/bin/env','bash']
    # Read preserved bytes through their declared interpreter; executable tmp mounts are unnecessary.
    driver="""import base64,os,pathlib,subprocess,tempfile
with tempfile.TemporaryDirectory(prefix='tnx-hostkey-',dir='/run') as directory:
 os.chmod(directory,0o700)
 original=pathlib.Path(directory)/'original';original.write_bytes(base64.b64decode(ORIGINAL));original.chmod(0o700)
 helper=pathlib.Path(directory)/'public-helper';helper.write_bytes(base64.b64decode(HELPER));helper.chmod(0o700)
 try:
  original_status=subprocess.run(INTERPRETER+[str(original)]).returncode
 except OSError:
  original_status=126
 publication=subprocess.run(['/usr/bin/python3',str(helper),INSTANCE_ID,ATTEMPT])
 raise SystemExit(original_status if original_status else publication.returncode)
"""
    driver=driver.replace('ORIGINAL',repr(base64.b64encode(original.encode()).decode())).replace('HELPER',repr(base64.b64encode(publisher).decode())).replace('INSTANCE_ID',repr(ID)).replace('ATTEMPT',repr(attempt)).replace('INTERPRETER',repr(interpreter))
    wrapped='#!/bin/bash\n/usr/bin/python3 - <<\'TUNNEX_PUBLIC_HOSTKEY_DRIVER\'\n'+driver+'TUNNEX_PUBLIC_HOSTKEY_DRIVER\n'
    return [{'key':i['key'],'value':wrapped if i['key']=='startup-script' else i['value']} for i in items]

def identity(instance):
    nic=instance['networkInterfaces'][0]
    if str(instance.get('id'))!=ID or instance.get('name')!=NAME or nic.get('networkIP')!=IP or not nic.get('network','').endswith('/projects/'+PROJECT+'/global/networks/tn-gcps2s-20261010-peer') or instance.get('status')!='RUNNING':raise ValueError('exact running owned client required')

def main():
    p=argparse.ArgumentParser();p.add_argument('--evidence-dir',required=True);p.add_argument('--publisher',required=True);p.add_argument('--publisher-sha256',required=True);a=p.parse_args()
    parent=pathlib.Path(a.evidence_dir);s=os.lstat(parent)
    if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('owned private evidence directory required')
    fd=os.open(a.publisher,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        source=os.fstat(fd)
        if not stat.S_ISREG(source.st_mode) or source.st_uid!=os.getuid() or source.st_mode & 0o022 or source.st_size>65536:raise ValueError('owned reviewed publisher source required')
        helper=os.read(fd,65537)
    finally:os.close(fd)
    if hashlib.sha256(helper).hexdigest()!=a.publisher_sha256:raise ValueError('reviewed helper hash required')
    attempt=str(uuid.uuid4());run=parent/('client-'+attempt);run.mkdir(mode=0o700)
    def save(name,value):
        fd=os.open(run/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as f:json.dump(value,f);f.write('\n');f.flush();os.fsync(f.fileno())
    token=subprocess.run(['gcloud','auth','print-access-token'],capture_output=True,text=True,timeout=20,check=True).stdout.strip()
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    def api(path,method='GET',body=None):
        request=urllib.request.Request(BASE+path,data=None if body is None else json.dumps(body).encode(),method=method,headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
        with opener.open(request,timeout=20) as r:
            raw=r.read(2*1024*1024+1)
            if len(raw)>2*1024*1024:raise ValueError('bounded Google response required')
            return json.loads(raw,object_pairs_hook=unique)
    def wait(operation):
        name=operation['name'];deadline=time.monotonic()+90
        while True:
            current=api('/zones/'+ZONE+'/operations/'+name)
            if current.get('status')=='DONE':
                if current.get('error'):raise ValueError('Google operation refused')
                return name
            if time.monotonic()>=deadline:raise ValueError('bounded Google operation timeout')
            time.sleep(1)
    before=api(INSTANCE);identity(before);original=metadata_items(before['metadata']);save('original-instance.json',before)
    original_hash=hashlib.sha256(json.dumps(original,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    serial=api(INSTANCE+'/serialPort?port=1&start=0');offset=int(serial['next'])
    installed=startup(original,helper,attempt)
    current=api(INSTANCE);identity(current)
    wait(api(INSTANCE+'/setMetadata','POST',cas_body(before['metadata'],current['metadata'],installed)))
    prepared=api(INSTANCE);identity(prepared)
    if metadata_items(prepared['metadata'])!=installed:raise ValueError('complete metadata readback mismatch')
    save('installed-metadata.json',prepared['metadata'])
    # No stop/retry/recreation: one genuine normal reset of this exact fixture only.
    reset=wait(api(INSTANCE+'/reset','POST',{}));deadline=time.monotonic()+120;found=None;carry=''
    while time.monotonic()<deadline:
        output=api(INSTANCE+'/serialPort?port=1&start='+str(offset));offset=int(output['next'])
        lines,carry=serial_lines(carry,output.get('contents',''))
        for line in lines:
            start=line.find('{"marker":"TUNNEX_OWNED_PUBLIC_HOSTKEY_V1"')
            if start<0:continue
            try:marker=parse_marker(line[start:],attempt)
            except (ValueError,KeyError,TypeError):continue
            found=marker;break
        if found:break
        time.sleep(1)
    if not found:raise ValueError('new reset publication marker absent; metadata retained for reviewed recovery')
    fingerprint=found['fingerprint']
    after=api(INSTANCE);identity(after)
    if metadata_items(after['metadata'])!=installed:raise ValueError('metadata changed; no blind restoration')
    wait(api(INSTANCE+'/setMetadata','POST',cas_body(prepared['metadata'],after['metadata'],original)))
    restored=api(INSTANCE);identity(restored)
    if metadata_items(restored['metadata'])!=original:raise ValueError('original complete metadata restoration mismatch')
    save('public-proof.json',dict(found,reset_operation=reset,original_metadata_restored=True,original_metadata_sha256=original_hash,publisher_sha256=a.publisher_sha256,trust_pinned=False))
    print(json.dumps({'instance_id':ID,'attempt':attempt,'boot_id':found['boot_id'],'fingerprint':fingerprint,'original_metadata_restored':True,'trust_pinned':False}))

if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt):print('Owned client recovery refused; private metadata/response withheld. Preserve evidence, no automatic retry.',file=sys.stderr);sys.exit(1)
