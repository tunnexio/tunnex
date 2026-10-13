#!/usr/bin/env python3
"""Restore exact original metadata after the single captured owned client attempt."""
import hashlib,json,os,pathlib,stat,subprocess,sys,time,urllib.request
PROJECT='project-0048836f-6ba1-4a14-8da';ZONE='asia-south2-b';NAME='tn-gcps2s-20261010-local-client';ID='4751969643435150303'
ROOT=pathlib.Path('/home/cyberking9560/tn-gcps2s-20261010/hostkey-recovery-b7db7300/evidence/client-f220e637-3b74-4b87-a6da-ff3834ea59a1')
EXPECTED_ORIGINAL='9b9039d68991082b1a81f91fefd1a2600473e88a868cca47fd15e3c8bfc581d4'
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

def unique(pairs):
    d={}
    for k,v in pairs:
        if k in d:raise ValueError('duplicate JSON field')
        d[k]=v
    return d

def private_json(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=os.getuid() or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o600 or s.st_size>2*1024*1024:raise ValueError('exact private capture required')
        raw=os.read(fd,2*1024*1024+1)
        after=os.fstat(fd)
        if len(raw)!=s.st_size or (s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_mode,s.st_uid,s.st_nlink)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns,after.st_mode,after.st_uid,after.st_nlink):raise ValueError('bounded stable capture required')
        return json.loads(raw,object_pairs_hook=unique)
    finally:os.close(fd)

def restore_body(original,installed,current):
    if str(original.get('id'))!=ID or str(current.get('id'))!=ID or current.get('name')!=NAME or current.get('status')!='RUNNING' or current['networkInterfaces'][0]['networkIP']!='10.70.0.10' or not current['networkInterfaces'][0].get('network','').endswith('/projects/'+PROJECT+'/global/networks/tn-gcps2s-20261010-peer'):raise ValueError('exact owned client required')
    if current['metadata']!=installed:raise ValueError('captured installed metadata changed')
    items=original['metadata']['items']
    if hashlib.sha256(json.dumps(items,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=EXPECTED_ORIGINAL:raise ValueError('original complete metadata hash mismatch')
    return {'fingerprint':current['metadata']['fingerprint'],'items':items}

def main():
    s=os.lstat(ROOT)
    if not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.getuid() or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('owned captured attempt directory required')
    original=private_json(ROOT/'original-instance.json');installed=private_json(ROOT/'installed-metadata.json')
    fd=os.open(ROOT/'metadata-restoration-receipt.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as evidence:
        evidence.write(json.dumps({'instance_id':ID,'attempt':'f220e637-3b74-4b87-a6da-ff3834ea59a1','restore_started':True})+'\n');evidence.flush();os.fsync(evidence.fileno())
        token=subprocess.run(['gcloud','auth','print-access-token'],capture_output=True,text=True,timeout=20,check=True).stdout.strip()
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect());base='https://compute.googleapis.com/compute/v1/projects/'+PROJECT;instance='/zones/'+ZONE+'/instances/'+NAME
        def api(path,method='GET',body=None):
            r=urllib.request.Request(base+path,data=None if body is None else json.dumps(body).encode(),method=method,headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
            with opener.open(r,timeout=20) as response:
                raw=response.read(2*1024*1024+1)
                if len(raw)>2*1024*1024:raise ValueError('bounded response required')
                return json.loads(raw,object_pairs_hook=unique)
        current=api(instance);body=restore_body(original,installed,current)
        operation=api(instance+'/setMetadata','POST',body);deadline=time.monotonic()+90
        while True:
            result=api('/zones/'+ZONE+'/operations/'+operation['name'])
            if result.get('status')=='DONE':
                if result.get('error'):raise ValueError('restoration refused')
                break
            if time.monotonic()>=deadline:raise ValueError('bounded restoration wait expired')
            time.sleep(1)
        after=api(instance)
        if str(after.get('id'))!=ID or after['metadata'].get('items')!=body['items']:raise ValueError('exact restored original readback required')
        out={'instance_id':ID,'original_metadata_restored':True,'original_complete_items_sha256':EXPECTED_ORIGINAL,'reset_executed':False,'trust_pinned':False}
        evidence.write(json.dumps(out)+'\n');evidence.flush();os.fsync(evidence.fileno());print(json.dumps(out))

if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt):print('Owned exact metadata restoration refused; private contents withheld, no automatic retry.',file=sys.stderr);sys.exit(1)
