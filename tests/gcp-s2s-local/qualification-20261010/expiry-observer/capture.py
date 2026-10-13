# Exact owned read-only capture. Only the coordinator executes this source.
import argparse,base64,hashlib,json,os,pathlib,re,shlex,stat
ROOT=pathlib.Path('/private/tmp/gcp-cloud-expiry-observer-20261010')
DEPENDENCY=pathlib.Path('/private/tmp/gcp-cloud-native-build-20261010-1/build.py')
DEPENDENCY_SHA='f2b27b12b40073ed5ad0d9625d92778047dbf766d460368db2fc97602d77ce38'
REMOTE="import subprocess,json,pathlib,hashlib\nc='5f77c5857fa78b0533eb4fddc46cc4a0e9c69369d8e7987ee068b88ec7ba8c2f'\ndef run(*args):\n b=subprocess.check_output(args,timeout=15)\n if len(b)>2*1024*1024:raise ValueError('bounded capture')\n return b.decode().strip()\ni=json.loads(run('docker','inspect',c))[0]\nif i['Id']!=c or i['Image']!='sha256:347bcb66318aa1b8ef1e949c6f57e28506e56a1497f2f4ae15b9ab74b8fed4c6' or not i['State']['Running']:raise ValueError('owned identity')\ndef ex(*a):return run('docker','exec',c,*a)\ndef guard():\n p=pathlib.Path('/var/lib/tunnex-gcp-s2s-cloud-20261010/ipsec/journal.json')\n if p.stat().st_size>16*1024*1024:raise ValueError('bounded journal')\n gs=json.loads(p.read_text())['Payload']['Guards']\n if len(gs)!=1:raise ValueError('one guard required')\n g=gs[0];return {k:g[k] for k in ['ExpectedJSON','Digest','Revision','Namespace']}\nif i['Config']['Labels'].get('org.opencontainers.image.revision')!='4143d866ab97386411ff1ac4705aaa0e4579bcf6' or run('cat','/proc/sys/kernel/random/boot_id')!='9617762e-19db-4a21-bdee-909dfb31e501':raise ValueError('source boot drift')\nn1=ex('readlink','/proc/self/ns/net');h1=run('readlink','/proc/self/ns/net');links=json.loads(ex('/sbin/ip','-j','-d','link','show'))\nreader=ex('sha256sum','/usr/sbin/nft').split()[0]\nif reader!='7156559ea0d2d062a40af33952eb412833a191cb7179e9ad9efe8b146a563d7f':raise ValueError('qualified reader drift')\nif n1!='net:[4026531840]' or h1!=n1:raise ValueError('exact namespace drift')\nbefore=guard()\nactual=json.loads(ex('/usr/sbin/nft','-j','list','table','inet','tunnex_ipsec'))\nafter=guard()\nafter_links=json.loads(ex('/sbin/ip','-j','-d','link','show'));n2=ex('readlink','/proc/self/ns/net');h2=run('readlink','/proc/self/ns/net')\nif before!=after or links!=after_links or n1!=n2 or n1!=h1 or h1!=h2 or before['Namespace']!=n1:raise ValueError('capture identity changed')\nprint(json.dumps({'source_commit':'4143d866ab97386411ff1ac4705aaa0e4579bcf6','container_id':c,'image_id':i['Image'],'boot_id':run('cat','/proc/sys/kernel/random/boot_id'),'expected_guard':before,'actual_guard':actual,'links':links,'namespace_before':n1,'namespace_after':n2,'host_namespace_before':h1,'host_namespace_after':h2,'guard_identity_stable':True,'reader_sha256':reader,'scope':'read-only exact guard projection; no full journal/material/raw XFRM state'}))\n"
def reserve(name):
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,79}\.json',name):raise ValueError('evidence filename refused')
    try:ROOT.mkdir(mode=0o700)
    except FileExistsError:pass
    p=ROOT.lstat()
    if not stat.S_ISDIR(p.st_mode) or p.st_uid!=os.getuid() or stat.S_IMODE(p.st_mode)!=0o700:raise ValueError('private evidence directory refused')
    directory=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    q=os.fstat(directory)
    if (p.st_dev,p.st_ino,p.st_uid,stat.S_IMODE(p.st_mode))!=(q.st_dev,q.st_ino,q.st_uid,stat.S_IMODE(q.st_mode)):os.close(directory);raise ValueError('directory identity drift')
    try:
        evidence=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
        error=os.open(name+'.private-stderr',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
    finally:os.close(directory)
    return evidence,error

def write(fd,value):
    with os.fdopen(fd,'wb') as f:f.write(value);f.flush();os.fsync(f.fileno())

def main():
    parser=argparse.ArgumentParser(description='read-only pinned GCP guard capture; unique private filename only')
    parser.add_argument('evidence_name');args=parser.parse_args()
    evidence,error=reserve(args.evidence_name) # Exclusively reserve BEFORE any SSH.
    try:
        dependency=DEPENDENCY.read_bytes()
        if hashlib.sha256(dependency).hexdigest()!=DEPENDENCY_SHA:raise ValueError('transport source drift')
        ns={};exec(dependency.decode().split('receipt=json.loads')[0],ns)
        command='sudo -n python3 -c '+shlex.quote('import base64;exec(base64.b64decode('+repr(base64.b64encode(REMOTE.encode()).decode())+'))')
        raw=ns['gateway'](command)
        if len(raw)>2*1024*1024:raise ValueError('bounded capture refused')
        v=json.loads(raw)
        if not v.get('guard_identity_stable'):raise ValueError('unstable capture refused')
    except Exception as e:
        private=getattr(e,'stderr',b'')or b''
        write(error,private)
        failed={'completed':False,'error_type':type(e).__name__,'private_error_sha256':hashlib.sha256(private).hexdigest(),'scope':'failure preserved; no retry or observation proof'}
        write(evidence,(json.dumps(failed)+'\n').encode())
        print(json.dumps({'completed':False,'receipt':str(ROOT/args.evidence_name),'error_type':type(e).__name__,'private_error_sha256':failed['private_error_sha256']}));return 1
    write(error,b'')
    payload=(json.dumps(v,indent=2)+'\n').encode();write(evidence,payload)
    print(json.dumps({'completed':True,'receipt':str(ROOT/args.evidence_name),'sha256':hashlib.sha256(payload).hexdigest(),'guard_revision':v['expected_guard']['Revision'],'namespace':v['namespace_before'],'scope':'read-only guard observation; API policy/deadline association external'}));return 0
if __name__=='__main__':raise SystemExit(main())
