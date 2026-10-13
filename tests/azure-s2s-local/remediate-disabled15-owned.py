#!/usr/bin/env python3
"""Reviewed one-shot owned negative cleanup. Run only while external CAS mutations are serialized."""
import argparse, datetime, hashlib, json, os, pathlib, re, signal, socket, stat, subprocess
OWNER = 'azure-s2s-01a12505'
CONNECTION = '9bfa4090-d3ca-4a8e-9ef9-3b41bd91fe99'
def command(args, timeout=10):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout).stdout

def digest(raw): return hashlib.sha256(raw).hexdigest()
def proc(pid):
    raw = pathlib.Path(f'/proc/{pid}/stat').read_text()
    fields = raw[raw.rindex(') ')+2:].split()
    if len(fields) < 20: raise ValueError('proc')
    return fields[0], int(fields[1]), int(fields[19])
def private_read(path, mode=0o600, maxbytes=2*1024*1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if st.st_uid != 0 or stat.S_IMODE(st.st_mode) != mode or not stat.S_ISREG(st.st_mode) or st.st_size > maxbytes: raise ValueError('private')
        parts=[]
        while True:
            chunk=os.read(fd,min(65536,maxbytes+1-sum(map(len,parts))))
            if not chunk: break
            parts.append(chunk)
            if sum(map(len,parts))>maxbytes: raise ValueError("size")
        raw=b"".join(parts)
        if len(raw)!=st.st_size: raise ValueError("changed-size")
        return raw, st
    finally: os.close(fd)
def save(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        view=memoryview(raw)
        while view: view=view[os.write(fd,view):]
        os.fsync(fd)
    finally: os.close(fd)
def normal(raw):
    v = json.loads(raw); c = v['connection']; now = datetime.datetime.now(datetime.timezone.utc)
    seen = datetime.datetime.fromisoformat(v['observed_at'].replace('Z', '+00:00'))
    if c['id'] != CONNECTION or c['desired_revision'] != 15 or c['desired_intent'] != 'disabled' or c['cleanup_state'] != 'pending' or not 0 <= (now-seen).total_seconds() <= 15: raise ValueError('normal')
    return v

def inspect(container):
    v = json.loads(command(['docker','inspect',container]))[0]
    if not re.fullmatch('[0-9a-f]{64}',v['Id']) or v['Config']['Labels'].get('tunnex.owner') != OWNER or not v['State']['Running'] or v['State']['Restarting']: raise ValueError('container')
    return v

def main():
    p=argparse.ArgumentParser(); p.add_argument('--container',required=True); p.add_argument('--private-root',required=True); p.add_argument('--lifecycle-helper',required=True); p.add_argument('--helper-binary',required=True); p.add_argument('--helper-sha256',required=True); p.add_argument('--evidence-dir',required=True); p.add_argument('--expected-cid',required=True); p.add_argument('--expected-image-id',required=True); p.add_argument('--expected-node-sha256',required=True); a=p.parse_args()
    stage='preflight'; resume=False; identity=None; cid=None; evidence=None
    try:
        if os.geteuid()!=0 or socket.gethostname()!='tunnex-peer': raise ValueError('host')
        binary, _=private_read(a.helper_binary,0o755,32*1024*1024)
        if digest(binary)!=a.helper_sha256: raise ValueError('binary')
        private=pathlib.Path(a.private_root); ps=private.lstat()
        if private.resolve()!=private or ps.st_uid!=1000 or stat.S_IMODE(ps.st_mode)!=0o700 or not stat.S_ISDIR(ps.st_mode): raise ValueError('private-root')
        evidence=pathlib.Path(a.evidence_dir)
        if evidence.parent!=private: raise ValueError('evidence-parent')
        evidence.mkdir(mode=0o700)
        helper=pathlib.Path(a.lifecycle_helper); hs=helper.lstat()
        if helper.resolve()!=helper or hs.st_uid!=0 or not stat.S_ISREG(hs.st_mode) or hs.st_mode & 0o022: raise ValueError('api-helper')
        v=inspect(a.container); cid=v['Id']; pid=v['State']['Pid']; ns=os.readlink(f'/proc/{pid}/ns/net'); ticks=proc(pid)[2]; exe=digest(pathlib.Path(f'/proc/{pid}/exe').read_bytes()); identity=(pid,ticks,ns,exe,v['State']['StartedAt'])
        if cid!=a.expected_cid or v['Image']!=a.expected_image_id or exe!=a.expected_node_sha256: raise ValueError('expected-runtime')
        def same():
            c=inspect(cid); q=c['State']['Pid']
            if c['Id']!=a.expected_cid or c['Image']!=a.expected_image_id: raise ValueError('expected-runtime')
            if (q,proc(q)[2],os.readlink(f'/proc/{q}/ns/net'),digest(pathlib.Path(f'/proc/{q}/exe').read_bytes()),c['State']['StartedAt']) != identity: raise ValueError('identity')
        stage='normal_api_read'
        raw=command(['sudo','-u','#1000','--','python3',str(helper),'read','--private-root',str(private)],20); read=normal(raw)
        save(evidence/'normal-read.json',raw)
        same(); stage='pause'; resume=True
        os.kill(pid,signal.SIGSTOP); same()
        if proc(pid)[0]!='T': raise ValueError('not-stopped')
        stage='frozen_baseline'; root=pathlib.Path(f'/proc/{pid}/root')
        journal,jst=private_read(root/'var/lib/tunnex-node/ipsec/journal.json'); payload=json.loads(journal)['Payload']; current=[e for e in payload['Entries'] if e['Phase']!='retained_refusal']
        if len(current)!=1 or len(payload['Guards'])!=1: raise ValueError('entries')
        e=current[0]; engine=e['Engines'][0]; allocation=e['Allocation']
        if e['Phase']!='cleanup_pending' or e['CleanupDesiredRevision']!=15 or e['CoveredDeliveryRevision']!=14 or allocation['ConnectionID']!=CONNECTION: raise ValueError('entry')
        packaged=digest((root/'opt/tunnex-ipsec/libexec/ipsec/charon').read_bytes()); children=set()
        for thread in pathlib.Path(f'/proc/{pid}/task').iterdir():
            children.update((thread/'children').read_text().split())
        matches=[]
        for child in children:
            q=int(child)
            if proc(q)[1]==pid and digest(pathlib.Path(f'/proc/{q}/exe').read_bytes())==packaged: matches.append(q)
        if len(matches)!=1: raise ValueError('daemon')
        q=matches[0]
        if proc(q)[0] in ('T','t','Z','X'): raise ValueError('daemon-not-running')
        nspid=[line for line in pathlib.Path(f'/proc/{q}/status').read_text().splitlines() if line.startswith('NSpid:')][0].split()[-1]
        if os.readlink(f'/proc/{q}/ns/net')!=ns or int(nspid)<=1: raise ValueError('daemon-namespace')
        config,cst=private_read(root/'run/tunnex-ipsec/strongswan.conf'); sst=(root/'run/tunnex-ipsec/charon.vici').lstat()
        if sst.st_uid!=0 or stat.S_IMODE(sst.st_mode)!=0o600 or not stat.S_ISSOCK(sst.st_mode): raise ValueError('socket')
        stage='private_install'
        for name in ['azure-cleanup15-v3-normal-read.json','azure-cleanup15-v3-baseline.json']:
            if (root/'run'/name).exists(): raise ValueError('existing-input')
        save(root/'run/azure-cleanup15-v3-normal-read.json',raw); rst=(root/'run/azure-cleanup15-v3-normal-read.json').stat()
        b=dict(CharonPID=int(nspid),CharonStartTicks=proc(q)[2],CharonExecutableSHA256=packaged,CharonConfigSHA256=digest(config),CharonConfigDevice=cst.st_dev,CharonConfigInode=cst.st_ino,SocketDevice=sst.st_dev,SocketInode=sst.st_ino,JournalSHA256=digest(journal),JournalDevice=jst.st_dev,JournalInode=jst.st_ino,Namespace=ns,BootID=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),NodeExecutableSHA256=exe,NodeStartTicks=ticks,OwnerID=payload['OwnerID'],OrgID=engine['Binding']['OrgID'],DeliveryID=e['DeliveryID'],CleanupID=e['CleanupID'],DesiredRevision=15,GuardExpectedSHA256=digest(payload['Guards'][0]['ExpectedJSON'].encode()),CPDesiredIntent='disabled',CPCleanupState='pending',CPDesiredRevision=15,NormalReadSHA256=digest(raw),NormalReadObservedAt=read['observed_at'],NormalReadDevice=rst.st_dev,NormalReadInode=rst.st_ino)
        baseline=json.dumps(b).encode(); save(evidence/'baseline.json',baseline); save(root/'run/azure-cleanup15-v3-baseline.json',baseline); save(evidence/'journal-frozen.json',journal)
        same()
        if private_read(root/'var/lib/tunnex-node/ipsec/journal.json')[0]!=journal: raise ValueError('journal-changed')
        normal(raw)
        save(root/'tmp/azure-cleanup15-v3-remediation.test',binary,0o755)
        stage='negative_cleanup_helper'
        result=subprocess.run(['docker','exec','-u','0',cid,'env','-u','TUNNEX_AZURE_DISABLED15_ATTESTATION_ONLY','TUNNEX_AZURE_DISABLED15_CLEANUP_REMEDIATION=1','/tmp/azure-cleanup15-v3-remediation.test','-test.run','^TestAzureDisabled15CleanupRemediationNative$','-test.timeout=30s'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=40)
        save(evidence/'helper-private.log',result.stdout)
        if result.returncode: raise ValueError('helper-refused')
        stage='negative_cleanup_completed'
    except (ValueError,KeyError,OSError,subprocess.SubprocessError):
        stage=stage+'_refused'
    finally:
        if resume:
            try:
                same(); os.kill(pid,signal.SIGCONT); resumed=True
            except (ValueError,KeyError,OSError,subprocess.SubprocessError): resumed=False; stage='exact_resume_refused'
        else: resumed=False
        print(json.dumps({'stage':stage,'agent_resumed':resumed,'observed_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}))
    return 0 if stage=='negative_cleanup_completed' else 1
if __name__=='__main__': raise SystemExit(main())
