"""Source-only helper: assemble complete per-delivery receipts in a fresh private directory.
Run only inside the reviewed sleeping replacement namespace. This never stops,
installs into /state, releases a gate, or edits the journal. Existing product CLI
validates the entire journal and real host stop proof for each selected delivery.
"""
import argparse, hashlib, json, os, pathlib, stat, subprocess, uuid

def sha(raw): return hashlib.sha256(raw).hexdigest()
def canonical(value):
    assert str(uuid.UUID(value)) == value and uuid.UUID(value).int
    return value

def active_deliveries(raw):
    j=json.loads(raw); entries=j['Payload']['Entries']; assert 0<len(entries)<=256
    owner=canonical(j['Payload']['OwnerID']); result=[]
    for e in entries:
        assert e['Engines'][0]['Binding']['GatewayID']==owner
        if e['Phase']=='retained_refusal': continue
        assert e['Phase']=='applied' and e['ContractVersion'] in (2,3)
        result.append(canonical(e['DeliveryID']))
    assert result and len(result)==len(set(result))
    return owner,sorted(result)

def private(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        st=os.fstat(fd); assert stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode)==0o600 and st.st_uid==0 and st.st_size<=4<<20
        with os.fdopen(os.dup(fd),'rb') as f: return f.read()
    finally: os.close(fd)

def main():
    p=argparse.ArgumentParser();p.add_argument('--cli',type=pathlib.Path,required=True);p.add_argument('--cli-sha',required=True)
    for k in ('journal','evidence','expected') :p.add_argument('--'+k,type=pathlib.Path,required=True);p.add_argument('--'+k+'-sha',required=True)
    p.add_argument('--out',type=pathlib.Path,required=True);p.add_argument('--execute',action='store_true');a=p.parse_args()
    if not a.execute: print('Source-only review mode; no receipts assembled');return
    assert os.geteuid()==0
    raw={k:private(getattr(a,k))for k in ('journal','evidence','expected')}
    for k,b in raw.items(): assert sha(b)==getattr(a,k+'_sha')
    owner,ids=active_deliveries(raw['journal']); expected=json.loads(raw['expected'])
    assert expected['OwnerID']==owner and expected['JournalSHA']==a.journal_sha and expected['DeliveryIDs']==ids
    cli=a.cli.lstat();assert stat.S_ISREG(cli.st_mode) and cli.st_uid==0 and stat.S_IMODE(cli.st_mode)==0o700 and sha(a.cli.read_bytes())==a.cli_sha
    boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();ns=os.readlink('/proc/self/ns/net')
    a.out.mkdir(mode=0o700,parents=False,exist_ok=False);receipts={}
    for delivery in ids:
        out=a.out/('restore-'+delivery+'.json')
        subprocess.run([str(a.cli),'--journal',str(a.journal),'--evidence',str(a.evidence),'--boot',boot,'--namespace',ns,'--delivery',delivery,'--out',str(out)],check=True,timeout=15)
        r=private(out);doc=json.loads(r)
        assert doc['OwnerID']==owner and doc['DeliveryID']==delivery and doc['Namespace']==ns and doc['EvidenceDigest']==a.evidence_sha
        receipts[delivery]=sha(r)
    assert all(private(getattr(a,k))==v for k,v in raw.items()) and os.readlink('/proc/self/ns/net')==ns and sha(a.cli.read_bytes())==a.cli_sha
    receiptset={'OwnerID':owner,'Namespace':ns,'JournalSHA':a.journal_sha,'EvidenceDigest':a.evidence_sha,'Receipts':receipts}
    fd=os.open(a.out/'receipt-set.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb')as f:f.write(json.dumps(receiptset,separators=(',',':')).encode()+b'\n');f.flush();os.fsync(f.fileno())
    fd=os.open(a.out,os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
    print('Complete exact receipt set assembled; installation and release remain separate')
if __name__=='__main__': main()
