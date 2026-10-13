"""ROOT staging only; never execute observer or alter enrolled service."""
import pathlib,hashlib,subprocess,shlex,json,os,stat,argparse
ELF=pathlib.Path('/private/tmp/gcp-xfrm-policy-observer-9c3ab006-amd64');SHA='e91d3189a13ac7d68e9a30dd411697779d4c44319725facd577f75a57321a904'
TRANSPORT=pathlib.Path('/private/tmp/gcp-cloud-native-build-20261010-1/build.py');TRANSPORT_SHA='f2b27b12b40073ed5ad0d9625d92778047dbf766d460368db2fc97602d77ce38'
REMOTE=r'''
import pathlib,os,stat,hashlib,json,subprocess,sys
CID='3bad435938b37398218e1c28a278fe72a57735cc489719527d2f8d1167e732ed';IMAGE='sha256:dfbe391873e7013111d47f489cf6ddbd6c8a83541b8bbb8aab191310879a8db9';SOURCE='9c3ab006c13b72285f43baed1805da1af273ffa7';NS='net:[4026531840]';BOOT='9617762e-19db-4a21-bdee-909dfb31e501';SHA='e91d3189a13ac7d68e9a30dd411697779d4c44319725facd577f75a57321a904'
def identity():
 i=json.loads(subprocess.check_output(['docker','inspect',CID],timeout=5))[0]
 if i['Id']!=CID or i['Image']!=IMAGE or i['State']['Running']is not True or i['Config']['Labels'].get('org.opencontainers.image.revision')!=SOURCE or pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=BOOT or os.readlink('/proc/self/ns/net')!=NS:raise ValueError('stage identity')
 return (i['State']['Pid'],i['State']['StartedAt'])
if os.geteuid()!=0:raise ValueError('root required')
before=identity();raw=sys.stdin.buffer.read(32*1024*1024+1)
if len(raw)>32*1024*1024 or hashlib.sha256(raw).hexdigest()!=SHA or raw[:6]!=b'\x7fELF\x02\x01' or raw[18:20]!=b'\x3e\x00':raise ValueError('ELF refused')
parent=pathlib.Path('/var/lib');s=parent.lstat()
if not stat.S_ISDIR(s.st_mode)or s.st_uid!=0 or stat.S_IMODE(s.st_mode)&0o022:raise ValueError('parent refused')
root=parent/'tunnex-gcp-policy-observer-20261011';root.mkdir(mode=0o700)
fd=os.open(root/'policy-observer',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700)
try:
 off=0
 while off<len(raw):
  n=os.write(fd,raw[off:])
  if n<=0:raise ValueError('write refused')
  off+=n
 os.fsync(fd)
finally:os.close(fd)
if identity()!=before or hashlib.sha256((root/'policy-observer').read_bytes()).hexdigest()!=SHA:raise ValueError('stage bracket')
print(json.dumps({'completed':True,'observer_executed':False,'service_mutations':0,'elf_sha256':SHA,'path':str(root/'policy-observer'),'source_commit':SOURCE,'container_id':CID}))
'''
def main():
 a=argparse.ArgumentParser();a.add_argument('--receipt',required=True);args=a.parse_args();p=pathlib.Path(args.receipt);s=p.parent.lstat()
 if not stat.S_ISDIR(s.st_mode)or s.st_uid!=os.geteuid()or stat.S_IMODE(s.st_mode)!=0o700:raise ValueError('private parent')
 raw=ELF.read_bytes();transport=TRANSPORT.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=SHA or hashlib.sha256(transport).hexdigest()!=TRANSPORT_SHA:raise ValueError('source pin')
 ns={};exec(compile(transport.decode().split('receipt=json.loads')[0],str(TRANSPORT),'exec'),ns)
 def exclusive(path):return os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')
 with exclusive(p)as out,exclusive(p.with_name(p.name+'.stderr'))as err:
  r=subprocess.run(ns['B']+[shlex.join(ns['G']+['sudo -n python3 -c '+shlex.quote(REMOTE)])],input=raw,stdout=out,stderr=err,timeout=60)
  out.flush();err.flush();os.fsync(out.fileno());os.fsync(err.fileno())
  if r.returncode:raise ValueError('staging refused; private partial preserved')
if __name__=='__main__':main()
