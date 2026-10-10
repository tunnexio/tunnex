#!/usr/bin/env python3
"""SOURCE ONLY: append invocation to preserved owned fixture startup after review."""
import base64,hashlib,json,os,pathlib,stat,subprocess,sys,urllib.request,uuid
OWNED_IDS={'4751969643435150303','7595462031766211538','139156170322758560'}

def public_key(path='/etc/ssh/ssh_host_ed25519_key.pub'):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_size>4096:raise ValueError('existing root-owned public key required')
        fields=os.read(fd,4097).decode('ascii').split()
    finally:os.close(fd)
    if len(fields)<2 or fields[0]!='ssh-ed25519':raise ValueError('existing ed25519 public key required')
    raw=base64.b64decode(fields[1],validate=True)
    # Exact OpenSSH ed25519 wire structure: no alternate key type or trailing data.
    if len(raw)!=51 or raw[:19]!=b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20':raise ValueError('exact ed25519 wire key required')
    return fields[0]+' '+fields[1],'SHA256:'+base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')

def main():
    if os.geteuid()!=0 or len(sys.argv)!=3 or sys.argv[1] not in OWNED_IDS:raise ValueError('owned root fixture invocation required')
    nonce=str(uuid.UUID(sys.argv[2]));expected=sys.argv[1]
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    r=urllib.request.Request('http://169.254.169.254/computeMetadata/v1/instance/id',headers={'Metadata-Flavor':'Google'})
    with opener.open(r,timeout=3) as response:
        if response.headers.get('Metadata-Flavor')!='Google':raise ValueError('instance metadata required')
        actual=response.read(64).decode().strip()
    if actual!=expected:raise ValueError('exact instance ID required')
    key,fingerprint=public_key();boot=str(uuid.UUID(pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()))
    data={'marker':'TUNNEX_OWNED_PUBLIC_HOSTKEY_V1','instance_id':actual,'attempt':nonce,'boot_id':boot,'public_key':key,'fingerprint':fingerprint}
    fd=os.open('/dev/ttyS0',os.O_WRONLY|os.O_NOCTTY|os.O_NOFOLLOW)
    try:os.write(fd,('\n'+json.dumps(data,separators=(',',':'))+'\n').encode())
    finally:os.close(fd)

if __name__=='__main__':
    try:main()
    except Exception:print('Owned public hostkey publication refused.',file=sys.stderr);sys.exit(1)
