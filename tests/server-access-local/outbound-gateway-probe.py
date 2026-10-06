"""Run in owned gateway. PTY to Linux target over enrolled mTLS outbound stream."""
import socket,ssl,subprocess,pty,fcntl,termios,struct,os,select,json,signal
ctx=ssl.create_default_context(cafile='/ssh-fixture/broker-ca.pem');ctx.minimum_version=ssl.TLSVersion.TLSv1_3;ctx.load_cert_chain('/state/cert.pem','/state/key.pem')
m,s=pty.openpty();fcntl.ioctl(m,termios.TIOCSWINSZ,struct.pack('HHHH',24,80,0,0))
ssh=['ssh','-F','/dev/null','-o','BatchMode=yes','-o','ConnectTimeout=5','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile=/ssh-fixture/known_hosts','-i','/ssh-fixture/actor-a','-p','2222','-tt','fixture@ssh-target','/bin/sh']
p=None
try:
 with ctx.wrap_socket(socket.create_connection(('outbound-broker',4443),timeout=5),server_hostname='outbound-broker') as stream:
  stream.sendall(b'{"purpose":"sa0-terminal-spike","server":"server-linux","account":"fixture"}\n')
  p=subprocess.Popen(ssh,stdin=s,stdout=s,stderr=s,start_new_session=True);os.close(s);s=-1;pending=b''
  while True:
   ready,_,_=select.select([stream,m],[],[],3)
   if not ready:raise RuntimeError('bounded stall')
   if stream in ready:
    data=stream.recv(4096)
    if not data:break
    pending+=data;assert len(pending)<16384
    while b'\n' in pending:
     line,pending=pending.split(b'\n',1);msg=json.loads(line)
     if msg['type']=='input':os.write(m,msg['data'].encode())
     elif msg['type']=='resize':fcntl.ioctl(m,termios.TIOCSWINSZ,struct.pack('HHHH',msg['rows'],msg['cols'],0,0));os.kill(p.pid,signal.SIGWINCH)
     else:raise RuntimeError('unknown frame')
   if m in ready:stream.sendall(os.read(m,4096))
 print('SA0 outbound channel ended; closing owned SSH client',flush=True)
finally:
 if p is not None and p.poll() is None:
  p.terminate()
  try:p.wait(timeout=2)
  except subprocess.TimeoutExpired:p.kill();p.wait()
 os.close(m)
 if s>=0:os.close(s)
