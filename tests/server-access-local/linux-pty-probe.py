"""Run inside owned gateway: native SSH PTY dimensions and resize."""
import os,pty,fcntl,termios,struct,subprocess,select,time,json,signal
base=['ssh','-F','/dev/null','-o','BatchMode=yes','-o','ConnectTimeout=5','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile=/ssh-fixture/known_hosts','-i','/ssh-fixture/client','-p','2222','-tt','fixture@ssh-target']
master,slave=pty.openpty();fcntl.ioctl(master,termios.TIOCSWINSZ,struct.pack('HHHH',24,80,0,0))
p=subprocess.Popen(base+['/bin/sh'],stdin=slave,stdout=slave,stderr=slave,start_new_session=True);os.close(slave);data=b''
def read_until(token):
 global data
 deadline=time.monotonic()+5
 while token not in data and time.monotonic()<deadline:
  if select.select([master],[],[],.2)[0]:
   try:data+=os.read(master,4096)
   except OSError:break
 assert token in data,data.decode(errors='replace')
try:
 os.write(master,b"stty -F /dev/tty size; printf 'DIM_A_DONE\\n'\n");read_until(b'24 80')
 fcntl.ioctl(master,termios.TIOCSWINSZ,struct.pack('HHHH',40,120,0,0));os.kill(p.pid,signal.SIGWINCH);time.sleep(.2)
 os.write(master,b"stty -F /dev/tty size; printf 'h\303\251llo\\n'\n");read_until(b'40 120');read_until('héllo'.encode())
 os.write(master,b'exit\n');p.wait(timeout=4);assert p.returncode==0
 print(json.dumps({'native_linux_pty':True,'initial':'24x80','resized':'40x120','utf8':True,'ssh_exit':p.returncode}))
finally:
 if p.poll() is None:p.terminate();p.wait(timeout=3)
 os.close(master)
