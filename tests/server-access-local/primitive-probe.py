"""Nonshipping OS/recording/lease feasibility probes; no product integration."""
import unittest,os,pty,fcntl,termios,struct,subprocess,json,tempfile,pathlib,threading,socket,time,errno,io
class Recorder:
 def __init__(self,enabled,sink):self.enabled=bool(enabled);self.sink=sink;self.closed=False;self.seq=0;self.events=['session_start'];self.start=time.monotonic()
 def output(self,data):
  if self.closed:raise RuntimeError('closed')
  if self.enabled:
   try:
    self.sink.write((json.dumps({'seq':self.seq,'time':time.monotonic()-self.start,'kind':'output','data':data})+'\n').encode());self.sink.flush();os.fsync(self.sink.fileno());self.seq+=1
   except OSError:self.closed=True;self.events.append('recording_failed');raise
  return data
class Probes(unittest.TestCase):
 def test_pty_resize_and_utf8(self):
  master,slave=pty.openpty()
  try:
   for rows,cols in [(24,80),(40,120)]:
    fcntl.ioctl(master,termios.TIOCSWINSZ,struct.pack('HHHH',rows,cols,0,0))
    p=subprocess.run(['/bin/sh','-c','stty size; printf "héllo\\n"'],stdin=slave,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3)
    self.assertEqual(p.returncode,0,p.stderr);self.assertIn(f'{rows} {cols}'.encode(),p.stdout);self.assertIn('héllo'.encode(),p.stdout)
  finally:os.close(master);os.close(slave)
 def test_recording_off_has_events_but_no_payload(self):
  r=Recorder(False,None);self.assertEqual(r.output('private output'),'private output');self.assertEqual(r.seq,0);self.assertEqual(r.events,['session_start'])
 def test_policy_is_admission_snapshot(self):
  settings={'enabled':False};r=Recorder(settings['enabled'],None);settings['enabled']=True;r.output('off session still off');self.assertEqual(r.seq,0)
 def test_enabled_durable_ordered_output(self):
  with tempfile.TemporaryFile() as f:
   r=Recorder(True,f);r.output('héllo');r.output('\x1b[31mred');f.seek(0);e=[json.loads(l) for l in f];self.assertEqual([x['seq'] for x in e],[0,1]);self.assertEqual(e[0]['data'],'héllo');self.assertLessEqual(e[0]['time'],e[1]['time'])
 def test_enospc_closes_before_forward(self):
  class Full:
   def write(self,_):raise OSError(errno.ENOSPC,'owned injected full sink')
  r=Recorder(True,Full())
  with self.assertRaises(OSError):r.output('not forwarded')
  self.assertTrue(r.closed);self.assertIn('recording_failed',r.events)
 @unittest.skipUnless(os.environ.get('SA0_FULL_DISK_DIR'), 'requires owned bounded tmpfs')
 def test_real_full_disk_closes_before_forward(self):
  directory=pathlib.Path(os.environ['SA0_FULL_DISK_DIR'])
  with (directory/'fill').open('wb',buffering=0) as fill:
   with self.assertRaises(OSError) as raised:
    while True:fill.write(b'x'*4096)
   self.assertEqual(raised.exception.errno,errno.ENOSPC)
  with (directory/'capture').open('wb',buffering=0) as sink:
   recorder=Recorder(True,sink);forwarded=[]
   with self.assertRaises(OSError) as raised:
    forwarded.append(recorder.output('must not reach browser'))
   self.assertEqual(raised.exception.errno,errno.ENOSPC)
   self.assertEqual(forwarded,[]);self.assertTrue(recorder.closed)
   self.assertEqual(recorder.events,['session_start','recording_failed'])
 def test_lease_watchdog_closes_with_stalled_renewal(self):
  a,b=socket.socketpair();b.settimeout(1);start=time.monotonic();timer=threading.Timer(.2,a.close);timer.start()
  try:self.assertEqual(b.recv(1),b'');self.assertLess(time.monotonic()-start,.7)
  finally:timer.join();a.close();b.close()
if __name__=='__main__':unittest.main(verbosity=2)
