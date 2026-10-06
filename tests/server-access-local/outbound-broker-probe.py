"""Nonshipping mTLS broker. Pinned enrolled gateway, fixture authority only."""
import socket,ssl,hashlib,json,threading,time,pathlib
r=pathlib.Path('/broker');context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_3;context.load_cert_chain(r/'server.pem',r/'server.key');context.load_verify_locations(r/'gateway-ca.pem');context.verify_mode=ssl.CERT_REQUIRED
expected=ssl.PEM_cert_to_DER_cert((r/'gateway-cert.pem').read_text());expected_hash=hashlib.sha256(expected).hexdigest()
with socket.socket() as listener:
 listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('0.0.0.0',4443));listener.listen(1)
 print('SA0 fixture outbound broker ready',flush=True)
 raw,_=listener.accept()
 with context.wrap_socket(raw,server_side=True) as stream:
  assert hashlib.sha256(stream.getpeercert(binary_form=True)).hexdigest()==expected_hash
  stream.settimeout(4);binding=b''
  while not binding.endswith(b'\n'):binding+=stream.recv(1);assert len(binding)<2048
  assert json.loads(binding)=={'purpose':'sa0-terminal-spike','server':'server-linux','account':'fixture'}
  stream.sendall(json.dumps({'type':'input','data':"stty -F /dev/tty size; printf 'SA0_OUTBOUND_PTY\\n'\n"}).encode()+b'\n')
  received=b''
  while b'24 80' not in received:received+=stream.recv(4096);assert len(received)<65536
  stream.sendall(json.dumps({'type':'resize','rows':40,'cols':120}).encode()+b'\n');time.sleep(.2)
  stream.sendall(json.dumps({'type':'input','data':"stty -F /dev/tty size\n"}).encode()+b'\n')
  while b'40 120' not in received:received+=stream.recv(4096);assert len(received)<65536
  # Independent shutdown, no renewal/push; not a product CP authority callback.
  start=time.monotonic()
  def end():
   try:stream.shutdown(socket.SHUT_RDWR)
   except OSError:pass
  watchdog=threading.Timer(.3,end);watchdog.start()
  try:
   while stream.recv(4096):pass
  except OSError:pass
  watchdog.join();elapsed=time.monotonic()-start
  print(json.dumps({'gateway_mtls_pinned':True,'outbound_only':True,'pty_roundtrip':True,'resize_roundtrip':True,'watchdog_seconds':round(elapsed,3),'authority':'fixture, not product CP authorization'}),flush=True)
