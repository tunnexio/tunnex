#!/usr/bin/env python3
"""Owned namespace reverse target: bounded HTTP1.1 keepalive and UDP echo, no payload logging."""
import argparse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import ipaddress
import json
from pathlib import Path
import socket
import threading
import time

spec=importlib.util.spec_from_file_location('owned_probe',Path(__file__).with_name('probe-packets.py'))
probe=importlib.util.module_from_spec(spec);spec.loader.exec_module(probe)
LARGE_BODY=b'0123456789abcdef'*4096

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--seconds',type=int,default=300)
 parser.add_argument('--receipt',type=Path,required=True)
 args=parser.parse_args()
 if not 1<=args.seconds<=600:raise ValueError('Bounded1..600second service lifetime required')
 lock=threading.Lock();stop=threading.Event();deadline=time.monotonic()+args.seconds
 state={'service':'azure-s2s-owned-lan-app','listen_address':'10.233.10.2','tcp_port':8082,'udp_port':8083,'started_at':probe.stamp(),'tcp_requests':0,'udp_echoes':0,'source_observations':[],'scope':'Actual target source metadata only; no payload, policy or health assertion'}
 def record(kind,source):
  address=ipaddress.ip_address(source)
  allowed=source in ('10.231.1.4','10.232.1.4') or address in ipaddress.ip_network('10.233.10.0/24') or address in ipaddress.ip_network('172.16.0.0/12')
  with lock:
   state[kind]+=1
   if len(state['source_observations'])<2048:
    item={'observed_at':probe.stamp(),'transport':'tcp' if kind=='tcp_requests' else 'udp','source_class':'owned_or_private' if allowed else 'unrecognized'}
    if allowed:item['server_observed_client_ip']=source
    state['source_observations'].append(item)
   probe.receipt(args.receipt,state)
 class Handler(BaseHTTPRequestHandler):
  protocol_version='HTTP/1.1'
  def do_GET(self):
   record('tcp_requests',self.client_address[0])
   body=LARGE_BODY if self.path=='/large' else json.dumps({'service':'azure-s2s-owned-lan-app','client_ip':self.client_address[0]}).encode()
   self.send_response(200);self.send_header('Content-Type','application/octet-stream' if self.path=='/large' else 'application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
  def log_message(self,*args):pass
  def handle(self):
   try:super().handle()
   except (OSError,ValueError):pass
 class Server(ThreadingHTTPServer):
  daemon_threads=True
  def handle_error(self,*args):pass
 server=Server(('10.233.10.2',8082),Handler);server.timeout=.5
 udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('10.233.10.2',8083));udp.settimeout(.5)
 def echo_loop():
  while not stop.is_set() and time.monotonic()<deadline:
   try:
    payload,peer=udp.recvfrom(4097)
    if len(payload)>4096:continue
    record('udp_echoes',peer[0]);udp.sendto(payload,peer)
   except socket.timeout:continue
   except OSError:break
 worker=threading.Thread(target=echo_loop,daemon=True);worker.start()
 probe.receipt(args.receipt,state)
 try:
  while time.monotonic()<deadline:server.handle_request()
 finally:
  stop.set();udp.close();server.server_close();worker.join(timeout=1)
  with lock:state['finished_at']=probe.stamp();probe.receipt(args.receipt,state)
 print('Owned LAN service bounded run finished; actual metadata saved privately')

if __name__=='__main__':
 try:main()
 except (OSError,ValueError):raise SystemExit('Owned LAN service prerequisite/input failed')
