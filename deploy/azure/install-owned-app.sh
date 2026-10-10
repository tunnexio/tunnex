#!/usr/bin/env bash
# Run via Azure bastion az vm run-command only on the owned private target.
set -euo pipefail
[[ $(hostname) == azure-target ]] || { echo 'Foreign host refused'; exit 1; }
install -d -m 755 /opt/tunnex-azure-lab
cat > /opt/tunnex-azure-lab/app.py <<'PYAPP'
#!/usr/bin/env python3
"""Owned lab private HTTP/UDP service; no credentials or cloud calls."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json,socket,threading
class Handler(BaseHTTPRequestHandler):
    protocol_version="HTTP/1.1"
    def do_GET(self):
        body=json.dumps({'service':'azure-s2s-owned-app','client_ip':self.client_address[0]}).encode()
        self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*args):pass
def udp():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('0.0.0.0',8081))
    while True:
        payload,peer=s.recvfrom(65535);s.sendto(payload,peer)
threading.Thread(target=udp,daemon=True).start()
ThreadingHTTPServer(('0.0.0.0',8080),Handler).serve_forever()
PYAPP
cat > /etc/systemd/system/tunnex-azure-lab-app.service <<'UNIT'
[Unit]
Description=Owned Azure S2S private test service
After=network.target
[Service]
ExecStart=/usr/bin/python3 /opt/tunnex-azure-lab/app.py
User=nobody
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable tunnex-azure-lab-app.service
systemctl restart tunnex-azure-lab-app.service
systemctl is-active tunnex-azure-lab-app.service
