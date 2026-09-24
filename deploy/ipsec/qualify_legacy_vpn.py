#!/usr/bin/env python3
"""Reviewed disposable candidate-image WG/OpenVPN payload proof; no host config."""
import io
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time
import uuid

DOCKER=["docker","--context","colima-f10-dev"]
PROJECT="tunnexs2scompat0924"
NETWORK=PROJECT+"-internal"
IMAGE="sha256:7e29f9e72a30513b486afd68aca925c757d436081c1bfe0808db248033a949ef"
TMPFS={"/run/compat":"rw,nosuid,nodev,mode=0700,size=8m"}
containers={}
network_id=None

def read(args):
    return subprocess.check_output(DOCKER+args,text=True,timeout=30)

def absent(kind,name):
    if subprocess.run(DOCKER+[kind,"inspect",name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30).returncode==0:
        raise RuntimeError("refusing existing lab resource")

def check_network():
    n=json.loads(read(["network","inspect",network_id]))[0]
    if not(n["Id"]==network_id and n["Name"]==NETWORK and n["Driver"]=="bridge" and n["Internal"]
        and not n.get("Ingress") and n["Labels"].get("com.docker.compose.project")==PROJECT
        and set(n.get("Containers",{})).issubset(set(containers.values()))):
        raise RuntimeError("internal lab network ownership mismatch")

def check(role):
    check_network()
    obj=json.loads(read(["inspect",containers[role]]))[0];h=obj["HostConfig"]
    caps={x.removeprefix("CAP_") for x in h.get("CapAdd",[])}
    devices=[{"PathOnHost":"/dev/net/tun","PathInContainer":"/dev/net/tun","CgroupPermissions":"rw"}]
    if not(obj["Id"]==containers[role] and obj["Name"]=="/"+PROJECT+"-"+role and obj["Image"]==IMAGE
        and obj["Config"]["Labels"].get("com.docker.compose.project")==PROJECT
        and h["NetworkMode"]==NETWORK and not h["Privileged"] and h["ReadonlyRootfs"]
        and h["CapDrop"]==["ALL"] and caps=={"NET_ADMIN","NET_RAW"}
        and not h.get("Binds") and h.get("Tmpfs")==TMPFS and not h.get("PortBindings")
        and h.get("Devices")==devices and h.get("PidMode")!="host"
        and all(m["Type"]=="tmpfs" and m["Destination"]=="/run/compat" for m in obj["Mounts"])
        and set(obj["NetworkSettings"]["Networks"])=={NETWORK}):
        raise RuntimeError("lab container isolation mismatch")
    return obj

def execute(role,args,data=None,check_result=True):
    check(role)
    p=subprocess.run(DOCKER+["exec"]+(["-i"] if data is not None else [])+[containers[role]]+args,
        input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    if check_result and p.returncode:
        # Commands contain paths/public identities only, never secret input.
        raise RuntimeError("lab command failed: "+str(args)+"; "+p.stderr.decode(errors="replace"))
    return p

def put_files(role,files):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode="w") as archive:
        for name,body in files.items():
            item=tarfile.TarInfo(name);item.size=len(body);item.mode=0o600
            archive.addfile(item,io.BytesIO(body))
    execute(role,["tar","-x","-C","/run/compat"],stream.getvalue())

def make_certificates(directory):
    def ssl(*args):
        subprocess.run(["openssl",*args],cwd=directory,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=30)
    ssl("req","-x509","-newkey","rsa:2048","-nodes","-keyout","ca.key","-out","ca.crt","-days","1","-subj","/CN=tunnex-synthetic-compat-ca","-addext","basicConstraints=critical,CA:TRUE")
    for i,role in enumerate(("server","client"),1):
        ssl("req","-new","-newkey","rsa:2048","-nodes","-keyout",role+".key","-out",role+".csr","-subj","/CN=tunnex-synthetic-"+role)
        (directory/(role+".ext")).write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage="+("serverAuth" if role=="server" else "clientAuth")+"\n")
        ssl("x509","-req","-in",role+".csr","-CA","ca.crt","-CAkey","ca.key","-set_serial",str(i),"-out",role+".crt","-days","1","-extfile",role+".ext")

def payload(role,address,interface,expected):
    route=execute(role,["ip","route","get",address]).stdout.decode()
    if "dev "+interface+" " not in route:
        raise RuntimeError("payload route does not use tunnel")
    actual=execute(role,["wget","-T","3","-qO-","http://"+address+":8080/payload"]).stdout
    if actual!=expected:
        raise RuntimeError("tunnel payload mismatch")

def main():
    global network_id
    os.umask(0o077)
    print("COMPOSE_PROJECT_NAME="+PROJECT+" exact image="+IMAGE,flush=True)
    endpoint=json.loads(read(["context","inspect","colima-f10-dev"]))[0]["Endpoints"]["docker"]["Host"]
    if not endpoint.startswith("unix://") or not endpoint.endswith("/.colima/f10-dev/docker.sock"):
        raise RuntimeError("unexpected Docker endpoint")
    info=json.loads(read(["info","--format","{{json .}}"] ))
    if info["OSType"]!="linux" or info["Architecture"] not in ("aarch64","arm64"):
        raise RuntimeError("compatibility fixture requires native Linux ARM64")
    image=json.loads(read(["image","inspect",IMAGE]))[0]
    if image["Id"]!=IMAGE or image["Architecture"]!="arm64":raise RuntimeError("wrong candidate image")
    absent("network",NETWORK)
    for role in ("server","client"):absent("container",PROJECT+"-"+role)
    evidence=Path(tempfile.mkdtemp(prefix="s2s-vpn-compat-evidence-",dir="/private/tmp"))
    expected=("synthetic-vpn-payload-"+str(uuid.uuid4())).encode()
    print("Evidence="+str(evidence),flush=True)
    try:
        network_id=read(["network","create","--internal","--driver","bridge","--label","com.docker.compose.project="+PROJECT,NETWORK]).strip()
        check_network()
        for role in ("server","client"):
            cid=read(["create","--name",PROJECT+"-"+role,"--label","com.docker.compose.project="+PROJECT,
                "--network",NETWORK,"--cap-drop","ALL","--cap-add","NET_ADMIN","--cap-add","NET_RAW",
                "--device","/dev/net/tun:/dev/net/tun:rw","--read-only","--tmpfs","/run/compat:"+TMPFS["/run/compat"],
                "--security-opt","no-new-privileges","--pids-limit","96","--memory","256m","--entrypoint","/bin/sh",IMAGE,"-c","sleep 300"]).strip()
            containers[role]=cid;check(role)
            subprocess.run(DOCKER+["start",cid],check=True,stdout=subprocess.DEVNULL,timeout=30)
        print("Verified two owned readonly candidate endpoints; internal network, tmpfs credentials, only TUN device",flush=True)
        addresses={role:str(ipaddress.IPv4Address(check(role)["NetworkSettings"]["Networks"][NETWORK]["IPAddress"])) for role in containers}
        execute("server",["mkdir","-m","700","/run/compat/www"])
        put_files("server",{"www/payload":expected})
        applets=execute("server",["busybox","--list"]).stdout.decode().splitlines()
        (evidence/"busybox-applets.txt").write_text("\n".join(applets))
        if "nc" not in applets:raise RuntimeError("candidate lacks bounded payload-listener applet")
        # Alpine's minimal BusyBox need not include httpd. Existing nc suffices;
        # send a fixed-length synthetic response and retain no request content.
        listener="while true; do { printf 'HTTP/1.1 200 OK\\r\\nConnection: close\\r\\nContent-Length: "+str(len(expected))+"\\r\\n\\r\\n'; cat /run/compat/www/payload; } | busybox nc -l -p 8080 -w 3 >/dev/null; done"
        check("server")
        subprocess.run(DOCKER+["exec","-d",containers["server"],"sh","-c",listener],check=True,timeout=30)
        # Baseline has no overlay destination; exact payload cannot pass yet.
        if execute("client",["wget","-T","1","-qO-","http://10.77.0.1:8080/payload"],check_result=False).returncode==0:
            raise RuntimeError("WG baseline unexpectedly reachable")
        pubs={}
        for role in containers:
            # No private-key argument, stdout, key dump or persistent host file.
            pubs[role]=execute(role,["sh","-c","umask 077; wg genkey | tee /run/compat/wg.key | wg pubkey"]).stdout.decode().strip()
            execute(role,["ip","link","add","wgcompat","type","wireguard"])
        for role,octet in (("server",1),("client",2)):
            peer="client" if role=="server" else "server";other=2 if octet==1 else 1
            execute(role,["wg","set","wgcompat","private-key","/run/compat/wg.key","listen-port","51820","peer",pubs[peer],"allowed-ips","10.77.0."+str(other)+"/32","endpoint",addresses[peer]+":51820","persistent-keepalive","1"])
            execute(role,["ip","addr","add","10.77.0."+str(octet)+"/24","dev","wgcompat"])
            execute(role,["ip","link","set","wgcompat","up"])
        execute("client",["ping","-c","2","-W","2","-I","wgcompat","10.77.0.1"])
        payload("client","10.77.0.1","wgcompat",expected)
        for role in containers:
            handshakes=execute(role,["wg","show","wgcompat","latest-handshakes"]).stdout.decode().splitlines()
            if len(handshakes)!=1 or int(handshakes[0].split()[1])<=0:raise RuntimeError("WG handshake absent")
        execute("client",["ip","link","set","wgcompat","down"])
        if execute("client",["wget","-T","1","-qO-","http://10.77.0.1:8080/payload"],check_result=False).returncode==0:raise RuntimeError("WG down control passed")
        execute("client",["ip","link","set","wgcompat","up"])
        print("WireGuard: both kernel handshakes + exact HTTP payload + interface-down refusal PASS",flush=True)
        with tempfile.TemporaryDirectory(prefix="s2s-synthetic-pki-",dir="/private/tmp") as folder:
            pki=Path(folder);make_certificates(pki)
            for role,octet in (("server",1),("client",2)):
                peer="client" if role=="server" else "server";other=2 if octet==1 else 1
                config=("dev ovpncompat\ndev-type tun\nproto udp\nport 1194\nremote "+addresses[peer]+" 1194\n"
                    +"tls-"+role+"\nifconfig 10.78.0."+str(octet)+" 10.78.0."+str(other)+"\n"
                    +"ca /run/compat/ca.crt\ncert /run/compat/leaf.crt\nkey /run/compat/leaf.key\n"
                    +"remote-cert-tls "+peer+"\nverify-x509-name tunnex-synthetic-"+peer+" name\n"
                    +"tls-version-min 1.2\ndata-ciphers AES-256-GCM\ndata-ciphers-fallback AES-256-GCM\n"
                    +("dh none\n" if role=="server" else "")
                    +"tmp-dir /run/compat\nverb 3\nlog /run/compat/openvpn.log\nwritepid /run/compat/openvpn.pid\n")
                put_files(role,{"ca.crt":(pki/"ca.crt").read_bytes(),"leaf.crt":(pki/(role+".crt")).read_bytes(),"leaf.key":(pki/(role+".key")).read_bytes(),"openvpn.conf":config.encode()})
        for role in containers:
            start=execute(role,["openvpn","--config","/run/compat/openvpn.conf","--daemon"],check_result=False)
            if start.returncode:
                log=execute(role,["cat","/run/compat/openvpn.log"],check_result=False).stdout
                (evidence/(role+"-openvpn.log")).write_bytes(log)
                raise RuntimeError("OpenVPN startup failed; synthetic nonsecret log retained")
        deadline=time.monotonic()+30
        while True:
            logs={role:execute(role,["cat","/run/compat/openvpn.log"]).stdout.decode() for role in containers}
            if all("Initialization Sequence Completed" in log for log in logs.values()):break
            if time.monotonic()>=deadline:
                for role,log in logs.items():(evidence/(role+"-openvpn.log")).write_text(log)
                raise RuntimeError("OpenVPN TLS readiness timed out; synthetic nonsecret logs retained")
            time.sleep(0.5)
        execute("client",["ping","-c","2","-W","2","-I","ovpncompat","10.78.0.1"])
        payload("client","10.78.0.1","ovpncompat",expected)
        payload("client","10.77.0.1","wgcompat",expected)
        for role,log in logs.items():
            if "Peer Connection Initiated" not in log:raise RuntimeError("OpenVPN authenticated peer evidence absent")
            (evidence/(role+"-openvpn.log")).write_text(log)
        pid=int(execute("client",["cat","/run/compat/openvpn.pid"]).stdout.strip())
        if pid<=1:raise RuntimeError("invalid owned OpenVPN pid")
        executable=execute("client",["sh","-c","command -v openvpn"]).stdout.decode().strip()
        canonical=execute("client",["readlink","-f",executable]).stdout.decode().strip()
        observed=execute("client",["readlink","/proc/"+str(pid)+"/exe"]).stdout.decode().strip()
        if not canonical.startswith("/") or observed!=canonical:
            raise RuntimeError("owned OpenVPN pid executable mismatch")
        execute("client",["busybox","kill",str(pid)])
        time.sleep(0.5)
        if execute("client",["wget","-T","1","-qO-","http://10.78.0.1:8080/payload"],check_result=False).returncode==0:raise RuntimeError("OpenVPN stopped control passed")
        result={"image":IMAGE,"native_architecture":"arm64","wireguard_handshake_and_payload":True,"openvpn_tls_and_payload":True,"both_running_payload":True,"loss_controls_refused":True,"ipsec_coexistence":"not tested"}
        (evidence/"result.json").write_text(json.dumps(result,indent=2))
        print("OpenVPN: mutual TLS + exact HTTP payload + daemon-stop refusal PASS; WG still passes while OpenVPN runs",flush=True)
    finally:
        for role,cid in list(containers.items()):
            check(role)
            subprocess.run(DOCKER+["rm","-f",cid],check=True,stdout=subprocess.DEVNULL,timeout=30)
        if network_id:
            check_network()
            subprocess.run(DOCKER+["network","rm",network_id],check=True,stdout=subprocess.DEVNULL,timeout=30)
        print("Removed only newly captured owned endpoints/internal network; synthetic tmpfs keys gone",flush=True)

if __name__=="__main__":main()
