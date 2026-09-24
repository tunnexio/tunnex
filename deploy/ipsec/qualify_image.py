#!/usr/bin/env python3
"""Main-agent-reviewed local build/content smoke. Does not run packet labs or publish."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

PROJECT = "tunnexs2spackage0924"
DOCKER = ["docker", "--context", "colima-f10-dev"]
TAG = PROJECT + ":node-arm64"
NAME = PROJECT + "-contents"
ROOT = Path(__file__).resolve().parents[2]
ASSETS = ["build.sh", "verify_source.py", "verify_runtime.sh", "PROVENANCE.json", "NOTICE", "STRONGSWAN-RELEASE-PGP-KEY", "strongswan-6.1.0.tar.gz.sig"]

def read(args):
    return subprocess.check_output(DOCKER+args, text=True)

def refuse_existing(kind, name):
    if subprocess.run(DOCKER+[kind,"inspect",name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode==0:
        raise RuntimeError("refusing preexisting qualification resource")

def validate_container(cid,image):
    obj=json.loads(read(["inspect",cid]))[0]
    host=obj["HostConfig"]
    if not (obj["Id"]==cid and obj["Name"]=="/"+NAME and obj["Image"]==image
            and obj["Config"]["Labels"].get("com.docker.compose.project")==PROJECT
            and host["NetworkMode"]=="none" and host["ReadonlyRootfs"]
            and host["CapDrop"]==["ALL"] and not host.get("CapAdd")
            and not host["Privileged"] and not host.get("Binds") and not obj["Mounts"]
            and not host.get("Devices") and not host.get("PortBindings")
            and host.get("PidMode")!="host"):
        raise RuntimeError("qualification container isolation mismatch")
    print("Verified owned container="+cid+" network=none, no mounts/ports/capabilities",flush=True)

def main():
    print("COMPOSE_PROJECT_NAME="+PROJECT,flush=True)
    context=json.loads(read(["context","inspect","colima-f10-dev"]))[0]
    endpoint=context["Endpoints"]["docker"]["Host"]
    if not endpoint.startswith("unix://") or not endpoint.endswith("/.colima/f10-dev/docker.sock"):
        raise RuntimeError("unexpected Docker endpoint")
    info=json.loads(read(["info","--format","{{json .}}"] ))
    if info["OSType"]!="linux" or info["Architecture"] not in ("aarch64","arm64"):
        raise RuntimeError("this smoke is native Linux ARM64 only")
    refuse_existing("image",TAG)
    refuse_existing("container",NAME)
    work=Path(tempfile.mkdtemp(prefix="s2s-packaging-build-",dir="/private/tmp"))
    print("Local evidence/context="+str(work),flush=True)
    contextdir=work/"context"
    # Production Go source only: no test fixtures, .git, .env, keys or caches.
    files=[p for p in (ROOT/"apps/node").rglob("*.go") if not p.name.endswith("_test.go")]
    files += [ROOT/"apps/node/go.mod",ROOT/"apps/node/go.sum",ROOT/"deploy/docker/node.Dockerfile"]
    files += [ROOT/"deploy/ipsec"/name for name in ASSETS]
    digests={}
    for src in files:
        if src.is_symlink() or not src.is_file():
            raise RuntimeError("unexpected build input")
        rel=src.relative_to(ROOT)
        target=contextdir/rel
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(src,target)
        digests[str(rel)]=hashlib.sha256(target.read_bytes()).hexdigest()
    (work/"input-sha256.json").write_text(json.dumps(digests,sort_keys=True,indent=2))
    env=dict(os.environ,COMPOSE_PROJECT_NAME=PROJECT)
    with (work/"build.log").open("w") as log:
        subprocess.run(DOCKER+["build","--platform","linux/arm64","--network=default",
            "--label","com.docker.compose.project="+PROJECT,"--build-arg","VERSION=s2s-local",
            "-f","deploy/docker/node.Dockerfile","-t",TAG,"."],cwd=contextdir,env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
    image=json.loads(read(["image","inspect",TAG]))[0]
    if image["Architecture"]!="arm64" or image["Config"]["Entrypoint"]!=["/usr/local/bin/tunnex-node"]:
        raise RuntimeError("unexpected built image")
    (work/"image.json").write_text(json.dumps(image,indent=2))
    cid=None
    try:
        cid=read(["create","--name",NAME,"--label","com.docker.compose.project="+PROJECT,
            "--network","none","--read-only","--cap-drop","ALL","--security-opt","no-new-privileges",
            "--pids-limit","64","--memory","256m","--entrypoint","/bin/sh",image["Id"],
            "/usr/share/tunnex-ipsec/verify_runtime.sh"]).strip()
        validate_container(cid,image["Id"])
        with (work/"contents.log").open("w") as log:
            subprocess.run(DOCKER+["start","-a",cid],stdout=log,stderr=subprocess.STDOUT,check=True)
        validate_container(cid,image["Id"])
        state=json.loads(read(["inspect",cid]))[0]["State"]
        if state["Running"] or state["ExitCode"]!=0:
            raise RuntimeError("image content smoke failed")
    finally:
        if cid:
            validate_container(cid,image["Id"])
            subprocess.run(DOCKER+["rm","-f",cid],check=True,stdout=subprocess.DEVNULL)
    print("Native ARM64 build/content smoke passed; packet/coexistence gates still pending. Evidence="+str(work),flush=True)

if __name__=="__main__":
    main()
