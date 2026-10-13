#!/usr/bin/env python3
"""Hash explicit product build inputs; never walk private harness runtime files."""
import argparse,hashlib,json,pathlib
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
repo=pathlib.Path(__file__).resolve().parents[2]
prefixes=['apps/api','apps/node','packages/apptransport','deploy/ipsec','deploy/bgp','deploy/docker/node.Dockerfile'];files={}
for prefix in prefixes:
 path=repo/prefix
 for f in ([path]if path.is_file()else path.rglob('*')):
  if not f.is_file()or any(v in ['.runtime','.git','node_modules','__pycache__']for v in f.parts):continue
  if f.name in ['.env','.DS_Store']:continue
  assert not f.is_symlink(),'Build source symlink requires explicit review'
  files[str(f.relative_to(repo))]=hashlib.sha256(f.read_bytes()).hexdigest()
def digest(selected):return hashlib.sha256(json.dumps(selected,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def subset(prefixes):return {k:v for k,v in files.items()if any(k==p or k.startswith(p+'/')for p in prefixes)}
manifest={'source_files':files,'source_snapshot_sha256':digest(files),'mounted_api_source_sha256':digest(subset(['apps/api','packages/apptransport'])),'mounted_node_source_sha256':digest(subset(['apps/node','packages/apptransport'])),'image_source_sha256':digest(subset(['apps/node','packages/apptransport','deploy/ipsec','deploy/bgp','deploy/docker/node.Dockerfile']))}
a.output.write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
