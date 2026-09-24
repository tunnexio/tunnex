#!/usr/bin/env python3
"""Authenticate one pinned upstream source before any extraction or build."""
import hashlib
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

VERSION = "6.1.0"
ARCHIVE = "strongswan-6.1.0.tar.gz"
SHA256 = "d9484eea319481bda86f992fa69cbdbdd9c0d6f8b9a4bd793a7df45c0760d963"
FINGERPRINT = "948F158A4E76A27BF3D07532DF42C170B34DBA77"
MAX_ARCHIVE = 20 * 1024 * 1024
MAX_EXPANDED = 200 * 1024 * 1024
MAX_ENTRIES = 30000

class InvalidSource(Exception):
    pass

def verify_digest(path):
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_ARCHIVE:
        raise InvalidSource()
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != SHA256:
        raise InvalidSource()

def valid_signature_status(status):
    lines = [line.split() for line in status.splitlines()]
    rejected = {"BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY", "FAILURE"}
    if any(len(line)>1 and line[0]=="[GNUPG:]" and line[1] in rejected for line in lines):
        return False
    valid = [line for line in lines if len(line)>2 and line[:2]==["[GNUPG:]", "VALIDSIG"]]
    return len(valid)==1 and valid[0][2]==FINGERPRINT

def verify_signature(archive, assets):
    with tempfile.TemporaryDirectory(prefix="ipsec-keyring-") as home:
        command = ["gpg", "--batch", "--no-autostart", "--homedir", home, "--no-auto-key-retrieve"]
        subprocess.run(command+["--import",str(assets/"STRONGSWAN-RELEASE-PGP-KEY")], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        result = subprocess.run(command+["--status-fd", "1", "--verify",str(assets/(ARCHIVE+".sig")),str(archive)], check=True, capture_output=True, text=True, timeout=15)
        if not valid_signature_status(result.stdout):
            raise InvalidSource()

def verify_archive_layout(path):
    names = set()
    total = 0
    with tarfile.open(path, "r:gz") as archive:
        for entry in archive:
            name = PurePosixPath(entry.name)
            total += entry.size
            if (name.is_absolute() or ".." in name.parts or not name.parts or name.parts[0] != "strongswan-6.1.0"
                or str(name) in names or not (entry.isfile() or entry.isdir()) or entry.size < 0
                or (len(name.parts)==1 and not entry.isdir()) or total > MAX_EXPANDED or len(names)>=MAX_ENTRIES):
                raise InvalidSource()
            names.add(str(name))
    if not names:
        raise InvalidSource()

def prepare(output):
    # Build-only fetch, fixed public URL; runtime has no downloader or source script execution.
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    archive = output/ARCHIVE
    with urllib.request.urlopen("https://download.strongswan.org/"+ARCHIVE, timeout=60) as response:
        with archive.open("xb") as dest:
            count=0
            while chunk:=response.read(65536):
                count+=len(chunk)
                if count>MAX_ARCHIVE:
                    raise InvalidSource()
                dest.write(chunk)
    assets=Path(__file__).resolve().parent
    verify_digest(archive)
    verify_signature(archive, assets)
    verify_archive_layout(archive)
    with tarfile.open(archive, "r:gz") as source:
        source.extractall(output, filter="data")
    for name in (ARCHIVE+".sig","STRONGSWAN-RELEASE-PGP-KEY"):
        shutil.copyfile(assets/name,output/name)

if __name__=="__main__":
    try:
        if len(sys.argv)!=2:
            raise InvalidSource()
        prepare(Path(sys.argv[1]))
    except (InvalidSource,OSError,ValueError,tarfile.TarError,subprocess.SubprocessError):
        sys.exit("IPsec source verification failed")
