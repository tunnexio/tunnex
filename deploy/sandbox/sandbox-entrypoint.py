#!/usr/bin/python3
"""Fixed unprivileged SSH foreground process; no service manager or installs."""
import os
import stat
import sys


def main():
    if len(sys.argv) != 1 or os.geteuid() != 1001 or os.getegid() != 1001:
        raise RuntimeError("sandbox runtime identity unavailable")
    parent = os.lstat("/run")
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 1001:
        raise RuntimeError("sandbox runtime directory unavailable")
    try:
        os.mkdir("/run/sshd", 0o755)
    except FileExistsError:
        pass
    directory = os.lstat("/run/sshd")
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 1001
            or directory.st_mode & 0o022):
        raise RuntimeError("sandbox SSH directory unavailable")
    os.execv("/usr/sbin/sshd", ["/usr/sbin/sshd", "-D", "-e", "-f",
                              "/run/tunnex-ssh/sshd_config"])


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError):
        print("sandbox terminal unavailable", file=sys.stderr)
        sys.exit(1)
