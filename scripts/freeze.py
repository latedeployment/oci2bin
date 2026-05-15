#!/usr/bin/env python3
"""
oci2bin freeze / thaw — application-consistent volume quiesce.

Use these around an external backup tool (restic, borg, rsync, zfs send)
when the container is writing to a SQLite-backed database:

    oci2bin freeze vaultwarden -- \
        restic -r b2:my-bucket backup ~/vw-data

For a standalone lifecycle (e.g. a cron job that schedules the snapshot
and a later cron job that clears it):

    oci2bin freeze vaultwarden     # take snapshots, write token
    # ...run external backup over the volume...
    oci2bin thaw vaultwarden       # delete the snapshot files

What it actually does
---------------------
Walks `/proc/<pid>/root/` (the running container's mount-namespaced view
of its own filesystem) under common data prefixes, finds every `*.db`,
`*.sqlite`, `*.sqlite3` file, and runs `sqlite3 <db> '.backup <db>.oci2bin-snap'`
inside the container's mount + PID namespace via `nsenter`. That gives a
crash-consistent snapshot file that any host-side backup tool can read
safely while the live database keeps taking writes.

If `sqlite3` is not present inside the container, the freeze fails fast
with a clear message — install it in the image, or provide a custom
freeze hook (planned).

Limitations
-----------
- Only handles SQLite-based applications today. Postgres / MySQL / Redis
  hooks and fsfreeze fallback are planned follow-ups.
- Requires `nsenter` on the host. Rootless invocations need the container
  to be in a user namespace the caller can join (the normal oci2bin
  rootless flow already handles this).
- Token files live at `$HOME/.local/share/oci2bin/freeze/<name>.json`.
"""

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path


VALID_NAME = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]*$')
DB_SUFFIXES = ('.db', '.sqlite', '.sqlite3')
WALK_SKIP_PREFIXES = (
    'proc', 'sys', 'dev', 'run', 'tmp', 'var/cache', 'var/tmp',
    'usr', 'lib', 'lib64', 'bin', 'sbin', 'boot',
    'media', 'mnt', '.oci2bin', 'etc',
)
MAX_DEPTH = 6


def _state_dir():
    home = os.environ.get('HOME', '')
    if not home or not os.path.isabs(home):
        print("oci2bin: HOME must be an absolute path", file=sys.stderr)
        sys.exit(1)
    return Path(home) / '.cache' / 'oci2bin' / 'containers'


def _freeze_token_dir():
    home = os.environ.get('HOME', '')
    if not home or not os.path.isabs(home):
        print("oci2bin: HOME must be an absolute path", file=sys.stderr)
        sys.exit(1)
    return Path(home) / '.local' / 'share' / 'oci2bin' / 'freeze'


def load_state(name):
    """Return (pid:int, binary:str, start_ticks:int) for the container, or
    fail with a clear error. Mirrors the validation done by `oci2bin stop`."""
    if not VALID_NAME.match(name):
        print(f"oci2bin: invalid container name '{name}'", file=sys.stderr)
        sys.exit(1)
    state_file = _state_dir() / f'{name}.json'
    if not state_file.is_file():
        print(f"oci2bin: no container named '{name}'", file=sys.stderr)
        sys.exit(1)
    if state_file.is_symlink():
        print(f"oci2bin: refusing symlinked state file '{state_file}'",
              file=sys.stderr)
        sys.exit(1)
    with state_file.open(encoding='utf-8') as f:
        data = json.load(f)
    pid = int(data.get('pid', 0))
    binary = data.get('binary', '')
    start_ticks = int(data.get('start_ticks', 0))
    if pid <= 0 or not binary:
        print(f"oci2bin: state file for '{name}' is malformed",
              file=sys.stderr)
        sys.exit(1)
    return pid, binary, start_ticks


def ensure_alive(pid, binary, start_ticks):
    """Verify the recorded PID is still the container's PID 1."""
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        print(f"oci2bin: PID {pid} is not running", file=sys.stderr)
        sys.exit(1)
    try:
        exe = os.readlink(f'/proc/{pid}/exe')
    except OSError as exc:
        print(f"oci2bin: cannot read /proc/{pid}/exe: {exc}", file=sys.stderr)
        sys.exit(1)
    if exe != binary:
        print(f"oci2bin: PID {pid} exe '{exe}' != expected '{binary}'",
              file=sys.stderr)
        sys.exit(1)
    if start_ticks:
        with open(f'/proc/{pid}/stat', encoding='utf-8') as f:
            raw = f.read().strip()
        rparen = raw.rfind(')')
        if rparen > 0:
            fields = raw[rparen + 2:].split()
            if len(fields) > 19 and fields[19] != str(start_ticks):
                print(f"oci2bin: PID {pid} start_ticks changed",
                      file=sys.stderr)
                sys.exit(1)


def find_databases_in_rootfs(root):
    """Walk `root` and return [(container_path, host_path), ...] for every
    `*.db`/`*.sqlite`/`*.sqlite3` file outside the well-known system
    prefixes. Exposed for testing — production code goes through
    find_databases() which derives root from the PID."""
    found = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel = os.path.relpath(dirpath, root)
        if rel == '.':
            rel = ''
        if any(rel == p or rel.startswith(p + '/')
               for p in WALK_SKIP_PREFIXES):
            dirnames[:] = []
            continue
        if rel.count('/') > MAX_DEPTH:
            dirnames[:] = []
            continue
        for name in filenames:
            if name.endswith(DB_SUFFIXES):
                host_path = os.path.join(dirpath, name)
                ctr_path = '/' + (os.path.join(rel, name) if rel else name)
                found.append((ctr_path, host_path))
    found.sort()
    return found


def find_databases(pid):
    """Return a list of (container_path, host_path) for SQLite files
    visible inside the container's rootfs."""
    root = f'/proc/{pid}/root'
    if not os.path.isdir(root):
        print(f"oci2bin: cannot enter container rootfs at {root}",
              file=sys.stderr)
        sys.exit(1)
    return find_databases_in_rootfs(root)


def snapshot_one(pid, ctr_path):
    """Run sqlite3 .backup inside the container's namespace.

    Returns the container path of the snapshot file on success, or None
    if sqlite3 is absent / the backup failed (caller decides whether to
    abort or skip).
    """
    snap_path = f'{ctr_path}.oci2bin-snap'
    cmd = [
        'nsenter', '-t', str(pid), '-m', '-p', '--',
        'sqlite3', ctr_path, f'.backup {snap_path}',
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60, check=False)
    except FileNotFoundError:
        print("oci2bin: 'nsenter' not found on the host PATH",
              file=sys.stderr)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"oci2bin: sqlite3 .backup of {ctr_path} timed out after 60s",
              file=sys.stderr)
        return None
    if result.returncode != 0:
        msg = (result.stderr or result.stdout).strip()
        if 'sqlite3' in msg and 'No such file' in msg:
            print(f"oci2bin: sqlite3 not present in the container image —"
                  f" install it or skip this DB ({ctr_path})",
                  file=sys.stderr)
        else:
            print(f"oci2bin: sqlite3 .backup of {ctr_path} failed: {msg}",
                  file=sys.stderr)
        return None
    return snap_path


def remove_snapshot(pid, snap_ctr_path):
    """Best-effort delete of a snapshot file inside the container ns."""
    cmd = [
        'nsenter', '-t', str(pid), '-m', '-p', '--',
        'rm', '-f', snap_ctr_path,
    ]
    try:
        subprocess.run(cmd, capture_output=True, check=False, timeout=15)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass


def _write_token(name, pid, snaps):
    token_dir = _freeze_token_dir()
    token_dir.mkdir(parents=True, exist_ok=True)
    token = token_dir / f'{name}.json'
    payload = {
        'name': name,
        'pid': pid,
        'snaps': snaps,
        'taken_at': int(time.time()),
    }
    tmp = token.with_suffix('.json.tmp')
    with tmp.open('w', encoding='utf-8') as f:
        json.dump(payload, f, indent=2)
    os.replace(tmp, token)
    return token


def _read_token(name):
    token = _freeze_token_dir() / f'{name}.json'
    if not token.is_file():
        return None
    with token.open(encoding='utf-8') as f:
        return json.load(f)


def cmd_freeze(name, command):
    pid, binary, start_ticks = load_state(name)
    ensure_alive(pid, binary, start_ticks)

    dbs = find_databases(pid)
    if not dbs:
        print(f"oci2bin freeze: no *.db/*.sqlite files found in container"
              f" '{name}' rootfs (depth ≤ {MAX_DEPTH})", file=sys.stderr)
        if command:
            # Still run the command — the volume may not be sqlite-backed.
            print("oci2bin freeze: running command without snapshots",
                  file=sys.stderr)
            return subprocess.call(command)
        return 0

    print(f"oci2bin freeze: '{name}' (PID {pid}) — snapshotting "
          f"{len(dbs)} database(s)", file=sys.stderr)
    snaps = []
    for ctr_path, _host_path in dbs:
        snap = snapshot_one(pid, ctr_path)
        if snap:
            print(f"  ok  {ctr_path} -> {snap}", file=sys.stderr)
            snaps.append(snap)
        else:
            # Clean up any snapshots we've already made before aborting.
            for prev in snaps:
                remove_snapshot(pid, prev)
            print("oci2bin freeze: aborting — see error above",
                  file=sys.stderr)
            return 1

    if command:
        rc = subprocess.call(command)
        for s in snaps:
            remove_snapshot(pid, s)
        return rc

    token = _write_token(name, pid, snaps)
    print(f"oci2bin freeze: token written to {token}", file=sys.stderr)
    return 0


def cmd_thaw(name):
    if not VALID_NAME.match(name):
        print(f"oci2bin: invalid container name '{name}'", file=sys.stderr)
        return 1
    token = _read_token(name)
    if token is None:
        print(f"oci2bin thaw: no freeze token for '{name}'", file=sys.stderr)
        return 1
    pid = int(token.get('pid', 0))
    if pid <= 0:
        print(f"oci2bin thaw: malformed token for '{name}'", file=sys.stderr)
        return 1
    # Re-resolve and verify the PID still belongs to the same container —
    # if it doesn't, the snaps are stale and the kernel-level paths can
    # belong to a different process now. Refuse to nsenter blindly.
    try:
        state_pid, binary, start_ticks = load_state(name)
    except SystemExit:
        # Container is gone — just remove the token, the snaps will be
        # garbage on a recycled rootfs and nothing we should chase.
        (_freeze_token_dir() / f'{name}.json').unlink(missing_ok=True)
        return 0
    if state_pid != pid:
        print(f"oci2bin thaw: token PID {pid} != current state PID "
              f"{state_pid}; refusing to nsenter", file=sys.stderr)
        return 1
    ensure_alive(pid, binary, start_ticks)

    for snap in token.get('snaps', []):
        remove_snapshot(pid, snap)
    (_freeze_token_dir() / f'{name}.json').unlink(missing_ok=True)
    print(f"oci2bin thaw: '{name}' thawed ({len(token.get('snaps', []))}"
          f" snapshot(s) removed)", file=sys.stderr)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog='oci2bin freeze')
    sub = ap.add_subparsers(dest='action', required=True)
    f = sub.add_parser('freeze',
                       help='Snapshot SQLite DBs inside a running container')
    f.add_argument('name')
    f.add_argument('cmd', nargs=argparse.REMAINDER,
                   help='Optional command to run while snapshots exist'
                        ' (after a -- separator); snapshots are removed'
                        ' on cmd exit regardless of exit code.')
    t = sub.add_parser('thaw',
                       help='Delete snapshots created by a prior freeze')
    t.add_argument('name')

    args = ap.parse_args(argv)

    if args.action == 'freeze':
        cmd = args.cmd or []
        # argparse REMAINDER leaves the '--' separator in the list when
        # it appears; trim it so the caller sees just the program + args.
        if cmd and cmd[0] == '--':
            cmd = cmd[1:]
        sys.exit(cmd_freeze(args.name, cmd))
    elif args.action == 'thaw':
        sys.exit(cmd_thaw(args.name))


if __name__ == '__main__':
    main()
