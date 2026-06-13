#!/usr/bin/env python3
"""
oci2bin pod-stack orchestrator — `oci2bin up` / `down` / `stack logs`.

A daemon-free, compose-lite runner for a set of oci2bin polyglot binaries. It
parses a declarative stack file and starts each service with the right runtime
flags (ports, env, volumes, --restart, --health, command override, and
service-name DNS aliases), honoring depends_on for startup ordering.

Stdlib only (no PyYAML): the stack file may be JSON, or a documented YAML subset
(block mappings, block/flow scalar lists, scalars, # comments). The schema:

    name: mystack            # optional; used to prefix --name in detached mode
    net: host                # host (default) | shared | none
    ipc: shared              # optional: shared (only meaningful with net:shared)
    services:
      db:
        binary: ./postgres
        env: { POSTGRES_PASSWORD: secret }
        volumes: ["./pgdata:/var/lib/postgresql/data"]
        restart: unless-stopped
      app:
        binary: ./myapp
        command: ["/myapp", "--port", "8080"]   # optional argv override
        depends_on: [db]
        ports: ["8080:8080"]
        env: { DB_HOST: db }
        health: true
        restart: on-failure:5

Networking model (built on oci2bin's primitives):
  - net: host (default) — every service runs on the host network; service names
    resolve to 127.0.0.1 via injected --add-host, so `DB_HOST: db` works. Ports
    are bound directly by the service. Detached mode (`up -d`) is supported.
  - net: shared — a pause process holds a private shared net/IPC namespace and
    each service joins it (--net container:PID); services reach each other on
    loopback. Foreground only (the pause process lives for the run).
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time

VALID_NAME = re.compile(r'^[a-zA-Z0-9][-a-zA-Z0-9_.]*$')
VALID_RESTART = re.compile(r'^(no|always|unless-stopped|on-failure(:\d+)?)$')


def _err(msg):
    print(f"oci2bin stack: {msg}", file=sys.stderr)


def die(msg, code=1):
    _err(msg)
    sys.exit(code)


# ── minimal YAML-subset parser ────────────────────────────────────────────────

def _parse_scalar(tok):
    """Convert a scalar token to a Python value (str/int/bool/None)."""
    t = tok.strip()
    if len(t) >= 2 and t[0] == t[-1] and t[0] in ('"', "'"):
        return t[1:-1]
    low = t.lower()
    if low in ('true', 'yes', 'on'):
        return True
    if low in ('false', 'no', 'off'):
        return False
    if low in ('null', '~', ''):
        return None
    if re.fullmatch(r'-?\d+', t):
        return int(t)
    return t


def _split_top(s, sep):
    """Split s on `sep` at brace/bracket depth 0, honoring quotes. Empty
    fragments (e.g. from a trailing comma) are dropped."""
    parts, buf, q, depth = [], '', None, 0
    for ch in s:
        if q:
            buf += ch
            if ch == q:
                q = None
        elif ch in ('"', "'"):
            q = ch
            buf += ch
        elif ch in '[{':
            depth += 1
            buf += ch
        elif ch in ']}':
            depth -= 1
            buf += ch
        elif ch == sep and depth == 0:
            parts.append(buf)
            buf = ''
        else:
            buf += ch
    parts.append(buf)
    return [p for p in parts if p.strip() != '']


def _parse_flow_value(tok):
    """Parse a flow scalar, list, or mapping (recursively)."""
    t = tok.strip()
    if t.startswith('[') and t.endswith(']'):
        return [_parse_flow_value(x) for x in _split_top(t[1:-1], ',')]
    if t.startswith('{') and t.endswith('}'):
        out = {}
        for pair in _split_top(t[1:-1], ','):
            kv = _split_top(pair, ':')
            if len(kv) < 2:
                die(f"YAML subset: bad flow mapping entry '{pair.strip()}'")
            out[kv[0].strip()] = _parse_flow_value(':'.join(kv[1:]))
        return out
    return _parse_scalar(t)


def _tokenize(text):
    """Return (indent, content) for each significant line."""
    out = []
    for raw in text.splitlines():
        # Strip trailing comments that are not inside quotes.
        line, q = '', None
        for ch in raw:
            if q:
                line += ch
                if ch == q:
                    q = None
            elif ch in ('"', "'"):
                q = ch
                line += ch
            elif ch == '#':
                break
            else:
                line += ch
        if not line.strip():
            continue
        if '\t' in (line[:len(line) - len(line.lstrip())]):
            die("YAML subset: tabs are not allowed for indentation")
        indent = len(line) - len(line.lstrip(' '))
        out.append((indent, line.strip()))
    return out


def _parse_block(lines, idx, indent):
    """Recursively parse a block at the given indent. Returns (value, idx)."""
    # Decide list vs mapping by the first line at this indent.
    if lines[idx][1].startswith('- '):
        result = []
        while idx < len(lines):
            ind, content = lines[idx]
            if ind < indent or not content.startswith('- '):
                break
            if ind > indent:
                die("YAML subset: unexpected indentation in list")
            result.append(_parse_scalar(content[2:]))
            idx += 1
        return result, idx

    result = {}
    while idx < len(lines):
        ind, content = lines[idx]
        if ind < indent:
            break
        if ind > indent:
            die("YAML subset: unexpected indentation")
        if ':' not in content:
            die(f"YAML subset: expected 'key: value', got '{content}'")
        key, _, rest = content.partition(':')
        key = key.strip()
        rest = rest.strip()
        idx += 1
        if rest == '':
            # Nested block (map or list) on following deeper-indented lines.
            if idx < len(lines) and lines[idx][0] > ind:
                value, idx = _parse_block(lines, idx, lines[idx][0])
            else:
                value = None
        elif (rest.startswith('[') and rest.endswith(']')) or \
                (rest.startswith('{') and rest.endswith('}')):
            value = _parse_flow_value(rest)
        else:
            value = _parse_scalar(rest)
        result[key] = value
    return result, idx


def parse_stack_text(text):
    """Parse a stack file: JSON if it looks like JSON, else the YAML subset."""
    stripped = text.lstrip()
    if stripped.startswith('{'):
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            die(f"invalid JSON stack file: {e}")
    lines = _tokenize(text)
    if not lines:
        die("stack file is empty")
    value, idx = _parse_block(lines, 0, lines[0][0])
    if idx != len(lines):
        die("YAML subset: trailing content could not be parsed")
    return value


# ── stack model ───────────────────────────────────────────────────────────────

class Service:
    def __init__(self, name, spec):
        self.name = name
        if not isinstance(spec, dict):
            die(f"service '{name}': definition must be a mapping")
        self.binary = spec.get('binary')
        if not self.binary or not isinstance(self.binary, str):
            die(f"service '{name}': 'binary' (path to an oci2bin binary) is required")
        self.command = self._as_list(name, spec.get('command'), 'command')
        self.ports = self._as_str_list(name, spec.get('ports'), 'ports')
        self.volumes = self._as_str_list(name, spec.get('volumes'), 'volumes')
        self.depends_on = self._as_str_list(name, spec.get('depends_on'),
                                            'depends_on')
        self.aliases = self._as_str_list(name, spec.get('aliases'), 'aliases')
        self.env = self._as_env(name, spec.get('env'))
        self.health = bool(spec.get('health', False))
        self.health_cmd = spec.get('health_cmd')
        self.restart = spec.get('restart')
        if self.restart is not None:
            self.restart = str(self.restart)
            if not VALID_RESTART.match(self.restart):
                die(f"service '{name}': invalid restart '{self.restart}'")
        self.net = spec.get('net')  # per-service override (host/none/slirp)

    @staticmethod
    def _as_list(name, v, field):
        if v is None:
            return []
        if isinstance(v, list):
            return [str(x) for x in v]
        die(f"service '{name}': '{field}' must be a list")

    @staticmethod
    def _as_str_list(name, v, field):
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        if isinstance(v, list):
            return [str(x) for x in v]
        die(f"service '{name}': '{field}' must be a string or list")

    @staticmethod
    def _as_env(name, v):
        if v is None:
            return {}
        if isinstance(v, dict):
            return {str(k): ('' if x is None else str(x)) for k, x in v.items()}
        if isinstance(v, list):
            out = {}
            for item in v:
                k, _, val = str(item).partition('=')
                out[k] = val
            return out
        die(f"service '{name}': 'env' must be a mapping or KEY=VALUE list")


class Stack:
    def __init__(self, data):
        if not isinstance(data, dict):
            die("stack file must define a top-level mapping")
        self.name = str(data.get('name', 'stack'))
        if not VALID_NAME.match(self.name):
            die(f"invalid stack name '{self.name}'")
        self.net = data.get('net', 'host')
        if self.net not in ('host', 'shared', 'none'):
            die(f"net must be host|shared|none, got '{self.net}'")
        self.ipc_shared = bool(data.get('ipc') == 'shared')
        services = data.get('services')
        if not isinstance(services, dict) or not services:
            die("stack must define a non-empty 'services' mapping")
        self.services = {}
        for sname, spec in services.items():
            if not VALID_NAME.match(str(sname)):
                die(f"invalid service name '{sname}'")
            self.services[str(sname)] = Service(str(sname), spec)
        self._validate_refs()
        self.order = self._topo_sort()

    def _validate_refs(self):
        for svc in self.services.values():
            for dep in svc.depends_on:
                if dep not in self.services:
                    die(f"service '{svc.name}': depends_on unknown service "
                        f"'{dep}'")
                if dep == svc.name:
                    die(f"service '{svc.name}': cannot depend on itself")

    def _topo_sort(self):
        """Kahn's algorithm: dependencies start before their dependents."""
        indeg = {n: 0 for n in self.services}
        adj = {n: [] for n in self.services}
        for svc in self.services.values():
            for dep in svc.depends_on:
                adj[dep].append(svc.name)
                indeg[svc.name] += 1
        # Stable order: process ready nodes in declaration order.
        ready = [n for n in self.services if indeg[n] == 0]
        order = []
        while ready:
            n = ready.pop(0)
            order.append(n)
            for m in adj[n]:
                indeg[m] -= 1
                if indeg[m] == 0:
                    ready.append(m)
        if len(order) != len(self.services):
            die("depends_on contains a cycle")
        return order


def load_stack(path):
    if not os.path.isfile(path):
        die(f"stack file not found: {path}")
    with open(path, 'r', encoding='utf-8') as f:
        return Stack(parse_stack_text(f.read()))


# ── argv construction ─────────────────────────────────────────────────────────

def service_argv(stack, svc, pause_pid):
    """Build the argv to launch one service binary."""
    argv = [svc.binary]

    # Networking.
    net = svc.net or stack.net
    if stack.net == 'shared' and pause_pid is not None:
        argv += ['--net', f'container:{pause_pid}']
        if stack.ipc_shared:
            argv += ['--ipc', f'container:{pause_pid}']
    elif net == 'none':
        argv += ['--net', 'none']
    elif net not in ('host', 'shared'):
        argv += ['--net', net]

    # Service-name DNS: every service (and its aliases) resolves to loopback,
    # so peers reach each other by name on host/shared loopback.
    names = list(stack.services.keys())
    for extra in svc.aliases:
        if extra not in names:
            names.append(extra)
    for n in names:
        argv += ['--add-host', f'{n}:127.0.0.1']

    for kv in sorted(svc.env.items()):
        argv += ['-e', f'{kv[0]}={kv[1]}']
    for vol in svc.volumes:
        argv += ['-v', vol]
    for port in svc.ports:
        argv += ['-p', port]
    if svc.restart:
        argv += ['--restart', svc.restart]
    if svc.health:
        argv += ['--health']
    if svc.health_cmd:
        argv += ['--health-cmd', str(svc.health_cmd)]

    # Command override (replaces the image CMD) goes last.
    if svc.command:
        argv += svc.command
    return argv


# ── subcommands ───────────────────────────────────────────────────────────────

def _check_binaries(stack):
    for svc in stack.services.values():
        if not (os.path.isfile(svc.binary) and os.access(svc.binary, os.X_OK)):
            die(f"service '{svc.name}': binary not executable: {svc.binary}")


def _start_pause(stack):
    """Start an unshare'd pause process holding the shared namespaces.
    Returns (pid, popen) or (None, None) when not needed."""
    if stack.net != 'shared':
        return None, None
    flags = ['--net']
    if stack.ipc_shared:
        flags.append('--ipc')
    # The pause prints its own PID then sleeps forever.
    proc = subprocess.Popen(
        ['unshare', *flags, '--', 'sh', '-c', 'echo $$; exec sleep infinity'],
        stdout=subprocess.PIPE)
    line = proc.stdout.readline().decode().strip()
    if not line.isdigit():
        proc.kill()
        die("could not start shared-namespace pause process "
            "(is unshare available / are user namespaces enabled?)")
    return int(line), proc


def _supervise(stack, start_delay, log_dir=None):
    """Start services in dependency order and supervise them until all exit
    or one fails (then tear the rest down). When log_dir is set, each
    service's stdout/stderr is redirected to <log_dir>/<svc>.log. The host
    PID of every service is recorded in the manifest as it starts so `down`
    can target the real processes. Returns the worst non-zero exit code."""
    pause_pid, pause_proc = _start_pause(stack)
    children = {}   # name -> Popen
    logfiles = []
    worst = 0
    stopping = {'flag': False}

    def _killpg(p, sig):
        # Each service leads its own session, so the whole container tree
        # shares the service's process-group — signal the group so workloads
        # inside the PID namespace are reached, not just the loader.
        try:
            os.killpg(p.pid, sig)
        except (ProcessLookupError, PermissionError):
            pass

    def shutdown(*_):
        stopping['flag'] = True
        for name in reversed(stack.order):
            p = children.get(name)
            if p and p.poll() is None:
                _killpg(p, signal.SIGTERM)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        for sname in stack.order:
            if stopping['flag']:
                break
            svc = stack.services[sname]
            argv = service_argv(stack, svc, pause_pid)
            out = None
            if log_dir is not None:
                out = open(os.path.join(log_dir, f'{sname}.log'), 'ab')
                logfiles.append(out)
            print(f"oci2bin stack: starting {sname} ({svc.binary})",
                  file=sys.stderr, flush=True)
            children[sname] = subprocess.Popen(
                argv, stdout=out, stderr=out, start_new_session=True,
                stdin=subprocess.DEVNULL if log_dir else None)
            if log_dir is not None:
                _update_manifest_pids(
                    stack.name,
                    {n: p.pid for n, p in children.items()}, pause_pid)
            if start_delay:
                time.sleep(start_delay)

        stop_time = [None]
        killed = [False]
        while True:
            alive = False
            for sname in stack.order:
                p = children.get(sname)
                if p is None:
                    continue
                rc = p.poll()
                if rc is None:
                    alive = True
                elif getattr(p, '_reported', False) is False:
                    p._reported = True
                    print(f"oci2bin stack: {sname} exited ({rc})",
                          file=sys.stderr, flush=True)
                    if rc != 0 and rc > worst:
                        worst = rc
                    if rc != 0 and not stopping['flag']:
                        shutdown()
            if not alive:
                break
            # Escalate to SIGKILL if a service ignores SIGTERM for too long.
            if stopping['flag']:
                if stop_time[0] is None:
                    stop_time[0] = time.monotonic()
                elif not killed[0] and time.monotonic() - stop_time[0] > 5:
                    killed[0] = True
                    for sname in stack.order:
                        p = children.get(sname)
                        if p and p.poll() is None:
                            _killpg(p, signal.SIGKILL)
            time.sleep(0.2)
    finally:
        for f in logfiles:
            f.close()
        if pause_proc is not None:
            pause_proc.terminate()
            try:
                pause_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pause_proc.kill()
    return worst


def cmd_up(args):
    stack = load_stack(args.file)
    _check_binaries(stack)

    if not args.detach:
        return _supervise(stack, args.start_delay, log_dir=None)

    # Detached: fork a backgrounded, self-contained supervisor that tracks the
    # real host PIDs of the services it spawns (no dependency on the loader's
    # --detach lifecycle). The parent records nothing and returns once the
    # child has written its manifest.
    log_dir = _stack_log_dir(stack.name)
    pid = os.fork()
    if pid > 0:
        for _ in range(50):
            if _manifest_exists(stack.name):
                break
            time.sleep(0.1)
        os.waitpid(pid, os.WNOHANG)  # reap if the fork-parent already exited
        print(f"oci2bin stack: '{stack.name}' started detached "
              f"({len(stack.order)} services). Manage with: "
              f"oci2bin down {stack.name} / oci2bin stack logs {stack.name}")
        return 0

    # Child: detach from the terminal and become the supervisor.
    os.setsid()
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 0)
    sup_log = os.open(os.path.join(log_dir, '_supervisor.log'),
                      os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.dup2(sup_log, 1)
    os.dup2(sup_log, 2)
    os.close(devnull)
    os.close(sup_log)
    _write_manifest(stack.name, {
        'name': stack.name, 'supervisor_pid': os.getpid(),
        'services': stack.order, 'log_dir': log_dir,
        'pids': {}, 'file': os.path.abspath(args.file)})
    try:
        _supervise(stack, args.start_delay, log_dir=log_dir)
    finally:
        _remove_manifest(stack.name)
    os._exit(0)


def _signal_group(pid, sig):
    """Signal a service's whole process group (the container tree shares it).
    Returns False only if the group is already gone."""
    try:
        os.killpg(pid, sig)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def cmd_down(args):
    name = _down_target(args)
    m = _read_manifest(name)
    if not m:
        die(f"no running stack named '{name}'")

    sup = m.get('supervisor_pid')
    order = m.get('services', [])
    pids = m.get('pids', {})

    # Stop the supervisor first so it does not relaunch anything, then signal
    # each service's process group: SIGTERM, escalate to SIGKILL for workloads
    # that run as PID 1 (which ignores SIGTERM).
    if sup:
        try:
            os.kill(sup, signal.SIGTERM)
        except ProcessLookupError:
            pass
    targets = [pids[s] for s in reversed(order) if pids.get(s)]
    for pid in targets:
        _signal_group(pid, signal.SIGTERM)

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not any(_pid_alive(p) for p in targets):
            break
        time.sleep(0.2)
    for pid in targets:
        if _pid_alive(pid):
            _signal_group(pid, signal.SIGKILL)
    if sup and _pid_alive(sup):
        try:
            os.kill(sup, signal.SIGKILL)
        except ProcessLookupError:
            pass

    _remove_manifest(name)
    print(f"oci2bin stack: '{name}' stopped")
    return 0


def cmd_logs(args):
    name = args.target
    m = _read_manifest(name)
    services = m.get('services', []) if m else []
    log_dir = (m or {}).get('log_dir') or _stack_log_dir(name)
    targets = [args.service] if args.service else services
    if not targets:
        die(f"no logs for stack '{name}' (not running detached?)")
    if args.follow and len(targets) > 1:
        die("logs -f follows a single service; pass one service name")
    rc = 0
    for sname in targets:
        path = os.path.join(log_dir, f'{sname}.log')
        if not os.path.exists(path):
            _err(f"no log for service '{sname}' at {path}")
            rc = 1
            continue
        print(f"==> {name}/{sname} <==")
        cmd = ['tail', '-n', '50']
        if args.follow:
            cmd.append('-f')
        cmd.append(path)
        rc = subprocess.run(cmd).returncode or rc
    return rc


def cmd_config(args):
    stack = load_stack(args.file)
    print(f"stack: {stack.name}  net={stack.net}  "
          f"ipc={'shared' if stack.ipc_shared else 'private'}")
    print(f"start order: {' -> '.join(stack.order)}")
    for sname in stack.order:
        svc = stack.services[sname]
        argv = service_argv(stack, svc,
                            '<pause>' if stack.net == 'shared' else None)
        print(f"  {sname}: {' '.join(argv)}")
    return 0


# ── detached-stack manifest (so down/logs can find the services) ──────────────

def _data_dir():
    base = os.environ.get('XDG_DATA_HOME') or \
        os.path.join(os.path.expanduser('~'), '.local', 'share')
    return os.path.join(base, 'oci2bin', 'stacks')


def _manifest_path(name):
    if not VALID_NAME.match(name):
        die(f"invalid stack name '{name}'")
    d = _data_dir()
    os.makedirs(d, mode=0o700, exist_ok=True)
    return os.path.join(d, f'{name}.json')


def _stack_log_dir(name):
    d = os.path.join(_data_dir(), name)
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def _manifest_exists(name):
    return os.path.isfile(_manifest_path(name))


def _write_manifest(name, manifest):
    tmp = _manifest_path(name) + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2)
    os.replace(tmp, _manifest_path(name))


def _update_manifest_pids(name, pids, pause_pid):
    m = _read_manifest(name)
    if not m:
        return
    m['pids'] = pids
    m['pause_pid'] = pause_pid
    _write_manifest(name, m)


def _read_manifest(name):
    path = _manifest_path(name)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _remove_manifest(name):
    try:
        os.unlink(_manifest_path(name))
    except OSError:
        pass


def _down_target(args):
    """down accepts a stack name or resolves the name from -f FILE."""
    if getattr(args, 'file', None):
        return load_stack(args.file).name
    return args.target


def main(argv=None):
    p = argparse.ArgumentParser(prog='oci2bin stack',
                                description='Declarative pod-stack runner')
    p.add_argument('--oci2bin', default=os.environ.get('OCI2BIN_SELF',
                                                       'oci2bin'),
                   help='Path to the oci2bin CLI (for down/logs).')
    sub = p.add_subparsers(dest='cmd', required=True)

    up = sub.add_parser('up', help='Start a stack')
    up.add_argument('-f', '--file', default='stack.yaml')
    up.add_argument('-d', '--detach', action='store_true')
    up.add_argument('--start-delay', type=float, default=0.0,
                    help='Seconds to pause between starting services.')
    up.set_defaults(func=cmd_up)

    down = sub.add_parser('down', help='Stop a detached stack')
    down.add_argument('target', nargs='?', default='stack',
                      help='Stack name (default: stack) or omit with -f.')
    down.add_argument('-f', '--file', default=None)
    down.set_defaults(func=cmd_down)

    logs = sub.add_parser('logs', help='Show logs for stack services')
    logs.add_argument('target', nargs='?', default='stack')
    logs.add_argument('service', nargs='?', default=None)
    logs.add_argument('-f', '--follow', action='store_true')
    logs.set_defaults(func=cmd_logs, file=None)

    cfg = sub.add_parser('config', help='Validate and print the resolved stack')
    cfg.add_argument('-f', '--file', default='stack.yaml')
    cfg.add_argument('-d', '--detach', action='store_true')
    cfg.set_defaults(func=cmd_config)

    args = p.parse_args(argv)
    return args.func(args) or 0


if __name__ == '__main__':
    sys.exit(main())
