#!/usr/bin/env python3
"""
dockerfile_build.py — Build an OCI image layout from a Dockerfile.

Supported instructions:
  FROM [--platform=linux/<arch>] scratch | <oci-layout-dir> | <docker-image>
       | <earlier-stage> [AS <name>]         (multi-stage builds)
  COPY [--from=<stage|image>] [--chmod=MODE] [--chown=] <src...> <dst>
  COPY <<EOF <dst>                          (heredoc file)
  ADD  <src> <dst>         (local files only, same as COPY)
  RUN  [--mount=...] <cmd> | ["exec", "form"] | <<EOF ... EOF
       (runs in WORKDIR through SHELL; as root — see USER)
  ENV  KEY=VAL | KEY VAL
  ENTRYPOINT ["cmd","arg"] | cmd arg
  CMD        ["cmd","arg"] | cmd arg
  SHELL      ["executable", "param"]
  WORKDIR    /path
  LABEL      key=value
  USER       uid[:gid]     (image runtime user; RUN steps stay root)
  EXPOSE     port[/proto]  (informational)
  ARG        NAME[=default]

Variables ($NAME, ${NAME}, ${NAME:-default}, ${NAME:+alt}) from ARG and ENV
are expanded in ADD, COPY, ENV, EXPOSE, FROM, LABEL, STOPSIGNAL, USER,
VOLUME, WORKDIR, ARG and SHELL; RUN/CMD/ENTRYPOINT see them as environment
variables, expanded by the shell.  --chown is accepted with a warning: the
builder emits a single root-owned layer.

RUN --mount types (BuildKit-compatible):
  --mount=type=bind,source=<src>,target=<dst>[,ro]
      Bind-mount from the build context (read-only by default).
  --mount=type=secret,id=<id>[,target=<path>][,required]
      Secret file provided via --build-secret id=<id>,src=<path>.
      NOT included in the image layer.
  --mount=type=ssh[,id=<id>][,target=<path>][,required]
      SSH agent socket forwarded from $SSH_AUTH_SOCK.
      NOT included in the image layer.
  --mount=type=cache,target=<path>[,id=<id>][,sharing=locked|shared|private]
      Persistent cache directory at ~/.cache/oci2bin/build-cache/<id>.
      NOT included in the image layer.
  --mount=type=tmpfs,target=<path>[,size=<bytes>]
      Temporary in-memory filesystem for the RUN step only.

Usage:
  dockerfile_build.py [Dockerfile] <out_oci_dir>
                      [--context DIR]
                      [--build-arg KEY=VAL ...]
                      [--build-secret id=<id>,src=<path> ...]
                      [--arch amd64|arm64]
"""

import argparse
import fnmatch
import io
import json
import os
import posixpath
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
import from_chroot  # noqa: E402


# ── Dockerfile parser ────────────────────────────────────────────────────────

_HEREDOC_RE = re.compile(r'<<(-?)(["\']?)([A-Za-z_][A-Za-z0-9_]*)\2')


def _parse_dockerfile(path: str) -> list:
    """Return a list of (INSTRUCTION, raw_args_str, heredocs) from *path*.

    heredocs is a list of (word, body) for RUN/COPY/ADD `<<WORD` documents,
    whose lines are consumed here instead of being read as instructions.
    Line continuations skip comment and blank lines inside them (as Docker
    does) instead of turning the next line into a new instruction, and CRLF
    line endings are accepted.
    """
    instructions = []
    with open(path, encoding="utf-8", newline="") as f:
        lines = f.read().replace("\r\n", "\n").split("\n")

    def _skippable(text):
        t = text.strip()
        return not t or t.startswith("#")

    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        i += 1
        if _skippable(line):
            continue
        while line.rstrip().endswith("\\"):
            line = line.rstrip()[:-1]
            while i < n and _skippable(lines[i]):
                i += 1
            if i >= n:
                break
            line += lines[i].lstrip()
            i += 1
        line = line.strip()
        parts = line.split(None, 1)
        if not parts:
            continue
        instr = parts[0].upper()
        rest = parts[1] if len(parts) > 1 else ""
        heredocs = []
        if instr in ("RUN", "COPY", "ADD"):
            for dash, _quote, word in _HEREDOC_RE.findall(rest):
                body = []
                terminated = False
                while i < n:
                    raw = lines[i]
                    i += 1
                    text = raw.lstrip("\t") if dash else raw
                    if text == word:
                        terminated = True
                        break
                    body.append(text)
                if not terminated:
                    print(f"error: {instr}: unterminated heredoc <<{word}",
                          file=sys.stderr)
                    sys.exit(1)
                heredocs.append((word, "\n".join(body) + "\n"))
        instructions.append((instr, rest, heredocs))
    return instructions


_VAR_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _matching_brace(text: str, start: int) -> int:
    """Index of the `}` closing the `${` whose `{` is at text[start], or
    -1.  Counts nested `${` so `${A:-${B:-c}}` closes at the last brace,
    not the first; a `\\` escapes the next character as in the rest of
    the expander."""
    depth = 0
    i = start
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "$" and i + 1 < n and text[i + 1] == "{":
            depth += 1
            i += 2
            continue
        if ch == "{" and i == start:
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _expand_vars(text: str, variables: dict) -> str:
    """Dockerfile variable substitution: $NAME, ${NAME}, ${NAME:-word},
    ${NAME:+word}; `\\$` is a literal dollar.  Unset names expand to "".
    The word after :- or :+ is itself expanded, nested braces included
    (${A:-${B:-c}}), as BuildKit does.

    Replaces the old per-build-arg str.replace(), which substituted
    prefixes ($FOO inside $FOOBAR), ignored ${VAR:-default} and never
    expanded ENV values.
    """
    out = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n and text[i + 1] == "$":
            out.append("$")
            i += 2
            continue
        if ch != "$" or i + 1 >= n:
            out.append(ch)
            i += 1
            continue
        if text[i + 1] == "{":
            end = _matching_brace(text, i + 1)
            if end < 0:
                out.append(text[i:])
                break
            inner = text[i + 2:end]
            m = _VAR_NAME_RE.match(inner)
            if not m:
                out.append(text[i:end + 1])
            else:
                name = m.group(0)
                tail = inner[m.end():]
                value = variables.get(name)
                if tail.startswith(":-"):
                    out.append(value if value else
                               _expand_vars(tail[2:], variables))
                elif tail.startswith(":+"):
                    out.append(_expand_vars(tail[2:], variables)
                               if value else "")
                elif tail == "":
                    out.append(value or "")
                else:
                    out.append(text[i:end + 1])  # unsupported modifier
            i = end + 1
            continue
        m = _VAR_NAME_RE.match(text, i + 1)
        if not m:
            out.append(ch)
            i += 1
            continue
        out.append(variables.get(m.group(0), ""))
        i = m.end()
    return "".join(out)


# Instructions whose arguments Docker expands with ARG/ENV values.  RUN,
# CMD and ENTRYPOINT are left to the shell at run time.
_EXPANDED_INSTRUCTIONS = frozenset((
    "ADD", "COPY", "ENV", "EXPOSE", "FROM", "LABEL", "STOPSIGNAL", "USER",
    "VOLUME", "WORKDIR", "ARG", "SHELL",
))


def _parse_json_array(s: str):
    """Return the list of strings if *s* is a JSON exec-form array."""
    s = s.strip()
    if s.startswith("["):
        try:
            val = json.loads(s)
            if isinstance(val, list) and all(isinstance(x, str) for x in val):
                return val
        except json.JSONDecodeError:
            pass
    return None


def _parse_json_or_shell(s: str, shell=None):
    """Parse ENTRYPOINT/CMD: JSON array or shell-form string (run through
    the current SHELL, default /bin/sh -c)."""
    val = _parse_json_array(s)
    if val is not None:
        return val
    s = s.strip()
    return list(shell or ["/bin/sh", "-c"]) + [s] if s else None


def _parse_kvs(spec: str) -> dict:
    """Parse 'key=val,key2=val2' into a dict. Bare keys get value True."""
    result: dict = {}
    for token in spec.split(","):
        token = token.strip()
        if not token:
            continue
        if "=" in token:
            k, v = token.split("=", 1)
            result[k.strip()] = v.strip()
        else:
            result[token] = True
    return result


def _read_shell_word(text: str, start: int) -> tuple:
    """Return (raw_word, end_index), respecting simple shell quotes."""
    i = start
    quote = ""
    escaped = False
    while i < len(text):
        ch = text[i]
        if escaped:
            escaped = False
            i += 1
            continue
        if quote:
            if quote == "'" and ch == "'":
                quote = ""
            elif quote == '"' and ch == '"':
                quote = ""
            elif quote == '"' and ch == "\\":
                escaped = True
            i += 1
            continue
        if ch.isspace():
            break
        if ch in ("'", '"'):
            quote = ch
            i += 1
            continue
        if ch == "\\":
            escaped = True
            i += 1
            continue
        i += 1
    return text[start:i], i


def _shell_word_token(raw: str):
    """Unquote a single shell word, returning None when malformed."""
    try:
        parts = shlex.split(raw, comments=False, posix=True)
    except ValueError:
        return None
    if len(parts) != 1:
        return None
    return parts[0]


def _parse_run_line(args: str) -> tuple:
    """
    Split RUN [--mount=...] CMD into (cmd_str, [mount_dicts], [unsupported]).

    Handles both '--mount=type=...' and '--mount type=...' forms. Only the
    leading BuildKit option words are parsed; the command remainder is returned
    byte-for-byte for /bin/sh so shell operators, redirections, expansions and
    quoting keep their Dockerfile semantics. Unrecognised leading flags are
    treated as part of the command.
    """
    mounts = []
    unsupported = []
    pos = 0
    saw_option = False
    while pos < len(args):
        opt_start = pos
        while opt_start < len(args) and args[opt_start].isspace():
            opt_start += 1
        if opt_start >= len(args):
            pos = opt_start
            break
        raw, word_end = _read_shell_word(args, opt_start)
        token = _shell_word_token(raw)
        if token is None:
            if saw_option:
                pos = opt_start
                break
            return args, [], []
        if token.startswith("--mount="):
            mounts.append(_parse_kvs(token[len("--mount="):]))
            pos = word_end
            saw_option = True
            continue
        if token == "--mount":
            value_start = word_end
            while value_start < len(args) and args[value_start].isspace():
                value_start += 1
            if value_start >= len(args):
                pos = opt_start if saw_option else 0
                break
            value_raw, value_end = _read_shell_word(args, value_start)
            value = _shell_word_token(value_raw)
            if value is None:
                pos = opt_start if saw_option else 0
                break
            mounts.append(_parse_kvs(value))
            pos = value_end
            saw_option = True
            continue
        if token in ("--network", "--security"):
            value_start = word_end
            while value_start < len(args) and args[value_start].isspace():
                value_start += 1
            if value_start >= len(args):
                pos = opt_start if saw_option else 0
                break
            value_raw, value_end = _read_shell_word(args, value_start)
            value = _shell_word_token(value_raw)
            unsupported.append(
                f"{token} {value if value is not None else value_raw}")
            pos = value_end
            saw_option = True
            continue
        if token.startswith("--network=") or token.startswith("--security="):
            unsupported.append(token)
            pos = word_end
            saw_option = True
            continue
        pos = opt_start if saw_option else 0
        break

    cmd = args[pos:].lstrip() if saw_option else args
    return cmd, mounts, unsupported


# ── Layer extraction helpers ─────────────────────────────────────────────────

class _DockerIgnore:
    """
    Minimal .dockerignore matcher.

    Reads <context>/.dockerignore once at construction. Each non-empty,
    non-`#`-comment line is a glob pattern (fnmatch syntax with `**`
    expanded to "any number of segments"). A leading `!` re-includes
    a previously-excluded path.

    Pattern semantics intended to match BuildKit's:
      foo            anywhere named foo
      /foo           foo at the context root only
      foo/           any directory named foo (and its descendants)
      *.log          any .log file at any depth
      docs/**.md     any .md file under docs/
      !keep.log      re-include a previously-excluded file

    Patterns are evaluated in order; the last matching rule wins. If
    the file is missing or empty the matcher excludes nothing.
    """

    def __init__(self, context_dir: str):
        self.patterns = []
        try:
            with open(os.path.join(context_dir, ".dockerignore"),
                      "r", encoding="utf-8", errors="replace") as f:
                for raw in f:
                    line = raw.rstrip("\r\n").strip()
                    if not line or line.startswith("#"):
                        continue
                    negated = line.startswith("!")
                    if negated:
                        line = line[1:].lstrip()
                    if not line:
                        continue
                    self.patterns.append((line, negated))
        except FileNotFoundError:
            pass

    @staticmethod
    def _match_one(pattern: str, rel: str) -> bool:
        pat = pattern.lstrip("/")
        is_dir_pat = pat.endswith("/")
        if is_dir_pat:
            pat = pat.rstrip("/")
        anchored = pattern.startswith("/")
        # `**` segments match zero-or-more path components.
        if "**" in pat:
            # Treat as a regex-ish split: split on **, fnmatch-match
            # each segment greedily against rel.
            segments = pat.split("**")
            cursor = 0
            for i, seg in enumerate(segments):
                seg = seg.strip("/")
                if not seg:
                    continue
                if i == 0 and anchored:
                    # Must match the prefix exactly.
                    sub = rel[cursor:cursor + len(seg)]
                    if not fnmatch.fnmatchcase(sub, seg):
                        return False
                    cursor += len(seg)
                    continue
                # Find the next position where seg matches a path
                # component starting after `cursor`.
                while cursor < len(rel):
                    end = rel.find("/", cursor)
                    chunk = rel[cursor:end] if end >= 0 else rel[cursor:]
                    if fnmatch.fnmatchcase(chunk, seg):
                        cursor = end + 1 if end >= 0 else len(rel)
                        break
                    cursor = end + 1 if end >= 0 else len(rel) + 1
                else:
                    return False
            return True
        # No `**`: ordinary fnmatch against full path or any ancestor.
        if anchored:
            if fnmatch.fnmatchcase(rel, pat):
                return True
            if is_dir_pat and (rel == pat or rel.startswith(pat + "/")):
                return True
            return False
        # Unanchored — match the full path or any single component.
        if fnmatch.fnmatchcase(rel, pat):
            return True
        for component in rel.split("/"):
            if fnmatch.fnmatchcase(component, pat):
                return True
        if is_dir_pat:
            for i in range(len(rel)):
                if rel[i] == "/" and fnmatch.fnmatchcase(rel[:i], pat):
                    return True
            if fnmatch.fnmatchcase(rel, pat):
                return True
        return False

    def matches(self, rel_path: str) -> bool:
        """Return True if rel_path (relative to context, '/'-separated)
        is excluded by the .dockerignore."""
        if not self.patterns:
            return False
        rel = rel_path.replace(os.sep, "/").lstrip("/")
        excluded = False
        for pattern, negated in self.patterns:
            if self._match_one(pattern, rel):
                excluded = not negated
        return excluded


def _resolve_in_root(rootfs: str, container_path: str,
                     follow_leaf: bool) -> str:
    """Resolve *container_path* the way the kernel would inside a chroot at
    *rootfs*: every symlink is followed with *rootfs* as "/", so an
    absolute target (`/var/run -> /run` on Debian/Ubuntu) is re-rooted
    rather than read as a host path, and `..` stops at the root.  The
    result is always *rootfs* or below it.  The leaf is only followed
    when *follow_leaf* is set.
    """
    if not container_path:
        raise ValueError("empty container path")
    if not container_path.startswith("/"):
        raise ValueError(
            f"container path must be absolute: {container_path!r}")
    real_root = os.path.realpath(rootfs)
    todo = [p for p in container_path.split("/") if p]
    done: list = []
    links_left = 40
    while todo:
        comp = todo.pop(0)
        if comp == ".":
            continue
        if comp == "..":
            if done:
                done.pop()
            continue
        host = os.path.join(real_root, *done, comp)
        if (todo or follow_leaf) and os.path.islink(host):
            links_left -= 1
            if links_left < 0:
                raise ValueError(
                    f"too many levels of symlinks: {container_path!r}")
            target = os.readlink(host)
            if target.startswith("/"):
                done = []
            todo = [p for p in target.split("/") if p] + todo
            continue
        done.append(comp)
    return os.path.join(real_root, *done)


def _safe_resolve(rootfs: str, container_path: str) -> str:
    """
    Resolve *container_path* (absolute, as seen inside the container) to a
    host path under *rootfs*.  Symlinks in the parent chain are followed
    inside the rootfs (see _resolve_in_root); the leaf is NOT dereferenced,
    so callers can replace a destination symlink without writing through it.
    Raises ValueError on empty or relative input.
    """
    return _resolve_in_root(rootfs, container_path, follow_leaf=False)


def _safe_resolve_follow(rootfs: str, container_path: str) -> str:
    """Resolve the full container path under *rootfs*, including the leaf.

    Use this only when the caller intends to use an existing path as a
    directory.  Callers that are going to replace the leaf should keep using
    _safe_resolve(), which deliberately leaves the leaf unresolved.
    """
    return _resolve_in_root(rootfs, container_path, follow_leaf=True)


def _safe_unlink_if_present(path: str) -> None:
    """Remove an existing file or symlink at *path* (no-op if absent).
    Used before writing through a destination so we replace a symlink
    rather than follow it."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except IsADirectoryError:
        pass


def _container_join(base: str, rel: str) -> str:
    rel_posix = rel.replace(os.sep, "/")
    if rel_posix in ("", "."):
        return posixpath.normpath(base)
    return posixpath.normpath(posixpath.join(base, rel_posix))


def _context_source_candidate(context_dir: str, source: str) -> str:
    """Map a Dockerfile source path to a lexical path below the context.

    Docker treats a leading slash as relative to the build-context root, not
    as a host absolute path.
    """
    if "\0" in source:
        raise ValueError("source path contains a NUL byte")
    rel = source.lstrip("/") if source.startswith("/") else source
    return os.path.normpath(os.path.join(context_dir, rel))


def _resolve_context_candidate(context_dir: str, candidate: str) -> str:
    """Resolve a host candidate and require it to stay in the context."""
    real_context = os.path.realpath(context_dir)
    resolved = os.path.realpath(os.path.normpath(candidate))
    if resolved != real_context and \
            not resolved.startswith(real_context + os.sep):
        raise ValueError(
            f"{candidate!r} resolves outside the build context "
            f"({resolved!r})")
    return resolved


def _glob_component_matches(name: str, pattern: str) -> bool:
    """Match one glob component using Python glob's hidden-file rule."""
    if name.startswith(".") and not pattern.startswith("."):
        return False
    return fnmatch.fnmatchcase(name, pattern)


def _expand_context_glob(context_dir: str, source: str) -> list:
    """Expand a source glob without recursively following symlinked dirs.

    Explicit traversal through an internal directory symlink is supported
    after confinement validation. A broad ``**`` does not descend through
    symlinks, preventing host-tree traversal before candidates are checked.
    """
    candidate = _context_source_candidate(context_dir, source)
    rel_pattern = os.path.relpath(candidate, context_dir).replace(os.sep, "/")
    components = [part for part in rel_pattern.split("/")
                  if part not in ("", ".")]
    if any(part == ".." for part in components):
        raise ValueError(f"{source!r} escapes the build context")
    if not any(any(char in part for char in "*?[")
               for part in components):
        return [candidate]

    results = []

    def scan_dir(path: str, ancestors: frozenset) -> tuple:
        resolved = _resolve_context_candidate(context_dir, path)
        try:
            st = os.stat(resolved)
        except FileNotFoundError:
            return [], ancestors
        if not os.path.isdir(resolved):
            return [], ancestors
        key = (st.st_dev, st.st_ino)
        if key in ancestors:
            return [], ancestors
        try:
            entries = sorted(os.scandir(resolved), key=lambda entry: entry.name)
        except (FileNotFoundError, NotADirectoryError):
            return [], ancestors
        return entries, ancestors | {key}

    def expand(path: str, index: int, ancestors: frozenset) -> None:
        if index == len(components):
            if os.path.lexists(path):
                results.append(path)
            return

        component = components[index]
        entries, child_ancestors = scan_dir(path, ancestors)
        if component == "**":
            expand(path, index + 1, ancestors)
            for entry in entries:
                if entry.name.startswith("."):
                    continue
                child = os.path.join(path, entry.name)
                if entry.is_dir(follow_symlinks=False):
                    expand(child, index, child_ancestors)
                elif index + 1 == len(components):
                    results.append(child)
            return

        for entry in entries:
            if not _glob_component_matches(entry.name, component):
                continue
            child = os.path.join(path, entry.name)
            expand(child, index + 1, child_ancestors)

    expand(context_dir, 0, frozenset())
    return list(dict.fromkeys(results))


def _context_source_ignored(state: "_State", candidate: str,
                            resolved: str) -> bool:
    """Check .dockerignore against both lexical and symlink-resolved paths."""
    if not state.dockerignore.patterns:
        return False
    real_context = os.path.realpath(state.context_dir)
    lexical_rel = os.path.relpath(candidate, state.context_dir)
    resolved_rel = os.path.relpath(resolved, real_context)
    return (state.dockerignore.matches(lexical_rel) or
            state.dockerignore.matches(resolved_rel))


def _copy_leaf(src_path: str, dest_host: str) -> None:
    """Copy one file/symlink to a destination whose parent is already safe."""
    os.makedirs(os.path.dirname(dest_host), exist_ok=True)
    _safe_unlink_if_present(dest_host)
    if os.path.islink(src_path):
        os.symlink(os.readlink(src_path), dest_host)
    else:
        shutil.copy2(src_path, dest_host)


def _copy_dir_contents(state: "_State", src_path: str,
                       dst_container: str) -> None:
    """Copy a source directory into a container destination safely.

    This avoids shutil.copytree() because copytree follows existing
    destination symlinks while merging, which lets a malicious base image
    redirect writes outside the rootfs.
    """
    for dirpath, dirnames, filenames in os.walk(src_path, followlinks=False):
        rel_dir = os.path.relpath(dirpath, src_path)
        dst_dir_container = _container_join(dst_container, rel_dir)
        try:
            dst_dir_host = _safe_resolve_follow(state.rootfs,
                                                dst_dir_container)
        except ValueError as exc:
            print(f"error: COPY destination escapes rootfs: {exc}",
                  file=sys.stderr)
            sys.exit(1)
        os.makedirs(dst_dir_host, exist_ok=True)

        kept_dirnames = []
        for dname in sorted(dirnames):
            src_child = os.path.join(dirpath, dname)
            rel_ctx = os.path.relpath(src_child, state.context_dir)
            if state.dockerignore.patterns and \
                    state.dockerignore.matches(rel_ctx):
                continue
            if os.path.islink(src_child):
                rel_child = os.path.relpath(src_child, src_path)
                dst_child_container = _container_join(dst_container,
                                                      rel_child)
                try:
                    dst_child_host = _safe_resolve(state.rootfs,
                                                   dst_child_container)
                except ValueError as exc:
                    print(f"error: COPY destination escapes rootfs: {exc}",
                          file=sys.stderr)
                    sys.exit(1)
                _copy_leaf(src_child, dst_child_host)
            else:
                kept_dirnames.append(dname)
        dirnames[:] = kept_dirnames

        for fname in sorted(filenames):
            src_child = os.path.join(dirpath, fname)
            rel_ctx = os.path.relpath(src_child, state.context_dir)
            if state.dockerignore.patterns and \
                    state.dockerignore.matches(rel_ctx):
                continue
            rel_child = os.path.relpath(src_child, src_path)
            dst_child_container = _container_join(dst_container, rel_child)
            try:
                dst_child_host = _safe_resolve(state.rootfs,
                                               dst_child_container)
            except ValueError as exc:
                print(f"error: COPY destination escapes rootfs: {exc}",
                      file=sys.stderr)
                sys.exit(1)
            _copy_leaf(src_child, dst_child_host)


def _extract_layer_tar(tf: tarfile.TarFile, rootfs: str) -> None:
    """Apply one OCI/docker layer tarball to *rootfs*, handling whiteouts.

    Every destination path is routed through _safe_resolve so a symlink
    planted by an earlier layer cannot redirect this layer's writes
    outside *rootfs*. Hardlink targets are likewise resolved so a
    crafted layer cannot hardlink-escape via member.linkname.
    """
    for member in tf.getmembers():
        name = member.name
        while name.startswith("./") or name.startswith("/"):
            name = name[2:] if name.startswith("./") else name[1:]
        if not name:
            continue
        if any(p == ".." for p in name.split("/")):
            print(f"  warning: skipping unsafe tar path: {member.name!r}",
                  file=sys.stderr)
            continue

        basename = os.path.basename(name)
        try:
            container_abs = "/" + name
            dest = _safe_resolve(rootfs, container_abs)
        except ValueError as exc:
            print(f"  warning: skipping unsafe tar path: "
                  f"{member.name!r}: {exc}", file=sys.stderr)
            continue

        if basename == ".wh..wh..opq":
            parent = os.path.dirname(dest)
            if os.path.isdir(parent):
                for entry in os.listdir(parent):
                    ep = os.path.join(parent, entry)
                    if os.path.islink(ep) or not os.path.isdir(ep):
                        os.unlink(ep)
                    else:
                        shutil.rmtree(ep, ignore_errors=True)
            continue

        if basename.startswith(".wh."):
            try:
                target = _safe_resolve(
                    rootfs,
                    "/" + os.path.dirname(name) + "/" +
                    basename[len(".wh."):])
            except ValueError as exc:
                print(f"  warning: whiteout escape: {exc}",
                      file=sys.stderr)
                continue
            if os.path.islink(target) or os.path.isfile(target):
                os.unlink(target)
            elif os.path.isdir(target):
                shutil.rmtree(target, ignore_errors=True)
            continue

        member.mode = member.mode & 0o1777
        try:
            if member.isdir():
                # A symlink left at the leaf by an earlier entry must not be
                # followed: makedirs/chmod would act on its (host) target.
                if os.path.islink(dest):
                    os.unlink(dest)
                os.makedirs(dest, exist_ok=True)
                os.chmod(dest, member.mode)
            elif member.issym():
                _safe_unlink_if_present(dest)
                os.symlink(member.linkname, dest)
            elif member.islnk():
                link_rel = member.linkname
                while link_rel.startswith("./") or link_rel.startswith("/"):
                    link_rel = (link_rel[2:] if link_rel.startswith("./")
                                else link_rel[1:])
                try:
                    link_src = _safe_resolve(rootfs, "/" + link_rel)
                except ValueError as exc:
                    print(f"  warning: hardlink escape: "
                          f"{member.name!r}: {exc}", file=sys.stderr)
                    continue
                _safe_unlink_if_present(dest)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                # Never follow a symlink leaf here: exists()/link() would
                # resolve it against the HOST, so a crafted layer (a -> /x,
                # b hardlinked to a) could pull a host file into the rootfs.
                if os.path.lexists(link_src):
                    os.link(link_src, dest, follow_symlinks=False)
            elif member.isfile():
                _safe_unlink_if_present(dest)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                fobj = tf.extractfile(member)
                if fobj:
                    with open(dest, "wb") as out:
                        shutil.copyfileobj(fobj, out)
                    os.chmod(dest, member.mode)
        except OSError as exc:
            print(f"  warning: {name}: {exc}", file=sys.stderr)


def _extract_oci_to_rootfs(oci_dir: str, rootfs: str) -> dict:
    """Extract all layers from an OCI layout directory into *rootfs*."""
    with open(os.path.join(oci_dir, "index.json")) as f:
        index = json.load(f)

    mfst_desc = index["manifests"][0]
    alg, hex_val = mfst_desc["digest"].split(":", 1)
    if alg != "sha256" or not re.fullmatch(r"[0-9a-f]+", hex_val):
        print("error: invalid manifest digest in index.json", file=sys.stderr)
        sys.exit(1)
    with open(os.path.join(oci_dir, "blobs", alg, hex_val)) as f:
        manifest = json.load(f)

    cfg_alg, cfg_hex = manifest["config"]["digest"].split(":", 1)
    if cfg_alg != "sha256" or not re.fullmatch(r"[0-9a-f]+", cfg_hex):
        print("error: invalid config digest in manifest", file=sys.stderr)
        sys.exit(1)
    with open(os.path.join(oci_dir, "blobs", cfg_alg, cfg_hex)) as f:
        cfg = json.load(f)

    for layer_desc in manifest["layers"]:
        l_alg, l_hex = layer_desc["digest"].split(":", 1)
        if l_alg != "sha256" or not re.fullmatch(r"[0-9a-f]+", l_hex):
            print("error: invalid layer digest", file=sys.stderr)
            sys.exit(1)
        layer_path = os.path.join(oci_dir, "blobs", l_alg, l_hex)
        print(f"  extracting layer sha256:{l_hex[:12]}...", file=sys.stderr)
        with tarfile.open(layer_path, mode="r:*") as tf:
            _extract_layer_tar(tf, rootfs)

    return cfg


def _extract_docker_save_to_rootfs(tar_path: str, rootfs: str) -> dict:
    """Extract a docker-save tar into *rootfs*, return parsed config."""
    with tarfile.open(tar_path, mode="r:*") as outer:
        mf_obj = outer.extractfile("manifest.json")
        if not mf_obj:
            print("error: manifest.json not found in docker-save tar",
                  file=sys.stderr)
            sys.exit(1)
        manifest_list = json.load(mf_obj)
        entry = manifest_list[0]

        cfg_obj = outer.extractfile(entry["Config"])
        cfg = json.load(cfg_obj) if cfg_obj else {}

        for layer_rel in entry["Layers"]:
            layer_member = outer.getmember(layer_rel)
            layer_f = outer.extractfile(layer_member)
            if not layer_f:
                continue
            layer_data = io.BytesIO(layer_f.read())
            short = layer_rel.split("/")[0][:12]
            print(f"  extracting layer {short}...", file=sys.stderr)
            with tarfile.open(fileobj=layer_data, mode="r:*") as inner:
                _extract_layer_tar(inner, rootfs)

    return cfg


# ── Build-state ──────────────────────────────────────────────────────────────

class _State:
    dockerignore: "_DockerIgnore"

    def __init__(self, context_dir: str, build_args: dict,
                 build_secrets: dict, arch: str):
        self.context_dir = os.path.abspath(context_dir)
        self.build_args = dict(build_args)
        self.build_secrets = dict(build_secrets)  # id -> host path
        self.dockerignore = _DockerIgnore(self.context_dir)
        self.arch = arch
        self.rootfs: str = ""
        self.env: list = []
        self.entrypoint = None
        self.cmd = None
        self.workdir = "/"
        self.labels: dict = {}
        self.user = ""
        self.exposed: list = []
        self.shell: list = ["/bin/sh", "-c"]
        # Multi-stage: finished stages by name and by index -> _Stage.
        self.stages: dict = {}
        self.stage_index = -1
        self.stage_name = None
        self.cmd_set_in_stage = False
        self.copy_images: dict = {}  # COPY --from=<image> -> unpacked root
        self.tmpdir = ""


class _Stage:
    """A finished build stage: its rootfs and the config it would emit."""

    def __init__(self, state: "_State"):
        self.rootfs = state.rootfs
        self.env = list(state.env)
        self.entrypoint = state.entrypoint
        self.cmd = state.cmd
        self.workdir = state.workdir
        self.labels = dict(state.labels)
        self.user = state.user
        self.shell = list(state.shell)


_ARCH_ALIASES = {"amd64": {"amd64", "x86_64"}, "arm64": {"arm64", "aarch64"}}


def _check_platform(state: "_State", platform: str) -> None:
    """FROM --platform: only the build's own linux/<arch> can be built."""
    os_part, _, rest = platform.partition("/")
    arch_part = rest.split("/", 1)[0]
    if os_part != "linux" or \
            arch_part not in _ARCH_ALIASES.get(state.arch, {state.arch}):
        print(f"error: FROM --platform={platform}: this build targets "
              f"linux/{state.arch} (use --arch to change it)",
              file=sys.stderr)
        sys.exit(1)


# ── RUN --mount helpers ──────────────────────────────────────────────────────

def _mount_bind(m: dict, state: _State) -> tuple:
    """
    --mount=type=bind,source=<src>,target=<dst>[,ro]

    Bind-mounts a path from the build context into the rootfs for the
    duration of the RUN step.  Default is read-only; pass rw to allow writes
    (changes are NOT captured into the layer).
    Returns (shell_cmd, host_cleanup_path_or_None).
    """
    src_rel = m.get("source") or m.get("src") or m.get("from") or "."
    dst = m.get("target") or m.get("dst")
    if not dst:
        print("error: --mount=type=bind requires target=", file=sys.stderr)
        sys.exit(1)

    try:
        candidate = _context_source_candidate(state.context_dir, src_rel)
        src = _resolve_context_candidate(state.context_dir, candidate)
    except ValueError:
        print(f"error: --mount=type=bind source escapes build context: "
              f"{src_rel}", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(src):
        print(f"error: --mount=type=bind source not found: {src_rel}",
              file=sys.stderr)
        sys.exit(1)
    if _context_source_ignored(state, candidate, src):
        print(f"error: --mount=type=bind source excluded by .dockerignore: "
              f"{src_rel}", file=sys.stderr)
        sys.exit(1)

    try:
        dst_in_rootfs = _safe_resolve_follow(
            state.rootfs, "/" + dst.lstrip("/"))
    except ValueError as exc:
        print(f"error: --mount=type=bind target escapes rootfs: {exc}",
              file=sys.stderr)
        sys.exit(1)
    is_dir = os.path.isdir(src)
    if is_dir:
        if os.path.lexists(dst_in_rootfs) and \
                not os.path.isdir(dst_in_rootfs):
            print("error: --mount=type=bind directory source requires a "
                  "directory target", file=sys.stderr)
            sys.exit(1)
        os.makedirs(dst_in_rootfs, exist_ok=True)
    else:
        if os.path.isdir(dst_in_rootfs):
            print("error: --mount=type=bind file source requires a file "
                  "target", file=sys.stderr)
            sys.exit(1)
        os.makedirs(os.path.dirname(dst_in_rootfs), exist_ok=True)
        if not os.path.lexists(dst_in_rootfs):
            with open(dst_in_rootfs, "w"):
                pass

    ro = "rw" not in m
    remount = (
        f"; mount -o remount,bind,ro {shlex.quote(dst_in_rootfs)}"
        if ro else ""
    )
    cmd = (
        f"mount --bind {shlex.quote(src)} {shlex.quote(dst_in_rootfs)}"
        + remount
    )
    # Bind mounts from context: don't delete the target, it may be a
    # real directory in the rootfs.  We just leave the empty placeholder.
    return cmd, None


def _mount_secret(m: dict, state: _State) -> tuple:
    """
    --mount=type=secret,id=<id>[,target=<path>][,required]

    Mounts a secret file provided via --build-secret id=<id>,src=<host-path>
    into the container for this RUN step only.  The file is NOT written into
    the image layer — only the empty mount-target placeholder is, which is
    also cleaned up after the step.
    """
    secret_id = m.get("id", "")
    if not secret_id:
        print("error: --mount=type=secret requires id=", file=sys.stderr)
        sys.exit(1)

    src = state.build_secrets.get(secret_id)
    if not src:
        if m.get("required") is True or m.get("required") == "true":
            print("error: --mount=type=secret: required secret not provided"
                  " (use --build-secret id=<id>,src=<path>)",
                  file=sys.stderr)
            sys.exit(1)
        print("  warning: optional secret not provided, skipping mount",
              file=sys.stderr)
        return "", None

    if not os.path.exists(src):
        print("error: --build-secret: secret file not found",
              file=sys.stderr)
        sys.exit(1)

    target = m.get("target") or m.get("dst") or f"/run/secrets/{secret_id}"
    dst_in_rootfs = _safe_resolve(state.rootfs, "/" + target.lstrip("/"))
    os.makedirs(os.path.dirname(dst_in_rootfs), exist_ok=True)
    # Create empty placeholder; will be cleaned up after RUN completes.
    if not os.path.exists(dst_in_rootfs):
        with open(dst_in_rootfs, "w"):
            pass

    cmd = (
        f"mount --bind {shlex.quote(src)} {shlex.quote(dst_in_rootfs)}"
        f"; mount -o remount,bind,ro {shlex.quote(dst_in_rootfs)}"
    )
    # Remove the placeholder after the step so it's not in the layer.
    return cmd, dst_in_rootfs


def _mount_ssh(m: dict, state: _State) -> tuple:
    """
    --mount=type=ssh[,id=<id>][,target=<path>][,required]

    Forwards the host SSH agent socket ($SSH_AUTH_SOCK) into the build
    container.  Sets SSH_AUTH_SOCK inside the container to the target path.

    The socket directory is bind-mounted read-only; the mount and the
    placeholder file are removed after the RUN step.
    """
    ssh_sock = os.environ.get("SSH_AUTH_SOCK", "")
    if not ssh_sock or not os.path.exists(ssh_sock):
        required = m.get("required") is True or m.get("required") == "true"
        msg = ("error" if required else "warning")
        print(f"  {msg}: --mount=type=ssh: SSH_AUTH_SOCK not set or missing",
              file=sys.stderr)
        if required:
            sys.exit(1)
        return "", None

    target = (m.get("target") or m.get("dst")
              or "/run/buildkit/ssh_agent.0")
    dst_in_rootfs = _safe_resolve(state.rootfs, "/" + target.lstrip("/"))
    os.makedirs(os.path.dirname(dst_in_rootfs), exist_ok=True)
    # Create a regular-file placeholder for the socket bind-mount.
    if not os.path.lexists(dst_in_rootfs):
        with open(dst_in_rootfs, "w"):
            pass

    # Bind-mount the socket file.  The mount namespace is discarded when
    # the RUN step exits so this never leaks outside the build step.
    cmd = f"mount --bind {shlex.quote(ssh_sock)} {shlex.quote(dst_in_rootfs)}"

    # Expose SSH_AUTH_SOCK inside the container via the temp script env.
    # We patch state.env temporarily in _do_run.
    m["_resolved_target"] = target  # pass back the in-container path

    return cmd, dst_in_rootfs


def _mount_cache(m: dict, state: _State) -> tuple:
    """
    --mount=type=cache,target=<path>[,id=<id>][,sharing=locked|shared|private]

    Persistent cache directory stored at ~/.cache/oci2bin/build-cache/<id>.
    Contents survive across builds but are NOT included in the image layer.
    """
    target = m.get("target") or m.get("dst")
    if not target:
        print("error: --mount=type=cache requires target=", file=sys.stderr)
        sys.exit(1)

    cache_id = m.get("id") or target.replace("/", "_").strip("_")
    # Sanitise cache_id: only allow safe characters.
    safe_id = re.sub(r"[^a-zA-Z0-9._-]", "_", cache_id)
    cache_dir = os.path.expanduser(
        os.path.join("~", ".cache", "oci2bin", "build-cache", safe_id))
    os.makedirs(cache_dir, exist_ok=True)

    dst_in_rootfs = _safe_resolve(state.rootfs, "/" + target.lstrip("/"))
    os.makedirs(dst_in_rootfs, exist_ok=True)

    cmd = f"mount --bind {shlex.quote(cache_dir)} {shlex.quote(dst_in_rootfs)}"
    # Do NOT clean up dst_in_rootfs — it's a real directory we created and
    # the layer should contain it (empty).  Only the cache contents are transient.
    return cmd, None


def _mount_tmpfs(m: dict, state: _State) -> tuple:
    """
    --mount=type=tmpfs,target=<path>[,size=<bytes>]

    In-memory filesystem for the RUN step only; discarded on exit.
    """
    target = m.get("target") or m.get("dst")
    if not target:
        print("error: --mount=type=tmpfs requires target=", file=sys.stderr)
        sys.exit(1)

    dst_in_rootfs = _safe_resolve(state.rootfs, "/" + target.lstrip("/"))
    os.makedirs(dst_in_rootfs, exist_ok=True)

    opts = ""
    if "size" in m:
        # Validate: must be a plain integer (bytes)
        if not re.fullmatch(r"[0-9]+", str(m["size"])):
            print("error: --mount=type=tmpfs,size= must be an integer",
                  file=sys.stderr)
            sys.exit(1)
        opts = f",size={m['size']}"

    cmd = f"mount -t tmpfs tmpfs{opts} {shlex.quote(dst_in_rootfs)}"
    return cmd, None


def _build_mount_cmds(mounts: list, state: _State) -> tuple:
    """
    Translate a list of mount spec dicts into (shell_cmd_list, cleanup_paths).

    shell_cmd_list — commands to run inside the unshare namespace before chroot
    cleanup_paths  — host paths to remove from rootfs after the RUN step
    """
    cmds: list = []
    cleanup: list = []
    ssh_targets: list = []

    handlers = {
        "bind":  _mount_bind,
        "secret": _mount_secret,
        "ssh":   _mount_ssh,
        "cache": _mount_cache,
        "tmpfs": _mount_tmpfs,
    }

    for m in mounts:
        mtype = m.get("type", "bind")
        handler = handlers.get(mtype)
        if handler is None:
            print(f"  warning: unsupported mount type: {mtype!r}",
                  file=sys.stderr)
            continue
        cmd, cleanup_path = handler(m, state)
        if cmd:
            cmds.append(cmd)
        if cleanup_path:
            cleanup.append(cleanup_path)
        if mtype == "ssh" and "_resolved_target" in m:
            ssh_targets.append(m["_resolved_target"])

    return cmds, cleanup, ssh_targets


# ── Instruction handlers ─────────────────────────────────────────────────────

def _parse_from(state: _State, args: str) -> tuple:
    """Split `[--platform=P] IMAGE [AS NAME]` into (image, stage_name)."""
    words = args.split()
    while words and words[0].startswith("--"):
        flag = words.pop(0)
        if flag.startswith("--platform="):
            _check_platform(state, flag[len("--platform="):])
        elif flag == "--platform" and words:
            _check_platform(state, words.pop(0))
        else:
            print(f"error: FROM: unsupported option {flag!r}",
                  file=sys.stderr)
            sys.exit(1)
    if not words:
        print("error: FROM requires an image", file=sys.stderr)
        sys.exit(1)
    image = words[0]
    name = None
    if len(words) == 3 and words[1].lower() == "as":
        name = words[2].lower()
    elif len(words) != 1:
        print(f"error: FROM: cannot parse {args!r}", file=sys.stderr)
        sys.exit(1)
    return image, name


def _materialize_image(state: _State, image: str, dest: str) -> dict:
    """Unpack *image* (scratch, a local OCI layout, or a registry image)
    into *dest* and return its image config dict."""
    if image.lower() == "scratch":
        print("oci2bin: FROM scratch — empty rootfs", file=sys.stderr)
        return {}

    if os.path.isdir(image) and os.path.exists(
            os.path.join(image, "oci-layout")):
        print(f"oci2bin: FROM {image} (local OCI layout)", file=sys.stderr)
        return _extract_oci_to_rootfs(image, dest)

    tmpdir = state.tmpdir
    # Remote image: prefer docker, then podman (CLI-compatible save/pull),
    # then skopeo (daemonless copy into an OCI layout). Same precedence as the
    # top-level `oci2bin` wrapper.
    engine = "docker" if shutil.which("docker") else (
        "podman" if shutil.which("podman") else None)
    if engine:
        print(f"oci2bin: FROM {image} ({engine} pull)", file=sys.stderr)
        subprocess.run([engine, "pull", "--platform", f"linux/{state.arch}",
                        image], check=True)
        save_tar = os.path.join(tmpdir, "base.tar")
        subprocess.run([engine, "save", "-o", save_tar, image], check=True)
        cfg = _extract_docker_save_to_rootfs(save_tar, dest)
        os.unlink(save_tar)
        return cfg

    if shutil.which("skopeo"):
        print(f"oci2bin: FROM {image} (skopeo copy, no daemon)",
              file=sys.stderr)
        oci_dir = tempfile.mkdtemp(dir=tmpdir, prefix="from_oci_")
        subprocess.run(["skopeo", "copy",
                        "--override-os", "linux",
                        "--override-arch", state.arch,
                        f"docker://{image}",
                        f"oci:{oci_dir}:latest"], check=True)
        cfg = _extract_oci_to_rootfs(oci_dir, dest)
        shutil.rmtree(oci_dir, ignore_errors=True)
        return cfg

    print(f"error: FROM {image!r}: not a local OCI dir and no "
          f"docker/podman/skopeo found", file=sys.stderr)
    sys.exit(1)


def _finish_stage(state: _State) -> None:
    """Record the current stage (by index and by its AS name, if any) so a
    later FROM or COPY --from can use it."""
    if state.stage_index < 0 or not state.rootfs:
        return
    stage = _Stage(state)
    state.stages[str(state.stage_index)] = stage
    if state.stage_name:
        state.stages[state.stage_name] = stage


def _do_from(state: _State, args: str, tmpdir: str) -> None:
    state.tmpdir = tmpdir
    image, name = _parse_from(state, args)
    _finish_stage(state)
    state.stage_index += 1
    state.stage_name = name

    state.rootfs = tempfile.mkdtemp(dir=tmpdir, prefix="rootfs_")
    state.env = []
    state.entrypoint = None
    state.cmd = None
    state.workdir = "/"
    state.labels = {}
    state.user = ""
    state.shell = ["/bin/sh", "-c"]
    state.cmd_set_in_stage = False

    base = state.stages.get(image.lower())
    if base is not None:
        # FROM <earlier stage>: start from a copy of its filesystem/config.
        print(f"oci2bin: FROM stage {image}", file=sys.stderr)
        shutil.copytree(base.rootfs, state.rootfs, symlinks=True,
                        dirs_exist_ok=True)
        state.env = list(base.env)
        state.entrypoint = base.entrypoint
        state.cmd = base.cmd
        state.workdir = base.workdir
        state.labels = dict(base.labels)
        state.user = base.user
        state.shell = list(base.shell)
        return

    _inherit_config(state, _materialize_image(state, image, state.rootfs))


def _inherit_config(state: _State, cfg: dict) -> None:
    c = cfg.get("config", {})
    if c.get("Env"):
        state.env = list(c["Env"])
    if c.get("Entrypoint"):
        state.entrypoint = list(c["Entrypoint"])
    if c.get("Cmd"):
        state.cmd = list(c["Cmd"])
    if c.get("WorkingDir"):
        state.workdir = c["WorkingDir"]
    if c.get("Labels"):
        state.labels.update(c["Labels"])
    if c.get("User"):
        state.user = c["User"]


def _copy_source_root(state: _State, ref: str) -> str:
    """COPY --from=REF: a finished stage (by AS name or index) or an image,
    materialized once per build.  Returns the root to copy from."""
    stage = state.stages.get(ref.lower())
    if stage is not None:
        return stage.rootfs
    cache = state.copy_images
    if ref not in cache:
        dest = tempfile.mkdtemp(dir=state.tmpdir, prefix="copyfrom_")
        _materialize_image(state, ref, dest)
        cache[ref] = dest
    return cache[ref]


def _apply_chmod(path: str, mode: int) -> None:
    """COPY --chmod: apply *mode* to *path* and, for a directory, to
    everything copied below it (symlinks are left alone)."""
    if os.path.islink(path):
        return
    os.chmod(path, mode)
    if os.path.isdir(path):
        for dirpath, dirnames, filenames in os.walk(path):
            for name in dirnames + filenames:
                full = os.path.join(dirpath, name)
                if not os.path.islink(full):
                    os.chmod(full, mode)


def _do_copy(state: _State, args: str, heredocs=None) -> None:
    parts = shlex.split(args)
    copy_from = None
    chmod_mode = None
    while parts and parts[0].startswith("--"):
        flag = parts.pop(0)
        if flag.startswith("--from="):
            copy_from = flag[len("--from="):]
        elif flag.startswith("--chmod="):
            try:
                chmod_mode = int(flag[len("--chmod="):], 8)
            except ValueError:
                print(f"error: COPY {flag}: expected an octal mode",
                      file=sys.stderr)
                sys.exit(1)
        elif flag.startswith("--chown="):
            # This builder emits a single layer in which every entry is
            # owned by root (from_chroot.build_layer); an owner cannot be
            # carried through, so say so instead of dropping it silently.
            print(f"  warning: COPY {flag}: ownership is not preserved by "
                  f"this builder; files will be owned by root",
                  file=sys.stderr)
        elif flag == "--link":
            pass  # a BuildKit cache optimisation; no effect on the result
        else:
            print(f"error: COPY: unsupported option {flag!r}",
                  file=sys.stderr)
            sys.exit(1)
    if heredocs:
        _copy_heredocs(state, parts, heredocs, chmod_mode)
        return
    if len(parts) < 2:
        print(f"error: COPY requires at least src and dst: {args!r}",
              file=sys.stderr)
        sys.exit(1)

    srcs, dst_rel = parts[:-1], parts[-1]
    dst_container = dst_rel if os.path.isabs(dst_rel) else \
        os.path.join(state.workdir, dst_rel)
    dst_container = posixpath.normpath(dst_container.replace(os.sep, "/"))
    try:
        dst_host = _safe_resolve(state.rootfs, dst_container)
    except ValueError as exc:
        print(f"error: COPY destination escapes rootfs: {exc}",
              file=sys.stderr)
        sys.exit(1)
    if dst_rel.endswith("/"):
        try:
            dst_host_followed = _safe_resolve_follow(state.rootfs,
                                                     dst_container)
        except ValueError as exc:
            print(f"error: COPY destination escapes rootfs: {exc}",
                  file=sys.stderr)
            sys.exit(1)
        dst_is_dir = True
    else:
        try:
            dst_host_followed = _safe_resolve_follow(state.rootfs,
                                                     dst_container)
            dst_is_dir = os.path.isdir(dst_host_followed)
        except ValueError as exc:
            if os.path.islink(dst_host):
                dst_is_dir = False
            else:
                print(f"error: COPY destination escapes rootfs: {exc}",
                      file=sys.stderr)
                sys.exit(1)

    candidates: list = []
    sources = []
    if copy_from is not None:
        # Paths name files inside the stage/image, resolved within its root
        # (absolute symlinks re-rooted); .dockerignore does not apply.
        src_root = _copy_source_root(state, copy_from)
        for src in srcs:
            container_src = src if src.startswith("/") else "/" + src
            src_path = _safe_resolve_follow(src_root, container_src)
            sources.append((src_path, src_path))
    else:
        for src in srcs:
            try:
                candidates.extend(_expand_context_glob(state.context_dir,
                                                       src))
            except ValueError as exc:
                print(f"error: COPY source escapes build context: {exc}",
                      file=sys.stderr)
                sys.exit(1)
        candidates = list(dict.fromkeys(candidates))

        for candidate in candidates:
            try:
                src_path = _resolve_context_candidate(
                    state.context_dir, candidate)
            except ValueError as exc:
                print(f"error: COPY source escapes build context: {exc}",
                      file=sys.stderr)
                sys.exit(1)
            if _context_source_ignored(state, candidate, src_path):
                continue
            sources.append((candidate, src_path))

    if not sources:
        print(f"error: COPY: no files matched: {srcs}", file=sys.stderr)
        sys.exit(1)

    for candidate, src_path in sources:
        if not os.path.lexists(src_path):
            print(f"error: COPY source not found: {src_path}", file=sys.stderr)
            sys.exit(1)
        if os.path.isdir(src_path) and not os.path.islink(src_path):
            if copy_from is not None:
                saved = (state.context_dir, state.dockerignore.patterns)
                state.context_dir = src_path
                state.dockerignore.patterns = []
                try:
                    _copy_dir_contents(state, src_path, dst_container)
                finally:
                    state.context_dir, state.dockerignore.patterns = saved
            else:
                _copy_dir_contents(state, src_path, dst_container)
            if chmod_mode is not None:
                _apply_chmod(_safe_resolve_follow(state.rootfs,
                                                  dst_container), chmod_mode)
        else:
            if dst_is_dir or len(sources) > 1:
                try:
                    dst_dir = _safe_resolve_follow(state.rootfs,
                                                   dst_container)
                except ValueError as exc:
                    print(f"error: COPY destination escapes rootfs: {exc}",
                          file=sys.stderr)
                    sys.exit(1)
                os.makedirs(dst_dir, exist_ok=True)
                dest_container = posixpath.join(
                    dst_container, os.path.basename(candidate))
                try:
                    dest = _safe_resolve(state.rootfs, dest_container)
                except ValueError as exc:
                    print(f"error: COPY destination escapes rootfs: {exc}",
                          file=sys.stderr)
                    sys.exit(1)
            else:
                dest = dst_host
            _copy_leaf(src_path, dest)
            if chmod_mode is not None:
                _apply_chmod(dest, chmod_mode)


def _copy_heredocs(state: _State, parts: list, heredocs: list,
                   chmod_mode) -> None:
    """COPY <<NAME [<<NAME2...] DEST: write each heredoc body as a file."""
    if not parts:
        print("error: COPY heredoc needs a destination", file=sys.stderr)
        sys.exit(1)
    dst_rel = parts[-1]
    dst_container = posixpath.normpath(
        dst_rel if dst_rel.startswith("/") else
        posixpath.join(state.workdir, dst_rel))
    to_dir = dst_rel.endswith("/") or len(heredocs) > 1
    for word, body in heredocs:
        target = posixpath.join(dst_container, word) if to_dir \
            else dst_container
        dest = _safe_resolve(state.rootfs, target)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        _safe_unlink_if_present(dest)
        with open(dest, "w", encoding="utf-8") as f:
            f.write(body)
        os.chmod(dest, chmod_mode if chmod_mode is not None else 0o644)


def _do_run(state: _State, args: str, heredocs=None) -> None:
    """
    RUN [--mount=type=bind|secret|ssh|cache|tmpfs,...] <cmd>

    Executes <cmd> inside the rootfs using unshare --user --map-root-user
    so no real root privilege is required.  All --mount options are set up
    inside the new mount namespace and torn down automatically on exit;
    secret/ssh mounts leave no trace in the image layer.
    """
    cmd, mounts, unsupported = _parse_run_line(args)
    if unsupported:
        print("error: unsupported RUN option(s): " +
              ", ".join(unsupported),
              file=sys.stderr)
        print("error: RUN --network and --security are not implemented; "
              "refusing to silently degrade", file=sys.stderr)
        sys.exit(1)

    # Resolve inside the rootfs: /bin/sh is usually a symlink (alpine:
    # -> /bin/busybox) whose absolute target means nothing on the host.
    sh = _safe_resolve_follow(state.rootfs, "/bin/sh")
    if not os.path.isfile(sh):
        print("error: RUN requires /bin/sh in the rootfs "
              "(FROM scratch cannot execute RUN)", file=sys.stderr)
        sys.exit(1)

    proc_dir = os.path.join(state.rootfs, "proc")
    os.makedirs(proc_dir, exist_ok=True)

    # Translate --mount options into shell commands + cleanup list.
    mount_cmds, cleanup_paths, ssh_targets = _build_mount_cmds(mounts, state)

    # Build the RUN environment from scratch.  Inheriting os.environ
    # would expose the host's tokens, cloud creds, proxy settings, CI
    # variables, and so on to whatever command the Dockerfile chose
    # to run — which is exactly the leak BuildKit explicitly avoids.
    # Start with a minimal safe base, then layer image ENV + declared
    # build-args + the SSH_AUTH_SOCK pointer for --mount=type=ssh.
    run_env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:"
                "/usr/bin:/sbin:/bin",
        "HOME": "/root",
        "TERM": "xterm",
        # Disable debconf prompts in apt-based images during RUN steps.
        "DEBIAN_FRONTEND": "noninteractive",
    }
    # Image ENV (Dockerfile ENV directives + inherited from FROM image).
    for kv in state.env:
        if "=" in kv:
            k, v = kv.split("=", 1)
            run_env[k] = v
    # Declared build-args (only those the user explicitly passed via
    # --build-arg KEY=VAL — we read those into state.build_args at
    # parse time, so this is an allowlist, not a host leak).
    for k, v in state.build_args.items():
        run_env[k] = v
    if ssh_targets:
        # Point SSH_AUTH_SOCK at the first ssh mount target inside the container.
        run_env["SSH_AUTH_SOCK"] = ssh_targets[0]
    # `unshare` itself needs to find a few host commands; pull just
    # those control variables across without leaking secrets.
    for k in ("LANG", "LC_ALL"):
        if k in os.environ:
            run_env[k] = os.environ[k]

    # What runs inside the chroot, with Docker's semantics: exec form runs
    # the argv as is; shell form runs `SHELL + [cmd]` (default /bin/sh -c) —
    # no implicit `set -e`, which changed `RUN a; b`.  `RUN <<EOF` runs the
    # heredoc body as the script; `RUN cmd <<EOF` hands cmd plus its
    # heredocs to the shell, which implements them.
    exec_form = None if heredocs else _parse_json_array(cmd)
    if exec_form is not None:
        argv = exec_form
    else:
        script = cmd
        if heredocs:
            if _HEREDOC_RE.fullmatch(cmd.strip()) and len(heredocs) == 1:
                script = heredocs[0][1]
            else:
                script = cmd + "\n" + "".join(
                    body + word + "\n" for word, body in heredocs)
        argv = list(state.shell) + [script]

    user = (state.user or "").strip()
    if user and user.split(":", 1)[0] not in ("0", "root"):
        # Only uid 0 is mapped in the rootless build namespace, so a switch
        # to another user cannot happen; say so rather than pretend.
        print(f"  warning: RUN executes as root; USER {user} only applies "
              f"to the built image", file=sys.stderr)

    workdir = state.workdir or "/"
    in_root = ("mkdir -p -- \"$0\" 2>/dev/null; "
               "cd -- \"$0\" && exec \"$@\"")

    try:
        # Build the inner shell script that runs inside the unshare namespace:
        #   1. Mount proc — best-effort, and a failure is reported instead
        #      of aborting the step with no message under `sh -e`
        #   2. Apply RUN --mount bind-mounts (inside the new namespace only)
        #   3. chroot into rootfs, cd to WORKDIR and exec the command
        steps = [f"mount -t proc proc {shlex.quote(proc_dir)} || "
                 f"echo 'oci2bin: warning: RUN: could not mount /proc' >&2"]
        steps.extend(mount_cmds)
        steps.append(
            f"chroot {shlex.quote(state.rootfs)} /bin/sh -c "
            f"{shlex.quote(in_root)} {shlex.quote(workdir)} "
            + " ".join(shlex.quote(a) for a in argv)
        )
        inner = "\n".join(steps)

        subprocess.run(
            ["unshare", "--user", "--map-root-user",
             "--mount", "--pid", "--fork",
             "sh", "-ec", inner],
            check=True,
            env=run_env,
        )
    finally:
        # Remove secret/ssh placeholder files left as mount targets.
        for path in cleanup_paths:
            try:
                if os.path.islink(path) or os.path.isfile(path):
                    os.unlink(path)
                elif os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
            except OSError:
                pass


def _do_env(state: _State, args: str) -> None:
    if "=" in args.split()[0]:
        for pair in shlex.split(args):
            if "=" not in pair:
                print(f"error: ENV: malformed pair: {pair!r}", file=sys.stderr)
                sys.exit(1)
            k, v = pair.split("=", 1)
            state.env = [e for e in state.env if not e.startswith(k + "=")]
            state.env.append(f"{k}={v}")
    else:
        parts = args.split(None, 1)
        if len(parts) != 2:
            print(f"error: ENV: expected KEY VALUE, got: {args!r}",
                  file=sys.stderr)
            sys.exit(1)
        k, v = parts
        state.env = [e for e in state.env if not e.startswith(k + "=")]
        state.env.append(f"{k}={v}")


def _do_workdir(state: _State, args: str) -> None:
    wd = args.strip()
    if not os.path.isabs(wd):
        wd = os.path.join(state.workdir, wd)
    state.workdir = os.path.normpath(wd)
    try:
        wd_host = _safe_resolve(state.rootfs, state.workdir)
    except ValueError as exc:
        print(f"error: WORKDIR escapes rootfs: {exc}", file=sys.stderr)
        sys.exit(1)
    os.makedirs(wd_host, exist_ok=True)


# ── Main build loop ──────────────────────────────────────────────────────────

def build_from_dockerfile(dockerfile: str, out_dir: str, *,
                          context_dir: str,
                          build_args: dict,
                          build_secrets: dict,
                          arch: str) -> None:
    instructions = _parse_dockerfile(dockerfile)
    if not instructions:
        print("error: Dockerfile is empty", file=sys.stderr)
        sys.exit(1)
    # Only ARG may precede the first FROM (global build args, usable in
    # FROM lines).
    first = next((ins for ins, _a, _h in instructions if ins != "ARG"), None)
    if first != "FROM":
        print("error: Dockerfile must begin with FROM (after any ARG)",
              file=sys.stderr)
        sys.exit(1)

    state = _State(context_dir, build_args, build_secrets, arch)
    tmpdir = tempfile.mkdtemp(prefix="oci2bin_build_")
    state.tmpdir = tmpdir
    try:
        for instr, args, heredocs in instructions:
            if instr in _EXPANDED_INSTRUCTIONS:
                variables = dict(state.build_args)
                for kv in state.env:
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        variables[k] = v
                args = _expand_vars(args, variables)

            # Summarise: truncate long args for readability
            summary = args[:72].replace("\n", " ")
            print(f"oci2bin: {instr} {summary}", file=sys.stderr)

            if instr == "FROM":
                _do_from(state, args, tmpdir)
            elif instr in ("COPY", "ADD"):
                _do_copy(state, args, heredocs)
            elif instr == "RUN":
                _do_run(state, args, heredocs)
            elif instr == "ENV":
                _do_env(state, args)
            elif instr == "ENTRYPOINT":
                state.entrypoint = _parse_json_or_shell(args, state.shell)
                # Docker: setting ENTRYPOINT resets a CMD inherited from
                # the base image.
                if not state.cmd_set_in_stage:
                    state.cmd = None
            elif instr == "CMD":
                state.cmd = _parse_json_or_shell(args, state.shell)
                state.cmd_set_in_stage = True
            elif instr == "SHELL":
                shell = _parse_json_array(args)
                if not shell:
                    print("error: SHELL requires a JSON array form",
                          file=sys.stderr)
                    sys.exit(1)
                state.shell = shell
            elif instr == "WORKDIR":
                _do_workdir(state, args)
            elif instr == "LABEL":
                for pair in shlex.split(args):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        state.labels[k] = v
            elif instr == "USER":
                state.user = args.strip()
            elif instr == "EXPOSE":
                state.exposed.append(args.strip())
            elif instr == "ARG":
                name_default = args.strip().split("=", 1)
                name = name_default[0]
                if name not in state.build_args and len(name_default) == 2:
                    default = name_default[1]
                    if len(default) >= 2 and default[0] == default[-1] \
                            and default[0] in "'\"":
                        default = default[1:-1]
                    state.build_args[name] = default
            elif instr in ("MAINTAINER", "STOPSIGNAL", "HEALTHCHECK",
                           "ONBUILD", "VOLUME"):
                pass
            else:
                print(f"  warning: unsupported instruction: {instr}",
                      file=sys.stderr)

        if not state.rootfs:
            print("error: Dockerfile has no FROM instruction", file=sys.stderr)
            sys.exit(1)

        from_chroot.build_oci_layout(
            state.rootfs, out_dir,
            entrypoint=state.entrypoint,
            cmd=state.cmd,
            env=state.env or None,
            workdir=state.workdir,
            arch=arch,
            user=state.user,
            labels=state.labels,
        )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ── CLI ───────────────────────────────────────────────────────────────────────

def _parse_build_secret(s: str) -> tuple:
    """Parse 'id=<id>,src=<path>' → (id, path)."""
    kv = _parse_kvs(s)
    sid = kv.get("id", "")
    src = kv.get("src") or kv.get("source") or kv.get("from") or ""
    if not sid or not src:
        print("error: --build-secret must be id=<id>,src=<path>",
              file=sys.stderr)
        sys.exit(1)
    src = os.path.abspath(src)
    if not os.path.exists(src):
        print(f"error: --build-secret src not found: {src}", file=sys.stderr)
        sys.exit(1)
    return sid, src


def main() -> None:
    p = argparse.ArgumentParser(
        description="Build an OCI image layout from a Dockerfile")
    p.add_argument("dockerfile", nargs="?", default="Dockerfile",
                   help="Path to Dockerfile (default: ./Dockerfile)")
    p.add_argument("out_dir", help="Output OCI layout directory")
    p.add_argument("--context", default=".", metavar="DIR",
                   help="Build context directory (default: .)")
    p.add_argument("--build-arg", action="append", default=[],
                   metavar="KEY=VAL",
                   help="Build-time variable (repeatable)")
    p.add_argument("--build-secret", action="append", default=[],
                   metavar="id=<id>,src=<path>",
                   help="Secret file available to RUN --mount=type=secret "
                        "(repeatable)")
    p.add_argument("--arch", choices=["amd64", "arm64"], default="amd64",
                   help="Target CPU architecture")
    args = p.parse_args()

    dockerfile = os.path.abspath(args.dockerfile)
    if not os.path.isfile(dockerfile):
        print(f"error: Dockerfile not found: {dockerfile}", file=sys.stderr)
        sys.exit(1)

    build_args: dict = {}
    for kv in args.build_arg:
        if "=" not in kv:
            print(f"error: --build-arg must be KEY=VAL, got: {kv!r}",
                  file=sys.stderr)
            sys.exit(1)
        k, v = kv.split("=", 1)
        build_args[k] = v

    build_secrets: dict = {}
    for spec in args.build_secret:
        sid, src = _parse_build_secret(spec)
        build_secrets[sid] = src

    build_from_dockerfile(
        dockerfile, args.out_dir,
        context_dir=args.context,
        build_args=build_args,
        build_secrets=build_secrets,
        arch=args.arch,
    )


if __name__ == "__main__":
    main()
