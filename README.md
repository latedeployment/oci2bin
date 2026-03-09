# oci2bin

**oci2bin** turns any Docker (OCI) image into a single file that is simultaneously a valid ELF executable and a valid POSIX tar archive — no daemon, no runtime, no installation required on the target machine.

```bash
# Package any image
./oci2bin ubuntu:latest        # -> ubuntu_latest
./oci2bin nginx:1.25 my-nginx  # -> my-nginx

# The output file has two personalities:
./my-nginx                        # runs as a rootless container
docker load < my-nginx            # imports as a Docker image
```

The output is a single self-contained file you can `scp`, commit to a repo, or attach to a release. On any Linux host with user namespace support (kernel ≥ 3.8, enabled by default since ~2014), it runs without root, without Docker, and without any installed container runtime.

## How it works

TAR puts its magic bytes (`ustar`) at byte 257. ELF puts its magic bytes (`\x7FELF`) at byte 0. These two formats have non-overlapping magic locations — so a 64-byte ELF header fits exactly inside the tar's 100-byte filename field, and both formats stay valid simultaneously.

```
Byte 0-3:     7f 45 4c 46    (ELF magic — the kernel sees an executable)
Byte 257-262: ustar\0        (tar magic — docker load sees an image archive)
```

When executed as an ELF, the embedded loader:
1. Reads the OCI image data from within itself (`/proc/self/exe`)
2. Extracts layers into a temporary rootfs
3. Patches the rootfs for single-UID namespace compatibility (see below)
4. Enters rootless namespaces (`CLONE_NEWUSER`, `CLONE_NEWNS`, `CLONE_NEWPID`, `CLONE_NEWUTS`)
5. Chroots into the rootfs and execs the container entrypoint

## Getting started

**Dependencies:** `musl-gcc`, `python3`, `docker`

```bash
# Fedora
sudo dnf install musl-gcc musl-devel musl-libc-static

# Debian/Ubuntu
sudo apt install musl-tools
```

Run `oci2bin` with any image — it compiles the loader on first use and pulls the image if it isn't local:

```bash
./oci2bin alpine:latest        # -> alpine_latest
./oci2bin ubuntu:22.04         # -> ubuntu_22.04
./oci2bin nginx:1.25 my-nginx  # -> my-nginx (explicit output name)
```

## Usage

```bash
# Run as a container
$ ./oci2bin.img
/ # cat /etc/os-release
NAME="Alpine Linux"
/ # whoami
root
/ # echo $$
1

# Load as a docker image
$ docker load < oci2bin.img
Loaded image: alpine:latest

# Verify the polyglot
$ file oci2bin.img
oci2bin.img: POSIX tar archive

$ xxd oci2bin.img | head -1
00000000: 7f45 4c46 0201 0100 ...  .ELF............

$ tar tf oci2bin.img
\177ELF\002\001\001
blobs/sha256/...
manifest.json
```

## Testing

```bash
# Fast unit tests — no Docker required (~5s)
make test-unit

# C unit tests only (TAP output)
make test-c

# Python unit tests only
make test-python

# Full suite including runtime tests (needs Docker + oci2bin.img)
make test

# Runtime integration tests only
make test-integration
```

The test suite covers:
- **`tests/test_build.py`** — 44 Python unit tests for `build_polyglot.py` helpers (`tar_octal`, `tar_checksum`, `build_tar_header`, `build_elf64_header`, `patch_markers`, `tar_pad`)
- **`tests/test_polyglot.py`** — structural invariants of the built `oci2bin.img` (ELF/TAR magic bytes, marker patching, embedded OCI tar validity, file permissions)
- **`tests/test_c_units.c`** — 50 TAP unit tests for `loader.c` internals (`json_get_string`, `json_get_array`, `json_parse_string_array`, `parse_opts`), compiled via `#include` trick
- **`tests/test_runtime.sh`** — 15 shell TAP tests covering `-v` volume mounts, `--entrypoint`, argument/exit-code passthrough, `docker load`, error handling, and Docker-free execution

## Disassembly

The polyglot has no ELF section headers (the ELF header is crammed into a tar filename field), so `objdump -d oci2bin.img` won't find `.text`. Use the original loader binary instead:

```bash
# Full disassembly with sections
objdump -d build/loader

# Disassemble the polyglot directly (raw binary mode with correct vaddr)
objdump -D -b binary -m i386:x86-64 \
  --adjust-vma=0x400000 \
  --start-address=0x4006ea \
  --stop-address=0x40b1fc \
  oci2bin.img
```

## File layout

```
[0-63]          ELF64 header (inside tar name field)
[64-511]        Tar header fields (mode, uid, gid, size, ustar magic at 257)
[512-4095]      Padding (page-aligns the loader code for mmap)
[4096-~75K]     Loader binary (statically linked, musl)
[~75K-end]      OCI image entries (manifest.json, config, layers)
```

## OCI image structure

The polyglot embeds a standard [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md) — the same format `docker save` produces since Docker v25. When you list the tar contents, you can see both the ELF loader and the OCI entries side by side:

```
oci2bin.img (single tar file)
├── \x7FELF...        ← loader binary (ELF header doubles as tar filename)
├── oci-layout        ← {"imageLayoutVersion":"1.0.0"}
├── index.json        ← OCI image index (points to manifest by digest)
├── manifest.json     ← Docker-compat manifest (Config + Layers paths)
└── blobs/sha256/
    ├── a40c03...     ← image config JSON (Cmd, Entrypoint, Env, etc.)
    ├── 589002...     ← filesystem layer (tar.gz of the rootfs)
    └── ...           ← other OCI descriptors
```

`docker load` simply ignores the unknown ELF entry and processes the OCI entries normally. The loader reads the same OCI data from within itself at a patched file offset.

## Rootfs patching for single-UID namespaces

The Linux kernel allows an unprivileged process to map exactly **one UID and one GID** into a user namespace without a setuid-root helper like `newuidmap`. The mapping is always `0 → real_uid` (container root = your host user).

This means any process inside the container that tries to call `seteuid(42)` or `setgroups([65534])` — as `apt`'s HTTP sandbox does — would get `EINVAL`/`EPERM`. The loader patches the extracted rootfs before entering the namespace to prevent this:

| File | What changes | Why |
|---|---|---|
| `/etc/passwd` | All UIDs remapped to `0` (except `65534`) | `getpwnam("_apt")` returns UID 0; `seteuid(0)` is a no-op |
| `/etc/group` | All GIDs remapped to `0` (except `65534`) | `setegid(0)` succeeds; `setgroups([0])` succeeds |
| `/etc/apt/apt.conf.d/99oci2bin` | `APT::Sandbox::User "root";` | Belt-and-suspenders: disables apt's privilege drop entirely |
| `/etc/resolv.conf` | Replaced with host file content | Symlink target (`/run/systemd/resolve/stub-resolv.conf`) doesn't exist in the chroot; host resolver is reachable because network namespace is **not** isolated |

GID `65534` is the kernel's overflow GID — the identity assigned to anything not in the `gid_map`. It must keep its name (`nogroup`/`nobody`) so tools that check unmapped groups don't error.

## Security notes

- No cryptographic protection on the tar envelope — the OCI spec verifies layer content by digest, but not the outer tar structure
- Namespace isolation is preserved — the rootless container runs in `CLONE_NEWUSER`, still unprivileged on the host

## References

- [OCI Image Spec](https://github.com/opencontainers/image-spec/blob/main/spec.md)
- [Polyglottar technique](https://sysfatal.github.io/polyglottar-en.html)
- [tar(5) format](https://www.gnu.org/software/tar/manual/html_node/Standard.html)
