# Quickstart

This page shows the smallest useful path: build a binary, run it, copy it to a
machine without Docker, and load it back into Docker if needed.

## Install

Build from the repository:

```bash
git clone https://github.com/latedeployment/oci2bin
cd oci2bin
make
```

Install to your path:

```bash
make install
```

Use a different install prefix:

```bash
make install PREFIX="$HOME/.local"
```

You can also run `./oci2bin` directly from the repository root.

## Check The Host

```bash
oci2bin doctor
```

The doctor command checks the build and runtime pieces `oci2bin` can use:

- compiler and static libc support
- Docker or Podman availability
- unprivileged user namespaces
- `newuidmap` and `newgidmap`
- seccomp, Landlock, and cgroup v2
- `slirp4netns` or `pasta`
- VM backend support

## Build One Binary

```bash
oci2bin alpine:latest
```

The default output name is derived from the image name:

```text
alpine_latest
```

Run it:

```bash
./alpine_latest
```

Override the image command:

```bash
./alpine_latest /bin/ls /etc
```

Use an explicit output name:

```bash
oci2bin nginx:1.25 my-nginx
./my-nginx
```

## Copy To Another Machine

```bash
oci2bin redis:7-alpine                                    # builds ./redis_7-alpine
scp ./redis_7-alpine deploy@server.example.com:/opt/redis/redis_7-alpine
ssh deploy@server.example.com /opt/redis/redis_7-alpine redis-server --port 6379
```

The target host does not need Docker installed.

## Pass Environment And Volumes

```bash
./redis_7-alpine -e REDIS_LOGLEVEL=notice -v /srv/redis:/data
```

Load variables from a file:

```bash
./myapp --env-file /etc/myapp.env
```

Mount secrets read-only:

```bash
./myapp --secret /etc/myapp/db_password:/run/secrets/db_password
```

## Load The Binary Back Into Docker

The output file is also a Docker-compatible saved-image tar archive:

```bash
docker load < redis_7-alpine
```

This is useful when a binary moves through a system as a single executable but
later needs to be inspected or re-imported as a normal image.

## Build From An OCI Layout

Use this when you do not want `oci2bin` to call Docker:

```bash
skopeo copy docker://redis:7-alpine oci:./redis-oci:latest
oci2bin --oci-dir ./redis-oci redis:7-alpine redis_7-alpine
```

## Build From A Chroot

```bash
oci2bin from-chroot ./rootfs -o myapp.bin \
  --entrypoint /usr/bin/myapp \
  --env APP_ENV=prod \
  --workdir /app
```

## Build From A Dockerfile Without Docker

```bash
oci2bin build-dockerfile -f Dockerfile -o myapp.bin --context .
```

Supported Dockerfile instructions are listed in the
[Build Binaries](build.md#build-from-a-dockerfile-without-docker) guide.

## Run Once Without Keeping The Binary

```bash
oci2bin run alpine:latest -- /bin/echo hello
```

This builds a temporary binary, executes it, and removes the temporary file.

