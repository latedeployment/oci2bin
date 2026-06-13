# Use Cases

The examples here show how features fit together in real commands.

## Ship A Small Service To A Server

Build locally:

```bash
oci2bin --strip --compress-binary zstd nginx:1.25 my-nginx
```

Copy and run:

```bash
scp ./my-nginx deploy@server.example.com:/opt/nginx/my-nginx
ssh deploy@server.example.com '/opt/nginx/my-nginx -p 8080:80 --net slirp'
```

Make a systemd unit:

```bash
oci2bin systemd ./my-nginx --restart always > my-nginx.service
```

Install the unit on the server:

```bash
mkdir -p ~/.config/systemd/user
cp my-nginx.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now my-nginx.service
```

## Package A Homelab App With Persistent State

```bash
oci2bin ghcr.io/example/rss:latest rss
./rss \
  --size pi4 \
  --overlay-persist /srv/rss/state \
  -v /srv/rss/config:/config \
  -p 8080:8080
```

Use `--size` to apply a resource profile, `--overlay-persist` to keep writable
rootfs changes, and `-v` for explicit host data.

## Run A Locked-Down Utility

```bash
oci2bin alpine:latest locked-alpine
./locked-alpine \
  --read-only \
  --tmpfs /tmp \
  --net none \
  --cap-drop all \
  --pids-limit 64 \
  --memory 256m \
  --cpus 0.5 \
  /bin/sh -c 'id && mount && ip addr'
```

This starts with a read-only rootfs, no network, no ambient capabilities, and
cgroup limits.

## Inject Config At Build Time

```bash
oci2bin \
  --add-file ./myapp.conf:/etc/myapp/myapp.conf \
  --add-dir ./templates:/usr/share/myapp/templates \
  myapp:latest \
  myapp.bin
```

Use build-time injection when every target should receive the same files. Use
runtime mounts when each target has different local state.

## Inject Secrets At Runtime

```bash
./myapp \
  --secret /etc/ssl/private/key.pem:/run/secrets/tls_key \
  --secret /etc/myapp/db_password
```

The default destination is `/run/secrets/<basename>`.

With TPM2-sealed systemd credentials:

```bash
systemd-creds encrypt --name=dbpass /dev/stdin /etc/credstore/dbpass.cred
./myapp --secret tpm2:dbpass:/run/secrets/db_password
```

## Build An Air-Gap Artifact

Pre-stage the image while online:

```bash
docker pull alpine:3.20
```

Then build offline:

```bash
oci2bin --offline-only alpine:3.20 alpine_3.20
```

From a staged OCI layout:

```bash
oci2bin --offline-only --oci-dir ./image-layout alpine:3.20 alpine_3.20
```

`--offline-only` refuses registry fetches, implies reproducible output, and
marks the binary metadata as hermetic.

## Sign A Binary And Require The Signature At Runtime

Create keys with your preferred key management flow, then build with a public
key policy:

```bash
oci2bin --require-signed pub.pem redis:7-alpine redis_7-alpine
oci2bin sign --key priv.pem --in redis_7-alpine
```

Run normally:

```bash
./redis_7-alpine
```

The binary refuses to run if the required signature is missing or invalid.

Verify explicitly:

```bash
oci2bin verify --key pub.pem --in redis_7-alpine
```

## Encrypt The Embedded Image

Recipient-based encryption:

```bash
oci2bin \
  --encrypt \
  --recipient age1example... \
  myapp:latest \
  myapp.bin

OCI2BIN_IDENTITY=/etc/oci2bin/identity.txt ./myapp.bin
```

Passphrase encryption:

```bash
oci2bin --passphrase --password-file ./pass.txt myapp:latest myapp.bin

OCI2BIN_PASSWORD_FILE=/etc/oci2bin/pass.txt ./myapp.bin
```

Encryption makes the embedded OCI payload opaque at rest.

## Debug A Container Entrypoint

```bash
./myapp --gdb
```

`--gdb` launches gdb inside the container with the image entrypoint as the
debuggee. It disables seccomp because debugging needs ptrace-related syscalls.

## Generate A Seccomp Profile

Trace one representative run:

```bash
./myapp --gen-seccomp myapp-seccomp.json -- /usr/bin/myapp --warm-up
```

Use the profile:

```bash
./myapp --seccomp-profile myapp-seccomp.json
```

## Run Multiple Binaries Together

Use pod mode when containers should share namespaces:

```bash
oci2bin pod run --net shared --ipc shared ./api ./worker ./sidecar
```

Use declarative stacks when you want a repeatable service group:

```bash
oci2bin up -f stack.yaml -d # the file's name: field names the stack
oci2bin stack logs mystack api -f # by stack name + service; -f follows
oci2bin down -f stack.yaml
```

## Build A VM-Mode Binary

```bash
oci2vm redis:7-alpine
./oci2vm_redis_7-alpine
```

`oci2vm` builds a binary that defaults to VM isolation. You can also build with
`oci2bin` and run with `--vm` when VM assets are embedded.

## Reconstruct A Binary From A Registry Round Trip

Build with an embedded loader:

```bash
oci2bin --embed-loader-layer redis:7-alpine redis_7-alpine
docker load < redis_7-alpine
docker tag redis:7-alpine registry.example.com/redis:7-alpine
docker push registry.example.com/redis:7-alpine
```

Later, rebuild the polyglot:

```bash
docker pull registry.example.com/redis:7-alpine
oci2bin reconstruct registry.example.com/redis:7-alpine --output redis_7-alpine
```

The loader can be stored either as an image layer or as chunked image labels.

## Compare Two Binaries

```bash
oci2bin diff app_v1 app_v2
```

Inspect filesystem changes from a persisted overlay:

```bash
oci2bin diff-fs /srv/app/state
```

## Snapshot A Running Service

```bash
oci2bin freeze mydb
oci2bin thaw mydb
```

Run a command while frozen, then thaw automatically:

```bash
oci2bin freeze mydb -- sqlite3 /data/app.db 'pragma integrity_check'
```

## AI Agent Integration

Start the MCP server:

```bash
oci2bin mcp-serve
```

Use it when an AI agent should inspect, build, or manage `oci2bin` artifacts
through a structured tool interface instead of shelling out manually.

