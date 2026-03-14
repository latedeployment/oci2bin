#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ftw.h>
#include <grp.h>
#include <sys/resource.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

/*
 * These markers get patched by the polyglot builder.
 * They mark the offset and size of the OCI tar data within this binary.
 * The PATCHED flag is set to 1 by the builder to indicate successful patching.
 */
static volatile unsigned long OCI_DATA_OFFSET = 0xDEADBEEFCAFEBABEUL;
static volatile unsigned long OCI_DATA_SIZE   = 0xCAFEBABEDEADBEEFUL;
static volatile unsigned long OCI_PATCHED     = 0xAAAAAAAAAAAAAAAAUL;

/* VM blob markers — patched by build_polyglot.py --kernel / --initramfs.
 * Sentinels match build_polyglot.py KERNEL_OFFSET_MARKER etc. (little-endian).
 * Use KERNEL_DATA_PATCHED / INITRAMFS_DATA_PATCHED to check presence — never
 * compare OFFSET/SIZE against sentinel literals in C (embeds extra copies). */
static volatile unsigned long KERNEL_DATA_OFFSET    = 0x7E57AB1E7E57AB1EUL;
static volatile unsigned long KERNEL_DATA_SIZE      = 0xB00BB00BB00BB00BUL;
static volatile unsigned long KERNEL_DATA_PATCHED   = 0x5A5A5A5A5A5A5A5AUL;
static volatile unsigned long INITRAMFS_DATA_OFFSET = 0xC0FFEE00C0FFEE00UL;
static volatile unsigned long INITRAMFS_DATA_SIZE   = 0xFACEB00CFACEB00CUL;
static volatile unsigned long INITRAMFS_DATA_PATCHED = 0x6B6B6B6B6B6B6B6BUL;

/* Max layers / volumes / exec args we support */
#define MAX_LAYERS   128
#define MAX_VOLUMES   32
#define MAX_SECRETS   32
#define MAX_ARGS      64
#define MAX_ENV       64
#define BUF_SIZE    65536

/* ── runtime options parsed from argv ───────────────────────────────────── */

struct container_opts
{
    /* -v host:container  (up to MAX_VOLUMES pairs) */
    char* vol_host[MAX_VOLUMES];
    char* vol_ctr[MAX_VOLUMES];
    int   n_vols;

    /* --secret HOST_FILE[:CONTAINER_PATH]  (read-only file mounts) */
    char* secret_host[MAX_SECRETS];
    char* secret_ctr[MAX_SECRETS];    /* NULL → /run/secrets/<basename> */
    int   n_secrets;

    /* --entrypoint /path  (overrides OCI Entrypoint) */
    char* entrypoint;

    /* --workdir /path  (overrides OCI WorkingDir) */
    char* workdir;

    /* --net host|none|container:<PID>|slirp|pasta|slirp:H:C
     * NULL/"host" = host network; "none" = isolated; container:<PID> = join
     * "slirp" = userspace TCP/UDP via slirp4netns
     * "pasta" = userspace TCP/UDP via pasta
     * "slirp:HOST_PORT:CTR_PORT" = slirp with port forward */
    char* net;
    pid_t net_join_pid; /* >0: join this PID's network namespace */
    /* port-forwards for slirp mode: "HOST_PORT:CTR_PORT" strings */
    char* net_portfwd[16];
    int   n_portfwd;

    /* --ipc host|container:<PID>
     * host = share host IPC (default); container:<PID> = join that IPC ns */
    pid_t ipc_join_pid; /* >0: join this PID's IPC namespace */

    /* --read-only  (mount overlay so rootfs is not modified) */
    int read_only;

    /* --overlay-persist DIR  (persist overlay upper layer across runs) */
    char* overlay_persist;

    /* --ssh-agent  (forward host SSH_AUTH_SOCK into the container) */
    int ssh_agent;

    /* --no-seccomp  (disable the default seccomp filter) */
    int no_seccomp;
    int no_host_dev; /* --no-host-dev: skip bind-mounting host /dev nodes */

    /* --hostname NAME  (override the UTS hostname) */
    char* hostname;

    /* --tmpfs PATH  (extra tmpfs mounts inside the container) */
    char* tmpfs_mounts[MAX_VOLUMES];
    int   n_tmpfs;

    /* --ulimit TYPE=VALUE  (resource limits via setrlimit) */
    struct
    {
        int     resource;
        rlim_t  value;
    } ulimits[16];
    int n_ulimits;

    /* --user UID[:GID]  (run as this uid/gid inside the container) */
    uid_t run_uid;
    gid_t run_gid;
    int   has_user;   /* 1 if --user was given */

    /* --cap-drop / --cap-add  (capability management) */
    int      cap_drop_all;     /* 1 if --cap-drop all was given */
    uint64_t cap_drop_mask;    /* bitmask of individual caps to drop */
    uint64_t cap_add_mask;     /* bitmask of caps to add (ambient) */

    /* --device /dev/HOST[:CONTAINER]  (expose host device nodes) */
    char* devices[MAX_VOLUMES];      /* host device paths */
    char* device_ctr[MAX_VOLUMES];   /* container paths (NULL = same as host) */
    int   n_devices;

    /* --init  (run a zombie-reaping init as PID 1) */
    int use_init;

    /* --detach / -d  (fork to background, print child PID) */
    int detach;

    /* --verify-key PATH  (verify binary signature before execution) */
    char* verify_key;

    /* --memory MEM, --cpus FLOAT, --pids-limit N  (cgroup v2 limits) */
    long long cg_memory_bytes; /* 0 = unset */
    long      cg_cpu_quota;    /* 0 = unset; cpu.max quota in 100000 period */
    long      cg_pids;         /* 0 = unset */

    /* -e KEY=VALUE  (additional environment variables, up to MAX_ENV) */
    char* env_vars[MAX_ENV];
    int   n_env;

    /* extra args after flags (overrides OCI Cmd) */
    char** extra_args;
    int    n_extra;

    /* --vm / --vmm VMM  (microVM isolation) */
    int   use_vm;   /* 1 if --vm was given */
    char* vmm;      /* "cloud-hypervisor" | path; NULL = default */
};

/* ── tiny JSON helpers (just enough to parse manifest.json and config) ─── */

/* Find a JSON string value for a given key. Returns malloc'd string or NULL. */
static char* json_get_string(const char* json, const char* key)
{
    char needle[256];
    int nlen = snprintf(needle, sizeof(needle), "\"%s\"", key);
    if (nlen < 0 || (size_t)nlen >= sizeof(needle))
    {
        return NULL;    /* key too long — refuse to match a truncated needle */
    }
    const char* p = strstr(json, needle);
    if (!p)
    {
        return NULL;
    }
    p += strlen(needle);
    while (*p == ' ' || *p == ':' || *p == '\t' || *p == '\n')
    {
        p++;
    }
    if (*p != '"')
    {
        return NULL;
    }
    p++; /* skip opening quote */
    /* scan forward, honouring backslash escapes */
    const char* end = p;
    while (*end && *end != '"')
    {
        if (*end == '\\')
        {
            end++;
            if (!*end)
            {
                break;    /* truncated escape — stop */
            }
        }
        end++;
    }
    if (*end != '"')
    {
        return NULL;
    }
    size_t len = end - p;
    char* result = malloc(len + 1);
    if (!result)
    {
        return NULL;
    }
    memcpy(result, p, len);
    result[len] = '\0';
    return result;
}

/* Find a JSON array value for a given key. Returns malloc'd string (with []) or NULL. */
static char* json_get_array(const char* json, const char* key)
{
    char needle[256];
    int nlen = snprintf(needle, sizeof(needle), "\"%s\"", key);
    if (nlen < 0 || (size_t)nlen >= sizeof(needle))
    {
        return NULL;    /* key too long — refuse to match a truncated needle */
    }
    const char* p = strstr(json, needle);
    if (!p)
    {
        return NULL;
    }
    p += strlen(needle);
    while (*p == ' ' || *p == ':' || *p == '\t' || *p == '\n')
    {
        p++;
    }
    if (*p != '[')
    {
        return NULL;
    }
    /* find matching ] */
    int depth = 0;
    const char* start = p;
    while (*p)
    {
        if (*p == '[')
        {
            depth++;
        }
        if (*p == ']')
        {
            depth--;
            if (depth == 0)
            {
                break;
            }
        }
        p++;
    }
    if (depth != 0)
    {
        return NULL;    /* unmatched '[', string was truncated */
    }
    size_t len = p - start + 1;
    char* result = malloc(len + 1);
    if (!result)
    {
        return NULL;
    }
    memcpy(result, start, len);
    result[len] = '\0';
    return result;
}

/* Parse a JSON array of strings into an array. Returns count. */
static int json_parse_string_array(const char* arr, char** out, int max)
{
    int count = 0;
    const char* p = arr;
    while (*p && count < max)
    {
        p = strchr(p, '"');
        if (!p)
        {
            break;
        }
        p++; /* skip opening quote */
        const char* end = p;
        /* handle escaped characters safely */
        while (*end && *end != '"')
        {
            if (*end == '\\')
            {
                end++;
                if (!*end)
                {
                    break;    /* truncated escape at NUL — stop */
                }
            }
            end++;
        }
        if (*end != '"')
        {
            break;    /* unterminated string */
        }
        size_t len = end - p;
        out[count] = malloc(len + 1);
        if (!out[count])
        {
            break;
        }
        memcpy(out[count], p, len);
        out[count][len] = '\0';
        count++;
        p = end + 1;
    }
    return count;
}

/* JSON-escape src into dst (capacity dstsz).  Escapes " and \.
 * Returns 0 on success, -1 if the output would be truncated. */
static int json_escape_string(const char* src, char* dst, size_t dstsz)
{
    size_t out = 0;
    for (const char* p = src; *p; p++)
    {
        if (*p == '"' || *p == '\\')
        {
            if (out + 2 >= dstsz)
            {
                return -1;
            }
            dst[out++] = '\\';
            dst[out++] = *p;
        }
        else
        {
            if (out + 1 >= dstsz)
            {
                return -1;
            }
            dst[out++] = *p;
        }
    }
    dst[out] = '\0';
    return 0;
}

/* ── file helpers ────────────────────────────────────────────────────────── */

static char* read_file(const char* path, size_t* out_size)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        return NULL;
    }
    struct stat st;
    if (fstat(fd, &st) < 0)
    {
        close(fd);
        return NULL;
    }
    /* Reject files that are implausibly large or would overflow size_t + 1 */
    if (st.st_size < 0 || st.st_size > (off_t)256 * 1024 * 1024)
    {
        close(fd);
        return NULL;
    }
    char* buf = malloc((size_t)st.st_size + 1);
    if (!buf)
    {
        close(fd);
        return NULL;
    }
    ssize_t n = read(fd, buf, st.st_size);
    close(fd);
    if (n < 0)
    {
        free(buf);
        return NULL;
    }
    buf[n] = '\0';
    if (out_size)
    {
        *out_size = n;
    }
    return buf;
}

static int write_file(const char* path, const char* data, size_t len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
    {
        return -1;
    }
    ssize_t written = write(fd, data, len);
    close(fd);
    return (written == (ssize_t)len) ? 0 : -1;
}

/* Write to /proc files (no O_CREAT, no O_TRUNC) */
static int write_proc(const char* path, const char* data, size_t len)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0)
    {
        return -1;
    }
    ssize_t written = write(fd, data, len);
    close(fd);
    return (written == (ssize_t)len) ? 0 : -1;
}

/* Run a command, wait for it. Returns exit status. */
static int run_cmd(char* const argv[])
{
    pid_t pid = fork();
    if (pid < 0)
    {
        perror("fork");
        return -1;
    }
    if (pid == 0)
    {
        execvp(argv[0], argv);
        perror("execvp");
        _exit(127);
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* ── OCI image extraction ────────────────────────────────────────────────── */

/*
 * Extract the OCI tar data from ourselves into a temp directory,
 * then parse manifest.json and extract layers into a rootfs.
 *
 * Returns path to rootfs (static buffer) or NULL on failure.
 */
static char* extract_oci_rootfs(const char* self_path)
{
    static char rootfs[PATH_MAX];
    char tmpdir[] = "/tmp/oci2bin.XXXXXX";

    if (!mkdtemp(tmpdir))
    {
        perror("mkdtemp");
        return NULL;
    }

    /* 1. Extract the embedded OCI tar from ourselves */
    char oci_tar_path[PATH_MAX];
    snprintf(oci_tar_path, sizeof(oci_tar_path), "%s/image.tar", tmpdir);

    int self_fd = open(self_path, O_RDONLY);
    if (self_fd < 0)
    {
        perror("open self");
        return NULL;
    }

    if (lseek(self_fd, OCI_DATA_OFFSET, SEEK_SET) < 0)
    {
        perror("lseek");
        close(self_fd);
        return NULL;
    }

    int out_fd = open(oci_tar_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0)
    {
        perror("open oci tar");
        close(self_fd);
        return NULL;
    }

    unsigned long remaining = OCI_DATA_SIZE;
    char buf[BUF_SIZE];
    int write_error = 0;
    while (remaining > 0)
    {
        size_t to_read = remaining < BUF_SIZE ? remaining : BUF_SIZE;
        ssize_t n = read(self_fd, buf, to_read);
        if (n <= 0)
        {
            break;
        }
        ssize_t written = write(out_fd, buf, n);
        if (written != n)
        {
            write_error = 1;
            break;
        }
        remaining -= n;
    }
    close(self_fd);
    close(out_fd);
    if (write_error)
    {
        fprintf(stderr, "oci2bin: write error extracting OCI data (disk full?)\n");
        return NULL;
    }

    /* 2. Extract the OCI tar into tmpdir/oci/ */
    char oci_dir[PATH_MAX];
    snprintf(oci_dir, sizeof(oci_dir), "%s/oci", tmpdir);
    if (mkdir(oci_dir, 0755) < 0)
    {
        perror("mkdir oci_dir");
        return NULL;
    }

    char* tar_argv[] = {"tar", "xf", oci_tar_path, "-C", oci_dir,
                        "--no-same-permissions", "--no-same-owner", NULL
                       };
    if (run_cmd(tar_argv) != 0)
    {
        fprintf(stderr, "oci2bin: failed to extract OCI tar\n");
        return NULL;
    }

    /* 3. Read manifest.json */
    char manifest_path[PATH_MAX];
    if (snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json", oci_dir)
            >= (int)sizeof(manifest_path))
    {
        fprintf(stderr, "oci2bin: manifest path too long\n");
        return NULL;
    }
    size_t manifest_size;
    char* manifest = read_file(manifest_path, &manifest_size);
    if (!manifest)
    {
        fprintf(stderr, "oci2bin: cannot read manifest.json\n");
        return NULL;
    }

    /* 4. Parse manifest to get Config and Layers */
    char* config_path_rel = json_get_string(manifest, "Config");
    char* layers_json = json_get_array(manifest, "Layers");
    if (!config_path_rel || !layers_json)
    {
        fprintf(stderr, "oci2bin: cannot parse manifest.json\n");
        free(manifest);
        return NULL;
    }

    /* 5. Extract layers in order into rootfs */
    snprintf(rootfs, sizeof(rootfs), "%s/rootfs", tmpdir);
    if (mkdir(rootfs, 0755) < 0)
    {
        perror("mkdir rootfs");
        return NULL;
    }

    char* layers[MAX_LAYERS];
    int nlayers = json_parse_string_array(layers_json, layers, MAX_LAYERS);

    for (int i = 0; i < nlayers; i++)
    {
        /* Reject any layer path that tries to traverse out of oci_dir */
        if (strstr(layers[i], "..") != NULL || layers[i][0] == '/')
        {
            fprintf(stderr, "oci2bin: rejecting dangerous layer path: %s\n", layers[i]);
            free(layers[i]);
            continue;
        }

        char layer_path[PATH_MAX];
        int lplen = snprintf(layer_path, sizeof(layer_path), "%s/%s", oci_dir,
                             layers[i]);
        if (lplen < 0 || (size_t)lplen >= sizeof(layer_path))
        {
            fprintf(stderr, "oci2bin: layer path too long, skipping: %s\n", layers[i]);
            free(layers[i]);
            continue;
        }

        char* layer_argv[] = {"tar", "xf", layer_path, "-C", rootfs,
                              "--no-same-permissions", "--no-same-owner", NULL
                             };
        if (run_cmd(layer_argv) != 0)
        {
            fprintf(stderr, "oci2bin: failed to extract layer %s\n", layers[i]);
        }
        free(layers[i]);
    }

    /* 6. Read the image config to get Cmd/Entrypoint */
    /* Reject config paths that could traverse outside oci_dir */
    if (strstr(config_path_rel, "..") != NULL || config_path_rel[0] == '/')
    {
        fprintf(stderr, "oci2bin: rejecting dangerous config path: %s\n",
                config_path_rel);
        free(config_path_rel);
        free(layers_json);
        free(manifest);
        return NULL;
    }
    char config_full_path[PATH_MAX];
    int cfplen = snprintf(config_full_path, sizeof(config_full_path), "%s/%s",
                          oci_dir, config_path_rel);
    if (cfplen < 0 || (size_t)cfplen >= sizeof(config_full_path))
    {
        fprintf(stderr, "oci2bin: config path too long\n");
        free(config_path_rel);
        free(layers_json);
        free(manifest);
        return NULL;
    }
    size_t config_size;
    char* config = read_file(config_full_path, &config_size);
    if (config)
    {
        /* Write parsed entrypoint/env info for use inside the container */
        char* cmd        = json_get_array(config, "Cmd");
        char* entrypoint = json_get_array(config, "Entrypoint");
        char* env_json   = json_get_array(config, "Env");
        char* workdir    = json_get_string(config, "WorkingDir");

        char info_path[PATH_MAX];
        if (snprintf(info_path, sizeof(info_path), "%s/.oci2bin_config", rootfs)
                < (int)sizeof(info_path))
        {
            /* Allocate generously — Env arrays can be large */
            size_t bufsz = 16384;
            char*  info_buf = calloc(1, bufsz);
            if (info_buf)
            {
                /* JSON-escape WorkingDir to prevent injection into the config */
                char workdir_escaped[PATH_MAX * 2];
                const char* wdir_safe = NULL;
                if (workdir)
                {
                    if (json_escape_string(workdir, workdir_escaped,
                                           sizeof(workdir_escaped)) == 0)
                    {
                        wdir_safe = workdir_escaped;
                    }
                    /* If escaping fails (path absurdly long), omit WorkingDir */
                }
                int n = snprintf(info_buf, bufsz,
                                 "{\"Cmd\":%s,\"Entrypoint\":%s,"
                                 "\"Env\":%s,\"WorkingDir\":%s%s%s}",
                                 cmd        ? cmd        : "null",
                                 entrypoint ? entrypoint : "null",
                                 env_json   ? env_json   : "null",
                                 wdir_safe  ? "\""       : "null",
                                 wdir_safe  ? wdir_safe  : "",
                                 wdir_safe  ? "\""       : "");
                if (n > 0 && (size_t)n < bufsz)
                {
                    write_file(info_path, info_buf, strlen(info_buf));
                }
                free(info_buf);
            }
        }

        free(cmd);
        free(entrypoint);
        free(env_json);
        free(workdir);
        free(config);
    }

    free(config_path_rel);
    free(layers_json);
    free(manifest);

    return rootfs;
}

/* ── namespace + container entry ─────────────────────────────────────────── */

static int setup_uid_map(uid_t real_uid, gid_t real_gid)
{
    char map[64];

    /* Deny setgroups first (required before gid_map for unprivileged users) */
    if (write_proc("/proc/self/setgroups", "deny", 4) < 0)
    {
        /* May fail on older kernels, non-fatal */
    }

    snprintf(map, sizeof(map), "0 %d 1\n", real_uid);
    if (write_proc("/proc/self/uid_map", map, strlen(map)) < 0)
    {
        perror("write uid_map");
        return -1;
    }

    snprintf(map, sizeof(map), "0 %d 1\n", real_gid);
    if (write_proc("/proc/self/gid_map", map, strlen(map)) < 0)
    {
        perror("write gid_map");
        return -1;
    }

    return 0;
}

/*
 * Patch the extracted rootfs so that tools which try to drop privileges
 * (e.g. apt's _apt sandbox) succeed inside a single-UID user namespace.
 */
static void patch_rootfs_ids(const char* rootfs)
{
    /* ── /etc/passwd ── remap all uid:gid fields to 0:0 ── */
    char passwd_path[PATH_MAX];
    snprintf(passwd_path, sizeof(passwd_path), "%s/etc/passwd", rootfs);
    size_t passwd_sz;
    char* passwd = read_file(passwd_path, &passwd_sz);
    if (passwd)
    {
        FILE *out = fopen(passwd_path, "w");
        if (out)
        {
            char* line = passwd;
            while (*line)
            {
                char* nl = strchr(line, '\n');
                size_t line_len = nl ? (size_t)(nl - line + 1) : strlen(line);
                char linebuf[4096];
                if (line_len >= sizeof(linebuf))
                {
                    line += line_len;
                    continue;
                }
                memcpy(linebuf, line, line_len);
                linebuf[line_len] = '\0';

                char* f[7];
                int nf = 0;
                char* p = linebuf;
                while (nf < 7)
                {
                    f[nf++] = p;
                    p = strchr(p, ':');
                    if (!p)
                    {
                        break;
                    }
                    *p++ = '\0';
                }
                if (nf == 7)
                {
                    unsigned long uid = strtoul(f[2], NULL, 10);
                    unsigned long gid = strtoul(f[3], NULL, 10);
                    if (uid != 0 && uid != 65534)
                    {
                        snprintf(f[2], 8, "0");
                    }
                    if (gid != 0 && gid != 65534)
                    {
                        snprintf(f[3], 8, "0");
                    }
                    fprintf(out, "%s:%s:%s:%s:%s:%s:%s\n",
                            f[0], f[1], f[2], f[3], f[4], f[5], f[6]);
                }
                else
                {
                    fwrite(line, 1, line_len, out);
                    if (!nl)
                    {
                        fputc('\n', out);
                    }
                }
                line += line_len;
            }
            fclose(out);
        }
        free(passwd);
    }

    /* ── /etc/group ── remap all gid fields to 0 ── */
    char group_path[PATH_MAX];
    snprintf(group_path, sizeof(group_path), "%s/etc/group", rootfs);
    size_t group_sz;
    char* grp = read_file(group_path, &group_sz);
    if (grp)
    {
        FILE *out = fopen(group_path, "w");
        if (out)
        {
            char* line = grp;
            while (*line)
            {
                char* nl = strchr(line, '\n');
                size_t line_len = nl ? (size_t)(nl - line + 1) : strlen(line);
                char linebuf[4096];
                if (line_len >= sizeof(linebuf))
                {
                    line += line_len;
                    continue;
                }
                memcpy(linebuf, line, line_len);
                linebuf[line_len] = '\0';

                char* f[4];
                int nf = 0;
                char* p = linebuf;
                while (nf < 4)
                {
                    f[nf++] = p;
                    p = strchr(p, ':');
                    if (!p)
                    {
                        break;
                    }
                    *p++ = '\0';
                }
                if (nf == 4)
                {
                    unsigned long gid = strtoul(f[2], NULL, 10);
                    if (gid != 0 && gid != 65534)
                    {
                        snprintf(f[2], 8, "0");
                    }
                    fprintf(out, "%s:%s:%s:%s\n", f[0], f[1], f[2], f[3]);
                }
                else
                {
                    fwrite(line, 1, line_len, out);
                    if (!nl)
                    {
                        fputc('\n', out);
                    }
                }
                line += line_len;
            }
            fclose(out);
        }
        free(grp);
    }

    /* ── apt sandbox ── belt-and-suspenders for Debian/Ubuntu images ── */
    char apt_conf_dir[PATH_MAX];
    snprintf(apt_conf_dir, sizeof(apt_conf_dir), "%s/etc/apt/apt.conf.d", rootfs);
    struct stat st;
    if (stat(apt_conf_dir, &st) == 0 && S_ISDIR(st.st_mode))
    {
        char apt_conf[PATH_MAX];
        if (snprintf(apt_conf, sizeof(apt_conf), "%s/99oci2bin", apt_conf_dir)
                < (int)sizeof(apt_conf))
        {
            const char* conf = "APT::Sandbox::User \"root\";\n";
            write_file(apt_conf, conf, strlen(conf));
        }
    }

    /* ── /etc/resolv.conf ── copy host resolver into chroot ── */
    {
        size_t resolv_sz;
        char* resolv = read_file("/etc/resolv.conf", &resolv_sz);
        if (resolv)
        {
            char resolv_path[PATH_MAX];
            snprintf(resolv_path, sizeof(resolv_path), "%s/etc/resolv.conf", rootfs);
            unlink(resolv_path);
            write_file(resolv_path, resolv, resolv_sz);
            free(resolv);
        }
    }
}

/*
 * Set up volume bind mounts.  Called inside container_main() after chroot,
 * so paths are relative to the container rootfs (i.e. / is the rootfs).
 *
 * We receive host paths as absolute host paths — but after chroot those are
 * unreachable.  So we must do the mounts BEFORE chroot.  See container_main()
 * for the ordering.
 */
static void setup_volumes(const char* rootfs, struct container_opts *opts)
{
    for (int i = 0; i < opts->n_vols; i++)
    {
        const char* ctr_path = opts->vol_ctr[i];
        /* Container path must be absolute and must not contain '..' components */
        if (ctr_path[0] != '/')
        {
            fprintf(stderr, "oci2bin: -v container path must be absolute: %s\n", ctr_path);
            continue;
        }
        if (strstr(ctr_path, "..") != NULL)
        {
            fprintf(stderr, "oci2bin: -v container path must not contain '..': %s\n",
                    ctr_path);
            continue;
        }
        char dst[PATH_MAX];
        int dlen = snprintf(dst, sizeof(dst), "%s%s", rootfs, ctr_path);
        if (dlen < 0 || (size_t)dlen >= sizeof(dst))
        {
            fprintf(stderr, "oci2bin: -v destination path too long: %s%s\n", rootfs,
                    ctr_path);
            continue;
        }

        /* Create mount point if it doesn't exist */
        struct stat st;
        if (stat(dst, &st) != 0)
        {
            mkdir(dst, 0755);
        }

        /* Bind mount: host path → container path (pre-chroot, both accessible) */
        if (mount(opts->vol_host[i], dst, NULL, MS_BIND | MS_REC, NULL) < 0)
        {
            fprintf(stderr, "oci2bin: bind mount %s -> %s failed: %s\n",
                    opts->vol_host[i], opts->vol_ctr[i], strerror(errno));
        }
        else
        {
            fprintf(stderr, "oci2bin: mounted %s -> %s\n",
                    opts->vol_host[i], opts->vol_ctr[i]);
        }
    }
}

/*
 * Bind-mount secret files (read-only) into the container rootfs.
 * Each secret is a single file; if no container path is given,
 * it lands at /run/secrets/<basename>.  Called pre-chroot.
 */
static void setup_secrets(const char* rootfs, struct container_opts *opts)
{
    if (opts->n_secrets == 0)
    {
        return;
    }

    /* Ensure /run/secrets exists in the rootfs */
    char run_secrets[PATH_MAX];
    if (snprintf(run_secrets, sizeof(run_secrets), "%s/run/secrets", rootfs)
            >= (int)sizeof(run_secrets))
    {
        fprintf(stderr, "oci2bin: rootfs path too long for /run/secrets\n");
        return;
    }
    /* mkdir /run first in case it doesn't exist */
    char run_dir[PATH_MAX];
    if (snprintf(run_dir, sizeof(run_dir), "%s/run",
                 rootfs) >= (int)sizeof(run_dir))
    {
        fprintf(stderr, "oci2bin: rootfs path too long for /run\n");
        return;
    }
    mkdir(run_dir, 0755);   /* EEXIST is expected and fine */
    mkdir(run_secrets, 0700); /* EEXIST is expected and fine */

    for (int i = 0; i < opts->n_secrets; i++)
    {
        const char* src  = opts->secret_host[i];
        const char* ctr  = opts->secret_ctr[i]; /* may be NULL */

        /* Validate src is absolute and has no '..' */
        if (src[0] != '/')
        {
            fprintf(stderr, "oci2bin: --secret host path must be absolute: %s\n", src);
            continue;
        }
        if (strstr(src, "..") != NULL)
        {
            fprintf(stderr, "oci2bin: --secret host path must not contain '..': %s\n",
                    src);
            continue;
        }

        /* Derive container path */
        char ctr_buf[PATH_MAX];
        if (ctr)
        {
            if (ctr[0] != '/')
            {
                fprintf(stderr,
                        "oci2bin: --secret container path must be absolute: %s\n", ctr);
                continue;
            }
            if (strstr(ctr, "..") != NULL)
            {
                fprintf(stderr,
                        "oci2bin: --secret container path must not contain '..': %s\n",
                        ctr);
                continue;
            }
        }
        else
        {
            /* Default: /run/secrets/<basename of src> */
            const char* base = strrchr(src, '/');
            base = base ? base + 1 : src;
            if (base[0] == '\0')
            {
                fprintf(stderr, "oci2bin: --secret cannot derive basename from: %s\n",
                        src);
                continue;
            }
            int n = snprintf(ctr_buf, sizeof(ctr_buf), "/run/secrets/%s", base);
            if (n < 0 || (size_t)n >= sizeof(ctr_buf))
            {
                fprintf(stderr, "oci2bin: --secret container path too long for: %s\n",
                        src);
                continue;
            }
            ctr = ctr_buf;
        }

        /* Build full destination path inside rootfs */
        char dst[PATH_MAX];
        int dlen = snprintf(dst, sizeof(dst), "%s%s", rootfs, ctr);
        if (dlen < 0 || (size_t)dlen >= sizeof(dst))
        {
            fprintf(stderr, "oci2bin: --secret destination path too long: %s%s\n",
                    rootfs, ctr);
            continue;
        }

        /* Create parent directory if needed */
        char par[PATH_MAX];
        int plen = snprintf(par, sizeof(par), "%s", dst);
        if (plen > 0 && (size_t)plen < sizeof(par))
        {
            char* slash = strrchr(par, '/');
            if (slash && slash != par)
            {
                *slash = '\0';
                mkdir(par, 0755);
            }
        }

        /* Create an empty target file so bind-mount has something to attach to.
         * O_CREAT|O_EXCL is atomic: no stat() pre-check needed or wanted. */
        {
            int fd = open(dst, O_WRONLY | O_CREAT | O_EXCL, 0000);
            if (fd >= 0)
            {
                close(fd);
            }
            /* EEXIST is fine: file already present, bind-mount will attach to it */
        }

        /* Bind-mount the secret file read-only */
        if (mount(src, dst, NULL, MS_BIND, NULL) < 0)
        {
            fprintf(stderr, "oci2bin: secret bind mount %s -> %s failed: %s\n",
                    src, ctr, strerror(errno));
            continue;
        }
        /* Re-mount read-only with no-exec/no-suid/no-dev.
         * MS_BIND alone does not enforce read-only; a second mount(2) call is
         * required.  If this step fails the secret is left writable, so we
         * must unmount and skip rather than continue with a writable mount. */
        if (mount(NULL, dst, NULL,
                  MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOEXEC | MS_NOSUID | MS_NODEV,
                  NULL) < 0)
        {
            fprintf(stderr, "oci2bin: secret remount read-only %s failed: %s\n",
                    ctr, strerror(errno));
            /* Undo the writable bind-mount rather than leave it accessible */
            if (umount2(dst, MNT_DETACH) < 0)
            {
                fprintf(stderr,
                        "oci2bin: warning: could not unmount writable secret %s: %s\n",
                        dst, strerror(errno));
            }
            continue;
        }
        fprintf(stderr, "oci2bin: secret %s -> %s (read-only)\n", src, ctr);
    }
}

/* ── capability management ───────────────────────────────────────────────── */

/*
 * Inline definitions for capset(2) to avoid depending on libcap headers.
 * These match the kernel ABI defined in linux/capability.h.
 */
#define _LINUX_CAPABILITY_VERSION_3  0x20080522
#define _LINUX_CAPABILITY_U32S_3     2

struct cap_header
{
    uint32_t version;
    int      pid;
};

struct cap_data
{
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

/*
 * Map a capability name (case-insensitive, with or without "CAP_" prefix)
 * to its number (0-40). Returns -1 if unknown.
 */
static int cap_name_to_num(const char* name)
{
    /* normalise: skip "cap_" or "CAP_" prefix */
    const char* n = name;
    if ((n[0] == 'c' || n[0] == 'C') &&
            (n[1] == 'a' || n[1] == 'A') &&
            (n[2] == 'p' || n[2] == 'P') &&
            n[3] == '_')
    {
        n += 4;
    }
    /* lowercase comparison via tolower-equivalent inline */
#define STREQI(a, b) (strcasecmp((a), (b)) == 0)
    if (STREQI(n, "chown"))
    {
        return 0;
    }
    if (STREQI(n, "dac_override"))
    {
        return 1;
    }
    if (STREQI(n, "dac_read_search"))
    {
        return 2;
    }
    if (STREQI(n, "fowner"))
    {
        return 3;
    }
    if (STREQI(n, "fsetid"))
    {
        return 4;
    }
    if (STREQI(n, "kill"))
    {
        return 5;
    }
    if (STREQI(n, "setgid"))
    {
        return 6;
    }
    if (STREQI(n, "setuid"))
    {
        return 7;
    }
    if (STREQI(n, "setpcap"))
    {
        return 8;
    }
    if (STREQI(n, "net_bind_service"))
    {
        return 10;
    }
    if (STREQI(n, "net_raw"))
    {
        return 13;
    }
    if (STREQI(n, "sys_chroot"))
    {
        return 18;
    }
    if (STREQI(n, "mknod"))
    {
        return 27;
    }
    if (STREQI(n, "audit_write"))
    {
        return 29;
    }
    if (STREQI(n, "setfcap"))
    {
        return 31;
    }
    if (STREQI(n, "net_admin"))
    {
        return 12;
    }
    if (STREQI(n, "sys_admin"))
    {
        return 21;
    }
    if (STREQI(n, "sys_ptrace"))
    {
        return 19;
    }
    if (STREQI(n, "sys_module"))
    {
        return 16;
    }
    if (STREQI(n, "ipc_lock"))
    {
        return 14;
    }
#undef STREQI
    return -1;
}

/*
 * Apply capability bounding set drops and ambient cap raises.
 * Called after chroot/chdir and before seccomp.
 */
static void apply_capabilities(const struct container_opts* opts)
{
    int cap;

    if (opts->cap_drop_all)
    {
        /*
         * When --cap-drop all is combined with --cap-add, we must set up
         * permitted+inheritable and raise ambient BEFORE dropping from the
         * bounding set.  PR_CAP_AMBIENT_RAISE requires the cap to still be
         * in the bounding set at the time of the call; if we drop the bounding
         * set first, the ambient raise will always fail with EPERM.
         *
         * Order:
         *   1. capset: put add_mask into permitted+inheritable
         *   2. PR_CAP_AMBIENT_RAISE for each cap in add_mask
         *   3. PR_CAPBSET_DROP for every cap NOT in add_mask
         */
        if (opts->cap_add_mask)
        {
            /* Step 1: set permitted+inheritable so ambient raise can succeed */
            struct cap_header hdr;
            struct cap_data   data[2];
            memset(&hdr,  0, sizeof(hdr));
            memset(data,  0, sizeof(data));
            hdr.version = _LINUX_CAPABILITY_VERSION_3;
            hdr.pid     = 0;
            data[0].permitted   = (uint32_t)(opts->cap_add_mask & 0xFFFFFFFF);
            data[0].inheritable = (uint32_t)(opts->cap_add_mask & 0xFFFFFFFF);
            data[1].permitted   = (uint32_t)(opts->cap_add_mask >> 32);
            data[1].inheritable = (uint32_t)(opts->cap_add_mask >> 32);
            if (syscall(SYS_capset, &hdr, data) < 0)
            {
                fprintf(stderr, "oci2bin: capset for --cap-add: %s (non-fatal)\n",
                        strerror(errno));
            }
            /* Step 2: raise ambient caps (bounding set still intact here) */
            for (cap = 0; cap <= 40; cap++)
            {
                if (!((opts->cap_add_mask >> cap) & 1))
                {
                    continue;
                }
                if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE,
                          (unsigned long)cap, 0, 0) < 0)
                {
                    fprintf(stderr,
                            "oci2bin: PR_CAP_AMBIENT_RAISE %d: %s (non-fatal)\n",
                            cap, strerror(errno));
                }
            }
        }
        /* Step 3: drop all bounding-set caps except those being re-added */
        for (cap = 0; cap <= 40; cap++)
        {
            if ((opts->cap_add_mask >> cap) & 1)
            {
                continue; /* keep in bounding set — ambient needs it */
            }
            if (prctl(PR_CAPBSET_DROP, (unsigned long)cap, 0, 0, 0) < 0)
            {
                if (errno != EINVAL) /* EINVAL = cap doesn't exist on this kernel */
                {
                    fprintf(stderr,
                            "oci2bin: PR_CAPBSET_DROP %d: %s (non-fatal)\n",
                            cap, strerror(errno));
                }
            }
        }
    }
    else if (opts->cap_drop_mask)
    {
        /* Drop only specified caps from the bounding set */
        for (cap = 0; cap <= 40; cap++)
        {
            if (!((opts->cap_drop_mask >> cap) & 1))
            {
                continue;
            }
            if (prctl(PR_CAPBSET_DROP, (unsigned long)cap, 0, 0, 0) < 0)
            {
                fprintf(stderr,
                        "oci2bin: PR_CAPBSET_DROP %d: %s (non-fatal)\n",
                        cap, strerror(errno));
            }
        }
    }
}

/* ── init reaper ─────────────────────────────────────────────────────────── */

/*
 * Global child PID used by the init signal forwarding handler.
 * Set before installing signal handlers; only written once.
 */
static volatile pid_t g_init_child_pid = 0;

static void init_forward_signal(int sig)
{
    if (g_init_child_pid > 0)
    {
        kill(g_init_child_pid, sig);
    }
}

/*
 * run_as_init: fork the entrypoint as a child, then loop reaping all zombies.
 * Returns the child's exit code, or 1 on fork failure.
 * Must be called AFTER seccomp/capability setup (both apply to parent+child).
 * The --user UID drop is applied only in the child.
 */
static int run_as_init(char** exec_args,
                       const struct container_opts* opts)
{
    pid_t child = fork();
    if (child < 0)
    {
        perror("oci2bin: --init fork");
        return 1;
    }

    if (child == 0)
    {
        /* Child: apply UID/GID drop if requested, then exec */
        if (opts->has_user)
        {
            if (setgroups(0, NULL) < 0
                    || setgid(opts->run_gid) < 0
                    || setuid(opts->run_uid) < 0)
            {
                perror("oci2bin: --init setuid/setgid");
                _exit(1);
            }
        }
        execvp(exec_args[0], exec_args);
        perror("execvp");
        _exit(127);
    }

    /* Parent: install signal forwarders then reap zombies */
    g_init_child_pid = child;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = init_forward_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags   = SA_RESTART;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);

    int child_status = 0;
    for (;;)
    {
        int   status = 0;
        pid_t reaped = waitpid(-1, &status, 0);
        if (reaped < 0)
        {
            if (errno == EINTR)
            {
                continue;    /* signal interrupted — restart */
            }
            if (errno == ECHILD)
            {
                break;    /* no more children */
            }
            break;
        }
        if (reaped == child)
        {
            child_status = status;
            /* Drain remaining zombies then stop */
            while (waitpid(-1, NULL, WNOHANG) > 0)
            {
            }
            break;
        }
        /* else: reaped an orphaned grandchild — continue */
    }

    if (WIFEXITED(child_status))
    {
        return WEXITSTATUS(child_status);
    }
    if (WIFSIGNALED(child_status))
    {
        return 128 + WTERMSIG(child_status);
    }
    return 1;
}

/* ── seccomp ─────────────────────────────────────────────────────────────── */

/*
 * Apply a seccomp-BPF filter that blocks syscalls with no legitimate use
 * inside a container (kernel load, reboot, raw BPF, keyring, etc.).
 * Uses the seccomp(2) syscall with TSYNC; falls back to prctl if unavailable.
 * PR_SET_NO_NEW_PRIVS is set unconditionally — it is good practice regardless.
 */
static void apply_seccomp_filter(void)
{
    /* Detect architecture at compile time */
#ifdef __aarch64__
#define MY_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#define MY_AUDIT_ARCH AUDIT_ARCH_X86_64
#endif

    /* Helper macros to build the BPF program */
#define SC_ALLOW  SECCOMP_RET_ALLOW
#define SC_KILL   SECCOMP_RET_KILL_PROCESS

    /* BPF_SYSCALL emits a jump-if-equal-to-syscall-number → kill */
#define BPF_BLOCK(nr) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SC_KILL)

    struct sock_filter filter[] =
    {
        /* 1. Verify architecture — kill if wrong arch */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
        (offsetof(struct seccomp_data, arch))),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, MY_AUDIT_ARCH, 1, 0),
            BPF_STMT(BPF_RET | BPF_K, SC_KILL),

        /* 2. Load syscall number */
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
            (offsetof(struct seccomp_data, nr))),

            /* 3. Block dangerous syscalls */
#ifdef __NR_kexec_load
                BPF_BLOCK(__NR_kexec_load),
#endif
#ifdef __NR_kexec_file_load
                BPF_BLOCK(__NR_kexec_file_load),
#endif
#ifdef __NR_reboot
                BPF_BLOCK(__NR_reboot),
#endif
#ifdef __NR_syslog
                BPF_BLOCK(__NR_syslog),
#endif
#ifdef __NR_perf_event_open
                BPF_BLOCK(__NR_perf_event_open),
#endif
#ifdef __NR_bpf
                BPF_BLOCK(__NR_bpf),
#endif
#ifdef __NR_add_key
                BPF_BLOCK(__NR_add_key),
#endif
#ifdef __NR_request_key
                BPF_BLOCK(__NR_request_key),
#endif
#ifdef __NR_keyctl
                BPF_BLOCK(__NR_keyctl),
#endif
#ifdef __NR_userfaultfd
                BPF_BLOCK(__NR_userfaultfd),
#endif
#ifdef __NR_nfsservctl
                BPF_BLOCK(__NR_nfsservctl),
#endif
#ifdef __NR_pivot_root
                BPF_BLOCK(__NR_pivot_root),
#endif
#ifdef __NR_ptrace
                BPF_BLOCK(__NR_ptrace),
#endif
#ifdef __NR_process_vm_readv
                BPF_BLOCK(__NR_process_vm_readv),
#endif
#ifdef __NR_process_vm_writev
                BPF_BLOCK(__NR_process_vm_writev),
#endif
#ifdef __NR_init_module
                BPF_BLOCK(__NR_init_module),
#endif
#ifdef __NR_finit_module
                BPF_BLOCK(__NR_finit_module),
#endif

            /* 4. Default: allow */
                BPF_STMT(BPF_RET | BPF_K, SC_ALLOW),
            };

#undef BPF_BLOCK
#undef SC_ALLOW
#undef SC_KILL
#undef MY_AUDIT_ARCH

    struct sock_fprog prog =
    {
        .len    = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    /* PR_SET_NO_NEW_PRIVS: prevent gaining new privileges via setuid/caps */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
    {
        fprintf(stderr,
                "oci2bin: prctl(PR_SET_NO_NEW_PRIVS) failed: %s (non-fatal)\n",
                strerror(errno));
    }

    /* Try seccomp(2) syscall with TSYNC first */
    if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_TSYNC, &prog) == 0)
    {
        fprintf(stderr, "oci2bin: seccomp filter applied\n");
        return;
    }

    /* Fall back to prctl */
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0)
    {
        fprintf(stderr, "oci2bin: seccomp filter failed: %s (non-fatal)\n",
                strerror(errno));
    }
    else
    {
        fprintf(stderr, "oci2bin: seccomp filter applied (via prctl)\n");
    }
}

static int container_main(const char* rootfs, struct container_opts *opts)
{
    /* Read entrypoint/cmd config written by extract_oci_rootfs() */
    char config_path[PATH_MAX];
    snprintf(config_path, sizeof(config_path), "%s/.oci2bin_config", rootfs);
    char* config = read_file(config_path, NULL);

    /* Build exec_args: [entrypoint...] [cmd...] */
    char* exec_args[MAX_ARGS + 1];
    int exec_argc = 0;

    /* --- Determine entrypoint --- */
    if (opts->entrypoint)
    {
        /* User supplied --entrypoint: use it as a single string */
        exec_args[exec_argc++] = opts->entrypoint;
    }
    else if (config)
    {
        char* ep_json = json_get_array(config, "Entrypoint");
        if (ep_json && strcmp(ep_json, "null") != 0)
        {
            exec_argc += json_parse_string_array(ep_json, exec_args + exec_argc,
                                                 MAX_ARGS - exec_argc);
        }
        free(ep_json);
    }

    /* --- Determine cmd / extra args --- */
    if (opts->n_extra > 0)
    {
        /* User supplied extra args: they replace OCI Cmd entirely */
        for (int i = 0; i < opts->n_extra && exec_argc < MAX_ARGS; i++)
        {
            exec_args[exec_argc++] = opts->extra_args[i];
        }
    }
    else if (config)
    {
        char* cmd_json = json_get_array(config, "Cmd");
        if (cmd_json && strcmp(cmd_json, "null") != 0)
        {
            exec_argc += json_parse_string_array(cmd_json, exec_args + exec_argc,
                                                 MAX_ARGS - exec_argc);
        }
        free(cmd_json);
    }

    /* Save image Env and WorkingDir before freeing config — applied after chroot */
    char* image_env_json = NULL;
    char* image_workdir  = NULL;
    if (config)
    {
        image_env_json = json_get_array(config, "Env");
        image_workdir  = json_get_string(config, "WorkingDir");
    }

    free(config);

    /* Fallback: if nothing resolved, run /bin/sh */
    if (exec_argc == 0)
    {
        exec_args[0] = "/bin/sh";
        exec_argc = 1;
    }
    exec_args[exec_argc] = NULL;

    /* Remove our temp config file */
    unlink(config_path);

    /* Set up volume bind mounts BEFORE chroot (host paths still reachable) */
    setup_volumes(rootfs, opts);
    setup_secrets(rootfs, opts);

    /* --ssh-agent: forward host SSH_AUTH_SOCK into the container.
     * The socket is bind-mounted at /run/ssh-agent.sock and SSH_AUTH_SOCK
     * is set accordingly so tools like ssh and git pick it up automatically. */
    char ssh_auth_sock_host[PATH_MAX];
    ssh_auth_sock_host[0] = '\0';
    if (opts->ssh_agent)
    {
        const char* sock = getenv("SSH_AUTH_SOCK");
        if (!sock || sock[0] == '\0')
        {
            fprintf(stderr, "oci2bin: --ssh-agent: SSH_AUTH_SOCK is not set (non-fatal)\n");
        }
        else if (sock[0] != '/')
        {
            fprintf(stderr,
                    "oci2bin: --ssh-agent: SSH_AUTH_SOCK must be an absolute path: %s\n",
                    sock);
        }
        else if (strstr(sock, "/../") != NULL ||
                 (strlen(sock) >= 3 &&
                  strcmp(sock + strlen(sock) - 3, "/..") == 0))
        {
            fprintf(stderr,
                    "oci2bin: --ssh-agent: SSH_AUTH_SOCK must not contain '..': %s\n",
                    sock);
        }
        else
        {
            int slen = snprintf(ssh_auth_sock_host, sizeof(ssh_auth_sock_host), "%s", sock);
            if (slen < 0 || (size_t)slen >= sizeof(ssh_auth_sock_host))
            {
                fprintf(stderr, "oci2bin: --ssh-agent: SSH_AUTH_SOCK path too long\n");
                ssh_auth_sock_host[0] = '\0';
            }
            else
            {
                /* Verify that SSH_AUTH_SOCK is actually a Unix socket */
                struct stat sock_st;
                if (lstat(ssh_auth_sock_host, &sock_st) < 0)
                {
                    fprintf(stderr,
                            "oci2bin: --ssh-agent: cannot stat SSH_AUTH_SOCK: %s\n",
                            strerror(errno));
                    ssh_auth_sock_host[0] = '\0';
                }
                else if (!S_ISSOCK(sock_st.st_mode))
                {
                    fprintf(stderr,
                            "oci2bin: --ssh-agent: SSH_AUTH_SOCK is not a socket\n");
                    ssh_auth_sock_host[0] = '\0';
                }
                else
                {
                    /* Create target socket file inside rootfs */
                    char sock_dir[PATH_MAX];
                    int dlen = snprintf(sock_dir, sizeof(sock_dir), "%s/run", rootfs);
                    if (dlen > 0 && (size_t)dlen < sizeof(sock_dir))
                    {
                        mkdir(sock_dir, 0755);
                    }
                    char sock_dst[PATH_MAX];
                    int tlen = snprintf(sock_dst, sizeof(sock_dst),
                                        "%s/run/ssh-agent.sock", rootfs);
                    if (tlen < 0 || (size_t)tlen >= sizeof(sock_dst))
                    {
                        fprintf(stderr,
                                "oci2bin: --ssh-agent: destination path too long\n");
                        ssh_auth_sock_host[0] = '\0';
                    }
                    else
                    {
                        /* Create empty placeholder file as bind-mount target.
                         * O_EXCL ensures we abort if the file already exists
                         * (e.g. a symlink planted by a malicious image layer)
                         * rather than silently following it. */
                        int fd = open(sock_dst, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
                                      0600);
                        if (fd < 0)
                        {
                            fprintf(stderr,
                                    "oci2bin: --ssh-agent: cannot create socket placeholder"
                                    " %s: %s\n",
                                    sock_dst, strerror(errno));
                            ssh_auth_sock_host[0] = '\0';
                        }
                        else
                        {
                            close(fd);
                        }
                        if (ssh_auth_sock_host[0] != '\0')
                        {
                            if (mount(ssh_auth_sock_host, sock_dst,
                                      NULL, MS_BIND, NULL) < 0)
                            {
                                fprintf(stderr,
                                        "oci2bin: --ssh-agent: bind mount failed: %s\n",
                                        strerror(errno));
                                ssh_auth_sock_host[0] = '\0';
                            }
                            else if (mount(NULL, sock_dst, NULL,
                                           MS_BIND | MS_REMOUNT | MS_RDONLY |
                                           MS_NOEXEC | MS_NOSUID | MS_NODEV,
                                           NULL) < 0)
                            {
                                fprintf(stderr,
                                        "oci2bin: --ssh-agent: remount read-only"
                                        " failed: %s\n",
                                        strerror(errno));
                                if (umount2(sock_dst, MNT_DETACH) < 0)
                                {
                                    fprintf(stderr,
                                            "oci2bin: --ssh-agent: umount"
                                            " failed: %s\n",
                                            strerror(errno));
                                }
                                ssh_auth_sock_host[0] = '\0';
                            }
                            else
                            {
                                fprintf(stderr,
                                        "oci2bin: ssh-agent socket forwarded"
                                        " to /run/ssh-agent.sock\n");
                            }
                        }
                    }
                } /* end S_ISSOCK check */
            }
        }
    }

    /* --read-only / --overlay-persist: mount overlayfs.
     * For --read-only:       upper/work live in a tmpdir (discarded on exit).
     * For --overlay-persist: upper/work live in the user-specified dir (kept). */
    if (opts->read_only || opts->overlay_persist)
    {
        char upper[PATH_MAX];
        char work[PATH_MAX];
        int upper_ok = 0;

        if (opts->overlay_persist)
        {
            /* --overlay-persist DIR: use DIR/upper and DIR/work */
            int ulen = snprintf(upper, sizeof(upper),
                                "%s/upper", opts->overlay_persist);
            int wlen = snprintf(work,  sizeof(work),
                                "%s/work",  opts->overlay_persist);
            if (ulen < 0 || (size_t)ulen >= sizeof(upper))
            {
                fprintf(stderr,
                        "oci2bin: --overlay-persist: upper path"
                        " truncated\n");
            }
            else if (wlen < 0 || (size_t)wlen >= sizeof(work))
            {
                fprintf(stderr,
                        "oci2bin: --overlay-persist: work path"
                        " truncated\n");
            }
            else
            {
                /* Create DIR, DIR/upper, DIR/work if needed */
                mkdir(opts->overlay_persist, 0755);
                mkdir(upper, 0755);
                mkdir(work,  0755);
                /* Verify upper and work are on the same filesystem */
                struct stat su, sw;
                if (stat(upper, &su) < 0 || stat(work, &sw) < 0)
                {
                    fprintf(stderr,
                            "oci2bin: --overlay-persist: stat"
                            " failed\n");
                }
                else if (su.st_dev != sw.st_dev)
                {
                    fprintf(stderr,
                            "oci2bin: --overlay-persist:"
                            " upper and work must be on the"
                            " same filesystem\n");
                }
                else
                {
                    upper_ok = 1;
                }
            }
        }
        else
        {
            /* --read-only: derive tmpdir by stripping "/rootfs" suffix */
            char tmpdir[PATH_MAX];
            int tmpdir_ok = 0;
            int tlen = snprintf(tmpdir, sizeof(tmpdir), "%s", rootfs);
            if (tlen > 0 && (size_t)tlen < sizeof(tmpdir))
            {
                char* slash = strrchr(tmpdir, '/');
                if (slash && strcmp(slash, "/rootfs") == 0)
                {
                    *slash = '\0';
                    tmpdir_ok = 1;
                }
                else
                {
                    tlen = snprintf(tmpdir, sizeof(tmpdir),
                                    "%s/..", rootfs);
                    if (tlen > 0 && (size_t)tlen < sizeof(tmpdir))
                    {
                        tmpdir_ok = 1;
                    }
                }
            }
            if (tmpdir_ok)
            {
                int ulen = snprintf(upper, sizeof(upper),
                                    "%s/upper", tmpdir);
                int wlen = snprintf(work,  sizeof(work),
                                    "%s/work",  tmpdir);
                if (ulen > 0 && (size_t)ulen < sizeof(upper) &&
                        wlen > 0 && (size_t)wlen < sizeof(work))
                {
                    mkdir(upper, 0755);
                    mkdir(work,  0755);
                    upper_ok = 1;
                }
            }
        }

        if (upper_ok)
        {
            char overlay_opts[PATH_MAX * 4];
            int olen = snprintf(overlay_opts, sizeof(overlay_opts),
                                "lowerdir=%s,upperdir=%s,workdir=%s",
                                rootfs, upper, work);
            if (olen > 0 && (size_t)olen < sizeof(overlay_opts))
            {
                if (mount("overlay", rootfs, "overlay", 0,
                          overlay_opts) < 0)
                {
                    fprintf(stderr,
                            "oci2bin: overlayfs unavailable,"
                            " running read-write\n");
                }
            }
        }
    }

    /* Chroot into rootfs */
    if (chroot(rootfs) < 0)
    {
        perror("chroot");
        return 1;
    }
    if (chdir("/") < 0)
    {
        perror("chdir /");
        return 1;
    }

    /* Mount /proc */
    mkdir("/proc", 0555);
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0)
    {
        perror("mount /proc (non-fatal)");
    }

    /* Mount /tmp as fresh tmpfs so container cannot see host /tmp */
    mkdir("/tmp", 0777);
    if (mount("tmpfs", "/tmp", "tmpfs",
              MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=1777") < 0)
    {
        perror("mount /tmp tmpfs (non-fatal)");
    }

    /* Mount tmpfs on /dev then bind-mount essential devices from the host.
     * mknod is not available in rootless user namespaces, but bind-mounting
     * existing host device nodes requires no special privileges. */
    mkdir("/dev", 0755);
    if (mount("tmpfs", "/dev", "tmpfs",
              MS_NOSUID | MS_NOEXEC, "mode=0755") < 0)
    {
        perror("mount /dev tmpfs (non-fatal)");
    }
    else
    {
        if (!opts->no_host_dev)
        {
            static const char* const DEV_NODES[] =
            {
                "/dev/null", "/dev/zero", "/dev/random",
                "/dev/urandom", "/dev/tty", NULL,
            };
            for (int di = 0; DEV_NODES[di]; di++)
            {
                int fd = open(DEV_NODES[di], O_CREAT | O_WRONLY, 0666);
                if (fd >= 0)
                {
                    close(fd);
                }
                if (mount(DEV_NODES[di], DEV_NODES[di], NULL,
                          MS_BIND, NULL) < 0)
                {
                    fprintf(stderr,
                            "oci2bin: bind-mount %s (non-fatal): %s\n",
                            DEV_NODES[di], strerror(errno));
                }
            }
        }
    }

    /* Expose --device host devices inside the container */
    for (int di = 0; di < opts->n_devices; di++)
    {
        const char* host_dev = opts->devices[di];
        const char* ctr_dev  = opts->device_ctr[di]
                               ? opts->device_ctr[di]
                               : host_dev;

        struct stat st;
        if (stat(host_dev, &st) < 0)
        {
            fprintf(stderr, "oci2bin: --device stat %s: %s (non-fatal)\n",
                    host_dev, strerror(errno));
            continue;
        }

        /* Create the device node inside the container */
        if (mknod(ctr_dev, st.st_mode, st.st_rdev) < 0)
        {
            /* mknod may fail in user namespaces — fall back to bind mount */
            if (errno == EPERM || errno == ENOTSUP)
            {
                /* Ensure container path exists */
                int fd = open(ctr_dev, O_CREAT | O_WRONLY, 0600);
                if (fd >= 0)
                {
                    close(fd);
                }
                if (mount(host_dev, ctr_dev, NULL, MS_BIND, NULL) < 0)
                {
                    fprintf(stderr,
                            "oci2bin: --device bind-mount %s→%s: %s (non-fatal)\n",
                            host_dev, ctr_dev, strerror(errno));
                }
            }
            else
            {
                fprintf(stderr, "oci2bin: --device mknod %s: %s (non-fatal)\n",
                        ctr_dev, strerror(errno));
            }
        }
        else
        {
            /* Set same permissions as host device */
            chmod(ctr_dev, st.st_mode & 0777);
        }
    }

    /* Mount extra --tmpfs paths inside the container */
    for (int ti = 0; ti < opts->n_tmpfs; ti++)
    {
        const char* ctr_path = opts->tmpfs_mounts[ti];
        /* mkdir at the container path (we are post-chroot) */
        if (mkdir(ctr_path, 0755) < 0 && errno != EEXIST)
        {
            fprintf(stderr, "oci2bin: --tmpfs mkdir %s: %s (non-fatal)\n",
                    ctr_path, strerror(errno));
            continue;
        }
        if (mount("tmpfs", ctr_path, "tmpfs",
                  MS_NOSUID | MS_NODEV, "mode=0755") < 0)
        {
            fprintf(stderr, "oci2bin: --tmpfs mount %s: %s (non-fatal)\n",
                    ctr_path, strerror(errno));
        }
    }

    /* Set hostname (--hostname overrides default) */
    {
        const char* hn = opts->hostname ? opts->hostname : "oci2bin";
        if (sethostname(hn, strlen(hn)) < 0)
        {
            fprintf(stderr, "oci2bin: sethostname: %s (non-fatal)\n",
                    strerror(errno));
        }
    }

    /* Set standard env */
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
           1);
    setenv("HOME", "/root", 1);
    setenv("TERM", "xterm", 1);

    /* Apply image Env from OCI config (overrides built-in defaults above).
     * image_env_json was extracted before free(config) above. */
    if (image_env_json && strcmp(image_env_json, "null") != 0)
    {
        char* image_envs[MAX_ENV];
        int n = json_parse_string_array(image_env_json, image_envs, MAX_ENV);
        for (int i = 0; i < n; i++)
        {
            char* eq = strchr(image_envs[i], '=');
            if (eq && eq != image_envs[i])   /* must have '=' and non-empty key */
            {
                *eq = '\0';
                setenv(image_envs[i], eq + 1, 1);
                *eq = '=';
            }
            free(image_envs[i]);
        }
    }
    free(image_env_json);

    /* Apply caller-supplied env vars (-e KEY=VALUE); these override the defaults above */
    for (int i = 0; i < opts->n_env; i++)
    {
        char* eq = strchr(opts->env_vars[i], '=');
        if (!eq)
        {
            continue;    /* already validated in parse_opts, but be safe */
        }
        *eq = '\0';
        if (setenv(opts->env_vars[i], eq + 1, 1) < 0)
        {
            fprintf(stderr, "oci2bin: setenv %s failed: %s\n", opts->env_vars[i],
                    strerror(errno));
        }
        *eq = '='; /* restore the string in case it is inspected later */
    }

    /* Set SSH_AUTH_SOCK inside the container if ssh-agent was forwarded */
    if (opts->ssh_agent && ssh_auth_sock_host[0] != '\0')
    {
        setenv("SSH_AUTH_SOCK", "/run/ssh-agent.sock", 1);
    }

    /* Apply workdir: --workdir flag overrides image WorkingDir */
    {
        const char* wdir = opts->workdir ? opts->workdir : image_workdir;
        if (wdir && wdir[0] != '\0')
        {
            if (chdir(wdir) < 0)
            {
                fprintf(stderr, "oci2bin: workdir %s: %s (non-fatal)\n", wdir,
                        strerror(errno));
            }
        }
    }
    free(image_workdir);

    /* Apply resource limits via setrlimit (non-fatal on failure) */
    for (int ri = 0; ri < opts->n_ulimits; ri++)
    {
        struct rlimit rl;
        rl.rlim_cur = opts->ulimits[ri].value;
        rl.rlim_max = opts->ulimits[ri].value;
        if (setrlimit(opts->ulimits[ri].resource, &rl) < 0)
        {
            fprintf(stderr, "oci2bin: setrlimit(%d, %llu): %s (non-fatal)\n",
                    opts->ulimits[ri].resource,
                    (unsigned long long)opts->ulimits[ri].value,
                    strerror(errno));
        }
    }

    /* Apply capability drops/adds before seccomp/fork (applies to all paths) */
    if (opts->cap_drop_all || opts->cap_drop_mask || opts->cap_add_mask)
    {
        apply_capabilities(opts);
    }

    /* Apply seccomp filter (must be before fork so child inherits it) */
    if (!opts->no_seccomp)
    {
        apply_seccomp_filter();
    }

    /* --detach: fork to background, print child PID, parent exits */
    if (opts->detach)
    {
        pid_t bg = fork();
        if (bg < 0)
        {
            perror("oci2bin: --detach fork");
            return 1;
        }
        if (bg > 0)
        {
            /* Parent: print child PID and exit cleanly */
            printf("%d\n", (int)bg);
            fflush(stdout);
            _exit(0);
        }
        /* Child: detach from terminal */
        setsid();
        int null_fd = open("/dev/null", O_RDONLY);
        if (null_fd >= 0)
        {
            dup2(null_fd, STDIN_FILENO);
            close(null_fd);
        }
    }

    /* --init: run a zombie-reaping init loop; UID drop happens inside */
    if (opts->use_init)
    {
        int rc = run_as_init(exec_args, opts);
        return rc;
    }

    /* Drop to requested UID/GID if --user was given (fatal if it fails) */
    if (opts->has_user)
    {
        if (setgroups(0, NULL) < 0)
        {
            fprintf(stderr, "oci2bin: setgroups failed: %s\n", strerror(errno));
            return 1;
        }
        if (setgid(opts->run_gid) < 0)
        {
            fprintf(stderr, "oci2bin: setgid(%d) failed: %s\n",
                    (int)opts->run_gid, strerror(errno));
            return 1;
        }
        if (setuid(opts->run_uid) < 0)
        {
            fprintf(stderr, "oci2bin: setuid(%d) failed: %s\n",
                    (int)opts->run_uid, strerror(errno));
            return 1;
        }
    }

    /* Exec the entrypoint — execvp searches PATH so relative names work */
    fprintf(stderr, "oci2bin: exec %s\n", exec_args[0]);
    execvp(exec_args[0], exec_args);

    /* If exec failed, try /bin/sh as fallback */
    perror("execvp");
    fprintf(stderr, "oci2bin: falling back to /bin/sh\n");
    execlp("/bin/sh", "sh", NULL);
    perror("execlp /bin/sh");
    return 1;
}

/* ── argument parsing ────────────────────────────────────────────────────── */

/*
 * load_env_file: read KEY=VALUE pairs from a file into opts->env_vars[].
 * Uses open()/read() per CLAUDE.md style. Lines starting with '#' or blank
 * are skipped. Each accepted line is strdup'd so it persists after the call.
 * Returns 0 on success, -1 on error (with a message printed to stderr).
 */
static int load_env_file(const char* path, struct container_opts* opts)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        fprintf(stderr, "oci2bin: --env-file %s: %s\n", path, strerror(errno));
        return -1;
    }

    /* Read entire file into a heap buffer (reject files > 1 MiB) */
    struct stat st;
    if (fstat(fd, &st) < 0)
    {
        fprintf(stderr, "oci2bin: --env-file fstat %s: %s\n", path,
                strerror(errno));
        close(fd);
        return -1;
    }
    if (st.st_size < 0 || st.st_size > 1024 * 1024)
    {
        fprintf(stderr, "oci2bin: --env-file %s: file too large\n", path);
        close(fd);
        return -1;
    }

    size_t sz = (size_t)st.st_size;
    char* buf = malloc(sz + 1);
    if (!buf)
    {
        fprintf(stderr, "oci2bin: --env-file: out of memory\n");
        close(fd);
        return -1;
    }

    ssize_t n = read(fd, buf, sz);
    close(fd);
    if (n < 0)
    {
        fprintf(stderr, "oci2bin: --env-file read %s: %s\n", path,
                strerror(errno));
        free(buf);
        return -1;
    }
    buf[n] = '\0';

    /* Parse line by line */
    char* p = buf;
    while (*p)
    {
        char* nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);

        /* Trim trailing \r */
        if (len > 0 && p[len - 1] == '\r')
        {
            len--;
        }

        /* Skip blank lines and comments */
        if (len == 0 || p[0] == '#')
        {
            p = nl ? nl + 1 : p + len;
            continue;
        }

        /* Validate KEY=VALUE format */
        char* eq = memchr(p, '=', len);
        if (!eq || eq == p)
        {
            fprintf(stderr,
                    "oci2bin: --env-file %s: invalid line (missing KEY=): %.*s\n",
                    path, (int)len, p);
            free(buf);
            return -1;
        }

        if (opts->n_env >= MAX_ENV)
        {
            fprintf(stderr, "oci2bin: --env-file: too many env vars (max %d)\n",
                    MAX_ENV);
            free(buf);
            return -1;
        }

        char* line = malloc(len + 1);
        if (!line)
        {
            fprintf(stderr, "oci2bin: --env-file: out of memory\n");
            free(buf);
            return -1;
        }
        memcpy(line, p, len);
        line[len] = '\0';
        opts->env_vars[opts->n_env++] = line;

        p = nl ? nl + 1 : p + len;
    }

    free(buf);
    return 0;
}

static void usage(const char* prog)
{
    fprintf(stderr,
            "Usage: %s [OPTIONS] [-- CMD [ARGS...]]\n"
            "       %s [OPTIONS] CMD [ARGS...]\n"
            "\n"
            "Options:\n"
            "  -v HOST:CONTAINER   Bind mount a host path into the container\n"
            "                      (may be repeated)\n"
            "  --secret HOST_FILE[:CONTAINER_PATH]\n"
            "                      Bind mount a host file read-only; defaults to\n"
            "                      /run/secrets/<basename> (may be repeated)\n"
            "  -e KEY=VALUE        Set an environment variable inside the container\n"
            "  -e KEY              Pass KEY from host environment (skip if unset)\n"
            "                      (may be repeated; overrides built-in defaults)\n"
            "  --entrypoint PATH   Override the image entrypoint\n"
            "  --workdir PATH      Set the working directory inside the container\n"
            "  --net host|none|slirp|pasta|slirp:H:C|container:<PID>\n"
            "                      Network: host (default), none (isolated),\n"
            "                      slirp (userspace via slirp4netns),\n"
            "                      pasta (userspace via pasta),\n"
            "                      slirp:HOST_PORT:CTR_PORT (with port"
            " forward),\n"
            "                      or join the network namespace of PID\n"
            "  --ipc host|container:<PID>\n"
            "                      IPC namespace: host (default, shares SysV IPC),\n"
            "                      or join the IPC namespace of PID\n"
            "  --read-only         Mount rootfs read-only via overlayfs\n"
            "  --overlay-persist DIR\n"
            "                      Persist the overlay upper layer to DIR;\n"
            "                      state accumulates across runs\n"
            "  --ssh-agent         Forward host SSH_AUTH_SOCK into the container\n"
            "  --no-seccomp        Disable the default seccomp syscall filter\n"
            "  --no-host-dev       Skip bind-mounting host /dev nodes (null, zero, "
            "random, tty)\n"
            "  --user UID[:GID]    Run as this numeric UID (and optional GID)\n"
            "  --hostname NAME     Set the hostname inside the container\n"
            "  --cap-drop CAP      Drop a capability (or 'all' to drop all)\n"
            "  --cap-add CAP       Add an ambient capability (use after --cap-drop all)\n"
            "  --device /dev/PATH[:CONTAINER_PATH]\n"
            "                      Expose a host device inside the container\n"
            "  --init              Run a zombie-reaping init as PID 1\n"
            "  --detach, -d        Run container in background; print PID to stdout\n"
            "  --memory SIZE       Limit container memory (e.g. 512m, 2g) via"
            " cgroup v2\n"
            "  --cpus FLOAT        Limit container CPU (e.g. 0.5 = 50%%)"
            " via cgroup v2\n"
            "  --pids-limit N      Limit number of PIDs inside the container"
            " via cgroup v2\n"
            "  --verify-key PATH   Verify binary signature before extraction;"
            " abort if invalid\n"
            "  --env-file FILE     Load KEY=VALUE pairs from FILE\n"
            "  --tmpfs PATH        Mount a fresh tmpfs at PATH inside the container\n"
            "  --ulimit TYPE=N     Set resource limit (nofile,nproc,cpu,as,fsize)\n"
            "  --config PATH       Load options from a key=value config file\n"
            "  --vm               run container inside a microVM (requires KVM or HVF)\n"
            "  --vmm VMM          VMM backend: cloud-hypervisor, or path to binary\n"
            "                     (default: cloud-hypervisor; libkrun if compiled with LIBKRUN=1)\n"
            "  --                  End of options; remaining args are CMD\n"
            "\n"
            "Examples:\n"
            "  %s                               # run image default entrypoint\n"
            "  %s /bin/ls /                     # run ls inside the container\n"
            "  %s --entrypoint /bin/bash        # open bash shell\n"
            "  %s -v /data:/mnt /bin/ls /mnt   # mount /data and list it\n"
            "  %s -e DEBUG=1 -e API_KEY=secret  # set environment variables\n",
            prog, prog, prog, prog, prog, prog, prog);
}

/*
 * Pre-scan argv for --config PATH.  Read the config file and return a
 * merged argv: argv[0], then config-file options (as defaults), then the
 * original argv[1..] with --config / PATH pairs stripped out.
 *
 * This means real argv flags override config file values (config file sets
 * defaults).  parse_opts is then called exactly once with the merged argv,
 * which consists entirely of strings that either come from the original argv
 * (permanent) or were heap-allocated here and stored in *out_extra (also
 * permanent for the process lifetime — they are freed on error but kept on
 * success, which is fine because we exec shortly after).
 *
 * Returns a heap-allocated argv array (NULL-terminated) on success.
 * Returns NULL on error (error message already printed).
 * *out_argc is set to the new argc.
 * *out_heap_strings is set to a NULL-terminated list of strings to free
 *   on error only; on success the caller must NOT free them.
 */
static char** build_merged_argv(int argc, char* argv[], int* out_argc,
                                char*** out_heap_strings)
{
    /* First pass: find --config PATH pairs and validate the path */
    const char* config_path = NULL;
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--config") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr,
                        "oci2bin: --config requires PATH argument\n");
                return NULL;
            }
            if (config_path)
            {
                fprintf(stderr,
                        "oci2bin: --config may only be specified"
                        " once\n");
                return NULL;
            }
            config_path = argv[i + 1];
            if (strstr(config_path, ".."))
            {
                fprintf(stderr,
                        "oci2bin: --config: path must not"
                        " contain '..'\n");
                return NULL;
            }
            i++; /* skip PATH */
        }
    }

    /* If no --config, return original argv unchanged */
    if (!config_path)
    {
        *out_argc         = argc;
        *out_heap_strings = NULL;
        return argv;
    }

    /* Read config file into a temporary heap-string array.
     * Each line "key=value" → two strings: "--key", "value"
     * Each line "key"       → one string:  "--key"
     * Max 128 pairs (256 tokens) from the config file. */
    char** cfg = malloc(257 * sizeof(char*));
    if (!cfg)
    {
        return NULL;
    }
    int cfg_n = 0;

    FILE* f = fopen(config_path, "r");
    if (!f)
    {
        fprintf(stderr, "oci2bin: --config: cannot open '%s': %s\n",
                config_path, strerror(errno));
        free(cfg);
        return NULL;
    }

    char line[4096];
    int  ok = 1;
    while (ok && fgets(line, (int)sizeof(line), f))
    {
        size_t len = strlen(line);
        while (len > 0 &&
                (line[len - 1] == '\n' || line[len - 1] == '\r' ||
                 line[len - 1] == ' '  || line[len - 1] == '\t'))
        {
            line[--len] = '\0';
        }
        if (len == 0 || line[0] == '#')
        {
            continue;
        }

        if (len > 4092)
        {
            fprintf(stderr,
                    "oci2bin: --config: line too long in '%s'\n",
                    config_path);
            ok = 0;
            break;
        }

        char* eq = strchr(line, '=');
        if (eq)
        {
            size_t key_len = (size_t)(eq - line);
            if (cfg_n + 2 > 256)
            {
                fprintf(stderr,
                        "oci2bin: --config: too many entries"
                        " in '%s'\n", config_path);
                ok = 0;
                break;
            }
            char* flag = malloc(key_len + 3);
            char* val  = strdup(eq + 1);
            if (!flag || !val)
            {
                free(flag);
                free(val);
                ok = 0;
                break;
            }
            flag[0] = '-';
            flag[1] = '-';
            memcpy(flag + 2, line, key_len);
            flag[key_len + 2] = '\0';
            cfg[cfg_n++] = flag;
            cfg[cfg_n++] = val;
        }
        else
        {
            if (cfg_n + 1 > 256)
            {
                fprintf(stderr,
                        "oci2bin: --config: too many entries"
                        " in '%s'\n", config_path);
                ok = 0;
                break;
            }
            char* flag = malloc(len + 3);
            if (!flag)
            {
                ok = 0;
                break;
            }
            flag[0] = '-';
            flag[1] = '-';
            memcpy(flag + 2, line, len + 1);
            cfg[cfg_n++] = flag;
        }
    }
    fclose(f);

    if (!ok)
    {
        for (int j = 0; j < cfg_n; j++)
        {
            free(cfg[j]);
        }
        free(cfg);
        return NULL;
    }
    cfg[cfg_n] = NULL;

    /* Build merged argv:
     *   [0]           = argv[0]
     *   [1..cfg_n]    = config-file options (defaults)
     *   [cfg_n+1..]   = original argv[1..] minus --config/PATH pairs
     */
    int real_n = 0; /* count of real argv entries after stripping --config */
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--config") == 0)
        {
            i++; /* skip PATH too */
        }
        else
        {
            real_n++;
        }
    }

    int    merged_argc = 1 + cfg_n + real_n;
    char** merged      = malloc((size_t)(merged_argc + 1) * sizeof(char*));
    if (!merged)
    {
        for (int j = 0; j < cfg_n; j++)
        {
            free(cfg[j]);
        }
        free(cfg);
        return NULL;
    }

    int mi     = 0;
    merged[mi++] = argv[0];
    for (int j = 0; j < cfg_n; j++)
    {
        merged[mi++] = cfg[j];
    }
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--config") == 0)
        {
            i++;
        }
        else
        {
            merged[mi++] = argv[i];
        }
    }
    merged[mi] = NULL;

    *out_argc         = merged_argc;
    *out_heap_strings = cfg; /* caller must NOT free on success */
    free(cfg);               /* free the indirection array; strings live in merged */
    *out_heap_strings = NULL;

    /* The cfg[] strings are now referenced from merged[] directly.
     * They are heap-allocated and persist for the process lifetime —
     * the same lifetime as argv[] itself.  We exec shortly after. */
    return merged;
}

static int parse_opts(int argc, char* argv[], struct container_opts *opts)
{
    /* Caller is responsible for zeroing opts before the first call. */
    int i = 1;
    for (; i < argc; i++)
    {
        if (strcmp(argv[i], "--") == 0)
        {
            i++;
            break;
        }
        else if (strcmp(argv[i], "-v") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "oci2bin: -v requires HOST:CONTAINER argument\n");
                return -1;
            }
            i++;
            char* spec = argv[i];
            char* colon = strchr(spec, ':');
            if (!colon)
            {
                fprintf(stderr, "oci2bin: -v argument must be HOST:CONTAINER\n");
                return -1;
            }
            if (opts->n_vols >= MAX_VOLUMES)
            {
                fprintf(stderr, "oci2bin: too many -v flags (max %d)\n", MAX_VOLUMES);
                return -1;
            }
            *colon = '\0';
            opts->vol_host[opts->n_vols] = spec;
            opts->vol_ctr[opts->n_vols]  = colon + 1;
            opts->n_vols++;
        }
        else if (strcmp(argv[i], "--secret") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr,
                        "oci2bin: --secret requires a HOST_FILE[:CONTAINER_PATH] argument\n");
                return -1;
            }
            if (opts->n_secrets >= MAX_SECRETS)
            {
                fprintf(stderr, "oci2bin: too many --secret flags (max %d)\n", MAX_SECRETS);
                return -1;
            }
            i++;
            char* spec   = argv[i];
            char* colon  = strchr(spec, ':');
            opts->secret_host[opts->n_secrets] = spec;
            if (colon)
            {
                *colon = '\0';
                opts->secret_ctr[opts->n_secrets] = colon + 1;
            }
            else
            {
                opts->secret_ctr[opts->n_secrets] =
                    NULL; /* default to /run/secrets/<basename> */
            }
            opts->n_secrets++;
        }
        else if (strcmp(argv[i], "--env-file") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "oci2bin: --env-file requires a FILE argument\n");
                return -1;
            }
            if (load_env_file(argv[++i], opts) < 0)
            {
                return -1;
            }
        }
        else if (strcmp(argv[i], "--tmpfs") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "oci2bin: --tmpfs requires a PATH argument\n");
                return -1;
            }
            i++;
            const char* tp = argv[i];
            if (tp[0] != '/')
            {
                fprintf(stderr,
                        "oci2bin: --tmpfs path must be absolute: %s\n", tp);
                return -1;
            }
            if (strstr(tp, ".."))
            {
                fprintf(stderr,
                        "oci2bin: --tmpfs path must not contain '..': %s\n",
                        tp);
                return -1;
            }
            if (opts->n_tmpfs >= MAX_VOLUMES)
            {
                fprintf(stderr,
                        "oci2bin: too many --tmpfs flags (max %d)\n",
                        MAX_VOLUMES);
                return -1;
            }
            opts->tmpfs_mounts[opts->n_tmpfs++] = (char*)tp;
        }
        else if (strcmp(argv[i], "--ulimit") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "oci2bin: --ulimit requires TYPE=VALUE\n");
                return -1;
            }
            i++;
            char* spec = argv[i];
            char* eq   = strchr(spec, '=');
            if (!eq)
            {
                fprintf(stderr,
                        "oci2bin: --ulimit argument must be TYPE=VALUE\n");
                return -1;
            }
            if (opts->n_ulimits >= 16)
            {
                fprintf(stderr, "oci2bin: too many --ulimit flags (max 16)\n");
                return -1;
            }
            int res = -1;
            size_t type_len = (size_t)(eq - spec);
            if (type_len == 6 && memcmp(spec, "nofile", 6) == 0)
            {
                res = RLIMIT_NOFILE;
            }
            else if (type_len == 5 && memcmp(spec, "nproc", 5) == 0)
            {
                res = RLIMIT_NPROC;
            }
            else if (type_len == 3 && memcmp(spec, "cpu", 3) == 0)
            {
                res = RLIMIT_CPU;
            }
            else if (type_len == 2 && memcmp(spec, "as", 2) == 0)
            {
                res = RLIMIT_AS;
            }
            else if (type_len == 5 && memcmp(spec, "fsize", 5) == 0)
            {
                res = RLIMIT_FSIZE;
            }
            if (res < 0)
            {
                fprintf(stderr,
                        "oci2bin: --ulimit unknown type '%.*s' "
                        "(use: nofile,nproc,cpu,as,fsize)\n",
                        (int)type_len, spec);
                return -1;
            }
            char*          endp  = NULL;
            unsigned long long val =
                strtoull(eq + 1, &endp, 10);
            if (!endp || *endp != '\0')
            {
                fprintf(stderr,
                        "oci2bin: --ulimit value must be a non-negative integer\n");
                return -1;
            }
            opts->ulimits[opts->n_ulimits].resource = res;
            opts->ulimits[opts->n_ulimits].value    = (rlim_t)val;
            opts->n_ulimits++;
        }
        else if (strcmp(argv[i], "-e") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "oci2bin: -e requires KEY[=VALUE] argument\n");
                return -1;
            }
            i++;
            if (argv[i][0] == '=')
            {
                fprintf(stderr, "oci2bin: -e argument must not start with '='\n");
                return -1;
            }
            if (opts->n_env >= MAX_ENV)
            {
                fprintf(stderr, "oci2bin: too many -e flags (max %d)\n", MAX_ENV);
                return -1;
            }
            if (!strchr(argv[i], '='))
            {
                /* VAR passthrough: look up in host environment */
                const char* host_val = getenv(argv[i]);
                if (host_val == NULL)
                {
                    fprintf(stderr,
                            "oci2bin: -e %s: not set in host environment"
                            " (skipped)\n",
                            argv[i]);
                }
                else
                {
                    size_t klen = strlen(argv[i]);
                    size_t vlen = strlen(host_val);
                    /* key + '=' + value + '\0'; reject unreasonably large values */
                    if (klen + 1 + vlen >= 32767)
                    {
                        fprintf(stderr,
                                "oci2bin: -e %s: value too large (skipped)\n",
                                argv[i]);
                    }
                    else
                    {
                        char* buf = malloc(klen + 1 + vlen + 1);
                        if (!buf)
                        {
                            fprintf(stderr, "oci2bin: -e: out of memory\n");
                            return -1;
                        }
                        memcpy(buf, argv[i], klen);
                        buf[klen] = '=';
                        memcpy(buf + klen + 1, host_val, vlen + 1);
                        opts->env_vars[opts->n_env++] = buf;
                    }
                }
            }
            else
            {
                opts->env_vars[opts->n_env++] = argv[i];
            }
        }
        else if (strcmp(argv[i], "--entrypoint") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "oci2bin: --entrypoint requires a path argument\n");
                return -1;
            }
            opts->entrypoint = argv[++i];
        }
        else if (strcmp(argv[i], "--workdir") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "oci2bin: --workdir requires a path argument\n");
                return -1;
            }
            opts->workdir = argv[++i];
        }
        else if (strcmp(argv[i], "--net") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr,
                        "oci2bin: --net requires host, none, or"
                        " container:<PID>\n");
                return -1;
            }
            i++;
            if (strcmp(argv[i], "host") == 0 || strcmp(argv[i], "none") == 0)
            {
                opts->net = argv[i];
            }
            else if (strncmp(argv[i], "container:", 10) == 0)
            {
                char* endptr;
                errno = 0;
                long pid = strtol(argv[i] + 10, &endptr, 10);
                if (*endptr != '\0' || errno == ERANGE ||
                        pid <= 0 || pid > INT_MAX)
                {
                    fprintf(stderr,
                            "oci2bin: --net container:<PID>:"
                            " invalid PID\n");
                    return -1;
                }
                opts->net_join_pid = (pid_t)pid;
            }
            else if (strcmp(argv[i], "pasta") == 0)
            {
                opts->net = argv[i]; /* "pasta" */
            }
            else if (strcmp(argv[i], "slirp") == 0)
            {
                opts->net = argv[i]; /* "slirp" */
            }
            else if (strncmp(argv[i], "slirp:", 6) == 0)
            {
                /* slirp:HOST_PORT:CTR_PORT */
                char* portspec = argv[i] + 6;
                char* colon = strchr(portspec, ':');
                if (!colon || colon == portspec || colon[1] == '\0')
                {
                    fprintf(stderr,
                            "oci2bin: --net slirp:HOST:CTR:"
                            " invalid port forward spec\n");
                    return -1;
                }
                if (opts->n_portfwd >= 16)
                {
                    fprintf(stderr,
                            "oci2bin: too many port forwards"
                            " (max 16)\n");
                    return -1;
                }
                opts->net_portfwd[opts->n_portfwd++] = portspec;
                opts->net = "slirp";
            }
            else
            {
                fprintf(stderr,
                        "oci2bin: --net must be host, none, slirp,"
                        " pasta, slirp:H:C, or container:<PID>\n");
                return -1;
            }
        }
        else if (strcmp(argv[i], "--ipc") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr,
                        "oci2bin: --ipc requires host or container:<PID>\n");
                return -1;
            }
            i++;
            if (strcmp(argv[i], "host") == 0)
            {
                /* explicit host — already the default, no-op */
            }
            else if (strncmp(argv[i], "container:", 10) == 0)
            {
                char* endptr;
                errno = 0;
                long pid = strtol(argv[i] + 10, &endptr, 10);
                if (*endptr != '\0' || errno == ERANGE ||
                        pid <= 0 || pid > INT_MAX)
                {
                    fprintf(stderr,
                            "oci2bin: --ipc container:<PID>:"
                            " invalid PID\n");
                    return -1;
                }
                opts->ipc_join_pid = (pid_t)pid;
            }
            else
            {
                fprintf(stderr,
                        "oci2bin: --ipc must be host or container:<PID>\n");
                return -1;
            }
        }
        else if (strcmp(argv[i], "--read-only") == 0)
        {
            opts->read_only = 1;
        }
        else if (strcmp(argv[i], "--overlay-persist") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr,
                        "oci2bin: --overlay-persist requires DIR"
                        " argument\n");
                return -1;
            }
            i++;
            if (strstr(argv[i], ".."))
            {
                fprintf(stderr,
                        "oci2bin: --overlay-persist: path must not"
                        " contain '..'\n");
                return -1;
            }
            opts->overlay_persist = argv[i];
        }
        else if (strcmp(argv[i], "--ssh-agent") == 0)
        {
            opts->ssh_agent = 1;
        }
        else if (strcmp(argv[i], "--no-seccomp") == 0)
        {
            opts->no_seccomp = 1;
        }
        else if (strcmp(argv[i], "--no-host-dev") == 0)
        {
            opts->no_host_dev = 1;
        }
        else if (strcmp(argv[i], "--init") == 0)
        {
            opts->use_init = 1;
        }
        else if (strcmp(argv[i], "--detach") == 0
                 || strcmp(argv[i], "-d") == 0)
        {
            opts->detach = 1;
        }
        else if (strcmp(argv[i], "--vm") == 0)
        {
            opts->use_vm = 1;
        }
        else if (strcmp(argv[i], "--vmm") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "oci2bin: --vmm requires a VMM argument\n");
                return -1;
            }
            opts->vmm = argv[++i];
        }
        else if (strcmp(argv[i], "--memory") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "oci2bin: --memory requires SIZE argument\n");
                return -1;
            }
            i++;
            char* spec = argv[i];
            char* endp = NULL;
            errno = 0;
            long long val = strtoll(spec, &endp, 10);
            if (endp == spec || val <= 0 || errno == ERANGE)
            {
                fprintf(stderr,
                        "oci2bin: --memory: invalid size '%s'\n", spec);
                return -1;
            }
            /* Parse optional suffix; check bounds BEFORE multiplying to
             * prevent signed integer overflow (UB) that would silently
             * bypass the 256 GiB cap check done after the multiplication. */
            if (*endp == 'k' || *endp == 'K')
            {
                if (val > 256LL * 1024LL * 1024LL * 1024LL / 1024LL)
                {
                    fprintf(stderr,
                            "oci2bin: --memory: value exceeds 256 GiB\n");
                    return -1;
                }
                val *= 1024LL;
                endp++;
            }
            else if (*endp == 'm' || *endp == 'M')
            {
                if (val > 256LL * 1024LL * 1024LL * 1024LL
                        / (1024LL * 1024LL))
                {
                    fprintf(stderr,
                            "oci2bin: --memory: value exceeds 256 GiB\n");
                    return -1;
                }
                val *= 1024LL * 1024LL;
                endp++;
            }
            else if (*endp == 'g' || *endp == 'G')
            {
                if (val > 256LL)
                {
                    fprintf(stderr,
                            "oci2bin: --memory: value exceeds 256 GiB\n");
                    return -1;
                }
                val *= 1024LL * 1024LL * 1024LL;
                endp++;
            }
            if (*endp != '\0')
            {
                fprintf(stderr,
                        "oci2bin: --memory: invalid suffix in '%s'\n", spec);
                return -1;
            }
            /* Reject > 256 GiB (no-suffix path) */
            if (val > 256LL * 1024LL * 1024LL * 1024LL)
            {
                fprintf(stderr,
                        "oci2bin: --memory: value exceeds 256 GiB\n");
                return -1;
            }
            opts->cg_memory_bytes = val;
        }
        else if (strcmp(argv[i], "--cpus") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "oci2bin: --cpus requires FLOAT argument\n");
                return -1;
            }
            i++;
            char* endp = NULL;
            double cpus = strtod(argv[i], &endp);
            if (endp == argv[i] || *endp != '\0' || cpus <= 0.0)
            {
                fprintf(stderr,
                        "oci2bin: --cpus: invalid value '%s'\n", argv[i]);
                return -1;
            }
            if (cpus > 1024.0)
            {
                fprintf(stderr, "oci2bin: --cpus: value exceeds 1024\n");
                return -1;
            }
            /* Convert to quota: round(cpus * 100000) */
            long quota = (long)(cpus * 100000.0 + 0.5);
            if (quota < 1)
            {
                quota = 1;
            }
            opts->cg_cpu_quota = quota;
        }
        else if (strcmp(argv[i], "--pids-limit") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr,
                        "oci2bin: --pids-limit requires N argument\n");
                return -1;
            }
            i++;
            char* endp = NULL;
            long pids = strtol(argv[i], &endp, 10);
            if (endp == argv[i] || *endp != '\0' || pids <= 0)
            {
                fprintf(stderr,
                        "oci2bin: --pids-limit: invalid value '%s'\n",
                        argv[i]);
                return -1;
            }
            if (pids > 65536)
            {
                fprintf(stderr,
                        "oci2bin: --pids-limit: value exceeds 65536\n");
                return -1;
            }
            opts->cg_pids = pids;
        }
        else if (strcmp(argv[i], "--verify-key") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr,
                        "oci2bin: --verify-key requires PATH argument\n");
                return -1;
            }
            i++;
            if (strstr(argv[i], ".."))
            {
                fprintf(stderr,
                        "oci2bin: --verify-key: key path must not"
                        " contain '..'\n");
                return -1;
            }
            opts->verify_key = argv[i];
        }
        else if (strcmp(argv[i], "--cap-drop") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "oci2bin: --cap-drop requires a CAP argument\n");
                return -1;
            }
            i++;
            if (strcasecmp(argv[i], "all") == 0)
            {
                opts->cap_drop_all = 1;
            }
            else
            {
                int cn = cap_name_to_num(argv[i]);
                if (cn < 0)
                {
                    fprintf(stderr,
                            "oci2bin: --cap-drop: unknown capability '%s'\n",
                            argv[i]);
                    return -1;
                }
                opts->cap_drop_mask |= (uint64_t)1 << cn;
            }
        }
        else if (strcmp(argv[i], "--cap-add") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "oci2bin: --cap-add requires a CAP argument\n");
                return -1;
            }
            i++;
            int cn = cap_name_to_num(argv[i]);
            if (cn < 0)
            {
                fprintf(stderr,
                        "oci2bin: --cap-add: unknown capability '%s'\n",
                        argv[i]);
                return -1;
            }
            opts->cap_add_mask |= (uint64_t)1 << cn;
        }
        else if (strcmp(argv[i], "--device") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr,
                        "oci2bin: --device requires /dev/PATH[:CONTAINER_PATH]\n");
                return -1;
            }
            i++;
            if (opts->n_devices >= MAX_VOLUMES)
            {
                fprintf(stderr,
                        "oci2bin: too many --device flags (max %d)\n",
                        MAX_VOLUMES);
                return -1;
            }
            char* spec = argv[i];
            /* Validate host path starts with /dev/ */
            if (strncmp(spec, "/dev/", 5) != 0)
            {
                fprintf(stderr,
                        "oci2bin: --device host path must start with /dev/: %s\n",
                        spec);
                return -1;
            }
            if (strstr(spec, ".."))
            {
                fprintf(stderr,
                        "oci2bin: --device path must not contain '..': %s\n",
                        spec);
                return -1;
            }
            char* colon = strchr(spec, ':');
            if (colon)
            {
                *colon = '\0';
                char* ctr = colon + 1;
                if (strncmp(ctr, "/dev/", 5) != 0)
                {
                    fprintf(stderr,
                            "oci2bin: --device container path must start"
                            " with /dev/: %s\n",
                            ctr);
                    return -1;
                }
                if (strstr(ctr, ".."))
                {
                    fprintf(stderr,
                            "oci2bin: --device container path must not"
                            " contain '..': %s\n",
                            ctr);
                    return -1;
                }
                opts->device_ctr[opts->n_devices] = ctr;
            }
            else
            {
                opts->device_ctr[opts->n_devices] = NULL;
            }
            opts->devices[opts->n_devices++] = spec;
        }
        else if (strcmp(argv[i], "--hostname") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "oci2bin: --hostname requires NAME\n");
                return -1;
            }
            opts->hostname = argv[++i];
        }
        else if (strcmp(argv[i], "--user") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "oci2bin: --user requires UID[:GID]\n");
                return -1;
            }
            i++;
            char* spec = argv[i];
            /* Only numeric UIDs/GIDs are accepted — no name lookup pre-chroot */
            char* colon = strchr(spec, ':');
            char* endp  = NULL;
            unsigned long uid_val;
            unsigned long gid_val;
            if (spec[0] < '0' || spec[0] > '9')
            {
                fprintf(stderr,
                        "oci2bin: --user requires a numeric UID, not a name\n");
                return -1;
            }
            uid_val = strtoul(spec, &endp, 10);
            /* endp must point to ':' (if a colon was given) or '\0' */
            if (endp != (colon ? colon : spec + strlen(spec)))
            {
                fprintf(stderr,
                        "oci2bin: --user UID contains non-numeric characters\n");
                return -1;
            }
            if (uid_val > 65534)
            {
                fprintf(stderr, "oci2bin: --user UID must be <= 65534\n");
                return -1;
            }
            opts->run_uid = (uid_t)uid_val;
            if (colon)
            {
                if (colon[1] < '0' || colon[1] > '9')
                {
                    fprintf(stderr,
                            "oci2bin: --user GID must be numeric\n");
                    return -1;
                }
                gid_val = strtoul(colon + 1, &endp, 10);
                if (*endp != '\0')
                {
                    fprintf(stderr,
                            "oci2bin: --user GID contains non-numeric characters\n");
                    return -1;
                }
                if (gid_val > 65534)
                {
                    fprintf(stderr, "oci2bin: --user GID must be <= 65534\n");
                    return -1;
                }
                opts->run_gid = (gid_t)gid_val;
            }
            else
            {
                opts->run_gid = (gid_t)uid_val;
            }
            opts->has_user = 1;
        }
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
        {
            usage(argv[0]);
            exit(0);
        }
        else if (argv[i][0] == '-')
        {
            fprintf(stderr, "oci2bin: unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return -1;
        }
        else
        {
            /* First non-flag arg: treat rest as CMD */
            break;
        }
    }
    /* Remaining args are extra CMD */
    if (i < argc)
    {
        opts->extra_args = &argv[i];
        opts->n_extra    = argc - i;
    }
    return 0;
}

/* ── binary signature verification ──────────────────────────────────────── */

/*
 * Verify the binary signature by delegating to sign_binary.py via execvp.
 * Never uses a shell. Returns 0 on success, -1 on failure.
 * Aborts the process on invalid signature.
 */
static int verify_signature(const char* key_path)
{
    /* Resolve SCRIPTS_DIR relative to /proc/self/exe */
    char self_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (len < 0)
    {
        perror("oci2bin: --verify-key: readlink /proc/self/exe");
        return -1;
    }
    self_path[len] = '\0';

    /* scripts dir = dirname(self_path) + "/../scripts" resolved via dirname */
    char scripts_dir[PATH_MAX];
    char* slash = strrchr(self_path, '/');
    if (!slash)
    {
        fprintf(stderr,
                "oci2bin: --verify-key: cannot determine script dir\n");
        return -1;
    }
    size_t dir_len = (size_t)(slash - self_path);
    /* Build: <dir>/../scripts/sign_binary.py */
    int n = snprintf(scripts_dir, sizeof(scripts_dir),
                     "%.*s/../scripts/sign_binary.py",
                     (int)dir_len, self_path);
    if (n < 0 || n >= (int)sizeof(scripts_dir))
    {
        fprintf(stderr,
                "oci2bin: --verify-key: scripts path truncated\n");
        return -1;
    }

    /* Validate key_path: must not contain '..' */
    if (strstr(key_path, ".."))
    {
        fprintf(stderr,
                "oci2bin: --verify-key: key path must not contain "
                "'..'\n");
        return -1;
    }

    /* execvp: python3 sign_binary.py verify --key KEY --in /proc/self/exe */
    pid_t pid = fork();
    if (pid < 0)
    {
        perror("oci2bin: --verify-key: fork");
        return -1;
    }
    if (pid == 0)
    {
        char* args[] =
        {
            "python3",
            scripts_dir,
            "verify",
            "--key", (char*)key_path,
            "--in", self_path,
            NULL
        };
        execvp("python3", args);
        perror("oci2bin: execvp python3");
        _exit(127);
    }
    int status;
    if (waitpid(pid, &status, 0) < 0)
    {
        perror("oci2bin: --verify-key: waitpid");
        return -1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        fprintf(stderr,
                "oci2bin: signature verification failed — "
                "aborting before extraction\n");
        return -1;
    }
    return 0;
}

/* ── cgroup v2 resource limits ───────────────────────────────────────────── */

/*
 * Write NUL-terminated string to a cgroup file.
 * Returns 0 on success, -1 on failure (prints warning).
 */
static int cg_write(const char* path, const char* value)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
    {
        fprintf(stderr, "oci2bin: cgroup: open %s: %s\n",
                path, strerror(errno));
        return -1;
    }
    ssize_t n = write(fd, value, strlen(value));
    int saved = errno;
    close(fd);
    if (n < 0)
    {
        fprintf(stderr, "oci2bin: cgroup: write %s (%s): %s\n",
                path, value, strerror(saved));
        return -1;
    }
    return 0;
}

static char g_cgroup_dir[PATH_MAX]; /* global so atexit can clean up */

static void cleanup_cgroup(void)
{
    if (g_cgroup_dir[0])
    {
        rmdir(g_cgroup_dir);
        g_cgroup_dir[0] = '\0';
    }
}

/*
 * Set up a cgroup v2 leaf for this process.  Called before unshare().
 * On failure: prints a warning and returns 0 (non-fatal).
 * Returns 1 if a cgroup namespace unshare should be done, 0 otherwise.
 */
static int setup_cgroup(const struct container_opts* opts)
{
    if (!opts->cg_memory_bytes && !opts->cg_cpu_quota && !opts->cg_pids)
    {
        return 0;
    }

    /* Verify cgroup v2 is mounted */
    struct stat st;
    if (stat("/sys/fs/cgroup/cgroup.controllers", &st) < 0)
    {
        fprintf(stderr,
                "oci2bin: cgroup v2 not available"
                " (/sys/fs/cgroup/cgroup.controllers missing);"
                " resource limits disabled\n");
        return 0;
    }

    /* Create leaf: /sys/fs/cgroup/oci2bin-<pid> */
    int n = snprintf(g_cgroup_dir, sizeof(g_cgroup_dir),
                     "/sys/fs/cgroup/oci2bin-%d", (int)getpid());
    if (n < 0 || n >= (int)sizeof(g_cgroup_dir))
    {
        fprintf(stderr, "oci2bin: cgroup dir path truncated\n");
        return 0;
    }

    if (mkdir(g_cgroup_dir, 0755) < 0 && errno != EEXIST)
    {
        fprintf(stderr, "oci2bin: cgroup mkdir %s: %s\n",
                g_cgroup_dir, strerror(errno));
        return 0;
    }

    /* Enable controllers in the root cgroup's subtree_control */
    {
        char ctrl_path[PATH_MAX];
        n = snprintf(ctrl_path, sizeof(ctrl_path),
                     "/sys/fs/cgroup/cgroup.subtree_control");
        if (n < 0 || n >= (int)sizeof(ctrl_path))
        {
            fprintf(stderr, "oci2bin: subtree_control path truncated\n");
        }
        else
        {
            /* Ignore failures — controllers may already be enabled */
            cg_write(ctrl_path, "+memory +cpu +pids");
        }
    }

    /* memory.max */
    if (opts->cg_memory_bytes > 0)
    {
        char path[PATH_MAX];
        n = snprintf(path, sizeof(path), "%s/memory.max", g_cgroup_dir);
        if (n < 0 || n >= (int)sizeof(path))
        {
            fprintf(stderr, "oci2bin: cgroup memory.max path truncated\n");
        }
        else
        {
            char val[32];
            int vn = snprintf(val, sizeof(val), "%lld\n",
                              opts->cg_memory_bytes);
            if (vn < 0 || vn >= (int)sizeof(val))
            {
                fprintf(stderr,
                        "oci2bin: memory value out of range\n");
            }
            else
            {
                cg_write(path, val);
            }
        }
    }

    /* cpu.max — format: "QUOTA PERIOD\n" */
    if (opts->cg_cpu_quota > 0)
    {
        char path[PATH_MAX];
        n = snprintf(path, sizeof(path), "%s/cpu.max", g_cgroup_dir);
        if (n < 0 || n >= (int)sizeof(path))
        {
            fprintf(stderr, "oci2bin: cgroup cpu.max path truncated\n");
        }
        else
        {
            char val[64];
            int vn = snprintf(val, sizeof(val), "%ld 100000\n",
                              opts->cg_cpu_quota);
            if (vn < 0 || vn >= (int)sizeof(val))
            {
                fprintf(stderr, "oci2bin: cpu quota value out of range\n");
            }
            else
            {
                cg_write(path, val);
            }
        }
    }

    /* pids.max */
    if (opts->cg_pids > 0)
    {
        char path[PATH_MAX];
        n = snprintf(path, sizeof(path), "%s/pids.max", g_cgroup_dir);
        if (n < 0 || n >= (int)sizeof(path))
        {
            fprintf(stderr, "oci2bin: cgroup pids.max path truncated\n");
        }
        else
        {
            char val[32];
            int vn = snprintf(val, sizeof(val), "%ld\n", opts->cg_pids);
            if (vn < 0 || vn >= (int)sizeof(val))
            {
                fprintf(stderr, "oci2bin: pids value out of range\n");
            }
            else
            {
                cg_write(path, val);
            }
        }
    }

    /* Move ourselves into the leaf cgroup */
    {
        char path[PATH_MAX];
        n = snprintf(path, sizeof(path), "%s/cgroup.procs", g_cgroup_dir);
        if (n < 0 || n >= (int)sizeof(path))
        {
            fprintf(stderr, "oci2bin: cgroup.procs path truncated\n");
            rmdir(g_cgroup_dir);
            g_cgroup_dir[0] = '\0';
            return 0;
        }
        char pid_str[16];
        int pn = snprintf(pid_str, sizeof(pid_str), "%d\n", (int)getpid());
        if (pn < 0 || pn >= (int)sizeof(pid_str))
        {
            fprintf(stderr, "oci2bin: pid string truncated\n");
            rmdir(g_cgroup_dir);
            g_cgroup_dir[0] = '\0';
            return 0;
        }
        if (cg_write(path, pid_str) < 0)
        {
            rmdir(g_cgroup_dir);
            g_cgroup_dir[0] = '\0';
            return 0;
        }
    }

    atexit(cleanup_cgroup);
    return 1; /* caller should unshare(CLONE_NEWCGROUP) */
}

/* ── tmpdir cleanup ──────────────────────────────────────────────────────── */

/*
 * Recursive deletion via nftw — no fork() required.
 * Used instead of "rm -rf" to avoid forking after CLONE_NEWPID, which would
 * fail with ENOMEM because the child PID namespace is already destroyed.
 */
static int rm_entry(const char* path, const struct stat* sb,
                    int typeflag, struct FTW* ftwbuf)
{
    (void)sb;
    (void)ftwbuf;
    if (typeflag == FTW_DP)
    {
        return rmdir(path);
    }
    return unlink(path);
}

static void rm_rf_dir(const char* path)
{
    nftw(path, rm_entry, 16, FTW_DEPTH | FTW_PHYS);
}

/* ── VM backend ──────────────────────────────────────────────────────────── */

/*
 * extract_vm_blob: read SIZE bytes from /proc/self/exe at OFFSET, write to
 * OUT_PATH.  Returns 0 on success, -1 on error.
 * Security checks: rejects sentinel offsets, sizes > 64 MiB, and
 * offset+size overflow.
 */
static int extract_vm_blob(unsigned long offset, unsigned long size,
                           const char* out_path)
{
    /* Reject zero offset (unpatched binary — caller must check PATCHED flag) */
    if (offset == 0)
    {
        fprintf(stderr, "oci2bin: VM blob not embedded (zero offset)\n");
        return -1;
    }
    /* Reject unreasonably large blobs (> 64 MiB) */
    if (size == 0 || size > 67108864UL)
    {
        fprintf(stderr, "oci2bin: VM blob size out of range: %lu\n", size);
        return -1;
    }
    /* Reject offset+size overflow */
    if (offset + size < offset)
    {
        fprintf(stderr, "oci2bin: VM blob offset+size overflow\n");
        return -1;
    }

    int in_fd = open("/proc/self/exe", O_RDONLY);
    if (in_fd < 0)
    {
        perror("open /proc/self/exe");
        return -1;
    }
    if (lseek(in_fd, (off_t)offset, SEEK_SET) < 0)
    {
        perror("lseek VM blob");
        close(in_fd);
        return -1;
    }

    int out_fd = open(out_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (out_fd < 0)
    {
        perror("open VM blob output");
        close(in_fd);
        return -1;
    }

    char buf[65536];
    unsigned long remaining = size;
    while (remaining > 0)
    {
        size_t to_read = remaining < sizeof(buf) ? remaining : sizeof(buf);
        ssize_t n = read(in_fd, buf, to_read);
        if (n <= 0)
        {
            fprintf(stderr, "oci2bin: read VM blob: short read at offset %lu\n",
                    size - remaining);
            close(in_fd);
            close(out_fd);
            return -1;
        }
        if (write(out_fd, buf, (size_t)n) != n)
        {
            perror("write VM blob");
            close(in_fd);
            close(out_fd);
            return -1;
        }
        remaining -= (unsigned long)n;
    }
    close(in_fd);
    if (close(out_fd) < 0)
    {
        perror("close VM blob output");
        return -1;
    }
    return 0;
}

/*
 * vm_init_main: PID 1 inside the microVM.
 * Called when OCI2BIN_VM_INIT is set in the environment.
 */
static int vm_init_main(void)
{
    /* 1. Mount pseudo-filesystems */
    mkdir("/proc", 0555); /* ignore EEXIST */
    if (mount("proc", "/proc", "proc",
              MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) < 0)
    {
        perror("mount /proc");
        /* continue anyway — some images may have it already */
    }
    mkdir("/sys", 0555);
    if (mount("sysfs", "/sys", "sysfs",
              MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) < 0)
    {
        perror("mount /sys");
    }
    /* /dev should already exist from initramfs rootfs */
    if (mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, "mode=0755") < 0)
    {
        perror("mount /dev");
    }
    mkdir("/dev/pts", 0755);
    if (mount("devpts", "/dev/pts", "devpts",
              MS_NOSUID | MS_NOEXEC, NULL) < 0)
    {
        perror("mount /dev/pts");
    }

    /* 2. Handle virtiofs mounts from cmdline: oci2bin.mount.N=tag:path */
    size_t cmdline_size;
    char* vm_cmdline = read_file("/proc/cmdline", &cmdline_size);
    if (vm_cmdline)
    {
        for (int mi = 0; mi < 64; mi++)
        {
            char key[32];
            int kn = snprintf(key, sizeof(key), "oci2bin.mount.%d=", mi);
            if (kn < 0 || (size_t)kn >= sizeof(key))
            {
                break;
            }
            char* pos = strstr(vm_cmdline, key);
            if (!pos)
            {
                break;
            }
            pos += strlen(key);
            /* format: tag:path */
            char* colon = strchr(pos, ':');
            if (!colon)
            {
                break;
            }
            size_t tag_len = (size_t)(colon - pos);
            char tag[256];
            if (tag_len >= sizeof(tag))
            {
                break;
            }
            memcpy(tag, pos, tag_len);
            tag[tag_len] = '\0';
            /* path ends at space or end-of-string */
            char* path_end = colon + 1;
            while (*path_end && *path_end != ' ' && *path_end != '\n')
            {
                path_end++;
            }
            size_t path_len = (size_t)(path_end - (colon + 1));
            char mnt_path[PATH_MAX];
            if (path_len >= sizeof(mnt_path))
            {
                break;
            }
            memcpy(mnt_path, colon + 1, path_len);
            mnt_path[path_len] = '\0';
            /* validate path — reject .. */
            if (strstr(mnt_path, "..") != NULL || mnt_path[0] != '/')
            {
                fprintf(stderr,
                        "oci2bin-init: skipping unsafe mount path: %s\n",
                        mnt_path);
                continue;
            }
            /* mkdir and mount */
            mkdir(mnt_path, 0755); /* ignore errors */
            if (mount(tag, mnt_path, "virtiofs", 0, NULL) < 0)
            {
                perror("mount virtiofs");
            }
        }
        free(vm_cmdline);
    }

    /* 3. Read /.oci2bin_config */
    size_t cfg_size;
    char* cfg = read_file("/.oci2bin_config", &cfg_size);
    if (!cfg)
    {
        fprintf(stderr, "oci2bin-init: /.oci2bin_config not found\n");
        return 1;
    }

    /* 4. Parse entrypoint + cmd + env + workdir from config */
    char* entrypoint_json = json_get_array(cfg, "Entrypoint");
    char* cmd_json        = json_get_array(cfg, "Cmd");
    char* env_json        = json_get_array(cfg, "Env");
    char* workdir         = json_get_string(cfg, "WorkingDir");
    free(cfg);

    /* 5. Build exec argv (entrypoint + cmd) */
    char* exec_args[MAX_ARGS + 1];
    int exec_argc = 0;

    if (entrypoint_json && strcmp(entrypoint_json, "null") != 0)
    {
        exec_argc += json_parse_string_array(entrypoint_json,
                                             exec_args + exec_argc,
                                             MAX_ARGS - exec_argc);
    }
    free(entrypoint_json);

    if (cmd_json && strcmp(cmd_json, "null") != 0)
    {
        exec_argc += json_parse_string_array(cmd_json,
                                             exec_args + exec_argc,
                                             MAX_ARGS - exec_argc);
    }
    free(cmd_json);

    if (exec_argc == 0)
    {
        exec_args[0] = "/bin/sh";
        exec_argc    = 1;
    }
    exec_args[exec_argc] = NULL;

    /* 6. Build flat env array */
    char* flat_env[MAX_ENV + 1];
    int flat_env_n = 0;

    /* Seed with defaults */
    flat_env[flat_env_n++] =
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    flat_env[flat_env_n++] = "HOME=/root";
    flat_env[flat_env_n++] = "TERM=xterm";

    char* image_envs[MAX_ENV];
    int n_image_env = 0;
    if (env_json && strcmp(env_json, "null") != 0)
    {
        n_image_env = json_parse_string_array(env_json, image_envs, MAX_ENV);
        for (int i = 0; i < n_image_env && flat_env_n < MAX_ENV; i++)
        {
            flat_env[flat_env_n++] = image_envs[i];
        }
    }
    free(env_json);
    flat_env[flat_env_n] = NULL;

    /* 7. chdir to workdir */
    if (workdir && workdir[0])
    {
        if (chdir(workdir) < 0)
        {
            perror("chdir workdir"); /* non-fatal */
        }
    }
    free(workdir);

    /* 8. exec */
    execvpe(exec_args[0], exec_args, flat_env);
    perror("oci2bin-init: execvpe");

    /* Free image_envs on failure path */
    for (int i = 0; i < n_image_env; i++)
    {
        free(image_envs[i]);
    }
    return 1;
}

#ifdef USE_LIBKRUN
#include <libkrun.h>

/*
 * run_as_vm_libkrun: launch the container using libkrun in-process VM.
 * Does not return on success (krun_start_enter never returns).
 */
static int run_as_vm_libkrun(const char* rootfs, const char* tmpdir,
                             struct container_opts* opts)
{
    (void)tmpdir; /* unused in libkrun path */

    /* Read rootfs config */
    char config_path[PATH_MAX];
    int cn = snprintf(config_path, sizeof(config_path),
                      "%s/.oci2bin_config", rootfs);
    if (cn < 0 || (size_t)cn >= sizeof(config_path))
    {
        fprintf(stderr, "oci2bin: config path truncated\n");
        return 1;
    }
    char* cfg = read_file(config_path, NULL);

    /* Parse entrypoint/cmd/env/workdir */
    char* entrypoint_json = cfg ? json_get_array(cfg, "Entrypoint") : NULL;
    char* cmd_json        = cfg ? json_get_array(cfg, "Cmd") : NULL;
    char* env_json        = cfg ? json_get_array(cfg, "Env") : NULL;
    char* image_workdir   = cfg ? json_get_string(cfg, "WorkingDir") : NULL;
    free(cfg);

    /* Build exec argv */
    char* exec_args[MAX_ARGS + 1];
    int exec_argc = 0;

    if (entrypoint_json && strcmp(entrypoint_json, "null") != 0)
    {
        exec_argc += json_parse_string_array(entrypoint_json,
                                             exec_args + exec_argc,
                                             MAX_ARGS - exec_argc);
    }
    free(entrypoint_json);

    if (opts->n_extra > 0)
    {
        for (int i = 0; i < opts->n_extra && exec_argc < MAX_ARGS; i++)
        {
            exec_args[exec_argc++] = opts->extra_args[i];
        }
    }
    else if (cmd_json && strcmp(cmd_json, "null") != 0)
    {
        exec_argc += json_parse_string_array(cmd_json,
                                             exec_args + exec_argc,
                                             MAX_ARGS - exec_argc);
    }
    free(cmd_json);

    if (exec_argc == 0)
    {
        exec_args[0] = "/bin/sh";
        exec_argc    = 1;
    }
    exec_args[exec_argc] = NULL;

    /* Build flat env array (image Env + opts->env_vars) */
    char* flat_env[MAX_ENV + 1];
    int flat_env_n = 0;
    char* image_envs[MAX_ENV];
    int n_image_env = 0;

    if (env_json && strcmp(env_json, "null") != 0)
    {
        n_image_env = json_parse_string_array(env_json, image_envs, MAX_ENV);
        for (int i = 0; i < n_image_env && flat_env_n < MAX_ENV; i++)
        {
            flat_env[flat_env_n++] = image_envs[i];
        }
    }
    free(env_json);

    for (int i = 0; i < opts->n_env && flat_env_n < MAX_ENV; i++)
    {
        flat_env[flat_env_n++] = opts->env_vars[i];
    }
    flat_env[flat_env_n] = NULL;

    /* Create libkrun context */
    int32_t ctx = krun_create_ctx();
    if (ctx < 0)
    {
        fprintf(stderr, "oci2bin: krun_create_ctx failed: %d\n", ctx);
        goto cleanup;
    }

    /* Set VM config */
    uint8_t vcpus = (opts->cg_cpu_quota > 0 && opts->cg_cpu_quota <= 255) ?
                    (uint8_t)opts->cg_cpu_quota : 1;
    uint32_t mem_mb =
        (opts->cg_memory_bytes > 0) ?
        (uint32_t)((unsigned long long)opts->cg_memory_bytes >> 20) : 256;
    if (krun_set_vm_config((uint32_t)ctx, vcpus, mem_mb) != 0)
    {
        fprintf(stderr, "oci2bin: krun_set_vm_config failed\n");
        goto cleanup;
    }

    /* Set rootfs */
    if (krun_set_root((uint32_t)ctx, rootfs) != 0)
    {
        fprintf(stderr, "oci2bin: krun_set_root failed\n");
        goto cleanup;
    }

    /* Add volume mounts via krun_set_mapped_volumes (format: "host:guest") */
    if (opts->n_vols > 0)
    {
        char vol_bufs[MAX_VOLUMES][PATH_MAX * 2 + 2];
        const char* mapped[MAX_VOLUMES + 1];
        for (int vi = 0; vi < opts->n_vols; vi++)
        {
            if (strstr(opts->vol_host[vi], "..") != NULL)
            {
                fprintf(stderr, "oci2bin: -v host path contains ..: %s\n",
                        opts->vol_host[vi]);
                goto cleanup;
            }
            if (strstr(opts->vol_ctr[vi], "..") != NULL ||
                    opts->vol_ctr[vi][0] != '/')
            {
                fprintf(stderr, "oci2bin: -v container path invalid: %s\n",
                        opts->vol_ctr[vi]);
                goto cleanup;
            }
            int vn = snprintf(vol_bufs[vi], sizeof(vol_bufs[vi]),
                              "%s:%s", opts->vol_host[vi], opts->vol_ctr[vi]);
            if (vn < 0 || (size_t)vn >= sizeof(vol_bufs[vi]))
            {
                fprintf(stderr, "oci2bin: volume path too long\n");
                goto cleanup;
            }
            mapped[vi] = vol_bufs[vi];
        }
        mapped[opts->n_vols] = NULL;
        if (krun_set_mapped_volumes((uint32_t)ctx, mapped) != 0)
        {
            fprintf(stderr, "oci2bin: krun_set_mapped_volumes failed\n");
            goto cleanup;
        }
    }

    /* Set workdir */
    {
        const char* wdir = opts->workdir ? opts->workdir :
                           (image_workdir ? image_workdir : NULL);
        if (wdir && wdir[0])
        {
            if (strstr(wdir, "..") != NULL)
            {
                fprintf(stderr,
                        "oci2bin: workdir contains ..: %s\n", wdir);
                goto cleanup;
            }
            if (krun_set_workdir((uint32_t)ctx, wdir) != 0)
            {
                fprintf(stderr,
                        "oci2bin: krun_set_workdir failed\n");
                goto cleanup;
            }
        }
    }
    free(image_workdir);
    image_workdir = NULL;

    /* Set exec */
    if (krun_set_exec((uint32_t)ctx, exec_args[0],
                      (const char* const *)(exec_args + 1),
                      (const char* const *)flat_env) != 0)
    {
        fprintf(stderr, "oci2bin: krun_set_exec failed\n");
        goto cleanup_ctx;
    }

    /* Start VM — does not return on success */
    if (krun_start_enter((uint32_t)ctx) != 0)
    {
        fprintf(stderr, "oci2bin: krun_start_enter returned unexpectedly\n");
    }

cleanup_ctx:
    for (int i = 0; i < n_image_env; i++)
    {
        free(image_envs[i]);
    }
    free(image_workdir);
    return 1;

cleanup:
    for (int i = 0; i < n_image_env; i++)
    {
        free(image_envs[i]);
    }
    free(image_workdir);
    return 1;
}
#endif /* USE_LIBKRUN */

/*
 * run_as_vm_ch: launch cloud-hypervisor with kernel + initramfs embedded in
 * this binary.  Calls execvp — does not return on success.
 * rootfs: path to the extracted OCI rootfs directory.
 */
static int run_as_vm_ch(const char* rootfs, const char* tmpdir,
                        struct container_opts* opts)
{
    /* Check kernel is embedded */
    if (KERNEL_DATA_PATCHED != 1)
    {
        fprintf(stderr,
                "oci2bin: --vm: no kernel embedded; "
                "rebuild with: oci2bin --kernel build/vmlinux IMAGE OUTPUT\n"
                "  or build with: make LIBKRUN=1 (no kernel needed)\n");
        return 1;
    }

    /* Extract kernel blob */
    char kernel_path[PATH_MAX];
    int n = snprintf(kernel_path, sizeof(kernel_path), "%s/vmlinux", tmpdir);
    if (n < 0 || (size_t)n >= sizeof(kernel_path))
    {
        fprintf(stderr, "oci2bin: kernel path truncated\n");
        return 1;
    }
    if (extract_vm_blob(KERNEL_DATA_OFFSET, KERNEL_DATA_SIZE, kernel_path) < 0)
    {
        return 1;
    }

    /* Extract or build initramfs */
    char initramfs_path[PATH_MAX];
    n = snprintf(initramfs_path, sizeof(initramfs_path),
                 "%s/rootfs.cpio.gz", tmpdir);
    if (n < 0 || (size_t)n >= sizeof(initramfs_path))
    {
        fprintf(stderr, "oci2bin: initramfs path truncated\n");
        return 1;
    }

    if (INITRAMFS_DATA_PATCHED == 1)
    {
        /* Pre-embedded initramfs: just write the blob */
        if (extract_vm_blob(INITRAMFS_DATA_OFFSET, INITRAMFS_DATA_SIZE,
                            initramfs_path) < 0)
        {
            return 1;
        }
    }
    else
    {
        /*
         * Build initramfs at runtime from the extracted rootfs.
         * First, copy /proc/self/exe to rootfs/init so our binary
         * becomes PID 1 in the VM.
         */
        char init_dst[PATH_MAX];
        n = snprintf(init_dst, sizeof(init_dst), "%s/init", rootfs);
        if (n < 0 || (size_t)n >= sizeof(init_dst))
        {
            fprintf(stderr, "oci2bin: init path truncated\n");
            return 1;
        }
        {
            int src_fd = open("/proc/self/exe", O_RDONLY);
            if (src_fd < 0)
            {
                perror("open /proc/self/exe for init copy");
                return 1;
            }
            int dst_fd = open(init_dst, O_CREAT | O_WRONLY | O_TRUNC, 0755);
            if (dst_fd < 0)
            {
                perror("open rootfs/init for writing");
                close(src_fd);
                return 1;
            }
            char cpbuf[65536];
            ssize_t nr;
            while ((nr = read(src_fd, cpbuf, sizeof(cpbuf))) > 0)
            {
                if (write(dst_fd, cpbuf, (size_t)nr) != nr)
                {
                    perror("write rootfs/init");
                    close(src_fd);
                    close(dst_fd);
                    return 1;
                }
            }
            close(src_fd);
            if (close(dst_fd) < 0)
            {
                perror("close rootfs/init");
                return 1;
            }
            if (chmod(init_dst, 0755) < 0)
            {
                perror("chmod rootfs/init");
                return 1;
            }
        }

        /* Find build_polyglot.py relative to self */
        char self_path[PATH_MAX];
        ssize_t slen = readlink("/proc/self/exe", self_path,
                                sizeof(self_path) - 1);
        if (slen < 0)
        {
            perror("readlink /proc/self/exe (initramfs)");
            return 1;
        }
        self_path[slen] = '\0';

        char polyglot_py[PATH_MAX];
        polyglot_py[0] = '\0';

        /* Find dirname of self_path */
        char self_dir[PATH_MAX];
        int sd = snprintf(self_dir, sizeof(self_dir), "%s", self_path);
        if (sd > 0 && (size_t)sd < sizeof(self_dir))
        {
            char* slash = strrchr(self_dir, '/');
            if (slash)
            {
                *slash = '\0';
            }
        }

        /* Search for build_polyglot.py in order:
         *  1. dirname(self)/scripts/          (dev / project root)
         *  2. dirname(self)/../scripts/       (bin/ next to scripts/)
         *  3. dirname(self)/../../share/oci2bin/scripts/ (installed)
         *  4. /usr/share/oci2bin/scripts/     (system fallback)
         */
        static const char* const PY_SUFFIXES[] =
        {
            "/scripts/build_polyglot.py",
            "/../scripts/build_polyglot.py",
            "/../../share/oci2bin/scripts/build_polyglot.py",
            NULL,
        };
        struct stat pystat;
        int found_py = 0;
        for (int si = 0; PY_SUFFIXES[si]; si++)
        {
            n = snprintf(polyglot_py, sizeof(polyglot_py),
                         "%s%s", self_dir, PY_SUFFIXES[si]);
            if (n > 0 && (size_t)n < sizeof(polyglot_py) &&
                    stat(polyglot_py, &pystat) == 0)
            {
                found_py = 1;
                break;
            }
        }
        if (!found_py)
        {
            n = snprintf(polyglot_py, sizeof(polyglot_py),
                         "/usr/share/oci2bin/scripts/build_polyglot.py");
            if (n < 0 || (size_t)n >= sizeof(polyglot_py))
            {
                fprintf(stderr,
                        "oci2bin: build_polyglot.py path truncated\n");
                return 1;
            }
        }

        /* build_polyglot.py --initramfs-only ROOTFSDIR OUTPATH */
        char* args[] =
        {
            "python3",
            polyglot_py,
            "--initramfs-only",
            (char*)rootfs,
            initramfs_path,
            NULL
        };
        pid_t pid = fork();
        if (pid < 0)
        {
            perror("fork initramfs build");
            return 1;
        }
        if (pid == 0)
        {
            execvp("python3", args);
            perror("execvp python3 build_polyglot.py");
            _exit(1);
        }
        int wstatus;
        if (waitpid(pid, &wstatus, 0) < 0)
        {
            perror("waitpid initramfs build");
            return 1;
        }
        if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0)
        {
            fprintf(stderr, "oci2bin: initramfs build failed\n");
            return 1;
        }
    }

    /* --overlay-persist: create/reuse a data disk image */
    char data_img_path[PATH_MAX];
    int have_data_disk = 0;
    if (opts->overlay_persist)
    {
        /* Sanitize: reject paths with .. */
        if (strstr(opts->overlay_persist, "..") != NULL)
        {
            fprintf(stderr,
                    "oci2bin: --overlay-persist path contains ..\n");
            return 1;
        }
        /* Build data image path: overlay_persist/oci2bin-data.ext2 */
        int nn = snprintf(data_img_path, sizeof(data_img_path),
                          "%s/oci2bin-data.ext2", opts->overlay_persist);
        if (nn < 0 || (size_t)nn >= sizeof(data_img_path))
        {
            fprintf(stderr,
                    "oci2bin: overlay_persist path too long\n");
            return 1;
        }
        /* Create data directory */
        if (mkdir(opts->overlay_persist, 0700) < 0 && errno != EEXIST)
        {
            perror("mkdir overlay_persist");
            return 1;
        }
        /* Create ext2 image if not already present */
        struct stat st;
        if (stat(data_img_path, &st) != 0)
        {
            /* Create sparse file (1 GiB) */
            int fd = open(data_img_path,
                          O_CREAT | O_RDWR | O_TRUNC, 0600);
            if (fd < 0)
            {
                perror("open data_img");
                return 1;
            }
            if (ftruncate(fd, 1073741824LL) < 0)
            {
                perror("ftruncate data_img");
                close(fd);
                return 1;
            }
            close(fd);
            /* mkfs.ext2 */
            char* mkfs_argv[] =
            {
                "mkfs.ext2", "-F", data_img_path, NULL
            };
            pid_t mkfs_pid = fork();
            if (mkfs_pid < 0)
            {
                perror("fork mkfs");
                return 1;
            }
            if (mkfs_pid == 0)
            {
                execvp("mkfs.ext2", mkfs_argv);
                perror("execvp mkfs.ext2");
                _exit(1);
            }
            int wst;
            if (waitpid(mkfs_pid, &wst, 0) < 0 ||
                    !WIFEXITED(wst) || WEXITSTATUS(wst) != 0)
            {
                fprintf(stderr, "oci2bin: mkfs.ext2 failed\n");
                return 1;
            }
        }
        have_data_disk = 1;
    }

    /* Build cpu/memory strings */
    char cpus_str[32];
    int vcpus = (opts->cg_cpu_quota > 0) ? (int)opts->cg_cpu_quota : 1;
    n = snprintf(cpus_str, sizeof(cpus_str), "boot=%d", vcpus);
    if (n < 0 || (size_t)n >= sizeof(cpus_str))
    {
        fprintf(stderr, "oci2bin: cpus string truncated\n");
        return 1;
    }

    char mem_str[32];
    unsigned long mem_mb =
        (opts->cg_memory_bytes > 0) ?
        (unsigned long)(opts->cg_memory_bytes >> 20) : 256;
    n = snprintf(mem_str, sizeof(mem_str), "size=%luM", mem_mb);
    if (n < 0 || (size_t)n >= sizeof(mem_str))
    {
        fprintf(stderr, "oci2bin: memory string truncated\n");
        return 1;
    }

    /* Build cmdline string (4096 bytes for multiple virtiofs entries) */
    char cmdline[4096];
    n = snprintf(cmdline, sizeof(cmdline),
                 "console=ttyS0 reboot=k panic=1 pci=off OCI2BIN_VM_INIT=1"
                 " init=/init");
    if (n < 0 || (size_t)n >= sizeof(cmdline))
    {
        fprintf(stderr, "oci2bin: cmdline truncated\n");
        return 1;
    }

    /* Append data disk cmdline param if applicable */
    if (have_data_disk)
    {
        int cn = snprintf(cmdline + strlen(cmdline),
                          sizeof(cmdline) - strlen(cmdline),
                          " oci2bin.data=/dev/vda");
        if (cn < 0 || (size_t)cn >= sizeof(cmdline) - strlen(cmdline))
        {
            fprintf(stderr,
                    "oci2bin: cmdline truncated (data disk)\n");
            return 1;
        }
    }

    /* Append virtiofs mount params to cmdline */
    for (int vi = 0; vi < opts->n_vols; vi++)
    {
        /* Validate container path */
        if (strstr(opts->vol_ctr[vi], "..") != NULL ||
                opts->vol_ctr[vi][0] != '/')
        {
            fprintf(stderr,
                    "oci2bin: -v container path invalid: %s\n",
                    opts->vol_ctr[vi]);
            return 1;
        }
        size_t cur_len = strlen(cmdline);
        int cn = snprintf(cmdline + cur_len,
                          sizeof(cmdline) - cur_len,
                          " oci2bin.mount.%d=vol%d:%s",
                          vi, vi, opts->vol_ctr[vi]);
        if (cn < 0 || (size_t)cn >= sizeof(cmdline) - cur_len)
        {
            fprintf(stderr,
                    "oci2bin: cmdline truncated (mount %d)\n", vi);
            return 1;
        }
    }

    /* Build argv for cloud-hypervisor */
    const char* vmm_bin = opts->vmm ? opts->vmm : "cloud-hypervisor";
    const char* argv[128];
    int ai = 0;

#define CH_ARG(x) do { \
    if (ai >= 126) { \
        fprintf(stderr, "oci2bin: too many cloud-hypervisor args\n"); \
        return 1; \
    } \
    argv[ai++] = (x); \
} while (0)

    CH_ARG(vmm_bin);
    CH_ARG("--kernel");
    CH_ARG(kernel_path);
    CH_ARG("--initramfs");
    CH_ARG(initramfs_path);
    CH_ARG("--cmdline");
    CH_ARG(cmdline);
    CH_ARG("--cpus");
    CH_ARG(cpus_str);
    CH_ARG("--memory");
    CH_ARG(mem_str);

    /* Add data disk if present */
    char disk_arg[PATH_MAX + 16];
    if (have_data_disk)
    {
        int nn = snprintf(disk_arg, sizeof(disk_arg),
                          "path=%s", data_img_path);
        if (nn < 0 || (size_t)nn >= sizeof(disk_arg))
        {
            fprintf(stderr, "oci2bin: disk arg too long\n");
            return 1;
        }
        CH_ARG("--disk");
        CH_ARG(disk_arg);
    }

    /* Per-volume virtiofs: fork virtiofsd for each -v mount */
    char fs_args[MAX_VOLUMES][PATH_MAX + 64];
    for (int vi = 0; vi < opts->n_vols; vi++)
    {
        char sock_path[PATH_MAX];
        int nn = snprintf(sock_path, sizeof(sock_path),
                          "%s/vfs-%d.sock", tmpdir, vi);
        if (nn < 0 || (size_t)nn >= sizeof(sock_path))
        {
            fprintf(stderr,
                    "oci2bin: virtiofs sock path too long\n");
            return 1;
        }
        /* Sanitize host path */
        if (strstr(opts->vol_host[vi], "..") != NULL)
        {
            fprintf(stderr,
                    "oci2bin: -v host path contains ..: %s\n",
                    opts->vol_host[vi]);
            return 1;
        }
        char* vfsd_argv[] =
        {
            "virtiofsd",
            "--socket-path", sock_path,
            "--shared-dir",  opts->vol_host[vi],
            "--sandbox",     "namespace",
            NULL
        };
        pid_t vfsd_pid = fork();
        if (vfsd_pid < 0)
        {
            perror("fork virtiofsd");
            return 1;
        }
        if (vfsd_pid == 0)
        {
            execvp("virtiofsd", vfsd_argv);
            perror("execvp virtiofsd");
            _exit(1);
        }
        /* Don't waitpid — virtiofsd runs for the lifetime of the VM */
        nn = snprintf(fs_args[vi], sizeof(fs_args[vi]),
                      "tag=vol%d,socket=%s,num_queues=1,queue_size=512",
                      vi, sock_path);
        if (nn < 0 || (size_t)nn >= sizeof(fs_args[vi]))
        {
            fprintf(stderr, "oci2bin: --fs arg too long\n");
            return 1;
        }
        CH_ARG("--fs");
        CH_ARG(fs_args[vi]);
    }

    argv[ai] = NULL;
#undef CH_ARG

    execvp(vmm_bin, (char* const*)argv);
    perror("execvp cloud-hypervisor");
    return 1;
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char* argv[])
{
    /* 0. If running as VM init (OCI2BIN_VM_INIT=1), skip all host logic */
    if (getenv("OCI2BIN_VM_INIT"))
    {
        return vm_init_main();
    }

    /* 1. Find ourselves */
    char self_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (len < 0)
    {
        perror("readlink /proc/self/exe");
        return 1;
    }
    self_path[len] = '\0';

    /* 2. Parse command-line options.
     * build_merged_argv pre-scans for --config PATH and, if found, reads
     * the config file and prepends its options as defaults.  parse_opts is
     * then called exactly once on the merged argv. */
    int    merged_argc = 0;
    char** unused_heap = NULL;
    char** merged_argv = build_merged_argv(argc, argv,
                                           &merged_argc, &unused_heap);
    if (!merged_argv)
    {
        return 1;
    }
    struct container_opts opts;
    memset(&opts, 0, sizeof(opts));
    if (parse_opts(merged_argc, merged_argv, &opts) < 0)
    {
        return 1;
    }

    fprintf(stderr, "oci2bin: self=%s offset=0x%lx size=0x%lx\n",
            self_path, OCI_DATA_OFFSET, OCI_DATA_SIZE);

    /* 3. Sanity check the markers */
    if (OCI_PATCHED != 1)
    {
        fprintf(stderr,
                "oci2bin: OCI data markers not patched!\n"
                "This binary must be built with the polyglot builder.\n");
        return 1;
    }

    /* 3a. Verify binary signature before any extraction */
    if (opts.verify_key)
    {
        if (verify_signature(opts.verify_key) < 0)
        {
            return 1;
        }
    }

    /* 4. Extract OCI image into rootfs */
    char* rootfs = extract_oci_rootfs(self_path);
    if (!rootfs)
    {
        fprintf(stderr, "oci2bin: failed to extract OCI rootfs\n");
        return 1;
    }

    fprintf(stderr, "oci2bin: rootfs at %s\n", rootfs);

    /* 4b. VM dispatch: after rootfs extraction so rootfs is available */
    if (opts.use_vm)
    {
        char vm_tmpdir[] = "/tmp/oci2bin-vm-XXXXXX";
        if (mkdtemp(vm_tmpdir) == NULL)
        {
            perror("mkdtemp VM tmpdir");
            free(rootfs);
            return 1;
        }
#ifdef USE_LIBKRUN
        if (!opts.vmm || strcmp(opts.vmm, "libkrun") == 0)
        {
            return run_as_vm_libkrun(rootfs, vm_tmpdir, &opts);
        }
#endif
        return run_as_vm_ch(rootfs, vm_tmpdir, &opts);
    }

    /* 5. Patch rootfs so privilege-dropping tools work in a single-UID namespace */
    patch_rootfs_ids(rootfs);

    /* 6. Capture real UID/GID before entering user namespace */
    uid_t real_uid = getuid();
    gid_t real_gid = getgid();

    /* 6a. Set up cgroup v2 resource limits (before unshare, uses host cgroupfs) */
    int cg_did_setup = setup_cgroup(&opts);

    /* 7. Enter user namespace first (needed before we can map UIDs) */
    if (unshare(CLONE_NEWUSER) < 0)
    {
        perror("unshare(CLONE_NEWUSER)");
        fprintf(stderr, "oci2bin: user namespaces may be disabled on this kernel\n");
        return 1;
    }

    /* 8. Map UID/GID */
    if (setup_uid_map(real_uid, real_gid) < 0)
    {
        return 1;
    }

    /* 9. Join shared namespaces (--net container:<PID>, --ipc container:<PID>).
     * Must happen after CLONE_NEWUSER so we have CAP_SYS_ADMIN in our user
     * namespace; must happen before unshare() so we don't create new
     * namespaces for the ones we are joining instead. */
    if (opts.net_join_pid > 0)
    {
        char ns_path[PATH_MAX];
        int n = snprintf(ns_path, sizeof(ns_path),
                         "/proc/%d/ns/net", (int)opts.net_join_pid);
        if (n < 0 || n >= (int)sizeof(ns_path))
        {
            fprintf(stderr, "oci2bin: net ns path truncated\n");
            return 1;
        }
        int fd = open(ns_path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
        {
            perror("oci2bin: open net namespace");
            return 1;
        }
        if (setns(fd, CLONE_NEWNET) < 0)
        {
            perror("oci2bin: setns(CLONE_NEWNET)");
            fprintf(stderr,
                    "oci2bin: joining another container's network namespace\n"
                    "oci2bin: requires the target to share the same user"
                    " namespace owner, or root privileges\n");
            close(fd);
            return 1;
        }
        close(fd);
    }

    if (opts.ipc_join_pid > 0)
    {
        char ns_path[PATH_MAX];
        int n = snprintf(ns_path, sizeof(ns_path),
                         "/proc/%d/ns/ipc", (int)opts.ipc_join_pid);
        if (n < 0 || n >= (int)sizeof(ns_path))
        {
            fprintf(stderr, "oci2bin: ipc ns path truncated\n");
            return 1;
        }
        int fd = open(ns_path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
        {
            perror("oci2bin: open ipc namespace");
            return 1;
        }
        if (setns(fd, CLONE_NEWIPC) < 0)
        {
            perror("oci2bin: setns(CLONE_NEWIPC)");
            fprintf(stderr,
                    "oci2bin: joining another container's IPC namespace\n"
                    "oci2bin: requires the target to share the same user"
                    " namespace owner, or root privileges\n");
            close(fd);
            return 1;
        }
        close(fd);
    }

    /* 10. Enter mount + PID + UTS namespaces; optionally network/cgroup ns.
     * When --net container:<PID> was used, setns() already joined the target
     * network namespace above — do not create a new one here. */
    {
        int ns_flags = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS;
        if (opts.net &&
                (strcmp(opts.net, "none") == 0 ||
                 strcmp(opts.net, "slirp") == 0 ||
                 strcmp(opts.net, "pasta") == 0))
        {
            ns_flags |= CLONE_NEWNET;
        }
        if (cg_did_setup)
        {
            ns_flags |= CLONE_NEWCGROUP;
        }
        if (unshare(ns_flags) < 0)
        {
            perror("unshare(NEWNS|NEWPID|NEWUTS)");
            return 1;
        }
    }

    /* 10b. For slirp/pasta modes: fork a net helper AFTER CLONE_NEWNET.
     * The net helper will exec slirp4netns or pasta, targeting our new
     * network namespace via /proc/<pid>/ns/net. */
    pid_t net_helper_pid = -1;
    if (opts.net &&
            (strcmp(opts.net, "slirp") == 0 || strcmp(opts.net, "pasta") == 0))
    {
        int sync_pipe[2];
        if (pipe(sync_pipe) < 0)
        {
            perror("oci2bin: slirp: pipe");
            return 1;
        }
        pid_t cur_pid = getpid();
        net_helper_pid = fork();
        if (net_helper_pid < 0)
        {
            perror("oci2bin: slirp: fork net helper");
            close(sync_pipe[0]);
            close(sync_pipe[1]);
            return 1;
        }
        if (net_helper_pid == 0)
        {
            /* Net helper child: wait for a byte on the pipe, then exec
             * slirp4netns/pasta targeting the container's net namespace */
            close(sync_pipe[1]);
            char ready;
            (void)read(sync_pipe[0], &ready, 1);
            close(sync_pipe[0]);

            char pid_str[16];
            int psn = snprintf(pid_str, sizeof(pid_str),
                               "%d", (int)cur_pid);
            if (psn < 0 || psn >= (int)sizeof(pid_str))
            {
                _exit(1);
            }

            if (strcmp(opts.net, "slirp") == 0)
            {
                /* Build argv for slirp4netns */
                const char* slirp_args[64];
                int ai = 0;
                slirp_args[ai++] = "slirp4netns";
                slirp_args[ai++] = "--configure";
                slirp_args[ai++] = "--mtu=65520";
                slirp_args[ai++] = "--disable-host-loopback";
                slirp_args[ai++] = "-6";
                /* Add port-forwards */
                char pf_bufs[16][32];
                for (int pi = 0; pi < opts.n_portfwd && ai + 2 < 60; pi++)
                {
                    int bn = snprintf(pf_bufs[pi], sizeof(pf_bufs[pi]),
                                      ":%s",
                                      opts.net_portfwd[pi]);
                    if (bn < 0 || bn >= (int)sizeof(pf_bufs[pi]))
                    {
                        continue;
                    }
                    slirp_args[ai++] = "-p";
                    slirp_args[ai++] = pf_bufs[pi];
                }
                slirp_args[ai++] = pid_str;
                slirp_args[ai++] = "tap0";
                slirp_args[ai]   = NULL;

                /* Try /usr/bin then /usr/local/bin */
                execvp("slirp4netns", (char* const*)slirp_args);
                /* If PATH lookup fails, try explicit paths */
                execv("/usr/bin/slirp4netns", (char* const*)slirp_args);
                execv("/usr/local/bin/slirp4netns",
                      (char* const*)slirp_args);
                fprintf(stderr, "oci2bin: slirp4netns not found in PATH,"
                                " /usr/bin, or /usr/local/bin\n");
                _exit(127);
            }
            else
            {
                /* pasta */
                char* pasta_args[] =
                {
                    "pasta",
                    "--config-net",
                    pid_str,
                    NULL
                };
                execvp("pasta", pasta_args);
                execv("/usr/bin/pasta", pasta_args);
                execv("/usr/local/bin/pasta", pasta_args);
                fprintf(stderr, "oci2bin: pasta not found in PATH,"
                                " /usr/bin, or /usr/local/bin\n");
                _exit(127);
            }
        }
        /* Parent: signal net helper that it can proceed */
        close(sync_pipe[0]);
        if (write(sync_pipe[1], "1", 1) < 0)
        {
            perror("oci2bin: slirp: write sync pipe");
        }
        close(sync_pipe[1]);
    }

    /* 11. Fork for PID namespace (child becomes PID 1) */
    pid_t child = fork();
    if (child < 0)
    {
        perror("fork");
        return 1;
    }

    if (child == 0)
    {
        _exit(container_main(rootfs, &opts));
    }

    /* Parent: wait for container to exit */
    int status;
    waitpid(child, &status, 0);
    /* Reap net helper if it was started */
    if (net_helper_pid > 0)
    {
        kill(net_helper_pid, SIGTERM);
        int helper_status;
        waitpid(net_helper_pid, &helper_status, 0);
    }

    /* Cleanup: remove the whole tmpdir without forking.
     * rootfs = tmpdir + "/rootfs"; strip the last component to get tmpdir.
     * Cannot use fork() here: after CLONE_NEWPID the child PID namespace is
     * destroyed when the container exits, so fork() returns ENOMEM. */
    char* last_slash = strrchr(rootfs, '/');
    if (last_slash)
    {
        *last_slash = '\0'; /* rootfs now points to tmpdir */
        rm_rf_dir(rootfs);
    }

    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
