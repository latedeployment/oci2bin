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

    /* --net host|none  (NULL means host; "none" adds CLONE_NEWNET) */
    char* net;

    /* --read-only  (mount overlay so rootfs is not modified) */
    int read_only;

    /* --ssh-agent  (forward host SSH_AUTH_SOCK into the container) */
    int ssh_agent;

    /* --no-seccomp  (disable the default seccomp filter) */
    int no_seccomp;

    /* --hostname NAME  (override the UTS hostname) */
    char* hostname;

    /* --user UID[:GID]  (run as this uid/gid inside the container) */
    uid_t run_uid;
    gid_t run_gid;
    int   has_user;   /* 1 if --user was given */

    /* -e KEY=VALUE  (additional environment variables, up to MAX_ENV) */
    char* env_vars[MAX_ENV];
    int   n_env;

    /* extra args after flags (overrides OCI Cmd) */
    char** extra_args;
    int    n_extra;
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

    /* --read-only: mount overlayfs so the rootfs is not modified at runtime.
     * upper/work dirs live in the tmpdir (parent of rootfs). */
    if (opts->read_only)
    {
        /* Derive tmpdir by stripping trailing "/rootfs" suffix */
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
                /* Fallback: rootfs path has unexpected structure; use parent */
                tlen = snprintf(tmpdir, sizeof(tmpdir), "%s/..", rootfs);
                if (tlen > 0 && (size_t)tlen < sizeof(tmpdir))
                {
                    tmpdir_ok = 1;
                }
            }
        }
        if (tmpdir_ok)
        {
            char upper[PATH_MAX];
            char work[PATH_MAX];
            int ulen = snprintf(upper, sizeof(upper), "%s/upper", tmpdir);
            int wlen = snprintf(work,  sizeof(work),  "%s/work",  tmpdir);
            if (ulen > 0 && (size_t)ulen < sizeof(upper) &&
                    wlen > 0 && (size_t)wlen < sizeof(work))
            {
                mkdir(upper, 0755);
                mkdir(work,  0755);
                char overlay_opts[PATH_MAX * 4];
                int olen = snprintf(overlay_opts, sizeof(overlay_opts),
                                    "lowerdir=%s,upperdir=%s,workdir=%s",
                                    rootfs, upper, work);
                if (olen > 0 && (size_t)olen < sizeof(overlay_opts))
                {
                    if (mount("overlay", rootfs, "overlay", 0, overlay_opts) < 0)
                    {
                        fprintf(stderr,
                                "oci2bin: overlayfs unavailable, running read-write\n");
                    }
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

    /* Mount /dev and create essential device nodes via mknod.
     * We cannot bind-mount host /dev in a rootless user namespace,
     * so we create the nodes manually after entering the namespace. */
    mkdir("/dev", 0755);
    if (mount("tmpfs", "/dev", "tmpfs",
              MS_NOSUID | MS_NOEXEC, "mode=0755") < 0)
    {
        perror("mount /dev tmpfs (non-fatal)");
    }
    else
    {
        /* c 1 3 */ if (mknod("/dev/null",    S_IFCHR | 0666, makedev(1, 3)) < 0)
        {
            perror("mknod /dev/null (non-fatal)");
        }
        /* c 1 5 */ if (mknod("/dev/zero",    S_IFCHR | 0666, makedev(1, 5)) < 0)
        {
            perror("mknod /dev/zero (non-fatal)");
        }
        /* c 1 8 */ if (mknod("/dev/random",  S_IFCHR | 0666, makedev(1, 8)) < 0)
        {
            perror("mknod /dev/random (non-fatal)");
        }
        /* c 1 9 */ if (mknod("/dev/urandom", S_IFCHR | 0666, makedev(1, 9)) < 0)
        {
            perror("mknod /dev/urandom (non-fatal)");
        }
        /* c 5 0 */ if (mknod("/dev/tty",     S_IFCHR | 0620, makedev(5, 0)) < 0)
        {
            perror("mknod /dev/tty (non-fatal)");
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

    /* Apply seccomp filter just before exec (all setup is complete) */
    if (!opts->no_seccomp)
    {
        apply_seccomp_filter();
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
            "                      (may be repeated; overrides built-in defaults)\n"
            "  --entrypoint PATH   Override the image entrypoint\n"
            "  --workdir PATH      Set the working directory inside the container\n"
            "  --net host|none     Network mode: host (default) or none (isolated)\n"
            "  --read-only         Mount rootfs read-only via overlayfs\n"
            "  --ssh-agent         Forward host SSH_AUTH_SOCK into the container\n"
            "  --no-seccomp        Disable the default seccomp syscall filter\n"
            "  --user UID[:GID]    Run as this numeric UID (and optional GID)\n"
            "  --hostname NAME     Set the hostname inside the container\n"
            "  --env-file FILE     Load KEY=VALUE pairs from FILE\n"
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

static int parse_opts(int argc, char* argv[], struct container_opts *opts)
{
    memset(opts, 0, sizeof(*opts));
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
        else if (strcmp(argv[i], "-e") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "oci2bin: -e requires KEY=VALUE argument\n");
                return -1;
            }
            i++;
            if (!strchr(argv[i], '=') || argv[i][0] == '=')
            {
                fprintf(stderr, "oci2bin: -e argument must be KEY=VALUE\n");
                return -1;
            }
            if (opts->n_env >= MAX_ENV)
            {
                fprintf(stderr, "oci2bin: too many -e flags (max %d)\n", MAX_ENV);
                return -1;
            }
            opts->env_vars[opts->n_env++] = argv[i];
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
                fprintf(stderr, "oci2bin: --net requires host or none\n");
                return -1;
            }
            i++;
            if (strcmp(argv[i], "host") != 0 && strcmp(argv[i], "none") != 0)
            {
                fprintf(stderr, "oci2bin: --net must be host or none\n");
                return -1;
            }
            opts->net = argv[i];
        }
        else if (strcmp(argv[i], "--read-only") == 0)
        {
            opts->read_only = 1;
        }
        else if (strcmp(argv[i], "--ssh-agent") == 0)
        {
            opts->ssh_agent = 1;
        }
        else if (strcmp(argv[i], "--no-seccomp") == 0)
        {
            opts->no_seccomp = 1;
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

/* ── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char* argv[])
{
    /* 1. Find ourselves */
    char self_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (len < 0)
    {
        perror("readlink /proc/self/exe");
        return 1;
    }
    self_path[len] = '\0';

    /* 2. Parse command-line options */
    struct container_opts opts;
    if (parse_opts(argc, argv, &opts) < 0)
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

    /* 4. Extract OCI image into rootfs */
    char* rootfs = extract_oci_rootfs(self_path);
    if (!rootfs)
    {
        fprintf(stderr, "oci2bin: failed to extract OCI rootfs\n");
        return 1;
    }

    fprintf(stderr, "oci2bin: rootfs at %s\n", rootfs);

    /* 5. Patch rootfs so privilege-dropping tools work in a single-UID namespace */
    patch_rootfs_ids(rootfs);

    /* 6. Capture real UID/GID before entering user namespace */
    uid_t real_uid = getuid();
    gid_t real_gid = getgid();

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

    /* 9. Enter mount + PID + UTS namespaces; optionally network namespace */
    {
        int ns_flags = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS;
        if (opts.net && strcmp(opts.net, "none") == 0)
        {
            ns_flags |= CLONE_NEWNET;
        }
        if (unshare(ns_flags) < 0)
        {
            perror("unshare(NEWNS|NEWPID|NEWUTS)");
            return 1;
        }
    }

    /* 10. Fork for PID namespace (child becomes PID 1) */
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
