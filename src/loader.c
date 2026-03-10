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
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * These markers get patched by the polyglot builder.
 * They mark the offset and size of the OCI tar data within this binary.
 * The PATCHED flag is set to 1 by the builder to indicate successful patching.
 */
static volatile unsigned long OCI_DATA_OFFSET = 0xDEADBEEFCAFEBABEUL;
static volatile unsigned long OCI_DATA_SIZE   = 0xCAFEBABEDEADBEEFUL;
static volatile unsigned long OCI_PATCHED     = 0xAAAAAAAAAAAAAAAAUL;

/* Max layers / volumes / exec args we support */
#define MAX_LAYERS  128
#define MAX_VOLUMES  32
#define MAX_ARGS     64
#define MAX_ENV      64
#define BUF_SIZE   65536

/* ── runtime options parsed from argv ───────────────────────────────────── */

struct container_opts
{
    /* -v host:container  (up to MAX_VOLUMES pairs) */
    char* vol_host[MAX_VOLUMES];
    char* vol_ctr[MAX_VOLUMES];
    int   n_vols;

    /* --entrypoint /path  (overrides OCI Entrypoint) */
    char* entrypoint;

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
        /* Write parsed entrypoint info for later use */
        char* cmd = json_get_array(config, "Cmd");
        char* entrypoint = json_get_array(config, "Entrypoint");

        char info_path[PATH_MAX];
        if (snprintf(info_path, sizeof(info_path), "%s/.oci2bin_config", rootfs)
                < (int)sizeof(info_path))
        {
            char info_buf[4096] = {0};
            snprintf(info_buf, sizeof(info_buf),
                     "{\"Cmd\":%s,\"Entrypoint\":%s}",
                     cmd ? cmd : "null",
                     entrypoint ? entrypoint : "null");
            write_file(info_path, info_buf, strlen(info_buf));
        }

        free(cmd);
        free(entrypoint);
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

    /* Mount /dev minimally */
    mkdir("/dev", 0755);

    /* Set hostname */
    sethostname("oci2bin", 7);

    /* Set standard env */
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
           1);
    setenv("HOME", "/root", 1);
    setenv("TERM", "xterm", 1);

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

    /* Exec the entrypoint */
    fprintf(stderr, "oci2bin: exec %s\n", exec_args[0]);
    execv(exec_args[0], exec_args);

    /* If exec failed, try /bin/sh as fallback */
    perror("execv");
    fprintf(stderr, "oci2bin: falling back to /bin/sh\n");
    execlp("/bin/sh", "sh", NULL);
    perror("execlp /bin/sh");
    return 1;
}

/* ── argument parsing ────────────────────────────────────────────────────── */

static void usage(const char* prog)
{
    fprintf(stderr,
            "Usage: %s [OPTIONS] [-- CMD [ARGS...]]\n"
            "       %s [OPTIONS] CMD [ARGS...]\n"
            "\n"
            "Options:\n"
            "  -v HOST:CONTAINER   Bind mount a host path into the container\n"
            "                      (may be repeated)\n"
            "  -e KEY=VALUE        Set an environment variable inside the container\n"
            "                      (may be repeated; overrides built-in defaults)\n"
            "  --entrypoint PATH   Override the image entrypoint\n"
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

    /* 9. Enter mount + PID + UTS namespaces */
    if (unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS) < 0)
    {
        perror("unshare(NEWNS|NEWPID|NEWUTS)");
        return 1;
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

    /* Cleanup: best effort — remove the whole tmpdir.
     * rootfs = tmpdir + "/rootfs"; strip the last component to get tmpdir.
     * Use execvp directly (no shell) to avoid any injection risk. */
    char* last_slash = strrchr(rootfs, '/');
    if (last_slash)
    {
        *last_slash = '\0'; /* rootfs now points to tmpdir */
        char* rm_argv[] = {"rm", "-rf", rootfs, NULL};
        run_cmd(rm_argv);
    }

    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
