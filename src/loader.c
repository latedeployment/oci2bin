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

/* Max layers we support */
#define MAX_LAYERS 128
#define BUF_SIZE   65536

/* ── tiny JSON helpers (just enough to parse manifest.json and config) ─── */

/* Find a JSON string value for a given key. Returns malloc'd string or NULL. */
static char *json_get_string(const char *json, const char *key)
{
    char needle[256];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p)
        return NULL;
    p += strlen(needle);
    while (*p == ' ' || *p == ':' || *p == '\t' || *p == '\n')
        p++;
    if (*p != '"')
        return NULL;
    p++; /* skip opening quote */
    const char *end = strchr(p, '"');
    if (!end)
        return NULL;
    size_t len = end - p;
    char *result = malloc(len + 1);
    memcpy(result, p, len);
    result[len] = '\0';
    return result;
}

/* Find a JSON array value for a given key. Returns malloc'd string (with []) or NULL. */
static char *json_get_array(const char *json, const char *key)
{
    char needle[256];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p)
        return NULL;
    p += strlen(needle);
    while (*p == ' ' || *p == ':' || *p == '\t' || *p == '\n')
        p++;
    if (*p != '[')
        return NULL;
    /* find matching ] */
    int depth = 0;
    const char *start = p;
    while (*p) {
        if (*p == '[') depth++;
        if (*p == ']') { depth--; if (depth == 0) break; }
        p++;
    }
    size_t len = p - start + 1;
    char *result = malloc(len + 1);
    memcpy(result, start, len);
    result[len] = '\0';
    return result;
}

/* Parse a JSON array of strings into an array. Returns count. */
static int json_parse_string_array(const char *arr, char **out, int max)
{
    int count = 0;
    const char *p = arr;
    while (*p && count < max) {
        p = strchr(p, '"');
        if (!p) break;
        p++; /* skip opening quote */
        const char *end = strchr(p, '"');
        if (!end) break;
        size_t len = end - p;
        out[count] = malloc(len + 1);
        memcpy(out[count], p, len);
        out[count][len] = '\0';
        count++;
        p = end + 1;
    }
    return count;
}

/* ── file helpers ────────────────────────────────────────────────────────── */

static char *read_file(const char *path, size_t *out_size)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return NULL; }
    char *buf = malloc(st.st_size + 1);
    if (!buf) { close(fd); return NULL; }
    ssize_t n = read(fd, buf, st.st_size);
    close(fd);
    if (n < 0) { free(buf); return NULL; }
    buf[n] = '\0';
    if (out_size) *out_size = n;
    return buf;
}

static int write_file(const char *path, const char *data, size_t len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    ssize_t written = write(fd, data, len);
    close(fd);
    return (written == (ssize_t)len) ? 0 : -1;
}

/* Write to /proc files (no O_CREAT, no O_TRUNC) */
static int write_proc(const char *path, const char *data, size_t len)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t written = write(fd, data, len);
    close(fd);
    return (written == (ssize_t)len) ? 0 : -1;
}

/* Run a command, wait for it. Returns exit status. */
static int run_cmd(char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }
    if (pid == 0) {
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
static char *extract_oci_rootfs(const char *self_path)
{
    static char rootfs[PATH_MAX];
    char tmpdir[] = "/tmp/oci2bin.XXXXXX";

    if (!mkdtemp(tmpdir)) {
        perror("mkdtemp");
        return NULL;
    }

    /* 1. Extract the embedded OCI tar from ourselves */
    char oci_tar_path[PATH_MAX];
    snprintf(oci_tar_path, sizeof(oci_tar_path), "%s/image.tar", tmpdir);

    int self_fd = open(self_path, O_RDONLY);
    if (self_fd < 0) { perror("open self"); return NULL; }

    if (lseek(self_fd, OCI_DATA_OFFSET, SEEK_SET) < 0) {
        perror("lseek");
        close(self_fd);
        return NULL;
    }

    int out_fd = open(oci_tar_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) { perror("open oci tar"); close(self_fd); return NULL; }

    unsigned long remaining = OCI_DATA_SIZE;
    char buf[BUF_SIZE];
    while (remaining > 0) {
        size_t to_read = remaining < BUF_SIZE ? remaining : BUF_SIZE;
        ssize_t n = read(self_fd, buf, to_read);
        if (n <= 0) break;
        write(out_fd, buf, n);
        remaining -= n;
    }
    close(self_fd);
    close(out_fd);

    /* 2. Extract the OCI tar into tmpdir/oci/ */
    char oci_dir[PATH_MAX];
    snprintf(oci_dir, sizeof(oci_dir), "%s/oci", tmpdir);
    mkdir(oci_dir, 0755);

    char *tar_argv[] = {"tar", "xf", oci_tar_path, "-C", oci_dir, NULL};
    if (run_cmd(tar_argv) != 0) {
        fprintf(stderr, "oci2bin: failed to extract OCI tar\n");
        return NULL;
    }

    /* 3. Read manifest.json */
    char manifest_path[PATH_MAX];
    snprintf(manifest_path, sizeof(manifest_path), "%s/manifest.json", oci_dir);
    size_t manifest_size;
    char *manifest = read_file(manifest_path, &manifest_size);
    if (!manifest) {
        fprintf(stderr, "oci2bin: cannot read manifest.json\n");
        return NULL;
    }

    /* 4. Parse manifest to get Config and Layers */
    char *config_path_rel = json_get_string(manifest, "Config");
    char *layers_json = json_get_array(manifest, "Layers");
    if (!config_path_rel || !layers_json) {
        fprintf(stderr, "oci2bin: cannot parse manifest.json\n");
        free(manifest);
        return NULL;
    }

    /* 5. Extract layers in order into rootfs */
    snprintf(rootfs, sizeof(rootfs), "%s/rootfs", tmpdir);
    mkdir(rootfs, 0755);

    char *layers[MAX_LAYERS];
    int nlayers = json_parse_string_array(layers_json, layers, MAX_LAYERS);

    for (int i = 0; i < nlayers; i++) {
        char layer_path[PATH_MAX];
        snprintf(layer_path, sizeof(layer_path), "%s/%s", oci_dir, layers[i]);

        char *layer_argv[] = {"tar", "xf", layer_path, "-C", rootfs, NULL};
        if (run_cmd(layer_argv) != 0) {
            fprintf(stderr, "oci2bin: failed to extract layer %s\n", layers[i]);
        }
        free(layers[i]);
    }

    /* 6. Read the image config to get Cmd/Entrypoint */
    char config_full_path[PATH_MAX];
    snprintf(config_full_path, sizeof(config_full_path), "%s/%s", oci_dir, config_path_rel);
    size_t config_size;
    char *config = read_file(config_full_path, &config_size);
    if (config) {
        /* Write parsed entrypoint info for later use */
        char *cmd = json_get_array(config, "Cmd");
        char *entrypoint = json_get_array(config, "Entrypoint");

        char info_path[PATH_MAX];
        snprintf(info_path, sizeof(info_path), "%s/.oci2bin_config", rootfs);
        char info_buf[4096] = {0};
        snprintf(info_buf, sizeof(info_buf),
                 "{\"Cmd\":%s,\"Entrypoint\":%s}",
                 cmd ? cmd : "null",
                 entrypoint ? entrypoint : "null");
        write_file(info_path, info_buf, strlen(info_buf));

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
    if (write_proc("/proc/self/setgroups", "deny", 4) < 0) {
        /* May fail on older kernels, non-fatal */
    }

    snprintf(map, sizeof(map), "0 %d 1\n", real_uid);
    if (write_proc("/proc/self/uid_map", map, strlen(map)) < 0) {
        perror("write uid_map");
        return -1;
    }

    snprintf(map, sizeof(map), "0 %d 1\n", real_gid);
    if (write_proc("/proc/self/gid_map", map, strlen(map)) < 0) {
        perror("write gid_map");
        return -1;
    }

    return 0;
}

/*
 * Patch the extracted rootfs so that tools which try to drop privileges
 * (e.g. apt's _apt sandbox) succeed inside a single-UID user namespace.
 *
 * The kernel only lets an unprivileged process map one UID/GID without
 * newuidmap, so we remap every non-root entry in /etc/passwd and /etc/group
 * to UID/GID 0.  That way seteuid(42) becomes seteuid(0) — a no-op — and
 * setegid/setgroups calls likewise succeed.
 *
 * For apt specifically we also drop an apt.conf snippet that disables its
 * privilege sandbox entirely, so it never calls seteuid in the first place.
 */
static void patch_rootfs_ids(const char *rootfs)
{
    /* ── /etc/passwd ── remap all uid:gid fields to 0:0 ── */
    char passwd_path[PATH_MAX];
    snprintf(passwd_path, sizeof(passwd_path), "%s/etc/passwd", rootfs);
    size_t passwd_sz;
    char *passwd = read_file(passwd_path, &passwd_sz);
    if (passwd) {
        /* Format: name:pw:uid:gid:gecos:home:shell  (7 colon-separated fields) */
        FILE *out = fopen(passwd_path, "w");
        if (out) {
            char *line = passwd;
            while (*line) {
                char *nl = strchr(line, '\n');
                size_t line_len = nl ? (size_t)(nl - line + 1) : strlen(line);
                char linebuf[4096];
                if (line_len >= sizeof(linebuf)) { line += line_len; continue; }
                memcpy(linebuf, line, line_len);
                linebuf[line_len] = '\0';

                /* Split on ':' to reach uid (field 3) and gid (field 4) */
                char *f[7]; int nf = 0;
                char *p = linebuf;
                while (nf < 7) {
                    f[nf++] = p;
                    p = strchr(p, ':');
                    if (!p) break;
                    *p++ = '\0';
                }
                if (nf == 7) {
                    unsigned long uid = strtoul(f[2], NULL, 10);
                    unsigned long gid = strtoul(f[3], NULL, 10);
                    /* Leave root (0) and nobody (65534) alone; remap everything else */
                    if (uid != 0 && uid != 65534) snprintf(f[2], 8, "0");
                    if (gid != 0 && gid != 65534) snprintf(f[3], 8, "0");
                    fprintf(out, "%s:%s:%s:%s:%s:%s:%s\n",
                            f[0], f[1], f[2], f[3], f[4], f[5], f[6]);
                } else {
                    /* Malformed line: pass through unchanged */
                    fwrite(line, 1, line_len, out);
                    if (!nl) fputc('\n', out);
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
    char *grp = read_file(group_path, &group_sz);
    if (grp) {
        /* Format: name:pw:gid:members */
        FILE *out = fopen(group_path, "w");
        if (out) {
            char *line = grp;
            while (*line) {
                char *nl = strchr(line, '\n');
                size_t line_len = nl ? (size_t)(nl - line + 1) : strlen(line);
                char linebuf[4096];
                if (line_len >= sizeof(linebuf)) { line += line_len; continue; }
                memcpy(linebuf, line, line_len);
                linebuf[line_len] = '\0';

                char *f[4]; int nf = 0;
                char *p = linebuf;
                while (nf < 4) {
                    f[nf++] = p;
                    p = strchr(p, ':');
                    if (!p) break;
                    *p++ = '\0';
                }
                if (nf == 4) {
                    unsigned long gid = strtoul(f[2], NULL, 10);
                    if (gid != 0 && gid != 65534) snprintf(f[2], 8, "0");
                    fprintf(out, "%s:%s:%s:%s\n", f[0], f[1], f[2], f[3]);
                } else {
                    fwrite(line, 1, line_len, out);
                    if (!nl) fputc('\n', out);
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
    if (stat(apt_conf_dir, &st) == 0 && S_ISDIR(st.st_mode)) {
        char apt_conf[PATH_MAX];
        snprintf(apt_conf, sizeof(apt_conf), "%s/99oci2bin", apt_conf_dir);
        const char *conf = "APT::Sandbox::User \"root\";\n";
        write_file(apt_conf, conf, strlen(conf));
    }

    /*
     * ── /etc/resolv.conf ──
     * The container shares the host network namespace (no CLONE_NEWNET), so
     * the host's resolver is reachable.  But the rootfs /etc/resolv.conf is
     * often a dangling symlink (e.g. Ubuntu points it at
     * /run/systemd/resolve/stub-resolv.conf which doesn't exist in the chroot).
     * Replace it with the host's actual file content.
     */
    {
        size_t resolv_sz;
        char *resolv = read_file("/etc/resolv.conf", &resolv_sz);
        if (resolv) {
            char resolv_path[PATH_MAX];
            snprintf(resolv_path, sizeof(resolv_path), "%s/etc/resolv.conf", rootfs);
            unlink(resolv_path);   /* remove symlink if present */
            write_file(resolv_path, resolv, resolv_sz);
            free(resolv);
        }
    }
}

static int container_main(const char *rootfs)
{
    /* Read entrypoint/cmd config */
    char config_path[PATH_MAX];
    snprintf(config_path, sizeof(config_path), "%s/.oci2bin_config", rootfs);
    char *config = read_file(config_path, NULL);

    /* Default entrypoint */
    char *exec_args[64] = {"/bin/sh", NULL};
    int exec_argc = 1;

    if (config) {
        /* Try Entrypoint first, then Cmd */
        char *entrypoint = json_get_array(config, "Entrypoint");
        char *cmd = json_get_array(config, "Cmd");

        char *to_parse = entrypoint;
        if (!to_parse || strcmp(to_parse, "null") == 0) {
            to_parse = cmd;
        }

        if (to_parse && strcmp(to_parse, "null") != 0) {
            exec_argc = json_parse_string_array(to_parse, exec_args, 63);
            exec_args[exec_argc] = NULL;
        }

        free(entrypoint);
        free(cmd);
        free(config);
    }

    /* Remove our temp config file */
    unlink(config_path);

    /* Chroot into rootfs */
    if (chroot(rootfs) < 0) {
        perror("chroot");
        return 1;
    }
    chdir("/");

    /* Mount /proc */
    mkdir("/proc", 0555);
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) < 0) {
        /* Non-fatal: some environments block this */
        perror("mount /proc (non-fatal)");
    }

    /* Mount /dev/null etc. minimally */
    mkdir("/dev", 0755);

    /* Set hostname */
    sethostname("oci2bin", 10);

    /* Set PATH (containers expect this) */
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
    setenv("HOME", "/root", 1);
    setenv("TERM", "xterm", 1);

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

/* ── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    /* 1. Find ourselves */
    char self_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (len < 0) {
        perror("readlink /proc/self/exe");
        return 1;
    }
    self_path[len] = '\0';

    fprintf(stderr, "oci2bin: self=%s offset=0x%lx size=0x%lx\n",
            self_path, OCI_DATA_OFFSET, OCI_DATA_SIZE);

    /* 2. Sanity check the markers */
    if (OCI_PATCHED != 1) {
        fprintf(stderr,
                "oci2bin: OCI data markers not patched!\n"
                "This binary must be built with the polyglot builder.\n");
        return 1;
    }

    /* 3. Extract OCI image into rootfs */
    char *rootfs = extract_oci_rootfs(self_path);
    if (!rootfs) {
        fprintf(stderr, "oci2bin: failed to extract OCI rootfs\n");
        return 1;
    }

    fprintf(stderr, "oci2bin: rootfs at %s\n", rootfs);

    /* 4. Patch rootfs so privilege-dropping tools work in a single-UID namespace */
    patch_rootfs_ids(rootfs);

    /* 5. Capture real UID/GID before entering user namespace */
    uid_t real_uid = getuid();
    gid_t real_gid = getgid();

    /* 6. Enter user namespace first (needed before we can map UIDs) */
    if (unshare(CLONE_NEWUSER) < 0) {
        perror("unshare(CLONE_NEWUSER)");
        fprintf(stderr, "oci2bin: user namespaces may be disabled on this kernel\n");
        return 1;
    }

    /* 7. Map UID/GID (must happen right after CLONE_NEWUSER, before other namespaces) */
    if (setup_uid_map(real_uid, real_gid) < 0) {
        return 1;
    }

    /* 8. Now enter the remaining namespaces (we have CAP_SYS_ADMIN in our user ns) */
    if (unshare(CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS) < 0) {
        perror("unshare(NEWNS|NEWPID|NEWUTS)");
        return 1;
    }

    /* 9. Fork for PID namespace (child becomes PID 1) */
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        /* Child: PID 1 in the new PID namespace */
        _exit(container_main(rootfs));
    }

    /* Parent: wait for container to exit */
    int status;
    waitpid(child, &status, 0);

    /* Cleanup: best effort */
    char rm_cmd[PATH_MAX + 16];
    snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf %s", rootfs);
    /* rootfs is inside /tmp/oci2bin.XXXXXX, go up one level */
    char *last_slash = strrchr(rootfs, '/');
    if (last_slash) {
        *last_slash = '\0';
        snprintf(rm_cmd, sizeof(rm_cmd), "rm -rf %s", rootfs);
    }
    system(rm_cmd);

    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
