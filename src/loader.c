#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <ftw.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <termios.h>
#include <grp.h>
#include <sys/resource.h>
#include <unistd.h>
#include <linux/audit.h>
#ifdef __NR_userfaultfd
#include <linux/userfaultfd.h>
#endif
#include <linux/elf.h>
#include <linux/filter.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <ctype.h>
#include <time.h>
#ifdef __aarch64__
#include <asm/ptrace.h>
#endif

/*
 * Newer kernels can support these syscalls even when the build headers are
 * older.  Define the numbers we need on the two supported arches so runtime
 * probing can decide feature availability instead of the preprocessor alone.
 */
#ifndef __NR_clone3
#if defined(__x86_64__) || defined(__aarch64__)
#define __NR_clone3 435
#endif
#endif

#ifndef __NR_openat2
#if defined(__x86_64__) || defined(__aarch64__)
#define __NR_openat2 437
#endif
#endif

#ifndef __NR_faccessat2
#if defined(__x86_64__) || defined(__aarch64__)
#define __NR_faccessat2 439
#endif
#endif

#ifndef __NR_mseal
#if defined(__x86_64__) || defined(__aarch64__)
#define __NR_mseal 462
#endif
#endif

#ifndef __NR_memfd_secret
#if defined(__x86_64__) || defined(__aarch64__)
#define __NR_memfd_secret 447
#endif
#endif

/* Maximum bytes buffered by run_cmd_capture() before aborting. */
#define RUN_CMD_CAPTURE_MAX (64u * 1024u * 1024u)

#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif

#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif

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
#define USERNS_REMAP_CONTAINER_IDS 65535UL
#ifndef CAP_SETGID
#define CAP_SETGID 6
#endif
#ifndef CAP_SETUID
#define CAP_SETUID 7
#endif

/* VM defaults — overridable at build time via -DDEFAULT_VM_CPUS=N etc. */
#ifndef DEFAULT_VM_CPUS
#define DEFAULT_VM_CPUS   1
#endif
#ifndef DEFAULT_VM_MEM_MB
#define DEFAULT_VM_MEM_MB 256
#endif

/* Debug logging toggle (set by --debug). */
static int g_debug = 0;

/* Audit log fd: -1 = disabled, STDERR_FILENO = --audit-log -, else a file fd */
static int g_audit_fd = -1;

enum kernel_feature_id
{
    KERNEL_FEATURE_CLONE3 = 0,
    KERNEL_FEATURE_MSEAL,
    KERNEL_FEATURE_UFFD,
    KERNEL_FEATURE_MAX,
};

enum kernel_feature_state
{
    KERNEL_FEATURE_UNKNOWN = 0,
    KERNEL_FEATURE_UNSUPPORTED = -1,
    KERNEL_FEATURE_SUPPORTED = 1,
};

static signed char g_kernel_feature_state[KERNEL_FEATURE_MAX];

static int write_all_fd(int fd, const char* data, size_t len);
static int json_escape_string(const char* src, char* dst, size_t dstsz);
static unsigned long long current_effective_caps(void);

static int kernel_feature_state_from_syscall(long rc, int err)
{
    if (rc >= 0 || err != ENOSYS)
    {
        return KERNEL_FEATURE_SUPPORTED;
    }
    return KERNEL_FEATURE_UNSUPPORTED;
}

static void kernel_set_feature_state(enum kernel_feature_id feature, int state)
{
    if (feature >= 0 && feature < KERNEL_FEATURE_MAX)
    {
        g_kernel_feature_state[feature] = (signed char)state;
    }
}

static int probe_clone3_support(void)
{
#ifdef __NR_clone3
    errno = 0;
    return kernel_feature_state_from_syscall(
               syscall(__NR_clone3, NULL, 0UL), errno) ==
           KERNEL_FEATURE_SUPPORTED;
#else
    return 0;
#endif
}

static int probe_mseal_support(void)
{
#ifdef __NR_mseal
    errno = 0;
    return kernel_feature_state_from_syscall(
               syscall(__NR_mseal, NULL, 0UL, 0UL), errno) ==
           KERNEL_FEATURE_SUPPORTED;
#else
    return 0;
#endif
}

/*
 * Probe userfaultfd availability by opening an fd and performing UFFD_API
 * negotiation.  Returns 1 if the kernel supports userfaultfd with the
 * expected API version, 0 otherwise.
 */
static int probe_uffd_support(void)
{
#ifdef __NR_userfaultfd
    int fd = (int)syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (fd < 0)
    {
        return 0;
    }
    struct uffdio_api api;
    api.api      = UFFD_API;
    api.features = 0;
    api.ioctls   = 0;
    int ok = (ioctl(fd, UFFDIO_API, &api) == 0 && api.api == UFFD_API);
    close(fd);
    return ok;
#else
    return 0;
#endif
}

static int kernel_feature_supported(enum kernel_feature_id feature)
{
    int state;

    if (feature < 0 || feature >= KERNEL_FEATURE_MAX)
    {
        return 0;
    }

    state = g_kernel_feature_state[feature];
    if (state == KERNEL_FEATURE_UNKNOWN)
    {
        switch (feature)
        {
            case KERNEL_FEATURE_CLONE3:
                state = probe_clone3_support() ?
                        KERNEL_FEATURE_SUPPORTED :
                        KERNEL_FEATURE_UNSUPPORTED;
                break;
            case KERNEL_FEATURE_MSEAL:
                state = probe_mseal_support() ?
                        KERNEL_FEATURE_SUPPORTED :
                        KERNEL_FEATURE_UNSUPPORTED;
                break;
            case KERNEL_FEATURE_UFFD:
                state = probe_uffd_support() ?
                        KERNEL_FEATURE_SUPPORTED :
                        KERNEL_FEATURE_UNSUPPORTED;
                break;
            default:
                state = KERNEL_FEATURE_UNSUPPORTED;
                break;
        }
        kernel_set_feature_state(feature, state);
    }

    return state == KERNEL_FEATURE_SUPPORTED;
}

static int kernel_supports_clone3(void)
{
    return kernel_feature_supported(KERNEL_FEATURE_CLONE3);
}

static int kernel_supports_mseal(void)
{
    return kernel_feature_supported(KERNEL_FEATURE_MSEAL);
}

static int kernel_supports_uffd(void)
{
    return kernel_feature_supported(KERNEL_FEATURE_UFFD);
}

/*
 * Emit one JSON audit event line to g_audit_fd.
 * Format: {"event":"<ev>","time":"<ISO8601>","pid":<n>,<extra>}
 * extra is a pre-formatted JSON fragment (without leading comma) or "".
 * Thread-unsafe but the loader is single-threaded before exec.
 */
static void audit_escape_string(const char* src, char* dst, size_t dstsz)
{
    if (!src)
    {
        src = "";
    }
    if (json_escape_string(src, dst, dstsz) < 0 && dstsz > 0)
    {
        snprintf(dst, dstsz, "<truncated>");
    }
}

static void audit_emit_pid(const char* event, pid_t pid, const char* extra)
{
    if (g_audit_fd < 0)
    {
        return;
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    /* ISO8601 UTC: "2006-01-02T15:04:05Z" */
    time_t t = ts.tv_sec;
    struct tm tm_buf;
    gmtime_r(&t, &tm_buf);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);

    char line[1024];
    int n;
    if (extra && extra[0])
    {
        n = snprintf(line, sizeof(line),
                     "{\"event\":\"%s\",\"time\":\"%s\",\"pid\":%d,%s}\n",
                     event, timebuf, (int)pid, extra);
    }
    else
    {
        n = snprintf(line, sizeof(line),
                     "{\"event\":\"%s\",\"time\":\"%s\",\"pid\":%d}\n",
                     event, timebuf, (int)pid);
    }
    if (n > 0 && n < (int)sizeof(line))
    {
        write_all_fd(g_audit_fd, line, (size_t)n);
    }
}

static void audit_emit(const char* event, const char* extra)
{
    audit_emit_pid(event, getpid(), extra);
}

static void audit_emit_wait_status(const char* event, pid_t pid, int status)
{
    char extra[96];

    if (WIFEXITED(status))
    {
        snprintf(extra, sizeof(extra), "\"exit_code\":%d",
                 WEXITSTATUS(status));
    }
    else if (WIFSIGNALED(status))
    {
        snprintf(extra, sizeof(extra), "\"signal\":%d",
                 WTERMSIG(status));
    }
    else
    {
        snprintf(extra, sizeof(extra), "\"status_raw\":%d", status);
    }
    audit_emit_pid(event, pid, extra);
}

static const char* safe_str(const char* s)
{
    return s ? s : "(null)";
}

__attribute__((format(printf, 2, 3)))
static void debug_log(const char* event, const char* fmt, ...)
{
    if (!g_debug)
    {
        return;
    }
    fprintf(stderr, "oci2bin[debug] pid=%d event=%s", (int)getpid(),
            safe_str(event));
    if (fmt && fmt[0] != '\0')
    {
        fputc(' ', stderr);
        va_list ap;
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
    }
    fputc('\n', stderr);
}

/* ── runtime options parsed from argv ───────────────────────────────────── */

struct container_opts
{
    /* -v host:container  (up to MAX_VOLUMES pairs) */
    char* vol_host[MAX_VOLUMES];
    char* vol_ctr[MAX_VOLUMES];
    int   n_vols;

    /* --secret HOST_FILE[:CONTAINER_PATH]  (read-only file mounts)
     * --secret tpm2:CRED_NAME[:CONTAINER_PATH]  (TPM2-sealed via systemd-creds) */
    char* secret_host[MAX_SECRETS]; /* host path OR NULL for tpm2 secrets */
    char* secret_ctr[MAX_SECRETS];  /* NULL → /run/secrets/<basename> */
    char* secret_cred[MAX_SECRETS]; /* NULL = plain file; non-NULL = tpm2 cred name */
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

    /* --seccomp-profile FILE  (load Docker-compatible JSON seccomp policy) */
    char* seccomp_profile;

    /* --add-host HOST:IP  (inject into /etc/hosts) */
    char* add_hosts[32];
    int   n_add_hosts;

    /* --dns IP  (custom DNS server, up to 8) */
    char* dns_servers[8];
    int   n_dns_servers;

    /* --dns-search DOMAIN  (DNS search domains, up to 8) */
    char* dns_search[8];
    int   n_dns_search;

    /* --no-auto-tmpfs  (skip auto /run tmpfs when --read-only) */
    int no_auto_tmpfs;

    /* --security-opt apparmor=PROFILE | label=TYPE:VAL */
    char* security_opt_apparmor; /* NULL = no AppArmor profile */
    char* security_opt_label;    /* NULL = no SELinux label */

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

    /* --name NAME  (container name for lifecycle management) */
    char* name;

    /* --verify-key PATH  (verify binary signature before execution) */
    char* verify_key;

    /* --self-update / --check-update (signed manifest flow before extraction) */
    int self_update;
    int check_update;

    /* --debug (print verbose runtime diagnostics for troubleshooting) */
    int debug;

    /* --memory MEM, --cpus FLOAT, --pids-limit N  (cgroup v2 limits) */
    long long cg_memory_bytes; /* 0 = unset */
    long      cg_cpu_quota;    /* 0 = unset; cpu.max quota in 100000 period */
    double    vm_cpus;         /* 0 = unset; raw --cpus value for VM backends */
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

    /* PTY relay: set by run_container() before fork, used by container_main() */
    int pty_master_fd; /* -1 if no PTY; parent closes slave, uses this for relay */
    int pty_slave_fd;  /* -1 if no PTY; child sets as controlling terminal */

    /* -t / --tty: explicitly allocate a pseudo-terminal */
    int allocate_tty;
    /* -i / --interactive: keep stdin open even if not a TTY */
    int interactive;

    /* --gen-seccomp FILE  (trace syscalls and emit a Docker-compatible profile) */
    char* gen_seccomp;

    /* --gdb  (bind-mount host gdb into container and exec it as debugger) */
    int gdb;

    /* --clock-offset SECS  (shift monotonic+boottime clocks, Linux 5.6+) */
    long clock_offset_secs;
    int  has_clock_offset;

    /* --audit-log FILE  (structured JSON audit log; "-" = stderr) */
    char* audit_log;

    /* --metrics-socket PATH  (Prometheus text over Unix socket) */
    char* metrics_socket;

    /* --no-userns-remap  (force single-ID user namespace fallback) */
    int no_userns_remap;

    /* --lazy  (experimental: attempt userfaultfd-based on-demand rootfs paging) */
    int lazy;
};

struct userns_map_plan
{
    int           use_subid_remap;
    unsigned long subuid_start;
    unsigned long subgid_start;
    char          newuidmap_path[PATH_MAX];
    char          newgidmap_path[PATH_MAX];
};

static void audit_emit_start_event(const char* image_path,
                                   const struct container_opts* opts)
{
    char image[PATH_MAX];
    char name[256];
    char net[64];
    char extra[1024];

    audit_escape_string(image_path, image, sizeof(image));
    audit_escape_string(opts->name ? opts->name : "", name, sizeof(name));
    audit_escape_string(opts->net ? opts->net : "host", net, sizeof(net));
    snprintf(extra, sizeof(extra),
             "\"image\":\"%s\",\"name\":\"%s\",\"net\":\"%s\","
             "\"caps\":\"0x%llx\"",
             image, name, net, (unsigned long long)opts->cap_add_mask);
    audit_emit("start", extra);
}

static void audit_emit_exec_event(const char* path)
{
    char escaped[PATH_MAX];
    char extra[PATH_MAX + 32];

    audit_escape_string(path, escaped, sizeof(escaped));
    snprintf(extra, sizeof(extra), "\"path\":\"%s\"", escaped);
    audit_emit("exec", extra);
}

static int argv_has_debug_flag(int argc, char* argv[])
{
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--debug") == 0)
        {
            return 1;
        }
    }
    return 0;
}

static const char* opts_net_mode(const struct container_opts* opts)
{
    if (opts->net_join_pid > 0)
    {
        return "container";
    }
    return opts->net ? opts->net : "host";
}

static void debug_dump_opts(const struct container_opts* opts)
{
    debug_log("opts.summary",
              "vm=%d vmm=%s net=%s ipc_join_pid=%d read_only=%d detach=%d "
              "no_seccomp=%d no_userns_remap=%d debug=%d",
              opts->use_vm,
              opts->vmm ? opts->vmm : "(default)",
              opts_net_mode(opts),
              (int)opts->ipc_join_pid,
              opts->read_only,
              opts->detach,
              opts->no_seccomp,
              opts->no_userns_remap,
              opts->debug);
    debug_log("opts.resources",
              "memory_bytes=%lld cpus_quota=%ld vm_cpus=%.3f pids=%ld",
              opts->cg_memory_bytes,
              opts->cg_cpu_quota,
              opts->vm_cpus,
              opts->cg_pids);
    debug_log("opts.counts",
              "volumes=%d secrets=%d env=%d tmpfs=%d ulimits=%d devices=%d "
              "extra_args=%d",
              opts->n_vols,
              opts->n_secrets,
              opts->n_env,
              opts->n_tmpfs,
              opts->n_ulimits,
              opts->n_devices,
              opts->n_extra);
    if (opts->entrypoint)
    {
        debug_log("opts.entrypoint", "value=%s", opts->entrypoint);
    }
    if (opts->workdir)
    {
        debug_log("opts.workdir", "value=%s", opts->workdir);
    }
    if (opts->overlay_persist)
    {
        debug_log("opts.overlay_persist", "dir=%s", opts->overlay_persist);
    }
    if (opts->verify_key)
    {
        debug_log("opts.verify_key", "path=%s", opts->verify_key);
    }
}

static ssize_t read_all_fd(int fd, char* buf, size_t len);
static int mkdir_p_secure(const char* path, mode_t leaf_mode, const char* what);

static int read_proc_start_ticks(pid_t pid, unsigned long long* out)
{
    char path[64];
    int n = snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    if (n < 0 || n >= (int)sizeof(path))
    {
        return -1;
    }

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        return -1;
    }

    char buf[4096];
    ssize_t nr = read_all_fd(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (nr <= 0)
    {
        return -1;
    }
    buf[nr] = '\0';

    char* rparen = strrchr(buf, ')');
    if (!rparen || rparen[1] != ' ')
    {
        return -1;
    }

    char* fields[64];
    int n_fields = 0;
    char* field = rparen + 2;
    while (field && *field && n_fields < (int)(sizeof(fields) / sizeof(fields[0])))
    {
        fields[n_fields++] = field;
        char* space = strchr(field, ' ');
        if (!space)
        {
            break;
        }
        *space = '\0';
        field = space + 1;
    }
    if (n_fields <= 19)
    {
        return -1;
    }

    char* endp = NULL;
    errno = 0;
    unsigned long long ticks = strtoull(fields[19], &endp, 10);
    if (errno != 0 || endp == fields[19] || *endp != '\0')
    {
        return -1;
    }

    *out = ticks;
    return 0;
}

static int open_path_nofollow(const char* path, int flags, mode_t mode)
{
    if (!path || path[0] != '/')
    {
        errno = EINVAL;
        return -1;
    }

    char buf[PATH_MAX];
    int n = snprintf(buf, sizeof(buf), "%s", path + 1);
    if (n < 0 || n >= (int)sizeof(buf))
    {
        errno = ENAMETOOLONG;
        return -1;
    }

    int cur_fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (cur_fd < 0)
    {
        return -1;
    }

    char* tok = buf;
    while (*tok == '/')
    {
        tok++;
    }
    if (*tok == '\0')
    {
        close(cur_fd);
        errno = EISDIR;
        return -1;
    }

    char* slash = NULL;
    while ((slash = strchr(tok, '/')) != NULL)
    {
        *slash = '\0';
        if (*tok != '\0')
        {
            int next = openat(cur_fd, tok,
                              O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                              O_CLOEXEC);
            close(cur_fd);
            if (next < 0)
            {
                return -1;
            }
            cur_fd = next;
        }
        tok = slash + 1;
        while (*tok == '/')
        {
            tok++;
        }
    }

    int fd = openat(cur_fd, tok, flags | O_NOFOLLOW | O_CLOEXEC, mode);
    close(cur_fd);
    return fd;
}

/*
 * Write a JSON container state file to
 * $HOME/.cache/oci2bin/containers/<name>.json.
 * When redirect_output is 1, redirect stdout/stderr to the log file.
 */
static void write_container_state(const char* name, pid_t pid,
                                  int redirect_output)
{
    const char* home = getenv("HOME");
    if (!home || !name || !*name)
    {
        return;
    }

    /* Reject HOME values that contain JSON-breaking characters or path
     * traversal.  HOME is trusted but a hostile environment could set it. */
    for (const char* hp = home; *hp; hp++)
    {
        if (*hp == '"' || *hp == '\\' || *hp == '\n')
        {
            return;
        }
    }
    if (home[0] != '/' || strstr(home, ".."))
    {
        return;
    }

    /* Resolve our own path for the state file */
    char self_path[PATH_MAX] = "";
    ssize_t slen = readlink("/proc/self/exe", self_path,
                            sizeof(self_path) - 1);
    if (slen > 0)
    {
        self_path[slen] = '\0';
    }

    char dir[PATH_MAX];
    int n = snprintf(dir, sizeof(dir),
                     "%s/.cache/oci2bin/containers", home);
    if (n < 0 || n >= (int)sizeof(dir))
    {
        return;
    }
    if (mkdir_p_secure(dir, 0700, "container state") < 0)
    {
        return;
    }

    unsigned long long start_ticks = 0;
    (void)read_proc_start_ticks(pid, &start_ticks);

    char log_path[PATH_MAX];
    n = snprintf(log_path, sizeof(log_path), "%s/%s.log", dir, name);
    if (n < 0 || n >= (int)sizeof(log_path))
    {
        return;
    }

    /* Redirect stdout/stderr to log file (detached child) */
    if (redirect_output)
    {
        int log_fd = open_path_nofollow(log_path,
                                        O_WRONLY | O_CREAT | O_APPEND,
                                        0600);
        if (log_fd >= 0)
        {
            if (dup2(log_fd, STDOUT_FILENO) < 0)
            {
                close(log_fd);
                return;
            }
            if (dup2(log_fd, STDERR_FILENO) < 0)
            {
                close(log_fd);
                return;
            }
            close(log_fd);
        }
    }

    char state_path[PATH_MAX];
    n = snprintf(state_path, sizeof(state_path), "%s/%s.json", dir, name);
    if (n < 0 || n >= (int)sizeof(state_path))
    {
        return;
    }

    /* Build ISO-8601 timestamp */
    time_t now = time(NULL);
    struct tm tm_buf;
    char ts[32] = "unknown";
    if (gmtime_r(&now, &tm_buf) != NULL)
    {
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
    }

    /* Sanitize self_path: replace '"' and '\' to prevent JSON injection */
    for (int i = 0; self_path[i]; i++)
    {
        if (self_path[i] == '"' || self_path[i] == '\\')
        {
            self_path[i] = '?';
        }
    }

    /* Note: log_file is omitted from the JSON — its path is always
     * $HOME/.cache/oci2bin/containers/<name>.log and is reconstructed
     * by consumers (oci2bin logs).  Keeping HOME out of the JSON body
     * breaks the getenv→write taint chain that triggers CodeQL
     * cpp/system-data-exposure. */
    char json[2048];
    n = snprintf(json, sizeof(json),
                 "{\"name\":\"%s\",\"pid\":%d,\"binary\":\"%s\","
                 "\"started_at\":\"%s\",\"start_ticks\":%llu}\n",
                 name, (int)pid, self_path, ts, start_ticks);
    if (n < 0 || n >= (int)sizeof(json))
    {
        return;
    }

    int fd = open_path_nofollow(state_path,
                                O_WRONLY | O_CREAT | O_TRUNC,
                                0600);
    if (fd < 0)
    {
        return;
    }
    size_t total = 0;
    size_t len   = strlen(json);
    while (total < len)
    {
        ssize_t w = write(fd, json + total, len - total);
        if (w < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            break;
        }
        total += (size_t)w;
    }
    close(fd);
}

/* ── tiny JSON helpers (just enough to parse manifest.json and config) ─── */

/*
 * Locate a JSON key and return a pointer to the first non-whitespace
 * character after the "key": separator.  Returns NULL if the key is not
 * found or the key string would overflow the internal needle buffer
 * (keys longer than 254 bytes).  Shared by json_get_string,
 * json_get_array, and json_parse_names_array.
 */
static const char* json_skip_to_value(const char* json, const char* key)
{
    char needle[256];
    int nlen = snprintf(needle, sizeof(needle), "\"%s\"", key);
    if (nlen < 0 || (size_t)nlen >= sizeof(needle))
    {
        return NULL;    /* key too long */
    }
    /* Reject matches that sit inside a JSON string value: a hostile
     * manifest could embed `\"Cmd\":fake` in an unrelated string.
     * Require the matched key to appear at a structural position —
     * the previous non-whitespace byte must be '{' or ',' (object
     * start or member separator), or the key is at the start. */
    const char* p = json;
    while ((p = strstr(p, needle)) != NULL)
    {
        const char* q = p;
        while (q > json && (q[-1] == ' ' || q[-1] == '\t' ||
                            q[-1] == '\n' || q[-1] == '\r'))
        {
            q--;
        }
        if (q == json || q[-1] == '{' || q[-1] == ',')
        {
            const char* v = p + (size_t)nlen;
            while (*v == ' ' || *v == ':' || *v == '\t' || *v == '\n')
            {
                v++;
            }
            return v;
        }
        p++;    /* not at structural position; keep scanning */
    }
    return NULL;
}

/* Find a JSON string value for a given key. Returns malloc'd string or NULL. */
static char* json_get_string(const char* json, const char* key)
{
    const char* p = json_skip_to_value(json, key);
    if (!p || *p != '"')
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
    const char* p = json_skip_to_value(json, key);
    if (!p || *p != '[')
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

static int path_has_dotdot_component(const char* path);
static int path_is_absolute_and_clean(const char* path);
static ssize_t read_all_fd(int fd, char* buf, size_t len);
static int write_all_fd(int fd, const char* data, size_t len);
static int parent_dir_path(const char* path, char* out, size_t out_sz);
static int mkdir_p_secure(const char* path, mode_t leaf_mode, const char* what);
static int ensure_path_not_symlink(const char* path, const char* what);
static int ensure_bind_mount_target(const char* src, const char* dst,
                                    const char* what);
static int parse_id_value(const char* text, long max_value, long* out);
static int lookup_passwd_user(const char* passwd_path, const char* name,
                              uid_t* out_uid, gid_t* out_gid);
static int lookup_group_name(const char* group_path, const char* name,
                             gid_t* out_gid);

/*
 * Create a runtime tmpdir in OCI2BIN_TMPDIR, TMPDIR, /tmp, or /var/tmp.
 * Returns 0 on success, -1 on failure.
 */
static int make_runtime_tmpdir(char* out, size_t out_sz, const char* prefix)
{
    const char* candidates[] =
    {
        getenv("OCI2BIN_TMPDIR"),
        getenv("TMPDIR"),
        "/tmp",
        "/var/tmp",
    };
    int n_candidates = (int)(sizeof(candidates) / sizeof(candidates[0]));

    for (int i = 0; i < n_candidates; i++)
    {
        const char* base = candidates[i];
        if (!base || base[0] == '\0')
        {
            continue;
        }
        if (path_has_dotdot_component(base))
        {
            continue;
        }
        int n = snprintf(out, out_sz, "%s/%sXXXXXX", base, prefix);
        if (n < 0 || (size_t)n >= out_sz)
        {
            continue;
        }
        if (mkdtemp(out))
        {
            return 0;
        }
    }
    return -1;
}

static int path_join_suffix(char* out, size_t out_sz,
                            const char* base, const char* suffix)
{
    size_t base_len = strlen(base);
    size_t suf_len  = strlen(suffix);
    if (base_len + suf_len + 1 > out_sz)
    {
        return -1;
    }
    memcpy(out, base, base_len);
    memcpy(out + base_len, suffix, suf_len + 1);
    return 0;
}

static int path_has_dotdot_component(const char* path)
{
    if (!path)
    {
        return 0;
    }

    const char* p = path;
    while (*p)
    {
        while (*p == '/')
        {
            p++;
        }

        const char* start = p;
        while (*p && *p != '/')
        {
            p++;
        }
        if ((size_t)(p - start) == 2 &&
                start[0] == '.' &&
                start[1] == '.')
        {
            return 1;
        }
    }
    return 0;
}

static int path_is_absolute_and_clean(const char* path)
{
    return path && path[0] == '/' && !path_has_dotdot_component(path);
}

static ssize_t read_all_fd(int fd, char* buf, size_t len)
{
    size_t off = 0;
    while (off < len)
    {
        ssize_t n = read(fd, buf + off, len - off);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }
        if (n == 0)
        {
            break;
        }
        off += (size_t)n;
    }
    return (ssize_t)off;
}

static int write_all_fd(int fd, const char* data, size_t len)
{
    size_t off = 0;
    while (off < len)
    {
        ssize_t n = write(fd, data + off, len - off);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

/*
 * Copy exactly nbytes from in_fd to out_fd.
 * Retries EINTR.  Returns 0 on success, -1 on short read or write error.
 */
static int copy_n_bytes(int in_fd, int out_fd, unsigned long nbytes)
{
    char buf[65536];
    unsigned long remaining = nbytes;
    while (remaining > 0)
    {
        size_t to_read = remaining < sizeof(buf) ? remaining : sizeof(buf);
        ssize_t nr;
        do
        {
            nr = read(in_fd, buf, to_read);
        }
        while (nr < 0 && errno == EINTR);
        if (nr <= 0)
        {
            fprintf(stderr,
                    "oci2bin: copy_n_bytes: premature EOF at offset %lu\n",
                    nbytes - remaining);
            return -1;
        }
        if (write_all_fd(out_fd, buf, (size_t)nr) < 0)
        {
            return -1;
        }
        remaining -= (unsigned long)nr;
    }
    return 0;
}

/*
 * Open a path beneath a directory fd without following symlinks at any
 * component.  relpath must be relative (no leading '/').
 * Each intermediate directory component is opened with
 * O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC.
 * The final component is opened with (flags|O_NOFOLLOW|O_CLOEXEC) and mode.
 * Returns fd on success or -1 on error (including ELOOP for any symlink).
 */
static int openat_beneath(int rootfs_fd, const char* relpath,
                          int flags, mode_t mode)
{
    char buf[PATH_MAX];
    if (snprintf(buf, sizeof(buf), "%s", relpath) >= (int)sizeof(buf))
    {
        return -1;
    }

    int cur_fd = dup(rootfs_fd);
    if (cur_fd < 0)
    {
        return -1;
    }

    char* tok = buf;
    char* slash;
    while ((slash = strchr(tok, '/')) != NULL)
    {
        *slash = '\0';
        if (*tok != '\0')
        {
            int next = openat(cur_fd, tok,
                              O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            close(cur_fd);
            if (next < 0)
            {
                return -1;
            }
            cur_fd = next;
        }
        tok = slash + 1;
    }

    /* final component */
    int fd = openat(cur_fd, tok, flags | O_NOFOLLOW | O_CLOEXEC, mode);
    close(cur_fd);
    return fd;
}

/*
 * Unlink a path beneath rootfs_fd without following symlinks.
 * relpath must be relative (no leading '/').
 */
static int unlinkat_beneath(int rootfs_fd, const char* relpath, int atflags)
{
    char buf[PATH_MAX];
    if (snprintf(buf, sizeof(buf), "%s", relpath) >= (int)sizeof(buf))
    {
        return -1;
    }

    char* slash = strrchr(buf, '/');
    if (!slash)
    {
        return unlinkat(rootfs_fd, buf, atflags);
    }

    *slash = '\0';
    int dir_fd = openat_beneath(rootfs_fd, buf,
                                O_RDONLY | O_DIRECTORY, 0);
    if (dir_fd < 0)
    {
        return -1;
    }
    int rc = unlinkat(dir_fd, slash + 1, atflags);
    close(dir_fd);
    return rc;
}

static int parent_dir_path(const char* path, char* out, size_t out_sz)
{
    int n = snprintf(out, out_sz, "%s", path);
    if (n < 0 || (size_t)n >= out_sz)
    {
        return -1;
    }

    char* slash = strrchr(out, '/');
    if (!slash)
    {
        return -1;
    }
    if (slash == out)
    {
        slash[1] = '\0';
        return 0;
    }
    *slash = '\0';
    return 0;
}

static int mkdir_p_secure(const char* path, mode_t leaf_mode, const char* what)
{
    char tmp[PATH_MAX];
    int n = snprintf(tmp, sizeof(tmp), "%s", path);
    if (n < 0 || (size_t)n >= sizeof(tmp))
    {
        fprintf(stderr, "oci2bin: %s path too long: %s\n", what, path);
        return -1;
    }

    for (char* p = tmp + 1;; p++)
    {
        if (*p != '/' && *p != '\0')
        {
            continue;
        }

        char saved = *p;
        *p = '\0';

        struct stat st;
        if (lstat(tmp, &st) == 0)
        {
            if (S_ISLNK(st.st_mode))
            {
                fprintf(stderr,
                        "oci2bin: %s path contains symlink component: %s\n",
                        what, tmp);
                return -1;
            }
            if (!S_ISDIR(st.st_mode))
            {
                fprintf(stderr,
                        "oci2bin: %s path component is not a directory: %s\n",
                        what, tmp);
                return -1;
            }
        }
        else if (errno == ENOENT)
        {
            mode_t mode = (saved == '\0') ? leaf_mode : 0755;
            if (mkdir(tmp, mode) < 0 && errno != EEXIST)
            {
                fprintf(stderr, "oci2bin: mkdir %s: %s\n",
                        tmp, strerror(errno));
                return -1;
            }
        }
        else
        {
            fprintf(stderr, "oci2bin: lstat %s: %s\n",
                    tmp, strerror(errno));
            return -1;
        }

        if (saved == '\0')
        {
            break;
        }
        *p = saved;
    }

    return 0;
}

static int ensure_path_not_symlink(const char* path, const char* what)
{
    struct stat st;
    if (lstat(path, &st) < 0)
    {
        if (errno == ENOENT)
        {
            return 0;
        }
        fprintf(stderr, "oci2bin: lstat %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (S_ISLNK(st.st_mode))
    {
        fprintf(stderr, "oci2bin: %s target must not be a symlink: %s\n",
                what, path);
        return -1;
    }
    return 0;
}

static int ensure_bind_mount_target(const char* src, const char* dst,
                                    const char* what)
{
    struct stat src_st;
    if (stat(src, &src_st) < 0)
    {
        fprintf(stderr, "oci2bin: stat %s: %s\n", src, strerror(errno));
        return -1;
    }

    char parent[PATH_MAX];
    if (parent_dir_path(dst, parent, sizeof(parent)) < 0)
    {
        fprintf(stderr, "oci2bin: %s destination path too long: %s\n",
                what, dst);
        return -1;
    }
    if (mkdir_p_secure(parent, 0755, what) < 0)
    {
        return -1;
    }

    struct stat dst_st;
    if (lstat(dst, &dst_st) == 0)
    {
        if (S_ISLNK(dst_st.st_mode))
        {
            fprintf(stderr,
                    "oci2bin: %s destination must not be a symlink: %s\n",
                    what, dst);
            return -1;
        }
        return 0;
    }
    if (errno != ENOENT)
    {
        fprintf(stderr, "oci2bin: lstat %s: %s\n", dst, strerror(errno));
        return -1;
    }

    if (S_ISDIR(src_st.st_mode))
    {
        if (mkdir(dst, 0755) < 0 && errno != EEXIST)
        {
            fprintf(stderr, "oci2bin: mkdir %s: %s\n",
                    dst, strerror(errno));
            return -1;
        }
        return ensure_path_not_symlink(dst, what);
    }

    int fd = open(dst, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
                  src_st.st_mode & 0777 ? (src_st.st_mode & 0777) : 0600);
    if (fd < 0)
    {
        fprintf(stderr, "oci2bin: create %s: %s\n", dst, strerror(errno));
        return -1;
    }
    close(fd);
    return 0;
}

static int parse_id_value(const char* text, long max_value, long* out)
{
    if (!text || !text[0])
    {
        return -1;
    }

    char* endp = NULL;
    errno = 0;
    long value = strtol(text, &endp, 10);
    if (endp == text || *endp != '\0' || errno == ERANGE ||
            value < 0 || value > max_value)
    {
        return -1;
    }

    *out = value;
    return 0;
}

static int lookup_passwd_user(const char* passwd_path, const char* name,
                              uid_t* out_uid, gid_t* out_gid)
{
    FILE* f = fopen(passwd_path, "r");
    if (!f)
    {
        return -1;
    }

    char line[1024];
    int found = 0;
    while (!found && fgets(line, sizeof(line), f))
    {
        char* user = line;
        char* passwd = strchr(user, ':');
        if (!passwd)
        {
            continue;
        }
        *passwd++ = '\0';

        char* uid_field = strchr(passwd, ':');
        if (!uid_field)
        {
            continue;
        }
        *uid_field++ = '\0';

        char* gid_field = strchr(uid_field, ':');
        if (!gid_field)
        {
            continue;
        }
        *gid_field++ = '\0';

        char* tail = strchr(gid_field, ':');
        if (!tail)
        {
            continue;
        }
        *tail = '\0';

        if (strcmp(user, name) == 0)
        {
            long uid_val = 0;
            long gid_val = 0;
            if (parse_id_value(uid_field, 65534, &uid_val) < 0 ||
                    parse_id_value(gid_field, 65534, &gid_val) < 0)
            {
                fclose(f);
                return -1;
            }
            *out_uid = (uid_t)uid_val;
            *out_gid = (gid_t)gid_val;
            found = 1;
        }
    }

    fclose(f);
    return found ? 0 : -1;
}

static int lookup_group_name(const char* group_path, const char* name,
                             gid_t* out_gid)
{
    FILE* f = fopen(group_path, "r");
    if (!f)
    {
        return -1;
    }

    char line[1024];
    int found = 0;
    while (!found && fgets(line, sizeof(line), f))
    {
        char* group = line;
        char* passwd = strchr(group, ':');
        if (!passwd)
        {
            continue;
        }
        *passwd++ = '\0';

        char* gid_field = strchr(passwd, ':');
        if (!gid_field)
        {
            continue;
        }
        *gid_field++ = '\0';

        char* members = strchr(gid_field, ':');
        if (members)
        {
            *members = '\0';
        }

        if (strcmp(group, name) == 0)
        {
            long gid_val = 0;
            if (parse_id_value(gid_field, 65534, &gid_val) < 0)
            {
                fclose(f);
                return -1;
            }
            *out_gid = (gid_t)gid_val;
            found = 1;
        }
    }

    fclose(f);
    return found ? 0 : -1;
}

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
    ssize_t n = read_all_fd(fd, buf, (size_t)st.st_size);
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
    int rc = write_all_fd(fd, data, len);
    close(fd);
    return rc;
}

static int write_file_beneath(int rootfs_fd, const char* rel_path,
                              const char* data, size_t len, mode_t mode)
{
    int fd = openat_beneath(rootfs_fd, rel_path,
                            O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0)
    {
        return -1;
    }
    int rc = write_all_fd(fd, data, len);
    close(fd);
    return rc;
}

static char* read_file_beneath(int rootfs_fd, const char* rel_path,
                               size_t* out_size)
{
    int fd = openat_beneath(rootfs_fd, rel_path, O_RDONLY, 0);
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
    ssize_t n = read_all_fd(fd, buf, (size_t)st.st_size);
    close(fd);
    if (n < 0)
    {
        free(buf);
        return NULL;
    }
    buf[n] = '\0';
    if (out_size)
    {
        *out_size = (size_t)n;
    }
    return buf;
}

/*
 * Resolve a username to numeric UID:GID using rootfs/etc/passwd.
 * Stores "uid:gid" in out (at least 32 bytes).  Returns 0 on success.
 * If the spec is already numeric (or "uid:gid"), it is copied as-is.
 */
static int resolve_user_in_rootfs(const char* rootfs, const char* spec,
                                  char* out, size_t outsz)
{
    if (!spec || !spec[0])
    {
        return -1;
    }
    /* Already numeric — copy as-is */
    if (spec[0] >= '0' && spec[0] <= '9')
    {
        if (snprintf(out, outsz, "%s", spec) >= (int)outsz)
        {
            return -1;
        }
        return 0;
    }
    int rootfs_fd = open(rootfs, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (rootfs_fd < 0)
    {
        return -1;
    }
    int passwd_fd = openat_beneath(rootfs_fd, "etc/passwd", O_RDONLY, 0);
    close(rootfs_fd);
    if (passwd_fd < 0)
    {
        return -1;
    }
    FILE* f = fdopen(passwd_fd, "r");
    if (!f)
    {
        close(passwd_fd);
        return -1;
    }
    char line[1024];
    uid_t uid = 0;
    gid_t gid = 0;
    int found = 0;
    while (!found && fgets(line, sizeof(line), f))
    {
        char* user = line;
        char* passwd = strchr(user, ':');
        if (!passwd)
        {
            continue;
        }
        *passwd++ = '\0';
        char* uid_field = strchr(passwd, ':');
        if (!uid_field)
        {
            continue;
        }
        *uid_field++ = '\0';
        char* gid_field = strchr(uid_field, ':');
        if (!gid_field)
        {
            continue;
        }
        *gid_field++ = '\0';
        char* tail = strchr(gid_field, ':');
        if (!tail)
        {
            continue;
        }
        *tail = '\0';
        if (strcmp(user, spec) == 0)
        {
            long uid_val = 0, gid_val = 0;
            if (parse_id_value(uid_field, 65534, &uid_val) < 0 ||
                    parse_id_value(gid_field, 65534, &gid_val) < 0)
            {
                fclose(f);
                return -1;
            }
            uid = (uid_t)uid_val;
            gid = (gid_t)gid_val;
            found = 1;
        }
    }
    fclose(f);
    if (!found)
    {
        return -1;
    }
    return snprintf(out, outsz, "%u:%u",
                    (unsigned)uid, (unsigned)gid) < (int)outsz ? 0 : -1;
}

/*
 * Copy the host /etc/resolv.conf into rootfs/etc/resolv.conf.
 * Prefers /run/systemd/resolve/resolv.conf (real upstream nameservers)
 * over /etc/resolv.conf which may contain 127.0.0.53 (systemd-resolved
 * stub, unreachable inside VMs).
 */
static void install_resolv_conf(const char* rootfs)
{
    size_t sz;
    char* data = read_file("/run/systemd/resolve/resolv.conf", &sz);
    if (!data)
    {
        data = read_file("/etc/resolv.conf", &sz);
    }
    if (!data)
    {
        return;
    }

    int rootfs_fd = open(rootfs, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (rootfs_fd < 0)
    {
        free(data);
        return;
    }

    unlinkat_beneath(rootfs_fd, "etc/resolv.conf", 0);
    int dst_fd = openat_beneath(rootfs_fd, "etc/resolv.conf",
                                O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dst_fd >= 0)
    {
        if (write_all_fd(dst_fd, data, sz) < 0)
        {
            fprintf(stderr, "oci2bin: warning: write resolv.conf: %s\n",
                    strerror(errno));
        }
        close(dst_fd);
    }
    close(rootfs_fd);
    free(data);
}

/*
 * Write a custom resolv.conf when --dns or --dns-search are given.
 * Called after install_resolv_conf() so it overwrites the host copy.
 */
static void install_custom_resolv_conf(const char* rootfs,
                                       char* const* dns_servers,
                                       int n_dns_servers,
                                       char* const* dns_search,
                                       int n_dns_search)
{
    if (n_dns_servers == 0 && n_dns_search == 0)
    {
        return;
    }

    int rootfs_fd = open(rootfs, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (rootfs_fd < 0)
    {
        return;
    }

    /* Build the content in a heap buffer */
    char buf[4096];
    int pos = 0;

    for (int i = 0; i < n_dns_servers && pos < (int)sizeof(buf) - 1; i++)
    {
        int n = snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                         "nameserver %s\n", dns_servers[i]);
        if (n > 0 && n < (int)(sizeof(buf) - (size_t)pos))
        {
            pos += n;
        }
    }
    if (n_dns_search > 0 && pos < (int)sizeof(buf) - 1)
    {
        int n = snprintf(buf + pos, sizeof(buf) - (size_t)pos, "search");
        if (n > 0 && n < (int)(sizeof(buf) - (size_t)pos))
        {
            pos += n;
        }
        for (int i = 0; i < n_dns_search && pos < (int)sizeof(buf) - 2; i++)
        {
            int n = snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                             " %s", dns_search[i]);
            if (n > 0 && n < (int)(sizeof(buf) - (size_t)pos))
            {
                pos += n;
            }
        }
        if (pos < (int)sizeof(buf) - 1)
        {
            buf[pos++] = '\n';
        }
    }
    buf[pos] = '\0';

    unlinkat_beneath(rootfs_fd, "etc/resolv.conf", 0);
    int dst_fd = openat_beneath(rootfs_fd, "etc/resolv.conf",
                                O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dst_fd >= 0)
    {
        if (write_all_fd(dst_fd, buf, (size_t)pos) < 0)
        {
            fprintf(stderr, "oci2bin: warning: write custom resolv.conf: %s\n",
                    strerror(errno));
        }
        close(dst_fd);
    }
    close(rootfs_fd);
}

/*
 * Append --add-host HOST:IP entries to /etc/hosts inside the rootfs.
 * Called pre-chroot so rootfs paths are directly accessible.
 */
static void install_extra_hosts(const char* rootfs,
                                char* const* add_hosts,
                                int n_add_hosts)
{
    if (n_add_hosts == 0)
    {
        return;
    }

    int rootfs_fd = open(rootfs, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (rootfs_fd < 0)
    {
        return;
    }

    /* Open for append (create if missing) */
    int dst_fd = openat_beneath(rootfs_fd, "etc/hosts",
                                O_WRONLY | O_CREAT | O_APPEND, 0644);
    close(rootfs_fd);
    if (dst_fd < 0)
    {
        return;
    }

    for (int i = 0; i < n_add_hosts; i++)
    {
        /* Format is HOST:IP — split on ':' and write as "IP HOST\n" */
        const char* spec = add_hosts[i];
        const char* colon = strchr(spec, ':');
        if (!colon)
        {
            continue;
        }
        size_t host_len = (size_t)(colon - spec);
        const char* ip   = colon + 1;

        char line[512];
        int n = snprintf(line, sizeof(line), "%s %.*s\n",
                         ip, (int)host_len, spec);
        if (n > 0 && (size_t)n < sizeof(line))
        {
            if (write_all_fd(dst_fd, line, (size_t)n) < 0)
            {
                fprintf(stderr, "oci2bin: warning: write /etc/hosts: %s\n",
                        strerror(errno));
            }
        }
    }
    close(dst_fd);
}

/*
 * Parsed OCI image config.  Populated by read_oci_config() from the
 * .oci2bin_config JSON written during extraction.  Caller must free
 * all non-NULL pointers when done.
 */
struct oci_config
{
    char* entrypoint_json; /* "Entrypoint" array or NULL */
    char* cmd_json;        /* "Cmd" array or NULL */
    char* env_json;        /* "Env" array or NULL */
    char* workdir;         /* "WorkingDir" string or NULL */
    char* user;            /* "User" string or NULL */
};

/*
 * Read and parse .oci2bin_config from rootfs (or "/" if rootfs is NULL).
 * Returns 0 on success, -1 if the config file cannot be read.
 */
static int read_oci_config(const char* rootfs, struct oci_config* out)
{
    memset(out, 0, sizeof(*out));
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/.oci2bin_config",
                     rootfs ? rootfs : "");
    if (n < 0 || (size_t)n >= sizeof(path))
    {
        fprintf(stderr, "oci2bin: config path truncated\n");
        return -1;
    }
    char* cfg = read_file(path, NULL);
    if (!cfg)
    {
        return -1;
    }
    out->entrypoint_json = json_get_array(cfg, "Entrypoint");
    out->cmd_json        = json_get_array(cfg, "Cmd");
    out->env_json        = json_get_array(cfg, "Env");
    out->workdir         = json_get_string(cfg, "WorkingDir");
    out->user            = json_get_string(cfg, "User");
    free(cfg);
    return 0;
}

static void free_oci_config(struct oci_config* c)
{
    free(c->entrypoint_json);
    free(c->cmd_json);
    free(c->env_json);
    free(c->workdir);
    free(c->user);
    memset(c, 0, sizeof(*c));
}

/*
 * Build an exec argv from parsed OCI config.
 *   - If user_entrypoint is non-NULL, it replaces the image Entrypoint.
 *   - If extra_args/n_extra are provided, they replace the image Cmd.
 *   - Falls back to /bin/sh if nothing resolves.
 * Returns the number of args placed in exec_args (null-terminated).
 */
static int build_exec_args(const struct oci_config* cfg,
                           const char* user_entrypoint,
                           char* const* extra_args, int n_extra,
                           char* exec_args[], int max_args)
{
    int argc = 0;

    /* Entrypoint */
    if (user_entrypoint)
    {
        exec_args[argc++] = (char*)user_entrypoint;
    }
    else if (cfg->entrypoint_json &&
             strcmp(cfg->entrypoint_json, "null") != 0)
    {
        argc += json_parse_string_array(cfg->entrypoint_json,
                                        exec_args + argc,
                                        max_args - argc);
    }

    /* Cmd / extra args */
    if (n_extra > 0)
    {
        for (int i = 0; i < n_extra && argc < max_args; i++)
        {
            exec_args[argc++] = extra_args[i];
        }
    }
    else if (cfg->cmd_json && strcmp(cfg->cmd_json, "null") != 0)
    {
        argc += json_parse_string_array(cfg->cmd_json,
                                        exec_args + argc,
                                        max_args - argc);
    }

    /* Fallback */
    if (argc == 0)
    {
        exec_args[0] = "/bin/sh";
        argc = 1;
    }
    exec_args[argc] = NULL;
    return argc;
}

/* Write to /proc files (no O_CREAT, no O_TRUNC) */
static int write_proc(const char* path, const char* data, size_t len)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0)
    {
        return -1;
    }
    int rc = write_all_fd(fd, data, len);
    close(fd);
    return rc;
}

/* Run a command, wait for it. Returns exit status (0 = success, -1 = error). */
static int run_cmd(char* const argv[])
{
    if (g_debug && argv && argv[0])
    {
        for (int i = 0; i < 32 && argv[i]; i++)
        {
            debug_log("run_cmd.arg", "index=%d value=%s", i, argv[i]);
        }
    }
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
    while (waitpid(pid, &status, 0) < 0)
    {
        if (errno == EINTR)
        {
            continue;
        }
        perror("waitpid");
        return -1;
    }
    debug_log("run_cmd.exit", "status=%d", WIFEXITED(status) ?
              WEXITSTATUS(status) : -1);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/*
 * Run a command, capturing its stdout into a malloc'd buffer.
 * *out_len receives the number of bytes read.
 * Caller must free() the returned pointer.
 * Returns NULL on error (fork/pipe/exec failure or non-zero exit).
 */
static char* run_cmd_capture(char* const argv[], size_t* out_len)
{
    int pipefd[2];
    if (pipe(pipefd) < 0)
    {
        perror("oci2bin: pipe");
        return NULL;
    }
    pid_t pid = fork();
    if (pid < 0)
    {
        perror("oci2bin: fork");
        close(pipefd[0]);
        close(pipefd[1]);
        return NULL;
    }
    if (pid == 0)
    {
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0)
        {
            _exit(127);
        }
        close(pipefd[1]);
        execvp(argv[0], argv);
        perror("execvp");
        _exit(127);
    }
    close(pipefd[1]);

    /* Read all output into a growable buffer */
    size_t   cap  = 4096;
    size_t   len  = 0;
    char*    buf  = malloc(cap);
    if (!buf)
    {
        close(pipefd[0]);
        waitpid(pid, NULL, 0);
        return NULL;
    }
    for (;;)
    {
        if (len == cap)
        {
            if (cap >= RUN_CMD_CAPTURE_MAX)
            {
                /* Refuse to buffer more than RUN_CMD_CAPTURE_MAX of data */
                fprintf(stderr, "oci2bin: systemd-creds output too large\n");
                free(buf);
                close(pipefd[0]);
                waitpid(pid, NULL, 0);
                return NULL;
            }
            cap *= 2;
            char* nb = realloc(buf, cap);
            if (!nb)
            {
                free(buf);
                close(pipefd[0]);
                waitpid(pid, NULL, 0);
                return NULL;
            }
            buf = nb;
        }
        ssize_t n = read(pipefd[0], buf + len, cap - len);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            perror("oci2bin: read pipe");
            free(buf);
            close(pipefd[0]);
            waitpid(pid, NULL, 0);
            return NULL;
        }
        if (n == 0)
        {
            break;
        }
        len += (size_t)n;
    }
    close(pipefd[0]);

    int status;
    while (waitpid(pid, &status, 0) < 0)
    {
        if (errno == EINTR)
        {
            continue;
        }
        perror("oci2bin: waitpid");
        free(buf);
        return NULL;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        fprintf(stderr, "oci2bin: command exited with status %d\n",
                WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        free(buf);
        return NULL;
    }
    *out_len = len;
    return buf;
}

/* Fork a daemon: exec argv[0] without waiting (child runs for the caller's
 * lifetime).  Returns the child pid, or -1 on error. */
static pid_t spawn_daemon(char* const argv[])
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
        _exit(1);
    }
    return pid;
}

/* ── OCI image extraction ────────────────────────────────────────────────── */

/* File-level static so the returned pointer is never to stack memory. */
static char s_oci_rootfs[PATH_MAX];

/*
 * Extract the OCI tar data from ourselves into a temp directory,
 * then parse manifest.json and extract layers into a rootfs.
 *
 * Returns path to rootfs (static buffer) or NULL on failure.
 */
static char* extract_oci_rootfs(const char* self_path)
{
    char* rootfs = s_oci_rootfs;
    char tmpdir[PATH_MAX];

    debug_log("extract.begin", "self=%s oci_offset=0x%lx oci_size=0x%lx",
              self_path, OCI_DATA_OFFSET, OCI_DATA_SIZE);

    if (make_runtime_tmpdir(tmpdir, sizeof(tmpdir), "oci2bin.") < 0)
    {
        perror("mkdtemp");
        return NULL;
    }

    /* 1. Extract the embedded OCI tar from ourselves */
    char oci_tar_path[PATH_MAX];
    if (path_join_suffix(oci_tar_path, sizeof(oci_tar_path), tmpdir,
                         "/image.tar") < 0)
    {
        fprintf(stderr, "oci2bin: oci tar path too long\n");
        return NULL;
    }

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

    if (copy_n_bytes(self_fd, out_fd, OCI_DATA_SIZE) < 0)
    {
        fprintf(stderr,
                "oci2bin: error extracting embedded OCI data\n");
        close(self_fd);
        close(out_fd);
        return NULL;
    }
    close(self_fd);
    close(out_fd);

    /* 2. Extract the OCI tar into tmpdir/oci/ */
    char oci_dir[PATH_MAX];
    if (path_join_suffix(oci_dir, sizeof(oci_dir), tmpdir, "/oci") < 0)
    {
        fprintf(stderr, "oci2bin: oci dir path too long\n");
        return NULL;
    }
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
    if (path_join_suffix(rootfs, sizeof(s_oci_rootfs), tmpdir, "/rootfs") < 0)
    {
        fprintf(stderr, "oci2bin: rootfs path too long\n");
        free(config_path_rel);
        free(layers_json);
        free(manifest);
        return NULL;
    }
    if (mkdir(rootfs, 0755) < 0)
    {
        perror("mkdir rootfs");
        return NULL;
    }

    char* layers[MAX_LAYERS];
    int nlayers = json_parse_string_array(layers_json, layers, MAX_LAYERS);
    debug_log("extract.manifest", "config=%s layers=%d",
              safe_str(config_path_rel), nlayers);

    for (int i = 0; i < nlayers; i++)
    {
        /* Reject any layer path that tries to traverse out of oci_dir */
        if (path_has_dotdot_component(layers[i]) || layers[i][0] == '/')
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
    if (path_has_dotdot_component(config_path_rel) ||
            config_path_rel[0] == '/')
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
        char* img_user   = json_get_string(config, "User");

        /* Allocate generously — Env arrays can be large */
        size_t bufsz = 16384;
        char*  info_buf = calloc(1, bufsz);
        if (info_buf)
        {
            /* JSON-escape WorkingDir and User to prevent injection */
            char workdir_escaped[PATH_MAX * 2];
            const char* wdir_safe = NULL;
            if (workdir)
            {
                if (json_escape_string(workdir, workdir_escaped,
                                       sizeof(workdir_escaped)) == 0)
                {
                    wdir_safe = workdir_escaped;
                }
            }
            /* Resolve username to numeric uid:gid now, before
             * patch_rootfs_ids() rewrites /etc/passwd to uid=0 */
            char user_resolved[64] = {0};
            char user_escaped[512];
            const char* user_safe = NULL;
            if (img_user && img_user[0])
            {
                const char* user_src = img_user;
                if (resolve_user_in_rootfs(rootfs, img_user,
                                           user_resolved,
                                           sizeof(user_resolved)) == 0)
                {
                    user_src = user_resolved;
                }
                if (json_escape_string(user_src, user_escaped,
                                       sizeof(user_escaped)) == 0)
                {
                    user_safe = user_escaped;
                }
            }
            int n = snprintf(info_buf, bufsz,
                             "{\"Cmd\":%s,\"Entrypoint\":%s,"
                             "\"Env\":%s,\"WorkingDir\":%s%s%s,"
                             "\"User\":%s%s%s}",
                             cmd        ? cmd        : "null",
                             entrypoint ? entrypoint : "null",
                             env_json   ? env_json   : "null",
                             wdir_safe  ? "\""       : "null",
                             wdir_safe  ? wdir_safe  : "",
                             wdir_safe  ? "\""       : "",
                             user_safe  ? "\""       : "null",
                             user_safe  ? user_safe  : "",
                             user_safe  ? "\""       : "");
            if (n > 0 && (size_t)n < bufsz)
            {
                int rootfs_fd = open(rootfs, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                if (rootfs_fd >= 0)
                {
                    (void)write_file_beneath(rootfs_fd, ".oci2bin_config",
                                             info_buf, strlen(info_buf), 0644);
                    close(rootfs_fd);
                }
            }
            free(info_buf);
        }

        free(cmd);
        free(entrypoint);
        free(env_json);
        free(workdir);
        free(img_user);
        free(config);
    }

    free(config_path_rel);
    free(layers_json);
    free(manifest);

    debug_log("extract.done", "rootfs=%s", rootfs);
    return rootfs;
}

/* ── namespace + container entry ─────────────────────────────────────────── */

/*
 * Rewrite a colon-delimited identity file (/etc/passwd or /etc/group),
 * mapping the fields at remap_indices[] to "0" whenever their numeric value
 * is neither 0 nor 65534 (the nobody sentinel).
 * n_fields: minimum number of colon-separated fields a line must have.
 * remap_indices[]: zero-terminated array of 0-based field indices to remap.
 * Fixes the double-newline bug: trailing '\n' is stripped before reassembly.
 */
static void rewrite_id_fields(int rootfs_fd, const char* rel_path,
                              int n_fields,
                              const int* remap_indices)
{
    size_t file_sz;
    char*  data = read_file_beneath(rootfs_fd, rel_path, &file_sz);
    if (!data)
    {
        return;
    }

    int   out_fd = openat_beneath(rootfs_fd, rel_path, O_WRONLY | O_TRUNC, 0);
    FILE* out    = out_fd >= 0 ? fdopen(out_fd, "w") : NULL;
    if (!out)
    {
        free(data);
        return;
    }

    char* line = data;
    while (*line)
    {
        char*  nl       = strchr(line, '\n');
        size_t line_len = nl ? (size_t)(nl - line + 1) : strlen(line);
        char   linebuf[4096];
        if (line_len >= sizeof(linebuf))
        {
            line += line_len;
            continue;
        }
        memcpy(linebuf, line, line_len);
        linebuf[line_len] = '\0';
        /* Strip trailing newline so reassembly doesn't double it */
        size_t buf_len = line_len;
        if (buf_len > 0 && linebuf[buf_len - 1] == '\n')
        {
            linebuf[--buf_len] = '\0';
        }

        /* Split on ':' (up to 8 fields) */
        char* f[8];
        int   nf = 0;
        char* p  = linebuf;
        while (nf < 8)
        {
            f[nf++] = p;
            p = strchr(p, ':');
            if (!p)
            {
                break;
            }
            *p++ = '\0';
        }

        if (nf >= n_fields)
        {
            /* Remap specified id fields to "0" unless nobody (65534) */
            for (const int* ip = remap_indices; *ip >= 0; ip++)
            {
                int idx = *ip;
                if (idx < nf)
                {
                    unsigned long v = strtoul(f[idx], NULL, 10);
                    if (v != 0 && v != 65534)
                    {
                        /* Write only "0\0" (2 bytes); any id field is at
                         * least 2 bytes wide (1-digit value + NUL delimiter).
                         * The bound 8 is a conservative upper limit — do not
                         * change the format string to a longer string without
                         * verifying the actual field width first. */
                        snprintf(f[idx], 8, "0");
                    }
                }
            }
            /* Reassemble fields with ':' separator then newline */
            for (int k = 0; k < nf; k++)
            {
                if (k > 0)
                {
                    fputc(':', out);
                }
                fputs(f[k], out);
            }
            fputc('\n', out);
        }
        else
        {
            /* Not enough fields — write original line unchanged */
            fwrite(line, 1, line_len, out);
            if (!nl)
            {
                fputc('\n', out);
            }
        }
        line += line_len;
    }
    fclose(out);
    free(data);
}

/*
 * Patch the extracted rootfs so that tools which try to drop privileges
 * (e.g. apt's _apt sandbox) succeed inside the single-ID user namespace
 * fallback or microVM mode.
 */
static void patch_rootfs_ids(const char* rootfs)
{
    /* Reject rootfs paths that would overflow any of the paths built below.
     * "/etc/apt/apt.conf.d" is the longest suffix (19 chars + NUL = 20). */
    if (strlen(rootfs) + 20 > PATH_MAX)
    {
        return;
    }

    int rootfs_fd = open(rootfs, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (rootfs_fd < 0)
    {
        return;
    }

    /* ── /etc/passwd ── remap uid (field 2) and gid (field 3) to 0 ── */
    {
        static const int remap[] = {2, 3, -1};
        rewrite_id_fields(rootfs_fd, "etc/passwd", 7, remap);
    }

    /* ── /etc/group ── remap gid (field 2) to 0 ── */
    {
        static const int remap[] = {2, -1};
        rewrite_id_fields(rootfs_fd, "etc/group", 4, remap);
    }

    /* ── apt sandbox ── belt-and-suspenders for Debian/Ubuntu images ── */
    {
        int apt_fd = openat_beneath(rootfs_fd, "etc/apt/apt.conf.d",
                                    O_RDONLY | O_DIRECTORY, 0);
        if (apt_fd >= 0)
        {
            int conf_fd = openat(apt_fd, "99oci2bin",
                                 O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW |
                                 O_CLOEXEC, 0644);
            if (conf_fd >= 0)
            {
                const char* conf = "APT::Sandbox::User \"root\";\n";
                write_all_fd(conf_fd, conf, strlen(conf));
                close(conf_fd);
            }
            close(apt_fd);
        }
    }

    /* ── user-switching wrappers ── replace setpriv/gosu/su-exec with
     * no-op shims so entrypoints that try to drop privileges don't fail
     * in the single-ID user namespace fallback (only UID 0 is mapped). */
    static const char setpriv_shim[] =
        "#!/bin/sh\n"
        "# oci2bin shim: in a single-ID namespace, privilege changes\n"
        "# are impossible.  For -d/--dump, report no capabilities so\n"
        "# entrypoints that check has_cap skip the priv-drop path.\n"
        "# For exec mode, strip all flags and run the command directly.\n"
        "case \"$1\" in -d|--dump) echo 'Capability bounding set:'; exit 0;; esac\n"
        "while [ $# -gt 0 ]; do\n"
        "  case \"$1\" in\n"
        "    --reuid|--regid|--groups|--inh-caps|--ambient-caps|--bounding-set|\\\n"
        "--securebits|--selinux-label|--apparmor-profile)\n"
        "      shift 2;;\n"
        "    --reuid=*|--regid=*|--groups=*|--inh-caps=*|--ambient-caps=*|\\\n"
        "--bounding-set=*|--securebits=*|--selinux-label=*|--apparmor-profile=*)\n"
        "      shift;;\n"
        "    --clear-groups|--keep-groups|--init-groups|--reset-env|--nnp|\\\n"
        "--no-new-privs)\n"
        "      shift;;\n"
        "    --) shift; break;;\n"
        "    *) break;;\n"
        "  esac\n"
        "done\n"
        "exec \"$@\"\n";
    /* gosu/su-exec shim: we cannot change uid in a single-ID namespace, so
     * just exec the command.  Two invocation patterns exist:
     *
     *   Pattern A: gosu user command [args...]
     *     → exec command args                (direct, depth=0)
     *
     *   Pattern B (redis-style re-entry): gosu user entrypoint.sh command [args...]
     *     The entrypoint calls "exec gosu user $0 $@", which re-runs itself
     *     as the same uid=0.  On the second call (depth≥1) we detect >1 arg
     *     after removing the user, skip the leading script, and exec the
     *     real command.
     */
    static const char gosu_shim[] =
        "#!/bin/sh\n"
        "# oci2bin shim: skip user arg, exec the command.\n"
        "shift\n"
        "if [ \"${OCI2BIN_GOSU_DEPTH:-0}\" -ge 1 ] && [ $# -gt 1 ]; then\n"
        "  shift\n"
        "fi\n"
        "export OCI2BIN_GOSU_DEPTH=$(( ${OCI2BIN_GOSU_DEPTH:-0} + 1 ))\n"
        "exec \"$@\"\n";
    /* chown shim: virtiofs passes host UIDs through untranslated, so
     * chown inside a microVM (or single-ID user namespace fallback) always fails
     * with EPERM.  Replace the binary with a no-op that exits 0. */
    static const char chown_shim[] =
        "#!/bin/sh\n"
        "# oci2bin shim: ownership changes are impossible in a single-ID\n"
        "# environment; silently succeed so entrypoint scripts continue.\n"
        "exit 0\n";
    static const struct
    {
        const char* path;
        const char* script;
    } shims[] =
    {
        {"/usr/bin/setpriv", setpriv_shim},
        {"/bin/setpriv",     setpriv_shim},
        {"/usr/sbin/gosu",       gosu_shim},
        {"/usr/local/bin/gosu",  gosu_shim},
        {"/sbin/gosu",           gosu_shim},
        {"/usr/local/bin/su-exec", gosu_shim},
        {"/sbin/su-exec",          gosu_shim},
        {"/bin/chown",       chown_shim},
        {"/usr/bin/chown",   chown_shim},
    };

    for (size_t i = 0; i < sizeof(shims) / sizeof(shims[0]); i++)
    {
        /* shims[i].path starts with '/', skip it for openat_beneath */
        const char* rel = shims[i].path + 1;
        /* Check existence via openat before attempting replacement */
        int probe = openat_beneath(rootfs_fd, rel, O_RDONLY, 0);
        if (probe < 0)
        {
            continue;
        }
        close(probe);
        /* Remove any existing file/symlink, then write the shim safely */
        unlinkat_beneath(rootfs_fd, rel, 0);
        int sfd = openat_beneath(rootfs_fd, rel,
                                 O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (sfd < 0)
        {
            fprintf(stderr, "oci2bin: warning: could not write shim %s: %s\n",
                    shims[i].path, strerror(errno));
            continue;
        }
        if (write_all_fd(sfd, shims[i].script, strlen(shims[i].script)) < 0)
        {
            fprintf(stderr, "oci2bin: warning: could not write shim %s: %s\n",
                    shims[i].path, strerror(errno));
        }
        else
        {
            fchmod(sfd, 0755);
        }
        close(sfd);
    }

    close(rootfs_fd);

    /* ── /etc/resolv.conf ── copy host resolver into chroot ── */
    install_resolv_conf(rootfs);
}

static int current_has_cap(int cap_num)
{
    unsigned long long caps;

    if (cap_num < 0 || cap_num >= 64)
    {
        return 0;
    }
    caps = current_effective_caps();
    return ((caps >> cap_num) & 1ULL) != 0;
}

static int find_helper_binary(const char* name, char* out, size_t outsz)
{
    static const char* dirs[] =
    {
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
    };

    if (!name || !out || outsz == 0)
    {
        return -1;
    }

    out[0] = '\0';
    for (size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++)
    {
        int n = snprintf(out, outsz, "%s/%s", dirs[i], name);
        if (n < 0 || (size_t)n >= outsz)
        {
            continue;
        }
        if (access(out, X_OK) == 0)
        {
            return 0;
        }
    }

    out[0] = '\0';
    return -1;
}

static int parse_subid_line(const char* line,
                            const char* owner_name,
                            const char* owner_uid_text,
                            unsigned long* start_out,
                            unsigned long* count_out)
{
    char buf[256];
    char* owner;
    char* start_text;
    char* count_text;
    char* extra;
    char* endp = NULL;
    unsigned long start;
    unsigned long count;

    if (!line || !owner_uid_text || !start_out || !count_out)
    {
        return -1;
    }

    if (snprintf(buf, sizeof(buf), "%s", line) >= (int)sizeof(buf))
    {
        return -1;
    }

    owner = buf;
    while (*owner == ' ' || *owner == '\t')
    {
        owner++;
    }
    if (*owner == '\0' || *owner == '#')
    {
        return -1;
    }

    start_text = strchr(owner, ':');
    if (!start_text)
    {
        return -1;
    }
    *start_text++ = '\0';

    count_text = strchr(start_text, ':');
    if (!count_text)
    {
        return -1;
    }
    *count_text++ = '\0';

    extra = strchr(count_text, ':');
    if (extra)
    {
        return -1;
    }

    for (char* p = count_text; *p; p++)
    {
        if (*p == '\n' || *p == '\r')
        {
            *p = '\0';
            break;
        }
    }

    if ((!owner_name || strcmp(owner, owner_name) != 0) &&
            strcmp(owner, owner_uid_text) != 0)
    {
        return -1;
    }

    errno = 0;
    start = strtoul(start_text, &endp, 10);
    if (errno != 0 || !endp || *endp != '\0')
    {
        return -1;
    }

    errno = 0;
    count = strtoul(count_text, &endp, 10);
    if (errno != 0 || !endp || *endp != '\0' || count == 0)
    {
        return -1;
    }

    *start_out = start;
    *count_out = count;
    return 0;
}

static int lookup_subid_range_in_file(const char* path,
                                      const char* owner_name,
                                      uid_t owner_uid,
                                      unsigned long min_count,
                                      unsigned long* start_out,
                                      unsigned long* count_out)
{
    FILE* fp;
    char line[256];
    char owner_uid_text[32];

    if (!path || !start_out || !count_out)
    {
        return -1;
    }

    if (snprintf(owner_uid_text, sizeof(owner_uid_text), "%u",
                 (unsigned)owner_uid) >= (int)sizeof(owner_uid_text))
    {
        return -1;
    }

    fp = fopen(path, "r");
    if (!fp)
    {
        return -1;
    }

    while (fgets(line, sizeof(line), fp))
    {
        unsigned long start;
        unsigned long count;

        if (parse_subid_line(line, owner_name, owner_uid_text,
                             &start, &count) < 0)
        {
            continue;
        }
        if (count < min_count)
        {
            continue;
        }
        fclose(fp);
        *start_out = start;
        *count_out = count;
        return 0;
    }

    fclose(fp);
    return -1;
}

static void warn_userns_single_id_fallback(const char* reason)
{
    if (!reason || !reason[0])
    {
        reason = "no reason provided";
    }
    fprintf(stderr,
            "oci2bin: rootless subordinate ID remap unavailable (%s);"
            " using single-ID user namespace. Install newuidmap/newgidmap"
            " and configure /etc/subuid,/etc/subgid, or pass"
            " --no-userns-remap.\n",
            reason);
}

static int lookup_user_name_from_passwd(uid_t uid, char* out, size_t outsz)
{
    FILE* fp;
    char line[512];

    if (!out || outsz == 0)
    {
        return -1;
    }

    out[0] = '\0';
    fp = fopen("/etc/passwd", "r");
    if (!fp)
    {
        return -1;
    }

    while (fgets(line, sizeof(line), fp))
    {
        char* name = line;
        char* passwd = strchr(name, ':');
        char* uid_text;
        char* gid_text;
        char* endp = NULL;
        unsigned long parsed_uid;

        if (!passwd)
        {
            continue;
        }
        *passwd++ = '\0';

        uid_text = strchr(passwd, ':');
        if (!uid_text)
        {
            continue;
        }
        *uid_text++ = '\0';

        gid_text = strchr(uid_text, ':');
        if (!gid_text)
        {
            continue;
        }
        *gid_text++ = '\0';

        errno = 0;
        parsed_uid = strtoul(uid_text, &endp, 10);
        if (errno != 0 || !endp || *endp != '\0')
        {
            continue;
        }
        if ((uid_t)parsed_uid != uid)
        {
            continue;
        }
        if (snprintf(out, outsz, "%s", name) >= (int)outsz)
        {
            fclose(fp);
            return -1;
        }
        fclose(fp);
        return 0;
    }

    fclose(fp);
    return -1;
}

static void plan_userns_map(const struct container_opts* opts,
                            uid_t real_uid,
                            struct userns_map_plan* plan)
{
    char user_name[256];
    const char* owner_name = NULL;
    unsigned long uid_count;
    unsigned long gid_count;

    memset(plan, 0, sizeof(*plan));

    if (opts->no_userns_remap)
    {
        debug_log("userns.plan", "mode=single reason=no_userns_remap");
        return;
    }

    if (current_has_cap(CAP_SETUID) && current_has_cap(CAP_SETGID))
    {
        debug_log("userns.plan", "mode=single reason=have_cap_setid");
        return;
    }

    user_name[0] = '\0';
    if (lookup_user_name_from_passwd(real_uid, user_name,
                                     sizeof(user_name)) == 0)
    {
        owner_name = user_name;
    }

    if (find_helper_binary("newuidmap", plan->newuidmap_path,
                           sizeof(plan->newuidmap_path)) < 0 ||
            find_helper_binary("newgidmap", plan->newgidmap_path,
                               sizeof(plan->newgidmap_path)) < 0)
    {
        warn_userns_single_id_fallback("missing newuidmap/newgidmap");
        return;
    }

    if (lookup_subid_range_in_file("/etc/subuid", owner_name, real_uid,
                                   USERNS_REMAP_CONTAINER_IDS,
                                   &plan->subuid_start, &uid_count) < 0)
    {
        warn_userns_single_id_fallback("missing /etc/subuid range");
        return;
    }

    if (lookup_subid_range_in_file("/etc/subgid", owner_name, real_uid,
                                   USERNS_REMAP_CONTAINER_IDS,
                                   &plan->subgid_start, &gid_count) < 0)
    {
        warn_userns_single_id_fallback("missing /etc/subgid range");
        return;
    }

    plan->use_subid_remap = 1;
    debug_log("userns.plan",
              "mode=subid uid_start=%lu uid_count=%lu gid_start=%lu"
              " gid_count=%lu uid_helper=%s gid_helper=%s",
              plan->subuid_start,
              uid_count,
              plan->subgid_start,
              gid_count,
              plan->newuidmap_path,
              plan->newgidmap_path);
}

static int setup_single_uid_map(uid_t real_uid, gid_t real_gid)
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

static int run_newidmap(const char* helper_path,
                        pid_t target_pid,
                        unsigned long host_root_id,
                        unsigned long subid_start)
{
    char pid_text[32];
    char host_root_text[32];
    char subid_text[32];
    char subcount_text[32];
    char* argv[9];
    int rc;

    if (snprintf(pid_text, sizeof(pid_text), "%d", (int)target_pid) >=
            (int)sizeof(pid_text) ||
            snprintf(host_root_text, sizeof(host_root_text), "%lu",
                     host_root_id) >= (int)sizeof(host_root_text) ||
            snprintf(subid_text, sizeof(subid_text), "%lu",
                     subid_start) >= (int)sizeof(subid_text) ||
            snprintf(subcount_text, sizeof(subcount_text), "%lu",
                     USERNS_REMAP_CONTAINER_IDS) >= (int)sizeof(subcount_text))
    {
        fprintf(stderr, "oci2bin: user namespace mapping argument overflow\n");
        return -1;
    }

    argv[0] = (char*)helper_path;
    argv[1] = pid_text;
    argv[2] = "0";
    argv[3] = host_root_text;
    argv[4] = "1";
    argv[5] = "1";
    argv[6] = subid_text;
    argv[7] = subcount_text;
    argv[8] = NULL;

    rc = run_cmd(argv);
    if (rc != 0)
    {
        fprintf(stderr, "oci2bin: %s failed with exit status %d\n",
                helper_path, rc);
        return -1;
    }

    return 0;
}

static int setup_uid_map(uid_t real_uid,
                         gid_t real_gid,
                         const struct userns_map_plan* plan)
{
    if (!plan || !plan->use_subid_remap)
    {
        return setup_single_uid_map(real_uid, real_gid);
    }

    if (write_proc("/proc/self/setgroups", "deny", 4) < 0)
    {
        /* May fail on older kernels, non-fatal */
    }

    if (run_newidmap(plan->newuidmap_path, getpid(),
                     (unsigned long)real_uid,
                     plan->subuid_start) < 0)
    {
        return -1;
    }

    if (run_newidmap(plan->newgidmap_path, getpid(),
                     (unsigned long)real_gid,
                     plan->subgid_start) < 0)
    {
        return -1;
    }

    return 0;
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
        const char* host_path = opts->vol_host[i];
        const char* ctr_path = opts->vol_ctr[i];
        /* Container path must be absolute and must not contain '..' components */
        if (!path_is_absolute_and_clean(host_path))
        {
            fprintf(stderr, "oci2bin: -v host path must be absolute and clean: %s\n",
                    host_path);
            continue;
        }
        if (!path_is_absolute_and_clean(ctr_path))
        {
            fprintf(stderr,
                    "oci2bin: -v container path must be absolute and clean: %s\n",
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

        if (ensure_bind_mount_target(host_path, dst, "-v") < 0)
        {
            continue;
        }

        /* Bind mount: host path → container path (pre-chroot, both accessible) */
        if (mount(host_path, dst, NULL, MS_BIND | MS_REC, NULL) < 0)
        {
            fprintf(stderr, "oci2bin: bind mount %s -> %s failed: %s\n",
                    host_path, opts->vol_ctr[i], strerror(errno));
        }
        else
        {
            fprintf(stderr, "oci2bin: mounted %s -> %s\n",
                    host_path, opts->vol_ctr[i]);
        }
    }
    /* Emit a single mount audit event summarising volume count */
    {
        char extra[64];
        snprintf(extra, sizeof(extra), "\"volumes\":%d", opts->n_vols);
        audit_emit("mount", extra);
    }
}

/*
 * If the container does not have gdb at the standard paths, bind-mount the
 * host gdb binary (and ld-linux interpreter if the container is musl/static)
 * at /usr/bin/gdb inside the rootfs.  Called pre-chroot when --gdb is set.
 */
static void setup_gdb_in_rootfs(const char* rootfs)
{
    /* Check if the container already has gdb */
    static const char* ctr_paths[] =
    {
        "/usr/bin/gdb", "/usr/local/bin/gdb", "/bin/gdb", NULL
    };
    for (int i = 0; ctr_paths[i]; i++)
    {
        char full[PATH_MAX];
        int n = snprintf(full, sizeof(full), "%s%s", rootfs, ctr_paths[i]);
        if (n < 0 || (size_t)n >= sizeof(full))
        {
            continue;
        }
        if (access(full, X_OK) == 0)
        {
            return; /* already present */
        }
    }

    /* Find gdb on the host */
    static const char* host_paths[] =
    {
        "/usr/bin/gdb", "/usr/local/bin/gdb", "/bin/gdb", NULL
    };
    const char* host_gdb = NULL;
    for (int i = 0; host_paths[i]; i++)
    {
        if (access(host_paths[i], X_OK) == 0)
        {
            host_gdb = host_paths[i];
            break;
        }
    }
    if (!host_gdb)
    {
        fprintf(stderr,
                "oci2bin: --gdb: gdb not found on host; "
                "install it with your package manager\n");
        return;
    }

    char dst[PATH_MAX];
    int n = snprintf(dst, sizeof(dst), "%s/usr/bin/gdb", rootfs);
    if (n < 0 || (size_t)n >= sizeof(dst))
    {
        return;
    }

    if (ensure_bind_mount_target(host_gdb, dst, "--gdb") < 0)
    {
        return;
    }

    if (mount(host_gdb, dst, NULL, MS_BIND | MS_RDONLY, NULL) < 0)
    {
        fprintf(stderr, "oci2bin: --gdb: bind-mount %s -> %s: %s\n",
                host_gdb, dst, strerror(errno));
    }
    else
    {
        fprintf(stderr, "oci2bin: --gdb: bind-mounted host %s into container\n",
                host_gdb);
    }
}

/*
 * Bind-mount secret files (read-only) into the container rootfs.
 * Each secret is a single file; if no container path is given,
 * it lands at /run/secrets/<basename>.  Called pre-chroot.
 */
/*
 * Decrypt a TPM2-sealed credential via systemd-creds and write the plaintext
 * to dst_path (on the rootfs tmpfs) with mode 0400.
 * Returns 0 on success, -1 on error.
 */
/* ── memfd_secret helpers ─────────────────────────────────────────────────── */

/*
 * Maximum size of a plain-file secret read into a memfd_secret region.
 * Secrets are typically small (keys, tokens, passwords); 4 MiB is generous.
 */
#define SECRET_MEMFD_MAX (4u * 1024u * 1024u)

/*
 * Attempt to create a memfd_secret(2) file descriptor (Linux ≥ 5.14,
 * CONFIG_SECRETMEM=y).  Returns the fd on success or -1 with errno=ENOSYS
 * when the kernel does not support it (caller falls back silently).
 *
 * Pages backed by this fd are excluded from the kernel's direct mapping,
 * are unpageable, and do not appear in /proc/kcore or crash dumps.
 */
static int
make_memfd_secret(void)
{
#ifdef __NR_memfd_secret
    return (int)syscall(__NR_memfd_secret, (unsigned long)0);
#else
    errno = ENOSYS;
    return -1;
#endif
}

/*
 * Write 'len' bytes from 'data' into the memfd_secret fd 'sfd', then
 * bind-mount the fd's /proc/self/fd/<n> path read-only onto 'dst_path'.
 *
 * 'sfd' is ALWAYS closed before this function returns (both on success and
 * failure), so the caller must not close it again.
 *
 * Returns 0 on success, -1 on failure (the bind-mount is cleaned up).
 */
static int
bind_mount_memfd_secret(int sfd, const void* data, size_t len,
                        const char* dst_path)
{
    if (ftruncate(sfd, (off_t)len) < 0)
    {
        fprintf(stderr, "oci2bin: memfd_secret ftruncate: %s\n",
                strerror(errno));
        close(sfd);
        return -1;
    }
    if (write_all_fd(sfd, data, len) < 0)
    {
        fprintf(stderr, "oci2bin: memfd_secret write: %s\n",
                strerror(errno));
        close(sfd);
        return -1;
    }
    char proc_path[64];
    int n = snprintf(proc_path, sizeof(proc_path),
                     "/proc/self/fd/%d", sfd);
    if (n < 0 || (size_t)n >= sizeof(proc_path))
    {
        fprintf(stderr, "oci2bin: memfd_secret: fd path overflow\n");
        close(sfd);
        return -1;
    }
    if (mount(proc_path, dst_path, NULL, MS_BIND, NULL) < 0)
    {
        fprintf(stderr,
                "oci2bin: memfd_secret bind mount -> %s: %s\n",
                dst_path, strerror(errno));
        close(sfd);
        return -1;
    }
    if (mount(NULL, dst_path, NULL,
              MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOEXEC | MS_NOSUID | MS_NODEV,
              NULL) < 0)
    {
        fprintf(stderr,
                "oci2bin: memfd_secret remount ro %s: %s\n",
                dst_path, strerror(errno));
        umount2(dst_path, MNT_DETACH);
        close(sfd);
        return -1;
    }
    close(sfd);
    return 0;
}

/*
 * Expose a plain host file as a read-only secret inside the container.
 *
 * Tries memfd_secret first: reads the file into a kernel-protected anonymous
 * memory region and bind-mounts /proc/self/fd/<n> onto dst_path so the
 * container sees a normal path but the data never touches the page cache.
 *
 * Falls back to a standard read-only bind-mount when:
 *   - the kernel lacks memfd_secret (Linux < 5.14)
 *   - the file is larger than SECRET_MEMFD_MAX
 *   - any step in the memfd path fails
 */
static int
install_plain_secret(const char* src, const char* dst, const char* ctr)
{
    int sfd = make_memfd_secret();
    if (sfd >= 0)
    {
        int used_memfd = 0;
        /* Open first, then fstat the fd to avoid a TOCTOU race. */
        int rfd = open(src, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        struct stat st_s;
        if (rfd >= 0 &&
                fstat(rfd, &st_s) == 0 &&
                st_s.st_size >= 0 &&
                (size_t)st_s.st_size <= SECRET_MEMFD_MAX)
        {
            size_t flen = (size_t)st_s.st_size;
            char*  fbuf = malloc(flen + 1);
            if (fbuf)
            {
                /* Use read_all_fd to handle short reads correctly. */
                ssize_t nread = read_all_fd(rfd, fbuf, flen);
                close(rfd);
                rfd = -1;
                if (nread >= 0 && (size_t)nread == flen)
                {
                    if (ensure_bind_mount_target(src, dst, "--secret") == 0)
                    {
                        /* bind_mount_memfd_secret always closes sfd */
                        if (bind_mount_memfd_secret(sfd, fbuf, flen, dst) == 0)
                        {
                            used_memfd = 1;
                            fprintf(stderr,
                                    "oci2bin: secret %s -> %s"
                                    " (memfd_secret)\n",
                                    src, ctr);
                        }
                        sfd = -1; /* closed by bind_mount_memfd_secret */
                    }
                }
                explicit_bzero(fbuf, flen + 1);
                free(fbuf);
            }
        }
        if (rfd >= 0)
        {
            close(rfd);
        }
        if (sfd >= 0)
        {
            close(sfd);
        }
        if (used_memfd)
        {
            return 0;
        }
        /* Fall through to bind-mount on any memfd failure */
    }

    /* Fallback: read-only bind-mount of the host file. */
    if (ensure_bind_mount_target(src, dst, "--secret") < 0)
    {
        return -1;
    }
    if (mount(src, dst, NULL, MS_BIND, NULL) < 0)
    {
        fprintf(stderr, "oci2bin: secret bind mount %s -> %s: %s\n",
                src, ctr, strerror(errno));
        return -1;
    }
    if (mount(NULL, dst, NULL,
              MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOEXEC | MS_NOSUID | MS_NODEV,
              NULL) < 0)
    {
        fprintf(stderr, "oci2bin: secret remount read-only %s: %s\n",
                ctr, strerror(errno));
        if (umount2(dst, MNT_DETACH) < 0)
        {
            fprintf(stderr,
                    "oci2bin: warning: could not unmount writable"
                    " secret %s: %s\n", dst, strerror(errno));
        }
        return -1;
    }
    fprintf(stderr, "oci2bin: secret %s -> %s (read-only)\n", src, ctr);
    return 0;
}

static int install_tpm2_secret(const char* cred_name, const char* dst_path,
                               const char* ctr)
{
    char creds_bin[PATH_MAX];
    if (find_helper_binary("systemd-creds", creds_bin,
                           sizeof(creds_bin)) < 0)
    {
        fprintf(stderr,
                "oci2bin: --secret tpm2:%s requires 'systemd-creds'"
                " (from systemd) but it was not found in PATH\n",
                cred_name);
        return -1;
    }

    char* const argv[] =
    {
        creds_bin, "decrypt", "--name", (char*)(uintptr_t)cred_name,
        "-", "-", NULL
    };
    size_t len = 0;
    char*  plaintext = run_cmd_capture(argv, &len);
    if (!plaintext)
    {
        fprintf(stderr,
                "oci2bin: systemd-creds decrypt failed for credential '%s'\n",
                cred_name);
        return -1;
    }

    /* Prefer memfd_secret (Linux ≥ 5.14): plaintext never reaches the page
     * cache or kernel crash dumps.  Create an empty regular file as the
     * bind-mount target, overlay it with the secretmem fd, then discard. */
    int sfd = make_memfd_secret();
    if (sfd >= 0)
    {
        int tfd = open(dst_path,
                       O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                       0400);
        if (tfd < 0)
        {
            fprintf(stderr,
                    "oci2bin: cannot create secret target %s: %s\n",
                    dst_path, strerror(errno));
            close(sfd);
            explicit_bzero(plaintext, len);
            free(plaintext);
            return -1;
        }
        close(tfd);
        /* bind_mount_memfd_secret always closes sfd */
        int rc = bind_mount_memfd_secret(sfd, plaintext, len, dst_path);
        explicit_bzero(plaintext, len);
        free(plaintext);
        if (rc == 0)
        {
            fprintf(stderr,
                    "oci2bin: tpm2 secret '%s' -> %s (memfd_secret)\n",
                    cred_name, ctr);
        }
        return rc;
    }

    /* Fallback: write plaintext to a regular file inside rootfs. */
    int fd = open(dst_path,
                  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                  0400);
    if (fd < 0)
    {
        fprintf(stderr, "oci2bin: cannot create secret file %s: %s\n",
                dst_path, strerror(errno));
        explicit_bzero(plaintext, len);
        free(plaintext);
        return -1;
    }
    int rc = 0;
    if (write_all_fd(fd, plaintext, len) < 0)
    {
        fprintf(stderr, "oci2bin: write secret %s failed: %s\n",
                dst_path, strerror(errno));
        rc = -1;
    }
    close(fd);
    explicit_bzero(plaintext, len);
    free(plaintext);
    if (rc == 0)
    {
        fprintf(stderr, "oci2bin: tpm2 secret '%s' -> %s (read-only)\n",
                cred_name, ctr);
    }
    return rc;
}

static void setup_secrets(const char* rootfs, struct container_opts *opts)
{
    if (opts->n_secrets == 0)
    {
        return;
    }

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
    if (mkdir_p_secure(run_dir, 0755, "--secret") < 0 ||
            mkdir_p_secure(run_secrets, 0700, "--secret") < 0)
    {
        return;
    }

    for (int i = 0; i < opts->n_secrets; i++)
    {
        const char* cred = opts->secret_cred[i]; /* non-NULL = TPM2 path */
        const char* src  = opts->secret_host[i];
        const char* ctr  = opts->secret_ctr[i]; /* may be NULL */

        /* Derive container path for both plain-file and tpm2 secrets */
        char ctr_buf[PATH_MAX];
        if (ctr)
        {
            if (!path_is_absolute_and_clean(ctr))
            {
                fprintf(stderr,
                        "oci2bin: --secret container path must be absolute"
                        " and clean: %s\n", ctr);
                continue;
            }
        }
        else
        {
            /* Default: /run/secrets/<cred name or src basename> */
            const char* base = cred ? cred : strrchr(src, '/');
            if (!cred)
            {
                base = base ? base + 1 : src;
            }
            if (!base || base[0] == '\0')
            {
                fprintf(stderr,
                        "oci2bin: --secret cannot derive basename\n");
                continue;
            }
            int n = snprintf(ctr_buf, sizeof(ctr_buf), "/run/secrets/%s", base);
            if (n < 0 || (size_t)n >= sizeof(ctr_buf))
            {
                fprintf(stderr,
                        "oci2bin: --secret container path too long\n");
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

        if (cred)
        {
            /* TPM2-sealed secret: decrypt and install (memfd_secret or file) */
            install_tpm2_secret(cred, dst, ctr);
            continue;
        }

        /* Plain-file secret: validate host path then install. */
        if (!path_is_absolute_and_clean(src))
        {
            fprintf(stderr,
                    "oci2bin: --secret host path must be absolute and clean: %s\n",
                    src);
            continue;
        }

        install_plain_secret(src, dst, ctr);
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

static unsigned long long current_effective_caps(void)
{
    struct cap_header hdr;
    struct cap_data   data[2];

    memset(&hdr, 0, sizeof(hdr));
    memset(data, 0, sizeof(data));
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid     = 0;
    if (syscall(SYS_capget, &hdr, data) < 0)
    {
        return 0;
    }
    return ((unsigned long long)data[1].effective << 32) |
           (unsigned long long)data[0].effective;
}

static void audit_emit_cap_set_event(const struct container_opts* opts)
{
    char extra[192];
    unsigned long long caps = current_effective_caps();

    snprintf(extra, sizeof(extra),
             "\"caps\":\"0x%llx\",\"drop_all\":%s,"
             "\"drop_mask\":\"0x%llx\",\"add_mask\":\"0x%llx\"",
             caps,
             opts->cap_drop_all ? "true" : "false",
             (unsigned long long)opts->cap_drop_mask,
             (unsigned long long)opts->cap_add_mask);
    audit_emit("cap_set", extra);
}

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

    audit_emit_cap_set_event(opts);
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
        audit_emit_wait_status("exit", child, child_status);
        return WEXITSTATUS(child_status);
    }
    if (WIFSIGNALED(child_status))
    {
        audit_emit_wait_status("exit", child, child_status);
        return 128 + WTERMSIG(child_status);
    }
    audit_emit_wait_status("exit", child, child_status);
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

/*
 * Apply a Docker-compatible JSON seccomp profile from a file.
 *
 * Docker profile format (subset we support):
 *   {
 *     "defaultAction": "SCMP_ACT_ERRNO" | "SCMP_ACT_ALLOW" | "SCMP_ACT_KILL",
 *     "syscalls": [
 *       { "names": ["read","write",...], "action": "SCMP_ACT_ALLOW" }
 *     ]
 *   }
 *
 * We parse the JSON manually (no external deps) and build a BPF program that:
 * - If defaultAction=ALLOW: only block explicitly denied syscalls.
 * - If defaultAction=ERRNO/KILL: only allow explicitly listed syscalls.
 *
 * For defaultAction=ALLOW we emit BPF_BLOCK for each denied syscall.
 * For defaultAction=KILL/ERRNO we build an allowlist (more complex BPF).
 *
 * To keep the BPF program size reasonable we limit to at most 256 syscall
 * rules.  PR_SET_NO_NEW_PRIVS is always set.
 *
 * Returns 0 on success, -1 on error (non-fatal: caller should warn and
 * fall through to the built-in default filter).
 */

/* Static syscall name→number table (x86_64 and aarch64 common subset). */
struct sc_entry
{
    const char* name;
    int         nr;
};

/* We include the platform headers to get __NR_* numbers. */
static const struct sc_entry g_syscall_table[] =
{
#define S(name) { #name, __NR_##name }
#ifdef __NR_read
    S(read),
#endif
#ifdef __NR_write
    S(write),
#endif
#ifdef __NR_open
    S(open),
#endif
#ifdef __NR_close
    S(close),
#endif
#ifdef __NR_stat
    S(stat),
#endif
#ifdef __NR_fstat
    S(fstat),
#endif
#ifdef __NR_lstat
    S(lstat),
#endif
#ifdef __NR_poll
    S(poll),
#endif
#ifdef __NR_lseek
    S(lseek),
#endif
#ifdef __NR_mmap
    S(mmap),
#endif
#ifdef __NR_mprotect
    S(mprotect),
#endif
#ifdef __NR_munmap
    S(munmap),
#endif
#ifdef __NR_brk
    S(brk),
#endif
#ifdef __NR_rt_sigaction
    S(rt_sigaction),
#endif
#ifdef __NR_rt_sigprocmask
    S(rt_sigprocmask),
#endif
#ifdef __NR_rt_sigreturn
    S(rt_sigreturn),
#endif
#ifdef __NR_ioctl
    S(ioctl),
#endif
#ifdef __NR_pread64
    S(pread64),
#endif
#ifdef __NR_pwrite64
    S(pwrite64),
#endif
#ifdef __NR_readv
    S(readv),
#endif
#ifdef __NR_writev
    S(writev),
#endif
#ifdef __NR_access
    S(access),
#endif
#ifdef __NR_pipe
    S(pipe),
#endif
#ifdef __NR_select
    S(select),
#endif
#ifdef __NR_sched_yield
    S(sched_yield),
#endif
#ifdef __NR_mremap
    S(mremap),
#endif
#ifdef __NR_msync
    S(msync),
#endif
#ifdef __NR_mincore
    S(mincore),
#endif
#ifdef __NR_madvise
    S(madvise),
#endif
#ifdef __NR_dup
    S(dup),
#endif
#ifdef __NR_dup2
    S(dup2),
#endif
#ifdef __NR_pause
    S(pause),
#endif
#ifdef __NR_nanosleep
    S(nanosleep),
#endif
#ifdef __NR_getitimer
    S(getitimer),
#endif
#ifdef __NR_alarm
    S(alarm),
#endif
#ifdef __NR_setitimer
    S(setitimer),
#endif
#ifdef __NR_getpid
    S(getpid),
#endif
#ifdef __NR_sendfile
    S(sendfile),
#endif
#ifdef __NR_socket
    S(socket),
#endif
#ifdef __NR_connect
    S(connect),
#endif
#ifdef __NR_accept
    S(accept),
#endif
#ifdef __NR_sendto
    S(sendto),
#endif
#ifdef __NR_recvfrom
    S(recvfrom),
#endif
#ifdef __NR_sendmsg
    S(sendmsg),
#endif
#ifdef __NR_recvmsg
    S(recvmsg),
#endif
#ifdef __NR_shutdown
    S(shutdown),
#endif
#ifdef __NR_bind
    S(bind),
#endif
#ifdef __NR_listen
    S(listen),
#endif
#ifdef __NR_getsockname
    S(getsockname),
#endif
#ifdef __NR_getpeername
    S(getpeername),
#endif
#ifdef __NR_socketpair
    S(socketpair),
#endif
#ifdef __NR_setsockopt
    S(setsockopt),
#endif
#ifdef __NR_getsockopt
    S(getsockopt),
#endif
#ifdef __NR_clone
    S(clone),
#endif
#ifdef __NR_fork
    S(fork),
#endif
#ifdef __NR_vfork
    S(vfork),
#endif
#ifdef __NR_execve
    S(execve),
#endif
#ifdef __NR_exit
    S(exit),
#endif
#ifdef __NR_wait4
    S(wait4),
#endif
#ifdef __NR_kill
    S(kill),
#endif
#ifdef __NR_uname
    S(uname),
#endif
#ifdef __NR_fcntl
    S(fcntl),
#endif
#ifdef __NR_flock
    S(flock),
#endif
#ifdef __NR_fsync
    S(fsync),
#endif
#ifdef __NR_fdatasync
    S(fdatasync),
#endif
#ifdef __NR_truncate
    S(truncate),
#endif
#ifdef __NR_ftruncate
    S(ftruncate),
#endif
#ifdef __NR_getdents
    S(getdents),
#endif
#ifdef __NR_getcwd
    S(getcwd),
#endif
#ifdef __NR_chdir
    S(chdir),
#endif
#ifdef __NR_fchdir
    S(fchdir),
#endif
#ifdef __NR_rename
    S(rename),
#endif
#ifdef __NR_mkdir
    S(mkdir),
#endif
#ifdef __NR_rmdir
    S(rmdir),
#endif
#ifdef __NR_creat
    S(creat),
#endif
#ifdef __NR_link
    S(link),
#endif
#ifdef __NR_unlink
    S(unlink),
#endif
#ifdef __NR_symlink
    S(symlink),
#endif
#ifdef __NR_readlink
    S(readlink),
#endif
#ifdef __NR_chmod
    S(chmod),
#endif
#ifdef __NR_fchmod
    S(fchmod),
#endif
#ifdef __NR_chown
    S(chown),
#endif
#ifdef __NR_fchown
    S(fchown),
#endif
#ifdef __NR_lchown
    S(lchown),
#endif
#ifdef __NR_umask
    S(umask),
#endif
#ifdef __NR_gettimeofday
    S(gettimeofday),
#endif
#ifdef __NR_getrlimit
    S(getrlimit),
#endif
#ifdef __NR_getrusage
    S(getrusage),
#endif
#ifdef __NR_sysinfo
    S(sysinfo),
#endif
#ifdef __NR_times
    S(times),
#endif
#ifdef __NR_getuid
    S(getuid),
#endif
#ifdef __NR_syslog
    S(syslog),
#endif
#ifdef __NR_getgid
    S(getgid),
#endif
#ifdef __NR_setuid
    S(setuid),
#endif
#ifdef __NR_setgid
    S(setgid),
#endif
#ifdef __NR_geteuid
    S(geteuid),
#endif
#ifdef __NR_getegid
    S(getegid),
#endif
#ifdef __NR_setpgid
    S(setpgid),
#endif
#ifdef __NR_getppid
    S(getppid),
#endif
#ifdef __NR_getpgrp
    S(getpgrp),
#endif
#ifdef __NR_setsid
    S(setsid),
#endif
#ifdef __NR_setreuid
    S(setreuid),
#endif
#ifdef __NR_setregid
    S(setregid),
#endif
#ifdef __NR_getgroups
    S(getgroups),
#endif
#ifdef __NR_setgroups
    S(setgroups),
#endif
#ifdef __NR_setresuid
    S(setresuid),
#endif
#ifdef __NR_getresuid
    S(getresuid),
#endif
#ifdef __NR_setresgid
    S(setresgid),
#endif
#ifdef __NR_getresgid
    S(getresgid),
#endif
#ifdef __NR_getpgid
    S(getpgid),
#endif
#ifdef __NR_setfsuid
    S(setfsuid),
#endif
#ifdef __NR_setfsgid
    S(setfsgid),
#endif
#ifdef __NR_getsid
    S(getsid),
#endif
#ifdef __NR_rt_sigsuspend
    S(rt_sigsuspend),
#endif
#ifdef __NR_sigaltstack
    S(sigaltstack),
#endif
#ifdef __NR_mknod
    S(mknod),
#endif
#ifdef __NR_personality
    S(personality),
#endif
#ifdef __NR_statfs
    S(statfs),
#endif
#ifdef __NR_fstatfs
    S(fstatfs),
#endif
#ifdef __NR_getpriority
    S(getpriority),
#endif
#ifdef __NR_setpriority
    S(setpriority),
#endif
#ifdef __NR_sched_setparam
    S(sched_setparam),
#endif
#ifdef __NR_sched_getparam
    S(sched_getparam),
#endif
#ifdef __NR_sched_setscheduler
    S(sched_setscheduler),
#endif
#ifdef __NR_sched_getscheduler
    S(sched_getscheduler),
#endif
#ifdef __NR_sched_get_priority_max
    S(sched_get_priority_max),
#endif
#ifdef __NR_sched_get_priority_min
    S(sched_get_priority_min),
#endif
#ifdef __NR_sched_rr_get_interval
    S(sched_rr_get_interval),
#endif
#ifdef __NR_mlock
    S(mlock),
#endif
#ifdef __NR_munlock
    S(munlock),
#endif
#ifdef __NR_mlockall
    S(mlockall),
#endif
#ifdef __NR_munlockall
    S(munlockall),
#endif
#ifdef __NR_vhangup
    S(vhangup),
#endif
#ifdef __NR_prctl
    S(prctl),
#endif
#ifdef __NR_arch_prctl
    S(arch_prctl),
#endif
#ifdef __NR_setrlimit
    S(setrlimit),
#endif
#ifdef __NR_chroot
    S(chroot),
#endif
#ifdef __NR_sync
    S(sync),
#endif
#ifdef __NR_acct
    S(acct),
#endif
#ifdef __NR_mount
    S(mount),
#endif
#ifdef __NR_umount2
    S(umount2),
#endif
#ifdef __NR_swapon
    S(swapon),
#endif
#ifdef __NR_swapoff
    S(swapoff),
#endif
#ifdef __NR_gettid
    S(gettid),
#endif
#ifdef __NR_futex
    S(futex),
#endif
#ifdef __NR_sched_setaffinity
    S(sched_setaffinity),
#endif
#ifdef __NR_sched_getaffinity
    S(sched_getaffinity),
#endif
#ifdef __NR_set_thread_area
    S(set_thread_area),
#endif
#ifdef __NR_get_thread_area
    S(get_thread_area),
#endif
#ifdef __NR_epoll_create
    S(epoll_create),
#endif
#ifdef __NR_epoll_ctl_old
    S(epoll_ctl_old),
#endif
#ifdef __NR_epoll_wait_old
    S(epoll_wait_old),
#endif
#ifdef __NR_set_tid_address
    S(set_tid_address),
#endif
#ifdef __NR_restart_syscall
    S(restart_syscall),
#endif
#ifdef __NR_semtimedop
    S(semtimedop),
#endif
#ifdef __NR_fadvise64
    S(fadvise64),
#endif
#ifdef __NR_timer_create
    S(timer_create),
#endif
#ifdef __NR_timer_settime
    S(timer_settime),
#endif
#ifdef __NR_timer_gettime
    S(timer_gettime),
#endif
#ifdef __NR_timer_getoverrun
    S(timer_getoverrun),
#endif
#ifdef __NR_timer_delete
    S(timer_delete),
#endif
#ifdef __NR_clock_settime
    S(clock_settime),
#endif
#ifdef __NR_clock_gettime
    S(clock_gettime),
#endif
#ifdef __NR_clock_getres
    S(clock_getres),
#endif
#ifdef __NR_clock_nanosleep
    S(clock_nanosleep),
#endif
#ifdef __NR_exit_group
    S(exit_group),
#endif
#ifdef __NR_epoll_wait
    S(epoll_wait),
#endif
#ifdef __NR_epoll_ctl
    S(epoll_ctl),
#endif
#ifdef __NR_tgkill
    S(tgkill),
#endif
#ifdef __NR_utimes
    S(utimes),
#endif
#ifdef __NR_mbind
    S(mbind),
#endif
#ifdef __NR_set_mempolicy
    S(set_mempolicy),
#endif
#ifdef __NR_get_mempolicy
    S(get_mempolicy),
#endif
#ifdef __NR_waitid
    S(waitid),
#endif
#ifdef __NR_ioprio_set
    S(ioprio_set),
#endif
#ifdef __NR_ioprio_get
    S(ioprio_get),
#endif
#ifdef __NR_inotify_init
    S(inotify_init),
#endif
#ifdef __NR_inotify_add_watch
    S(inotify_add_watch),
#endif
#ifdef __NR_inotify_rm_watch
    S(inotify_rm_watch),
#endif
#ifdef __NR_openat
    S(openat),
#endif
#ifdef __NR_mkdirat
    S(mkdirat),
#endif
#ifdef __NR_mknodat
    S(mknodat),
#endif
#ifdef __NR_fchownat
    S(fchownat),
#endif
#ifdef __NR_futimesat
    S(futimesat),
#endif
#ifdef __NR_newfstatat
    S(newfstatat),
#endif
#ifdef __NR_unlinkat
    S(unlinkat),
#endif
#ifdef __NR_renameat
    S(renameat),
#endif
#ifdef __NR_linkat
    S(linkat),
#endif
#ifdef __NR_symlinkat
    S(symlinkat),
#endif
#ifdef __NR_readlinkat
    S(readlinkat),
#endif
#ifdef __NR_fchmodat
    S(fchmodat),
#endif
#ifdef __NR_faccessat
    S(faccessat),
#endif
#ifdef __NR_pselect6
    S(pselect6),
#endif
#ifdef __NR_ppoll
    S(ppoll),
#endif
#ifdef __NR_unshare
    S(unshare),
#endif
#ifdef __NR_set_robust_list
    S(set_robust_list),
#endif
#ifdef __NR_get_robust_list
    S(get_robust_list),
#endif
#ifdef __NR_splice
    S(splice),
#endif
#ifdef __NR_tee
    S(tee),
#endif
#ifdef __NR_sync_file_range
    S(sync_file_range),
#endif
#ifdef __NR_vmsplice
    S(vmsplice),
#endif
#ifdef __NR_move_pages
    S(move_pages),
#endif
#ifdef __NR_utimensat
    S(utimensat),
#endif
#ifdef __NR_epoll_pwait
    S(epoll_pwait),
#endif
#ifdef __NR_signalfd
    S(signalfd),
#endif
#ifdef __NR_timerfd_create
    S(timerfd_create),
#endif
#ifdef __NR_eventfd
    S(eventfd),
#endif
#ifdef __NR_fallocate
    S(fallocate),
#endif
#ifdef __NR_timerfd_settime
    S(timerfd_settime),
#endif
#ifdef __NR_timerfd_gettime
    S(timerfd_gettime),
#endif
#ifdef __NR_accept4
    S(accept4),
#endif
#ifdef __NR_signalfd4
    S(signalfd4),
#endif
#ifdef __NR_eventfd2
    S(eventfd2),
#endif
#ifdef __NR_epoll_create1
    S(epoll_create1),
#endif
#ifdef __NR_dup3
    S(dup3),
#endif
#ifdef __NR_pipe2
    S(pipe2),
#endif
#ifdef __NR_inotify_init1
    S(inotify_init1),
#endif
#ifdef __NR_preadv
    S(preadv),
#endif
#ifdef __NR_pwritev
    S(pwritev),
#endif
#ifdef __NR_rt_tgsigqueueinfo
    S(rt_tgsigqueueinfo),
#endif
#ifdef __NR_prlimit64
    S(prlimit64),
#endif
#ifdef __NR_fanotify_init
    S(fanotify_init),
#endif
#ifdef __NR_fanotify_mark
    S(fanotify_mark),
#endif
#ifdef __NR_name_to_handle_at
    S(name_to_handle_at),
#endif
#ifdef __NR_open_by_handle_at
    S(open_by_handle_at),
#endif
#ifdef __NR_clock_adjtime
    S(clock_adjtime),
#endif
#ifdef __NR_syncfs
    S(syncfs),
#endif
#ifdef __NR_sendmmsg
    S(sendmmsg),
#endif
#ifdef __NR_setns
    S(setns),
#endif
#ifdef __NR_getcpu
    S(getcpu),
#endif
#ifdef __NR_process_vm_readv
    S(process_vm_readv),
#endif
#ifdef __NR_process_vm_writev
    S(process_vm_writev),
#endif
#ifdef __NR_kcmp
    S(kcmp),
#endif
#ifdef __NR_finit_module
    S(finit_module),
#endif
#ifdef __NR_sched_setattr
    S(sched_setattr),
#endif
#ifdef __NR_sched_getattr
    S(sched_getattr),
#endif
#ifdef __NR_renameat2
    S(renameat2),
#endif
#ifdef __NR_seccomp
    S(seccomp),
#endif
#ifdef __NR_getrandom
    S(getrandom),
#endif
#ifdef __NR_memfd_create
    S(memfd_create),
#endif
#ifdef __NR_execveat
    S(execveat),
#endif
#ifdef __NR_copy_file_range
    S(copy_file_range),
#endif
#ifdef __NR_preadv2
    S(preadv2),
#endif
#ifdef __NR_pwritev2
    S(pwritev2),
#endif
#ifdef __NR_statx
    S(statx),
#endif
#ifdef __NR_io_uring_setup
    S(io_uring_setup),
#endif
#ifdef __NR_io_uring_enter
    S(io_uring_enter),
#endif
#ifdef __NR_io_uring_register
    S(io_uring_register),
#endif
#ifdef __NR_clone3
    S(clone3),
#endif
#ifdef __NR_close_range
    S(close_range),
#endif
#ifdef __NR_openat2
    S(openat2),
#endif
#ifdef __NR_faccessat2
    S(faccessat2),
#endif
#ifdef __NR_landlock_create_ruleset
    S(landlock_create_ruleset),
#endif
#ifdef __NR_landlock_add_rule
    S(landlock_add_rule),
#endif
#ifdef __NR_landlock_restrict_self
    S(landlock_restrict_self),
#endif
#undef S
};

static const int g_syscall_table_size =
    (int)(sizeof(g_syscall_table) / sizeof(g_syscall_table[0]));

/* Look up a syscall name and return its number, or -1 if not found. */
static int syscall_name_to_nr(const char* name)
{
    for (int i = 0; i < g_syscall_table_size; i++)
    {
        if (strcmp(g_syscall_table[i].name, name) == 0)
        {
            return g_syscall_table[i].nr;
        }
    }
    return -1;
}

/* ── --gen-seccomp: ptrace-based syscall profiler ────────────────────────── */

/*
 * Per-PID in-syscall toggle.  ptrace delivers entry and exit stops alternately;
 * we only record the entry stop.  Track up to 256 concurrent PIDs — more than
 * enough for typical container workloads.
 */
#define GEN_SECCOMP_MAX_PIDS 256

struct gs_pid_state
{
    pid_t pid;
    int   in_syscall; /* 1 after entry stop, 0 after exit stop */
};

static int gs_pid_in_syscall(struct gs_pid_state* states, int* n,
                             pid_t pid)
{
    for (int i = 0; i < *n; i++)
    {
        if (states[i].pid == pid)
        {
            return states[i].in_syscall;
        }
    }
    /* New PID — not yet in table; starts at entry (0) */
    if (*n < GEN_SECCOMP_MAX_PIDS)
    {
        states[(*n)].pid        = pid;
        states[(*n)].in_syscall = 0;
        (*n)++;
    }
    return 0;
}

static void gs_pid_toggle(struct gs_pid_state* states, int n, pid_t pid)
{
    for (int i = 0; i < n; i++)
    {
        if (states[i].pid == pid)
        {
            states[i].in_syscall ^= 1;
            return;
        }
    }
}

/*
 * Run exec_args under ptrace, collect every unique syscall number the workload
 * makes, then write a Docker-compatible JSON allowlist to out_path.
 * Returns the child's exit code (or 1 on tracer error).
 */
static int do_gen_seccomp(const char* out_path, char* const* exec_args)
{
    /* Bitset: seen[nr/8] bit (nr%8) = syscall nr was observed */
    unsigned char seen[64];
    memset(seen, 0, sizeof(seen));

    fprintf(stderr,
            "oci2bin: --gen-seccomp: tracing container (output → %s)\n",
            out_path);
    fprintf(stderr,
            "oci2bin: --gen-seccomp: run the container workload normally,"
            " then exit\n");

    pid_t child = fork();
    if (child < 0)
    {
        perror("oci2bin: --gen-seccomp: fork");
        return 1;
    }

    if (child == 0)
    {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
        {
            perror("oci2bin: --gen-seccomp: ptrace TRACEME");
            _exit(1);
        }
        execvp(exec_args[0], exec_args);
        perror(exec_args[0]);
        _exit(127);
    }

    /* Wait for the initial SIGTRAP raised by the kernel on exec */
    int status;
    if (waitpid(child, &status, 0) < 0)
    {
        perror("oci2bin: --gen-seccomp: waitpid");
        return 1;
    }

    /* TRACESYSGOOD: syscall stops get SIGTRAP|0x80 so we can distinguish them
     * from real SIGTRAPs.  TRACEFORK/CLONE: auto-attach forked children. */
    long opts = PTRACE_O_TRACESYSGOOD |
                PTRACE_O_TRACEFORK    |
                PTRACE_O_TRACEVFORK   |
                PTRACE_O_TRACECLONE   |
                PTRACE_O_TRACEEXEC;
    if (ptrace(PTRACE_SETOPTIONS, child, NULL, (void*)opts) < 0)
    {
        perror("oci2bin: --gen-seccomp: PTRACE_SETOPTIONS");
    }
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);

    struct gs_pid_state pid_states[GEN_SECCOMP_MAX_PIDS];
    int n_pid_states = 0;
    int child_exit   = 0;

    for (;;)
    {
        pid_t stopped = waitpid(-1, &status, 0);
        if (stopped < 0)
        {
            break;
        }

        if (WIFEXITED(status))
        {
            if (stopped == child)
            {
                child_exit = WEXITSTATUS(status);
                break;
            }
            continue;
        }
        if (WIFSIGNALED(status))
        {
            if (stopped == child)
            {
                child_exit = 1;
                break;
            }
            continue;
        }
        if (!WIFSTOPPED(status))
        {
            continue;
        }

        int  sig          = WSTOPSIG(status);
        int  ptrace_event = (status >> 16) & 0xff;

        if (ptrace_event != 0)
        {
            /* fork/clone/exec event; new tracee is already attached */
            ptrace(PTRACE_SYSCALL, stopped, NULL, NULL);
            continue;
        }

        if (sig == (SIGTRAP | 0x80))
        {
            /* Syscall entry or exit stop */
            int was_in = gs_pid_in_syscall(pid_states, &n_pid_states, stopped);
            gs_pid_toggle(pid_states, n_pid_states, stopped);

            if (!was_in)
            {
                /* Entry stop — read the syscall number */
                long nr = -1;
#ifdef __aarch64__
                struct iovec iov;
                struct user_pt_regs aregs;
                iov.iov_base = &aregs;
                iov.iov_len  = sizeof(aregs);
                if (ptrace(PTRACE_GETREGSET, stopped,
                           (void*)(long)NT_PRSTATUS, &iov) == 0)
                {
                    nr = (long)aregs.regs[8]; /* x8 = syscall nr on aarch64 */
                }
#else
                struct user_regs_struct regs;
                if (ptrace(PTRACE_GETREGS, stopped, NULL, &regs) == 0)
                {
                    nr = (long)regs.orig_rax;
                }
#endif
                if (nr >= 0 && nr < (long)(sizeof(seen) * 8))
                {
                    seen[nr / 8] |= (unsigned char)(1u << (nr % 8));
                }
            }
            ptrace(PTRACE_SYSCALL, stopped, NULL, NULL);
        }
        else if (sig == SIGTRAP)
        {
            /* Exec-stop or other SIGTRAP — don't forward SIGTRAP */
            ptrace(PTRACE_SYSCALL, stopped, NULL, NULL);
        }
        else
        {
            /* Real signal — deliver it to the tracee */
            ptrace(PTRACE_SYSCALL, stopped, NULL, (void*)(long)sig);
        }
    }

    /* Map observed syscall numbers to names via g_syscall_table */
    const char* names[512];
    int         n_names = 0;

    for (int nr = 0; nr < (int)(sizeof(seen) * 8); nr++)
    {
        if (!(seen[nr / 8] & (1u << (nr % 8))))
        {
            continue;
        }
        for (int i = 0; i < g_syscall_table_size; i++)
        {
            if (g_syscall_table[i].nr == nr)
            {
                if (n_names < (int)(sizeof(names) / sizeof(names[0])))
                {
                    names[n_names++] = g_syscall_table[i].name;
                }
                break;
            }
        }
    }

    /* Emit Docker-compatible JSON seccomp profile */
    FILE* f = fopen(out_path, "w");
    if (!f)
    {
        fprintf(stderr, "oci2bin: --gen-seccomp: cannot write %s: %s\n",
                out_path, strerror(errno));
        return child_exit;
    }

    fprintf(f, "{\n");
    fprintf(f, "  \"defaultAction\": \"SCMP_ACT_ERRNO\",\n");
    fprintf(f, "  \"syscalls\": [\n");
    fprintf(f, "    {\n");
    fprintf(f, "      \"names\": [\n");
    for (int i = 0; i < n_names; i++)
    {
        fprintf(f, "        \"%s\"%s\n", names[i],
                i < n_names - 1 ? "," : "");
    }
    fprintf(f, "      ],\n");
    fprintf(f, "      \"action\": \"SCMP_ACT_ALLOW\"\n");
    fprintf(f, "    }\n");
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    fclose(f);

    fprintf(stderr,
            "oci2bin: --gen-seccomp: %d syscalls observed → %s\n"
            "oci2bin: --gen-seccomp: use with: --seccomp-profile %s\n",
            n_names, out_path, out_path);
    return child_exit;
}



/*
 * Parse a JSON string array value: ["a","b","c"].
 * Returns array of malloc'd strings.  *out_n is set to count.
 * Caller must free each string and the array.
 */
static char** json_parse_names_array(const char* json, const char* key,
                                     int* out_n)
{
    *out_n = 0;
    const char* p = json_skip_to_value(json, key);
    if (!p || *p != '[')
    {
        return NULL;
    }
    p++; /* skip '[' */

    /* Count items first */
    int count = 0;
    const char* scan = p;
    while (*scan && *scan != ']')
    {
        while (*scan == ' ' || *scan == ',' || *scan == '\n')
        {
            scan++;
        }
        if (!*scan)
        {
            break;    /* truncated input — NUL before ']' */
        }
        if (*scan == '"')
        {
            scan++;
            while (*scan && *scan != '"')
            {
                if (*scan == '\\')
                {
                    scan++;
                }
                if (*scan)
                {
                    scan++;
                }
            }
            if (*scan == '"')
            {
                scan++;
            }
            count++;
        }
        else if (*scan == ']')
        {
            break;
        }
        else
        {
            scan++;
        }
    }
    if (count == 0)
    {
        return NULL;
    }

    char** arr = calloc((size_t)count, sizeof(char*));
    if (!arr)
    {
        return NULL;
    }

    int idx = 0;
    while (*p && *p != ']' && idx < count)
    {
        while (*p == ' ' || *p == ',' || *p == '\n')
        {
            p++;
        }
        if (!*p)
        {
            break;    /* truncated input */
        }
        if (*p == '"')
        {
            p++;
            const char* end = p;
            while (*end && *end != '"')
            {
                if (*end == '\\')
                {
                    end++;
                    if (*end)
                    {
                        end++;
                    }
                }
                else
                {
                    end++;
                }
            }
            size_t len = (size_t)(end - p);
            arr[idx] = malloc(len + 1);
            if (arr[idx])
            {
                memcpy(arr[idx], p, len);
                arr[idx][len] = '\0';
                idx++;
            }
            if (*end == '"')
            {
                p = end + 1;
            }
        }
        else if (*p == ']')
        {
            break;
        }
        else
        {
            p++;
        }
    }
    *out_n = idx;
    return arr;
}

/*
 * Apply a Docker-compatible JSON seccomp profile.
 * Returns 0 on success, -1 on error.
 */
static int apply_seccomp_profile(const char* profile_path)
{
#ifdef __aarch64__
#define MY_AUDIT_ARCH_PROFILE AUDIT_ARCH_AARCH64
#else
#define MY_AUDIT_ARCH_PROFILE AUDIT_ARCH_X86_64
#endif

    size_t json_sz = 0;
    char* json = read_file(profile_path, &json_sz);
    if (!json)
    {
        fprintf(stderr, "oci2bin: --seccomp-profile: cannot read '%s': %s\n",
                profile_path, strerror(errno));
        return -1;
    }

    /* Determine defaultAction */
    char* default_action_str = json_get_string(json, "defaultAction");
    if (!default_action_str)
    {
        fprintf(stderr,
                "oci2bin: --seccomp-profile: missing 'defaultAction' field\n");
        free(json);
        return -1;
    }

    /* 0=ALLOW (allowlist needed), 1=ERRNO/KILL (denylist) */
    int default_is_allow = (strstr(default_action_str, "ALLOW") != NULL);
    free(default_action_str);

    /* We support up to 256 syscall numbers from the profile */
    int listed_nrs[256];
    int n_listed = 0;
    int listed_is_allow = -1; /* -1 = unset; 0 = deny; 1 = allow */
    int mixed_actions   = 0;  /* set if profile has conflicting entry actions */

    /* Find each "syscalls" entry object and collect names+action */
    const char* p = json;
    while ((p = strstr(p, "\"names\"")) != NULL)
    {
        /* Get the action for this entry by looking for "action" nearby */
        const char* action_search = p;
        const char* action_end   = strstr(p, "},");
        if (!action_end)
        {
            action_end = strstr(p, "}");
        }
        char action_buf[64] = {0};
        const char* akey = strstr(action_search, "\"action\"");
        if (akey && (!action_end || akey < action_end + 64))
        {
            /* Extract action value */
            akey += 8; /* skip "action" */
            while (*akey == ' ' || *akey == ':' || *akey == '\t')
            {
                akey++;
            }
            if (*akey == '"')
            {
                akey++;
                int ai = 0;
                while (*akey && *akey != '"' && ai < 62)
                {
                    action_buf[ai++] = *akey++;
                }
                action_buf[ai] = '\0';
            }
        }

        int entry_allow = (strstr(action_buf, "ALLOW") != NULL);

        /* Detect mixed actions across entries — we only support a single
         * uniform action across all "syscalls" entries.  If different
         * entries have different actions (e.g. one ALLOW, one ERRNO) the
         * single listed_is_allow flag cannot represent both correctly, so
         * record the conflict and fall back to the built-in filter. */
        if (listed_is_allow == -1)
        {
            listed_is_allow = entry_allow;
        }
        else if (listed_is_allow != entry_allow)
        {
            mixed_actions = 1;
        }

        /* Parse names array at current position */
        int n_names = 0;
        char** names = json_parse_names_array(p, "names", &n_names);
        if (names)
        {
            for (int ni = 0; ni < n_names; ni++)
            {
                if (n_listed < 256)
                {
                    int nr = syscall_name_to_nr(names[ni]);
                    if (nr >= 0)
                    {
                        listed_nrs[n_listed++] = nr;
                    }
                }
                free(names[ni]);
            }
            free(names);
        }

        p++;
    }

    if (listed_is_allow == -1)
    {
        listed_is_allow = 0; /* default: treat unlabelled entries as deny */
    }

    if (mixed_actions)
    {
        fprintf(stderr,
                "oci2bin: --seccomp-profile: profile has mixed ALLOW/DENY"
                " entry actions which are not supported; falling back to"
                " built-in filter\n");
        free(json);
        return -1;
    }

    free(json);

    /* PR_SET_NO_NEW_PRIVS */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
    {
        fprintf(stderr,
                "oci2bin: prctl(PR_SET_NO_NEW_PRIVS) failed: %s (non-fatal)\n",
                strerror(errno));
    }

    if (n_listed == 0)
    {
        /* No rules — just apply the default */
        if (!default_is_allow)
        {
            /* defaultAction=KILL with no exceptions: block all.
             * Use a minimal filter that kills every syscall. */
            struct sock_filter kill_all[] =
            {
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
            };
            struct sock_fprog prog2 =
            {
                .len = 1, .filter = kill_all
            };
            if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                        SECCOMP_FILTER_FLAG_TSYNC, &prog2) == 0 ||
                    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog2) == 0)
            {
                fprintf(stderr,
                        "oci2bin: seccomp profile applied (kill-all)\n");
                return 0;
            }
        }
        /* defaultAction=ALLOW with no exceptions: allow all — no filter needed */
        return 0;
    }

    /*
     * Build BPF program.
     * Each instruction is a struct sock_filter (8 bytes).
     * Maximum size: arch check (3) + load nr (1) + per-syscall (2 each) + default (1)
     * = 4 + 2*n_listed + 1
     */
    int max_insns = 4 + 2 * n_listed + 1;
    struct sock_filter* filter = calloc((size_t)max_insns,
                                        sizeof(struct sock_filter));
    if (!filter)
    {
        fprintf(stderr, "oci2bin: --seccomp-profile: out of memory\n");
        return -1;
    }

    int fi = 0;

    /* 1. Verify architecture */
    filter[fi++] = (struct sock_filter)BPF_STMT(
                       BPF_LD | BPF_W | BPF_ABS,
                       offsetof(struct seccomp_data, arch));
    filter[fi++] = (struct sock_filter)BPF_JUMP(
                       BPF_JMP | BPF_JEQ | BPF_K, MY_AUDIT_ARCH_PROFILE, 1, 0);
    filter[fi++] = (struct sock_filter)BPF_STMT(
                       BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);

    /* 2. Load syscall number */
    filter[fi++] = (struct sock_filter)BPF_STMT(
                       BPF_LD | BPF_W | BPF_ABS,
                       offsetof(struct seccomp_data, nr));

    /* 3. Per-syscall rules */
    if (default_is_allow)
    {
        /* Allowlist mode: default=ALLOW, listed syscalls with non-ALLOW action
         * → emit BPF_KILL/ERRNO for each listed non-allow syscall */
        for (int li = 0; li < n_listed; li++)
        {
            if (!listed_is_allow)
            {
                /* if nr == listed_nrs[li] → kill */
                filter[fi++] = (struct sock_filter)BPF_JUMP(
                                   BPF_JMP | BPF_JEQ | BPF_K,
                                   (unsigned int)listed_nrs[li], 0, 1);
                filter[fi++] = (struct sock_filter)BPF_STMT(
                                   BPF_RET | BPF_K,
                                   SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
            }
        }
        /* Default: allow */
        filter[fi++] = (struct sock_filter)BPF_STMT(
                           BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    }
    else
    {
        /* Denylist mode: default=KILL/ERRNO, listed=ALLOW
         * → emit jump-to-allow for each listed syscall, then kill.
         *
         * Each BPF_JUMP jump-true offset (jt) encodes the number of
         * instructions to skip forward to reach the final ALLOW stmt.
         * For entry [li] that is: (n_listed - li - 1) + 1 = n_listed - li
         * instructions ahead (one BPF_JUMP per remaining rule, then KILL,
         * then ALLOW).  The offset is stored in an unsigned char (0–255),
         * so the maximum safe n_listed is 128 (first entry jt = 128*1 - 1
         * ... actually let's be precise):
         *   entry li=0: jt = (n_listed-1) instructions to skip
         * jt must fit in unsigned char → n_listed-1 ≤ 255 → n_listed ≤ 128
         * (at n_listed=128, li=0: jt=127 JUMPs remaining + 1 KILL = 128—fits).
         * Cap here to prevent silent wrap-around which would misclassify
         * syscalls as denied when they should be allowed. */
        if (n_listed > 128)
        {
            fprintf(stderr,
                    "oci2bin: --seccomp-profile: denylist has %d rules,"
                    " truncating to 128 (BPF jump offset limit)\n",
                    n_listed);
            n_listed = 128;
        }
        int remaining = n_listed;
        for (int li = 0; li < n_listed; li++)
        {
            remaining--;
            /* if nr == listed_nrs[li] → jump forward past remaining rules
             * and the KILL stmt to land on the ALLOW stmt at the end.
             * Distance = remaining (one BPF_JUMP each) + 1 (KILL stmt). */
            int jt = remaining + 1;
            filter[fi++] = (struct sock_filter)BPF_JUMP(
                               BPF_JMP | BPF_JEQ | BPF_K,
                               (unsigned int)listed_nrs[li],
                               (unsigned char)jt, 0);
        }
        /* Kill (default) */
        filter[fi++] = (struct sock_filter)BPF_STMT(
                           BPF_RET | BPF_K,
                           SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
        /* Allow */
        filter[fi++] = (struct sock_filter)BPF_STMT(
                           BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    }

    struct sock_fprog prog =
    {
        .len    = (unsigned short)fi,
        .filter = filter,
    };

    int rc = -1;
    if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                SECCOMP_FILTER_FLAG_TSYNC, &prog) == 0)
    {
        fprintf(stderr, "oci2bin: seccomp profile applied (%d rules)\n",
                n_listed);
        rc = 0;
    }
    else if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == 0)
    {
        fprintf(stderr,
                "oci2bin: seccomp profile applied via prctl (%d rules)\n",
                n_listed);
        rc = 0;
    }
    else
    {
        fprintf(stderr,
                "oci2bin: --seccomp-profile: failed to apply: %s\n",
                strerror(errno));
    }

    free(filter);

#undef MY_AUDIT_ARCH_PROFILE
    return rc;
}

/* ── PTY relay for job control ──────────────────────────────────────────── */

/* Global master fd used by SIGWINCH handler to forward terminal resize. */
static volatile int g_pty_master_fd = -1;

/* Global child PID for signal forwarding from PTY parent. */
static volatile pid_t g_pty_child_pid = 0;

static void pty_forward_signal(int sig)
{
    if (g_pty_child_pid > 0)
    {
        kill(g_pty_child_pid, sig);
    }
}

static void sigwinch_handler(int sig)
{
    (void)sig;
    if (g_pty_master_fd < 0)
    {
        return;
    }
    struct winsize ws;
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0)
    {
        ioctl(g_pty_master_fd, TIOCSWINSZ, &ws);
    }
}

/*
 * Relay data between the host terminal (stdin/stdout) and the PTY master.
 * Runs until the slave side closes (child exits) — read() returns EIO or 0.
 * Restores the saved terminal settings before returning.
 */
static void relay_pty(int master_fd, struct termios *saved_termios,
                      int saved_termios_ok)
{
    char buf[4096];
    struct pollfd fds[2];

    fds[0].fd     = STDIN_FILENO;
    fds[0].events = POLLIN;
    fds[1].fd     = master_fd;
    fds[1].events = POLLIN;

    for (;;)
    {
        int n = poll(fds, 2, -1);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            break;
        }

        /* stdin → master: user keystrokes into container */
        if (fds[0].revents & POLLIN)
        {
            ssize_t r = read(STDIN_FILENO, buf, sizeof(buf));
            if (r <= 0)
            {
                break;
            }
            if (write(master_fd, buf, r) < 0)
            {
                break;
            }
        }

        /* master → stdout: container output to user */
        if (fds[1].revents & POLLIN)
        {
            ssize_t r = read(master_fd, buf, sizeof(buf));
            if (r <= 0)
            {
                break;
            }
            ssize_t w = 0;
            while (w < r)
            {
                ssize_t ww = write(STDOUT_FILENO, buf + w, r - w);
                if (ww < 0)
                {
                    goto done;
                }
                w += ww;
            }
        }

        /* stdin closed — stop sending to master, but keep draining output */
        if (fds[0].revents & (POLLHUP | POLLERR))
        {
            fds[0].fd = -1;   /* stop polling stdin */
        }

        /* master closed — drain any final data then exit */
        if (fds[1].revents & POLLHUP)
        {
            /* drain remaining bytes */
            for (;;)
            {
                ssize_t r = read(master_fd, buf, sizeof(buf));
                if (r <= 0)
                {
                    break;
                }
                ssize_t w = 0;
                while (w < r)
                {
                    ssize_t ww = write(STDOUT_FILENO, buf + w, r - w);
                    if (ww < 0)
                    {
                        goto done;
                    }
                    w += ww;
                }
            }
            break;
        }
        if (fds[1].revents & POLLERR)
        {
            break;
        }
    }
done:
    /* Restore the host terminal before returning so the prompt looks right */
    if (saved_termios_ok)
    {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, saved_termios);
    }
    g_pty_master_fd = -1;
    close(master_fd);
}

/* ── end PTY relay ──────────────────────────────────────────────────────── */

/*
 * Resolve an OCI "User" spec into uid/gid.  Called after chroot so
 * /etc/passwd and /etc/group refer to the container's files.
 *
 * Formats: "user" | "uid" | "user:group" | "uid:gid" | "uid:group" | "user:gid"
 * Returns 0 on success, -1 if the spec cannot be resolved.
 */
static int resolve_user(const char* spec, uid_t* out_uid, gid_t* out_gid)
{
    if (!spec || !spec[0])
    {
        return -1;
    }
    char buf[256];
    int sn = snprintf(buf, sizeof(buf), "%s", spec);
    if (sn < 0 || (size_t)sn >= sizeof(buf))
    {
        return -1;
    }

    char* colon      = strchr(buf, ':');
    char* group_part = NULL;
    if (colon)
    {
        *colon     = '\0';
        group_part = colon + 1;
    }

    uid_t uid = 0;
    gid_t gid = 0;

    /* Resolve user part: numeric UID or name lookup in /etc/passwd */
    if (buf[0] >= '0' && buf[0] <= '9')
    {
        long v = 0;
        if (parse_id_value(buf, 65534, &v) < 0)
        {
            return -1;
        }
        uid = (uid_t)v;
        /* numeric UID with no group spec → gid defaults to 0 */
    }
    else
    {
        if (lookup_passwd_user("/etc/passwd", buf, &uid, &gid) < 0)
        {
            return -1;
        }
    }

    /* Resolve group part if given: numeric GID or name lookup in /etc/group */
    if (group_part)
    {
        if (group_part[0] >= '0' && group_part[0] <= '9')
        {
            long v = 0;
            if (parse_id_value(group_part, 65534, &v) < 0)
            {
                return -1;
            }
            gid = (gid_t)v;
        }
        else
        {
            if (lookup_group_name("/etc/group", group_part, &gid) < 0)
            {
                return -1;
            }
        }
    }

    *out_uid = uid;
    *out_gid = gid;
    return 0;
}

static int container_main(const char* rootfs, struct container_opts *opts)
{
    debug_log("container_main.begin", "rootfs=%s", rootfs);

    /* Read OCI image config and build exec argv */
    struct oci_config oci_cfg;
    read_oci_config(rootfs, &oci_cfg);

    char* exec_args[MAX_ARGS + 1];
    int exec_argc = build_exec_args(&oci_cfg, opts->entrypoint,
                                    opts->extra_args, opts->n_extra,
                                    exec_args, MAX_ARGS);
    if (g_debug)
    {
        for (int i = 0; i < exec_argc; i++)
        {
            debug_log("container.exec_arg", "index=%d value=%s", i,
                      safe_str(exec_args[i]));
        }
    }

    /* Save image Env, WorkingDir and User — applied after chroot.
     * Transfer ownership from oci_cfg so free_oci_config won't free them.
     * User is copied to a stack buffer to survive subsequent heap activity. */
    char* image_env_json = oci_cfg.env_json;
    char* image_workdir  = oci_cfg.workdir;
    char  image_user_buf[256] = {0};
    if (oci_cfg.user && oci_cfg.user[0])
    {
        int _un = snprintf(image_user_buf, sizeof(image_user_buf), "%s",
                           oci_cfg.user);
        if (_un < 0 || (size_t)_un >= sizeof(image_user_buf))
        {
            fprintf(stderr, "oci2bin: User field too long; ignoring\n");
            image_user_buf[0] = '\0';
        }
    }
    char* image_user = image_user_buf;
    oci_cfg.env_json = NULL;
    oci_cfg.workdir  = NULL;
    free_oci_config(&oci_cfg);

    /* Remove our temp config file */
    {
        char config_path[PATH_MAX];
        int cpn = snprintf(config_path, sizeof(config_path),
                           "%s/.oci2bin_config", rootfs);
        if (cpn > 0 && (size_t)cpn < sizeof(config_path))
        {
            unlink(config_path);
        }
    }

    /* Set up volume bind mounts BEFORE chroot (host paths still reachable) */
    setup_volumes(rootfs, opts);
    setup_secrets(rootfs, opts);
    if (opts->gdb)
    {
        setup_gdb_in_rootfs(rootfs);
    }

    /* Append --add-host entries to /etc/hosts before chroot */
    install_extra_hosts(rootfs, opts->add_hosts, opts->n_add_hosts);

    /* Apply custom DNS resolv.conf if --dns or --dns-search were given */
    if (opts->n_dns_servers > 0 || opts->n_dns_search > 0)
    {
        install_custom_resolv_conf(rootfs,
                                   opts->dns_servers, opts->n_dns_servers,
                                   opts->dns_search, opts->n_dns_search);
    }

    /* Mount tmpfs on rootfs/dev and bind-mount host device nodes.
     * Must be done before chroot so the host paths are still reachable as
     * bind-mount sources.  After chroot the paths resolve inside the
     * container and the bind would silently map an empty tmpfs file to
     * itself instead of the real host device node. */
    {
        char dev_dir[PATH_MAX];
        int dlen = snprintf(dev_dir, sizeof(dev_dir), "%s/dev", rootfs);
        if (dlen > 0 && (size_t)dlen < sizeof(dev_dir))
        {
            if (mkdir_p_secure(dev_dir, 0755, "/dev") < 0)
            {
                return 1;
            }
            if (mount("tmpfs", dev_dir, "tmpfs",
                      MS_NOSUID | MS_NOEXEC, "mode=0755") < 0)
            {
                perror("mount /dev tmpfs (non-fatal)");
            }
            else
            {
                if (!opts->no_host_dev)
                {
                    static const char* const HOST_DEVS[] =
                    {
                        "/dev/null", "/dev/zero", "/dev/random",
                        "/dev/urandom", "/dev/tty", NULL,
                    };
                    for (int di = 0; HOST_DEVS[di]; di++)
                    {
                        char dst[PATH_MAX];
                        int plen = snprintf(dst, sizeof(dst), "%s%s",
                                            rootfs, HOST_DEVS[di]);
                        if (plen < 0 || (size_t)plen >= sizeof(dst))
                        {
                            continue;
                        }
                        if (ensure_bind_mount_target(HOST_DEVS[di], dst,
                                                     "/dev") < 0)
                        {
                            continue;
                        }
                        if (mount(HOST_DEVS[di], dst, NULL,
                                  MS_BIND, NULL) < 0)
                        {
                            fprintf(stderr,
                                    "oci2bin: bind-mount %s"
                                    " (non-fatal): %s\n",
                                    HOST_DEVS[di], strerror(errno));
                        }
                    }
                }
                /* Create /dev/pts dir; devpts is mounted after chroot */
                char pts_dir[PATH_MAX];
                int plen = snprintf(pts_dir, sizeof(pts_dir),
                                    "%s/dev/pts", rootfs);
                if (plen > 0 && (size_t)plen < sizeof(pts_dir))
                {
                    if (mkdir_p_secure(pts_dir, 0755, "/dev/pts") < 0)
                    {
                        return 1;
                    }
                }
                /* Create /dev/ptmx placeholder for post-chroot bind */
                char ptmx_path[PATH_MAX];
                int mlen = snprintf(ptmx_path, sizeof(ptmx_path),
                                    "%s/dev/ptmx", rootfs);
                if (mlen > 0 && (size_t)mlen < sizeof(ptmx_path))
                {
                    if (ensure_bind_mount_target("/dev/null", ptmx_path,
                                                 "/dev/ptmx") < 0)
                    {
                        return 1;
                    }
                }
            }
        }
    }

    /* Expose --device host devices inside the container.
     * Must be done PRE-CHROOT so host device paths resolve on the host
     * filesystem, not inside the container's /dev tmpfs.  Container paths
     * are prefixed with rootfs so bind-mount targets land in the right place.
     * stat() and mknod() fallback to bind-mount use the host-side source. */
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

        /* Destination inside rootfs (pre-chroot path) */
        char dst[PATH_MAX];
        int dlen = snprintf(dst, sizeof(dst), "%s%s", rootfs, ctr_dev);
        if (dlen < 0 || (size_t)dlen >= sizeof(dst))
        {
            fprintf(stderr, "oci2bin: --device destination path too long: %s%s"
                            " (non-fatal)\n", rootfs, ctr_dev);
            continue;
        }

        /* Try mknod first; fall back to bind-mount in user namespaces */
        if (mknod(dst, st.st_mode, st.st_rdev) < 0)
        {
            if (errno == EPERM || errno == ENOTSUP)
            {
                if (ensure_bind_mount_target(host_dev, dst, "--device") < 0)
                {
                    continue;
                }
                if (mount(host_dev, dst, NULL, MS_BIND, NULL) < 0)
                {
                    fprintf(stderr,
                            "oci2bin: --device bind-mount %s→%s: %s (non-fatal)\n",
                            host_dev, ctr_dev, strerror(errno));
                }
            }
            else
            {
                fprintf(stderr, "oci2bin: --device mknod %s: %s (non-fatal)\n",
                        dst, strerror(errno));
            }
        }
        else
        {
            chmod(dst, st.st_mode & 0777);
        }
    }

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
        else if (path_has_dotdot_component(sock))
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
                        if (mkdir_p_secure(sock_dir, 0755, "--ssh-agent") < 0)
                        {
                            ssh_auth_sock_host[0] = '\0';
                        }
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
                    else if (ssh_auth_sock_host[0] != '\0')
                    {
                        if (ensure_bind_mount_target(ssh_auth_sock_host, sock_dst,
                                                     "--ssh-agent") < 0)
                        {
                            ssh_auth_sock_host[0] = '\0';
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

    /* When --read-only is active, also mount /run as tmpfs so containers
     * that need a writable /run (e.g. systemd, D-Bus, ssh) still work.
     * Skip if user passed --no-auto-tmpfs. */
    if (opts->read_only && !opts->no_auto_tmpfs)
    {
        /* Only mount if not already covered by a user-supplied --tmpfs /run */
        int run_covered = 0;
        for (int ti = 0; ti < opts->n_tmpfs; ti++)
        {
            if (strcmp(opts->tmpfs_mounts[ti], "/run") == 0)
            {
                run_covered = 1;
                break;
            }
        }
        if (!run_covered)
        {
            mkdir("/run", 0755);
            if (mount("tmpfs", "/run", "tmpfs",
                      MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=0755") < 0)
            {
                perror("mount /run tmpfs (non-fatal)");
            }
        }
    }

    /* Mount devpts for TTY/job control support.  /dev is already a tmpfs
     * with host device nodes bind-mounted (done pre-chroot above). */
    if (mount("devpts", "/dev/pts", "devpts",
              MS_NOSUID | MS_NOEXEC,
              "newinstance,ptmxmode=0666,mode=0620") < 0)
    {
        perror("mount devpts (non-fatal)");
    }
    /* /dev/ptmx -> pts/ptmx so openpty() finds the right multiplexer */
    if (mount("/dev/pts/ptmx", "/dev/ptmx", NULL, MS_BIND, NULL) < 0)
    {
        perror("bind-mount /dev/ptmx (non-fatal)");
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

    /* Build a clean environment — drop all host vars so that LANG, USER,
     * DISPLAY, XDG_*, etc. cannot bleed into the container.  All required
     * variables are set explicitly below. */
    clearenv();

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

    /* Apply seccomp filter (must be before fork so child inherits it).
     * --gdb disables seccomp entirely: gdb needs ptrace and many syscalls. */
    if (opts->gdb)
    {
        fprintf(stderr,
                "oci2bin: --gdb: seccomp disabled to allow ptrace\n");
    }
    if (!opts->no_seccomp && !opts->gdb)
    {
        if (opts->seccomp_profile)
        {
            /* Custom profile: fall back to built-in default on parse error */
            if (apply_seccomp_profile(opts->seccomp_profile) < 0)
            {
                fprintf(stderr,
                        "oci2bin: --seccomp-profile failed,"
                        " falling back to built-in filter\n");
                apply_seccomp_filter();
            }
        }
        else
        {
            apply_seccomp_filter();
        }
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
            /* Parent: write state file then print child PID and exit */
            if (opts->name)
            {
                write_container_state(opts->name, bg, 0);
            }
            printf("%d\n", (int)bg);
            fflush(stdout);
            _exit(0);
        }
        /* Child: detach from terminal, redirect output to log */
        setsid();
        if (opts->name)
        {
            write_container_state(opts->name, getpid(), 1);
        }
        if (!opts->interactive)
        {
            int null_fd = open("/dev/null", O_RDONLY);
            if (null_fd >= 0)
            {
                dup2(null_fd, STDIN_FILENO);
                close(null_fd);
            }
        }
    }

    /* --init: run a zombie-reaping init loop; UID drop happens inside */
    if (opts->use_init)
    {
        int rc = run_as_init(exec_args, opts);
        return rc;
    }

    /* Drop to requested UID/GID.  --user overrides the image User field. */
    uid_t drop_uid = 0;
    gid_t drop_gid = 0;
    int   do_drop  = 0;

    if (opts->has_user)
    {
        drop_uid = opts->run_uid;
        drop_gid = opts->run_gid;
        do_drop  = 1;
    }
    else if (image_user && image_user[0])
    {
        if (resolve_user(image_user, &drop_uid, &drop_gid) == 0 &&
                (drop_uid != 0 || drop_gid != 0))
        {
            do_drop = 1;
            debug_log("container.user", "spec=%s uid=%d gid=%d",
                      image_user, (int)drop_uid, (int)drop_gid);
        }
        else
        {
            fprintf(stderr,
                    "oci2bin: warning: could not resolve image User \"%s\"\n",
                    image_user);
        }
    }

    if (do_drop)
    {
        /* setgroups may be denied in a user namespace (EPERM) — non-fatal */
        setgroups(0, NULL);
        /* In a user namespace only UID/GID 0 is mapped; setgid/setuid
         * for other IDs fails with EINVAL.  Treat as non-fatal so the
         * container still runs as the mapped uid=0. */
        if (setgid(drop_gid) < 0)
        {
            debug_log("container.setgid_skip", "gid=%d err=%s",
                      (int)drop_gid, strerror(errno));
        }
        if (setuid(drop_uid) < 0)
        {
            debug_log("container.setuid_skip", "uid=%d err=%s",
                      (int)drop_uid, strerror(errno));
        }
    }

    /* Set up PTY slave as controlling terminal for job control.
     * The PTY master/slave pair was allocated before fork() in main().
     * The child closes the master (parent's end) and claims the slave
     * via setsid() + TIOCSCTTY so the container shell gets full job control. */
    if (opts->pty_slave_fd >= 0)
    {
        if (opts->pty_master_fd >= 0)
        {
            close(opts->pty_master_fd);
        }
        setsid();
        if (ioctl(opts->pty_slave_fd, TIOCSCTTY, 0) == 0)
        {
            dup2(opts->pty_slave_fd, STDIN_FILENO);
            dup2(opts->pty_slave_fd, STDOUT_FILENO);
            dup2(opts->pty_slave_fd, STDERR_FILENO);
        }
        if (opts->pty_slave_fd > STDERR_FILENO)
        {
            close(opts->pty_slave_fd);
        }
    }

    /* Apply AppArmor profile if requested (optional compile-time support) */
#ifdef HAVE_APPARMOR
    if (opts->security_opt_apparmor)
    {
        if (aa_change_onexec(opts->security_opt_apparmor) < 0)
        {
            fprintf(stderr,
                    "oci2bin: --security-opt apparmor=%s: %s (non-fatal)\n",
                    opts->security_opt_apparmor, strerror(errno));
        }
        else
        {
            fprintf(stderr, "oci2bin: AppArmor profile '%s' set\n",
                    opts->security_opt_apparmor);
        }
    }
#else
    if (opts->security_opt_apparmor)
    {
        fprintf(stderr,
                "oci2bin: --security-opt apparmor: not compiled with "
                "AppArmor support (-DHAVE_APPARMOR)\n");
    }
#endif

    /* Apply SELinux exec label if requested (optional compile-time support) */
#ifdef HAVE_SELINUX
    if (opts->security_opt_label)
    {
        if (setexeccon(opts->security_opt_label) < 0)
        {
            fprintf(stderr,
                    "oci2bin: --security-opt label=%s: %s (non-fatal)\n",
                    opts->security_opt_label, strerror(errno));
        }
        else
        {
            fprintf(stderr, "oci2bin: SELinux label '%s' set\n",
                    opts->security_opt_label);
        }
    }
#else
    if (opts->security_opt_label)
    {
        fprintf(stderr,
                "oci2bin: --security-opt label: not compiled with "
                "SELinux support (-DHAVE_SELINUX)\n");
    }
#endif

    /* Block host-side ptrace and /proc/<pid>/mem access.  After execvp the
     * container process runs as uid 0 inside its own user namespace; without
     * this, the host root can still attach via ptrace or read /proc/<pid>/mem.
     * Errors are non-fatal but logged so the operator can see if the kernel
     * refuses the call. */
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
    {
        fprintf(stderr, "oci2bin: warning: PR_SET_DUMPABLE 0 failed: %s\n",
                strerror(errno));
    }

    /* --gen-seccomp: trace the workload instead of exec'ing directly */
    if (opts->gen_seccomp)
    {
        return do_gen_seccomp(opts->gen_seccomp, exec_args);
    }

    /* --gdb: launch gdb with the container entrypoint as the debuggee.
     * Build argv: gdb --args <exec_args[0]> [exec_args[1]...] */
    if (opts->gdb)
    {
        /* Count exec_args */
        int na = 0;
        while (exec_args[na])
        {
            na++;
        }
        /* gdb --args <exec_args...> NULL  = na + 3 slots */
        char** gdb_argv = malloc((size_t)(na + 3) * sizeof(char*));
        if (!gdb_argv)
        {
            perror("oci2bin: --gdb: malloc");
            return 1;
        }
        gdb_argv[0] = "gdb";
        gdb_argv[1] = "--args";
        for (int gi = 0; gi < na; gi++)
        {
            gdb_argv[gi + 2] = exec_args[gi];
        }
        gdb_argv[na + 2] = NULL;
        debug_log("container.exec", "gdb --args %s argc=%d",
                  safe_str(exec_args[0]), na);
        execvp("gdb", gdb_argv);
        perror("oci2bin: --gdb: execvp gdb");
        free(gdb_argv);
        return 1;
    }

    /* Exec the entrypoint */
    debug_log("container.exec", "path=%s argc=%d", safe_str(exec_args[0]),
              exec_argc);
    audit_emit_exec_event(exec_args[0]);
    execvp(exec_args[0], exec_args);

    /* If exec failed, try /bin/sh as fallback */
    perror("execvp");
    debug_log("container.exec_fallback", "path=/bin/sh");
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

    ssize_t n = read_all_fd(fd, buf, sz);
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
            "       %s mcp-serve [--allow-net]\n"
            "\n"
            "Subcommands:\n"
            "  mcp-serve [--allow-net]\n"
            "                      Start a JSON-RPC 2.0 MCP server on stdin/stdout.\n"
            "                      Exposes tools: run_container, exec_in_container,\n"
            "                      list_containers, stop_container, inspect_image,\n"
            "                      get_logs. Network is forced to 'none' unless\n"
            "                      --allow-net is passed here AND the caller requests\n"
            "                      net=host. No --device exposure through MCP.\n"
            "\n"
            "Options:\n"
            "  -v HOST:CONTAINER   Bind mount a host path into the container\n"
            "                      (may be repeated)\n"
            "  -p HOST_PORT:CTR_PORT\n"
            "                      Publish a container port to the host via slirp\n"
            "                      (may be repeated; implies --net slirp)\n"
            "  --secret HOST_FILE[:CONTAINER_PATH]\n"
            "                      Bind mount a host file read-only into the container;\n"
            "                      defaults to /run/secrets/<basename> (may be repeated)\n"
            "  --secret tpm2:CRED_NAME[:CONTAINER_PATH]\n"
            "                      Decrypt a TPM2-sealed credential via systemd-creds\n"
            "                      and place it in the container at CONTAINER_PATH\n"
            "                      (or /run/secrets/CRED_NAME by default)\n"
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
            "  --add-host HOST:IP  Inject a hostname→IP mapping into /etc/hosts\n"
            "                      (may be repeated)\n"
            "  --dns IP            Add a DNS server to resolv.conf (may be repeated)\n"
            "  --dns-search DOMAIN Add a DNS search domain (may be repeated)\n"
            "  --read-only         Mount rootfs read-only via overlayfs;\n"
            "                      auto-mounts /run as tmpfs (see --no-auto-tmpfs)\n"
            "  --no-auto-tmpfs     Do not auto-mount /run as tmpfs with --read-only\n"
            "  --overlay-persist DIR\n"
            "                      Persist the overlay upper layer to DIR;\n"
            "                      state accumulates across runs\n"
            "  --ssh-agent         Forward host SSH_AUTH_SOCK into the container\n"
            "  --no-seccomp        Disable the default seccomp syscall filter\n"
            "  --seccomp-profile FILE\n"
            "                      Apply a Docker-compatible JSON seccomp profile\n"
            "                      instead of the built-in default filter\n"
            "  --gen-seccomp FILE  Run container, trace all syscalls via ptrace,\n"
            "                      and write a minimal Docker-compatible allowlist\n"
            "                      JSON to FILE. Use the output with\n"
            "                      --seccomp-profile for hardened production runs.\n"
            "  --gdb               Launch gdb inside the container with the image\n"
            "                      entrypoint as the debuggee (host gdb bind-mounted\n"
            "                      in if not present). Disables seccomp to allow\n"
            "                      ptrace.\n"
            "  --clock-offset SECS Shift the container's monotonic and boottime clocks\n"
            "                      by SECS seconds (Linux 5.6+, CLONE_NEWTIME).\n"
            "                      Useful for replay testing and timestamp freezing.\n"
            "  --audit-log FILE    Append structured JSON lifecycle events to FILE\n"
            "                      (use '-' to write the audit stream to stderr)\n"
            "  --metrics-socket PATH\n"
            "                      Serve Prometheus metrics over a Unix socket at PATH\n"
            "  --security-opt apparmor=PROFILE\n"
            "                      Apply AppArmor profile before exec\n"
            "                      (requires -DHAVE_APPARMOR at build time)\n"
            "  --security-opt label=TYPE:VAL\n"
            "                      Set SELinux exec label before exec\n"
            "                      (requires -DHAVE_SELINUX at build time)\n"
            "  --no-host-dev       Skip bind-mounting host /dev nodes (null, zero, "
            "random, tty)\n"
            "  --user UID[:GID]    Run as this numeric UID (and optional GID)\n"
            "  --no-userns-remap   Disable subordinate UID/GID remapping and use\n"
            "                      the single-ID user namespace fallback\n"
            "  --lazy              [EXPERIMENTAL] Attempt userfaultfd-based on-demand\n"
            "                      rootfs paging (Linux 4.3+); falls back to full\n"
            "                      extraction if unsupported\n"
            "  --hostname NAME     Set the hostname inside the container\n"
            "  --cap-drop CAP      Drop a capability (or 'all' to drop all)\n"
            "  --cap-add CAP       Add an ambient capability (use after --cap-drop all)\n"
            "  --device /dev/PATH[:CONTAINER_PATH]\n"
            "                      Expose a host device inside the container\n"
            "  --init              Run a zombie-reaping init as PID 1\n"
            "  --detach, -d        Run container in background; print PID to stdout\n"
            "  -t, --tty           Allocate a pseudo-terminal for the container\n"
            "  -i, --interactive   Keep stdin open; combine with -t for -it mode\n"
            "  --name NAME         Assign a name for lifecycle management\n"
            "                      (use with --detach for oci2bin ps/stop/logs)\n"
            "  --memory SIZE       Limit container memory (e.g. 512m, 2g) via"
            " cgroup v2\n"
            "  --cpus FLOAT        Limit container CPU (e.g. 0.5 = 50%%)"
            " via cgroup v2\n"
            "  --pids-limit N      Limit number of PIDs inside the container"
            " via cgroup v2\n"
            "  --verify-key PATH   Verify binary signature before extraction;"
            " abort if invalid\n"
            "  --check-update      Check the embedded signed update manifest and exit\n"
            "  --self-update       Download and atomically replace the binary if"
            " a newer signed update exists\n"
            "  --env-file FILE     Load KEY=VALUE pairs from FILE\n"
            "  --tmpfs PATH        Mount a fresh tmpfs at PATH inside the container\n"
            "  --ulimit TYPE=N     Set resource limit (nofile,nproc,cpu,as,fsize)\n"
            "  --config PATH       Load options from a key=value config file\n"
            "  --debug             Emit verbose runtime debug diagnostics\n"
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
            prog, prog, prog, prog, prog, prog, prog, prog);
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
 */
static char** build_merged_argv(int argc, char* argv[], int* out_argc)
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
            if (path_has_dotdot_component(config_path))
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
        debug_log("argv.merge", "config=none argc=%d", argc);
        *out_argc = argc;
        return argv;
    }
    debug_log("argv.merge", "config=%s", config_path);

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

    *out_argc = merged_argc;
    free(cfg);               /* free the indirection array; strings live in merged */
    debug_log("argv.merge", "merged_argc=%d", merged_argc);

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
            if (!path_is_absolute_and_clean(spec))
            {
                fprintf(stderr,
                        "oci2bin: -v host path must be absolute and clean: %s\n",
                        spec);
                return -1;
            }
            if (!path_is_absolute_and_clean(colon + 1))
            {
                fprintf(stderr,
                        "oci2bin: -v container path must be absolute and clean: %s\n",
                        colon + 1);
                return -1;
            }
            opts->vol_host[opts->n_vols] = spec;
            opts->vol_ctr[opts->n_vols]  = colon + 1;
            opts->n_vols++;
        }
        else if (strcmp(argv[i], "-p") == 0)
        {
            /* -p HOST_PORT:CTR_PORT — shorthand for --net slirp:HOST:CTR */
            if (i + 1 >= argc)
            {
                fprintf(stderr,
                        "oci2bin: -p requires HOST_PORT:CTR_PORT argument\n");
                return -1;
            }
            i++;
            char* spec = argv[i];
            char* colon = strchr(spec, ':');
            if (!colon || colon == spec || *(colon + 1) == '\0')
            {
                fprintf(stderr,
                        "oci2bin: -p argument must be HOST_PORT:CTR_PORT\n");
                return -1;
            }
            if (opts->n_portfwd >= 16)
            {
                fprintf(stderr,
                        "oci2bin: too many -p / port forward flags (max 16)\n");
                return -1;
            }
            opts->net_portfwd[opts->n_portfwd++] = spec;
            /* Auto-enable slirp networking if not already set */
            if (!opts->net || strcmp(opts->net, "host") == 0)
            {
                opts->net = "slirp";
            }
        }
        else if (strcmp(argv[i], "--secret") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr,
                        "oci2bin: --secret requires a HOST_FILE[:CONTAINER_PATH]"
                        " or tpm2:CRED_NAME[:CONTAINER_PATH] argument\n");
                return -1;
            }
            if (opts->n_secrets >= MAX_SECRETS)
            {
                fprintf(stderr, "oci2bin: too many --secret flags (max %d)\n",
                        MAX_SECRETS);
                return -1;
            }
            i++;
            char* spec = argv[i];
            opts->secret_cred[opts->n_secrets] = NULL;

            if (strncmp(spec, "tpm2:", 5) == 0)
            {
                /* TPM2 path: tpm2:CRED_NAME[:CONTAINER_PATH] */
                char* cred_start = spec + 5;
                char* ctr_sep    = strchr(cred_start, ':');
                if (ctr_sep)
                {
                    *ctr_sep = '\0';
                    const char* ctr_path = ctr_sep + 1;
                    if (!path_is_absolute_and_clean(ctr_path))
                    {
                        fprintf(stderr,
                                "oci2bin: --secret tpm2 container path must"
                                " be absolute and clean: %s\n", ctr_path);
                        return -1;
                    }
                    opts->secret_ctr[opts->n_secrets] = ctr_sep + 1;
                }
                else
                {
                    opts->secret_ctr[opts->n_secrets] = NULL;
                }
                /* Validate credential name: only alnum, '-', '_', '.' */
                for (const char* p = cred_start; *p; p++)
                {
                    if (!isalnum((unsigned char)*p) && *p != '-' &&
                            *p != '_' && *p != '.')
                    {
                        fprintf(stderr,
                                "oci2bin: --secret tpm2 credential name"
                                " contains invalid character '%c'\n", *p);
                        return -1;
                    }
                }
                if (cred_start[0] == '\0')
                {
                    fprintf(stderr,
                            "oci2bin: --secret tpm2: credential name"
                            " must not be empty\n");
                    return -1;
                }
                opts->secret_cred[opts->n_secrets] = cred_start;
                opts->secret_host[opts->n_secrets] = NULL;
            }
            else
            {
                /* Plain-file path: HOST_FILE[:CONTAINER_PATH] */
                char* colon = strchr(spec, ':');
                if (!path_is_absolute_and_clean(spec))
                {
                    fprintf(stderr,
                            "oci2bin: --secret host path must be absolute"
                            " and clean: %s\n", spec);
                    return -1;
                }
                opts->secret_host[opts->n_secrets] = spec;
                if (colon)
                {
                    *colon = '\0';
                    if (!path_is_absolute_and_clean(colon + 1))
                    {
                        fprintf(stderr,
                                "oci2bin: --secret container path must be"
                                " absolute and clean: %s\n", colon + 1);
                        return -1;
                    }
                    opts->secret_ctr[opts->n_secrets] = colon + 1;
                }
                else
                {
                    opts->secret_ctr[opts->n_secrets] = NULL;
                }
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
            if (path_has_dotdot_component(tp))
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
            i++;
            if (path_has_dotdot_component(argv[i]))
            {
                fprintf(stderr,
                        "oci2bin: --workdir path must not contain"
                        " '..' components: %s\n", argv[i]);
                return -1;
            }
            opts->workdir = argv[i];
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
            if (path_has_dotdot_component(argv[i]))
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
        else if (strcmp(argv[i], "--seccomp-profile") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr,
                        "oci2bin: --seccomp-profile requires a FILE argument\n");
                return -1;
            }
            i++;
            if (path_has_dotdot_component(argv[i]))
            {
                fprintf(stderr,
                        "oci2bin: --seccomp-profile: path must not"
                        " contain '..'\n");
                return -1;
            }
            opts->seccomp_profile = argv[i];
        }
        else if (strcmp(argv[i], "--gen-seccomp") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr,
                        "oci2bin: --gen-seccomp requires a FILE argument\n");
                return -1;
            }
            i++;
            if (path_has_dotdot_component(argv[i]))
            {
                fprintf(stderr,
                        "oci2bin: --gen-seccomp: path must not"
                        " contain '..'\n");
                return -1;
            }
            opts->gen_seccomp = argv[i];
        }
        else if (strcmp(argv[i], "--gdb") == 0)
        {
            opts->gdb = 1;
        }
        else if (strcmp(argv[i], "--clock-offset") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr,
                        "oci2bin: --clock-offset requires SECS argument\n");
                return -1;
            }
            i++;
            char* endp = NULL;
            opts->clock_offset_secs = strtol(argv[i], &endp, 10);
            if (!endp || *endp != '\0')
            {
                fprintf(stderr,
                        "oci2bin: --clock-offset: invalid number '%s'\n",
                        argv[i]);
                return -1;
            }
            opts->has_clock_offset = 1;
        }
        else if (strcmp(argv[i], "--audit-log") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr,
                        "oci2bin: --audit-log requires FILE argument\n");
                return -1;
            }
            opts->audit_log = argv[++i];
        }
        else if (strcmp(argv[i], "--metrics-socket") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr,
                        "oci2bin: --metrics-socket requires PATH argument\n");
                return -1;
            }
            i++;
            if (!path_is_absolute_and_clean(argv[i]))
            {
                fprintf(stderr,
                        "oci2bin: --metrics-socket path must be absolute"
                        " and clean: %s\n",
                        argv[i]);
                return -1;
            }
            opts->metrics_socket = argv[i];
        }
        else if (strcmp(argv[i], "--add-host") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr,
                        "oci2bin: --add-host requires HOST:IP argument\n");
                return -1;
            }
            i++;
            if (opts->n_add_hosts >= 32)
            {
                fprintf(stderr,
                        "oci2bin: too many --add-host flags (max 32)\n");
                return -1;
            }
            if (!strchr(argv[i], ':'))
            {
                fprintf(stderr,
                        "oci2bin: --add-host argument must be HOST:IP\n");
                return -1;
            }
            opts->add_hosts[opts->n_add_hosts++] = argv[i];
        }
        else if (strcmp(argv[i], "--dns") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "oci2bin: --dns requires IP argument\n");
                return -1;
            }
            i++;
            if (opts->n_dns_servers >= 8)
            {
                fprintf(stderr,
                        "oci2bin: too many --dns flags (max 8)\n");
                return -1;
            }
            opts->dns_servers[opts->n_dns_servers++] = argv[i];
        }
        else if (strcmp(argv[i], "--dns-search") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "oci2bin: --dns-search requires DOMAIN argument\n");
                return -1;
            }
            i++;
            if (opts->n_dns_search >= 8)
            {
                fprintf(stderr,
                        "oci2bin: too many --dns-search flags (max 8)\n");
                return -1;
            }
            opts->dns_search[opts->n_dns_search++] = argv[i];
        }
        else if (strcmp(argv[i], "--no-auto-tmpfs") == 0)
        {
            opts->no_auto_tmpfs = 1;
        }
        else if (strcmp(argv[i], "--security-opt") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr,
                        "oci2bin: --security-opt requires apparmor=PROFILE"
                        " or label=TYPE:VAL\n");
                return -1;
            }
            i++;
            if (strncmp(argv[i], "apparmor=", 9) == 0)
            {
                opts->security_opt_apparmor = argv[i] + 9;
            }
            else if (strncmp(argv[i], "label=", 6) == 0)
            {
                opts->security_opt_label = argv[i] + 6;
            }
            else
            {
                fprintf(stderr,
                        "oci2bin: --security-opt: unknown option '%s'\n"
                        "  supported: apparmor=PROFILE, label=TYPE:VAL\n",
                        argv[i]);
                return -1;
            }
        }
        else if (strcmp(argv[i], "--no-host-dev") == 0)
        {
            opts->no_host_dev = 1;
        }
        else if (strcmp(argv[i], "--init") == 0)
        {
            opts->use_init = 1;
        }
        else if (strcmp(argv[i], "--debug") == 0)
        {
            opts->debug = 1;
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
            opts->vm_cpus = cpus;
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
            if (path_has_dotdot_component(argv[i]))
            {
                fprintf(stderr,
                        "oci2bin: --verify-key: key path must not"
                        " contain '..'\n");
                return -1;
            }
            opts->verify_key = argv[i];
        }
        else if (strcmp(argv[i], "--self-update") == 0)
        {
            opts->self_update = 1;
        }
        else if (strcmp(argv[i], "--check-update") == 0)
        {
            opts->check_update = 1;
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
            if (path_has_dotdot_component(spec))
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
                if (path_has_dotdot_component(ctr))
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
        else if (strcmp(argv[i], "--no-userns-remap") == 0)
        {
            opts->no_userns_remap = 1;
        }
        else if (strcmp(argv[i], "--lazy") == 0)
        {
            opts->lazy = 1;
        }
        else if (strcmp(argv[i], "-t") == 0
                 || strcmp(argv[i], "--tty") == 0)
        {
            opts->allocate_tty = 1;
        }
        else if (strcmp(argv[i], "-i") == 0
                 || strcmp(argv[i], "--interactive") == 0)
        {
            opts->interactive = 1;
        }
        else if (strcmp(argv[i], "-it") == 0
                 || strcmp(argv[i], "-ti") == 0)
        {
            opts->allocate_tty = 1;
            opts->interactive  = 1;
        }
        else if (strcmp(argv[i], "--name") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "oci2bin: --name requires NAME\n");
                return -1;
            }
            i++;
            const char* p = argv[i];
            while (*p)
            {
                if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                        (*p >= '0' && *p <= '9') || *p == '-' || *p == '_'))
                {
                    fprintf(stderr,
                            "oci2bin: --name: only alphanumeric, "
                            "'-', '_' allowed\n");
                    return -1;
                }
                p++;
            }
            if (strlen(argv[i]) == 0 || strlen(argv[i]) > 128)
            {
                fprintf(stderr,
                        "oci2bin: --name: length must be 1-128 chars\n");
                return -1;
            }
            opts->name = argv[i];
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
static int open_verifier_script_fd(char* fd_path, size_t fd_path_size)
{
    char self_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (len < 0)
    {
        perror("oci2bin: verifier: readlink /proc/self/exe");
        return -1;
    }
    self_path[len] = '\0';

    char scripts_dir[PATH_MAX];
    char* slash = strrchr(self_path, '/');
    if (!slash)
    {
        fprintf(stderr, "oci2bin: verifier: cannot determine script dir\n");
        return -1;
    }
    size_t dir_len = (size_t)(slash - self_path);
    int n = snprintf(scripts_dir, sizeof(scripts_dir),
                     "%.*s/../scripts/sign_binary.py",
                     (int)dir_len, self_path);
    if (n < 0 || n >= (int)sizeof(scripts_dir))
    {
        fprintf(stderr, "oci2bin: verifier: scripts path truncated\n");
        return -1;
    }
    int script_fd = open(scripts_dir, O_RDONLY | O_NOFOLLOW);
    if (script_fd < 0)
    {
        fprintf(stderr, "oci2bin: verifier: cannot open verifier script\n");
        return -1;
    }
    struct stat vst;
    if (fstat(script_fd, &vst) < 0)
    {
        fprintf(stderr, "oci2bin: verifier: cannot stat verifier script\n");
        close(script_fd);
        return -1;
    }
    if (vst.st_mode & (S_IWGRP | S_IWOTH))
    {
        fprintf(stderr,
                "oci2bin: verifier: verifier script is group/world "
                "writable — refusing to execute\n");
        close(script_fd);
        return -1;
    }
    n = snprintf(fd_path, fd_path_size, "/proc/self/fd/%d", script_fd);
    if (n < 0 || n >= (int)fd_path_size)
    {
        fprintf(stderr, "oci2bin: verifier: fd path truncated\n");
        close(script_fd);
        return -1;
    }
    return script_fd;
}

static int verify_signature(const char* self_path, const char* key_path)
{
    if (path_has_dotdot_component(key_path))
    {
        fprintf(stderr,
                "oci2bin: --verify-key: key path must not contain "
                "'..'\n");
        return -1;
    }

    char fd_path[32];
    int script_fd = open_verifier_script_fd(fd_path, sizeof(fd_path));
    if (script_fd < 0)
    {
        return -1;
    }
    char* args[] =
    {
        "/usr/bin/python3",
        fd_path,
        "verify",
        "--key", (char*)key_path,
        "--in", (char*)self_path,
        NULL
    };
    int rc = run_cmd(args);
    close(script_fd);
    if (rc != 0)
    {
        fprintf(stderr,
                "oci2bin: signature verification failed — "
                "aborting before extraction\n");
        return -1;
    }
    return 0;
}

static int run_python_helper(const char* script, const char* arg1,
                             const char* arg2, const char* arg3,
                             const char* arg4)
{
    char* args[9];
    int ai = 0;
    args[ai++] = "/usr/bin/python3";
    args[ai++] = "-c";
    args[ai++] = (char*)script;
    args[ai++] = (char*)arg1;
    if (arg2)
    {
        args[ai++] = (char*)arg2;
    }
    if (arg3)
    {
        args[ai++] = (char*)arg3;
    }
    if (arg4)
    {
        args[ai++] = (char*)arg4;
    }
    args[ai] = NULL;
    return run_cmd(args);
}

static int verify_pinned_digest(const char* self_path)
{
    static const char script[] =
        "import hashlib,json,re,struct,sys\n"
        "MAGIC=b'OCI2BIN_META\\x00'\n"
        "TRAILER=b'OCI2BIN_SIG_END\\x00'\n"
        "SUPPORTED={'sha256':64,'sha512':128}\n"
        "path=sys.argv[1]\n"
        "data=open(path,'rb').read()\n"
        "if len(data)>=20 and data[-20:-4]==TRAILER:\n"
        " t=struct.unpack('>I',data[-4:])[0]\n"
        " data=data[:-t] if 0<t<=len(data) else data\n"
        "m=data.rfind(MAGIC)\n"
        "sys.exit(0) if m<4 else None\n"
        "tot=struct.unpack_from('<I',data,m-4)[0]\n"
        "js=m+len(MAGIC)\n"
        "je=(m-4)+tot\n"
        "sys.exit(0) if je>len(data) or je<=js else None\n"
        "meta=json.loads(data[js:je].rstrip(b'\\x00'))\n"
        "pin=meta.get('pin_digest','')\n"
        "sys.exit(0) if not pin else None\n"
        "algo,want=('sha256',pin)\n"
        "if ':' in pin:\n"
        " algo,want=pin.split(':',1)\n"
        " algo=algo.lower()\n"
        " if algo not in SUPPORTED:\n"
        "  print('oci2bin: unsupported pin_digest algorithm',"
        "file=sys.stderr)\n"
        "  sys.exit(1)\n"
        "if len(want)!=SUPPORTED[algo] or not re.fullmatch(r'[0-9a-fA-F]+',want):\n"
        " print('oci2bin: invalid pin_digest value',file=sys.stderr)\n"
        " sys.exit(1)\n"
        "want=want.lower()\n"
        "needle=(f'\\\"pin_digest\\\":\\\"{pin}\\\"').encode()\n"
        "idx=data.find(needle)\n"
        "sys.exit(1) if idx<0 else None\n"
        "place=('0'*SUPPORTED[algo]) if algo=='sha256' else "
        "f'{algo}:{\"0\"*SUPPORTED[algo]}'\n"
        "repl=(f'\\\"pin_digest\\\":\\\"{place}\\\"').encode()\n"
        "buf=data[:idx]+repl+data[idx+len(needle):]\n"
        "calc=hashlib.new(algo,buf).hexdigest()\n"
        "ok=(calc==want)\n"
        "print('oci2bin: pinned digest mismatch',file=sys.stderr) if not ok else None\n"
        "sys.exit(0 if ok else 1)\n";
    return run_python_helper(script, self_path, NULL, NULL, NULL);
}

static int run_self_update(const char* self_path, const char* key_path,
                           int apply_update, const char* helper_path)
{
    static const char script[] =
        "import hashlib,importlib.machinery,importlib.util,json,os,re,struct,subprocess,sys,tempfile,urllib.request\n"
        "MAGIC=b'OCI2BIN_META\\x00'\n"
        "path,key,mode,helper=sys.argv[1:5]\n"
        "try:\n"
        " loader=importlib.machinery.SourceFileLoader("
        "'oci2bin_sign_binary',helper)\n"
        " spec=importlib.util.spec_from_loader('oci2bin_sign_binary',loader)\n"
        " mod=importlib.util.module_from_spec(spec)\n"
        " loader.exec_module(mod)\n"
        "except Exception as exc:\n"
        " print(f'oci2bin: failed to load verifier helper: {exc}',"
        "file=sys.stderr)\n"
        " sys.exit(1)\n"
        "data=open(path,'rb').read()\n"
        "m=data.rfind(MAGIC)\n"
        "sys.exit(1) if m<4 else None\n"
        "tot=struct.unpack_from('<I',data,m-4)[0]\n"
        "js=m+len(MAGIC)\n"
        "je=(m-4)+tot\n"
        "sys.exit(1) if je>len(data) or je<=js else None\n"
        "meta=json.loads(data[js:je].rstrip(b'\\x00'))\n"
        "url=meta.get('self_update_url','')\n"
        "cur=meta.get('version','0')\n"
        "sys.exit(1) if not url else None\n"
        "fdnum=int(helper.rsplit('/',1)[1])\n"
        "v=lambda s:[int(x) for x in re.findall(r'\\d+',s)] or [0]\n"
        "with tempfile.TemporaryDirectory(prefix='oci2bin-update-') as td:\n"
        " mp=os.path.join(td,'manifest.json')\n"
        " sp=os.path.join(td,'manifest.json.sig')\n"
        " _MAX_MANIFEST=1048576\n"
        " with urllib.request.urlopen(url, timeout=30) as r, open(mp,'wb') as f:\n"
        "  buf=r.read(_MAX_MANIFEST+1)\n"
        "  if len(buf)>_MAX_MANIFEST:\n"
        "   print('oci2bin: update manifest too large',file=sys.stderr)\n"
        "   sys.exit(1)\n"
        "  f.write(buf)\n"
        " with urllib.request.urlopen(url + '.sig', timeout=30) as r, open(sp,'wb') as f:\n"
        "  buf=r.read(_MAX_MANIFEST+1)\n"
        "  if len(buf)>_MAX_MANIFEST:\n"
        "   print('oci2bin: update manifest signature too large',file=sys.stderr)\n"
        "   sys.exit(1)\n"
        "  f.write(buf)\n"
        " os.lseek(fdnum,0,0)\n"
        " vr=subprocess.run([sys.executable,helper,'verify-file','--key',key,"
        " '--in',mp,'--sig',sp],capture_output=True,text=True,"
        "pass_fds=(fdnum,))\n"
        " if vr.returncode!=0:\n"
        "  err=(vr.stderr or vr.stdout or '').strip()\n"
        "  print(err,file=sys.stderr) if err else None\n"
        "  print('oci2bin: update manifest signature verification failed',"
        "file=sys.stderr)\n"
        "  sys.exit(1)\n"
        " manifest=json.load(open(mp,'r',encoding='utf-8'))\n"
        " nxt=manifest.get('version','')\n"
        " burl=manifest.get('url','')\n"
        " want_spec=manifest.get('digest') or manifest.get('sha256','')\n"
        " if not nxt or not burl or not want_spec:\n"
        "  print('oci2bin: update manifest missing version/url/digest',"
        "file=sys.stderr)\n"
        "  sys.exit(1)\n"
        " try:\n"
        "  algo,want=mod._parse_digest_spec(want_spec)\n"
        " except ValueError as exc:\n"
        "  print(f'oci2bin: update manifest has invalid digest: {exc}',"
        "file=sys.stderr)\n"
        "  sys.exit(1)\n"
        " if v(nxt)<v(cur):\n"
        "  print('oci2bin: refusing rollback update manifest',file=sys.stderr)\n"
        "  sys.exit(1)\n"
        " if v(nxt)==v(cur):\n"
        "  print(f'oci2bin: already up to date ({cur})',file=sys.stderr)\n"
        "  sys.exit(0)\n"
        " if mode=='check':\n"
        "  print(f'oci2bin: update available {cur} -> {nxt}',file=sys.stderr)\n"
        "  sys.exit(10)\n"
        " out_fd,out_path=tempfile.mkstemp(prefix='.oci2bin-update.',"
        "dir=os.path.dirname(path) or '.')\n"
        " os.close(out_fd)\n"
        " try:\n"
        "  h=hashlib.new(algo)\n"
        "  with urllib.request.urlopen(burl, timeout=30) as r, open(out_path,'wb') as f:\n"
        "   while True:\n"
        "    chunk=r.read(65536)\n"
        "    if not chunk:\n"
        "     break\n"
        "    h.update(chunk)\n"
        "    f.write(chunk)\n"
        "  got=h.hexdigest()\n"
        "  if got!=want:\n"
        "   print(f'oci2bin: downloaded update {algo} mismatch',"
        "file=sys.stderr)\n"
        "   sys.exit(1)\n"
        "  os.chmod(out_path, os.stat(out_path).st_mode | 0o111)\n"
        "  os.replace(out_path, path)\n"
        "  print(f'oci2bin: updated to {nxt}',file=sys.stderr)\n"
        " finally:\n"
        "  if os.path.exists(out_path):\n"
        "   os.unlink(out_path)\n";
    return run_python_helper(script, self_path, key_path,
                             apply_update ? "apply" : "check", helper_path);
}

static void seal_loader_rodata(void)
{
#ifdef __NR_mseal
    /*
     * Walk /proc/self/maps and call mseal() on every r-xp and r--p segment.
     * This prevents any future mprotect/mmap from changing these ranges,
     * hardening the loader against self-modification attacks from a
     * compromised container.
     */
    if (!kernel_supports_mseal())
    {
        return;
    }
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps)
    {
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), maps))
    {
        unsigned long start, end;
        char perms[8];
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) != 3)
        {
            continue;
        }
        /* Only seal executable (r-xp) and read-only data (r--p) segments.
         * Skip writable or shared mappings — mseal rejects them anyway. */
        if ((strcmp(perms, "r-xp") != 0) && (strcmp(perms, "r--p") != 0))
        {
            continue;
        }
        size_t len = end - start;
        if (len == 0)
        {
            continue;
        }
        long rc = syscall(__NR_mseal, (void*)start, len, 0UL);
        if (rc < 0 && errno == ENOSYS)
        {
            kernel_set_feature_state(KERNEL_FEATURE_MSEAL,
                                     KERNEL_FEATURE_UNSUPPORTED);
            break;
        }
    }
    fclose(maps);
#endif
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
    int rc = write_all_fd(fd, value, strlen(value));
    int saved = errno;
    close(fd);
    if (rc < 0)
    {
        fprintf(stderr, "oci2bin: cgroup: write %s (%s): %s\n",
                path, value, strerror(saved));
        return -1;
    }
    return 0;
}

static char g_cgroup_dir[PATH_MAX]; /* global so atexit can clean up */
static int  g_cgroup_fd = -1;       /* open O_DIRECTORY fd to g_cgroup_dir */

struct metrics_snapshot
{
    unsigned long long cpu_usage_usec;
    unsigned long long cpu_user_usec;
    unsigned long long cpu_system_usec;
    unsigned long long cpu_nr_periods;
    unsigned long long cpu_nr_throttled;
    unsigned long long cpu_throttled_usec;
    unsigned long long memory_current;
    unsigned long long pids_current;
};

static volatile sig_atomic_t g_metrics_stop = 0;

static void metrics_stop_signal(int sig)
{
    (void)sig;
    g_metrics_stop = 1;
}

static int read_text_file_at(int dirfd, const char* relpath,
                             char* buf, size_t buf_sz)
{
    if (!buf || buf_sz == 0)
    {
        errno = EINVAL;
        return -1;
    }

    int fd = openat(dirfd, relpath, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        return -1;
    }

    size_t total = 0;
    while (total + 1 < buf_sz)
    {
        ssize_t nr = read(fd, buf + total, buf_sz - total - 1);
        if (nr < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            close(fd);
            return -1;
        }
        if (nr == 0)
        {
            break;
        }
        total += (size_t)nr;
    }
    buf[total] = '\0';
    close(fd);
    return 0;
}

static int parse_u64_text(const char* text, unsigned long long* out)
{
    char* endp = NULL;
    unsigned long long value;

    if (!text || !out)
    {
        return -1;
    }

    errno = 0;
    value = strtoull(text, &endp, 10);
    if (errno != 0 || endp == text)
    {
        return -1;
    }
    while (*endp == '\n' || *endp == ' ' || *endp == '\t')
    {
        endp++;
    }
    if (*endp != '\0')
    {
        return -1;
    }
    *out = value;
    return 0;
}

static int parse_cpu_stat_text(const char* text, struct metrics_snapshot* snap)
{
    char buf[512];
    char* saveptr = NULL;
    char* line;

    if (!text || !snap)
    {
        return -1;
    }
    if (snprintf(buf, sizeof(buf), "%s", text) >= (int)sizeof(buf))
    {
        return -1;
    }

    line = strtok_r(buf, "\n", &saveptr);
    while (line)
    {
        char key[64];
        unsigned long long value;
        if (sscanf(line, "%63s %llu", key, &value) == 2)
        {
            if (strcmp(key, "usage_usec") == 0)
            {
                snap->cpu_usage_usec = value;
            }
            else if (strcmp(key, "user_usec") == 0)
            {
                snap->cpu_user_usec = value;
            }
            else if (strcmp(key, "system_usec") == 0)
            {
                snap->cpu_system_usec = value;
            }
            else if (strcmp(key, "nr_periods") == 0)
            {
                snap->cpu_nr_periods = value;
            }
            else if (strcmp(key, "nr_throttled") == 0)
            {
                snap->cpu_nr_throttled = value;
            }
            else if (strcmp(key, "throttled_usec") == 0)
            {
                snap->cpu_throttled_usec = value;
            }
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }
    return 0;
}

static int read_metrics_snapshot(int dirfd, struct metrics_snapshot* snap)
{
    char buf[512];

    if (!snap)
    {
        return -1;
    }
    memset(snap, 0, sizeof(*snap));

    if (read_text_file_at(dirfd, "cpu.stat", buf, sizeof(buf)) < 0)
    {
        return -1;
    }
    if (parse_cpu_stat_text(buf, snap) < 0)
    {
        return -1;
    }
    if (read_text_file_at(dirfd, "memory.current", buf, sizeof(buf)) < 0 ||
            parse_u64_text(buf, &snap->memory_current) < 0)
    {
        return -1;
    }
    if (read_text_file_at(dirfd, "pids.current", buf, sizeof(buf)) < 0 ||
            parse_u64_text(buf, &snap->pids_current) < 0)
    {
        return -1;
    }
    return 0;
}

static int format_metrics_text(const struct metrics_snapshot* snap,
                               char* buf, size_t buf_sz)
{
    int n = snprintf(
                buf, buf_sz,
                "# HELP oci2bin_cpu_usage_usec Total CPU time used by the"
                " container in microseconds.\n"
                "# TYPE oci2bin_cpu_usage_usec counter\n"
                "oci2bin_cpu_usage_usec %llu\n"
                "# HELP oci2bin_cpu_user_usec User CPU time used by the"
                " container in microseconds.\n"
                "# TYPE oci2bin_cpu_user_usec counter\n"
                "oci2bin_cpu_user_usec %llu\n"
                "# HELP oci2bin_cpu_system_usec System CPU time used by the"
                " container in microseconds.\n"
                "# TYPE oci2bin_cpu_system_usec counter\n"
                "oci2bin_cpu_system_usec %llu\n"
                "# HELP oci2bin_cpu_nr_periods Number of elapsed CFS periods.\n"
                "# TYPE oci2bin_cpu_nr_periods counter\n"
                "oci2bin_cpu_nr_periods %llu\n"
                "# HELP oci2bin_cpu_nr_throttled Number of throttled CFS periods.\n"
                "# TYPE oci2bin_cpu_nr_throttled counter\n"
                "oci2bin_cpu_nr_throttled %llu\n"
                "# HELP oci2bin_cpu_throttled_usec Total throttled CPU time in"
                " microseconds.\n"
                "# TYPE oci2bin_cpu_throttled_usec counter\n"
                "oci2bin_cpu_throttled_usec %llu\n"
                "# HELP oci2bin_memory_current Current memory usage in bytes.\n"
                "# TYPE oci2bin_memory_current gauge\n"
                "oci2bin_memory_current %llu\n"
                "# HELP oci2bin_pids_current Current number of tasks in the"
                " container cgroup.\n"
                "# TYPE oci2bin_pids_current gauge\n"
                "oci2bin_pids_current %llu\n",
                snap->cpu_usage_usec,
                snap->cpu_user_usec,
                snap->cpu_system_usec,
                snap->cpu_nr_periods,
                snap->cpu_nr_throttled,
                snap->cpu_throttled_usec,
                snap->memory_current,
                snap->pids_current);
    if (n < 0 || (size_t)n >= buf_sz)
    {
        return -1;
    }
    return 0;
}

static pid_t start_metrics_helper(const char* socket_path)
{
    int sync_pipe[2];
    if (pipe(sync_pipe) < 0)
    {
        perror("oci2bin: metrics pipe");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0)
    {
        perror("oci2bin: metrics fork");
        close(sync_pipe[0]);
        close(sync_pipe[1]);
        return -1;
    }
    if (pid == 0)
    {
        close(sync_pipe[0]);
        g_metrics_stop = 0;

        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = metrics_stop_signal;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGHUP, &sa, NULL);

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        if (snprintf(addr.sun_path, sizeof(addr.sun_path), "%s",
                     socket_path) >= (int)sizeof(addr.sun_path))
        {
            fprintf(stderr, "oci2bin: --metrics-socket path too long: %s\n",
                    socket_path);
            (void)write(sync_pipe[1], "0", 1);
            close(sync_pipe[1]);
            _exit(1);
        }

        /* Unlink any stale socket unconditionally; treat ENOENT as OK. */
        if (unlink(socket_path) < 0 && errno != ENOENT)
        {
            fprintf(stderr, "oci2bin: --metrics-socket unlink %s: %s\n",
                    socket_path, strerror(errno));
            (void)write(sync_pipe[1], "0", 1);
            close(sync_pipe[1]);
            _exit(1);
        }

        int listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (listen_fd < 0)
        {
            perror("oci2bin: metrics socket");
            (void)write(sync_pipe[1], "0", 1);
            close(sync_pipe[1]);
            _exit(1);
        }
        if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        {
            fprintf(stderr, "oci2bin: --metrics-socket bind %s: %s\n",
                    socket_path, strerror(errno));
            close(listen_fd);
            (void)write(sync_pipe[1], "0", 1);
            close(sync_pipe[1]);
            _exit(1);
        }
        if (listen(listen_fd, 1) < 0)
        {
            fprintf(stderr, "oci2bin: --metrics-socket listen %s: %s\n",
                    socket_path, strerror(errno));
            unlink(socket_path);
            close(listen_fd);
            (void)write(sync_pipe[1], "0", 1);
            close(sync_pipe[1]);
            _exit(1);
        }

        struct metrics_snapshot snap;
        memset(&snap, 0, sizeof(snap));
        if (read_metrics_snapshot(g_cgroup_fd, &snap) < 0)
        {
            fprintf(stderr, "oci2bin: metrics initial read failed: %s\n",
                    strerror(errno));
        }
        (void)write(sync_pipe[1], "1", 1);
        close(sync_pipe[1]);

        char metrics[2048];
        while (!g_metrics_stop)
        {
            struct pollfd pfd;
            memset(&pfd, 0, sizeof(pfd));
            pfd.fd = listen_fd;
            pfd.events = POLLIN;

            int prc = poll(&pfd, 1, 5000);
            if (prc < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                break;
            }
            if (prc == 0)
            {
                if (read_metrics_snapshot(g_cgroup_fd, &snap) < 0)
                {
                    fprintf(stderr, "oci2bin: metrics read failed: %s\n",
                            strerror(errno));
                }
                continue;
            }
            if (!(pfd.revents & POLLIN))
            {
                continue;
            }

            int client_fd = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
            if (client_fd < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                break;
            }
            if (read_metrics_snapshot(g_cgroup_fd, &snap) < 0)
            {
                fprintf(stderr, "oci2bin: metrics read failed: %s\n",
                        strerror(errno));
            }
            if (format_metrics_text(&snap, metrics, sizeof(metrics)) == 0)
            {
                write_all_fd(client_fd, metrics, strlen(metrics));
            }
            close(client_fd);
        }

        unlink(socket_path);
        close(listen_fd);
        _exit(0);
    }

    close(sync_pipe[1]);
    char ready = '0';
    ssize_t nr;
    do
    {
        nr = read(sync_pipe[0], &ready, 1);
    }
    while (nr < 0 && errno == EINTR);
    close(sync_pipe[0]);
    if (nr != 1 || ready != '1')
    {
        waitpid(pid, NULL, 0);
        return -1;
    }
    return pid;
}

/* Write a formatted value to a cgroup knob under g_cgroup_dir.
 * Non-fatal: prints a warning on any failure. */
__attribute__((format(printf, 2, 3)))
static void cg_set(const char* knob, const char* fmt, ...)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", g_cgroup_dir, knob);
    if (n < 0 || n >= (int)sizeof(path))
    {
        fprintf(stderr, "oci2bin: cgroup %s path truncated\n", knob);
        return;
    }
    char val[64];
    va_list ap;
    va_start(ap, fmt);
    int vn = vsnprintf(val, sizeof(val), fmt, ap);
    va_end(ap);
    if (vn < 0 || vn >= (int)sizeof(val))
    {
        fprintf(stderr, "oci2bin: cgroup %s value out of range\n", knob);
        return;
    }
    cg_write(path, val);
}

static void cleanup_cgroup(void)
{
    if (g_cgroup_fd >= 0)
    {
        close(g_cgroup_fd);
        g_cgroup_fd = -1;
    }
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
    if (!opts->cg_memory_bytes && !opts->cg_cpu_quota &&
            !opts->cg_pids && !opts->metrics_socket)
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

    if (opts->cg_memory_bytes > 0)
    {
        cg_set("memory.max", "%lld\n", opts->cg_memory_bytes);
    }
    if (opts->cg_cpu_quota > 0)
    {
        cg_set("cpu.max", "%ld 100000\n", opts->cg_cpu_quota);
    }
    if (opts->cg_pids > 0)
    {
        cg_set("pids.max", "%ld\n", opts->cg_pids);
    }

    /* Open the cgroup directory fd for use with clone3(CLONE_INTO_CGROUP).
     * The container child will be spawned directly into this cgroup without
     * the parent ever joining it, eliminating the parent's resource usage
     * from the container's accounting and closing the post-fork write race. */
    g_cgroup_fd = open(g_cgroup_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (g_cgroup_fd < 0)
    {
        fprintf(stderr, "oci2bin: cgroup open %s: %s\n",
                g_cgroup_dir, strerror(errno));
        rmdir(g_cgroup_dir);
        g_cgroup_dir[0] = '\0';
        return 0;
    }

    atexit(cleanup_cgroup);
    return 1; /* caller should unshare(CLONE_NEWCGROUP) */
}

/*
 * Fork a child into the pre-created cgroup (g_cgroup_fd) using
 * clone3(CLONE_INTO_CGROUP) when available (Linux 5.7+).  Falls back
 * to plain fork() followed by writing the child's PID to cgroup.procs.
 * Returns the child PID (>0 in parent, 0 in child) or -1 on error.
 */
static pid_t fork_into_cgroup(void)
{
    if (g_cgroup_fd >= 0 && kernel_supports_clone3())
    {
#ifdef __NR_clone3
        struct clone_args args;
        memset(&args, 0, sizeof(args));
        args.flags = CLONE_INTO_CGROUP;
        args.cgroup = (uint64_t)g_cgroup_fd;
        args.exit_signal = SIGCHLD;
        pid_t pid = (pid_t)syscall(__NR_clone3, &args, sizeof(args));
        if (pid >= 0)
        {
            return pid;
        }
        if (errno == ENOSYS)
        {
            kernel_set_feature_state(KERNEL_FEATURE_CLONE3,
                                     KERNEL_FEATURE_UNSUPPORTED);
        }
        else if (errno != EINVAL)
        {
            return pid;
        }
#endif
    }
    pid_t pid = fork();
    if (pid == 0 && g_cgroup_fd >= 0)
    {
        /* Child: write own PID to cgroup.procs (fallback path only) */
        char pid_str[16];
        int n = snprintf(pid_str, sizeof(pid_str), "%d\n", (int)getpid());
        if (n > 0 && n < (int)sizeof(pid_str))
        {
            int procs_fd = openat(g_cgroup_fd, "cgroup.procs",
                                  O_WRONLY | O_CLOEXEC);
            if (procs_fd >= 0)
            {
                write_all_fd(procs_fd, pid_str, (size_t)n);
                close(procs_fd);
            }
        }
    }
    return pid;
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

    if (copy_n_bytes(in_fd, out_fd, size) < 0)
    {
        close(in_fd);
        close(out_fd);
        return -1;
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
    size_t dbg_cmdline_size = 0;
    char* dbg_cmdline = read_file("/proc/cmdline", &dbg_cmdline_size);
    (void)dbg_cmdline_size;
    if (dbg_cmdline && strstr(dbg_cmdline, "OCI2BIN_DEBUG=1"))
    {
        g_debug = 1;
    }
    free(dbg_cmdline);

    debug_log("vm.init.begin", "bootstrap=1");

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

    /* 3. Read OCI config and build exec argv */
    struct oci_config oci_cfg;
    if (read_oci_config("", &oci_cfg) < 0)
    {
        fprintf(stderr, "oci2bin-init: /.oci2bin_config not found\n");
        return 1;
    }

    char* exec_args[MAX_ARGS + 1];
    int exec_argc = build_exec_args(&oci_cfg, NULL, NULL, 0, exec_args,
                                    MAX_ARGS);
    if (g_debug)
    {
        for (int i = 0; i < exec_argc; i++)
        {
            debug_log("vm.init.exec_arg", "index=%d value=%s", i,
                      safe_str(exec_args[i]));
        }
    }

    /* 4. Build flat env array */
    char* flat_env[MAX_ENV + 1];
    int flat_env_n = 0;

    /* Seed with defaults */
    flat_env[flat_env_n++] =
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    flat_env[flat_env_n++] = "HOME=/root";
    flat_env[flat_env_n++] = "TERM=xterm";

    char* image_envs[MAX_ENV];
    int n_image_env = 0;
    if (oci_cfg.env_json && strcmp(oci_cfg.env_json, "null") != 0)
    {
        n_image_env = json_parse_string_array(oci_cfg.env_json,
                                              image_envs, MAX_ENV);
        for (int i = 0; i < n_image_env && flat_env_n < MAX_ENV; i++)
        {
            flat_env[flat_env_n++] = image_envs[i];
        }
    }
    flat_env[flat_env_n] = NULL;

    /* 5. chdir to workdir */
    if (oci_cfg.workdir && oci_cfg.workdir[0])
    {
        if (chdir(oci_cfg.workdir) < 0)
        {
            perror("chdir workdir"); /* non-fatal */
        }
    }

    /* 6. exec */
    debug_log("vm.init.exec", "path=%s argc=%d env=%d", safe_str(exec_args[0]),
              exec_argc, flat_env_n);
    execvpe(exec_args[0], exec_args, flat_env);
    perror("oci2bin-init: execvpe");

    /* Cleanup on failure */
    for (int i = 0; i < n_image_env; i++)
    {
        free(image_envs[i]);
    }
    free_oci_config(&oci_cfg);
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
    debug_log("vm.libkrun.begin", "rootfs=%s", rootfs);

    /* Read OCI config and build exec argv */
    struct oci_config oci_cfg;
    if (read_oci_config(rootfs, &oci_cfg) < 0)
    {
        fprintf(stderr, "oci2bin: cannot read OCI config\n");
        return 1;
    }

    char* exec_args[MAX_ARGS + 1];
    build_exec_args(&oci_cfg, opts->entrypoint,
                    opts->extra_args, opts->n_extra,
                    exec_args, MAX_ARGS);

    /* Build flat env array (image Env + opts->env_vars) */
    char* flat_env[MAX_ENV + 1];
    int flat_env_n = 0;
    char* image_envs[MAX_ENV];
    int n_image_env = 0;

    if (oci_cfg.env_json && strcmp(oci_cfg.env_json, "null") != 0)
    {
        n_image_env = json_parse_string_array(oci_cfg.env_json,
                                              image_envs, MAX_ENV);
        for (int i = 0; i < n_image_env && flat_env_n < MAX_ENV; i++)
        {
            flat_env[flat_env_n++] = image_envs[i];
        }
    }

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
    uint8_t vcpus = (opts->vm_cpus > 0.0) ?
                    (uint8_t)(opts->vm_cpus < 255.0 ?
                              (int)(opts->vm_cpus + 0.5) : 255)
                    : DEFAULT_VM_CPUS;
    uint32_t mem_mb =
        (opts->cg_memory_bytes > 0) ?
        (uint32_t)((unsigned long long)opts->cg_memory_bytes >> 20)
        : DEFAULT_VM_MEM_MB;
    debug_log("vm.libkrun.config", "vcpus=%u mem_mb=%u", (unsigned)vcpus,
              (unsigned)mem_mb);
    if (krun_set_vm_config((uint32_t)ctx, vcpus, mem_mb) != 0)
    {
        fprintf(stderr, "oci2bin: krun_set_vm_config failed\n");
        goto cleanup;
    }

    /* Ensure VM guest has a usable /etc/resolv.conf (not 127.0.0.53) */
    install_resolv_conf(rootfs);

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
                           (oci_cfg.workdir ? oci_cfg.workdir : NULL);
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

    /* Set exec */
    if (krun_set_exec((uint32_t)ctx, exec_args[0],
                      (const char* const *)(exec_args + 1),
                      (const char* const *)flat_env) != 0)
    {
        fprintf(stderr, "oci2bin: krun_set_exec failed\n");
        goto cleanup_ctx;
    }

    /* Start VM — does not return on success */
    debug_log("vm.libkrun.start", "entering_guest=1");
    if (krun_start_enter((uint32_t)ctx) != 0)
    {
        fprintf(stderr, "oci2bin: krun_start_enter returned unexpectedly\n");
    }

cleanup_ctx:
    for (int i = 0; i < n_image_env; i++)
    {
        free(image_envs[i]);
    }
    free_oci_config(&oci_cfg);
    return 1;

cleanup:
    for (int i = 0; i < n_image_env; i++)
    {
        free(image_envs[i]);
    }
    free_oci_config(&oci_cfg);
    return 1;
}
#endif /* USE_LIBKRUN */

/*
 * All path/string buffers for run_as_vm_ch in one heap-allocated block.
 * Keeps the function's stack frame small and makes lifetime explicit.
 */
struct vm_ch_ctx
{
    char kernel_path[PATH_MAX];
    char initramfs_path[PATH_MAX];
    char init_dst[PATH_MAX];
    char self_path[PATH_MAX];
    char self_dir[PATH_MAX];
    char polyglot_py[PATH_MAX];
    char data_img_path[PATH_MAX];
    char disk_arg[PATH_MAX + 16];
    char cpus_str[32];
    char mem_str[32];
    char cmdline[4096];
    char fs_args[MAX_VOLUMES][PATH_MAX + 64];
    char cpbuf[65536];
    const char* argv[128];
};

/* ── vm_ch helpers (return 0 on success, -1 on error) ─────────────────── */

/* Copy /proc/self/exe to dest_path and chmod 0755. */
static int vm_ch_copy_self_to_init(struct vm_ch_ctx* ctx, const char* dest_path)
{
    int src_fd = open("/proc/self/exe", O_RDONLY);
    if (src_fd < 0)
    {
        perror("oci2bin: open /proc/self/exe for init copy");
        return -1;
    }
    int dst_fd = open(dest_path, O_CREAT | O_WRONLY | O_TRUNC, 0755);
    if (dst_fd < 0)
    {
        perror("oci2bin: open rootfs/init for writing");
        close(src_fd);
        return -1;
    }
    ssize_t nr;
    int copy_err = 0;
    while (1)
    {
        do
        {
            nr = read(src_fd, ctx->cpbuf, sizeof(ctx->cpbuf));
        }
        while (nr < 0 && errno == EINTR);
        if (nr == 0)
        {
            break;
        }
        if (nr < 0 || write_all_fd(dst_fd, ctx->cpbuf, (size_t)nr) < 0)
        {
            perror("oci2bin: write rootfs/init");
            copy_err = 1;
            break;
        }
    }
    close(src_fd);
    /* fchmod on the open fd avoids the TOCTOU race that chmod(path) has
     * between close() and the subsequent path lookup. */
    if (!copy_err && fchmod(dst_fd, 0755) < 0)
    {
        perror("oci2bin: fchmod rootfs/init");
        copy_err = 1;
    }
    if (close(dst_fd) < 0 || copy_err)
    {
        if (!copy_err)
        {
            perror("oci2bin: close rootfs/init");
        }
        return -1;
    }
    return 0;
}

/*
 * Resolve the path to build_polyglot.py relative to /proc/self/exe.
 * Writes result into ctx->polyglot_py.  Falls back to the system path.
 */
static int vm_ch_find_polyglot_py(struct vm_ch_ctx* ctx)
{
    ssize_t slen = readlink("/proc/self/exe", ctx->self_path,
                            sizeof(ctx->self_path) - 1);
    if (slen < 0)
    {
        perror("oci2bin: readlink /proc/self/exe (initramfs)");
        return -1;
    }
    ctx->self_path[slen] = '\0';

    int n = snprintf(ctx->self_dir, sizeof(ctx->self_dir),
                     "%s", ctx->self_path);
    if (n < 0 || (size_t)n >= sizeof(ctx->self_dir))
    {
        fprintf(stderr, "oci2bin: self_dir path truncated\n");
        return -1;
    }
    char* slash = strrchr(ctx->self_dir, '/');
    if (slash)
    {
        *slash = '\0';
    }

    static const char* const PY_SUFFIXES[] =
    {
        "/scripts/build_polyglot.py",
        "/../scripts/build_polyglot.py",
        "/../../share/oci2bin/scripts/build_polyglot.py",
        NULL,
    };
    struct stat pystat;
    for (int si = 0; PY_SUFFIXES[si]; si++)
    {
        n = snprintf(ctx->polyglot_py, sizeof(ctx->polyglot_py),
                     "%s%s", ctx->self_dir, PY_SUFFIXES[si]);
        if (n > 0 && (size_t)n < sizeof(ctx->polyglot_py) &&
                stat(ctx->polyglot_py, &pystat) == 0)
        {
            return 0;
        }
    }
    /* System fallback */
    n = snprintf(ctx->polyglot_py, sizeof(ctx->polyglot_py),
                 "/usr/share/oci2bin/scripts/build_polyglot.py");
    if (n < 0 || (size_t)n >= sizeof(ctx->polyglot_py))
    {
        fprintf(stderr, "oci2bin: build_polyglot.py path truncated\n");
        return -1;
    }
    return 0;
}

/*
 * Build the initramfs cpio.gz from rootfs by invoking build_polyglot.py.
 * Writes the result to ctx->initramfs_path, which must already be set.
 * Also copies /proc/self/exe to rootfs/init (VM PID 1).
 */
static int vm_ch_build_initramfs(struct vm_ch_ctx* ctx, const char* rootfs)
{
    int n = snprintf(ctx->init_dst, sizeof(ctx->init_dst),
                     "%s/init", rootfs);
    if (n < 0 || (size_t)n >= sizeof(ctx->init_dst))
    {
        fprintf(stderr, "oci2bin: init path truncated\n");
        return -1;
    }
    if (vm_ch_copy_self_to_init(ctx, ctx->init_dst) < 0)
    {
        return -1;
    }
    if (vm_ch_find_polyglot_py(ctx) < 0)
    {
        return -1;
    }

    char* py_args[] =
    {
        "python3", ctx->polyglot_py,
        "--initramfs-only", (char*)rootfs, ctx->initramfs_path,
        NULL
    };
    if (run_cmd(py_args) != 0)
    {
        fprintf(stderr, "oci2bin: initramfs build failed\n");
        return -1;
    }
    debug_log("vm.ch.initramfs", "source=built path=%s", ctx->initramfs_path);
    return 0;
}

/*
 * Ensure a persistent ext2 data disk exists at opts->overlay_persist.
 * Writes the image path into ctx->data_img_path.
 * Returns 1 if a data disk was prepared, 0 if overlay_persist is unset,
 * -1 on error.
 */
static int vm_ch_prepare_data_disk(struct vm_ch_ctx* ctx,
                                   struct container_opts* opts)
{
    if (!opts->overlay_persist)
    {
        return 0;
    }
    if (strstr(opts->overlay_persist, "..") != NULL)
    {
        fprintf(stderr, "oci2bin: --overlay-persist path contains ..\n");
        return -1;
    }
    int n = snprintf(ctx->data_img_path, sizeof(ctx->data_img_path),
                     "%s/oci2bin-data.ext2", opts->overlay_persist);
    if (n < 0 || (size_t)n >= sizeof(ctx->data_img_path))
    {
        fprintf(stderr, "oci2bin: overlay_persist path too long\n");
        return -1;
    }
    if (mkdir(opts->overlay_persist, 0700) < 0 && errno != EEXIST)
    {
        perror("oci2bin: mkdir overlay_persist");
        return -1;
    }
    struct stat st;
    if (stat(ctx->data_img_path, &st) == 0)
    {
        return 1; /* already exists */
    }
    /* Create sparse 1 GiB file then format as ext2 */
    int fd = open(ctx->data_img_path, O_CREAT | O_RDWR | O_TRUNC, 0600);
    if (fd < 0)
    {
        perror("oci2bin: open data_img");
        return -1;
    }
    if (ftruncate(fd, 1073741824LL) < 0)
    {
        perror("oci2bin: ftruncate data_img");
        close(fd);
        return -1;
    }
    close(fd);
    char* mkfs_argv[] = { "mkfs.ext2", "-F", ctx->data_img_path, NULL };
    if (run_cmd(mkfs_argv) != 0)
    {
        fprintf(stderr, "oci2bin: mkfs.ext2 failed\n");
        return -1;
    }
    return 1;
}

/*
 * Assemble the kernel command line into ctx->cmdline.
 * have_data_disk: 1 if a persistent data disk was prepared.
 */
static int vm_ch_build_cmdline(struct vm_ch_ctx* ctx,
                               struct container_opts* opts, int have_data_disk)
{
    int n = snprintf(ctx->cmdline, sizeof(ctx->cmdline),
                     "console=ttyS0 reboot=k panic=1 pci=off"
                     " OCI2BIN_VM_INIT=1 init=/init");
    if (n < 0 || (size_t)n >= sizeof(ctx->cmdline))
    {
        fprintf(stderr, "oci2bin: cmdline truncated\n");
        return -1;
    }

    /* Append a formatted string to ctx->cmdline; return -1 on truncation. */
#define CMDLINE_APPEND(fmt, ...) \
    do { \
        size_t _cur = strlen(ctx->cmdline); \
        int _cn = snprintf(ctx->cmdline + _cur, \
                           sizeof(ctx->cmdline) - _cur, fmt, ##__VA_ARGS__); \
        if (_cn < 0 || (size_t)_cn >= sizeof(ctx->cmdline) - _cur) { \
            fprintf(stderr, "oci2bin: cmdline truncated\n"); \
            return -1; \
        } \
    } while (0)

    if (opts->debug)
    {
        CMDLINE_APPEND(" OCI2BIN_DEBUG=1");
    }
    if (have_data_disk)
    {
        CMDLINE_APPEND(" oci2bin.data=/dev/vda");
    }
    for (int vi = 0; vi < opts->n_vols; vi++)
    {
        if (strstr(opts->vol_ctr[vi], "..") != NULL ||
                opts->vol_ctr[vi][0] != '/' ||
                strchr(opts->vol_ctr[vi], ' ') != NULL)
        {
            fprintf(stderr, "oci2bin: -v container path invalid: %s\n",
                    opts->vol_ctr[vi]);
            return -1;
        }
        CMDLINE_APPEND(" oci2bin.mount.%d=vol%d:%s", vi, vi,
                       opts->vol_ctr[vi]);
    }
#undef CMDLINE_APPEND
    return 0;
}

/*
 * For each -v volume: fork a virtiofsd daemon and append --fs to ctx->argv.
 * *ai is updated as args are appended.
 */
static int vm_ch_start_virtiofsd(struct vm_ch_ctx* ctx,
                                 struct container_opts* opts,
                                 const char* tmpdir, int* ai)
{
    for (int vi = 0; vi < opts->n_vols; vi++)
    {
        if (strstr(opts->vol_host[vi], "..") != NULL)
        {
            fprintf(stderr, "oci2bin: -v host path contains ..: %s\n",
                    opts->vol_host[vi]);
            return -1;
        }
        char sock_path[PATH_MAX];
        int nn = snprintf(sock_path, sizeof(sock_path),
                          "%s/vfs-%d.sock", tmpdir, vi);
        if (nn < 0 || (size_t)nn >= sizeof(sock_path))
        {
            fprintf(stderr, "oci2bin: virtiofs sock path too long\n");
            return -1;
        }
        char* vfsd_argv[] =
        {
            "virtiofsd",
            "--socket-path", sock_path,
            "--shared-dir",  opts->vol_host[vi],
            "--sandbox",     "namespace",
            NULL
        };
        /* spawn_daemon: virtiofsd runs for the lifetime of the VM */
        if (spawn_daemon(vfsd_argv) < 0)
        {
            return -1;
        }
        nn = snprintf(ctx->fs_args[vi], sizeof(ctx->fs_args[vi]),
                      "tag=vol%d,socket=%s,num_queues=1,queue_size=512",
                      vi, sock_path);
        if (nn < 0 || (size_t)nn >= sizeof(ctx->fs_args[vi]))
        {
            fprintf(stderr, "oci2bin: --fs arg too long\n");
            return -1;
        }
        if (*ai >= 126)
        {
            fprintf(stderr, "oci2bin: too many cloud-hypervisor args\n");
            return -1;
        }
        ctx->argv[(*ai)++] = "--fs";
        if (*ai >= 126)
        {
            fprintf(stderr, "oci2bin: too many cloud-hypervisor args\n");
            return -1;
        }
        ctx->argv[(*ai)++] = ctx->fs_args[vi];
    }
    return 0;
}

/* ── run_as_vm_ch ──────────────────────────────────────────────────────── */

/*
 * Launch cloud-hypervisor with the kernel + initramfs embedded in this
 * binary.  Calls execvp — does not return on success.
 */
static int run_as_vm_ch(const char* rootfs, const char* tmpdir,
                        struct container_opts* opts)
{
    debug_log("vm.ch.begin", "rootfs=%s tmpdir=%s", rootfs, tmpdir);
    install_resolv_conf(rootfs);

    if (KERNEL_DATA_PATCHED != 1)
    {
        fprintf(stderr,
                "oci2bin: --vm: no kernel embedded; "
                "rebuild with: oci2bin --kernel build/vmlinux IMAGE OUTPUT\n"
                "  or build with: make LIBKRUN=1 (no kernel needed)\n");
        return 1;
    }

    struct vm_ch_ctx* ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
    {
        perror("oci2bin: vm_ch_ctx alloc");
        return 1;
    }

#define CH_CALL(expr) do { if ((expr) < 0) { free(ctx); return 1; } } while (0)

    /* 1. Extract kernel blob */
    int n = snprintf(ctx->kernel_path, sizeof(ctx->kernel_path),
                     "%s/vmlinux", tmpdir);
    if (n < 0 || (size_t)n >= sizeof(ctx->kernel_path))
    {
        fprintf(stderr, "oci2bin: kernel path truncated\n");
        free(ctx);
        return 1;
    }
    CH_CALL(extract_vm_blob(KERNEL_DATA_OFFSET, KERNEL_DATA_SIZE,
                            ctx->kernel_path));
    debug_log("vm.ch.kernel", "path=%s size=%lu", ctx->kernel_path,
              KERNEL_DATA_SIZE);

    /* 2. Extract or build initramfs */
    n = snprintf(ctx->initramfs_path, sizeof(ctx->initramfs_path),
                 "%s/rootfs.cpio.gz", tmpdir);
    if (n < 0 || (size_t)n >= sizeof(ctx->initramfs_path))
    {
        fprintf(stderr, "oci2bin: initramfs path truncated\n");
        free(ctx);
        return 1;
    }
    if (INITRAMFS_DATA_PATCHED == 1)
    {
        CH_CALL(extract_vm_blob(INITRAMFS_DATA_OFFSET, INITRAMFS_DATA_SIZE,
                                ctx->initramfs_path));
        debug_log("vm.ch.initramfs", "source=embedded path=%s size=%lu",
                  ctx->initramfs_path, INITRAMFS_DATA_SIZE);
    }
    else
    {
        CH_CALL(vm_ch_build_initramfs(ctx, rootfs));
    }

    /* 3. Prepare persistent data disk (0 = none, 1 = ready, -1 = error) */
    int have_data_disk = vm_ch_prepare_data_disk(ctx, opts);
    if (have_data_disk < 0)
    {
        free(ctx);
        return 1;
    }

    /* 4. Build VM resource strings */
    int vcpus = (opts->vm_cpus > 0.0) ? (int)(opts->vm_cpus + 0.5)
                : DEFAULT_VM_CPUS;
    unsigned long mem_mb = (opts->cg_memory_bytes > 0)
                           ? (unsigned long)(opts->cg_memory_bytes >> 20)
                           : DEFAULT_VM_MEM_MB;
    n = snprintf(ctx->cpus_str, sizeof(ctx->cpus_str), "boot=%d", vcpus);
    if (n < 0 || (size_t)n >= sizeof(ctx->cpus_str))
    {
        fprintf(stderr, "oci2bin: cpus string truncated\n");
        free(ctx);
        return 1;
    }
    n = snprintf(ctx->mem_str, sizeof(ctx->mem_str), "size=%luM", mem_mb);
    if (n < 0 || (size_t)n >= sizeof(ctx->mem_str))
    {
        fprintf(stderr, "oci2bin: memory string truncated\n");
        free(ctx);
        return 1;
    }

    /* 5. Build kernel cmdline */
    CH_CALL(vm_ch_build_cmdline(ctx, opts, have_data_disk));

    /* 6. Assemble cloud-hypervisor argv */
    const char* vmm_bin = opts->vmm ? opts->vmm : "cloud-hypervisor";
    debug_log("vm.ch.config", "vmm=%s vcpus=%d mem_mb=%lu", vmm_bin, vcpus,
              mem_mb);
    debug_log("vm.ch.cmdline", "value=%s", ctx->cmdline);

    int ai = 0;
    ctx->argv[ai++] = vmm_bin;
    ctx->argv[ai++] = "--kernel";
    ctx->argv[ai++] = ctx->kernel_path;
    ctx->argv[ai++] = "--initramfs";
    ctx->argv[ai++] = ctx->initramfs_path;
    ctx->argv[ai++] = "--cmdline";
    ctx->argv[ai++] = ctx->cmdline;
    ctx->argv[ai++] = "--cpus";
    ctx->argv[ai++] = ctx->cpus_str;
    ctx->argv[ai++] = "--memory";
    ctx->argv[ai++] = ctx->mem_str;

    if (have_data_disk)
    {
        n = snprintf(ctx->disk_arg, sizeof(ctx->disk_arg),
                     "path=%s", ctx->data_img_path);
        if (n < 0 || (size_t)n >= sizeof(ctx->disk_arg))
        {
            fprintf(stderr, "oci2bin: disk arg too long\n");
            free(ctx);
            return 1;
        }
        ctx->argv[ai++] = "--disk";
        ctx->argv[ai++] = ctx->disk_arg;
    }

    /* 7. Start virtiofsd daemons for -v mounts */
    CH_CALL(vm_ch_start_virtiofsd(ctx, opts, tmpdir, &ai));

    ctx->argv[ai] = NULL;
#undef CH_CALL

    debug_log("vm.ch.exec", "binary=%s argc=%d", vmm_bin, ai);
    /* ctx intentionally not freed: execvp replaces the process image and
     * ctx->argv contains pointers into ctx. */
    execvp(vmm_bin, (char* const*)ctx->argv);
    perror("execvp cloud-hypervisor");
    free(ctx);
    return 1;
}

/* ── oci2vm mode ─────────────────────────────────────────────────────────── */

/*
 * When invoked as "oci2vm" (via symlink or renamed binary), prepend "--vm"
 * to argv so VM mode is the default without the user typing --vm every time.
 * Returns a new heap-allocated argv (permanent for process lifetime) with
 * argc incremented, or NULL on allocation failure.
 */
static char** inject_vm_flag(int argc, char* argv[], int* out_argc)
{
    char** merged = malloc((size_t)(argc + 2) * sizeof(char*));
    if (!merged)
    {
        return NULL;
    }
    merged[0] = argv[0];
    merged[1] = (char*)"--vm";
    for (int i = 1; i < argc; i++)
    {
        merged[i + 1] = argv[i];
    }
    merged[argc + 1] = NULL;
    *out_argc = argc + 1;
    return merged;
}

/* ── namespace helpers ───────────────────────────────────────────────────── */

/*
 * Open /proc/<pid>/ns/<ns_name> and call setns(fd, ns_flag).
 * Returns 0 on success, -1 on failure (message already printed).
 */
static int join_ns_of_pid(pid_t pid, int ns_flag, const char* ns_name)
{
    char ns_path[PATH_MAX];
    int n = snprintf(ns_path, sizeof(ns_path),
                     "/proc/%d/ns/%s", (int)pid, ns_name);
    if (n < 0 || n >= (int)sizeof(ns_path))
    {
        fprintf(stderr, "oci2bin: %s ns path truncated\n", ns_name);
        return -1;
    }
    int fd = open(ns_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
    {
        fprintf(stderr, "oci2bin: open %s namespace: %s\n",
                ns_name, strerror(errno));
        return -1;
    }
    if (setns(fd, ns_flag) < 0)
    {
        fprintf(stderr, "oci2bin: setns(%s): %s\n"
                        "oci2bin: joining another container's %s namespace requires\n"
                        "oci2bin: the target to share the same user namespace owner,"
                        " or root privileges\n",
                ns_name, strerror(errno), ns_name);
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

/* ── MCP JSON-RPC 2.0 server ─────────────────────────────────────────────── */

/*
 * Minimal stdio MCP (Model Context Protocol) server using JSON-RPC 2.0.
 * Transport: newline-delimited JSON (one request per line on stdin, one
 * response per line on stdout).
 *
 * Security defaults:
 *  - --net none unless session was started with --allow-net AND caller
 *    explicitly passes net="host".
 *  - No --device flags ever exposed through MCP.
 *  - All string inputs validated for length and path safety before use.
 */

#define MCP_MAX_CONTAINERS  64
#define MCP_LINE_MAX        (512 * 1024)
#define MCP_NAME_MAX        128
#define MCP_ENV_MAX         64
#define MCP_VOL_MAX         32
#define MCP_CMD_MAX         64

struct mcp_ctr
{
    char  name[MCP_NAME_MAX];
    pid_t pid;
    char  log_path[PATH_MAX];
};

static struct mcp_ctr g_mcp_ctrs[MCP_MAX_CONTAINERS];
static int            g_mcp_n_ctrs;

/* Validate an MCP container name: alphanumeric, '-', '_', '.' only */
static int mcp_name_valid(const char* s)
{
    if (!s || s[0] == '\0' || strlen(s) >= MCP_NAME_MAX)
    {
        return 0;
    }
    for (const char* p = s; *p; p++)
    {
        if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_' && *p != '.')
        {
            return 0;
        }
    }
    return 1;
}

/* Write JSON-RPC success response to stdout */
static void mcp_send_result(long id, const char* result_json)
{
    char hdr[128];
    int  n = snprintf(hdr, sizeof(hdr),
                      "{\"jsonrpc\":\"2.0\",\"id\":%ld,\"result\":", id);
    if (n > 0 && (size_t)n < sizeof(hdr))
    {
        write_all_fd(STDOUT_FILENO, hdr, (size_t)n);
    }
    write_all_fd(STDOUT_FILENO, result_json ? result_json : "null",
                 result_json ? strlen(result_json) : 4);
    write_all_fd(STDOUT_FILENO, "}\n", 2);
}

/* Write JSON-RPC error response to stdout */
static void mcp_send_error(long id, int code, const char* msg)
{
    char esc[512];
    if (json_escape_string(msg, esc, sizeof(esc)) < 0)
    {
        esc[0] = '\0';
    }
    char buf[1024];
    int n = snprintf(buf, sizeof(buf),
                     "{\"jsonrpc\":\"2.0\",\"id\":%ld,"
                     "\"error\":{\"code\":%d,\"message\":\"%s\"}}\n",
                     id, code, esc);
    if (n > 0 && (size_t)n < sizeof(buf))
    {
        write_all_fd(STDOUT_FILENO, buf, (size_t)n);
    }
}

/* Find a tracked container by name; returns index or -1 */
static int mcp_find_ctr(const char* name)
{
    for (int i = 0; i < g_mcp_n_ctrs; i++)
    {
        if (g_mcp_ctrs[i].pid > 0 &&
                strcmp(g_mcp_ctrs[i].name, name) == 0)
        {
            return i;
        }
    }
    return -1;
}

/* tools/call: run_container */
static void mcp_tool_run_container(long id, const char* args_json,
                                   const char* self_path, int allow_net)
{
    char* image = json_get_string(args_json, "image");
    char* name  = json_get_string(args_json, "name");
    char* net   = json_get_string(args_json, "net");
    char* env_arr = json_get_array(args_json, "env");
    char* vol_arr = json_get_array(args_json, "volumes");

    /* Validate image path */
    if (!image || !path_is_absolute_and_clean(image))
    {
        mcp_send_error(id, -32602,
                       "run_container: 'image' must be an absolute path");
        free(image);
        free(name);
        free(net);
        free(env_arr);
        free(vol_arr);
        return;
    }
    if (access(image, X_OK) < 0)
    {
        mcp_send_error(id, -32602,
                       "run_container: 'image' is not executable");
        free(image);
        free(name);
        free(net);
        free(env_arr);
        free(vol_arr);
        return;
    }

    /* Auto-generate name if not provided */
    char auto_name[MCP_NAME_MAX];
    if (!name || !mcp_name_valid(name))
    {
        free(name);
        snprintf(auto_name, sizeof(auto_name), "ctr-%d", (int)getpid());
        name = auto_name;
    }

    /* Net mode: default none; host only if allow_net AND caller asked */
    const char* net_mode = "none";
    if (net && strcmp(net, "host") == 0 && allow_net)
    {
        net_mode = "host";
    }

    if (g_mcp_n_ctrs >= MCP_MAX_CONTAINERS)
    {
        mcp_send_error(id, -32603,
                       "run_container: too many tracked containers");
        if (name != auto_name)
        {
            free(name);
        }
        free(image);
        free(net);
        free(env_arr);
        free(vol_arr);
        return;
    }

    if (mcp_find_ctr(name) >= 0)
    {
        mcp_send_error(id, -32602,
                       "run_container: a container with that name already exists");
        if (name != auto_name)
        {
            free(name);
        }
        free(image);
        free(net);
        free(env_arr);
        free(vol_arr);
        return;
    }

    /* Build log path */
    char log_path[PATH_MAX];
    if (snprintf(log_path, sizeof(log_path),
                 "/tmp/oci2bin-mcp-%s.log", name) >= (int)sizeof(log_path))
    {
        mcp_send_error(id, -32603, "run_container: container name too long");
        if (name != auto_name)
        {
            free(name);
        }
        free(image);
        free(net);
        free(env_arr);
        free(vol_arr);
        return;
    }

    /* Parse env and volumes */
    char* env_strs[MCP_ENV_MAX];
    int   n_env = 0;
    if (env_arr)
    {
        n_env = json_parse_string_array(env_arr, env_strs, MCP_ENV_MAX);
    }

    char* vol_strs[MCP_VOL_MAX];
    int   n_vol = 0;
    if (vol_arr)
    {
        int raw_n_vol = json_parse_string_array(vol_arr, vol_strs, MCP_VOL_MAX);
        /* Validate each volume spec: HOST:CONTAINER — both must be absolute
         * clean paths with no '..' components. */
        for (int i = 0; i < raw_n_vol; i++)
        {
            char* colon = strchr(vol_strs[i], ':');
            int   ok    = 0;
            if (colon)
            {
                *colon = '\0';
                const char* host_part = vol_strs[i];
                const char* ctr_part  = colon + 1;
                /* Strip optional :ro or :rw option suffix */
                const char* ctr_end = strchr(ctr_part, ':');
                char        ctr_buf[PATH_MAX];
                if (ctr_end)
                {
                    size_t clen = (size_t)(ctr_end - ctr_part);
                    if (clen < sizeof(ctr_buf))
                    {
                        memcpy(ctr_buf, ctr_part, clen);
                        ctr_buf[clen] = '\0';
                        ctr_part = ctr_buf;
                    }
                }
                if (path_is_absolute_and_clean(host_part) &&
                        !path_has_dotdot_component(host_part) &&
                        path_is_absolute_and_clean(ctr_part) &&
                        !path_has_dotdot_component(ctr_part))
                {
                    ok = 1;
                }
                *colon = ':'; /* restore for argv */
            }
            if (ok)
            {
                vol_strs[n_vol++] = vol_strs[i];
            }
            else
            {
                fprintf(stderr,
                        "oci2bin: MCP: rejecting invalid volume spec: %s\n",
                        vol_strs[i]);
                free(vol_strs[i]);
            }
        }
    }

    /* Build argv for the container binary */
    char* ctr_argv[8 + MCP_ENV_MAX * 2 + MCP_VOL_MAX * 2 + 2];
    int   ai = 0;
    ctr_argv[ai++] = image;
    ctr_argv[ai++] = "--net";
    ctr_argv[ai++] = (char*)(uintptr_t)net_mode;
    ctr_argv[ai++] = "--name";
    ctr_argv[ai++] = name;
    ctr_argv[ai++] = "--detach";
    for (int i = 0; i < n_env &&
            ai < (int)(sizeof(ctr_argv) / sizeof(ctr_argv[0])) - 3; i++)
    {
        ctr_argv[ai++] = "-e";
        ctr_argv[ai++] = env_strs[i];
    }
    for (int i = 0; i < n_vol &&
            ai < (int)(sizeof(ctr_argv) / sizeof(ctr_argv[0])) - 3; i++)
    {
        ctr_argv[ai++] = "-v";
        ctr_argv[ai++] = vol_strs[i];
    }
    ctr_argv[ai] = NULL;

    /* Open log file before fork.  O_NOFOLLOW prevents a symlink attack on the
     * predictable /tmp/oci2bin-mcp-<name>.log path. */
    int log_fd = open(log_path,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                      0600);
    if (log_fd < 0)
    {
        mcp_send_error(id, -32603, "run_container: cannot open log file");
        goto cleanup_env;
    }

    pid_t child = fork();
    if (child < 0)
    {
        close(log_fd);
        mcp_send_error(id, -32603, "run_container: fork failed");
        goto cleanup_env;
    }

    if (child == 0)
    {
        /* Redirect stdout+stderr to log file */
        dup2(log_fd, STDOUT_FILENO);
        dup2(log_fd, STDERR_FILENO);
        close(log_fd);
        /* stdin = /dev/null */
        int null_fd = open("/dev/null", O_RDONLY);
        if (null_fd >= 0)
        {
            dup2(null_fd, STDIN_FILENO);
            close(null_fd);
        }
        execvp(ctr_argv[0], ctr_argv);
        perror("execvp");
        _exit(127);
    }

    close(log_fd);

    /* Track the container */
    int slot = g_mcp_n_ctrs++;
    strncpy(g_mcp_ctrs[slot].name, name, MCP_NAME_MAX - 1);
    g_mcp_ctrs[slot].name[MCP_NAME_MAX - 1] = '\0';
    g_mcp_ctrs[slot].pid = child;
    strncpy(g_mcp_ctrs[slot].log_path, log_path, PATH_MAX - 1);
    g_mcp_ctrs[slot].log_path[PATH_MAX - 1] = '\0';

    /* Return container ID */
    char result[256];
    char name_esc[MCP_NAME_MAX * 2];
    json_escape_string(name, name_esc, sizeof(name_esc));
    snprintf(result, sizeof(result),
             "{\"content\":[{\"type\":\"text\",\"text\":\"%s\"}]}",
             name_esc);
    mcp_send_result(id, result);

cleanup_env:
    for (int i = 0; i < n_env; i++)
    {
        free(env_strs[i]);
    }
    for (int i = 0; i < n_vol; i++)
    {
        free(vol_strs[i]);
    }
    if (name != auto_name)
    {
        free(name);
    }
    free(image);
    free(net);
    free(env_arr);
    free(vol_arr);
}

/* tools/call: list_containers */
static void mcp_tool_list_containers(long id)
{
    char  buf[4096];
    int   pos  = 0;
    int   first = 1;
    const int bufsz = (int)sizeof(buf);

    pos += snprintf(buf + pos, (size_t)(bufsz - pos),
                    "{\"content\":[{\"type\":\"text\",\"text\":\"[");
    for (int i = 0; i < g_mcp_n_ctrs && pos < bufsz - 64; i++)
    {
        struct mcp_ctr* c = &g_mcp_ctrs[i];
        if (c->pid <= 0)
        {
            continue;
        }
        /* Check if still running */
        int status;
        pid_t reaped = waitpid(c->pid, &status, WNOHANG);
        if (reaped == c->pid)
        {
            c->pid = -1;
            continue;
        }
        int running = (kill(c->pid, 0) == 0);

        char name_esc[MCP_NAME_MAX * 2];
        json_escape_string(c->name, name_esc, sizeof(name_esc));
        pos += snprintf(buf + pos, (size_t)(bufsz - pos),
                        "%s{\\\"name\\\":\\\"%s\\\","
                        "\\\"pid\\\":%d,\\\"running\\\":%s}",
                        first ? "" : ",",
                        name_esc,
                        (int)c->pid,
                        running ? "true" : "false");
        first = 0;
    }
    if (pos < bufsz - 8)
    {
        pos += snprintf(buf + pos, (size_t)(bufsz - pos), "]\"}]}");
    }
    buf[bufsz - 1] = '\0';
    mcp_send_result(id, buf);
}

/* tools/call: stop_container */
static void mcp_tool_stop_container(long id, const char* args_json)
{
    char* name = json_get_string(args_json, "name");
    if (!name)
    {
        mcp_send_error(id, -32602, "stop_container: 'name' is required");
        return;
    }

    int idx = mcp_find_ctr(name);
    free(name);
    if (idx < 0)
    {
        mcp_send_error(id, -32602, "stop_container: container not found");
        return;
    }

    pid_t pid = g_mcp_ctrs[idx].pid;
    kill(pid, SIGTERM);

    /* Wait up to 10 seconds */
    int exit_code = -1;
    for (int t = 0; t < 100; t++)
    {
        struct timespec ts = {0, 100000000}; /* 100 ms */
        nanosleep(&ts, NULL);
        int status;
        if (waitpid(pid, &status, WNOHANG) == pid)
        {
            exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            break;
        }
    }
    if (exit_code == -1)
    {
        kill(pid, SIGKILL);
        int status;
        waitpid(pid, &status, 0);
        exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }
    g_mcp_ctrs[idx].pid = -1;

    char result[128];
    snprintf(result, sizeof(result),
             "{\"content\":[{\"type\":\"text\",\"text\":\"%d\"}]}",
             exit_code);
    mcp_send_result(id, result);
}

/* tools/call: exec_in_container */
static void mcp_tool_exec_in_container(long id, const char* args_json)
{
    char* name     = json_get_string(args_json, "name");
    char* cmd_arr  = json_get_array(args_json, "cmd");

    if (!name || !cmd_arr)
    {
        mcp_send_error(id, -32602,
                       "exec_in_container: 'name' and 'cmd' are required");
        free(name);
        free(cmd_arr);
        return;
    }

    int idx = mcp_find_ctr(name);
    free(name);
    if (idx < 0)
    {
        mcp_send_error(id, -32602, "exec_in_container: container not found");
        free(cmd_arr);
        return;
    }

    pid_t ctr_pid = g_mcp_ctrs[idx].pid;
    if (kill(ctr_pid, 0) < 0)
    {
        mcp_send_error(id, -32602, "exec_in_container: container is not running");
        free(cmd_arr);
        return;
    }

    /* Parse cmd array */
    char* cmd_strs[MCP_CMD_MAX];
    int   n_cmd = json_parse_string_array(cmd_arr, cmd_strs, MCP_CMD_MAX);
    free(cmd_arr);
    if (n_cmd == 0)
    {
        mcp_send_error(id, -32602, "exec_in_container: 'cmd' must not be empty");
        return;
    }

    /* Build nsenter argv */
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d", (int)ctr_pid);
    char* ns_argv[16 + MCP_CMD_MAX];
    int   ai = 0;
    ns_argv[ai++] = "nsenter";
    ns_argv[ai++] = "-m";
    ns_argv[ai++] = "-p";
    ns_argv[ai++] = "-u";
    ns_argv[ai++] = "-i";
    ns_argv[ai++] = "--target";
    ns_argv[ai++] = pid_str;
    ns_argv[ai++] = "--";
    for (int i = 0; i < n_cmd
            && ai < (int)(sizeof(ns_argv) / sizeof(ns_argv[0])) - 1; i++)
    {
        ns_argv[ai++] = cmd_strs[i];
    }
    ns_argv[ai] = NULL;

    size_t out_len = 0;
    char*  output  = run_cmd_capture(ns_argv, &out_len);

    for (int i = 0; i < n_cmd; i++)
    {
        free(cmd_strs[i]);
    }

    if (!output)
    {
        mcp_send_error(id, -32603,
                       "exec_in_container: command failed or nsenter unavailable");
        return;
    }

    /* Truncate output to 64 KiB for sanity */
    if (out_len > 65536)
    {
        out_len = 65536;
    }
    output[out_len] = '\0'; /* safe: run_cmd_capture malloc'd len+cap */

    /* Escape and return */
    char* esc = malloc(out_len * 6 + 1);
    if (!esc)
    {
        free(output);
        mcp_send_error(id, -32603, "exec_in_container: out of memory");
        return;
    }
    if (json_escape_string(output, esc, out_len * 6 + 1) < 0)
    {
        esc[0] = '\0';
    }
    free(output);

    size_t rlen = strlen(esc) + 64;
    char*  result = malloc(rlen);
    if (result)
    {
        snprintf(result, rlen,
                 "{\"content\":[{\"type\":\"text\",\"text\":\"%s\"}]}", esc);
        mcp_send_result(id, result);
        free(result);
    }
    free(esc);
}

/* tools/call: inspect_image — forks the image with OCI2BIN_INSPECT=1 */
static void mcp_tool_inspect_image(long id, const char* args_json)
{
    char* image = json_get_string(args_json, "image");
    if (!image || !path_is_absolute_and_clean(image))
    {
        mcp_send_error(id, -32602,
                       "inspect_image: 'image' must be an absolute path");
        free(image);
        return;
    }
    if (access(image, X_OK) < 0)
    {
        mcp_send_error(id, -32602,
                       "inspect_image: 'image' is not executable");
        free(image);
        return;
    }

    /* Set OCI2BIN_INSPECT=1 in child environment */
    char* argv_inspect[] = {image, NULL};

    /* We need to set env var for the child without modifying our env.
     * Fork, set env in child, exec. */
    int pipefd[2];
    if (pipe(pipefd) < 0)
    {
        free(image);
        mcp_send_error(id, -32603, "inspect_image: pipe failed");
        return;
    }
    pid_t child = fork();
    if (child < 0)
    {
        close(pipefd[0]);
        close(pipefd[1]);
        free(image);
        mcp_send_error(id, -32603, "inspect_image: fork failed");
        return;
    }
    if (child == 0)
    {
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0)
        {
            _exit(127);
        }
        close(pipefd[1]);
        setenv("OCI2BIN_INSPECT", "1", 1);
        execvp(image, argv_inspect);
        _exit(127);
    }
    close(pipefd[1]);
    free(image);

    /* Read output */
    size_t cap = 4096, len = 0;
    char*  buf = malloc(cap);
    if (!buf)
    {
        close(pipefd[0]);
        waitpid(child, NULL, 0);
        mcp_send_error(id, -32603, "inspect_image: out of memory");
        return;
    }
    for (;;)
    {
        if (len == cap)
        {
            if (cap >= 256 * 1024)
            {
                break;
            }
            cap *= 2;
            char* nb = realloc(buf, cap);
            if (!nb)
            {
                break;
            }
            buf = nb;
        }
        ssize_t n = read(pipefd[0], buf + len, cap - len);
        if (n <= 0)
        {
            break;
        }
        len += (size_t)n;
    }
    close(pipefd[0]);
    int status;
    waitpid(child, &status, 0);

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || len == 0)
    {
        free(buf);
        mcp_send_error(id, -32603,
                       "inspect_image: image does not support OCI2BIN_INSPECT");
        return;
    }
    buf[len < cap ? len : cap - 1] = '\0';

    /* buf should already be JSON from inspect_image_main() */
    size_t rlen = len + 64;
    char*  result = malloc(rlen);
    if (result)
    {
        snprintf(result, rlen,
                 "{\"content\":[{\"type\":\"text\",\"text\":%s}]}", buf);
        mcp_send_result(id, result);
        free(result);
    }
    free(buf);
}

/* tools/call: get_logs */
static void mcp_tool_get_logs(long id, const char* args_json)
{
    char* name   = json_get_string(args_json, "name");
    char* lines_s = json_get_string(args_json, "lines");

    if (!name)
    {
        mcp_send_error(id, -32602, "get_logs: 'name' is required");
        free(name);
        free(lines_s);
        return;
    }

    int n_lines = 50; /* default */
    if (lines_s)
    {
        char* endp;
        long  v = strtol(lines_s, &endp, 10);
        if (*endp == '\0' && v > 0 && v <= 10000)
        {
            n_lines = (int)v;
        }
        free(lines_s);
    }

    int idx = mcp_find_ctr(name);
    free(name);
    if (idx < 0)
    {
        mcp_send_error(id, -32602, "get_logs: container not found");
        return;
    }

    /* Read log file */
    size_t log_size;
    char*  log_data = read_file(g_mcp_ctrs[idx].log_path, &log_size);
    if (!log_data)
    {
        mcp_send_result(id,
                        "{\"content\":[{\"type\":\"text\",\"text\":\"\"}]}");
        return;
    }

    /* Find the last n_lines lines */
    const char* start = log_data;
    if (log_size > 0)
    {
        /* count newlines from end */
        int nl_count = 0;
        const char* p = log_data + log_size - 1;
        while (p >= log_data && nl_count < n_lines)
        {
            if (*p == '\n')
            {
                nl_count++;
                if (nl_count == n_lines)
                {
                    start = p + 1;
                    break;
                }
            }
            p--;
        }
    }

    size_t tail_len = log_size - (size_t)(start - log_data);
    char*  esc      = malloc(tail_len * 6 + 1);
    if (!esc)
    {
        free(log_data);
        mcp_send_error(id, -32603, "get_logs: out of memory");
        return;
    }
    if (json_escape_string(start, esc, tail_len * 6 + 1) < 0)
    {
        esc[0] = '\0';
    }
    free(log_data);

    size_t rlen = strlen(esc) + 64;
    char*  result = malloc(rlen);
    if (result)
    {
        snprintf(result, rlen,
                 "{\"content\":[{\"type\":\"text\",\"text\":\"%s\"}]}", esc);
        mcp_send_result(id, result);
        free(result);
    }
    free(esc);
}

/* Return the MCP tools/list response JSON */
static const char* mcp_tools_list_json(void)
{
    return "{"
           "\"tools\":["
           "{"
           "\"name\":\"run_container\","
           "\"description\":\"Run an oci2bin container image\","
           "\"inputSchema\":{"
           "\"type\":\"object\","
           "\"properties\":{"
           "\"image\":{\"type\":\"string\",\"description\":\"Absolute path to oci2bin binary\"},"
           "\"name\":{\"type\":\"string\",\"description\":\"Container name (optional)\"},"
           "\"net\":{\"type\":\"string\",\"enum\":[\"none\",\"host\"],\"default\":\"none\"},"
           "\"env\":{\"type\":\"array\",\"items\":{\"type\":\"string\"}},"
           "\"volumes\":{\"type\":\"array\",\"items\":{\"type\":\"string\"}}"
           "},"
           "\"required\":[\"image\"]"
           "}"
           "},"
           "{"
           "\"name\":\"exec_in_container\","
           "\"description\":\"Run a command inside a running container\","
           "\"inputSchema\":{"
           "\"type\":\"object\","
           "\"properties\":{"
           "\"name\":{\"type\":\"string\"},"
           "\"cmd\":{\"type\":\"array\",\"items\":{\"type\":\"string\"}}"
           "},"
           "\"required\":[\"name\",\"cmd\"]"
           "}"
           "},"
           "{"
           "\"name\":\"list_containers\","
           "\"description\":\"List all tracked containers and their status\","
           "\"inputSchema\":{\"type\":\"object\",\"properties\":{}}"
           "},"
           "{"
           "\"name\":\"stop_container\","
           "\"description\":\"Stop a running container\","
           "\"inputSchema\":{"
           "\"type\":\"object\","
           "\"properties\":{\"name\":{\"type\":\"string\"}},"
           "\"required\":[\"name\"]"
           "}"
           "},"
           "{"
           "\"name\":\"inspect_image\","
           "\"description\":\"Inspect OCI metadata of an oci2bin image binary\","
           "\"inputSchema\":{"
           "\"type\":\"object\","
           "\"properties\":{\"image\":{\"type\":\"string\"}},"
           "\"required\":[\"image\"]"
           "}"
           "},"
           "{"
           "\"name\":\"get_logs\","
           "\"description\":\"Get container log output\","
           "\"inputSchema\":{"
           "\"type\":\"object\","
           "\"properties\":{"
           "\"name\":{\"type\":\"string\"},"
           "\"lines\":{\"type\":\"integer\",\"default\":50}"
           "},"
           "\"required\":[\"name\"]"
           "}"
           "}"
           "]"
           "}";
}

/*
 * OCI image inspection: prints JSON metadata to stdout.
 * Called when OCI2BIN_INSPECT=1 is set, before any namespace setup.
 */
static int inspect_image_main(const char* self_path)
{
    int  rc     = 1;
    char tmpdir[PATH_MAX];
    tmpdir[0] = '\0';

    /* Extract OCI tar to a temp dir and read manifest + config */
    if (make_runtime_tmpdir(tmpdir, sizeof(tmpdir), "oci2bin-inspect.") < 0)
    {
        return 1;
    }

    char tar_path[PATH_MAX];
    if (snprintf(tar_path, sizeof(tar_path), "%s/image.tar", tmpdir)
            >= (int)sizeof(tar_path))
    {
        goto out;
    }

    {
        int self_fd = open(self_path, O_RDONLY);
        if (self_fd < 0)
        {
            goto out;
        }
        if (lseek(self_fd, (off_t)OCI_DATA_OFFSET, SEEK_SET) < 0)
        {
            close(self_fd);
            goto out;
        }
        int out_fd = open(tar_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (out_fd < 0)
        {
            close(self_fd);
            goto out;
        }
        if (copy_n_bytes(self_fd, out_fd, OCI_DATA_SIZE) < 0)
        {
            close(self_fd);
            close(out_fd);
            goto out;
        }
        close(self_fd);
        close(out_fd);
    }

    /* Extract OCI tar */
    char oci_dir[PATH_MAX];
    if (snprintf(oci_dir, sizeof(oci_dir), "%s/oci", tmpdir)
            >= (int)sizeof(oci_dir))
    {
        goto out;
    }
    if (mkdir(oci_dir, 0700) < 0)
    {
        goto out;
    }
    {
        char* tar_argv[] =
        {
            "tar", "xf", tar_path, "-C", oci_dir,
            "--no-same-permissions", "--no-same-owner", NULL
        };
        if (run_cmd(tar_argv) != 0)
        {
            goto out;
        }
    }

    /* Read manifest.json */
    char manifest_path[PATH_MAX];
    if (snprintf(manifest_path, sizeof(manifest_path),
                 "%s/manifest.json", oci_dir) >= (int)sizeof(manifest_path))
    {
        goto out;
    }
    {
        size_t manifest_size;
        char*  manifest = read_file(manifest_path, &manifest_size);
        if (!manifest)
        {
            goto out;
        }

        /* Get config digest from manifest */
        char* config_digest = json_get_string(manifest, "Config");
        free(manifest);

        if (!config_digest)
        {
            goto out;
        }

        /* Sanitize config digest: only alnum, ':', '-', '_' — no '/' to prevent
         * path traversal when the digest is appended to oci_dir. */
        for (char* p = config_digest; *p; p++)
        {
            if (!isalnum((unsigned char)*p) && *p != ':' &&
                    *p != '-' && *p != '_')
            {
                *p = '_';
            }
        }

        /* Read config JSON from oci_dir/<digest> */
        char config_path[PATH_MAX];
        int n = snprintf(config_path, sizeof(config_path), "%s/%s",
                         oci_dir, config_digest);
        free(config_digest);
        if (n < 0 || n >= (int)sizeof(config_path))
        {
            goto out;
        }

        /* Reject path traversal (belt-and-suspenders) */
        if (path_has_dotdot_component(config_path))
        {
            goto out;
        }
        /* Reject paths that escape oci_dir (e.g. from a leading '/' in the
         * digest after sanitisation still produced a rooted component). */
        size_t oci_dir_len = strlen(oci_dir);
        if (strncmp(config_path, oci_dir, oci_dir_len) != 0 ||
                config_path[oci_dir_len] != '/')
        {
            goto out;
        }

        size_t config_size;
        char*  config_json = read_file(config_path, &config_size);
        if (!config_json)
        {
            goto out;
        }

        /* Extract entrypoint, cmd, env from config */
        char* entrypoint_arr = json_get_array(config_json, "Entrypoint");
        char* cmd_arr        = json_get_array(config_json, "Cmd");
        char* env_arr        = json_get_array(config_json, "Env");
        free(config_json);

        /* Print JSON to stdout */
        printf("{\"entrypoint\":%s,\"cmd\":%s,\"env\":%s}\n",
               entrypoint_arr ? entrypoint_arr : "null",
               cmd_arr        ? cmd_arr        : "null",
               env_arr        ? env_arr        : "null");
        fflush(stdout);

        free(entrypoint_arr);
        free(cmd_arr);
        free(env_arr);
        rc = 0;
    }

out:
    if (tmpdir[0] != '\0')
    {
        rm_rf_dir(tmpdir);
    }
    return rc;
}

/*
 * Main MCP JSON-RPC server loop.
 * Reads newline-delimited JSON-RPC 2.0 requests from stdin.
 * Writes responses to stdout.
 * allow_net: 1 if --allow-net was passed to mcp-serve.
 */
static int mcp_serve_main(const char* self_path, int allow_net)
{
    (void)self_path;

    char* line = malloc(MCP_LINE_MAX);
    if (!line)
    {
        return 1;
    }

    /* Signal to client that we're ready */
    const char* init_resp =
        "{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{"
        "\"protocolVersion\":\"2024-11-05\","
        "\"capabilities\":{\"tools\":{}},"
        "\"serverInfo\":{\"name\":\"oci2bin\",\"version\":\"1.0\"}"
        "}}\n";
    write_all_fd(STDOUT_FILENO, init_resp, strlen(init_resp));

    for (;;)
    {
        /* Read one line (one JSON-RPC request) */
        size_t len = 0;
        for (;;)
        {
            ssize_t n = read(STDIN_FILENO, line + len, 1);
            if (n <= 0)
            {
                free(line);
                return 0; /* EOF or error: clean exit */
            }
            if (line[len] == '\n')
            {
                break;
            }
            len++;
            if (len >= MCP_LINE_MAX - 1)
            {
                /* Line too long: drain and reject */
                while (read(STDIN_FILENO, line, 1) == 1 && line[0] != '\n')
                {
                    ;
                }
                mcp_send_error(-1, -32700, "request line too large");
                len = 0;
            }
        }
        line[len] = '\0';
        if (len == 0)
        {
            continue;
        }

        /* Parse id */
        char* id_s = json_get_string(line, "id");
        long  id   = id_s ? strtol(id_s, NULL, 10) : -1;
        free(id_s);

        /* Parse method */
        char* method = json_get_string(line, "method");
        if (!method)
        {
            mcp_send_error(id, -32600, "invalid request: missing method");
            continue;
        }

        if (strcmp(method, "initialize") == 0)
        {
            /* Already sent init_resp above; this is the client's handshake */
            const char* resp =
                "{\"protocolVersion\":\"2024-11-05\","
                "\"capabilities\":{\"tools\":{}},"
                "\"serverInfo\":{\"name\":\"oci2bin\",\"version\":\"1.0\"}}";
            mcp_send_result(id, resp);
        }
        else if (strcmp(method, "notifications/initialized") == 0 ||
                 strncmp(method, "notifications/", 14) == 0)
        {
            /* Notifications: no response required */
        }
        else if (strcmp(method, "tools/list") == 0)
        {
            mcp_send_result(id, mcp_tools_list_json());
        }
        else if (strcmp(method, "tools/call") == 0)
        {
            /* Parse params.name and params.arguments */
            char* params = json_get_string(line, "params");
            if (!params)
            {
                free(method);
                mcp_send_error(id, -32602, "tools/call: params missing");
                continue;
            }

            char* tool_name = json_get_string(params, "name");
            char* args_raw  = json_get_string(params, "arguments");
            /* arguments may be an object; try array fallback */
            char* args_obj  = args_raw;
            if (!args_obj)
            {
                /* Try reading arguments as raw object */
                const char* a = json_skip_to_value(params, "arguments");
                if (a && *a == '{')
                {
                    /* Find matching } */
                    int depth = 0;
                    const char* p = a;
                    while (*p)
                    {
                        if (*p == '{')
                        {
                            depth++;
                        }
                        else if (*p == '}')
                        {
                            depth--;
                            if (depth == 0)
                            {
                                break;
                            }
                        }
                        p++;
                    }
                    size_t alen = (size_t)(p - a + 1);
                    args_obj = malloc(alen + 1);
                    if (args_obj)
                    {
                        memcpy(args_obj, a, alen);
                        args_obj[alen] = '\0';
                    }
                }
            }
            free(params);

            if (!tool_name)
            {
                free(args_obj);
                free(method);
                mcp_send_error(id, -32602, "tools/call: tool name missing");
                continue;
            }

            const char* args = args_obj ? args_obj : "{}";

            if (strcmp(tool_name, "run_container") == 0)
            {
                mcp_tool_run_container(id, args, self_path, allow_net);
            }
            else if (strcmp(tool_name, "list_containers") == 0)
            {
                mcp_tool_list_containers(id);
            }
            else if (strcmp(tool_name, "stop_container") == 0)
            {
                mcp_tool_stop_container(id, args);
            }
            else if (strcmp(tool_name, "exec_in_container") == 0)
            {
                mcp_tool_exec_in_container(id, args);
            }
            else if (strcmp(tool_name, "inspect_image") == 0)
            {
                mcp_tool_inspect_image(id, args);
            }
            else if (strcmp(tool_name, "get_logs") == 0)
            {
                mcp_tool_get_logs(id, args);
            }
            else
            {
                char msg[256];
                char esc[256];
                json_escape_string(tool_name, esc, sizeof(esc));
                snprintf(msg, sizeof(msg), "unknown tool: %s", esc);
                mcp_send_error(id, -32602, msg);
            }
            free(tool_name);
            free(args_obj);
        }
        else if (strcmp(method, "ping") == 0)
        {
            mcp_send_result(id, "{}");
        }
        else
        {
            char msg[256];
            char esc[256];
            json_escape_string(method, esc, sizeof(esc));
            snprintf(msg, sizeof(msg), "method not found: %s", esc);
            mcp_send_error(id, -32601, msg);
        }
        free(method);
    }
    free(line);
    return 0;
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char* argv[])
{
    if (getenv("OCI2BIN_DEBUG"))
    {
        g_debug = 1;
    }
    if (argv_has_debug_flag(argc, argv))
    {
        g_debug = 1;
    }

    /* Sanitize PATH before executing any host helpers */
    setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);

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
    debug_log("main.self", "path=%s", self_path);

    /* 1a. OCI2BIN_INSPECT=1: print image metadata as JSON and exit */
    if (getenv("OCI2BIN_INSPECT"))
    {
        return inspect_image_main(self_path);
    }

    /* 1b. "mcp-serve" subcommand: start JSON-RPC 2.0 MCP server */
    if (argc >= 2 && strcmp(argv[1], "mcp-serve") == 0)
    {
        int allow_net = 0;
        for (int i = 2; i < argc; i++)
        {
            if (strcmp(argv[i], "--allow-net") == 0)
            {
                allow_net = 1;
            }
        }
        return mcp_serve_main(self_path, allow_net);
    }

    /* 1b. oci2vm mode: if invoked as "oci2vm", prepend --vm to argv so VM
     * mode is the default without requiring an explicit flag. */
    char** vm_argv = NULL;
    {
        const char* base0 = strrchr(argv[0], '/');
        base0 = base0 ? base0 + 1 : argv[0];
        if (strcmp(base0, "oci2vm") == 0)
        {
            int vm_argc = 0;
            vm_argv = inject_vm_flag(argc, argv, &vm_argc);
            if (!vm_argv)
            {
                return 1;
            }
            argc = vm_argc;
            argv = vm_argv;
        }
    }

    /* 2. Parse command-line options.
     * build_merged_argv pre-scans for --config PATH and, if found, reads
     * the config file and prepends its options as defaults.  parse_opts is
     * then called exactly once on the merged argv. */
    int    merged_argc = 0;
    char** merged_argv = build_merged_argv(argc, argv, &merged_argc);
    /* Free the vm_argv injection array if build_merged_argv allocated a new
     * merged array (--config path); if no --config, merged_argv == argv == vm_argv
     * so we must not double-free. */
    if (vm_argv && merged_argv != vm_argv)
    {
        free(vm_argv);
    }
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
    if (opts.debug)
    {
        g_debug = 1;
    }
    debug_dump_opts(&opts);

    /* Seal loader text/rodata against future mmap/mprotect when supported.
     * Must run after argv parsing (opts complete) and before any fork(). */
    seal_loader_rodata();

    /* Open audit log if requested */
    if (opts.audit_log)
    {
        if (strcmp(opts.audit_log, "-") == 0)
        {
            g_audit_fd = STDERR_FILENO;
        }
        else
        {
            g_audit_fd = open(opts.audit_log,
                              O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
                              0640);
            if (g_audit_fd < 0)
            {
                fprintf(stderr, "oci2bin: --audit-log %s: %s\n",
                        opts.audit_log, strerror(errno));
            }
        }
    }

    debug_log("main.oci_blob", "offset=0x%lx size=0x%lx",
              OCI_DATA_OFFSET, OCI_DATA_SIZE);

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
        if (verify_signature(self_path, opts.verify_key) < 0)
        {
            return 1;
        }
    }

    if (verify_pinned_digest(self_path) != 0)
    {
        return 1;
    }

    if (opts.check_update || opts.self_update)
    {
        if (!opts.verify_key)
        {
            fprintf(stderr,
                    "oci2bin: --check-update/--self-update require "
                    "--verify-key PATH\n");
            return 1;
        }
        char helper_fd_path[32];
        int helper_fd = open_verifier_script_fd(helper_fd_path,
                                                sizeof(helper_fd_path));
        if (helper_fd < 0)
        {
            return 1;
        }
        int update_rc = run_self_update(self_path, opts.verify_key,
                                        opts.self_update, helper_fd_path);
        close(helper_fd);
        return update_rc;
    }

    /* Emit audit start event now that opts are fully resolved */
    audit_emit_start_event(self_path, &opts);

    /* 4. Extract OCI image into rootfs */
#ifdef __NR_userfaultfd
    if (opts.lazy)
    {
        if (kernel_supports_uffd())
        {
            fprintf(stderr,
                    "oci2bin: --lazy: userfaultfd available (Linux ≥4.3);"
                    " lazy rootfs paging is experimental — falling back to"
                    " full extraction\n");
        }
        else
        {
            fprintf(stderr,
                    "oci2bin: --lazy: userfaultfd not supported by this"
                    " kernel — falling back to full extraction\n");
        }
    }
#else
    if (opts.lazy)
    {
        fprintf(stderr,
                "oci2bin: --lazy: built without userfaultfd support"
                " (#ifdef __NR_userfaultfd not set) — falling back to"
                " full extraction\n");
    }
#endif
    char* rootfs = extract_oci_rootfs(self_path);
    if (!rootfs)
    {
        fprintf(stderr, "oci2bin: failed to extract OCI rootfs\n");
        return 1;
    }
    debug_log("main.rootfs", "path=%s", rootfs);

    /* 4b. VM dispatch: after rootfs extraction so rootfs is available */
    if (opts.use_vm)
    {
        /* MicroVM mode still needs the compatibility shims because ownership
         * changes operate on host IDs through virtiofs. */
        patch_rootfs_ids(rootfs);
        char vm_tmpdir[PATH_MAX];
        if (make_runtime_tmpdir(vm_tmpdir, sizeof(vm_tmpdir),
                                "oci2bin-vm.") < 0)
        {
            perror("mkdtemp VM tmpdir");
            return 1;
        }
        debug_log("main.vm_dispatch", "tmpdir=%s vmm=%s", vm_tmpdir,
                  opts.vmm ? opts.vmm : "(default)");
#ifdef USE_LIBKRUN
        if (!opts.vmm || strcmp(opts.vmm, "libkrun") == 0)
        {
            return run_as_vm_libkrun(rootfs, vm_tmpdir, &opts);
        }
#endif
        return run_as_vm_ch(rootfs, vm_tmpdir, &opts);
    }

    /* 6. Capture real UID/GID before entering user namespace */
    uid_t real_uid = getuid();
    gid_t real_gid = getgid();
    struct userns_map_plan userns_plan;
    debug_log("main.identity", "uid=%d gid=%d", (int)real_uid, (int)real_gid);

    plan_userns_map(&opts, real_uid, &userns_plan);

    /* Single-ID fallback needs passwd/group rewrites and privilege-drop shims.
     * Full subordinate-ID remap exposes the container's normal 0-65535 range,
     * so keep the image metadata intact in that mode. */
    if (!userns_plan.use_subid_remap)
    {
        patch_rootfs_ids(rootfs);
    }

    /* 6a. Set up cgroup v2 resource limits (before unshare, uses host cgroupfs) */
    int cg_did_setup = setup_cgroup(&opts);
    if (opts.metrics_socket && !cg_did_setup)
    {
        fprintf(stderr,
                "oci2bin: --metrics-socket requires cgroup v2 support"
                " and a writable cgroup subtree\n");
        return 1;
    }
    debug_log("main.cgroup", "enabled=%d dir=%s", cg_did_setup,
              g_cgroup_dir[0] ? g_cgroup_dir : "(none)");

    /* 7. Enter user namespace first (needed before we can map UIDs) */
    if (unshare(CLONE_NEWUSER) < 0)
    {
        perror("unshare(CLONE_NEWUSER)");
        fprintf(stderr, "oci2bin: user namespaces may be disabled on this kernel\n");
        return 1;
    }

    /* 8. Map UID/GID */
    if (setup_uid_map(real_uid, real_gid, &userns_plan) < 0)
    {
        return 1;
    }

    /* 9. Join shared namespaces (--net container:<PID>, --ipc container:<PID>).
     * Must happen after CLONE_NEWUSER so we have CAP_SYS_ADMIN in our user
     * namespace; must happen before unshare() so we don't create new
     * namespaces for the ones we are joining instead. */
    if (opts.net_join_pid > 0 &&
            join_ns_of_pid(opts.net_join_pid, CLONE_NEWNET, "net") < 0)
    {
        return 1;
    }
    if (opts.ipc_join_pid > 0 &&
            join_ns_of_pid(opts.ipc_join_pid, CLONE_NEWIPC, "ipc") < 0)
    {
        return 1;
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
        debug_log("main.unshare", "flags=0x%x", ns_flags);
    }

    /* 10c. Time namespace: shift monotonic and boottime clocks when
     * supported. Must happen after CLONE_NEWUSER (needs CAP_SYS_TIME in
     * user ns) and before fork so the child inherits the shifted namespace. */
    if (opts.has_clock_offset)
    {
        if (unshare(CLONE_NEWTIME) < 0)
        {
            if (errno == EINVAL || errno == ENOSYS)
            {
                fprintf(stderr,
                        "oci2bin: --clock-offset: CLONE_NEWTIME not"
                        " supported by this kernel (need 5.6+): %s\n",
                        strerror(errno));
            }
            else
            {
                fprintf(stderr,
                        "oci2bin: --clock-offset: unshare(CLONE_NEWTIME):"
                        " %s\n",
                        strerror(errno));
            }
        }
        else
        {
            /* Write offsets to /proc/self/timens_offsets before forking.
             * Format: "<clock_id> <offset_secs> <offset_nsecs>" */
            int tfd = open("/proc/self/timens_offsets", O_WRONLY | O_CLOEXEC);
            if (tfd < 0)
            {
                fprintf(stderr,
                        "oci2bin: --clock-offset: open timens_offsets: %s\n",
                        strerror(errno));
            }
            else
            {
                char buf[128];
                int n;
                n = snprintf(buf, sizeof(buf), "monotonic %ld 0\n",
                             opts.clock_offset_secs);
                if (n > 0 && n < (int)sizeof(buf))
                {
                    write_all_fd(tfd, buf, (size_t)n);
                }
                n = snprintf(buf, sizeof(buf), "boottime %ld 0\n",
                             opts.clock_offset_secs);
                if (n > 0 && n < (int)sizeof(buf))
                {
                    write_all_fd(tfd, buf, (size_t)n);
                }
                close(tfd);
                debug_log("main.timens", "offset=%ld secs",
                          opts.clock_offset_secs);
            }
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

    /* 11. Allocate a PTY so the container shell gets job control.
     * We open /dev/ptmx (the POSIX PTY multiplexer) before fork():
     *   parent  → master_fd: relays host terminal ↔ container I/O
     *   child   → slave_fd:  setsid() + TIOCSCTTY → controlling terminal
     *
     * PTY is allocated when:
     *   -t / --tty was given explicitly, OR
     *   stdin is an interactive terminal and --detach was not given.
     *
     * -i / --interactive keeps stdin open (pipe mode) without a PTY.
     * SIGWINCH handler is only installed when stdin is a real terminal. */
    opts.pty_master_fd = -1;
    opts.pty_slave_fd  = -1;
    struct termios saved_termios;
    int saved_termios_ok = 0;

    if (opts.allocate_tty ||
            (!opts.detach && isatty(STDIN_FILENO) &&
             tcgetpgrp(STDIN_FILENO) == getpgrp()))
    {
        int master_fd = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
        if (master_fd >= 0 && grantpt(master_fd) == 0 &&
                unlockpt(master_fd) == 0)
        {
            char* slave_name = ptsname(master_fd);
            if (slave_name)
            {
                int slave_fd = open(slave_name, O_RDWR | O_NOCTTY);
                if (slave_fd >= 0)
                {
                    /* Propagate current terminal size to slave */
                    struct winsize ws;
                    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0)
                    {
                        ioctl(slave_fd, TIOCSWINSZ, &ws);
                    }
                    opts.pty_master_fd = master_fd;
                    opts.pty_slave_fd  = slave_fd;

                    /* Save terminal state and switch to raw mode */
                    if (tcgetattr(STDIN_FILENO, &saved_termios) == 0)
                    {
                        saved_termios_ok = 1;
                        struct termios raw = saved_termios;
                        cfmakeraw(&raw);
                        tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
                    }

                    /* Install SIGWINCH handler to forward resize events.
                     * Only useful when stdin is a real terminal that
                     * can report window size via TIOCGWINSZ. */
                    g_pty_master_fd = master_fd;
                    if (isatty(STDIN_FILENO))
                    {
                        struct sigaction sa;
                        memset(&sa, 0, sizeof(sa));
                        sa.sa_handler = sigwinch_handler;
                        sigemptyset(&sa.sa_mask);
                        sigaction(SIGWINCH, &sa, NULL);
                    }
                }
                else
                {
                    close(master_fd);
                }
            }
            else
            {
                close(master_fd);
            }
        }
    }

    /* 12. Fork for PID namespace (child becomes PID 1).
     * Use clone3(CLONE_INTO_CGROUP) when cgroup limits are active so the
     * child lands directly in the cgroup without the parent joining it.
     * Falls back to fork() + cgroup.procs write on older kernels. */
    pid_t child = fork_into_cgroup();
    if (child < 0)
    {
        perror("fork");
        if (saved_termios_ok)
        {
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_termios);
        }
        return 1;
    }

    if (child == 0)
    {
        /* Redirect stderr to the PTY slave immediately so all child
         * diagnostic output goes through the PTY line discipline
         * (LF→CRLF) and the parent relay, instead of writing directly
         * to the raw-mode host terminal where \n skips carriage return. */
        if (opts.pty_slave_fd >= 0)
        {
            dup2(opts.pty_slave_fd, STDERR_FILENO);
        }
        _exit(container_main(rootfs, &opts));
    }
    debug_log("main.child", "pid=%d", (int)child);

    pid_t metrics_pid = -1;
    if (opts.metrics_socket)
    {
        metrics_pid = start_metrics_helper(opts.metrics_socket);
        if (metrics_pid < 0)
        {
            kill(child, SIGTERM);
            waitpid(child, NULL, 0);
            if (saved_termios_ok)
            {
                tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_termios);
            }
            return 1;
        }
    }

    /* Parent: close slave end — only the child needs it */
    if (opts.pty_slave_fd >= 0)
    {
        close(opts.pty_slave_fd);
    }

    /* Forward SIGINT/SIGTERM/SIGHUP/SIGUSR1/SIGUSR2 to the child so that
     * signals from the host (e.g. kill, systemd stop) reach the container
     * process.  Ctrl-C in the PTY relay goes through the slave line
     * discipline, but external signals need explicit forwarding. */
    g_pty_child_pid = child;
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = pty_forward_signal;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags   = SA_RESTART;
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGHUP, &sa, NULL);
        sigaction(SIGUSR1, &sa, NULL);
        sigaction(SIGUSR2, &sa, NULL);
    }

    /* Parent: if PTY active, relay until child exits */
    int status = 0;
    if (opts.pty_master_fd >= 0)
    {
        relay_pty(opts.pty_master_fd, &saved_termios, saved_termios_ok);
        /* relay_pty() returned because slave closed; reap child */
        waitpid(child, &status, 0);
    }
    else
    {
        waitpid(child, &status, 0);
        if (saved_termios_ok)
        {
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved_termios);
        }
    }

    /* Reap net helper if it was started */
    if (net_helper_pid > 0)
    {
        kill(net_helper_pid, SIGTERM);
        int helper_status;
        waitpid(net_helper_pid, &helper_status, 0);
    }
    if (metrics_pid > 0)
    {
        kill(metrics_pid, SIGTERM);
        waitpid(metrics_pid, NULL, 0);
    }

    if (!opts.use_init)
    {
        audit_emit_wait_status("exit", child, status);
    }
    audit_emit_wait_status("stop", child, status);

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
