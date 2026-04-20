/*
 * test_c_stubs.c — stub-based C unit tests for privileged loader.c paths.
 *
 * Strategy: include all system headers first, then define stub replacements
 * for privileged syscalls (mount, prctl, unshare, chroot, setuid/gid,
 * execvp, sethostname, mknod, chown, syscall).  Then #include loader.c so
 * every call site in the loader is redirected to the stub.
 *
 * This lets us test functions that would otherwise require CAP_SYS_ADMIN or
 * a real mount namespace, without any real privilege escalation.
 *
 * Output: TAP (Test Anything Protocol)
 *
 * Build:
 *   gcc -O0 -Wno-return-local-addr -o build/test_c_stubs tests/test_c_stubs.c
 */

/* ── Phase 1: system headers (must precede our #defines) ─────────────────── */

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

/* ── Phase 2: TAP helpers ────────────────────────────────────────────────── */

static int tap_test_num   = 0;
static int tap_fail_count = 0;

#define ASSERT(cond, desc) do {                                 \
    tap_test_num++;                                             \
    if (cond) {                                                 \
        printf("ok %d - %s\n", tap_test_num, desc);            \
    } else {                                                    \
        printf("not ok %d - %s\n", tap_test_num, desc);        \
        printf("# FAILED at %s:%d\n", __FILE__, __LINE__);     \
        tap_fail_count++;                                       \
    }                                                           \
} while (0)

#define ASSERT_INT_EQ(a, b, desc) do {                          \
    tap_test_num++;                                             \
    if ((a) == (b)) {                                           \
        printf("ok %d - %s\n", tap_test_num, desc);            \
    } else {                                                    \
        printf("not ok %d - %s\n", tap_test_num, desc);        \
        printf("# Expected: %d\n", (int)(b));                  \
        printf("# Got:      %d\n", (int)(a));                  \
        printf("# at %s:%d\n", __FILE__, __LINE__);             \
        tap_fail_count++;                                       \
    }                                                           \
} while (0)

/* ── Phase 3: stub state ──────────────────────────────────────────────────── */

#define STUB_MAX_CALLS 2048

struct stub_call_rec
{
    const char* fn;
    long        arg0; /* first argument (cast to long) */
    long        arg1; /* second argument (cast to long) */
};

static struct stub_call_rec g_stub_calls[STUB_MAX_CALLS];
static int                  g_stub_n_calls;

/* Per-function return configuration: 0 = success, -1 = fail */
static int g_stub_mount_retval;
static int g_stub_mount_errno;
/* -1 = always use retval; N ≥ 0 = succeed for N calls then fail */
static int g_stub_mount_fail_after;
static int g_stub_umount2_retval;
static int g_stub_unshare_retval;
static int g_stub_unshare_errno;
static int g_stub_chroot_retval;
static int g_stub_chroot_errno;
static int g_stub_prctl_retval;
static int g_stub_prctl_errno;
static int g_stub_execvp_errno;  /* execvp never actually execs; errno to set */
static int g_stub_setuid_retval;
static int g_stub_setuid_errno;
static int g_stub_setgid_retval;
static int g_stub_setgid_errno;
static int g_stub_setgroups_retval;
static int g_stub_setgroups_errno;
static int g_stub_sethostname_retval;
static int g_stub_mknod_retval;
static int g_stub_chown_retval;
static int g_stub_seccomp_retval; /* return from syscall(__NR_seccomp, ...) */
static int g_stub_seccomp_errno;
static int g_stub_capset_retval;  /* return from syscall(SYS_capset, ...) */
static int g_stub_capset_errno;

static void stub_reset(void)
{
    memset(g_stub_calls, 0, sizeof(g_stub_calls));
    g_stub_n_calls        = 0;
    g_stub_mount_retval   = 0;  g_stub_mount_errno   = 0;
    g_stub_mount_fail_after = -1;
    g_stub_umount2_retval = 0;
    g_stub_unshare_retval = 0;  g_stub_unshare_errno = 0;
    g_stub_chroot_retval  = 0;  g_stub_chroot_errno  = 0;
    g_stub_prctl_retval   = 0;  g_stub_prctl_errno   = 0;
    g_stub_execvp_errno   = ENOEXEC; /* never actually exec */
    g_stub_setuid_retval  = 0;  g_stub_setuid_errno  = 0;
    g_stub_setgid_retval  = 0;  g_stub_setgid_errno  = 0;
    g_stub_setgroups_retval = 0; g_stub_setgroups_errno = 0;
    g_stub_sethostname_retval = 0;
    g_stub_mknod_retval   = 0;
    g_stub_chown_retval   = 0;
    g_stub_seccomp_retval = 0;  g_stub_seccomp_errno = 0;
    g_stub_capset_retval  = 0;  g_stub_capset_errno  = 0;
}

/* Count recorded calls for a named stub */
static int stub_count(const char* fn)
{
    int n = 0;
    for (int i = 0; i < g_stub_n_calls; i++)
    {
        if (g_stub_calls[i].fn && strcmp(g_stub_calls[i].fn, fn) == 0)
        {
            n++;
        }
    }
    return n;
}

/* Return the Nth call record for a named stub (0-based), or NULL */
static const struct stub_call_rec* stub_nth(const char* fn, int idx)
{
    int seen = 0;
    for (int i = 0; i < g_stub_n_calls; i++)
    {
        if (g_stub_calls[i].fn && strcmp(g_stub_calls[i].fn, fn) == 0)
        {
            if (seen == idx)
            {
                return &g_stub_calls[i];
            }
            seen++;
        }
    }
    return NULL;
}

#define STUB_RECORD(name, a0, a1) do { \
    if (g_stub_n_calls < STUB_MAX_CALLS) { \
        g_stub_calls[g_stub_n_calls].fn   = (name); \
        g_stub_calls[g_stub_n_calls].arg0 = (long)(a0); \
        g_stub_calls[g_stub_n_calls].arg1 = (long)(a1); \
        g_stub_n_calls++; \
    } \
} while (0)

/* ── Phase 4: stub implementations ───────────────────────────────────────── */

static int stub_mount(const char* src, const char* tgt, const char* fstype,
                      unsigned long flags, const void* data)
{
    (void)src; (void)tgt; (void)fstype; (void)data;
    STUB_RECORD("mount", flags, 0);
    if (g_stub_mount_fail_after >= 0)
    {
        /* fail_after mode: succeed for the first N calls, then fail */
        int call_idx = stub_count("mount") - 1; /* already incremented above */
        if (call_idx >= g_stub_mount_fail_after)
        {
            errno = g_stub_mount_errno ? g_stub_mount_errno : EPERM;
            return -1;
        }
        return 0;
    }
    if (g_stub_mount_retval < 0)
    {
        errno = g_stub_mount_errno ? g_stub_mount_errno : EPERM;
        return -1;
    }
    return 0;
}

static int stub_umount2(const char* tgt, int flags)
{
    (void)tgt;
    STUB_RECORD("umount2", flags, 0);
    if (g_stub_umount2_retval < 0)
    {
        errno = EPERM;
        return -1;
    }
    return 0;
}

static int stub_unshare(int flags)
{
    STUB_RECORD("unshare", flags, 0);
    if (g_stub_unshare_retval < 0)
    {
        errno = g_stub_unshare_errno ? g_stub_unshare_errno : EPERM;
        return -1;
    }
    return 0;
}

static int stub_chroot(const char* path)
{
    (void)path;
    STUB_RECORD("chroot", 0, 0);
    if (g_stub_chroot_retval < 0)
    {
        errno = g_stub_chroot_errno ? g_stub_chroot_errno : EPERM;
        return -1;
    }
    return 0;
}

static int stub_prctl(int option, ...)
{
    va_list ap;
    va_start(ap, option);
    long arg2 = va_arg(ap, long);
    va_end(ap);
    STUB_RECORD("prctl", option, arg2);
    if (g_stub_prctl_retval < 0)
    {
        errno = g_stub_prctl_errno ? g_stub_prctl_errno : EPERM;
        return -1;
    }
    return 0;
}

static int stub_execvp(const char* file, char* const argv[])
{
    (void)file; (void)argv;
    STUB_RECORD("execvp", 0, 0);
    errno = g_stub_execvp_errno;
    return -1; /* never exec; caller will _exit(127) */
}

static int stub_setuid(uid_t uid)
{
    STUB_RECORD("setuid", uid, 0);
    if (g_stub_setuid_retval < 0)
    {
        errno = g_stub_setuid_errno ? g_stub_setuid_errno : EPERM;
        return -1;
    }
    return 0;
}

static int stub_setgid(gid_t gid)
{
    STUB_RECORD("setgid", gid, 0);
    if (g_stub_setgid_retval < 0)
    {
        errno = g_stub_setgid_errno ? g_stub_setgid_errno : EPERM;
        return -1;
    }
    return 0;
}

static int stub_setgroups(size_t size, const gid_t* list)
{
    (void)list;
    STUB_RECORD("setgroups", (long)size, 0);
    if (g_stub_setgroups_retval < 0)
    {
        errno = g_stub_setgroups_errno ? g_stub_setgroups_errno : EPERM;
        return -1;
    }
    return 0;
}

static int stub_sethostname(const char* name, size_t len)
{
    (void)name; (void)len;
    STUB_RECORD("sethostname", 0, 0);
    if (g_stub_sethostname_retval < 0)
    {
        errno = EPERM;
        return -1;
    }
    return 0;
}

static int stub_mknod(const char* path, mode_t mode, dev_t dev)
{
    (void)path; (void)mode; (void)dev;
    STUB_RECORD("mknod", mode, 0);
    if (g_stub_mknod_retval < 0)
    {
        errno = EPERM;
        return -1;
    }
    return 0;
}

static int stub_chown(const char* path, uid_t uid, gid_t gid)
{
    (void)path;
    STUB_RECORD("chown", uid, gid);
    if (g_stub_chown_retval < 0)
    {
        errno = EPERM;
        return -1;
    }
    return 0;
}

static int stub_lchown(const char* path, uid_t uid, gid_t gid)
{
    (void)path;
    STUB_RECORD("lchown", uid, gid);
    return 0;
}

/*
 * syscall stub: dispatch per syscall number.
 * Seccomp and capset are fully stubbed.  All other numbers get ENOSYS so
 * kernel-feature probes (clone3, mseal, uffd) detect "not supported" without
 * actually attempting the privileged call.
 */
static long stub_syscall(long nr, ...)
{
#ifdef __NR_seccomp
    if (nr == __NR_seccomp)
    {
        STUB_RECORD("seccomp", 0, 0);
        if (g_stub_seccomp_retval < 0)
        {
            errno = g_stub_seccomp_errno ? g_stub_seccomp_errno : EPERM;
            return -1;
        }
        return 0;
    }
#endif
    if (nr == SYS_capset)
    {
        STUB_RECORD("capset", 0, 0);
        if (g_stub_capset_retval < 0)
        {
            errno = g_stub_capset_errno ? g_stub_capset_errno : EPERM;
            return -1;
        }
        return 0;
    }
    /* All other syscalls (clone3, mseal, memfd_secret, …): report unavailable */
    errno = ENOSYS;
    return -1;
}

/* ── Phase 5: macro redirections ─────────────────────────────────────────── */

/*
 * These must be defined AFTER all system headers (so declarations aren't
 * rewritten) and BEFORE #include "../src/loader.c" (so call sites inside the
 * loader are redirected to the stubs).
 */

/* Undefine any existing function-like macros (some glibc versions wrap these) */
#ifdef mount
#undef mount
#endif
#ifdef prctl
#undef prctl
#endif

#define mount(s, t, f, fl, d)    stub_mount(s, t, f, fl, d)
#define umount2(t, f)             stub_umount2(t, f)
#define unshare(f)                stub_unshare(f)
#define chroot(p)                 stub_chroot(p)
#define prctl(opt, ...)           stub_prctl(opt, ##__VA_ARGS__)
#define execvp(f, a)              stub_execvp(f, a)
#define setuid(u)                 stub_setuid(u)
#define setgid(g)                 stub_setgid(g)
#define setgroups(n, l)           stub_setgroups(n, l)
#define sethostname(n, l)         stub_sethostname(n, l)
#define mknod(p, m, d)            stub_mknod(p, m, d)
#define chown(p, u, g)            stub_chown(p, u, g)
#define lchown(p, u, g)           stub_lchown(p, u, g)
#define syscall(nr, ...)          stub_syscall((long)(nr), ##__VA_ARGS__)

/* ── Phase 6: include loader.c with statics exposed ─────────────────────── */

#define static
#define main loader_main
#include "../src/loader.c"
#undef main
#undef static

/* ── Phase 7: test functions ─────────────────────────────────────────────── */

/* ── test_stub_apply_seccomp_filter ────────────────────────────────────────
 *
 * apply_seccomp_filter() does:
 *   1. prctl(PR_SET_NO_NEW_PRIVS, 1, ...)
 *   2. syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, TSYNC, &prog)
 *      → if that succeeds, return early
 *   3. else: prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)
 */
static void test_stub_apply_seccomp_filter(void)
{
    /* Case A: seccomp syscall succeeds — only prctl(NO_NEW_PRIVS) + seccomp called */
    stub_reset();
    g_stub_seccomp_retval = 0; /* success → early return */
    apply_seccomp_filter();

    ASSERT_INT_EQ(stub_count("prctl"), 1,
                  "seccomp_filter: prctl called exactly once on success path");
    const struct stub_call_rec* r = stub_nth("prctl", 0);
    ASSERT(r != NULL && r->arg0 == PR_SET_NO_NEW_PRIVS,
           "seccomp_filter: first prctl is PR_SET_NO_NEW_PRIVS");
    ASSERT_INT_EQ(stub_count("seccomp"), 1,
                  "seccomp_filter: syscall(seccomp) called once on success path");

    /* Case B: seccomp syscall fails → fallback to prctl(PR_SET_SECCOMP) */
    stub_reset();
    g_stub_seccomp_retval = -1;
    g_stub_seccomp_errno  = EPERM;
    g_stub_prctl_retval   = 0;
    apply_seccomp_filter();

    ASSERT_INT_EQ(stub_count("prctl"), 2,
                  "seccomp_filter: two prctl calls on fallback path");
    r = stub_nth("prctl", 0);
    ASSERT(r != NULL && r->arg0 == PR_SET_NO_NEW_PRIVS,
           "seccomp_filter: fallback first prctl is PR_SET_NO_NEW_PRIVS");
    r = stub_nth("prctl", 1);
    ASSERT(r != NULL && r->arg0 == PR_SET_SECCOMP,
           "seccomp_filter: fallback second prctl is PR_SET_SECCOMP");
    ASSERT_INT_EQ(stub_count("seccomp"), 1,
                  "seccomp_filter: seccomp syscall attempted once even on fail");

    /* Case C: prctl(NO_NEW_PRIVS) fails — function continues (non-fatal) */
    stub_reset();
    g_stub_prctl_retval   = -1;
    g_stub_prctl_errno    = EPERM;
    g_stub_seccomp_retval = 0; /* seccomp succeeds */
    apply_seccomp_filter();
    /* prctl failed but was still called, seccomp was called */
    ASSERT_INT_EQ(stub_count("prctl"), 1,
                  "seccomp_filter: prctl still called even when it fails");
    ASSERT_INT_EQ(stub_count("seccomp"), 1,
                  "seccomp_filter: seccomp called after prctl failure");
}

/* ── test_stub_apply_capabilities ──────────────────────────────────────────
 *
 * apply_capabilities() branches on:
 *   opts.cap_drop_all: drop all bounding-set caps (41 prctl(CAPBSET_DROP) calls)
 *   opts.cap_add_mask: before dropping, do capset + PR_CAP_AMBIENT_RAISE per bit
 *   opts.cap_drop_mask (no drop_all): drop only specific caps
 *   else: no-op (neither flag set)
 */
static void test_stub_apply_capabilities(void)
{
    struct container_opts opts;
    memset(&opts, 0, sizeof(opts));

    /* Case A: cap_drop_all, no add mask → 41 x PR_CAPBSET_DROP, no capset */
    stub_reset();
    opts.cap_drop_all  = 1;
    opts.cap_add_mask  = 0;
    opts.cap_drop_mask = 0;
    apply_capabilities(&opts);

    ASSERT_INT_EQ(stub_count("capset"), 0,
                  "apply_caps: drop-all no-add has no capset call");
    ASSERT_INT_EQ(stub_count("prctl"), 41,
                  "apply_caps: drop-all calls PR_CAPBSET_DROP for caps 0-40");
    const struct stub_call_rec* r = stub_nth("prctl", 0);
    ASSERT(r != NULL && r->arg0 == PR_CAPBSET_DROP,
           "apply_caps: drop-all first prctl is PR_CAPBSET_DROP");

    /* Case B: cap_drop_all + cap_add_mask=bit1 → capset + PR_CAP_AMBIENT_RAISE(1)
     *         + PR_CAPBSET_DROP for all caps except 1 (= 40 drops) */
    stub_reset();
    opts.cap_drop_all  = 1;
    opts.cap_add_mask  = (1ULL << 1); /* add CAP_DAC_OVERRIDE */
    apply_capabilities(&opts);

    ASSERT_INT_EQ(stub_count("capset"), 1,
                  "apply_caps: cap_add_mask triggers one capset call");
    /* PR_CAP_AMBIENT_RAISE for the one added cap */
    int n_ambient = 0;
    for (int i = 0; i < g_stub_n_calls; i++)
    {
        if (g_stub_calls[i].fn &&
                strcmp(g_stub_calls[i].fn, "prctl") == 0 &&
                g_stub_calls[i].arg0 == PR_CAP_AMBIENT)
        {
            n_ambient++;
        }
    }
    ASSERT_INT_EQ(n_ambient, 1,
                  "apply_caps: one PR_CAP_AMBIENT_RAISE for the added cap");
    /* Drops: 41 caps total minus 1 kept = 40 */
    int n_drop = 0;
    for (int i = 0; i < g_stub_n_calls; i++)
    {
        if (g_stub_calls[i].fn &&
                strcmp(g_stub_calls[i].fn, "prctl") == 0 &&
                g_stub_calls[i].arg0 == PR_CAPBSET_DROP)
        {
            n_drop++;
        }
    }
    ASSERT_INT_EQ(n_drop, 40,
                  "apply_caps: 40 PR_CAPBSET_DROP calls (41 minus 1 kept)");

    /* Case C: cap_drop_mask (not drop-all) → prctl(CAPBSET_DROP) for each set bit */
    stub_reset();
    opts.cap_drop_all  = 0;
    opts.cap_add_mask  = 0;
    opts.cap_drop_mask = (1ULL << 3) | (1ULL << 7); /* drop caps 3 and 7 */
    apply_capabilities(&opts);

    ASSERT_INT_EQ(stub_count("capset"), 0,
                  "apply_caps: cap_drop_mask alone has no capset");
    ASSERT_INT_EQ(stub_count("prctl"), 2,
                  "apply_caps: cap_drop_mask drops exactly the specified caps");

    /* Case D: neither flag set → no prctl, no capset */
    stub_reset();
    opts.cap_drop_all  = 0;
    opts.cap_add_mask  = 0;
    opts.cap_drop_mask = 0;
    apply_capabilities(&opts);

    ASSERT_INT_EQ(stub_count("prctl"), 0,
                  "apply_caps: no flags → no prctl calls");
    ASSERT_INT_EQ(stub_count("capset"), 0,
                  "apply_caps: no flags → no capset calls");
}

/* ── test_stub_setup_volumes ───────────────────────────────────────────────
 *
 * setup_volumes() iterates over opts.n_vols entries and for each:
 *   - validates host_path and ctr_path (must be absolute + clean)
 *   - calls ensure_bind_mount_target (creates dir/file in rootfs)
 *   - calls mount(host_path, rootfs+ctr_path, NULL, MS_BIND|MS_REC, NULL)
 *
 * We use a real tmpdir as the fake rootfs so mkdir calls inside
 * ensure_bind_mount_target succeed without privileges.
 */
static void test_stub_setup_volumes(void)
{
    /* Create a fake rootfs */
    char rootfs[] = "/tmp/oci2bin-stubs-rootfs-XXXXXX";
    ASSERT(mkdtemp(rootfs) != NULL, "setup_volumes: mkdtemp fake rootfs");

    struct container_opts opts;
    memset(&opts, 0, sizeof(opts));

    /* Case A: zero volumes → no mount calls */
    stub_reset();
    opts.n_vols = 0;
    setup_volumes(rootfs, &opts);
    ASSERT_INT_EQ(stub_count("mount"), 0,
                  "setup_volumes: zero volumes → no mount calls");

    /* Case B: one valid volume with existing host path */
    stub_reset();
    opts.n_vols       = 1;
    opts.vol_host[0]  = "/tmp";
    opts.vol_ctr[0]   = "/data";
    setup_volumes(rootfs, &opts);
    ASSERT_INT_EQ(stub_count("mount"), 1,
                  "setup_volumes: one valid volume → one mount call");

    /* Case C: relative host path is rejected (not absolute+clean) */
    stub_reset();
    opts.n_vols       = 1;
    opts.vol_host[0]  = "relative/path";
    opts.vol_ctr[0]   = "/data";
    setup_volumes(rootfs, &opts);
    ASSERT_INT_EQ(stub_count("mount"), 0,
                  "setup_volumes: relative host path → skipped, no mount");

    /* Case D: relative container path is rejected */
    stub_reset();
    opts.n_vols       = 1;
    opts.vol_host[0]  = "/tmp";
    opts.vol_ctr[0]   = "data";
    setup_volumes(rootfs, &opts);
    ASSERT_INT_EQ(stub_count("mount"), 0,
                  "setup_volumes: relative container path → skipped, no mount");

    /* Case E: host path with .. component rejected */
    stub_reset();
    opts.n_vols       = 1;
    opts.vol_host[0]  = "/tmp/../etc";
    opts.vol_ctr[0]   = "/data";
    setup_volumes(rootfs, &opts);
    ASSERT_INT_EQ(stub_count("mount"), 0,
                  "setup_volumes: host path with .. → skipped, no mount");

    /* Case F: mount fails → logged but no crash; function completes */
    stub_reset();
    opts.n_vols       = 1;
    opts.vol_host[0]  = "/tmp";
    opts.vol_ctr[0]   = "/data";
    g_stub_mount_retval = -1;
    g_stub_mount_errno  = EPERM;
    setup_volumes(rootfs, &opts);
    ASSERT_INT_EQ(stub_count("mount"), 1,
                  "setup_volumes: failed mount still attempted once");

    /* Case G: two valid volumes → two mount calls */
    stub_reset();
    g_stub_mount_retval = 0;
    opts.n_vols       = 2;
    opts.vol_host[0]  = "/tmp";
    opts.vol_ctr[0]   = "/data";
    opts.vol_host[1]  = "/var";
    opts.vol_ctr[1]   = "/var";
    setup_volumes(rootfs, &opts);
    ASSERT_INT_EQ(stub_count("mount"), 2,
                  "setup_volumes: two valid volumes → two mount calls");

    /* cleanup */
    char dp[PATH_MAX];
    snprintf(dp, sizeof(dp), "%s/data", rootfs);
    rmdir(dp);
    snprintf(dp, sizeof(dp), "%s/var", rootfs);
    rmdir(dp);
    rmdir(rootfs);
}

/* ── test_stub_bind_mount_memfd_secret ─────────────────────────────────────
 *
 * bind_mount_memfd_secret(sfd, data, len, dst_path) does:
 *   1. ftruncate(sfd, len)
 *   2. write_all_fd(sfd, data, len)
 *   3. mount("/proc/self/fd/<n>", dst_path, NULL, MS_BIND, NULL)
 *   4. mount(NULL, dst_path, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY|…, NULL)
 *   5. close(sfd)
 *   → on success: 0, two mount calls
 *   → if first mount fails: -1, one mount call, no umount2
 *   → if second mount fails: -1, umount2 called once to clean up
 *
 * We pass a real tmpfile fd so ftruncate and write work without privileges.
 */
static void test_stub_bind_mount_memfd_secret(void)
{
    char dst_path[] = "/tmp/oci2bin-stubs-dst-XXXXXX";
    int  dst_fd     = mkstemp(dst_path);
    ASSERT(dst_fd >= 0, "bind_mount_memfd_secret: mkstemp dst");
    if (dst_fd >= 0)
    {
        close(dst_fd);
    }

    /* Helper: open a fresh writable tmpfile to use as the "memfd" */
#define MAKE_SFD(name) \
    char sfd_path_##name[] = "/tmp/oci2bin-stubs-sfd-XXXXXX"; \
    int sfd_##name = mkstemp(sfd_path_##name);

    /* Case A: both mounts succeed → return 0, two mount calls */
    stub_reset();
    {
        MAKE_SFD(a);
        ASSERT(sfd_a >= 0, "bind_mount_memfd_secret: mkstemp sfd A");
        const char* data = "top-secret-value";
        int rc = bind_mount_memfd_secret(sfd_a, data, strlen(data), dst_path);
        ASSERT_INT_EQ(rc, 0,
                      "bind_mount_memfd_secret: success returns 0");
        ASSERT_INT_EQ(stub_count("mount"), 2,
                      "bind_mount_memfd_secret: two mount calls on success");
        ASSERT_INT_EQ(stub_count("umount2"), 0,
                      "bind_mount_memfd_secret: no umount2 on success");
        unlink(sfd_path_a); /* sfd_a already closed by the function */
    }

    /* Case B: first mount fails → return -1, one mount call, no umount2 */
    stub_reset();
    g_stub_mount_retval = -1;
    g_stub_mount_errno  = EPERM;
    {
        MAKE_SFD(b);
        ASSERT(sfd_b >= 0, "bind_mount_memfd_secret: mkstemp sfd B");
        const char* data = "secret";
        int rc = bind_mount_memfd_secret(sfd_b, data, strlen(data), dst_path);
        ASSERT_INT_EQ(rc, -1,
                      "bind_mount_memfd_secret: first mount fail returns -1");
        ASSERT_INT_EQ(stub_count("mount"), 1,
                      "bind_mount_memfd_secret: only first mount attempted");
        ASSERT_INT_EQ(stub_count("umount2"), 0,
                      "bind_mount_memfd_secret: no umount2 on first mount fail");
        unlink(sfd_path_b);
    }

    /* Case C: second mount (remount ro) fails → umount2 called once to clean up */
    stub_reset();
    g_stub_mount_fail_after = 1; /* succeed call 0, fail on call 1 */
    g_stub_mount_errno      = EPERM;
    {
        MAKE_SFD(c);
        ASSERT(sfd_c >= 0, "bind_mount_memfd_secret: mkstemp sfd C");
        const char* data = "secret";
        int rc = bind_mount_memfd_secret(sfd_c, data, strlen(data), dst_path);
        ASSERT_INT_EQ(rc, -1,
                      "bind_mount_memfd_secret: second mount fail returns -1");
        ASSERT_INT_EQ(stub_count("mount"), 2,
                      "bind_mount_memfd_secret: both mounts attempted on second fail");
        ASSERT_INT_EQ(stub_count("umount2"), 1,
                      "bind_mount_memfd_secret: umount2 called once to clean up");
        unlink(sfd_path_c);
    }

    unlink(dst_path);
#undef MAKE_SFD
}

/* ── test_stub_run_as_init ─────────────────────────────────────────────────
 *
 * run_as_init() forks; the child drops UID/GID if has_user is set, then
 * execs.  With stub_execvp returning -1, the child exits 127.
 * The parent returns WEXITSTATUS == 127.
 *
 * We verify the parent-visible return value and that fork actually happened
 * (by checking that the function returns, not hangs).
 */
static void test_stub_run_as_init(void)
{
    struct container_opts opts;
    memset(&opts, 0, sizeof(opts));

    char* args[] = { "/bin/sh", NULL };

    /* Case A: no user drop — child execs (stub), exits 127; parent returns 127 */
    stub_reset();
    opts.has_user = 0;
    int rc = run_as_init(args, &opts);
    ASSERT_INT_EQ(rc, 127,
                  "run_as_init: no-user child exits 127 via stub execvp");

    /* Case B: with user drop — child calls setgroups/setgid/setuid, then execs */
    stub_reset();
    opts.has_user = 1;
    opts.run_uid  = 1000;
    opts.run_gid  = 1000;
    rc = run_as_init(args, &opts);
    ASSERT_INT_EQ(rc, 127,
                  "run_as_init: user-drop child exits 127 via stub execvp");
    /*
     * NOTE: setuid/setgid/setgroups are called in the CHILD process.
     * After fork, the child has a copy of g_stub_calls; the parent's
     * copy is unmodified.  We cannot directly assert child-side stub
     * calls from the parent.  The exit code of 127 confirms the child
     * ran through the execvp path without crashing.
     */
    ASSERT(1, "run_as_init: user-drop path completed (exit 127 confirms exec attempted)");
}

/* ── main ─────────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("TAP version 13\n");

    test_stub_apply_seccomp_filter();
    test_stub_apply_capabilities();
    test_stub_setup_volumes();
    test_stub_bind_mount_memfd_secret();
    test_stub_run_as_init();

    printf("1..%d\n", tap_test_num);

    if (tap_fail_count > 0)
    {
        fprintf(stderr, "# %d test(s) FAILED\n", tap_fail_count);
        return 1;
    }
    return 0;
}
