/*
 * fuzz_layer_merge.c — libFuzzer harness for the in-process OCI layer
 * merge in loader.c (safe_merge_layer / safe_merge_walk).
 *
 * The loader does NOT parse tar bytes itself — safe_extract_layer() shells
 * out to the system `tar`, which writes a staging directory tree. The
 * security-critical loader code is what runs AFTER that: the symlink-safe
 * merge of the staging tree into the rootfs via openat2(RESOLVE_IN_ROOT),
 * mkdirat_in_root, mkdir_p_in_root, and tar_entry_name_unsafe.
 *
 * This harness reproduces that surface without invoking tar: it materializes
 * a staging tree from fuzz input (directories, regular files, and symlinks
 * with attacker-chosen targets — including absolute and "../" escapes), then
 * calls safe_merge_layer() to merge it into a fresh rootfs.
 *
 * Oracle (beyond ASan/UBSan): a sibling "canary" directory holds a file with
 * known contents. RESOLVE_IN_ROOT must prevent any layer entry — e.g. a
 * symlink to "../canary" followed by a write through it — from reaching
 * outside the rootfs. After each merge we verify the canary is untouched;
 * any change aborts so libFuzzer records a finding.
 *
 * Build:
 *   clang -fsanitize=fuzzer,address,undefined \
 *         -g -O1 -o build/fuzz_layer_merge tests/fuzz/fuzz_layer_merge.c
 *
 * Run:
 *   ./build/fuzz_layer_merge tests/fuzz/corpus/layer_merge -max_len=8192
 */

/* Expose static functions and suppress loader's main */
#define static
#define main loader_main

#include "../../src/loader.c"

#undef main
#undef static

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* Bounds — keep each iteration cheap and the staging tree shallow. */
#define FLM_MAX_ENTRIES   64
#define FLM_MAX_NAME      48
#define FLM_MAX_TARGET    128
#define FLM_MAX_CONTENT   256
#define FLM_CANARY_TEXT   "CANARY-DO-NOT-OVERWRITE"

static char  g_base[PATH_MAX];   /* mkdtemp working root, created once */
static char  g_stage[PATH_MAX];
static char  g_rootfs[PATH_MAX];
static char  g_canary_dir[PATH_MAX];
static char  g_canary_file[PATH_MAX];

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    (void)argc;
    (void)argv;

    /* Silence the loader's diagnostics so libFuzzer output stays readable. */
    int null_fd = open("/dev/null", O_WRONLY);
    if (null_fd >= 0)
    {
        dup2(null_fd, STDOUT_FILENO);
        dup2(null_fd, STDERR_FILENO);
        close(null_fd);
    }
    g_audit_fd = open("/dev/null", O_WRONLY);

    const char* tmp = getenv("TMPDIR");
    if (!tmp || !tmp[0])
    {
        tmp = "/tmp";
    }
    snprintf(g_base, sizeof(g_base), "%s/flm-XXXXXX", tmp);
    if (!mkdtemp(g_base))
    {
        _exit(0); /* cannot fuzz without a working dir */
    }
    snprintf(g_stage, sizeof(g_stage), "%s/stage", g_base);
    snprintf(g_rootfs, sizeof(g_rootfs), "%s/rootfs", g_base);
    snprintf(g_canary_dir, sizeof(g_canary_dir), "%s/canary", g_base);
    snprintf(g_canary_file, sizeof(g_canary_file), "%s/SECRET", g_canary_dir);
    return 0;
}

/* A tiny cursor over the fuzz input. */
struct cursor
{
    const uint8_t* p;
    size_t         left;
};

static uint8_t take_byte(struct cursor* c)
{
    if (c->left == 0)
    {
        return 0;
    }
    c->left--;
    return *c->p++;
}

/*
 * Read up to max_len bytes into out (NUL-terminated), turning bytes that
 * would break path materialization into benign ones: NUL → '_', and a
 * leading '/' is dropped so we always create *inside* the stage dir. '/'
 * elsewhere is kept so the fuzzer can build nested paths. Returns length.
 */
static size_t take_name(struct cursor* c, char* out, size_t max_len)
{
    size_t n = take_byte(c) % (max_len + 1);
    if (n > c->left)
    {
        n = c->left;
    }
    size_t w = 0;
    for (size_t i = 0; i < n; i++)
    {
        unsigned char b = (unsigned char)take_byte(c);
        if (b == '\0')
        {
            b = '_';
        }
        out[w++] = (char)b;
    }
    out[w] = '\0';
    return w;
}

/*
 * Materialize one path component-by-component under base_fd, creating
 * intermediate directories with mkdirat and refusing to traverse any
 * non-directory or symlink component (O_NOFOLLOW). This keeps the harness's
 * own writes strictly inside the staging tree — only the loader's merge,
 * which we are testing, is allowed to attempt escapes. Returns an fd to the
 * leaf's parent dir and writes the leaf name into *leaf_out, or -1.
 */
static int open_parent_for_create(int base_fd, const char* relpath,
                                   char* leaf_out, size_t leaf_sz)
{
    char buf[PATH_MAX];
    snprintf(buf, sizeof(buf), "%s", relpath);

    /* Strip leading slashes — always create inside base. */
    char* cur = buf;
    while (*cur == '/')
    {
        cur++;
    }
    if (*cur == '\0')
    {
        return -1;
    }

    int dir_fd = dup(base_fd);
    if (dir_fd < 0)
    {
        return -1;
    }

    for (;;)
    {
        char* slash = strchr(cur, '/');
        if (!slash)
        {
            /* cur is the leaf */
            if (*cur == '\0' || strcmp(cur, ".") == 0 ||
                    strcmp(cur, "..") == 0)
            {
                close(dir_fd);
                return -1;
            }
            snprintf(leaf_out, leaf_sz, "%s", cur);
            return dir_fd;
        }
        *slash = '\0';
        if (*cur == '\0' || strcmp(cur, ".") == 0 || strcmp(cur, "..") == 0)
        {
            close(dir_fd);
            return -1;
        }
        mkdirat(dir_fd, cur, 0755); /* ignore EEXIST */
        int next = openat(dir_fd, cur,
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        close(dir_fd);
        if (next < 0)
        {
            return -1; /* component is a symlink / non-dir — bail safely */
        }
        dir_fd = next;
        cur = slash + 1;
        while (*cur == '/')
        {
            cur++;
        }
    }
}

static void make_dir_entry(int stage_fd, const char* rel)
{
    char leaf[FLM_MAX_NAME + 1];
    int pfd = open_parent_for_create(stage_fd, rel, leaf, sizeof(leaf));
    if (pfd < 0)
    {
        return;
    }
    mkdirat(pfd, leaf, 0755);
    close(pfd);
}

static void make_file_entry(int stage_fd, const char* rel,
                            const char* content, size_t clen)
{
    char leaf[FLM_MAX_NAME + 1];
    int pfd = open_parent_for_create(stage_fd, rel, leaf, sizeof(leaf));
    if (pfd < 0)
    {
        return;
    }
    int fd = openat(pfd, leaf, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW,
                    0644);
    close(pfd);
    if (fd < 0)
    {
        return;
    }
    if (clen > 0)
    {
        (void)!write(fd, content, clen);
    }
    close(fd);
}

static void make_symlink_entry(int stage_fd, const char* rel,
                               const char* target)
{
    char leaf[FLM_MAX_NAME + 1];
    int pfd = open_parent_for_create(stage_fd, rel, leaf, sizeof(leaf));
    if (pfd < 0)
    {
        return;
    }
    /* target is attacker-controlled: absolute, "../..", etc. are all fair. */
    symlinkat(target, pfd, leaf);
    close(pfd);
}

/* Verify the sibling canary file is byte-for-byte intact. */
static void assert_canary_intact(void)
{
    int fd = open(g_canary_file, O_RDONLY | O_NOFOLLOW);
    if (fd < 0)
    {
        /* Canary vanished → the merge escaped the rootfs and clobbered it. */
        fprintf(stderr, "fuzz_layer_merge: canary missing — rootfs escape!\n");
        abort();
    }
    char buf[sizeof(FLM_CANARY_TEXT) + 8];
    ssize_t r = read(fd, buf, sizeof(buf));
    close(fd);
    if (r != (ssize_t)strlen(FLM_CANARY_TEXT) ||
            memcmp(buf, FLM_CANARY_TEXT, (size_t)r) != 0)
    {
        fprintf(stderr, "fuzz_layer_merge: canary altered — rootfs escape!\n");
        abort();
    }
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (g_base[0] == '\0')
    {
        return 0;
    }

    /* Fresh stage / rootfs / canary for this iteration. */
    rm_rf_dir(g_stage);
    rm_rf_dir(g_rootfs);
    rm_rf_dir(g_canary_dir);

    if (mkdir(g_stage, 0700) < 0 ||
            mkdir(g_rootfs, 0700) < 0 ||
            mkdir(g_canary_dir, 0700) < 0)
    {
        return 0;
    }
    int cfd = open(g_canary_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (cfd >= 0)
    {
        (void)!write(cfd, FLM_CANARY_TEXT, strlen(FLM_CANARY_TEXT));
        close(cfd);
    }

    int stage_fd = open(g_stage, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (stage_fd < 0)
    {
        return 0;
    }

    /* Build the staging tree from fuzz input. */
    struct cursor c = { data, size };
    for (int i = 0; i < FLM_MAX_ENTRIES && c.left > 0; i++)
    {
        uint8_t kind = take_byte(&c) % 3;
        char rel[FLM_MAX_NAME + 1];
        if (take_name(&c, rel, FLM_MAX_NAME) == 0)
        {
            continue;
        }
        if (kind == 0)
        {
            make_dir_entry(stage_fd, rel);
        }
        else if (kind == 1)
        {
            char content[FLM_MAX_CONTENT];
            size_t clen = take_name(&c, content, FLM_MAX_CONTENT - 1);
            make_file_entry(stage_fd, rel, content, clen);
        }
        else
        {
            char target[FLM_MAX_TARGET + 1];
            take_name(&c, target, FLM_MAX_TARGET);
            make_symlink_entry(stage_fd, rel, target);
        }
    }
    close(stage_fd);

    /* The function under test: merge staging tree into rootfs. */
    int rootfs_fd = open(g_rootfs, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (rootfs_fd >= 0)
    {
        (void)safe_merge_layer(rootfs_fd, g_stage);
        close(rootfs_fd);
    }

    assert_canary_intact();

    rm_rf_dir(g_stage);
    rm_rf_dir(g_rootfs);
    rm_rf_dir(g_canary_dir);
    return 0;
}
