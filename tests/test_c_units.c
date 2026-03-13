/*
 * test_c_units.c — C unit tests for loader.c internal functions.
 *
 * Uses the #include trick to expose static functions:
 *   - json_get_string
 *   - json_get_array
 *   - json_parse_string_array
 *   - parse_opts
 *
 * Output: TAP (Test Anything Protocol)
 *
 * Build:
 *   musl-gcc -static -Wno-return-local-addr -o build/test_c_units tests/test_c_units.c
 *
 * Run:
 *   ./build/test_c_units
 */

/* Expose all static functions from loader.c */
#define static

/* Rename loader's main so we can define our own */
#define main loader_main

#include "../src/loader.c"

#undef main
#undef static

/* ── TAP helpers ─────────────────────────────────────────────────────────── */

static int tap_test_num  = 0;
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

#define ASSERT_NOT_NULL(ptr, desc) ASSERT((ptr) != NULL, desc)
#define ASSERT_NULL(ptr, desc)     ASSERT((ptr) == NULL, desc)

#define ASSERT_STR_EQ(a, b, desc) do {                          \
    tap_test_num++;                                             \
    if ((a) != NULL && (b) != NULL && strcmp((a),(b)) == 0) {  \
        printf("ok %d - %s\n", tap_test_num, desc);            \
    } else {                                                    \
        printf("not ok %d - %s\n", tap_test_num, desc);        \
        printf("# Expected: \"%s\"\n", (b) ? (b) : "(null)"); \
        printf("# Got:      \"%s\"\n", (a) ? (a) : "(null)"); \
        printf("# at %s:%d\n", __FILE__, __LINE__);             \
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

/* ── Test functions ──────────────────────────────────────────────────────── */

static void test_json_get_string(void)
{
    const char *json = "{\"Config\":\"sha256abc.json\",\"Layers\":[\"layer.tar\"]}";

    char *val = json_get_string(json, "Config");
    ASSERT_NOT_NULL(val, "json_get_string: finds existing key");
    ASSERT_STR_EQ(val, "sha256abc.json", "json_get_string: correct value");
    free(val);

    char *missing = json_get_string(json, "NonExistent");
    ASSERT_NULL(missing, "json_get_string: missing key returns NULL");

    /* Path separators in value */
    const char *json2 = "{\"Path\":\"a/b/c.json\"}";
    char *path = json_get_string(json2, "Path");
    ASSERT_NOT_NULL(path, "json_get_string: value with slashes found");
    ASSERT_STR_EQ(path, "a/b/c.json", "json_get_string: value with slashes correct");
    free(path);

    /* Value with spaces around colon */
    const char *json3 = "{ \"Key\" : \"value123\" }";
    char *spaced = json_get_string(json3, "Key");
    ASSERT_NOT_NULL(spaced, "json_get_string: value with spaces around colon found");
    ASSERT_STR_EQ(spaced, "value123", "json_get_string: value with spaces correct");
    free(spaced);
}

static void test_json_get_array(void)
{
    const char *json = "{\"Layers\":[\"a/layer.tar\",\"b/layer.tar\"]}";

    char *arr = json_get_array(json, "Layers");
    ASSERT_NOT_NULL(arr, "json_get_array: finds existing array key");
    ASSERT(arr[0] == '[', "json_get_array: result starts with [");
    ASSERT(arr[strlen(arr)-1] == ']', "json_get_array: result ends with ]");
    free(arr);

    char *missing = json_get_array(json, "Missing");
    ASSERT_NULL(missing, "json_get_array: missing key returns NULL");

    /* Nested arrays: depth tracking */
    const char *json2 = "{\"Nested\":[[\"a\"],[\"b\",\"c\"]]}";
    char *nested = json_get_array(json2, "Nested");
    ASSERT_NOT_NULL(nested, "json_get_array: nested array found");
    /* Should include outer brackets and inner content */
    ASSERT(strstr(nested, "[[") != NULL, "json_get_array: nested brackets preserved");
    free(nested);

    /* Empty array */
    const char *json3 = "{\"Empty\":[]}";
    char *empty = json_get_array(json3, "Empty");
    ASSERT_NOT_NULL(empty, "json_get_array: empty array found");
    ASSERT_STR_EQ(empty, "[]", "json_get_array: empty array is []");
    free(empty);
}

static void test_json_parse_string_array(void)
{
    /* Two elements */
    const char *arr2 = "[\"alpha\",\"beta\"]";
    char *out2[16];
    int n2 = json_parse_string_array(arr2, out2, 16);
    ASSERT_INT_EQ(n2, 2, "json_parse_string_array: two elements count");
    ASSERT_STR_EQ(out2[0], "alpha", "json_parse_string_array: first element");
    ASSERT_STR_EQ(out2[1], "beta",  "json_parse_string_array: second element");
    free(out2[0]); free(out2[1]);

    /* Empty array */
    const char *empty = "[]";
    char *out_e[4];
    int ne = json_parse_string_array(empty, out_e, 4);
    ASSERT_INT_EQ(ne, 0, "json_parse_string_array: empty array returns 0");

    /* Single element */
    const char *single = "[\"/bin/sh\"]";
    char *out_s[4];
    int ns = json_parse_string_array(single, out_s, 4);
    ASSERT_INT_EQ(ns, 1, "json_parse_string_array: single element count");
    ASSERT_STR_EQ(out_s[0], "/bin/sh", "json_parse_string_array: single element value");
    free(out_s[0]);

    /* max limit respected */
    const char *arr5 = "[\"a\",\"b\",\"c\",\"d\",\"e\"]";
    char *out5[3];
    int n5 = json_parse_string_array(arr5, out5, 3);
    ASSERT_INT_EQ(n5, 3, "json_parse_string_array: max limit respected");
    free(out5[0]); free(out5[1]); free(out5[2]);

    /* Escaped quotes in value */
    const char *arr_esc = "[\"say \\\"hello\\\"\"]";
    char *out_esc[4];
    int n_esc = json_parse_string_array(arr_esc, out_esc, 4);
    ASSERT_INT_EQ(n_esc, 1, "json_parse_string_array: escaped-quote element count");
    /* The parser skips over backslash-escaped characters */
    free(out_esc[0]);
}

static void test_parse_opts(void)
{
    struct container_opts opts;

    /* No args */
    {
        char *argv[] = {"prog", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(1, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: no args returns 0");
        ASSERT_INT_EQ(opts.n_vols, 0, "parse_opts: no args n_vols=0");
        ASSERT_NULL(opts.entrypoint, "parse_opts: no args entrypoint=NULL");
        ASSERT_INT_EQ(opts.n_extra, 0, "parse_opts: no args n_extra=0");
    }

    /* -v HOST:CONTAINER */
    {
        char spec[] = "/host:/ctr";
        char *argv[] = {"prog", "-v", spec, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: -v returns 0");
        ASSERT_INT_EQ(opts.n_vols, 1, "parse_opts: -v n_vols=1");
        ASSERT_STR_EQ(opts.vol_host[0], "/host", "parse_opts: -v host split");
        ASSERT_STR_EQ(opts.vol_ctr[0],  "/ctr",  "parse_opts: -v ctr split");
    }

    /* Two -v flags */
    {
        char s1[] = "/a:/b";
        char s2[] = "/c:/d";
        char *argv[] = {"prog", "-v", s1, "-v", s2, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(5, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: two -v returns 0");
        ASSERT_INT_EQ(opts.n_vols, 2, "parse_opts: two -v n_vols=2");
    }

    /* --entrypoint */
    {
        char *argv[] = {"prog", "--entrypoint", "/bin/bash", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --entrypoint returns 0");
        ASSERT_STR_EQ(opts.entrypoint, "/bin/bash", "parse_opts: --entrypoint value");
    }

    /* CMD positional args */
    {
        char *argv[] = {"prog", "/bin/ls", "-la", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: positional args returns 0");
        ASSERT_INT_EQ(opts.n_extra, 2, "parse_opts: positional n_extra=2");
        ASSERT_STR_EQ(opts.extra_args[0], "/bin/ls", "parse_opts: extra_args[0]");
    }

    /* -- separator */
    {
        char *argv[] = {"prog", "--", "/bin/echo", "hello", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(4, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: -- separator returns 0");
        ASSERT_INT_EQ(opts.n_extra, 2, "parse_opts: -- n_extra=2");
        ASSERT_STR_EQ(opts.extra_args[0], "/bin/echo", "parse_opts: after -- extra_args[0]");
    }

    /* -v missing arg */
    {
        char *argv[] = {"prog", "-v", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: -v missing arg returns -1");
    }

    /* -v without colon */
    {
        char spec[] = "nocolon";
        char *argv[] = {"prog", "-v", spec, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: -v without colon returns -1");
    }

    /* Unknown flag */
    {
        char *argv[] = {"prog", "--unknown", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: unknown flag returns -1");
    }

    /* --entrypoint missing arg */
    {
        char *argv[] = {"prog", "--entrypoint", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --entrypoint missing arg returns -1");
    }

    /* -e KEY=VALUE */
    {
        char env1[] = "FOO=bar";
        char *argv[] = {"prog", "-e", env1, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: -e returns 0");
        ASSERT_INT_EQ(opts.n_env, 1, "parse_opts: -e n_env=1");
        ASSERT_STR_EQ(opts.env_vars[0], "FOO=bar", "parse_opts: -e value");
    }

    /* Two -e flags */
    {
        char e1[] = "A=1";
        char e2[] = "B=2";
        char *argv[] = {"prog", "-e", e1, "-e", e2, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(5, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: two -e returns 0");
        ASSERT_INT_EQ(opts.n_env, 2, "parse_opts: two -e n_env=2");
    }

    /* -e missing arg */
    {
        char *argv[] = {"prog", "-e", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: -e missing arg returns -1");
    }

    /* -e without = (VAR passthrough — skipped if unset, not an error) */
    {
        char bad[] = "OCI2BIN_TEST_UNSET_VAR_XYZ";
        char *argv[] = {"prog", "-e", bad, NULL};
        struct container_opts o2;
        memset(&o2, 0, sizeof(o2));
        int r = parse_opts(3, argv, &o2);
        /* Should succeed (return 0) and skip the unset var */
        ASSERT_INT_EQ(r, 0, "parse_opts: -e without = returns 0 for unset var");
    }

    /* -e with empty key */
    {
        char bad[] = "=value";
        char *argv[] = {"prog", "-e", bad, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: -e with empty key returns -1");
    }

    /* Combined: -v + -e + --entrypoint + CMD */
    {
        char spec[] = "/data:/mnt";
        char env[] = "DEBUG=1";
        char *argv[] = {"prog", "-v", spec, "-e", env, "--entrypoint", "/bin/sh", "arg1", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(8, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: combined returns 0");
        ASSERT_INT_EQ(opts.n_vols, 1, "parse_opts: combined n_vols=1");
        ASSERT_INT_EQ(opts.n_env, 1, "parse_opts: combined n_env=1");
        ASSERT_STR_EQ(opts.env_vars[0], "DEBUG=1", "parse_opts: combined env_vars[0]");
        ASSERT_STR_EQ(opts.entrypoint, "/bin/sh", "parse_opts: combined entrypoint");
        ASSERT_INT_EQ(opts.n_extra, 1, "parse_opts: combined n_extra=1");
        ASSERT_STR_EQ(opts.extra_args[0], "arg1", "parse_opts: combined extra_args[0]");
    }

    /* --net container:<PID> valid */
    {
        char arg[] = "container:1234";
        char *argv[] = {"prog", "--net", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --net container:1234 returns 0");
        ASSERT_INT_EQ((int)opts.net_join_pid, 1234,
                      "parse_opts: --net container:1234 sets net_join_pid");
    }

    /* --net container: with invalid PID (non-numeric) */
    {
        char arg[] = "container:abc";
        char *argv[] = {"prog", "--net", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --net container:abc returns -1");
    }

    /* --net container: with zero PID */
    {
        char arg[] = "container:0";
        char *argv[] = {"prog", "--net", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --net container:0 returns -1");
    }

    /* --net container: with negative PID */
    {
        char arg[] = "container:-5";
        char *argv[] = {"prog", "--net", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --net container:-5 returns -1");
    }

    /* --ipc host (explicit, no-op) */
    {
        char arg[] = "host";
        char *argv[] = {"prog", "--ipc", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --ipc host returns 0");
        ASSERT_INT_EQ((int)opts.ipc_join_pid, 0,
                      "parse_opts: --ipc host leaves ipc_join_pid=0");
    }

    /* --ipc container:<PID> valid */
    {
        char arg[] = "container:5678";
        char *argv[] = {"prog", "--ipc", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --ipc container:5678 returns 0");
        ASSERT_INT_EQ((int)opts.ipc_join_pid, 5678,
                      "parse_opts: --ipc container:5678 sets ipc_join_pid");
    }

    /* --ipc with invalid mode */
    {
        char arg[] = "none";
        char *argv[] = {"prog", "--ipc", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --ipc none returns -1");
    }

    /* --ipc container: with invalid PID */
    {
        char arg[] = "container:xyz";
        char *argv[] = {"prog", "--ipc", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --ipc container:xyz returns -1");
    }

    /* --ipc missing argument */
    {
        char *argv[] = {"prog", "--ipc", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --ipc missing arg returns -1");
    }

    /* --net with unknown mode */
    {
        char arg[] = "bridge";
        char *argv[] = {"prog", "--net", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --net bridge returns -1");
    }
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    /* TAP plan printed after we know the count — use streaming output instead */
    printf("TAP version 13\n");

    test_json_get_string();
    test_json_get_array();
    test_json_parse_string_array();
    test_parse_opts();

    printf("1..%d\n", tap_test_num);

    if (tap_fail_count > 0) {
        fprintf(stderr, "# %d test(s) FAILED\n", tap_fail_count);
        return 1;
    }
    return 0;
}
