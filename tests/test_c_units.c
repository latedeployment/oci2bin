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
    const char* json = "{\"Config\":\"sha256abc.json\",\"Layers\":[\"layer.tar\"]}";

    char* val = json_get_string(json, "Config");
    ASSERT_NOT_NULL(val, "json_get_string: finds existing key");
    ASSERT_STR_EQ(val, "sha256abc.json", "json_get_string: correct value");
    free(val);

    char* missing = json_get_string(json, "NonExistent");
    ASSERT_NULL(missing, "json_get_string: missing key returns NULL");

    /* Path separators in value */
    const char* json2 = "{\"Path\":\"a/b/c.json\"}";
    char* path = json_get_string(json2, "Path");
    ASSERT_NOT_NULL(path, "json_get_string: value with slashes found");
    ASSERT_STR_EQ(path, "a/b/c.json",
                  "json_get_string: value with slashes correct");
    free(path);

    /* Value with spaces around colon */
    const char* json3 = "{ \"Key\" : \"value123\" }";
    char* spaced = json_get_string(json3, "Key");
    ASSERT_NOT_NULL(spaced,
                    "json_get_string: value with spaces around colon found");
    ASSERT_STR_EQ(spaced, "value123", "json_get_string: value with spaces correct");
    free(spaced);
}

static void test_json_get_array(void)
{
    const char* json = "{\"Layers\":[\"a/layer.tar\",\"b/layer.tar\"]}";

    char* arr = json_get_array(json, "Layers");
    ASSERT_NOT_NULL(arr, "json_get_array: finds existing array key");
    ASSERT(arr[0] == '[', "json_get_array: result starts with [");
    ASSERT(arr[strlen(arr)-1] == ']', "json_get_array: result ends with ]");
    free(arr);

    char* missing = json_get_array(json, "Missing");
    ASSERT_NULL(missing, "json_get_array: missing key returns NULL");

    /* Nested arrays: depth tracking */
    const char* json2 = "{\"Nested\":[[\"a\"],[\"b\",\"c\"]]}";
    char* nested = json_get_array(json2, "Nested");
    ASSERT_NOT_NULL(nested, "json_get_array: nested array found");
    /* Should include outer brackets and inner content */
    ASSERT(strstr(nested, "[[") != NULL,
           "json_get_array: nested brackets preserved");
    free(nested);

    /* Empty array */
    const char* json3 = "{\"Empty\":[]}";
    char* empty = json_get_array(json3, "Empty");
    ASSERT_NOT_NULL(empty, "json_get_array: empty array found");
    ASSERT_STR_EQ(empty, "[]", "json_get_array: empty array is []");
    free(empty);
}

static void test_json_parse_string_array(void)
{
    /* Two elements */
    const char* arr2 = "[\"alpha\",\"beta\"]";
    char* out2[16];
    int n2 = json_parse_string_array(arr2, out2, 16);
    ASSERT_INT_EQ(n2, 2, "json_parse_string_array: two elements count");
    ASSERT_STR_EQ(out2[0], "alpha", "json_parse_string_array: first element");
    ASSERT_STR_EQ(out2[1], "beta",  "json_parse_string_array: second element");
    free(out2[0]);
    free(out2[1]);

    /* Empty array */
    const char* empty = "[]";
    char* out_e[4];
    int ne = json_parse_string_array(empty, out_e, 4);
    ASSERT_INT_EQ(ne, 0, "json_parse_string_array: empty array returns 0");

    /* Single element */
    const char* single = "[\"/bin/sh\"]";
    char* out_s[4];
    int ns = json_parse_string_array(single, out_s, 4);
    ASSERT_INT_EQ(ns, 1, "json_parse_string_array: single element count");
    ASSERT_STR_EQ(out_s[0], "/bin/sh",
                  "json_parse_string_array: single element value");
    free(out_s[0]);

    /* max limit respected */
    const char* arr5 = "[\"a\",\"b\",\"c\",\"d\",\"e\"]";
    char* out5[3];
    int n5 = json_parse_string_array(arr5, out5, 3);
    ASSERT_INT_EQ(n5, 3, "json_parse_string_array: max limit respected");
    free(out5[0]);
    free(out5[1]);
    free(out5[2]);

    /* Escaped quotes in value */
    const char* arr_esc = "[\"say \\\"hello\\\"\"]";
    char* out_esc[4];
    int n_esc = json_parse_string_array(arr_esc, out_esc, 4);
    ASSERT_INT_EQ(n_esc, 1, "json_parse_string_array: escaped-quote element count");
    /* The parser skips over backslash-escaped characters */
    free(out_esc[0]);
}

static void test_path_has_dotdot_component(void)
{
    ASSERT(path_has_dotdot_component("/safe/../path"),
           "path_has_dotdot_component: detects parent component");
    ASSERT(path_has_dotdot_component("../relative"),
           "path_has_dotdot_component: detects leading parent component");
    ASSERT(!path_has_dotdot_component("/safe/..hidden/path"),
           "path_has_dotdot_component: ignores non-component '..' substring");
    ASSERT(!path_has_dotdot_component("/safe/path"),
           "path_has_dotdot_component: accepts clean path");
}

static void test_parse_opts(void)
{
    struct container_opts opts;

    /* No args */
    {
        char* argv[] = {"prog", NULL};
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
        char* argv[] = {"prog", "-v", spec, NULL};
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
        char* argv[] = {"prog", "-v", s1, "-v", s2, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(5, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: two -v returns 0");
        ASSERT_INT_EQ(opts.n_vols, 2, "parse_opts: two -v n_vols=2");
    }

    /* --entrypoint */
    {
        char* argv[] = {"prog", "--entrypoint", "/bin/bash", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --entrypoint returns 0");
        ASSERT_STR_EQ(opts.entrypoint, "/bin/bash", "parse_opts: --entrypoint value");
    }

    /* --debug */
    {
        char* argv[] = {"prog", "--debug", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --debug returns 0");
        ASSERT_INT_EQ(opts.debug, 1, "parse_opts: --debug sets debug=1");
    }

    /* CMD positional args */
    {
        char* argv[] = {"prog", "/bin/ls", "-la", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: positional args returns 0");
        ASSERT_INT_EQ(opts.n_extra, 2, "parse_opts: positional n_extra=2");
        ASSERT_STR_EQ(opts.extra_args[0], "/bin/ls", "parse_opts: extra_args[0]");
    }

    /* -- separator */
    {
        char* argv[] = {"prog", "--", "/bin/echo", "hello", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(4, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: -- separator returns 0");
        ASSERT_INT_EQ(opts.n_extra, 2, "parse_opts: -- n_extra=2");
        ASSERT_STR_EQ(opts.extra_args[0], "/bin/echo",
                      "parse_opts: after -- extra_args[0]");
    }

    /* -v missing arg */
    {
        char* argv[] = {"prog", "-v", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: -v missing arg returns -1");
    }

    /* -v without colon */
    {
        char spec[] = "nocolon";
        char* argv[] = {"prog", "-v", spec, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: -v without colon returns -1");
    }

    /* Unknown flag */
    {
        char* argv[] = {"prog", "--unknown", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: unknown flag returns -1");
    }

    /* --entrypoint missing arg */
    {
        char* argv[] = {"prog", "--entrypoint", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --entrypoint missing arg returns -1");
    }

    /* -e KEY=VALUE */
    {
        char env1[] = "FOO=bar";
        char* argv[] = {"prog", "-e", env1, NULL};
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
        char* argv[] = {"prog", "-e", e1, "-e", e2, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(5, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: two -e returns 0");
        ASSERT_INT_EQ(opts.n_env, 2, "parse_opts: two -e n_env=2");
    }

    /* -e missing arg */
    {
        char* argv[] = {"prog", "-e", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: -e missing arg returns -1");
    }

    /* -e without = (VAR passthrough — skipped if unset, not an error) */
    {
        char bad[] = "OCI2BIN_TEST_UNSET_VAR_XYZ";
        char* argv[] = {"prog", "-e", bad, NULL};
        struct container_opts o2;
        memset(&o2, 0, sizeof(o2));
        int r = parse_opts(3, argv, &o2);
        /* Should succeed (return 0) and skip the unset var */
        ASSERT_INT_EQ(r, 0, "parse_opts: -e without = returns 0 for unset var");
    }

    /* -e with empty key */
    {
        char bad[] = "=value";
        char* argv[] = {"prog", "-e", bad, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: -e with empty key returns -1");
    }

    /* Combined: -v + -e + --entrypoint + CMD */
    {
        char spec[] = "/data:/mnt";
        char env[] = "DEBUG=1";
        char* argv[] = {"prog", "-v", spec, "-e", env, "--entrypoint", "/bin/sh", "arg1", NULL};
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
        char* argv[] = {"prog", "--net", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --net container:1234 returns 0");
        ASSERT_INT_EQ((int)opts.net_join_pid, 1234,
                      "parse_opts: --net container:1234 sets net_join_pid");
    }

    /* --net container: with invalid PID (non-numeric) */
    {
        char arg[] = "container:abc";
        char* argv[] = {"prog", "--net", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --net container:abc returns -1");
    }

    /* --net container: with zero PID */
    {
        char arg[] = "container:0";
        char* argv[] = {"prog", "--net", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --net container:0 returns -1");
    }

    /* --net container: with negative PID */
    {
        char arg[] = "container:-5";
        char* argv[] = {"prog", "--net", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --net container:-5 returns -1");
    }

    /* --ipc host (explicit, no-op) */
    {
        char arg[] = "host";
        char* argv[] = {"prog", "--ipc", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --ipc host returns 0");
        ASSERT_INT_EQ((int)opts.ipc_join_pid, 0,
                      "parse_opts: --ipc host leaves ipc_join_pid=0");
    }

    /* --ipc container:<PID> valid */
    {
        char arg[] = "container:5678";
        char* argv[] = {"prog", "--ipc", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --ipc container:5678 returns 0");
        ASSERT_INT_EQ((int)opts.ipc_join_pid, 5678,
                      "parse_opts: --ipc container:5678 sets ipc_join_pid");
    }

    /* --ipc with invalid mode */
    {
        char arg[] = "none";
        char* argv[] = {"prog", "--ipc", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --ipc none returns -1");
    }

    /* --ipc container: with invalid PID */
    {
        char arg[] = "container:xyz";
        char* argv[] = {"prog", "--ipc", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --ipc container:xyz returns -1");
    }

    /* --ipc missing argument */
    {
        char* argv[] = {"prog", "--ipc", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --ipc missing arg returns -1");
    }

    /* --net with unknown mode */
    {
        char arg[] = "bridge";
        char* argv[] = {"prog", "--net", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --net bridge returns -1");
    }

    /* --tmpfs path with ".." inside a component should be allowed */
    {
        char arg[] = "/safe/..cache";
        char* argv[] = {"prog", "--tmpfs", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --tmpfs allows '..' inside component name");
        ASSERT_STR_EQ(opts.tmpfs_mounts[0], "/safe/..cache",
                      "parse_opts: --tmpfs preserves clean component name");
    }
}

/* ── test_build_exec_args ─────────────────────────────────────────────── */

static void test_build_exec_args(void)
{
    struct oci_config cfg;
    char* exec_args[16];

    /* OCI entrypoint + OCI cmd, no user overrides */
    {
        memset(&cfg, 0, sizeof(cfg));
        cfg.entrypoint_json = strdup("[\"/bin/redis-server\"]");
        cfg.cmd_json        = strdup("[\"--port\",\"6379\"]");
        int n = build_exec_args(&cfg, NULL, NULL, 0, exec_args, 16);
        ASSERT_INT_EQ(n, 3, "build_exec_args: OCI ep+cmd -> 3 args");
        ASSERT_STR_EQ(exec_args[0], "/bin/redis-server",
                      "build_exec_args: OCI ep[0]");
        ASSERT_STR_EQ(exec_args[1], "--port",
                      "build_exec_args: OCI cmd[0]");
        ASSERT_STR_EQ(exec_args[2], "6379",
                      "build_exec_args: OCI cmd[1]");
        ASSERT_NULL(exec_args[3], "build_exec_args: null-terminated");
        free(exec_args[0]);
        free(exec_args[1]);
        free(exec_args[2]);
        free_oci_config(&cfg);
    }

    /* User entrypoint overrides OCI entrypoint; OCI cmd still used */
    {
        memset(&cfg, 0, sizeof(cfg));
        cfg.entrypoint_json = strdup("[\"/wrong\"]");
        cfg.cmd_json        = strdup("[\"arg1\"]");
        int n = build_exec_args(&cfg, "/bin/sh", NULL, 0, exec_args, 16);
        ASSERT_INT_EQ(n, 2, "build_exec_args: user ep overrides OCI ep");
        ASSERT_STR_EQ(exec_args[0], "/bin/sh",
                      "build_exec_args: user ep is [0]");
        ASSERT_STR_EQ(exec_args[1], "arg1",
                      "build_exec_args: OCI cmd used when user ep given");
        /* exec_args[0] = literal pointer; exec_args[1] = malloc'd */
        free(exec_args[1]);
        free_oci_config(&cfg);
    }

    /* Extra args override OCI cmd */
    {
        memset(&cfg, 0, sizeof(cfg));
        cfg.entrypoint_json = strdup("[\"/bin/ep\"]");
        cfg.cmd_json        = strdup("[\"ignored\"]");
        char* extra[]       = {"override1", "override2"};
        int n = build_exec_args(&cfg, NULL, extra, 2, exec_args, 16);
        ASSERT_INT_EQ(n, 3, "build_exec_args: extra_args override OCI cmd");
        ASSERT_STR_EQ(exec_args[0], "/bin/ep",
                      "build_exec_args: OCI ep still used");
        ASSERT_STR_EQ(exec_args[1], "override1",
                      "build_exec_args: extra[0]");
        ASSERT_STR_EQ(exec_args[2], "override2",
                      "build_exec_args: extra[1]");
        free(exec_args[0]);
        free_oci_config(&cfg);
    }

    /* Empty cfg -> fallback to /bin/sh */
    {
        memset(&cfg, 0, sizeof(cfg));
        int n = build_exec_args(&cfg, NULL, NULL, 0, exec_args, 16);
        ASSERT_INT_EQ(n, 1, "build_exec_args: fallback /bin/sh count");
        ASSERT_STR_EQ(exec_args[0], "/bin/sh",
                      "build_exec_args: fallback is /bin/sh");
        ASSERT_NULL(exec_args[1],
                    "build_exec_args: fallback null-terminated");
        /* exec_args[0] = static literal; nothing to free */
    }

    /* entrypoint_json = "null" skips OCI ep; cmd used instead */
    {
        memset(&cfg, 0, sizeof(cfg));
        cfg.entrypoint_json = strdup("null");
        cfg.cmd_json        = strdup("[\"/bin/ls\"]");
        int n = build_exec_args(&cfg, NULL, NULL, 0, exec_args, 16);
        ASSERT_INT_EQ(n, 1, "build_exec_args: null ep uses OCI cmd");
        ASSERT_STR_EQ(exec_args[0], "/bin/ls",
                      "build_exec_args: cmd[0] used when ep=null");
        free(exec_args[0]);
        free_oci_config(&cfg);
    }
}

/* ── test_cap_name_to_num ─────────────────────────────────────────────── */

static void test_cap_name_to_num(void)
{
    ASSERT_INT_EQ(cap_name_to_num("chown"),  0,
                  "cap_name_to_num: chown=0");
    ASSERT_INT_EQ(cap_name_to_num("CAP_CHOWN"), 0,
                  "cap_name_to_num: CAP_CHOWN prefix stripped");
    ASSERT_INT_EQ(cap_name_to_num("cap_chown"), 0,
                  "cap_name_to_num: cap_chown lowercase prefix");
    ASSERT_INT_EQ(cap_name_to_num("setuid"),  7,
                  "cap_name_to_num: setuid=7");
    ASSERT_INT_EQ(cap_name_to_num("CAP_SETUID"), 7,
                  "cap_name_to_num: CAP_SETUID=7");
    ASSERT_INT_EQ(cap_name_to_num("kill"),    5,
                  "cap_name_to_num: kill=5");
    ASSERT_INT_EQ(cap_name_to_num("net_bind_service"), 10,
                  "cap_name_to_num: net_bind_service=10");
    ASSERT_INT_EQ(cap_name_to_num("net_admin"), 12,
                  "cap_name_to_num: net_admin=12");
    ASSERT_INT_EQ(cap_name_to_num("sys_admin"), 21,
                  "cap_name_to_num: sys_admin=21");
    ASSERT_INT_EQ(cap_name_to_num("setfcap"),  31,
                  "cap_name_to_num: setfcap=31");
    ASSERT_INT_EQ(cap_name_to_num("unknown_capability"), -1,
                  "cap_name_to_num: unknown returns -1");
    ASSERT_INT_EQ(cap_name_to_num(""), -1,
                  "cap_name_to_num: empty string returns -1");
}

/* ── test_parse_opts_resource_limits ─────────────────────────────────── */

static void test_parse_opts_resource_limits(void)
{
    struct container_opts opts;

    /* --memory 512m */
    {
        char arg[] = "512m";
        char* argv[] = {"prog", "--memory", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --memory 512m returns 0");
        ASSERT_INT_EQ((int)(opts.cg_memory_bytes / (1024LL * 1024LL)), 512,
                      "parse_opts: --memory 512m = 512 MiB");
    }

    /* --memory 1g */
    {
        char arg[] = "1g";
        char* argv[] = {"prog", "--memory", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --memory 1g returns 0");
        ASSERT_INT_EQ(
            (opts.cg_memory_bytes == 1LL * 1024 * 1024 * 1024), 1,
            "parse_opts: --memory 1g = 1 GiB");
    }

    /* --memory 1024k */
    {
        char arg[] = "1024k";
        char* argv[] = {"prog", "--memory", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --memory 1024k returns 0");
        ASSERT_INT_EQ(
            (opts.cg_memory_bytes == 1024LL * 1024LL), 1,
            "parse_opts: --memory 1024k = 1 MiB");
    }

    /* --memory 256G: boundary accepted */
    {
        char arg[] = "256G";
        char* argv[] = {"prog", "--memory", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --memory 256G (max) accepted");
    }

    /* --memory 257g: exceeds limit */
    {
        char arg[] = "257g";
        char* argv[] = {"prog", "--memory", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --memory 257g rejected");
    }

    /* --memory 0: rejected (val <= 0) */
    {
        char arg[] = "0";
        char* argv[] = {"prog", "--memory", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --memory 0 rejected");
    }

    /* --memory abc: non-numeric */
    {
        char arg[] = "abc";
        char* argv[] = {"prog", "--memory", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --memory abc rejected");
    }

    /* --memory 1z: unknown suffix */
    {
        char arg[] = "1z";
        char* argv[] = {"prog", "--memory", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --memory 1z (bad suffix) rejected");
    }

    /* --memory missing arg */
    {
        char* argv[] = {"prog", "--memory", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --memory missing arg returns -1");
    }

    /* --cpus 0.5 */
    {
        char arg[] = "0.5";
        char* argv[] = {"prog", "--cpus", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --cpus 0.5 returns 0");
        ASSERT_INT_EQ((int)opts.cg_cpu_quota, 50000,
                      "parse_opts: --cpus 0.5 = 50000 quota");
    }

    /* --cpus 1.0 */
    {
        char arg[] = "1.0";
        char* argv[] = {"prog", "--cpus", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --cpus 1.0 returns 0");
        ASSERT_INT_EQ((int)opts.cg_cpu_quota, 100000,
                      "parse_opts: --cpus 1.0 = 100000 quota");
    }

    /* --cpus 0: rejected */
    {
        char arg[] = "0";
        char* argv[] = {"prog", "--cpus", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --cpus 0 rejected");
    }

    /* --cpus 1025: exceeds limit */
    {
        char arg[] = "1025";
        char* argv[] = {"prog", "--cpus", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --cpus 1025 rejected");
    }

    /* --cpus abc: non-numeric */
    {
        char arg[] = "abc";
        char* argv[] = {"prog", "--cpus", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --cpus abc rejected");
    }

    /* --pids-limit 100 */
    {
        char arg[] = "100";
        char* argv[] = {"prog", "--pids-limit", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --pids-limit 100 returns 0");
        ASSERT_INT_EQ((int)opts.cg_pids, 100,
                      "parse_opts: --pids-limit 100 value");
    }

    /* --pids-limit 65536: boundary accepted */
    {
        char arg[] = "65536";
        char* argv[] = {"prog", "--pids-limit", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --pids-limit 65536 (max) accepted");
    }

    /* --pids-limit 65537: exceeds limit */
    {
        char arg[] = "65537";
        char* argv[] = {"prog", "--pids-limit", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --pids-limit 65537 rejected");
    }

    /* --pids-limit 0: rejected */
    {
        char arg[] = "0";
        char* argv[] = {"prog", "--pids-limit", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --pids-limit 0 rejected");
    }
}

/* ── test_parse_opts_user ─────────────────────────────────────────────── */

static void test_parse_opts_user(void)
{
    struct container_opts opts;

    /* basic UID: GID defaults to same */
    {
        char arg[] = "1000";
        char* argv[] = {"prog", "--user", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --user 1000 returns 0");
        ASSERT_INT_EQ(opts.has_user, 1,
                      "parse_opts: --user 1000 has_user=1");
        ASSERT_INT_EQ((int)opts.run_uid, 1000,
                      "parse_opts: --user 1000 run_uid=1000");
        ASSERT_INT_EQ((int)opts.run_gid, 1000,
                      "parse_opts: --user 1000 gid defaults to uid");
    }

    /* UID:GID */
    {
        char arg[] = "1000:2000";
        char* argv[] = {"prog", "--user", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --user 1000:2000 returns 0");
        ASSERT_INT_EQ((int)opts.run_uid, 1000,
                      "parse_opts: --user 1000:2000 uid");
        ASSERT_INT_EQ((int)opts.run_gid, 2000,
                      "parse_opts: --user 1000:2000 gid");
    }

    /* UID max (65534): accepted */
    {
        char arg[] = "65534";
        char* argv[] = {"prog", "--user", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --user 65534 (max) accepted");
    }

    /* UID 65535: rejected */
    {
        char arg[] = "65535";
        char* argv[] = {"prog", "--user", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --user 65535 rejected");
    }

    /* name (non-numeric) rejected */
    {
        char arg[] = "root";
        char* argv[] = {"prog", "--user", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --user root (name) rejected");
    }

    /* trailing garbage rejected */
    {
        char arg[] = "100abc";
        char* argv[] = {"prog", "--user", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --user 100abc rejected");
    }

    /* GID non-numeric rejected */
    {
        char arg[] = "100:abc";
        char* argv[] = {"prog", "--user", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --user 100:abc rejected");
    }

    /* missing arg */
    {
        char* argv[] = {"prog", "--user", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --user missing arg returns -1");
    }
}

/* ── test_parse_opts_caps ─────────────────────────────────────────────── */

static void test_parse_opts_caps(void)
{
    struct container_opts opts;

    /* --cap-drop all */
    {
        char arg[] = "all";
        char* argv[] = {"prog", "--cap-drop", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --cap-drop all returns 0");
        ASSERT_INT_EQ(opts.cap_drop_all, 1,
                      "parse_opts: --cap-drop all sets cap_drop_all");
    }

    /* --cap-drop chown: sets bit 0 */
    {
        char arg[] = "chown";
        char* argv[] = {"prog", "--cap-drop", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --cap-drop chown returns 0");
        ASSERT_INT_EQ((int)(opts.cap_drop_mask & 1), 1,
                      "parse_opts: --cap-drop chown sets bit 0");
    }

    /* --cap-drop CAP_SETUID: sets bit 7 */
    {
        char arg[] = "CAP_SETUID";
        char* argv[] = {"prog", "--cap-drop", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --cap-drop CAP_SETUID returns 0");
        ASSERT_INT_EQ((int)((opts.cap_drop_mask >> 7) & 1), 1,
                      "parse_opts: --cap-drop CAP_SETUID sets bit 7");
    }

    /* --cap-drop unknown: rejected */
    {
        char arg[] = "unknown_cap";
        char* argv[] = {"prog", "--cap-drop", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --cap-drop unknown rejected");
    }

    /* --cap-drop missing arg */
    {
        char* argv[] = {"prog", "--cap-drop", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --cap-drop missing arg returns -1");
    }

    /* --cap-add net_bind_service: sets bit 10 */
    {
        char arg[] = "net_bind_service";
        char* argv[] = {"prog", "--cap-add", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0,
                      "parse_opts: --cap-add net_bind_service returns 0");
        ASSERT_INT_EQ((int)((opts.cap_add_mask >> 10) & 1), 1,
                      "parse_opts: --cap-add net_bind_service sets bit 10");
    }

    /* --cap-add unknown: rejected */
    {
        char arg[] = "unknown_cap";
        char* argv[] = {"prog", "--cap-add", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --cap-add unknown rejected");
    }

    /* --cap-add missing arg */
    {
        char* argv[] = {"prog", "--cap-add", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --cap-add missing arg returns -1");
    }
}

/* ── test_parse_opts_ulimit ───────────────────────────────────────────── */

static void test_parse_opts_ulimit(void)
{
    struct container_opts opts;

    /* nofile */
    {
        char arg[] = "nofile=1024";
        char* argv[] = {"prog", "--ulimit", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --ulimit nofile=1024 returns 0");
        ASSERT_INT_EQ(opts.n_ulimits, 1,
                      "parse_opts: --ulimit n_ulimits=1");
        ASSERT_INT_EQ(opts.ulimits[0].resource, RLIMIT_NOFILE,
                      "parse_opts: --ulimit nofile resource type");
        ASSERT_INT_EQ((int)opts.ulimits[0].value, 1024,
                      "parse_opts: --ulimit nofile=1024 value");
    }

    /* nproc */
    {
        char arg[] = "nproc=50";
        char* argv[] = {"prog", "--ulimit", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --ulimit nproc=50 returns 0");
        ASSERT_INT_EQ(opts.ulimits[0].resource, RLIMIT_NPROC,
                      "parse_opts: --ulimit nproc resource type");
    }

    /* cpu */
    {
        char arg[] = "cpu=60";
        char* argv[] = {"prog", "--ulimit", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --ulimit cpu=60 returns 0");
        ASSERT_INT_EQ(opts.ulimits[0].resource, RLIMIT_CPU,
                      "parse_opts: --ulimit cpu resource type");
    }

    /* as + fsize together */
    {
        char a1[] = "as=1048576";
        char a2[] = "fsize=10485760";
        char* argv[] = {"prog", "--ulimit", a1, "--ulimit", a2, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(5, argv, &opts);
        ASSERT_INT_EQ(r, 0,
                      "parse_opts: --ulimit as + fsize returns 0");
        ASSERT_INT_EQ(opts.n_ulimits, 2,
                      "parse_opts: two --ulimit n_ulimits=2");
        ASSERT_INT_EQ(opts.ulimits[0].resource, RLIMIT_AS,
                      "parse_opts: --ulimit as resource type");
        ASSERT_INT_EQ(opts.ulimits[1].resource, RLIMIT_FSIZE,
                      "parse_opts: --ulimit fsize resource type");
    }

    /* unknown type: rejected */
    {
        char arg[] = "maxfoo=1";
        char* argv[] = {"prog", "--ulimit", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --ulimit unknown type rejected");
    }

    /* missing '=': rejected */
    {
        char arg[] = "nofile";
        char* argv[] = {"prog", "--ulimit", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --ulimit missing = rejected");
    }

    /* non-numeric value: rejected */
    {
        char arg[] = "nofile=abc";
        char* argv[] = {"prog", "--ulimit", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --ulimit non-numeric value rejected");
    }

    /* missing arg */
    {
        char* argv[] = {"prog", "--ulimit", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --ulimit missing arg returns -1");
    }
}

/* ── test_parse_opts_misc_flags ───────────────────────────────────────── */

static void test_parse_opts_misc_flags(void)
{
    struct container_opts opts;

    /* --secret HOST only (no container path) */
    {
        char arg[] = "/host/secret.txt";
        char* argv[] = {"prog", "--secret", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --secret host-only returns 0");
        ASSERT_INT_EQ(opts.n_secrets, 1,
                      "parse_opts: --secret n_secrets=1");
        ASSERT_STR_EQ(opts.secret_host[0], "/host/secret.txt",
                      "parse_opts: --secret host path");
        ASSERT_NULL(opts.secret_ctr[0],
                    "parse_opts: --secret ctr_path=NULL");
    }

    /* --secret HOST:CTR */
    {
        char arg[] = "/host/key:/ctr/key";
        char* argv[] = {"prog", "--secret", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --secret HOST:CTR returns 0");
        ASSERT_STR_EQ(opts.secret_host[0], "/host/key",
                      "parse_opts: --secret HOST split");
        ASSERT_STR_EQ(opts.secret_ctr[0], "/ctr/key",
                      "parse_opts: --secret CTR split");
    }

    /* --hostname */
    {
        char arg[] = "mycontainer";
        char* argv[] = {"prog", "--hostname", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --hostname returns 0");
        ASSERT_STR_EQ(opts.hostname, "mycontainer",
                      "parse_opts: --hostname value set");
    }

    /* --hostname missing arg */
    {
        char* argv[] = {"prog", "--hostname", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --hostname missing arg returns -1");
    }

    /* --workdir */
    {
        char arg[] = "/app";
        char* argv[] = {"prog", "--workdir", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --workdir returns 0");
        ASSERT_STR_EQ(opts.workdir, "/app",
                      "parse_opts: --workdir value set");
    }

    /* --read-only */
    {
        char* argv[] = {"prog", "--read-only", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --read-only returns 0");
        ASSERT_INT_EQ(opts.read_only, 1,
                      "parse_opts: --read-only sets flag");
    }

    /* --overlay-persist DIR */
    {
        char arg[] = "/var/overlay";
        char* argv[] = {"prog", "--overlay-persist", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --overlay-persist returns 0");
        ASSERT_STR_EQ(opts.overlay_persist, "/var/overlay",
                      "parse_opts: --overlay-persist value set");
    }

    /* --overlay-persist with '..' rejected */
    {
        char arg[] = "/var/../overlay";
        char* argv[] = {"prog", "--overlay-persist", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --overlay-persist with '..' rejected");
    }

    /* --no-seccomp */
    {
        char* argv[] = {"prog", "--no-seccomp", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --no-seccomp returns 0");
        ASSERT_INT_EQ(opts.no_seccomp, 1,
                      "parse_opts: --no-seccomp sets flag");
    }

    /* --init */
    {
        char* argv[] = {"prog", "--init", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --init returns 0");
        ASSERT_INT_EQ(opts.use_init, 1, "parse_opts: --init sets flag");
    }

    /* --vm */
    {
        char* argv[] = {"prog", "--vm", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --vm returns 0");
        ASSERT_INT_EQ(opts.use_vm, 1, "parse_opts: --vm sets flag");
    }

    /* --vmm path */
    {
        char arg[] = "/usr/bin/cloud-hypervisor";
        char* argv[] = {"prog", "--vmm", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --vmm returns 0");
        ASSERT_STR_EQ(opts.vmm, "/usr/bin/cloud-hypervisor",
                      "parse_opts: --vmm value set");
    }

    /* --detach */
    {
        char* argv[] = {"prog", "--detach", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --detach returns 0");
        ASSERT_INT_EQ(opts.detach, 1,
                      "parse_opts: --detach sets flag");
    }

    /* -d alias */
    {
        char* argv[] = {"prog", "-d", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: -d returns 0");
        ASSERT_INT_EQ(opts.detach, 1, "parse_opts: -d sets detach flag");
    }

    /* --net none */
    {
        char arg[] = "none";
        char* argv[] = {"prog", "--net", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --net none returns 0");
        ASSERT_STR_EQ(opts.net, "none",
                      "parse_opts: --net none sets net=none");
    }

    /* --net slirp:8080:80 port forward */
    {
        char arg[] = "slirp:8080:80";
        char* argv[] = {"prog", "--net", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0,
                      "parse_opts: --net slirp:8080:80 returns 0");
        ASSERT_INT_EQ(opts.n_portfwd, 1,
                      "parse_opts: slirp:H:C n_portfwd=1");
        ASSERT_STR_EQ(opts.net, "slirp",
                      "parse_opts: slirp:H:C sets net=slirp");
    }

    /* --net slirp:8080: (missing ctr port): rejected */
    {
        char arg[] = "slirp:8080:";
        char* argv[] = {"prog", "--net", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --net slirp:8080: (no ctr port) rejected");
    }

    /* --device /dev/kvm */
    {
        char arg[] = "/dev/kvm";
        char* argv[] = {"prog", "--device", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --device /dev/kvm returns 0");
        ASSERT_INT_EQ(opts.n_devices, 1,
                      "parse_opts: --device n_devices=1");
        ASSERT_STR_EQ(opts.devices[0], "/dev/kvm",
                      "parse_opts: --device host path stored");
        ASSERT_NULL(opts.device_ctr[0],
                    "parse_opts: --device no explicit ctr path");
    }

    /* --device must start with /dev/: rejected otherwise */
    {
        char arg[] = "/tmp/device";
        char* argv[] = {"prog", "--device", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --device without /dev/ prefix rejected");
    }

    /* --device with '..' rejected */
    {
        char arg[] = "/dev/../kvm";
        char* argv[] = {"prog", "--device", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --device with '..' rejected");
    }
}

/* ── test_path_has_dotdot_extra ───────────────────────────────────────── */

static void test_path_has_dotdot_extra(void)
{
    /* NULL → false (safe) */
    ASSERT(!path_has_dotdot_component(NULL),
           "path_has_dotdot_component: NULL returns false");

    /* empty string → false */
    ASSERT(!path_has_dotdot_component(""),
           "path_has_dotdot_component: empty string returns false");

    /* standalone ".." → true */
    ASSERT(path_has_dotdot_component(".."),
           "path_has_dotdot_component: standalone '..' is traversal");

    /* "/..": root-relative parent → true */
    ASSERT(path_has_dotdot_component("/.."),
           "path_has_dotdot_component: '/..' is traversal");

    /* trailing "/.." → true */
    ASSERT(path_has_dotdot_component("/a/b/.."),
           "path_has_dotdot_component: trailing '/..' is traversal");

    /* "..." (three dots) component → NOT a traversal */
    ASSERT(!path_has_dotdot_component("/safe/...hidden"),
           "path_has_dotdot_component: '...' component is not '..'");

    /* single "." component → not a traversal */
    ASSERT(!path_has_dotdot_component("/a/./b"),
           "path_has_dotdot_component: single '.' is not traversal");

    /* double slash prefix → still detects ".." */
    ASSERT(path_has_dotdot_component("//.."),
           "path_has_dotdot_component: '//..' is traversal");
}

/* ── test_json_get_string_edge ────────────────────────────────────────────── */

static void test_json_get_string_edge(void)
{
    /* Key exactly at the needle buffer limit (254 usable chars + 2 quotes = 256).
     * json_skip_to_value must return NULL — not truncate and match a wrong key. */
    char long_key[300];
    memset(long_key, 'x', sizeof(long_key) - 1);
    long_key[sizeof(long_key) - 1] = '\0';

    /* Build {"<255-char key>":"value"} */
    char json_buf[700];
    snprintf(json_buf, sizeof(json_buf), "{\"%s\":\"value\"}", long_key);
    char* v = json_get_string(json_buf, long_key);
    ASSERT_NULL(v, "json_get_string: key > 254 chars returns NULL (needle overflow guard)");

    /* Unterminated string value — no closing quote: must return NULL */
    const char* bad = "{\"Key\":\"no closing quote}";
    char* bad_val = json_get_string(bad, "Key");
    ASSERT_NULL(bad_val, "json_get_string: unterminated value returns NULL");

    /* Truncated escape at end of input: must return NULL */
    const char* trunc = "{\"K\":\"val\\";
    char* trunc_val = json_get_string(trunc, "K");
    ASSERT_NULL(trunc_val, "json_get_string: truncated escape at EOI returns NULL");
}

/* ── test_parse_opts_path_validation ─────────────────────────────────────── */

static void test_parse_opts_path_validation(void)
{
    struct container_opts opts;

    /* -v: relative host path (no leading '/') must be rejected */
    {
        char spec[] = "relative/path:/ctr";
        char* argv[] = {"prog", "-v", spec, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: -v relative host path rejected");
    }

    /* -v: host path with '..' must be rejected */
    {
        char spec[] = "/host/../etc:/ctr";
        char* argv[] = {"prog", "-v", spec, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: -v host path with '..' rejected");
    }

    /* -v: container path with '..' must be rejected */
    {
        char spec[] = "/host:/ctr/../etc";
        char* argv[] = {"prog", "-v", spec, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: -v container path with '..' rejected");
    }

    /* --secret: host path with '..' must be rejected */
    {
        char arg[] = "/host/../etc/passwd";
        char* argv[] = {"prog", "--secret", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --secret host path with '..' rejected");
    }

    /* --secret: relative host path must be rejected */
    {
        char arg[] = "relative/secret.txt";
        char* argv[] = {"prog", "--secret", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --secret relative host path rejected");
    }

    /* --workdir: path with '..' must be rejected */
    {
        char arg[] = "/app/../etc";
        char* argv[] = {"prog", "--workdir", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --workdir with '..' rejected");
    }

    /* --tmpfs: path with '..' as a real component must be rejected */
    {
        char arg[] = "/run/../etc";
        char* argv[] = {"prog", "--tmpfs", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --tmpfs path with '..' component rejected");
    }
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(void)
{
    /* TAP plan printed after we know the count — use streaming output instead */
    printf("TAP version 13\n");

    test_json_get_string();
    test_json_get_string_edge();
    test_json_get_array();
    test_json_parse_string_array();
    test_path_has_dotdot_component();
    test_path_has_dotdot_extra();
    test_parse_opts();
    test_parse_opts_path_validation();
    test_build_exec_args();
    test_cap_name_to_num();
    test_parse_opts_resource_limits();
    test_parse_opts_user();
    test_parse_opts_caps();
    test_parse_opts_ulimit();
    test_parse_opts_misc_flags();

    printf("1..%d\n", tap_test_num);

    if (tap_fail_count > 0)
    {
        fprintf(stderr, "# %d test(s) FAILED\n", tap_fail_count);
        return 1;
    }
    return 0;
}
