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

    /* --audit-log */
    {
        char* argv[] = {"prog", "--audit-log", "-", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --audit-log returns 0");
        ASSERT_STR_EQ(opts.audit_log, "-", "parse_opts: --audit-log value");
    }

    /* --metrics-socket */
    {
        char* argv[] = {"prog", "--metrics-socket", "/tmp/metrics.sock", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --metrics-socket returns 0");
        ASSERT_STR_EQ(opts.metrics_socket, "/tmp/metrics.sock",
                      "parse_opts: --metrics-socket value");
    }

    /* --self-update */
    {
        char* argv[] = {"prog", "--self-update", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --self-update returns 0");
        ASSERT_INT_EQ(opts.self_update, 1,
                      "parse_opts: --self-update sets self_update=1");
    }

    /* --check-update */
    {
        char* argv[] = {"prog", "--check-update", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --check-update returns 0");
        ASSERT_INT_EQ(opts.check_update, 1,
                      "parse_opts: --check-update sets check_update=1");
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

    /* --audit-log missing arg */
    {
        char* argv[] = {"prog", "--audit-log", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, -1, "parse_opts: --audit-log missing arg returns -1");
    }

    /* --metrics-socket missing arg */
    {
        char* argv[] = {"prog", "--metrics-socket", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --metrics-socket missing arg returns -1");
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

    /* --secret tpm2:CRED (no container path) */
    {
        char arg[] = "tpm2:mydb";
        char* argv[] = {"prog", "--secret", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0,
                      "parse_opts: --secret tpm2 no ctr path returns 0");
        ASSERT_INT_EQ(opts.n_secrets, 1,
                      "parse_opts: --secret tpm2 n_secrets=1");
        ASSERT_STR_EQ(opts.secret_cred[0], "mydb",
                      "parse_opts: --secret tpm2 cred stored");
        ASSERT_NULL(opts.secret_host[0],
                    "parse_opts: --secret tpm2 host=NULL");
        ASSERT_NULL(opts.secret_ctr[0],
                    "parse_opts: --secret tpm2 ctr=NULL");
    }

    /* --secret tpm2:CRED:/ctr/path */
    {
        char arg[] = "tpm2:mydb:/run/secrets/db";
        char* argv[] = {"prog", "--secret", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0,
                      "parse_opts: --secret tpm2 with ctr path returns 0");
        ASSERT_STR_EQ(opts.secret_cred[0], "mydb",
                      "parse_opts: --secret tpm2 cred name");
        ASSERT_STR_EQ(opts.secret_ctr[0], "/run/secrets/db",
                      "parse_opts: --secret tpm2 ctr path");
    }

    /* --secret tpm2 with invalid char in cred name */
    {
        char arg[] = "tpm2:my/bad";
        char* argv[] = {"prog", "--secret", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --secret tpm2 slash in cred rejected");
    }

    /* --secret tpm2 with empty cred name */
    {
        char arg[] = "tpm2:";
        char* argv[] = {"prog", "--secret", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --secret tpm2 empty cred rejected");
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

    /* --no-userns-remap */
    {
        char* argv[] = {"prog", "--no-userns-remap", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --no-userns-remap returns 0");
        ASSERT_INT_EQ(opts.no_userns_remap, 1,
                      "parse_opts: --no-userns-remap sets flag");
    }

    /* --landlock / --no-landlock */
    {
        memset(&opts, 0, sizeof(opts));
        ASSERT_INT_EQ(opts.landlock_mode, LANDLOCK_MODE_AUTO,
                      "parse_opts: landlock default is AUTO");
    }
    {
        char* argv[] = {"prog", "--landlock", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --landlock returns 0");
        ASSERT_INT_EQ(opts.landlock_mode, LANDLOCK_MODE_ON,
                      "parse_opts: --landlock sets ON");
    }
    {
        char* argv[] = {"prog", "--no-landlock", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --no-landlock returns 0");
        ASSERT_INT_EQ(opts.landlock_mode, LANDLOCK_MODE_OFF,
                      "parse_opts: --no-landlock sets OFF");
    }

    /* --seccomp-deny-write */
    {
        char a1[] = "/etc";
        char a2[] = "/var/lib/secret";
        char* argv[] = {"prog", "--seccomp-deny-write", a1,
                        "--seccomp-deny-write", a2, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(5, argv, &opts);
        ASSERT_INT_EQ(r, 0,
                      "parse_opts: --seccomp-deny-write x2 returns 0");
        ASSERT_INT_EQ(opts.n_deny_write, 2,
                      "parse_opts: n_deny_write counts both");
        ASSERT_STR_EQ(opts.deny_write[0], "/etc",
                      "parse_opts: --seccomp-deny-write[0] stored");
        ASSERT_STR_EQ(opts.deny_write[1], "/var/lib/secret",
                      "parse_opts: --seccomp-deny-write[1] stored");
    }
    {
        char arg[] = "relative/path";
        char* argv[] = {"prog", "--seccomp-deny-write", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --seccomp-deny-write rejects relative");
    }
    {
        char arg[] = "/etc/../passwd";
        char* argv[] = {"prog", "--seccomp-deny-write", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --seccomp-deny-write rejects ..");
    }
    {
        char* argv[] = {"prog", "--seccomp-deny-write", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --seccomp-deny-write missing arg returns -1");
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

    /* --lazy */
    {
        char* argv[] = {"prog", "--lazy", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --lazy returns 0");
        ASSERT_INT_EQ(opts.lazy, 1, "parse_opts: --lazy sets flag");
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

    /* --metrics-socket: relative path must be rejected */
    {
        char arg[] = "metrics.sock";
        char* argv[] = {"prog", "--metrics-socket", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --metrics-socket relative path rejected");
    }
}

/* ── test_json_escape_string ──────────────────────────────────────────────── */

static void test_json_escape_string(void)
{
    char buf[256];

    /* Plain ASCII — no escaping needed */
    ASSERT_INT_EQ(json_escape_string("hello", buf, sizeof(buf)), 0,
                  "json_escape_string: plain string returns 0");
    ASSERT_STR_EQ(buf, "hello", "json_escape_string: plain string unchanged");

    /* Empty string */
    ASSERT_INT_EQ(json_escape_string("", buf, sizeof(buf)), 0,
                  "json_escape_string: empty string returns 0");
    ASSERT_STR_EQ(buf, "", "json_escape_string: empty string produces empty");

    /* Double-quote in value must be escaped */
    ASSERT_INT_EQ(json_escape_string("say \"hi\"", buf, sizeof(buf)), 0,
                  "json_escape_string: quote escaping returns 0");
    ASSERT_STR_EQ(buf, "say \\\"hi\\\"",
                  "json_escape_string: quotes escaped correctly");

    /* Backslash must be escaped */
    ASSERT_INT_EQ(json_escape_string("a\\b", buf, sizeof(buf)), 0,
                  "json_escape_string: backslash escaping returns 0");
    ASSERT_STR_EQ(buf, "a\\\\b",
                  "json_escape_string: backslash doubled");

    /* Buffer exactly fits result (including NUL) — should succeed */
    char small[4]; /* "ab" + NUL fits; "a\"" needs 4 bytes → "a\\\"" needs 5 */
    ASSERT_INT_EQ(json_escape_string("ab", small, 3), 0,
                  "json_escape_string: exact-fit buffer succeeds");

    /* Buffer too small — must return -1, not overflow */
    char tiny[3];
    ASSERT_INT_EQ(json_escape_string("a\"b", tiny, 3), -1,
                  "json_escape_string: buffer too small returns -1");
}

static int raw_probe_clone3_expected(void)
{
#ifdef __NR_clone3
    errno = 0;
    return (syscall(__NR_clone3, NULL, 0UL) >= 0 || errno != ENOSYS) ? 1 : 0;
#else
    return 0;
#endif
}

static int raw_probe_mseal_expected(void)
{
#ifdef __NR_mseal
    errno = 0;
    return (syscall(__NR_mseal, NULL, 0UL, 0UL) >= 0 ||
            errno != ENOSYS) ? 1 : 0;
#else
    return 0;
#endif
}

static void test_kernel_feature_runtime_detection(void)
{
    memset(g_kernel_feature_state, 0, sizeof(g_kernel_feature_state));

    ASSERT_INT_EQ(kernel_feature_state_from_syscall(-1, ENOSYS),
                  KERNEL_FEATURE_UNSUPPORTED,
                  "kernel feature: ENOSYS maps to unsupported");
    ASSERT_INT_EQ(kernel_feature_state_from_syscall(-1, EINVAL),
                  KERNEL_FEATURE_SUPPORTED,
                  "kernel feature: non-ENOSYS error maps to supported");
    ASSERT_INT_EQ(kernel_feature_state_from_syscall(0, 0),
                  KERNEL_FEATURE_SUPPORTED,
                  "kernel feature: successful syscall maps to supported");

    kernel_set_feature_state(KERNEL_FEATURE_CLONE3,
                             KERNEL_FEATURE_UNSUPPORTED);
    ASSERT_INT_EQ(kernel_supports_clone3(), 0,
                  "kernel feature: clone3 cached unsupported");
    kernel_set_feature_state(KERNEL_FEATURE_CLONE3,
                             KERNEL_FEATURE_SUPPORTED);
    ASSERT_INT_EQ(kernel_supports_clone3(), 1,
                  "kernel feature: clone3 cached supported");

    kernel_set_feature_state(KERNEL_FEATURE_MSEAL,
                             KERNEL_FEATURE_UNSUPPORTED);
    ASSERT_INT_EQ(kernel_supports_mseal(), 0,
                  "kernel feature: mseal cached unsupported");
    kernel_set_feature_state(KERNEL_FEATURE_MSEAL,
                             KERNEL_FEATURE_SUPPORTED);
    ASSERT_INT_EQ(kernel_supports_mseal(), 1,
                  "kernel feature: mseal cached supported");

    kernel_set_feature_state(KERNEL_FEATURE_CLONE3, KERNEL_FEATURE_UNKNOWN);
    ASSERT_INT_EQ(kernel_supports_clone3(), raw_probe_clone3_expected(),
                  "kernel feature: clone3 runtime probe matches raw syscall");
    ASSERT_INT_EQ(g_kernel_feature_state[KERNEL_FEATURE_CLONE3],
                  raw_probe_clone3_expected() ?
                  KERNEL_FEATURE_SUPPORTED :
                  KERNEL_FEATURE_UNSUPPORTED,
                  "kernel feature: clone3 probe result cached");

    kernel_set_feature_state(KERNEL_FEATURE_MSEAL, KERNEL_FEATURE_UNKNOWN);
    ASSERT_INT_EQ(kernel_supports_mseal(), raw_probe_mseal_expected(),
                  "kernel feature: mseal runtime probe matches raw syscall");
    ASSERT_INT_EQ(g_kernel_feature_state[KERNEL_FEATURE_MSEAL],
                  raw_probe_mseal_expected() ?
                  KERNEL_FEATURE_SUPPORTED :
                  KERNEL_FEATURE_UNSUPPORTED,
                  "kernel feature: mseal probe result cached");

    /* userfaultfd probe */
    kernel_set_feature_state(KERNEL_FEATURE_UFFD, KERNEL_FEATURE_UNSUPPORTED);
    ASSERT_INT_EQ(kernel_supports_uffd(), 0,
                  "kernel feature: uffd cached unsupported");
    kernel_set_feature_state(KERNEL_FEATURE_UFFD, KERNEL_FEATURE_SUPPORTED);
    ASSERT_INT_EQ(kernel_supports_uffd(), 1,
                  "kernel feature: uffd cached supported");

    kernel_set_feature_state(KERNEL_FEATURE_UFFD, KERNEL_FEATURE_UNKNOWN);
    {
        int uffd_live = kernel_supports_uffd();
        ASSERT_INT_EQ(uffd_live == 0 || uffd_live == 1, 1,
                      "kernel feature: uffd runtime probe returns 0 or 1");
        ASSERT_INT_EQ(g_kernel_feature_state[KERNEL_FEATURE_UFFD],
                      uffd_live ? KERNEL_FEATURE_SUPPORTED :
                      KERNEL_FEATURE_UNSUPPORTED,
                      "kernel feature: uffd probe result cached");
    }

    /* Landlock probe */
    kernel_set_feature_state(KERNEL_FEATURE_LANDLOCK,
                             KERNEL_FEATURE_UNSUPPORTED);
    ASSERT_INT_EQ(kernel_supports_landlock(), 0,
                  "kernel feature: landlock cached unsupported");
    kernel_set_feature_state(KERNEL_FEATURE_LANDLOCK,
                             KERNEL_FEATURE_SUPPORTED);
    ASSERT_INT_EQ(kernel_supports_landlock(), 1,
                  "kernel feature: landlock cached supported");

    kernel_set_feature_state(KERNEL_FEATURE_LANDLOCK,
                             KERNEL_FEATURE_UNKNOWN);
    {
        int ll_live = kernel_supports_landlock();
        ASSERT_INT_EQ(ll_live == 0 || ll_live == 1, 1,
                      "kernel feature: landlock runtime probe returns 0 or 1");
        ASSERT_INT_EQ(g_kernel_feature_state[KERNEL_FEATURE_LANDLOCK],
                      ll_live ? KERNEL_FEATURE_SUPPORTED :
                      KERNEL_FEATURE_UNSUPPORTED,
                      "kernel feature: landlock probe result cached");
    }
}

static void test_audit_logging_helpers(void)
{
    char path[] = "/tmp/oci2bin-audit-test-XXXXXX";
    int fd = mkstemp(path);
    ASSERT(fd >= 0, "audit helpers: mkstemp succeeds");
    if (fd < 0)
    {
        return;
    }

    int saved_audit_fd = g_audit_fd;
    g_audit_fd = fd;

    struct container_opts opts;
    memset(&opts, 0, sizeof(opts));
    opts.name = "svc\"name";
    opts.net = "slirp\"mode";
    opts.cap_add_mask = 0x2aULL;

    audit_emit_start_event("/tmp/bin\"name", &opts);
    audit_emit_exec_event("/bin/echo\"quoted");
    audit_emit_wait_status("exit", 42, (7 << 8));
    audit_emit_wait_status("stop", 42, SIGTERM);

    ASSERT_INT_EQ(lseek(fd, 0, SEEK_SET), 0,
                  "audit helpers: rewind temp file");
    char buf[2048];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    ASSERT(n > 0, "audit helpers: read log output");
    if (n > 0)
    {
        buf[n] = '\0';
        ASSERT(strstr(buf, "\"event\":\"start\"") != NULL,
               "audit helpers: start event emitted");
        ASSERT(strstr(buf, "\"image\":\"/tmp/bin\\\"name\"") != NULL,
               "audit helpers: image path escaped");
        ASSERT(strstr(buf, "\"name\":\"svc\\\"name\"") != NULL,
               "audit helpers: container name escaped");
        ASSERT(strstr(buf, "\"net\":\"slirp\\\"mode\"") != NULL,
               "audit helpers: network mode escaped");
        ASSERT(strstr(buf, "\"caps\":\"0x2a\"") != NULL,
               "audit helpers: start caps field emitted");
        ASSERT(strstr(buf, "\"event\":\"exec\"") != NULL,
               "audit helpers: exec event emitted");
        ASSERT(strstr(buf, "\"path\":\"/bin/echo\\\"quoted\"") != NULL,
               "audit helpers: exec path escaped");
        ASSERT(strstr(buf, "\"event\":\"exit\",\"time\":") != NULL,
               "audit helpers: exit event emitted");
        ASSERT(strstr(buf, "\"pid\":42,\"exit_code\":7") != NULL,
               "audit helpers: exit code emitted");
        ASSERT(strstr(buf, "\"event\":\"stop\",\"time\":") != NULL,
               "audit helpers: stop event emitted");
        ASSERT(strstr(buf, "\"pid\":42,\"signal\":15") != NULL,
               "audit helpers: signal emitted");
    }

    close(fd);
    unlink(path);
    g_audit_fd = saved_audit_fd;
}

static void test_metrics_helpers(void)
{
    struct metrics_snapshot snap;
    memset(&snap, 0, sizeof(snap));

    const char* cpu_stat =
        "usage_usec 1234\n"
        "user_usec 1200\n"
        "system_usec 34\n"
        "nr_periods 10\n"
        "nr_throttled 2\n"
        "throttled_usec 55\n";
    ASSERT_INT_EQ(parse_cpu_stat_text(cpu_stat, &snap), 0,
                  "metrics helpers: parse_cpu_stat_text returns 0");
    ASSERT_INT_EQ((int)snap.cpu_usage_usec, 1234,
                  "metrics helpers: usage_usec parsed");
    ASSERT_INT_EQ((int)snap.cpu_user_usec, 1200,
                  "metrics helpers: user_usec parsed");
    ASSERT_INT_EQ((int)snap.cpu_system_usec, 34,
                  "metrics helpers: system_usec parsed");
    ASSERT_INT_EQ((int)snap.cpu_nr_periods, 10,
                  "metrics helpers: nr_periods parsed");
    ASSERT_INT_EQ((int)snap.cpu_nr_throttled, 2,
                  "metrics helpers: nr_throttled parsed");
    ASSERT_INT_EQ((int)snap.cpu_throttled_usec, 55,
                  "metrics helpers: throttled_usec parsed");

    snap.memory_current = 4096;
    snap.pids_current = 7;

    char buf[2048];
    ASSERT_INT_EQ(format_metrics_text(&snap, buf, sizeof(buf)), 0,
                  "metrics helpers: format_metrics_text returns 0");
    ASSERT(strstr(buf, "oci2bin_cpu_usage_usec 1234\n") != NULL,
           "metrics helpers: cpu usage metric emitted");
    ASSERT(strstr(buf, "oci2bin_cpu_nr_throttled 2\n") != NULL,
           "metrics helpers: throttled periods metric emitted");
    ASSERT(strstr(buf, "oci2bin_memory_current 4096\n") != NULL,
           "metrics helpers: memory metric emitted");
    ASSERT(strstr(buf, "oci2bin_pids_current 7\n") != NULL,
           "metrics helpers: pids metric emitted");
}

static void test_userns_subid_helpers(void)
{
    unsigned long start = 0;
    unsigned long count = 0;

    ASSERT_INT_EQ(parse_subid_line("omer:524288:65536\n", "omer", "1000",
                                   &start, &count),
                  0,
                  "userns subid: parse_subid_line accepts matching name");
    ASSERT(start == 524288UL,
           "userns subid: parse_subid_line stores start");
    ASSERT(count == 65536UL,
           "userns subid: parse_subid_line stores count");

    ASSERT_INT_EQ(parse_subid_line("1000:600000:70000\n", "omer", "1000",
                                   &start, &count),
                  0,
                  "userns subid: parse_subid_line accepts numeric owner");
    ASSERT(start == 600000UL,
           "userns subid: parse_subid_line numeric owner start");
    ASSERT(count == 70000UL,
           "userns subid: parse_subid_line numeric owner count");

    ASSERT_INT_EQ(parse_subid_line("other:1:2\n", "omer", "1000",
                                   &start, &count),
                  -1,
                  "userns subid: parse_subid_line rejects other owners");
    ASSERT_INT_EQ(parse_subid_line("omer:bad:65536\n", "omer", "1000",
                                   &start, &count),
                  -1,
                  "userns subid: parse_subid_line rejects bad start");
    ASSERT_INT_EQ(parse_subid_line("omer:1:2:3\n", "omer", "1000",
                                   &start, &count),
                  -1,
                  "userns subid: parse_subid_line rejects extra fields");

    char path[] = "/tmp/oci2bin-subid-test-XXXXXX";
    int fd = mkstemp(path);
    ASSERT(fd >= 0, "userns subid: mkstemp succeeds");
    if (fd < 0)
    {
        return;
    }

    const char* file_data =
        "ignored\n"
        "omer:700000:65536\n"
        "1001:800000:70000\n"
        "tiny:900000:16\n";
    ASSERT_INT_EQ(write_all_fd(fd, file_data, strlen(file_data)),
                  0,
                  "userns subid: write temp file succeeds");
    close(fd);

    ASSERT_INT_EQ(lookup_subid_range_in_file(path, "omer", 1000,
                                             USERNS_REMAP_CONTAINER_IDS,
                                             &start, &count),
                  0,
                  "userns subid: lookup_subid_range_in_file finds named range");
    ASSERT(start == 700000UL,
           "userns subid: named lookup start");
    ASSERT(count == 65536UL,
           "userns subid: named lookup count");

    ASSERT_INT_EQ(lookup_subid_range_in_file(path, NULL, 1001,
                                             USERNS_REMAP_CONTAINER_IDS,
                                             &start, &count),
                  0,
                  "userns subid: lookup_subid_range_in_file finds numeric owner");
    ASSERT(start == 800000UL,
           "userns subid: numeric lookup start");
    ASSERT(count == 70000UL,
           "userns subid: numeric lookup count");

    ASSERT_INT_EQ(lookup_subid_range_in_file(path, "tiny", 1002,
                                             USERNS_REMAP_CONTAINER_IDS,
                                             &start, &count),
                  -1,
                  "userns subid: lookup_subid_range_in_file rejects short ranges");

    unlink(path);
}

/* ── test_parse_id_value ──────────────────────────────────────────────────── */

static void test_parse_id_value(void)
{
    long out;

    /* Zero — valid */
    out = -1;
    ASSERT_INT_EQ(parse_id_value("0", 65534, &out), 0,
                  "parse_id_value: 0 returns 0");
    ASSERT_INT_EQ((int)out, 0, "parse_id_value: 0 stores 0");

    /* Positive number within range */
    out = -1;
    ASSERT_INT_EQ(parse_id_value("1000", 65534, &out), 0,
                  "parse_id_value: 1000 returns 0");
    ASSERT_INT_EQ((int)out, 1000, "parse_id_value: 1000 stored");

    /* Exact maximum */
    out = -1;
    ASSERT_INT_EQ(parse_id_value("65534", 65534, &out), 0,
                  "parse_id_value: max value accepted");
    ASSERT_INT_EQ((int)out, 65534, "parse_id_value: max value stored");

    /* One over maximum — rejected */
    ASSERT_INT_EQ(parse_id_value("65535", 65534, &out), -1,
                  "parse_id_value: max+1 rejected");

    /* Negative number — rejected */
    ASSERT_INT_EQ(parse_id_value("-1", 65534, &out), -1,
                  "parse_id_value: negative rejected");

    /* Non-numeric — rejected */
    ASSERT_INT_EQ(parse_id_value("abc", 65534, &out), -1,
                  "parse_id_value: non-numeric rejected");

    /* Trailing garbage — rejected */
    ASSERT_INT_EQ(parse_id_value("123abc", 65534, &out), -1,
                  "parse_id_value: trailing garbage rejected");

    /* Empty string — rejected */
    ASSERT_INT_EQ(parse_id_value("", 65534, &out), -1,
                  "parse_id_value: empty string rejected");

    /* NULL — rejected */
    ASSERT_INT_EQ(parse_id_value(NULL, 65534, &out), -1,
                  "parse_id_value: NULL rejected");
}

/* ── test_path_is_absolute_and_clean ─────────────────────────────────────── */

static void test_path_is_absolute_and_clean(void)
{
    /* Valid absolute paths */
    ASSERT(path_is_absolute_and_clean("/usr/bin/python3"),
           "path_is_absolute_and_clean: deep absolute path accepted");
    ASSERT(path_is_absolute_and_clean("/"),
           "path_is_absolute_and_clean: root '/' accepted");
    ASSERT(path_is_absolute_and_clean("/a/./b"),
           "path_is_absolute_and_clean: single '.' component accepted");
    ASSERT(path_is_absolute_and_clean("/usr/lib/python3..8"),
           "path_is_absolute_and_clean: '..X' component name accepted");

    /* Relative paths — rejected */
    ASSERT(!path_is_absolute_and_clean("relative/path"),
           "path_is_absolute_and_clean: relative path rejected");
    ASSERT(!path_is_absolute_and_clean("./relative"),
           "path_is_absolute_and_clean: ./ relative path rejected");

    /* Paths with '..' component — rejected */
    ASSERT(!path_is_absolute_and_clean("/usr/../etc"),
           "path_is_absolute_and_clean: path with '..' rejected");
    ASSERT(!path_is_absolute_and_clean("/.."),
           "path_is_absolute_and_clean: '/..' rejected");

    /* NULL and empty — rejected */
    ASSERT(!path_is_absolute_and_clean(NULL),
           "path_is_absolute_and_clean: NULL rejected");
    ASSERT(!path_is_absolute_and_clean(""),
           "path_is_absolute_and_clean: empty string rejected");
}

/* ── test_path_join_suffix ────────────────────────────────────────────────── */

static void test_path_join_suffix(void)
{
    char buf[32];

    /* Normal join */
    ASSERT_INT_EQ(path_join_suffix(buf, sizeof(buf), "/tmp/dir", "/oci"), 0,
                  "path_join_suffix: normal join returns 0");
    ASSERT_STR_EQ(buf, "/tmp/dir/oci",
                  "path_join_suffix: normal join result correct");

    /* Result exactly fills buffer (base + suffix + NUL) */
    char exact[13]; /* "/tmp/dir/oci" is 12 chars + NUL = 13 */
    ASSERT_INT_EQ(path_join_suffix(exact, 13, "/tmp/dir", "/oci"), 0,
                  "path_join_suffix: exact-fit buffer succeeds");

    /* Result one byte too long — must return -1 */
    char small[12];
    ASSERT_INT_EQ(path_join_suffix(small, 12, "/tmp/dir", "/oci"), -1,
                  "path_join_suffix: buffer too small returns -1");

    /* Empty suffix */
    ASSERT_INT_EQ(path_join_suffix(buf, sizeof(buf), "/tmp/dir", ""), 0,
                  "path_join_suffix: empty suffix returns 0");
    ASSERT_STR_EQ(buf, "/tmp/dir",
                  "path_join_suffix: empty suffix result is base");
}

/* ── test_parse_opts_name ─────────────────────────────────────────────────── */

static void test_parse_opts_name(void)
{
    struct container_opts opts;

    /* Valid name */
    {
        char arg[] = "my-container_1";
        char* argv[] = {"prog", "--name", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --name valid alphanumeric/dash returns 0");
        ASSERT_STR_EQ(opts.name, "my-container_1",
                      "parse_opts: --name value stored");
    }

    /* Space in name — rejected */
    {
        char arg[] = "bad name";
        char* argv[] = {"prog", "--name", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --name with space rejected");
    }

    /* Slash in name — rejected */
    {
        char arg[] = "bad/name";
        char* argv[] = {"prog", "--name", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --name with slash rejected");
    }

    /* 128-char name — accepted (boundary) */
    {
        char arg[129];
        memset(arg, 'a', 128);
        arg[128] = '\0';
        char* argv[] = {"prog", "--name", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0,
                      "parse_opts: --name 128 chars (max) accepted");
    }

    /* 129-char name — rejected */
    {
        char arg[130];
        memset(arg, 'a', 129);
        arg[129] = '\0';
        char* argv[] = {"prog", "--name", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --name 129 chars rejected");
    }

    /* Missing argument */
    {
        char* argv[] = {"prog", "--name", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --name missing arg returns -1");
    }
}

/* ── test_parse_opts_limits ───────────────────────────────────────────────── */

static void test_parse_opts_limits(void)
{
    struct container_opts opts;

    /* MAX_VOLUMES (32) -v flags accepted; 33rd rejected */
    {
        /* Build argv with 32 -v flags */
        /* Each -v takes 2 argv slots; plus prog = 65 total */
        char specs[MAX_VOLUMES][32];
        char* argv[MAX_VOLUMES * 2 + 2];
        argv[0] = "prog";
        int ai = 1;
        for (int i = 0; i < MAX_VOLUMES; i++)
        {
            snprintf(specs[i], sizeof(specs[i]), "/host%d:/ctr%d", i, i);
            argv[ai++] = "-v";
            argv[ai++] = specs[i];
        }
        argv[ai] = NULL;

        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(ai, argv, &opts);
        ASSERT_INT_EQ(r, 0,
                      "parse_opts: MAX_VOLUMES -v flags accepted");
        ASSERT_INT_EQ(opts.n_vols, MAX_VOLUMES,
                      "parse_opts: n_vols == MAX_VOLUMES");
    }

    {
        /* One more than MAX_VOLUMES */
        char specs[MAX_VOLUMES + 1][32];
        char* argv[MAX_VOLUMES * 2 + 4];
        argv[0] = "prog";
        int ai = 1;
        for (int i = 0; i <= MAX_VOLUMES; i++)
        {
            snprintf(specs[i], sizeof(specs[i]), "/host%d:/ctr%d", i, i);
            argv[ai++] = "-v";
            argv[ai++] = specs[i];
        }
        argv[ai] = NULL;

        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(ai, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: MAX_VOLUMES+1 -v flags rejected");
    }

    /* --add-host: valid HOST:IP accepted */
    {
        char arg[] = "myhost:192.168.1.1";
        char* argv[] = {"prog", "--add-host", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --add-host valid returns 0");
        ASSERT_INT_EQ(opts.n_add_hosts, 1,
                      "parse_opts: --add-host n_add_hosts=1");
    }

    /* --add-host: missing colon rejected */
    {
        char arg[] = "myhost_192.168.1.1";
        char* argv[] = {"prog", "--add-host", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --add-host missing colon rejected");
    }

    /* --add-host: missing argument rejected */
    {
        char* argv[] = {"prog", "--add-host", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --add-host missing arg returns -1");
    }

    /* --net slirp (no port-forward suffix) */
    {
        char arg[] = "slirp";
        char* argv[] = {"prog", "--net", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --net slirp returns 0");
        ASSERT_STR_EQ(opts.net, "slirp",
                      "parse_opts: --net slirp sets net=slirp");
        ASSERT_INT_EQ(opts.n_portfwd, 0,
                      "parse_opts: --net slirp n_portfwd=0");
    }

    /* --net pasta */
    {
        char arg[] = "pasta";
        char* argv[] = {"prog", "--net", arg, NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --net pasta returns 0");
        ASSERT_STR_EQ(opts.net, "pasta",
                      "parse_opts: --net pasta sets net=pasta");
    }
}

/* ── test_build_exec_args_extended ────────────────────────────────────────── */

static void test_build_exec_args_extended(void)
{
    struct oci_config cfg;
    char* exec_args[16];

    /* Multi-element entrypoint: ["/bin/sh", "-c"] + cmd ["echo", "hi"] */
    {
        memset(&cfg, 0, sizeof(cfg));
        cfg.entrypoint_json = strdup("[\"/bin/sh\",\"-c\"]");
        cfg.cmd_json        = strdup("[\"echo\",\"hi\"]");
        int n = build_exec_args(&cfg, NULL, NULL, 0, exec_args, 16);
        ASSERT_INT_EQ(n, 4,
                      "build_exec_args: multi-element ep + cmd = 4 args");
        ASSERT_STR_EQ(exec_args[0], "/bin/sh",
                      "build_exec_args: multi-ep [0]");
        ASSERT_STR_EQ(exec_args[1], "-c",
                      "build_exec_args: multi-ep [1]");
        ASSERT_STR_EQ(exec_args[2], "echo",
                      "build_exec_args: cmd[0] after multi-ep");
        ASSERT_STR_EQ(exec_args[3], "hi",
                      "build_exec_args: cmd[1] after multi-ep");
        ASSERT_NULL(exec_args[4],
                    "build_exec_args: null-terminated after multi-ep");
        free(exec_args[0]);
        free(exec_args[1]);
        free(exec_args[2]);
        free(exec_args[3]);
        free_oci_config(&cfg);
    }

    /* max_args overflow: ep + cmd would exceed buffer; result capped and
     * NULL-terminated within the buffer (no out-of-bounds write) */
    {
        memset(&cfg, 0, sizeof(cfg));
        /* 4-element entrypoint; max_args=3 → only 3 fit */
        cfg.entrypoint_json = strdup("[\"/a\",\"/b\",\"/c\",\"/d\"]");
        int n = build_exec_args(&cfg, NULL, NULL, 0, exec_args, 3);
        ASSERT_INT_EQ(n, 3,
                      "build_exec_args: result capped at max_args");
        ASSERT_NULL(exec_args[3],
                    "build_exec_args: slot at max_args is NULL (null-terminated)");
        for (int i = 0; i < 3; i++)
        {
            free(exec_args[i]);
        }
        free_oci_config(&cfg);
    }

    /* Both entrypoint_json and cmd_json are "null": fallback to /bin/sh */
    {
        memset(&cfg, 0, sizeof(cfg));
        cfg.entrypoint_json = strdup("null");
        cfg.cmd_json        = strdup("null");
        int n = build_exec_args(&cfg, NULL, NULL, 0, exec_args, 16);
        ASSERT_INT_EQ(n, 1,
                      "build_exec_args: both null → fallback /bin/sh count");
        ASSERT_STR_EQ(exec_args[0], "/bin/sh",
                      "build_exec_args: both null → fallback is /bin/sh");
        free_oci_config(&cfg);
    }
}

/* ── main ────────────────────────────────────────────────────────────────── */

/* ── test_mcp_helpers ─────────────────────────────────────────────────────── */

/* ── test_parent_dir_path ─────────────────────────────────────────────────── */

static void test_parent_dir_path(void)
{
    char out[PATH_MAX];

    /* normal multi-component path */
    ASSERT_INT_EQ(parent_dir_path("/foo/bar/baz", out, sizeof(out)), 0,
                  "parent_dir: /foo/bar/baz returns 0");
    ASSERT_INT_EQ(strcmp(out, "/foo/bar"), 0,
                  "parent_dir: /foo/bar/baz -> /foo/bar");

    /* one level below root */
    ASSERT_INT_EQ(parent_dir_path("/foo", out, sizeof(out)), 0,
                  "parent_dir: /foo returns 0");
    ASSERT_INT_EQ(strcmp(out, "/"), 0,
                  "parent_dir: /foo -> /");

    /* no slash at all */
    ASSERT_INT_EQ(parent_dir_path("nopath", out, sizeof(out)), -1,
                  "parent_dir: no slash returns -1");

    /* buffer too small */
    char tiny[4];
    ASSERT_INT_EQ(parent_dir_path("/foo/bar", tiny, sizeof(tiny)), -1,
                  "parent_dir: tiny buffer returns -1");
}

/* ── test_read_write_all_fd ───────────────────────────────────────────────── */

static void test_read_write_all_fd(void)
{
    char path[] = "/tmp/oci2bin-rwfd-XXXXXX";
    int fd = mkstemp(path);
    ASSERT(fd >= 0, "rwfd: mkstemp succeeds");
    if (fd < 0)
        return;

    const char* msg = "hello, read_all_fd world\n";
    size_t len = strlen(msg);

    ASSERT_INT_EQ(write_all_fd(fd, msg, len), 0,
                  "rwfd: write_all_fd returns 0");

    ASSERT_INT_EQ((int)lseek(fd, 0, SEEK_SET), 0,
                  "rwfd: lseek to start succeeds");

    char buf[128];
    memset(buf, 0, sizeof(buf));
    ssize_t n = read_all_fd(fd, buf, len);
    ASSERT(n == (ssize_t)len, "rwfd: read_all_fd returns full length");
    ASSERT_INT_EQ(memcmp(buf, msg, len), 0,
                  "rwfd: round-trip content matches");

    /* write_all_fd with zero bytes is a no-op */
    ASSERT_INT_EQ(write_all_fd(fd, msg, 0), 0,
                  "rwfd: write_all_fd zero bytes returns 0");

    close(fd);
    unlink(path);
}

/* ── test_read_write_file ─────────────────────────────────────────────────── */

static void test_read_write_file(void)
{
    char path[] = "/tmp/oci2bin-rwfile-XXXXXX";
    int fd = mkstemp(path);
    ASSERT(fd >= 0, "rwfile: mkstemp succeeds");
    if (fd < 0)
        return;

    const char* content = "line1\nline2\n";
    size_t clen = strlen(content);

    ASSERT_INT_EQ(write_all_fd(fd, content, clen), 0,
                  "rwfile: write_all_fd returns 0");
    close(fd);

    size_t got_size = 0;
    char* got = read_file(path, &got_size);
    ASSERT(got != NULL, "rwfile: read_file returns non-NULL");
    if (got)
    {
        ASSERT(got_size == clen, "rwfile: read_file returns correct size");
        ASSERT_INT_EQ(memcmp(got, content, clen), 0,
                      "rwfile: read_file content matches");
        free(got);
    }

    /* read_file on missing path returns NULL */
    ASSERT(read_file("/tmp/oci2bin-no-such-file-xyz", NULL) == NULL,
           "rwfile: read_file missing path returns NULL");

    unlink(path);
}

/* ── test_copy_n_bytes ────────────────────────────────────────────────────── */

static void test_copy_n_bytes(void)
{
    char src_path[] = "/tmp/oci2bin-cpysrc-XXXXXX";
    char dst_path[] = "/tmp/oci2bin-cpydst-XXXXXX";
    int src_fd = mkstemp(src_path);
    int dst_fd = mkstemp(dst_path);
    ASSERT(src_fd >= 0 && dst_fd >= 0, "copy_n_bytes: mkstemp succeeds");
    if (src_fd < 0 || dst_fd < 0)
    {
        if (src_fd >= 0) { close(src_fd); unlink(src_path); }
        if (dst_fd >= 0) { close(dst_fd); unlink(dst_path); }
        return;
    }

    const char* data = "0123456789abcdef";
    unsigned long dlen = (unsigned long)strlen(data);
    ASSERT_INT_EQ(write_all_fd(src_fd, data, dlen), 0,
                  "copy_n_bytes: write source succeeds");
    ASSERT_INT_EQ((int)lseek(src_fd, 0, SEEK_SET), 0,
                  "copy_n_bytes: rewind source succeeds");

    ASSERT_INT_EQ(copy_n_bytes(src_fd, dst_fd, dlen), 0,
                  "copy_n_bytes: returns 0 on success");

    ASSERT_INT_EQ((int)lseek(dst_fd, 0, SEEK_SET), 0,
                  "copy_n_bytes: rewind dest succeeds");
    char buf[64];
    ssize_t n = read_all_fd(dst_fd, buf, dlen);
    ASSERT(n == (ssize_t)dlen, "copy_n_bytes: dest has full length");
    ASSERT_INT_EQ(memcmp(buf, data, dlen), 0,
                  "copy_n_bytes: dest content matches source");

    /* premature EOF returns -1 */
    ASSERT_INT_EQ((int)lseek(src_fd, 0, SEEK_SET), 0,
                  "copy_n_bytes: rewind for eof test");
    ASSERT_INT_EQ(copy_n_bytes(src_fd, dst_fd, dlen * 2), -1,
                  "copy_n_bytes: premature EOF returns -1");

    close(src_fd); unlink(src_path);
    close(dst_fd); unlink(dst_path);
}

/* ── test_lookup_passwd_group ─────────────────────────────────────────────── */

static void test_lookup_passwd_group(void)
{
    char pw_path[] = "/tmp/oci2bin-passwd-XXXXXX";
    char gr_path[] = "/tmp/oci2bin-group-XXXXXX";
    int pw_fd = mkstemp(pw_path);
    int gr_fd = mkstemp(gr_path);
    ASSERT(pw_fd >= 0 && gr_fd >= 0, "passwd/group: mkstemp succeeds");
    if (pw_fd < 0 || gr_fd < 0)
    {
        if (pw_fd >= 0) { close(pw_fd); unlink(pw_path); }
        if (gr_fd >= 0) { close(gr_fd); unlink(gr_path); }
        return;
    }

    const char* pw_data =
        "root:x:0:0:root:/root:/bin/sh\n"
        "nobody:x:65534:65534:nobody:/:/sbin/nologin\n"
        "appuser:x:1000:1001:App User:/home/app:/bin/bash\n";
    ASSERT_INT_EQ(write_all_fd(pw_fd, pw_data, strlen(pw_data)), 0,
                  "passwd/group: write passwd file");
    close(pw_fd);

    const char* gr_data =
        "root:x:0:\n"
        "appgroup:x:1001:appuser\n"
        "nobody:x:65534:\n";
    ASSERT_INT_EQ(write_all_fd(gr_fd, gr_data, strlen(gr_data)), 0,
                  "passwd/group: write group file");
    close(gr_fd);

    uid_t uid; gid_t gid;

    ASSERT_INT_EQ(lookup_passwd_user(pw_path, "root", &uid, &gid), 0,
                  "passwd: lookup root returns 0");
    ASSERT_INT_EQ((int)uid, 0, "passwd: root uid=0");
    ASSERT_INT_EQ((int)gid, 0, "passwd: root gid=0");

    ASSERT_INT_EQ(lookup_passwd_user(pw_path, "appuser", &uid, &gid), 0,
                  "passwd: lookup appuser returns 0");
    ASSERT_INT_EQ((int)uid, 1000, "passwd: appuser uid=1000");
    ASSERT_INT_EQ((int)gid, 1001, "passwd: appuser gid=1001");

    ASSERT_INT_EQ(lookup_passwd_user(pw_path, "missing", &uid, &gid), -1,
                  "passwd: missing user returns -1");

    ASSERT_INT_EQ(lookup_passwd_user("/no-such-file", "root", &uid, &gid), -1,
                  "passwd: missing file returns -1");

    gid_t g;
    ASSERT_INT_EQ(lookup_group_name(gr_path, "appgroup", &g), 0,
                  "group: lookup appgroup returns 0");
    ASSERT_INT_EQ((int)g, 1001, "group: appgroup gid=1001");

    ASSERT_INT_EQ(lookup_group_name(gr_path, "nobody", &g), 0,
                  "group: lookup nobody returns 0");
    ASSERT_INT_EQ((int)g, 65534, "group: nobody gid=65534");

    ASSERT_INT_EQ(lookup_group_name(gr_path, "missing", &g), -1,
                  "group: missing group returns -1");

    ASSERT_INT_EQ(lookup_group_name("/no-such-file", "root", &g), -1,
                  "group: missing file returns -1");

    unlink(pw_path);
    unlink(gr_path);
}

/* ── test_openat_beneath ──────────────────────────────────────────────────── */

/* ── test_misc_helpers ────────────────────────────────────────────────────── */

/* ── test_write_read_file_beneath ─────────────────────────────────────────── */

static void test_write_read_file_beneath(void)
{
    char base[] = "/tmp/oci2bin-fb-XXXXXX";
    ASSERT(mkdtemp(base) != NULL, "file_beneath: mkdtemp succeeds");

    int root_fd = open(base, O_RDONLY | O_DIRECTORY);
    ASSERT(root_fd >= 0, "file_beneath: open base dir");
    if (root_fd < 0)
    {
        rmdir(base);
        return;
    }

    const char* content = "beneath content\n";
    size_t clen = strlen(content);

    ASSERT_INT_EQ(write_file_beneath(root_fd, "test.txt",
                                     content, clen, 0644),
                  0, "file_beneath: write_file_beneath succeeds");

    size_t got_sz = 0;
    char* got = read_file_beneath(root_fd, "test.txt", &got_sz);
    ASSERT(got != NULL, "file_beneath: read_file_beneath returns non-NULL");
    if (got)
    {
        ASSERT(got_sz == clen, "file_beneath: size matches");
        ASSERT_INT_EQ(memcmp(got, content, clen), 0,
                      "file_beneath: content matches");
        free(got);
    }

    /* missing file returns NULL */
    ASSERT(read_file_beneath(root_fd, "no-such.txt", NULL) == NULL,
           "file_beneath: missing file returns NULL");

    close(root_fd);

    /* cleanup */
    char fp[PATH_MAX];
    snprintf(fp, sizeof(fp), "%s/test.txt", base);
    unlink(fp);
    rmdir(base);
}

/* ── test_kernel_feature_state ────────────────────────────────────────────── */

static void test_kernel_feature_state(void)
{
    /* kernel_feature_state_from_syscall: rc >= 0 => SUPPORTED */
    ASSERT_INT_EQ(kernel_feature_state_from_syscall(0, 0),
                  KERNEL_FEATURE_SUPPORTED,
                  "kfstate: rc=0 -> SUPPORTED");
    ASSERT_INT_EQ(kernel_feature_state_from_syscall(1, ENOSYS),
                  KERNEL_FEATURE_SUPPORTED,
                  "kfstate: rc=1 ENOSYS -> SUPPORTED (rc wins)");
    /* ENOSYS with negative rc => UNSUPPORTED */
    ASSERT_INT_EQ(kernel_feature_state_from_syscall(-1, ENOSYS),
                  KERNEL_FEATURE_UNSUPPORTED,
                  "kfstate: rc=-1 ENOSYS -> UNSUPPORTED");
    /* non-ENOSYS error with negative rc => SUPPORTED (kernel has it, call just failed) */
    ASSERT_INT_EQ(kernel_feature_state_from_syscall(-1, EINVAL),
                  KERNEL_FEATURE_SUPPORTED,
                  "kfstate: rc=-1 EINVAL -> SUPPORTED");

    /* kernel_set_feature_state: out-of-bounds feature is ignored */
    kernel_set_feature_state(KERNEL_FEATURE_MAX, KERNEL_FEATURE_SUPPORTED);
    kernel_set_feature_state(-1, KERNEL_FEATURE_SUPPORTED);

    /* kernel_set_feature_state: valid id is stored and readable */
    kernel_set_feature_state(0, KERNEL_FEATURE_UNSUPPORTED);
    ASSERT_INT_EQ((int)g_kernel_feature_state[0],
                  KERNEL_FEATURE_UNSUPPORTED,
                  "kfstate: set stores value at index 0");
    kernel_set_feature_state(0, KERNEL_FEATURE_UNKNOWN);
}

static void test_misc_helpers(void)
{
    /* safe_str: NULL input becomes "(null)" */
    ASSERT_INT_EQ(strcmp(safe_str(NULL), "(null)"), 0,
                  "safe_str: NULL -> (null)");
    /* safe_str: non-NULL returned as-is */
    const char* s = "hello";
    ASSERT(safe_str(s) == s, "safe_str: non-NULL returned unchanged");

    /* argv_has_debug_flag */
    char* argv1[] = { "prog", "--debug", "arg" };
    ASSERT_INT_EQ(argv_has_debug_flag(3, argv1), 1,
                  "argv_has_debug_flag: finds --debug");
    char* argv2[] = { "prog", "--other", "arg" };
    ASSERT_INT_EQ(argv_has_debug_flag(3, argv2), 0,
                  "argv_has_debug_flag: no --debug returns 0");
    char* argv3[] = { "prog" };
    ASSERT_INT_EQ(argv_has_debug_flag(1, argv3), 0,
                  "argv_has_debug_flag: only argv[0] returns 0");

    /* opts_net_mode */
    struct container_opts opts;
    memset(&opts, 0, sizeof(opts));
    ASSERT_INT_EQ(strcmp(opts_net_mode(&opts), "host"), 0,
                  "opts_net_mode: default is host");
    opts.net = "slirp4netns";
    ASSERT_INT_EQ(strcmp(opts_net_mode(&opts), "slirp4netns"), 0,
                  "opts_net_mode: custom net string returned");
    opts.net_join_pid = 42;
    ASSERT_INT_EQ(strcmp(opts_net_mode(&opts), "container"), 0,
                  "opts_net_mode: net_join_pid > 0 returns container");

    /* debug_log: exercise with g_debug enabled (prints to stderr, not checked) */
    int saved = g_debug;
    g_debug = 1;
    debug_log("test.event", "val=%d", 7);
    debug_log("test.empty", "");
    debug_log("test.null", NULL);
    g_debug = saved;
}

/* ── test_openat_beneath ──────────────────────────────────────────────────── */

static void test_openat_beneath(void)
{
    char base[] = "/tmp/oci2bin-ob-XXXXXX";
    ASSERT(mkdtemp(base) != NULL, "openat_beneath: mkdtemp succeeds");

    /* create subdir and file inside base */
    char subdir[PATH_MAX];
    snprintf(subdir, sizeof(subdir), "%s/sub", base);
    ASSERT_INT_EQ(mkdir(subdir, 0755), 0, "openat_beneath: mkdir sub");

    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s/sub/file.txt", base);
    int wfd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    ASSERT(wfd >= 0, "openat_beneath: create test file");
    if (wfd >= 0)
    {
        write_all_fd(wfd, "test", 4);
        close(wfd);
    }

    int root_fd = open(base, O_RDONLY | O_DIRECTORY);
    ASSERT(root_fd >= 0, "openat_beneath: open base dir");
    if (root_fd < 0)
        goto cleanup_ob;

    /* open nested file */
    int fd = openat_beneath(root_fd, "sub/file.txt", O_RDONLY, 0);
    ASSERT(fd >= 0, "openat_beneath: opens nested file");
    if (fd >= 0) close(fd);

    /* open file in root */
    int wfd2 = openat_beneath(root_fd, "top.txt",
                              O_WRONLY | O_CREAT | O_TRUNC, 0644);
    ASSERT(wfd2 >= 0, "openat_beneath: creates top-level file");
    if (wfd2 >= 0) close(wfd2);

    /* missing file returns -1 */
    fd = openat_beneath(root_fd, "no-such-file", O_RDONLY, 0);
    ASSERT_INT_EQ(fd, -1, "openat_beneath: missing file returns -1");

    /* unlinkat_beneath: remove nested file */
    ASSERT_INT_EQ(unlinkat_beneath(root_fd, "sub/file.txt", 0), 0,
                  "unlinkat_beneath: removes nested file");

    /* verify it's gone */
    fd = openat_beneath(root_fd, "sub/file.txt", O_RDONLY, 0);
    ASSERT_INT_EQ(fd, -1, "unlinkat_beneath: file is gone after removal");

    /* unlinkat_beneath on top-level file */
    ASSERT_INT_EQ(unlinkat_beneath(root_fd, "top.txt", 0), 0,
                  "unlinkat_beneath: removes top-level file");

    close(root_fd);

cleanup_ob:
    /* cleanup */
    rmdir(subdir);
    rmdir(base);
}

static void test_mcp_helpers(void)
{
    /* mcp_name_valid: accepts alnum + allowed chars */
    ASSERT_INT_EQ(mcp_name_valid("myapp"), 1,
                  "mcp_helpers: valid name accepted");
    ASSERT_INT_EQ(mcp_name_valid("my-app_1.2"), 1,
                  "mcp_helpers: name with dash/underscore/dot accepted");
    ASSERT_INT_EQ(mcp_name_valid(""), 0,
                  "mcp_helpers: empty name rejected");
    ASSERT_INT_EQ(mcp_name_valid(NULL), 0,
                  "mcp_helpers: NULL name rejected");
    ASSERT_INT_EQ(mcp_name_valid("bad/name"), 0,
                  "mcp_helpers: slash in name rejected");
    ASSERT_INT_EQ(mcp_name_valid("bad name"), 0,
                  "mcp_helpers: space in name rejected");

    /* mcp container tracking */
    g_mcp_n_ctrs = 0;
    memset(g_mcp_ctrs, 0, sizeof(g_mcp_ctrs));
    ASSERT_INT_EQ(mcp_find_ctr("missing"), -1,
                  "mcp_helpers: find_ctr returns -1 for unknown name");

    /* add a fake container */
    strncpy(g_mcp_ctrs[0].name, "test-ctr", MCP_NAME_MAX - 1);
    g_mcp_ctrs[0].pid = 99999; /* fake PID */
    g_mcp_n_ctrs = 1;
    ASSERT_INT_EQ(mcp_find_ctr("test-ctr"), 0,
                  "mcp_helpers: find_ctr finds tracked container");
    ASSERT_INT_EQ(mcp_find_ctr("other"), -1,
                  "mcp_helpers: find_ctr misses different name");

    /* reset */
    g_mcp_n_ctrs = 0;
}

static void test_tar_entry_name_unsafe(void)
{
    ASSERT_INT_EQ(tar_entry_name_unsafe(NULL),         1,
                  "tar_entry_name_unsafe: NULL is unsafe");
    ASSERT_INT_EQ(tar_entry_name_unsafe(""),           1,
                  "tar_entry_name_unsafe: empty is unsafe");
    ASSERT_INT_EQ(tar_entry_name_unsafe("/etc/passwd"), 1,
                  "tar_entry_name_unsafe: absolute path");
    ASSERT_INT_EQ(tar_entry_name_unsafe("../etc"),     1,
                  "tar_entry_name_unsafe: leading ..");
    ASSERT_INT_EQ(tar_entry_name_unsafe("a/../b"),     1,
                  "tar_entry_name_unsafe: embedded ..");
    ASSERT_INT_EQ(tar_entry_name_unsafe("a/b/.."),     1,
                  "tar_entry_name_unsafe: trailing ..");
    ASSERT_INT_EQ(tar_entry_name_unsafe("a/b/c"),      0,
                  "tar_entry_name_unsafe: clean relative");
    ASSERT_INT_EQ(tar_entry_name_unsafe("a/..hidden"), 0,
                  "tar_entry_name_unsafe: dotdot prefix in name not segment");
    ASSERT_INT_EQ(tar_entry_name_unsafe("usr/bin/sh"), 0,
                  "tar_entry_name_unsafe: deep clean path");
}

/*
 * test_safe_merge_layer_blocks_escape: build a staging directory whose
 * contents would, if merged naively, redirect a write outside the
 * rootfs via a symlink. Verify safe_merge_layer keeps writes inside.
 */
static void test_safe_merge_layer_blocks_escape(void)
{
    char tmpl[] = "/tmp/oci2bin-merge-test-XXXXXX";
    char* tdir = mkdtemp(tmpl);
    ASSERT_NOT_NULL(tdir, "merge test: mkdtemp");
    if (!tdir)
    {
        return;
    }

    char rootfs[256], stage[256], victim[256];
    snprintf(rootfs, sizeof(rootfs), "%s/rootfs", tdir);
    snprintf(stage,  sizeof(stage),  "%s/stage",  tdir);
    snprintf(victim, sizeof(victim), "%s/victim", tdir);

    mkdir(rootfs, 0755);
    mkdir(stage,  0755);
    mkdir(victim, 0755);

    /* Stage layer 1: an absolute symlink pointing outside rootfs */
    char layer1_link[256];
    snprintf(layer1_link, sizeof(layer1_link), "%s/escape", stage);
    int sl_rc = symlink(victim, layer1_link);
    ASSERT_INT_EQ(sl_rc, 0, "merge test: stage symlink created");

    int rfd = open(rootfs, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    ASSERT(rfd >= 0, "merge test: rootfs fd opened");
    int rc = safe_merge_layer(rfd, stage);
    ASSERT_INT_EQ(rc, 0, "merge test: layer 1 (symlink) merge succeeds");

    /* The rootfs should now have the symlink — but as a symlink, not
     * as a path that resolves outside. Verify it's a symlink. */
    char rootfs_escape[256];
    snprintf(rootfs_escape, sizeof(rootfs_escape), "%s/escape", rootfs);
    struct stat st;
    int lst = lstat(rootfs_escape, &st);
    ASSERT_INT_EQ(lst, 0, "merge test: rootfs/escape exists");
    ASSERT(S_ISLNK(st.st_mode),
           "merge test: rootfs/escape is a symlink");

    /* Stage layer 2: a regular file at "escape/poison". If the merge
     * naively followed the rootfs/escape symlink it would write to
     * <victim>/poison. With RESOLVE_IN_ROOT, the symlink target
     * "<victim>" is resolved inside rootfs (rootfs/<victim>) which
     * doesn't exist, so the openat2 fails with ENOENT and the file
     * is NOT created in the victim dir. */
    char stage2[256];
    snprintf(stage2, sizeof(stage2), "%s/stage2", tdir);
    mkdir(stage2, 0755);
    char layer2_dir[256], layer2_file[256];
    snprintf(layer2_dir,  sizeof(layer2_dir),  "%s/escape", stage2);
    snprintf(layer2_file, sizeof(layer2_file), "%s/escape/poison", stage2);
    mkdir(layer2_dir, 0755);
    int pfd = creat(layer2_file, 0644);
    ASSERT(pfd >= 0, "merge test: layer2 poison created in stage");
    if (pfd >= 0)
    {
        if (write(pfd, "PWNED", 5) != 5) { /* ignore */ }
        close(pfd);
    }

    /* Merge layer 2 — the file open in rootfs will fail because
     * "escape" resolves via RESOLVE_IN_ROOT to a non-existent
     * <rootfs>/<victim_path>, blocking the escape. */
    safe_merge_layer(rfd, stage2);

    char victim_poison[256];
    snprintf(victim_poison, sizeof(victim_poison), "%s/poison", victim);
    struct stat vst;
    int vrc = lstat(victim_poison, &vst);
    ASSERT(vrc < 0,
           "merge test: poison did NOT escape into victim/");

    close(rfd);

    /* Best-effort cleanup */
    unlink(layer1_link);
    unlink(layer2_file);
    rmdir(layer2_dir);
    rmdir(stage2);
    unlink(rootfs_escape);
    rmdir(rootfs);
    rmdir(stage);
    rmdir(victim);
    rmdir(tdir);
}

static void test_is_resolver_token_safe(void)
{
    ASSERT_INT_EQ(is_resolver_token_safe(NULL, 100),  0,
                  "is_resolver_token_safe: NULL is unsafe");
    ASSERT_INT_EQ(is_resolver_token_safe("",   100),  0,
                  "is_resolver_token_safe: empty is unsafe");
    ASSERT_INT_EQ(is_resolver_token_safe("foo", 100), 1,
                  "is_resolver_token_safe: plain ascii ok");
    ASSERT_INT_EQ(is_resolver_token_safe("foo:1.2.3.4", 100), 1,
                  "is_resolver_token_safe: host:ip ok");
    ASSERT_INT_EQ(is_resolver_token_safe("foo\nbar", 100), 0,
                  "is_resolver_token_safe: newline rejected");
    ASSERT_INT_EQ(is_resolver_token_safe("foo\rbar", 100), 0,
                  "is_resolver_token_safe: CR rejected");
    ASSERT_INT_EQ(is_resolver_token_safe("foo\tbar", 100), 0,
                  "is_resolver_token_safe: tab rejected");
    ASSERT_INT_EQ(is_resolver_token_safe("foo\xff", 100), 0,
                  "is_resolver_token_safe: high byte rejected");
    ASSERT_INT_EQ(is_resolver_token_safe("12345", 4), 0,
                  "is_resolver_token_safe: over max_len rejected");
    ASSERT_INT_EQ(is_resolver_token_safe("1234", 4), 1,
                  "is_resolver_token_safe: at max_len accepted");
    ASSERT_INT_EQ(is_resolver_token_safe("123",  4), 1,
                  "is_resolver_token_safe: under max_len ok");
}

static void test_parse_opts_resolver_injection(void)
{
    struct container_opts opts;

    /* --add-host with newline injection */
    {
        char* argv[] = {"prog", "--add-host", "evil:1.2.3.4\nnameserver 6.6.6.6", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --add-host rejects newline");
    }
    /* --add-host with normal value */
    {
        char* argv[] = {"prog", "--add-host", "host.example:127.0.0.1", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0,
                      "parse_opts: --add-host accepts plain value");
        ASSERT_INT_EQ(opts.n_add_hosts, 1,
                      "parse_opts: --add-host stored once");
    }
    /* --dns with newline */
    {
        char* argv[] = {"prog", "--dns", "8.8.8.8\nfoo", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --dns rejects newline");
    }
    /* --dns-search with control byte */
    {
        char* argv[] = {"prog", "--dns-search", "example\x01com", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --dns-search rejects control byte");
    }
    /* --dns-search with normal value */
    {
        char* argv[] = {"prog", "--dns-search", "example.com", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0,
                      "parse_opts: --dns-search accepts plain value");
    }
}

static void test_parse_opts_strict(void)
{
    struct container_opts opts;
    {
        char* argv[] = {"prog", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(1, argv, &opts);
        ASSERT_INT_EQ(r, 0,
                      "parse_opts: no --strict default 0");
        ASSERT_INT_EQ(opts.strict, 0,
                      "parse_opts: opts.strict defaults to 0");
    }
    {
        char* argv[] = {"prog", "--strict", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --strict returns 0");
        ASSERT_INT_EQ(opts.strict, 1,
                      "parse_opts: --strict sets opts.strict");
    }
}

static void test_parse_opts_profile(void)
{
    struct container_opts opts;

    /* dev: no-op marker */
    {
        char* argv[] = {"prog", "--profile", "dev", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --profile dev returns 0");
        ASSERT_INT_EQ(opts.read_only, 0,
                      "parse_opts: dev keeps read_only off");
        ASSERT_INT_EQ(opts.cap_drop_all, 0,
                      "parse_opts: dev keeps caps");
        ASSERT_INT_EQ(opts.strict, 0,
                      "parse_opts: dev does not enable strict");
    }
    /* prod: net=none, read-only, drop+baseline caps */
    {
        char* argv[] = {"prog", "--profile", "prod", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0, "parse_opts: --profile prod returns 0");
        ASSERT_NOT_NULL(opts.net,
                        "parse_opts: prod sets opts.net");
        if (opts.net)
        {
            ASSERT_STR_EQ(opts.net, "none",
                          "parse_opts: prod default net is none");
        }
        ASSERT_INT_EQ(opts.read_only, 1,
                      "parse_opts: prod sets read_only");
        ASSERT_INT_EQ(opts.cap_drop_all, 1,
                      "parse_opts: prod drops all caps");
        ASSERT(opts.cap_add_mask & (1ULL << 0),
               "parse_opts: prod adds CAP_CHOWN");
        ASSERT(opts.cap_add_mask & (1ULL << 7),
               "parse_opts: prod adds CAP_SETUID");
        ASSERT_INT_EQ(opts.strict, 0,
                      "parse_opts: prod does not enable strict");
    }
    /* locked-down: prod + landlock + strict + cgroup limits */
    {
        char* argv[] = {"prog", "--profile", "locked-down", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, 0,
                      "parse_opts: --profile locked-down returns 0");
        ASSERT_INT_EQ(opts.read_only, 1,
                      "parse_opts: locked-down sets read_only");
        ASSERT_INT_EQ(opts.landlock_mode, LANDLOCK_MODE_ON,
                      "parse_opts: locked-down forces landlock on");
        ASSERT_INT_EQ(opts.strict, 1,
                      "parse_opts: locked-down enables strict");
        ASSERT(opts.cg_pids > 0,
               "parse_opts: locked-down sets pids limit");
        ASSERT(opts.cg_memory_bytes > 0,
               "parse_opts: locked-down sets memory limit");
    }
    /* later --net host overrides prod profile's --net none */
    {
        char* argv[] = {"prog", "--profile", "prod", "--net", "host",
                        NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(5, argv, &opts);
        ASSERT_INT_EQ(r, 0,
                      "parse_opts: prod + --net host returns 0");
        if (opts.net)
        {
            ASSERT_STR_EQ(opts.net, "host",
                          "parse_opts: --net host overrides prod default");
        }
    }
    /* unknown profile name */
    {
        char* argv[] = {"prog", "--profile", "frogurt", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(3, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --profile rejects unknown name");
    }
    /* --profile with no arg */
    {
        char* argv[] = {"prog", "--profile", NULL};
        memset(&opts, 0, sizeof(opts));
        int r = parse_opts(2, argv, &opts);
        ASSERT_INT_EQ(r, -1,
                      "parse_opts: --profile rejects missing name");
    }
}

int main(void)
{
    /* TAP plan printed after we know the count — use streaming output instead */
    printf("TAP version 13\n");

    test_json_get_string();
    test_json_get_string_edge();
    test_json_get_array();
    test_json_parse_string_array();
    test_json_escape_string();
    test_kernel_feature_runtime_detection();
    test_audit_logging_helpers();
    test_metrics_helpers();
    test_userns_subid_helpers();
    test_path_has_dotdot_component();
    test_path_has_dotdot_extra();
    test_path_is_absolute_and_clean();
    test_path_join_suffix();
    test_parse_id_value();
    test_parse_opts();
    test_parse_opts_path_validation();
    test_parse_opts_name();
    test_parse_opts_limits();
    test_build_exec_args();
    test_build_exec_args_extended();
    test_cap_name_to_num();
    test_parse_opts_resource_limits();
    test_parse_opts_user();
    test_parse_opts_caps();
    test_parse_opts_ulimit();
    test_parse_opts_misc_flags();
    test_mcp_helpers();
    test_parent_dir_path();
    test_read_write_all_fd();
    test_read_write_file();
    test_copy_n_bytes();
    test_lookup_passwd_group();
    test_openat_beneath();
    test_misc_helpers();
    test_write_read_file_beneath();
    test_kernel_feature_state();
    test_tar_entry_name_unsafe();
    test_safe_merge_layer_blocks_escape();
    test_is_resolver_token_safe();
    test_parse_opts_resolver_injection();
    test_parse_opts_strict();
    test_parse_opts_profile();

    printf("1..%d\n", tap_test_num);

    if (tap_fail_count > 0)
    {
        fprintf(stderr, "# %d test(s) FAILED\n", tap_fail_count);
        return 1;
    }
    return 0;
}
