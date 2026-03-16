/*
 * fuzz_parse_opts.c — libFuzzer harness for parse_opts() and load_env_file().
 *
 * Strategy: treat the fuzz input as a sequence of NUL-terminated strings.
 * Split them on '\0' bytes to build an argv[] array.  The first "token" is
 * always a fake argv[0] (the binary name) so parse_opts starts at index 1.
 *
 * A second pass uses the same input as an env-file written to disk.
 *
 * Build:
 *   clang -fsanitize=fuzzer,address,undefined \
 *         -g -O1 -o build/fuzz_parse_opts tests/fuzz/fuzz_parse_opts.c
 *
 * Run:
 *   ./build/fuzz_parse_opts tests/fuzz/corpus/parse_opts -max_len=4096
 */

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

/* Maximum number of argv tokens we'll build from the fuzz input */
#define MAX_FUZZ_ARGC 64

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0)
        return 0;

    /* ── Part 1: parse_opts ─────────────────────────────────────────────── */

    /* Make a mutable copy — parse_opts mutates argv strings (e.g. -v) */
    char* buf = malloc(size + 1);
    if (!buf)
        return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    /* Split on NUL bytes to build argv */
    char* argv[MAX_FUZZ_ARGC + 1];
    int argc = 0;

    /* argv[0] = fake program name */
    argv[argc++] = "oci2bin";

    char* p = buf;
    char* end = buf + size;
    while (p < end && argc < MAX_FUZZ_ARGC) {
        /* skip runs of NUL */
        while (p < end && *p == '\0')
            p++;
        if (p >= end)
            break;
        argv[argc++] = p;
        /* advance to next NUL or end */
        while (p < end && *p != '\0')
            p++;
    }
    argv[argc] = NULL;

    struct container_opts opts;
    memset(&opts, 0, sizeof(opts));
    parse_opts(argc, argv, &opts);

    free(buf);

    /* ── Part 2: load_env_file ──────────────────────────────────────────── */

    char tmppath[] = "/tmp/fuzz_envfile_XXXXXX";
    int fd = mkstemp(tmppath);
    if (fd >= 0) {
        (void)write(fd, data, size);
        close(fd);

        struct container_opts opts2;
        memset(&opts2, 0, sizeof(opts2));
        load_env_file(tmppath, &opts2);

        /* load_env_file malloc's each accepted line; free them */
        for (int i = 0; i < opts2.n_env; i++)
            free(opts2.env_vars[i]);

        unlink(tmppath);
    }

    return 0;
}
