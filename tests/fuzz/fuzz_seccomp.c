/*
 * fuzz_seccomp.c — libFuzzer harness for apply_seccomp_profile().
 *
 * apply_seccomp_profile reads a JSON file from disk, so we write the fuzz
 * input to a temp file and pass the path.  The actual BPF load is guarded
 * behind seccomp(2), which is not available inside the fuzzer sandbox;
 * we short-circuit it by catching the ENOSYS/EPERM from the syscall and
 * returning before the kernel call.  The interesting parsing and buffer
 * operations happen before that point.
 *
 * Build:
 *   clang -fsanitize=fuzzer,address,undefined \
 *         -g -O1 -o build/fuzz_seccomp tests/fuzz/fuzz_seccomp.c
 *
 * Run:
 *   ./build/fuzz_seccomp tests/fuzz/corpus/seccomp -max_len=65536
 */

#define static
#define main loader_main

/*
 * Intercept the actual BPF load so the fuzzer does not need
 * CAP_SYS_ADMIN / a real kernel seccomp path.  We replace
 * prctl(PR_SET_SECCOMP, ...) with a no-op stub.
 */
#define prctl fuzz_prctl_stub
static int fuzz_prctl_stub(int option, ...)
{
    (void)option;
    return 0;
}

#include "../../src/loader.c"

#undef main
#undef static
#undef prctl

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Reject giant inputs to keep the fuzzer fast */
    if (size > 256 * 1024)
        return 0;

    /* Write input to a temp file */
    char tmppath[] = "/tmp/fuzz_seccomp_XXXXXX";
    int fd = mkstemp(tmppath);
    if (fd < 0)
        return 0;

    ssize_t written = write(fd, data, size);
    close(fd);
    if (written != (ssize_t)size) {
        unlink(tmppath);
        return 0;
    }

    /* Exercise the parser — ignore return value, crash is the signal */
    apply_seccomp_profile(tmppath);

    unlink(tmppath);
    return 0;
}
