/*
 * fuzz_json.c — libFuzzer harness for loader.c JSON helpers.
 *
 * Targets:
 *   json_skip_to_value, json_get_string, json_get_array,
 *   json_parse_string_array, json_parse_names_array
 *
 * Build:
 *   clang -fsanitize=fuzzer,address,undefined \
 *         -g -O1 -o build/fuzz_json tests/fuzz/fuzz_json.c
 *
 * Run:
 *   ./build/fuzz_json tests/fuzz/corpus/json -max_len=65536
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

/*
 * We exercise all JSON helpers with the fuzz input as the JSON buffer.
 * A fixed set of key names covers the keys used in real OCI manifests
 * and seccomp profiles.
 */
static const char* const FUZZ_KEYS[] = {
    "Config",
    "Layers",
    "Entrypoint",
    "Cmd",
    "Env",
    "WorkingDir",
    "User",
    "defaultAction",
    "action",
    "names",
    "syscalls",
    "",                 /* empty key */
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", /* 256-byte key — must not crash */
};
#define N_FUZZ_KEYS (int)(sizeof(FUZZ_KEYS) / sizeof(FUZZ_KEYS[0]))

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Make a NUL-terminated copy so helpers can use strstr/strchr safely */
    char* json = malloc(size + 1);
    if (!json)
        return 0;
    memcpy(json, data, size);
    json[size] = '\0';

    for (int k = 0; k < N_FUZZ_KEYS; k++) {
        const char* key = FUZZ_KEYS[k];

        /* json_skip_to_value — returns pointer into json, no alloc */
        (void)json_skip_to_value(json, key);

        /* json_get_string — malloc'd result; free it */
        char* s = json_get_string(json, key);
        free(s);

        /* json_get_array — malloc'd result */
        char* arr = json_get_array(json, key);
        if (arr) {
            /* json_parse_string_array on the returned array */
            char* items[256];
            int n = json_parse_string_array(arr, items, 256);
            for (int i = 0; i < n; i++)
                free(items[i]);
            free(arr);
        }

        /* json_parse_names_array — malloc'd array of malloc'd strings */
        int n_names = 0;
        char** names = json_parse_names_array(json, key, &n_names);
        if (names) {
            for (int i = 0; i < n_names; i++)
                free(names[i]);
            free(names);
        }
    }

    free(json);
    return 0;
}
