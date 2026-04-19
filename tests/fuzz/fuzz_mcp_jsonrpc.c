/*
 * fuzz_mcp_jsonrpc.c — libFuzzer harness for the MCP JSON-RPC parser in loader.c.
 *
 * Feeds arbitrary bytes into the JSON helpers and MCP dispatch path,
 * exercising the full request-parsing surface: method extraction,
 * params/arguments parsing, tool name dispatch, and all per-tool
 * parameter validation.
 *
 * Build:
 *   clang -fsanitize=fuzzer,address,undefined \
 *         -g -O1 -o build/fuzz_mcp_jsonrpc tests/fuzz/fuzz_mcp_jsonrpc.c
 *
 * Run:
 *   ./build/fuzz_mcp_jsonrpc tests/fuzz/corpus/mcp -max_len=65536
 *
 * Corpus: tests/fuzz/corpus/mcp/
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
 * Redirect stdout/stderr to /dev/null so the fuzzer output is clean.
 * Called once before fuzzing begins.
 */
int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    (void)argc;
    (void)argv;
    int null_fd = open("/dev/null", O_WRONLY);
    if (null_fd >= 0)
    {
        dup2(null_fd, STDOUT_FILENO);
        dup2(null_fd, STDERR_FILENO);
        close(null_fd);
    }
    /* Point g_audit_fd at /dev/null too */
    g_audit_fd = open("/dev/null", O_WRONLY);
    return 0;
}

/*
 * Exercise the JSON-RPC parsing helpers on arbitrary input.
 *
 * We do NOT call mcp_serve_main() because that blocks on stdin.
 * Instead we replicate the parsing logic inline: extract method,
 * id, params.name, params.arguments — the same code path that
 * mcp_serve_main() executes per request.
 */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Reject absurdly large inputs early (same cap as MCP_LINE_MAX) */
    if (size > MCP_LINE_MAX)
    {
        return 0;
    }

    /* NUL-terminate a copy of the fuzz input */
    char* line = malloc(size + 1);
    if (!line)
    {
        return 0;
    }
    memcpy(line, data, size);
    line[size] = '\0';

    /* ── replicate mcp_serve_main() request parsing ── */

    /* 1. Extract id */
    char* id_s = json_get_string(line, "id");
    long  id   = id_s ? strtol(id_s, NULL, 10) : -1;
    free(id_s);

    /* 2. Extract method */
    char* method = json_get_string(line, "method");

    /* 3. Exercise per-tool argument extraction for every known tool */
    static const char* const TOOLS[] = {
        "run_container",
        "exec_in_container",
        "list_containers",
        "stop_container",
        "inspect_image",
        "get_logs",
    };

    /* Parse params object — may appear as a string or raw object */
    char* params = json_get_string(line, "params");

    /* Also try reading params as a raw object (common in real JSON-RPC) */
    const char* raw_params = json_skip_to_value(line, "params");
    char* params_obj = NULL;
    if (raw_params && *raw_params == '{')
    {
        int   depth = 0;
        const char* p = raw_params;
        while (*p)
        {
            if (*p == '{')
            {
                depth++;
            }
            else if (*p == '}')
            {
                if (--depth == 0)
                {
                    break;
                }
            }
            p++;
        }
        if (depth == 0)
        {
            size_t olen = (size_t)(p - raw_params + 1);
            params_obj  = malloc(olen + 1);
            if (params_obj)
            {
                memcpy(params_obj, raw_params, olen);
                params_obj[olen] = '\0';
            }
        }
    }

    /* Exercise argument extraction from both the params string and the full line */
    const char* ctx_list[3] = {line, params, params_obj};
    for (int c = 0; c < 3; c++)
    {
        const char* ctx = ctx_list[c];
        if (!ctx)
        {
            continue;
        }

        /* Extract fields used by all tools */
        char* name   = json_get_string(ctx, "name");
        char* image  = json_get_string(ctx, "image");
        char* net    = json_get_string(ctx, "net");
        char* lines_s = json_get_string(ctx, "lines");

        /* Validate name as mcp_name_valid does */
        if (name)
        {
            (void)mcp_name_valid(name);
        }

        /* Validate image path as the run_container tool does */
        if (image)
        {
            (void)path_is_absolute_and_clean(image);
            (void)path_has_dotdot_component(image);
        }

        /* Parse env and volumes arrays */
        char* env_arr = json_get_array(ctx, "env");
        char* vol_arr = json_get_array(ctx, "volumes");
        char* cmd_arr = json_get_array(ctx, "cmd");
        char* args_arr = json_get_array(ctx, "arguments");

        if (env_arr)
        {
            char* env_strs[MCP_ENV_MAX];
            int n = json_parse_string_array(env_arr, env_strs, MCP_ENV_MAX);
            for (int i = 0; i < n; i++)
            {
                free(env_strs[i]);
            }
            free(env_arr);
        }
        if (vol_arr)
        {
            char* vol_strs[MCP_VOL_MAX];
            int n = json_parse_string_array(vol_arr, vol_strs, MCP_VOL_MAX);
            for (int i = 0; i < n; i++)
            {
                free(vol_strs[i]);
            }
            free(vol_arr);
        }
        if (cmd_arr)
        {
            char* cmd_strs[MCP_CMD_MAX];
            int n = json_parse_string_array(cmd_arr, cmd_strs, MCP_CMD_MAX);
            for (int i = 0; i < n; i++)
            {
                free(cmd_strs[i]);
            }
            free(cmd_arr);
        }
        if (args_arr)
        {
            free(args_arr);
        }

        /* Exercise json_escape_string on extracted values */
        if (name)
        {
            char esc[MCP_NAME_MAX * 2];
            (void)json_escape_string(name, esc, sizeof(esc));
        }
        if (net)
        {
            char esc[64];
            (void)json_escape_string(net, esc, sizeof(esc));
        }

        /* lines: validate as mcp_tool_get_logs does */
        if (lines_s)
        {
            char* endp;
            long  v = strtol(lines_s, &endp, 10);
            (void)(v > 0 && v <= 10000 && *endp == '\0');
            free(lines_s);
        }

        free(name);
        free(image);
        free(net);
    }

    /* Exercise tool-name matching for each known tool */
    if (method)
    {
        for (size_t t = 0; t < sizeof(TOOLS) / sizeof(TOOLS[0]); t++)
        {
            (void)strcmp(method, TOOLS[t]);
        }
    }

    /* Exercise json_escape_string on the raw fuzz input (output capped) */
    {
        size_t escsz = size * 6 + 4;
        if (escsz < 65536)
        {
            char* esc = malloc(escsz);
            if (esc)
            {
                (void)json_escape_string(line, esc, escsz);
                free(esc);
            }
        }
    }

    free(method);
    free(params);
    free(params_obj);
    free(line);
    return 0;
}
