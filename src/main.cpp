#include <sys/ioctl.h>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <error.h>
#include <errno.h>
#include <cstdio>
#include <sys/resource.h>
#include "format.hpp"
#include "argmap.hpp"
#include <string>

#define INIT_FGET_BUF(x) x[strcspn(x, "\n")] = 0;

using function_t = size_t(*)(const ArgMap* argv, size_t argc);

namespace terminal {
    size_t cls(const ArgMap* argv, size_t argc) { system("clear"); return 0; }
    size_t exit(const ArgMap* argv, size_t argc) { ::exit(0); __builtin_unreachable(); }
}

constexpr struct {const char* name; function_t function;} functions[] = {
    {"drives", &fs::get_drives},
    {"volumes", &fs::get_volumes},
    {"clear",  &terminal::cls},
    {"exit",  &terminal::exit},
    {NULL, NULL}
};

void raise_stack_limit(size_t bytes) {
    struct rlimit rl;

    rl.rlim_cur = bytes;
    rl.rlim_max = bytes;

    if (setrlimit(RLIMIT_STACK, &rl) != 0) {
        perror("setrlimit(RLIMIT_STACK)");
    }
}

size_t get_args_size(const char* cmd) {
    size_t size = 1;

    for (const char* i = cmd; *i != 0; i++) {
        if (*i == ' ' || *i == '\n' || *i == '\0') {
            size += sizeof(ArgMap);
        }
    } 

    if (size == 0) size = 1;

    return size;
}

size_t parse_args(const char* cmd, ArgMap* out_buffer) {
    char buffer[256]{0};
    uint16_t buffer_index = 0;
    unsigned char buffer_type = 0; // 0=key; 1=value

    ArgMap tmp;
    memset(&tmp, 0, sizeof(tmp));

    size_t out_buffer_index = 0;

    for (const char* i = cmd; ; i++) {
        if (buffer_index >= 256) {
            error(1, ENOBUFS, "Overfilled buffer (singular token greater or equal to 256 bytes in size)\n");
        }
        if (*i == ' ' || *i == '\n' || *i == '\0') {
            if (buffer_index > 0 || buffer_type == 1) {
                if (buffer_type == 1) {
                    memset(tmp.value, 0, 256);
                    memcpy(tmp.value, buffer, buffer_index);
                } else {
                    memset(tmp.key, 0, 256);
                    memcpy(tmp.key, buffer, buffer_index);
                }

                if (buffer_type == 0)
                    tmp.value_exists = 0;
                else
                    tmp.value_exists = 1;

                if (out_buffer != NULL)
                    *(out_buffer+out_buffer_index) = tmp;
                
                out_buffer_index++;
                buffer_index = 0;
                buffer_type = 0;
                
                memset(&tmp, 0, sizeof(tmp));
                memset(buffer, 0, 256);
            }

            if (*i == '\0') break;
        }
        else if (*i == '=' && buffer_type == 0) {
            if (buffer_index == 0) continue;
            memcpy(tmp.key, buffer, 256);
            buffer_index = 0;
            buffer_type = 1;
            memset(buffer, 0, 256);
        }
        else {
            buffer[buffer_index] = *i;
            buffer_index++;
        }
    }

    return out_buffer_index;
}

static bool key_equals(const ArgMap& arg, const char* literal) {
    size_t lit_len = strlen(literal);

    // literal must fit
    if (lit_len >= 256)
        return false;

    // bytes must match
    if (memcmp(arg.key, literal, lit_len) != 0)
        return false;

    // ensure no extra characters in key
    return arg.key[lit_len] == '\0';
}



int main() {
    raise_stack_limit(4 * 1024 * 1024); // 4 MB

    while (true) {
        //type:shell

        char input_buffer[4096*4];

        printf("disk-manage >\t");
        fgets(input_buffer, sizeof input_buffer, stdin);
        INIT_FGET_BUF(input_buffer);

        size_t arg_size = parse_args(input_buffer, NULL);
        ArgMap* arguments = NULL;
        if (arg_size > 256) {  // Bounds check to avoid large alloca() calls
            arguments = (ArgMap*)malloc(arg_size * sizeof(ArgMap));
        } else {
            arguments = (ArgMap*)alloca(arg_size * sizeof(ArgMap));
        }

        size_t args_argc = parse_args(input_buffer, arguments);

        printf("argc = %zu\n", args_argc);
        for (size_t i = 0; i < args_argc; ++i) {
            printf("arg[%zu] = '%s'\n", i, arguments[i].key);
        }

        // do something with the arguments now
        char* command = arguments[0].key;

        for (auto entry : functions) {
            if (entry.name == NULL || entry.function == NULL) break;

            if (key_equals(arguments[0], entry.name)) {
                entry.function(arguments, args_argc);
                goto goto_found;
            }
        }

        printf("Invalid function.\n");

        goto_found:
    }
}
