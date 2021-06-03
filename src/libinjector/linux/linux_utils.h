#include <errno.h>
#include <glib.h>
#include <inttypes.h>
#include <json-c/json.h>
#include <libinjector/libinjector.h>
#include <libvmi/libvmi.h>
#include <libvmi/x86.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "libdrakvuf/libdrakvuf.h"
#include "../private.h"

typedef enum
{
    INJECT_RESULT_SUCCESS,
    INJECT_RESULT_TIMEOUT,
    INJECT_RESULT_CRASH,
    INJECT_RESULT_PREMATURE,
    INJECT_RESULT_ERROR_CODE,
} inject_result_t;

struct injector {
    // Inputs:
    const char* target_file;
    const char* target_file_name;
    vmi_pid_t target_pid;
    addr_t target_base;
    uint32_t target_tid;

    // Internal:
    drakvuf_t drakvuf;
    bool hijacked, detected;
    injection_method_t method;
    addr_t exec_func, libc_addr;
    reg_t target_rsp, target_rip;

    // for exec()
    const char* args[10];
    int args_count;

    // For shellcode execution
    addr_t payload, payload_addr, memset;
    size_t payload_size;
    uint32_t status;

    x86_registers_t saved_regs;

    drakvuf_trap_t bp;
    drakvuf_trap_t* cr3_trap;
    drakvuf_trap_t* int3_trap;
    GSList* memtraps;

    // Results:
    injector_status_t rc;
    inject_result_t result;
    struct {
        bool valid;
        uint32_t code;
        const char* string;
    } error_code;

    uint32_t pid, tid;
};

void free_memtraps(injector_t injector);
void free_injector(injector_t injector);
