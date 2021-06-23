#ifndef LINUX_UTILS_H
#define LINUX_UTILS_H

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
#include <assert.h>
#include <libdrakvuf/libdrakvuf.h>
#include <libinjector/private.h>

typedef enum
{
    INJECT_RESULT_SUCCESS,
    INJECT_RESULT_TIMEOUT,
    INJECT_RESULT_CRASH,
    INJECT_RESULT_ERROR_CODE,
} inject_result_t;

typedef enum {
    sys_exit = 60,
} syscall_t;

struct injector
{
    // Inputs:
    vmi_pid_t target_pid;
    uint32_t target_tid;
    const char* shellcode_file;
    int args_count;
    const char** args;
    output_format_t format;

    // Internal:
    drakvuf_t drakvuf;
    injection_method_t method;
    syscall_t syscall;

    drakvuf_trap_t bp;

    // Traps
    drakvuf_trap_t *cr3_trap;

    // Results:
    injector_status_t rc;
    inject_result_t result;
    struct
    {
        bool valid;
        uint32_t code;
        const char* string;
    } error_code;
};

void free_injector(injector_t injector);

#endif
