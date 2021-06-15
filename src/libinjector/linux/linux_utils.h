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

#include "libdrakvuf/libdrakvuf.h"
#include "libinjector/private.h"

typedef enum
{
    INJECT_RESULT_SUCCESS,
    INJECT_RESULT_TIMEOUT,
    INJECT_RESULT_CRASH,
    INJECT_RESULT_PREMATURE,
    INJECT_RESULT_ERROR_CODE,
} inject_result_t;

typedef enum {
    sys_read = 0,
    sys_write = 1,
    sys_open = 2,
    sys_close = 3,
    sys_stat = 4,
    sys_mmap = 9,
    sys_mprotect = 10,
    sys_munmap = 11,
    sys_exit = 60,
    sys_kill = 62,
} syscall_t;

struct injector
{
    // Inputs:
    vmi_pid_t target_pid;
    uint32_t target_tid;
    const char* shellcode_file;
    const char* target_file;
    int args_count;
    const char* args[10];
    output_format_t format;

    // Internal:
    drakvuf_t drakvuf;
    injection_method_t method;
    syscall_t syscall;

    // read_file, write_file
    addr_t file_descriptor;

    // mmap
    addr_t virtual_memory_addr;

    // for restoring stack
    registers_t saved_regs;
    struct
    {
        addr_t loc;
        void *data;
    } memdata;

    drakvuf_trap_t bp;
    GSList* memtraps;

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


void free_memtraps(injector_t injector);
void free_injector(injector_t injector);
bool setup_mmap_syscall(injector_t injector, x86_registers_t* regs, size_t size);
bool setup_open_file_syscall(injector_t injector, x86_registers_t* regs);
bool setup_read_file_syscall(injector_t injector, x86_registers_t* regs, size_t size);
bool setup_exit_syscall(injector_t injector, x86_registers_t* regs, uint32_t no);

#endif
