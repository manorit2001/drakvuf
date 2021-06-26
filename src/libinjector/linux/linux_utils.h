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
    INJECT_RESULT_METHOD_UNSUPPORTED,
} inject_result_t;

typedef enum {
    STEP1,
    STEP2,
    STEP3,
    STEP4,
    STEP5,
    STEP6,
    STEP7,
    STEP8,
    STEP9,
} injector_step_t;

struct injector
{
    // Inputs:
    vmi_pid_t target_pid;
    uint32_t target_tid;
    const char* target_file;
    int args_count;
    const char** args;
    output_format_t format;

    // Internal:
    drakvuf_t drakvuf;
    injection_method_t method;
    injector_step_t step;

    // shellcode
    struct {
        void *data;
        int len;
    } shellcode;

    // for restoring stack
    x86_registers_t saved_regs;
    struct
    {
        addr_t loc;
        void *data;
        int len;
    } memdata;

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
bool save_vm_state(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t size);
bool restore_vm_state(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
bool save_rip_for_ret(drakvuf_t drakvuf, x86_registers_t* regs);
bool load_file_to_injector_shellcode(injector_t injector, const char* file);
bool check_userspace_int3_trap(injector_t injector, drakvuf_trap_info_t* info);

#endif
