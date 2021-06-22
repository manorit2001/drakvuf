#include "linux_utils.h"
#include "linux_debug.h"
#include "linux_shellcode.h"

static event_response_t injector_int3_userspace_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info) {

    injector_t injector = info->trap->data;

    PRINT_DEBUG("INT3 Callback @ 0x%lx. CR3 0x%lx. vcpu %i. TID %u\n",
                info->regs->rip, info->regs->cr3, info->vcpu, info->proc_data.tid);

    if (!check_userspace_int3_trap(injector, info))
        return VMI_EVENT_RESPONSE_NONE;

    event_response_t event = VMI_EVENT_RESPONSE_NONE;
    event = handle_shellcode(drakvuf, info);

    print_stack(drakvuf, info);
    print_registers(info);

    drakvuf_remove_trap(drakvuf, info->trap, NULL);
    // drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);

    return event;

}

static event_response_t wait_for_target_process_cr3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info) {
    injector_t injector = info->trap->data;

    // right now we are in kernel space
    PRINT_DEBUG("CR3 changed to 0x%" PRIx64 ". PID: %u PPID: %u TID: %u\n",
                info->regs->cr3, info->proc_data.pid, info->proc_data.ppid, info->proc_data.tid);

    if (info->proc_data.pid != injector->target_pid && info->proc_data.tid != injector->target_tid)
        return 0;

    // rcx register should have the address for userspace rip
    // for x64 systems
    addr_t bp_addr = info->regs->rcx;

    // setup int3 trap
    injector->bp.type = BREAKPOINT;
    injector->bp.name = "entry";
    injector->bp.cb = injector_int3_userspace_cb;
    injector->bp.data = injector;
    injector->bp.breakpoint.lookup_type = LOOKUP_DTB;
    injector->bp.breakpoint.dtb = info->regs->cr3;
    injector->bp.breakpoint.addr_type = ADDR_VA;
    injector->bp.breakpoint.addr = bp_addr;
    injector->bp.ttl = UNLIMITED_TTL;
    injector->bp.ah_cb = NULL;

    if ( drakvuf_add_trap(injector->drakvuf, &injector->bp) ) {
        PRINT_DEBUG("Usermode Trap Addr: %lx\n", info->regs->rcx);

        // Unsubscribe from the CR3 trap
        drakvuf_remove_trap(drakvuf, info->trap, NULL);
        injector->cr3_trap = NULL;
    }
    else {
        fprintf(stderr, "Failed to trap trapframe return address\n");
        print_registers(info);
        print_stack(drakvuf, info);
    }

    return 0;
}

static bool is_interrupted(drakvuf_t drakvuf, void* data __attribute__((unused)))
{
    return drakvuf_is_interrupted(drakvuf);
}

static bool inject(drakvuf_t drakvuf, injector_t injector) {

    drakvuf_trap_t trap =
    {
        .type = REGISTER,
        .reg = CR3,
        .cb = wait_for_target_process_cr3_cb,
        .data = injector,
    };

    injector->cr3_trap = &trap;

    if (!drakvuf_add_trap(drakvuf, &trap))
        return false;

    if (!drakvuf_is_interrupted(drakvuf)) {
        const char * method = "Injection";
        PRINT_DEBUG("Starting %s loop\n", method);
        drakvuf_loop(drakvuf, is_interrupted, NULL);
        PRINT_DEBUG("Finished %s loop\n", method);
    }

    if (SIGDRAKVUFTIMEOUT == drakvuf_is_interrupted(drakvuf))
        injector->rc = INJECTOR_TIMEOUTED;

    // should be handled inside the callbacks
    // drakvuf_remove_trap(drakvuf, &trap, NULL);

    return true;
}

injector_status_t injector_start_app_on_linux(
    drakvuf_t drakvuf,
    vmi_pid_t pid,
    uint32_t tid,
    const char* file,
    injection_method_t method,
    output_format_t format,
    int args_count,
    const char* args[10]
) {
    injector_t injector = (injector_t)g_try_malloc0(sizeof(struct injector));
    injector->drakvuf = drakvuf;
    injector->target_pid = pid;
    injector->target_tid = tid;
    injector->shellcode_file = file;
    injector->args_count = args_count;
    for ( int i = 0; i<args_count; i++ )
        injector->args[i] = args[i];
    injector->method = method;
    injector->format = format;

    inject(drakvuf, injector);
    injector->rc = INJECT_RESULT_SUCCESS;

    injector_status_t rc = injector->rc;
    free_injector(injector);
    return rc;
}
