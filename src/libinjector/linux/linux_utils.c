#include "linux_utils.h"
#include "linux_debug.h"
#include <sys/mman.h>
#include <fcntl.h>

bool setup_exit_syscall(injector_t injector, x86_registers_t* regs, uint32_t no) {
    // exit (exit_no)
    struct argument args[10] = { {0} };
    init_int_argument(&args[0], no);

    bool success = setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args));
    if(success)
        injector->syscall = sys_exit;
    else
        fprintf(stderr, "Could not setup stack for sys_exit");

    return success;
}

bool check_userspace_int3_trap(injector_t injector, drakvuf_trap_info_t* info) {

    // check CPL
    unsigned long int CPL = (info->regs->cs_sel & 3);
    PRINT_DEBUG("CPL 0x%lx\n", CPL);

    if ( CPL != 0)
    {
        PRINT_DEBUG("Reached userspace, yayy!\n");
    }
    else
    {
        PRINT_DEBUG("INT3 received but CPL is not 0x3\n");
        print_stack(injector->drakvuf, info);
        print_registers(info);
        return false;
    }

    if ( info->proc_data.pid != injector->target_pid )
    {
        PRINT_DEBUG("INT3 received but '%s' PID (%u) doesn't match target process (%u)\n",
                    info->proc_data.name, info->proc_data.pid, injector->target_pid);
        return false;
    }

    if (info->regs->rip != info->trap->breakpoint.addr) {
        PRINT_DEBUG("INT3 received but BP_ADDR (%lx) doesn't match RIP (%lx)",
                    info->trap->breakpoint.addr, info->regs->rip);
        return false;
    }

    if (injector->target_tid && (uint32_t)info->proc_data.tid != injector->target_tid)
    {
        PRINT_DEBUG("INT3 received but '%s' TID (%u) doesn't match target process (%u)\n",
                    info->proc_data.name, info->proc_data.tid, injector->target_tid);
        return false;
    }

    else if (!injector->target_tid)
    {
        PRINT_DEBUG("Target TID not provided by the user, pinning TID to %u\n",
                    info->proc_data.tid);
        injector->target_tid = info->proc_data.tid;
    }
    return true;

}

void free_injector(injector_t injector)
{
    if (!injector) return;

    PRINT_DEBUG("Injector freed\n");

    if (injector->cr3_trap) {
        drakvuf_remove_trap(injector->drakvuf, injector->cr3_trap, NULL);
        injector->cr3_trap = NULL;
    }

    if (injector)
        g_free((void*)injector);


    injector = NULL;
}
