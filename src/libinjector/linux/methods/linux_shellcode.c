#include "linux_shellcode.h"
#include "linux_debug.h"
#include "linux_syscalls.h"

event_response_t handle_shellcode(drakvuf_t drakvuf, drakvuf_trap_info_t* info) {

    injector_t injector = (injector_t)info->trap->data;

    event_response_t event;

    switch(injector->step)
    {
    case STEP1: // saves the registries/memory and injects the shellcode
    {
        PRINT_DEBUG("Save Current state\n");
        save_vm_state(drakvuf, info, injector->shellcode.len);

        save_rip_for_ret(drakvuf, info->regs);

        // access rip location
        ACCESS_CONTEXT(ctx,
                       .translate_mechanism = VMI_TM_PROCESS_DTB,
                       .dtb = info->regs->cr3,
                       .addr = info->regs->rip
                      );

        size_t bytes_write = 0;
        // lock vmi
        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

        bool success = (VMI_SUCCESS == vmi_write(vmi, &ctx, injector->shellcode.len, injector->shellcode.data, &bytes_write));
        if (!success)
            fprintf(stderr, "Could not write the shellcode");
        else {
            PRINT_DEBUG("Shellcode write success\n");
            print_hex(injector->shellcode.data, injector->shellcode.len, bytes_write);
        }

        // release vmi
        drakvuf_release_vmi(drakvuf);

        // rsp is changing due to save_rip_for_ret
        event = VMI_EVENT_RESPONSE_SET_REGISTERS;
        break;
    }
    case STEP2: // restores the made changes
    {
        PRINT_DEBUG("Restoring the state\n");
        restore_vm_state(drakvuf, info);
        event = VMI_EVENT_RESPONSE_SET_REGISTERS;
        break;
    }
    case STEP3: // removes the trap and exits drakvuf_loop
    {
        // injection finished
        drakvuf_remove_trap(drakvuf, info->trap, NULL);
        drakvuf_interrupt(drakvuf, SIGINT);
        event = VMI_EVENT_RESPONSE_NONE;
        break;
    }
    default:
    {
        PRINT_DEBUG("Should not be here\n");
        assert(false);
    }
    }

    injector->step+=1;


    return event;
}
