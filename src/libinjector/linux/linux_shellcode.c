#include "linux_shellcode.h"
#include "linux_debug.h"
#include "linux_syscalls.h"

event_response_t handle_shellcode(drakvuf_t drakvuf, drakvuf_trap_info_t* info) {

    injector_t injector = (injector_t)info->trap->data;

    // Disassembly of section .text:
    //
    // 0000000000000000 <_start>:
    //    6:   0f 05                   syscall
    //    b:   c3                      ret

    // shellcode with just syscall, and registers set using `info->regs`
    // const char shellcode[] = {0xf, 0x5, 0xc3};
    // shellcode used for testing save and restore since exit syscall will
    // terminate the program not allowing the stack to be restored
    const char shellcode[] = {0x90, 0x90, 0x90, 0xc3};

    // access rip location
    ACCESS_CONTEXT(ctx,
                   .translate_mechanism = VMI_TM_PROCESS_DTB,
                   .dtb = info->regs->cr3,
                   .addr = info->regs->rip
                  );

    size_t bytes_read_write;
    event_response_t event = VMI_EVENT_RESPONSE_NONE;

    switch(injector->step)
    {
    case STEP1:
    {
        PRINT_DEBUG("Save Current state\n");
        save_vm_state(drakvuf, info, sizeof(shellcode));

        // PRINT_DEBUG("Setting up exit syscall\n");
        setup_exit_syscall(injector, info->regs, 22);
        // info->regs->rax = injector->syscall;

        // lock vmi
        vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

        bool success = (VMI_SUCCESS == vmi_write(vmi, &ctx, sizeof(shellcode), (void *)shellcode, &bytes_read_write));
        if (!success)
            fprintf(stderr, "Could not write the shellcode");
        else
            PRINT_DEBUG("BYTES: %ld\n", bytes_read_write);

        // release vmi
        drakvuf_release_vmi(drakvuf);

        event = VMI_EVENT_RESPONSE_SET_REGISTERS;
        break;
    }
    case STEP2:
    {
        PRINT_DEBUG("Restoring the state\n");
        restore_vm_state(drakvuf, info);
        event = VMI_EVENT_RESPONSE_SET_REGISTERS;
        break;
    }
    case STEP3:
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
