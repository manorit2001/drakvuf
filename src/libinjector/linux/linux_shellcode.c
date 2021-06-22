#include "linux_shellcode.h"
#include "linux_debug.h"

event_response_t handle_shellcode(drakvuf_t drakvuf, drakvuf_trap_info_t* info) {

    injector_t injector = (injector_t)info->trap->data;

    // Disassembly of section .text:
    //
    // 0000000000000000 <_start>:
    //    6:   0f 05                   syscall

    // shellcode with just syscall, and registers set using `info->regs`
    const char shellcode[] = {0xf, 0x5};

    // access rip location
    ACCESS_CONTEXT(ctx,
                   .translate_mechanism = VMI_TM_PROCESS_DTB,
                   .dtb = info->regs->cr3,
                   .addr = info->regs->rip
                  );

    // TODO: save registry and memdata

    size_t bytes_read_write;

    PRINT_DEBUG("Setting up exit syscall\n");
    setup_exit_syscall(injector, info->regs, 22);
    info->regs->rax = injector->syscall;

    // lock vmi
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    bool success = (VMI_SUCCESS == vmi_write(vmi, &ctx, sizeof(shellcode), (void *)shellcode, &bytes_read_write));
    if (!success)
        fprintf(stderr, "Could not write the data");
    else
        PRINT_DEBUG("BYTES: %ld\n", bytes_read_write);

    // release vmi
    drakvuf_release_vmi(drakvuf);

    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}
