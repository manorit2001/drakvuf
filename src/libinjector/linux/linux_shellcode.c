#include "linux_shellcode.h"
#include "linux_debug.h"

event_response_t handle_shellcode(drakvuf_t drakvuf, drakvuf_trap_info_t* info) {

    const char shellcode[] = {0xf, 0x5};

    // access rip location
    ACCESS_CONTEXT(ctx,
                   .translate_mechanism = VMI_TM_PROCESS_DTB,
                   .dtb = info->regs->cr3,
                   .addr = info->regs->rip
                  );

    // TODO: save registry and memdata

    size_t bytes_write = 0;
    registers_t regs;

    // lock vmi
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    vmi_get_vcpuregs(vmi, &regs, info->vcpu);

    info->regs->rax = 60;
    info->regs->rdi = 39;

    if (VMI_SUCCESS != vmi_write(vmi, &ctx, sizeof(shellcode), (void *)shellcode, &bytes_write))
        fprintf(stderr, "Could not write the shellcode on guest");

    if (bytes_write != sizeof(shellcode))
        PRINT_DEBUG("vmi_write failed to inject shellcode. Written: %lx/%lx bytes: \n", bytes_write, sizeof(shellcode));

    // release vmi
    drakvuf_release_vmi(drakvuf);

    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}
