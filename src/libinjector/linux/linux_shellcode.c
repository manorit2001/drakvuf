#include "linux_shellcode.h"
#include "linux_debug.h"

event_response_t handle_shellcode(drakvuf_t drakvuf, drakvuf_trap_info_t* info) {

    // exit_no_null.o:     file format elf64-x86-64
    //
    // Disassembly of section .text:
    //
    // 0000000000000000 <_start>:
    //    0:   6a 3c                   push   0x3c
    //    2:   58                      pop    rax
    //    3:   6a 01                   push   0x1
    //    5:   5f                      pop    rdi
    //    6:   0f 05                   syscall
    //

    // works like charm with proper exit code
    // const char shellcode[] = {0x6a, 0x3c, 0x58, 0x6a, 0x1, 0x5f, 0xf, 0x5};

    // Trying to write only the `syscall` instruction on the memory, and set registers using regs.x86 or setup_stack

    // works but doesn't give proper exit code set manually by regs.x86.rdi or setup_stack ( inside setup_exit_syscall )
    // const char shellcode[] = {0xf, 0x5};

    // konstanty sir suggested
    const char shellcode[] = { 0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, 0x0F, 0x05  };

    // access rip location
    ACCESS_CONTEXT(ctx,
                   .translate_mechanism = VMI_TM_PROCESS_DTB,
                   .dtb = info->regs->cr3,
                   .addr = info->regs->rip
                  );

    // TODO: save registry and memdata

    size_t bytes_read_write;
    registers_t regs;

    // lock vmi
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    vmi_get_vcpuregs(vmi, &regs, info->vcpu);

    info->regs->rax = 60;
    regs.x86.rdi = 38;
    regs.x86.rax = 60;
    info->regs->rdi = 39; // set different value for differentiating

    bool success = (VMI_SUCCESS == vmi_write(vmi, &ctx, sizeof(shellcode), (void *)shellcode, &bytes_read_write));
    if (!success)
        fprintf(stderr, "Could not write the data");
    else
        PRINT_DEBUG("BYTES: %ld\n", bytes_read_write);

    // release vmi
    drakvuf_release_vmi(drakvuf);

    drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &regs);

    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}
