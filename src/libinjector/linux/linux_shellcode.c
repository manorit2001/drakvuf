#include "linux_shellcode.h"
#include "linux_debug.h"

event_response_t handle_shellcode(drakvuf_t drakvuf, drakvuf_trap_info_t* info) {

    injector_t injector = info->trap->data;

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

    const char *shellcode = "\x6a\x3c\x58\x6a\x01\x5f\x0f\x05";

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    // allocate memory
    injector->memdata.data = g_try_malloc0(sizeof(shellcode));

    // access rsp location
    ACCESS_CONTEXT(ctx,
                   .translate_mechanism = VMI_TM_PROCESS_DTB,
                   .dtb = info->regs->cr3,
                   .addr = info->regs->rsp
                  );

    size_t bytes_read_write;
    // save the rsp bytes
    bool success = (VMI_SUCCESS == vmi_read(vmi, &ctx, sizeof(shellcode), injector->memdata.data, &bytes_read_write));
    PRINT_DEBUG("BYTES: %ld\n", bytes_read_write);
    // save the registries
    memcpy(&injector->saved_regs, info->regs, sizeof(x86_registers_t));

    //release vmi
    drakvuf_release_vmi(drakvuf);

    if (!success) {
        fprintf(stderr, "Could not read the data to be restored later");
    }

    print_stack(drakvuf, info);
    print_registers(info);

    vmi = drakvuf_lock_and_get_vmi(drakvuf);
    success = (VMI_SUCCESS == vmi_write(vmi, &ctx, sizeof(shellcode), (void *)shellcode, &bytes_read_write));
    PRINT_DEBUG("BYTES: %ld\n", bytes_read_write);

    if (!success) {
        fprintf(stderr, "Could not write the data");
    }

    // release vmi
    drakvuf_release_vmi(drakvuf);

    print_stack(drakvuf, info);

    registers_t regs;
    vmi_get_vcpuregs(vmi, &regs, info->vcpu);

    regs.x86.rax = 60;
    regs.x86.rdi = 1337;
    drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &regs);

    print_registers(info);

    return 0;
}
