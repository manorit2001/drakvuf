#include "linux_utils.h"
#include "linux_debug.h"
#include <sys/mman.h>
#include <fcntl.h>

bool save_vm_state(drakvuf_t drakvuf, drakvuf_trap_info_t* info, uint32_t size) {

    injector_t injector = (injector_t)info->trap->data;

    // access rip location
    ACCESS_CONTEXT(ctx,
                   .translate_mechanism = VMI_TM_PROCESS_DTB,
                   .dtb = info->regs->cr3,
                   .addr = info->regs->rip
                  );

    size_t bytes_read = 0;

    // save registers
    memcpy(&injector->saved_regs, info->regs, sizeof(x86_registers_t));

    // allocate memory
    injector->memdata.data = g_try_malloc0(size);

    // lock vmi
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    // read the bytes
    bool success = (VMI_SUCCESS == vmi_read(vmi, &ctx, size, (void *)injector->memdata.data, &bytes_read));
    if (!success)
        fprintf(stderr, "Could not read the data from memory");
    else {
        PRINT_DEBUG("Read data from memory success\n");
        print_hex(injector->memdata.data, size, bytes_read);
    }

    injector->memdata.loc = info->regs->rip;
    injector->memdata.len = bytes_read;

    // release vmi
    drakvuf_release_vmi(drakvuf);

    return success;
}

bool restore_vm_state(drakvuf_t drakvuf, drakvuf_trap_info_t* info) {

    injector_t injector = (injector_t)info->trap->data;

    if(!injector->memdata.loc)
        return true;

    // access rip location
    ACCESS_CONTEXT(ctx,
                   .translate_mechanism = VMI_TM_PROCESS_DTB,
                   .dtb = info->regs->cr3,
                   .addr = injector->memdata.loc
                  );

    size_t bytes_write = 0;

    // restore registers
    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));

    // lock vmi
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    bool success = (VMI_SUCCESS == vmi_write(vmi, &ctx, injector->memdata.len, (void *)injector->memdata.data, &bytes_write));
    if (!success)
        fprintf(stderr, "Could not restore the data in memory");
    else {
        PRINT_DEBUG("Memory data is restored\n");
        print_hex(injector->memdata.data, injector->memdata.len, bytes_write);
    }

    injector->memdata.loc = 0;
    injector->memdata.len = 0;

    // release vmi
    drakvuf_release_vmi(drakvuf);

    // free memory
    g_free((void*)injector->memdata.data);
    injector->memdata.data = NULL;

    return success;
}

bool save_rip_for_ret(drakvuf_t drakvuf, x86_registers_t* regs) {

    // lock vmi
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    ACCESS_CONTEXT(ctx,
                   .translate_mechanism = VMI_TM_PROCESS_DTB,
                   .dtb = regs->cr3
                  );
    addr_t addr = regs->rsp;

    // make space for storing rip
    addr -= 0x8;
    ctx.addr = addr;

    if (VMI_FAILURE == vmi_write_64(vmi, &ctx, &regs->rip)) {
        // release before returning
        drakvuf_release_vmi(drakvuf);
        return false;
    }

    regs->rsp = addr;

    // release vmi
    drakvuf_release_vmi(drakvuf);
    return true;

}

bool load_file_to_injector_shellcode(injector_t injector, const char* file)
{
    FILE* fp = fopen(file, "rb");
    if (!fp)
        return false;

    fseek (fp, 0, SEEK_END);
    if ( (injector->shellcode.len = ftell (fp)) < 0 )
    {
        fclose(fp);
        return false;
    }
    rewind (fp);

    // we are adding +1 as we will append ret instruction for restoring the state of the VM
    injector->shellcode.data = g_try_malloc0(injector->shellcode.len + 1);
    if ( !injector->shellcode.data )
    {
        fclose(fp);
        injector->shellcode.len = 0;
        return false;
    }

    if ( (size_t)injector->shellcode.len != fread(injector->shellcode.data, 1, injector->shellcode.len, fp))
    {
        g_free(injector->shellcode.data);
        injector->shellcode.data = NULL;
        injector->shellcode.len = 0;
        fclose(fp);
        return false;
    }
    *(char *)(injector->shellcode.data + injector->shellcode.len ) = 0xc3; //ret
    injector->shellcode.len += 1; // increase the length in variable

    PRINT_DEBUG("Shellcode loaded to injector->shellcode\n");
    print_hex(injector->shellcode.data, injector->shellcode.len, -1);

    fclose(fp);

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

    if (injector->memdata.data)
        g_free((void*)injector->memdata.data);

    if (injector->shellcode.data)
        g_free((void*)injector->shellcode.data);

    if (injector)
        g_free((void*)injector);


    injector = NULL;
}
