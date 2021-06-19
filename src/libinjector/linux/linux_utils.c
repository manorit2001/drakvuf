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

    size_t bytes_read_write = 0;
    injector->memdata.len = size;

    // save registers
    memcpy(&injector->saved_regs, info->regs, sizeof(x86_registers_t));

    // allocate memory
    injector->memdata.data = g_try_malloc0(size);

    // lock vmi
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    // read the bytes
    bool success = (VMI_SUCCESS == vmi_read(vmi, &ctx, size, (void *)injector->memdata.data, &bytes_read_write));
    if (!success)
        fprintf(stderr, "Could not read the data");
    else
        PRINT_DEBUG("BYTES: %ld\n", bytes_read_write);

    injector->memdata.loc = info->regs->rip;
    print_shellcode(injector->memdata.data, size);

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

    size_t bytes_read_write = 0;

    // restore registers
    memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));

    // lock vmi
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    bool success = (VMI_SUCCESS == vmi_write(vmi, &ctx, injector->memdata.len, (void *)injector->memdata.data, &bytes_read_write));
    if (!success)
        fprintf(stderr, "Could not restore the data");
    else
        PRINT_DEBUG("BYTES: %ld\n", bytes_read_write);

    injector->memdata.loc = 0;
    injector->memdata.len = 0;

    // release vmi
    drakvuf_release_vmi(drakvuf);

    // free memory
    g_free((void*)injector->memdata.data);
    injector->memdata.data = NULL;

    return success;
}

bool setup_mmap_syscall(injector_t injector, x86_registers_t* regs, size_t size) {
    // mmap(NULL, size, PROT_EXEC|PROT_WRITE|PROT_READ, MAP_SHARED|MAP_ANONYMOUS, -1, 0)
    struct argument args[10] = { {0} };
    init_int_argument(&args[0], 0);
    init_int_argument(&args[1], size);
    init_int_argument(&args[2], PROT_EXEC|PROT_WRITE|PROT_READ);
    init_int_argument(&args[4], MAP_SHARED|MAP_ANONYMOUS);
    init_int_argument(&args[5], -1);
    init_int_argument(&args[5], 0);

    bool success = setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args));
    if(success)
        injector->syscall = sys_mmap;

    return success;

}

bool setup_open_file_syscall(injector_t injector, x86_registers_t* regs) {
    // open (file_name, flags, mode)
    struct argument args[10] = { {0} };
    init_int_argument(&args[0], injector->file_descriptor);
    if (injector->method == INJECT_METHOD_READ_FILE)
        init_int_argument(&args[1], O_RDONLY);
    else
        init_int_argument(&args[1], O_WRONLY);

    if (injector->method == INJECT_METHOD_WRITE_FILE)
        init_int_argument(&args[2], O_CREAT | O_TRUNC);

    bool success = setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args));
    if(success)
        injector->syscall = sys_open;

    return success;
}

bool setup_read_file_syscall(injector_t injector, x86_registers_t* regs, size_t size) {
    // read (fd, buf_addr, count)
    struct argument args[10] = { {0} };
    init_int_argument(&args[0], injector->file_descriptor);
    init_int_argument(&args[1], injector->virtual_memory_addr);
    init_int_argument(&args[2], size);

    bool success = setup_stack(injector->drakvuf, regs, args, ARRAY_SIZE(args));
    if(success)
        injector->syscall = sys_read;

    return success;
}

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

    if (injector->memdata.data)
        g_free((void*)injector->memdata.data);

    if (injector)
        g_free((void*)injector);


    injector = NULL;
}
