#include "linux_syscalls.h"
#include <sys/mman.h>
#include <fcntl.h>

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

