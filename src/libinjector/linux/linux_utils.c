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

    return success;
}


void free_injector(injector_t injector)
{
    if (!injector) return;

    PRINT_DEBUG("Injector freed\n");

    if (injector)
        g_free((void*)injector);

    injector = NULL;
}
