#include "linux_utils.h"
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

void free_memtraps(injector_t injector)
{
    GSList* loop = injector->memtraps;
    injector->memtraps = NULL;

    while (loop)
    {
        drakvuf_remove_trap(injector->drakvuf, loop->data, (drakvuf_trap_free_t)free);
        loop = loop->next;
    }
    g_slist_free(loop);
}

void free_injector(injector_t injector)
{
    if (!injector) return;

    PRINT_DEBUG("Injector freed\n");

    if (injector->memtraps)
        free_memtraps(injector);

    if (injector)
        g_free((void*)injector);

    injector = NULL;
}
