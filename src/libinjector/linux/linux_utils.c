#include "linux_utils.h"
#include "linux_debug.h"
#include <sys/mman.h>
#include <fcntl.h>

void free_injector(injector_t injector)
{
    if (!injector) return;

    PRINT_DEBUG("Injector freed\n");

    if (injector->cr3_trap) {
        drakvuf_remove_trap(injector->drakvuf, injector->cr3_trap, NULL);
        injector->cr3_trap = NULL;
    }

    if (injector)
        g_free((void*)injector);

    injector = NULL;
}
