#include "linux_utils.h"
#include "linux_debug.h"

injector_status_t injector_start_app_on_linux(
    drakvuf_t drakvuf,
    vmi_pid_t pid,
    uint32_t tid,
    const char* file,
    injection_method_t method,
    output_format_t format,
    int args_count,
    const char* args[10]
)
{
    injector_t injector = (injector_t)g_try_malloc0(sizeof(struct injector));
    injector->drakvuf = drakvuf;
    injector->target_pid = pid;
    injector->target_tid = tid;
    injector->shellcode_file = file;
    injector->args_count = args_count;
    for ( int i = 0; i<args_count; i++ )
        injector->args[i] = args[i];
    injector->method = method;
    injector->format = format;

    injector_status_t rc = injector->rc;
    g_free(injector);
    return rc;
}
