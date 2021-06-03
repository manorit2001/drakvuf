#include "linux_utils.h"

injector_status_t injector_start_app_on_linux(
    drakvuf_t drakvuf,
    vmi_pid_t pid,
    uint32_t tid,
    const char* file,
    injection_method_t method,
    output_format_t format,
    int args_count,
    const char* args[]
);

