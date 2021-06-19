#ifndef LINUX_DEBUG_H
#define LINUX_DEBUG_H

#include "linux_utils.h"

void print_shellcode(char* shellcode, int len);
void print_stack(drakvuf_t drakvuf, drakvuf_trap_info_t* info);
void print_registers(drakvuf_trap_info_t* info);

#endif
