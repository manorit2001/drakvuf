#pragma once

#include <iostream>
#include <sstream>
#include <string>
#include <Python.h>

#include "libpy.h"
#include "plugins/private.h"
#include <libusermode/userhook.hpp>

// drakvuf required
void on_dll_discovered(drakvuf_t drakvuf, const dll_view_t* dll, void* extra);

void on_dll_hooked(drakvuf_t drakvuf, const dll_view_t* dll, const std::vector<hook_target_view_t>& targets, void* extra);

// python helpers
int add_usermode_hook(const char* dll_name, const char* func_name, callback_t cb);
char* read_str(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t addr);
