#include "userhooks.h"
#include <vector>
#include <unordered_map>

static std::vector<plugin_target_config_entry_t> wanted_hooks;
static std::unordered_map<plugin_target_config_entry_t*, callback_t> hook_map;

void on_dll_discovered(drakvuf_t drakvuf, const dll_view_t* dll, void* extra)
{
    vmi_lock_guard lg(drakvuf);
    unicode_string_t* dll_name = drakvuf_read_unicode_va(lg.vmi, dll->mmvad.file_name_ptr, 0);

    if (dll_name && dll_name->contents)
    {
        for (auto& wanted_hook : wanted_hooks)
        {
            if (strstr((const char*)dll_name->contents, wanted_hook.dll_name.c_str()) != 0)
            {
                 PRINT_DEBUG("[PYMON] HOOKING %s\n", wanted_hook.dll_name.c_str());
                 drakvuf_request_usermode_hook(drakvuf, dll, &wanted_hook, hook_map.at(&wanted_hook), extra);
            }
        }
    }

    if (dll_name)
        vmi_free_unicode_str(dll_name);
}

void on_dll_hooked(drakvuf_t drakvuf, const dll_view_t* dll, const std::vector<hook_target_view_t>& targets, void* extra)
{
    PRINT_DEBUG("[PYMON] ON_DLL_HOOKED\n");
}

int add_usermode_hook(const char* dll_name, const char* func_name, callback_t cb)
{
    PRINT_DEBUG("[PYMON] Usermode hooking: %s, %s, %p\n", dll_name, func_name, reinterpret_cast<void*>(cb));
    auto& entry = wanted_hooks.emplace_back();
    entry.function_name = func_name;
    entry.dll_name = dll_name;
    entry.type = HOOK_BY_NAME;
    entry.actions = HookActions::empty().set_log().set_stack();
    // BUG: this will fail if multiple hooks have same cb
    hook_map.insert_or_assign(&entry, cb);
    return 0;
}

char* read_str(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t addr)
{
    auto vmi = drakvuf_lock_and_get_vmi(drakvuf);
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = addr
    };

    return vmi_read_str(vmi, &ctx);
}
