/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2023 Tamas K Lengyel.                                  *
 * Tamas K Lengyel is hereinafter referred to as the author.               *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed DRAKVUF technology into proprietary   *
 * software, alternative licenses can be acquired from the author.         *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files.                             *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * DRAKVUF with other software in compressed or archival form does not     *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * DRAKVUF or grant special permissions to use it in other open source     *
 * software.  Please contact tamas.k.lengyel@gmail.com with any such       *
 * requests.  Similarly, we don't incorporate incompatible open source     *
 * software into Covered Software without special permission from the      *
 * copyright holders.                                                      *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * DRAKVUF in other works, are happy to help.  As mentioned above,         *
 * alternative license can be requested from the author to integrate       *
 * DRAKVUF into proprietary applications and appliances.  Please email     *
 * tamas.k.lengyel@gmail.com for further information.                      *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port DRAKVUF to new platforms, fix bugs, *
 * and add new features.  You are highly encouraged to submit your changes *
 * on https://github.com/tklengyel/drakvuf, or by other methods.           *
 * By sending these changes, it is understood (unless you specify          *
 * otherwise) that you are offering unlimited, non-exclusive right to      *
 * reuse, modify, and relicense the code.  DRAKVUF will always be          *
 * available Open Source, but this is important because the inability to   *
 * relicense code has caused devastating problems for other Free Software  *
 * projects (such as KDE and NASM).                                        *
 * To specify special license conditions of your contributions, just say   *
 * so when you send them.                                                  *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the DRAKVUF   *
 * license file for more details (it's in a COPYING file included with     *
 * DRAKVUF, and also available from                                        *
 * https://github.com/tklengyel/drakvuf/COPYING)                           *
 *                                                                         *
 ***************************************************************************/

/**
 * User mode hooking module.
 *
 * (1) Observes when a process is loading a new DLL through the side effects
 * of NtMapViewOfSection or NtProtectVirtualMemory being called.
 * (2) Finds the DLL export information and checks if it's fully readable,
 * if not, triggers a page fault or MmCopyVirutalMemory to force system to load
 * it into memory.
 * (3) Translates given export symbols to virtual addresses, checks if
 * the underlying memory is available (if not, again triggers page fault)
 * and finally adds a standard DRAKVUF trap.
 */

#include <fstream>
#include <sstream>
#include <map>
#include <string>
#include <optional>
#include <stdexcept>

#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>
#include <libdrakvuf/libdrakvuf.h>
#include <assert.h>

#include "userhook.hpp"
#include "uh-private.hpp"


static void wrap_delete(drakvuf_trap_t* trap)
{
    g_slice_free(drakvuf_trap_t, trap);
}

static std::string drakvuf_read_unicode(drakvuf_t drakvuf, addr_t addr)
{
    std::string str;
    auto vmi = vmi_lock_guard(drakvuf);
    unicode_string_t* us = drakvuf_read_unicode_va(drakvuf, addr, 0);
    if (us && us->contents)
        str.assign(reinterpret_cast<const char*>(us->contents));
    if (us)
        vmi_free_unicode_str(us);
    return str;
}

proc_data_t get_proc_data(drakvuf_t drakvuf, const drakvuf_trap_info_t* info)
{
    proc_data_t proc_data = info->proc_data;
    {
        auto vmi = vmi_lock_guard(drakvuf);
        if (VMI_OS_WINDOWS == vmi_get_ostype(vmi))
            proc_data = info->attached_proc_data;
    }
    return proc_data;
}

/**
 * Check if this thread is currently in process of loading a DLL.
 * If so, return a pointer to the associated metadata.
 */
static dll_t* get_pending_dll(drakvuf_t drakvuf, drakvuf_trap_info* info, userhook* plugin)
{
    uint32_t thread_id;
    if (!drakvuf_get_current_thread_id(drakvuf, info, &thread_id))
        return nullptr;

    proc_data_t proc_data = get_proc_data(drakvuf, info);

    auto vec_it = plugin->loaded_dlls.find(proc_data.pid);

    if (vec_it == plugin->loaded_dlls.end())
        return nullptr;

    for (auto& dll_meta : vec_it->second)
    {
        if (!dll_meta.v.is_hooked && dll_meta.v.thread_id == thread_id)
            return &dll_meta;
    }

    return nullptr;
}

/**
 * Check if DLL is interesting, if so, build a "hooking context" of a DLL. Such context is needed,
 * because user mode hooking is a stateful operation which requires a VM to be un-paused many times.
 */
static dll_t* create_dll_meta(drakvuf_t drakvuf, drakvuf_trap_info* info, userhook* plugin, addr_t dll_base)
{
    proc_data_t proc_data = get_proc_data(drakvuf, info);

    mmvad_info_t mmvad;
    if (!drakvuf_find_mmvad(drakvuf, proc_data.base_addr, dll_base, &mmvad))
    {
        PRINT_DEBUG("[USERHOOK] Failed to find MMVAD\n");
        return nullptr;
    }

    if (mmvad.file_name_ptr == 0)
    {
        PRINT_DEBUG("[USERHOOK] MMVAD null file name pointer\n");
        return nullptr;
    }

    auto vec_it = plugin->loaded_dlls.find(proc_data.pid);

    if (vec_it != plugin->loaded_dlls.end())
    {
        for (auto const& dll_meta : vec_it->second)
        {
            if (dll_meta.v.real_dll_base == mmvad.starting_vpn << 12)
            {
                PRINT_DEBUG("[USERHOOK] DLL %d!%llx is already hooked\n", proc_data.pid, (unsigned long long)mmvad.starting_vpn << 12);
                return nullptr;
            }
        }
    }

    uint32_t thread_id;
    if (!drakvuf_get_current_thread_id(drakvuf, info, &thread_id))
    {
        PRINT_DEBUG("[USERHOOK] Failed to get TID\n");
        return nullptr;
    }

    dll_t dll_meta =
    {
        .v.dtb = info->regs->cr3,
        .v.thread_id = thread_id,
        .v.real_dll_base = (mmvad.starting_vpn << 12),
        .v.mmvad = mmvad,
        .v.is_hooked = false
    };

    std::string dll_name = drakvuf_read_unicode(drakvuf, dll_meta.v.mmvad.file_name_ptr);

    if (!dll_name.empty())
    {
        for (auto& reg : plugin->plugins)
        {
            reg.pre_cb(drakvuf, dll_name, (const dll_view_t*)&dll_meta, reg.extra);
        }
    }

    if (dll_meta.targets.empty())
        return nullptr;

    PRINT_DEBUG("[USERHOOK] Found DLL which is worth processing %llx: %s\n", (unsigned long long)mmvad.starting_vpn << 12, dll_name.data());
    addr_t vad_start = mmvad.starting_vpn << 12;
    size_t vad_length = (mmvad.ending_vpn - mmvad.starting_vpn + 1) << 12;

    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = vad_start
    );

    addr_t export_header_rva = 0;
    size_t export_header_size = 0;

    constexpr int MAX_HEADER_BYTES = 1024;   // keep under 1 page
    uint8_t image[MAX_HEADER_BYTES];

    {
        auto vmi = vmi_lock_guard(drakvuf);
        if (VMI_SUCCESS != peparse_get_image(vmi, &ctx, MAX_HEADER_BYTES, image))
            return nullptr;
    }

    void* optional_header = NULL;
    uint16_t magic = 0;

    peparse_assign_headers(image, NULL, NULL, &magic, &optional_header, NULL, NULL);
    export_header_rva = peparse_get_idd_rva(IMAGE_DIRECTORY_ENTRY_EXPORT, &magic, optional_header, NULL, NULL);
    export_header_size = peparse_get_idd_size(IMAGE_DIRECTORY_ENTRY_EXPORT, &magic, optional_header, NULL, NULL);

    if (export_header_rva >= vad_length)
    {
        PRINT_DEBUG("[USERHOOK] Export header RVA is forwarded outside VAD\n");
        return nullptr;
    }
    else if (export_header_size >= vad_length - export_header_rva)
    {
        PRINT_DEBUG("[USERHOOK] Export header size is forwarded outside VAD\n");
        return nullptr;
    }

    dll_meta.pf_current_addr = vad_start + export_header_rva & ~(VMI_PS_4KB - 1);
    dll_meta.pf_max_addr = vad_start + export_header_rva + export_header_size;

    if (dll_meta.pf_max_addr & VMI_PS_4KB)
    {
        dll_meta.pf_max_addr += VMI_PS_4KB;
        dll_meta.pf_max_addr = dll_meta.pf_max_addr & ~(VMI_PS_4KB - 1);
    }

    auto it = plugin->loaded_dlls.emplace(proc_data.pid, std::vector<dll_t>()).first;
    it->second.push_back(std::move(dll_meta));
    return &it->second.back();
}

bool make_trap(vmi_instance_t vmi, drakvuf_t drakvuf, drakvuf_trap_info* info, hook_target_entry_t* target, addr_t exec_func)
{
    if (VMI_OS_WINDOWS == vmi_get_ostype((vmi)))
        target->pid = info->attached_proc_data.pid;
    else
        target->pid = info->proc_data.pid;

    drakvuf_trap_t* trap = g_slice_new0(drakvuf_trap_t);
    trap->type = BREAKPOINT;
    trap->name = target->target_name.c_str();
    trap->cb = target->callback;
    trap->data = target;

    // during CoW we need to find all traps placed on the same physical page
    // that's why we'll manually resolve vaddr and store paddr under trap->breakpoint.addr
    addr_t pa;

    if (vmi_pagetable_lookup(vmi, info->regs->cr3, exec_func, &pa) != VMI_SUCCESS)
        goto fail;

    trap->breakpoint.lookup_type = LOOKUP_NONE;
    trap->breakpoint.addr_type = ADDR_PA;
    trap->breakpoint.addr = pa;
    trap->ttl = drakvuf_get_limited_traps_ttl(drakvuf);

    if (drakvuf_add_trap(drakvuf, trap))
    {
        target->trap = trap;
        return true;
    }

fail:
    PRINT_DEBUG("[USERHOOK] Failed to add trap :(\n");
    g_slice_free(drakvuf_trap_t, trap);
    return false;
}

bool is_pagetable_loaded(vmi_instance_t vmi, const drakvuf_trap_info* info, addr_t vaddr)
{
    page_info_t pinfo;
    return vmi_pagetable_lookup_extended(vmi, info->regs->cr3, vaddr, &pinfo) == VMI_SUCCESS;
}

static event_response_t perform_hooking(drakvuf_t drakvuf, drakvuf_trap_info* info, userhook* plugin, dll_t* dll_meta)
{
    bool was_hooked = dll_meta->v.is_hooked;
    event_response_t ret = internal_perform_hooking(drakvuf, info, plugin, dll_meta);

    if (!was_hooked && dll_meta->v.is_hooked)
    {
        std::vector<hook_target_view_t> targets;

        for (const auto& target : dll_meta->targets)
        {
            targets.emplace_back(target.target_name, target.offset, target.state);
        }

        for (const auto& reg : plugin->plugins)
        {
            reg.post_cb(drakvuf, (const dll_view_t*)dll_meta, targets, reg.extra);
        }
    }

    return ret;
}

event_response_t hook_dll(drakvuf_t drakvuf, drakvuf_trap_info_t* info, addr_t base_address)
{
    auto plugin = get_trap_plugin<userhook>(info);

    dll_t* dll_meta = get_pending_dll(drakvuf, info, plugin);

    if (!dll_meta)
        dll_meta = create_dll_meta(drakvuf, info, plugin, base_address);

    if (dll_meta)
        return perform_hooking(drakvuf, info, plugin, dll_meta);

    return VMI_EVENT_RESPONSE_NONE;
}

static void search_process_system_dlls(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<userhook>(info);

    struct visitor_context
    {
        drakvuf_trap_info_t* info{nullptr};
        userhook* plugin{nullptr};

        addr_t dll_base{0};
    };

    if (auto search = plugin->proc_ntdll_hooked.find(info->attached_proc_data.pid);
        search == plugin->proc_ntdll_hooked.end() || !search->second)
    {
        auto visitor = [](drakvuf_t drakvuf_, const module_info_t* module_info, bool* need_free, bool* need_stop, void* ctx)
        {
            auto vctx = static_cast<visitor_context*>(ctx);
            auto info = vctx->info;
            auto plugin = vctx->plugin;
            std::string name{(const char*)module_info->base_name->contents};
            if (name.find("ntdll.dll") != std::string::npos)
            {
                plugin->proc_ntdll_hooked[info->attached_proc_data.pid] = true;
                vctx->dll_base = module_info->base_addr;
                *need_stop = true;
            }

            return true;
        };

        visitor_context ctx{info, plugin};
        drakvuf_enumerate_process_modules(drakvuf, info->attached_proc_data.base_addr, visitor, &ctx);

        if (ctx.dll_base)
            hook_dll(drakvuf, info, ctx.dll_base);
    }
}

/**
 * This is used in order to observe when SysWOW64 process is loading a new DLL.
 * If the DLL is interesting, we perform further investigation and try to equip user mode hooks.
 */
static event_response_t protect_virtual_memory_hook_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<userhook>(info);
    auto params = get_trap_params<protect_virtual_memory_result_t>(info);

    if (!params->verify_result_call_params(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    event_response_t ret = hook_dll(drakvuf, info, params->base_address);
    if (!drakvuf_lookup_injection(drakvuf, info))
        plugin->destroy_trap(info->trap);

    return ret;
}

static event_response_t protect_virtual_memory_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    search_process_system_dlls(drakvuf, info);
    if (drakvuf_lookup_injection(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    // IN HANDLE ProcessHandle
    uint64_t process_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    // IN OUT PVOID *BaseAddress
    addr_t base_address_ptr = drakvuf_get_function_argument(drakvuf, info, 2);

    if (process_handle != ~0ULL)
        return VMI_EVENT_RESPONSE_NONE;

    addr_t base_address;
    {
        ACCESS_CONTEXT(ctx,
            .translate_mechanism = VMI_TM_PROCESS_DTB,
            .dtb = info->regs->cr3,
            .addr = base_address_ptr
        );

        auto vmi = vmi_lock_guard(drakvuf);
        if (VMI_SUCCESS != vmi_read_addr(vmi, &ctx, &base_address))
            return VMI_EVENT_RESPONSE_NONE;
    }

    /* We have to finish handling NtProtectVirtualMemory on return to avoid
     * possible injection collision with "search_process_system_dlls" function
     * from the beginning of the function.
     * If some system dll, e.g. "ntdll.dll", been processed then state injection
     * been used to restore pre-injection state. Thus preventing "hook_dll"
     * function from other injections.
     */
    auto plugin = get_trap_plugin<userhook>(info);
    auto trap = plugin->register_trap<protect_virtual_memory_result_t>(
            info,
            protect_virtual_memory_hook_ret_cb,
            breakpoint_by_pid_searcher(),
            "NtProtectVirtualMemory ret");
    if (!trap)
        return VMI_EVENT_RESPONSE_NONE;

    auto params = get_trap_params<protect_virtual_memory_result_t>(trap);
    if (!params)
        return VMI_EVENT_RESPONSE_NONE;

    params->set_result_call_params(info);

    // IN OUT PVOID *BaseAddress
    params->base_address = base_address;

    return VMI_EVENT_RESPONSE_NONE;
}

static status_t read_addr(drakvuf_t drakvuf, drakvuf_trap_info_t* info, const addr_t& base_address_ptr, addr_t base_address)
{
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = base_address_ptr
    );

    auto vmi = vmi_lock_guard(drakvuf);
    return vmi_read_addr(vmi, &ctx, &base_address);
}

/**
 * This is used in order to observe when 64 bit process is loading a new DLL.
 * If the DLL is interesting, we perform further investigation and try to equip user mode hooks.
 */
static event_response_t map_view_of_section_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<userhook>(info);
    auto params = get_trap_params<map_view_of_section_result_t>(info);

    if (!params->verify_result_call_params(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    addr_t base_address{0};
    if (VMI_SUCCESS != read_addr(drakvuf, info, params->base_address_ptr, base_address))
    {
        plugin->destroy_trap(info->trap);
        return VMI_EVENT_RESPONSE_NONE;
    }

    event_response_t ret = hook_dll(drakvuf, info, base_address);
    if (!drakvuf_lookup_injection(drakvuf, info))
        plugin->destroy_trap(info->trap);

    return ret;
}

static event_response_t map_view_of_section_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    search_process_system_dlls(drakvuf, info);
    if (drakvuf_lookup_injection(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    auto plugin = get_trap_plugin<userhook>(info);
    auto trap = plugin->register_trap<map_view_of_section_result_t>(
            info,
            map_view_of_section_ret_cb,
            breakpoint_by_pid_searcher(),
            "NtMapViewOfSection ret");
    if (!trap)
        return VMI_EVENT_RESPONSE_NONE;

    auto params = get_trap_params<map_view_of_section_result_t>(trap);
    if (!params)
        return VMI_EVENT_RESPONSE_NONE;

    params->set_result_call_params(info);

    // IN HANDLE SectionHandle
    params->section_handle = drakvuf_get_function_argument(drakvuf, info, 1);
    // IN HANDLE ProcessHandle
    params->process_handle = drakvuf_get_function_argument(drakvuf, info, 2);
    // IN OUT PVOID *BaseAddress
    params->base_address_ptr = drakvuf_get_function_argument(drakvuf, info, 3);

    return VMI_EVENT_RESPONSE_NONE;
}

/**
 * Observe process exit and remove all user mode hooks
 */
static event_response_t clean_process_address_space_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<userhook>(info);

    addr_t cleaned_process_base = drakvuf_get_function_argument(drakvuf, info, 1);

    vmi_pid_t exit_pid;
    if (!drakvuf_get_process_pid(drakvuf, cleaned_process_base, &exit_pid))
        return VMI_EVENT_RESPONSE_NONE;

    auto vec_it = plugin->loaded_dlls.find(exit_pid);

    if (vec_it == plugin->loaded_dlls.end())
        return VMI_EVENT_RESPONSE_NONE;

    for (auto& it : vec_it->second)
    {
        for (auto& target : it.targets)
        {
            if (target.state == HOOK_OK)
            {
                PRINT_DEBUG("[USERHOOK] Erased trap for pid %d %s\n", exit_pid,
                    target.target_name.c_str());
                drakvuf_remove_trap(drakvuf, target.trap, wrap_delete);
            }
        }
    }

    plugin->loaded_dlls.erase(vec_it);
    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t copy_on_write_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<userhook>(info);
    auto params = get_trap_params<copy_on_write_result_t>(info);

    if (!params->verify_result_call_params(drakvuf, info))
        return VMI_EVENT_RESPONSE_NONE;

    plugin->destroy_trap(info->trap);

    auto vmi = vmi_lock_guard(drakvuf);

    // sometimes the physical address was incorrectly cached in this moment, so we need to flush it
    vmi_v2pcache_flush(vmi, info->regs->cr3);
    addr_t pa;

    if (vmi_pagetable_lookup(vmi, info->regs->cr3, params->vaddr, &pa) != VMI_SUCCESS)
    {
        PRINT_DEBUG("[USERHOOK] failed to get pa\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (params->old_cow_pa == pa)
    {
        PRINT_DEBUG("[USERHOOK] PA after CoW remained the same, wtf? Nothing to do here...\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    for (auto& hook : params->hooks)
    {
        if (hook->trap)
        {
            addr_t hook_va = ((params->vaddr >> 12) << 12) + (hook->trap->breakpoint.addr & 0xFFF);
            PRINT_DEBUG("adding hook at %lx\n", hook_va);

            drakvuf_remove_trap(drakvuf, hook->trap, wrap_delete);
            hook->state = HOOK_FAILED;
            hook->trap = nullptr;

            make_trap(vmi, drakvuf, info, hook, hook_va);
        }
    }

    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t copy_on_write_handler(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    auto plugin = get_trap_plugin<userhook>(info);

    addr_t vaddr = drakvuf_get_function_argument(drakvuf, info, 1);
    addr_t pte = drakvuf_get_function_argument(drakvuf, info, 2);
    addr_t pa;

    proc_data_t proc_data = get_proc_data(drakvuf, info);

    {
        auto vmi = vmi_lock_guard(drakvuf);

        if (vmi_pagetable_lookup(vmi, info->regs->cr3, vaddr, &pa) != VMI_SUCCESS)
        {
            PRINT_DEBUG("[USERHOOK] failed to get pa");
            return VMI_EVENT_RESPONSE_NONE;
        }
    }

    std::vector < hook_target_entry_t* > hooks;
    for (auto& dll : plugin->loaded_dlls[proc_data.pid])
    {
        for (auto& hook : dll.targets)
        {
            if (hook.state == HOOK_OK)
            {
                addr_t hook_addr = hook.trap->breakpoint.addr;
                if (hook_addr >> 12 == pa >> 12)
                {
                    hooks.push_back(&hook);
                }
            }
        }
    }

    PRINT_DEBUG("[USERHOOK] copy on write called: vaddr: %llx pte: %llx, pid: %d, cr3: %llx\n", (unsigned long long)vaddr, (unsigned long long)pte, proc_data.pid, (unsigned long long)info->regs->cr3);
    PRINT_DEBUG("[USERHOOK] old CoW PA: %llx\n", (unsigned long long)pa);

    if (!hooks.empty())
    {
        PRINT_DEBUG("USERHOOK] Found %zu hooks on CoW page, registering return trap\n", hooks.size());

        auto trap = plugin->register_trap<copy_on_write_result_t>(
                info,
                copy_on_write_ret_cb,
                breakpoint_by_pid_searcher());
        if (!trap)
            return VMI_EVENT_RESPONSE_NONE;

        auto params = get_trap_params<copy_on_write_result_t>(trap);

        params->set_result_call_params(info);

        params->vaddr = vaddr;
        params->pte = pte;
        params->old_cow_pa = pa;
        params->hooks = hooks;
    }

    return VMI_EVENT_RESPONSE_NONE;
}


void userhook::request_usermode_hook(drakvuf_t drakvuf, const dll_view_t* dll, const plugin_target_config_entry_t* target, callback_t callback, void* extra)
{
    dll_t* p_dll = reinterpret_cast<dll_t*>(const_cast<dll_view_t*>(dll));

    if (target->type == HOOK_BY_NAME)
        p_dll->targets.emplace_back(target->function_name, target->clsid, callback, target->argument_printers, extra);
    else // HOOK_BY_OFFSET
        p_dll->targets.emplace_back(target->function_name, target->clsid, target->offset, callback, target->argument_printers, extra);
}

void userhook::register_plugin(drakvuf_t drakvuf, usermode_cb_registration reg)
{
    this->plugins.push_back(reg);
}

bool userhook::is_supported(drakvuf_t drakvuf)
{
    {
        // Lock vmi.
        auto vmi = vmi_lock_guard(drakvuf);
        win_build_info_t build;
        if (vmi_get_windows_build_info(vmi, &build) &&
            VMI_OS_WINDOWS_10 == build.version &&
            15063 >= build.buildnumber)
        {
            PRINT_DEBUG("[USERHOOK] Usermode hooking is not yet supported on this operating system.\n");
            return false;
        }
    } // Unlock vmi.

#ifndef LIBUSERMODE_USE_INJECTION
    page_mode_t pm = drakvuf_get_page_mode(drakvuf);
    if (pm != VMI_PM_IA32E)
    {
        PRINT_DEBUG("[USERHOOK] Usermode hooking is not yet supported on this architecture/bitness.\n");
        return false;
    }
#endif

    return true;
}

userhook::userhook(drakvuf_t drakvuf): pluginex(drakvuf, OUTPUT_DEFAULT), m_drakvuf(drakvuf)
{
    if (!is_supported(drakvuf))
        throw -1;

    if (!drakvuf_get_kernel_struct_members_array_rva(drakvuf, offset_names, __OFFSET_MAX, offsets.data()))
    {
        PRINT_DEBUG("[USERHOOK] Failed to get kernel struct member offsets\n");
#ifndef LIBUSERMODE_USE_INJECTION
        throw -1;
#endif
    }

    this->copy_virt_mem_va =
        drakvuf_kernel_symbol_to_va(drakvuf, "MmCopyVirtualMemory");

    breakpoint_in_system_process_searcher bp;
    if (!register_trap(nullptr, protect_virtual_memory_hook_cb, bp.for_syscall_name("NtProtectVirtualMemory"), nullptr, UNLIMITED_TTL) ||
        !register_trap(nullptr, map_view_of_section_hook_cb, bp.for_syscall_name("NtMapViewOfSection"), nullptr, UNLIMITED_TTL) ||
#ifndef LIBUSERMODE_USE_INJECTION
        !register_trap(nullptr, system_service_handler_hook_cb, bp.for_syscall_name("KiSystemServiceHandler"), nullptr, UNLIMITED_TTL) ||
#endif
        !register_trap(nullptr, clean_process_address_space_hook_cb, bp.for_syscall_name("MmCleanProcessAddressSpace"), nullptr, UNLIMITED_TTL) ||
        !register_trap(nullptr, copy_on_write_handler, bp.for_syscall_name("MiCopyOnWrite"), nullptr, UNLIMITED_TTL))
        throw -1;
}

userhook::~userhook()
{
    for (auto& it : this->loaded_dlls)
    {
        for (auto& loaded_dll : it.second)
        {
            for (auto& target : loaded_dll.targets)
            {
                if (target.state == HOOK_OK)
                {
                    drakvuf_remove_trap(m_drakvuf, target.trap, wrap_delete);
                }
            }
        }
    }

    for (auto trap : running_traps)
        delete trap;
    running_traps.clear();

    for (auto trap : running_rh_traps)
        rh_data_t::free_trap(trap);
    running_rh_traps.clear();
}

void drakvuf_register_usermode_callback(drakvuf_t drakvuf, usermode_cb_registration* reg)
{
    userhook::get_instance(drakvuf).register_plugin(drakvuf, *reg);
}

bool drakvuf_request_usermode_hook(drakvuf_t drakvuf, const dll_view_t* dll, const plugin_target_config_entry_t* target, callback_t callback, void* extra)
{
    userhook::get_instance(drakvuf).request_usermode_hook(drakvuf, dll, target, callback, extra);
    return true;
}

std::optional<HookActions> get_hook_actions(const std::string& str)
{
    if (str == "log")
    {
        return HookActions::empty().set_log();
    }
    else if (str == "log+stack")
    {
        return HookActions::empty().set_log().set_stack();
    }

    return std::nullopt;
}

namespace
{
std::optional<std::string> try_parse_token(std::stringstream& ss)
{
    const char SEPARATOR = ',';
    std::string result;
    if (!std::getline(ss, result, SEPARATOR) || result.empty())
    {
        return std::nullopt;
    }
    return result;
}

std::string parse_token(std::stringstream& ss)
{
    auto maybe_token = try_parse_token(ss);
    if (!maybe_token)
    {
        throw std::runtime_error{"Expected a token"};
    }
    return *maybe_token;
}

std::unique_ptr<ArgumentPrinter> make_arg_printer(
    const PrinterConfig& config,
    const std::string& type,
    const std::string& name)
{
    if (type == "lpstr" || type == "lpcstr" || type == "lpctstr")
    {
        return std::make_unique<AsciiPrinter>(name, config);
    }
    else if (type == "lpcwstr" || type == "lpwstr" || type == "bstr")
    {
        return std::make_unique<WideStringPrinter>(name, config);
    }
    else if (type == "punicode_string")
    {
        return std::make_unique<UnicodePrinter>(name, config);
    }
    else if (type == "pulong")
    {
        return std::make_unique<UlongPrinter>(name, config);
    }
    else if (type == "pulonglong")
    {
        return std::make_unique<UlongLongPrinter>(name, config);
    }
    else if (type == "lpvoid*")
    {
        return std::make_unique<PointerToPointerPrinter>(name, config);
    }
    else if (type == "refclsid" || type == "refiid")
    {
        return std::make_unique<GuidPrinter>(name, config);
    }
    else if (type == "binary16")
    {
        return std::make_unique<Binary16StringPrinter>(name, config);
    }

    return std::make_unique<ArgumentPrinter>(name, config);
}


std::vector<std::unique_ptr<ArgumentPrinter>> parse_arguments(
        const PrinterConfig& config,
        std::stringstream& ss)
{
    std::vector<std::unique_ptr<ArgumentPrinter>> argument_printers;

    for (size_t arg_idx = 0; ; arg_idx++)
    {
        auto maybe_arg = try_parse_token(ss);
        if (!maybe_arg) break;

        const std::string arg = *maybe_arg;
        std::string arg_name;
        std::string arg_type;
        const auto pos = arg.find_first_of(':');

        if (pos == std::string::npos)
        {
            arg_name = std::string("Arg") + std::to_string(arg_idx);
            arg_type = arg;
        }
        else
        {
            arg_name = arg.substr(0, pos);
            arg_type = arg.substr(pos + 1);
        }

        argument_printers.emplace_back(make_arg_printer(config, arg_type, arg_name));
    }
    return argument_printers;
}

plugin_target_config_entry_t parse_entry(
    std::stringstream& ss,
    PrinterConfig& config)
{
    plugin_target_config_entry_t entry{};

    entry.dll_name = parse_token(ss);
    entry.function_name = parse_token(ss);
    entry.type = HOOK_BY_NAME;

    std::string log_strategy_or_offset;
    std::string token = parse_token(ss);
    if (token == "clsid")
    {
        entry.clsid = parse_token(ss);
        log_strategy_or_offset = parse_token(ss);
    }
    else
    {
        log_strategy_or_offset = token;
    }

    std::optional<HookActions> actions = get_hook_actions(log_strategy_or_offset);
    if (!actions)
    {
        entry.type = HOOK_BY_OFFSET;
        try
        {
            entry.offset = std::stoull(log_strategy_or_offset, 0, 16);
        }
        catch (const std::logic_error& exc)
        {
            throw std::runtime_error{"Invalid offset"};
        }

        std::string strategy_name = parse_token(ss);
        actions = get_hook_actions(strategy_name);
        if (!actions)
            throw std::runtime_error{"Invalid hook action"};
    }

    entry.actions = *actions;
    entry.argument_printers = parse_arguments(config, ss);

    return entry;
}
} // namespace


void drakvuf_load_dll_hook_config(drakvuf_t drakvuf, const char* dll_hooks_list_path, bool print_no_addr, const hook_filter_t& hook_filter, wanted_hooks_t& wanted_hooks)
{
    PrinterConfig config{};
    config.print_no_addr = print_no_addr;

    if (!dll_hooks_list_path)
    {
        const auto log_and_stack = HookActions::empty().set_log().set_stack();
        // if the DLL hook list was not provided, we provide some simple defaults
        std::vector<std::unique_ptr<ArgumentPrinter>> arg_vec1;
        arg_vec1.push_back(std::make_unique<ArgumentPrinter>("wVersionRequired", config));
        arg_vec1.push_back(std::make_unique<ArgumentPrinter>("lpWSAData", config));
        plugin_target_config_entry_t e1("ws2_32.dll", "WSAStartup", log_and_stack, std::move(arg_vec1));

        std::vector<std::unique_ptr<ArgumentPrinter>> arg_vec2;
        arg_vec2.push_back(std::make_unique<ArgumentPrinter>("ExitCode", config));
        arg_vec2.push_back(std::make_unique<ArgumentPrinter>("Unknown", config));
        plugin_target_config_entry_t e2("ntdll.dll", "RtlExitUserProcess", log_and_stack, std::move(arg_vec2));

        if (!hook_filter(e1)) wanted_hooks.add_hook(std::move(e1));
        if (!hook_filter(e2)) wanted_hooks.add_hook(std::move(e2));
        return;
    }

    std::ifstream ifs(dll_hooks_list_path, std::ifstream::in);

    if (!ifs)
    {
        throw std::runtime_error{"Cannnot open DLL hook file"};
    }

    std::string line;
    for (size_t line_no = 1; std::getline(ifs, line); line_no++)
    {
        if (line.empty() || line[0] == '#')
            continue;

        try
        {
            std::stringstream ss(line);
            auto e = parse_entry(ss, config);
            if (!hook_filter(e)) wanted_hooks.add_hook(std::move(e));
        }
        catch (const std::runtime_error& exc)
        {
            std::stringstream ss;
            ss << "Invalid entry on line " << line_no << ": " << exc.what();

            // Rethrow exception
            throw std::runtime_error{ss.str()};
        }
    }
}

bool drakvuf_are_userhooks_supported(drakvuf_t drakvuf)
{
    return userhook::is_supported(drakvuf);
}

static bool dll_name_comparator(char x, char y)
{
    return std::toupper(x) == std::toupper(y);
}

void wanted_hooks_t::visit_hooks_for(const std::string& dll_name, std::function<void(const plugin_target_config_entry_t&)>&& visitor) const
{
    for (const auto& [pattern, wanted_hooks] : hooks)
    {
        if (std::search(dll_name.begin(), dll_name.end(), pattern.begin(), pattern.end(),
                dll_name_comparator) != dll_name.end())
        {
            std::for_each(std::begin(wanted_hooks), std::end(wanted_hooks), visitor);
        }
    }
}
