/*********************IMPORTANT DRAKVUF LICENSE TERMS***********************
 *                                                                         *
 * DRAKVUF (C) 2014-2020 Tamas K Lengyel.                                  *
 * Tamas K Lengyel is hereinafter referred to as the author.               *
 * This program is free software; you may redistribute and/or modify it    *
 * under the terms of the GNU General Public License as published by the   *
 * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
 * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
 * right to use, modify, and redistribute this software under certain      *
 * conditions.  If you wish to embed DRAKVUF technology into proprietary   *
 * software, alternative licenses can be aquired from the author.          *
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
 * User mode hooking module of MEMDUMP plugin.
 *
 * (1) Observes when a process is loading a new DLL through the side effects
 * of NtMapViewOfSection or NtProtectVirtualMemory being called.
 * (2) Finds the DLL export information and checks if it's fully readable,
 * if not, triggers a page fault to force system to load it into memory.
 * (3) Translates given export symbols to virtual addresses, checks if
 * the underlying memory is available (if not, again triggers page fault)
 * and finally adds a standard DRAKVUF trap.
 */

#include <fstream>
#include <sstream>
#include <map>
#include <string>

#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>
#include <libdrakvuf/private.h>
#include <libusermode/userhook.hpp>
#include <assert.h>

#include "memdump.h"
#include "private.h"



bool ssl_encrypt_packet_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info, memdump* plugin)
{
    // SECURITY_STATUS WINAPI SslEncryptPacket(
    //   _In_    NCRYPT_PROV_HANDLE hSslProvider,
    //   _Inout_ NCRYPT_KEY_HANDLE  hKey,
    //   _In_    PBYTE              *pbInput,
    //   _In_    DWORD              cbInput,
    //   _Out_   PBYTE              pbOutput,
    //   _In_    DWORD              cbOutput,
    //   _Out_   DWORD              *pcbResult,
    //   _In_    ULONGLONG          SequenceNumber,
    //   _In_    DWORD              dwContentType,
    //   _In_    DWORD              dwFlags
    // );
    fprintf(stderr, "[KOSTUS][>] ssl_encrypt_packet_cb()\n");

    addr_t ptx_addr = drakvuf_get_function_argument(drakvuf, info, 3);
    uint64_t ptx_len = drakvuf_get_function_argument(drakvuf, info, 4);

    char *buf = (char*)malloc(ptx_len);
    access_context_t ctx = {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = ptx_addr
    };
    vmi_lock_guard lg(drakvuf);
    if (VMI_SUCCESS != vmi_read(lg.vmi, &ctx, ptx_len, buf, nullptr)) {
        fprintf(stderr, "[KOSTUS][!] vmi_read failed\n");
        return 0;
    }

    // Print buf in hex format
    fprintf(stderr, "[KOSTUS][i] ptx (%lu bytes): \n", ptx_len);
    for (uint64_t i = 0; i < ptx_len; i++) {
        fprintf(stderr, "\\x%02x", buf[i]);
    }
    fprintf(stderr, "\n");

    fprintf(stderr, "[KOSTUS][<] ssl_encrypt_packet_cb()\n");
    return 1;
}

template<typename T>
struct ssl_decrypt_packet_params_t: public call_result_t<T>
{
    addr_t ssl_provider_handle_addr;
    addr_t key_handle_addr;
    addr_t pb_input;
    uint32_t cb_input;
    addr_t pb_output;
    uint32_t cb_output;
    addr_t pcb_result;
    uint64_t sequence_number;
    uint32_t flags;

    ssl_decrypt_packet_params_t(T* src) : call_result_t<T>(src), ssl_provider_handle_addr(), key_handle_addr(), pb_input(), cb_input(), pb_output(), cb_output(), pcb_result(), sequence_number(), flags() {}
};


static event_response_t ssl_decrypt_packet_ret_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    fprintf(stderr, "[KOSTUS][>] ssl_decrypt_packet_ret_cb()\n");

    auto params = get_trap_params<memdump, ssl_decrypt_packet_params_t<memdump>>(info);
    auto plugin = get_trap_plugin<memdump, ssl_decrypt_packet_params_t<memdump>>(info);
    if (!params || !plugin) {
        fprintf(stderr, "[KOSTUS][!] !params || !plugin\n");
        return VMI_EVENT_RESPONSE_NONE;
    }

    if (!params->verify_result_call_params(info, drakvuf_get_current_thread(drakvuf, info))) {
        fprintf(stderr, "[KOSTUS][!] verify_result_call_params failed\n");
        return VMI_EVENT_RESPONSE_NONE;
    }
    // [KOSTUS] dziala do tego miejsca

    plugin->destroy_trap(drakvuf, info->trap);
    // [KOSTUS] tu juz nie dziala

    // access_context_t ctx = {
    //     .translate_mechanism = VMI_TM_PROCESS_DTB,
    //     .dtb = info->regs->cr3,
    //     .addr = params->pcb_result
    // };
    // // vmi_lock_guard lg(drakvuf);
    // vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);

    // uint32_t ptx_length = 0;
    // if (VMI_SUCCESS != vmi_read(vmi, &ctx, sizeof(ptx_length), &ptx_length, nullptr)) {
    //     fprintf(stderr, "[KOSTUS][!] failed to read ptx_length\n");
    //     drakvuf_release_vmi(drakvuf);
    //     fprintf(stderr, "[KOSTUS][<] ssl_decrypt_packet_ret_cb()\n");
    // }
    // fprintf(stderr, "[KOSTUS][i] ptx_length: 0x%x\n", ptx_length);

    // char *ptx = (char*) malloc(ptx_length);
    // if (!ptx) {
    //     fprintf(stderr, "[KOSTUS][i] malloc failed\n");
    //     drakvuf_release_vmi(drakvuf);
    //     fprintf(stderr, "[KOSTUS][<] ssl_decrypt_packet_ret_cb()\n");
    // }
    // ctx.addr = params->pb_output;
    // if (VMI_SUCCESS != vmi_read(vmi, &ctx, ptx_length, ptx, nullptr)) {
    //     fprintf(stderr, "[KOSTUS][!] failed to read ptx\n");
    //     drakvuf_release_vmi(drakvuf);
    //     fprintf(stderr, "[KOSTUS][<] ssl_decrypt_packet_ret_cb()\n");
    // }
    // drakvuf_release_vmi(drakvuf);

    // fprintf(stderr, "[KOSTUS] ptx: ");
    // for (uint32_t i = 0; i < ptx_length; i++) {
    //     fprintf(stderr, "\\x%02x", ptx[i]);
    // }
    // fprintf(stderr, "\n");


    fprintf(stderr, "[KOSTUS][<] ssl_decrypt_packet_ret_cb()\n");
    return VMI_EVENT_RESPONSE_NONE;
}


bool ssl_decrypt_packet_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    // SECURITY_STATUS WINAPI SslDecryptPacket(
    // _In_    NCRYPT_PROV_HANDLE hSslProvider,
    // _Inout_ NCRYPT_KEY_HANDLE  hKey,
    // _In_    PBYTE              *pbInput,
    // _In_    DWORD              cbInput,
    // _Out_   PBYTE              pbOutput,
    // _In_    DWORD              cbOutput,
    // _Out_   DWORD              *pcbResult,
    // _In_    ULONGLONG          SequenceNumber,
    // _In_    DWORD              dwFlags
    // );
    fprintf(stderr, "[KOSTUS][>] ssl_decrypt_packet_cb()\n");

    auto plugin = get_trap_plugin<memdump>(info);
    if (!plugin) {
        fprintf(stderr, "[KOSTUS][!] get_trap_plugin failed\n");
        return 0;
    }
    auto trap = plugin->register_trap<memdump, ssl_decrypt_packet_params_t<memdump>>(
        drakvuf,
        info,
        plugin,
        ssl_decrypt_packet_ret_cb,
        breakpoint_by_dtb_searcher());
    if (!trap) {
        fprintf(stderr, "[KOSTUS][!] register_trap failed\n");
        return 0;
    }

    auto params = get_trap_params<memdump, ssl_decrypt_packet_params_t<memdump>>(trap);
    if (!params) {
        fprintf(stderr, "[KOSTUS][!] get_trap_params failed\n");
        plugin->destroy_trap(drakvuf, trap);
        return 0;
    }
    params->set_result_call_params(info, drakvuf_get_current_thread(drakvuf, info));
    params->ssl_provider_handle_addr = drakvuf_get_function_argument(drakvuf, info, 1);
    params->key_handle_addr = drakvuf_get_function_argument(drakvuf, info, 2);
    params->pb_input = drakvuf_get_function_argument(drakvuf, info, 3);
    params->cb_input = drakvuf_get_function_argument(drakvuf, info, 4);
    params->pb_output = drakvuf_get_function_argument(drakvuf, info, 5);
    params->cb_output = drakvuf_get_function_argument(drakvuf, info, 6);
    params->pcb_result = drakvuf_get_function_argument(drakvuf, info, 7);
    params->sequence_number = drakvuf_get_function_argument(drakvuf, info, 8);
    params->flags = drakvuf_get_function_argument(drakvuf, info, 9);

    fprintf(stderr, "[KOSTUS][<] ssl_decrypt_packet_cb()\n");
    return 1;
}


static event_response_t usermode_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info* info)
{
    hook_target_entry_t* target = (hook_target_entry_t*)info->trap->data;

    // TODO check thread_id and cr3?
    if (target->pid != info->proc_data.pid)
        return VMI_EVENT_RESPONSE_NONE;

    if (target->target_name == "AssemblyNative::LoadImage")
        dotnet_assembly_native_load_image_cb(drakvuf, info, (memdump*)target->plugin);


    if (target->target_name == "SslEncryptPacket")
        ssl_encrypt_packet_cb(drakvuf, info, (memdump*)target->plugin);
    if (target->target_name == "SslDecryptPacket")
        ssl_decrypt_packet_cb(drakvuf, info);

    return VMI_EVENT_RESPONSE_NONE;

    dump_from_stack(drakvuf, info, (memdump*)target->plugin);
    return VMI_EVENT_RESPONSE_NONE;
}

static void on_dll_discovered(drakvuf_t drakvuf, const dll_view_t* dll, void* extra)
{
    memdump* plugin = (memdump*)extra;

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    unicode_string_t* dll_name = drakvuf_read_unicode_va(vmi, dll->mmvad.file_name_ptr, 0);

    if (dll_name && dll_name->contents)
    {
        for (auto const& wanted_hook : plugin->wanted_hooks)
        {
            if (strstr((const char*)dll_name->contents, wanted_hook.dll_name.c_str()) != 0)
            {
                drakvuf_request_usermode_hook(drakvuf, dll, &wanted_hook, usermode_hook_cb, plugin);
            }
        }
    }

    if (dll_name)
        vmi_free_unicode_str(dll_name);

    drakvuf_release_vmi(drakvuf);
}

static void on_dll_hooked(drakvuf_t drakvuf, const dll_view_t* dll, const std::vector<hook_target_view_t>& targets, void* extra)
{
    PRINT_DEBUG("[MEMDUMP] DLL hooked - done\n");
}

void memdump::userhook_init(drakvuf_t drakvuf, const memdump_config* c, output_format_t output)
{
    try
    {
        drakvuf_load_dll_hook_config(drakvuf, c->dll_hooks_list, &this->wanted_hooks);
    }
    catch (int e)
    {
        fprintf(stderr, "Malformed DLL hook configuration for MEMDUMP plugin\n");
        throw -1;
    }

    auto it = std::begin(this->wanted_hooks);

    while (it != std::end(this->wanted_hooks))
    {
        if ((*it).log_strategy != "stack" && (*it).log_strategy != "log+stack")
            it = this->wanted_hooks.erase(it);
        else
            ++it;
    }

    for (auto it2 = std::begin(this->wanted_hooks); it2 != std::end(this->wanted_hooks); it2++) {
        fprintf(stderr, "[KOSTUS] Setting hook for: %s\n", it2->function_name.c_str());
    }

    if (this->wanted_hooks.empty())
    {
        // don't load this part of plugin if there is nothing to do
        return;
    }

    usermode_cb_registration reg = {
        .pre_cb = on_dll_discovered,
        .post_cb = on_dll_hooked,
        .extra = (void *)this
    };

    usermode_reg_status_t status = drakvuf_register_usermode_callback(drakvuf, &reg);

    if (status == USERMODE_ARCH_UNSUPPORTED ||
        status == USERMODE_OS_UNSUPPORTED) {
        PRINT_DEBUG("[MEMDUMP] Usermode hooking is not supported on this architecture/bitness/os version, these features will be disabled\n");
    } else if (status != USERMODE_REGISTER_SUCCESS) {
        PRINT_DEBUG("[MEMDUMP] Failed to subscribe to libusermode\n");
        throw -1;
    }
}

void memdump::setup_dotnet_hooks(drakvuf_t drakvuf, const char* dll_name, const char* profile)
{
    PRINT_DEBUG("%s profile found, will setup usermode hooks for .NET\n", dll_name);

    auto profile_json = json_object_from_file(profile);
    if (!profile_json)
    {
        PRINT_DEBUG("[MEMDUMP] Failed to load JSON debug info for %s\n", dll_name);
        return;
    }

    addr_t func_rva = 0;
    // LoadImage_1 => AssemblyNative::LoadImage
    if (!json_get_symbol_rva(drakvuf, profile_json, "LoadImage_1", &func_rva))
    {
        PRINT_DEBUG("[MEMDUMP] Failed to find LoadImage_1 (AssemblyNative::LoadImage) RVA in json for %s", dll_name);
        return;
    }

    plugin_target_config_entry_t entry;
    entry.function_name = "AssemblyNative::LoadImage";
    entry.dll_name = dll_name;
    entry.type = HOOK_BY_OFFSET;
    entry.offset = func_rva;
    entry.log_strategy = "log+stack";
    this->wanted_hooks.push_back(std::move(entry));
}


void memdump::userhook_destroy()
{

}
