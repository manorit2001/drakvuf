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

#include <config.h>
#include <glib.h>
#include <inttypes.h>
#include <libvmi/libvmi.h>
#include <libvmi/peparse.h>
#include <assert.h>
#include <libdrakvuf/json-util.h>
#include <set>

#include "ipt.h"
#include "plugins/output_format.h"
#include "private.h"

std::set<uint64_t> gfns;


struct wtf_struct {
    ipt* plugin;
    addr_t rip;
};

template<typename T>
struct access_fault_result_t: public call_result_t<T>
{
    access_fault_result_t(T* src) : call_result_t<T>(src), fault_va() {}

    addr_t fault_va;
};

int frame = 0;

static event_response_t execute_faulted_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info) {
    struct wtf_struct *wtf_inst = (struct wtf_struct *)info->trap->data;
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    access_context_t ctx =
    {
        .translate_mechanism = VMI_TM_PROCESS_DTB,
        .dtb = info->regs->cr3,
        .addr = wtf_inst->rip
    };

    size_t bytes_read = 0;
    uint8_t pagebuf[4096] = {0,};

    vmi_read(vmi, &ctx, 4096, pagebuf, &bytes_read);

    char buf[128];
    sprintf(buf, "/tmp/frames/frame_%05d", frame);
    FILE *fp = fopen(buf, "wb");

    if (!fp)
    {
        printf("/tmp/frames doesnt exist?\n");
        drakvuf_release_vmi(drakvuf);
        return VMI_EVENT_RESPONSE_NONE;
    }

    fwrite(pagebuf, 1, bytes_read, fp);
    fclose(fp);

    uint64_t tsc = __rdtsc();

    mmvad_info_t mmvad;
    unicode_string_t* dll_name = nullptr;
    char *dll_name_str = nullptr;
    char wtf[] = "(null)";

    addr_t base_va = 0;
    addr_t end_va = 0;

    if (drakvuf_find_mmvad(drakvuf, info->proc_data.base_addr, wtf_inst->rip, &mmvad))
    {
        dll_name = drakvuf_read_unicode_va(vmi, mmvad.file_name_ptr, 0);
        dll_name_str = dll_name != nullptr ? (char *)dll_name->contents : nullptr;

        base_va = mmvad.starting_vpn << 12;
        end_va = ((mmvad.ending_vpn + 1) << 12) - 1;
    }

    if (!dll_name_str)
        dll_name_str = wtf;

    jsonfmt::print("execframe", drakvuf, info,
            keyval("FrameFile", fmt::Qstr(buf)),
            keyval("FrameVA", fmt::Xval(wtf_inst->rip)),
            keyval("TrapPA", fmt::Xval(info->trap_pa)),
            keyval("CR3", fmt::Xval(info->regs->cr3)),
            keyval("TSC", fmt::Nval(tsc)),
            keyval("VADName", fmt::Qstr(dll_name_str)),
            keyval("VADBase", fmt::Xval(base_va)),
            keyval("VADEnd", fmt::Xval(end_va))
            );

    if (dll_name)
        vmi_free_unicode_str(dll_name);

    frame++;

    PRINT_DEBUG("[MQWTF] Caught X on PA 0x%lx, frame VA %llx, CR3 %lx\n", info->trap_pa, (unsigned long long)info->regs->rip, info->regs->cr3);

    drakvuf_release_vmi(drakvuf);

    drakvuf_remove_trap(drakvuf, info->trap, nullptr);

    return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t mm_access_fault_return_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info) {
	auto data = get_trap_params<ipt, access_fault_result_t<ipt>>(info);
	if (!data || !data->plugin())
	{
		PRINT_DEBUG("ipt mm_access_fault invalid trap params!\n");
		drakvuf_remove_trap(drakvuf, info->trap, nullptr);
		return VMI_EVENT_RESPONSE_NONE;
	}

	if (!data->verify_result_call_params(info, drakvuf_get_current_thread(drakvuf, info)))
		return VMI_EVENT_RESPONSE_NONE;

	ipt* plugin = data->plugin();

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    page_info_t p_info = {};
    if (VMI_SUCCESS != vmi_pagetable_lookup_extended(vmi, info->regs->cr3, data->fault_va, &p_info)) {
        PRINT_DEBUG("[MEMDUMP] failed to lookup page info\n");
        drakvuf_release_vmi(drakvuf);
        return VMI_EVENT_RESPONSE_NONE;
    }

    jsonfmt::print("pagefault", drakvuf, info,
                   keyval("CR3", fmt::Xval(info->regs->cr3)),
                   keyval("VA", fmt::Xval(data->fault_va)),
                   keyval("PA", fmt::Xval(p_info.paddr))
    );

    struct wtf_struct *wtf_inst = (struct wtf_struct *)malloc(sizeof(struct wtf_struct));
	wtf_inst->plugin = plugin;
	wtf_inst->rip = ((data->fault_va >> 12) << 12);
	drakvuf_trap_t *wtf_trap = (drakvuf_trap_t *)malloc(sizeof(drakvuf_trap_t));

	wtf_trap->type = MEMACCESS;
	wtf_trap->memaccess.gfn = p_info.paddr >> 12;
	wtf_trap->memaccess.type = PRE;
	wtf_trap->memaccess.access = VMI_MEMACCESS_X;
	wtf_trap->data = wtf_inst; // FIXME memleak
	wtf_trap->cb = execute_faulted_cb;
	wtf_trap->name = nullptr;

    drakvuf_add_trap(drakvuf, wtf_trap);
	PRINT_DEBUG("[MQWTF] Trap X on GFN 0x%lx\n", p_info.paddr >> 12);

	drakvuf_release_vmi(drakvuf);

	plugin->destroy_trap(drakvuf, info->trap);

	return VMI_EVENT_RESPONSE_NONE;
}

static event_response_t mm_access_fault_hook_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info) {
    addr_t fault_va = drakvuf_get_function_argument(drakvuf, info, 2);
    // printf("[MQWTF] MmAccessFault(%d, %lx)\n", info->proc_data.pid, fault_va);

    if (fault_va & (1ULL << 63))
    {
        PRINT_DEBUG("[MQWTF] Don't trap in kernel %d %lx\n", info->proc_data.pid, fault_va);
        return VMI_EVENT_RESPONSE_NONE;
    }

    auto plugin = get_trap_plugin<ipt>(info);
    if (!plugin)
        return VMI_EVENT_RESPONSE_NONE;

    auto trap = plugin->register_trap<ipt, access_fault_result_t<ipt>>(
            drakvuf,
            info,
            plugin,
            mm_access_fault_return_hook_cb,
            breakpoint_by_pid_searcher());
    if (!trap)
        return VMI_EVENT_RESPONSE_NONE;

    auto data = get_trap_params<ipt, access_fault_result_t<ipt>>(trap);
    if (!data)
    {
        plugin->destroy_plugin_params(plugin->detach_plugin_params(trap));
        return VMI_EVENT_RESPONSE_NONE;
    }

    data->set_result_call_params(info, drakvuf_get_current_thread(drakvuf, info));
    data->fault_va = fault_va;

    return VMI_EVENT_RESPONSE_NONE;
}

ipt::ipt(drakvuf_t drakvuf, const ipt_config* c, output_format_t output)
    : pluginex(drakvuf, output)
{
    breakpoint_in_system_process_searcher bp;

    if (!register_trap<ipt>(drakvuf, nullptr, this, mm_access_fault_hook_cb, bp.for_syscall_name("MmAccessFault")))
    {
        throw -1;
    }
}
