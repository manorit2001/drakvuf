/*********************IMPORTANT DRAKVUF LICENSE TERMS**********************
 *                                                                         *
 * DRAKVUF (C) 2014-2021 Tamas K Lengyel.                                  *
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

#include "linux_utils.h"

static event_response_t linux_injector_int3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info);

static bool setup_linux_int3_trap(injector_t injector, drakvuf_trap_info_t* info, addr_t bp_addr)
{
    injector->bp.type = BREAKPOINT;
    injector->bp.name = "entry";
    injector->bp.cb = linux_injector_int3_cb;
    injector->bp.data = injector;
    injector->bp.breakpoint.lookup_type = LOOKUP_DTB;
    injector->bp.breakpoint.dtb = info->regs->cr3;
    injector->bp.breakpoint.addr_type = ADDR_VA;
    injector->bp.breakpoint.addr = bp_addr;
    injector->bp.ttl = UNLIMITED_TTL;
    injector->bp.ah_cb = NULL;

    return drakvuf_add_trap(injector->drakvuf, &injector->bp);
}

static event_response_t wait_for_target_linux_process_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    PRINT_DEBUG("CR3 changed to 0x%" PRIx64 ". TID: %u PID: %u PPID: %u\n",
        info->regs->cr3, info->proc_data.tid, info->proc_data.pid, info->proc_data.ppid);

    if (info->proc_data.pid != injector->target_pid || (uint32_t)info->proc_data.tid != injector->target_tid)
    {
        return 0;
    }

    PRINT_DEBUG("INFO Rip is 0x%lx \n", info->regs->rip);

    if (setup_linux_int3_trap(injector, info, info->regs->rip))
    {
        // Unsubscribe from the CR3 trap
        drakvuf_remove_trap(drakvuf, info->trap, NULL);
    }
    else
        PRINT_DEBUG("Failed to trap trapframe return address\n");

    return 0;
}

static event_response_t wait_for_process_in_userspace(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    PRINT_DEBUG("INT3 Callback @ 0x%lx. CR3 0x%lx.\n", info->regs->rip, info->regs->cr3);
    PRINT_DEBUG("RAX: 0x%lx\n", info->regs->rax);
    PRINT_DEBUG("RIP: 0x%lx, BPADDR: 0x%lx\n", info->regs->rip, info->trap->breakpoint.addr);
    if (info->regs->rip != info->trap->breakpoint.addr)
    {
        return 0;
    }
    injector_t injector = info->trap->data;

    char *shellcode= "\x05\x0f\x00\x00";

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = info->proc_data.pid,
        .addr = info->regs->rip
    );
    size_t bytes_written = 0;
    size_t bytes_read = 0;
    void *buf = g_try_malloc0(sizeof(shellcode));
    vmi_read(vmi, &ctx, sizeof(shellcode), buf, &bytes_read);
    vmi_write(vmi, &ctx, sizeof(shellcode), shellcode, &bytes_written);

    memcpy(&injector->saved_regs, info->regs, sizeof(x86_registers_t));

    registers_t regs;
    vmi_get_vcpuregs(vmi, &regs, info->vcpu);
    drakvuf_release_vmi(drakvuf);

    regs.x86.rax = 60;
    regs.x86.rdi = 1337;
    drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &regs);

    vmi = drakvuf_lock_and_get_vmi(drakvuf);
    vmi_write(vmi, &ctx, bytes_read, buf , &bytes_written);

    g_free((void*)buf);

    drakvuf_release_vmi(drakvuf);
    drakvuf_set_vcpu_gprs(drakvuf, info->vcpu, &injector->saved_regs);

    // Unexpected state
    drakvuf_remove_trap(drakvuf, info->trap, NULL);
    injector->rc = INJECTOR_SUCCEEDED;
    //drakvuf_interrupt(drakvuf, SIGDRAKVUFERROR);
    //memcpy(info->regs, &injector->saved_regs, sizeof(x86_registers_t));
    g_free((void*)injector->int3_trap);
    return VMI_EVENT_RESPONSE_SET_REGISTERS;
}

static bool setup_linux_int3_trap_in_userspace(injector_t injector, drakvuf_trap_info_t* info, addr_t bp_addr)
{
    drakvuf_trap_t* new_trap = g_try_malloc0(sizeof(drakvuf_trap_t));
    new_trap->type = BREAKPOINT;
    new_trap->name = "entry";
    new_trap->breakpoint.lookup_type = LOOKUP_PID;
    new_trap->breakpoint.pid = info->proc_data.tid;
    new_trap->breakpoint.addr_type = ADDR_VA;
    new_trap->breakpoint.addr = bp_addr;
    new_trap->cb = wait_for_process_in_userspace;
    new_trap->data = injector;
    new_trap->ttl = UNLIMITED_TTL;

    if (!drakvuf_add_trap(injector->drakvuf, new_trap)){
        g_free((void *)new_trap);
        return false;
    }

    injector->int3_trap = new_trap;
    return true;
}

static event_response_t linux_injector_int3_cb(drakvuf_t drakvuf, drakvuf_trap_info_t* info)
{
    injector_t injector = info->trap->data;

    PRINT_DEBUG("INT3 Callback @ 0x%lx. CR3 0x%lx.\n", info->regs->rip, info->regs->cr3);
    PRINT_DEBUG("Pid: %u|%u, Tid: %u|%u \n", info->proc_data.pid, injector->target_pid, info->proc_data.tid, injector->target_tid);
    // pid is thread group id in linux, and tid is thread id
    if ((uint32_t)info->proc_data.tid == injector->target_tid && info->proc_data.pid == injector->target_pid)
    {
        PRINT_DEBUG("SUCCESS Pid: %u|%u, Tid: %u|%u \n", info->proc_data.pid, injector->target_pid, info->proc_data.tid, injector->target_tid);

        // kernel mode
        // rcx -> value of rip in usermode
        addr_t bp_addr = info->regs->rcx;
        injector->target_rip = bp_addr;
        PRINT_DEBUG("Usermode Breakpoint addr using rcx: %lx \n", bp_addr);

        // setting TRAP on BP addr -> rcx -> rip
        if (setup_linux_int3_trap_in_userspace(injector, info, bp_addr))
        {
            PRINT_DEBUG("Got return address 0x%lx and it's now trapped in usermode!\n", bp_addr);
            // Unsubscribe from the CR3 trap
            drakvuf_remove_trap(drakvuf, info->trap, NULL);
        }
        else{

            PRINT_DEBUG("Failed to trap trapframe return address using rcx\n");

            // otherwise acquire it from stack here
            bp_addr = drakvuf_get_function_return_address(drakvuf, info);
            injector->target_rip = bp_addr;
            PRINT_DEBUG("Usermode Breakpoint addr function return address: %lx \n", bp_addr);

            if (setup_linux_int3_trap_in_userspace(injector, info, bp_addr))
            {
                PRINT_DEBUG("Got return address 0x%lx and it's now trapped in usermode!\n", bp_addr);
                // Unsubscribe from the CR3 trap
                drakvuf_remove_trap(drakvuf, info->trap, NULL);
            }
            else {
              PRINT_DEBUG("Failed to trap return address using both methods\n");
            }

        }
    }
    return 0;
}

static bool is_interrupted(drakvuf_t drakvuf, void* data)
{
    UNUSED(data);
    return drakvuf_is_interrupted(drakvuf);
}

static bool inject(drakvuf_t drakvuf, injector_t injector)
{
    injector->hijacked = 0;
    injector->status = STATUS_NULL;

    drakvuf_trap_t trap =
    {
        .type = REGISTER,
        .reg = CR3,
        .cb = wait_for_target_linux_process_cb,
        .data = injector
    };

    if (!drakvuf_add_trap(drakvuf, &trap))
        return false;

    if (!drakvuf_is_interrupted(drakvuf))
    {
        const char* method = injector->method == INJECT_METHOD_TERMINATEPROC ? "termination" : "injection";
        PRINT_DEBUG("Starting %s loop\n", method);
        drakvuf_loop(drakvuf, is_interrupted, NULL);
        PRINT_DEBUG("Finished %s loop\n", method);
    }

    if (SIGDRAKVUFTIMEOUT == drakvuf_is_interrupted(drakvuf))
        injector->rc = INJECTOR_TIMEOUTED;

    free_memtraps(injector);

    drakvuf_remove_trap(drakvuf, &trap, NULL);
    return true;
}

static bool load_file_to_memory(addr_t* output, size_t* size, const char* file)
{
    long payload_size = 0;
    unsigned char* data = NULL;
    FILE* fp = fopen(file, "rb");

    if (!fp)
        return false;

    // obtain file size:
    fseek (fp, 0, SEEK_END);
    if ( (payload_size = ftell (fp)) < 0 )
    {
        fclose(fp);
        return false;
    }
    rewind (fp);

    data = g_try_malloc0(payload_size);
    if ( !data )
    {
        fclose(fp);
        return false;
    }

    if ( (size_t)payload_size != fread(data, 1, payload_size, fp))
    {
        g_free(data);
        fclose(fp);
        return false;
    }

    *output = (addr_t)data;
    *size = payload_size;

    PRINT_DEBUG("Size of file read: %lu\n", payload_size);

    fclose(fp);

    return true;
}

static void print_injection_info(output_format_t format, const char* file, injector_t injector)
{
    gint64 t = g_get_real_time();
    char* arguments = (char*)g_malloc0(1);

    for (int i=0; i<injector->args_count; i++)
    {
        char* tmp = g_strconcat(arguments, injector->args[i], " ", NULL);
        g_free(arguments);
        arguments = tmp;
    }

    switch (injector->result)
    {
        case INJECT_RESULT_SUCCESS:
            switch (format)
            {
                case OUTPUT_CSV:
                    printf("inject," FORMAT_TIMEVAL ",Success,%u,\"%s\",\"%s\",%u,%u\n",
                        UNPACK_TIMEVAL(t), injector->target_pid, file, arguments, injector->pid, injector->tid);
                    break;

                case OUTPUT_KV:
                    printf("inject Time=" FORMAT_TIMEVAL ",Status=Success,PID=%u,ProcessName=\"%s\",Arguments=\"%s\",InjectedPid=%u,InjectedTid=%u\n",
                        UNPACK_TIMEVAL(t), injector->target_pid, file, arguments, injector->pid, injector->tid);
                    break;

                case OUTPUT_JSON:
                    printf( "{"
                        "\"Inject TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
                        "\"Status\" : \"Success\","
                        "\"Pid\" : %d,"
                        "\"Injected File\": \"%s\","
                        "\"Arguments\": \"%s\","
                        "\"Injected Pid\": %u,"
                        "\"Injected Tid\": %u,"
                        "\"Method\" : %d"
                        "}\n",
                        UNPACK_TIMEVAL(t),
                        injector->target_pid,
                        file,
                        arguments,
                        injector->pid,
                        injector->tid,
                        injector->method);
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " STATUS:SUCCESS PID:%u FILE:\"%s\" ARGUMENTS:\"%s\" INJECTED_PID:%u INJECTED_TID:%u\n",
                        UNPACK_TIMEVAL(t), injector->target_pid, file, arguments, injector->pid, injector->tid);
                    break;
            }
            break;
        case INJECT_RESULT_TIMEOUT:
            switch (format)
            {
                case OUTPUT_CSV:
                    printf("inject," FORMAT_TIMEVAL ",Timeout\n", UNPACK_TIMEVAL(t));
                    break;

                case OUTPUT_KV:
                    printf("inject Time=" FORMAT_TIMEVAL ",Status=Timeout\n", UNPACK_TIMEVAL(t));
                    break;

                case OUTPUT_JSON:
                    printf( "{"
                        "\"Inject TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
                        "\"Status\" : \"Timeout\""
                        "}\n",
                        UNPACK_TIMEVAL(t));
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " STATUS:Timeout\n", UNPACK_TIMEVAL(t));
                    break;
            }
            break;
        case INJECT_RESULT_CRASH:
            switch (format)
            {
                case OUTPUT_CSV:
                    printf("inject," FORMAT_TIMEVAL ",Crash\n", UNPACK_TIMEVAL(t));
                    break;

                case OUTPUT_KV:
                    printf("inject Time=" FORMAT_TIMEVAL ",Status=Crash\n", UNPACK_TIMEVAL(t));
                    break;

                case OUTPUT_JSON:
                    printf( "{"
                        "\"Inject TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
                        "\"Status\" : \"Crash\""
                        "}\n",
                        UNPACK_TIMEVAL(t));
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " STATUS:Crash\n", UNPACK_TIMEVAL(t));
                    break;
            }
            break;
        case INJECT_RESULT_PREMATURE:
            switch (format)
            {
                case OUTPUT_CSV:
                    printf("inject," FORMAT_TIMEVAL ",PrematureBreak\n", UNPACK_TIMEVAL(t));
                    break;

                case OUTPUT_KV:
                    printf("inject Time=" FORMAT_TIMEVAL ",Status=PrematureBreak\n", UNPACK_TIMEVAL(t));
                    break;

                case OUTPUT_JSON:
                    printf( "{"
                        "\"Inject TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
                        "\"Status\" : \"PrematureBreak\""
                        "}\n",
                        UNPACK_TIMEVAL(t));
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " STATUS:PrematureBreak\n", UNPACK_TIMEVAL(t));
                    break;
            }
            break;
        case INJECT_RESULT_ERROR_CODE:
            switch (format)
            {
                case OUTPUT_CSV:
                    printf("inject," FORMAT_TIMEVAL ",Error,%d,\"%s\"\n",
                        UNPACK_TIMEVAL(t), injector->error_code.code, injector->error_code.string);
                    break;

                case OUTPUT_KV:
                    printf("inject Time=" FORMAT_TIMEVAL ",Status=Error,ErrorCode=%d,Error=\"%s\"\n",
                        UNPACK_TIMEVAL(t), injector->error_code.code, injector->error_code.string);
                    break;

                case OUTPUT_JSON:
                    printf( "{"
                        "\"Inject TimeStamp\" :" "\"" FORMAT_TIMEVAL "\","
                        "\"Status\" : \"Error\","
                        "\"Error Code\": %d,"
                        "\"Error\" : \"%s\""
                        "}\n",
                        UNPACK_TIMEVAL(t),
                        injector->error_code.code,
                        injector->error_code.string);
                    break;

                default:
                case OUTPUT_DEFAULT:
                    printf("[INJECT] TIME:" FORMAT_TIMEVAL " STATUS:Error ERROR_CODE:%d ERROR:\"%s\"\n",
                        UNPACK_TIMEVAL(t), injector->error_code.code, injector->error_code.string);
                    break;
            }
            break;
    }

    g_free(arguments);
}

static bool initialize_linux_injector_functions(injector_t injector)
{
    if (injector->method == INJECT_METHOD_SHELLCODE_LINUX)
    {
        PRINT_DEBUG("File is %s\n", injector->target_file);
        if ( !load_file_to_memory(&injector->payload, &injector->payload_size, injector->target_file) )
        {
            PRINT_DEBUG("Failed to load file into memory\n");
            return false;
        }
        PRINT_DEBUG("File address in memory %lx\n", injector->payload);
        PRINT_DEBUG("File size in memory %lx\n", injector->payload_size);
        return true;
    }
    return true;
}

injector_status_t injector_start_app_on_linux(
    drakvuf_t drakvuf,
    vmi_pid_t pid,
    uint32_t tid,
    const char* file,
    injection_method_t method,
    output_format_t format,
    int args_count,
    const char* args[])
{
    int rc = 0, i = 0;
    injector_t injector = (injector_t)g_try_malloc0(sizeof(struct injector));
    if (!injector)
    {
        printf("Injector NOT initialized \n");
        return 0;
    }
    injector->drakvuf = drakvuf;
    injector->target_pid = pid;  // Pid = Thread Group Id in Linux
    injector->target_tid = tid;
    injector->method = method;
    injector->target_file = file;
    char* file_name = g_strrstr(file, "/");
    injector->target_file_name = file_name ? file_name + 1 : file;
    injector->status = STATUS_NULL;
    injector->error_code.valid = false;
    injector->error_code.code = -1;
    injector->error_code.string = "<UNKNOWN>";
    injector->args_count = args_count;
    for (i=0; i<args_count; i++)
        injector->args[i] = args[i];

    if (!initialize_linux_injector_functions(injector))
    {
        PRINT_DEBUG("Unable to initialize injector functions\n");
        free_injector(injector);
        return 0;
    }

    if (inject(drakvuf, injector) && injector->rc)
    {
        injector->result = INJECT_RESULT_SUCCESS;
        print_injection_info(format, file, injector);
    }
    else
    {
        if (SIGDRAKVUFTIMEOUT == drakvuf_is_interrupted(drakvuf))
        {
            injector->result = INJECT_RESULT_TIMEOUT;
            print_injection_info(format, file, injector);
        }
        else if (SIGDRAKVUFCRASH == drakvuf_is_interrupted(drakvuf))
        {
            injector->result = INJECT_RESULT_CRASH;
            print_injection_info(format, file, injector);
        }
        else if (injector->error_code.valid)
        {
            injector->result = INJECT_RESULT_ERROR_CODE;
            print_injection_info(format, file, injector);
        }
        else
        {
            injector->result = INJECT_RESULT_PREMATURE;
            print_injection_info(format, file, injector);
        }
    }

    rc = injector->rc;
    PRINT_DEBUG("Finished with injection. Ret: %i.\n", rc);

    free_injector(injector);

    return rc;
}
