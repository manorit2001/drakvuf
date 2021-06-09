#include "linux_utils.h"

void free_memtraps(injector_t injector)
{
  GSList* loop = injector->memtraps;
  injector->memtraps = NULL;

  while (loop)
  {
    drakvuf_remove_trap(injector->drakvuf, loop->data, (drakvuf_trap_free_t)free);
    loop = loop->next;
  }
  g_slist_free(loop);
}

void free_injector(injector_t injector)
{
  if (!injector) return;

  PRINT_DEBUG("Injector freed\n");

  free_memtraps(injector);

  g_free((void*)injector->payload);
  g_free((void*)injector);
}

void print_stack(drakvuf_t drakvuf, drakvuf_trap_info_t* info){
  PRINT_DEBUG("\nRSP: %lx\n", info->regs->rsp);
  PRINT_DEBUG("Stack");
  vmi_instance_t vmi = drakvuf_lock_and_get_vmi(drakvuf);
  for(int i=0;i<256;i++){
    ACCESS_CONTEXT(ctx,
        .translate_mechanism = VMI_TM_PROCESS_PID,
        .pid = info->proc_data.pid,
        .addr = (info->regs->rsp - 512 + i*8)
        );
    addr_t val = 0;
    vmi_read_64(vmi, &ctx, &val);
    if((i%4)==0)
      PRINT_DEBUG("\n%016lx:", info->regs->rsp - 512 + (i/4)*32);
    PRINT_DEBUG(" %016lx", val);
  }
  PRINT_DEBUG("\n\n");
  drakvuf_release_vmi(drakvuf);
}

static char *repeatStr (const char *str, size_t count) {
  if (count == 0) return NULL;
  char *ret = malloc (strlen (str) * count + count);
  if (ret == NULL) return NULL;
  strcpy (ret, str);
  while (--count > 0) {
    strcat (ret, " ");
    strcat (ret, str);
  }
  return ret;
}

void print_registers(drakvuf_trap_info_t* info){
  const char *fmt_base = "%s:\t%016lx\n";
  char *fmt= repeatStr(fmt_base, 24);
  PRINT_DEBUG(fmt,
      "rax",    info->regs->rax,
      "rcx",    info->regs->rcx,
      "rdx",    info->regs->rdx,
      "rbx",    info->regs->rbx,
      "rsp",    info->regs->rsp,
      "rbp",    info->regs->rbp,
      "rsi",    info->regs->rsi,
      "rdi",    info->regs->rdi,
      "r8",     info->regs->r8,
      "r9",     info->regs->r9,
      "r10",    info->regs->r10,
      "r11",    info->regs->r11,
      "r12",    info->regs->r12,
      "r13",    info->regs->r13,
      "r14",    info->regs->r14,
      "r15",    info->regs->r15,
      "rflags", info->regs->rflags,
      "dr6",    info->regs->dr6,
      "dr7",    info->regs->dr7,
      "rip",    info->regs->rip,
      "cr0",    info->regs->cr0,
      "cr2",    info->regs->cr2,
      "cr3",    info->regs->cr3,
      "cr4",    info->regs->cr4
        );
  g_free((void*)fmt);


}

