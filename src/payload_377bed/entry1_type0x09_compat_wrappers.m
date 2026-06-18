// Compatibility wrappers for names that were cleaned up during manual analysis.
__int64 __fastcall kwrite_with_retry(struct_krwCtx *krwCtx, __int64 address, const void *buf, mach_vm_size_t bufSize)
{
  return kwritebuf_last_arg_1(krwCtx, address, buf, bufSize);
}
bool __fastcall kreadbuf_last_0(struct_krwCtx *krwCtx, unsigned __int64 addr, mach_vm_size_t size, void *outBuf)
{
  return kreadbuf_0(krwCtx, addr, size, outBuf);
}
bool __fastcall kread_physmap_decorated(struct_krwCtx *krwCtx, unsigned __int64 vaddr, unsigned __int64 *out)
{
  return kread64(krwCtx, vaddr, out);
}
//__int64 __fastcall kread_u32_value(__int64 a1, unsigned __int64 a2) { return kread_u32_value(krwCtx, a2); }
bool __fastcall kwrite64_last_arg(struct_krwCtx *krwCtx, mach_vm_address_t address, __int64 newValue, int whatIsThis)
{
  return this_is_the_kwrite64(krwCtx, address, newValue, whatIsThis);
}
bool __fastcall krw_task_for_pid(struct_krwCtx *krwCtx, int a2, mach_port_name_t *a3) { return real_task_for_pid(krwCtx, a2, a3); }
bool __fastcall krw_task_for_pid_or_name_ret_ptr(struct_krwCtx *krwCtx, int victim_pid, const char *victim_process_name, mach_port_name_t *out_task)
{
  return real_task_for_pid_or_name(krwCtx, victim_pid, victim_process_name, out_task);
}
__int64 __fastcall kreadptr(struct_krwCtx *krwCtx, __int64 addr) { return get_task_struct_field_offset(krwCtx, addr); }
__int64 __fastcall driver_cmd_setup_untethered_persistence_maybe(struct_krwCtx *krwCtx, int a2)
{
  return setup_untethered_persistence_maybe(krwCtx, a2);
}
unsigned __int64 __fastcall krw_xpac_vaddr_2(struct_krwCtx *krwCtx, __int64 a2) { return maybe_sptm_translate_kaddr(krwCtx, a2); }
__int64 __fastcall nullsub_1(uint64_t a1) { return a1; }
__int64 __fastcall nullsub_2(uint64_t a1) { return a1; }
__int64 __fastcall macho_read_u64_thunk(uint64_t a1, uint64_t a2) { return macho_read_u64((__int64 *)a1, (__int64 *)a2); }

__int64 j___get_cpu_capabilities(void) { return _get_cpu_capabilities(); }
__int64 __fastcall j__fileport_makeport(int a1, mach_port_t *a2) { return fileport_makeport(a1, a2); }
int __fastcall j__fileport_makefd(mach_port_t port) { return fileport_makefd(port); }
