//----- (000000000001F07C) ----------------------------------------------------
__int64 __fastcall mach_vm_page_info_query_0(vm_map_read_t a1, mach_vm_address_t a2, uint64_t *a3)
{
  mach_msg_type_number_t infoCnt; // [xsp+Ch] [xbp-34h] BYREF
  int info; // [xsp+10h] [xbp-30h] BYREF
  __int64 v7; // [xsp+18h] [xbp-28h]
  __int64 v8; // [xsp+20h] [xbp-20h]

  infoCnt = 8;
  if ( mach_vm_page_info(a1, a2, 1, &info, &infoCnt) )
    return 0;
  if ( a3 )
    *a3 = v8;
  return v7;
}

//----- (000000000001F0D8) ----------------------------------------------------
__int64 number_of_cpus()
{
  return (unsigned __int8)((unsigned int)j___get_cpu_capabilities() >> 0x10);
}
// 4103C: using guessed type __int64 j___get_cpu_capabilities(void);

//----- (000000000001F0F4) ----------------------------------------------------
unsigned __int64 comm_page_memory_size()
{
  unsigned __int64 result; // x0

  result = comm_page64_base_address();
  if ( result )
    return *(uint64_t *)(result + COMM_PAGE_MEMORY_SIZE_OFFSET);
  return result;
}

//----- (000000000001F114) ----------------------------------------------------
__int64 sub_get_page_size()
{
  host_t v0; // w0
  vm_size_t v2; // [xsp+8h] [xbp-8h] BYREF

  v0 = mach_host_self();
  if ( host_page_size(v0, &v2) )
    return 0;
  else
    return (unsigned int)v2;
}

//----- (000000000001F148) ----------------------------------------------------
__int64 __fastcall get_task_vm_info_1(task_name_t a1)
{
  mach_msg_type_number_t task_info_outCnt; // [xsp+4h] [xbp-17Ch] BYREF
  integer_t task_info_out[90]; // [xsp+8h] [xbp-178h] BYREF

  task_info_outCnt = 36;
  if ( task_info(a1, 0x16u, task_info_out, &task_info_outCnt) )
    return 0;
  else
    return (unsigned int)task_info_out[3];
}

//----- (000000000001F190) ----------------------------------------------------
__int64 get_page_size()
{
  int v0; // w8
  unsigned int StatusReg; // w9

  if ( dyldVersionNumber >= 900.0 )
  {
    v0 = 4095;
    StatusReg = _ReadStatusReg(ARM64_SYSREG(3, 3, 13, 0, 2));
  }
  else
  {
    v0 = 7;
    StatusReg = _ReadStatusReg(ARM64_SYSREG(3, 3, 13, 0, 3));
  }
  return v0 & StatusReg;
}

//----- (000000000001F1C8) ----------------------------------------------------
__int64 __fastcall get_task_memory_info(task_name_t a1, uint64_t *a2, uint64_t *a3)
{
  __int64 result; // x0
  __int64 v6; // x8
  mach_msg_type_number_t task_info_outCnt; // [xsp+4h] [xbp-18Ch] BYREF
  integer_t task_info_out[38]; // [xsp+8h] [xbp-188h] BYREF
  __int64 v9; // [xsp+A0h] [xbp-F0h]
  __int64 v10; // [xsp+A8h] [xbp-E8h]

  task_info_outCnt = 42;
  result = task_info(a1, 0x16u, task_info_out, &task_info_outCnt);
  if ( !(uint32_t)result )
  {
    if ( task_info_outCnt == 42 )
    {
      result = 0;
      v6 = v10;
      *a2 = v9;
      *a3 = v6;
    }
    else
    {
      return 4;
    }
  }
  return result;
}

//----- (000000000001F240) ----------------------------------------------------
unsigned __int64 __fastcall comm_page_get_cpu_family(uint32_t *cpuFamily)
{
  unsigned __int64 result; // x0

  result = comm_page64_base_address();
  if ( result )
  {
    *cpuFamily = *(uint32_t *)(result + COMM_PAGE_CPUFAMILY_OFFSET);
    return 1;
  }
  return result;
}

//----- (000000000001F274) ----------------------------------------------------
__int64 __fastcall alloc_buf_with_magic(unsigned int a1, uint64_t *a2)
{
  __int64 v2; // x19
  uint32_t *v5; // x0
  uint32_t *v6; // x22
  uint32_t *v7; // x0

  v2 = 708617;
  if ( a1 < 4 )
    return 708609;
  v5 = calloc(0x10u, 1u);
  if ( v5 )
  {
    v6 = v5;
    v7 = calloc(a1, 1u);
    *(uint64_t *)v6 = v7;
    if ( v7 )
    {
      v2 = 0;
      *v7 = 211;
      v6[2] = 4;
      v6[3] = a1;
      *a2 = v6;
    }
    else
    {
      free(v6);
    }
  }
  return v2;
}

//----- (000000000001F308) ----------------------------------------------------
__int64 __fastcall parse_load_command_entry(__int64 *a1, int a2, size_t __n, uint64_t *__src)
{
  __int64 result; // x0
  unsigned int v6; // w9
  unsigned int v7; // w9
  __int64 v8; // x10
  __int64 v9; // x9
  unsigned int v10; // w10
  unsigned int v11; // w8
  int v12; // w20

  result = 708609;
  if ( !BYTE3(__n) )
  {
    v6 = ((a2 & 0x7F000000u) - 0x1000000) >> 24;
    if ( v6 <= 0xB )
    {
      if ( ((1 << v6) & 0xC07) != 0 )
      {
        v7 = 4;
      }
      else if ( ((1 << v6) & 0x380) != 0 )
      {
        v7 = (__n + 7) & 0xFFFFFFFC;
      }
      else
      {
        if ( v6 != 3 )
          return result;
        v7 = 12;
      }
      v8 = *((unsigned int *)a1 + 2);
      if ( v7 > *((uint32_t *)a1 + 3) - (int)v8 )
        return 708620;
      v9 = *a1;
      *(uint32_t *)(*a1 + v8) = __n | a2;
      v10 = *((uint32_t *)a1 + 2) + 4;
      *((uint32_t *)a1 + 2) = v10;
      v11 = ((a2 & 0x7F000000u) - 0x4000000) >> 24;
      if ( v11 - 4 < 3 )
      {
        v12 = (__n + 3) & 0xFFFFFFFC;
        memcpy((void *)(v9 + v10), __src, (unsigned int)__n);
LABEL_15:
        result = 0;
        *((uint32_t *)a1 + 2) += v12;
        return result;
      }
      if ( !v11 )
      {
        *(uint64_t *)(v9 + v10) = *__src;
        v12 = 8;
        goto LABEL_15;
      }
      return 0;
    }
  }
  return result;
}

//----- (000000000001F418) ----------------------------------------------------
__int64 __fastcall copy_buf_struct_to_heap(__int64 a1, uint64_t *a2, uint32_t *a3)
{
  __int64 v3; // x19
  size_t v5; // x22
  void *v8; // x0

  v3 = 708609;
  if ( *(uint64_t *)a1 )
  {
    v5 = *(unsigned int *)(a1 + 8);
    if ( (uint32_t)v5 )
    {
      if ( *(uint32_t *)(a1 + 12) )
      {
        v8 = malloc(*(unsigned int *)(a1 + 8));
        *a2 = v8;
        if ( v8 )
        {
          memcpy(v8, *(const void **)a1, v5);
          v3 = 0;
          *a3 = *(uint32_t *)(a1 + 8);
        }
        else
        {
          return 708617;
        }
      }
    }
  }
  return v3;
}

//----- (000000000001F4A4) ----------------------------------------------------
__int64 __fastcall free_and_null_ptr(void **a1)
{
  void *v2; // x0

  v2 = *a1;
  if ( v2 )
    free(v2);
  *a1 = 0;
  a1[1] = 0;
  free(a1);
  return 0;
}

//----- (000000000001F4E0) ----------------------------------------------------
__int64 __fastcall fd_make_pipe(int a1[2])
{
  int v2; // w19
  int v3; // w8

  if ( pipe(a1) )
  {
    v2 = errno;
    v3 = errno;
    if ( v2 < 0 )
      v3 = -v3;
    return v3 | 0x40000000u;
  }
  else if ( *a1 == -1 || a1[1] == -1 )
  {
    return 163882;
  }
  else
  {
    return 0;
  }
}

//----- (000000000001F550) ----------------------------------------------------
__int64 __fastcall fd_read_test(int *fd)
{
  int v3; // w19
  int v4; // w8
  uint8_t outBuf[256]; // [xsp+8h] [xbp-118h] BYREF

  while ( read(*fd, outBuf, 0x100u) > 0 )
    ;
  if ( errno == 35 )
    return 0;
  v3 = errno;
  v4 = errno;
  if ( v3 < 0 )
    v4 = -v4;
  return v4 | 0x40000000u;
}

//----- (000000000001F5F0) ----------------------------------------------------
__int64 __fastcall setup_two_fds(int *a1)
{
  __int64 result; // x0
  int fd; // w0

  result = setup_fd(*a1);
  if ( !(uint32_t)result )
  {
    fd = a1[1];
    return setup_fd(fd);
  }
  return result;
}
// 1F62C: variable 'vars8' is possibly undefined

//----- (000000000001F63C) ----------------------------------------------------
__int64 __fastcall setup_fd(int a1)
{
  int v2; // w0
  int v3; // w0
  int v5; // w19
  int v6; // w8

  if ( a1 == -1 )
    return 0xAD001;
  if ( fcntl(a1, 73, 1) != -1 )
  {
    v2 = fcntl(a1, 1);
    if ( v2 != -1 && fcntl(a1, 2, v2 | 1u) != -1 )
    {
      v3 = fcntl(a1, 3);
      if ( v3 != -1 && fcntl(a1, 4, v3 | 4u) != -1 )
        return 0;
    }
  }
  v5 = errno;
  v6 = errno;
  if ( v5 < 0 )
    v6 = -v6;
  return v6 | 0x40000000u;
}

//----- (000000000001F714) ----------------------------------------------------
__int64 __fastcall fd_write(__int64 a1, const void *a2, size_t a3)
{
  ssize_t v4; // x0
  int v6; // w19
  int v7; // w8

  v4 = write(*(uint32_t *)(a1 + 4), a2, a3);
  if ( v4 < 0 )
  {
    v6 = errno;
    v7 = errno;
    if ( v6 < 0 )
      v7 = -v7;
    return v7 | 0x40000000u;
  }
  else if ( v4 == a3 )
  {
    return 0;
  }
  else
  {
    return 163898;
  }
}

//----- (000000000001F770) ----------------------------------------------------
__int64 __fastcall fd_read(int *a1, void *a2, size_t a3)
{
  ssize_t v4; // x0
  int v6; // w19
  int v7; // w8

  v4 = read(*a1, a2, a3);
  if ( v4 < 0 )
  {
    v6 = errno;
    v7 = errno;
    if ( v6 < 0 )
      v7 = -v7;
    return v7 | 0x40000000u;
  }
  else if ( v4 == a3 )
  {
    return 0;
  }
  else
  {
    return 163899;
  }
}

//----- (000000000001F7CC) ----------------------------------------------------
int *__fastcall sptm_ulock_write_trampoline(__int64 a1)
{
  int *result; // x0
  int v3; // w20
  int v4; // w8
  int v5; // w8

  result = (int *)remount_hfs(*(uint64_t *)(a1 + 8), *(const char **)a1, 0);
  if ( (uint32_t)result )
  {
    v3 = errno;
    result = __error();
    v4 = *result;
    if ( v3 < 0 )
      v4 = -v4;
    v5 = v4 | 0x40000000;
  }
  else
  {
    v5 = 0;
  }
  *(uint32_t *)(a1 + 16) = v5;
  return result;
}

//----- (000000000001F828) ----------------------------------------------------
int *__fastcall mkdir_factory_mount(int *a1)
{
  int *result; // x0
  int v3; // w8
  int v4; // w20
  int v5; // w8

  result = (int *)mkdir("/private/var/factory_mount", 0x1FFu);
  if ( (uint32_t)result && (result = __error(), *result != 17) )
  {
    v4 = errno;
    result = __error();
    v5 = *result;
    if ( v4 < 0 )
      v5 = -v5;
    v3 = v5 | 0x40000000;
  }
  else
  {
    v3 = 0;
  }
  *a1 = v3;
  return result;
}

//----- (000000000001F894) ----------------------------------------------------
int *__fastcall mmap_with_ctx_params(__int64 a1)
{
  int *result; // x0
  int v3; // w8
  int v4; // w20
  int v5; // w8

  result = (int *)mmap(
                    *(void **)(a1 + 8),
                    *(uint64_t *)(a1 + 16),
                    *(uint32_t *)(a1 + 24),
                    18,
                    *(uint32_t *)a1,
                    *(uint64_t *)(a1 + 32));
  if ( result == (int *)-1LL )
  {
    v4 = errno;
    result = __error();
    v5 = *result;
    if ( v4 < 0 )
      v5 = -v5;
    v3 = v5 | 0x40000000;
  }
  else
  {
    v3 = 0;
  }
  *(uint32_t *)(a1 + 40) = v3;
  return result;
}

//----- (000000000001F900) ----------------------------------------------------
__int64 __fastcall krw_dispatch_call_6args(struct_krwCtx *krwCtx, int a2, __int64 a3, __int64 a4, int a5, __int64 a6)
{
  int v7; // [xsp+0h] [xbp-30h] BYREF
  __int64 v8; // [xsp+8h] [xbp-28h]
  __int64 v9; // [xsp+10h] [xbp-20h]
  int v10; // [xsp+18h] [xbp-18h]
  __int64 v11; // [xsp+20h] [xbp-10h]
  unsigned int v12; // [xsp+28h] [xbp-8h]

  v7 = a2;
  v8 = a3;
  v9 = a4;
  v10 = a5;
  v11 = a6;
  v12 = 708609;
  if ( pthread_create_and_join(krwCtx, (__int64)mmap_with_ctx_params, &v7) )
    return v12;
  else
    return 0x28003;
}

//----- (000000000001F964) ----------------------------------------------------
int *__fastcall unlink_and_close_fd(int *a1)
{
  int v2; // w20
  int *result; // x0
  int v4; // w20
  int v5; // w8
  int v6; // w8
  char v7[1025]; // [xsp+17h] [xbp-429h] BYREF

  v2 = *a1;
  bzero(v7, 0x401u);
  if ( fcntl(v2, 50, v7) || unlink(v7) || (result = (int *)close(v2), (uint32_t)result) )
  {
    v4 = errno;
    result = __error();
    v5 = *result;
    if ( v4 < 0 )
      v5 = -v5;
    v6 = v5 | 0x40000000;
  }
  else
  {
    v6 = 0;
  }
  a1[1] = v6;
  return result;
}

//----- (000000000001FA28) ----------------------------------------------------
__int64 __fastcall krw_dispatch_call_1arg(struct_krwCtx *krwCtx, int a2)
{
  int v3; // [xsp+8h] [xbp-8h] BYREF
  unsigned int v4; // [xsp+Ch] [xbp-4h]

  v3 = a2;
  v4 = 708609;
  if ( pthread_create_and_join(krwCtx, (__int64)unlink_and_close_fd, &v3) )
    return v4;
  else
    return 163843;
}

//----- (000000000001FA7C) ----------------------------------------------------
__int64 __fastcall krw_dispatch_call_3args(struct_krwCtx *krwCtx, __int64 a2, int a3, __int64 a4)
{
  __int64 v5; // [xsp+0h] [xbp-20h] BYREF
  int v6; // [xsp+8h] [xbp-18h]
  __int64 v7; // [xsp+10h] [xbp-10h]
  unsigned int v8; // [xsp+18h] [xbp-8h]

  v5 = a2;
  v6 = a3;
  v7 = a4;
  v8 = 708609;
  if ( pthread_create_and_join(krwCtx, (__int64)create_temp_file_in_factory_mount, &v5) )
    return v8;
  else
    return 163843;
}

//----- (000000000001FADC) ----------------------------------------------------
__int64 __fastcall create_temp_file_in_factory_mount(__int64 a1)
{
  const void *v2; // x22
  size_t v3; // x21
  int *v4; // x25
  __int64 result; // x0
  int v6; // w24
  char *v7; // x0
  const char *v8; // x20
  int v9; // w0
  int v10; // w23
  unsigned int v11; // w24
  unsigned __int64 v12; // x0
  int v14; // w20
  int v15; // w8
  int v16; // w0
  int v17; // w21
  int v18; // w8
  char __str[1024]; // [xsp+10h] [xbp-CC0h] BYREF
  struct statfs v20; // [xsp+410h] [xbp-8C0h] BYREF

  v2 = *(const void **)a1;
  v3 = *(unsigned int *)(a1 + 8);
  v4 = *(int **)(a1 + 16);
  bzero(&v20, 0x878u);
  result = check_factory_mount_hfs(&v20);
  v6 = result;
  if ( !(uint32_t)result )
  {
    snprintf(__str, 0x400u, "%s/temp.XXXXXX", "/private/var/factory_mount");
    v7 = mktemp(__str);
    if ( !v7 || (v8 = v7, v9 = open_dprotected_np(v7, 1538, 4, 0, 493), v9 < 0) )
    {
      v14 = errno;
      result = (__int64)__error();
      v15 = *(uint32_t *)result;
      if ( v14 < 0 )
        v15 = -v15;
      v6 = v15 | 0x40000000;
    }
    else
    {
      v10 = v9;
      v11 = 0;
      while ( 1 )
      {
        v12 = write(v10, v2, v3);
        if ( v12 != -1 )
          break;
        if ( errno == 4 && v11++ < 0x64 )
          continue;
        v6 = 110597;
        goto LABEL_20;
      }
      v6 = 110597;
      if ( !HIDWORD(v12) && (uint32_t)v3 == (uint32_t)v12 )
      {
        v16 = open(v8, 0);
        if ( (v16 & 0x80000000) == 0 )
        {
          *v4 = v16;
          result = close(v10);
          v6 = 0;
          goto LABEL_21;
        }
        v17 = errno;
        v18 = errno;
        if ( v17 < 0 )
          v18 = -v18;
        v6 = v18 | 0x40000000;
      }
LABEL_20:
      close(v10);
      result = unlink(v8);
    }
  }
LABEL_21:
  *(uint32_t *)(a1 + 24) = v6;
  return result;
}

//----- (000000000001FC94) ----------------------------------------------------
__int64 __fastcall get_mount_point_via_dispatch(struct_krwCtx *krwCtx)
{
  __int64 result; // x0
  char *f_mntonname; // [xsp+8h] [xbp-8B8h] BYREF
  __int64 v4; // [xsp+10h] [xbp-8B0h]
  unsigned int v5; // [xsp+18h] [xbp-8A8h]
  struct statfs v6; // [xsp+20h] [xbp-8A0h] BYREF

  bzero(&v6, 0x878u);
  LODWORD(result) = check_factory_mount_hfs(&v6);
  if ( (uint32_t)result )
  {
    if ( (uint32_t)result == 708625 )
      return 0;
    else
      return (unsigned int)result;
  }
  else
  {
    f_mntonname = v6.f_mntonname;
    v4 = 0;
    v5 = 708609;
    if ( pthread_create_and_join(krwCtx, (__int64)unmount_path_retry, &f_mntonname) )
      result = v5;
    else
      result = 708619;
    if ( !(uint32_t)result )
    {
      f_mntonname = v6.f_mntfromname;
      v4 = 0;
      v5 = 708609;
      if ( pthread_create_and_join(krwCtx, (__int64)stat_path_or_notfound, &f_mntonname) )
        return v5;
      else
        return 708619;
    }
  }
  return result;
}

//----- (000000000001FD98) ----------------------------------------------------
__int64 __fastcall check_factory_mount_hfs(struct statfs *a1)
{
  __int64 v2; // x19
  int v3; // w19
  int v4; // w8

  v2 = 708625;
  if ( statfs("/private/var/factory_mount", a1) )
  {
    if ( errno != 2 )
    {
      v3 = errno;
      v4 = errno;
      if ( v3 < 0 )
        v4 = -v4;
      return v4 | 0x40000000u;
    }
  }
  else if ( !strcmp("/private/var/factory_mount", a1->f_mntonname) )
  {
    if ( !strcmp("hfs", a1->f_fstypename) )
      return 0;
    else
      return 708613;
  }
  return v2;
}

//----- (000000000001FE38) ----------------------------------------------------
__int64 __fastcall setup_untethered_persistence_maybe(struct_krwCtx *krwCtx, int a2)
{
  __int64 st_uid; // x22
  CFMutableDictionaryRef Mutable; // x0
  CFMutableDictionaryRef v6; // x21
  size_t v7; // x0
  CFDataRef v8; // x0
  CFDataRef v9; // x23
  CFNumberRef v10; // x0
  CFNumberRef v11; // x24
  const struct __CFData *Data; // x0
  const struct __CFData *v13; // x25
  size_t Length; // x22
  void *v15; // x20
  const UInt8 *BytePtr; // x0
  __darwin_ino64_t v17; // x28
  IONotificationPort *v18; // x0
  IONotificationPort *v19; // x22
  CFRunLoopSourceRef RunLoopSource; // x0
  struct __CFRunLoopSource *v21; // x23
  struct __CFRunLoop *Current; // x0
  const CFDictionaryRef *v23; // x21
  void (__cdecl *v24)(void *, io_iterator_t); // x0
  kern_return_t v25; // w0
  int v26; // w25
  char *v27; // x21
  struct __CFRunLoop *v28; // x0
  int v30; // w22
  unsigned int v31; // w25
  CFRunLoopRunResult v32; // w0
  uint64_t valuePtr; // [xsp+8h] [xbp-A18h] BYREF
  unsigned int v34; // [xsp+10h] [xbp-A10h]
  struct statfs v35; // [xsp+88h] [xbp-998h] BYREF
  io_iterator_t notification[2]; // [xsp+900h] [xbp-120h] BYREF
  const char *v37; // [xsp+908h] [xbp-118h]
  uint64_t *p_valuePtr; // [xsp+910h] [xbp-110h]
  __int64 v39; // [xsp+918h] [xbp-108h]
  struct stat __str; // [xsp+920h] [xbp-100h] BYREF

  bzero(&v35, 0x878u);
  st_uid = check_factory_mount_hfs(&v35);
  if ( (uint32_t)st_uid != 708625 )
    return st_uid;
  __str.st_dev = 708609;
  st_uid = pthread_create_and_join(krwCtx, (__int64)mkdir_factory_mount, &__str) ? (unsigned int)__str.st_dev : 708619LL;
  if ( (uint32_t)st_uid )
    return st_uid;
  valuePtr = mach_absolute_time();
  Mutable = CFDictionaryCreateMutable(
              kCFAllocatorDefault,
              1,
              &kCFTypeDictionaryKeyCallBacks,
              &kCFTypeDictionaryValueCallBacks);
  if ( !Mutable )
    return 708617;
  v6 = Mutable;
  snprintf((char *)&__str, 0x40u, "ram://%u", a2 << 11);
  v7 = strlen((const char *)&__str);
  v8 = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)&__str, v7);
  if ( !v8 )
  {
    CFRelease(v6);
    return 708617;
  }
  v9 = v8;
  v10 = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &valuePtr);
  if ( v10 )
  {
    v11 = v10;
    CFDictionaryAddValue(v6, CFSTR("autodiskmount"), kCFBooleanFalse);
    CFDictionaryAddValue(v6, CFSTR("ota-unique-identifier"), v11);
    CFDictionaryAddValue(v6, CFSTR("image-path"), v9);
    Data = CFPropertyListCreateData(kCFAllocatorDefault, v6, kCFPropertyListXMLFormat_v1_0, 0, 0);
    if ( Data )
    {
      v13 = Data;
      Length = CFDataGetLength(Data);
      v15 = calloc(Length + 1, 1u);
      if ( v15 )
      {
        BytePtr = CFDataGetBytePtr(v13);
        memcpy(v15, BytePtr, Length);
        st_uid = 0;
        v17 = valuePtr;
      }
      else
      {
        v17 = 0;
        st_uid = 708617;
      }
      CFRelease(v13);
    }
    else
    {
      v15 = 0;
      v17 = 0;
      st_uid = 708617;
    }
    CFRelease(v11);
  }
  else
  {
    v15 = 0;
    v17 = 0;
    st_uid = 708617;
  }
  CFRelease(v9);
  CFRelease(v6);
  if ( !(uint32_t)st_uid )
  {
    valuePtr = (uint64_t)v15;
    v34 = 708619;
    if ( !krwCtx || !v15 )
    {
      st_uid = 708609;
      goto LABEL_38;
    }
    st_uid = 708609;
    if ( v17 )
    {
      st_uid = 708619;
      if ( (unsigned int)krw_inject_entitlements2_maybe(
                           krwCtx,
                           mach_task_self_,
                           "<dict><key>com.apple.private.diskimages.kext.user-client-access</key><true/><key>com.apple.pr"
                           "ivate.security.disk-device-access</key><true/><key>com.apple.security.iokit-user-client-class"
                           "</key><array><string>IOHDIXControllerUserClient</string></array></dict>",
                           1) )
      {
        if ( pthread_create_and_join(krwCtx, (__int64)iokit_connect_call_struct_method, &valuePtr) )
        {
          st_uid = v34;
          if ( !v34 )
          {
            *(uint64_t *)&__str.st_dev = 0;
            __str.st_ino = v17;
            notification[0] = 0;
            v18 = IONotificationPortCreate(kIOMasterPortDefault);
            if ( !v18 )
            {
              v26 = 6;
              goto LABEL_37;
            }
            v19 = v18;
            RunLoopSource = IONotificationPortGetRunLoopSource(v18);
            if ( !RunLoopSource )
            {
              IONotificationPortDestroy(v19);
              v26 = 29;
              goto LABEL_37;
            }
            v21 = RunLoopSource;
            Current = CFRunLoopGetCurrent();
            CFRunLoopAddSource(Current, v21, kCFRunLoopDefaultMode);
            v23 = IOServiceMatching("IOMedia");
            v24 = (void (__cdecl *)(void *, io_iterator_t))nullsub_1(ioregistry_iter_read_cf_props);
            v25 = IOServiceAddMatchingNotification(v19, "IOServiceMatched", v23, v24, &__str, notification);
            if ( v25 )
            {
              v26 = v25;
              v27 = 0;
              goto LABEL_36;
            }
            ioregistry_iter_read_cf_props((__int64)&__str, notification[0]);
            v27 = *(char **)&__str.st_dev;
            if ( *(uint64_t *)&__str.st_dev )
            {
LABEL_34:
              v26 = 0;
              *(uint64_t *)&__str.st_dev = 0;
              goto LABEL_35;
            }
            v31 = 0;
            while ( 1 )
            {
              v32 = CFRunLoopRunInMode(kCFRunLoopDefaultMode, 1.0, 1u);
              if ( v32 == kCFRunLoopRunTimedOut )
              {
                ++v31;
              }
              else if ( v32 != kCFRunLoopRunHandledSource )
              {
                if ( (unsigned int)(v32 - 1) < 2 )
                {
                  v27 = *(char **)&__str.st_dev;
                  if ( *(uint64_t *)&__str.st_dev )
                    goto LABEL_34;
                  goto LABEL_59;
                }
                v27 = 0;
                v26 = 18;
LABEL_35:
                IOObjectRelease(notification[0]);
LABEL_36:
                v28 = CFRunLoopGetCurrent();
                CFRunLoopRemoveSource(v28, v21, kCFRunLoopDefaultMode);
                IONotificationPortDestroy(v19);
                if ( v26 )
                {
LABEL_37:
                  st_uid = v26 | 0x80000000;
                  break;
                }
                snprintf((char *)&valuePtr, 0x80u, "/dev/%s", v27);
                memset(&__str, 0, sizeof(__str));
                *(uint64_t *)notification = "/sbin/newfs_hfs";
                v37 = "-P";
                p_valuePtr = &valuePtr;
                v39 = 0;
                st_uid = posix_spawn_with_sigdefault((const char **)notification);
                if ( !(uint32_t)st_uid )
                {
                  v30 = 1000;
                  while ( lstat((const char *)&valuePtr, &__str) || (__str.st_mode & 0xF000) != 0x6000 )
                  {
                    usleep(0x4E20u);
                    if ( !--v30 )
                    {
                      st_uid = 708632;
                      goto LABEL_46;
                    }
                  }
                  *(uint64_t *)&__str.st_dev = "/private/var/factory_mount";
                  __str.st_ino = (__darwin_ino64_t)&valuePtr;
                  __str.st_uid = 708609;
                  if ( pthread_create_and_join(krwCtx, (__int64)sptm_ulock_write_trampoline, &__str) )
                  {
                    st_uid = __str.st_uid;
                    if ( !__str.st_uid )
                    {
LABEL_47:
                      free(v27);
                      break;
                    }
                  }
                  else
                  {
                    st_uid = 708619;
                  }
                }
LABEL_46:
                *(uint64_t *)&__str.st_dev = &valuePtr;
                __str.st_ino = 0;
                __str.st_uid = 708609;
                pthread_create_and_join(krwCtx, (__int64)stat_path_or_notfound, &__str);
                goto LABEL_47;
              }
              v27 = *(char **)&__str.st_dev;
              if ( *(uint64_t *)&__str.st_dev || v31 >= 0xA )
              {
                if ( *(uint64_t *)&__str.st_dev )
                  goto LABEL_34;
LABEL_59:
                v26 = 49;
                goto LABEL_35;
              }
            }
          }
        }
      }
    }
LABEL_38:
    free(v15);
  }
  return st_uid;
}
// 19728: using guessed type __int64 __fastcall nullsub_1(uint64_t);
// 44958: using guessed type __CFString cfstr_Autodiskmount;
// 44978: using guessed type __CFString cfstr_OtaUniqueIdent;
// 44998: using guessed type __CFString cfstr_ImagePath;

//----- (00000000000203B0) ----------------------------------------------------
__int64 __fastcall get_root_mount_info(struct_krwCtx *krwCtx, uint32_t *a2, char *a3)
{
  __int64 result; // x0
  struct statfs v6; // [xsp+0h] [xbp-8A0h] BYREF

  bzero(&v6, 0x878u);
  result = check_factory_mount_hfs(&v6);
  if ( (uint32_t)result == 708625 )
  {
    result = 0;
    *a2 = 0;
    *a3 = 0;
  }
  else if ( !(uint32_t)result )
  {
    *a2 = 4;
    strlcpy(a3, v6.f_mntonname, 0x400u);
    return 0;
  }
  return result;
}

//----- (0000000000020468) ----------------------------------------------------
__int64 __fastcall physmap_check_range_wrapper(struct_krwCtx *krwCtx, __int64 a2, int a3)
{
  if ( physmap_single_check(krwCtx, a2, a3) )
    return 0;
  else
    return 708619;
}

//----- (0000000000020490) ----------------------------------------------------
int *__fastcall unmount_path_retry(__int64 a1)
{
  unsigned int v2; // w21
  int v3; // w20
  int *result; // x0
  int v5; // w22
  int v6; // w8
  int v7; // w8

  v2 = 0;
  v3 = 1073741840;
  while ( 1 )
  {
    result = (int *)unmount(*(const char **)a1, 0x80000);
    if ( !(uint32_t)result )
    {
      v3 = 0;
      goto LABEL_11;
    }
    v5 = errno;
    result = __error();
    v6 = *result;
    if ( v5 < 0 )
      v6 = -v6;
    v7 = v6 | 0x40000000;
    if ( v7 != 1073741840 )
      break;
    result = (int *)usleep(0xC8u);
    if ( v2++ >= 4 )
      goto LABEL_11;
  }
  v3 = v7;
LABEL_11:
  *(uint32_t *)(a1 + 16) = v3;
  return result;
}

//----- (0000000000020524) ----------------------------------------------------
int *__fastcall stat_path_or_notfound(__int64 a1)
{
  const char *v2; // x20
  int *result; // x0
  int v4; // w21
  int v5; // w0
  int v6; // w20
  int v7; // w21
  int v8; // w8
  int v9; // w20
  int v10; // w8
  struct stat v11; // [xsp+10h] [xbp-B0h] BYREF

  memset(&v11, 0, sizeof(v11));
  v2 = *(const char **)a1;
  result = (int *)stat(*(const char **)a1, &v11);
  if ( (uint32_t)result )
  {
    result = __error();
    if ( *result == 2 )
    {
      v4 = 0;
      goto LABEL_16;
    }
    goto LABEL_10;
  }
  if ( (v11.st_mode & 0xF000) != 0x6000 )
  {
    v4 = 708627;
    goto LABEL_16;
  }
  v5 = open(v2, 0);
  if ( v5 < 0 )
  {
LABEL_10:
    v9 = errno;
    result = __error();
    v10 = *result;
    if ( v9 < 0 )
      v10 = -v10;
    v4 = v10 | 0x40000000;
    goto LABEL_16;
  }
  v6 = v5;
  if ( ioctl(v5, 0x20006415u, 0) )
  {
    v7 = errno;
    v8 = errno;
    if ( v7 < 0 )
      v8 = -v8;
    v4 = v8 | 0x40000000;
  }
  else
  {
    v4 = 0;
  }
  result = (int *)close(v6);
LABEL_16:
  *(uint32_t *)(a1 + 16) = v4;
  return result;
}

//----- (000000000002062C) ----------------------------------------------------
const CFDictionaryRef *__fastcall iokit_connect_call_struct_method(const CFDictionaryRef *result)
{
  const CFDictionaryRef *v1; // x19
  io_object_t v2; // w20
  io_service_t service; // w0
  kern_return_t v3; // w0
  kern_return_t v4; // w0
  unsigned int v5; // w8
  int outputStruct; // [xsp+4h] [xbp-13Ch] BYREF
  size_t outputStructCnt; // [xsp+8h] [xbp-138h] BYREF
  io_connect_t connect; // [xsp+14h] [xbp-12Ch] BYREF
  struct iohdix_method_input
  {
    uint64_t magic;
    const char *path;
    size_t pathLen;
    uint8_t reserved[0xE8];
  } inputStruct; // [xsp+18h] [xbp-128h] BYREF

  if ( result )
  {
    v1 = result;
    service = ioservice_get_matching("IOHDIXController");
    if ( service + 1 < 2 )
    {
      *((uint32_t *)v1 + 2) = 708625;
    }
    else
    {
      v2 = service;
      connect = 0;
      v3 = IOServiceOpen(service, mach_task_self_, 0, &connect);
      if ( v3 )
      {
        *((uint32_t *)v1 + 2) = v3 | 0x80000000;
      }
      else
      {
        outputStructCnt = 4;
        outputStruct = 0;
        memset(&inputStruct, 0, sizeof(inputStruct));
        inputStruct.magic = 0x1BEEFFEEDLL;
        inputStruct.path = *(const char **)v1;
        inputStruct.pathLen = strlen(inputStruct.path);
        v4 = IOConnectCallStructMethod(connect, 0, &inputStruct, 0x100u, &outputStruct, &outputStructCnt);
        v5 = v4 | 0x80000000;
        if ( !v4 )
          v5 = 0;
        *((uint32_t *)v1 + 2) = v5;
        IOServiceClose(connect);
      }
      return (const CFDictionaryRef *)IOObjectRelease(v2);
    }
  }
  return result;
}

//----- (0000000000020780) ----------------------------------------------------
__int64 __fastcall ioregistry_iter_read_cf_props(__int64 a1, io_iterator_t iterator)
{
  __int64 result; // x0
  io_registry_entry_t v5; // w22
  const struct __CFNumber *v6; // x0
  const struct __CFNumber *v7; // x26
  CFTypeID v8; // x27
  const struct __CFString *CFProperty; // x0
  const struct __CFString *v10; // x27
  CFTypeID v11; // x28
  CFStringEncoding SystemEncoding; // w0
  __int64 valuePtr; // [xsp+8h] [xbp-E8h] BYREF
  char buffer[128]; // [xsp+10h] [xbp-E0h] BYREF

  valuePtr = 0;
  memset(buffer, 0, sizeof(buffer));
  result = IOIteratorNext(iterator);
  if ( (uint32_t)result )
  {
    v5 = result;
    do
    {
      v6 = (const struct __CFNumber *)IORegistryEntrySearchCFProperty(
                                 v5,
                                 "IOService",
                                 CFSTR("ota-unique-identifier"),
                                 kCFAllocatorDefault,
                                 3u);
      if ( v6 )
      {
        v7 = v6;
        v8 = CFGetTypeID(v6);
        if ( v8 == CFNumberGetTypeID()
          && CFNumberGetValue(v7, kCFNumberSInt64Type, &valuePtr) == 1
          && valuePtr == *(uint64_t *)(a1 + 8) )
        {
          CFProperty = (const struct __CFString *)IORegistryEntryCreateCFProperty(
                                             v5,
                                             CFSTR("BSD Name"),
                                             kCFAllocatorDefault,
                                             0);
          if ( CFProperty )
          {
            v10 = CFProperty;
            v11 = CFGetTypeID(CFProperty);
            if ( v11 == CFStringGetTypeID() )
            {
              SystemEncoding = CFStringGetSystemEncoding();
              if ( CFStringGetCString(v10, buffer, 128, SystemEncoding) == 1 )
              {
                if ( *(uint64_t *)a1 )
                  free(*(void **)a1);
                *(uint64_t *)a1 = strdup(buffer);
              }
            }
            CFRelease(v10);
          }
        }
        CFRelease(v7);
      }
      IOObjectRelease(v5);
      result = IOIteratorNext(iterator);
      v5 = result;
    }
    while ( (uint32_t)result );
  }
  return result;
}
// 44978: using guessed type __CFString cfstr_OtaUniqueIdent;
// 449B8: using guessed type __CFString cfstr_BsdName;

//----- (0000000000020930) ----------------------------------------------------
__int64 __fastcall append_to_dynamic_buf(struct_krwCtx *krwCtx, __int64 *a2, __int64 a3)
{
  __int64 v4; // x21
  __int64 *v5; // x9
  int v6; // w10
  size_t v7; // x8
  __int64 v8; // x22
  unsigned int v9; // w10
  size_t *p_src; // x20
  void *v11; // x0
  size_t v12; // x2
  size_t *v13; // x1
  size_t v15; // [xsp+0h] [xbp-30h] BYREF
  __int64 __src; // [xsp+8h] [xbp-28h] BYREF

  if ( *((uint8_t *)a2 + 64) )
  {
    __src = a3;
    v4 = a2[4];
    if ( v4 )
    {
      v5 = a2 + 5;
    }
    else
    {
      v5 = a2 + 1;
      v4 = *a2;
    }
    v6 = *((uint32_t *)a2 + 18);
    v7 = krwCtx->stride_0x168;
    v8 = (unsigned int)(v6 + 2 * v7);
    v9 = 3 * v7 + v6;
    if ( a3 )
    {
      p_src = (size_t *)&__src;
      v15 = v8 - v7 + *v5;
    }
    else
    {
      p_src = &v15;
      v15 = 0;
    }
    memcpy((void *)(v4 + v9), &v15, v7);
    v11 = (void *)(v4 + v8);
    v12 = krwCtx->stride_0x168;
    v13 = p_src;
  }
  else
  {
    if ( a3 )
      __src = a3 - *((unsigned int *)a2 + 25);
    else
      __src = 0;
    v11 = (void *)(*a2 + *((unsigned int *)a2 + 23) + 512);
    v12 = krwCtx->stride_0x168;
    v13 = (size_t *)&__src;
  }
  memcpy(v11, v13, v12);
  return 0;
}

//----- (0000000000020A14) ----------------------------------------------------
__int64 __fastcall write_loop_to_fd_from_ctx(__int64 a1, int a2, char a3)
{
  __int64 v5; // x22
  unsigned int v6; // w23
  __int64 v7; // x19
  unsigned __int64 v8; // x0
  bool v9; // cf
  unsigned __int64 v10; // x0
  unsigned int v11; // w23
  bool v12; // zf
  unsigned int v14; // w21
  unsigned __int64 v15; // x0
  unsigned __int64 v16; // x0
  unsigned int v17; // w21

  v5 = *(uint64_t *)(a1 + 32);
  if ( (a3 & 1) == 0 && (!a2 || v5) )
    goto LABEL_19;
  v6 = 0;
  v7 = 163849;
  while ( 1 )
  {
    v8 = write(*(uint32_t *)(a1 + 24), *(const void **)a1, *(unsigned int *)(a1 + 16));
    if ( v8 != -1 )
      break;
    if ( errno == 4 )
    {
      v9 = v6++ >= 0x64;
      if ( !v9 )
        continue;
    }
    return v7;
  }
  if ( !HIDWORD(v8) && *(uint32_t *)(a1 + 16) == (uint32_t)v8 )
  {
    v10 = read(*(uint32_t *)(a1 + 20), *(void **)a1, (unsigned int)v8);
    if ( v10 == -1 )
    {
      v11 = 0;
      while ( errno == 4 && v11 <= 0x63 )
      {
        ++v11;
        v10 = read(*(uint32_t *)(a1 + 20), *(void **)a1, *(unsigned int *)(a1 + 16));
        if ( v10 != -1 )
          goto LABEL_17;
      }
      return 163850;
    }
LABEL_17:
    v7 = 163850;
    if ( !HIDWORD(v10) && *(uint32_t *)(a1 + 16) == (uint32_t)v10 )
    {
LABEL_19:
      if ( v5 )
        v12 = a2 == 0;
      else
        v12 = 1;
      if ( v12 )
        return 0;
      v14 = 0;
      v7 = 163849;
      while ( 1 )
      {
        v15 = write(*(uint32_t *)(a1 + 56), *(const void **)(a1 + 32), *(unsigned int *)(a1 + 48));
        if ( v15 != -1 )
          break;
        if ( errno == 4 )
        {
          v9 = v14++ >= 0x64;
          if ( !v9 )
            continue;
        }
        return v7;
      }
      if ( !HIDWORD(v15) && *(uint32_t *)(a1 + 48) == (uint32_t)v15 )
      {
        v16 = read(*(uint32_t *)(a1 + 52), *(void **)(a1 + 32), (unsigned int)v15);
        if ( v16 == -1 )
        {
          v17 = 0;
          while ( errno == 4 && v17 <= 0x63 )
          {
            ++v17;
            v16 = read(*(uint32_t *)(a1 + 52), *(void **)(a1 + 32), *(unsigned int *)(a1 + 48));
            if ( v16 != -1 )
              goto LABEL_38;
          }
          return 163850;
        }
LABEL_38:
        v7 = 163850;
        if ( !HIDWORD(v16) && *(uint32_t *)(a1 + 48) == (uint32_t)v16 )
          return 0;
      }
    }
  }
  return v7;
}

//----- (0000000000020C00) ----------------------------------------------------
__int64 __fastcall append_buf_and_get_pid(struct_krwCtx *krwCtx, __int64 a2, __int64 a3, int *a4)
{
  __int64 result; // x0
  int x; // [xsp+Ch] [xbp-14h] BYREF

  append_to_dynamic_buf(krwCtx, (__int64 *)a2, a3);
  result = write_loop_to_fd_from_ctx(a2, 0, 1);
  if ( !(uint32_t)result )
  {
    result = pid_for_task(*(uint32_t *)(a2 + 60), &x);
    if ( (uint32_t)result )
      return (unsigned int)result | 0x80000000;
    else
      *a4 = x;
  }
  return result;
}

//----- (0000000000020C64) ----------------------------------------------------
__int64 __fastcall append_buf_and_wait_port(struct_krwCtx *krwCtx, __int64 a2, __int64 a3, int *a4)
{
  __int64 result; // x0
  integer_t port_info_out; // [xsp+8h] [xbp-28h] BYREF
  mach_msg_type_number_t port_info_outCnt; // [xsp+Ch] [xbp-24h] BYREF

  if ( *(uint8_t *)(a2 + 64) )
  {
    append_to_dynamic_buf(krwCtx, (__int64 *)a2, a3);
    result = write_loop_to_fd_from_ctx(a2, 1, 0);
    if ( !(uint32_t)result )
    {
      port_info_outCnt = 1;
      result = mach_port_get_attributes(mach_task_self_, *(uint32_t *)(a2 + 60), 3, &port_info_out, &port_info_outCnt);
      if ( (uint32_t)result )
        return (unsigned int)result | 0x80000000;
      else
        *a4 = port_info_out;
    }
  }
  else
  {
    return append_buf_and_get_pid(krwCtx, a2, a3, a4);
  }
  return result;
}

//----- (0000000000020D24) ----------------------------------------------------
__int64 __fastcall read_two_consecutive_port_slots(struct_krwCtx *krwCtx, __int64 a2, __int64 a3, unsigned __int64 *a4)
{
  __int64 result; // x0
  unsigned int v9; // [xsp+8h] [xbp-28h] BYREF
  unsigned int v10; // [xsp+Ch] [xbp-24h] BYREF

  result = append_buf_and_wait_port(krwCtx, a2, a3, (int *)&v10);
  if ( !(uint32_t)result )
  {
    result = append_buf_and_wait_port(krwCtx, a2, a3 + 4, (int *)&v9);
    if ( !(uint32_t)result )
      *a4 = v10 | ((unsigned __int64)v9 << 32);
  }
  return result;
}

//----- (0000000000020D90) ----------------------------------------------------
__int64 __fastcall check_iogpu_krw_ready_4(struct_krwCtx *krwCtx, __int64 a2, unsigned __int64 a3, int a4, unsigned __int64 *a5)
{
  __int64 v10; // x19
  __int64 v11; // x0
  unsigned int v12; // w26
  unsigned int v13; // w24
  unsigned __int64 v14; // x0
  unsigned __int64 v15; // x28
  __int64 v16; // x27
  unsigned __int64 i; // x24
  __int64 v18; // x0
  int v19; // w8
  unsigned __int64 v20; // x10
  unsigned __int64 v21; // x9
  int v22; // w11
  unsigned __int64 v23; // x26
  int v24; // w8
  unsigned __int64 v25; // x10
  unsigned __int64 v26; // x9
  int v27; // w11
  unsigned int v29; // [xsp+Ch] [xbp-64h]
  unsigned __int64 xnuVersionPacked; // [xsp+10h] [xbp-60h]
  int v31; // [xsp+1Ch] [xbp-54h] BYREF

  v10 = 163852;
  v11 = get_task_struct_cached_offset(krwCtx);
  if ( !(uint32_t)v11 )
    return 163851;
  if ( !a3 )
    return 163848;
  v12 = v11;
  v13 = compute_optimal_kobj_stride(krwCtx, v11);
  v14 = find_aligned_kaddr_in_region(krwCtx, a3, v12, v13);
  if ( !v14 )
    return 163878;
  v15 = v14;
  v29 = v13;
  xnuVersionPacked = krwCtx->xnuVersionPacked;
  v16 = v12;
  if ( v14 <= a3 )
  {
    i = a3;
    do
    {
      if ( a2 )
      {
        v18 = append_buf_and_wait_port(krwCtx, a2, i, &v31);
        if ( (uint32_t)v18 )
          return v18;
      }
      else if ( !kread_u32(krwCtx, i, &v31) )
      {
        return 163855;
      }
      v19 = v31 & 0x3FF;
      if ( xnuVersionPacked < XNU_VERSION_PACKED(7195, 100, 326, 0, 0) )
      {
        if ( v19 == a4 )
          goto LABEL_47;
        if ( v19 != 17 )
        {
          v20 = 0;
          do
          {
            v21 = v20;
            if ( v20 == 9 )
              break;
            v22 = kLegacyIokitSlotTypes[++v20];
          }
          while ( v22 != v19 );
          if ( v21 > 8 )
            break;
        }
      }
      else if ( a4 == 2 && v19 == 2 )
      {
        if ( !(unsigned int)iokit_slot_alloc_pgtable_lookup(krwCtx, a2, v31, i) )
          goto LABEL_47;
      }
      else if ( v19 == a4 )
      {
LABEL_47:
        v10 = 0;
        *a5 = i;
        return v10;
      }
      i -= v12;
    }
    while ( i >= v15 );
  }
  v23 = v29 - (unsigned __int64)v12 + v15;
  for ( i = v16 + a3; i <= v23; i += v16 )
  {
    if ( a2 )
    {
      v18 = append_buf_and_wait_port(krwCtx, a2, i, &v31);
      if ( (uint32_t)v18 )
        return v18;
    }
    else if ( !kread_u32(krwCtx, i, &v31) )
    {
      return 163855;
    }
    v24 = v31 & 0x3FF;
    if ( xnuVersionPacked < XNU_VERSION_PACKED(7195, 100, 326, 0, 0) )
    {
      if ( v24 == a4 )
        goto LABEL_47;
      if ( v24 != 17 )
      {
        v25 = 0;
        do
        {
          v26 = v25;
          if ( v25 == 9 )
            break;
          v27 = kLegacyIokitSlotTypes[++v25];
        }
        while ( v27 != v24 );
        if ( v26 > 8 )
          return v10;
      }
    }
    else if ( a4 == 2 && v24 == 2 )
    {
      if ( !(unsigned int)iokit_slot_alloc_pgtable_lookup(krwCtx, a2, v31, i) )
        goto LABEL_47;
    }
    else if ( v24 == a4 )
    {
      goto LABEL_47;
    }
  }
  return v10;
}

//----- (0000000000021060) ----------------------------------------------------
__int64 __fastcall iokit_slot_alloc_pgtable_lookup(struct_krwCtx *krwCtx, __int64 a2, __int16 a3, __int64 a4)
{
  __int64 v6; // x0
  __int64 v7; // x21
  unsigned __int64 v8; // x1
  unsigned int v9; // w0
  unsigned __int64 v10; // x8
  unsigned __int64 v12; // [xsp+8h] [xbp-28h] BYREF

  if ( (a3 & 0x7FF) != 2 )
    return 163848;
  v6 = ipc_port_kobject_field_offset(krwCtx, a4);
  v12 = v6;
  if ( !v6 )
    return 163878;
  if ( a2 )
  {
    v7 = read_two_consecutive_port_slots(krwCtx, a2, v6, &v12);
    if ( (uint32_t)v7 )
      return v7;
    v8 = maybe_sptm_translate_kaddr(krwCtx, v12);
    v12 = v8;
  }
  else
  {
    if ( !kread_physmap_decorated(krwCtx, v6, &v12) )
      return 163855;
    v8 = v12;
  }
  if ( !validate_kaddr_range(krwCtx, v8) )
    return 163878;
  v9 = get_task_context_size(krwCtx);
  v7 = 163878;
  if ( !v9 )
    return v7;
  v10 = v12 + v9;
  if ( a2 )
  {
    v7 = read_two_consecutive_port_slots(krwCtx, a2, v10, &v12);
    if ( !(uint32_t)v7 )
    {
      v12 = maybe_sptm_translate_kaddr(krwCtx, v12);
      v7 = read_two_consecutive_port_slots(krwCtx, a2, v12 + 32, &v12);
      if ( !(uint32_t)v7 )
      {
LABEL_20:
        if ( validate_kaddr_range(krwCtx, v12) )
          return 0;
        else
          return 163878;
      }
    }
  }
  else
  {
    v7 = 163855;
    if ( kread_physmap_decorated(krwCtx, v10, &v12) && kread_physmap_decorated(krwCtx, v12 + 32, &v12) )
      goto LABEL_20;
  }
  return v7;
}

//----- (00000000000211F4) ----------------------------------------------------
__int64 __fastcall check_iogpu_krw_ready_type2(struct_krwCtx *krwCtx, __int64 a2, unsigned __int64 a3, unsigned __int64 *a4)
{
  return check_iogpu_krw_ready_4(krwCtx, a2, a3, 2, a4);
}

//----- (0000000000021200) ----------------------------------------------------
__int64 __fastcall fileport_kobj_vm_attr_check(struct_krwCtx *krwCtx, int w1_0)
{
  __int64 v3; // x19
  int xnuMajorVersion; // w9
  unsigned __int64 v8; // x0
  mach_vm_address_t v9; // x21
  int v10; // [xsp+8h] [xbp-28h] BYREF
  mach_port_t a2; // [xsp+Ch] [xbp-24h] BYREF

  v3 = 163847;
  xnuMajorVersion = krwCtx->xnuMajorVersion;
  if ( xnuMajorVersion > 8018 )
  {
    if ( (unsigned int)(xnuMajorVersion - 8019) >= 2 && xnuMajorVersion != 8792 )
      return v3;
LABEL_12:
    if ( (unsigned int)j__fileport_makeport(w1_0, &a2) )
      return 163853;
    v8 = get_task_kobject_addr(krwCtx, a2);
    if ( !v8 )
      return 163854;
    v9 = v8 + 20;
    if ( !kread_u32(krwCtx, v8 + 20, &v10) )
      return 163855;
    if ( (unsigned int)(v10 - 1) > 9 )
      return 163857;
    if ( noppl_kwrite32(krwCtx, v9, 0xFFFF) )
      return 0;
    return 163856;
  }
  if ( xnuMajorVersion == 6153 || xnuMajorVersion == 7195 )
    goto LABEL_12;
  return v3;
}

//----- (0000000000021304) ----------------------------------------------------
uint64_t __fastcall update_timer_lru_cache(struct_krwCtx *krwCtx)
{
  __int64 v2; // x20
  uint64_t result; // x0
  __int64 i; // x8
  __int64 v5; // x10

  v2 = krwCtx->lruCacheLastUpdatedTime;
  result = mach_absolute_time();
  if ( v2 )
  {
    if ( (result - krwCtx->lruCacheLastUpdatedTime) * krwCtx->timebase.numer / krwCtx->timebase.denom < 0x12A153440LL )
      return result;
    for ( i = 0; i != 640; i += 40 )
    {
      v5 = (__int64)&krwCtx->raw_0x370[142] + i;
      *(uint64_t *)(v5 + 32) = 0;
      *(__int128 *)v5 = 0u;
      *(__int128 *)(v5 + 16) = 0u;
    }
    result = mach_absolute_time();
  }
  krwCtx->lruCacheLastUpdatedTime = result;
  return result;
}

//----- (0000000000021388) ----------------------------------------------------
unsigned __int64 __fastcall krw_lookup_and_process_entry(struct_krwCtx *krwCtx)
{
  unsigned __int64 result; // x0

  result = lookup_or_resolve_kaddr(krwCtx);
  if ( result )
  {
    return walk_task_context_to_kobj(krwCtx, result);
  }
  return result;
}
// 213B8: variable 'vars8' is possibly undefined

//----- (00000000000213D4) ----------------------------------------------------
__n128 __fastcall pgtable_walk_full(struct_krwCtx *krwCtx, unsigned __int64 a2, __int64 a3, __int64 a4)
{
  __int64 v8; // x23
  unsigned __int64 v9; // x1
  unsigned __int64 v10; // x9
  __n128 result; // q0
  __int64 v12; // x24
  unsigned __int64 v13; // x25
  unsigned __int64 v14; // x23
  __int64 v15; // x26
  int v16; // w0
  unsigned __int64 v17; // x8
  unsigned __int64 v18; // x9
  unsigned __int64 v19; // x23
  int v20; // w10
  __int64 v21; // x11
  __int64 v22; // x11
  int v23; // w9
  unsigned __int64 v24; // x0
  unsigned __int64 v25; // x23
  int v26; // w8
  unsigned __int64 v27; // x1
  unsigned __int64 v28; // x9
  __int128 v29; // q1
  __int64 v30; // x23
  __int64 v31; // x24
  int has_flag; // w0
  int v33; // w8
  unsigned __int64 v34; // x8
  unsigned __int64 v35; // x25
  __int64 v36; // x11
  __int64 v37; // x8
  PgtableWalkCacheEntry *v38; // x8
  unsigned __int64 v40; // [xsp+0h] [xbp-50h] BYREF
  unsigned __int64 v41; // [xsp+8h] [xbp-48h] BYREF

  result.n128_u64[0] = 0;
  result.n128_u64[1] = 0;
  if ( !a3 )
    return result;
  v8 = 0;
  *(uint64_t *)(a3 + 32) = 0;
  *(__int128 *)a3 = 0u;
  *(__int128 *)(a3 + 16) = 0u;
  do
  {
    PgtableWalkCacheEntry *cacheEntry = &krwCtx->pgtableWalkCache[v8 / 40];
    v9 = cacheEntry->tableKva;
    if ( !v9 )
      break;
    v10 = cacheEntry->virtualBase;
    if ( v10 <= a2 && v10 + cacheEntry->span > a2 )
    {
      if ( kreadbuf_universal(krwCtx, v9, 8u, &cacheEntry->descriptor, a4) )
      {
        memcpy((void *)a3, cacheEntry, sizeof(*cacheEntry));
        result = *(__n128 *)a3;
        return result;
      }
      break;
    }
    v8 += 40;
  }
  while ( v8 != 640 );
  if ( !krwCtx->pgtableRootKva )
  {
    v24 = krw_lookup_and_process_entry(krwCtx);
    TRACE_DMAFAIL("pgtable_walk_full roots init ctx=%llx va=%llx ttbr0_pa_ptr=%llx off=%x page=%x flags=%x\n",
                  (unsigned long long)ctx,
                  (unsigned long long)a2,
                  (unsigned long long)v24,
                  (unsigned int)krwCtx->stride_0x168,
                  krwCtx->pageSizeOrSomething,
                  krwCtx->flags);
    if ( !v24 )
      return result;
    v25 = v24;
    if ( !kread_physmap_decorated(krwCtx, v24, &v41) )
    {
      TRACE_DMAFAIL("pgtable_walk_full roots init read0 failed ptr=%llx\n",
                    (unsigned long long)v24);
      return result;
    }
    if ( !kread_physmap_decorated(krwCtx, v25 + krwCtx->stride_0x168, &v40) )
    {
      TRACE_DMAFAIL("pgtable_walk_full roots init read1 failed ptr=%llx off=%x root0=%llx\n",
                    (unsigned long long)(v25 + krwCtx->stride_0x168),
                    (unsigned int)krwCtx->stride_0x168,
                    (unsigned long long)v41);
      return result;
    }
    if ( krwCtx->pageSizeOrSomething == 4096 )
      v26 = 512;
    else
      v26 = 2048;
    v28 = v40;
    v27 = v41;
    TRACE_DMAFAIL("pgtable_walk_full roots init root=%llx delta=%llx span=%x\n",
                  (unsigned long long)v27,
                  (unsigned long long)v28,
                  v26);
    krwCtx->pgtableRootKva = v27;
    krwCtx->pgtableRootDelta = v28;
    krwCtx->pgtableRootSpan = v26;
    map_physpage_for_kobj(krwCtx, v27);
  }
  if ( krwCtx->pageSizeOrSomething == 4096 || krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A8) )
  {
    v12 = krwCtx->pgtableRootKva;
    v13 = krwCtx->pgtableRootDelta;
    v14 = translate_physmap_addr_via_segments(krwCtx, v12, v13, v13);
    v15 = (a2 >> 27) & 0x7F8;
    v16 = kreadbuf_universal(krwCtx, v12 + v15, 8u, &v41, a4);
    if ( !v16 )
      goto LABEL_58;
    v17 = v41;
    v18 = v41 & 3;
    if ( (v41 & 3) == 0 )
      goto LABEL_57;
    if ( v18 == 1 )
    {
      v19 = v14 + v15;
      v20 = 0x40000000;
      v21 = -1073741824;
LABEL_14:
      v22 = v21 & a2;
      *(uint64_t *)a3 = v19;
LABEL_15:
      *(uint64_t *)(a3 + 8) = v22;
      *(uint32_t *)(a3 + 16) = v20;
      *(uint8_t *)(a3 + 20) = v18;
      *(uint64_t *)(a3 + 32) = v17;
      if ( (v17 & 0x80) != 0 )
        v23 = 1;
      else
        v23 = 3;
      *(uint32_t *)(a3 + 24) = (((v17 >> 51) & 4) | v23) ^ 4;
      v16 = 1;
      goto LABEL_58;
    }
    if ( (v41 & 0x800000000000000LL) != 0 )
      *(uint32_t *)(a3 + 20) |= 0x100u;
    v19 = translate_physmap_addr_via_segments(krwCtx, v12, v13, v17 & 0xFFFFFFFFF000LL) + ((a2 >> 18) & 0xFF8);
    v16 = kreadbuf_universal(krwCtx, v19, 8u, &v41, a4);
    if ( v16 )
    {
      v17 = v41;
      v18 = v41 & 3;
      if ( (v41 & 3) == 0 )
        goto LABEL_57;
      if ( v18 == 1 )
      {
        v20 = 0x200000;
        v21 = -2097152;
        goto LABEL_14;
      }
      if ( (v41 & 0x800000000000000LL) != 0 )
        *(uint32_t *)(a3 + 20) |= 0x100u;
      v19 = translate_physmap_addr_via_segments(krwCtx, v12, v13, v17 & 0xFFFFFFFFF000LL) + ((a2 >> 9) & 0xFF8);
      v16 = kreadbuf_universal(krwCtx, v19, 8u, &v41, a4);
      if ( v16 )
      {
        v17 = v41;
        if ( (~(uint8_t)v41 & 3) == 0 )
        {
          LOBYTE(v18) = 3;
          v20 = 4096;
          v21 = -4096;
          goto LABEL_14;
        }
LABEL_57:
        v16 = 0;
      }
    }
  }
  else
  {
    if ( krwCtx->pageSizeOrSomething != 0x4000 )
      return result;
    v30 = krwCtx->pgtableRootKva;
    v31 = krwCtx->pgtableRootDelta;
    has_flag = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A16_A17_MASK | KRW_CTX_FLAG_CPU_HIGH_CORE_CLUSTER);
    v33 = 2047;
    if ( !has_flag )
      v33 = 7;
    v16 = kreadbuf_universal(krwCtx, v30 + 8 * ((unsigned __int64)(unsigned int)v33 & (a2 >> 36)), 8u, &v41, a4);
    TRACE_DMAFAIL("pgtable_walk_full 16k L0 va=%llx root=%llx delta=%llx idx=%llx read=%llx ok=%d desc=%llx high=%d\n",
                  (unsigned long long)a2,
                  (unsigned long long)v30,
                  (unsigned long long)v31,
                  (unsigned long long)((unsigned __int64)(unsigned int)v33 & (a2 >> 36)),
                  (unsigned long long)(v30 + 8 * ((unsigned __int64)(unsigned int)v33 & (a2 >> 36))),
                  v16,
                  (unsigned long long)v41,
                  has_flag);
    if ( !v16 )
      goto LABEL_58;
    v34 = v41;
    if ( (~(uint8_t)v41 & 3) != 0 )
      goto LABEL_57;
    if ( (v41 & 0x800000000000000LL) != 0 )
      *(uint32_t *)(a3 + 20) |= 0x100u;
    v35 = translate_physmap_addr_via_segments(krwCtx, v30, v31, v34 & 0xFFFFFFFFC000LL) + ((a2 >> 22) & 0x3FF8);
    v16 = kreadbuf_universal(krwCtx, v35, 8u, &v41, a4);
    TRACE_DMAFAIL("pgtable_walk_full 16k L1 va=%llx table=%llx idx=%llx read=%llx ok=%d desc=%llx\n",
                  (unsigned long long)a2,
                  (unsigned long long)(v34 & 0xFFFFFFFFC000LL),
                  (unsigned long long)((a2 >> 22) & 0x3FF8),
                  (unsigned long long)v35,
                  v16,
                  (unsigned long long)v41);
    if ( v16 )
    {
      v17 = v41;
      v18 = v41 & 3;
      if ( (v41 & 3) == 0 )
        goto LABEL_57;
      if ( v18 == 1 )
      {
        v20 = 0x2000000;
        v36 = -33554432;
      }
      else
      {
        if ( (v41 & 0x800000000000000LL) != 0 )
          *(uint32_t *)(a3 + 20) |= 0x100u;
        v35 = translate_physmap_addr_via_segments(krwCtx, v30, v31, v17 & 0xFFFFFFFFC000LL) + ((a2 >> 11) & 0x3FF8);
        v16 = kreadbuf_universal(krwCtx, v35, 8u, &v41, a4);
        TRACE_DMAFAIL("pgtable_walk_full 16k L2 va=%llx table=%llx idx=%llx read=%llx ok=%d desc=%llx\n",
                      (unsigned long long)a2,
                      (unsigned long long)(v17 & 0xFFFFFFFFC000LL),
                      (unsigned long long)((a2 >> 11) & 0x3FF8),
                      (unsigned long long)v35,
                      v16,
                      (unsigned long long)v41);
        if ( !v16 )
          goto LABEL_58;
        v17 = v41;
        if ( (~(uint8_t)v41 & 3) != 0 )
          goto LABEL_57;
        LOBYTE(v18) = 3;
        v20 = 0x4000;
        v36 = -16384;
      }
      v22 = v36 & a2;
      *(uint64_t *)a3 = v35;
      goto LABEL_15;
    }
  }
LABEL_58:
  if ( v16 )
  {
    result = *(__n128 *)a3;
    v37 = 0;
    while ( krwCtx->pgtableWalkCache[v37 / 40].tableKva )
    {
      v37 += 40;
      if ( v37 == 640 )
        return result;
    }
    v38 = &krwCtx->pgtableWalkCache[v37 / 40];
    result = *(__n128 *)a3;
    memcpy(v38, (const void *)a3, sizeof(*v38));
  }
  return result;
}

//----- (000000000002183C) ----------------------------------------------------
int __fastcall pgtable_walk_wrapper(struct_krwCtx *krwCtx, unsigned __int64 a2, void *a3)
{
  return (int)pgtable_walk_full(krwCtx, a2, (__int64)a3, 1).n128_u64[0];
}

//----- (0000000000021844) ----------------------------------------------------
unsigned __int64 __fastcall kaddr_to_phys_v1(struct_krwCtx *krwCtx, unsigned __int64 a2)
{
  int v4; // w0
  struct
  {
    __int128 v6[2];
    volatile __int64 v7;
  } out; // [xsp+0h] [xbp-40h] BYREF

  memset(&out, 0, sizeof(out));
  v4 = (int)pgtable_walk_full(krwCtx, a2, (__int64)&out, 1).n128_u64[0];
  if ( v4 )
    return (krwCtx->pageMask & a2) | (out.v7 & 0xFFFFFFFFC000LL);
  else
    return 0;
}
// 21878: variable 'v4' is possibly undefined

//----- (00000000000218A8) ----------------------------------------------------
unsigned __int64 __fastcall kaddr_to_phys_v2(struct_krwCtx *krwCtx, unsigned __int64 a2, __int64 a3)
{
  int v5; // w0
  struct
  {
    __int128 v7[2];
    volatile __int64 v8;
  } out; // [xsp+0h] [xbp-40h] BYREF

  memset(&out, 0, sizeof(out));
  v5 = (int)pgtable_walk_full(krwCtx, a2, (__int64)&out, a3).n128_u64[0];
  if ( v5 )
    return (krwCtx->pageMask & a2) | (out.v8 & 0xFFFFFFFFC000LL);
  else
    return 0;
}
// 218DC: variable 'v5' is possibly undefined

//----- (000000000002190C) ----------------------------------------------------
__int64 __fastcall free_entry_struct(int a1, uint64_t *a2)
{
  void *v3; // x0

  if ( !a2 )
    return 708609;
  v3 = (void *)a2[3];
  if ( v3 )
    free(v3);
  *(__int128 *)a2 = 0u;
  *((__int128 *)a2 + 1) = 0u;
  free(a2);
  return 0;
}

//----- (0000000000021960) ----------------------------------------------------
__int64 __fastcall validate_physmap_range_5(struct_krwCtx *krwCtx, vm_size_t **a2)
{
  // struct_krwCtx *krwCtx; // x19
  __int64 v4; // x21
  vm_size_t *v5; // x0
  vm_size_t *v6; // x19
  vm_size_t v7; // x23
  __int64 v8; // x0
  __int64 v9; // x28
  __int64 v10; // x24
  unsigned __int64 v11; // x8
  __int128 *v12; // x3
  __int64 v13; // x25
  char *v14; // x8
  unsigned int v15; // w8
  unsigned __int64 v16; // x24
  vm_size_t v17; // x8
  __int64 v18; // x24
  __int64 v19; // x1
  __int64 v20; // x0
  char *v21; // x1
  __int64 *v22; // x23
  unsigned __int64 v23; // x8
  unsigned __int64 v24; // x25
  __int64 *v25; // x8
  int v26; // w8
  __int64 *v27; // x0
  __int64 *v28; // x1
  unsigned __int64 v29; // x8
  __int64 v30; // x26
  __int128 *v31; // x27
  unsigned int v32; // w9
  unsigned int v33; // w10
  int v34; // w9
  __int64 v35; // x25
  __int64 v36; // x27
  __int64 v37; // x8
  unsigned __int64 v38; // x23
  __int128 v39; // q1
  char *v40; // x1
  __int64 v42; // [xsp+0h] [xbp-F0h]
  vm_size_t size; // [xsp+8h] [xbp-E8h] BYREF
  __int64 v44[2]; // [xsp+10h] [xbp-E0h] BYREF
  __int128 v45[4]; // [xsp+20h] [xbp-D0h] BYREF
  __int128 v46[3]; // [xsp+60h] [xbp-90h] BYREF

  v4 = 708617;
  v5 = (vm_size_t *)calloc(0x20u, 1u);
  if ( v5 )
  {
    v6 = v5;
    v7 = krwCtx->gap_0x208;
    if ( v7 )
      goto LABEL_3;
    v16 = krwCtx->gap_0x1998;
    if ( v16 )
    {
LABEL_20:
      v9 = 163855;
      LODWORD(v8) = kread_physmap_decorated(krwCtx, v16, &size);
      if ( (uint32_t)v8 )
      {
        v7 = v16;
        if ( !size )
          goto LABEL_67;
        v8 = validate_kaddr_range(krwCtx, size);
        if ( v8 )
        {
          v17 = size;
          v7 = v16;
          if ( size )
          {
            while ( 1 )
            {
              v7 = v17;
              if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8791, 1023, 1023, 1023, 1023) )
              {
                LODWORD(v8) = krw_read_thunk(krwCtx, v17, 48, v45);
                if ( !(uint32_t)v8 )
                  goto LABEL_43;
                LODWORD(v8) = krw_read_thunk(krwCtx, *((uint64_t *)&v45[0] + 1) + 4LL, 16, v44);
                if ( !(uint32_t)v8 )
                  goto LABEL_43;
                v17 = *(uint64_t *)&v45[0];
              }
              else
              {
                LODWORD(v8) = krw_read_thunk(krwCtx, v17, 40, v46);
                if ( !(uint32_t)v8 )
                  goto LABEL_43;
                LODWORD(v8) = krw_read_thunk(krwCtx, *(uint64_t *)&v46[2] + 4LL, 16, v44);
                if ( !(uint32_t)v8 )
                  goto LABEL_43;
                v17 = *(uint64_t *)&v46[0];
              }
              if ( !((v44[0] ^ 0x403020100LL) | v44[1]) )
                break;
              size = v17;
              if ( !v17 )
                goto LABEL_67;
            }
            if ( size )
            {
              v9 = 0;
              v7 = size;
              goto LABEL_109;
            }
          }
LABEL_67:
          v29 = krwCtx->xnuVersionPacked >> 43;
          if ( v29 <= 0x44A )
            v30 = 48;
          else
            v30 = 64;
          if ( v29 <= 0x44A )
            v31 = v46;
          else
            v31 = v45;
          v32 = krwCtx->pageSizeOrSomething;
          v33 = ((unsigned int)v30 | 0x5800) % v32;
          v34 = v32 - v33;
          if ( !v33 )
            v34 = 0;
          LODWORD(size) = v34 + (v30 | 0x5800);
          v8 = alloc_physmap_page(krwCtx, (unsigned int *)&size);
          if ( !v8 )
          {
            v36 = 708617;
LABEL_108:
            v9 = v36;
            goto LABEL_109;
          }
          v35 = v8;
          v42 = (__int64)v31;
          if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8791, 1023, 1023, 1023, 1023) )
          {
            v36 = 163855;
            if ( kread_physmap_decorated(krwCtx, v16, (unsigned __int64 *)v44) )
            {
              v36 = 0;
              *(uint64_t *)&v46[0] = v44[0];
              *((uint64_t *)&v46[0] + 1) = v35 + 24;
              *(uint64_t *)&v46[1] = (unsigned int)size - 24LL;
              HIDWORD(v46[2]) = 0;
              DWORD2(v46[1]) = 1;
              *(__int128 *)((char *)&v46[1] + 12) = xmmword_43460;
            }
          }
          else
          {
            v36 = 163855;
            if ( kread_physmap_decorated(krwCtx, v16, (unsigned __int64 *)v44) )
            {
              v36 = 0;
              *(uint64_t *)&v45[0] = v44[0];
              *(__int128 *)((char *)v45 + 8) = xmmword_43450;
              *((uint64_t *)&v45[1] + 1) = (unsigned int)size - 40LL;
              *(uint64_t *)&v45[2] = v35 + 40;
              DWORD2(v45[2]) = 1;
              HIDWORD(v45[3]) = 0;
              *(__int128 *)((char *)&v45[2] + 12) = xmmword_43460;
            }
          }
          if ( !(uint32_t)v36 )
          {
            if ( (unsigned int)kwrite_with_retry(krwCtx, v35, v42, v30) )
            {
              if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) )
              {
                if ( (uint32_t)ppl_kwrite_physmap_checked(krwCtx, v16, v35) )
                {
LABEL_86:
                  v36 = 0;
                  v7 = v35;
                  goto LABEL_108;
                }
              }
              else
              {
                LODWORD(v8) = kwrite64(krwCtx, v16, v35);
                if ( (uint32_t)v8 )
                  goto LABEL_86;
              }
            }
            v36 = 163856;
          }
          LODWORD(v8) = map_shared_mem_and_transfer_data(krwCtx, v35, (unsigned int)size);
          goto LABEL_108;
        }
        v7 = 0;
        v9 = 163857;
      }
      else
      {
LABEL_43:
        v7 = 0;
      }
LABEL_109:
      if ( (uint32_t)v9 )
        goto LABEL_117;
      krwCtx->gap_0x208 = v7;
LABEL_3:
      *v6 = v7;
      v6[1] = 0x200000014LL;
      v8 = (__int64)calloc(0x5800u, 1u);
      v9 = 708617;
      if ( v8 )
      {
        v10 = v8;
        v6[3] = v8;
        memset(v46, 0, sizeof(v46));
        memset(v45, 0, sizeof(v45));
        if ( v7 )
        {
          v9 = 163855;
          v11 = krwCtx->xnuVersionPacked >> 43;
          if ( v11 <= 0x44A )
            v12 = v46;
          else
            v12 = v45;
          if ( v11 <= 0x44A )
            v13 = 48;
          else
            v13 = 64;
          LODWORD(v8) = krw_read_thunk(krwCtx, v7, v13, v12);
          if ( (uint32_t)v8 )
          {
            if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8791, 1023, 1023, 1023, 1023) )
              v14 = (char *)&v46[2] + 12;
            else
              v14 = (char *)&v45[3] + 12;
            v15 = *(uint32_t *)v14;
            if ( v15 > 0x3FF )
            {
              v9 = 708620;
            }
            else
            {
              *((uint32_t *)v6 + 4) = v15;
              if ( !v15
                || (LODWORD(v8) = krw_read_thunk(krwCtx, v7 + v13, 22 * v15, (void *)v10), (uint32_t)v8) )
              {
                v4 = 0;
                *a2 = v6;
                return v4;
              }
            }
          }
        }
        else
        {
          v9 = 708609;
        }
      }
LABEL_117:
      free_entry_struct(v8, v6);
      return v9;
    }
    v8 = krwCtx->kernelMachoCtx;
    if ( !v8 )
    {
LABEL_116:
      v9 = 708625;
      goto LABEL_117;
    }
    if ( krwCtx->xnuVersionPacked >> 43 < 0x44Bu )
    {
      resolve_kernel_text_range(v45, krwCtx);
      if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8020, 119, 1023, 1023, 1023) )
        v21 = "0A 05 40 F9 2B 11 40 39";
      else
        v21 = "0B 05 40 F9 6C 11 40 39";
      v46[0] = v45[0];
      *(uint64_t *)&v46[1] = *(uint64_t *)&v45[1];
      v8 = kernel_pattern_scan((__int64)v46, v21, 0);
      if ( v8 )
      {
        v22 = (__int64 *)v8;
        v23 = krwCtx->xnuVersionPacked;
        if ( v23 < XNU_VERSION_PACKED(7195, 0, 46, 0, 0) )
        {
          v27 = krwCtx->kernelMachoCtx;
          if ( v23 < XNU_VERSION_PACKED(6153, 102, 2, 0, 0) )
            v28 = v22 - 2;
          else
            v28 = (__int64 *)((char *)v22 - 28);
LABEL_112:
          v8 = find_kernel_func(v27, v28);
          goto LABEL_113;
        }
        v24 = v8 - 64;
        if ( v8 - 4 >= (unsigned __int64)(v8 - 64) )
        {
          do
          {
            LODWORD(v8) = (unsigned __int64)macho_read_u32(krwCtx->kernelMachoCtx, (__int64 *)((char *)v22 - 4));
            if ( (v8 & 0x9F000000) == 0x90000000 )
            {
              LODWORD(v8) = (unsigned __int64)macho_read_u32(krwCtx->kernelMachoCtx, v22);
              if ( (v8 & 0xBFC00000) == 0xB9400000 )
                goto LABEL_111;
            }
            else if ( (uint32_t)v8 == -721215457 )
            {
              LODWORD(v8) = (unsigned __int64)macho_read_u32(krwCtx->kernelMachoCtx, v22);
              if ( BYTE3(v8) == 88 )
              {
LABEL_111:
                v27 = krwCtx->kernelMachoCtx;
                v28 = (__int64 *)((char *)v22 - 4);
                goto LABEL_112;
              }
            }
            v25 = v22 - 1;
            v22 = (__int64 *)((char *)v22 - 4);
          }
          while ( (unsigned __int64)v25 >= v24 );
        }
      }
    }
    else
    {
      macho_find_text_section(v8, v46);
      if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) )
      {
        v18 = krwCtx->kextMachoCtx2;
        if ( v18 )
        {
LABEL_39:
          macho_find_text_section(v18, v45);
          v8 = kernel_pattern_scan(
                 (__int64)v45,
                 "1F 20 03 D5 .. .. .. .. .. .. .. .. .. .. .. .. 08 05 00 51 1F F9 03 71",
                 0);
          if ( v8 )
          {
            v8 = (unsigned __int64)find_kernel_func_by_branch(krwCtx->kextMachoCtx2, (__int64 *)(v8 - 4), 0);
            if ( v8 )
            {
              v8 = macho_read_u64_thunk(krwCtx->kextMachoCtx2, v8 + 32);
              if ( v8 )
              {
                v19 = v8;
                v20 = krwCtx->kextMachoCtx2;
LABEL_102:
                v8 = macho_read_u64_thunk(v20, v19);
LABEL_113:
                v16 = v8;
                if ( v8 )
                  krwCtx->gap_0x1998 = v8;
LABEL_115:
                if ( v16 )
                  goto LABEL_20;
                goto LABEL_116;
              }
            }
          }
        }
        else
        {
          LODWORD(v8) = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_PAC_KERNEL_LAYOUT);
          if ( (uint32_t)v8 )
          {
            v37 = *(uint64_t *)(krwCtx->mappedKernelRegion + 328LL);
            if ( v37 )
            {
              LODWORD(v44[0]) = 0;
              v38 = v37 & ~krwCtx->pageMask;
              while ( 1 )
              {
                v38 -= krwCtx->pageSizeOrSomething;
                LODWORD(v8) = kread_u32(krwCtx, v38, v44);
                if ( !(uint32_t)v8 )
                  break;
                if ( LODWORD(v44[0]) == -17958193 )
                {
                  if ( v38 )
                  {
                    v8 = (__int64)calloc(0x128u, 1u);
                    if ( v8 )
                    {
                      v18 = v8;
                      krw_ctx_zero_fields((struct_a1 *)v8, krwCtx);
                      v39 = *(__int128 *)&krwCtx->gap_0x150;
                      *(__int128 *)(v18 + 112) = *(__int128 *)&krwCtx->xnuMajorVersion;
                      *(__int128 *)(v18 + 128) = v39;
                      *(uint64_t *)(v18 + 144) = krwCtx->gap_0x160_size8;
                      *(uint32_t *)(v18 + 152) = krwCtx->vmMapSize_size4;
                      *(uint32_t *)(v18 + 56) = krwCtx->pageSizeOrSomething;
                      LODWORD(v8) = iosurface_physmap_setup_bool(v18, 0, v38, 0);
                      if ( (uint32_t)v8 )
                      {
                        krwCtx->kextMachoCtx2 = v18;
                        goto LABEL_39;
                      }
                    }
                  }
                  break;
                }
              }
            }
          }
        }
      }
      else
      {
        v26 = krwCtx->xnuMajorVersion;
        if ( v26 < 10002 )
        {
          if ( v26 <= 8795 )
            v40 = "3F 7D 01 A9 .. .. .. .. 5F 01 00 F9";
          else
            v40 = "00 E4 00 .. 20 01 00 AD .. .. .. .. 5F 01 00 F9";
          v45[0] = v46[0];
          *(uint64_t *)&v45[1] = *(uint64_t *)&v46[1];
          v8 = kernel_pattern_scan((__int64)v45, v40, 0);
          if ( v8 )
          {
            v8 = find_kernel_func(krwCtx->kernelMachoCtx, (__int64 *)(v8 - 12));
            if ( v8 )
            {
              v19 = v8;
              v20 = krwCtx->kernelMachoCtx;
              goto LABEL_102;
            }
          }
        }
        else
        {
          v45[0] = v46[0];
          *(uint64_t *)&v45[1] = *(uint64_t *)&v46[1];
          v8 = kernel_pattern_scan((__int64)v45, "E0 03 13 AA 01 00 80 52 02 05 80 52 .. .. .. .. E0 03", 0);
          if ( v8 )
          {
            v8 = find_kernel_func(krwCtx->kernelMachoCtx, (__int64 *)(v8 - 20));
            if ( v8 )
            {
              v19 = v8 + krwCtx->stride_0x168;
              v20 = krwCtx->kernelMachoCtx;
              goto LABEL_102;
            }
          }
        }
      }
    }
    v16 = 0;
    goto LABEL_115;
  }
  return v4;
}
// 21F64: variable 'v8' is possibly undefined
// 19B94: using guessed type __int64 __fastcall macho_read_u64_thunk(uint64_t, uint64_t);
// 43450: using guessed type __int128 xmmword_43450;
// 43460: using guessed type __int128 xmmword_43460;

//----- (0000000000022144) ----------------------------------------------------
bool __fastcall compare_krw_chunk_data(int a1, __int64 a2, void *__s2, size_t __n)
{
  __int64 v4; // x21
  __int64 v5; // x8
  unsigned int v7; // w22
  size_t v8; // x20
  int v9; // w23
  __int64 v10; // x24
  int v11; // w8
  uint64_t result; // x0
  bool v13; // zf

  if ( !a2 )
    return 0;
  v4 = *(uint64_t *)(a2 + 24);
  if ( !v4 )
    return 0;
  v5 = *(unsigned int *)(a2 + 16);
  if ( !(uint32_t)v5 || *(uint32_t *)(a2 + 8) != (uint32_t)__n )
    return 0;
  v7 = 0;
  v8 = (unsigned int)__n;
  v9 = *(uint32_t *)(a2 + 12) + __n;
  v10 = v5 - 1;
  do
  {
    v11 = memcmp((const void *)(v4 + v7), __s2, v8);
    result = v11 == 0;
    v7 += v9;
    if ( v11 )
      v13 = v10 == 0;
    else
      v13 = 1;
    --v10;
  }
  while ( !v13 );
  return result;
}

//----- (00000000000221E0) ----------------------------------------------------
size_t __fastcall lookup_and_copy_krw_chunk(struct_krwCtx *krwCtx, __int64 a2, void *a3, size_t __n)
{
  size_t v4; // x19
  __int64 v6; // x23
  unsigned int v7; // w22
  unsigned int v9; // w8
  void *v10; // x23
  int v11; // w9
  void *v12; // x21
  size_t v13; // x20
  int (__cdecl *v14)(const void *, const void *); // x0

  v4 = 708609;
  if ( a2 )
  {
    v6 = *(uint64_t *)(a2 + 24);
    if ( v6 )
    {
      v7 = __n;
      if ( *(uint32_t *)(a2 + 8) == (uint32_t)__n )
      {
        if ( compare_krw_chunk_data(krwCtx, a2, a3, __n) )
          return 0;
        v9 = *(uint32_t *)(a2 + 16);
        if ( v9 > 0x3FF )
          return 708620;
        v10 = (void *)(v6 + (*(uint32_t *)(a2 + 12) + v7) * v9);
        memcpy(v10, a3, v7);
        v11 = *(uint32_t *)(a2 + 12);
        ++*(uint32_t *)(a2 + 16);
        if ( v11 == 2 )
        {
          *((uint8_t *)v10 + *(unsigned int *)(a2 + 8)) = 2;
          *((uint8_t *)v10 + (unsigned int)(*(uint32_t *)(a2 + 8) + 1)) = 0;
        }
        v12 = *(void **)(a2 + 24);
        if ( v12 )
        {
          v4 = *(unsigned int *)(a2 + 16);
          if ( (uint32_t)v4 )
          {
            v13 = (unsigned int)(*(uint32_t *)(a2 + 12) + *(uint32_t *)(a2 + 8));
            v14 = (int (__cdecl *)(const void *, const void *))nullsub_1(memcmp20);
            qsort(v12, v4, v13, v14);
            return 0;
          }
        }
      }
    }
  }
  return v4;
}
// 19728: using guessed type __int64 __fastcall nullsub_1(uint64_t);

//----- (00000000000222F0) ----------------------------------------------------
__int64 __fastcall read_kaddr_via_chunk_offset(struct_krwCtx *krwCtx, __int64 a2)
{
  __int64 v2; // x19
  __int64 v4; // x2
  unsigned __int64 v6; // x22
  __int64 v7; // x9
  __int64 v8; // x8

  v2 = 708609;
  if ( a2 )
  {
    v4 = *(uint64_t *)(a2 + 24);
    if ( v4 )
    {
      if ( *(uint64_t *)a2 )
      {
        v2 = 163856;
        v6 = krwCtx->xnuVersionPacked >> 43;
        v7 = 48;
        if ( v6 > 0x44A )
          v7 = 64;
        if ( (unsigned int)kwrite_with_retry(
                             krwCtx,
                             v7 + *(uint64_t *)a2,
                             v4,
                             (unsigned int)((*(uint32_t *)(a2 + 12) + *(uint32_t *)(a2 + 8)) * *(uint32_t *)(a2 + 16))) )
        {
          v8 = 44;
          if ( v6 > 0x44A )
            v8 = 60;
          if ( noppl_kwrite32(krwCtx, *(uint64_t *)a2 + v8, *(uint32_t *)(a2 + 16)) )
            return 0;
          else
            return 163856;
        }
      }
    }
  }
  return v2;
}

//----- (00000000000223A4) ----------------------------------------------------
bool __fastcall physmap_entry_check(struct_krwCtx *krwCtx, unsigned int a2, int a3, __int64 a4)
{
  int v7; // w22
  uint64_t *v8; // x21
  __int64 v9; // x24
  __int64 v10; // x23
  int v11; // w0
  int v13[2]; // [xsp+8h] [xbp-38h] BYREF

  *(uint64_t *)v13 = 0;
  if ( a3 == 20 )
  {
    v7 = validate_physmap_range_5(krwCtx, (vm_size_t **)v13);
    if ( !v7 )
    {
      v8 = *(uint64_t **)v13;
      if ( a2 )
      {
        v9 = 0;
        v10 = 20LL * a2;
        while ( 1 )
        {
          v11 = lookup_and_copy_krw_chunk(0, (__int64)v8, (void *)(a4 + ((unsigned int)v9 & 0xFFFFFFFC)), 0x14u);
          if ( v11 )
            break;
          v9 += 20;
          if ( v10 == v9 )
            goto LABEL_7;
        }
      }
      else
      {
LABEL_7:
        v11 = read_kaddr_via_chunk_offset(krwCtx, (__int64)v8);
      }
      v7 = v11;
      free_entry_struct(v11, v8);
    }
  }
  else
  {
    v7 = 708609;
  }
  return v7 == 0;
}

//----- (0000000000022464) ----------------------------------------------------
bool __fastcall physmap_single_check(struct_krwCtx *krwCtx, __int64 a2, int a3)
{
  return physmap_entry_check(krwCtx, 1u, a3, a2);
}

//----- (0000000000022470) ----------------------------------------------------
__int64 __fastcall memcmp20(__int64 a1, __int64 a2)
{
  __int64 v2; // x8
  unsigned int v3; // w9
  unsigned int v4; // w10

  v2 = 0LL;
  while ( 1 )
  {
    v3 = *(unsigned __int8 *)(a1 + v2);
    v4 = *(unsigned __int8 *)(a2 + v2);
    if ( v3 < v4 )
      return 0xFFFFFFFFLL;
    if ( v3 > v4 )
      break;
    if ( ++v2 == 20 )
      return 0LL;
  }
  return 1LL;
}

//----- (00000000000224AC) ----------------------------------------------------
__int64 __fastcall krw_lookup_via_ctx_field32(struct_krwCtx *krwCtx, unsigned int a2)
{
  return task_self_get_ipc_port(KRWCTX_FROM_RAW_FIELD(krwCtx, 32), a2);
}

//----- (00000000000224B4) ----------------------------------------------------
unsigned __int64 __fastcall get_task_kobject_addr_from_field32(struct_krwCtx *krwCtx, unsigned int a2)
{
  return get_task_kobject_addr(KRWCTX_FROM_RAW_FIELD(krwCtx, 32), a2);
}

//----- (00000000000224BC) ----------------------------------------------------
__int64 __fastcall get_iodevicetree_chosen_data(char **a1, unsigned int a2)
{
  io_registry_entry_t v4; // w0
  io_registry_entry_t v5; // w20
  const struct __CFString *v6; // x0
  const struct __CFString *v7; // x22
  CFTypeRef CFProperty; // x0
  const void *v9; // x23
  CFTypeID TypeID; // x24
  CFIndex Length; // x24
  const UInt8 *BytePtr; // x0
  uint8_t *v13; // x8
  int v14; // t1
  char *v15; // x0
  __int64 v16; // x19
  char __str[512]; // [xsp+10h] [xbp-350h] BYREF
  __int128 v50[16]; // [xsp+210h] [xbp-150h] BYREF

  memset(v50, 0, sizeof(v50));
  memset(__str, 0, sizeof(__str));
  v4 = IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/chosen");
  if ( !v4 )
    return 0;
  v5 = v4;
  v6 = CFStringCreateWithCString(kCFAllocatorDefault, "boot-manifest-hash", 0x8000100u);
  if ( v6 )
  {
    v7 = v6;
    CFProperty = IORegistryEntryCreateCFProperty(v5, v6, kCFAllocatorDefault, 0);
    if ( CFProperty )
    {
      v9 = CFProperty;
      TypeID = CFDataGetTypeID();
      if ( TypeID != CFGetTypeID(v9) )
        goto LABEL_12;
      Length = CFDataGetLength((CFDataRef)v9);
      BytePtr = CFDataGetBytePtr((CFDataRef)v9);
      if ( (unsigned __int64)(Length - 1) > 0x7E )
        goto LABEL_12;
      v13 = v50;
      do
      {
        v14 = *BytePtr++;
        *v13 = a0123456789abcd[(unsigned __int8)(v14 ^ a2) >> 4];
        v13[1] = a0123456789abcd[(v14 ^ a2) & 0xFLL];
        v13 += 2;
        LODWORD(Length) = Length - 1;
      }
      while ( (uint32_t)Length );
      snprintf(__str, 0x200u, "com.apple.os.update-%s", (const char *)v50);
      v15 = strdup(__str);
      if ( v15 )
      {
        *a1 = v15;
        v16 = 1;
      }
      else
      {
LABEL_12:
        v16 = 0;
      }
      CFRelease(v9);
    }
    else
    {
      v16 = 0;
    }
    CFRelease(v7);
  }
  else
  {
    v16 = 0;
  }
  IOObjectRelease(v5);
  return v16;
}

//----- (00000000000226D4) ----------------------------------------------------
__int64 check_necp_kread_available()
{
  __int64 result; // x0

  result = fs_snapshot(255, 0, 0, 0, 0, 0);
  if ( (uint32_t)result )
    return errno != 1;
  return result;
}

//----- (0000000000022718) ----------------------------------------------------
__int64 __fastcall open_and_kread_ptr_data(const char *a1, uint64_t *a2, unsigned int *a3)
{
  __int64 v6; // x23
  __int64 v7; // x0
  __int64 v8; // x19
  char *v9; // x21
  unsigned int v10; // w0
  unsigned int v11; // w23
  void *v12; // x0
  unsigned __int64 v13; // x24
  const char *v14; // x25
  __int128 v16; // [xsp+0h] [xbp-60h] BYREF
  __int64 v17; // [xsp+10h] [xbp-50h]

  v16 = xmmword_43478;
  v17 = 0;
  *a3 = 0;
  v6 = 0;
  if ( getattrlist_check_file(a1) )
  {
    v7 = open(a1, 0x100000, v16, v17);
    if ( (v7 & 0x80000000) != 0 )
    {
      return 0;
    }
    else
    {
      v8 = v7;
      v9 = (char *)calloc(0x1000u, 1u);
      if ( v9
        && (v10 = getattrlistbulk(v8, (__int64)&v16, (__int64)v9, 4096, 64), (v10 & 0x80000000) == 0)
        && (v11 = v10, *a3 = v10, v12 = calloc(v10, 8u), (*a2 = v12) != 0) )
      {
        if ( v11 )
        {
          v13 = 0;
          v14 = v9;
          do
          {
            if ( (v14[4] & 1) != 0 )
            {
              *(uint64_t *)(*a2 + 8 * v13) = calloc(*((unsigned int *)v14 + 7), 1u);
              strcpy(*(char **)(*a2 + 8 * v13), v14 + 32);
              v11 = *a3;
            }
            else
            {
              *(uint64_t *)(*a2 + 8 * v13) = 0;
            }
            v14 += *(unsigned int *)v14;
            ++v13;
          }
          while ( v13 < v11 );
        }
        v6 = 1;
      }
      else
      {
        v6 = 0;
      }
      if ( (int)v8 >= 1 )
        close(v8);
      if ( v9 )
        free(v9);
    }
  }
  return v6;
}
// 43478: using guessed type __int128 xmmword_43478;

//----- (0000000000022878) ----------------------------------------------------
bool __fastcall getattrlist_check_file(const char *a1)
{
  int v1; // w0
  __int128 v3[5]; // [xsp+0h] [xbp-70h] BYREF
  uint64_t v4[3]; // [xsp+58h] [xbp-18h] BYREF

  v4[0] = 5;
  v4[1] = 2147614720LL;
  v4[2] = 0;
  memset(v3, 0, 76);
  v1 = getattrlist(a1, v4, v3, 0x4Cu, 0x20u);
  return (v1 | (DWORD2(v3[0]) & 0x20000)) != 0;
}

//----- (00000000000228E4) ----------------------------------------------------
__int64 __fastcall check_and_copy_file_paths(const char *a1, const char *a2, char a3)
{
  __int64 v6; // x19
  unsigned __int64 v7; // x26
  const char **v8; // x27
  char *v9; // x22
  unsigned __int64 v10; // x23
  int v12; // w8
  int v13; // w25
  __int64 v14; // x20
  __int64 v15; // x22
  const char **v16; // x21
  bool v17; // zf
  void **v18; // x23
  void *v19; // t1
  char *v21; // x23
  const char *v22; // x24
  char *v23; // [xsp+0h] [xbp-70h] BYREF
  char *__s2; // [xsp+8h] [xbp-68h] BYREF
  unsigned int v25; // [xsp+14h] [xbp-5Ch] BYREF
  const char **v26; // [xsp+18h] [xbp-58h] BYREF

  v26 = 0;
  v25 = 0;
  v23 = 0;
  __s2 = 0;
  if ( (unsigned int)get_iodevicetree_chosen_data(&__s2, 0)
    && (unsigned int)get_iodevicetree_chosen_data(&v23, 0x41u)
    && (unsigned int)open_and_kread_ptr_data(a1, &v26, &v25) )
  {
    v6 = open(a1, 0x100000);
    if ( (v6 & 0x80000000) != 0 )
    {
      v14 = 0;
    }
    else
    {
      v7 = v25;
      if ( v25 )
      {
        v8 = v26;
        v9 = __s2;
        if ( !strcmp(*v26, __s2) )
        {
          v12 = 0;
          v13 = 1;
        }
        else
        {
          v10 = 1;
          while ( v7 != v10 )
          {
            if ( !strcmp(v8[v10++], v9) )
            {
              v12 = 0;
              v13 = v10 - 1 < v7;
              goto LABEL_39;
            }
          }
          v13 = v10 < v7;
          v21 = v23;
          while ( 1 )
          {
            v22 = *v8;
            if ( !strcmp(*v8, v21) )
              goto LABEL_37;
            if ( a2 && !strcmp(v22, a2) )
              break;
            ++v8;
            if ( !--v7 )
              goto LABEL_28;
          }
          if ( (a3 & 1) != 0 )
          {
LABEL_37:
            v12 = fs_snapshot(3, v6, (__int64)v22, (__int64)v9, 0, 0) == 0;
            goto LABEL_39;
          }
          v12 = 1;
        }
      }
      else
      {
        v13 = 0;
LABEL_28:
        v12 = 0;
      }
LABEL_39:
      v14 = v13 | (unsigned int)v12;
    }
  }
  else
  {
    v14 = 0;
    LODWORD(v6) = -1;
  }
  v15 = v25;
  v16 = v26;
  if ( v25 )
    v17 = v26 == 0;
  else
    v17 = 1;
  if ( !v17 )
  {
    v18 = (void **)v26;
    do
    {
      v19 = *v18++;
      free(v19);
      --v15;
    }
    while ( v15 );
    free(v16);
  }
  if ( __s2 )
    free(__s2);
  if ( v23 )
    free(v23);
  if ( (int)v6 >= 1 )
    close(v6);
  return v14;
}

//----- (0000000000022ADC) ----------------------------------------------------
__int64 __fastcall enumerate_file_paths(const char *a1, const char *a2)
{
  __int64 v4; // x19
  __int64 v5; // x23
  const char **v6; // x24
  char *v7; // x21
  __int64 v8; // x25
  const char **v9; // x26
  const char *v10; // x22
  char *v11; // x20
  const char *v12; // x22
  int v13; // w9
  int v14; // w8
  __int64 v15; // x20
  __int64 v16; // x22
  void *v17; // x21
  bool v18; // zf
  void **v19; // x23
  int v21; // w0
  char *__s2; // [xsp+0h] [xbp-60h] BYREF
  char *v23; // [xsp+8h] [xbp-58h] BYREF
  unsigned int v24; // [xsp+14h] [xbp-4Ch] BYREF
  void *v25; // [xsp+18h] [xbp-48h] BYREF

  v25 = 0;
  v24 = 0;
  __s2 = 0;
  v23 = 0;
  if ( (unsigned int)get_iodevicetree_chosen_data(&v23, 0)
    && (unsigned int)get_iodevicetree_chosen_data(&__s2, 0x41u)
    && (unsigned int)open_and_kread_ptr_data(a1, &v25, &v24) )
  {
    v4 = open(a1, 0x100000);
    if ( (v4 & 0x80000000) != 0 )
    {
      v15 = 0;
    }
    else
    {
      v5 = v24;
      if ( v24 )
      {
        v6 = (const char **)v25;
        v7 = __s2;
        v8 = v24;
        v9 = (const char **)v25;
        do
        {
          v10 = *v9;
          if ( *v9 && (!strcmp(*v9, v7) || (a2 && !strcmp(v10, a2))) )
          {
            v14 = 0;
            v13 = 1;
            goto LABEL_37;
          }
          ++v9;
          --v8;
        }
        while ( v8 );
        v11 = v23;
        while ( 1 )
        {
          v12 = *v6;
          if ( *v6 )
          {
            if ( !strcmp(*v6, v11) )
              break;
          }
          ++v6;
          if ( !--v5 )
            goto LABEL_16;
        }
        v21 = fs_snapshot(3, v4, (__int64)v12, (__int64)v7, 0, 0);
        v13 = 0;
        v14 = v21 == 0;
      }
      else
      {
LABEL_16:
        v13 = 0;
        v14 = 0;
      }
LABEL_37:
      v15 = v13 | (unsigned int)v14;
    }
  }
  else
  {
    v15 = 0;
    LODWORD(v4) = -1;
  }
  v16 = v24;
  v17 = v25;
  if ( v24 )
    v18 = v25 == 0;
  else
    v18 = 1;
  if ( !v18 )
  {
    v19 = (void **)v25;
    do
    {
      if ( *v19 )
        free(*v19);
      ++v19;
      --v16;
    }
    while ( v16 );
    free(v17);
  }
  if ( (int)v4 >= 1 )
    close(v4);
  if ( v23 )
    free(v23);
  if ( __s2 )
    free(__s2);
  return v15;
}

//----- (0000000000022CA8) ----------------------------------------------------
bool __fastcall check_root_fs_mounted(bool *a1)
{
  uint64_t result; // x0
  int v3; // w8
  char v5[2]; // [xsp+Eh] [xbp-892h] BYREF
  struct statfs v6; // [xsp+10h] [xbp-890h] BYREF

  strcpy(v5, "/");
  bzero(&v6, 0x878u);
  result = getattrlist_check_file(v5);
  if ( result )
  {
    if ( statfs(v5, &v6) )
      return 1;
    v3 = HIBYTE(v6.f_fsid.val[0]) << 24;
    result = v3 != 0x1000000;
    if ( v3 != 0x1000000 && a1 != 0 )
    {
      *a1 = strchr(v6.f_mntfromname, 64) == 0;
      return 1;
    }
  }
  return result;
}
