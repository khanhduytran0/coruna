//----- (0000000000032820) ----------------------------------------------------
__int64 __fastcall ipc_port_kobject_field_offset(struct_krwCtx *krwCtx, __int64 ipc_port)
{
  __int64 result; // x0
  int xnuMajorVersion; // w8
  bool v5; // zf
  int v6; // w9
  __int64 v8; // x8

  result = 0LL;
  xnuMajorVersion = krwCtx->xnuMajorVersion;
  if ( xnuMajorVersion <= 8019 )
  {
    if ( xnuMajorVersion == 6153 || xnuMajorVersion == 7195 )
    {
      v8 = 104LL;
    }
    else
    {
      if ( xnuMajorVersion != 8019 )
        return result;
      v8 = 88LL;
    }
    return v8 + ipc_port;
  }
  if ( xnuMajorVersion > 8795 )
  {
    v5 = xnuMajorVersion == 8796;
    v6 = 10002;
  }
  else
  {
    v5 = xnuMajorVersion == 8020;
    v6 = 8792;
  }
  if ( v5 || xnuMajorVersion == v6 )
  {
    v8 = 72LL;
    return v8 + ipc_port;
  }
  return result;
}

//----- (00000000000328A4) ----------------------------------------------------
unsigned __int64 __fastcall maybe_ipc_port_get_kobject(struct_krwCtx *krwCtx, unsigned __int64 ipc_port_kaddr)
{
  unsigned __int64 result; // x0
  uint64_t xnuVersionPacked; // x8
  int v6; // [xsp+4h] [xbp-1Ch] BYREF
  __int64 v7; // [xsp+8h] [xbp-18h] BYREF

  if ( !kread_u32(krwCtx, ipc_port_kaddr, &v6) )
    return 0;
  result = ipc_port_kobject_field_offset(krwCtx, ipc_port_kaddr);
  if ( !result )
    return result;
  if ( !kread_physmap_decorated(krwCtx, result, (unsigned __int64 *)&v7) )
    return 0;
  result = validate_kaddr_range(krwCtx, v7);
  if ( !result )
    return result;
  xnuVersionPacked = krwCtx->xnuVersionPacked;
  if ( xnuVersionPacked >= XNU_VERSION_PACKED(10002, 0, 0, 0, 0) )
  {
    if ( (v6 & 0x3FFu) > 0x29 || ((1LL << v6) & 0x20068000000LL) == 0 )
      return v7;
    if ( !kread_physmap_decorated(krwCtx, v7 + 48, (unsigned __int64 *)&v7) )
      return 0;
    xnuVersionPacked = krwCtx->xnuVersionPacked;
  }
  if ( xnuVersionPacked > XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) || (v6 & 0x400) == 0 )
    return v7;
  if ( kread_physmap_decorated(krwCtx, v7 + krwCtx->stride_0x168, (unsigned __int64 *)&v7) )
  {
    result = validate_kaddr_range(krwCtx, v7);
    if ( !result )
      return result;
    return v7;
  }
  return 0;
}

//----- (00000000000329B8) ----------------------------------------------------
__int64 __fastcall get_task_struct_offset(struct_krwCtx *krwCtx, __int64 a2)
{
    switch ( krwCtx->xnuMajorVersion ) {
        case 6153:
            if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(6153, 40, 149, 1023, 1023) )
                return a2 + 152;
            else
                return a2 + 144;
        case 7195:
            return a2 + 144;
        case 8019:
            return a2 + 128;
        case 8020:
        case 8792:
        case 8796:
        case 10002:
            return a2 + 112;
        default:
            return 0;
    }
}

//----- (0000000000032A64) ----------------------------------------------------
__int64 __fastcall get_ipc_port_offset_by_version(struct_krwCtx *krwCtx, __int64 a2)
{
    switch ( krwCtx->xnuMajorVersion ) {
        case 6153:
            if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(6153, 40, 149, 1023, 1023) )
                return a2 + 168;
            else
                return a2 + 160;
        case 7195:
                return a2 + 160;
        case 8019:
            return a2 + 144;
        case 8020:
        case 8792:
        case 8796:
        case 10002:
            return a2 + 128;
        default:
            return 0;
    }
}

//----- (0000000000032B10) ----------------------------------------------------
__int64 __fastcall get_privileged_host_port(struct_krwCtx *krwCtx)
{
  host_t v2; // w0
  kern_return_t v3; // w19
  mach_msg_type_number_t info_outCnt; // [xsp+Ch] [xbp-24h] BYREF
  integer_t info_out; // [xsp+10h] [xbp-20h] BYREF
  host_t host; // [xsp+18h] [xbp-18h] BYREF
  processor_set_name_t default_set; // [xsp+1Ch] [xbp-14h] BYREF

  host = 0;
  info_outCnt = 2;
  if ( krwCtx->raw_0x4[6] && getuid() )
  {
    return mach_host_self();
  }
  else
  {
    v2 = mach_host_self();
    v3 = processor_set_default(v2, &default_set);
    if ( !v3 )
    {
      v3 = processor_set_info(default_set, 5, &host, &info_out, &info_outCnt);
      mach_port_deallocate(mach_task_self_, default_set);
    }
    if ( v3 == 53 )
      return mach_host_self();
    else
      return host;
  }
}

//----- (0000000000032BC8) ----------------------------------------------------
__int64 __fastcall get_task_struct_cached_offset(struct_krwCtx *krwCtx)
{
  __int64 v1; // x8
  int v2; // w9
  bool v3; // zf
  int v4; // w10

  v1 = krwCtx->gap_0x174;
  if ( (uint32_t)v1 )
    return v1;
  v2 = krwCtx->xnuMajorVersion;
  if ( v2 <= 8019 )
  {
    switch ( v2 )
    {
      case 6153:
        if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(6153, 40, 149, 1023, 1023) )
          v1 = 176LL;
        else
          v1 = 168LL;
        break;
      case 7195:
        v1 = 168LL;
        break;
      case 8019:
        v1 = 160LL;
        break;
      default:
        return v1;
    }
LABEL_20:
    krwCtx->gap_0x174 = v1;
    return v1;
  }
  if ( v2 > 8795 )
  {
    v3 = v2 == 8796;
    v4 = 10002;
  }
  else
  {
    v3 = v2 == 8020;
    v4 = 8792;
  }
  if ( v3 || v2 == v4 )
  {
    v1 = 144LL;
    goto LABEL_20;
  }
  return v1;
}

//----- (0000000000032C78) ----------------------------------------------------
unsigned __int64 __fastcall get_task_kobject_addr(struct_krwCtx *krwCtx, mach_port_t a2)
{
  mach_port_t v4; // w21
  unsigned __int64 result; // x0
  bool v6; // zf

  v4 = mach_task_self_;
  if ( mach_task_self_ != a2 || (result = *(uint64_t *)&krwCtx->gap_0x1B0) == 0 )
  {
    if ( a2 == -1 )
    {
      return lookup_or_resolve_kaddr(krwCtx);
    }
    else
    {
      result = task_get_ipc_port(krwCtx, mach_task_self_, a2);
      if ( result )
      {
        result = maybe_ipc_port_get_kobject(krwCtx, result);
        v6 = v4 != a2 || result == 0;
        if ( !v6 && !*(uint64_t *)&krwCtx->gap_0x1B0 )
          *(uint64_t *)&krwCtx->gap_0x1B0 = result;
      }
    }
  }
  return result;
}
// 32D14: variable 'vars8' is possibly undefined

//----- (0000000000032D24) ----------------------------------------------------
unsigned __int64 __fastcall lookup_or_resolve_kaddr(struct_krwCtx *krwCtx)
{
  __int64 v1; // x8
  unsigned __int64 v3; // x1
  unsigned int v4; // w1

  v1 = krwCtx->gap_0x19D8;
  if ( v1 )
    return v1;
  v3 = krwCtx->gap_0x19D0_size8;
  if ( v3 )
    return maybe_ipc_port_get_kobject(krwCtx, v3);
  v4 = krwCtx->parentTaskPort;
  if ( v4 == -1 )
    return 0;
  if ( !v4 )
  {
    v4 = krwCtx->targetVmPort;
    if ( v4 + 1 < 2 )
      return 0;
  }
  return get_task_kobject_addr(krwCtx, v4);
}

//----- (0000000000032D6C) ----------------------------------------------------
unsigned __int64 __fastcall task_self_get_ipc_port(struct_krwCtx *krwCtx, mach_port_t port)
{
  return task_get_ipc_port(krwCtx, mach_task_self_, port);
}

//----- (0000000000032D80) ----------------------------------------------------
__int64 __fastcall get_task_struct_field_offset(struct_krwCtx *krwCtx, __int64 addr)
{
  __int64 result; // x0
  int xnuMajorVersion; // w8
  bool v5; // cc
  __int64 off; // x8
  __int64 v7; // x9
  __int64 out; // [xsp+8h] [xbp-18h] BYREF

  result = 0;
  xnuMajorVersion = krwCtx->xnuMajorVersion;
  if ( xnuMajorVersion <= 8791 )
  {
    if ( (unsigned int)(xnuMajorVersion - 8019) < 2 )
    {
      v5 = krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023);
      off = 816;
      v7 = 776;
LABEL_16:
      if ( v5 )
        off = v7;
      goto LABEL_20;
    }
    if ( xnuMajorVersion != 6153 )
    {
      if ( xnuMajorVersion != 7195 )
        return result;
      v5 = krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023);
      off = 816;
      v7 = 824;
      goto LABEL_16;
    }
    off = 800;
LABEL_20:
    if ( !kread_physmap_decorated(krwCtx, off + addr, (unsigned __int64 *)&out) )
      return 0;
    if ( validate_kaddr_range(krwCtx, out) )
      return out;
    return 0;
  }
  if ( xnuMajorVersion == 8792 || xnuMajorVersion == 8796 || xnuMajorVersion == 10002 )
  {
    off = 768;
    goto LABEL_20;
  }
  return result;
}

//----- (0000000000032E84) ----------------------------------------------------
__int64 __fastcall get_task_pid_offset(struct_krwCtx *krwCtx)
{
  __int64 result; // x0
  int v3; // w9

  result = 0LL;
  v3 = krwCtx->xnuMajorVersion;
  if ( v3 > 8791 )
  {
    if ( v3 == 8792 || v3 == 8796 || v3 == 10002 )
      return 696LL;
  }
  else if ( (unsigned int)(v3 - 8019) < 2 )
  {
    if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
      return 744LL;
    else
      return 704LL;
  }
  else if ( v3 == 6153 )
  {
    return 720LL;
  }
  else if ( v3 == 7195 )
  {
    return 736LL;
  }
  return result;
}

//----- (0000000000032F1C) ----------------------------------------------------
__int64 __fastcall task_proc_struct_field_offset(struct_krwCtx *krwCtx)
{
  __int64 result; // x0
  int xnuMajorVersion; // w8
  uint64_t xnuVersionPacked; // x20
  int has_flag; // w0
  unsigned int v6; // w9
  unsigned int v7; // w10
  bool v9; // cc
  unsigned int v10; // w8
  unsigned int v11; // w9
  int v12; // w0
  uint64_t v13; // x8
  bool v14; // cc
  unsigned int v15; // w8
  unsigned int v16; // w9

  result = 0;
  xnuMajorVersion = krwCtx->xnuMajorVersion;
  if ( xnuMajorVersion <= 8791 )
  {
    if ( (unsigned int)(xnuMajorVersion - 8019) >= 2 )
    {
      if ( xnuMajorVersion == 6153 )
      {
        if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) )
          return 904;
        else
          return 896;
      }
      else if ( xnuMajorVersion == 7195 )
      {
        xnuVersionPacked = krwCtx->xnuVersionPacked;
        has_flag = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK);
        if ( has_flag )
          v6 = 928;
        else
          v6 = 912;
        if ( has_flag )
          v7 = 944;
        else
          v7 = 920;
        if ( xnuVersionPacked >= XNU_VERSION_PACKED(7195, 100, 326, 0, 0) )
          return v7;
        else
          return v6;
      }
      return result;
    }
    if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A15) )
    {
      v12 = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK);
      v13 = krwCtx->xnuVersionPacked;
      v14 = v13 > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023);
      if ( v13 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
        v15 = 928;
      else
        v15 = 888;
      if ( v14 )
        v16 = 912;
      else
        v16 = 952;
      if ( v12 )
        return v16;
      else
        return v15;
    }
    v9 = krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023);
    v10 = 968;
    v11 = 928;
LABEL_27:
    if ( v9 )
      return v11;
    else
      return v10;
  }
  if ( xnuMajorVersion == 8792 )
  {
    v9 = krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8792, 60, 50, 1023, 1023);
    v10 = 1328;
    v11 = 1336;
    goto LABEL_27;
  }
  if ( xnuMajorVersion == 8796 || xnuMajorVersion == 10002 )
    return 1840;
  return result;
}

//----- (0000000000033098) ----------------------------------------------------
__int64 __fastcall get_ptrauth_data_ptr_offset(struct_krwCtx *krwCtx)
{
  __int64 result; // x0
  int xnuMajorVersion; // w8

  result = 0;
  xnuMajorVersion = krwCtx->xnuMajorVersion;
  if ( xnuMajorVersion <= 8795 )
  {
    if ( (unsigned int)(xnuMajorVersion - 8019) < 2 )
    {
      if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(8019, 60, 40, 0, 0) )
        return 0;
      else
        return (unsigned int)task_proc_struct_field_offset(krwCtx) + 8;
    }
    if ( xnuMajorVersion != 8792 )
      return result;
    goto LABEL_11;
  }
  if ( xnuMajorVersion == 8796 || xnuMajorVersion == 10002 )
  {
LABEL_11:
    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A15_A16_A17_MASK) )
    {
      return 928;
    }
    else if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) )
    {
      return 904;
    }
    else
    {
      return 880;
    }
  }
  return result;
}

//----- (0000000000033168) ----------------------------------------------------
__int64 __fastcall get_context_version_offset_40(struct_krwCtx *krwCtx)
{
  __int64 result; // x0
  int v3; // w9

  result = 0LL;
  v3 = krwCtx->xnuMajorVersion;
  if ( v3 <= 8795 )
  {
    if ( (unsigned int)(v3 - 8019) >= 2 && v3 != 8792 )
      return result;
LABEL_7:
    if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
      return 0LL;
    else
      return 40LL;
  }
  if ( v3 == 10002 || v3 == 8796 )
    goto LABEL_7;
  return result;
}

//----- (00000000000331D0) ----------------------------------------------------
__int64 __fastcall get_context_version_offset_112(struct_krwCtx *krwCtx)
{
  __int64 result; // x0
  int v3; // w9

  result = 0LL;
  v3 = krwCtx->xnuMajorVersion;
  if ( v3 <= 8795 )
  {
    if ( (unsigned int)(v3 - 8019) >= 2 && v3 != 8792 )
      return result;
LABEL_7:
    if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
      return 0LL;
    else
      return 112LL;
  }
  if ( v3 == 10002 || v3 == 8796 )
    goto LABEL_7;
  return result;
}

//----- (0000000000033238) ----------------------------------------------------
__int64 __fastcall get_version_adjusted_offset(struct_krwCtx *krwCtx)
{
  __int64 result; // x0

  result = get_context_version_offset_112(krwCtx);
  if ( (uint32_t)result )
    return (unsigned int)(result - krwCtx->stride_0x168);
  return result;
}

//----- (0000000000033268) ----------------------------------------------------
unsigned __int64 __fastcall get_ptrauth_base_offset(struct_krwCtx *krwCtx, unsigned int a2)
{
  int v4; // w0
  unsigned int v5; // w21
  unsigned __int64 result; // x0

  if ( krwCtx->xnuMajorVersion >= 8792 )
  {
    v4 = get_ptrauth_data_ptr_offset(krwCtx);
    if ( v4 )
    {
      v5 = v4 - krwCtx->stride_0x168;
      goto LABEL_5;
    }
    return 0;
  }
  v5 = task_proc_struct_field_offset(krwCtx);
  if ( !v5 )
    return 0;
LABEL_5:
  result = get_task_kobject_addr(krwCtx, a2);
  if ( result )
    result += v5 + ((__int64)krwCtx->stride_0x168 << (krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023)));
  return result;
}

//----- (0000000000033304) ----------------------------------------------------
__int64 __fastcall read_kaddr_at_task_offset(struct_krwCtx *krwCtx, __int64 a2)
{
  unsigned int v4; // w0
  __int64 v6; // [xsp+8h] [xbp-18h] BYREF

  v4 = task_proc_struct_field_offset(krwCtx);
  if ( !v4 )
    return 0;
  if ( krwCtx->xnuMajorVersion >= 8792 )
    return a2 - v4;
  if ( !kread_physmap_decorated(krwCtx, v4 + a2, (unsigned __int64 *)&v6) || !v6 )
    return 0;
  if ( validate_kaddr_range(krwCtx, v6) )
    return v6;
  return 0;
}

//----- (000000000003338C) ----------------------------------------------------
__int64 __fastcall get_task_context_size(struct_krwCtx *krwCtx)
{
  __int64 result; // x0
  int v3; // w10
  __int64 v4; // x9

  result = 0LL;
  v3 = krwCtx->xnuMajorVersion;
  v4 = 40LL;
  if ( v3 <= 8791 )
  {
    if ( (unsigned int)(v3 - 8019) >= 2 && v3 != 6153 )
    {
      if ( v3 != 7195 )
        return result;
      if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023) )
        return 40LL;
      else
        return 32LL;
    }
    return v4;
  }
  if ( v3 == 8792 || v3 == 8796 || v3 == 10002 )
    return v4;
  return result;
}

//----- (0000000000033414) ----------------------------------------------------
__int64 __fastcall krw_task_for_pid_0(struct_krwCtx *krwCtx, __int64 a2, int pid)
{
  return krw_task_for_pid_or_name_ret_x0(krwCtx, a2, pid, 0);
}

//----- (000000000003341C) ----------------------------------------------------
__int64 __fastcall krw_task_for_pid_or_name_ret_x0(struct_krwCtx *krwCtx, __int64 a2, int pid, const char *a4)
{
  uint32_t xnuMajorVersion; // w8
  uint64_t pidOffset; // x24
  uint64_t nameOffset; // x25
  int taskContextSize; // w0
  uint32_t taskListNextOffset; // w23
  uint64_t dataBase; // x26
  uint64_t dataSize; // x8
  uint64_t dataEnd; // x20
  uint64_t taskListHead; // [xsp+8h] [xbp-88h] BYREF
  int taskPid; // [xsp+4h] [xbp-8Ch] BYREF
  SearchObj dataSegment; // [xsp+10h] [xbp-80h] BYREF

  xnuMajorVersion = krwCtx->xnuMajorVersion;
  pidOffset = 0;
  nameOffset = 0;
  if ( a4 )
  {
    if ( xnuMajorVersion == 8792 )
      nameOffset = 897;
    else if ( xnuMajorVersion == 8796 || xnuMajorVersion == 10002 )
      nameOffset = 1401;
    else
      return 0;
  }
  else if ( xnuMajorVersion == 8792 || xnuMajorVersion == 8796 || xnuMajorVersion == 10002 )
  {
    pidOffset = 96;
  }
  else if ( xnuMajorVersion == 6153 || xnuMajorVersion == 7195 || (unsigned int)(xnuMajorVersion - 8019) < 2 )
  {
    pidOffset = 104;
  }
  else
  {
    return 0;
  }

  taskContextSize = get_task_context_size(krwCtx);
  if ( !taskContextSize )
    return 0;

  dataBase = 0;
  dataSize = 0;
  dataEnd = 0;
  if ( krwCtx->kernelMachoCtx )
  {
    macho_walk_segment_by_name("__DATA", krwCtx->kernelMachoCtx, &dataSegment);
    dataBase = dataSegment.base_ptr;
    if ( !dataBase )
      return 0;
    dataSize = dataSegment.size;
    if ( !dataSize )
      return 0;
    if ( dataSegment.field_0x00 )
      dataEnd = dataBase + dataSize;
  }

  taskListNextOffset = (uint32_t)(krwCtx->stride_0x168 + taskContextSize);
  for ( int retry = 0; retry != 6; ++retry )
  {
    taskListHead = a2;
    while ( 1 )
    {
      uint64_t task = read_kaddr_at_task_offset(krwCtx, taskListHead);
      if ( task )
      {
        if ( a4 )
        {
          char buf[40];
          if ( !(unsigned int)krw_read_thunk(krwCtx, task + nameOffset, 33, (__int64)&buf) )
            return 0LL;
          if ( !strncmp((const char *)&buf, a4, 0x21u) )
            return taskListHead;
        }
        else
        {
          if ( !(unsigned int)krw_read_thunk(krwCtx, task + pidOffset, 4, (__int64)&taskPid) )
            return 0;
          if ( taskPid == pid )
            return taskListHead;
        }
      }

      if ( !kread_physmap_decorated(krwCtx, taskListHead + taskListNextOffset, &taskListHead) )
        return 0;
      taskListHead = validate_kaddr_range_reloaded(krwCtx, taskListHead);
      if ( !taskListHead )
        break;

      if ( dataEnd && taskListHead >= dataBase && taskListHead < dataEnd )
      {
        if ( !kread_physmap_decorated(krwCtx, taskListHead, &taskListHead) )
          return 0;
        taskListHead = validate_kaddr_range_reloaded(krwCtx, taskListHead);
        if ( !taskListHead )
          break;
      }

      if ( taskListHead == a2 )
        break;
    }
    semaphore_timedwait_ns(krwCtx, 0x3D090u);
  }
  return 0;
}

//----- (00000000000336AC) ----------------------------------------------------
__int64 __fastcall krw_task_for_name(struct_krwCtx *krwCtx, __int64 a2, const char *a3)
{
  return krw_task_for_pid_or_name_ret_x0(krwCtx, a2, 0, a3);
}

//----- (00000000000336B8) ----------------------------------------------------
__int64 __fastcall read_pte_entry_chain(struct_krwCtx *krwCtx, __int64 a2, uint32_t *a3, uint32_t *a4)
{
  __int64 result; // x0
  int xnuMajorVersion; // w8
  __int64 v11; // x23
  unsigned __int64 v14; // x1
  unsigned __int64 v15; // x1
  unsigned __int64 v16; // [xsp+0h] [xbp-40h] BYREF
  unsigned int v17; // [xsp+Ch] [xbp-34h] BYREF

  result = 0;
  v17 = 0;
  xnuMajorVersion = krwCtx->xnuMajorVersion;
  if ( xnuMajorVersion > 8791 )
  {
    if ( xnuMajorVersion != 8792 && xnuMajorVersion != 10002 && xnuMajorVersion != 8796 )
      return result;
  }
  else if ( (unsigned int)(xnuMajorVersion - 8019) >= 2 )
  {
    if ( xnuMajorVersion != 6153 && xnuMajorVersion != 7195 )
      return result;
    v11 = 20;
    goto LABEL_18;
  }
  v11 = 8;
LABEL_18:
  if ( !kread_physmap_decorated(krwCtx, a2 + 32, &v16) )
    return 0;
  v14 = v16;
  if ( !v16 )
    return 0;
  if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8792, 40, 107, 1023, 1023) )
  {
    v14 = decode_pte_to_physmap_addr(krwCtx, v16, &v17);
    v16 = v14;
  }
  result = validate_kaddr_range(krwCtx, v14);
  v16 = result;
  if ( result )
  {
    if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8792, 40, 107, 1023, 1023) )
    {
      if ( krwCtx->xnuMajorVersion < 7938 )
        v15 = v11 + a2;
      else
        v15 = result + v11;
      if ( kread_u32(krwCtx, v15, &v17) )
        goto LABEL_30;
    }
    else if ( v17 )
    {
      v17 /= 0x18u;
LABEL_30:
      *a3 = v17;
      *a4 = 24;
      return v16;
    }
    return 0;
  }
  return result;
}

//----- (000000000003382C) ----------------------------------------------------
__int64 __fastcall setup_task_port_chain(struct_krwCtx *krwCtx, mach_port_name_t task, uint32_t *a3, uint32_t *a4)
{
  // struct_krwCtx *krwCtx; // x21
  uint64_t cachedTaskKaddr; // x1
  uint64_t selfPortKobject; // x23
  uint64_t taskListEntry; // x23
  uint64_t registeredTaskPort; // x0
  uint64_t registeredTaskPortOffset; // x8
  uint64_t taskKaddr; // x0
  mach_port_t init_port_set; // [xsp+4h] [xbp-3Ch] BYREF
  int pid; // [xsp+8h] [xbp-38h] BYREF

  if ( mach_task_self_ == task )
  {
    cachedTaskKaddr = krwCtx->gap_0x1A0;
    if ( cachedTaskKaddr )
      return read_pte_entry_chain(krwCtx, cachedTaskKaddr, a3, a4);
  }

  if ( !krwCtx->gap_0x19D0_size8 )
    return 0;
  selfPortKobject = maybe_ipc_port_get_kobject(krwCtx, krwCtx->gap_0x19D0_size8);
  if ( !selfPortKobject )
    return 0;

  if ( krwCtx->targetVmPort + 1 <= 1 )
  {
    pid = 0;
    if ( pid_for_task(task, &pid) )
      return 0;
    taskListEntry = krw_task_for_pid_or_name_ret_x0(krwCtx, selfPortKobject, pid, 0);
    if ( !taskListEntry )
      return 0;
  }
  else
  {
    init_port_set = task;
    if ( mach_ports_register(krwCtx->targetVmPort, &init_port_set, 1u) )
      return 0;

    if ( krwCtx->xnuMajorVersion == 6153 )
      registeredTaskPortOffset = 776;
    else if ( krwCtx->xnuMajorVersion == 7195 )
      registeredTaskPortOffset = 792;
    else
      return 0;

    registeredTaskPort = 0;
    if ( !kread_physmap_decorated(krwCtx, selfPortKobject + registeredTaskPortOffset, &registeredTaskPort) )
      return 0;
    registeredTaskPort = validate_kaddr_range_reloaded(krwCtx, registeredTaskPort);
    if ( !registeredTaskPort )
      return 0;
    taskListEntry = maybe_ipc_port_get_kobject(krwCtx, registeredTaskPort);
    if ( !taskListEntry )
      return 0;

    init_port_set = 0;
    if ( mach_ports_register(krwCtx->targetVmPort, &init_port_set, 1u) )
      return 0;
  }

  taskKaddr = kreadptr(krwCtx, taskListEntry);
  if ( !taskKaddr )
    return 0;
  if ( mach_task_self_ == task )
    krwCtx->gap_0x1A0 = taskKaddr;
  return read_pte_entry_chain(krwCtx, taskKaddr, a3, a4);
}

//----- (00000000000339B4) ----------------------------------------------------
__int64 __fastcall task_get_ipc_port_ptr(struct_krwCtx *krwCtx, mach_port_name_t task, mach_port_t port)
{
  __int64 result; // x0
  int v5; // [xsp+8h] [xbp-18h] BYREF
  mach_port_t v6; // [xsp+Ch] [xbp-14h] BYREF

  if ( port + 1 < 2 )
    return 0;
  result = setup_task_port_chain(krwCtx, task, &v6, &v5);
  if ( !result )
    return result;
  if ( port >> 8 >= v6 )
    return 0;
  result += v5 * (port >> 8);
  return result;
}

//----- (0000000000033A1C) ----------------------------------------------------
__int64 __fastcall task_self_get_ipc_port_ptr(struct_krwCtx *krwCtx, unsigned int a2)
{
  return task_get_ipc_port_ptr(krwCtx, mach_task_self_, a2);
}

//----- (0000000000033A30) ----------------------------------------------------
unsigned __int64 __fastcall task_get_ipc_port(struct_krwCtx *krwCtx, mach_port_name_t task, mach_port_t port)
{
  unsigned __int64 result; // x0
  __int64 vaddr; // [xsp+8h] [xbp-18h] BYREF

  result = task_get_ipc_port_ptr(krwCtx, task, port);
  if ( result )
  {
    if ( kread_physmap_decorated(krwCtx, result, (unsigned __int64 *)&vaddr) )
      return validate_kaddr_range(krwCtx, vaddr);
    else
      return 0;
  }
  return result;
}

//----- (0000000000033A88) ----------------------------------------------------
__int64 __fastcall walk_kaddr_chain_to_target(struct_krwCtx *krwCtx, __int64 a2, char a3)
{
  __int64 result; // x0
  unsigned __int64 v6; // x1
  __int64 v7; // [xsp+8h] [xbp-28h] BYREF
  __int64 v8; // [xsp+10h] [xbp-20h] BYREF
  __int64 v9; // [xsp+18h] [xbp-18h] BYREF

  v7 = 0;
  if ( !kread_physmap_decorated(krwCtx, a2 + 16LL * ((krwCtx->xnuVersionPacked - XNU_VERSION_PACKED(8020, 100, 0, 0, 0)) >> 32 > 4), (unsigned __int64 *)&v9) )
    return 0;
  result = validate_kaddr_range(krwCtx, v9);
  if ( !result )
    return result;
  result = v9;
  if ( krwCtx->xnuMajorVersion < 7195 )
  {
    v7 = v9;
    return result;
  }
  if ( !kread_physmap_decorated(krwCtx, v9 + 32, (unsigned __int64 *)&v8) )
    return 0;
  result = validate_kaddr_range(krwCtx, v8);
  if ( result )
  {
    result = v8;
    if ( (a3 & 1) == 0 )
    {
      if ( kread64_internal(krwCtx, v8 + 56, &v7) )
      {
        v6 = v7;
        if ( krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(8020, 140, 30, 0, 0) )
        {
          v6 = port_right_index_to_kaddr(krwCtx, HIDWORD(v7));
          v7 = v6;
        }
        return validate_kaddr_range(krwCtx, v6);
      }
      else
      {
        return v7;
      }
    }
  }
  return result;
}

//----- (0000000000033B98) ----------------------------------------------------
__int64 __fastcall traverse_sptm_pgtable_chain(struct_krwCtx *krwCtx, unsigned int a2, unsigned __int64 a3)
{
  unsigned __int64 v5; // x0
  __int64 v6; // x20
  unsigned int v7; // w25
  char v8; // w26
  unsigned __int64 v9; // x22
  int v10; // w23
  __int64 v11; // x24
  unsigned __int64 v12; // x1
  unsigned __int64 v15; // [xsp+8h] [xbp-58h] BYREF
  unsigned __int64 v16; // [xsp+10h] [xbp-50h] BYREF
  __int64 v17; // [xsp+18h] [xbp-48h] BYREF

  v5 = find_kernel_struct_addr(krwCtx, a2);
  v6 = 0;
  if ( v5 )
  {
    v7 = 0;
    v8 = 0;
    v9 = v5 + 56;
    while ( 1 )
    {
      v10 = kread_physmap_decorated(krwCtx, v9, (unsigned __int64 *)&v17);
      if ( v10 )
      {
        do
        {
          v11 = v17;
          if ( !v17 || !validate_kaddr_range(krwCtx, v17) || !kread_physmap_decorated(krwCtx, v11 - 16, &v16) )
            break;
          if ( v16 <= a3 )
          {
            if ( !kread_physmap_decorated(krwCtx, v11 - 8, &v15) )
              break;
            if ( v15 > a3 )
            {
              v6 = v11 - 32;
              v8 = 1;
              if ( v10 )
                goto LABEL_14;
              return v6;
            }
            v12 = v17 + 8;
          }
          else
          {
            v12 = v17;
          }
        }
        while ( kread_physmap_decorated(krwCtx, v12, (unsigned __int64 *)&v17) );
      }
      if ( !v10 )
        break;
LABEL_14:
      if ( (v8 & 1) == 0 && v7++ < 5 )
        continue;
      return v6;
    }
  }
  return v6;
}

//----- (0000000000033CB0) ----------------------------------------------------
unsigned __int64 __fastcall find_kernel_struct_addr(struct_krwCtx *krwCtx, unsigned int a2)
{
  unsigned int v4; // w0
  unsigned int v5; // w20
  unsigned __int64 result; // x0
  __int64 v7; // [xsp+8h] [xbp-28h] BYREF

  v4 = get_task_context_size(krwCtx);
  if ( !v4 )
    return 0;
  v5 = v4;
  result = get_task_kobject_addr(krwCtx, a2);
  v7 = result;
  if ( !result )
    return result;
  if ( !kread_physmap_decorated(krwCtx, result + v5, (unsigned __int64 *)&v7) )
    return 0;
  if ( validate_kaddr_range(krwCtx, v7) )
    return v7;
  return 0;
}

//----- (0000000000033D38) ----------------------------------------------------
unsigned __int64 __fastcall scan_and_validate_kaddr(struct_krwCtx *krwCtx, unsigned int port, unsigned __int64 a3, unsigned __int64 *a4)
{
  unsigned __int64 result; // x0
  __int64 v9; // x8
  unsigned __int64 v10; // x1
  __int64 v11; // x8
  unsigned __int64 v12; // x8
  __int64 v13; // x0
  unsigned __int64 v14; // x1
  uint64_t v15[2]; // [xsp+0h] [xbp-30h] BYREF

  if ( !krw_ctx_has_flag((struct_krwCtx *)krwCtx, KRW_CTX_FLAG_SELF_TASK_PORT_CLEARED) )
  {
    v13 = traverse_sptm_pgtable_chain((struct_krwCtx *)krwCtx, port, a3);
    if ( v13 && (unsigned int)krw_read_thunk((struct_krwCtx *)krwCtx, v13 + 56, 16, v15) )
    {
      v14 = v15[0];
      if ( krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(8020, 140, 30, 0, 0) )
      {
        v14 = port_right_index_to_kaddr(krwCtx, HIDWORD(v15[0]));
        v15[0] = v14;
      }
      if ( validate_kaddr_range(krwCtx, v14) )
      {
        result = v15[0];
        *a4 = v15[1] & 0xFFFFFFFFFFFFF000LL;
        return result;
      }
    }
    return 0;
  }
  result = mach_vm_page_info_query_0(port, a3, a4);
  if ( !result )
    return result;
  if ( (result & 1) != 0 )
  {
    v10 = result - krwCtx->gap_0x138;
    if ( HIDWORD(result) )
    {
      if ( HIDWORD(v10) )
        goto LABEL_20;
    }
    else
    {
      v10 = (unsigned int)(result - (uint32_t)krwCtx->gap_0x138);
    }
    v12 = krwCtx->gap_0x130;
    if ( v12 )
      goto LABEL_19;
    return 0;
  }
  v9 = krwCtx->gap_0x19E0_size8;
  if ( !v9 )
    return 0;
  v10 = v9 + result;
  if ( !((v9 + result) >> 32) )
  {
    v11 = krwCtx->machHeaderPlus0x8000;
    if ( v11 )
    {
      v12 = v11 & 0xFFFFFFFF00000000LL;
LABEL_19:
      v10 |= v12;
      goto LABEL_20;
    }
    return 0;
  }
LABEL_20:
  return validate_kaddr_range(krwCtx, v10);
}

//----- (0000000000033E8C) ----------------------------------------------------
unsigned __int64 __fastcall kread_task_struct(struct_krwCtx *krwCtx, unsigned int a2)
{
  unsigned __int64 result; // x0

  result = get_task_kobject_addr(krwCtx, a2);
  if ( result )
  {
    return read_kaddr_at_task_offset(krwCtx, result);
  }
  return result;
}
// 33EBC: variable 'vars8' is possibly undefined

//----- (0000000000033ED8) ----------------------------------------------------
__int64 __fastcall walk_task_kaddr_chain(struct_krwCtx *krwCtx, __int64 a2)
{
  __int64 result; // x0
  __int64 v4; // x8
  int xnuMajorVersion; // w8
  __int64 v6; // x8
  __int64 v7; // [xsp+8h] [xbp-18h] BYREF

  result = read_kaddr_at_task_offset(krwCtx, a2);
  v7 = result;
  if ( result )
  {
    if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
    {
      v4 = 32;
      if ( krwCtx->xnuMajorVersion > 8791 )
        v4 = 24;
      if ( !kread_physmap_decorated(krwCtx, v4 + result, (unsigned __int64 *)&v7) )
        return 0;
      result = validate_kaddr_range(krwCtx, v7);
      if ( !result )
        return result;
    }
    result = 0;
    xnuMajorVersion = krwCtx->xnuMajorVersion;
    if ( xnuMajorVersion <= 8791 )
    {
      if ( (unsigned int)(xnuMajorVersion - 8019) < 2 )
      {
        v6 = 216;
        if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
          v6 = 32;
      }
      else if ( xnuMajorVersion == 6153 )
      {
        v6 = 256;
      }
      else
      {
        if ( xnuMajorVersion != 7195 )
          return result;
        v6 = 240;
      }
      return v7 + v6;
    }
    if ( xnuMajorVersion == 8792 || xnuMajorVersion == 8796 || xnuMajorVersion == 10002 )
    {
      v6 = 32;
      return v7 + v6;
    }
  }
  return result;
}

//----- (0000000000033FFC) ----------------------------------------------------
unsigned __int64 __fastcall get_task_kobj_and_walk_chain(struct_krwCtx *krwCtx, mach_port_t a2)
{
  unsigned __int64 result; // x0

  result = get_task_kobject_addr(krwCtx, a2);
  if ( result )
  {
    return walk_task_kaddr_chain(krwCtx, result);
  }
  return result;
}
// 3402C: variable 'vars8' is possibly undefined

//----- (0000000000034048) ----------------------------------------------------
unsigned __int64 __fastcall resolve_task_kobj_kaddr(struct_krwCtx *krwCtx, __int64 a2, uint64_t *a3)
{
  unsigned __int64 result; // x0
  unsigned __int64 v6; // x21
  __int64 v7; // [xsp+0h] [xbp-30h] BYREF
  __int64 v8; // [xsp+8h] [xbp-28h] BYREF

  result = walk_task_kaddr_chain(krwCtx, a2);
  if ( result )
  {
    v6 = result;
    if ( kread_physmap_decorated(krwCtx, result, (unsigned __int64 *)&v8) )
    {
      result = validate_kaddr_range(krwCtx, v8);
      if ( !result )
        return result;
      if ( !a3 )
        return v8;
      if ( kread64_internal(krwCtx, v6, &v7) )
      {
        *a3 = v7;
        return v8;
      }
    }
    return 0;
  }
  return result;
}

//----- (00000000000340D8) ----------------------------------------------------
__int64 __fastcall get_kobj_and_resolve_kaddr(struct_krwCtx *krwCtx, unsigned int a2, uint64_t *a3)
{
  __int64 result; // x0

  result = get_task_kobject_addr(krwCtx, a2);
  if ( result )
  {
    return resolve_task_kobj_kaddr(krwCtx, result, a3);
  }
  return result;
}
// 34110: variable 'vars8' is possibly undefined

//----- (000000000003412C) ----------------------------------------------------
unsigned __int64 __fastcall get_task_kobj_kaddr_with_flags(struct_krwCtx *krwCtx, unsigned int a2)
{
  unsigned __int64 result; // x0
  unsigned __int64 v4; // x20
  int xnuMajorVersion; // w8
  __int64 v7; // x8
  bool v8; // zf
  __int64 v9; // x9
  unsigned __int64 v10; // x1
  unsigned __int64 v11; // [xsp+8h] [xbp-18h] BYREF

  result = get_task_kobject_addr(krwCtx, a2);
  if ( result )
  {
    v4 = result;
    xnuMajorVersion = krwCtx->xnuMajorVersion;
    if ( (unsigned int)(xnuMajorVersion - 8019) >= 2 && xnuMajorVersion != 7195 )
    {
      if ( xnuMajorVersion != 6153 )
        return 0;
      v8 = !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A11_TO_A17_OR_SELF_TASK_PORT_MASK);
      v7 = 960;
      v9 = 984;
      goto LABEL_13;
    }
    if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(7195, 100, 326, 0, 0) )
    {
      v8 = !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A11_TO_A17_OR_SELF_TASK_PORT_MASK);
      v7 = 1048;
      v9 = 1120;
    }
    else
    {
      if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A15) )
      {
        v7 = 1264;
LABEL_15:
        v10 = v4 + v7;
        if ( krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(8019, 60, 40, 0, 0) )
        {
          v11 = v4 + v7;
          goto LABEL_19;
        }
        if ( kread_physmap_decorated(krwCtx, v10, &v11) )
        {
          v10 = v11;
LABEL_19:
          if ( validate_kaddr_range(krwCtx, v10) )
            return v11;
          else
            return 0;
        }
        return 0;
      }
      if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A13_A14_MASK) )
      {
        v7 = 1256;
        goto LABEL_15;
      }
      if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12) )
      {
        v7 = 1248;
        goto LABEL_15;
      }
      v8 = !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A11);
      v7 = 1232;
      v9 = 1296;
    }
LABEL_13:
    if ( v8 )
      v7 = v9;
    goto LABEL_15;
  }
  return result;
}

//----- (0000000000034298) ----------------------------------------------------
unsigned __int64 __fastcall get_task_kobj_dispatch(struct_krwCtx *krwCtx, unsigned int a2)
{
  unsigned __int64 v3; // x0
  unsigned __int64 result; // x0
  int v5; // w8
  __int64 v6; // x8

  if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(8019, 60, 40, 0, 0) )
  {
    result = get_task_kobj_kaddr_with_flags(krwCtx, a2);
    if ( !result )
      return result;
    v5 = krwCtx->xnuMajorVersion;
    switch ( v5 )
    {
      case 8019:
        v6 = 288;
        break;
      case 7195:
        v6 = 296;
        break;
      case 6153:
        v6 = 336;
        if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(6153, 40, 149, 1023, 1023) )
          v6 = 296;
        break;
      default:
        return 0;
    }
    result += v6;
    return result;
  }
  v3 = get_task_kobj_via_physmap(krwCtx, a2);
  if ( v3 )
    return v3 + 8;
  else
    return 0;
}

//----- (0000000000034358) ----------------------------------------------------
unsigned __int64 __fastcall get_task_kobj_via_physmap(struct_krwCtx *krwCtx, unsigned int a2)
{
  unsigned int v4; // w0
  unsigned int v5; // w21
  unsigned __int64 result; // x0
  __int64 v7; // [xsp+8h] [xbp-28h] BYREF

  v7 = 0;
  v4 = thread_port_field_offset(krwCtx);
  if ( !v4 )
    return 0;
  v5 = v4;
  result = get_task_kobject_addr(krwCtx, a2);
  if ( !result )
    return result;
  if ( !kread_physmap_decorated(krwCtx, result + v5, (unsigned __int64 *)&v7) )
    return 0;
  if ( validate_kaddr_range(krwCtx, v7) )
    return v7;
  return 0;
}

//----- (00000000000343E0) ----------------------------------------------------
__int64 __fastcall thread_port_field_offset(struct_krwCtx *krwCtx)
{
  __int64 result; // x0
  int xnuMajorVersion; // w8
  unsigned int v4; // w8
  uint64_t xnuVersionPacked; // x9
  unsigned int v6; // w10
  unsigned __int64 v7; // x11

  result = 0;
  xnuMajorVersion = krwCtx->xnuMajorVersion;
  if ( xnuMajorVersion > 8795 )
  {
    if ( xnuMajorVersion != 8796 )
    {
      if ( xnuMajorVersion != 10002 )
        return result;
      if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A17) )
      {
        v4 = 960;
      }
      else if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A15_A16_MASK) )
      {
        v4 = 880;
      }
      else if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A13_A14_MASK) )
      {
        v4 = 872;
      }
      else if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12) )
      {
        v4 = 856;
      }
      else
      {
        v4 = 904;
      }
      xnuVersionPacked = krwCtx->xnuVersionPacked;
      v6 = v4 + 16;
      v7 = XNU_VERSION_PACKED(10002, 42, 7, 1023, 1023);
LABEL_37:
      if ( xnuVersionPacked <= v7 )
        return v4;
      else
        return v6;
    }
  }
  else
  {
    if ( (unsigned int)(xnuMajorVersion - 8019) < 2 )
    {
      if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(8019, 60, 40, 0, 0) )
        return 0;
      if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A15) )
      {
        v4 = 928;
      }
      else if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A13_A14_MASK) )
      {
        v4 = 920;
      }
      else if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12) )
      {
        v4 = 912;
      }
      else if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A11) )
      {
        v4 = 896;
      }
      else
      {
        v4 = 960;
      }
      xnuVersionPacked = krwCtx->xnuVersionPacked;
      v6 = v4 - 8;
      v7 = XNU_VERSION_PACKED(8020, 119, 1023, 1023, 1023);
      goto LABEL_37;
    }
    if ( xnuMajorVersion != 8792 )
      return result;
  }
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A15_A16_MASK) )
    return 888;
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A13_A14_MASK) )
    return 880;
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12) )
    return 864;
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A11) )
    return 848;
  return 912;
}

//----- (00000000000345D4) ----------------------------------------------------
__int64 __fastcall get_task_kobj_with_offset(struct_krwCtx *krwCtx, unsigned int a2)
{
  unsigned __int64 v3; // x0
  __int64 v4; // x8
  int v5; // w9
  __int64 v6; // x8

  v3 = get_task_kobj_kaddr_with_flags(krwCtx, a2);
  v4 = 0;
  if ( v3 )
  {
    v5 = krwCtx->xnuMajorVersion;
    if ( v5 > 8018 )
    {
      if ( v5 == 8019 )
      {
        v6 = 256;
        return v6 + v3;
      }
      if ( v5 == 8020 )
      {
        v6 = 240;
        return v6 + v3;
      }
    }
    else
    {
      if ( v5 == 6153 )
      {
        v6 = 304;
        if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(6153, 40, 149, 1023, 1023) )
          v6 = 264;
        return v6 + v3;
      }
      if ( v5 == 7195 )
      {
        v6 = 264;
        return v6 + v3;
      }
    }
  }
  return v4;
}

//----- (0000000000034680) ----------------------------------------------------
unsigned __int64 __fastcall get_task_csflags_kaddr(struct_krwCtx *krwCtx, unsigned int a2)
{
  unsigned __int64 v3; // x0
  __int64 v4; // x8
  int v5; // w9
  __int64 v6; // x8

  if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
    v3 = kread_task_struct(krwCtx, a2);
  else
    v3 = kread_physmap_two_hops(krwCtx, a2);
  v4 = 0;
  if ( !v3 )
    return v4;
  v5 = krwCtx->xnuMajorVersion;
  if ( v5 > 8791 )
  {
    if ( v5 != 8792 && v5 != 8796 && v5 != 10002 )
      return v4;
LABEL_13:
    v6 = 768;
    if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
      v6 = 28;
    return v6 + v3;
  }
  if ( (unsigned int)(v5 - 8019) < 2 )
    goto LABEL_13;
  if ( v5 == 6153 )
  {
    v6 = 664;
    return v6 + v3;
  }
  if ( v5 == 7195 )
  {
    v6 = 640;
    return v6 + v3;
  }
  return v4;
}

//----- (0000000000034754) ----------------------------------------------------
__int64 __fastcall kread_physmap_two_hops(struct_krwCtx *krwCtx, unsigned int a2)
{
  unsigned int v4; // w0
  unsigned int v5; // w21
  __int64 result; // x0
  __int64 v7; // x20
  __int64 v8; // x0
  __int64 v10; // [xsp+0h] [xbp-30h] BYREF
  __int64 v11; // [xsp+8h] [xbp-28h] BYREF

  v4 = get_ptrauth_data_ptr_offset(krwCtx);
  if ( !v4 )
    return 0;
  v5 = v4;
  result = get_task_kobject_addr(krwCtx, a2);
  if ( !result )
    return result;
  v7 = result;
  result = validate_kaddr_range(krwCtx, result);
  if ( !result )
    return result;
  if ( !kread_physmap_decorated(krwCtx, v7 + v5, (unsigned __int64 *)&v11) )
    return 0;
  result = validate_kaddr_range(krwCtx, v11);
  if ( !result )
    return result;
  if ( !kread_physmap_decorated(krwCtx, v11 + 8, (unsigned __int64 *)&v10) )
    return 0;
  v8 = validate_kaddr_range(krwCtx, v10);
  if ( v7 != v10 || v8 == 0 )
    return 0;
  else
    return v11;
}

//----- (000000000003481C) ----------------------------------------------------
__int64 __fastcall get_task_struct_csblob_offset(struct_krwCtx *krwCtx)
{
  __int64 result; // x0
  int v3; // w8

  result = 0LL;
  v3 = krwCtx->xnuMajorVersion;
  if ( v3 <= 8019 )
  {
    if ( v3 == 6153 || v3 == 7195 )
      return 268LL;
    if ( v3 == 8019 )
      return 284LL;
    return result;
  }
  if ( v3 > 8795 )
  {
    if ( v3 != 8796 )
    {
      if ( v3 == 10002 )
        return 200LL;
      return result;
    }
    return 180LL;
  }
  if ( v3 == 8020 )
    return 148LL;
  if ( v3 == 8792 )
    return 180LL;
  return result;
}

//----- (00000000000348BC) ----------------------------------------------------
__int64 __fastcall get_task_struct_small_offset(struct_krwCtx *krwCtx)
{
  __int64 result; // x0
  int v3; // w8
  bool v4; // zf
  int v5; // w9

  result = 0LL;
  v3 = krwCtx->xnuMajorVersion;
  if ( v3 <= 8019 )
  {
    if ( v3 == 6153 || v3 == 7195 || v3 == 8019 )
      return 72LL;
  }
  else
  {
    if ( v3 > 8795 )
    {
      v4 = v3 == 10002;
      v5 = 8796;
    }
    else
    {
      v4 = v3 == 8020;
      v5 = 8792;
    }
    if ( v4 || v3 == v5 )
      return 64LL;
  }
  return result;
}

//----- (000000000003492C) ----------------------------------------------------
__int64 __fastcall walk_task_context_to_kobj(struct_krwCtx *krwCtx, __int64 a2)
{
  unsigned int v4; // w0
  __int64 result; // x0
  unsigned int v6; // w0
  __int64 v7; // [xsp+0h] [xbp-20h] BYREF
  __int64 v8; // [xsp+8h] [xbp-18h] BYREF

  v4 = get_task_context_size(krwCtx);
  if ( !v4 || !kread_physmap_decorated(krwCtx, a2 + v4, (unsigned __int64 *)&v8) )
    return 0;
  result = validate_kaddr_range(krwCtx, v8);
  if ( !result )
    return result;
  v6 = get_task_struct_small_offset(krwCtx);
  if ( !v6 || !kread_physmap_decorated(krwCtx, v8 + v6, (unsigned __int64 *)&v7) )
    return 0;
  if ( validate_kaddr_range(krwCtx, v7) )
    return v7;
  return 0;
}

//----- (00000000000349C8) ----------------------------------------------------
unsigned __int64 __fastcall task_struct_field_kread(struct_krwCtx *krwCtx, unsigned int a2)
{
  unsigned int v4; // w0
  unsigned int v5; // w20
  unsigned __int64 result; // x0
  unsigned __int64 v7; // [xsp+8h] [xbp-28h] BYREF

  v4 = get_task_struct_small_offset(krwCtx);
  if ( !v4 )
    return 0;
  v5 = v4;
  result = find_kernel_struct_addr(krwCtx, a2);
  v7 = result;
  if ( result )
  {
    if ( kread_physmap_decorated(krwCtx, result + v5, &v7) )
      return v7;
    else
      return 0;
  }
  return result;
}

//----- (0000000000034A40) ----------------------------------------------------
__int64 __fastcall kread_task_port_entry(struct_krwCtx *krwCtx, __int64 a2)
{
  __int64 result; // x0
  int v4; // w8
  int v5; // w9
  __int64 v6; // x8
  __int64 v7; // x8
  unsigned __int64 v8; // x8
  unsigned __int64 v9; // x8
  uint64_t v10; // [xsp+8h] [xbp-38h] BYREF
  __int64 v11; // [xsp+10h] [xbp-30h] BYREF
  __int64 v12; // [xsp+18h] [xbp-28h] BYREF
  __int64 v13; // [xsp+20h] [xbp-20h] BYREF

  v12 = 0;
  v13 = 0;
  result = resolve_task_kobj_kaddr(krwCtx, a2, 0);
  if ( !result )
    return result;
  result = kread_physmap_decorated(krwCtx, result + 120, (unsigned __int64 *)&v11);
  if ( !(uint32_t)result )
    return result;
  result = validate_kaddr_range(krwCtx, v11);
  if ( !result )
    return result;
  result = 0;
  v4 = krwCtx->xnuMajorVersion;
  if ( v4 > 8791 )
  {
    if ( v4 == 8792 || v4 == 10002 )
      goto LABEL_12;
    v5 = 8796;
  }
  else
  {
    if ( (unsigned int)(v4 - 8019) < 2 || v4 == 6153 )
      goto LABEL_12;
    v5 = 7195;
  }
  if ( v4 != v5 )
    return result;
LABEL_12:
  result = kread_physmap_decorated(krwCtx, v11 + krwCtx->stride_0x168, (unsigned __int64 *)&v12);
  if ( !(uint32_t)result )
    return result;
  if ( (unsigned __int64)(v12 + 1) >= 2 && !validate_kaddr_range(krwCtx, v12) )
  {
    v8 = krwCtx->xnuVersionPacked;
    if ( v8 <= XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
      return 0;
    if ( (krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 && (v12 & 0x7FFFFFFFFFLL) == 0 )
    {
      v12 = 0;
    }
    else if ( v8 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
    {
      return 0;
    }
  }
  if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) && (krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 )
  {
    result = kread64_internal(krwCtx, v11 + krwCtx->stride_0x168, &v10);
    if ( !(uint32_t)result )
      return result;
    v6 = v10;
  }
  else
  {
    v6 = v12;
  }
        krwCtx->gap_0x3A0 = v6;
  result = kread_physmap_decorated(
             krwCtx,
             v11 + (unsigned int)(2 * krwCtx->stride_0x168),
             (unsigned __int64 *)&v13);
  if ( (uint32_t)result )
  {
    if ( (unsigned __int64)(v13 + 1) < 2 || validate_kaddr_range(krwCtx, v13) )
      goto LABEL_23;
    v9 = krwCtx->xnuVersionPacked;
    if ( v9 > XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
    {
      if ( (krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 && (v13 & 0x7FFFFFFFFFLL) == 0 )
      {
        v13 = 0;
      }
      else if ( v9 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
      {
        return 0;
      }
LABEL_23:
      if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) || (krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) == 0 )
      {
        v7 = v13;
        krwCtx->gap_0x3A8 = v13;
        goto LABEL_28;
      }
      result = kread64_internal(krwCtx, v11 + (unsigned int)(2 * krwCtx->stride_0x168), &v10);
      if ( (uint32_t)result )
      {
        krwCtx->gap_0x3A8 = v10;
        v7 = v13;
LABEL_28:
        krwCtx->gap_0x390 = v12;
        krwCtx->gap_0x398 = v7;
        krwCtx->gap_0x378 = 0x100000000LL;
        krwCtx->gap_0x18F0 = v11;
        LODWORD(krwCtx->gap_0x18F8) = 0;
        return 1;
      }
      return result;
    }
    return 0;
  }
  return result;
}

//----- (0000000000034D14) ----------------------------------------------------
__int64 __fastcall necp_set_opt_string_6(struct_krwCtx *krwCtx, unsigned int a2)
{
  __int64 result; // x0

  result = get_task_kobject_addr(krwCtx, a2);
  if ( result )
  {
    result = kread_task_port_entry(krwCtx, result);
    if ( (uint32_t)result )
    {
      krwCtx->gap_0x18F8 = a2;
      return 1;
    }
  }
  return result;
}

//----- (0000000000034D58) ----------------------------------------------------
unsigned __int64 __fastcall get_task_port_kaddr(struct_krwCtx *krwCtx, unsigned int a2, int a3)
{
  unsigned __int64 result; // x0
  unsigned __int64 v5; // x8
  int xnuMajorVersion; // w9
  int v7; // w10
  unsigned __int64 v8; // x19
  int v9; // w8
  unsigned __int64 v10; // x21
  int v11; // w0
  __int64 v12; // x9
  __int64 v13; // x10
  __int64 v14; // x8
  bool v15; // zf
  __int64 v16; // x9
  int has_flag; // w0
  unsigned __int64 xnuVersionPacked; // x8
  bool v19; // cc

  if ( a3 )
  {
    result = kread_physmap_two_hops(krwCtx, a2);
    if ( !result )
      return result;
    v5 = result;
    result = 0;
    xnuMajorVersion = krwCtx->xnuMajorVersion;
    if ( xnuMajorVersion > 8795 )
    {
      if ( xnuMajorVersion != 10002 )
      {
        v7 = 8796;
LABEL_20:
        if ( xnuMajorVersion != v7 )
          return result;
      }
    }
    else if ( xnuMajorVersion != 8020 )
    {
      v7 = 8792;
      goto LABEL_20;
    }
    return v5 + 120;
  }
  result = get_task_kobject_addr(krwCtx, a2);
  if ( !result )
    return result;
  v8 = result;
  result = 0;
  v9 = krwCtx->xnuMajorVersion;
  if ( v9 <= 8791 )
  {
    if ( (unsigned int)(v9 - 8019) < 2 )
    {
      if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A15) )
      {
        v14 = 1052;
        if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
          v14 = 1004;
        return v14 + v8;
      }
      has_flag = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK);
      xnuVersionPacked = krwCtx->xnuVersionPacked;
      v16 = 1000;
      if ( xnuVersionPacked > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
        v16 = 952;
      v19 = xnuVersionPacked > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023);
      v14 = 1036;
      if ( v19 )
        v14 = 988;
      v15 = !has_flag;
    }
    else
    {
      if ( v9 != 6153 )
      {
        if ( v9 != 7195 )
          return result;
        v10 = krwCtx->xnuVersionPacked;
        v11 = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK);
        v12 = 1012;
        if ( !v11 )
          v12 = 984;
        v13 = 1028;
        if ( !v11 )
          v13 = 992;
        if ( v10 >= XNU_VERSION_PACKED(7195, 100, 326, 0, 0) )
          v14 = v13;
        else
          v14 = v12;
        return v14 + v8;
      }
      v15 = !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK);
      v14 = 960;
      v16 = 952;
    }
    goto LABEL_38;
  }
  if ( v9 == 8792 || v9 == 8796 || v9 == 10002 )
  {
    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A15_A16_A17_MASK) )
    {
      v14 = 976;
      return v14 + v8;
    }
    v15 = !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK);
    v14 = 952;
    v16 = 928;
LABEL_38:
    if ( v15 )
      v14 = v16;
    return v14 + v8;
  }
  return result;
}

//----- (0000000000034F5C) ----------------------------------------------------
unsigned __int64 __fastcall get_task_port_kaddr_checked(struct_krwCtx *krwCtx, unsigned int a2, int a3, unsigned int *a4)
{
  unsigned __int64 v7; // x19
  unsigned int v8; // w9
  unsigned int v10; // [xsp+Ch] [xbp-24h] BYREF

  v10 = 0;
  v7 = get_task_port_kaddr(krwCtx, a2, a3);
  if ( !v7 )
    return v7;
  if ( !kread_u32(krwCtx, v7, &v10) )
    return 0;
  if ( krwCtx->xnuMajorVersion < 4904 )
  {
    v8 = HIBYTE(v10);
  }
  else
  {
    v8 = v10 & 3;
    if ( !a3 )
    {
      if ( v8 == 3 )
        goto LABEL_6;
      return 0;
    }
  }
  if ( v8 )
    return 0;
LABEL_6:
  if ( a4 )
    *a4 = v10;
  return v7;
}

//----- (0000000000034FF8) ----------------------------------------------------
unsigned __int64 __fastcall get_task_port_kaddr_wrap(struct_krwCtx *krwCtx, unsigned int a2, unsigned int *a3)
{
  return get_task_port_kaddr_checked(krwCtx, a2, 0, a3);
}

//----- (0000000000035004) ----------------------------------------------------
__int64 __fastcall find_proc_kobj_via_processors(struct_krwCtx *krwCtx, int a2, __int64 a3, unsigned int *a4)
{
  __int64 v8; // x26
  int v9; // w8
  __int64 v10; // x23
  __int64 v11; // x24
  __int64 v12; // x27
  __int64 v15; // x0
  __int64 v16; // x0
  unsigned __int64 v17; // x0
  unsigned __int64 v18; // x24
  mach_msg_type_number_t v19; // w25
  unsigned int v20; // w28
  unsigned __int64 v21; // x8
  kern_return_t v22; // w0
  mach_msg_type_number_t v23; // w8
  unsigned __int64 v24; // x28
  unsigned int v25; // w25
  unsigned __int64 v26; // x0
  unsigned __int64 v27; // x23
  unsigned __int64 v28; // x20
  vm_size_t v29; // x2
  mach_msg_type_number_t v31; // [xsp+4h] [xbp-8Ch]
  __int64 v32; // [xsp+8h] [xbp-88h] BYREF
  unsigned __int64 v33; // [xsp+10h] [xbp-80h] BYREF
  mach_msg_type_number_t out_processor_listCnt; // [xsp+1Ch] [xbp-74h] BYREF
  processor_array_t out_processor_list; // [xsp+20h] [xbp-70h] BYREF
  uint64_t v36[3]; // [xsp+28h] [xbp-68h] BYREF

  v8 = 163855;
  out_processor_list = 0;
  out_processor_listCnt = 0;
  v32 = 0;
  v33 = 0;
  v9 = krwCtx->xnuMajorVersion;
  v10 = 163847;
  if ( v9 > 8791 )
  {
    if ( v9 != 8792 && v9 != 8796 && v9 != 10002 )
      return v10;
    goto LABEL_17;
  }
  if ( (unsigned int)(v9 - 8019) < 2 )
  {
LABEL_17:
    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A17) )
      v12 = 15676;
    else
      v12 = 2220;
    if ( krwCtx->xnuMajorVersion >= 8019 )
    {
      v15 = krwCtx->kernelMachoCtx;
      if ( !v15 )
        return 708625;
      macho_find_text_section(v15, v36);
      v16 = kernel_pattern_scan((__int64)v36, "14 D9 33 F8", 0);
      if ( !v16 )
        return 708625;
      v10 = 708620;
      v17 = find_kernel_func(krwCtx->kernelMachoCtx, (__int64 *)(v16 - 8));
      if ( !v17 )
        return 708625;
      v18 = v17;
      out_processor_listCnt = number_of_cpus();
      v31 = out_processor_listCnt;
      if ( out_processor_listCnt )
      {
        v19 = 0;
        v20 = 0;
        do
        {
          if ( !kread_physmap_decorated(krwCtx, v18 + krwCtx->stride_0x168 * v19, &v33) )
            return 163855;
          if ( v33 )
          {
            if ( !validate_kaddr_range(krwCtx, v33) )
              return 163878;
            v21 = v33;
          }
          else
          {
            v21 = 0;
          }
          if ( !kread_physmap_decorated(krwCtx, v21 + 40, (unsigned __int64 *)&v32) )
            return 163855;
          if ( !validate_kaddr_range(krwCtx, v32) )
            return 163878;
          if ( !kread_u32(krwCtx, v32 + v12, v36) )
            return 163855;
          if ( (unsigned int)(LODWORD(v36[0]) - 1) > 1 )
            return 163857;
          if ( LODWORD(v36[0]) == a2 )
          {
            if ( v20 >= *a4 )
              return v10;
            *(uint64_t *)(a3 + 8LL * v20++) = v33;
          }
          ++v19;
        }
        while ( v19 < v31 );
      }
      else
      {
        v20 = 0;
      }
      v10 = 0;
      *a4 = v20;
      return v10;
    }
    v11 = 40;
    goto LABEL_43;
  }
  if ( v9 == 6153 )
  {
    v12 = 1092;
    v11 = 32;
  }
  else
  {
    if ( v9 != 7195 )
      return v10;
    if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(7195, 80, 15, 1023, 1023) )
      v11 = 32;
    else
      v11 = 40;
    v12 = 1204;
  }
LABEL_43:
  v22 = host_processors(krwCtx->hostPrivPort, &out_processor_list, &out_processor_listCnt);
  if ( v22 )
    return v22 | 0x80000000;
  v23 = out_processor_listCnt;
  if ( !out_processor_listCnt )
  {
    v25 = 0;
LABEL_58:
    v10 = 0;
    *a4 = v25;
    goto LABEL_69;
  }
  v24 = 0;
  v25 = 0;
  while ( 1 )
  {
    v26 = get_task_kobject_addr(krwCtx, out_processor_list[v24]);
    v33 = v26;
    if ( !v26 )
    {
      v8 = 163854;
      goto LABEL_68;
    }
    v27 = v26;
    if ( !kread_physmap_decorated(krwCtx, v26 + v11, (unsigned __int64 *)&v32) )
      goto LABEL_68;
    if ( !validate_kaddr_range(krwCtx, v32) )
    {
      v8 = 163878;
      goto LABEL_68;
    }
    if ( !kread_u32(krwCtx, v32 + v12, v36) )
      goto LABEL_68;
    if ( (unsigned int)(LODWORD(v36[0]) - 1) > 1 )
    {
      v8 = 163857;
      goto LABEL_68;
    }
    if ( LODWORD(v36[0]) == a2 )
      break;
LABEL_55:
    ++v24;
    v23 = out_processor_listCnt;
    if ( v24 >= out_processor_listCnt )
      goto LABEL_58;
  }
  if ( v25 < *a4 )
  {
    *(uint64_t *)(a3 + 8LL * v25++) = v27;
    goto LABEL_55;
  }
  v8 = 708620;
LABEL_68:
  v23 = out_processor_listCnt;
  v10 = v8;
LABEL_69:
  if ( v23 )
  {
    v28 = 0;
    do
      mach_port_deallocate(mach_task_self_, out_processor_list[v28++]);
    while ( v28 < out_processor_listCnt );
    v29 = 4LL * out_processor_listCnt;
  }
  else
  {
    v29 = 0;
  }
  vm_deallocate(mach_task_self_, (vm_address_t)out_processor_list, v29);
  return v10;
}

//----- (00000000000353DC) ----------------------------------------------------
__int64 __fastcall get_task_port_offset(struct_krwCtx *krwCtx)
{
  int v1; // w8

  v1 = krwCtx->xnuMajorVersion;
  if ( (unsigned int)(v1 - 8019) < 2 )
    return 96LL;
  if ( v1 == 6153 )
    return 88LL;
  if ( v1 == 7195 )
    return 96LL;
  return 0LL;
}

//----- (0000000000035420) ----------------------------------------------------
__int64 __fastcall get_task_version_field(struct_krwCtx *krwCtx, __int64 a2)
{
  __int64 result; // x0
  int v4; // w8
  bool v5; // zf
  int v6; // w9
  __int64 v8; // x8

  result = 0LL;
  v4 = krwCtx->xnuMajorVersion;
  if ( v4 <= 8019 )
  {
    if ( v4 == 6153 || v4 == 7195 )
    {
      v8 = 64LL;
    }
    else
    {
      if ( v4 != 8019 )
        return result;
      v8 = 48LL;
    }
    return v8 + a2;
  }
  if ( v4 > 8795 )
  {
    v5 = v4 == 8796;
    v6 = 10002;
  }
  else
  {
    v5 = v4 == 8020;
    v6 = 8792;
  }
  if ( v5 || v4 == v6 )
  {
    v8 = 32LL;
    return v8 + a2;
  }
  return result;
}

//----- (00000000000354A4) ----------------------------------------------------
unsigned __int64 __fastcall get_mach_task_port_slot(struct_krwCtx *krwCtx, unsigned int a2)
{
  unsigned __int64 result; // x0

  result = task_get_ipc_port(krwCtx, mach_task_self_, a2);
  if ( result )
  {
    return get_task_version_field(krwCtx, result);
  }
  return result;
}
// 354E4: variable 'vars8' is possibly undefined

//----- (0000000000035500) ----------------------------------------------------
__int64 __fastcall kread_mach_task_port_slot(struct_krwCtx *krwCtx, unsigned int a2)
{
  __int64 result; // x0
  __int64 v4; // [xsp+8h] [xbp-18h] BYREF

  result = get_mach_task_port_slot(krwCtx, a2);
  v4 = result;
  if ( result )
  {
    if ( kread_physmap_decorated(krwCtx, result, (unsigned __int64 *)&v4) )
    {
      if ( validate_kaddr_range(krwCtx, v4) )
        return v4;
      else
        return 0;
    }
    else
    {
      return 0;
    }
  }
  return result;
}

//----- (0000000000035568) ----------------------------------------------------
__int64 __fastcall kread_mach_task_port_slot_plus80(struct_krwCtx *krwCtx, unsigned int a2)
{
  __int64 result; // x0
  unsigned __int64 xnuVersionPacked; // x8
  unsigned __int64 v5; // x1
  bool v6; // cc
  __int64 v7; // x8
  __int64 v8; // [xsp+8h] [xbp-18h] BYREF

  result = kread_mach_task_port_slot(krwCtx, a2);
  v8 = result;
  if ( result )
  {
    xnuVersionPacked = krwCtx->xnuVersionPacked;
    if ( xnuVersionPacked < XNU_VERSION_PACKED(7195, 42, 1, 0, 0) )
    {
      v5 = result + 24;
    }
    else
    {
      if ( xnuVersionPacked >> 43 >= 0x44B )
        return result + 80;
      v6 = xnuVersionPacked > XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023);
      v7 = 32;
      if ( v6 )
        v7 = 24;
      v5 = v7 + result;
    }
    if ( kread_physmap_decorated(krwCtx, v5, (unsigned __int64 *)&v8) )
      return v8;
    return 0;
  }
  return result;
}

//----- (0000000000035610) ----------------------------------------------------
unsigned __int64 __fastcall get_ipc_port_kaddr_via_host(struct_krwCtx *krwCtx, int a2)
{
  unsigned __int64 v4; // x1
  unsigned __int64 v5; // x0
  unsigned int v6; // w0
  unsigned __int64 ipc_port; // x0
  unsigned __int64 v9; // [xsp+8h] [xbp-18h] BYREF

  v4 = krwCtx->gap_0x1A8_size8;
  if ( !v4 )
  {
    v6 = get_privileged_host_port(krwCtx);
    if ( v6 + 1 < 2 )
      return 0;
    ipc_port = task_get_ipc_port(krwCtx, mach_task_self_, v6);
    v4 = ipc_port;
    if ( !ipc_port )
      return v4;
    krwCtx->gap_0x1A8_size8 = ipc_port;
  }
  if ( a2 == 1 )
    return v4;
  v5 = maybe_ipc_port_get_kobject(krwCtx, v4);
  if ( !v5 )
    return 0;
  if ( kread_physmap_decorated(krwCtx, v5 + (unsigned int)(krwCtx->stride_0x168 * a2) + 16, &v9) )
    return v9;
  else
    return 0;
}

