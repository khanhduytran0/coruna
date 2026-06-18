//----- (0000000000005EC4) ----------------------------------------------------
__int64 __fastcall driver(uint64_t *a1)
{
    if ( !a1 ) return 708609;
    uint64_t *v3 = calloc(1u, 0x50u);
    if ( !v3 ) return 708617;
    *(uint32_t *)v3 = 131074;
    v3[2] = driver_free;
    v3[3] = driver_init;
    v3[4] = driver_close;
    v3[5] = driver_dispatch_command;
    v3[6] = krw_teardown_dispatch;
    v3[7] = krw_get_conn_port;
    v3[8] = krw_read_iogpu;
    v3[9] = parse_kernel_version;
    *a1 = v3;
    return 0;
}

//----- (0000000000005F9C) ----------------------------------------------------
__int64 __fastcall driver_free(__int128 *a1)
{
  if ( !a1 )
    return 708609;
  a1[3] = 0u;
  a1[4] = 0u;
  a1[1] = 0u;
  a1[2] = 0u;
  *a1 = 0u;
  free(a1);
  return 0;
}

//----- (0000000000005FDC) ----------------------------------------------------
__int64 __fastcall driver_init(__int64 vtable, char something, struct_krwCtx **krwCtxOut)
{
  __int64 result; // x0
  struct_krwCtx *krwCtxOut_; // [xsp+8h] [xbp-18h] BYREF

  krwCtxOut_ = 0;
  result = 0xAD001;
  if ( vtable && krwCtxOut )
  {
    result = driver_init2(&krwCtxOut_, something);
    if ( !(uint32_t)result )
      *krwCtxOut = krwCtxOut_;
  }
  return result;
}

//----- (0000000000006030) ----------------------------------------------------
__int64 __fastcall driver_dispatch_command(
        __int64 vtable,
        struct_krwCtx *krwCtx,
        int cmd,
        __int64 arg0,
        __int64 arg1,
        __int64 arg2,
        __int64 arg3,
        __int64 arg4)
{
  if ( vtable && krwCtx )
    return driver_dispatch_command2(krwCtx, cmd, cmd, arg0, arg1, arg2, arg3, arg4, arg0);
  else
    return 708609;
}

//----- (0000000000006070) ----------------------------------------------------
__int64 __fastcall krw_teardown_dispatch(__int64 a1, __int64 a2)
{
  if ( a1 && a2 )
    return reinit_and_refresh_krw_ctx(a2);
  else
    return 708609;
}

//----- (000000000000608C) ----------------------------------------------------
__int64 __fastcall driver_close(__int64 a1, char *a2)
{
  if ( a1 && a2 )
    return driver_close_internal(a2);
  else
    return 708609;
}

//----- (00000000000060A8) ----------------------------------------------------
__int64 __fastcall krw_get_conn_port(__int64 a1, __int64 a2, uint32_t *a3)
{
  __int64 result; // x0
  int v5; // w8

  result = 708609LL;
  if ( a1 && a2 && a3 )
  {
    v5 = *(uint32_t *)(a2 + 6424);
    result = 708618LL;
    if ( (unsigned int)(v5 + 1) >= 2 )
    {
      result = 0LL;
      *a3 = v5;
    }
  }
  return result;
}

//----- (00000000000060EC) ----------------------------------------------------
__int64 __fastcall krw_read_iogpu(__int64 a1, __int64 *a2, __int64 a3, unsigned int a4, int a5)
{
  __int64 v5; // x20
  __int64 *v11; // x24
  unsigned __int64 v12; // x25
  int v13; // w26
  __int64 v14; // x2
  __int64 v15; // t1
  unsigned int v16; // w0
  __int64 v19; // [xsp+8h] [xbp-48h] BYREF

  v19 = 0;
  v5 = 708609;
  if ( a1 && a2 && ((a3 && a4) || (!a3 && !a4)) )
  {
    if ( *a2 )
    {
      v19 = *a2;
    }
    else
    {
      v5 = (*(__int64 (__fastcall **)(__int64, uint64_t, __int64 *))(a1 + 24))(a1, 0, &v19);
      if ( (uint32_t)v5 )
        return v5;
    }
    if ( !a4 )
      goto LABEL_24;
    LODWORD(v5) = 0;
    v11 = (__int64 *)(a3 + 8);
    v12 = 1;
    LOBYTE(v13) = 1;
    do
    {
      v14 = *((unsigned int *)v11 - 2);
      v15 = *v11;
      v11 += 2;
      v16 = (*(__int64 (__fastcall **)(__int64, __int64, __int64, __int64))(a1 + 40))(a1, v19, v14, v15);
      if ( v13 )
        v5 = v16;
      else
        v5 = (unsigned int)v5;
      v13 = v5 == 0;
    }
    while ( (a5 | v13) == 1 && v12++ < a4 );
    if ( (uint32_t)v5 )
    {
      if ( !*a2 )
      {
        if ( (a5 & 1) == 0 )
          (*(void (__fastcall **)(__int64, __int64))(a1 + 48))(a1, v19);
        (*(void (__fastcall **)(__int64, __int64))(a1 + 32))(a1, v19);
      }
    }
    else
    {
LABEL_24:
      v5 = 0;
      *a2 = v19;
    }
  }
  return v5;
}

//----- (0000000000006224) ----------------------------------------------------
__int64 __fastcall parse_kernel_version(__int64 a1, __int64 a2)
{
  __int64 v3; // x21
  __int64 result; // x0
  host_t v6; // w0
  kern_return_t v7; // w0
  kern_return_t v8; // w20
  char *v9; // x0
  size_t kernel_version_len; // [xsp+18h] [xbp-238h] BYREF
  uint32_t xnu_patch; // [xsp+20h] [xbp-230h] BYREF
  uint32_t xnu_major; // [xsp+28h] [xbp-228h] BYREF
  uint32_t xnu_minor; // [xsp+2Ch] [xbp-224h] BYREF
  int sysctl_mib[2]; // [xsp+28h] [xbp-228h] BYREF
  kernel_version_t kernel_version; // [xsp+30h] [xbp-220h] BYREF

  v3 = 708628;
  result = 708609;
  if ( a1 && a2 )
  {
    memset(kernel_version, 0, sizeof(kernel_version));
    v6 = mach_host_self();
    v7 = host_kernel_version(v6, kernel_version);
    if ( v7 )
    {
      v8 = v7;
      if ( v7 != 53 )
        return v8 | 0x80000000;
      sysctl_mib[0] = 1;
      sysctl_mib[1] = 4;
      kernel_version_len = 512;
      if ( sysctl(sysctl_mib, 2u, kernel_version, &kernel_version_len, 0, 0) )
        return v8 | 0x80000000;
    }
    if ( !strstr(kernel_version, "RELEASE") )
      return 708616;
    v9 = strstr(kernel_version, "xnu-");
    if ( v9 )
    {
      xnu_major = 0;
      xnu_minor = 0;
      xnu_patch = 0;
      if ( sscanf(v9, "xnu-%u.%u.%u%*s", &xnu_major, &xnu_minor, &xnu_patch) == 3 )
      {
        v3 = 0;
        *(uint64_t *)a2 = ((uint64_t)xnu_minor << 32) | xnu_major;
        *(uint32_t *)(a2 + 8) = xnu_patch;
      }
    }
    return v3;
  }
  return result;
}

//----- (0000000000006384) ----------------------------------------------------
vm_address_t __fastcall vm_remap_new_target(vm_address_t src_address, vm_size_t size, boolean_t copy)
{
  vm_prot_t cur_protection[2]; // [xsp+20h] [xbp-10h] BYREF
  vm_address_t target_address; // [xsp+28h] [xbp-8h] BYREF

  *(uint64_t *)cur_protection = 0;
  target_address = 0;
  vm_remap(
    mach_task_self_,
    &target_address,
    size,
    0,
    1,
    mach_task_self_,
    src_address,
    copy,
    &cur_protection[1],
    cur_protection,
    1u);
  return target_address;
}

//----- (00000000000063E8) ----------------------------------------------------
__int64 __fastcall vm_remap_inplace(vm_address_t src_address, vm_size_t size, boolean_t copy)
{
  vm_prot_t cur_protection[2]; // [xsp+20h] [xbp-10h] BYREF
  vm_address_t target_address; // [xsp+28h] [xbp-8h] BYREF

  *(uint64_t *)cur_protection = 0;
  target_address = src_address;
  return vm_remap(
           mach_task_self_,
           &target_address,
           size,
           0,
           0x4000,
           mach_task_self_,
           src_address,
           copy,
           &cur_protection[1],
           cur_protection,
           1u);
}

//----- (0000000000006448) ----------------------------------------------------
vm_region_nesting_result __fastcall query_vm_region_nesting(vm_address_t a1)
{
  uint32_t info[19]; // [xsp+0h] [xbp-70h] BYREF
  vm_size_t size; // [xsp+58h] [xbp-18h] BYREF
  vm_address_t address; // [xsp+60h] [xbp-10h] BYREF
  mach_msg_type_number_t infoCnt; // [xsp+68h] [xbp-8h] BYREF
  natural_t nesting_depth; // [xsp+6Ch] [xbp-4h] BYREF

  size = 0;
  address = a1;
  memset(info, 0, sizeof(info));
  infoCnt = 19;
  nesting_depth = 1;
  vm_region_recurse_64(mach_task_self_, &address, &size, &nesting_depth, (vm_region_recurse_info_t)info, &infoCnt);
  return (vm_region_nesting_result){
    info[6] | ((unsigned __int64)info[10] << 32),
    *(uint64_t *)&info[17],
  };
}

//----- (00000000000064B8) ----------------------------------------------------
__int64 __fastcall compare_entry_by_offset(__int64 a1, __int64 a2)
{
  if ( *(uint64_t *)(a1 + 8) < *(uint64_t *)(a2 + 8) )
    return 0xFFFFFFFFLL;
  else
    return 1LL;
}

//----- (00000000000064D0) ----------------------------------------------------
__int64 __fastcall compare_entry_unsigned(__int64 a1, __int64 a2)
{
  unsigned __int64 v2; // x8
  unsigned __int64 v3; // x9
  bool v4; // cf
  unsigned int v5; // w8

  v2 = *(uint64_t *)(a1 + 8);
  v3 = *(uint64_t *)(a2 + 8);
  v4 = v2 >= v3;
  if ( v2 <= v3 )
    v5 = 0;
  else
    v5 = -1;
  if ( v4 )
    return v5;
  else
    return 1LL;
}

//----- (00000000000064E8) ----------------------------------------------------
__int64 setup_thread_policy()
{
  unsigned __int32 v0[2]; // d0
  unsigned __int32 v1[2]; // d1
  thread_act_t v2; // w0
  struct mach_timebase_info info; // [xsp+8h] [xbp-18h] BYREF
  integer_t policy_info[4]; // [xsp+10h] [xbp-10h] BYREF

  mach_timebase_info(&info);
  v1[0] = info.numer;
  v0[0] = info.denom;
  policy_info[0] = (unsigned int)((double)*(unsigned __int64 *)v0 / (double)*(unsigned __int64 *)v1 * 1000000.0 * 50.0);
  policy_info[1] = policy_info[0];
  policy_info[2] = policy_info[0];
  policy_info[3] = 0;
  v2 = mach_thread_self();
  thread_policy_set(v2, 2u, policy_info, 4u);
  return thread_switch(0, 2, 0);
}
// 6504: variable 'v0' is possibly undefined
// 6508: variable 'v1' is possibly undefined

//----- (0000000000006564) ----------------------------------------------------
void __fastcall sort_compact_vm_regions(__int64 a1, __int64 a2)
{
  __int64 v3; // x10
  char v4; // w13
  __int64 i; // x12
  __int64 v6; // x15
  __int64 v7; // x13
  __int64 v8; // x14
  __int64 v9; // x15
  __int64 *v10; // x13
  int (__cdecl *v11)(const void *, const void *); // x0
  __int128 v12[8]; // [xsp+0h] [xbp-A0h] BYREF

  memset(v12, 0, sizeof(v12));
  v3 = *(uint64_t *)(a2 + 8);
  v4 = 1;
  for ( i = 1; i != 64000; ++i )
  {
    v6 = v3 + 256;
    v3 = *(uint64_t *)(a2 + 16 * i + 8);
    if ( v3 == v6 )
    {
      ++v4;
    }
    else
    {
      if ( (v4 & 0x3F) == 0 )
      {
        v7 = 0;
        v8 = (*(uint64_t *)(a2 + 16 * i - 1016) & 0x3FFFLL) | 0x4000;
        while ( 1 )
        {
          v9 = *(uint64_t *)&v12[v7];
          if ( !v9 )
          {
            v10 = (__int64 *)&v12[v7];
            *v10 = v8;
            v10[1] = 1;
            goto LABEL_5;
          }
          if ( v9 == v8 )
            break;
          if ( ++v7 == 8 )
            goto LABEL_5;
        }
        ++*((uint64_t *)&v12[v7] + 1);
      }
LABEL_5:
      v4 = 1;
    }
  }
  v11 = (int (__cdecl *)(const void *, const void *))nullsub_1(compare_entry_unsigned);
  qsort(v12, 8u, 0x10u, v11);
  *(uint64_t *)(a1 + 8) = *(uint64_t *)&v12[0];
}
// 19728: using guessed type __int64 __fastcall nullsub_1(uint64_t);

//----- (00000000000066A4) ----------------------------------------------------
void __fastcall grow_vm_region_list(uint64_t *a1)
{
  uint64_t *v2; // x19
  void *v3; // x0
  __int64 v4; // x23
  char *v5; // x21
  __int64 i; // x23
  __int64 j; // x23
  __int64 v8; // x1
  int (__cdecl *v9)(const void *, const void *); // x0
  __int64 v10; // x8
  unsigned __int64 v11; // x12
  __int64 v12; // x9
  __int64 v13; // x13
  unsigned __int64 v14; // x15
  __int64 v15; // x14
  __int64 *v16; // x15
  __int64 v17; // x16
  __int64 v18; // t1
  bool v19; // w14
  __int64 v20; // x15
  uint64_t *v21; // x14
  vm_address_t address; // [xsp+8h] [xbp-38h] BYREF

  v2 = malloc(0x28u);
  v2[1] = malloc(0xFA000u);
  v3 = malloc(0x3E80u);
  v4 = 0;
  v2[3] = 0;
  v2[4] = 0;
  v2[2] = v3;
  *v2 = *a1;
  *a1 = v2;
  do
  {
    address = 0;
    vm_allocate(mach_task_self_, &address, 0x4000u, 1);
    v5 = (char *)v2[1];
    *(uint64_t *)&v5[v4] = address;
    v4 += 16;
  }
  while ( v4 != 1024000 );
  for ( i = 0; i != 1024000; i += 16 )
  {
    vm_remap_inplace(*(uint64_t *)&v5[i], 0x4000u, 0);
    v5 = (char *)v2[1];
  }
  for ( j = 0; j != 1024000; j += 16 )
  {
    vm_region_nesting_result nesting = query_vm_region_nesting(*(uint64_t *)&v5[j]);
    v5 = (char *)v2[1];
    *(uint64_t *)&v5[j + 8] = nesting.object_id;
  }
  v9 = (int (__cdecl *)(const void *, const void *))nullsub_1(compare_entry_by_offset);
  qsort(v5, 0xFA00u, 0x10u, v9);
  v10 = a1[1];
  if ( !v10 )
  {
    sort_compact_vm_regions((__int64)a1, v2[1]);
    v10 = a1[1];
  }
  v11 = 0;
  v12 = v2[1];
  do
  {
    v13 = *(uint64_t *)(v12 + 16 * v11 + 8);
    if ( (((unsigned __int16)v10 ^ (unsigned __int16)v13) & 0x3FFF) != 0 )
      goto LABEL_19;
    v14 = v11 + 1;
    v15 = v13 + 256;
    if ( *(uint64_t *)(v12 + 16 * (v11 + 1) + 8) == v13 + 256 )
    {
      v16 = (__int64 *)(v12 + 40 + 16 * v11);
      v17 = 1;
      while ( v17 != 63 )
      {
        v18 = *v16;
        v16 += 2;
        v15 += 256;
        ++v17;
        if ( v15 != v18 )
        {
          v19 = (unsigned __int64)(v17 - 1) < 0x3F;
          v14 = v11 + v17;
          goto LABEL_17;
        }
      }
LABEL_18:
      v20 = v2[4];
      v21 = (uint64_t *)(v2[2] + 16 * v20);
      *v21 = *(uint64_t *)(v12 + 16 * v11);
      v21[1] = v13;
      *(uint64_t *)(v12 + 16 * v11) = 0;
      v2[4] = v20 + 1;
      v11 += 63LL;
      goto LABEL_19;
    }
    v19 = 1;
LABEL_17:
    v11 = v14 - 1;
    if ( !v19 )
      goto LABEL_18;
LABEL_19:
    ++v11;
  }
  while ( v11 < 0xF9C1 );
}
// 6880: conditional instruction was optimized away because x16.8==3F
// 6778: variable 'v8' is possibly undefined
// 19728: using guessed type __int64 __fastcall nullsub_1(uint64_t);

//----- (00000000000068A0) ----------------------------------------------------
__int64 __fastcall get_vm_region_slot(uint64_t *a1)
{
  uint64_t *v2; // x8
  __int64 v3; // x9
  __int64 result; // x0

  v2 = (uint64_t *)*a1;
  if ( !*a1 || (v3 = v2[3], v3 == v2[4]) )
  {
    grow_vm_region_list(a1);
    v2 = (uint64_t *)*a1;
    v3 = *(uint64_t *)(*a1 + 24LL);
  }
  result = v2[2] + 16 * v3;
  v2[3] = v3 + 1;
  return result;
}

