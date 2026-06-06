bool __fastcall iosurface_physmap_setup(__int64 someStruct, int a2, __int64 a3, unsigned int a4)
{
  bool result; // w0
  __int64 v9; // x23
  int *v10; // x9
  __int64 v11; // x24
  unsigned __int64 v12; // x10
  unsigned __int64 v13; // x11
  unsigned int v16; // w8
  unsigned __int64 v17; // x14
  int v18; // w16
  unsigned int v19; // w15
  unsigned __int64 v20; // x25
  unsigned __int64 v21; // x24
  __int64 v22; // x22
  __int128 v23; // q0
  __int128 v24; // q0
  __int64 v25; // x8
  int8x16_t *v26; // x8
  int8x16_t *v27; // x27
  __int64 v28; // x8
  int8x16_t *v29; // x24
  unsigned __int64 v30; // x26
  int v31; // w22
  int v32; // w23
  unsigned __int64 v33; // x28
  __int64 v34; // x8
  unsigned __int64 v35; // x8
  unsigned __int64 v36; // x8
  __int64 v38; // x8
  int8x16_t v39; // q1
  unsigned __int64 v40; // x8
  unsigned __int64 v41; // x9
  bool v42; // cf
  unsigned __int64 v43; // x9
  void *segments; // x0
  __int64 v44; // [xsp+0h] [xbp-70h]
  uint64_t v45[3]; // [xsp+8h] [xbp-68h] BYREF

  result = alloc_kernel_offset_table(someStruct, a3);
  if ( !result )
    return result;
  *(uint32_t *)(someStruct + 216) = a2;
  *(uint8_t *)(someStruct + 256) = 1;
  v9 = **(uint64_t **)(someStruct + 208);
  v10 = (int *)(v9 + 32);
  v11 = *(unsigned int *)(v9 + 20);
  v12 = v9 + 32 + v11;
  v13 = v12 - 8;
  if ( v9 + 32 >= v12 || v9 + 40 > v12 || (unsigned __int64)v10 > v13 )
    return 0;
  v16 = 0;
  do
  {
    v17 = (unsigned int)v10[1];
    if ( (unsigned int)v17 < 8 || v12 - (unsigned __int64)v10 < v17 )
      break;
    v18 = *v10;
    v19 = 24;
    if ( *v10 <= 10 )
    {
      switch ( v18 )
      {
        case -2147483617:
          goto LABEL_26;
        case -2147483614:
LABEL_24:
          v19 = 48;
          goto LABEL_26;
        case 2:
          goto LABEL_26;
      }
    }
    else if ( v18 > 24 )
    {
      if ( v18 == 34 )
        goto LABEL_24;
      if ( v18 == 25 )
      {
        ++v16;
        v19 = 72;
        goto LABEL_26;
      }
    }
    else
    {
      if ( v18 == 11 )
      {
        v19 = 80;
LABEL_26:
        if ( (unsigned int)v17 < v19 )
          break;
        goto LABEL_27;
      }
      if ( v18 == 13 )
        goto LABEL_26;
    }
LABEL_27:
    v10 = (int *)((char *)v10 + v17);
  }
  while ( (unsigned __int64)v10 < v12 && (unsigned __int64)(v10 + 2) <= v12 && (unsigned __int64)v10 <= v13 );
  if ( !v16 )
    return 0;
  *(uint32_t *)(someStruct + 8) = v16;
  segments = malloc(56LL * v16);
  *(uint64_t *)someStruct = (uint64_t)segments;
  if ( !segments )
    return false;
  *(uint64_t *)(someStruct + 272) = "__TEXT";
  v20 = v9 + 32;
  v21 = v9 + 32 + v11;
  if ( v9 + 32 < v21 )
  {
    v22 = (__int64)segments;
    do
    {
      if ( *(uint32_t *)v20 == 25 )
      {
        if ( *(unsigned int *)(v20 + 64) > ((unsigned __int64)*(unsigned int *)(v20 + 4) - 72) / 0x50 )
          return 0;
        if ( !strcmp((const char *)(v20 + 8), "__TEXT_EXEC") )
          *(uint64_t *)(someStruct + 272) = "__TEXT_EXEC";
        v23 = *(__int128 *)(v20 + 40);
        *(uint64_t *)v22 = someStruct;
        *(__int128 *)(v22 + 8) = v23;
        v24 = *(__int128 *)(v20 + 24);
        *(uint64_t *)(v22 + 24) = someStruct;
        *(__int128 *)(v22 + 32) = v24;
        *(uint64_t *)(v22 + 48) = v20;
        v22 += 56;
      }
      v20 += *(unsigned int *)(v20 + 4);
    }
    while ( v20 < v21 );
    v9 = **(uint64_t **)(someStruct + 208);
  }
  *(int32x2_t *)(someStruct + 40) = vrev64_s32(*(int32x2_t *)(v9 + 4));
  *(uint32_t *)(someStruct + 48) = *(uint32_t *)(v9 + 24);
  if ( (a4 & 0x100) != 0 )
  {
    macho_getsectbyname("__TEXT", someStruct, "__thread_starts", v45);
    if ( v45[2] )
      *(uint8_t *)(someStruct + 156) = 1;
    if ( (a4 & 0x400) != 0 )
    {
      if ( *(uint64_t *)someStruct )
      {
        v25 = *(uint64_t *)(*(uint64_t *)someStruct + 8LL);
        if ( v25 )
          *(uint64_t *)(someStruct + 160) = a3 - v25;
      }
    }
  }
  if ( (a4 & 0x40) != 0 )
    return true;
  v26 = **(int8x16_t ***)(someStruct + 208);
  v27 = v26 + 2;
  v28 = v26[1].u32[1];
  v29 = (int8x16_t *)((char *)v27 + v28);
  if ( v27 >= (int8x16_t *)&v27->i8[v28] )
    return 0;
  v30 = 0;
  v31 = 0;
  v44 = *(int *)(someStruct + 56) - 1LL;
  v32 = a4 & 0x580;
  v33 = a3;
  while ( 2 )
  {
    if ( v27->i32[0] == 25 )
    {
      if ( !strcmp(&v27->i8[8], "__TEXT") )
      {
        *(uint64_t *)(someStruct + 248) = a3 - v27[1].i64[1];
        if ( (a4 & 0x100) != 0 )
          goto LABEL_54;
      }
      else if ( (a4 & 0x100) != 0 )
      {
LABEL_54:
        if ( !strcmp(&v27->i8[8], "__KLD") )
          v31 = KRW_CTX_FLAG_CPU_someStruct2;
      }
      if ( v32 != 384 )
      {
        v34 = v27[2].i64[0];
        if ( v34 )
        {
          v35 = v27[1].i64[1] + v34;
          if ( v35 > v30 )
            v30 = v35;
        }
      }
      if ( (a4 & 0x400) != 0 && v27[2].i64[0] )
      {
        v36 = v27[1].u64[1];
        if ( v36 < v33 && v36 != 0 )
          v33 = v27[1].u64[1];
      }
      if ( !strcmp(&v27->i8[8], "__LINKEDIT") )
      {
        v38 = v27[1].i64[1];
        v39 = vextq_s8(v27[2], v27[2], 8u);
        if ( v32 == 384 )
          v30 = v27[2].i64[0] + v38;
        *(uint64_t *)(someStruct + 16) = v38;
        *(int8x16_t *)(someStruct + 24) = v39;
      }
    }
    v27 = (int8x16_t *)((char *)v27 + (unsigned int)v27->i32[1]);
    if ( v27 < v29 )
      continue;
    break;
  }
  result = false;
  if ( ((v31 == 0) & (a4 >> 8)) == 0 && v30 )
  {
    if ( (~a4 & 0x500) == 0 && *(uint64_t *)(someStruct + 160) )
      v33 = *(uint64_t *)(someStruct + 160);
    v40 = v33 & ~v44;
    if ( v33 == a3 )
      v40 = a3;
    v41 = (v30 + v44) & ~v44;
    v42 = v41 >= v40;
    v43 = v41 - v40;
    if ( v42 )
    {
      *(uint64_t *)(someStruct + 224) = v40;
      *(uint64_t *)(someStruct + 232) = v43;
      return map_macho_image_vm(someStruct) != 0;
    }
    else
    {
      return 0;
    }
  }
  return result;
}
