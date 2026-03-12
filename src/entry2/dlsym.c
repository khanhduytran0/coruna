/*
 * dlsym.c - Custom symbol resolution from F00DBEEF containers
 *
 * Decompiled from entry2_type0x0f.dylib offsets 0x1dbc0–0x1dd60
 *
 * Instead of using the standard dlsym(), entry2 has its own symbol
 * resolution mechanism that works with F00DBEEF-formatted containers.
 * This is used to resolve "_driver" from the type0x09 LOADER dylib
 * without going through dyld.
 */

#include "entry2.h"
#include <stdlib.h>
#include <string.h>

/* ── e2_create_resolver (0x1dbc0) ────────────────────────────────── *
 * Creates a symbol resolver object (0x38 bytes) that can look up
 * symbols from a loaded dylib's export trie or symbol table.
 *
 * The resolver wraps an internal dyld handle obtained via 0x1e748
 * (likely _dyld_process_info_create or similar) and populates a
 * vtable with PAC-signed lookup functions.
 *
 * Vtable layout (0x38 bytes):
 *   +0x00: flags (0x10001)
 *   +0x08: dyld_handle (from internal dyld query)
 *   +0x10: fn_lookup — resolves a symbol name to address
 *   +0x18: fn_iterate — iterate exports
 *   +0x20: fn_info — get module info
 *   +0x28: fn_close — cleanup
 *   +0x30: fn_query — query capabilities
 */
kern_return_t e2_create_resolver(symbol_resolver_t **out)
{
    if (!out)
        return E2_ERR_NULL;

    /* Get internal dyld handle */
    void *dyld_handle = NULL;
    kern_return_t kr;

    /* 0x1e748: queries dyld internals — likely uses
     * _dyld_process_info_create / _dyld_process_info_for_each_image
     * to enumerate loaded images */
    kr = /* e2_get_dyld_handle */ 0; /* placeholder: 0x1e748(&dyld_handle) */
    if (kr != KERN_SUCCESS)
        return kr;

    symbol_resolver_t *resolver = calloc(1, 0x38);
    if (!resolver) {
        /* cleanup dyld_handle: 0x1e688 */
        return E2_ERR_ALLOC;
    }

    resolver->flags = 0x10001;
    resolver->dyld_handle = dyld_handle;

    /* PAC-sign each vtable function pointer with paciza.
     * These are at relative offsets from the adr instructions:
     *   +0x10: adr x16, #+428  → lookup function
     *   +0x18: adr x16, #+544  → iterate function
     *   +0x20: adr x16, #+716  → info function
     *   +0x28: adr x16, #+828  → close function
     *   +0x30: adr x16, #+1048 → query function
     */
    /* resolver->fn_lookup = paciza(lookup_func);
     * resolver->fn_18     = paciza(iterate_func);
     * resolver->fn_20     = paciza(info_func);
     * resolver->fn_28     = paciza(close_func);
     * resolver->fn_30     = paciza(query_func); */

    *out = resolver;
    return KERN_SUCCESS;
}

/* ── e2_custom_dlsym (0x1dc98) ───────────────────────────────────── *
 * Custom dlsym implementation that resolves symbols from F00DBEEF
 * containers. This is the mechanism used to resolve "_driver" from
 * the type0x09 LOADER.
 *
 * Flow:
 *   1. Validate the container has F00DBEEF magic
 *   2. Check bounds: entry_count * 16 + 8 must fit in size
 *   3. Create a resolver via e2_create_resolver
 *   4. Call the resolver's lookup function to find the symbol
 *   5. Store result in the output object
 *
 * Parameters:
 *   output    — receives the parsed container/module context
 *   container — raw F00DBEEF container data from type0x09
 *   size      — byte length of container data
 */
kern_return_t e2_custom_dlsym(void *output, void *container, uint32_t size)
{
    if (!output || !container || !size)
        return E2_ERR_NULL;

    /* Minimum size: magic(4) + count(4) + 1 entry = 9 bytes */
    if (size < 9)
        return E2_ERR_BAD_MAGIC;

    /* Validate F00DBEEF magic */
    foodbeef_container_t *hdr = (foodbeef_container_t *)container;
    if (hdr->magic != MAGIC_FOODBEEF)
        return E2_ERR_BAD_MAGIC;

    /* Get entry count and validate bounds */
    if (hdr->entry_count == 0)
        return E2_ERR_BAD_MAGIC;

    /* Each entry is 16 bytes (foodbeef_entry_t), header is 8 bytes */
    uint64_t required = sizeof(foodbeef_container_t) +
                        ((uint64_t)hdr->entry_count * sizeof(foodbeef_entry_t));
    if (required > (uint64_t)size)
        return E2_ERR_BAD_MAGIC;

    /* Create a symbol resolver */
    symbol_resolver_t *resolver = NULL;
    kern_return_t kr = e2_create_resolver(&resolver);
    if (kr != KERN_SUCCESS)
        return kr;

    /* Use the resolver's lookup function to process the container */
    kr = resolver->fn_lookup(resolver->dyld_handle, container, size);

    if (kr != KERN_SUCCESS) {
        /* Cleanup resolver on failure */
        /* e2_destroy_resolver(resolver); — at 0x1dd68 */
        return kr;
    }

    /* Success — store parsed result in output.
     * The resolver remains alive; the output object now holds
     * a reference to the resolved module context which can be
     * used to call fn_dlsym (offset 0x30) on the module. */

    /* ... further processing to extract symbol table ... */
    return KERN_SUCCESS;
}
