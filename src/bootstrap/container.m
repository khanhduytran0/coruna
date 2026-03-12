/*
 * container.m - F00DBEEF container parsing and module management
 *
 * Decompiled from bootstrap.dylib offsets 0x7c9c-0x8928
 */

#import "bootstrap.h"
#import <string.h>
#import <stdlib.h>
#import <dlfcn.h>

/* ── parse_foodbeef (0x7c9c) ────────────────────────────────────── */

uint32_t parse_foodbeef(bootstrap_ctx_t *ctx, uint32_t type,
                        void *data, uint32_t size)
{
    uint32_t err = ERR_NULL_CTX - 8;

    if (!ctx || !data || !size)
        return err;
    if (size < 4)
        return ERR_BAD_SIZE;

    uint32_t magic = *(uint32_t *)data;
    if (magic == MAGIC_FOODBEEF) {
        print_log("[bootstrap] parse_foodbeef: F00DBEEF container size=%u", size);
        if (size < 9)
            return ERR_BAD_SIZE;

        foodbeef_header_t *hdr = (foodbeef_header_t *)data;
        uint32_t count = hdr->entry_count;
        print_log("[bootstrap] parse_foodbeef: %u entries", count);
        if (count < 1)
            return 0;

        uint8_t *base = (uint8_t *)data;
        uint8_t *end = base + size;

        for (uint32_t i = 0; i < count; i++) {
            foodbeef_entry_t *entry = &hdr->entries[i];
            if ((uint8_t *)entry < base || (uint8_t *)(entry + 1) > end)
                return ERR_BAD_BOUNDS;

            uint32_t etype = entry->type_flags;
            if (!etype)
                continue;

            uint8_t *edata = base + entry->data_offset;
            uint32_t esize = entry->data_size;

            int found = 0;
            for (int j = 0; j < MAX_CONTAINERS; j++) {
                uint32_t st = ctx->containers[j].type;
                if (st == 0 || st == etype) {
                    memset(&ctx->containers[j], 0, sizeof(container_slot_t));
                    ctx->containers[j].type = etype;
                    ctx->containers[j].flags = entry->flags;
                    ctx->containers[j].data_ptr = edata;
                    ctx->containers[j].data_size = esize;
                    found = 1;
                    print_log("[bootstrap] parse_foodbeef: slot[%d] type=0x%x size=0x%x", j, etype, esize);
                    break;
                }
            }
            if (!found)
                return ERR_GENERIC;
        }
        return 0;
    }

    print_log("[bootstrap] parse_foodbeef: raw data type=0x%x size=%u", type, size);
    if (!type)
        return ERR_BAD_MAGIC;

    for (int i = 0; i < MAX_CONTAINERS; i++) {
        uint32_t st = ctx->containers[i].type;
        if (st == 0 || st == type) {
            memset(&ctx->containers[i], 0, sizeof(container_slot_t));
            ctx->containers[i].type = type;
            ctx->containers[i].flags = 1;
            ctx->containers[i].data_ptr = data;
            ctx->containers[i].data_size = size;
            return 0;
        }
    }
    return ERR_GENERIC;
}

/* ── resolve_all_containers (0x7e10) ────────────────────────────── */

uint32_t resolve_all_containers(bootstrap_ctx_t *ctx)
{
    print_log("[bootstrap] resolve_all_containers");
    for (int i = 0; i < MAX_CONTAINERS; i++) {
        container_slot_t *slot = &ctx->containers[i];
        if (!slot->type || !slot->flags)
            continue;
        if (slot->resolved_ptr)
            continue;

        void *out = NULL;
        uint32_t err = ((fn_decrypt_t)ctx->decrypt_func)(
            ctx, slot->data_ptr, slot->data_size, &out);
        if (err) {
            print_log("[bootstrap] resolve_all_containers: decrypt FAIL slot=%d err=0x%x", i, err);
            return err;
        }

        slot->resolved_ptr = out;
        uint8_t *hdr = (uint8_t *)out;
        slot->field_20 = *(uint64_t *)(hdr + 0x58);
        ctx->containers[i].field_20 = *(uint64_t *)(hdr + 0x58);
        *(uint32_t *)((uint8_t *)&ctx->containers[i] + 0x20) =
            *(uint32_t *)(hdr + 0xa8);
    }
    return 0;
}

/* ── find_or_load_container (0x7ed4) ────────────────────────────── */

uint32_t find_or_load_container(bootstrap_ctx_t *ctx, uint32_t type)
{
    uint32_t err = ERR_NULL_CTX;
    if (!ctx)
        return err;

    if (!ctx->decrypt_func || !type)
        return err;

    container_slot_t *slot = NULL;
    for (int i = 0; i < MAX_CONTAINERS; i++) {
        if (ctx->containers[i].type == type) {
            slot = &ctx->containers[i];
            break;
        }
    }

    if (!slot) {
        print_log("[bootstrap] find_or_load_container: type=0x%x NOT FOUND", type);
        return ERR_NO_CONTAINER;
    }

    if (slot->resolved_ptr)
        return ERR_CONTAINER_FOUND;

    if (!slot->data_ptr || !slot->data_size)
        return ERR_NO_DATA;

    print_log("[bootstrap] find_or_load_container: decrypting type=0x%x size=%u", type, slot->data_size);
    void *out = NULL;
    err = ((fn_decrypt_t)ctx->decrypt_func)(
        ctx, slot->data_ptr, slot->data_size, &out);
    if (err)
        return err;

    slot->resolved_ptr = out;
    uint8_t *hdr = (uint8_t *)out;
    slot->field_20 = *(uint64_t *)(hdr + 0x58);
    *(uint32_t *)((uint8_t *)slot + 0x20) = *(uint32_t *)(hdr + 0xa8);
    return 0;
}

/* ── unload_container (0x7fc8) ──────────────────────────────────── */

uint32_t unload_container(bootstrap_ctx_t *ctx, uint32_t type)
{
    uint32_t err = ERR_NULL_CTX;
    if (!ctx)
        return err;

    if (!ctx->fn_unload_cont || !type)
        return err;

    container_slot_t *slot = NULL;
    for (int i = 0; i < MAX_CONTAINERS; i++) {
        if (ctx->containers[i].type == type) {
            slot = &ctx->containers[i];
            break;
        }
    }

    if (!slot)
        return ERR_NO_CONTAINER;

    if (slot->resolved_ptr) {
        err = ctx->fn_unload_cont(ctx, slot->resolved_ptr);
        if (err)
            return err;
    }

    slot->resolved_ptr = NULL;
    slot->field_20 = 0;
    *(uint32_t *)((uint8_t *)slot + 0x20) = 0;
    print_log("[bootstrap] unload_container: type=0x%x", type);
    return 0;
}

/* ── get_container_ptr (0x8080) ─────────────────────────────────── */

uint32_t get_container_ptr(bootstrap_ctx_t *ctx, uint32_t type, void **out)
{
    uint32_t err = ERR_NULL_CTX;
    if (!ctx || !out)
        return err;

    *out = NULL;
    if (!type)
        return err;

    container_slot_t *slot = NULL;
    for (int i = 0; i < MAX_CONTAINERS; i++) {
        if (ctx->containers[i].type == type) {
            slot = &ctx->containers[i];
            break;
        }
    }

    if (!slot)
        return ERR_NO_CONTAINER;

    if (slot->resolved_ptr) {
        *out = slot->resolved_ptr;
        return 0;
    }

    err = find_or_load_container(ctx, type);
    if (err)
        return err;

    *out = slot->resolved_ptr;
    return 0;
}

/* ── get_raw_data (0x812c) ──────────────────────────────────────── */

uint32_t get_raw_data(bootstrap_ctx_t *ctx, uint32_t type,
                      void **out_ptr, uint32_t *out_size)
{
    uint32_t err = ERR_NULL_CTX;
    if (!ctx || !out_ptr || !out_size)
        return err;

    *out_ptr = NULL;
    *out_size = 0;
    if (!type)
        return err;

    for (int i = 0; i < MAX_CONTAINERS; i++) {
        print_log("ctx->containers[i].type %d == type %d", ctx->containers[i].type, type);
        if (ctx->containers[i].type == type) {
            void *data = ctx->containers[i].data_ptr;
            if (!data)
                return ERR_NO_DATA;
            uint32_t sz = ctx->containers[i].data_size;
            if (!sz)
                return ERR_NO_DATA;

            *out_ptr = data;
            *out_size = sz;
            return 0;
        }
    }
    return ERR_NO_CONTAINER;
}

/* ── init_function_table (0x8210) ───────────────────────────────── */

uint32_t init_function_table(bootstrap_ctx_t *ctx)
{
    print_log("[bootstrap] init_function_table");
    for (int i = 0; i < MAX_CONTAINERS; i++)
        memset(&ctx->containers[i], 0, sizeof(container_slot_t));

    ctx->fn_parse_container = (fn_parse_container_t)parse_foodbeef;
    ctx->fn_resolve_all     = (fn_resolve_all_t)resolve_all_containers;
    ctx->fn_find_or_load    = (fn_find_or_load_t)find_or_load_container;
    ctx->fn_unload          = (fn_unload_t)unload_container;
    ctx->fn_get_pointer     = (fn_get_pointer_t)get_container_ptr;
    ctx->fn_get_raw_data    = (fn_get_raw_data_t)get_raw_data;
    return 0;
}

/* ── load_module (0x8590) ───────────────────────────────────────── */

uint32_t load_module(bootstrap_ctx_t *ctx, uint32_t type, void **out)
{
    print_log("[bootstrap] load_module: type=0x%x", type);

    void *raw_ptr = NULL;
    uint32_t raw_size = 0;
    void *decrypted = NULL;
    void *dlsym_result = NULL;

    uint32_t err = ctx->fn_get_raw_data(ctx, type, &raw_ptr, &raw_size);
    if (err) {
        print_log("[bootstrap] load_module: get_raw_data FAIL err=0x%x", err);
        return err;
    }

    module_handle_t *handle = (module_handle_t *)malloc(sizeof(module_handle_t));
    if (!handle)
        return ERR_GENERIC;

    err = ((fn_decrypt_t)ctx->decrypt_func)(ctx, raw_ptr, raw_size, &decrypted);
    if (err)
        goto fail;

    if (ctx->fn_icache_flush) {
        uint8_t *code = *(uint8_t **)((uint8_t *)decrypted + 0x58);
        uint32_t code_size = *(uint32_t *)((uint8_t *)decrypted + 0xa8);
        ctx->fn_icache_flush(ctx, code, code_size);
    }

    handle->container = decrypted;

    err = ((fn_dlsym_t)ctx->dlsym_func)(ctx, decrypted, "_driver", &dlsym_result);
    if (err) {
        print_log("[bootstrap] load_module: dlsym _driver FAIL err=0x%x", err);
        goto fail;
    }

    handle->vtable = NULL;
    typedef uint32_t (*driver_fn_t)(void *, module_vtable_t **);
    err = SIGN_FPTR(driver_fn_t, dlsym_result)(decrypted, &handle->vtable);
    if (err)
        goto fail;

    module_vtable_t *vt = handle->vtable;
    if (!vt)
        goto fail_vtable;

    sign_vtable_fptrs(vt);

    if (vt->version != 2)
        goto fail;
    if (vt->num_funcs < 2)
        goto fail;

    vt->fn_deinit  = (void *)strip_pac((uint64_t)vt->fn_deinit);
    vt->fn_init    = (void *)strip_pac((uint64_t)vt->fn_init);
    vt->fn_cleanup = (void *)strip_pac((uint64_t)vt->fn_cleanup);
    vt->fn_command = (void *)strip_pac((uint64_t)vt->fn_command);
    vt->fn_30      = (void *)strip_pac((uint64_t)vt->fn_30);
    vt->fn_38      = (void *)strip_pac((uint64_t)vt->fn_38);
    vt->fn_40      = (void *)strip_pac((uint64_t)vt->fn_40);
    vt->fn_48      = (void *)strip_pac((uint64_t)vt->fn_48);

    print_log("[bootstrap] load_module: OK vtable version=%d funcs=%d", vt->version, vt->num_funcs);
    *out = handle;
    return 0;

fail_vtable:
    err = ERR_MODULE_NO_VTBL;
fail:
    print_log("[bootstrap] load_module: FAIL err=0x%x", err);
    if (decrypted && ctx->fn_unload_cont)
        ctx->fn_unload_cont(ctx, decrypted);
    free(handle);
    return err;
}

/* ── load_module_wrapper (0x8798) ───────────────────────────────── */

uint32_t load_module_wrapper(bootstrap_ctx_t *ctx, void **out)
{
    return load_module(ctx, CONTAINER_TYPE_LOADER, out);
}

/* ── module_call_init (0x87d8) ──────────────────────────────────── */

uint32_t module_call_init(module_handle_t *handle, uint32_t mode, void **out)
{
    if (!handle)
        return ERR_NULL_CTX;
    if (!out)
        return ERR_NULL_CTX;

    module_vtable_t *vt = handle->vtable;
    if (!vt)
        return ERR_MODULE_NO_VTBL;

    print_log("[bootstrap] module_call_init: mode=%u", mode);
    typedef uint32_t (*init_fn_t)(module_vtable_t *, uint32_t, void **);
    return ((init_fn_t)vt->fn_init)(vt, mode, out);
}

/* ── module_call_cmd (0x8840) ───────────────────────────────────── */

uint32_t module_call_cmd(module_handle_t *handle, void *arg1,
                         uint32_t cmd, void *arg3)
{
    if (!handle)
        return ERR_NULL_CTX;

    uint32_t err = ERR_MODULE_NO_INIT;
    if (!arg1)
        return err;

    module_vtable_t *vt = handle->vtable;
    if (!vt)
        return err + 4;

    print_log("[bootstrap] module_call_cmd: cmd=0x%x", cmd);
    typedef uint32_t (*cmd_fn_t)(module_vtable_t *, void *, uint32_t, void *);
    return ((cmd_fn_t)vt->fn_command)(vt, arg1, cmd, arg3);
}

/* ── module_call_cleanup (0x88b4) ───────────────────────────────── */

uint32_t module_call_cleanup(module_handle_t *handle, void *arg)
{
    if (!handle)
        return ERR_NULL_CTX;

    uint32_t err = ERR_MODULE_NO_INIT;
    if (!arg)
        return err;

    module_vtable_t *vt = handle->vtable;
    if (!vt)
        return err + 4;

    print_log("[bootstrap] module_call_cleanup");
    typedef uint32_t (*cleanup_fn_t)(module_vtable_t *, void *);
    return ((cleanup_fn_t)vt->fn_cleanup)(vt, arg);
}

/* ── close_module (0x8928) ──────────────────────────────────────── */

uint32_t close_module(bootstrap_ctx_t *ctx, module_handle_t *handle)
{
    uint32_t err = ERR_NULL_CTX;
    if (!ctx || !handle)
        return err;

    module_vtable_t *vt = handle->vtable;
    if (!vt)
        return ERR_MODULE_NO_VTBL;

    print_log("[bootstrap] close_module");
    typedef void (*deinit_fn_t)(module_vtable_t *);
    ((deinit_fn_t)vt->fn_deinit)(vt);

    err = ctx->fn_unload_cont(ctx, handle->container);

    handle->container = NULL;
    handle->vtable = NULL;
    free(handle);
    return err;
}
