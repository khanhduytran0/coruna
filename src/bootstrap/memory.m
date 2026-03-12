/*
 * memory.m - Cache, buffer allocation, and memory region management
 *
 * Decompiled from bootstrap.dylib offsets 0x5dc8-0x5fe8, 0x8298-0x842c
 */

#import "bootstrap.h"
#import <string.h>
#import <unistd.h>
#import <mach/mach.h>
#import <libkern/OSAtomic.h>

extern void sys_dcache_flush(void *addr, size_t size);
extern void sys_icache_invalidate(void *addr, size_t size);
extern int proc_pidinfo(int pid, int flavor, uint64_t arg,
                        void *buf, int bufsize);

/* ── flush_icache (0x5dc8) ───────────────────────────────────────── */

void flush_icache(bootstrap_ctx_t *ctx, void *addr, uint32_t size)
{
    uint8_t *base;
    uint32_t total;

    if (addr && size) {
        base = (uint8_t *)addr;
        total = size;
    } else {
        total = ctx->exec_size;
        if (total == 0) return;
        base = ctx->exec_base;
    }

    print_log("[bootstrap] flush_icache: base=%p size=0x%x", base, total);

    uint32_t offset = 0;
    uint32_t remaining = total;
    while (total > offset) {
        uint32_t chunk = remaining;
        if (chunk > 0x50000)
            chunk = 0x50000;
        sys_dcache_flush(base + offset, chunk);
        sys_icache_invalidate(base + offset, chunk);
        offset += 0x50000;
        remaining = total - offset;
    }
}

/* ── alloc_buffer (0x5e78) ───────────────────────────────────────── */

uint32_t alloc_buffer(bootstrap_ctx_t *ctx, uint32_t size)
{
    print_log("[bootstrap] alloc_buffer: size=0x%x", size);

    uint8_t *exec_base = ctx->exec_base;
    uint32_t exec_size = ctx->exec_size;
    uint32_t *state = ctx->atomic_state;

    if (!state)
        state = (uint32_t *)(exec_base + exec_size - 4);

    for (;;) {
        uint32_t current = __atomic_load_n(state, __ATOMIC_ACQUIRE);
        uint32_t add = size;
        if (current == 0)
            add += 4;
        uint32_t new_val = current + add;
        if (new_val > exec_size) {
            print_log("[bootstrap] alloc_buffer: FAIL size exceeds exec region (0x%x > 0x%x)", new_val, exec_size);
            return 0xc003;
        }

        uint32_t expected = current;
        if (__atomic_compare_exchange_n(state, &expected, new_val,
                                        0, __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE))
        {
            uint8_t *ptr = exec_base + exec_size - new_val;
            ctx->buffer_ptr = ptr;
            ctx->buffer_remaining = size;
            bzero(ptr, (size_t)size);

            if (ctx->fn_icache_flush)
                ctx->fn_icache_flush(ctx, ctx->buffer_ptr, ctx->buffer_remaining);

            print_log("[bootstrap] alloc_buffer: OK ptr=%p", ptr);
            return 0;
        }
    }
}

/* ── consume_buffer (0x5f4c) ─────────────────────────────────────── */

void *consume_buffer(bootstrap_ctx_t *ctx, uint32_t size)
{
    if (ctx->buffer_remaining < size)
        return NULL;

    uint8_t *old = ctx->buffer_ptr;
    ctx->buffer_ptr = old + size;
    ctx->buffer_remaining -= size;
    return old;
}

/* ── secure_bzero (0x5fa0) ───────────────────────────────────────── */

uint32_t secure_bzero(bootstrap_ctx_t *ctx, void *ptr, uint32_t size)
{
    if (ptr && size)
        bzero(ptr, size);
    return 0;
}

/* ── ensure_rwx_protection ───────────────────────────────────────── */
/* On modern iOS (14.5+), JIT regions may have current protection ---
 * with max protection rwx. We need to vm_protect them to rwx before use.
 */

static uint32_t ensure_rwx_protection(uint64_t addr, uint64_t size,
                                       uint32_t cur_prot, uint32_t max_prot)
{
    if (cur_prot == 0x7) {
        /* Already rwx */
        return 0;
    }

    if (max_prot != 0x7) {
        print_log("[bootstrap] ensure_rwx_protection: max_prot=0x%x (not rwx), cannot fix", max_prot);
        return 0xc001;
    }

    print_log("[bootstrap] ensure_rwx_protection: promoting ---/rwx -> rwx/rwx at 0x%llx size=0x%llx",
              (unsigned long long)addr, (unsigned long long)size);
    kern_return_t kr = vm_protect(mach_task_self(), (vm_address_t)addr,
                                  (vm_size_t)size, 0,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        print_log("[bootstrap] ensure_rwx_protection: vm_protect FAIL kr=0x%x", kr);
        return kr | 0x80000000;
    }
    return 0;
}

/* ── setup_memory (0x8298) ───────────────────────────────────────── */

uint32_t setup_memory(bootstrap_ctx_t *ctx)
{
    print_log("[bootstrap] setup_memory: flag_a=%d flag_b=%d flag_direct_mem=%d", ctx->flag_a, ctx->flag_b, ctx->flag_direct_mem);

    if (ctx->flag_a || ctx->flag_b || ctx->flag_direct_mem) {
        ctx->fn_icache_flush = (fn_icache_flush_t)flush_icache;

        if (!ctx->flag_b && !ctx->flag_direct_mem) {
            ctx->buffer_remaining = 0;
            return 0;
        }
        return 0;
    }

    uint32_t os_ver = ctx->os_version;
    print_log("[bootstrap] setup_memory: os_ver=0x%x", os_ver);

    if (os_ver >= 0x0F0000) {
        /* iOS 15+: use proc_pidinfo (PROC_PIDREGIONINFO = 7) */
        /* Returns struct proc_regioninfo (0x60 bytes):
         *   +0x00: pri_protection      (uint32_t)
         *   +0x04: pri_max_protection  (uint32_t)
         *   ...
         *   +0x50: pri_address         (uint64_t)
         *   +0x58: pri_size            (uint64_t)
         */
        struct {
            uint8_t data[0x60];
        } info;

        int ret = proc_pidinfo(getpid(), 7,
                               (uint64_t)ctx->buffer_ptr,
                               &info, 0x60);
        if (ret <= 0) {
            print_log("[bootstrap] setup_memory: proc_pidinfo FAIL ret=%d", ret);
            return 0x80000005;
        }

        uint64_t region_addr = *(uint64_t *)((uint8_t *)&info + 0x50);
        uint64_t region_size = *(uint64_t *)((uint8_t *)&info + 0x58);

        uint32_t prot     = *(uint32_t *)((uint8_t *)&info);
        uint32_t max_prot = *(uint32_t *)((uint8_t *)&info + 4);
        print_log("[bootstrap] setup_memory: region addr=0x%llx size=0x%llx prot=0x%x max_prot=0x%x",
                  (unsigned long long)region_addr, (unsigned long long)region_size, prot, max_prot);

        if (!ctx->mmap_secondary && prot != 0x7) {
            /* Current protection is not rwx — try to promote if max allows */
            uint32_t fix_err = ensure_rwx_protection(region_addr, region_size, prot, max_prot);
            if (fix_err) {
                print_log("[bootstrap] setup_memory: cannot get rwx protection");
                return fix_err;
            }
        }

        if (!region_addr || !region_size)
            return 0xc003;

        uint64_t half = region_size >> 1;
        if (half > region_size)
            return 0xc003;

        uint32_t *end = (uint32_t *)(region_addr + half);
        end--;
        if (half < *end)
            return 0xc003;

        ctx->atomic_state = end;
        ctx->exec_base = (uint8_t *)(region_addr + half);
        uint32_t usable;
        if (ctx->flag_new_ios)
            usable = (uint32_t)(half - 0x100000);
        else
            usable = (uint32_t)(region_size >> 2);
        ctx->exec_size = usable;
        ctx->fn_alloc_buffer = (fn_alloc_buffer_t)alloc_buffer;
        print_log("[bootstrap] setup_memory: iOS15+ exec_base=%p exec_size=0x%x", ctx->exec_base, usable);
        goto install_funcs;
    }

    /* Pre-iOS 15: use vm_region_64 */
    {
        mach_vm_address_t addr = (mach_vm_address_t)ctx->buffer_ptr;
        mach_vm_size_t size_out = 0;
        vm_region_flavor_t flavor = 9;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = 9;
        mach_port_t object_name;

        kern_return_t kr = vm_region_64(mach_task_self(),
                                        (vm_address_t *)&addr,
                                        (vm_size_t *)&size_out,
                                        flavor,
                                        (vm_region_info_t)&info,
                                        &count,
                                        &object_name);
        if (kr != KERN_SUCCESS) {
            print_log("[bootstrap] setup_memory: vm_region_64 FAIL kr=0x%x", kr);
            return kr | 0x80000000;
        }

        uint32_t prot = info.protection;
        uint32_t max_prot = info.max_protection;
        print_log("[bootstrap] setup_memory: region addr=0x%llx size=0x%llx prot=0x%x max_prot=0x%x",
                  (unsigned long long)addr, (unsigned long long)size_out, prot, max_prot);

        if (!ctx->mmap_secondary && prot != 0x7) {
            /* Current protection is not rwx — try to promote if max allows */
            uint32_t fix_err = ensure_rwx_protection(addr, size_out, prot, max_prot);
            if (fix_err) {
                print_log("[bootstrap] setup_memory: cannot get rwx protection");
                return fix_err;
            }
        }

        if (!addr || !size_out)
            return 0xc003;

        uint64_t half = size_out >> 1;
        uint32_t *end = (uint32_t *)(addr + half);
        end--;
        if (half < *end)
            return 0xc003;

        ctx->atomic_state = end;
        ctx->exec_base = (uint8_t *)(addr + half);
        uint32_t usable;
        if (ctx->flag_new_ios)
            usable = (uint32_t)(half - 0x100000);
        else
            usable = (uint32_t)(size_out >> 2);
        ctx->exec_size = usable;
        ctx->fn_alloc_buffer = (fn_alloc_buffer_t)alloc_buffer;
        print_log("[bootstrap] setup_memory: pre-15 exec_base=%p exec_size=0x%x", ctx->exec_base, usable);
    }

install_funcs:
    ctx->fn_icache_flush = (fn_icache_flush_t)flush_icache;
    print_log("[bootstrap] setup_memory: OK");
    return 0;
}
