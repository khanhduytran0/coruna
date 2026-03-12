/*
 * pac.m - Pointer Authentication Code utilities
 *
 * Decompiled from bootstrap.dylib offsets 0x5cec-0x5dc4, 0x6fec-0x708c,
 * 0x7ba0-0x7be8
 */

#import "bootstrap.h"
#import <stdlib.h>

/* ── Raw PAC instruction wrappers (0x7ba0-0x7bbc) ────────────────── */

__attribute__((noinline))
uint64_t pacia(uint64_t ptr, uint64_t ctx)
{
    __asm__ volatile("pacia %0, %1" : "+r"(ptr) : "r"(ctx));
    return ptr;
}

__attribute__((noinline))
uint64_t pacda(uint64_t ptr, uint64_t ctx)
{
    __asm__ volatile("pacda %0, %1" : "+r"(ptr) : "r"(ctx));
    return ptr;
}

__attribute__((noinline))
uint64_t pacib(uint64_t ptr, uint64_t ctx)
{
    __asm__ volatile("pacib %0, %1" : "+r"(ptr) : "r"(ctx));
    return ptr;
}

__attribute__((noinline))
uint64_t pacdb(uint64_t ptr, uint64_t ctx)
{
    __asm__ volatile("pacdb %0, %1" : "+r"(ptr) : "r"(ctx));
    return ptr;
}

/* ── check_pac_enabled (0x7bc0) ──────────────────────────────────── */

int check_pac_enabled(void)
{
    uint64_t test_val = 0xAAAAAAAAAAAAAAAAULL;
    uint64_t result;
    __asm__ volatile(
        "mov x30, %1\n"
        "xpaclri\n"
        "mov %0, x30\n"
        : "=r"(result)
        : "r"(test_val)
        : "x30"
    );
    int enabled = (result != test_val) ? 1 : 0;
    print_log("[bootstrap] check_pac_enabled: %d", enabled);
    return enabled;
}

/* ── has_pac (0x5cec) ────────────────────────────────────────────── */

int has_pac(void)
{
    return check_pac_enabled() != 0 ? 1 : 0;
}

/* ── strip_pac (0x5d2c) ─────────────────────────────────────────── */

uint64_t strip_pac(uint64_t ptr)
{
    uint64_t result;
    __asm__ volatile(
        "mov x30, %1\n"
        "xpaclri\n"
        "mov %0, x30\n"
        : "=r"(result)
        : "r"(ptr)
        : "x30"
    );
    return result;
}

/* ── pac_sign_if_needed (0x5d68) ─────────────────────────────────── */

uint64_t pac_sign_if_needed(uint64_t ptr, uint64_t ctx)
{
    if (check_pac_enabled())
        ptr = pacia(ptr, ctx);
    return ptr;
}

/* ── resolve_pac_pointer (0x6fec) ─────────────────────────────────
 * SIGSEGV handler for PAC authentication faults.
 */

void resolve_pac_pointer(int sig, void *info, void *ucontext)
{
    print_log("[bootstrap] resolve_pac_pointer: sig=%d", sig);

    uint64_t *mctx = *(uint64_t **)((uint8_t *)ucontext + 0x30);
    uint64_t pc = *(uint64_t *)((uint8_t *)mctx + 0x110);

    uint64_t upper = pc >> 39;
    if (upper == 0x4000) {
        pc &= ~(1ULL << 53);
    } else {
        uint64_t x0_val = mctx[0];
        uint64_t masked = x0_val & 0xFFFFFF8000000000ULL;

        if (masked == 0x2000000000000000ULL) {
            uint64_t x0_low = x0_val & 0x7FFFFFFFFFULL;
            uint64_t pc_low = pc & 0x7FFFFFFFFFULL;
            if (x0_low != pc_low)
                abort();
        } else if (masked == 0x0020000000000000ULL) {
            uint64_t x0_low = x0_val & 0x7FFFFFFFFFULL;
            uint64_t pc_low = pc & 0x7FFFFFFFFFULL;
            if (x0_low != pc_low)
                abort();
        } else {
            abort();
        }
        pc = pac_sign_if_needed(x0_val & 0x7FFFFFFFFFULL, 0x7481);
    }

    *(uint64_t *)((uint8_t *)mctx + 0x110) = pc;
    print_log("[bootstrap] resolve_pac_pointer: fixed PC=0x%llx", pc);
}
