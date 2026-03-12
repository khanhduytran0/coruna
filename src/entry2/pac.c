/*
 * pac.c - Pointer Authentication Code utilities
 *
 * Decompiled from entry2_type0x0f.dylib offsets 0x861c–0x8664
 * These are nearly identical to bootstrap.dylib's PAC helpers.
 */

#include "entry2.h"

/* ── Raw PAC instruction wrappers (0x861c–0x8638) ────────────────── */

/* 0x861c: pacia x0, x1; ret */
__attribute__((noinline))
uint64_t e2_pacia(uint64_t ptr, uint64_t ctx)
{
    __asm__ volatile("pacia %0, %1" : "+r"(ptr) : "r"(ctx));
    return ptr;
}

/* 0x8624: pacda x0, x1; ret */
__attribute__((noinline))
uint64_t e2_pacda(uint64_t ptr, uint64_t ctx)
{
    __asm__ volatile("pacda %0, %1" : "+r"(ptr) : "r"(ctx));
    return ptr;
}

/* 0x862c: pacib x0, x1; ret */
__attribute__((noinline))
uint64_t e2_pacib(uint64_t ptr, uint64_t ctx)
{
    __asm__ volatile("pacib %0, %1" : "+r"(ptr) : "r"(ctx));
    return ptr;
}

/* 0x8634: pacdb x0, x1; ret */
__attribute__((noinline))
uint64_t e2_pacdb(uint64_t ptr, uint64_t ctx)
{
    __asm__ volatile("pacdb %0, %1" : "+r"(ptr) : "r"(ctx));
    return ptr;
}

/* ── e2_check_pac (0x863c) ───────────────────────────────────────── *
 * Tests if Pointer Authentication is active by loading a known value
 * into LR, stripping it with xpaclri, and comparing.
 *
 * Returns 1 if PAC is active (values differ), 0 if not.
 */
int e2_check_pac(void)
{
    uint64_t test = 0xAAAAAAAAAAAAAAAAULL;
    uint64_t result;

    __asm__ volatile(
        "stp x29, x30, [sp, #-0x10]!\n"
        "mov x30, %1\n"       /* load known value into LR */
        "xpaclri\n"           /* strip PAC bits from LR */
        "mov %0, x30\n"       /* save result */
        "ldp x29, x30, [sp], #0x10\n"
        : "=r"(result)
        : "r"(test)
        : "memory"
    );
    return (result != test) ? 1 : 0;
}

/* ── e2_strip_pac (0x19f4c) ──────────────────────────────────────── *
 * Strips PAC bits from a pointer using xpaclri.
 */
uint64_t e2_strip_pac(uint64_t ptr)
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

/* ── e2_sign_pointer (0x19f68) ───────────────────────────────────── *
 * Conditionally PAC-signs a pointer with PACIA.
 * If PAC is available, signs ptr with ctx=0 (paciza).
 * If not, returns the raw pointer.
 *
 * Note: at 0x19f68, it calls 0x863c (check) and 0x861c (pacia).
 * If PAC is active, it tail-calls the actual sign function at 0x861c.
 */
uint64_t e2_sign_pointer(uint64_t ptr, uint64_t ctx)
{
    if (e2_check_pac()) {
        return e2_pacia(ptr, ctx);
    }
    return ptr;
}
