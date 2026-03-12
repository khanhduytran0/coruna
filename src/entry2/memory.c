/*
 * memory.c - Custom memory operations
 *
 * Decompiled from entry2_type0x0f.dylib offsets 0x10010–0x10120
 *
 * These are custom memcpy/memset implementations that avoid using
 * libSystem. They are used in contexts where libSystem may not be
 * available (e.g., inside newly-injected threads before library
 * initialization).
 *
 * Note: These are intentionally naive byte-by-byte implementations
 * — the original binary does not use SIMD or word-sized copies.
 */

#include "entry2.h"

/* ── e2_memcpy_custom (0x10010) ──────────────────────────────────── *
 * Byte-by-byte copy from src to dst.
 *
 * Unlike standard memcpy, this returns dst (not dst+n).
 * Used in injected thread context where libc may not be loaded.
 *
 * The decompiled code is notably unoptimized — it uses stack-based
 * loop variables rather than registers, suggesting it was compiled
 * with -O0 or is hand-written C.
 *
 * asm (0x10010–0x100a0):
 *   str  x0, [sp, #0x28]     // dst
 *   str  x1, [sp, #0x20]     // src
 *   str  x2, [sp, #0x18]     // len
 *   ...
 *   str  xzr, [sp]           // i = 0
 *   loop:
 *     ldr  x8, [sp]          // i
 *     ldr  x9, [sp, #0x18]   // len
 *     cmp  x8, x9
 *     b.lo body
 *     b    done
 *   body:
 *     ldr  x8, [sp, #0x20]   // src
 *     ldr  x9, [sp]          // i
 *     add  x8, x8, x9
 *     ldrb w8, [x8]          // src[i]
 *     ldr  x9, [sp, #0x10]   // dst (saved copy)
 *     ldr  x10, [sp]         // i
 *     add  x9, x9, x10
 *     strb w8, [x9]          // dst[i] = src[i]
 *     ldr  x8, [sp]
 *     add  x8, x8, #1
 *     str  x8, [sp]          // i++
 *     b    loop
 */
void *e2_memcpy_custom(void *dst, const void *src, size_t len)
{
    if (!dst || !src || len == 0)
        return dst;

    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;

    for (size_t i = 0; i < len; i++) {
        d[i] = s[i];
    }

    return dst;
}

/* ── e2_memset_custom (0x100a4) ──────────────────────────────────── *
 * Byte-by-byte fill of dst with val.
 *
 * Same stack-heavy style as memcpy. Used to zero-fill sensitive
 * buffers and prepare injected code regions.
 *
 * asm (0x100a4–0x1011c):
 *   str  x0, [sp, #0x28]     // dst
 *   str  w1, [sp, #0x24]     // val
 *   str  x2, [sp, #0x18]     // len
 *   ...
 *   strb w1, [sp, #0xf]      // val_byte = (uint8_t)val
 *   str  xzr, [sp]           // i = 0
 *   loop:
 *     ldr  x8, [sp]          // i
 *     ldr  x9, [sp, #0x18]   // len
 *     cmp  x8, x9
 *     b.lo body
 *     b    done
 *   body:
 *     ldrb w8, [sp, #0xf]    // val_byte
 *     ldr  x9, [sp, #0x10]   // dst (saved)
 *     ldr  x10, [sp]         // i
 *     add  x9, x9, x10
 *     strb w8, [x9]          // dst[i] = val_byte
 *     ldr  x8, [sp]
 *     add  x8, x8, #1
 *     str  x8, [sp]          // i++
 *     b    loop
 */
void *e2_memset_custom(void *dst, int val, size_t len)
{
    if (!dst || len == 0)
        return dst;

    uint8_t byte = (uint8_t)val;
    uint8_t *d = (uint8_t *)dst;

    for (size_t i = 0; i < len; i++) {
        d[i] = byte;
    }

    return dst;
}

/* ── e2_memcpy_alias (0x10120) ───────────────────────────────────── *
 * Just a tail-call to e2_memcpy_custom.
 * Exists as a separate symbol for different calling conventions.
 *
 * asm:
 *   b 0x10010
 */
void *e2_memcpy_alias(void *dst, const void *src, size_t len)
{
    return e2_memcpy_custom(dst, src, len);
}
