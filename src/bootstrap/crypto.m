/*
 * crypto.m - ChaCha20 encryption and LZMA decompression
 *
 * Decompiled from bootstrap.dylib offsets 0xad8c-0xb09c, 0x8430-0x858c
 */

#import "bootstrap.h"
#import <string.h>
#import <stdlib.h>
#import <compression.h>

/* ── ChaCha20 quarter round macros ───────────────────────────────── */

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QR(a, b, c, d) do {    \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d,  8); \
    c += d; b ^= c; b = ROTL32(b,  7); \
} while(0)

static const uint32_t sigma[4] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};

/* ── chacha20_encrypt (0xad8c) ───────────────────────────────────── */

void chacha20_encrypt(uint8_t *key, uint8_t *data, uint64_t size)
{
    if (!key || !data || !size)
        return;

    print_log("[bootstrap] chacha20_encrypt: size=%llu", size);

    uint32_t state[16];
    uint32_t working[16];

    state[0] = sigma[0];
    state[1] = sigma[1];
    state[2] = sigma[2];
    state[3] = sigma[3];

    memcpy(&state[4], key, 32);

    state[12] = 0;
    state[13] = 0;
    state[14] = 0;
    state[15] = 0;

    uint64_t offset = 0;
    uint64_t ks_pos = 64;

    while (offset < size) {
        if (ks_pos >= 64) {
            memcpy(working, state, 64);

            for (int i = 0; i < 10; i++) {
                QR(working[0], working[4], working[ 8], working[12]);
                QR(working[1], working[5], working[ 9], working[13]);
                QR(working[2], working[6], working[10], working[14]);
                QR(working[3], working[7], working[11], working[15]);
                QR(working[0], working[5], working[10], working[15]);
                QR(working[1], working[6], working[11], working[12]);
                QR(working[2], working[7], working[ 8], working[13]);
                QR(working[3], working[4], working[ 9], working[14]);
            }

            for (int i = 0; i < 16; i++)
                working[i] += state[i];

            state[12]++;
            if (state[12] == 0)
                state[13]++;

            ks_pos = 0;
        }

        data[offset] ^= ((uint8_t *)working)[ks_pos];
        ks_pos++;
        offset++;
    }

    print_log("[bootstrap] chacha20_encrypt: done");
}

/* ── decompress (0x8430) ─────────────────────────────────────────── */

uint32_t decompress(void **ptr_to_data, uint32_t *ptr_to_size)
{
    uint32_t err = ERR_NULL_CTX;

    if (!ptr_to_data || !ptr_to_size)
        return err;

    uint8_t *src = (uint8_t *)*ptr_to_data;
    uint32_t src_size = *ptr_to_size;

    if (!src || !src_size)
        return err;

    if (src_size < 8)
        return 0;

    uint32_t magic = *(uint32_t *)src;
    if (magic != MAGIC_BEDF00D)
        return 0;

    uint32_t decomp_size = *(uint32_t *)(src + 4);
    if (!decomp_size)
        return 0;

    print_log("[bootstrap] decompress: src_size=%u decomp_size=%u", src_size, decomp_size);

    uint32_t comp_data_size = src_size - 8;
    if (comp_data_size >= decomp_size)
        return 0;

    uint64_t alloc_size = (uint64_t)decomp_size + 1;
    uint8_t *dst = (uint8_t *)malloc(alloc_size);
    if (!dst) {
        print_log("[bootstrap] decompress: malloc FAIL");
        return err + 8;
    }

    memset_s(dst, decomp_size, 0, decomp_size);

    size_t result = compression_decode_buffer(
        dst, alloc_size,
        src + 8, comp_data_size,
        NULL, COMPRESSION_LZMA
    );

    if (result != decomp_size) {
        print_log("[bootstrap] decompress: FAIL result=%zu expected=%u", result, decomp_size);
        memset_s(dst, decomp_size, 0, decomp_size);
        free(dst);
        return err + 0xa;
    }

    memset_s(src, src_size, 0, src_size);
    free(src);

    *ptr_to_data = dst;
    *ptr_to_size = decomp_size;
    print_log("[bootstrap] decompress: OK size=%u", decomp_size);
    return 0;
}
