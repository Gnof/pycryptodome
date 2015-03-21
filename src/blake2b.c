/* ===================================================================
 *
 * Copyright (c) 2014, Legrandin <helderijs@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 * ===================================================================
 */

#include "pycrypto_common.h"

#include <assert.h>
#include <stdio.h>

FAKE_INIT(BLAKE2b)

typedef struct {
        uint64_t h[8];
        uint64_t off_counter_low;
        uint64_t off_counter_high;
        size_t   buf_occ;
        union {
            uint8_t  b[16*sizeof(uint64_t)];
            uint64_t w[16];
        } buf;
} hash_state;

typedef enum { NON_FINAL_BLOCK, FINAL_BLOCK } block_type;

static const uint64_t iv[8] = {
    0x6A09E667F3BCC908ull,
    0xBB67AE8584CAA73Bull,
    0x3C6EF372FE94F82Bull,
    0xA54FF53A5F1D36F1ull,
    0x510E527FADE682D1ull,
    0x9B05688C2B3E6C1Full,
    0x1F83D9ABFB41BD6Bull,
    0x5BE0CD19137E2179ull
};

static unsigned minAB(unsigned a, unsigned b)
{
    return a < b ? a : b;
}

static int little_endian(void) {
    int test = 1;
    return *((uint8_t*)&test) == 1;
}

static void byteswap64(uint64_t *v)
{
    union {
        uint64_t w;
        uint8_t b[8];
    } x, y;

    x.w = *v;
    y.b[0] = x.b[7];
    y.b[1] = x.b[6];
    y.b[2] = x.b[5];
    y.b[3] = x.b[4];
    y.b[4] = x.b[3];
    y.b[5] = x.b[2];
    y.b[6] = x.b[1];
    y.b[7] = x.b[0];
    *v = y.w;
}

EXPORT_SYM int blake2b_init (hash_state **state,
                            const uint8_t *key,
                            size_t key_size,
                            size_t digest_size)
{
    hash_state *hs;
    unsigned i;

    if (NULL == state)
        return ERR_NULL;

    if (NULL == key || key_size > 64)
        return ERR_KEY_SIZE;

    if (digest_size == 0 || digest_size > 64)
        return ERR_DIGEST_SIZE;

    *state = hs = (hash_state*) calloc(1, sizeof(hash_state));
    if (NULL == hs)
        return ERR_MEMORY;

    for (i=0; i<8; i++)
        hs->h[i] = iv[i];
    hs->h[0] ^= 0x01010000 ^ (key_size << 8) ^ digest_size;

    /** If the key is present, the first block is the key padded with zeroes **/
    if (key_size>0) {
        memcpy(hs->buf.b, key, key_size);
        hs->buf_occ = sizeof hs->buf;
    }

    return 0;
}

EXPORT_SYM int blake2b_destroy(hash_state *hs)
{
    free(hs);
    return 0;
}

EXPORT_SYM int blake2b_copy(const hash_state *src, hash_state *dst)
{
    if (NULL == src || NULL == dst) {
        return ERR_NULL;
    }

    *dst = *src;
    return 0;
}

#define ROTR64(x,n) (((x) >> (n)) ^ ((x) << (64 - (n))))

#define G(v,a,b,c,d,x,y) \
{ \
    v[a] = v[a] + v[b] + x; \
    v[d] = ROTR64(v[d] ^ v[a], 32); \
    v[c] = v[c] + v[d]; \
    v[b] = ROTR64(v[b] ^ v[c], 24); \
    v[a] = v[a] + v[b] + y; \
    v[d] = ROTR64(v[d] ^ v[a], 16); \
    v[c] = v[c] + v[d]; \
    v[b] = ROTR64(v[b] ^ v[c], 63); \
}

static void blake2b_compress(uint64_t state[8],
                             const uint64_t m[16],
                             uint64_t off_counter_low,
                             uint64_t off_counter_high,
                             block_type bt
                             )
{
    static const uint8_t sigma[12][16] = {
           { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
           { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
           { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
           { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
           { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
           { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
           { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
           { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
           { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
           { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
           { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
           { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
    };
    unsigned i;
    uint64_t work[16];

    for (i=0; i<8; i++) {
        work[i] = state[i];
        work[i+8] = iv[i];
    }

    work[12] ^= off_counter_low;
    work[13] ^= off_counter_high;

    if (bt == FINAL_BLOCK)
        work[14] = ~work[14];

    for (i=0; i<12; i++) {
        const uint8_t *s;

        s = &sigma[i][0];
        G(work, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]]);
        G(work, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]]);
        G(work, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]]);
        G(work, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]]);
        G(work, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]]);
        G(work, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        G(work, 2, 7,  8, 13, m[s[12]], m[s[13]]);
        G(work, 3, 4,  9, 14, m[s[14]], m[s[15]]);
    }

    for (i=0; i<8; i++)
      state[i] ^= work[i] ^ work[i+8];
}

void blake2b_process_buffer(hash_state *hs, size_t new_data_added,
                          block_type bt)
{
    if (!little_endian()) {
        unsigned i;
        for (i=0; i<16; i++)
            byteswap64(hs->buf.w + i);
    }

    hs->off_counter_low += new_data_added;
    if (hs->off_counter_low < new_data_added)
        hs->off_counter_high++;

    blake2b_compress(hs->h,
                     hs->buf.w,
                     hs->off_counter_low,
                     hs->off_counter_high,
                     bt);

    hs->buf_occ = 0;
}

EXPORT_SYM int blake2b_update(hash_state *hs, const uint8_t *in, size_t len)
{
    if (NULL == hs)
        return ERR_NULL;

    if (len > 0 && NULL == in)
        return ERR_NULL;

    while (len > 0) {
        size_t consumed;

        if (hs->buf_occ == sizeof hs->buf) {
            blake2b_process_buffer(hs, sizeof hs->buf.b, NON_FINAL_BLOCK);
        }

        /** Consume input **/
        consumed = minAB(len, sizeof hs->buf.b - hs->buf_occ);
        memcpy(hs->buf.b + hs->buf_occ, in, consumed);
        len -= consumed;
        in += consumed;
        hs->buf_occ += consumed;
    }

    return 0;
}

EXPORT_SYM int blake2b_digest(const hash_state *hs, uint8_t digest[64])
{
    hash_state temp_hs;

    if (NULL==hs || NULL==digest)
        return ERR_NULL;

    temp_hs = *hs;

    /** Fill buffer with zeroes **/
    memset(temp_hs.buf.b + temp_hs.buf_occ,
           0,
           sizeof temp_hs.buf.b - temp_hs.buf_occ);

    blake2b_process_buffer(&temp_hs,
                           temp_hs.buf_occ,
                           FINAL_BLOCK);

    if (!little_endian()) {
        unsigned i;
        for (i=0; i<8; i++)
            byteswap64(temp_hs.h + i);
    }
    memcpy(digest, temp_hs.h, 64);
    return 0;
}
