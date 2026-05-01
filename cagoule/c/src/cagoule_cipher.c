#include <stdlib.h>
#include <string.h>
#include "cagoule_math.h"
#include "cagoule_matrix.h"
#include "cagoule_sbox.h"
#include "cagoule_cipher.h"

#define N CAGOULE_N

static inline size_t _p_bytes(uint64_t p) {
    return cagoule_p_bytes(p);
}

static inline void _u64_to_be(uint64_t val, uint8_t* buf, size_t p_bytes) {
    for (size_t i = p_bytes; i-- > 0;) {
        buf[i] = (uint8_t)(val & 0xFF);
        val >>= 8;
    }
}

static inline uint64_t _be_to_u64(const uint8_t* buf, size_t p_bytes) {
    uint64_t val = 0;
    for (size_t i = 0; i < p_bytes; i++)
        val = (val << 8) | buf[i];
    return val;
}

int cagoule_cbc_encrypt(
    const uint8_t*       padded,
    size_t               n_blocks,
    uint8_t*             out,
    size_t               out_size,
    const CagouleMatrix* mat,
    CagouleSBox64*       sbox,
    const uint64_t*      round_keys,
    size_t               num_keys,
    uint64_t             p)
{
    size_t p_bytes = _p_bytes(p);
    size_t out_needed = n_blocks * N * p_bytes;

    if (!padded || !out || !mat || !sbox || !round_keys)
        return CAGOULE_ERR_NULL;
    if (out_size < out_needed)
        return CAGOULE_ERR_SIZE;

    uint64_t prev[N] = {0};
    uint64_t block[N], tmp[N];

    for (size_t bi = 0; bi < n_blocks; bi++) {
        const uint8_t* src = padded + bi * N;

        for (int j = 0; j < N; j++)
            block[j] = (uint64_t)src[j];

        for (int j = 0; j < N; j++)
            block[j] = addmod64(block[j], prev[j], p);

        cagoule_matrix_mul(mat, block, tmp);
        cagoule_sbox_block_forward(sbox, tmp, block, N);

        uint64_t rk = round_keys[bi % num_keys];
        for (int j = 0; j < N; j++)
            block[j] = addmod64(block[j], rk, p);

        memcpy(prev, block, N * sizeof(uint64_t));

        uint8_t* dst = out + bi * N * p_bytes;
        for (int j = 0; j < N; j++)
            _u64_to_be(block[j], dst + j * p_bytes, p_bytes);
    }

    return CAGOULE_OK;
}

int cagoule_cbc_decrypt(
    const uint8_t*       cipher_bytes,
    size_t               n_blocks,
    uint8_t*             out,
    size_t               out_size,
    const CagouleMatrix* mat,
    CagouleSBox64*       sbox,
    const uint64_t*      round_keys,
    size_t               num_keys,
    uint64_t             p)
{
    size_t p_bytes = _p_bytes(p);
    size_t pt_needed = n_blocks * N;

    if (!cipher_bytes || !out || !mat || !sbox || !round_keys)
        return CAGOULE_ERR_NULL;
    if (out_size < pt_needed)
        return CAGOULE_ERR_SIZE;

    uint64_t prev[N] = {0};
    uint64_t cipher_block[N], tmp[N];

    for (size_t bi = 0; bi < n_blocks; bi++) {
        const uint8_t* src = cipher_bytes + bi * N * p_bytes;

        for (int j = 0; j < N; j++)
            cipher_block[j] = _be_to_u64(src + j * p_bytes, p_bytes);

        uint64_t c_save[N];
        memcpy(c_save, cipher_block, N * sizeof(uint64_t));

        uint64_t rk = round_keys[bi % num_keys];
        for (int j = 0; j < N; j++)
            tmp[j] = submod64(cipher_block[j], rk, p);

        cagoule_sbox_block_inverse(sbox, tmp, cipher_block, N);
        cagoule_matrix_mul_inv(mat, cipher_block, tmp);

        uint8_t* dst = out + bi * N;
        for (int j = 0; j < N; j++) {
            uint64_t b = submod64(tmp[j], prev[j], p);
            if (b > 255)
                return CAGOULE_ERR_CORRUPT;
            dst[j] = (uint8_t)b;
        }

        memcpy(prev, c_save, N * sizeof(uint64_t));
    }

    return CAGOULE_OK;
}