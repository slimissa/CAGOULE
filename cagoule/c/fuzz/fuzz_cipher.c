/**
 * fuzz_cipher.c — libFuzzer harness for CAGOULE (CBC + CTR)
 *                 CAGOULE v3.1.0
 *
 * Build:
 *   clang -O1 -g -fsanitize=fuzzer,address,undefined \
 *         -Iinclude fuzz/fuzz_cipher.c -L. -lcagoule -Wl,-rpath,. -o fuzz_cipher
 *
 * Run:
 *   ./fuzz_cipher -max_len=65536 -runs=1000000
 *
 * Modes (bits of first byte):
 *   bit 0 : enable Z-offset (extracted from input if enough bytes)
 *   bit 1 : enable roundtrip (decrypt → re-encrypt)
 *   bit 2 : use CTR mode instead of CBC (v3.0.0)
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "cagoule_cipher.h"
#include "cagoule_ctr.h"
#include "cagoule_matrix.h"
#include "cagoule_sbox.h"

/* ── Fixed test parameters ────────────────────────────────────────── */
static CagouleMatrix* g_mat = NULL;
static CagouleSBox64  g_sbox;
static uint64_t       g_rk[64];
static const uint64_t P = 10441487724840939323ULL;

static void setup(void) {
    uint64_t nodes[16];
    for (int i = 0; i < 16; i++)
        nodes[i] = (uint64_t)((i + 1) * 7 + 3) % P;
    for (int j = 0; j < 16; j++) {
        for (int k = 0; k < j; k++) {
            while (nodes[j] == nodes[k])
                nodes[j] = (nodes[j] + 1) % P;
        }
    }
    g_mat = cagoule_matrix_build(nodes, 16, P);
    cagoule_sbox_init(&g_sbox, P, 2147483693ULL, 3221225473ULL);
    for (int i = 0; i < 64; i++)
        g_rk[i] = (uint64_t)(i * 1234567891011ULL % P) + 1;
}

/* ── libFuzzer entry point ────────────────────────────────────────── */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static int initialized = 0;
    if (!initialized) { setup(); initialized = 1; }

    /* Minimum: 1 byte for mode flags */
    if (size < 1) return 0;

    /* Parse mode flags */
    uint8_t mode      = data[0];
    int     use_zo     = (mode & 1) != 0;   /* bit 0: Z-offset */
    int     roundtrip  = (mode & 2) != 0;   /* bit 1: decrypt→encrypt roundtrip */
    int     use_ctr    = (mode & 4) != 0;   /* bit 2: CTR mode (v3.0.0) */

    const uint8_t *payload = data + 1;
    size_t payload_len     = size - 1;

    /* ── Z-offset extraction ──────────────────────────────────────── */
    const uint64_t *zo = NULL;
    size_t nzo = 0;
    uint64_t zo_buf[16];

    if (use_zo && payload_len >= 128) {
        /* Use first 128 bytes of payload as 16 uint64 Z-offsets */
        memcpy(zo_buf, payload, 128);
        zo = zo_buf;
        nzo = 16;
    }

    /* ── CTR Mode ─────────────────────────────────────────────────── */
    if (use_ctr) {
        /* CTR needs at least an IV (8 bytes) + some ciphertext */
        if (payload_len < 9) return 0;  /* 8 bytes IV + at least 1 byte CT */

        /* First 8 bytes of payload = IV */
        const uint8_t *iv = payload;
        const uint8_t *ct = payload + 8;
        size_t ct_len     = payload_len - 8;

        if (ct_len == 0) return 0;
        if (ct_len > 65536) ct_len = 65536;  /* Cap at 64KB */

        uint8_t *out = (uint8_t *)malloc(ct_len);
        if (!out) return 0;

        /* CTR decrypt */
        cagoule_ctr_decrypt(ct, ct_len, iv, g_mat, &g_sbox, g_rk, 64, P,
                             zo, nzo, out, ct_len);

        /* CTR roundtrip: re-encrypt the decrypted output */
        if (roundtrip) {
            uint8_t *enc_out = (uint8_t *)malloc(ct_len);
            if (enc_out) {
                /* Use a fresh IV for re-encryption (next 8 bytes of payload if available) */
                const uint8_t *iv2 = iv;
                if (payload_len >= 17 + ct_len) {
                    iv2 = payload + 8 + ct_len;
                }
                cagoule_ctr_encrypt(out, ct_len, iv2, g_mat, &g_sbox, g_rk, 64, P,
                                     zo, nzo, enc_out, ct_len);
                free(enc_out);
            }
        }

        /* CTR keystream generation (independent fuzz target) */
        if (ct_len >= 16) {
            uint8_t ks[64];  /* 4 blocks max = 64 bytes */
            size_t n_ks_blocks = (ct_len / 16);
            if (n_ks_blocks > 4) n_ks_blocks = 4;
            cagoule_ctr_keystream(iv, 0, g_mat, &g_sbox, g_rk, 64, P,
                                   ks, n_ks_blocks);

            /* 4x pipeline: generate keystream for 4 blocks via encrypt_4x */
            if (n_ks_blocks >= 4) {
                uint8_t *enc_4x_out = (uint8_t *)malloc(64);
                if (enc_4x_out) {
                    cagoule_ctr_encrypt_4x(out, 64, iv,
                                            g_mat, &g_sbox, g_rk, 64, P,
                                            zo, nzo, enc_4x_out, 64);
                    free(enc_4x_out);
                }
            }
        }

        free(out);
        return 0;
    }

    /* ── CBC Mode (legacy) ────────────────────────────────────────── */
    /* Minimum: 1 block = 16 uint64_t = 128 bytes of ciphertext */
    if (payload_len < 128) return 0;

    const uint8_t *ct = payload;
    size_t ct_len     = payload_len;

    /* Round down to block boundary (16 * 8 = 128 bytes per block) */
    size_t n_blocks = ct_len / 128;
    if (n_blocks == 0) return 0;
    if (n_blocks > 1024) n_blocks = 1024;  /* Cap at 16KB */

    size_t pt_size = n_blocks * 16;
    uint8_t *out = (uint8_t *)malloc(pt_size);
    if (!out) return 0;

    /* CBC decrypt */
    cagoule_cbc_decrypt(ct, n_blocks, out, pt_size,
                         g_mat, &g_sbox, g_rk, 64, P, zo, nzo);

    /* CBC roundtrip */
    if (roundtrip) {
        size_t enc_ct_size = n_blocks * 16 * 8;  /* p_bytes = 8 for P≈2^64 */
        uint8_t *enc_out = (uint8_t *)malloc(enc_ct_size);
        if (enc_out) {
            /* Use the decrypted output as plaintext (may be invalid PKCS7) */
            cagoule_cbc_encrypt(out, n_blocks, enc_out, enc_ct_size,
                                g_mat, &g_sbox, g_rk, 64, P, zo, nzo);
            free(enc_out);
        }
    }

    free(out);
    return 0;
}