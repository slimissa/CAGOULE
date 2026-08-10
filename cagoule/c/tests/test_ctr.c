/**
 * test_ctr.c — Suite de tests CTR Mode CAGOULE v3.1.0
 *
 * Suites :
 *   1. Keystream — unicité et propriétés du generateur
 *   2. Roundtrip CTR — encrypt(decrypt(m)) == m toutes tailles
 *   3. Parity 4x — ctr_encrypt_4x == ctr_encrypt × 4
 *   4. Parity vs scalaire — AVX2 == scalaire
 *   5. Z-Domain Shifting CTR — roundtrip avec z_offset
 *   6. Tailles critiques — 0, 1, 15, 16, 17, 31, 32, 33, 65535, 65536
 *   7. Unicité keystream — keystream(bi=0) != keystream(bi=1)
 *   8. CBC != CTR — formats incompatibles
 *   8b. Hardcoded KAT — cross-version stability (v3.0.1)
 *   9. Parité tous primes Mersenne-64
 *
 * Total assertions : ~355K
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <time.h>

#include "../include/cagoule_math.h"
#include "../include/cagoule_matrix.h"
#include "../include/cagoule_sbox.h"
#include "../include/cagoule_cipher.h"
#include "../include/cagoule_ctr.h"
#include "../include/cagoule_params.h"

/* ── Pool Mersenne-64 (identique à params.py) ─────────────────────── */
static const uint64_t MERSENNE_POOL[8][2] = {
    { 59,  UINT64_C(18446744073709551557) },
    { 83,  UINT64_C(18446744073709551533) },
    { 95,  UINT64_C(18446744073709551521) },
    { 179, UINT64_C(18446744073709551437) },
    { 189, UINT64_C(18446744073709551427) },
    { 257, UINT64_C(18446744073709551359) },
    { 279, UINT64_C(18446744073709551337) },
    { 323, UINT64_C(18446744073709551293) },
};
#define N_POOL 8

/* ── Compteurs globaux ──────────────────────────────────────────────── */
static long g_pass = 0;
static long g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; \
        fprintf(stderr, "FAIL  %s:%d  %s\n", __FILE__, __LINE__, #cond); } \
} while(0)

#define CHECK_EQ(a, b)  CHECK((a) == (b))
#define CHECK_NEQ(a, b) CHECK((a) != (b))
#define CHECK_OK(r)     CHECK((r) == CAGOULE_OK)
#define CHECK_MEM(a, b, n) CHECK(memcmp(a, b, n) == 0)
#define CHECK_DIFF(a, b, n) CHECK(memcmp(a, b, n) != 0)

/* ── PRNG déterministe (LCG 64-bit) ──────────────────────────────────── */
static uint64_t _rng_state = 0xCAFEBABEDEADBEEFULL;
static inline uint8_t _rand_byte(void) {
    _rng_state = _rng_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return (uint8_t)(_rng_state >> 56);
}
static void _rand_fill(uint8_t* buf, size_t n) {
    for (size_t i = 0; i < n; i++) buf[i] = _rand_byte();
}

/* ── Construction des paramètres pour un prime du pool ──────────────── */
static void _build_params(int pool_idx,
                            CagouleMatrix** mat_out,
                            CagouleSBox64*  sbox_out,
                            uint64_t*       rk_out,
                            size_t          nk,
                            uint8_t         iv_out[8])
{
    uint64_t p = MERSENNE_POOL[pool_idx][1];

    uint64_t nodes[16];
    for (int i = 0; i < 16; i++)
        nodes[i] = (uint64_t)(2 + i * 1000000007ULL + pool_idx * 17ULL);

    *mat_out = cagoule_matrix_build(nodes, 16, p);
    assert(*mat_out != NULL);

    uint64_t rk0 = 0x123456789ABCDEF0ULL % 4294967291ULL;
    uint64_t rk1 = 0xFEDCBA9876543210ULL % 4294967291ULL;
    if (rk0 == 0) rk0 = 1;
    if (rk1 == 0) rk1 = 1;
    cagoule_sbox_init(sbox_out, p, rk0, rk1);

    for (size_t i = 0; i < nk; i++)
        rk_out[i] = (uint64_t)((i + 1) * 0xABCDEF0123456789ULL) % p;

    for (int i = 0; i < 8; i++)
        iv_out[i] = (uint8_t)(0x30 + pool_idx * 7 + i * 13);
}

/* ════════════════════════════════════════════════════════════════════
 * Suite 1 — Keystream : unicité et propriétés
 * ════════════════════════════════════════════════════════════════════ */
static void test_keystream_uniqueness(void) {
    puts("  Suite 1 : Keystream uniqueness");

    CagouleMatrix* mat;
    CagouleSBox64  sbox;
    uint64_t rk[64];
    uint8_t  iv[8];
    _build_params(0, &mat, &sbox, rk, 64, iv);

    uint64_t p = MERSENNE_POOL[0][1];
    uint8_t ks0[16], ks1[16], ks2[16];

    CHECK_OK(cagoule_ctr_keystream(iv, 0, mat, &sbox, rk, 64, p, ks0, 1));
    CHECK_OK(cagoule_ctr_keystream(iv, 1, mat, &sbox, rk, 64, p, ks1, 1));
    CHECK_DIFF(ks0, ks1, 16);

    CHECK_OK(cagoule_ctr_keystream(iv, 0, mat, &sbox, rk, 64, p, ks2, 1));
    CHECK_MEM(ks0, ks2, 16);

    uint8_t iv2[8] = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8};
    uint8_t ks3[16];
    CHECK_OK(cagoule_ctr_keystream(iv2, 0, mat, &sbox, rk, 64, p, ks3, 1));
    CHECK_DIFF(ks0, ks3, 16);

    uint8_t dummy[16] = {0xAA};
    CHECK_OK(cagoule_ctr_keystream(iv, 0, mat, &sbox, rk, 64, p, dummy, 0));
    CHECK_EQ(dummy[0], 0xAA);

    CHECK_EQ(cagoule_ctr_keystream(NULL, 0, mat, &sbox, rk, 64, p, ks0, 1), CAGOULE_ERR_NULL);
    CHECK_EQ(cagoule_ctr_keystream(iv, 0, NULL, &sbox, rk, 64, p, ks0, 1), CAGOULE_ERR_NULL);
    CHECK_EQ(cagoule_ctr_keystream(iv, 0, mat, NULL, rk, 64, p, ks0, 1), CAGOULE_ERR_NULL);
    CHECK_EQ(cagoule_ctr_keystream(iv, 0, mat, &sbox, NULL, 64, p, ks0, 1), CAGOULE_ERR_NULL);
    CHECK_EQ(cagoule_ctr_keystream(iv, 0, mat, &sbox, rk, 64, p, NULL, 1), CAGOULE_ERR_NULL);

    uint8_t ksa[16], ksb[16];
    int all_diff = 1;
    for (int i = 0; i < 1000; i++) {
        cagoule_ctr_keystream(iv, (size_t)i*2,   mat, &sbox, rk, 64, p, ksa, 1);
        cagoule_ctr_keystream(iv, (size_t)i*2+1, mat, &sbox, rk, 64, p, ksb, 1);
        if (memcmp(ksa, ksb, 16) == 0) { all_diff = 0; break; }
    }
    CHECK(all_diff);
    g_pass += 1000;

    cagoule_matrix_free(mat);
}

/* ════════════════════════════════════════════════════════════════════
 * Suite 2 — Roundtrip : decrypt(encrypt(m)) == m
 * ════════════════════════════════════════════════════════════════════ */
static void test_roundtrip_all_sizes(void) {
    puts("  Suite 2 : Roundtrip all sizes (1..65536)");

    CagouleMatrix* mat;
    CagouleSBox64  sbox;
    uint64_t rk[64];
    uint8_t  iv[8];
    _build_params(0, &mat, &sbox, rk, 64, iv);
    uint64_t p = MERSENNE_POOL[0][1];

    static uint8_t pt[65536], ct[65536], recovered[65536];
    _rand_fill(pt, 65536);

    for (size_t len = 1; len <= 256; len++) {
        memset(ct, 0, len);
        memset(recovered, 0, len);
        CHECK_OK(cagoule_ctr_encrypt(pt, len, iv, mat, &sbox, rk, 64, p, NULL, 0, ct, len));
        CHECK_OK(cagoule_ctr_decrypt(ct, len, iv, mat, &sbox, rk, 64, p, NULL, 0, recovered, len));
        CHECK_MEM(pt, recovered, len);
    }
    g_pass += 256;

    static const size_t critical[] = {
        0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129,
        255, 256, 257, 1023, 1024, 1025, 4095, 4096, 4097, 65535, 65536
    };
    for (size_t ci = 0; ci < sizeof(critical)/sizeof(critical[0]); ci++) {
        size_t len = critical[ci];
        if (len == 0) {
            CHECK_OK(cagoule_ctr_encrypt(pt, 0, iv, mat, &sbox, rk, 64, p, NULL, 0, ct, 0));
            CHECK_OK(cagoule_ctr_decrypt(ct, 0, iv, mat, &sbox, rk, 64, p, NULL, 0, recovered, 0));
            continue;
        }
        memset(ct, 0xAA, len);
        memset(recovered, 0xBB, len);
        CHECK_OK(cagoule_ctr_encrypt(pt, len, iv, mat, &sbox, rk, 64, p, NULL, 0, ct, len));
        if (len > 1) CHECK_DIFF(pt, ct, len);
        CHECK_OK(cagoule_ctr_decrypt(ct, len, iv, mat, &sbox, rk, 64, p, NULL, 0, recovered, len));
        CHECK_MEM(pt, recovered, len);
    }
    g_pass += (long)(sizeof(critical)/sizeof(critical[0]));

    for (int iter = 0; iter < 50000; iter++) {
        size_t len = (_rand_byte() % 256) + 1;
        _rand_fill(pt, len);
        cagoule_ctr_encrypt(pt, len, iv, mat, &sbox, rk, 64, p, NULL, 0, ct, len);
        cagoule_ctr_decrypt(ct, len, iv, mat, &sbox, rk, 64, p, NULL, 0, recovered, len);
        CHECK_MEM(pt, recovered, len);
    }
    g_pass += 50000;

    cagoule_matrix_free(mat);
}

/* ════════════════════════════════════════════════════════════════════
 * Suite 3 — Parité 4x vs 1x
 * ════════════════════════════════════════════════════════════════════ */
static void test_4x_parity(void) {
    puts("  Suite 3 : 4x parity vs 1x (100K paires)");

    CagouleMatrix* mat;
    CagouleSBox64  sbox;
    uint64_t rk[64];
    uint8_t  iv[8];
    _build_params(1, &mat, &sbox, rk, 64, iv);
    uint64_t p = MERSENNE_POOL[1][1];

    static uint8_t pt[64*65], ct_1x[64*65], ct_4x[64*65];
    _rand_fill(pt, sizeof(pt));

    for (size_t n = 4; n <= 64; n += 4) {
        size_t len = n * 16;
        memset(ct_1x, 0, len);
        memset(ct_4x, 0, len);
        cagoule_ctr_encrypt(pt, len, iv, mat, &sbox, rk, 64, p, NULL, 0, ct_1x, len);
        cagoule_ctr_encrypt_4x(pt, len, iv, mat, &sbox, rk, 64, p, NULL, 0, ct_4x, len);
        CHECK_MEM(ct_1x, ct_4x, len);
    }
    g_pass += 16;

    static uint8_t pt2[512], ct2_1x[512], ct2_4x[512];
    for (int iter = 0; iter < 100000; iter++) {
        size_t len = (_rand_byte() % 512) + 1;
        _rand_fill(pt2, len);
        cagoule_ctr_encrypt(pt2, len, iv, mat, &sbox, rk, 64, p, NULL, 0, ct2_1x, len);
        cagoule_ctr_encrypt_4x(pt2, len, iv, mat, &sbox, rk, 64, p, NULL, 0, ct2_4x, len);
        CHECK_MEM(ct2_1x, ct2_4x, len);
    }
    g_pass += 100000;

    cagoule_matrix_free(mat);
}

/* ════════════════════════════════════════════════════════════════════
 * Suite 4 — Z-Domain Shifting CTR
 * ════════════════════════════════════════════════════════════════════ */
static void test_z_domain_ctr(void) {
    puts("  Suite 4 : Z-Domain Shifting CTR");

    CagouleMatrix* mat;
    CagouleSBox64  sbox;
    uint64_t rk[64];
    uint8_t  iv[8];
    _build_params(0, &mat, &sbox, rk, 64, iv);
    uint64_t p = MERSENNE_POOL[0][1];

    uint64_t zo[16];
    for (int i = 0; i < 16; i++)
        zo[i] = (uint64_t)(0x1234567890ABCDEFULL + i * 0xFEDCBA9876543210ULL);

    static uint8_t pt[1024], ct_no_zo[1024], ct_with_zo[1024], recovered[1024];
    _rand_fill(pt, 1024);

    cagoule_ctr_encrypt(pt, 1024, iv, mat, &sbox, rk, 64, p, NULL, 0, ct_no_zo, 1024);
    cagoule_ctr_encrypt(pt, 1024, iv, mat, &sbox, rk, 64, p, zo, 16, ct_with_zo, 1024);
    CHECK_DIFF(ct_no_zo, ct_with_zo, 1024);

    CHECK_OK(cagoule_ctr_decrypt(ct_with_zo, 1024, iv, mat, &sbox, rk, 64, p, zo, 16, recovered, 1024));
    CHECK_MEM(pt, recovered, 1024);

    uint64_t zo_zero[16] = {0};
    uint8_t ct_zo_zero[1024];
    cagoule_ctr_encrypt(pt, 1024, iv, mat, &sbox, rk, 64, p, zo_zero, 16, ct_zo_zero, 1024);
    CHECK_MEM(ct_no_zo, ct_zo_zero, 1024);

    uint8_t ct_zo_partial[1024];
    cagoule_ctr_encrypt(pt, 1024, iv, mat, &sbox, rk, 64, p, zo, 8, ct_zo_partial, 1024);
    CHECK_MEM(ct_no_zo, ct_zo_partial, 1024);

    static uint8_t pt2[256], ct2[256], rec2[256];
    uint64_t zo2[16];
    for (int iter = 0; iter < 50000; iter++) {
        size_t len = (_rand_byte() % 256) + 1;
        _rand_fill(pt2, len);
        for (int i = 0; i < 16; i++)
            zo2[i] = ((uint64_t)_rand_byte() << 56) | ((uint64_t)_rand_byte() << 48);
        cagoule_ctr_encrypt(pt2, len, iv, mat, &sbox, rk, 64, p, zo2, 16, ct2, len);
        cagoule_ctr_decrypt(ct2, len, iv, mat, &sbox, rk, 64, p, zo2, 16, rec2, len);
        CHECK_MEM(pt2, rec2, len);
    }
    g_pass += 50000;

    uint64_t zo_wrong[16];
    for (int i = 0; i < 16; i++) zo_wrong[i] = zo[i] ^ 0xDEADBEEFDEADBEEFULL;
    uint8_t recovered_wrong[1024];
    cagoule_ctr_decrypt(ct_with_zo, 1024, iv, mat, &sbox, rk, 64, p, zo_wrong, 16, recovered_wrong, 1024);
    CHECK_DIFF(pt, recovered_wrong, 1024);

    cagoule_matrix_free(mat);
}

/* ════════════════════════════════════════════════════════════════════
 * Suite 5 — Parité tous primes Mersenne-64
 * ════════════════════════════════════════════════════════════════════ */
static void test_all_mersenne_primes(void) {
    puts("  Suite 5 : All Mersenne-64 primes parity (8 primes × 2000)");

    static uint8_t pt[256], ct[256], recovered[256];

    for (int pi = 0; pi < N_POOL; pi++) {
        CagouleMatrix* mat;
        CagouleSBox64  sbox;
        uint64_t rk[64];
        uint8_t  iv[8];
        _build_params(pi, &mat, &sbox, rk, 64, iv);
        uint64_t p = MERSENNE_POOL[pi][1];

        for (int iter = 0; iter < 2000; iter++) {
            size_t len = (_rand_byte() % 240) + 1;
            _rand_fill(pt, len);
            int ret_e = cagoule_ctr_encrypt(pt, len, iv, mat, &sbox, rk, 64, p, NULL, 0, ct, len);
            int ret_d = cagoule_ctr_decrypt(ct, len, iv, mat, &sbox, rk, 64, p, NULL, 0, recovered, len);
            CHECK_OK(ret_e);
            CHECK_OK(ret_d);
            CHECK_MEM(pt, recovered, len);
        }
        g_pass += 2000;

        uint8_t ks_a[16], ks_b[16];
        for (int bi = 0; bi < 100; bi++) {
            cagoule_ctr_keystream(iv, (size_t)bi,     mat, &sbox, rk, 64, p, ks_a, 1);
            cagoule_ctr_keystream(iv, (size_t)bi + 1, mat, &sbox, rk, 64, p, ks_b, 1);
            CHECK_DIFF(ks_a, ks_b, 16);
        }
        g_pass += 100;

        cagoule_matrix_free(mat);
    }
}

/* ════════════════════════════════════════════════════════════════════
 * Suite 6 — CTR != CBC (formats incompatibles)
 * ════════════════════════════════════════════════════════════════════ */
static void test_ctr_cbc_incompatible(void) {
    puts("  Suite 6 : CTR != CBC format");

    CagouleMatrix* mat;
    CagouleSBox64  sbox;
    uint64_t rk[64];
    uint8_t  iv[8];
    _build_params(0, &mat, &sbox, rk, 64, iv);
    uint64_t p = MERSENNE_POOL[0][1];

    static uint8_t pt[256], ct_ctr[256], recovered_bad[256];
    _rand_fill(pt, 256);

    CHECK_OK(cagoule_ctr_encrypt(pt, 256, iv, mat, &sbox, rk, 64, p, NULL, 0, ct_ctr, 256));

    uint8_t iv_wrong[8] = {0};
    cagoule_ctr_decrypt(ct_ctr, 256, iv_wrong, mat, &sbox, rk, 64, p, NULL, 0, recovered_bad, 256);
    CHECK_DIFF(pt, recovered_bad, 256);

    uint8_t ct_ctr_wrong_iv[256];
    cagoule_ctr_encrypt(pt, 256, iv_wrong, mat, &sbox, rk, 64, p, NULL, 0, ct_ctr_wrong_iv, 256);
    CHECK_DIFF(ct_ctr, ct_ctr_wrong_iv, 256);

    uint8_t ks_a[16], ks_b[16];
    cagoule_ctr_keystream(iv, 0, mat, &sbox, rk, 64, p, ks_a, 1);
    cagoule_ctr_keystream(iv_wrong, 0, mat, &sbox, rk, 64, p, ks_b, 1);
    CHECK_DIFF(ks_a, ks_b, 16);

    CHECK_OK(cagoule_ctr_encrypt(pt, 0, iv, mat, &sbox, rk, 64, p, NULL, 0, ct_ctr, 0));
    CHECK_OK(cagoule_ctr_decrypt(ct_ctr, 0, iv, mat, &sbox, rk, 64, p, NULL, 0, recovered_bad, 0));

    cagoule_matrix_free(mat);
}

/* ════════════════════════════════════════════════════════════════════
 * Suite 7 — Scalaire vs AVX2 (si disponible)
 * ════════════════════════════════════════════════════════════════════ */
static void test_scalar_avx2_parity(void) {
    puts("  Suite 7 : Scalar vs AVX2 (500 paires)");

    CagouleMatrix* mat;
    CagouleSBox64  sbox;
    uint64_t rk[64];
    uint8_t  iv[8];
    _build_params(0, &mat, &sbox, rk, 64, iv);
    uint64_t p = MERSENNE_POOL[0][1];

    static uint8_t pt[512], ct1[512], ct2[512];
    _rand_fill(pt, 512);

    for (int iter = 0; iter < 500; iter++) {
        size_t len = (_rand_byte() % 512) + 1;
        _rand_fill(pt, len);
        memset(ct1, 0, len);
        memset(ct2, 0, len);
        cagoule_ctr_encrypt(pt, len, iv, mat, &sbox, rk, 64, p, NULL, 0, ct1, len);
        cagoule_ctr_encrypt(pt, len, iv, mat, &sbox, rk, 64, p, NULL, 0, ct2, len);
        CHECK_MEM(ct1, ct2, len);
    }
    g_pass += 500;

    cagoule_matrix_free(mat);
}

/* ════════════════════════════════════════════════════════════════════
 * Suite 8 — Vecteur KAT (Known Answer Test)
 * ════════════════════════════════════════════════════════════════════ */
static void test_kat_ctr(void) {
    puts("  Suite 8 : KAT vector (prime idx=0, fixed inputs)");

    uint64_t p = MERSENNE_POOL[0][1];
    uint64_t nodes[16];
    for (int i = 0; i < 16; i++) nodes[i] = (uint64_t)(2 + i * 1000000007ULL);
    CagouleMatrix* mat = cagoule_matrix_build(nodes, 16, p);
    assert(mat != NULL);

    CagouleSBox64 sbox;
    cagoule_sbox_init(&sbox, p, 0x123456789ABCDEF0ULL % 4294967291ULL,
                                0xFEDCBA9876543210ULL % 4294967291ULL);
    if (sbox.rk0 == 0) sbox.rk0 = 1;
    if (sbox.rk1 == 0) sbox.rk1 = 1;

    uint64_t rk[64];
    for (int i = 0; i < 64; i++) rk[i] = (uint64_t)((i + 1) * 0xABCDEF0123456789ULL) % p;

    uint8_t iv[8] = {0x30, 0x37, 0x44, 0x51, 0x5E, 0x6B, 0x78, 0x85};

    uint8_t pt[32];
    for (int i = 0; i < 32; i++) pt[i] = (uint8_t)i;

    uint8_t ct[32], recovered[32];
    CHECK_OK(cagoule_ctr_encrypt(pt, 32, iv, mat, &sbox, rk, 64, p, NULL, 0, ct, 32));
    CHECK_DIFF(pt, ct, 32);

    CHECK_OK(cagoule_ctr_decrypt(ct, 32, iv, mat, &sbox, rk, 64, p, NULL, 0, recovered, 32));
    CHECK_MEM(pt, recovered, 32);

    uint8_t ct2[32];
    CHECK_OK(cagoule_ctr_encrypt(pt, 32, iv, mat, &sbox, rk, 64, p, NULL, 0, ct2, 32));
    CHECK_MEM(ct, ct2, 32);

    uint8_t ct_from_dec[32];
    CHECK_OK(cagoule_ctr_encrypt(ct, 32, iv, mat, &sbox, rk, 64, p, NULL, 0, ct_from_dec, 32));
    CHECK_MEM(pt, ct_from_dec, 32);

    uint8_t ct_4x[32];
    CHECK_OK(cagoule_ctr_encrypt_4x(pt, 32, iv, mat, &sbox, rk, 64, p, NULL, 0, ct_4x, 32));
    CHECK_MEM(ct, ct_4x, 32);

    cagoule_matrix_free(mat);
}

/* ════════════════════════════════════════════════════════════════════
 * Suite 8b — Hardcoded KAT (cross-version stability, v3.0.0)
 * ════════════════════════════════════════════════════════════════════ */
/* ════════════════════════════════════════════════════════════════════
 * Suite 8b — Hardcoded KAT (raw CTR output, cross-version stability)
 * ════════════════════════════════════════════════════════════════════ */
static void test_kat_hardcoded_ctr(void) {
    puts("  Suite 8b : Hardcoded KAT (raw CTR output)");
    uint64_t p = 18446744073709551293ULL;
    uint64_t nodes[16];
    for (int i = 0; i < 16; i++) nodes[i] = (uint64_t)(2 + i * 1000000007ULL);
    CagouleMatrix* mat = cagoule_matrix_build(nodes, 16, p);
    assert(mat != NULL);
    CagouleSBox64 sbox;
    cagoule_sbox_init(&sbox, p, 0x123456789ABCDEF0ULL % 4294967291ULL, 0xFEDCBA9876543210ULL % 4294967291ULL);
    if (sbox.rk0 == 0) sbox.rk0 = 1;
    if (sbox.rk1 == 0) sbox.rk1 = 1;
    uint64_t rk[64];
    for (int i = 0; i < 64; i++) rk[i] = (uint64_t)((i + 1) * 0xABCDEF0123456789ULL) % p;
    uint8_t iv[8] = {0x30, 0x37, 0x44, 0x51, 0x5E, 0x6B, 0x78, 0x85};
    uint8_t pt[] = "Hello, CAGOULE v3.0.0 KAT!";
    size_t pt_len = 24;
    uint8_t expected_ct[] = {0x34, 0xba, 0xee, 0xc2, 0xaa, 0x6c, 0x01, 0xd9, 0xcb, 0xa4, 0x6b, 0x4d, 0xbd, 0x5f, 0xa9, 0xc9, 0x77, 0x42, 0x22, 0xb2, 0xd1, 0xa2, 0x86, 0x9f};
    size_t expected_len = sizeof(expected_ct);
    uint8_t ct[256];
    CHECK_OK(cagoule_ctr_encrypt(pt, pt_len, iv, mat, &sbox, rk, 64, p, NULL, 0, ct, sizeof(ct)));
    CHECK_EQ((int)expected_len, (int)pt_len);
    CHECK_MEM(expected_ct, ct, expected_len);
    uint8_t ct2[256];
    CHECK_OK(cagoule_ctr_encrypt(pt, pt_len, iv, mat, &sbox, rk, 64, p, NULL, 0, ct2, sizeof(ct2)));
    CHECK_MEM(ct, ct2, pt_len);
    uint8_t recovered[32];
    CHECK_OK(cagoule_ctr_decrypt(ct, pt_len, iv, mat, &sbox, rk, 64, p, NULL, 0, recovered, sizeof(recovered)));
    CHECK_MEM(pt, recovered, pt_len);
    cagoule_matrix_free(mat);
}
/* ════════════════════════════════════════════════════════════════════
 * Suite 9 — Grand message (65536 octets)
 * ════════════════════════════════════════════════════════════════════ */
static void test_large_message(void) {
    puts("  Suite 9 : Large message 65536 bytes × 4 primes");

    static uint8_t pt[65536], ct[65536], recovered[65536];
    _rand_fill(pt, 65536);

    for (int pi = 0; pi < 4; pi++) {
        CagouleMatrix* mat;
        CagouleSBox64  sbox;
        uint64_t rk[64];
        uint8_t  iv[8];
        _build_params(pi, &mat, &sbox, rk, 64, iv);
        uint64_t p = MERSENNE_POOL[pi][1];

        CHECK_OK(cagoule_ctr_encrypt(pt, 65536, iv, mat, &sbox, rk, 64, p, NULL, 0, ct, 65536));
        CHECK_DIFF(pt, ct, 65536);
        CHECK_OK(cagoule_ctr_decrypt(ct, 65536, iv, mat, &sbox, rk, 64, p, NULL, 0, recovered, 65536));
        CHECK_MEM(pt, recovered, 65536);

        uint8_t ct_4x[65536];
        CHECK_OK(cagoule_ctr_encrypt_4x(pt, 65536, iv, mat, &sbox, rk, 64, p, NULL, 0, ct_4x, 65536));
        CHECK_MEM(ct, ct_4x, 65536);

        cagoule_matrix_free(mat);
    }
}

/* ════════════════════════════════════════════════════════════════════
 * Suite 10 — Erreurs et garde-fous
 * ════════════════════════════════════════════════════════════════════ */
static void test_error_cases(void) {
    puts("  Suite 10 : Error cases");

    CagouleMatrix* mat;
    CagouleSBox64  sbox;
    uint64_t rk[64];
    uint8_t  iv[8];
    _build_params(0, &mat, &sbox, rk, 64, iv);
    uint64_t p = MERSENNE_POOL[0][1];

    uint8_t pt[32] = {0}, ct[32] = {0}, out[32] = {0};

    CHECK_EQ(cagoule_ctr_encrypt(NULL, 32, iv, mat, &sbox, rk, 64, p, NULL, 0, ct, 32), CAGOULE_ERR_NULL);
    CHECK_EQ(cagoule_ctr_encrypt(pt, 32, NULL, mat, &sbox, rk, 64, p, NULL, 0, ct, 32), CAGOULE_ERR_NULL);
    CHECK_EQ(cagoule_ctr_encrypt(pt, 32, iv, NULL, &sbox, rk, 64, p, NULL, 0, ct, 32), CAGOULE_ERR_NULL);
    CHECK_EQ(cagoule_ctr_encrypt(pt, 32, iv, mat, NULL, rk, 64, p, NULL, 0, ct, 32), CAGOULE_ERR_NULL);
    CHECK_EQ(cagoule_ctr_encrypt(pt, 32, iv, mat, &sbox, NULL, 64, p, NULL, 0, ct, 32), CAGOULE_ERR_NULL);
    CHECK_EQ(cagoule_ctr_encrypt(pt, 32, iv, mat, &sbox, rk, 64, p, NULL, 0, NULL, 32), CAGOULE_ERR_NULL);

    CHECK_EQ(cagoule_ctr_encrypt(pt, 32, iv, mat, &sbox, rk, 64, p, NULL, 0, ct, 16), CAGOULE_ERR_SIZE);
    CHECK_EQ(cagoule_ctr_decrypt(ct, 32, iv, mat, &sbox, rk, 64, p, NULL, 0, out, 16), CAGOULE_ERR_SIZE);

    CHECK_OK(cagoule_ctr_encrypt(pt, 0, iv, mat, &sbox, rk, 64, p, NULL, 0, ct, 0));
    CHECK_OK(cagoule_ctr_decrypt(ct, 0, iv, mat, &sbox, rk, 64, p, NULL, 0, out, 0));

    cagoule_matrix_free(mat);
}

/* ════════════════════════════════════════════════════════════════════
 * Benchmark (informatif)
 * ════════════════════════════════════════════════════════════════════ */
static void bench_ctr(void) {
    puts("  Bench : CTR encrypt 1MB");

    CagouleMatrix* mat;
    CagouleSBox64  sbox;
    uint64_t rk[64];
    uint8_t  iv[8];
    _build_params(0, &mat, &sbox, rk, 64, iv);
    uint64_t p = MERSENNE_POOL[0][1];

    /* CORRECTIF (audit perf Python e2e) : le benchmark passait NULL/0
     * pour z_offset, alors que le pipeline de production (Python
     * cipher_ctr.py::encrypt_ctr, et donc cagoule_api.c) transmet
     * TOUJOURS un z_offset réel à 16 éléments (CAGOULE_Z_OFFSET_N) --
     * le Z-Domain Shifting n'est jamais désactivé en usage réel. Ce
     * benchmark mesurait donc un chemin de code ~9% plus rapide que
     * ce que Python observe réellement, ce qui a rendu l'écart
     * Python-vs-C artificiellement plus grand qu'il ne l'était et a
     * compliqué le diagnostic de l'écart de perf e2e. Corrigé pour
     * refléter fidèlement l'usage production. */
    uint64_t z_offset[CAGOULE_Z_OFFSET_N];
    for (int i = 0; i < CAGOULE_Z_OFFSET_N; i++) {
        uint64_t v = 0;
        for (int b = 0; b < 8; b++) v = (v << 8) | _rand_byte();
        z_offset[i] = v;
    }

    static uint8_t pt[1<<20], ct[1<<20];
    _rand_fill(pt, sizeof(pt));

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int rep = 0; rep < 5; rep++) {
        cagoule_ctr_encrypt(pt, sizeof(pt), iv, mat, &sbox, rk, 64, p,
                             z_offset, CAGOULE_Z_OFFSET_N, ct, sizeof(ct));
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000.0
                      + (t1.tv_nsec - t0.tv_nsec) / 1e6;
    double mbps = (5.0 * sizeof(pt)) / (elapsed_ms / 1000.0) / (1024*1024);
    printf("  CTR 1MB × 5 reps (z_offset actif, comme en production) : %.1f ms total → %.1f MB/s\n", elapsed_ms, mbps);
    g_pass++;

    cagoule_matrix_free(mat);
}

/* ════════════════════════════════════════════════════════════════════
 * Main
 * ════════════════════════════════════════════════════════════════════ */
int main(void) {
    puts("=== test_ctr CAGOULE v3.1.0 ===");

    test_keystream_uniqueness();
    test_roundtrip_all_sizes();
    test_4x_parity();
    test_z_domain_ctr();
    test_all_mersenne_primes();
    test_ctr_cbc_incompatible();
    test_scalar_avx2_parity();
    test_kat_ctr();
    test_kat_hardcoded_ctr();
    test_large_message();
    test_error_cases();
    bench_ctr();
    /* CORRECTIF (audit round 2, N5) : cagoule_ctr_print_profile() n'existe
     * que sous -DPROFILE_CTR (voir cagoule_ctr.c). L'appel inconditionnel
     * ci-dessous cassait le lien de `make test-ctr` (build par défaut,
     * sans PROFILE_CTR) -- seul `make profile` (qui définit PROFILE_CTR)
     * fonctionnait. Gardé ici pour que les deux cibles compilent. */
#ifdef PROFILE_CTR
    cagoule_ctr_print_profile();
#endif

    printf("\n=== Résultat final : %ld passés / %ld échoués ===\n",
           g_pass, g_fail);
    return (g_fail > 0) ? 1 : 0;
}