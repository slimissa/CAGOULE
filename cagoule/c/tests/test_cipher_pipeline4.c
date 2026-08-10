/**
 * test_cipher_pipeline4.c — Tests parité & benchmarks pipeline4 v3.1.0
 *
 * Vérifie :
 *   1. Déterminisme : deux appels identiques → même ciphertext
 *   2. Round-trip : encrypt→decrypt → plaintext original
 *   3. Edge cases : n_blocks = 1..9, 15, 16, 17, 32, 33
 *   4. Guards null-pointer et out_size
 *   5. Parité 10 000 messages aléatoires (tailles 8..64 blocs)
 *   6. Benchmark
 *   6b. Z-Domain Shifting + Pipeline4 (v2.5.2) throughput encrypt/decrypt
 *   7. Regression: decrypt residual n_blocks % 4 != 0 (v2.4.0 BUG 1 fix)
 *
 * Total assertions : ~95
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "cagoule_math.h"
#include "cagoule_matrix.h"
#include "cagoule_sbox.h"
#include "cagoule_cipher.h"

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; printf("  FAIL [line %d] %s\n", __LINE__, (msg)); } \
} while(0)

static uint64_t now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ── Fixtures ────────────────────────────────────────────────────────── */
static const uint64_t P    = 10441487724840939323ULL;
static const uint64_t RK0  = 2147483693ULL;
static const uint64_t RK1  = 3221225473ULL;
#define NUM_KEYS 64
static uint64_t       g_rk[NUM_KEYS];
static CagouleMatrix* g_mat  = NULL;
static CagouleSBox64  g_sbox;

static void gen_nodes(uint64_t* nodes, int n) {
    for (int i = 0; i < n; i++) {
        nodes[i] = (uint64_t)((i + 1) * 7 + 3) % P;
        for (int j = 0; j < i; j++)
            while (nodes[i] == nodes[j]) nodes[i] = (nodes[i] + 1) % P;
    }
}

static void setup(void) {
    uint64_t nodes[CAGOULE_N];
    gen_nodes(nodes, CAGOULE_N);
    g_mat = cagoule_matrix_build(nodes, CAGOULE_N, P);
    cagoule_sbox_init(&g_sbox, P, RK0, RK1);
    for (int i = 0; i < NUM_KEYS; i++)
        g_rk[i] = (uint64_t)(i * 1234567891011ULL % P) + 1;
}

/* ── Helpers ─────────────────────────────────────────────────────────── */
static size_t pb(void) { return (P > 0xFFFFFFFF) ? 8 : 4; }

static void fill_plain(uint8_t* buf, size_t sz, int seed) {
    for (size_t i = 0; i < sz; i++)
        buf[i] = (uint8_t)((i * 0xAB + seed) & 0xFF);
}

/* ── Test 1 : Edge cases n_blocks ─────────────────────────────────────── */
static void test_edge_cases(void) {
    printf("\n[1] Edge cases n_blocks...\n");
    int edges[] = {1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 32, 33};
    int ne = (int)(sizeof(edges)/sizeof(edges[0]));

    for (int ei = 0; ei < ne; ei++) {
        size_t nb       = (size_t)edges[ei];
        size_t plain_sz = nb * CAGOULE_N;
        size_t ct_sz    = nb * CAGOULE_N * pb();

        uint8_t* plain = malloc(plain_sz);
        uint8_t* ct1   = malloc(ct_sz);
        uint8_t* ct2   = malloc(ct_sz);
        uint8_t* pt    = malloc(plain_sz);

        fill_plain(plain, plain_sz, ei);

        int r1 = cagoule_cbc_encrypt(plain, nb, ct1, ct_sz,
                                      g_mat, &g_sbox, g_rk, NUM_KEYS, P, NULL, 0);
        int r2 = cagoule_cbc_encrypt(plain, nb, ct2, ct_sz,
                                      g_mat, &g_sbox, g_rk, NUM_KEYS, P, NULL, 0);
        char msg[80];
        snprintf(msg, sizeof(msg), "encrypt OK n=%zu", nb);
        CHECK(r1 == CAGOULE_OK && r2 == CAGOULE_OK, msg);
        snprintf(msg, sizeof(msg), "deterministe n=%zu", nb);
        CHECK(memcmp(ct1, ct2, ct_sz) == 0, msg);

        int r3 = cagoule_cbc_decrypt(ct1, nb, pt, plain_sz,
                                      g_mat, &g_sbox, g_rk, NUM_KEYS, P, NULL, 0);
        snprintf(msg, sizeof(msg), "decrypt OK n=%zu", nb);
        CHECK(r3 == CAGOULE_OK, msg);
        snprintf(msg, sizeof(msg), "round-trip n=%zu", nb);
        CHECK(memcmp(plain, pt, plain_sz) == 0, msg);

        free(plain); free(ct1); free(ct2); free(pt);
    }
    printf("  → %d edge cases\n", ne);
}

/* ── Test 2 : Guards ─────────────────────────────────────────────────── */
static void test_guards(void) {
    printf("\n[2] Guards null/size...\n");
    size_t csz = 16 * CAGOULE_N * pb();
    uint8_t plain[16*CAGOULE_N] = {0};
    uint8_t out[16*CAGOULE_N*8];

    CHECK(cagoule_cbc_encrypt(NULL, 1, out, csz, g_mat, &g_sbox, g_rk, NUM_KEYS, P, NULL, 0)
          == CAGOULE_ERR_NULL, "encrypt NULL padded");
    CHECK(cagoule_cbc_encrypt(plain, 1, NULL, 0, g_mat, &g_sbox, g_rk, NUM_KEYS, P, NULL, 0)
          == CAGOULE_ERR_NULL, "encrypt NULL out");
    CHECK(cagoule_cbc_encrypt(plain, 4, out, 0, g_mat, &g_sbox, g_rk, NUM_KEYS, P, NULL, 0)
          == CAGOULE_ERR_SIZE, "encrypt out_size=0");
    CHECK(cagoule_cbc_decrypt(NULL, 1, plain, sizeof(plain), g_mat, &g_sbox, g_rk, NUM_KEYS, P, NULL, 0)
          == CAGOULE_ERR_NULL, "decrypt NULL cipher");
    CHECK(cagoule_cbc_decrypt(out, 4, NULL, 0, g_mat, &g_sbox, g_rk, NUM_KEYS, P, NULL, 0)
          == CAGOULE_ERR_NULL, "decrypt NULL out");
    printf("  → guards OK\n");
}

/* ── Test 3 : Parité 10 000 messages aléatoires ─────────────────────── */
static void test_parity_random(void) {
    printf("\n[3] Parité 10 000 messages aleatoires (8..64 blocs)...\n");
    srand(0xCAFEBABE);
    int n_ok = 0;

    for (int iter = 0; iter < 10000; iter++) {
        size_t nb      = 8 + (size_t)(rand() % 57);
        size_t plain_sz = nb * CAGOULE_N;
        size_t ct_sz    = nb * CAGOULE_N * pb();

        uint8_t* plain = malloc(plain_sz);
        uint8_t* ct1   = malloc(ct_sz);
        uint8_t* ct2   = malloc(ct_sz);
        uint8_t* pt    = malloc(plain_sz);

        for (size_t i = 0; i < plain_sz; i++)
            plain[i] = (uint8_t)(rand() & 0xFF);

        int r1 = cagoule_cbc_encrypt(plain, nb, ct1, ct_sz, g_mat, &g_sbox, g_rk, NUM_KEYS, P, NULL, 0);
        int r2 = cagoule_cbc_encrypt(plain, nb, ct2, ct_sz, g_mat, &g_sbox, g_rk, NUM_KEYS, P, NULL, 0);
        int r3 = cagoule_cbc_decrypt(ct1, nb, pt, plain_sz, g_mat, &g_sbox, g_rk, NUM_KEYS, P, NULL, 0);

        if (r1 == CAGOULE_OK && r2 == CAGOULE_OK && r3 == CAGOULE_OK &&
            memcmp(ct1, ct2, ct_sz) == 0 &&
            memcmp(plain, pt, plain_sz) == 0)
            n_ok++;

        free(plain); free(ct1); free(ct2); free(pt);
    }

    CHECK(n_ok == 10000, "parity + round-trip 10 000 messages");
    printf("  → %d/10 000 OK\n", n_ok);
}

/* ── Test 4 : Benchmark ─────────────────────────────────────────────── */
static void test_benchmark(void) {
    printf("\n[4] Benchmark throughput...\n");

    /* 4096 blocs × 16 bytes = 64 KB × 16 runs = 1 MB */
    size_t nb = 4096, n_runs = 16;
    size_t plain_sz = nb * CAGOULE_N;
    size_t ct_sz    = nb * CAGOULE_N * pb();

    uint8_t* plain = malloc(plain_sz);
    uint8_t* ct    = malloc(ct_sz);
    uint8_t* pt    = malloc(plain_sz);

    fill_plain(plain, plain_sz, 0);

    /* Warmup */
    cagoule_cbc_encrypt(plain, nb, ct, ct_sz, g_mat, &g_sbox, g_rk, NUM_KEYS, P, NULL, 0);

    uint64_t t0 = now_ms();
    for (size_t r = 0; r < n_runs; r++)
        cagoule_cbc_encrypt(plain, nb, ct, ct_sz, g_mat, &g_sbox, g_rk, NUM_KEYS, P, NULL, 0);
    uint64_t t_enc = now_ms() - t0;

    uint64_t t1 = now_ms();
    for (size_t r = 0; r < n_runs; r++)
        cagoule_cbc_decrypt(ct, nb, pt, plain_sz, g_mat, &g_sbox, g_rk, NUM_KEYS, P, NULL, 0);
    uint64_t t_dec = now_ms() - t1;

    CHECK(memcmp(plain, pt, plain_sz) == 0, "benchmark round-trip");

    double mb = (double)(plain_sz * n_runs) / (1024.0 * 1024.0);
    double enc_mbs = (t_enc > 0) ? mb / (t_enc / 1000.0) : 999.0;
    double dec_mbs = (t_dec > 0) ? mb / (t_dec / 1000.0) : 999.0;
    printf("  encrypt : %.1f MB/s | decrypt : %.1f MB/s | %.0f MB total\n",
           enc_mbs, dec_mbs, mb);

    #ifdef DEBUG
        int under_debug = 1;
    #else
        int under_debug = 0;
    #endif
    if (!under_debug) {
        CHECK(enc_mbs > 3.0, "encrypt > 3 MB/s");
        CHECK(dec_mbs > 3.0, "decrypt > 3 MB/s");
    } else {
        printf("  (seuils de performance ignorés en mode debug)\n");
    }

    free(plain); free(ct); free(pt);
}


/* ── Test 4b : Z-Domain Shifting + Pipeline4 (v2.5.2) ───────────────── */
static void test_z_domain_pipeline4(void) {
    printf("\n[4b] Z-Domain Shifting + Pipeline4 parity...\n");

    uint64_t zo[16];
    for (int i = 0; i < 16; i++)
        zo[i] = (uint64_t)((i * 0x9E3779B97F4A7C15ULL) % P);

    /* Test with pipeline4 threshold (8 blocks) + residual (9, 16, 17 blocks) */
    int counts[] = {8, 9, 16, 17};
    for (int ci = 0; ci < 4; ci++) {
        size_t nb = (size_t)counts[ci];
        size_t plain_sz = nb * CAGOULE_N;
        size_t ct_sz = nb * CAGOULE_N * pb();

        uint8_t* plain = malloc(plain_sz);
        uint8_t* ct_zo = malloc(ct_sz);
        uint8_t* ct_no = malloc(ct_sz);
        uint8_t* pt    = malloc(plain_sz);

        fill_plain(plain, plain_sz, ci + 200);

        /* Encrypt WITH Z-shifting */
        int r = cagoule_cbc_encrypt(plain, nb, ct_zo, ct_sz,
                                     g_mat, &g_sbox, g_rk, NUM_KEYS, P, zo, 16);
        char msg[80];
        snprintf(msg, sizeof(msg), "Z-shift encrypt pipeline4 n=%zu", nb);
        CHECK(r == CAGOULE_OK, msg);

        /* Encrypt WITHOUT Z-shifting */
        r = cagoule_cbc_encrypt(plain, nb, ct_no, ct_sz,
                                 g_mat, &g_sbox, g_rk, NUM_KEYS, P, NULL, 0);
        snprintf(msg, sizeof(msg), "non-Z encrypt pipeline4 n=%zu", nb);
        CHECK(r == CAGOULE_OK, msg);

        /* Ciphertexts MUST differ */
        int differ = memcmp(ct_zo, ct_no, ct_sz) != 0;
        snprintf(msg, sizeof(msg), "Z-shift differs pipeline4 n=%zu", nb);
        CHECK(differ, msg);

        /* Roundtrip WITH Z-shifting */
        r = cagoule_cbc_decrypt(ct_zo, nb, pt, plain_sz,
                                 g_mat, &g_sbox, g_rk, NUM_KEYS, P, zo, 16);
        snprintf(msg, sizeof(msg), "Z-shift decrypt pipeline4 n=%zu", nb);
        CHECK(r == CAGOULE_OK, msg);

        snprintf(msg, sizeof(msg), "Z-shift roundtrip pipeline4 n=%zu", nb);
        CHECK(memcmp(plain, pt, plain_sz) == 0, msg);

        free(plain); free(ct_zo); free(ct_no); free(pt);
    }

    /* Test with 10K random messages (reduced from full suite) */
    srand(0xCAFEBABE);
    int n_ok = 0;
    for (int iter = 0; iter < 1000; iter++) {
        size_t nb = 8 + (size_t)(rand() % 57);
        size_t plain_sz = nb * CAGOULE_N;
        size_t ct_sz = nb * CAGOULE_N * pb();

        uint8_t* plain = malloc(plain_sz);
        uint8_t* ct = malloc(ct_sz);
        uint8_t* pt = malloc(plain_sz);

        for (size_t i = 0; i < plain_sz; i++)
            plain[i] = (uint8_t)(rand() & 0xFF);

        int r1 = cagoule_cbc_encrypt(plain, nb, ct, ct_sz,
                                      g_mat, &g_sbox, g_rk, NUM_KEYS, P, zo, 16);
        int r2 = cagoule_cbc_decrypt(ct, nb, pt, plain_sz,
                                      g_mat, &g_sbox, g_rk, NUM_KEYS, P, zo, 16);

        if (r1 == CAGOULE_OK && r2 == CAGOULE_OK &&
            memcmp(plain, pt, plain_sz) == 0)
            n_ok++;

        free(plain); free(ct); free(pt);
    }
    CHECK(n_ok == 1000, "Z-shift pipeline4 1000 random roundtrips");
    printf("  → %d/1000 OK\n", n_ok);
}

/* ── Test 5 : Regression — decrypt residual n_blocks % 4 != 0 ────────── */
static void test_decrypt_residual_regression(void) {
    printf("\n[5] Regression: decrypt residual n_blocks %% 4 != 0...\n");

    /* Test all residual sizes: 1, 2, 3 blocks past the pipeline threshold.
     * These exercise the saved_r[] array logic in the residual loop.
     * Using pipeline threshold + residual to force the pipeline path. */
    int residuals[] = {8+1, 8+2, 8+3, 12+1, 12+2, 12+3, 16+1, 16+2, 16+3};
    int nr = (int)(sizeof(residuals)/sizeof(residuals[0]));

    for (int ri = 0; ri < nr; ri++) {
        size_t nb       = (size_t)residuals[ri];
        size_t plain_sz = nb * CAGOULE_N;
        size_t ct_sz    = nb * CAGOULE_N * pb();

        uint8_t* plain = malloc(plain_sz);
        uint8_t* ct    = malloc(ct_sz);
        uint8_t* pt    = malloc(plain_sz);

        /* Use a deterministic but varied pattern per block count */
        fill_plain(plain, plain_sz, ri + 0x100);

        int r_enc = cagoule_cbc_encrypt(plain, nb, ct, ct_sz,
                                         g_mat, &g_sbox, g_rk, NUM_KEYS, P, NULL, 0);
        char msg[80];
        snprintf(msg, sizeof(msg), "encrypt n=%zu", nb);
        CHECK(r_enc == CAGOULE_OK, msg);

        int r_dec = cagoule_cbc_decrypt(ct, nb, pt, plain_sz,
                                         g_mat, &g_sbox, g_rk, NUM_KEYS, P, NULL, 0);
        snprintf(msg, sizeof(msg), "decrypt n=%zu", nb);
        CHECK(r_dec == CAGOULE_OK, msg);

        snprintf(msg, sizeof(msg), "round-trip n=%zu (residual=%zu)", nb, nb % 4);
        CHECK(memcmp(plain, pt, plain_sz) == 0, msg);

        free(plain); free(ct); free(pt);
    }
    printf("  → %d residual cases OK\n", nr);
}

/* ── main ─────────────────────────────────────────────────────────── */
int main(void) {
    printf("═══════════════════════════════════════════════════════\n");
    printf("  test_cipher_pipeline4 — CAGOULE v3.1.0\n");
    printf("═══════════════════════════════════════════════════════\n");

    setup();

    test_edge_cases();              /* Test 1: blocks 1..33 */
    test_guards();                  /* Test 2: null/size */
    test_decrypt_residual_regression(); /* Test 3: BUG 1 regression */
    test_parity_random();           /* Test 4: 10 000 random */
    test_benchmark();               /* Test 5: performance */
    test_z_domain_pipeline4();      /* Test 5b: Z-Domain + pipeline4 */

    cagoule_matrix_free(g_mat);

    printf("\n═══════════════════════════════════════════════════════\n");
    int total = g_pass + g_fail;
    printf("  %d/%d assertions", g_pass, total);
    if (g_fail > 0) printf("  — %d ÉCHECS", g_fail);
    printf("\n═══════════════════════════════════════════════════════\n");

    return (g_fail == 0) ? 0 : 1;
}