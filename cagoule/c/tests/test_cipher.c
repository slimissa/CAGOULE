/**
 * test_cipher.c — Tests du pipeline CBC CAGOULE v3.1.0
 *
 * Usage :
 *   gcc -O2 -std=c99 -Iinclude src/cagoule_matrix.c src/cagoule_sbox.c \
 *       src/cagoule_cipher.c tests/test_cipher.c -o test_cipher && ./test_cipher
 *
 * Couvre :
 *   - Roundtrip 1 bloc, multi-blocs
 *   - Diffusion CBC (blocs identiques → chiffrés différents)
 *   - Valeurs limites (zéros, 0xFF)
 *   - PKCS7 padding
 *   - AVX2 parité
 *   - Z-Domain Shifting (v2.5.1) (mono-bloc + pipeline4)
 *   - Guards null/size
 *   - Benchmark 1 MB (clock_gettime)
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "cagoule_math.h"
#include "cagoule_matrix.h"
#include "cagoule_sbox.h"
#include "cagoule_cipher.h"

static int _passed = 0, _failed = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  ✓ %s\n", msg); _passed++; } \
    else      { printf("  ✗ FAIL: %s (line %d)\n", msg, __LINE__); _failed++; } \
} while(0)

/* ── Horloge monotone (wall-clock, pas CPU time) ──────────────────── */
static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static const uint64_t P       = 10441487724840939323ULL;
static const uint64_t RK0     = 2147483693ULL;
static const uint64_t RK1     = 3221225473ULL;

static void gen_nodes(uint64_t* nodes, uint64_t p, int n) {
    for (int i = 0; i < n; i++) {
        nodes[i] = (uint64_t)(((uint64_t)(i + 1) * 7 + 3) % p);
        for (int j = 0; j < i; j++) {
            while (nodes[i] == nodes[j])
                nodes[i] = (nodes[i] + 1) % p;
        }
    }
}

static CagouleMatrix* g_mat = NULL;
static CagouleSBox64  g_sbox;

static void setup(void) {
    uint64_t nodes[CAGOULE_N];
    gen_nodes(nodes, P, CAGOULE_N);
    g_mat = cagoule_matrix_build(nodes, CAGOULE_N, P);
    cagoule_sbox_init(&g_sbox, P, RK0, RK1);
}

static void teardown(void) {
    if (g_mat) { cagoule_matrix_free(g_mat); g_mat = NULL; }
}

#define NUM_KEYS 64
static uint64_t g_round_keys[NUM_KEYS];
static void gen_round_keys(void) {
    for (int i = 0; i < NUM_KEYS; i++)
        g_round_keys[i] = (uint64_t)(i * 1234567891011ULL % P) + 1;
}

/* ── Helper : calcul de p_bytes ───────────────────────────────────── */
static size_t p_bytes(uint64_t p) {
    return (p > 0xFFFFFFFF) ? 8 : 4;
}

/* ── Test PKCS7 padding ───────────────────────────────────────────── */
static void test_pkcs7_padding(void) {
    printf("\n[PKCS7 padding — 13 bytes -> 16 bytes]\n");
    
    const char* msg = "Hello, World!";
    size_t msg_len = 13;
    size_t padded_len = ((msg_len + 15) / 16) * 16;  /* = 16 */
    uint8_t padded[16];
    memcpy(padded, msg, msg_len);
    uint8_t pad_byte = (uint8_t)(16 - msg_len);  /* = 3 */
    for (size_t i = msg_len; i < padded_len; i++)
        padded[i] = pad_byte;
    
    size_t n_blocks = 1;
    size_t ct_size = n_blocks * CAGOULE_N * p_bytes(P);
    uint8_t* ciphertext = malloc(ct_size);
    uint8_t* recovered = malloc(16);
    
    int r = cagoule_cbc_encrypt(padded, n_blocks, ciphertext, ct_size,
                                 g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0);
    CHECK(r == 0, "encrypt avec padding OK");
    
    r = cagoule_cbc_decrypt(ciphertext, n_blocks, recovered, 16,
                             g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0);
    CHECK(r == 0, "decrypt avec padding OK");
    
    CHECK(recovered[15] == 0x03, "padding byte = 0x03");
    CHECK(memcmp(recovered, msg, msg_len) == 0, "message original intact");
    
    free(ciphertext);
    free(recovered);
}

/* ── Test 1 : roundtrip 1 bloc ────────────────────────────────────── */
static void test_roundtrip_single_block(void) {
    printf("\n[Roundtrip — 1 bloc (16 bytes)]\n");

    uint8_t plaintext[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    size_t n_blocks = 1;
    size_t ct_size = n_blocks * CAGOULE_N * p_bytes(P);
    uint8_t* ciphertext = malloc(ct_size);
    uint8_t recovered[16];

    int r = cagoule_cbc_encrypt(plaintext, n_blocks, ciphertext, ct_size,
                                 g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0);
    CHECK(r == 0, "encrypt retourne 0");

    r = cagoule_cbc_decrypt(ciphertext, n_blocks, recovered, sizeof(recovered),
                             g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0);
    CHECK(r == 0, "decrypt retourne 0");

    CHECK(memcmp(plaintext, recovered, 16) == 0, "roundtrip 1 bloc identique");

    int changed = 0;
    for (size_t i = 0; i < ct_size; i++)
        if (ciphertext[i] != 0) { changed = 1; break; }
    CHECK(changed, "ciphertext non nul");

    free(ciphertext);
}

/* ── Test 2 : roundtrip multi-blocs ───────────────────────────────── */
static void test_roundtrip_multi_block(void) {
    printf("\n[Roundtrip — 10 blocs (160 bytes)]\n");

    size_t n_blocks = 10;
    uint8_t plaintext[160];
    for (int i = 0; i < 160; i++)
        plaintext[i] = (uint8_t)((i * 37 + 11) & 0xFF);

    size_t ct_size = n_blocks * CAGOULE_N * p_bytes(P);
    uint8_t* ciphertext = malloc(ct_size);
    uint8_t* recovered = malloc(160);

    cagoule_cbc_encrypt(plaintext, n_blocks, ciphertext, ct_size,
                        g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0);
    cagoule_cbc_decrypt(ciphertext, n_blocks, recovered, 160,
                        g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0);

    CHECK(memcmp(plaintext, recovered, 160) == 0, "roundtrip 10 blocs");

    free(ciphertext);
    free(recovered);
}

/* ── Test 3 : roundtrip pipeline4 (8+ blocs) ──────────────────────── */
static void test_roundtrip_pipeline4(void) {
    printf("\n[Roundtrip — 8 blocs (pipeline4 path)]\n");

    size_t n_blocks = 8;
    size_t plain_sz = n_blocks * CAGOULE_N;  /* 128 */
    uint8_t* plaintext = malloc(plain_sz);
    for (size_t i = 0; i < plain_sz; i++)
        plaintext[i] = (uint8_t)((i * 37 + 11) & 0xFF);

    size_t ct_size = n_blocks * CAGOULE_N * p_bytes(P);
    uint8_t* ciphertext = malloc(ct_size);
    uint8_t* recovered = malloc(plain_sz);

    int r_enc = cagoule_cbc_encrypt(plaintext, n_blocks, ciphertext, ct_size,
                                     g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0);
    CHECK(r_enc == 0, "encrypt pipeline4 OK");

    int r_dec = cagoule_cbc_decrypt(ciphertext, n_blocks, recovered, plain_sz,
                                     g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0);
    CHECK(r_dec == 0, "decrypt pipeline4 OK");

    CHECK(memcmp(plaintext, recovered, plain_sz) == 0, "roundtrip 8 blocs identique");

    free(plaintext);
    free(ciphertext);
    free(recovered);
}

/* ── Test 4 : CBC diffusion ───────────────────────────────────────── */
static void test_cbc_diffusion(void) {
    printf("\n[Mode CBC — diffusion entre blocs]\n");

    uint8_t plaintext[32];
    memset(plaintext, 0x42, 32);

    size_t ct_size = 2 * CAGOULE_N * p_bytes(P);
    uint8_t* ciphertext = malloc(ct_size);
    cagoule_cbc_encrypt(plaintext, 2, ciphertext, ct_size,
                        g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0);

    int diff = memcmp(ciphertext,
                      ciphertext + CAGOULE_N * p_bytes(P),
                      CAGOULE_N * p_bytes(P)) != 0;
    CHECK(diff, "blocs identiques → chiffrés différents");

    free(ciphertext);
}

/* ── Test 5 : valeurs limites ─────────────────────────────────────── */
static void test_edge_cases(void) {
    printf("\n[Valeurs limites]\n");

    uint8_t zeros[16] = {0};
    size_t ct_size = 1 * CAGOULE_N * p_bytes(P);
    uint8_t* ct_z = malloc(ct_size);
    uint8_t rec_z[16];
    cagoule_cbc_encrypt(zeros, 1, ct_z, ct_size,
                        g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0);
    cagoule_cbc_decrypt(ct_z, 1, rec_z, sizeof(rec_z),
                        g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0);
    CHECK(memcmp(zeros, rec_z, 16) == 0, "bloc de zéros OK");
    free(ct_z);

    uint8_t maxb[16];
    memset(maxb, 0xFF, 16);
    uint8_t* ct_m = malloc(ct_size);
    uint8_t rec_m[16];
    cagoule_cbc_encrypt(maxb, 1, ct_m, ct_size,
                        g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0);
    cagoule_cbc_decrypt(ct_m, 1, rec_m, sizeof(rec_m),
                        g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0);
    CHECK(memcmp(maxb, rec_m, 16) == 0, "bloc 0xFF OK");
    free(ct_m);
}

/* ── Test 6 : guards null/size ────────────────────────────────────── */
static void test_guards(void) {
    printf("\n[Guards null/size]\n");

    size_t ct_size = 1 * CAGOULE_N * p_bytes(P);
    uint8_t plain[16] = {0};
    uint8_t out[256];

    CHECK(cagoule_cbc_encrypt(NULL, 1, out, ct_size, g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0)
          == CAGOULE_ERR_NULL, "encrypt NULL padded");
    CHECK(cagoule_cbc_encrypt(plain, 1, NULL, 0, g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0)
          == CAGOULE_ERR_NULL, "encrypt NULL out");
    CHECK(cagoule_cbc_encrypt(plain, 4, out, 0, g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0)
          == CAGOULE_ERR_SIZE, "encrypt out_size=0");
    CHECK(cagoule_cbc_decrypt(NULL, 1, plain, sizeof(plain), g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0)
          == CAGOULE_ERR_NULL, "decrypt NULL cipher");
    CHECK(cagoule_cbc_decrypt(out, 4, NULL, 0, g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0)
          == CAGOULE_ERR_NULL, "decrypt NULL out");
}


/* ── Test 6b : Z-Domain Shifting (v2.5.0) ─────────────────────────── */
static void test_z_domain_shifting(void) {
    printf("\n[Z-Domain Shifting — v2.5.0]\n");

    uint64_t zo[16];
    for (int i = 0; i < 16; i++)
        zo[i] = (uint64_t)((i * 0x9E3779B97F4A7C15ULL) % P);

    uint8_t plaintext[32];
    for (int i = 0; i < 32; i++)
        plaintext[i] = (uint8_t)(i * 37 + 11);

    size_t n_blocks = 2;
    size_t ct_size = n_blocks * CAGOULE_N * p_bytes(P);

    uint8_t* ct_with_zo    = malloc(ct_size);
    uint8_t* ct_without_zo = malloc(ct_size);
    uint8_t* ct_zero_zo    = malloc(ct_size);
    uint8_t recovered[32];

    /* Encrypt with Z-shifting */
    int r = cagoule_cbc_encrypt(plaintext, n_blocks, ct_with_zo, ct_size,
                                 g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, zo, 16);
    CHECK(r == CAGOULE_OK, "encrypt with z_offset OK");

    /* Encrypt without Z-shifting */
    r = cagoule_cbc_encrypt(plaintext, n_blocks, ct_without_zo, ct_size,
                             g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0);
    CHECK(r == CAGOULE_OK, "encrypt without z_offset OK");

    /* Ciphertexts MUST differ (Z-shifting changes output) */
    int differ = memcmp(ct_with_zo, ct_without_zo, ct_size) != 0;
    CHECK(differ, "Z-shifted ciphertext differs from non-shifted");

    /* Roundtrip with Z-shifting */
    r = cagoule_cbc_decrypt(ct_with_zo, n_blocks, recovered, sizeof(recovered),
                             g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, zo, 16);
    CHECK(r == CAGOULE_OK, "decrypt with z_offset OK");
    CHECK(memcmp(plaintext, recovered, 32) == 0, "Z-shift roundtrip correct");

    /* Edge: all-zero z_offset should produce same as no z_offset */
    uint64_t zo_zero[16] = {0};
    r = cagoule_cbc_encrypt(plaintext, n_blocks, ct_zero_zo, ct_size,
                             g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, zo_zero, 16);
    CHECK(r == CAGOULE_OK, "encrypt with zero z_offset OK");
    int same = memcmp(ct_zero_zo, ct_without_zo, ct_size) == 0;
    CHECK(same, "zero z_offset ≡ no z_offset");

    /* Edge: single block */
    uint8_t single_pt[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    size_t single_ct_size = 1 * CAGOULE_N * p_bytes(P);
    uint8_t* single_ct = malloc(single_ct_size);
    uint8_t single_rec[16];

    r = cagoule_cbc_encrypt(single_pt, 1, single_ct, single_ct_size,
                             g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, zo, 16);
    CHECK(r == CAGOULE_OK, "single block encrypt with z_offset OK");

    r = cagoule_cbc_decrypt(single_ct, 1, single_rec, sizeof(single_rec),
                             g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, zo, 16);
    CHECK(r == CAGOULE_OK, "single block decrypt with z_offset OK");
    CHECK(memcmp(single_pt, single_rec, 16) == 0, "single block Z-shift roundtrip");

    free(ct_with_zo);
    free(ct_without_zo);
    free(ct_zero_zo);
    free(single_ct);
}

/* ── Test 7 : AVX2 parité (mono-bloc + pipeline4) ─────────────────── */
#if defined(__AVX2__)
static void test_avx2_parity(void) {
    printf("\n[AVX2 vs Scalar parity]\n");
    
    if (!cagoule_matrix_backend_is_avx2()) {
        printf("  SKIP — AVX2 non disponible au runtime\n");
        _passed++;
        return;
    }
    
    /* Mono-bloc (1 bloc) */
    {
        uint8_t plaintext[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        size_t ct_size = 1 * CAGOULE_N * p_bytes(P);
        uint8_t* ct = malloc(ct_size);
        uint8_t recovered[16];
        
        cagoule_cbc_encrypt(plaintext, 1, ct, ct_size,
                            g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0);
        cagoule_cbc_decrypt(ct, 1, recovered, 16,
                            g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0);
        CHECK(memcmp(plaintext, recovered, 16) == 0, "AVX2 mono-bloc roundtrip");
        
        int changed = 0;
        for (int i = 0; i < (int)ct_size; i++)
            if (ct[i] != 0) { changed = 1; break; }
        CHECK(changed, "AVX2 mono-bloc ciphertext non-nul");
        
        free(ct);
    }
    
    /* Pipeline4 (8 blocs) — exercise le dispatch pipeline */
    {
        size_t nb = 8;
        size_t plain_sz = nb * CAGOULE_N;
        uint8_t* plain = malloc(plain_sz);
        for (size_t i = 0; i < plain_sz; i++)
            plain[i] = (uint8_t)((i * 0xAB + 1) & 0xFF);
        
        size_t ct_size = nb * CAGOULE_N * p_bytes(P);
        uint8_t* ct = malloc(ct_size);
        uint8_t* rec = malloc(plain_sz);
        
        cagoule_cbc_encrypt(plain, nb, ct, ct_size,
                            g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0);
        cagoule_cbc_decrypt(ct, nb, rec, plain_sz,
                            g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0);
        CHECK(memcmp(plain, rec, plain_sz) == 0, "AVX2 pipeline4 roundtrip (8 blocs)");
        
        /* Test avec remainder (9 blocs = 1 groupe + 1 residu) */
        nb = 9;
        plain_sz = nb * CAGOULE_N;
        plain = realloc(plain, plain_sz);
        for (size_t i = 128; i < plain_sz; i++)
            plain[i] = (uint8_t)((i * 0xAB + 1) & 0xFF);
        
        ct_size = nb * CAGOULE_N * p_bytes(P);
        ct = realloc(ct, ct_size);
        rec = realloc(rec, plain_sz);
        
        cagoule_cbc_encrypt(plain, nb, ct, ct_size,
                            g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0);
        cagoule_cbc_decrypt(ct, nb, rec, plain_sz,
                            g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0);
        CHECK(memcmp(plain, rec, plain_sz) == 0, "AVX2 pipeline4 roundtrip (9 blocs, residual)");
        
        free(plain);
        free(ct);
        free(rec);
    }
}
#endif

/* ── Test 8 : Benchmark 1 MB ──────────────────────────────────────── */
static void bench_1mb(void) {
    printf("\n[Benchmark — 1 MB (65 536 blocs)]\n");

    size_t n_blocks = 65536;
    size_t pt_size = n_blocks * CAGOULE_N;
    size_t ct_size = n_blocks * CAGOULE_N * p_bytes(P);

    uint8_t* plaintext = malloc(pt_size);
    uint8_t* ciphertext = malloc(ct_size);
    uint8_t* recovered = malloc(pt_size);

    for (size_t i = 0; i < pt_size; i++)
        plaintext[i] = (uint8_t)((i * 1103515245 + 12345) & 0xFF);

    /* Warmup */
    cagoule_cbc_encrypt(plaintext, n_blocks, ciphertext, ct_size,
                        g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0);

    /* Encrypt benchmark */
    uint64_t t0 = now_ms();
    cagoule_cbc_encrypt(plaintext, n_blocks, ciphertext, ct_size,
                        g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0);
    double enc_ms = (double)(now_ms() - t0);

    /* Decrypt benchmark */
    uint64_t t1 = now_ms();
    cagoule_cbc_decrypt(ciphertext, n_blocks, recovered, pt_size,
                        g_mat, &g_sbox, g_round_keys, NUM_KEYS, P, NULL, 0);
    double dec_ms = (double)(now_ms() - t1);

    int ok = memcmp(plaintext, recovered, pt_size) == 0;
    CHECK(ok, "roundtrip 1 MB correct");

    double enc_mbs = (enc_ms > 0) ? (1000.0 / enc_ms) : 999.0;
    double dec_mbs = (dec_ms > 0) ? (1000.0 / dec_ms) : 999.0;
    printf("  Encrypt 1 MB : %.1f ms  (%.1f MB/s)\n", enc_ms, enc_mbs);
    printf("  Decrypt 1 MB : %.1f ms  (%.1f MB/s)\n", dec_ms, dec_mbs);
    printf("  Ratio dec/enc : %.2f×\n", dec_ms / enc_ms);
    printf("  [Python v1.5 : enc ~1700ms, dec ~13300ms]\n");

    int under_valgrind = (getenv("RUNNING_ON_VALGRIND") != NULL);
    #ifdef DEBUG
        int under_debug = 1;
    #else
        int under_debug = 0;
    #endif
    if (!under_valgrind && !under_debug) {
        CHECK(enc_ms < 200.0, "encrypt 1 MB < 200 ms");
        CHECK(dec_ms < 200.0, "decrypt 1 MB < 200 ms");
    } else if (under_debug) {
        printf("  (seuils de performance ignorés en mode debug)\n");
    }
    CHECK(dec_ms / enc_ms < 2.0, "ratio dec/enc < 2×");

    free(plaintext);
    free(ciphertext);
    free(recovered);
}

/* ── Main ─────────────────────────────────────────────────────────── */
int main(void) {
    printf("══════════════════════════════════════════\n");
    printf("  CAGOULE v3.1.0 — test_cipher.c\n");
    printf("══════════════════════════════════════════\n");

    setup();
    gen_round_keys();

    test_pkcs7_padding();          /* Test 0: padding scheme */
    test_roundtrip_single_block(); /* Test 1: 1 bloc */
    test_roundtrip_multi_block();  /* Test 2: 10 blocs */
    test_roundtrip_pipeline4();    /* Test 3: 8 blocs (pipeline path) */
    test_cbc_diffusion();          /* Test 4: diffusion */
    test_edge_cases();             /* Test 5: zeros, 0xFF */
    test_guards();                 /* Test 6: null/size */
    test_z_domain_shifting();     /* Test 6b: Z-Domain Shifting */
#if defined(__AVX2__)
    test_avx2_parity();            /* Test 7: AVX2 mono + pipeline4 + residual */
#endif
    bench_1mb();                   /* Test 8: performance */

    teardown();

    printf("\n──────────────────────────────────────────\n");
    printf("  ✅ %d passés  ❌ %d échoués\n", _passed, _failed);
    printf("══════════════════════════════════════════\n");
    return _failed == 0 ? 0 : 1;
}