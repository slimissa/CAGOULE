/**
 * test_cipher.c — Tests du pipeline CBC CAGOULE v2.0.0
 *
 * Usage :
 *   gcc -O2 -std=c99 -Iinclude src/cagoule_matrix.c src/cagoule_sbox.c \
 *       src/cagoule_cipher.c tests/test_cipher.c -o test_cipher && ./test_cipher
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

/* ── Helper : calcul de p_bytes (identique à cipher.c) ────────────── */
static size_t p_bytes(uint64_t p) {
    return (p > 0xFFFFFFFF) ? 8 : 4;
}

/* ── Test PKCS7 padding (NOUVEAU) ─────────────────────────────────── */
static void test_pkcs7_padding(void) {
    printf("\n[PKCS7 padding — 13 bytes -> 16 bytes]\n");
    
    /* Message de 13 bytes (non multiple de 16) */
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
    
    /* Chiffrement avec padding */
    int r = cagoule_cbc_encrypt(padded, n_blocks, ciphertext, ct_size,
                                 g_mat, &g_sbox, g_round_keys, NUM_KEYS, P);
    CHECK(r == 0, "encrypt avec padding OK");
    
    r = cagoule_cbc_decrypt(ciphertext, n_blocks, recovered, 16,
                             g_mat, &g_sbox, g_round_keys, NUM_KEYS, P);
    CHECK(r == 0, "decrypt avec padding OK");
    
    /* Vérifier le padding (dernier byte = 0x03) */
    CHECK(recovered[15] == 0x03, "padding byte = 0x03");
    CHECK(memcmp(recovered, msg, msg_len) == 0, "message original intact");
    
    free(ciphertext);
    free(recovered);
}

/* ── Test 1 : roundtrip encrypt / decrypt (adapté) ────────────────── */
static void test_roundtrip_single_block(void) {
    printf("\n[Roundtrip — 1 bloc (16 bytes)]\n");

    uint8_t plaintext[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    size_t n_blocks = 1;
    size_t ct_size = n_blocks * CAGOULE_N * p_bytes(P);
    uint8_t ciphertext[128];
    uint8_t recovered[16];

    int r = cagoule_cbc_encrypt(plaintext, n_blocks, ciphertext, sizeof(ciphertext),
                                 g_mat, &g_sbox, g_round_keys, NUM_KEYS, P);
    CHECK(r == 0, "encrypt retourne 0");

    r = cagoule_cbc_decrypt(ciphertext, n_blocks, recovered, sizeof(recovered),
                             g_mat, &g_sbox, g_round_keys, NUM_KEYS, P);
    CHECK(r == 0, "decrypt retourne 0");

    CHECK(memcmp(plaintext, recovered, 16) == 0, "roundtrip 1 bloc identique");

    int changed = 0;
    for (size_t i = 0; i < ct_size; i++)
        if (ciphertext[i] != 0) { changed = 1; break; }
    CHECK(changed, "ciphertext non nul");
}

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
                        g_mat, &g_sbox, g_round_keys, NUM_KEYS, P);
    cagoule_cbc_decrypt(ciphertext, n_blocks, recovered, 160,
                        g_mat, &g_sbox, g_round_keys, NUM_KEYS, P);

    CHECK(memcmp(plaintext, recovered, 160) == 0, "roundtrip 10 blocs");

    free(ciphertext);
    free(recovered);
}

/* ── Test CBC diffusion ───────────────────────────────────────────── */
static void test_cbc_diffusion(void) {
    printf("\n[Mode CBC — diffusion entre blocs]\n");

    uint8_t plaintext[32];
    memset(plaintext, 0x42, 32);

    size_t ct_size = 2 * CAGOULE_N * p_bytes(P);
    uint8_t ciphertext[256];
    cagoule_cbc_encrypt(plaintext, 2, ciphertext, sizeof(ciphertext),
                        g_mat, &g_sbox, g_round_keys, NUM_KEYS, P);

    int diff = memcmp(ciphertext,
                      ciphertext + CAGOULE_N * p_bytes(P),
                      CAGOULE_N * p_bytes(P)) != 0;
    CHECK(diff, "blocs identiques → chiffrés différents");
}

/* ── Test valeurs limites ─────────────────────────────────────────── */
static void test_edge_cases(void) {
    printf("\n[Valeurs limites]\n");

    uint8_t zeros[16] = {0};
    uint8_t ct_z[128], rec_z[16];
    cagoule_cbc_encrypt(zeros, 1, ct_z, sizeof(ct_z),
                        g_mat, &g_sbox, g_round_keys, NUM_KEYS, P);
    cagoule_cbc_decrypt(ct_z, 1, rec_z, sizeof(rec_z),
                        g_mat, &g_sbox, g_round_keys, NUM_KEYS, P);
    CHECK(memcmp(zeros, rec_z, 16) == 0, "bloc de zéros OK");

    uint8_t maxb[16];
    memset(maxb, 0xFF, 16);
    uint8_t ct_m[128], rec_m[16];
    cagoule_cbc_encrypt(maxb, 1, ct_m, sizeof(ct_m),
                        g_mat, &g_sbox, g_round_keys, NUM_KEYS, P);
    cagoule_cbc_decrypt(ct_m, 1, rec_m, sizeof(rec_m),
                        g_mat, &g_sbox, g_round_keys, NUM_KEYS, P);
    CHECK(memcmp(maxb, rec_m, 16) == 0, "bloc 0xFF OK");
}

/* ── Benchmark 1MB (adapté) ───────────────────────────────────────── */
static void bench_1mb(void) {
    printf("\n[Benchmark — 1 MB (65 536 blocs)]\n");

    size_t n_blocks = 65536;
    size_t pt_size = n_blocks * 16;
    size_t ct_size = n_blocks * CAGOULE_N * p_bytes(P);

    uint8_t* plaintext = malloc(pt_size);
    uint8_t* ciphertext = malloc(ct_size);
    uint8_t* recovered = malloc(pt_size);

    for (size_t i = 0; i < pt_size; i++)
        plaintext[i] = (uint8_t)((i * 1103515245 + 12345) & 0xFF);

    clock_t t0 = clock();
    cagoule_cbc_encrypt(plaintext, n_blocks, ciphertext, ct_size,
                        g_mat, &g_sbox, g_round_keys, NUM_KEYS, P);
    double enc_ms = (double)(clock() - t0) / CLOCKS_PER_SEC * 1000.0;

    t0 = clock();
    cagoule_cbc_decrypt(ciphertext, n_blocks, recovered, pt_size,
                        g_mat, &g_sbox, g_round_keys, NUM_KEYS, P);
    double dec_ms = (double)(clock() - t0) / CLOCKS_PER_SEC * 1000.0;

    int ok = memcmp(plaintext, recovered, pt_size) == 0;
    CHECK(ok, "roundtrip 1 MB correct");

    printf("  Encrypt 1 MB : %.1f ms  (%.1f MB/s)\n", enc_ms, 1000.0 / enc_ms);
    printf("  Decrypt 1 MB : %.1f ms  (%.1f MB/s)\n", dec_ms, 1000.0 / dec_ms);
    printf("  Ratio dec/enc : %.2f×\n", dec_ms / enc_ms);
    printf("  [Python v1.5 : enc ~1700ms, dec ~13300ms]\n");

    /* Seuils resserrés */
    CHECK(enc_ms < 200.0, "encrypt 1 MB < 200 ms");
    CHECK(dec_ms < 200.0, "decrypt 1 MB < 200 ms");
    CHECK(dec_ms / enc_ms < 2.0, "ratio dec/enc < 2×");

    free(plaintext);
    free(ciphertext);
    free(recovered);
}

/* ── Main ─────────────────────────────────────────────────────────── */
int main(void) {
    printf("══════════════════════════════════════════\n");
    printf("  CAGOULE v2.0.0 — test_cipher.c\n");
    printf("══════════════════════════════════════════\n");

    setup();
    gen_round_keys();

    test_roundtrip_single_block();
    test_roundtrip_multi_block();
    test_cbc_diffusion();
    test_edge_cases();
    test_pkcs7_padding();     /* NOUVEAU */
    bench_1mb();

    teardown();

    printf("\n──────────────────────────────────────────\n");
    printf("  ✅ %d passés  ❌ %d échoués\n", _passed, _failed);
    printf("══════════════════════════════════════════\n");
    return _failed == 0 ? 0 : 1;
}