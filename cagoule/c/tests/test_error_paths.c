/**
 * test_error_paths.c — Error-path coverage for gaps found by audit
 * CAGOULE v3.1.0
 *
 * Scope, chosen deliberately rather than attempting to re-test every
 * function in the codebase (that already happens across the other 15
 * test binaries):
 *
 *   1. cagoule_encrypt_v3 / cagoule_decrypt_v3 (mono-message API) --
 *      had ZERO test coverage anywhere in the suite before this file.
 *      Full round-trip, wrong password, corrupted/truncated ciphertext,
 *      bad magic/version, NULL guards.
 *
 *   2. cagoule_ctr_decrypt -- cagoule_ctr_encrypt already has a full
 *      NULL-guard sweep (test_ctr.c Suite 10), but cagoule_ctr_decrypt
 *      had none of its own (only a size check). Closes that asymmetry.
 *
 *   3. cagoule_cbc_decrypt -- only 2 of 6 possible NULL-checkable
 *      pointer args were tested (test_cipher.c). Completes the sweep.
 *
 *   4. Truncated-mid-body ciphertext (valid header, missing/partial
 *      tag) at the handle API level -- test_api_raw.c's boundary tests
 *      cover "too short for any valid overhead"; this file adds the
 *      distinct case of a ciphertext that looks structurally plausible
 *      but is truncated partway through the tag.
 *
 * NOTE on scope: cagoule_cbc_decrypt/cagoule_ctr_decrypt are raw
 * algebraic primitives with no password parameter and no MAC at that
 * layer -- "wrong password" and "corrupted ciphertext is rejected"
 * are not meaningful concepts at that level (garbage input produces
 * garbage plaintext, which is correct behavior for a primitive, not an
 * error). Those properties are tested at the authenticated layers
 * (cagoule_api.c handle/mono-message functions, cagoule_stream.c) --
 * both already covered in test_api_raw.c and test_stream.c, extended
 * further in this pass.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "cagoule_api.h"
#include "cagoule_matrix.h"
#include "cagoule_sbox.h"
#include "cagoule_ctr.h"
#include "cagoule_cipher.h"
#include "cagoule_math.h"

static long g_pass = 0, g_fail = 0;

#define CHECK(c) do { if(c) g_pass++; else { g_fail++; \
    fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#c);} } while(0)

static const uint8_t PASSWORD[] = "error_path_test_password_CAGOULE";
static const size_t  PASSWORD_LEN = sizeof(PASSWORD) - 1;

/* ════════════════════════════════════════════════════════════════════
 * Part 1 : cagoule_encrypt_v3 / cagoule_decrypt_v3 -- zero prior coverage
 * ════════════════════════════════════════════════════════════════════ */

static void test_v3_roundtrip(void) {
    puts("  Suite 1 : cagoule_encrypt_v3/decrypt_v3 basic round-trip");

    const uint8_t pt[] = "mono-message API round-trip payload";
    size_t pt_len = sizeof(pt) - 1;
    size_t ct_len = cagoule_api_encrypt_out_len(pt_len);
    uint8_t *ct = malloc(ct_len);
    size_t out_len = ct_len;

    int ret = cagoule_encrypt_v3(PASSWORD, PASSWORD_LEN, pt, pt_len, ct, &out_len);
    CHECK(ret == CAGOULE_API_OK);
    CHECK(out_len == ct_len);

    size_t pt_cap = cagoule_api_decrypt_out_len(out_len);
    CHECK(pt_cap == pt_len);
    uint8_t *pt_out = malloc(pt_cap);
    size_t pt_out_len = pt_cap;
    ret = cagoule_decrypt_v3(PASSWORD, PASSWORD_LEN, ct, out_len, pt_out, &pt_out_len);
    CHECK(ret == CAGOULE_API_OK);
    CHECK(pt_out_len == pt_len);
    CHECK(memcmp(pt_out, pt, pt_len) == 0);

    free(ct); free(pt_out);
}

static void test_v3_wrong_password(void) {
    puts("  Suite 2 : cagoule_decrypt_v3 wrong password rejected");

    const uint8_t pt[] = "secret payload";
    size_t pt_len = sizeof(pt) - 1;
    size_t ct_len = cagoule_api_encrypt_out_len(pt_len);
    uint8_t *ct = malloc(ct_len);
    size_t out_len = ct_len;
    CHECK(cagoule_encrypt_v3(PASSWORD, PASSWORD_LEN, pt, pt_len, ct, &out_len) == CAGOULE_API_OK);

    static const uint8_t wrong_pw[] = "definitely_the_wrong_password";
    uint8_t pt_out[128];
    size_t pt_out_len = sizeof(pt_out);
    int ret = cagoule_decrypt_v3(wrong_pw, sizeof(wrong_pw)-1, ct, out_len, pt_out, &pt_out_len);
    CHECK(ret == CAGOULE_API_ERR_AUTH);

    free(ct);
}

static void test_v3_corrupted_ciphertext(void) {
    puts("  Suite 3 : cagoule_decrypt_v3 corrupted ciphertext rejected");

    const uint8_t pt[] = "another payload to corrupt in transit";
    size_t pt_len = sizeof(pt) - 1;
    size_t ct_len = cagoule_api_encrypt_out_len(pt_len);
    uint8_t *ct = malloc(ct_len);
    size_t out_len = ct_len;
    CHECK(cagoule_encrypt_v3(PASSWORD, PASSWORD_LEN, pt, pt_len, ct, &out_len) == CAGOULE_API_OK);

    /* Flip a byte in the ciphertext body (after the header, before the tag). */
    ct[out_len - 20] ^= 0xFF;

    uint8_t pt_out[128];
    size_t pt_out_len = sizeof(pt_out);
    int ret = cagoule_decrypt_v3(PASSWORD, PASSWORD_LEN, ct, out_len, pt_out, &pt_out_len);
    CHECK(ret == CAGOULE_API_ERR_AUTH);

    free(ct);
}

static void test_v3_truncated_ciphertext(void) {
    puts("  Suite 4 : cagoule_decrypt_v3 truncated ciphertext rejected");

    const uint8_t pt[] = "a payload that will be truncated for this test";
    size_t pt_len = sizeof(pt) - 1;
    size_t ct_len = cagoule_api_encrypt_out_len(pt_len);
    uint8_t *ct = malloc(ct_len);
    size_t out_len = ct_len;
    CHECK(cagoule_encrypt_v3(PASSWORD, PASSWORD_LEN, pt, pt_len, ct, &out_len) == CAGOULE_API_OK);

    uint8_t pt_out[128];

    /* Case A: shorter than the minimum overhead entirely -- must be
     * rejected on a cheap length check, not attempt any crypto. */
    {
        size_t pt_out_len = sizeof(pt_out);
        int ret = cagoule_decrypt_v3(PASSWORD, PASSWORD_LEN, ct, 10, pt_out, &pt_out_len);
        CHECK(ret == CAGOULE_API_ERR_SIZE);
    }

    /* Case B: structurally long enough to look plausible (past the fixed
     * header) but truncated partway through the tag -- must fail
     * authentication, not read past the buffer or accept a partial tag. */
    {
        size_t truncated_len = out_len - 5;  /* chop the last 5 bytes of the 16-byte tag */
        size_t pt_out_len = sizeof(pt_out);
        int ret = cagoule_decrypt_v3(PASSWORD, PASSWORD_LEN, ct, truncated_len, pt_out, &pt_out_len);
        CHECK(ret != CAGOULE_API_OK);
    }

    /* Case C: exactly one byte short of the full ciphertext. */
    {
        size_t truncated_len = out_len - 1;
        size_t pt_out_len = sizeof(pt_out);
        int ret = cagoule_decrypt_v3(PASSWORD, PASSWORD_LEN, ct, truncated_len, pt_out, &pt_out_len);
        CHECK(ret != CAGOULE_API_OK);
    }

    free(ct);
}

static void test_v3_bad_format(void) {
    puts("  Suite 5 : cagoule_decrypt_v3 bad magic/version rejected");

    const uint8_t pt[] = "format check payload";
    size_t pt_len = sizeof(pt) - 1;
    size_t ct_len = cagoule_api_encrypt_out_len(pt_len);
    uint8_t *ct = malloc(ct_len);
    size_t out_len = ct_len;
    CHECK(cagoule_encrypt_v3(PASSWORD, PASSWORD_LEN, pt, pt_len, ct, &out_len) == CAGOULE_API_OK);

    uint8_t pt_out[128];

    /* Bad magic bytes. */
    {
        uint8_t *bad = malloc(out_len);
        memcpy(bad, ct, out_len);
        bad[0] ^= 0xFF;
        size_t pt_out_len = sizeof(pt_out);
        int ret = cagoule_decrypt_v3(PASSWORD, PASSWORD_LEN, bad, out_len, pt_out, &pt_out_len);
        CHECK(ret == CAGOULE_API_ERR_FORMAT);
        free(bad);
    }

    /* Bad version byte (magic intact, version corrupted -- byte 4). */
    {
        uint8_t *bad = malloc(out_len);
        memcpy(bad, ct, out_len);
        bad[4] = 0xEE;
        size_t pt_out_len = sizeof(pt_out);
        int ret = cagoule_decrypt_v3(PASSWORD, PASSWORD_LEN, bad, out_len, pt_out, &pt_out_len);
        CHECK(ret == CAGOULE_API_ERR_FORMAT);
        free(bad);
    }

    free(ct);
}

static void test_v3_null_guards(void) {
    puts("  Suite 6 : cagoule_encrypt_v3/decrypt_v3 NULL guards");

    uint8_t buf[128];
    size_t buf_len = sizeof(buf);
    const uint8_t dummy[1] = {0};

    CHECK(cagoule_encrypt_v3(NULL, 0, dummy, 0, buf, &buf_len) == CAGOULE_API_ERR_NULL);
    CHECK(cagoule_encrypt_v3(PASSWORD, PASSWORD_LEN, NULL, 0, buf, &buf_len) == CAGOULE_API_ERR_NULL);
    CHECK(cagoule_encrypt_v3(PASSWORD, PASSWORD_LEN, dummy, 0, NULL, &buf_len) == CAGOULE_API_ERR_NULL);
    CHECK(cagoule_encrypt_v3(PASSWORD, PASSWORD_LEN, dummy, 0, buf, NULL) == CAGOULE_API_ERR_NULL);

    CHECK(cagoule_decrypt_v3(NULL, 0, dummy, 0, buf, &buf_len) == CAGOULE_API_ERR_NULL);
    CHECK(cagoule_decrypt_v3(PASSWORD, PASSWORD_LEN, NULL, 0, buf, &buf_len) == CAGOULE_API_ERR_NULL);
    CHECK(cagoule_decrypt_v3(PASSWORD, PASSWORD_LEN, dummy, 0, NULL, &buf_len) == CAGOULE_API_ERR_NULL);
    CHECK(cagoule_decrypt_v3(PASSWORD, PASSWORD_LEN, dummy, 0, buf, NULL) == CAGOULE_API_ERR_NULL);
}

/* ════════════════════════════════════════════════════════════════════
 * Part 2 : cagoule_ctr_decrypt -- complete the NULL-guard sweep
 * (cagoule_ctr_encrypt already has one in test_ctr.c Suite 10; decrypt
 * had none of its own before this file, only a size check).
 * ════════════════════════════════════════════════════════════════════ */

static void test_ctr_decrypt_null_guards(void) {
    puts("  Suite 7 : cagoule_ctr_decrypt NULL guards (was untested)");

    uint64_t nodes[16];
    for (int i = 0; i < 16; i++) nodes[i] = (uint64_t)(2 + i * 1000000007ULL);
    uint64_t p = CAGOULE_MERSENNE_P[0];
    CagouleMatrix *mat = cagoule_matrix_build(nodes, 16, p);
    CHECK(mat != NULL);
    if (!mat) return;

    CagouleSBox64 sbox;
    cagoule_sbox_init(&sbox, p, 12345, 67890);

    uint64_t rk[64];
    for (int i = 0; i < 64; i++) rk[i] = (uint64_t)((i + 1) * 0x9E3779B97F4A7C15ULL) % p;

    uint8_t iv[8] = {1,2,3,4,5,6,7,8};
    uint8_t ct[32] = {0};
    uint8_t out[32] = {0};

    CHECK(cagoule_ctr_decrypt(NULL, 32, iv, mat, &sbox, rk, 64, p, NULL, 0, out, 32) == CAGOULE_ERR_NULL);
    CHECK(cagoule_ctr_decrypt(ct, 32, NULL, mat, &sbox, rk, 64, p, NULL, 0, out, 32) == CAGOULE_ERR_NULL);
    CHECK(cagoule_ctr_decrypt(ct, 32, iv, NULL, &sbox, rk, 64, p, NULL, 0, out, 32) == CAGOULE_ERR_NULL);
    CHECK(cagoule_ctr_decrypt(ct, 32, iv, mat, NULL, rk, 64, p, NULL, 0, out, 32) == CAGOULE_ERR_NULL);
    CHECK(cagoule_ctr_decrypt(ct, 32, iv, mat, &sbox, NULL, 64, p, NULL, 0, out, 32) == CAGOULE_ERR_NULL);
    CHECK(cagoule_ctr_decrypt(ct, 32, iv, mat, &sbox, rk, 64, p, NULL, 0, NULL, 32) == CAGOULE_ERR_NULL);
    CHECK(cagoule_ctr_decrypt(ct, 32, iv, mat, &sbox, rk, 64, p, NULL, 0, out, 16) == CAGOULE_ERR_SIZE);

    cagoule_matrix_free(mat);
}

/* ════════════════════════════════════════════════════════════════════
 * Part 3 : cagoule_cbc_decrypt -- complete the NULL-guard sweep
 * (only cipher_bytes and out were tested before; mat/sbox/round_keys
 * were not).
 * ════════════════════════════════════════════════════════════════════ */

static void test_cbc_decrypt_null_guards(void) {
    puts("  Suite 8 : cagoule_cbc_decrypt NULL guards (mat/sbox/round_keys were untested)");

    uint64_t nodes[16];
    for (int i = 0; i < 16; i++) nodes[i] = (uint64_t)(3 + i * 998244353ULL);
    uint64_t p = CAGOULE_MERSENNE_P[1];
    CagouleMatrix *mat = cagoule_matrix_build(nodes, 16, p);
    CHECK(mat != NULL);
    if (!mat) return;

    CagouleSBox64 sbox;
    cagoule_sbox_init(&sbox, p, 111, 222);

    uint64_t rk[64];
    for (int i = 0; i < 64; i++) rk[i] = (uint64_t)((i + 3) * 0x2545F4914F6CDD1DULL) % p;

    uint8_t cipher_bytes[16 * 8] = {0};
    uint8_t out[16 * 8] = {0};

    CHECK(cagoule_cbc_decrypt(NULL, 1, out, sizeof(out), mat, &sbox, rk, 64, p, NULL, 0) == CAGOULE_ERR_NULL);
    CHECK(cagoule_cbc_decrypt(cipher_bytes, 1, NULL, 0, mat, &sbox, rk, 64, p, NULL, 0) == CAGOULE_ERR_NULL);
    CHECK(cagoule_cbc_decrypt(cipher_bytes, 1, out, sizeof(out), NULL, &sbox, rk, 64, p, NULL, 0) == CAGOULE_ERR_NULL);
    CHECK(cagoule_cbc_decrypt(cipher_bytes, 1, out, sizeof(out), mat, NULL, rk, 64, p, NULL, 0) == CAGOULE_ERR_NULL);
    CHECK(cagoule_cbc_decrypt(cipher_bytes, 1, out, sizeof(out), mat, &sbox, NULL, 64, p, NULL, 0) == CAGOULE_ERR_NULL);
    CHECK(cagoule_cbc_decrypt(cipher_bytes, 1, out, 0, mat, &sbox, rk, 64, p, NULL, 0) == CAGOULE_ERR_SIZE);

    cagoule_matrix_free(mat);
}

/* ════════════════════════════════════════════════════════════════════
 * Part 4 : truncated-mid-body ciphertext at the handle API level
 * (test_api_raw.c's boundary tests cover "too short for any valid
 * overhead"; this adds "structurally plausible but truncated in the tag").
 * ════════════════════════════════════════════════════════════════════ */

static void test_handle_truncated_tag(void) {
    puts("  Suite 9 : handle API, ciphertext truncated partway through the tag");

    static const uint8_t salt[32] = {
        9,8,7,6,5,4,3,2,1,0, 9,8,7,6,5,4,3,2,1,0, 9,8,7,6,5,4,3,2,1,0, 9,8
    };
    CagouleKeyHandle *h = cagoule_derive_key(PASSWORD, PASSWORD_LEN, salt, sizeof(salt));
    CHECK(h != NULL);
    if (!h) return;

    const uint8_t pt[] = "payload whose tag will be truncated";
    size_t pt_len = sizeof(pt) - 1;
    size_t ct_len = cagoule_api_encrypt_out_len(pt_len);
    uint8_t *ct = malloc(ct_len);
    size_t out_len = ct_len;
    CHECK(cagoule_encrypt_with_handle(h, pt, pt_len, ct, &out_len) == CAGOULE_API_OK);

    /* Truncate by 8 of the 16 tag bytes -- long enough to pass any cheap
     * "too short" length check, short enough to definitely not carry a
     * valid tag. Must be rejected, not accepted with a wrong/partial
     * comparison. */
    size_t truncated_len = out_len - 8;
    uint8_t out[128];
    size_t out_len2 = sizeof(out);
    int ret = cagoule_decrypt_with_handle(h, ct, truncated_len, out, &out_len2);
    CHECK(ret != CAGOULE_API_OK);

    free(ct);
    cagoule_key_handle_free(h);
}

int main(void) {
    puts("=== test_error_paths CAGOULE v3.1.0 ===");
    test_v3_roundtrip();
    test_v3_wrong_password();
    test_v3_corrupted_ciphertext();
    test_v3_truncated_ciphertext();
    test_v3_bad_format();
    test_v3_null_guards();
    test_ctr_decrypt_null_guards();
    test_cbc_decrypt_null_guards();
    test_handle_truncated_tag();
    printf("\n=== %ld passés / %ld échoués ===\n", g_pass, g_fail);
    return g_fail != 0;
}
