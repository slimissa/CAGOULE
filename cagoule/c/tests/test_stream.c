/**
 * test_stream.c — Tests for the streaming API (cagoule_stream.c)
 * CAGOULE v3.1.0
 *
 * Closes a real audit gap: the streaming API had no dedicated C test
 * file before this one. Covers: init/free lifecycle, single and
 * multi-chunk round-trips (default AEAD 0x02 mode), init_from_salt
 * reconstructing a matching decrypt context, tamper/auth rejection,
 * chunk-reorder rejection, and basic error paths.
 *
 * Also serves as a regression guard for the two P0 fixes applied to
 * cagoule_stream.c / cagoule_omega.c in this pass: both fixes only
 * touch error paths that don't change return values on the success
 * path, so a clean pass here confirms no behavioral regression was
 * introduced by those fixes.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "cagoule_stream.h"

static long g_pass = 0, g_fail = 0;

#define CHECK(c) do { if(c) g_pass++; else { g_fail++; \
    fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#c);} } while(0)

static const uint8_t PASSWORD[]    = "stream_test_password_123";
#define PASSWORD_LEN (sizeof(PASSWORD) - 1)

/* ── Suite 1 : lifecycle ─────────────────────────────────────────── */
static void test_init_free(void) {
    puts("  Suite 1 : init/free lifecycle");

    CagouleStreamCtx *ctx = cagoule_stream_init(PASSWORD, PASSWORD_LEN, 0, 0);
    CHECK(ctx != NULL);
    cagoule_stream_free(ctx);

    /* NULL password must not crash, must return NULL */
    CHECK(cagoule_stream_init(NULL, 0, 0, 0) == NULL);

    /* free(NULL) must be a safe no-op */
    cagoule_stream_free(NULL);
}

/* ── Suite 2 : single-chunk round-trip (default AEAD 0x02) ─────────── */
static void test_roundtrip_single_chunk(void) {
    puts("  Suite 2 : single-chunk round-trip (AEAD 0x02)");

    CagouleStreamCtx *enc = cagoule_stream_init(PASSWORD, PASSWORD_LEN, 0, 0);
    CHECK(enc != NULL);
    if (!enc) return;

    const uint8_t plaintext[] = "the quick brown fox jumps over the lazy dog";
    size_t pt_len = sizeof(plaintext) - 1;

    size_t ct_cap = cagoule_stream_update_out_len(enc, pt_len);
    uint8_t *ct = malloc(ct_cap);
    size_t ct_len = ct_cap;

    int ret = cagoule_stream_update(enc, plaintext, pt_len, ct, &ct_len);
    CHECK(ret == CAGOULE_STREAM_OK);
    CHECK(ct_len == pt_len + CAGOULE_STREAM_OVERHEAD_AEAD);

    /* Decrypt using a fresh context reconstructed from the session salt,
     * exactly like the documented cross-process usage pattern. */
    const uint8_t *salt = cagoule_stream_session_salt(enc);
    CHECK(salt != NULL);

    CagouleStreamCtx *dec = cagoule_stream_init_from_salt(PASSWORD, PASSWORD_LEN, salt, 0, 0);
    CHECK(dec != NULL);
    if (dec) {
        size_t pt_out_cap = cagoule_stream_decrypt_out_len(dec, ct_len);
        uint8_t *pt_out = malloc(pt_out_cap);
        size_t pt_out_len = pt_out_cap;

        ret = cagoule_stream_decrypt(dec, ct, ct_len, pt_out, &pt_out_len);
        CHECK(ret == CAGOULE_STREAM_OK);
        CHECK(pt_out_len == pt_len);
        CHECK(memcmp(pt_out, plaintext, pt_len) == 0);

        free(pt_out);
        cagoule_stream_free(dec);
    }

    free(ct);
    cagoule_stream_free(enc);
}

/* ── Suite 3 : multi-chunk round-trip, sequential chunk_idx ─────────── */
static void test_roundtrip_multi_chunk(void) {
    puts("  Suite 3 : multi-chunk round-trip (10 chunks, sequential)");

    CagouleStreamCtx *enc = cagoule_stream_init(PASSWORD, PASSWORD_LEN, 0, 0);
    CHECK(enc != NULL);
    if (!enc) return;

    const uint8_t *salt = cagoule_stream_session_salt(enc);
    CagouleStreamCtx *dec = cagoule_stream_init_from_salt(PASSWORD, PASSWORD_LEN, salt, 0, 0);
    CHECK(dec != NULL);
    if (!dec) { cagoule_stream_free(enc); return; }

    int all_ok = 1;
    for (int i = 0; i < 10; i++) {
        char chunk[64];
        int chunk_len = snprintf(chunk, sizeof(chunk), "chunk number %d of the stream", i);

        size_t ct_cap = cagoule_stream_update_out_len(enc, (size_t)chunk_len);
        uint8_t *ct = malloc(ct_cap);
        size_t ct_len = ct_cap;
        if (cagoule_stream_update(enc, (uint8_t*)chunk, (size_t)chunk_len, ct, &ct_len) != CAGOULE_STREAM_OK)
            all_ok = 0;

        size_t pt_cap = cagoule_stream_decrypt_out_len(dec, ct_len);
        uint8_t *pt_out = malloc(pt_cap);
        size_t pt_out_len = pt_cap;
        if (cagoule_stream_decrypt(dec, ct, ct_len, pt_out, &pt_out_len) != CAGOULE_STREAM_OK)
            all_ok = 0;
        if (pt_out_len != (size_t)chunk_len || memcmp(pt_out, chunk, (size_t)chunk_len) != 0)
            all_ok = 0;

        free(ct);
        free(pt_out);
    }
    CHECK(all_ok);

    cagoule_stream_free(enc);
    cagoule_stream_free(dec);
}

/* ── Suite 4 : tampered chunk rejected, plaintext never written ─────── */
static void test_tamper_rejected(void) {
    puts("  Suite 4 : tampered chunk rejected (TAG check before output)");

    CagouleStreamCtx *enc = cagoule_stream_init(PASSWORD, PASSWORD_LEN, 0, 0);
    CHECK(enc != NULL);
    if (!enc) return;

    const uint8_t pt[] = "sensitive chunk data";
    size_t pt_len = sizeof(pt) - 1;
    size_t ct_cap = cagoule_stream_update_out_len(enc, pt_len);
    uint8_t *ct = malloc(ct_cap);
    size_t ct_len = ct_cap;
    CHECK(cagoule_stream_update(enc, pt, pt_len, ct, &ct_len) == CAGOULE_STREAM_OK);

    /* flip a byte in the ciphertext body */
    ct[ct_len - 5] ^= 0xFF;

    const uint8_t *salt = cagoule_stream_session_salt(enc);
    CagouleStreamCtx *dec = cagoule_stream_init_from_salt(PASSWORD, PASSWORD_LEN, salt, 0, 0);
    CHECK(dec != NULL);
    if (dec) {
        size_t pt_out_cap = cagoule_stream_decrypt_out_len(dec, ct_len);
        uint8_t *pt_out = malloc(pt_out_cap);
        memset(pt_out, 0xAA, pt_out_cap); /* sentinel: must remain untouched on auth failure */
        size_t pt_out_len = pt_out_cap;

        int ret = cagoule_stream_decrypt(dec, ct, ct_len, pt_out, &pt_out_len);
        CHECK(ret == CAGOULE_STREAM_ERR_AUTH);

        /* out buffer must be untouched — sentinel still intact */
        int untouched = 1;
        for (size_t i = 0; i < pt_out_cap; i++) if (pt_out[i] != 0xAA) untouched = 0;
        CHECK(untouched);

        free(pt_out);
        cagoule_stream_free(dec);
    }

    free(ct);
    cagoule_stream_free(enc);
}

/* ── Suite 5 : chunk reorder / replay rejected ───────────────────────── */
static void test_reorder_rejected(void) {
    puts("  Suite 5 : chunk reorder/replay rejected");

    CagouleStreamCtx *enc = cagoule_stream_init(PASSWORD, PASSWORD_LEN, 0, 0);
    CHECK(enc != NULL);
    if (!enc) return;
    const uint8_t *salt = cagoule_stream_session_salt(enc);
    CagouleStreamCtx *dec = cagoule_stream_init_from_salt(PASSWORD, PASSWORD_LEN, salt, 0, 0);
    CHECK(dec != NULL);
    if (!dec) { cagoule_stream_free(enc); return; }

    const uint8_t ptA[] = "first chunk";
    const uint8_t ptB[] = "second chunk";
    uint8_t ctA[128], ctB[128];
    size_t lenA = sizeof(ctA), lenB = sizeof(ctB);
    CHECK(cagoule_stream_update(enc, ptA, sizeof(ptA)-1, ctA, &lenA) == CAGOULE_STREAM_OK);
    CHECK(cagoule_stream_update(enc, ptB, sizeof(ptB)-1, ctB, &lenB) == CAGOULE_STREAM_OK);

    /* Decrypt chunk B first (out of order) — must be rejected since dec's
     * internal chunk_idx expects 0 (chunk A), not 1 (chunk B). */
    uint8_t out[128];
    size_t out_len = sizeof(out);
    int ret = cagoule_stream_decrypt(dec, ctB, lenB, out, &out_len);
    CHECK(ret != CAGOULE_STREAM_OK);

    cagoule_stream_free(enc);
    cagoule_stream_free(dec);
}

/* ── Suite 6 : wrong password rejected ───────────────────────────────── */
static void test_wrong_password_rejected(void) {
    puts("  Suite 6 : wrong password rejected");

    CagouleStreamCtx *enc = cagoule_stream_init(PASSWORD, PASSWORD_LEN, 0, 0);
    CHECK(enc != NULL);
    if (!enc) return;

    const uint8_t pt[] = "secret";
    uint8_t ct[128];
    size_t ct_len = sizeof(ct);
    CHECK(cagoule_stream_update(enc, pt, sizeof(pt)-1, ct, &ct_len) == CAGOULE_STREAM_OK);

    const uint8_t *salt = cagoule_stream_session_salt(enc);
    const uint8_t wrong_pw[] = "not_the_right_password";
    CagouleStreamCtx *dec = cagoule_stream_init_from_salt(wrong_pw, sizeof(wrong_pw)-1, salt, 0, 0);
    CHECK(dec != NULL); /* init itself succeeds — auth fails at decrypt */
    if (dec) {
        uint8_t out[128];
        size_t out_len = sizeof(out);
        int ret = cagoule_stream_decrypt(dec, ct, ct_len, out, &out_len);
        CHECK(ret == CAGOULE_STREAM_ERR_AUTH);
        cagoule_stream_free(dec);
    }

    cagoule_stream_free(enc);
}

/* ── Suite 7 : init_from_salt error paths (regression guard, P0-2) ──── */
static void test_init_from_salt_error_paths(void) {
    puts("  Suite 7 : init_from_salt error paths (P0-2 regression guard)");

    /* NULL password / NULL salt must return NULL cleanly, no crash */
    uint8_t dummy_salt[32] = {0};
    CHECK(cagoule_stream_init_from_salt(NULL, 0, dummy_salt, 0, 0) == NULL);
    CHECK(cagoule_stream_init_from_salt(PASSWORD, PASSWORD_LEN, NULL, 0, 0) == NULL);

    /* Normal success path still works after the free()->stream_free() fix */
    CagouleStreamCtx *ctx = cagoule_stream_init_from_salt(PASSWORD, PASSWORD_LEN, dummy_salt, 0, 0);
    CHECK(ctx != NULL);
    cagoule_stream_free(ctx);
}

/* ── Suite 8 : accessor / out_len helpers on NULL ctx ────────────────── */
static void test_null_ctx_helpers(void) {
    puts("  Suite 8 : NULL ctx helpers do not crash");
    CHECK(cagoule_stream_update_out_len(NULL, 100) == 0);
    CHECK(cagoule_stream_decrypt_out_len(NULL, 100) == 0);
    CHECK(cagoule_stream_session_salt(NULL) == NULL);
}

/* ── Suite 9 : exact 3-chunk session, decrypt in order ─────────────── */
static void test_three_chunk_session(void) {
    puts("  Suite 9 : 3-chunk session, encrypt then decrypt in order");

    CagouleStreamCtx *enc = cagoule_stream_init(PASSWORD, PASSWORD_LEN, 0, 0);
    CHECK(enc != NULL);
    if (!enc) return;
    const uint8_t *salt = cagoule_stream_session_salt(enc);
    CagouleStreamCtx *dec = cagoule_stream_init_from_salt(PASSWORD, PASSWORD_LEN, salt, 0, 0);
    CHECK(dec != NULL);
    if (!dec) { cagoule_stream_free(enc); return; }

    const char *plain[3] = { "first message in the session",
                              "second message, different length here",
                              "third and final chunk" };
    uint8_t ct[3][128];
    size_t  ct_len[3];
    uint8_t pt_out[3][128];
    size_t  pt_len[3];

    int all_encrypted = 1, all_decrypted = 1, all_match = 1;
    for (int i = 0; i < 3; i++) {
        size_t plen = strlen(plain[i]);
        ct_len[i] = sizeof(ct[i]);
        if (cagoule_stream_update(enc, (const uint8_t*)plain[i], plen, ct[i], &ct_len[i]) != CAGOULE_STREAM_OK)
            all_encrypted = 0;
    }
    for (int i = 0; i < 3; i++) {
        pt_len[i] = sizeof(pt_out[i]);
        if (cagoule_stream_decrypt(dec, ct[i], ct_len[i], pt_out[i], &pt_len[i]) != CAGOULE_STREAM_OK)
            all_decrypted = 0;
        if (pt_len[i] != strlen(plain[i]) || memcmp(pt_out[i], plain[i], pt_len[i]) != 0)
            all_match = 0;
    }
    CHECK(all_encrypted);
    CHECK(all_decrypted);
    CHECK(all_match);

    cagoule_stream_free(enc);
    cagoule_stream_free(dec);
}

/* ── Suite 10 : session salt -- dedicated correctness properties ────── */
static void test_session_salt_properties(void) {
    puts("  Suite 10 : session salt properties (size, freshness, correct round-trip)");

    CagouleStreamCtx *a = cagoule_stream_init(PASSWORD, PASSWORD_LEN, 0, 0);
    CagouleStreamCtx *b = cagoule_stream_init(PASSWORD, PASSWORD_LEN, 0, 0);
    CHECK(a != NULL);
    CHECK(b != NULL);
    if (!a || !b) { if (a) cagoule_stream_free(a); if (b) cagoule_stream_free(b); return; }

    const uint8_t *salt_a = cagoule_stream_session_salt(a);
    const uint8_t *salt_b = cagoule_stream_session_salt(b);
    CHECK(salt_a != NULL);
    CHECK(salt_b != NULL);

    /* Freshness: two independent init() calls (same password) must not
     * reuse the same session salt -- each session is independently keyed. */
    CHECK(memcmp(salt_a, salt_b, CAGOULE_STREAM_SESSION_SALT_SIZE) != 0);

    /* Correct round-trip: init_from_salt(salt_a) must produce a context
     * that can decrypt what session A actually encrypted -- verifying
     * the salt accessor returns the REAL salt driving derivation, not a
     * stale or placeholder copy. */
    const uint8_t plain[] = "salt round-trip verification payload";
    uint8_t ct[128];
    size_t ct_len = sizeof(ct);
    CHECK(cagoule_stream_update(a, plain, sizeof(plain)-1, ct, &ct_len) == CAGOULE_STREAM_OK);

    CagouleStreamCtx *reconstructed = cagoule_stream_init_from_salt(PASSWORD, PASSWORD_LEN, salt_a, 0, 0);
    CHECK(reconstructed != NULL);
    if (reconstructed) {
        uint8_t out[128];
        size_t out_len = sizeof(out);
        int ret = cagoule_stream_decrypt(reconstructed, ct, ct_len, out, &out_len);
        CHECK(ret == CAGOULE_STREAM_OK);
        CHECK(out_len == sizeof(plain)-1);
        CHECK(memcmp(out, plain, out_len) == 0);
        cagoule_stream_free(reconstructed);
    }

    /* Negative control: init_from_salt(salt_b) must NOT be able to
     * decrypt what session A produced -- wrong salt, wrong derived keys. */
    CagouleStreamCtx *wrong = cagoule_stream_init_from_salt(PASSWORD, PASSWORD_LEN, salt_b, 0, 0);
    CHECK(wrong != NULL);
    if (wrong) {
        uint8_t out[128];
        size_t out_len = sizeof(out);
        int ret = cagoule_stream_decrypt(wrong, ct, ct_len, out, &out_len);
        CHECK(ret != CAGOULE_STREAM_OK);
        cagoule_stream_free(wrong);
    }

    cagoule_stream_free(a);
    cagoule_stream_free(b);
}

/* ── Suite 11 : init_from_salt positive path, dedicated (not incidental) ─ */
static void test_init_from_salt_positive_path(void) {
    puts("  Suite 11 : init_from_salt positive path (fresh, caller-supplied salt)");

    /* Simulates a real deployment pattern: caller generates/stores a salt
     * independently (e.g., loaded from disk across a process restart),
     * not necessarily one that came from a prior cagoule_stream_init(). */
    uint8_t caller_salt[CAGOULE_STREAM_SESSION_SALT_SIZE];
    for (int i = 0; i < CAGOULE_STREAM_SESSION_SALT_SIZE; i++)
        caller_salt[i] = (uint8_t)(i * 7 + 3);

    CagouleStreamCtx *ctx1 = cagoule_stream_init_from_salt(PASSWORD, PASSWORD_LEN, caller_salt, 0, 0);
    CHECK(ctx1 != NULL);
    if (!ctx1) return;

    /* Determinism: init_from_salt with the SAME (password, salt) twice
     * must derive the same keys -- verified indirectly by round-tripping
     * across two independently-constructed contexts. */
    CagouleStreamCtx *ctx2 = cagoule_stream_init_from_salt(PASSWORD, PASSWORD_LEN, caller_salt, 0, 0);
    CHECK(ctx2 != NULL);
    if (ctx2) {
        const uint8_t plain[] = "deterministic derivation check";
        uint8_t ct[128];
        size_t ct_len = sizeof(ct);
        CHECK(cagoule_stream_update(ctx1, plain, sizeof(plain)-1, ct, &ct_len) == CAGOULE_STREAM_OK);

        uint8_t out[128];
        size_t out_len = sizeof(out);
        int ret = cagoule_stream_decrypt(ctx2, ct, ct_len, out, &out_len);
        CHECK(ret == CAGOULE_STREAM_OK);
        CHECK(out_len == sizeof(plain)-1);
        CHECK(memcmp(out, plain, out_len) == 0);
        cagoule_stream_free(ctx2);
    }

    /* Accessor sanity: session salt read back must equal what was supplied. */
    const uint8_t *readback = cagoule_stream_session_salt(ctx1);
    CHECK(readback != NULL);
    CHECK(memcmp(readback, caller_salt, CAGOULE_STREAM_SESSION_SALT_SIZE) == 0);

    cagoule_stream_free(ctx1);
}

/* ── Suite 12 : edge-case chunk sizes ────────────────────────────────── */
static void test_edge_case_chunk_sizes(void) {
    puts("  Suite 12 : edge-case chunk sizes (1 byte, 16 bytes, 64 KB)");

    const size_t sizes[] = { 1, 16, 65536 };
    const char *labels[] = { "1 byte", "16 bytes", "64 KB" };

    for (size_t s = 0; s < sizeof(sizes)/sizeof(sizes[0]); s++) {
        size_t n = sizes[s];
        CagouleStreamCtx *enc = cagoule_stream_init(PASSWORD, PASSWORD_LEN, 0, 0);
        CHECK(enc != NULL);
        if (!enc) continue;
        const uint8_t *salt = cagoule_stream_session_salt(enc);
        CagouleStreamCtx *dec = cagoule_stream_init_from_salt(PASSWORD, PASSWORD_LEN, salt, 0, 0);
        CHECK(dec != NULL);
        if (!dec) { cagoule_stream_free(enc); continue; }

        uint8_t *plain = malloc(n);
        CHECK(plain != NULL);
        if (!plain) { cagoule_stream_free(enc); cagoule_stream_free(dec); continue; }
        for (size_t i = 0; i < n; i++) plain[i] = (uint8_t)(i * 31 + 11);

        size_t ct_cap = cagoule_stream_update_out_len(enc, n);
        uint8_t *ct = malloc(ct_cap);
        size_t ct_len = ct_cap;
        int enc_ok = (cagoule_stream_update(enc, plain, n, ct, &ct_len) == CAGOULE_STREAM_OK);
        CHECK(enc_ok);

        size_t pt_cap = cagoule_stream_decrypt_out_len(dec, ct_len);
        uint8_t *pt_out = malloc(pt_cap);
        size_t pt_out_len = pt_cap;
        int dec_ok = enc_ok && (cagoule_stream_decrypt(dec, ct, ct_len, pt_out, &pt_out_len) == CAGOULE_STREAM_OK);
        CHECK(dec_ok);

        int match = dec_ok && pt_out_len == n && memcmp(pt_out, plain, n) == 0;
        CHECK(match);
        if (!match) fprintf(stderr, "    (chunk size %s: enc_ok=%d dec_ok=%d match=%d)\n", labels[s], enc_ok, dec_ok, match);

        free(plain); free(ct); free(pt_out);
        cagoule_stream_free(enc);
        cagoule_stream_free(dec);
    }
}

int main(void) {
    puts("=== test_stream CAGOULE v3.1.0 ===");
    test_init_free();
    test_roundtrip_single_chunk();
    test_roundtrip_multi_chunk();
    test_tamper_rejected();
    test_reorder_rejected();
    test_wrong_password_rejected();
    test_init_from_salt_error_paths();
    test_null_ctx_helpers();
    test_three_chunk_session();
    test_session_salt_properties();
    test_init_from_salt_positive_path();
    test_edge_case_chunk_sizes();
    printf("\n=== %ld passés / %ld échoués ===\n", g_pass, g_fail);
    return g_fail != 0;
}
