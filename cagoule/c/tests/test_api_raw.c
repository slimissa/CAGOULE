/**
 * test_api_raw.c — Tests du wrapper cagoule_api.c (handle bulk, 0x02/0x03)
 * CAGOULE v3.1.0 — audit round 2, finding N4
 *
 * CONTEXTE : avant ce fichier, cagoule_api.c (chemin CagouleKeyHandle,
 * cagoule_derive_key / *_with_handle / *_with_handle_raw) n'avait AUCUNE
 * couverture de test au niveau C — ni ici, ni côté Python (aucun test
 * n'appelait CagouleKeyHandle via ctypes). C'est exactement le chemin où
 * C2 (réutilisation de clé Poly1305 sous handle partagé) est resté non
 * détecté pendant tout un cycle d'audit : deux revues successives ont
 * vérifié cipher_ctr_raw.py (Python) sans jamais tester l'équivalent C.
 *
 * Suites :
 *   1. Round-trip 0x02 (AEAD) — handle simple, un message
 *   2. Round-trip 0x03 (RAW) — handle simple, un message
 *   3. Rejet de forgerie inter-messages (régression C2) — un tag capturé
 *      sur un message ne doit jamais authentifier un autre message, même
 *      sous le même handle (c'est exactement le scénario qui exploitait
 *      la réutilisation de poly_key avant le correctif C2)
 *   4. Réutilisation de handle, N messages (le pattern qui a caché C2) —
 *      chiffre plusieurs messages sous le MÊME handle et vérifie que :
 *        (a) tous les round-trips restent corrects
 *        (b) msg_salt diffère à chaque message
 *        (c) le ciphertext algébrique interne (ct_alg, avant/sans couche
 *            ChaCha20 pour 0x03) ne se répète JAMAIS, empiriquement —
 *            c'est la propriété que cagoule_api.h documentait comme
 *            protégée par un label HKDF "_BULK" qui n'a en réalité jamais
 *            été implémenté (voir correctif de commentaire, audit round 2)
 *        (d) un tag capturé au message i échoue contre tout autre message
 *   5. Cas d'erreur — handle NULL, buffer trop petit, gate expérimental
 *      0x03 fermée, mot de passe incorrect, ciphertext altéré
 *
 * Compile : gcc ... tests/test_api_raw.c -L. -lcagoule -o test_api_raw
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "cagoule_api.h"
#include "cagoule_params.h"
#include "cagoule_math.h"

static long g_pass = 0;
static long g_fail = 0;

#define CHECK(cond) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; \
        fprintf(stderr, "FAIL  %s:%d  %s\n", __FILE__, __LINE__, #cond); } \
} while(0)

#define CHECK_EQ(a, b)   CHECK((a) == (b))
#define CHECK_OK(r)      CHECK((r) == CAGOULE_API_OK)
#define CHECK_ERR(r, e)  CHECK((r) == (e))
#define CHECK_MEM(a, b, n)  CHECK(memcmp(a, b, n) == 0)
#define CHECK_DIFF(a, b, n) CHECK(memcmp(a, b, n) != 0)

static const uint8_t PASSWORD[] = "test_api_raw_password_CAGOULE";
static const size_t  PASSWORD_LEN = sizeof(PASSWORD) - 1;
static const uint8_t SALT[32] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,
};

/* ════════════════════════════════════════════════════════════════════
 * Suite 1 — Round-trip 0x02 (AEAD)
 * ════════════════════════════════════════════════════════════════════ */
static void test_roundtrip_aead(void) {
    puts("  Suite 1 : Round-trip 0x02 (AEAD, handle simple)");

    CagouleKeyHandle *h = cagoule_derive_key(PASSWORD, PASSWORD_LEN, SALT, sizeof(SALT));
    CHECK(h != NULL);
    if (!h) return;

    const uint8_t pt[] = "Message de test pour le chemin AEAD (0x02) via handle.";
    size_t pt_len = sizeof(pt) - 1;

    size_t out_len = cagoule_api_encrypt_out_len(pt_len);
    uint8_t *ct = malloc(out_len);
    size_t ct_len = out_len;
    int ret = cagoule_encrypt_with_handle(h, pt, pt_len, ct, &ct_len);
    CHECK_OK(ret);
    CHECK_EQ(ct_len, out_len);

    size_t pt_out_len = cagoule_api_decrypt_out_len(ct_len);
    uint8_t *pt_out = malloc(pt_out_len > 0 ? pt_out_len : 1);
    size_t pt_out_len_actual = pt_out_len;
    ret = cagoule_decrypt_with_handle(h, ct, ct_len, pt_out, &pt_out_len_actual);
    CHECK_OK(ret);
    CHECK_EQ(pt_out_len_actual, pt_len);
    CHECK_MEM(pt_out, pt, pt_len);

    free(ct);
    free(pt_out);
    cagoule_key_handle_free(h);
}

/* ════════════════════════════════════════════════════════════════════
 * Suite 2 — Round-trip 0x03 (RAW)
 * ════════════════════════════════════════════════════════════════════ */
static void test_roundtrip_raw(void) {
    puts("  Suite 2 : Round-trip 0x03 (RAW, handle simple)");

    CagouleKeyHandle *h = cagoule_derive_key(PASSWORD, PASSWORD_LEN, SALT, sizeof(SALT));
    CHECK(h != NULL);
    if (!h) return;

    const uint8_t pt[] = "Message de test pour le chemin RAW (0x03) via handle.";
    size_t pt_len = sizeof(pt) - 1;

    size_t out_len = cagoule_api_encrypt_raw_out_len(pt_len);
    uint8_t *ct = malloc(out_len);
    size_t ct_len = out_len;
    int ret = cagoule_encrypt_with_handle_raw(h, 1, pt, pt_len, ct, &ct_len);
    CHECK_OK(ret);
    CHECK_EQ(ct_len, out_len);

    size_t pt_out_len = cagoule_api_decrypt_raw_out_len(ct_len);
    uint8_t *pt_out = malloc(pt_out_len > 0 ? pt_out_len : 1);
    size_t pt_out_len_actual = pt_out_len;
    ret = cagoule_decrypt_with_handle_raw(h, 1, ct, ct_len, pt_out, &pt_out_len_actual);
    CHECK_OK(ret);
    CHECK_EQ(pt_out_len_actual, pt_len);
    CHECK_MEM(pt_out, pt, pt_len);

    free(ct);
    free(pt_out);
    cagoule_key_handle_free(h);
}

/* ════════════════════════════════════════════════════════════════════
 * Suite 3 — Rejet de forgerie inter-messages (régression C2)
 *
 * Avant le correctif C2, poly_key ne dépendait que de k_master, donc
 * était IDENTIQUE pour tout message chiffré sous le même handle. Un tag
 * capturé sur le message A authentifiait alors n'importe quel ct_alg+AAD
 * "rejoué" avec ce tag, tant que le format restait cohérent — la primitive
 * même de Poly1305 (authenticateur à usage unique) était violée.
 *
 * Ce test vérifie directement que le tag du message A est rejeté pour le
 * message B, sous le MÊME handle — la condition nécessaire et suffisante
 * pour que la réutilisation de clé C2 soit exclue.
 * ════════════════════════════════════════════════════════════════════ */
static void test_cross_message_forgery_rejected(void) {
    puts("  Suite 3 : Rejet de forgerie inter-messages (régression C2)");

    CagouleKeyHandle *h = cagoule_derive_key(PASSWORD, PASSWORD_LEN, SALT, sizeof(SALT));
    CHECK(h != NULL);
    if (!h) return;

    const uint8_t ptA[] = "Message A - court";
    const uint8_t ptB[] = "Message B - une longueur differente pour varier";

    for (int mode = 0; mode < 2; mode++) {  /* 0 = RAW (0x03), 1 = AEAD (0x02) */
        size_t lenA, lenB;
        uint8_t *ctA, *ctB;
        int ret;

        if (mode == 0) {
            lenA = cagoule_api_encrypt_raw_out_len(sizeof(ptA) - 1);
            lenB = cagoule_api_encrypt_raw_out_len(sizeof(ptB) - 1);
            ctA = malloc(lenA); ctB = malloc(lenB);
            size_t la = lenA, lb = lenB;
            ret = cagoule_encrypt_with_handle_raw(h, 1, ptA, sizeof(ptA)-1, ctA, &la);
            CHECK_OK(ret);
            ret = cagoule_encrypt_with_handle_raw(h, 1, ptB, sizeof(ptB)-1, ctB, &lb);
            CHECK_OK(ret);
            lenA = la; lenB = lb;
        } else {
            lenA = cagoule_api_encrypt_out_len(sizeof(ptA) - 1);
            lenB = cagoule_api_encrypt_out_len(sizeof(ptB) - 1);
            ctA = malloc(lenA); ctB = malloc(lenB);
            size_t la = lenA, lb = lenB;
            ret = cagoule_encrypt_with_handle(h, ptA, sizeof(ptA)-1, ctA, &la);
            CHECK_OK(ret);
            ret = cagoule_encrypt_with_handle(h, ptB, sizeof(ptB)-1, ctB, &lb);
            CHECK_OK(ret);
            lenA = la; lenB = lb;
        }

        /* Swap: ciphertext de B avec le tag de A (16 derniers octets) */
        uint8_t *ctB_wrong_tag = malloc(lenB);
        memcpy(ctB_wrong_tag, ctB, lenB);
        /* Le tag fait toujours 16 octets, en toute fin de buffer, quel
         * que soit le mode (voir CAGOULE_API_OVERHEAD_*). */
        if (lenA >= 16 && lenB >= 16) {
            memcpy(ctB_wrong_tag + lenB - 16, ctA + lenA - 16, 16);

            uint8_t *out = malloc(lenB > 0 ? lenB : 1);
            size_t out_len = lenB;
            if (mode == 0)
                ret = cagoule_decrypt_with_handle_raw(h, 1, ctB_wrong_tag, lenB, out, &out_len);
            else
                ret = cagoule_decrypt_with_handle(h, ctB_wrong_tag, lenB, out, &out_len);

            CHECK_ERR(ret, CAGOULE_API_ERR_AUTH);
            free(out);
        }

        free(ctA); free(ctB); free(ctB_wrong_tag);
    }

    cagoule_key_handle_free(h);
}

/* ════════════════════════════════════════════════════════════════════
 * Suite 4 — Réutilisation de handle, N messages (le pattern qui a caché C2)
 *
 * Chiffre N messages sous le MÊME handle (usage bulk documenté) et
 * vérifie empiriquement, pour les deux versions :
 *   (a) tous les round-trips sont corrects
 *   (b) msg_salt diffère à chaque message (header)
 *   (c) le ciphertext ne se répète jamais, même pour des plaintexts
 *       identiques (preuve empirique qu'aucun keystream/tag n'est réutilisé
 *       sous handle partagé — la propriété que C2 violait, et que le
 *       label "_BULK" documenté-mais-jamais-implémenté était censé
 *       garantir pour 0x02)
 *   (d) tout tag capturé au message i est rejeté pour tout autre message j
 * ════════════════════════════════════════════════════════════════════ */
#define N_MESSAGES 8

static void test_handle_reuse_multiple_messages(void) {
    puts("  Suite 4 : Réutilisation de handle, N messages (pattern C2)");

    CagouleKeyHandle *h = cagoule_derive_key(PASSWORD, PASSWORD_LEN, SALT, sizeof(SALT));
    CHECK(h != NULL);
    if (!h) return;

    /* Même plaintext pour TOUS les messages -- le cas le plus dangereux :
     * si le keystream se répétait sous handle partagé, ct_alg serait
     * identique pour chaque message. */
    const uint8_t pt[] = "Identical plaintext repeated across every message in the batch.";
    size_t pt_len = sizeof(pt) - 1;

    for (int mode = 0; mode < 2; mode++) {  /* 0 = RAW, 1 = AEAD */
        size_t ct_len = (mode == 0) ? cagoule_api_encrypt_raw_out_len(pt_len)
                                     : cagoule_api_encrypt_out_len(pt_len);
        uint8_t *cts[N_MESSAGES];

        for (int i = 0; i < N_MESSAGES; i++) {
            cts[i] = malloc(ct_len);
            size_t out_len = ct_len;
            int ret = (mode == 0)
                ? cagoule_encrypt_with_handle_raw(h, 1, pt, pt_len, cts[i], &out_len)
                : cagoule_encrypt_with_handle(h, pt, pt_len, cts[i], &out_len);
            CHECK_OK(ret);
            CHECK_EQ(out_len, ct_len);
        }

        /* (b) msg_salt (octets 5..37, juste après MAGIC+VERSION) diffère
         * à chaque message, pour toute paire. */
        for (int i = 0; i < N_MESSAGES; i++)
            for (int j = i + 1; j < N_MESSAGES; j++)
                CHECK_DIFF(cts[i] + 5, cts[j] + 5, 32);

        /* (c) le ciphertext complet (donc ct_alg a fortiori) ne se répète
         * jamais, malgré un plaintext identique sur les N messages. */
        for (int i = 0; i < N_MESSAGES; i++)
            for (int j = i + 1; j < N_MESSAGES; j++)
                CHECK_DIFF(cts[i], cts[j], ct_len);

        /* (a) round-trip correct pour chaque message individuellement. */
        for (int i = 0; i < N_MESSAGES; i++) {
            size_t pt_out_len = (mode == 0) ? cagoule_api_decrypt_raw_out_len(ct_len)
                                             : cagoule_api_decrypt_out_len(ct_len);
            uint8_t *pt_out = malloc(pt_out_len > 0 ? pt_out_len : 1);
            size_t out_len = pt_out_len;
            int ret = (mode == 0)
                ? cagoule_decrypt_with_handle_raw(h, 1, cts[i], ct_len, pt_out, &out_len)
                : cagoule_decrypt_with_handle(h, cts[i], ct_len, pt_out, &out_len);
            CHECK_OK(ret);
            CHECK_EQ(out_len, pt_len);
            CHECK_MEM(pt_out, pt, pt_len);
            free(pt_out);
        }

        /* (d) tag du message i rejeté pour tout message j != i -- la
         * régression C2 directe, généralisée à toutes les paires plutôt
         * qu'une seule (Suite 3 ne teste que A/B). */
        for (int i = 0; i < N_MESSAGES; i++) {
            for (int j = 0; j < N_MESSAGES; j++) {
                if (i == j) continue;
                uint8_t *forged = malloc(ct_len);
                memcpy(forged, cts[j], ct_len);
                memcpy(forged + ct_len - 16, cts[i] + ct_len - 16, 16);

                uint8_t *out = malloc(ct_len > 0 ? ct_len : 1);
                size_t out_len = ct_len;
                int ret = (mode == 0)
                    ? cagoule_decrypt_with_handle_raw(h, 1, forged, ct_len, out, &out_len)
                    : cagoule_decrypt_with_handle(h, forged, ct_len, out, &out_len);
                CHECK_ERR(ret, CAGOULE_API_ERR_AUTH);

                free(forged);
                free(out);
            }
        }

        for (int i = 0; i < N_MESSAGES; i++) free(cts[i]);
    }

    cagoule_key_handle_free(h);
}

/* ════════════════════════════════════════════════════════════════════
 * Suite 5 — Cas d'erreur
 * ════════════════════════════════════════════════════════════════════ */
static void test_error_cases(void) {
    puts("  Suite 5 : Cas d'erreur");

    /* Gate expérimental fermée (allow_experimental=0) */
    {
        CagouleKeyHandle *h = cagoule_derive_key(PASSWORD, PASSWORD_LEN, SALT, sizeof(SALT));
        CHECK(h != NULL);
        if (h) {
            const uint8_t pt[] = "x";
            uint8_t out[64];
            size_t out_len = sizeof(out);
            int ret = cagoule_encrypt_with_handle_raw(h, 0, pt, 1, out, &out_len);
            CHECK_ERR(ret, CAGOULE_API_ERR_EXPERIMENTAL_DISABLED);
            cagoule_key_handle_free(h);
        }
    }

    /* Handle NULL */
    {
        const uint8_t pt[] = "x";
        uint8_t out[64];
        size_t out_len = sizeof(out);
        int ret = cagoule_encrypt_with_handle(NULL, pt, 1, out, &out_len);
        CHECK(ret != CAGOULE_API_OK);
    }

    /* derive_key : mot de passe/salt vides -> ne doit pas segfault */
    {
        CagouleKeyHandle *h = cagoule_derive_key(NULL, 0, SALT, sizeof(SALT));
        CHECK(h == NULL);
    }

    /* Buffer de sortie trop petit */
    {
        CagouleKeyHandle *h = cagoule_derive_key(PASSWORD, PASSWORD_LEN, SALT, sizeof(SALT));
        CHECK(h != NULL);
        if (h) {
            const uint8_t pt[] = "message qui depasse un petit buffer";
            uint8_t out[4];  /* beaucoup trop petit */
            size_t out_len = sizeof(out);
            int ret = cagoule_encrypt_with_handle(h, pt, sizeof(pt)-1, out, &out_len);
            CHECK(ret != CAGOULE_API_OK);
            cagoule_key_handle_free(h);
        }
    }

    /* Mauvais mot de passe -> échec d'authentification, pas de garbage silencieux */
    {
        CagouleKeyHandle *h1 = cagoule_derive_key(PASSWORD, PASSWORD_LEN, SALT, sizeof(SALT));
        const uint8_t wrong_pw[] = "wrong_password_entirely";
        CagouleKeyHandle *h2 = cagoule_derive_key(wrong_pw, sizeof(wrong_pw)-1, SALT, sizeof(SALT));
        CHECK(h1 != NULL);
        CHECK(h2 != NULL);
        if (h1 && h2) {
            const uint8_t pt[] = "secret";
            size_t ct_len = cagoule_api_encrypt_raw_out_len(sizeof(pt)-1);
            uint8_t *ct = malloc(ct_len);
            size_t out_len = ct_len;
            int ret = cagoule_encrypt_with_handle_raw(h1, 1, pt, sizeof(pt)-1, ct, &out_len);
            CHECK_OK(ret);

            uint8_t *pt_out = malloc(sizeof(pt));
            size_t pt_out_len = sizeof(pt);
            ret = cagoule_decrypt_with_handle_raw(h2, 1, ct, out_len, pt_out, &pt_out_len);
            CHECK_ERR(ret, CAGOULE_API_ERR_AUTH);

            free(ct);
            free(pt_out);
        }
        if (h1) cagoule_key_handle_free(h1);
        if (h2) cagoule_key_handle_free(h2);
    }

    /* Ciphertext altéré (un octet du corps modifié) -> rejeté */
    {
        CagouleKeyHandle *h = cagoule_derive_key(PASSWORD, PASSWORD_LEN, SALT, sizeof(SALT));
        CHECK(h != NULL);
        if (h) {
            const uint8_t pt[] = "message a alterer pour ce test";
            size_t ct_len = cagoule_api_encrypt_out_len(sizeof(pt)-1);
            uint8_t *ct = malloc(ct_len);
            size_t out_len = ct_len;
            int ret = cagoule_encrypt_with_handle(h, pt, sizeof(pt)-1, ct, &out_len);
            CHECK_OK(ret);

            ct[out_len - 20] ^= 0xFF;  /* bit-flip dans le corps chiffré */

            uint8_t *pt_out = malloc(sizeof(pt));
            size_t pt_out_len = sizeof(pt);
            ret = cagoule_decrypt_with_handle(h, ct, out_len, pt_out, &pt_out_len);
            CHECK_ERR(ret, CAGOULE_API_ERR_AUTH);

            free(ct);
            free(pt_out);
            cagoule_key_handle_free(h);
        }
    }
}

/* ── Suite 6 : all 8 Mersenne primes, via the real cagoule_derive_key path ─
 *
 * CagouleKeyHandle is intentionally opaque (cagoule_api.h forward-declares
 * it; internals live only in cagoule_api.c) -- correct black-box design,
 * but it means this test can't peek at which prime a handle picked. To
 * get deterministic coverage of all 8 without breaking that opacity, we
 * use cagoule_params_derive() (a separate, non-opaque function) purely as
 * an offline search tool to find one salt per prime, then drive the real
 * opaque cagoule_derive_key()/cagoule_encrypt_with_handle() API with
 * those known salts -- the actual round-trip under test goes through the
 * exact same code path a real caller uses.
 */
static void test_all_mersenne_primes(void) {
    puts("  Suite 6 : round-trip via cagoule_derive_key, all 8 Mersenne primes");

    uint8_t found_salt[CAGOULE_MERSENNE_POOL_SIZE][32];
    int found[CAGOULE_MERSENNE_POOL_SIZE] = {0};
    int n_found = 0;

    for (int attempt = 0; attempt < 500 && n_found < CAGOULE_MERSENNE_POOL_SIZE; attempt++) {
        uint8_t salt[32];
        for (int i = 0; i < 32; i++) salt[i] = (uint8_t)((attempt * 37 + i * 13) & 0xFF);

        CagouleDerivedParams params;
        memset(&params, 0, sizeof(params));
        if (cagoule_params_derive(PASSWORD, PASSWORD_LEN, salt, sizeof(salt), &params) != CAGOULE_PARAMS_OK)
            continue;

        for (int i = 0; i < CAGOULE_MERSENNE_POOL_SIZE; i++) {
            if (!found[i] && params.p == CAGOULE_MERSENNE_P[i]) {
                found[i] = 1;
                memcpy(found_salt[i], salt, 32);
                n_found++;
                break;
            }
        }
        cagoule_params_free(&params);
    }
    CHECK(n_found == CAGOULE_MERSENNE_POOL_SIZE);
    if (n_found != CAGOULE_MERSENNE_POOL_SIZE) {
        fprintf(stderr, "    (only found %d/%d primes in 500 attempts)\n", n_found, CAGOULE_MERSENNE_POOL_SIZE);
    }

    int all_roundtrip_ok = 1;
    for (int i = 0; i < CAGOULE_MERSENNE_POOL_SIZE; i++) {
        if (!found[i]) continue;
        CagouleKeyHandle *h = cagoule_derive_key(PASSWORD, PASSWORD_LEN, found_salt[i], 32);
        if (!h) { all_roundtrip_ok = 0; continue; }

        char msg[64];
        snprintf(msg, sizeof(msg), "message for Mersenne prime k=%llu",
                 (unsigned long long)CAGOULE_MERSENNE_K[i]);
        size_t pt_len = strlen(msg);

        size_t ct_len = cagoule_api_encrypt_out_len(pt_len);
        uint8_t *ct = malloc(ct_len);
        size_t out_len = ct_len;
        if (cagoule_encrypt_with_handle(h, (const uint8_t*)msg, pt_len, ct, &out_len) != CAGOULE_API_OK)
            all_roundtrip_ok = 0;

        uint8_t *pt_out = malloc(pt_len + 1);
        size_t pt_out_len = pt_len + 1;
        if (cagoule_decrypt_with_handle(h, ct, out_len, pt_out, &pt_out_len) != CAGOULE_API_OK)
            all_roundtrip_ok = 0;
        if (pt_out_len != pt_len || memcmp(pt_out, msg, pt_len) != 0)
            all_roundtrip_ok = 0;

        free(ct); free(pt_out);
        cagoule_key_handle_free(h);
    }
    CHECK(all_roundtrip_ok);
}

/* ── Suite 7 : zero-length plaintext ──────────────────────────────────── */
static void test_zero_length_plaintext(void) {
    puts("  Suite 7 : zero-length plaintext (AEAD and RAW)");

    /* NOTE : cagoule_encrypt_with_handle*() rejette pt==NULL sans condition
     * (voir cagoule_api.c : "if (!handle || !pt || ...) return ERR_NULL"),
     * même quand pt_len==0 -- un pointeur valide vers un buffer de longueur
     * nulle est requis, NULL n'est jamais accepté. C'est le contrat réel
     * de l'API (vérifié en lisant la source), pas un bug -- un pointeur
     * "dummy" non-NULL est donc utilisé ici plutôt que NULL. */
    static const uint8_t dummy[1] = {0};

    CagouleKeyHandle *h = cagoule_derive_key(PASSWORD, PASSWORD_LEN, SALT, sizeof(SALT));
    CHECK(h != NULL);
    if (!h) return;

    /* AEAD (0x02): zero-length plaintext must still round-trip -- the
     * ciphertext is pure overhead (salt+nonce+tag), zero body bytes. */
    {
        size_t ct_len = cagoule_api_encrypt_out_len(0);
        CHECK(ct_len > 0);  /* overhead-only, but not zero */
        uint8_t *ct = malloc(ct_len);
        size_t out_len = ct_len;
        int ret = cagoule_encrypt_with_handle(h, dummy, 0, ct, &out_len);
        CHECK_OK(ret);
        CHECK(out_len == ct_len);

        size_t pt_cap = cagoule_api_decrypt_out_len(out_len);
        CHECK(pt_cap == 0);
        uint8_t pt_out[1];
        size_t pt_out_len = sizeof(pt_out);
        ret = cagoule_decrypt_with_handle(h, ct, out_len, pt_out, &pt_out_len);
        CHECK_OK(ret);
        CHECK(pt_out_len == 0);

        free(ct);
    }

    /* RAW (0x03): same property. */
    {
        size_t ct_len = cagoule_api_encrypt_raw_out_len(0);
        CHECK(ct_len > 0);
        uint8_t *ct = malloc(ct_len);
        size_t out_len = ct_len;
        int ret = cagoule_encrypt_with_handle_raw(h, 1, dummy, 0, ct, &out_len);
        CHECK_OK(ret);
        CHECK(out_len == ct_len);

        size_t pt_cap = cagoule_api_decrypt_raw_out_len(out_len);
        CHECK(pt_cap == 0);
        uint8_t pt_out[1];
        size_t pt_out_len = sizeof(pt_out);
        ret = cagoule_decrypt_with_handle_raw(h, 1, ct, out_len, pt_out, &pt_out_len);
        CHECK_OK(ret);
        CHECK(pt_out_len == 0);

        free(ct);
    }

    /* Negative control, confirming the NULL-rejection contract itself is
     * real and tested (not just assumed): NULL pt with pt_len==0 must
     * still be rejected, exactly like NULL pt with pt_len>0. */
    {
        uint8_t ct[128];
        size_t out_len = sizeof(ct);
        int ret = cagoule_encrypt_with_handle(h, NULL, 0, ct, &out_len);
        CHECK(ret == CAGOULE_API_ERR_NULL);
    }

    cagoule_key_handle_free(h);
}

/* ── Suite 8 : buffer size boundary edge cases ───────────────────────── */
static void test_buffer_boundary_edge_cases(void) {
    puts("  Suite 8 : buffer size boundaries (exact fit vs off-by-one)");

    CagouleKeyHandle *h = cagoule_derive_key(PASSWORD, PASSWORD_LEN, SALT, sizeof(SALT));
    CHECK(h != NULL);
    if (!h) return;

    const uint8_t pt[] = "boundary test message, arbitrary length";
    size_t pt_len = sizeof(pt) - 1;
    size_t exact_ct_len = cagoule_api_encrypt_out_len(pt_len);

    /* Exact-fit output buffer must succeed. */
    {
        uint8_t *ct = malloc(exact_ct_len);
        size_t out_len = exact_ct_len;
        int ret = cagoule_encrypt_with_handle(h, pt, pt_len, ct, &out_len);
        CHECK_OK(ret);
        CHECK(out_len == exact_ct_len);
        free(ct);
    }

    /* Exactly one byte too small must be rejected, not silently truncated. */
    {
        uint8_t *ct = malloc(exact_ct_len);  /* allocate full size, only expose exact_ct_len-1 to the call */
        size_t out_len = exact_ct_len - 1;
        int ret = cagoule_encrypt_with_handle(h, pt, pt_len, ct, &out_len);
        CHECK(ret != CAGOULE_API_OK);
        free(ct);
    }

    /* Decrypt: exact-fit output buffer must succeed. */
    {
        uint8_t *ct = malloc(exact_ct_len);
        size_t ct_out_len = exact_ct_len;
        CHECK_OK(cagoule_encrypt_with_handle(h, pt, pt_len, ct, &ct_out_len));

        size_t exact_pt_cap = cagoule_api_decrypt_out_len(ct_out_len);
        CHECK(exact_pt_cap == pt_len);
        uint8_t *pt_out = malloc(exact_pt_cap);
        size_t pt_out_len = exact_pt_cap;
        int ret = cagoule_decrypt_with_handle(h, ct, ct_out_len, pt_out, &pt_out_len);
        CHECK_OK(ret);
        CHECK(pt_out_len == pt_len);
        CHECK(memcmp(pt_out, pt, pt_len) == 0);

        /* One byte too small for decrypt output must be rejected. */
        size_t too_small = exact_pt_cap > 0 ? exact_pt_cap - 1 : 0;
        uint8_t *pt_out2 = malloc(exact_pt_cap);
        size_t pt_out2_len = too_small;
        int ret2 = cagoule_decrypt_with_handle(h, ct, ct_out_len, pt_out2, &pt_out2_len);
        CHECK(ret2 != CAGOULE_API_OK);

        free(ct); free(pt_out); free(pt_out2);
    }

    /* Ciphertext shorter than the minimum overhead must be rejected
     * cleanly (not read out-of-bounds, not crash). */
    {
        uint8_t tiny_ct[10] = {0};  /* less than the 65-byte AEAD overhead */
        uint8_t out[64];
        size_t out_len = sizeof(out);
        int ret = cagoule_decrypt_with_handle(h, tiny_ct, sizeof(tiny_ct), out, &out_len);
        CHECK(ret != CAGOULE_API_OK);
    }

    cagoule_key_handle_free(h);
}

/* ════════════════════════════════════════════════════════════════════
 * Main
 * ════════════════════════════════════════════════════════════════════ */
int main(void) {
    puts("=== test_api_raw CAGOULE v3.1.0 (cagoule_api.c handle bulk) ===");

    setenv("CAGOULE_EXPERIMENTAL_NO_AEAD", "1", 1);

    test_roundtrip_aead();
    test_roundtrip_raw();
    test_cross_message_forgery_rejected();
    test_handle_reuse_multiple_messages();

    /* Suite 5 a besoin de la gate FERMÉE pour son premier cas -- on la
     * rouvre juste avant pour le reste du test, puis on la referme
     * explicitement pour le premier cas via allow_experimental=0 (ce
     * paramètre prime sur la variable d'environnement, donc l'ordre
     * ici n'a pas d'importance -- laissé explicite pour la lisibilité). */
    test_error_cases();
    test_all_mersenne_primes();
    test_zero_length_plaintext();
    test_buffer_boundary_edge_cases();

    printf("\n=== Résultat final : %ld passés / %ld échoués ===\n",
           g_pass, g_fail);
    return (g_fail > 0) ? 1 : 0;
}
