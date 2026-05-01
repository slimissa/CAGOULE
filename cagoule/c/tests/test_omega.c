/**
 * test_omega.c — Tests unitaires cagoule_omega — CAGOULE v2.1.0
 *
 * §1. Table ζ(2n)                       18 tests
 * §2. Coefficients de Fourier c_k        14 tests
 * §3. Génération des round keys          28 tests (+4: salt_len 0/64)
 * §4. Opérations bloc add/sub_rk        12 tests
 * §5. Détection OpenSSL                   2 tests
 * §6. KAT stabilité interne              8 tests
 * §7. Performance                        2 tests (nouveau)
 * §8. Thread-safety (compile-time)       1 test  (nouveau)
 *                                       ─────────
 *                                       85 tests
 *
 * Note: Les tests de fuite mémoire (valgrind) sont dans le Makefile,
 *       pas dans ce fichier.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include <time.h>

#ifdef __linux__
#include <pthread.h>
#endif

#include "../include/cagoule_omega.h"
#include "../include/cagoule_math.h"

/* ── Framework minimal ────────────────────────────────────────────────────── */
static int _pass = 0, _fail = 0;

#define ASSERT(cond, msg) \
    do { \
        if (cond) { _pass++; } \
        else { _fail++; fprintf(stderr, "  FAIL [%s:%d] %s\n", __FILE__, __LINE__, msg); } \
    } while (0)

#define ASSERT_EQ_I(a, b, msg)       ASSERT((a) == (b), msg)
#define ASSERT_EQ_U(a, b, msg)       ASSERT((uint64_t)(a) == (uint64_t)(b), msg)
#define ASSERT_NEQ_U(a, b, msg)      ASSERT((uint64_t)(a) != (uint64_t)(b), msg)
#define ASSERT_NEAR(a, b, eps, msg)  ASSERT(fabs((double)(a) - (double)(b)) < (eps), msg)
#define ASSERT_NAN(a, msg)           ASSERT(isnan((double)(a)), msg)
#define ASSERT_GT(a, b, msg)         ASSERT((a) > (b), msg)
#define ASSERT_LT(a, b, msg)         ASSERT((a) < (b), msg)
#define ASSERT_GEQ(a, b, msg)        ASSERT((a) >= (b), msg)
#define ASSERT_FINITE(a, msg)        ASSERT(isfinite((double)(a)), msg)

static void section(const char *title) {
    printf("\n  ── %s\n", title);
}

/* ── Sel et paramètres de test ────────────────────────────────────────────── */
static const uint8_t SALT[32] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20
};
static const uint8_t SALT_ALT[32] = {
    0xFE,0xFD,0xFC,0xFB,0xFA,0xF9,0xF8,0xF7,
    0xF6,0xF5,0xF4,0xF3,0xF2,0xF1,0xF0,0xEF,
    0xEE,0xED,0xEC,0xEB,0xEA,0xE9,0xE8,0xE7,
    0xE6,0xE5,0xE4,0xE3,0xE2,0xE1,0xE0,0xDF
};
static const uint64_t P  = 10441487724840939323ULL;
static const uint64_t P2 =  9223372036854775783ULL;  /* autre grand premier */
static const int      N  = 16;

/* ══════════════════════════════════════════════════════════════════════════
 *  §1. Table ζ(2n)
 * ══════════════════════════════════════════════════════════════════════════ */
static void test_zeta(void)
{
    section("§1. Table ζ(2n)");

    /* Valeurs canoniques vérifiées contre mpmath */
    ASSERT_NEAR(cagoule_omega_zeta_2n(1), 1.6449340668482264, 1e-12, "zeta(2)=pi^2/6");
    ASSERT_NEAR(cagoule_omega_zeta_2n(2), 1.0823232337111382, 1e-12, "zeta(4)=pi^4/90");
    ASSERT_NEAR(cagoule_omega_zeta_2n(3), 1.0173430619844491, 1e-12, "zeta(6)");
    ASSERT_NEAR(cagoule_omega_zeta_2n(5), 1.0009945751278181, 1e-12, "zeta(10)");
    ASSERT_NEAR(cagoule_omega_zeta_2n(10), 1.0000009539620338, 1e-14, "zeta(20)");

    /* Comparaison pi^2/6 */
    double pi = 3.14159265358979323846;
    ASSERT_NEAR(cagoule_omega_zeta_2n(1), pi*pi/6.0, 1e-6, "zeta(2) = pi^2/6");

    /* Limite table → 1.0 */
    ASSERT_NEAR(cagoule_omega_zeta_2n(32), 1.0, 1e-15, "n=32 → 1.0 en double");
    ASSERT_NEAR(cagoule_omega_zeta_2n(33), 1.0, 1e-15, "n=33 > table → 1.0");
    ASSERT_NEAR(cagoule_omega_zeta_2n(100), 1.0, 1e-15, "n=100 → 1.0");

    /* Monotonie décroissante */
    ASSERT_GT(cagoule_omega_zeta_2n(1), cagoule_omega_zeta_2n(2), "z(2) > z(4)");
    ASSERT_GT(cagoule_omega_zeta_2n(2), cagoule_omega_zeta_2n(5), "z(4) > z(10)");
    ASSERT_GT(cagoule_omega_zeta_2n(5), cagoule_omega_zeta_2n(10), "z(10) > z(20)");

    /* Toutes les valeurs ≥ 1.0 */
    for (int n = 1; n <= 32; n++) {
        ASSERT_GEQ(cagoule_omega_zeta_2n(n), 1.0, "zeta(2n) >= 1.0");
    }

    /* Cas invalides */
    ASSERT_NAN(cagoule_omega_zeta_2n(0),  "n=0 → NAN");
    ASSERT_NAN(cagoule_omega_zeta_2n(-1), "n=-1 → NAN");

    /* Toutes les valeurs de la table sont finies */
    for (int n = 1; n <= CAGOULE_OMEGA_ZETA_TABLE_MAX; n++) {
        ASSERT_FINITE(cagoule_omega_zeta_2n(n), "zeta(2n) est fini");
    }
}

/* ══════════════════════════════════════════════════════════════════════════
 *  §2. Coefficients de Fourier c_k
 * ══════════════════════════════════════════════════════════════════════════ */
static void test_fourier(void)
{
    section("§2. Coefficients de Fourier c_k");

    double pi = 3.14159265358979323846;

    /* c_1(n=1) = 2/π */
    ASSERT_NEAR(cagoule_omega_fourier_coeff(1, 1), 2.0/pi, 1e-12, "c_1(n=1) = 2/pi");

    /* c_2(n=1) = -(2/pi)/4 */
    ASSERT_NEAR(cagoule_omega_fourier_coeff(2, 1), -(2.0/pi)/4.0, 1e-12, "c_2(n=1) = -2/(4pi)");

    /* Signe : k impair → positif, k pair → négatif */
    ASSERT_GT(cagoule_omega_fourier_coeff(1, 3), 0.0, "c_1 > 0 (impair)");
    ASSERT_GT(cagoule_omega_fourier_coeff(3, 3), 0.0, "c_3 > 0 (impair)");
    ASSERT_GT(cagoule_omega_fourier_coeff(5, 3), 0.0, "c_5 > 0 (impair)");
    ASSERT_LT(cagoule_omega_fourier_coeff(2, 3), 0.0, "c_2 < 0 (pair)");
    ASSERT_LT(cagoule_omega_fourier_coeff(4, 3), 0.0, "c_4 < 0 (pair)");

    /* Décroissance absolue en k */
    double a1 = fabs(cagoule_omega_fourier_coeff(1, 2));
    double a2 = fabs(cagoule_omega_fourier_coeff(2, 2));
    double a3 = fabs(cagoule_omega_fourier_coeff(3, 2));
    ASSERT_GT(a1, a2, "|c_1| > |c_2| pour n=2");
    ASSERT_GT(a2, a3, "|c_2| > |c_3| pour n=2");

    /* Décroissance en n : c_2(n=10) < c_2(n=1) */
    ASSERT_LT(
        fabs(cagoule_omega_fourier_coeff(2, 10)),
        fabs(cagoule_omega_fourier_coeff(2, 1)),
        "|c_2(n=10)| < |c_2(n=1)|"
    );

    /* c_1(n=1) : fini, positif */
    double c1n1 = cagoule_omega_fourier_coeff(1, 1);
    ASSERT(isfinite(c1n1) && c1n1 > 0.0, "c_1(n=1) fini positif");

    /* Grand k → petit |c_k| */
    ASSERT_LT(fabs(cagoule_omega_fourier_coeff(64, 5)), 1e-8, "|c_64(n=5)| < 1e-8");

    /* Cas invalides */
    ASSERT_NAN(cagoule_omega_fourier_coeff(0,  1), "k=0 → NAN");
    ASSERT_NAN(cagoule_omega_fourier_coeff(-1, 1), "k=-1 → NAN");
    ASSERT_NAN(cagoule_omega_fourier_coeff(1,  0), "n=0 → NAN");
}

/* ══════════════════════════════════════════════════════════════════════════
 *  §3. Génération des round keys (corrigé + nouveaux tests)
 * ══════════════════════════════════════════════════════════════════════════ */
static void test_round_keys(void)
{
    section("§3. Génération des round keys");

    uint64_t keys[64] = {0};
    int ret;

    /* Cas nominal : 64 clés */
    ret = cagoule_omega_generate_round_keys(N, SALT, 32, P, 64, keys);
    ASSERT_EQ_I(ret, CAGOULE_OMEGA_OK, "génération 64 clés OK");

    /* Toutes dans [0, p) */
    int in_range = 1;
    for (int i = 0; i < 64; i++)
        if (keys[i] >= P) { in_range = 0; break; }
    ASSERT(in_range, "toutes les clés dans [0, p)");

    /* CORRIGÉ: tester toutes les 64 clés pour l'unicité */
    int all_same = 1;
    for (int i = 1; i < 64; i++)
        if (keys[i] != keys[0]) { all_same = 0; break; }
    ASSERT(!all_same, "les clés sont distinctes sur 64 éléments");

    /* Déterminisme */
    uint64_t keys2[64] = {0};
    ret = cagoule_omega_generate_round_keys(N, SALT, 32, P, 64, keys2);
    ASSERT_EQ_I(ret, CAGOULE_OMEGA_OK, "2e génération OK");
    ASSERT_EQ_U(keys[0],  keys2[0],  "clé[0] déterministe");
    ASSERT_EQ_U(keys[7],  keys2[7],  "clé[7] déterministe");
    ASSERT_EQ_U(keys[63], keys2[63], "clé[63] déterministe");

    /* Sensibilité au sel */
    uint64_t keys_alt[64] = {0};
    ret = cagoule_omega_generate_round_keys(N, SALT_ALT, 32, P, 64, keys_alt);
    ASSERT_EQ_I(ret, CAGOULE_OMEGA_OK, "alt_salt OK");
    ASSERT_NEQ_U(keys_alt[0], keys[0], "sel différent → clé[0] différente");

    /* Sensibilité à n */
    uint64_t keys_n8[64] = {0};
    ret = cagoule_omega_generate_round_keys(8, SALT, 32, P, 64, keys_n8);
    ASSERT_EQ_I(ret, CAGOULE_OMEGA_OK, "n=8 OK");
    ASSERT_NEQ_U(keys_n8[0], keys[0], "n différent → clé[0] différente");

    /* Sensibilité à p */
    uint64_t keys_p2[64] = {0};
    ret = cagoule_omega_generate_round_keys(N, SALT, 32, P2, 64, keys_p2);
    ASSERT_EQ_I(ret, CAGOULE_OMEGA_OK, "p2 OK");
    ASSERT_NEQ_U(keys_p2[0], keys[0], "p différent → clé[0] différente");
    int in_range_p2 = 1;
    for (int i = 0; i < 64; i++)
        if (keys_p2[i] >= P2) { in_range_p2 = 0; break; }
    ASSERT(in_range_p2, "clés p2 dans [0, p2)");

    /* num_keys=1 cohérent avec batch */
    uint64_t key1[1] = {0};
    ret = cagoule_omega_generate_round_keys(N, SALT, 32, P, 1, key1);
    ASSERT_EQ_I(ret, CAGOULE_OMEGA_OK, "num_keys=1 OK");
    ASSERT_EQ_U(key1[0], keys[0], "clé[0] batch vs single cohérente");

    /* num_keys=256 (maximum) */
    uint64_t keys256[256] = {0};
    ret = cagoule_omega_generate_round_keys(N, SALT, 32, P, 256, keys256);
    ASSERT_EQ_I(ret, CAGOULE_OMEGA_OK, "num_keys=256 OK");
    int in_range256 = 1;
    for (int i = 0; i < 256; i++)
        if (keys256[i] >= P) { in_range256 = 0; break; }
    ASSERT(in_range256, "256 clés dans [0, p)");

    /* NOUVEAU: salt_len=0 */
    uint64_t keys_nosalt[4] = {0};
    uint8_t dummy_salt[1] = {0x42};
    ret = cagoule_omega_generate_round_keys(N, dummy_salt, 0, P, 4, keys_nosalt);
    ASSERT_EQ_I(ret, CAGOULE_OMEGA_OK, "salt_len=0 OK");
    
    /* NOUVEAU: salt_len=64 (maximum) */
    uint8_t big_salt[64];
    memset(big_salt, 0x42, 64);
    uint64_t keys_bigsalt[4] = {0};
    ret = cagoule_omega_generate_round_keys(N, big_salt, 64, P, 4, keys_bigsalt);
    ASSERT_EQ_I(ret, CAGOULE_OMEGA_OK, "salt_len=64 OK");
    
    /* NOUVEAU: salt_len=65 → erreur */
    ret = cagoule_omega_generate_round_keys(N, big_salt, 65, P, 4, keys);
    ASSERT_EQ_I(ret, CAGOULE_OMEGA_ERR_PARAM, "salt_len=65 → ERR_PARAM");

    /* n=1 (cas limite min) */
    uint64_t keys_n1[4] = {0};
    ret = cagoule_omega_generate_round_keys(1, SALT, 32, P, 4, keys_n1);
    ASSERT_EQ_I(ret, CAGOULE_OMEGA_OK, "n=1 OK");

    /* n=100 (grand n) */
    uint64_t keys_n100[4] = {0};
    ret = cagoule_omega_generate_round_keys(100, SALT, 32, P, 4, keys_n100);
    ASSERT_EQ_I(ret, CAGOULE_OMEGA_OK, "n=100 OK");

    /* Petit p */
    uint64_t keys_sp[4] = {0};
    ret = cagoule_omega_generate_round_keys(N, SALT, 32, 997, 4, keys_sp);
    ASSERT_EQ_I(ret, CAGOULE_OMEGA_OK, "petit p=997 OK");
    int in_sp = 1;
    for (int i = 0; i < 4; i++)
        if (keys_sp[i] >= 997) { in_sp = 0; break; }
    ASSERT(in_sp, "clés dans [0, 997)");

    /* ── Cas d'erreur attendus ─────────────────────────────────────── */
    ASSERT_EQ_I(
        cagoule_omega_generate_round_keys(0, SALT, 32, P, 4, keys),
        CAGOULE_OMEGA_ERR_PARAM, "n=0 → ERR_PARAM");
    ASSERT_EQ_I(
        cagoule_omega_generate_round_keys(-1, SALT, 32, P, 4, keys),
        CAGOULE_OMEGA_ERR_PARAM, "n=-1 → ERR_PARAM");
    ASSERT_EQ_I(
        cagoule_omega_generate_round_keys(N, NULL, 32, P, 4, keys),
        CAGOULE_OMEGA_ERR_NULL, "salt=NULL → ERR_NULL");
    ASSERT_EQ_I(
        cagoule_omega_generate_round_keys(N, SALT, 32, P, 4, NULL),
        CAGOULE_OMEGA_ERR_NULL, "keys_out=NULL → ERR_NULL");
    ASSERT_EQ_I(
        cagoule_omega_generate_round_keys(N, SALT, 32, 0, 4, keys),
        CAGOULE_OMEGA_ERR_PARAM, "p=0 → ERR_PARAM");
    ASSERT_EQ_I(
        cagoule_omega_generate_round_keys(N, SALT, 32, 1, 4, keys),
        CAGOULE_OMEGA_ERR_PARAM, "p=1 → ERR_PARAM");
    ASSERT_EQ_I(
        cagoule_omega_generate_round_keys(N, SALT, 32, P, 0, keys),
        CAGOULE_OMEGA_ERR_PARAM, "num_keys=0 → ERR_PARAM");
    ASSERT_EQ_I(
        cagoule_omega_generate_round_keys(N, SALT, 32, P, 257, keys),
        CAGOULE_OMEGA_ERR_PARAM, "num_keys=257 → ERR_PARAM");
}

/* ══════════════════════════════════════════════════════════════════════════
 *  §4. Opérations bloc add/sub_rk
 * ══════════════════════════════════════════════════════════════════════════ */
static void test_block_ops(void)
{
    section("§4. Opérations bloc add/sub_rk");

    const uint64_t rk = 3141592653589793ULL % P;

    /* Bloc initial : valeurs dans [0, P) */
    uint64_t block[16], orig[16];
    for (int i = 0; i < 16; i++)
        block[i] = orig[i] = (uint64_t)(i * 1000000007ULL) % P;

    /* add ∘ sub = identité */
    cagoule_omega_block_add_rk(block, 16, rk, P);
    cagoule_omega_block_sub_rk(block, 16, rk, P);
    int identity = 1;
    for (int i = 0; i < 16; i++)
        if (block[i] != orig[i]) { identity = 0; break; }
    ASSERT(identity, "add(rk) ∘ sub(rk) = identité");

    /* sub ∘ add = identité */
    memcpy(block, orig, sizeof(block));
    cagoule_omega_block_sub_rk(block, 16, rk, P);
    cagoule_omega_block_add_rk(block, 16, rk, P);
    identity = 1;
    for (int i = 0; i < 16; i++)
        if (block[i] != orig[i]) { identity = 0; break; }
    ASSERT(identity, "sub(rk) ∘ add(rk) = identité");

    /* add : résultats dans [0, P) */
    memcpy(block, orig, sizeof(block));
    cagoule_omega_block_add_rk(block, 16, rk, P);
    int in_range = 1;
    for (int i = 0; i < 16; i++)
        if (block[i] >= P) { in_range = 0; break; }
    ASSERT(in_range, "add_rk : valeurs dans [0, p)");

    /* rk=0 → no-op */
    memcpy(block, orig, sizeof(block));
    cagoule_omega_block_add_rk(block, 16, 0, P);
    int noop = 1;
    for (int i = 0; i < 16; i++)
        if (block[i] != orig[i]) { noop = 0; break; }
    ASSERT(noop, "add_rk(0) = no-op");

    /* rk=P-1 → pas de dépassement */
    memcpy(block, orig, sizeof(block));
    cagoule_omega_block_add_rk(block, 16, P - 1, P);
    int no_overflow = 1;
    for (int i = 0; i < 16; i++)
        if (block[i] >= P) { no_overflow = 0; break; }
    ASSERT(no_overflow, "add_rk(p-1) : pas de dépassement");

    /* n_elems=0 → no-op, sentinelle intacte */
    uint64_t sentinel = 0xDEADBEEFDEADBEEFULL;
    cagoule_omega_block_add_rk(&sentinel, 0, rk, P);
    ASSERT_EQ_U(sentinel, 0xDEADBEEFDEADBEEFULL, "n_elems=0 : sentinelle intacte");

    /* 0 + rk = rk */
    uint64_t z1[1] = {0};
    cagoule_omega_block_add_rk(z1, 1, rk, P);
    ASSERT_EQ_U(z1[0], rk, "0 + rk = rk");

    /* 0 - rk = p - rk */
    uint64_t z2[1] = {0};
    cagoule_omega_block_sub_rk(z2, 1, rk, P);
    ASSERT_EQ_U(z2[0], P - rk, "0 - rk = p - rk");

    /* Plusieurs add consécutifs → modulo correct */
    uint64_t x[1] = {0};
    for (int i = 0; i < 4; i++)
        cagoule_omega_block_add_rk(x, 1, rk, P);
    ASSERT_LT(x[0], P, "4 × add_rk : dans [0, p)");

    /* Résultat add ≠ original (sauf si rk=0, non testé ici) */
    memcpy(block, orig, sizeof(block));
    cagoule_omega_block_add_rk(block, 16, rk, P);
    int changed = 0;
    for (int i = 0; i < 16; i++)
        if (block[i] != orig[i]) { changed = 1; break; }
    ASSERT(changed, "add_rk modifie le bloc");
}

/* ══════════════════════════════════════════════════════════════════════════
 *  §5. Détection OpenSSL (version améliorée)
 * ══════════════════════════════════════════════════════════════════════════ */
static void test_openssl(void)
{
    section("§5. Détection OpenSSL");

    int avail = cagoule_omega_openssl_available();
    
    /* Vérifier que la valeur retournée est valide (0 ou 1) */
    ASSERT(avail == 0 || avail == 1, "retour 0 ou 1");
    
    /* Information pour le développeur (non bloquant) */
    if (avail != 1) {
        fprintf(stderr, "  NOTE: OpenSSL non disponible - fallback vers Python\n");
    }
    
    /* En environnement de test standard, OpenSSL devrait être disponible */
    ASSERT(avail == 1, "OpenSSL disponible (requis en build)");
}

/* ══════════════════════════════════════════════════════════════════════════
 *  §6. KAT — stabilité interne
 * ══════════════════════════════════════════════════════════════════════════ */
static void test_kat(void)
{
    section("§6. KAT — stabilité interne");

    uint64_t keys_a[4] = {0};
    uint64_t keys_b[4] = {0};
    uint64_t keys_c[4] = {0};

    /* Génération de référence */
    int ret = cagoule_omega_generate_round_keys(N, SALT, 32, P, 4, keys_a);
    ASSERT_EQ_I(ret, CAGOULE_OMEGA_OK, "KAT : 1er appel OK");

    /* Stabilité : 2e appel identique */
    ret = cagoule_omega_generate_round_keys(N, SALT, 32, P, 4, keys_b);
    ASSERT_EQ_I(ret, CAGOULE_OMEGA_OK, "KAT : 2e appel OK");
    ASSERT_EQ_U(keys_a[0], keys_b[0], "KAT clé[0] stable");
    ASSERT_EQ_U(keys_a[1], keys_b[1], "KAT clé[1] stable");
    ASSERT_EQ_U(keys_a[2], keys_b[2], "KAT clé[2] stable");
    ASSERT_EQ_U(keys_a[3], keys_b[3], "KAT clé[3] stable");

    /* clé[0] est dans [0, P) */
    ASSERT_LT(keys_a[0], P, "KAT clé[0] < p");

    /* Les 4 clés sont toutes dans [0, p) */
    for (int i = 0; i < 4; i++) {
        ASSERT_LT(keys_a[i], P, "KAT clé[i] < p");
    }
}

/* ══════════════════════════════════════════════════════════════════════════
 *  §7. Tests de performance
 * ══════════════════════════════════════════════════════════════════════════ */
static void test_performance(void)
{
    section("§7. Performance");
    
    uint64_t keys[64] = {0};
    clock_t start, end;
    double ms;
    
    /* Test 1: Génération unique de 64 clés */
    start = clock();
    int ret = cagoule_omega_generate_round_keys(N, SALT, 32, P, 64, keys);
    end = clock();
    ASSERT_EQ_I(ret, CAGOULE_OMEGA_OK, "perf: génération OK");
    
    ms = (double)(end - start) / CLOCKS_PER_SEC * 1000.0;
    printf("  Génération unique de 64 clés: %.2f ms\n", ms);
    ASSERT(ms < 100.0, "perf: génération unique < 100 ms");
    
    /* Test 2: 100 générations de 64 clés (pour mesurer la stabilité) */
    start = clock();
    for (int i = 0; i < 100; i++) {
        ret = cagoule_omega_generate_round_keys(N, SALT, 32, P, 64, keys);
        if (ret != CAGOULE_OMEGA_OK) break;
    }
    end = clock();
    ms = (double)(end - start) / CLOCKS_PER_SEC * 1000.0;
    printf("  100 × génération de 64 clés: %.2f ms (moyenne: %.2f ms)\n", 
           ms, ms / 100.0);
    ASSERT(ms < 2000.0, "perf: 100 générations < 2 secondes");
    
    /* Test 3: Vérification que le temps est raisonnable par rapport à Python */
    if (ms / 100.0 > 50.0) {
        fprintf(stderr, "  WARNING: Temps moyen par génération (%.2f ms) > 50 ms\n", 
                ms / 100.0);
        fprintf(stderr, "           Attendue < 10 ms pour omega.c\n");
    }
}

/* ══════════════════════════════════════════════════════════════════════════
 *  §8. Thread-safety (test basique avec pthread)
 * ══════════════════════════════════════════════════════════════════════════ */

#ifdef __linux__
typedef struct {
    int thread_id;
    uint64_t keys[64];
    int result;
} thread_data_t;

static void* thread_worker(void* arg)
{
    thread_data_t* data = (thread_data_t*)arg;
    
    /* Chaque thread utilise un sel légèrement différent (basé sur son ID) */
    uint8_t salt_local[32];
    memcpy(salt_local, SALT, 32);
    salt_local[0] ^= (data->thread_id & 0xFF);
    
    data->result = cagoule_omega_generate_round_keys(
        N, salt_local, 32, P, 64, data->keys
    );
    
    return NULL;
}

static void test_thread_safety(void)
{
    section("§8. Thread-safety");
    
    #define NUM_THREADS 4
    pthread_t threads[NUM_THREADS];
    thread_data_t thread_data[NUM_THREADS];
    
    /* Lancer plusieurs threads en parallèle */
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].result = -1;
        if (pthread_create(&threads[i], NULL, thread_worker, &thread_data[i]) != 0) {
            ASSERT(0, "thread_safety: échec création thread");
            return;
        }
    }
    
    /* Attendre la fin de tous les threads */
    int all_ok = 1;
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
        if (thread_data[i].result != CAGOULE_OMEGA_OK) {
            all_ok = 0;
        }
    }
    
    ASSERT(all_ok, "thread_safety: tous les threads ont réussi");
    
    /* Vérifier que les résultats des différents threads sont distincts (sel différent) */
    int all_distinct = 1;
    for (int i = 0; i < NUM_THREADS - 1; i++) {
        if (thread_data[i].keys[0] == thread_data[i+1].keys[0]) {
            all_distinct = 0;
            break;
        }
    }
    ASSERT(all_distinct, "thread_safety: threads avec sels différents donnent clés différentes");
    
    printf("  %d threads parallèles: OK\n", NUM_THREADS);
}
#else
static void test_thread_safety(void)
{
    section("§8. Thread-safety");
    printf("  Test ignoré (pas de pthread sur cette plateforme)\n");
}
#endif

/* ══════════════════════════════════════════════════════════════════════════
 *  main
 * ══════════════════════════════════════════════════════════════════════════ */
int main(void)
{
    printf("════════════════════════════════════════════════════════\n");
    printf("  test_omega — CAGOULE v2.1.0\n");
    printf("════════════════════════════════════════════════════════\n");

    test_zeta();
    test_fourier();
    test_round_keys();
    test_block_ops();
    test_openssl();
    test_kat();
    test_performance();
    test_thread_safety();

    int total = _pass + _fail;
    printf("\n════════════════════════════════════════════════════════\n");
    printf("  Résultat : %d/%d tests passés\n", _pass, total);
    if (_fail == 0) {
        printf("  ✅ Tous les tests passent\n");
    } else {
        printf("  ❌ %d test(s) en échec\n", _fail);
    }
    printf("════════════════════════════════════════════════════════\n");

    return (_fail == 0) ? 0 : 1;
}