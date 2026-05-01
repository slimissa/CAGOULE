/**
 * cagoule_omega.c — Pilier Ω : ζ(2n) → Round Keys — CAGOULE v2.1.0
 *
 * Implémentation complète sans mpmath.
 * Compatible bit-à-bit avec omega.py pour n ≤ 32.
 *
 * Dépendances :
 *   - libcrypto (OpenSSL ≥ 1.1) : HMAC-SHA256 pour HKDF
 *   - libm                       : pow(), fabs(), M_PI
 *   - __uint128_t                : réduction modulaire 256 bits
 */

#include "cagoule_omega.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

/* OpenSSL HMAC-SHA256 */
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

/* ══════════════════════════════════════════════════════════════════════════
 *  §1. Table ζ(2n) précalculée
 *      Valeurs générées avec mpmath.zeta(2*n) à 50 décimales puis arrondies
 *      à la précision double (IEEE 754 binary64, ~15.9 décimales significatives).
 *      Invariant : ZETA_TABLE[n-1] == ζ(2n) pour n = 1..CAGOULE_OMEGA_ZETA_TABLE_MAX
 * ══════════════════════════════════════════════════════════════════════════ */

static const double ZETA_TABLE[CAGOULE_OMEGA_ZETA_TABLE_MAX] = {
    /* n= 1 */ 1.6449340668482264,
    /* n= 2 */ 1.0823232337111382,
    /* n= 3 */ 1.0173430619844491,
    /* n= 4 */ 1.0040773561979443,
    /* n= 5 */ 1.0009945751278181,
    /* n= 6 */ 1.0002460865533080,
    /* n= 7 */ 1.0000612481350588,
    /* n= 8 */ 1.0000152822594086,
    /* n= 9 */ 1.0000038172932649,
    /* n=10 */ 1.0000009539620338,
    /* n=11 */ 1.0000002384505017,
    /* n=12 */ 1.0000000596081902,
    /* n=13 */ 1.0000000149015548,
    /* n=14 */ 1.0000000037253340,
    /* n=15 */ 1.0000000009313225,
    /* n=16 */ 1.0000000002328306,
    /* n=17 */ 1.0000000000582076,
    /* n=18 */ 1.0000000000145519,
    /* n=19 */ 1.0000000000036380,
    /* n=20 */ 1.0000000000009095,
    /* n=21 */ 1.0000000000002274,
    /* n=22 */ 1.0000000000000568,
    /* n=23 */ 1.0000000000000142,
    /* n=24 */ 1.0000000000000036,
    /* n=25 */ 1.0000000000000009,
    /* n=26 */ 1.0000000000000002,
    /* n=27 */ 1.0000000000000000,  /* ζ(54) ≡ 1.0 en double */
    /* n=28 */ 1.0000000000000000,
    /* n=29 */ 1.0000000000000000,
    /* n=30 */ 1.0000000000000000,
    /* n=31 */ 1.0000000000000000,
    /* n=32 */ 1.0000000000000000,
};

/* ══════════════════════════════════════════════════════════════════════════
 *  §2. Constantes mathématiques
 * ══════════════════════════════════════════════════════════════════════════ */

/* 2/π — même valeur que mpmath.mpf(2)/mpmath.pi à 64 bits */
#define TWO_DIV_PI   0.6366197723675814

/* 2^32 en double */
#define SCALE_2_32   4294967296.0

/* Longueur du digest SHA-256 en octets */
#define SHA256_LEN   32

/* Taille du préfixe d'info HKDF : "CAGOULE_ROUND_KEY_" = 18 octets + 4 = 22 */
#define INFO_PREFIX_LEN  18
#define INFO_TOTAL_LEN   22

/* Taille maximale du sel (évite allocation dynamique) */
#define MAX_SALT_LEN     64

/* ══════════════════════════════════════════════════════════════════════════
 *  §3. ζ(2n) — API publique
 * ══════════════════════════════════════════════════════════════════════════ */

double cagoule_omega_zeta_2n(int n)
{
    if (n < 1) return NAN;

    if (n <= CAGOULE_OMEGA_ZETA_TABLE_MAX)
        return ZETA_TABLE[n - 1];

    /* Pour n > 32 : 2^(-2n) < 2^(-64) < epsilon_machine.
     * La série ζ(2n) = 1 + 2^(-2n) + 3^(-2n) + ...
     * est indistinguable de 1.0 en double. */
    return 1.0;
}

/* ══════════════════════════════════════════════════════════════════════════
 *  §4. Coefficient de Fourier c_k = (2/π) × (−1)^k / k^(2n)
 * ══════════════════════════════════════════════════════════════════════════ */

double cagoule_omega_fourier_coeff(int k, int n)
{
    if (k < 1 || n < 1) return NAN;

    /* Signe : +1 si k impair, -1 si k pair (≡ omega.py) */
    double sign = (k % 2 == 1) ? 1.0 : -1.0;

    /* k^(2n) — pow() en double, suffisant car on tronque ensuite à 64 bits */
    double exponent = 2.0 * (double)n;
    double kpow     = pow((double)k, exponent);

    /* Protection contre le dépassement :
     * - Si kpow est infini (dépassement), c_k ≈ 0
     * - Si kpow est 0 (underflow), c_k ≈ 0
     * - Sinon, calcul normal
     */
    if (!isfinite(kpow) || kpow == 0.0) {
        /* Pour les très grandes valeurs, le coefficient est nul */
        return 0.0;
    }

    return TWO_DIV_PI * sign / kpow;
}

/* ══════════════════════════════════════════════════════════════════════════
 *  §5. HKDF-SHA256 (implémentation manuelle, compatible OpenSSL 1.1 et 3.x)
 *
 *  Reproduit exactement :
 *    cryptography.hazmat.primitives.kdf.hkdf.HKDF(
 *        algorithm=hashes.SHA256(), length=32, salt=None, info=info
 *    ).derive(ikm)
 *
 *  salt=None dans la bibliothèque Python correspond à un sel de SHA256_LEN
 *  zéros (RFC 5869 §2.2 : "If not provided, [salt] is set to a string of
 *  HashLen zeros.").
 * ══════════════════════════════════════════════════════════════════════════ */

/** HKDF-Extract : PRK = HMAC-SHA256(zero_salt, IKM) */
static int hkdf_extract(const uint8_t *ikm, size_t ikm_len, uint8_t prk[SHA256_LEN])
{
    static const uint8_t zero_salt[SHA256_LEN] = {0};
    unsigned int out_len = SHA256_LEN;

    if (!HMAC(EVP_sha256(),
              zero_salt, SHA256_LEN,
              ikm, ikm_len,
              prk, &out_len))
        return CAGOULE_OMEGA_ERR_OPENSSL;

    return CAGOULE_OMEGA_OK;
}

/**
 * HKDF-Expand : T(1) = HMAC-SHA256(PRK, info ‖ 0x01)
 * (un seul bloc de 32 octets suffit puisque out_len ≤ SHA256_LEN)
 */
static int hkdf_expand(const uint8_t prk[SHA256_LEN],
                        const uint8_t *info, size_t info_len,
                        uint8_t *out, size_t out_len)
{
    if (out_len > SHA256_LEN) return CAGOULE_OMEGA_ERR_PARAM;

    /* T(1) = HMAC(PRK, info ‖ 0x01) */
    uint8_t  buf[256];  /* Buffer généreux pour info_len */
    uint8_t  t1[SHA256_LEN];
    unsigned int t1_len = SHA256_LEN;

    if (info_len > sizeof(buf) - 1) return CAGOULE_OMEGA_ERR_PARAM;

    memcpy(buf, info, info_len);
    buf[info_len] = 0x01;

    if (!HMAC(EVP_sha256(), prk, SHA256_LEN,
              buf, info_len + 1,
              t1, &t1_len))
        return CAGOULE_OMEGA_ERR_OPENSSL;

    memcpy(out, t1, out_len);
    return CAGOULE_OMEGA_OK;
}

/** HKDF-SHA256 complet (Extract + Expand), salt=NULL (zéros). */
static int hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                        const uint8_t *info, size_t info_len,
                        uint8_t *out, size_t out_len)
{
    uint8_t prk[SHA256_LEN];

    int ret = hkdf_extract(ikm, ikm_len, prk);
    if (ret != CAGOULE_OMEGA_OK) return ret;

    return hkdf_expand(prk, info, info_len, out, out_len);
}

/* ══════════════════════════════════════════════════════════════════════════
 *  §6. Réduction modulaire 256 bits → uint64_t
 *
 *  Reproduit : int.from_bytes(rk_bytes, 'big') % p
 *  où rk_bytes est un tableau de 32 octets.
 *
 *  On utilise la méthode de Horner :
 *    val = 0
 *    for each byte b in rk_bytes:  val = (val × 256 + b) % p
 *
 *  Arithmétique : val < p ≤ 2^64, val×256 < 2^72 → __uint128_t suffisant.
 * ══════════════════════════════════════════════════════════════════════════ */

static uint64_t bytes_to_int_mod_p(const uint8_t buf[SHA256_LEN], uint64_t p)
{
    __uint128_t val = 0;
    const __uint128_t P = (__uint128_t)p;

    for (int i = 0; i < SHA256_LEN; i++) {
        val = (val * 256 + buf[i]) % P;
    }

    return (uint64_t)val;
}

/* ══════════════════════════════════════════════════════════════════════════
 *  §7. Génération des round keys — API publique principale
 * ══════════════════════════════════════════════════════════════════════════ */

int cagoule_omega_generate_round_keys(
    int            n,
    const uint8_t *salt,
    size_t         salt_len,
    uint64_t       p,
    int            num_keys,
    uint64_t      *keys_out)
{
    /* ── Validation ────────────────────────────────────────────────────── */
    if (!salt || !keys_out)              return CAGOULE_OMEGA_ERR_NULL;
    if (n < 1 || num_keys < 1)          return CAGOULE_OMEGA_ERR_PARAM;
    if (num_keys > CAGOULE_OMEGA_MAX_KEYS) return CAGOULE_OMEGA_ERR_PARAM;
    if (salt_len > MAX_SALT_LEN)        return CAGOULE_OMEGA_ERR_PARAM;
    if (p < 2)                           return CAGOULE_OMEGA_ERR_PARAM;

    /* ── n_bytes : n encodé sur 4 octets big-endian ────────────────────── */
    uint8_t n_bytes[4];
    n_bytes[0] = ((uint32_t)n >> 24) & 0xFF;
    n_bytes[1] = ((uint32_t)n >> 16) & 0xFF;
    n_bytes[2] = ((uint32_t)n >> 8)  & 0xFF;
    n_bytes[3] =  (uint32_t)n        & 0xFF;

    /* ── Allocation stack (évite malloc/free) ─────────────────────────── */
    /* max size = 8 (ak_seed) + MAX_SALT_LEN (64) + 4 (n_bytes) = 76 octets */
    uint8_t key_material[8 + MAX_SALT_LEN + 4];
    size_t km_len = 8 + salt_len + 4;

    /* Copier salt dans key_material (les 8 premiers octets seront écrasés) */
    memcpy(key_material + 8, salt, salt_len);

    /* info fixe : "CAGOULE_ROUND_KEY_" + k_bytes(4) */
    uint8_t info[INFO_TOTAL_LEN];
    memcpy(info, "CAGOULE_ROUND_KEY_", INFO_PREFIX_LEN);

    uint8_t rk_bytes[SHA256_LEN];

    for (int k = 1; k <= num_keys; k++) {

        /* 1. Coefficient de Fourier c_k = (2/π)×(−1)^k / k^(2n) */
        double ak = cagoule_omega_fourier_coeff(k, n);

        /* 2. ak_seed = floor(|c_k| × 2^32) → 8 octets */
        uint64_t scaled = (uint64_t)(fabs(ak) * SCALE_2_32);

        /* Encodage big-endian 8 octets */
        for (int i = 7; i >= 0; i--) {
            key_material[i] = (uint8_t)(scaled & 0xFF);
            scaled >>= 8;
        }

        /* 3. key_material = ak_seed ‖ salt ‖ n_bytes (déjà en place) */
        memcpy(key_material + 8 + salt_len, n_bytes, 4);

        /* 4. info = "CAGOULE_ROUND_KEY_" ‖ k (4 octets big-endian) */
        info[INFO_PREFIX_LEN]     = ((uint32_t)k >> 24) & 0xFF;
        info[INFO_PREFIX_LEN + 1] = ((uint32_t)k >> 16) & 0xFF;
        info[INFO_PREFIX_LEN + 2] = ((uint32_t)k >> 8)  & 0xFF;
        info[INFO_PREFIX_LEN + 3] =  (uint32_t)k        & 0xFF;

        /* 5. rk_bytes = HKDF-SHA256(key_material, info, 32) */
        int ret = hkdf_sha256(key_material, km_len, info, INFO_TOTAL_LEN,
                               rk_bytes, SHA256_LEN);
        if (ret != CAGOULE_OMEGA_OK) {
            return ret;
        }

        /* 6. round_key = int.from_bytes(rk_bytes, 'big') % p */
        keys_out[k - 1] = bytes_to_int_mod_p(rk_bytes, p);

        /* Zeroize rk_bytes avant de passer au suivant */
        volatile uint8_t *vrk = rk_bytes;
        for (size_t i = 0; i < SHA256_LEN; i++) vrk[i] = 0;
    }

    /* ── Zeroize le buffer sensible avant sortie ──────────────────────── */
    volatile uint8_t *vp = key_material;
    for (size_t i = 0; i < km_len; i++) vp[i] = 0;

    return CAGOULE_OMEGA_OK;
}

/* ══════════════════════════════════════════════════════════════════════════
 *  §8. Opérations sur les blocs — apply / remove round key
 * ══════════════════════════════════════════════════════════════════════════ */

void cagoule_omega_block_add_rk(uint64_t *block, size_t n_elems,
                                 uint64_t rk, uint64_t p)
{
    for (size_t i = 0; i < n_elems; i++) {
        /* Addition sans débordement : block[i] < p, rk < p → somme < 2p ≤ 2^65 */
        __uint128_t s = (__uint128_t)block[i] + rk;
        block[i] = (uint64_t)(s % p);
    }
}

void cagoule_omega_block_sub_rk(uint64_t *block, size_t n_elems,
                                 uint64_t rk, uint64_t p)
{
    for (size_t i = 0; i < n_elems; i++) {
        /* Soustraction mod p, sans dépassement négatif */
        block[i] = (block[i] >= rk) ? (block[i] - rk) : (p - rk + block[i]);
    }
}

/* ══════════════════════════════════════════════════════════════════════════
 *  §9. Détection OpenSSL à l'exécution (compatible OpenSSL 3.0)
 * ══════════════════════════════════════════════════════════════════════════ */

int cagoule_omega_openssl_available(void)
{
    static int tested = 0;
    static int available = 0;
    
    if (!tested) {
        /* Test simple : vérifier que HMAC-SHA256 fonctionne */
        unsigned int len;
        uint8_t out[32];
        uint8_t key[32] = {0};
        uint8_t data[1] = {0};
        
        /* HMAC() est la fonction recommandée (pas dépréciée) */
        if (HMAC(EVP_sha256(), key, 32, data, 1, out, &len) && len == 32) {
            available = 1;
        }
        tested = 1;
    }
    return available;
}

/* ══════════════════════════════════════════════════════════════════════════
 *  §10. Zeroization globale (API publique)
 * ══════════════════════════════════════════════════════════════════════════ */

void cagoule_omega_secure_zeroize(void)
{
    /* Rien à effacer au niveau global pour l'instant.
     * Cette fonction est réservée pour d'éventuels buffers statiques
     * ou de la mémoire partagée dans de futures versions.
     * Elle est appelée par le binding Python via omega.py.
     */
}

/* ══════════════════════════════════════════════════════════════════════════
 *  §11. Version de l'API
 * ══════════════════════════════════════════════════════════════════════════ */

const char* cagoule_omega_version(void)
{
    return "2.1.0";
}