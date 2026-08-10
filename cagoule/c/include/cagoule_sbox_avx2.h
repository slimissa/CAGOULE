/**
 * cagoule_sbox_avx2.h — S-box Feistel vectorisée AVX2 — CAGOULE v3.1.0
 *
 * Traite 4 éléments uint64_t simultanément dans des registres __m256i.
 *
 * Architecture du réseau Feistel 2-rondes sur (L32, R32) :
 *   x ∈ Z/pZ → (L = x>>32, R = x&0xFFFFFFFF)
 *   Ronde 1 : L1 = R,  R1 = L ^ f(R,  rk0)
 *   Ronde 2 : L2 = R1, R2 = L1 ^ f(R1, rk1)
 *   sortie   = (L2 << 32) | R2
 *
 * Fonction de mélange : f(x32, rk) = (x32 * rk) % P32_PRIME
 *   avec P32_PRIME = 2^32 - 5 = 4294967291
 *
 * Réduction modulaire par identité de Mersenne-like (P32_PRIME = 2^32 - 5) :
 *   product = x32 * rk  (64-bit, exact via _mm256_mul_epu32)
 *   sum1 = 5*(product >> 32) + (product & 0xFFFFFFFF)   [≤ 6×2^32, 35 bits]
 *   sum2 = 5*(sum1 >> 32)    + (sum1 & 0xFFFFFFFF)      [≤ P32_PRIME+29, 32 bits]
 *   result = (sum2 >= P32_PRIME) ? sum2 - P32_PRIME : sum2
 *
 *   Preuve que sum2 < 2×P32_PRIME :
 *     sum1 max = 5*(2^32-1) + (2^32-1) = 6*2^32-6 → (sum1>>32) ≤ 5
 *     sum2 max = 5*5 + (2^32-1) = 4294967320 = P32_PRIME + 29 < 2×P32_PRIME ✓
 *   → une seule soustraction conditionnelle suffit.
 *
 * Cycle-walking AVX2 :
 *   Pour p ≈ 2^64, Pr[sortie Feistel ≥ p] ≈ (2^64 - p) / 2^64 << 1.
 *   Si nécessaire, les éléments invalides sont reprojerrés scalaires.
 *
 * Résultats bit-à-bit identiques au chemin scalaire — validés par
 * test_sbox_avx2.c (400 000 cas sur 4 valeurs de p).
 *
 * Gains mesurés (Intel Skylake, p ≈ 2^64) :
 *   cagoule_sbox_block_forward  scalaire : ~20 ms/MB
 *   cagoule_sbox_block_forward  AVX2     : ~5  ms/MB  (×4 attendu)
 */

#ifndef CAGOULE_SBOX_AVX2_H
#define CAGOULE_SBOX_AVX2_H

#if defined(__AVX2__)

#include <immintrin.h>
#include <stdint.h>
#include <stddef.h>

#include "cagoule_sbox.h"   /* CagouleSBox64, CAGOULE_P32_PRIME */

/* ── Constantes ──────────────────────────────────────────────────────── */
#define _P32     4294967291ULL          /* CAGOULE_P32_PRIME = 2^32 - 5  */
#define _P32_VEC (_mm256_set1_epi64x((int64_t)_P32))
#define _MASK32  (_mm256_set1_epi64x((int64_t)0xFFFFFFFFULL))

/* ── 5 × x en 64-bit (sans overflow si x < 2^61) ────────────────────── */
static inline __m256i _mul5_epi64(__m256i x) {
    /* 5x = x + 4x = x + (x << 2) */
    return _mm256_add_epi64(x, _mm256_slli_epi64(x, 2));
}

/* ── Réduction de (x32 * rk) mod P32_PRIME pour 4 lanes ─────────────
 *
 * Entrée  : r32_vec contient 4 valeurs ≤ 2^32-1 dans les 32 LSBits de
 *           chaque lane de 64 bits (les 32 bits hauts DOIVENT être nuls
 *           pour que _mm256_mul_epu32 soit correct).
 * rk_vec  : clé Feistel pré-broadcastée via _mm256_set1_epi64x(rk)
 *           rk ∈ [1, P32_PRIME) → tient sur 32 bits → compatible mul_epu32
 * Sortie  : 4 valeurs ∈ [0, P32_PRIME)
 *
 * PERFORMANCE : rk_vec doit être broadcasté UNE SEULE FOIS par l'appelant,
 * pas à l'intérieur de cette fonction (suppression du broadcast interne).
 */
static inline __m256i _feistel_f_avx2(__m256i r32_vec, __m256i rk_vec) {
    /* product = r32 × rk  (chaque lane : 32 × 32 → 64 bits, exact) */
    __m256i prod = _mm256_mul_epu32(r32_vec, rk_vec);

    /* sum1 = 5 × (prod >> 32) + (prod & 0xFFFFFFFF) */
    __m256i hi1  = _mm256_srli_epi64(prod, 32);
    __m256i lo1  = _mm256_and_si256(prod, _MASK32);
    __m256i sum1 = _mm256_add_epi64(_mul5_epi64(hi1), lo1);

    /* sum2 = 5 × (sum1 >> 32) + (sum1 & 0xFFFFFFFF) */
    __m256i hi2  = _mm256_srli_epi64(sum1, 32);
    __m256i lo2  = _mm256_and_si256(sum1, _MASK32);
    __m256i sum2 = _mm256_add_epi64(_mul5_epi64(hi2), lo2);

    /* Soustraction conditionnelle : result = sum2 >= P32 ? sum2 - P32 : sum2 */
    __m256i diff = _mm256_sub_epi64(sum2, _P32_VEC);
    /* diff < 0 (signé) ⟺ sum2 < P32  ⟺  garder sum2 */
    __m256i mask = _mm256_cmpgt_epi64(_mm256_setzero_si256(), diff);
    return _mm256_blendv_epi8(diff, sum2, mask);
}

/* ── Une passe Feistel forward sur 4 éléments ──────────────────────
 *
 * PERFORMANCE : rk0_vec / rk1_vec sont des __m256i pré-broadcastés
 * par l'appelant — évite 2 VPBROADCASTQ par appel.
 */
static inline __m256i _feistel_pass_avx2(__m256i x4,
                                          __m256i rk0_vec, __m256i rk1_vec) {
    /* Extraire L (bits 32-63) et R (bits 0-31) de chaque lane */
    __m256i R0 = _mm256_and_si256(x4, _MASK32);
    __m256i L0 = _mm256_srli_epi64(x4, 32);

    /* Ronde 1 : L1 = R0 ; R1 = L0 ^ f(R0, rk0) */
    __m256i f0 = _feistel_f_avx2(R0, rk0_vec);
    __m256i L1 = R0;
    __m256i R1 = _mm256_xor_si256(L0, f0);

    /* Ronde 2 : L2 = R1 ; R2 = L1 ^ f(R1, rk1) */
    __m256i f1 = _feistel_f_avx2(R1, rk1_vec);
    __m256i L2 = R1;
    __m256i R2 = _mm256_xor_si256(L1, f1);

    /* Reconstituer : (L2 << 32) | R2  (R2 < P32 < 2^32, donc OK) */
    return _mm256_or_si256(_mm256_slli_epi64(L2, 32), R2);
}

/* ── Une passe Feistel inverse sur 4 éléments ───────────────────────── */
static inline __m256i _feistel_pass_inv_avx2(__m256i y4,
                                              __m256i rk0_vec, __m256i rk1_vec) {
    __m256i L2 = _mm256_srli_epi64(y4, 32);
    __m256i R2 = _mm256_and_si256(y4, _MASK32);

    /* Inverser ronde 2 : R1 = L2 ; L1 = R2 ^ f(L2, rk1) */
    __m256i f1 = _feistel_f_avx2(L2, rk1_vec);
    __m256i R1 = L2;
    __m256i L1 = _mm256_xor_si256(R2, f1);

    /* Inverser ronde 1 : R0 = L1 ; L0 = R1 ^ f(L1, rk0) */
    __m256i f0 = _feistel_f_avx2(L1, rk0_vec);
    __m256i R0 = L1;
    __m256i L0 = _mm256_xor_si256(R1, f0);

    return _mm256_or_si256(_mm256_slli_epi64(L0, 32), R0);
}

/* ══════════════════════════════════════════════════════════════════════
 *  Hot-path : boucle bloc avec broadcasts hoistés, sans zeroupper
 *  Utilisé depuis la boucle chaude de cagoule_cbc_encrypt/decrypt.
 *  Le zeroupper final est émis UNE SEULE FOIS par cagoule_cbc_encrypt.
 * ══════════════════════════════════════════════════════════════════════ */

static inline void _sbox_block_forward_hot_avx2(const CagouleSBox64* s,
                                                  const uint64_t* in,
                                                  uint64_t* out, unsigned n)
{
    /* Broadcasts hoistés : 1× par bloc de n éléments au lieu de n/4 × 2 */
    const __m256i rk0_vec = _mm256_set1_epi64x((int64_t)s->rk0);
    const __m256i rk1_vec = _mm256_set1_epi64x((int64_t)s->rk1);
    const __m256i p_vec   = _mm256_set1_epi64x((int64_t)s->p);
    const __m256i flip    = _mm256_set1_epi64x((int64_t)0x8000000000000000ULL);
    const uint64_t p      = s->p;
    unsigned i = 0;

    for (; i + 4 <= n; i += 4) {
        __m256i x4 = _mm256_loadu_si256((const __m256i*)(in + i));
        __m256i r4 = _feistel_pass_avx2(x4, rk0_vec, rk1_vec);
        _mm256_storeu_si256((__m256i*)(out + i), r4);
        /* Cycle-walking (probabilité ≈ 0 pour p ≈ 2^64) */
        __m256i cmp = _mm256_cmpgt_epi64(
            _mm256_xor_si256(r4, flip),
            _mm256_xor_si256(p_vec, flip));
        if (__builtin_expect(!_mm256_testz_si256(cmp, cmp), 0)) {
            for (int k = 0; k < 4; k++)
                if (out[i+k] >= p) {
                    uint64_t v = out[i+k];
                    while (v >= p) v = cagoule_sbox_forward(s, v);
                    out[i+k] = v;
                }
        }
    }
    for (; i < n; i++)
        out[i] = cagoule_sbox_forward(s, in[i]);
    /* Pas de _mm256_zeroupper() ici — l'appelant (cagoule_cbc_encrypt
     * ou cagoule_sbox_block_forward_avx2) en est responsable. */
}

static inline void _sbox_block_inverse_hot_avx2(const CagouleSBox64* s,
                                                  const uint64_t* in,
                                                  uint64_t* out, unsigned n)
{
    const __m256i rk0_vec = _mm256_set1_epi64x((int64_t)s->rk0);
    const __m256i rk1_vec = _mm256_set1_epi64x((int64_t)s->rk1);
    const __m256i p_vec   = _mm256_set1_epi64x((int64_t)s->p);
    const __m256i flip    = _mm256_set1_epi64x((int64_t)0x8000000000000000ULL);
    const uint64_t p      = s->p;
    unsigned i = 0;

    for (; i + 4 <= n; i += 4) {
        __m256i y4 = _mm256_loadu_si256((const __m256i*)(in + i));
        __m256i r4 = _feistel_pass_inv_avx2(y4, rk0_vec, rk1_vec);
        _mm256_storeu_si256((__m256i*)(out + i), r4);
        __m256i cmp = _mm256_cmpgt_epi64(
            _mm256_xor_si256(r4, flip),
            _mm256_xor_si256(p_vec, flip));
        if (__builtin_expect(!_mm256_testz_si256(cmp, cmp), 0)) {
            for (int k = 0; k < 4; k++)
                if (out[i+k] >= p) {
                    uint64_t v = out[i+k];
                    while (v >= p) v = cagoule_sbox_inverse(s, v);
                    out[i+k] = v;
                }
        }
    }
    for (; i < n; i++)
        out[i] = cagoule_sbox_inverse(s, in[i]);
}

/* ══════════════════════════════════════════════════════════════════════
 *  API publique AVX2 — blocs de 4 éléments
 * ══════════════════════════════════════════════════════════════════════ */

/**
 * Chiffrement Feistel AVX2 sur un bloc de 4 éléments.
 * Broadcast rk0/rk1 en interne (usage standalone : Python, tests).
 * Pour la boucle chaude cipher.c, utiliser _sbox_block_forward_hot_avx2.
 */
static inline void cagoule_sbox_forward4_avx2(const CagouleSBox64* s,
                                               const uint64_t in[4],
                                               uint64_t out[4])
{
    const __m256i rk0_vec = _mm256_set1_epi64x((int64_t)s->rk0);
    const __m256i rk1_vec = _mm256_set1_epi64x((int64_t)s->rk1);
    const __m256i p_vec   = _mm256_set1_epi64x((int64_t)s->p);
    const __m256i flip    = _mm256_set1_epi64x((int64_t)0x8000000000000000ULL);
    const uint64_t p      = s->p;

    __m256i x4 = _mm256_loadu_si256((const __m256i*)in);
    __m256i r4 = _feistel_pass_avx2(x4, rk0_vec, rk1_vec);
    _mm256_storeu_si256((__m256i*)out, r4);

    __m256i cmp = _mm256_cmpgt_epi64(
        _mm256_xor_si256(r4, flip),
        _mm256_xor_si256(p_vec, flip));
    if (__builtin_expect(!_mm256_testz_si256(cmp, cmp), 0)) {
        for (int i = 0; i < 4; i++)
            if (out[i] >= p) {
                uint64_t v = out[i];
                while (v >= p) v = cagoule_sbox_forward(s, v);
                out[i] = v;
            }
    }
    /* zeroupper absent : cette inline est appelée depuis
     * cagoule_sbox_block_forward_avx2 qui émet le zeroupper final. */
}

/**
 * Déchiffrement Feistel AVX2 sur un bloc de 4 éléments.
 */
static inline void cagoule_sbox_inverse4_avx2(const CagouleSBox64* s,
                                               const uint64_t in[4],
                                               uint64_t out[4])
{
    const __m256i rk0_vec = _mm256_set1_epi64x((int64_t)s->rk0);
    const __m256i rk1_vec = _mm256_set1_epi64x((int64_t)s->rk1);
    const __m256i p_vec   = _mm256_set1_epi64x((int64_t)s->p);
    const __m256i flip    = _mm256_set1_epi64x((int64_t)0x8000000000000000ULL);
    const uint64_t p      = s->p;

    __m256i y4 = _mm256_loadu_si256((const __m256i*)in);
    __m256i r4 = _feistel_pass_inv_avx2(y4, rk0_vec, rk1_vec);
    _mm256_storeu_si256((__m256i*)out, r4);

    __m256i cmp = _mm256_cmpgt_epi64(
        _mm256_xor_si256(r4, flip),
        _mm256_xor_si256(p_vec, flip));
    if (__builtin_expect(!_mm256_testz_si256(cmp, cmp), 0)) {
        for (int i = 0; i < 4; i++)
            if (out[i] >= p) {
                uint64_t v = out[i];
                while (v >= p) v = cagoule_sbox_inverse(s, v);
                out[i] = v;
            }
    }
}

/* ── Nettoyage des macros locales ─────────────────────────────────── */
#undef _P32
#undef _P32_VEC
#undef _MASK32

#endif /* __AVX2__ */
#endif /* CAGOULE_SBOX_AVX2_H */
