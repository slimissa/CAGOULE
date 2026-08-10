/**
 * cagoule_math.h — Arithmétique modulaire 64-bit CAGOULE v3.1.0
 *
 * Toutes les fonctions sont inline pour permettre l'optimisation
 * par le compilateur au site d'appel (élimination de boucle, unroll...).
 *
 * Requis : compilateur supportant __uint128_t (GCC ≥ 4.6, Clang ≥ 3.1)
 *          Architecture x86_64 recommandée (instruction MUL 64-bit native).
 */

#ifndef CAGOULE_MATH_H
#define CAGOULE_MATH_H

#include <stdint.h>
#include <assert.h>

/* ── Primitive de base : multiplication mod p ──────────────────────────
 *
 * a * b mod p sans overflow — clé de tout le schéma.
 * __uint128_t émet une seule instruction MUL 128-bit sur x86_64.
 */
static inline uint64_t mulmod64(uint64_t a, uint64_t b, uint64_t p) {
    return (uint64_t)((__uint128_t)a * b % p);
}

/* ── Addition/soustraction mod p optimisées (sans division 128-bit) ──
 *
 * Version rapide : une seule condition, pas de modulo coûteux.
 * Pour p ≈ 2^64, le risque de overflow est géré par le test sum < a.
 */
static inline uint64_t addmod64(uint64_t a, uint64_t b, uint64_t p) {
    uint64_t sum = a + b;
    if (sum < a || sum >= p) sum -= p;
    return sum;
}

static inline uint64_t submod64(uint64_t a, uint64_t b, uint64_t p) {
    uint64_t diff = a - b;
    if (a < b) diff += p;
    return diff;
}

/* ── Exponentiation rapide mod p (square-and-multiply) ─────────────── */
static inline uint64_t powmod64(uint64_t base, uint64_t exp, uint64_t p) {
    if (p == 1) return 0;
    uint64_t result = 1;
    base %= p;
    while (exp > 0) {
        if (exp & 1) result = mulmod64(result, base, p);
        base = mulmod64(base, base, p);
        exp >>= 1;
    }
    return result;
}

/* ── Inverse modulaire par petit théorème de Fermat ────────────────────
 *
 * a^(-1) mod p = a^(p-2) mod p  (valide car p premier)
 * Précondition : a != 0, p premier
 */
static inline uint64_t invmod64(uint64_t a, uint64_t p) {
    assert(a != 0 && "invmod64: division par zéro");
    assert(p > 1 && "invmod64: modulus must be > 1");
    return powmod64(a, p - 2, p);
}

/* ── Négation mod p ─────────────────────────────────────────────────── */
static inline uint64_t negmod64(uint64_t a, uint64_t p) {
    return a == 0 ? 0 : p - a;
}

/* ── Lazy reduction helpers (v3.1.0 performance) ─────────────────────
 *
 * For Mersenne-64 primes p = 2^64 - k with k < 2^10, up to 32 products
 * can be accumulated in a __uint128_t before overflow. This eliminates
 * 15 out of 16 modular reductions per dot product in the matrix path.
 */

/* Accumulate a*b into a __uint128_t without reduction.
 * Safe for up to k terms per accumulator (k ≥ 59 for all CAGOULE primes). */
static inline void mulacc128(__uint128_t *acc, uint64_t a, uint64_t b) {
    *acc += (__uint128_t)a * b;
}

/* Reduce a __uint128_t accumulator modulo p.
 * For Mersenne primes p = 2^64 - k, use the identity:
 *   hi*2^64 + lo ≡ hi*k + lo (mod p)
 * Since hi < k (accumulator < k*p < k*2^64), hi*k fits in uint64_t. */
static inline uint64_t reduce128_mersenne(__uint128_t acc, uint64_t p, uint64_t k) {
    uint64_t hi = (uint64_t)(acc >> 64);
    uint64_t lo = (uint64_t)acc;
    /* hi < k < 2^10, so hi*k < 2^74 — fits in __uint128_t */
    __uint128_t reduced = (__uint128_t)hi * k + lo;
    /* One conditional subtract if >= p */
    if (reduced >= p) reduced -= p;
    if (reduced >= p) reduced -= p;  /* second subtract for k > 1 edge case */
    return (uint64_t)reduced;
}

/* Generic lazy reduction for non-Mersenne primes.
 * Uses Barrett-like: acc % p via __uint128_t division (one DIV, slow). */
static inline uint64_t reduce128_generic(__uint128_t acc, uint64_t p) {
    return (uint64_t)(acc % p);
}

#endif /* CAGOULE_MATH_H */
/* ══════════════════════════════════════════════════════════════════════
 * Pool Mersenne-64 — CAGOULE v2.5.0
 *
 * 8 premiers de la forme p = 2^64 − k, vérifiés Miller-Rabin (13 témoins).
 * k < 2^10 garantit : hi*k < 2^74, gérable en 2 rounds de carry dans
 * mulmod_mersenne64x4.
 *
 * Sélection : index = HKDF(k_master, "CAGOULE_PRIME_SEL_V25")[0] % 8
 * Définitions dans cagoule_math.c ; déclarations extern ici pour éviter
 * les redéfinitions lors de l'inclusion multiple.
 * ══════════════════════════════════════════════════════════════════════ */
#define CAGOULE_MERSENNE_POOL_SIZE 8

extern const uint64_t CAGOULE_MERSENNE_K[CAGOULE_MERSENNE_POOL_SIZE];
extern const uint64_t CAGOULE_MERSENNE_P[CAGOULE_MERSENNE_POOL_SIZE];

/**
 * Retourne k si p appartient au pool Mersenne-64, 0 sinon.
 * Utilisé par cagoule_matrix_build() pour initialiser CagouleMatrix.k_mersenne.
 */
uint64_t cagoule_mersenne_k(uint64_t p);

