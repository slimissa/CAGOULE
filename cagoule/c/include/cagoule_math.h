/**
 * cagoule_math.h — Arithmétique modulaire 64-bit CAGOULE v2.0.0
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

#endif /* CAGOULE_MATH_H */