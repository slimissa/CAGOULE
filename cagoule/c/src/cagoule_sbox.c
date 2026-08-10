/**
 * sbox.c — S-box Feistel 32-bit CAGOULE v3.1.0
 *
 * Résout le ratio 7.8× déchiffrement/chiffrement de v1.x.
 * v2.0 : forward = Feistel 2 rondes → 2 mulmod32
 *        inverse = Feistel inversé → 2 mulmod32 (MÊME COÛT)
 *
 * Technique : cycle-walking pour garantir la sortie dans [0, p).
 * Pour p ≈ 2^64 : la probabilité de marche > 0 itération ≈ 0.
 *
 * Fallback x^d pour p < 2^32 (tests/petits p) avec inverse rapide.
 */

#include <stdlib.h>
#include <string.h>

#include "cagoule_math.h"
#include "cagoule_sbox.h"

/* ── Fonction de mélange Feistel (CORRIGÉE : retour uint64_t) ────────
 *
 * f(x32, rk) = (x32 * rk) % CAGOULE_P32_PRIME
 * Retourne un uint64_t car P32_PRIME < 2^32, mais safe.
 */
static inline uint64_t _feistel_f(uint32_t x, uint64_t rk) {
    return (__uint128_t)x * rk % CAGOULE_P32_PRIME;
}

/* ── Une passe Feistel forward (adaptée au nouveau type) ─────────────*/
static inline uint64_t _feistel_pass(uint64_t x, uint64_t rk0, uint64_t rk1) {
    uint32_t L0 = (uint32_t)(x >> 32);
    uint32_t R0 = (uint32_t)(x & 0xFFFFFFFF);

    uint32_t L1 = R0;
    uint32_t R1 = L0 ^ (uint32_t)_feistel_f(R0, rk0);

    uint32_t L2 = R1;
    uint32_t R2 = L1 ^ (uint32_t)_feistel_f(R1, rk1);

    return ((uint64_t)L2 << 32) | (uint64_t)R2;
}

/* ── Une passe Feistel inverse (adaptée) ─────────────────────────────*/
static inline uint64_t _feistel_pass_inv(uint64_t y, uint64_t rk0, uint64_t rk1) {
    uint32_t L2 = (uint32_t)(y >> 32);
    uint32_t R2 = (uint32_t)(y & 0xFFFFFFFF);

    uint32_t R1 = L2;
    uint32_t L1 = R2 ^ (uint32_t)_feistel_f(L2, rk1);

    uint32_t R0 = L1;
    uint32_t L0 = R1 ^ (uint32_t)_feistel_f(L1, rk0);

    return ((uint64_t)L0 << 32) | (uint64_t)R0;
}

/* ── Inverse modulaire générique (Euclide étendu) pour fallback ──────
 * Calcule a^(-1) mod m (m non nécessairement premier)
 */
/* CORRECTIF v3.1.0 (Finding 3) : l'ancienne implémentation utilisait int64_t
 * pour des valeurs jusqu'à ~2^64 (primes Mersenne-64), causant un overflow
 * implementation-defined. Cette fonction n'est appelée QUE sur le chemin
 * use_feistel==0 (p < CAGOULE_SBOX_LARGE_PRIME_THRESHOLD = 2^32), donc jamais
 * en production avec le pool Mersenne-64. Néanmoins, corrigée pour utiliser
 * __int128 afin d'être correcte sur tous les inputs possibles.
 *
 * NOTE : si le support des petits premiers (p < 2^32) est définitivement retiré,
 * supprimer cette fonction. */
static uint64_t _invmod_generic(uint64_t a, uint64_t m) {
    __int128 t = 0, newt = 1;
    __int128 r = (__int128)m, newr = (__int128)a;

    while (newr != 0) {
        __int128 q = r / newr;
        __int128 tmp = newt;
        newt = t - q * newt;
        t = tmp;
        tmp = newr;
        newr = r - q * newr;
        r = tmp;
    }

    if (r > 1) return 0;   /* Pas d'inverse */
    if (t < 0) t += (__int128)m;
    return (uint64_t)t;
}

/* ── Calcul du d pour fallback (gcd(d, p-1) = 1) ────────────────────*/
static uint64_t _find_d(uint64_t p) {
    if (p <= 3) return 1;
    uint64_t pm1 = p - 1;
    for (uint64_t d = 3; d < pm1 && d < 100; d += 2) {
        uint64_t a = d, b = pm1;
        while (b) { uint64_t t = b; b = a % b; a = t; }
        if (a == 1) return d;
    }
    return 1;
}

/* ── API publique ───────────────────────────────────────────────────*/

void cagoule_sbox_init(CagouleSBox64* s, uint64_t p, uint64_t rk0, uint64_t rk1) {
    s->p = p;
    /* CORRECTIF v3.1.0 (Finding 5) : rk0/rk1 ne peuvent pas être 0 car
     * _feistel_f(x, 0) = (x * 0) % P32_PRIME = 0 (constante → pas de confusion).
     * Remplacement silencieux par 1. La couche Python (params.py) doit dériver
     * delta dans [1, p-1] pour éviter ce cas : voir fix params.py correspondant.
     * Note : rk0/rk1 sont des clés de ronde dérivées de k_master via HKDF —
     * la probabilité que HKDF produise exactement 0 est ~2^-64, négligeable. */
    s->rk0 = (rk0 == 0) ? 1 : (rk0 % CAGOULE_P32_PRIME);
    s->rk1 = (rk1 == 0) ? 1 : (rk1 % CAGOULE_P32_PRIME);

    if (p >= CAGOULE_SBOX_LARGE_PRIME_THRESHOLD) {
        s->use_feistel = 1;
        s->d = s->d_inv = 0;
    } else {
        s->use_feistel = 0;
        s->d = _find_d(p);
        if (s->d == 1) {
            s->d_inv = 1;
        } else {
            s->d_inv = _invmod_generic(s->d, p - 1);
            if (s->d_inv == 0) s->d_inv = 1;  /* Fallback ultime */
        }
    }
}

uint64_t cagoule_sbox_forward(const CagouleSBox64* s, uint64_t x) {
    if (!s->use_feistel)
        return powmod64(x, s->d, s->p);

    uint64_t r = _feistel_pass(x, s->rk0, s->rk1);
    while (r >= s->p)
        r = _feistel_pass(r, s->rk0, s->rk1);
    return r;
}

uint64_t cagoule_sbox_inverse(const CagouleSBox64* s, uint64_t y) {
    if (!s->use_feistel)
        return powmod64(y, s->d_inv, s->p);

    uint64_t r = _feistel_pass_inv(y, s->rk0, s->rk1);
    while (r >= s->p)
        r = _feistel_pass_inv(r, s->rk0, s->rk1);
    return r;
}

void cagoule_sbox_block_forward(const CagouleSBox64* s,
                                 const uint64_t* in,
                                 uint64_t* out, size_t n)
{
    for (size_t i = 0; i < n; i++)
        out[i] = cagoule_sbox_forward(s, in[i]);
}

void cagoule_sbox_block_inverse(const CagouleSBox64* s,
                                 const uint64_t* in,
                                 uint64_t* out, size_t n)
{
    for (size_t i = 0; i < n; i++)
        out[i] = cagoule_sbox_inverse(s, in[i]);
}