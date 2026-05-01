/**
 * cagoule_sbox.h — S-box Feistel 32-bit CAGOULE v2.0.0
 *
 * Réseau de Feistel à 2 rondes sur demi-mots 32 bits.
 * Garantit Forward et Inverse à COÛT IDENTIQUE → ratio decrypt/encrypt ≈ 1×.
 *
 * Design :
 *   x ∈ Z/pZ  →  split en (L=x>>32, R=x&0xFFFFFFFF)
 *   Ronde 1 : L' = R,   R' = L ⊕ f(R, rk0)
 *   Ronde 2 : L''= R',  R''= L'⊕ f(R', rk1)
 *   Sortie  : (L''<<32)|R''  puis cycle-walk si ≥ p
 *
 *   f(x32, rk) = ((__uint128_t)x32 * rk) % P32_PRIME
 *
 * Pour p < 2^32 : fallback vers x^d mod p (comportement v1.x pour tests)
 */

#ifndef CAGOULE_SBOX_H
#define CAGOULE_SBOX_H

#include <stdint.h>
#include <stddef.h>

/* Plus grand nombre premier < 2^32 (4294967291) – tient dans uint32_t */
#define CAGOULE_P32_PRIME  4294967291ULL

/* Seuil : p < 2^32 → fallback x^d (petits premiers pour tests) */
#define CAGOULE_SBOX_LARGE_PRIME_THRESHOLD  (1ULL << 32)

/* Fonction de mélange Feistel inline (pour performance) */
static inline uint32_t cagoule_feistel_f(uint32_t x, uint64_t rk) {
    return (uint32_t)(((__uint128_t)x * rk) % CAGOULE_P32_PRIME);
}

/* ── Structure ─────────────────────────────────────────────────────── */
typedef struct {
    uint64_t p;           /* Premier de travail (Z/pZ) */
    uint64_t rk0;         /* Clé de ronde 0 (1 ≤ rk0 < P32_PRIME) */
    uint64_t rk1;         /* Clé de ronde 1 (1 ≤ rk1 < P32_PRIME) */
    uint64_t d;           /* Exposant fallback (d=3 pour forward) */
    uint64_t d_inv;       /* Inverse de d mod (p-1) pour fallback */
    int      use_feistel; /* 1 si Feistel, 0 si fallback x^d */
} CagouleSBox64;

/* ── API ─────────────────────────────────────────────────────────────── */

/**
 * Initialise la S-box avec les clés de ronde Feistel.
 *
 * @param s    Pointeur vers la structure à initialiser
 * @param p    Premier de travail (doit être > 1)
 * @param rk0  Clé de ronde 0 (doit être != 0 et < P32_PRIME)
 * @param rk1  Clé de ronde 1 (doit être != 0 et < P32_PRIME)
 */
void cagoule_sbox_init(CagouleSBox64* s, uint64_t p,
                       uint64_t rk0, uint64_t rk1);

/**
 * Chiffrement : y = S(x)
 * @param x Entrée (0 <= x < p)
 * @return y (0 <= y < p)
 * @note Utilise le cycle-walking si le résultat Feistel >= p
 */
uint64_t cagoule_sbox_forward(const CagouleSBox64* s, uint64_t x);

/**
 * Déchiffrement : x = S^{-1}(y)
 * @param y Entrée (0 <= y < p)
 * @return x (0 <= x < p)
 * @note Même coût que forward (propriété Feistel)
 */
uint64_t cagoule_sbox_inverse(const CagouleSBox64* s, uint64_t y);

/**
 * Application vectorisée sur un bloc de n éléments (forward).
 */
void cagoule_sbox_block_forward(const CagouleSBox64* s,
                                const uint64_t* in,
                                uint64_t* out,
                                size_t n);

/**
 * Application vectorisée sur un bloc de n éléments (inverse).
 */
void cagoule_sbox_block_inverse(const CagouleSBox64* s,
                                const uint64_t* in,
                                uint64_t* out,
                                size_t n);

#endif /* CAGOULE_SBOX_H */