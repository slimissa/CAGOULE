/**
 * cagoule_cipher.h — Pipeline CBC-like CAGOULE v3.1.0
 *
 * v2.5.0 — Z-Domain Shifting en C-layer :
 *   z_offset[16] uint64 ∈ Z/pZ, appliqué comme byte[i] = (byte[i] + zo[i]%256) % 256 (Z/256Z byte domain) avant la matrice (encrypt)
 *   et soustrait après la S-box inverse (decrypt). Coût ~8 ms/MB
 *   vs 82 ms/MB en Python. Gain : +32% Python e2e.
 *
 * v2.4.0 — Pipeline multi-blocs SIMD :
 *   Dispatch automatique vers _pipeline4 si AVX2 + n_blocks >= THRESHOLD.
 *   Résultats bit-à-bit identiques au chemin mono-bloc.
 */

#ifndef CAGOULE_CIPHER_H
#define CAGOULE_CIPHER_H

#include <stdint.h>
#include <stddef.h>
#include "cagoule_math.h"
#include "cagoule_matrix.h"
#include "cagoule_sbox.h"

/* Codes d'erreur */
#define CAGOULE_OK           0
#define CAGOULE_ERR_NULL    -1
#define CAGOULE_ERR_SIZE    -2
#define CAGOULE_ERR_CORRUPT -3

/* Seuil pour activer le pipeline4 */
#define CAGOULE_PIPELINE4_THRESHOLD 8

/* ── CGL1 Version constants (v3.0.0) ──────────────────────────────── */
#define CAGOULE_CGL1_VERSION_CBC  0x01
#define CAGOULE_CGL1_VERSION_CTR  0x02


/* Nombre d'octets pour un élément de Z/pZ */
static inline size_t cagoule_p_bytes(uint64_t p) {
    return (p > 0xFFFFFFFF) ? 8 : 4;
}

/**
 * cagoule_cbc_encrypt — v3.0.0
 *
 * @param padded      Plaintext PKCS7-paddé (n_blocks × 16 bytes)
 * @param n_blocks    Nombre de blocs
 * @param out         Sortie (n_blocks × 16 × p_bytes)
 * @param out_size    Taille buffer out
 * @param mat         Matrice Vandermonde forward
 * @param sbox        S-box Feistel
 * @param round_keys  Clés de ronde (mod p)
 * @param num_keys    Nombre de clés de ronde
 * @param p           Premier de travail (Mersenne ou autre)
 * @param z_offset    Z-Domain Shifting : 16 offsets uint64 dans [0,p).
 *                    NULL ou num_zo==0 → pas de z_offset (compatibilité v2.4).
 * @param num_zo      Nombre d'éléments dans z_offset (0 ou 16)
 * @return            CAGOULE_OK ou code erreur négatif
 */
int cagoule_cbc_encrypt(
    const uint8_t*       padded,
    size_t               n_blocks,
    uint8_t*             out,
    size_t               out_size,
    const CagouleMatrix* mat,
    const CagouleSBox64* sbox,
    const uint64_t*      round_keys,
    size_t               num_keys,
    uint64_t             p,
    const uint64_t*      z_offset,
    size_t               num_zo
);

/**
 * cagoule_cbc_decrypt — v2.5.4
 *
 * @param z_offset    Z-Domain Shifting inverse (même tableau que encrypt).
 *                    NULL ou num_zo==0 → désactivé.
 */
int cagoule_cbc_decrypt(
    const uint8_t*       cipher_bytes,
    size_t               n_blocks,
    uint8_t*             out,
    size_t               out_size,
    const CagouleMatrix* mat,
    const CagouleSBox64* sbox,
    const uint64_t*      round_keys,
    size_t               num_keys,
    uint64_t             p,
    const uint64_t*      z_offset,
    size_t               num_zo
);

#endif /* CAGOULE_CIPHER_H */

