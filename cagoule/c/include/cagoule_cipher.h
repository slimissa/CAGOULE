/**
 * cagoule_cipher.h — Pipeline CBC-like CAGOULE v2.0.0
 *
 * Clé de l'optimisation v2.0 :
 *   v1.x : 65 536 appels ctypes par MB → overhead ×6
 *   v2.0 : 1 seul appel C pour tout le MB → overhead ~0
 *
 * Entrée/Sortie en bytes bruts (uint8_t) :
 *   - Python passe le plaintext PKCS7-paddé une seule fois
 *   - C traite tous les blocs en boucle native
 *   - Python récupère T(message) en bytes
 */

#ifndef CAGOULE_CIPHER_H
#define CAGOULE_CIPHER_H

#include <stdint.h>
#include <stddef.h>
#include "cagoule_math.h"      
#include "cagoule_matrix.h"
#include "cagoule_sbox.h"

/* Codes d'erreur explicites */
#define CAGOULE_OK          0
#define CAGOULE_ERR_NULL   -1
#define CAGOULE_ERR_SIZE   -2
#define CAGOULE_ERR_CORRUPT -3

/* Calcule le nombre d'octets nécessaires pour stocker un élément de Z/pZ */
static inline size_t cagoule_p_bytes(uint64_t p) {
    return (p > 0xFFFFFFFF) ? 8 : 4;
}

/* ── Chiffrement CBC-like ───────────────────────────────────────────
 *
 * Traite n_blocks blocs de 16 bytes en une seule passe C.
 *
 * @param padded      Plaintext PKCS7-paddé (longueur = n_blocks * 16)
 * @param n_blocks    Nombre de blocs
 * @param out         Sortie T(message) (taille = n_blocks * 16 * p_bytes)
 * @param out_size    Taille du buffer out (pour sécurité)
 * @param mat         Matrice de diffusion Vandermonde (forward)
 * @param sbox        S-box Feistel
 * @param round_keys  Tableau des clés de ronde (mod p)
 * @param num_keys    Nombre de clés de ronde
 * @param p           Premier de travail
 * @return            0 si succès, code négatif si erreur
 */
int cagoule_cbc_encrypt(
    const uint8_t*       padded,
    size_t               n_blocks,
    uint8_t*             out,
    size_t               out_size,
    const CagouleMatrix* mat,
    CagouleSBox64*       sbox,
    const uint64_t*      round_keys,
    size_t               num_keys,
    uint64_t             p
);

/* ── Déchiffrement CBC-like (inverse) ───────────────────────────────
 *
 * @param cipher_bytes  T(message) chiffré (taille = n_blocks * 16 * p_bytes)
 * @param n_blocks      Nombre de blocs
 * @param out           Plaintext PKCS7-paddé (taille = n_blocks * 16)
 * @param out_size      Taille du buffer out (pour sécurité)
 * @param mat           Matrice de diffusion (inverse)
 * @param sbox          S-box Feistel
 * @param round_keys    Tableau des clés de ronde
 * @param num_keys      Nombre de clés de ronde
 * @param p             Premier de travail
 * @return              0 si succès, code négatif si erreur
 */
int cagoule_cbc_decrypt(
    const uint8_t*       cipher_bytes,
    size_t               n_blocks,
    uint8_t*             out,
    size_t               out_size,
    const CagouleMatrix* mat,
    CagouleSBox64*       sbox,
    const uint64_t*      round_keys,
    size_t               num_keys,
    uint64_t             p
);

#endif /* CAGOULE_CIPHER_H */