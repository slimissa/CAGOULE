/**
 * cagoule_ctr.h — CTR Mode CAGOULE v3.1.0
 *
 * Implémentation du mode compteur (CTR) pour CAGOULE.
 *
 * Architecture :
 *   Pour le bloc bi (0-indexé), le bloc compteur est construit comme :
 *     counter_block[0..7]  = IV  (big-endian uint64, 8 octets, un par élément)
 *     counter_block[8..15] = bi  (big-endian uint64, 8 octets, un par élément)
 *   Soit 16 octets chargés comme 16 uint64 (1 octet par élément),
 *   identique à _load_plain en CBC.
 *
 *   Pipeline keystream (sans feedback inter-blocs) :
 *     1. Charger counter_block → blk[16] ∈ [0,255]^16
 *     2. cagoule_matrix_mul(mat, blk, tmp)
 *     3. cagoule_sbox_block_forward(sbox, tmp, blk)
 *     4. blk[j] = (blk[j] + rk[bi % nk]) % p
 *     5. keystream[j] = (uint8_t)(blk[j] & 0xFF)  pour j = 0..15
 *
 * Extraction keystream → 16 octets par bloc compteur.
 *
 * Chiffrement :
 *   with z_offset (Z-Domain Shifting) :
 *     ct[bi*16+j] = ((pt[bi*16+j] + zo_byte[j]) & 0xFF) ^ ks[j]
 *   sans z_offset :
 *     ct[bi*16+j] = pt[bi*16+j] ^ ks[j]
 *
 * Déchiffrement (CTR est symétrique) :
 *   with z_offset :
 *     pt[bi*16+j] = ((ct[bi*16+j] ^ ks[j]) - zo_byte[j] + 256) & 0xFF
 *   sans z_offset :
 *     pt[bi*16+j] = ct[bi*16+j] ^ ks[j]
 *
 * Propriétés :
 *   - Zéro dépendance inter-blocs → ILP maximal (×4 en ctr_encrypt_4x)
 *   - Longueur ciphertext == longueur plaintext (pas de PKCS7)
 *   - Z-Domain Shifting conservé identique au mode CBC
 *   - Constant-time : même pipeline que CBC (mulmod_mersenne64x4, addmod64x4)
 *
 * Format CGL1 v0x02 :
 *   MAGIC(4) | VERSION=0x02(1) | SALT(32) | NONCE(12) | CT(n) | TAG(16)
 *   IV = HKDF(k_master, "CAGOULE_CTR_V31" + nonce, 8) — non stocké dans
 *   le header (dérivé côté appelant à partir de k_master et du nonce
 *   déjà présent dans le header). CORRECTIF (audit round 2) : le nonce
 *   manquait dans cette formule -- l'IV ne dépendait alors, sur le
 *   papier, que de k_master, ce qui aurait été un two-time-pad classique
 *   sous k_master partagé. Ce n'est PAS ce que fait le code réel (voir
 *   cagoule_api.c::derive_iv() pour la formule exacte et le contexte
 *   complet -- both derive_iv() pour 0x02/mono-message et
 *   derive_iv_raw() pour 0x03) -- cette fonction-ci (cagoule_ctr_encrypt/
 *   decrypt) ne dérive PAS l'IV elle-même, elle reçoit un `iv` déjà
 *   calculé en paramètre ; ce commentaire documente la convention que
 *   l'appelant doit suivre, pas du code implémenté dans ce fichier.
 *   CT exactement |plaintext| octets, pas de padding
 *
 * Rétrocompatibilité :
 *   VERSION 0x01 (CBC) → dispatch vers cagoule_cbc_encrypt/decrypt
 *   VERSION 0x02 (CTR) → dispatch vers cagoule_ctr_encrypt/decrypt
 */

#ifndef CAGOULE_CTR_H
#define CAGOULE_CTR_H

#include <stdint.h>
#include <stddef.h>
#include "cagoule_math.h"
#include "cagoule_matrix.h"
#include "cagoule_sbox.h"
#include "cagoule_cipher.h"   /* CAGOULE_OK, CAGOULE_ERR_*, CAGOULE_N */

/* Taille de l'IV CTR en octets (uint64 big-endian) */
#define CAGOULE_CTR_IV_SIZE       8

/* Seuil pour activer le pipeline 4x (identique au seuil CBC p4) */
#define CAGOULE_CTR_P4_THRESHOLD  CAGOULE_PIPELINE4_THRESHOLD

#ifdef PROFILE_CTR
void cagoule_ctr_print_profile(void);
#endif

/**
 * cagoule_ctr_keystream — Génère n_blocks × 16 octets de keystream.
 *
 * @param iv         IV de 8 octets (big-endian uint64), dérivé de k_master
 * @param start_bi   Index du premier bloc compteur (0 pour le début du message)
 * @param mat        Matrice Vandermonde (forward)
 * @param sbox       S-box Feistel
 * @param rk         Clés de ronde
 * @param nk         Nombre de clés de ronde
 * @param p          Premier de travail (Mersenne ou autre)
 * @param out        Buffer de sortie : n_blocks × 16 octets de keystream
 * @param n_blocks   Nombre de blocs compteurs à générer
 * @return           CAGOULE_OK ou code d'erreur négatif
 */
int cagoule_ctr_keystream(
    const uint8_t*        iv,
    size_t                start_bi,
    const CagouleMatrix*  mat,
    const CagouleSBox64*  sbox,
    const uint64_t*       rk,
    size_t                nk,
    uint64_t              p,
    uint8_t*              out,
    size_t                n_blocks
);

/**
 * cagoule_ctr_encrypt — Chiffrement CTR (et déchiffrement, symétrique).
 *
 * Produit un ciphertext de même longueur que le plaintext.
 * Pas de PKCS7.
 *
 * @param pt         Plaintext (longueur arbitraire)
 * @param pt_len     Longueur du plaintext en octets
 * @param iv         IV 8 octets
 * @param mat        Matrice Vandermonde
 * @param sbox       S-box Feistel
 * @param rk         Clés de ronde
 * @param nk         Nombre de clés de ronde
 * @param p          Premier de travail
 * @param z_offset   Z-Domain Shifting : 16 offsets uint64, ou NULL si désactivé
 * @param num_zo     Taille de z_offset (16 ou 0)
 * @param out        Buffer de sortie (doit avoir au moins pt_len octets)
 * @param out_size   Taille du buffer out (doit être >= pt_len)
 * @return           CAGOULE_OK ou code d'erreur négatif
 */
int cagoule_ctr_encrypt(
    const uint8_t*        pt,
    size_t                pt_len,
    const uint8_t*        iv,
    const CagouleMatrix*  mat,
    const CagouleSBox64*  sbox,
    const uint64_t*       rk,
    size_t                nk,
    uint64_t              p,
    const uint64_t*       z_offset,
    size_t                num_zo,
    uint8_t*              out,
    size_t                out_size
);

/**
 * cagoule_ctr_decrypt — Déchiffrement CTR (identique à encrypt, CTR est symétrique).
 *
 * Même signature que cagoule_ctr_encrypt.
 * Fourni séparément pour la clarté de l'API et les tests Python.
 */
int cagoule_ctr_decrypt(
    const uint8_t*        ct,
    size_t                ct_len,
    const uint8_t*        iv,
    const CagouleMatrix*  mat,
    const CagouleSBox64*  sbox,
    const uint64_t*       rk,
    size_t                nk,
    uint64_t              p,
    const uint64_t*       z_offset,
    size_t                num_zo,
    uint8_t*              out,
    size_t                out_size
);

/**
 * cagoule_ctr_encrypt_4x — Variante pipeline 4-blocs simultanés.
 *
 * Traite 4 blocs compteurs indépendants en parallèle (ILP maximal).
 * Résultat bit-à-bit identique à cagoule_ctr_encrypt.
 * Utilisé quand n_blocs >= CAGOULE_CTR_P4_THRESHOLD et AVX2 disponible.
 * Symétrique (valide pour encrypt ET decrypt).
 */
int cagoule_ctr_encrypt_4x(
    const uint8_t*        pt,
    size_t                pt_len,
    const uint8_t*        iv,
    const CagouleMatrix*  mat,
    const CagouleSBox64*  sbox,
    const uint64_t*       rk,
    size_t                nk,
    uint64_t              p,
    const uint64_t*       z_offset,
    size_t                num_zo,
    uint8_t*              out,
    size_t                out_size
);

#endif /* CAGOULE_CTR_H */
