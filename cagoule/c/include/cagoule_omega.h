/**
 * cagoule_omega.h — Pilier Ω : ζ(2n) → Round Keys — CAGOULE v2.1.0
 *
 * Portage C complet de omega.py.
 * Supprime la dépendance mpmath en production.
 *
 * Algorithme (fidèle à omega.py) :
 *   1. ζ(2n) — table précalculée pour n ≤ 32, approximation 1.0 pour n > 32
 *   2. c_k = (2/π) * (−1)^k / k^(2n)   [coefficient de Fourier]
 *   3. ak_seed = floor(|c_k| × 2^32) & 0xFFFFFFFFFFFFFFFF  → 8 octets big-endian
 *   4. key_material = ak_seed ‖ salt ‖ n_bytes(4)
 *   5. rk_bytes = HKDF-SHA256(key_material, info="CAGOULE_ROUND_KEY_" ‖ k_bytes(4), len=32)
 *   6. round_key = int(rk_bytes, big-endian) % p
 *
 * Dépendance : OpenSSL ≥ 1.1 (libcrypto) pour HMAC-SHA256.
 *
 * Compatibilité : résultats bit-à-bit identiques à omega.py pour n ≤ 32.
 *                 Pour n > 32, double et mpmath donnent tous deux 1.0.
 */

#ifndef CAGOULE_OMEGA_H
#define CAGOULE_OMEGA_H

#ifndef M_PI
#define M_PI 3.14159265358979323846264338327950288419716939937510
#endif

#include <stdint.h>
#include <stddef.h>
#include <math.h>

/* ── Codes d'erreur ────────────────────────────────────────────────────── */
#define CAGOULE_OMEGA_OK            0
#define CAGOULE_OMEGA_ERR_NULL     -1   /* Pointeur NULL inattendu        */
#define CAGOULE_OMEGA_ERR_PARAM    -2   /* Paramètre hors domaine (n<1)   */
#define CAGOULE_OMEGA_ERR_OPENSSL  -3   /* Erreur HMAC / HKDF OpenSSL     */
#define CAGOULE_OMEGA_ERR_ALLOC    -4   /* Échec malloc                   */
#define CAGOULE_OMEGA_ERR_HKDF     -5   /* Erreur spécifique à HKDF (détail dans message d'erreur) */

/* ── Constantes ────────────────────────────────────────────────────────── */

/** Nombre de valeurs ζ(2n) stockées dans la table. Pour n > ZETA_TABLE_MAX,
 *  ζ(2n) = 1.0 en précision double (2^(−2n) < epsilon_machine). */
#define CAGOULE_OMEGA_ZETA_TABLE_MAX  32

/** Nombre de clés de ronde par défaut (identique à omega.py). */
#define CAGOULE_OMEGA_DEFAULT_NUM_KEYS  64

#define CAGOULE_OMEGA_SALT_RECOMMENDED 32   /* Taille recommandée du sel (identique à omega.py) */
#define CAGOULE_OMEGA_SALT_MAX        64    /* Limitation arbitraire pour éviter les abus (HKDF est plus lent avec de grands sels) */
#define CAGOULE_OMEGA_MAX_KEYS        256   /* Limitation mémoire */
/* ══════════════════════════════════════════════════════════════════════════
 *  API publique
 * ══════════════════════════════════════════════════════════════════════════ */

/**
 * Retourne ζ(2n) en précision double.
 *
 * Pour n ∈ [1, 32] : valeur de la table précalculée (précision ≈ 15 chiffres).
 * Pour n > 32      : retourne 1.0 (indistinguable en double de la vraie valeur).
 * Pour n < 1       : retourne NAN.
 *
 * @param n  Entier ≥ 1.
 * @return   ζ(2n) ou NAN si n < 1.
 */
double cagoule_omega_zeta_2n(int n);

/**
 * Calcule le k-ième coefficient de Fourier pour ζ(2n).
 *
 * Formule : c_k = (2/π) × (−1)^k / k^(2n)
 *
 * @param k  Indice ≥ 1.
 * @param n  Paramètre ζ(2n), entier ≥ 1.
 * @return   c_k ou NAN si k < 1 ou n < 1.
 */
double cagoule_omega_fourier_coeff(int k, int n);

/**
 * Génère num_keys clés de ronde dans Z/pZ depuis ζ(2n) et HKDF-SHA256.
 *
 * Reproduit bit-à-bit le comportement de omega.py::generate_round_keys().
 *
 * @param n          Taille de bloc (paramètre ζ, entier ≥ 1).
 * @param salt       Sel de 32 octets (obligatoire).
 * @param salt_len   Taille du sel (doit être 32).
 * @param p          Premier de travail (Z/pZ), p ≥ 2.
 * @param num_keys   Nombre de clés à générer (≤ 256).
 * @param keys_out   Buffer de sortie, doit contenir au moins num_keys uint64_t.
 * @return           CAGOULE_OMEGA_OK ou code d'erreur négatif.
 */
int cagoule_omega_generate_round_keys(
    int            n,
    const uint8_t *salt,
    size_t         salt_len,
    uint64_t       p,
    int            num_keys,
    uint64_t      *keys_out
);

/**
 * Ajoute une clé de ronde à chaque élément du bloc (mod p).
 * Équivaut à omega.py::apply_round_key().
 *
 * @param block    Tableau de n_elems éléments dans [0, p).
 * @param n_elems  Nombre d'éléments (typiquement 16 = CAGOULE_N).
 * @param rk       Clé de ronde dans [0, p).
 * @param p        Premier de travail.
 */
void cagoule_omega_block_add_rk(uint64_t *block, size_t n_elems,
                                 uint64_t rk, uint64_t p);

/**
 * Retire une clé de ronde de chaque élément du bloc (mod p).
 * Équivaut à omega.py::remove_round_key().
 *
 * @param block    Tableau de n_elems éléments dans [0, p).
 * @param n_elems  Nombre d'éléments.
 * @param rk       Clé de ronde dans [0, p).
 * @param p        Premier de travail.
 */
void cagoule_omega_block_sub_rk(uint64_t *block, size_t n_elems,
                                 uint64_t rk, uint64_t p);

/**
 * Retourne 1 si le backend OpenSSL est disponible à l'exécution, 0 sinon.
 * Permet au code Python de choisir le fallback mpmath si nécessaire.
 */
int cagoule_omega_openssl_available(void);

#endif /* CAGOULE_OMEGA_H */
