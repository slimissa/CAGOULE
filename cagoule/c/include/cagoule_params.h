/**
 * cagoule_params.h — Dérivation complète des paramètres CAGOULE en C
 * CAGOULE v3.1.0 Feature 2 — portage fidèle de params.py::CagouleParams.derive()
 *
 * Pipeline (portage voulu fidèle de params.py — voir CORRECTIF ci-dessous
 * pour l'état réel de la parité) :
 *   1. k_master = Argon2id(password, salt, t=3, m=64MiB, p=1, len=64)
 *   2. n_zeta   = (HKDF_u64(k_master,"CAGOULE_N",2) % 65533) + 4
 *   3. prime_idx = HKDF_u64(k_master,"CAGOULE_PRIME_SEL_V25",1) % 8
 *      (p, k_mersenne) = MERSENNE_POOL[prime_idx]   (CAGOULE_MERSENNE_P/K)
 *   4. mu/alpha0 = LUT précalculée (mu ne dépend que de p — 8 valeurs fixes,
 *      voir cagoule_mu_table.h et sa justification)
 *   5. delta = (HKDF_u64(k_master,"CAGOULE_DELTA",8) % (p-1)) + 1   [∈ 1,p-1]
 *      rk0 = (delta % (P32_PRIME-1)) + 1 ; rk1 = ((delta>>32) % (P32_PRIME-1)) + 1
 *
 * CORRECTIF (audit round 2, H1/H1b) : l'affirmation "vérifié par KAT croisé
 * Python/C" ci-dessus était FAUSSE -- aucun KAT ne teste la sortie de
 * cagoule_params_derive() (ni côté C, ni côté Python) ; regenerate_kat.py
 * exerce params.py::derive() directement, pas cette fonction. Cette
 * fonction divergeait aussi réellement de derive() jusqu'à ce correctif :
 * l'étape 5 utilisait `delta %= p` (peut valoir 0) au lieu de la formule
 * `(raw % (p-1)) + 1` documentée et utilisée par derive(). Voir
 * cagoule_params.c pour le détail. À ajouter : un test croisé C↔Python
 * réel (encrypt C via cagoule_derive_key + decrypt Python, et l'inverse)
 * -- il n'en existe aucun à ce jour.
 *   6. nodes[16] : nodes[0]=alpha0, nodes[i>=1] = HKDF_u64(...,"CAGOULE_NODE_i",8) % p
 *      avec évitement de collision par incrémentation (+1 mod p, max 10000 essais)
 *   7. matrix = cagoule_matrix_build(nodes, 16, p)
 *   8. sbox   = cagoule_sbox_init(p, rk0, rk1)
 *   9. k_stream  = HKDF(k_master,"CAGOULE_ENC",32)        [AEAD 0x02 — ChaCha20]
 *  10. round_keys[64] = cagoule_omega_generate_round_keys(n_zeta, salt, p, 64, ...)
 *  11. z_offset[16] = HKDF(k_master,"CAGOULE_Z_SHIFT_V25",128) → 16×uint64 BE % p
 *  12. poly_key  = HKDF(k_master,"CAGOULE_POLY_V31",32)   [champ CagouleDerivedParams,
 *      voir CORRECTIF ci-dessous -- ce champ statique n'est PLUS la clé
 *      Poly1305 réellement utilisée pour authentifier les messages]
 *
 * CORRECTIF (audit round 2, C2) : le champ poly_key ci-dessus (calculé une
 * seule fois par appel à cagoule_params_derive, donc identique pour tout
 * le handle) est mort côté chemin RAW (0x03) -- cagoule_api.c dérive
 * désormais une clé Poly1305 PAR MESSAGE via derive_poly_key(k_master,
 * msg_salt), indépendante de ce champ. Réutiliser p->poly_key pour
 * plusieurs messages était exactement la faille C2 (réutilisation de clé
 * Poly1305, forgerie universelle après 2 messages) -- voir cagoule_api.c
 * et SECURITY.md CAGOULE-2026-003 pour le détail complet. Ce champ reste
 * calculé et zéroïsé ici (compatibilité de struct) mais ne doit plus être
 * lu directement par du nouveau code cherchant la clé Poly1305 active.
 *
 * NUM_ROUND_KEYS = 64 (= NUM_ROUND_KEYS dans params.py).
 */
#ifndef CAGOULE_PARAMS_H
#define CAGOULE_PARAMS_H

#include <stdint.h>
#include <stddef.h>
#include "cagoule_matrix.h"
#include "cagoule_sbox.h"
#include "cagoule_kdf.h"   /* CAGOULE_K_MASTER_LEN, CAGOULE_SALT_LEN */

#define CAGOULE_PARAMS_OK             0
#define CAGOULE_PARAMS_ERR_NULL      -1
#define CAGOULE_PARAMS_ERR_PARAM     -2
#define CAGOULE_PARAMS_ERR_KDF       -3
#define CAGOULE_PARAMS_ERR_ALLOC     -4
#define CAGOULE_PARAMS_ERR_OMEGA     -5
#define CAGOULE_PARAMS_ERR_COLLISION -6  /* noeuds : échec évitement collision */

#define CAGOULE_NUM_ROUND_KEYS 64
#define CAGOULE_Z_OFFSET_N     16
#define CAGOULE_K_STREAM_LEN   32
#define CAGOULE_POLY_KEY_LEN   32

typedef struct {
    uint8_t        k_master[CAGOULE_K_MASTER_LEN];   /* 64 octets */
    uint8_t        salt[CAGOULE_SALT_LEN];           /* 32 octets */
    uint64_t       p;
    uint64_t       k_mersenne;
    int            n_zeta;
    CagouleMatrix *matrix;          /* alloué — cagoule_matrix_free() */
    CagouleSBox64  sbox;
    uint64_t       round_keys[CAGOULE_NUM_ROUND_KEYS];
    uint64_t       z_offset[CAGOULE_Z_OFFSET_N];
    uint8_t        k_stream[CAGOULE_K_STREAM_LEN];
    uint8_t        poly_key[CAGOULE_POLY_KEY_LEN];
} CagouleDerivedParams;

/**
 * Dérive l'intégralité des paramètres CAGOULE depuis (password, salt).
 * Équivalent C de CagouleParams.derive(password, salt).
 *
 * @param out  DOIT être zéro-initialisé par l'appelant (out->matrix sera
 *             alloué ici). Sur erreur, tout ce qui a été alloué est libéré.
 */
int cagoule_params_derive(const uint8_t *password, size_t pwd_len,
                           const uint8_t *salt, size_t salt_len,
                           CagouleDerivedParams *out);

/**
 * Libère matrix et zéroïse k_master/k_stream/poly_key/round_keys/z_offset.
 * Sûr à appeler sur une struct partiellement initialisée (champs à zéro).
 */
void cagoule_params_free(CagouleDerivedParams *params);

#endif /* CAGOULE_PARAMS_H */
