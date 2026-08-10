/**
 * cagoule_api.h — Wrapper C unifié — CAGOULE v3.1.0 Feature 2
 *
 * Élimine la surcharge ctypes (~28% mesuré v3.0.0/roadmap §3.1) en
 * exposant le pipeline complet (KDF → matrix/sbox → CTR → AEAD) comme
 * une poignée de fonctions C, buffer de sortie possédé par l'appelant.
 *
 * ════════════════════════════════════════════════════════════════════
 * ⚠️  CONSTAT DE SÉCURITÉ — RÉUTILISATION DE HANDLE (lire avant usage)
 * ════════════════════════════════════════════════════════════════════
 * CORRECTIF (audit round 2, M1) : ce paragraphe décrivait à l'origine
 * un bug Python comme s'il était ENCORE PRÉSENT au présent de
 * l'indicatif ("dérive l'IV CTR UNIQUEMENT depuis k_master"). C'était
 * déjà FAUX au moment où ce fichier a été écrit : le bug qu'il décrit
 * est Bug 2 (two-time-pad CTR v3.0.0), corrigé en v3.0.1 -- voir
 * CAGOULE-2026-001 dans SECURITY.md et cipher_ctr.py::_derive_ctr_iv(),
 * qui lie l'IV au nonce depuis ce correctif, pas seulement à k_master.
 * Conservé ci-dessous en tant que contexte HISTORIQUE (pourquoi la
 * dérivation d'IV du wrapper C ci-dessous a été conçue avec cette
 * rigueur), reformulé au passé pour ne plus laisser croire que Python
 * est concerné aujourd'hui :
 *
 * En concevant ce module, la même classe de bug a été examinée par
 * précaution : dans le v3.0.0 originel (avant le correctif v3.0.1),
 * encrypt_bulk_ctr(params=...) (Python) dérivait l'IV CTR UNIQUEMENT
 * depuis k_master — donc IDENTIQUE pour tout message partageant le
 * même `params`. Deux messages de même taille chiffrés avec le même
 * `params` partagé auraient alors produit un keystream algébrique CTR
 * bit-à-bit identique (two-time-pad classique).
 *
 * Impact v0x02 (ChaCha20-Poly1305, défaut) : NON exploitable de
 * l'extérieur — le nonce ChaCha20 est frais à chaque message et
 * ré-randomise entièrement le ct_alg interne avant publication. C'est
 * une utilisation standard et sûre de ChaCha20-Poly1305 (clé fixe, nonce
 * frais par message).
 *
 * Impact v0x03 (Poly1305 seul, expérimental, roadmap §2) : CRITIQUE.
 * ct_alg est publié SANS ré-encryption — la réutilisation de keystream
 * entre deux messages partageant un handle expose XOR(pt1, pt2) à tout
 * observateur du ciphertext. Combiner v0x03 avec un handle bulk partagé
 * (exactement le scénario visé par §3.3/§6 pour la cible >150 MB/s)
 * aurait cassé la confidentialité dès le deuxième message si le C
 * wrapper avait reproduit la même dérivation naïve.
 *
 * FIX appliqué ICI (cagoule_api.c uniquement, pas de modification du
 * code Python v3.0.0 déjà audité/fermé) :
 *
 * CORRECTIF (audit round 2, N4) : le paragraphe ci-dessous décrivait à
 * l'origine un label HKDF distinct "CAGOULE_CTR_V31_BULK" pour
 * cagoule_encrypt_with_handle()/decrypt_with_handle() — CE LABEL N'A
 * JAMAIS ÉTÉ IMPLÉMENTÉ (grep confirmé : absent de cagoule_api.c). La
 * bonne nouvelle, vérifiée empiriquement (voir tests/test_api_raw.c,
 * "Suite : IV/ct_alg uniqueness under handle reuse") : le two-time-pad
 * décrit plus haut n'existe PAS dans le code actuel, mais pas pour la
 * raison documentée ici à l'origine. Voici ce qui protège réellement
 * chaque chemin :
 *
 *   - cagoule_encrypt_v3()/decrypt_v3() (mono-message) :
 *     IV = HKDF(k_master, "CAGOULE_CTR_V31" + nonce, 8). Sûr car
 *     k_master est unique par appel (salt Argon2id frais) ET nonce
 *     frais (RAND_bytes) — double garantie, compatible bit-à-bit avec
 *     encrypt_ctr()/decrypt_ctr() Python.
 *   - cagoule_encrypt_with_handle()/decrypt_with_handle() (bulk 0x02,
 *     k_master PARTAGÉ entre appels) : IV = HKDF(k_master,
 *     "CAGOULE_CTR_V31" + nonce, 8) — MÊME formule que mono-message,
 *     AUCUN label "_BULK". Sûr quand même car `nonce` (12 octets) est
 *     RAND_bytes-généré À CHAQUE APPEL, indépendamment du partage de
 *     k_master — le ct_alg interne ne se répète donc jamais, et n'a
 *     même pas besoin du masquage ChaCha20 externe pour rester unique
 *     (la couche ChaCha20 apporte la confidentialité/authentification,
 *     pas l'unicité de ct_alg, contrairement à ce que ce commentaire
 *     affirmait initialement).
 *   - cagoule_encrypt_with_handle_raw()/decrypt_with_handle_raw()
 *     (bulk 0x03, PAS de couche ChaCha20 — ct_alg publié directement) :
 *     IV = HKDF(k_master, "CAGOULE_CTR_V31" + msg_salt[32], 8) —
 *     CORRECTIF (audit round 2, M9) : msg_salt (32 octets,
 *     RAND_bytes frais à chaque appel) mélangé en entier dans l'IV.
 *     Avant ce correctif, seuls les 12 premiers octets de msg_salt
 *     étaient utilisés (réutilisation accidentelle du buffer nonce[12]
 *     de derive_iv()) — toujours suffisant pour l'unicité (96 bits
 *     d'entropie fraîche), mais incompatible avec Python (voir M9).
 *     Ce chemin est le plus critique (pas de ré-encryption externe) :
 *     msg_salt frais à chaque appel est donc le mécanisme de sécurité
 *     PRINCIPAL ici, pas un détail secondaire.
 *
 * Contrairement à l'affirmation initiale, aucun chemin ci-dessus ne
 * produit un ciphertext delibérément incompatible avec son équivalent
 * mono-message/Python pour des raisons de sécurité — la compatibilité
 * cross-langage de 0x03 a été restaurée par le correctif M9 (audit
 * round 2) précisément parce que rien dans le mécanisme de sécurité
 * réel n'en dépendait.
 * ════════════════════════════════════════════════════════════════════
 *
 * Format wire — identique à cipher_ctr.py / cipher_ctr_raw.py (Feature 1) :
 *   0x02 : MAGIC(4) VERSION(1) SALT(32) NONCE(12) CT(n) TAG(16) — overhead 65
 *   0x03 : MAGIC(4) VERSION(1) SALT(32) CT(n) TAG(16)            — overhead 53
 *
 * Garantie d'ordre (roadmap §3.1) : le MAC est TOUJOURS vérifié dans un
 * buffer interne avant tout déchiffrement CTR vers le buffer de sortie
 * de l'appelant — aucun plaintext non authentifié n'est jamais écrit
 * dans `out`.
 */
#ifndef CAGOULE_API_H
#define CAGOULE_API_H

#include <stdint.h>
#include <stddef.h>
#include "cagoule_params.h"

#define CAGOULE_API_OK            0
#define CAGOULE_API_ERR_NULL     -1
#define CAGOULE_API_ERR_SIZE     -2
#define CAGOULE_API_ERR_AUTH     -3   /* Échec vérification MAC */
#define CAGOULE_API_ERR_FORMAT   -4   /* Magic/version invalide */
#define CAGOULE_API_ERR_EXPERIMENTAL_DISABLED (-8) /* mode expérimental non activé */
#define CAGOULE_API_ERR_KDF      -5
#define CAGOULE_API_ERR_CRYPTO   -6   /* Échec OpenSSL EVP interne */
#define CAGOULE_API_ERR_ALLOC    -7

/**
 * Traduit un code de retour cagoule_api.h (CAGOULE_API_OK ou l'un des
 * CAGOULE_API_ERR_*) en message d'erreur humainement lisible, en anglais.
 *
 * @param code   Un code retourné par une fonction de ce header.
 * @return       Pointeur vers une chaîne statique, en lecture seule,
 *               ne nécessitant AUCUN free(). Jamais NULL — un code
 *               inconnu retourne une chaîne générique plutôt qu'un
 *               pointeur nul, pour que l'appelant puisse toujours
 *               logger/afficher un message sans vérification supplémentaire.
 * Thread-safe : ne lit ni n'écrit aucun état partagé, chaînes statiques
 * const en lecture seule uniquement.
 */
const char* cagoule_api_strerror(int code);

#define CAGOULE_API_VERSION_AEAD 0x02   /* ChaCha20-Poly1305 — défaut */
#define CAGOULE_API_VERSION_RAW  0x03   /* Poly1305 seul — expérimental */

#define CAGOULE_API_OVERHEAD_AEAD 65    /* MAGIC+VERSION+SALT+NONCE+TAG */
#define CAGOULE_API_OVERHEAD_RAW  53    /* MAGIC+VERSION+SALT+TAG (corrigé, roadmap §6.1) */

/* ── Handle de clé pré-dérivée (roadmap §3.3 — amortissement bulk) ──── */
typedef struct CagouleKeyHandle CagouleKeyHandle;

/**
 * Dérive une clé complète (Argon2id + matrix + sbox + round_keys +
 * z_offset + k_stream + poly_key) et retourne un handle opaque.
 * Coût : ~Argon2id(64MiB, t=3) — à amortir sur N messages via les
 * fonctions *_with_handle().
 *
 * @return handle alloué, ou NULL en cas d'échec (KDF ou paramètres invalides)
 */
CagouleKeyHandle* cagoule_derive_key(const uint8_t* password, size_t pwd_len,
                                      const uint8_t* salt, size_t salt_len);

/** Libère le handle — zéroïse k_master/k_stream/poly_key/round_keys/z_offset. */
void cagoule_key_handle_free(CagouleKeyHandle* handle);

/* ── Tailles de buffer requises (à appeler avant d'allouer `out`) ───── */
static inline size_t cagoule_api_encrypt_out_len(size_t pt_len) { return pt_len + CAGOULE_API_OVERHEAD_AEAD; }
static inline size_t cagoule_api_encrypt_raw_out_len(size_t pt_len) { return pt_len + CAGOULE_API_OVERHEAD_RAW; }
static inline size_t cagoule_api_decrypt_out_len(size_t ct_len) {
    return (ct_len >= CAGOULE_API_OVERHEAD_AEAD) ? (ct_len - CAGOULE_API_OVERHEAD_AEAD) : 0;
}
static inline size_t cagoule_api_decrypt_raw_out_len(size_t ct_len) {
    return (ct_len >= CAGOULE_API_OVERHEAD_RAW) ? (ct_len - CAGOULE_API_OVERHEAD_RAW) : 0;
}

/* ── Chemin bulk (handle partagé) — VERSION 0x02 (défaut, ChaCha20) ── */

/**
 * @param out      Buffer appelant, taille >= cagoule_api_encrypt_out_len(pt_len)
 * @param out_len  IN: capacité de out. OUT: octets effectivement écrits.
 */
int cagoule_encrypt_with_handle(CagouleKeyHandle* handle,
                                 const uint8_t* pt, size_t pt_len,
                                 uint8_t* out, size_t* out_len);

int cagoule_decrypt_with_handle(CagouleKeyHandle* handle,
                                 const uint8_t* ct, size_t ct_len,
                                 uint8_t* out, size_t* out_len);

/* ── Chemin bulk — VERSION 0x03 (expérimental, Poly1305 seul) ───────
 * Gate double, comme cipher_ctr_raw.py (Feature 1) : nécessite
 * allow_experimental=1 ET la variable d'environnement
 * CAGOULE_EXPERIMENTAL_NO_AEAD=1 au moment de l'appel (vérifié à
 * l'exécution, pas seulement à la compilation — voir cagoule_api.c). */
int cagoule_encrypt_with_handle_raw(CagouleKeyHandle* handle, int allow_experimental,
                                     const uint8_t* pt, size_t pt_len,
                                     uint8_t* out, size_t* out_len);

int cagoule_decrypt_with_handle_raw(CagouleKeyHandle* handle, int allow_experimental,
                                     const uint8_t* ct, size_t ct_len,
                                     uint8_t* out, size_t* out_len);

/* ── Chemin mono-message (derive + crypt + free en un appel) ─────────
 * VERSION 0x02 — compatible bit-à-bit avec encrypt_ctr()/decrypt_ctr()
 * Python (même formule IV, pas de salt bulk-safe nécessaire ici car
 * k_master est toujours unique par appel). */
int cagoule_encrypt_v3(const uint8_t* password, size_t pwd_len,
                        const uint8_t* pt, size_t pt_len,
                        uint8_t* out, size_t* out_len);

int cagoule_decrypt_v3(const uint8_t* password, size_t pwd_len,
                        const uint8_t* ct, size_t ct_len,
                        uint8_t* out, size_t* out_len);

#endif /* CAGOULE_API_H */
