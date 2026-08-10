/**
 * cagoule_stream.h — API de chiffrement en flux — CAGOULE v3.1.0 Feature 4
 *
 * Conception : MAC indépendant par chunk (roadmap §5.2) — pattern libsodium
 * secretstream. L'option "bufferiser tout le ciphertext avant vérification"
 * annulerait l'objectif RAM, et "relâcher le plaintext avant vérification"
 * est un pattern Lucky13/POODLE-class explicitement exclu par le roadmap.
 *
 * Par défaut : ChaCha20-Poly1305 par chunk (VERSION 0x02 sémantique, même
 * niveau de sécurité que le mode single-shot). Le mode Poly1305-seul (0x03)
 * est disponible uniquement sous le même double gate que cipher_ctr_raw.py.
 *
 * Wire format — C-API uniquement pour v3.1.0, pas de VERSION byte CGL1
 * dédié (roadmap §4, décision "streaming is C-API only for v3.1.0").
 * L'appelant est responsable du framing/persistance entre chunks.
 *
 * Format par chunk (output de cagoule_stream_update) :
 *   ChaCha20-Poly1305 (défaut 0x02) :
 *     CHUNK_IDX(8) | NONCE(12) | CT_ALG(chunk_len) | TAG(16)
 *     overhead par chunk : 36 octets
 *   Poly1305-seul (expérimental 0x03) :
 *     CHUNK_IDX(8) | CT_ALG(chunk_len) | TAG(16)
 *     overhead par chunk : 24 octets
 *
 * Tag MAC :
 *   clé MAC = HKDF(k_master, "CAGOULE_CHUNK" || chunk_index, 32)
 *   AAD = MAGIC(4) || VERSION(1) || session_salt(32) || chunk_idx(8LE)
 *   Cette construction garantit :
 *     - Clé MAC unique par chunk (pas de réutilisation inter-chunk)
 *     - Liaison au contexte de session (session_salt, version) via AAD
 *     - Résistance à la réorganisation / replay de chunks
 *
 * Overhead total sur 500MB (chunk=64KB) : 128KB = 0.025% (roadmap §5.3).
 *
 * Usage correct :
 *   CagouleStreamCtx *ctx = cagoule_stream_init(pwd, pwd_len, chunk_size, 0);
 *   while (chunk = read_chunk()) {
 *       size_t out_cap = cagoule_stream_update_out_len(ctx, chunk_size);
 *       uint8_t *out = malloc(out_cap);
 *       size_t out_len = out_cap;
 *       cagoule_stream_update(ctx, chunk, chunk_len, out, &out_len);
 *       write(out, out_len);
 *       free(out);
 *   }
 *   cagoule_stream_free(ctx);
 */
#ifndef CAGOULE_STREAM_H
#define CAGOULE_STREAM_H

#include <stdint.h>
#include <stddef.h>
#include "cagoule_params.h"

#define CAGOULE_STREAM_OK             0
#define CAGOULE_STREAM_ERR_NULL      -1
#define CAGOULE_STREAM_ERR_SIZE      -2
#define CAGOULE_STREAM_ERR_AUTH      -3
#define CAGOULE_STREAM_ERR_FORMAT    -4
#define CAGOULE_STREAM_ERR_KDF       -5
#define CAGOULE_STREAM_ERR_CRYPTO    -6
#define CAGOULE_STREAM_ERR_ALLOC     -7
/* CAGOULE_STREAM_ERR_GATE (-8) retiré (audit round 2) : jamais retourné
 * par aucun chemin de code. La "double gate" expérimentale (voir
 * cagoule_stream.c, "CORRECTIF v3.1.0 (Finding 3)") ne fait PAS échouer
 * l'appel quand allow_experimental=1 sans la variable d'environnement --
 * elle retombe silencieusement en mode sûr (experimental=0, AEAD 0x02)
 * à la place. C'est un choix délibéré et déjà correct : "wire up" ce
 * code d'erreur aurait annulé le correctif Finding 3 en le remplaçant
 * par un échec strict. -8 n'est plus utilisé -- vérifié : aucune
 * référence externe (Python, tests) à ce code avant suppression.
 */

#define CAGOULE_STREAM_DEFAULT_CHUNK_SIZE (64 * 1024)  /* 64 KB */

#define CAGOULE_STREAM_CHUNK_IDX_SIZE  8
#define CAGOULE_STREAM_TAG_SIZE        16
#define CAGOULE_STREAM_NONCE_SIZE      12

/* Overhead par chunk (octets écrits en plus du plaintext du chunk) */
#define CAGOULE_STREAM_OVERHEAD_AEAD   (CAGOULE_STREAM_CHUNK_IDX_SIZE + CAGOULE_STREAM_NONCE_SIZE + CAGOULE_STREAM_TAG_SIZE)   /* 36 */
#define CAGOULE_STREAM_OVERHEAD_RAW    (CAGOULE_STREAM_CHUNK_IDX_SIZE + CAGOULE_STREAM_TAG_SIZE)                                /* 24 */

#define CAGOULE_STREAM_SESSION_SALT_SIZE CAGOULE_SALT_LEN  /* 32 */

typedef struct CagouleStreamCtx CagouleStreamCtx;

/**
 * Initialise un contexte de chiffrement en flux.
 *
 * @param password, pwd_len   Mot de passe
 * @param chunk_size          Taille de chunk en octets (0 -> défaut 64KB).
 *                            Le dernier chunk peut être plus petit.
 * @param allow_experimental  0 -> VERSION 0x02 ChaCha20-Poly1305 (défaut).
 *                            1 + CAGOULE_EXPERIMENTAL_NO_AEAD=1 -> Poly1305 seul (0x03).
 *
 * @return contexte alloué, ou NULL en cas d'erreur.
 */
CagouleStreamCtx* cagoule_stream_init(const uint8_t *password, size_t pwd_len,
                                       size_t chunk_size, int allow_experimental);

/** Taille de buffer de sortie nécessaire pour un chunk de input_len octets. */
size_t cagoule_stream_update_out_len(const CagouleStreamCtx *ctx, size_t input_len);

/** Taille de buffer de sortie nécessaire pour décoder un chunk chiffré. */
size_t cagoule_stream_decrypt_out_len(const CagouleStreamCtx *ctx, size_t ct_chunk_len);

/**
 * Chiffre un chunk, écrit le bloc (CHUNK_IDX|[NONCE]|CT_ALG|TAG) dans out.
 * Peut être appelé N fois de suite pour N chunks consécutifs.
 * Incrémente automatiquement le compteur de chunk interne.
 *
 * @param out      Buffer appelant, capacité >= cagoule_stream_update_out_len(ctx, input_len)
 * @param out_len  IN: capacité. OUT: octets écrits.
 */
int cagoule_stream_update(CagouleStreamCtx *ctx,
                           const uint8_t *input, size_t input_len,
                           uint8_t *out, size_t *out_len);

/**
 * Déchiffre un chunk. Vérifie le TAG AVANT d'écrire dans out.
 * Si TAG invalide -> CAGOULE_STREAM_ERR_AUTH, out n'est jamais touché.
 */
int cagoule_stream_decrypt(CagouleStreamCtx *ctx,
                            const uint8_t *ct_chunk, size_t ct_chunk_len,
                            uint8_t *out, size_t *out_len);

/** Libère le contexte et zéroïse les clés. */
void cagoule_stream_free(CagouleStreamCtx *ctx);

/** Accesseur de session_salt pour que le déchiffreur puisse recréer le même contexte. */
const uint8_t* cagoule_stream_session_salt(const CagouleStreamCtx *ctx);

/**
 * Initialise un contexte de DÉCHIFFREMENT à partir d'un session_salt reçu
 * hors bande (typiquement le premier message du protocole de framing).
 * Le chunk_idx est initialisé à 0.
 *
 * @param allow_experimental  Doit correspondre au mode utilisé lors du chiffrement.
 */
CagouleStreamCtx* cagoule_stream_init_from_salt(const uint8_t *password, size_t pwd_len,
                                                  const uint8_t *session_salt,
                                                  size_t chunk_size,
                                                  int allow_experimental);

#endif /* CAGOULE_STREAM_H */
