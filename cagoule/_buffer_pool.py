"""
_buffer_pool.py — Thread-local buffer pool — CAGOULE v2.5.0 P4

Réduit l'overhead d'allocation ctypes pour les petits messages (~10-15% gain).
Chaque thread possède ses propres buffers, redimensionnés à la demande.
Zéroisation automatique après chaque utilisation pour éviter les fuites de données.
"""

from __future__ import annotations

import ctypes
import threading

# ── Thread-local storage ────────────────────────────────────────────

_tls = threading.local()

def _get_padded_buf(size: int) -> ctypes.Array:
    if not hasattr(_tls, 'padded_buf') or len(_tls.padded_buf) < size:
        if hasattr(_tls, 'padded_buf'):
            ctypes.memset(_tls.padded_buf, 0, ctypes.sizeof(_tls.padded_buf))
        _tls.padded_buf = (ctypes.c_uint8 * size)()
    else:
        ctypes.memset(_tls.padded_buf, 0, ctypes.sizeof(_tls.padded_buf))
    return _tls.padded_buf

def _get_out_buf(size: int) -> ctypes.Array:
    """Buffer thread-local pour la sortie (ciphertext ou plaintext).

    CORRECTIF v3.1.0 (Finding 4) : protection re-entrance. Si un appel encrypt
    imbrique un autre appel encrypt (ex: handler de log qui chiffre), le buffer
    interne serait corrompu. On détecte et on alloue un buffer frais.

    CORRECTIF v3.1.0 (Finding 1) : zéroisation sur le chemin de RÉUTILISATION
    (pas seulement redimensionnement). Sans ça, un buffer réutilisé pour une
    requête plus petite contient des données résiduelles de l'appel précédent
    dans sa queue — plaintext ou ciphertext d'un appel antérieur potentiellement
    différent. Le coût est un memset(size) par appel, acceptable vu le gain de
    sécurité. La queue (bytes size..len) est aussi zérorisée pour la même raison.
    """
    # Re-entrancy guard: si le buffer est déjà en cours d'utilisation
    # (appel imbriqué depuis le même thread), allouer un buffer frais indépendant
    if getattr(_tls, '_out_buf_in_use', False):
        return (ctypes.c_uint8 * size)()

    if not hasattr(_tls, 'out_buf') or len(_tls.out_buf) < size:
        if hasattr(_tls, 'out_buf'):
            ctypes.memset(_tls.out_buf, 0, ctypes.sizeof(_tls.out_buf))
        _tls.out_buf = (ctypes.c_uint8 * size)()
    else:
        ctypes.memset(_tls.out_buf, 0, ctypes.sizeof(_tls.out_buf))
    return _tls.out_buf


def _acquire_out_buf(size: int) -> ctypes.Array:
    """Acquiert le buffer de sortie et marque le flag re-entrancy.

    CORRECTIF (audit round 2, M4) : l'ordre original mettait le flag
    _out_buf_in_use à True AVANT d'appeler _get_out_buf() -- qui vérifie
    ce même flag pour décider s'il doit allouer un buffer frais (cas
    imbriqué) ou réutiliser le buffer TLS partagé (cas normal). Résultat :
    TOUT appel à _acquire_out_buf(), y compris le tout premier (non
    imbriqué), voyait le flag déjà à True et prenait systématiquement la
    branche "buffer frais" -- annulant complètement l'intérêt du pool
    (réutilisation TLS pour éviter une allocation ctypes par appel).
    Ce bug était latent depuis la création de ces fonctions : elles
    n'étaient jamais appelées ensemble avant ce correctif, donc jamais
    testées. Ordre corrigé : lire le flag / obtenir le buffer approprié
    D'ABORD, puis marquer le flag pour les appels imbriqués éventuels.
    """
    buf = _get_out_buf(size)
    _tls._out_buf_in_use = True
    return buf


def _release_out_buf() -> None:
    """Libère le flag re-entrancy après utilisation."""
    _tls._out_buf_in_use = False


def _get_rk_arr(num_keys: int) -> ctypes.Array:
    if not hasattr(_tls, 'rk_arr') or len(_tls.rk_arr) < num_keys:
        if hasattr(_tls, 'rk_arr'):
            ctypes.memset(_tls.rk_arr, 0, ctypes.sizeof(_tls.rk_arr))
        _tls.rk_arr = (ctypes.c_uint64 * num_keys)()
    else:
        ctypes.memset(_tls.rk_arr, 0, ctypes.sizeof(_tls.rk_arr))
    return _tls.rk_arr


def _get_input_buf(size: int) -> ctypes.Array:
    """Buffer thread-local pour l'entrée déchiffrement (ciphertext bytes).

    CORRECTIF v3.1.0 (Finding 1) : même correction que _get_out_buf.
    """
    if not hasattr(_tls, 'input_buf') or len(_tls.input_buf) < size:
        if hasattr(_tls, 'input_buf'):
            ctypes.memset(_tls.input_buf, 0, ctypes.sizeof(_tls.input_buf))
        _tls.input_buf = (ctypes.c_uint8 * size)()
    else:
        ctypes.memset(_tls.input_buf, 0, ctypes.sizeof(_tls.input_buf))
    return _tls.input_buf


# ── Zeroization helpers ──────────────────────────────────────────────

def _zeroize_buf(buf: ctypes.Array, size: int) -> None:
    """Zéroise un buffer ctypes après utilisation.

    CORRECTIF v3.1.0 (Finding 3) : ne plus avaler toutes les exceptions.
    Un échec de zéroisation est un problème de sécurité réel — il doit être
    au moins loggué. Seules les exceptions bénignes sont ignorées.

    Note : ctypes.memset(None, ...) segfaulte au niveau C avant que Python
    puisse l'attraper. On vérifie buf is not None explicitement.
    """
    if buf is None:
        import logging
        logging.getLogger(__name__).warning(
            "_zeroize_buf: buf=None — matériel de clé potentiellement non effacé"
        )
        return
    if size <= 0:
        return
    try:
        ctypes.memset(buf, 0, size)
    except (TypeError, ValueError, ctypes.ArgumentError) as e:
        import logging
        logging.getLogger(__name__).debug(
            "_zeroize_buf: échec zéroisation (%s: %s) — matériel de clé "
            "potentiellement non effacé", type(e).__name__, e
        )
    # Les autres exceptions (MemoryError, etc.) se propagent normalement


def _pool_stats() -> dict:
    """Statistiques d'utilisation du pool (debug)."""
    stats = {}
    for name in ('padded_buf', 'out_buf', 'rk_arr', 'input_buf'):
        if hasattr(_tls, name):
            buf = getattr(_tls, name)
            stats[name] = {'size': len(buf), 'id': id(buf)}
        else:
            stats[name] = None
    return stats