"""
utils.py — Utilitaires de sécurité CAGOULE v3.1.0

Fournit :
  - secure_zeroize() : effacement sécurisé de données sensibles
  - SensitiveBuffer : context manager pour buffers effaçables
  - analyse S-box : différentielle, linéaire, rapports
"""

from __future__ import annotations

import ctypes
import sys
import warnings
from typing import Union, Optional


# ============================================================
# Effacement sécurisé de données sensibles
# ============================================================

def secure_zeroize(data: Union[bytearray, memoryview]) -> None:
    """
    Efface un buffer mutable en écrivant des zéros.
    Utilise ctypes.memset pour éviter les allocations temporaires.

    Args:
        data: Buffer mutable (bytearray ou memoryview)

    Raises:
        TypeError: Si data n'est pas effaçable
    """
    if isinstance(data, memoryview):
        n = len(data)
        # Effacer par chunks pour éviter une grosse allocation temporaire
        for i in range(0, n, 4096):
            end = min(i + 4096, n)
            data[i:end] = b'\x00' * (end - i)
        return

    if isinstance(data, bytearray):
        n = len(data)
        if n == 0:
            return

        # Méthode principale : ctypes.memset (pas d'allocation temporaire)
        try:
            # CORRECTIF (audit round 2, M8) : (ctypes.c_char * n) au lieu de
            # ctypes.c_char seul. Les deux donnent la même adresse de départ
            # (from_buffer() partage la mémoire du bytearray -- ce n'est
            # PAS une copie, ctypes l'exige pour un buffer accepté en
            # écriture -- donc `data` restant vivant durant tout l'appel
            # suffit à garantir que l'adresse reste valide, que le type
            # utilisé pour l'obtenir soit c_char ou c_char*n). Mais un
            # c_char seul décrit un objet de 1 octet alors qu'on l'utilise
            # ensuite pour memset() n octets -- correct mais trompeur pour
            # quiconque relit ce code sans connaître cette garantie ctypes
            # précise. Le type (c_char * n) documente l'intention réelle
            # directement dans le code, pas seulement dans ce commentaire.
            addr = ctypes.addressof((ctypes.c_char * n).from_buffer(data))
            ctypes.memset(addr, 0, n)
        except Exception:
            # CORRECTIF (audit round 2, M9-utils) : affectation octet par
            # octet au lieu de `data[i:end] = b'\x00' * (end-i)`, qui
            # allouait un objet bytes tout-zéro temporaire par chunk avant
            # affectation. Chemin de repli rarement emprunté (seulement si
            # ctypes.memset échoue, ce qui ne devrait pas arriver pour un
            # bytearray valide) -- la correction n'alloue plus rien du tout,
            # au prix d'une boucle Python pure plus lente que le memset
            # normal, acceptable ici puisque ce n'est pas le chemin
            # habituel.
            for i in range(n):
                data[i] = 0
        return

    raise TypeError(
        f"secure_zeroize attend bytearray ou memoryview, reçu {type(data).__name__}"
    )


def bytes_to_zeroizable(data: bytes) -> bytearray:
    """Convertit des bytes en bytearray effaçable."""
    return bytearray(data)


def zeroize_str(s: str) -> None:
    """
    Efface une chaîne de caractères (impossible - lève une exception).
    Les chaînes Python sont immutables et ne peuvent pas être effacées.
    Utiliser SensitiveBuffer à la place.
    """
    raise TypeError(
        "Les chaînes Python sont immutables. "
        "Utiliser SensitiveBuffer pour les données sensibles."
    )


# ============================================================
# SensitiveBuffer - Context manager sécurisé
# ============================================================

class SensitiveBuffer:
    """
    Buffer sécurisé qui s'efface automatiquement à la sortie du contexte.

    Utilisation:
        with SensitiveBuffer.from_bytes(secret) as buf:
            # utiliser buf (bytearray)
            ...
        # buf est maintenant effacé
    """

    def __init__(self, size: int) -> None:
        if size < 0:
            raise ValueError(f"Taille invalide: {size}")
        self._buf = bytearray(size)
        self._size = size

    def __enter__(self) -> bytearray:
        return self._buf

    def __exit__(self, *args) -> None:
        secure_zeroize(self._buf)
        self._buf = None

    @classmethod
    def from_bytes(cls, data: bytes) -> "SensitiveBuffer":
        """Crée un buffer à partir de bytes."""
        obj = cls(len(data))
        obj._buf[:] = data
        return obj

    @classmethod
    def zero(cls, size: int) -> "SensitiveBuffer":
        """Crée un buffer de zéros de taille donnée."""
        return cls(size)

    def __len__(self) -> int:
        return self._size

    def __repr__(self) -> str:
        return f"SensitiveBuffer(size={self._size})"


# ============================================================
# Analyse cryptographique de S-box (pour validation)
# ============================================================

def sbox_differential_uniformity(sbox_map: list, p: int) -> dict:
    """
    Calcule l'uniformité différentielle d'une S-box.

    Args:
        sbox_map: Liste de p éléments (sorties de la S-box)
        p: Cardinalité

    Returns:
        Dictionnaire avec:
            - delta: differential uniformity (plus petit = meilleur)
            - distribution: nombre de paires (a,b) pour chaque count
            - mean: moyenne des counts
    """
    max_count = 0
    distribution = {}

    for a in range(1, p):  # a != 0
        for b in range(p):
            count = sum(1 for x in range(p)
                        if (sbox_map[(x + a) % p] - sbox_map[x]) % p == b)
            if count > 0:
                distribution[count] = distribution.get(count, 0) + 1
            if count > max_count:
                max_count = count

    total = sum(distribution.values())
    mean = sum(k * v for k, v in distribution.items()) / total if total else 0

    return {
        "delta": max_count,
        "distribution": distribution,
        "mean": round(mean, 3),
        "p": p
    }


def sbox_linear_bias(sbox_map: list, p: int) -> dict:
    """
    Calcule le biais linéaire maximal d'une S-box (analyse linéaire).

    Calcule le biais de la meilleure approximation linéaire :
        Pr[S(x) = a·x + b mod p] - 1/p

    Args:
        sbox_map: Liste de p éléments (sorties de la S-box)
        p: Cardinalité

    Returns:
        Dictionnaire avec:
            - max_bias: biais linéaire maximal (plus petit = meilleur)
            - min_distance: distance minimale à l'ensemble des fonctions affines
    """
    max_bias = 0.0

    for a in range(1, p):  # a != 0
        for b in range(p):
            matches = sum(1 for x in range(p)
                          if sbox_map[x] == (a * x + b) % p)
            bias = abs(matches / p - 1 / p)
            if bias > max_bias:
                max_bias = bias

    min_distance = max(0, round(p * (1 / p - max_bias), 3))

    return {
        "max_bias": round(max_bias, 6),
        "min_distance": min_distance,
        "p": p,
        "note": "Valeurs plus petites = meilleure résistance linéaire"
    }


def analyze_sbox(sbox_instance, p: int) -> dict:
    """
    Analyse complète d'une S-box (exhaustive, pour petits p uniquement).

    Args:
        sbox_instance: Instance de SBox (C ou Python)
        p: Cardinalité (doit être <= 500 pour analyse exhaustive)

    Returns:
        Dictionnaire contenant les résultats d'analyse
    """
    if p > 500:
        raise ValueError(f"p={p} trop grand pour l'analyse exhaustive (O(p²)).")

    # Générer la table de mapping
    sbox_map = [sbox_instance.forward(x) for x in range(p)]

    # Vérifier la bijectivité
    is_bijective = len(set(sbox_map)) == p

    # Déterminer le type de S-box
    if hasattr(sbox_instance, '_s') and sbox_instance._s is not None:
        sbox_type = "feistel" if sbox_instance._s.use_feistel else "fallback x^d"
        d_or_c = None
    elif hasattr(sbox_instance, 'use_fallback'):
        sbox_type = "python x^d" if sbox_instance.use_fallback else "python cubic"
        d_or_c = getattr(sbox_instance, 'd', None) or getattr(sbox_instance, 'c', None)
    else:
        sbox_type = "unknown"
        d_or_c = None

    # Analyse différentielle et linéaire
    diff = sbox_differential_uniformity(sbox_map, p)
    lin = sbox_linear_bias(sbox_map, p)

    return {
        "p": p,
        "is_bijective": is_bijective,
        "type": sbox_type,
        "d_or_c": d_or_c,
        "differential": diff,
        "linear": lin,
        "security_note": f"delta={diff['delta']} — usage académique (p≤{p})"
    }


def sbox_report(analysis: dict) -> str:
    """
    Formate un rapport d'analyse de S-box en texte lisible.

    Args:
        analysis: Dictionnaire retourné par analyze_sbox()

    Returns:
        Rapport texte formaté
    """
    d = analysis
    lines = [
        f"S-box Analysis — p={d['p']} — type={d['type']}",
        f"  Bijective       : {'✓' if d['is_bijective'] else '✗'}",
        f"  Diff. uniformity: δ = {d['differential']['delta']}",
        f"  Max linear bias : {d['linear']['max_bias']}",
        f"  Note            : {d['security_note']}",
    ]
    return "\n".join(lines)


# ============================================================
# Alias pour compatibilité avec les autres modules
# ============================================================

def zeroize(data) -> None:
    """Alias de secure_zeroize pour compatibilité avec les objets CAGOULE."""
    if isinstance(data, (bytearray, memoryview)):
        secure_zeroize(data)
    elif hasattr(data, 'zeroize') and callable(data.zeroize):
        data.zeroize()
    else:
        warnings.warn(
            f"zeroize: type {type(data)} non effaçable",
            RuntimeWarning,
            stacklevel=2
        )