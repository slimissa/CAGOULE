"""
utils.py — Utilitaires de sécurité CAGOULE v1.5

Fonctions de nettoyage mémoire sécurisé pour les données cryptographiques
sensibles : K_master, K_stream, round keys, plaintext temporaire.

En Python, le GC peut conserver des copies — on utilise bytearray + overwrite
pour minimiser la surface d'exposition. Ce n'est pas une garantie absolue
(le GC peut avoir copié la valeur), mais c'est la meilleure approche possible
en Python pur.
"""

from __future__ import annotations

import ctypes
import sys
from typing import Union


# ─── Zeroization ─────────────────────────────────────────────────────────────

def secure_zeroize(data: Union[bytearray, memoryview]) -> None:
    """
    Écrase les octets de data avec des zéros de façon sécurisée.

    Fonctionne uniquement sur bytearray et memoryview (mutables).
    Les objets bytes (immuables) ne peuvent pas être effacés.

    Args:
        data : bytearray ou memoryview à zéroïser

    Example:
        key = bytearray(b"secret_key")
        secure_zeroize(key)
        assert key == bytearray(b"\\x00" * 10)
    """
    if isinstance(data, memoryview):
        data[:] = bytes(len(data))
        return

    if not isinstance(data, bytearray):
        raise TypeError(
            f"secure_zeroize attend un bytearray ou memoryview, reçu {type(data).__name__}. "
            "Les objets bytes sont immuables et ne peuvent pas être zéroïsés."
        )

    n = len(data)
    if n == 0:
        return

    # Méthode 1 : overwrite Python natif
    data[:] = b"\x00" * n

    # Méthode 2 : ctypes pour s'assurer que le compilateur n'optimise pas
    # (évite le "dead store elimination" qui peut supprimer les écritures inutiles)
    try:
        addr = id(data) + sys.getsizeof(bytearray()) - n
        ctypes.memset(addr, 0, n)
    except Exception:
        pass  # Fallback silencieux si ctypes échoue (PyPy, etc.)


def bytes_to_zeroizable(data: bytes) -> bytearray:
    """
    Convertit bytes → bytearray pour permettre la zéroïsation ultérieure.

    À utiliser dès la réception de données sensibles.

    Args:
        data : données sensibles en bytes

    Returns:
        bytearray : copie mutable, à zéroïser après usage
    """
    return bytearray(data)


def zeroize_str(s: str) -> None:
    """
    Tente de zéroïser une chaîne Python (best-effort).

    Note : les str Python sont immuables — cette fonction est
    principalement documentaire. Préférer bytearray dès que possible.
    """
    # En Python, str est immuable. On ne peut pas garantir l'effacement.
    # On encourage l'utilisateur à utiliser bytearray.
    pass


# ─── Context manager ─────────────────────────────────────────────────────────

class SensitiveBuffer:
    """
    Context manager pour les données sensibles.

    Alloue un bytearray et le zéroïse automatiquement à la sortie du bloc.

    Example:
        with SensitiveBuffer(32) as buf:
            buf[:] = os.urandom(32)
            use(buf)
        # buf est zéroïsé ici
    """

    def __init__(self, size: int) -> None:
        self._buf = bytearray(size)

    def __enter__(self) -> bytearray:
        return self._buf

    def __exit__(self, *args) -> None:
        secure_zeroize(self._buf)

    @classmethod
    def from_bytes(cls, data: bytes) -> "SensitiveBuffer":
        """Crée un SensitiveBuffer initialisé avec data."""
        obj = cls(len(data))
        obj._buf[:] = data
        return obj


# ─── Analyse S-box : différentielle et linéaire ───────────────────────────────

def sbox_differential_uniformity(sbox_map: list[int], p: int) -> dict:
    """
    Calcule l'uniformité différentielle de la S-box sur Z/pZ.

    Uniformité différentielle δ = max_{a≠0, b} #{x : S(x+a) - S(x) = b mod p}

    Une bonne S-box cryptographique a δ petit (AES : δ = 4 sur GF(2⁸)).
    Pour x³+cx sur Z/pZ, δ peut être plus élevé.

    Args:
        sbox_map : liste de p entiers, sbox_map[x] = S(x)
        p        : le premier

    Returns:
        dict avec 'delta' (uniformité), 'distribution', 'mean'
    """
    # Tableau de différences : DDT[a][b] = #{x : S(x+a)-S(x) = b mod p}
    max_count = 0
    total_entries = 0
    distribution = {}

    for a in range(1, p):  # a ≠ 0
        for b in range(p):
            count = sum(
                1 for x in range(p)
                if (sbox_map[(x + a) % p] - sbox_map[x]) % p == b
            )
            if count > 0:
                distribution[count] = distribution.get(count, 0) + 1
                total_entries += 1
            if count > max_count:
                max_count = count

    mean = sum(k * v for k, v in distribution.items()) / total_entries if total_entries else 0

    return {
        "delta":        max_count,          # uniformité différentielle
        "distribution": distribution,        # fréquence de chaque comptage
        "mean":         round(mean, 3),
        "p":            p,
    }


def sbox_nonlinearity(sbox_map: list[int], p: int) -> dict:
    """
    Calcule la non-linéarité de la S-box via la corrélation de Walsh-Hadamard.

    Pour Z/pZ, on utilise les caractères additifs : χ_a(x) = exp(2πi·ax/p).
    La non-linéarité est liée à la distance aux fonctions affines.

    Approximation pratique : on mesure la corrélation max entre S(x) et ax+b.

    Args:
        sbox_map : liste de p entiers
        p        : le premier

    Returns:
        dict avec 'max_bias' (corrélation max), 'min_distance' (distance aux affines)
    """
    max_bias = 0.0

    for a in range(1, p):      # pente de la fonction affine
        for b in range(p):     # intercept
            # Compter les x où S(x) == ax+b mod p (corrélation avec affine)
            matches = sum(1 for x in range(p) if sbox_map[x] == (a * x + b) % p)
            bias = abs(matches / p - 1 / p)
            if bias > max_bias:
                max_bias = bias

    # Distance minimale aux fonctions affines (non-linéarité)
    # = p * (0.5 - max_correlation/2) approximation
    min_distance = max(0, round(p * (1/p - max_bias), 3))

    return {
        "max_bias":     round(max_bias, 6),
        "min_distance": min_distance,
        "p":            p,
        "note": "Valeurs plus petites = meilleure résistance linéaire",
    }


def analyze_sbox(sbox_instance, p: int) -> dict:
    """
    Analyse complète d'une S-box CAGOULE sur Z/pZ.

    Args:
        sbox_instance : objet SBox (cagoule.sbox.SBox)
        p             : premier de travail (doit être petit pour l'exhaustif)

    Returns:
        dict avec toutes les métriques

    Warning:
        Complexité O(p²) pour l'uniformité différentielle.
        Ne pas utiliser pour p > 1000 sans patience.
    """
    if p > 500:
        raise ValueError(
            f"p={p} trop grand pour l'analyse exhaustive (O(p²)). "
            "Utiliser p ≤ 500 pour cette fonction."
        )

    sbox_map = [sbox_instance.forward(x) for x in range(p)]

    # Vérification de bijectivité
    is_bijective = len(set(sbox_map)) == p

    diff = sbox_differential_uniformity(sbox_map, p)
    lin  = sbox_nonlinearity(sbox_map, p)

    return {
        "p":                p,
        "is_bijective":     is_bijective,
        "type":             "fallback x^d" if sbox_instance.is_fallback() else "cubique x³+cx",
        "d_or_c":           sbox_instance.d if sbox_instance.is_fallback() else sbox_instance.c,
        "differential":     diff,
        "linear":           lin,
        "security_note": (
            "δ=1 : parfaite (AES-like). "
            f"δ={diff['delta']} obtenu — "
            + ("acceptable" if diff["delta"] <= p // 4 else "élevé, usage académique uniquement")
        ),
    }


# ─── Rapport lisible ──────────────────────────────────────────────────────────

def sbox_report(analysis: dict) -> str:
    """Formate les résultats d'analyze_sbox en texte lisible."""
    d = analysis
    lines = [
        f"S-box Analysis — p={d['p']} — type={d['type']}",
        f"  Bijective       : {'✓' if d['is_bijective'] else '✗'}",
        f"  Paramètre       : {d['d_or_c']}",
        f"  Diff. uniformity: δ = {d['differential']['delta']}  (idéal: 1)",
        f"  Mean DDT count  : {d['differential']['mean']}",
        f"  Max linear bias : {d['linear']['max_bias']}  (idéal: ~1/p)",
        f"  Min dist affine : {d['linear']['min_distance']}",
        f"  Note            : {d['security_note']}",
    ]
    return "\n".join(lines)
