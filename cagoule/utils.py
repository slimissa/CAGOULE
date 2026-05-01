"""
utils.py — Utilitaires de sécurité CAGOULE v2.0.0

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
    Utilise plusieurs méthodes pour résister aux optimisations.
    
    Args:
        data: Buffer mutable (bytearray ou memoryview)
    
    Raises:
        TypeError: Si data n'est pas effaçable
    """
    if isinstance(data, memoryview):
        # Effacer directement à travers le memoryview
        n = len(data)
        data[:] = b'\x00' * n
        return
    
    if isinstance(data, bytearray):
        n = len(data)
        if n == 0:
            return
        
        # Méthode 1: assignation directe
        data[:] = b'\x00' * n
        
        # Méthode 2: via ctypes pour lutter contre l'optimisation
        try:
            # Obtenir l'adresse du buffer interne (plateforme CPython)
            # Note: Cette méthode est spécifique à CPython
            if sys.implementation.name == 'cpython':
                # Le buffer interne est disponible via memoryview
                view = memoryview(data)
                if view.contiguous:
                    addr = ctypes.addressof(ctypes.c_char.from_buffer(view))
                    ctypes.memset(addr, 0, n)
        except Exception:
            # Ignorer les erreurs de ctypes
            pass
        
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
            - delta: différential uniformity (plus petit = meilleur)
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


def sbox_nonlinearity(sbox_map: list, p: int) -> dict:
    """
    Calcule la non-linéarité d'une S-box (analyse linéaire).
    
    Args:
        sbox_map: Liste de p éléments (sorties de la S-box)
        p: Cardinalité
    
    Returns:
        Dictionnaire avec:
            - max_bias: biais linéaire maximal
            - min_distance: distance minimale
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
    
    # Déterminer le type
    if hasattr(sbox_instance, '_s') and sbox_instance._s is not None:
        sbox_type = "feistel" if sbox_instance._s.use_feistel else "fallback x^d"
        d_or_c = None
    else:
        sbox_type = "python x^d" if getattr(sbox_instance, 'use_fallback', True) else "python cubic"
        d_or_c = getattr(sbox_instance, 'd', None) or getattr(sbox_instance, 'c', None)
    
    # Analyse différentielle et linéaire
    diff = sbox_differential_uniformity(sbox_map, p)
    lin = sbox_nonlinearity(sbox_map, p)
    
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
    """Alias de secure_zeroize pour compatibilité."""
    if isinstance(data, (bytearray, memoryview)):
        secure_zeroize(data)
    elif hasattr(data, 'zeroize') and callable(data.zeroize):
        data.zeroize()
    else:
        warnings.warn(f"zeroize: type {type(data)} non effaçable", RuntimeWarning, stacklevel=2)