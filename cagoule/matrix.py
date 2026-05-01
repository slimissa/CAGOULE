"""
matrix.py — Matrice de diffusion CAGOULE v2.0.0

Délègue à libcagoule.so (C) si disponible, sinon fallback Python v1.x.
L'API publique (DiffusionMatrix) est identique à v1.x — aucun breaking change.
"""

from __future__ import annotations

import ctypes
import math
import warnings

from ._binding import (
    CAGOULE_C_AVAILABLE, _lib,
    CagouleMatrixC,
    list_to_uint64_array, uint64_array_to_list,
    CAGOULE_N,
)
from .logger import get_logger

_log = get_logger(__name__)

Matrix = list[list[int]]


# ════════════════════════════════════════════════════════════════════════
# Implémentation C (chemin rapide)
# ════════════════════════════════════════════════════════════════════════

class DiffusionMatrixC:
    """
    Wrapper Python autour de CagouleMatrix* (C).
    Même API que DiffusionMatrixPython.
    """

    def __init__(self, ptr: ctypes.POINTER, p: int, kind: int) -> None:
        self._ptr = ptr
        self.p = p
        self.kind = "vandermonde" if kind == 0 else "cauchy"
        self.n = CAGOULE_N

    @classmethod
    def from_nodes(cls, nodes: list[int], p: int,
                   beta: list[int] | None = None) -> "DiffusionMatrixC":
        """Construit la matrice depuis les nœuds (beta ignoré en mode C)."""
        if beta is not None:
            warnings.warn(
                "DiffusionMatrixC.from_nodes(): paramètre 'beta' ignoré "
                "(fallback Cauchy automatique en C)",
                RuntimeWarning, stacklevel=2
            )
        arr = list_to_uint64_array(nodes)
        ptr = _lib.cagoule_matrix_build(arr, len(nodes), p)
        if not ptr:
            raise ValueError(
                f"cagoule_matrix_build a échoué pour p={p}, nodes={nodes[:4]}..."
            )
        return cls(ptr, p, ptr.contents.kind)

    def get_ptr(self):
        """Retourne le pointeur C pour utilisation directe (utilisé par cipher.py)."""
        return self._ptr

    def apply(self, block: list[int]) -> list[int]:
        """P × block mod p — chemin C."""
        v_in = list_to_uint64_array(block)
        v_out = (ctypes.c_uint64 * CAGOULE_N)()
        _lib.cagoule_matrix_mul(self._ptr, v_in, v_out)
        return uint64_array_to_list(v_out, CAGOULE_N)

    def apply_inverse(self, block: list[int]) -> list[int]:
        """P⁻¹ × block mod p — chemin C."""
        v_in = list_to_uint64_array(block)
        v_out = (ctypes.c_uint64 * CAGOULE_N)()
        _lib.cagoule_matrix_mul_inv(self._ptr, v_in, v_out)
        return uint64_array_to_list(v_out, CAGOULE_N)

    def verify_inverse(self) -> bool:
        return bool(_lib.cagoule_matrix_verify(self._ptr))

    def __del__(self) -> None:
        if self._ptr and _lib is not None:
            try:
                _lib.cagoule_matrix_free(self._ptr)
                self._ptr = None
            except Exception as e:
                _log.debug(f"Erreur libération matrice: {e}")

    def __repr__(self) -> str:
        return f"DiffusionMatrix[C]({self.kind}, n={self.n}, p={self.p})"


# ════════════════════════════════════════════════════════════════════════
# Implémentation Python (fallback v1.x — inchangée)
# ════════════════════════════════════════════════════════════════════════

def _mulmod(a: int, b: int, p: int) -> int:
    return (a * b) % p


def _vandermonde_matrix(nodes: list[int], p: int) -> Matrix:
    n = len(nodes)
    m = []
    for i in range(n):
        row = []
        alpha = nodes[i] % p
        power = 1
        for j in range(n):
            row.append(power)
            power = power * alpha % p
        m.append(row)
    return m


def _cauchy_matrix(alpha: list[int], beta: list[int], p: int) -> Matrix:
    n = len(alpha)
    m = []
    for i in range(n):
        row = []
        a = alpha[i] % p
        for j in range(n):
            b = beta[j] % p
            denom = (a + b) % p
            if denom == 0:
                raise ValueError(f"Cauchy singulière : alpha[{i}]+beta[{j}]=0")
            row.append(pow(denom, p - 2, p))
        m.append(row)
    return m


def _matrix_inverse_mod(m: Matrix, p: int) -> Matrix:
    n = len(m)
    aug = [list(m[i]) + [int(i == j) for j in range(n)] for i in range(n)]
    for col in range(n):
        pivot = next((row for row in range(col, n) if aug[row][col] % p), None)
        if pivot is None:
            raise ValueError(f"Matrice singulière mod {p}")
        aug[col], aug[pivot] = aug[pivot], aug[col]
        inv_diag = pow(aug[col][col], p - 2, p)
        aug[col] = [x * inv_diag % p for x in aug[col]]
        for row in range(n):
            if row == col:
                continue
            factor = aug[row][col]
            if factor == 0:
                continue
            aug[row] = [(aug[row][k] - factor * aug[col][k]) % p for k in range(2 * n)]
    return [row[n:] for row in aug]


def _matmul_vec(mat: Matrix, v: list[int], p: int) -> list[int]:
    n = len(mat)
    return [sum(mat[i][j] * v[j] for j in range(n)) % p for i in range(n)]


class DiffusionMatrixPython:
    """Implémentation Python pure — fallback si libcagoule.so absent."""

    def __init__(self, matrix: Matrix, matrix_inv: Matrix, p: int, kind: str) -> None:
        self.matrix = matrix
        self.matrix_inv = matrix_inv
        self.p = p
        self.kind = kind
        self.n = len(matrix)

    def get_ptr(self):
        """Retourne None (pas de pointeur C en mode Python)."""
        return None

    @classmethod
    def from_nodes(cls, nodes: list[int], p: int,
                   beta: list[int] | None = None) -> "DiffusionMatrixPython":
        n = len(nodes)
        nodes_mod = [x % p for x in nodes]
        if len(set(nodes_mod)) == n:
            mat = _vandermonde_matrix(nodes_mod, p)
            kind = "vandermonde"
        else:
            seen, alpha = set(), []
            for node in nodes_mod:
                v = node
                while v in seen:
                    v = (v + 1) % p
                alpha.append(v)
                seen.add(v)
            beta_vals = [(p // 2 + 1 + i * 7919) % p for i in range(n)] \
                        if beta is None else list(beta)
            mat = _cauchy_matrix(alpha, beta_vals, p)
            kind = "cauchy"
        mat_inv = _matrix_inverse_mod(mat, p)
        return cls(mat, mat_inv, p, kind)

    def apply(self, block: list[int]) -> list[int]:
        return _matmul_vec(self.matrix, block, self.p)

    def apply_inverse(self, block: list[int]) -> list[int]:
        return _matmul_vec(self.matrix_inv, block, self.p)

    def verify_inverse(self) -> bool:
        n = self.n
        for i in range(n):
            e = [0] * n
            e[i] = 1
            fwd = self.apply(e)
            back = self.apply_inverse(fwd)
            if back[i] != 1 or any(back[j] != 0 for j in range(n) if j != i):
                return False
        return True

    def __repr__(self) -> str:
        return f"DiffusionMatrix[Python]({self.kind}, n={self.n}, p={self.p})"


# ════════════════════════════════════════════════════════════════════════
# API publique unifiée — sélection automatique C / Python
# ════════════════════════════════════════════════════════════════════════

class DiffusionMatrix:
    """
    API publique — identique à v1.x.
    Délègue à DiffusionMatrixC si libcagoule.so disponible,
    sinon DiffusionMatrixPython (fallback transparent).
    """

    def __init__(self, *args, **kwargs):
        raise TypeError(
            "Utiliser DiffusionMatrix.from_nodes() - "
            "l'instanciation directe n'est pas supportée"
        )

    @staticmethod
    def from_nodes(nodes: list[int], p: int,
                   beta: list[int] | None = None):
        """Construit la matrice de diffusion depuis les nœuds."""
        if CAGOULE_C_AVAILABLE:
            return DiffusionMatrixC.from_nodes(nodes, p, beta)
        return DiffusionMatrixPython.from_nodes(nodes, p, beta)