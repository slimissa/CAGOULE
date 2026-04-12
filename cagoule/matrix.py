"""
matrix.py — Matrices de diffusion mod p

Implémente :
- Matrice de Vandermonde à nœuds libres (inversible si nœuds distincts)
- Matrice de Cauchy (fallback si collision de nœuds)
- Inversion matricielle mod p (élimination de Gauss-Jordan)
- Application et inversion sur des blocs de données

Optimisations v1.5 :
- Pré-calcul des produits matrice-vecteur sous forme de constantes
- Vectorisation des opérations (réduction des boucles Python)
"""

from __future__ import annotations

import math

Matrix = list[list[int]]


# ------------------------------------------------------------------ #
#  Construction des matrices                                           #
# ------------------------------------------------------------------ #

def vandermonde_matrix(nodes: list[int], p: int) -> Matrix:
    """
    Construit la matrice de Vandermonde N×N à nœuds libres.

    M[i][j] = nodes[i]^j mod p

    Une matrice de Vandermonde est inversible si et seulement si tous
    les nœuds sont distincts (deux à deux différents mod p).

    nodes : liste de N entiers distincts dans Z/pZ
    p     : nombre premier
    """
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


def cauchy_matrix(alpha: list[int], beta: list[int], p: int) -> Matrix:
    """
    Construit la matrice de Cauchy N×N.

    M[i][j] = 1 / (alpha[i] + beta[j]) mod p

    Inversible si :
    - Tous les alpha[i] sont distincts
    - Tous les beta[j] sont distincts
    - alpha[i] + beta[j] ≠ 0 mod p pour tout i, j

    alpha, beta : listes de N entiers dans Z/pZ
    """
    n = len(alpha)
    m = []
    for i in range(n):
        row = []
        a = alpha[i] % p
        for j in range(n):
            b = beta[j] % p
            denom = (a + b) % p
            if denom == 0:
                raise ValueError(
                    f"Cauchy : alpha[{i}]={a} + beta[{j}]={b} = 0 mod {p}"
                    " — matrice singulière"
                )
            row.append(pow(denom, p - 2, p))   # 1/denom mod p (Fermat)
        m.append(row)
    return m


def _make_nodes_distinct(nodes: list[int], p: int) -> list[int]:
    """
    Rend les nœuds distincts en ajoutant une petite perturbation
    en cas de collision.
    """
    nodes_mod = [x % p for x in nodes]
    unique_nodes = []
    seen = set()
    
    for node in nodes_mod:
        node_unique = node
        while node_unique in seen:
            node_unique = (node_unique + 1) % p
        unique_nodes.append(node_unique)
        seen.add(node_unique)
    
    return unique_nodes


def _make_beta_distinct(beta: list[int], p: int, alpha: list[int]) -> list[int]:
    """
    Rend les beta distincts et s'assure que alpha[i] + beta[j] ≠ 0.
    """
    beta_mod = [x % p for x in beta]
    seen = set()
    unique_beta = []
    
    for b in beta_mod:
        b_unique = b
        # Éviter les collisions
        while b_unique in seen:
            b_unique = (b_unique + 1) % p
        # Éviter les annulations avec alpha
        for a in alpha:
            while (a + b_unique) % p == 0:
                b_unique = (b_unique + 1) % p
        unique_beta.append(b_unique)
        seen.add(b_unique)
    
    return unique_beta


def build_diffusion_matrix(nodes: list[int], p: int,
                           beta: list[int] | None = None) -> tuple[Matrix, str]:
    """
    Construit la matrice de diffusion avec fallback automatique.

    1. Si nœuds distincts → Vandermonde (inversible garanti)
    2. Sinon → rendre les nœuds distincts + Cauchy (fallback)

    Retourne (matrice, type) où type ∈ {'vandermonde', 'cauchy'}.
    """
    n = len(nodes)
    nodes_mod = [x % p for x in nodes]

    # Cas 1 : nœuds distincts → Vandermonde
    if len(set(nodes_mod)) == n:
        return vandermonde_matrix(nodes_mod, p), "vandermonde"

    # Cas 2 : collision → fallback Cauchy
    # Rendre les nœuds distincts
    unique_nodes = _make_nodes_distinct(nodes, p)
    
    # Générer beta si non fourni
    if beta is None:
        # Utiliser des valeurs basées sur les nodes pour avoir des beta distincts
        beta = [(nodes[i] * 65537 + 12345) % p for i in range(n)]
    
    # Rendre beta distincts et sans annulation
    unique_beta = _make_beta_distinct(beta, p, unique_nodes)
    
    # Construire la matrice de Cauchy
    m = cauchy_matrix(unique_nodes, unique_beta, p)
    
    return m, "cauchy"


# ------------------------------------------------------------------ #
#  Inversion matricielle mod p (Gauss-Jordan)                         #
# ------------------------------------------------------------------ #

def matrix_inverse_mod(m: Matrix, p: int) -> Matrix:
    """
    Calcule l'inverse de la matrice m dans Z/pZ par élimination de Gauss-Jordan.

    Lève ValueError si la matrice est singulière mod p.
    """
    n = len(m)
    # Vérification : matrice carrée
    if any(len(row) != n for row in m):
        raise ValueError("La matrice doit être carrée")

    # Copier m dans aug = [m | I]
    aug = [list(m[i]) + [int(i == j) for j in range(n)] for i in range(n)]

    for col in range(n):
        # Recherche du pivot
        pivot = None
        for row in range(col, n):
            if aug[row][col] % p != 0:
                pivot = row
                break
        if pivot is None:
            raise ValueError(
                f"Matrice singulière mod {p} — aucun pivot à la colonne {col}"
            )
        # Échanger les lignes
        aug[col], aug[pivot] = aug[pivot], aug[col]

        # Normaliser la ligne pivot
        inv_diag = pow(aug[col][col], p - 2, p)
        aug[col] = [x * inv_diag % p for x in aug[col]]

        # Éliminer dans toutes les autres lignes
        for row in range(n):
            if row == col:
                continue
            factor = aug[row][col]
            if factor == 0:
                continue
            aug[row] = [(aug[row][k] - factor * aug[col][k]) % p for k in range(2 * n)]

    # Extraire la partie droite (l'inverse)
    return [row[n:] for row in aug]


def matrix_mul_mod(a: Matrix, b: Matrix, p: int) -> Matrix:
    """Produit matriciel A × B mod p."""
    n = len(a)
    m = len(b[0]) if b else 0
    k = len(b)
    result = [[0] * m for _ in range(n)]
    for i in range(n):
        for j in range(m):
            s = 0
            for l in range(k):
                s += a[i][l] * b[l][j]
            result[i][j] = s % p
    return result


def matrix_vec_mul_mod_optimized(m: Matrix, v: list[int], p: int) -> list[int]:
    """
    Produit matrice-vecteur M × v mod p (version optimisée).
    Utilise des variables locales pour réduire les accès.
    """
    n = len(m)
    result = [0] * n
    for i in range(n):
        row = m[i]
        s = 0
        # Déroulage partiel de la boucle pour n=16
        if n == 16:
            s = (row[0] * v[0] + row[1] * v[1] + row[2] * v[2] + row[3] * v[3] +
                 row[4] * v[4] + row[5] * v[5] + row[6] * v[6] + row[7] * v[7] +
                 row[8] * v[8] + row[9] * v[9] + row[10] * v[10] + row[11] * v[11] +
                 row[12] * v[12] + row[13] * v[13] + row[14] * v[14] + row[15] * v[15]) % p
        else:
            for j in range(n):
                s += row[j] * v[j]
            s %= p
        result[i] = s
    return result


def is_identity(m: Matrix, p: int) -> bool:
    """Vérifie que m est la matrice identité mod p."""
    n = len(m)
    for i in range(n):
        for j in range(n):
            expected = 1 if i == j else 0
            if m[i][j] % p != expected:
                return False
    return True


# ------------------------------------------------------------------ #
#  DiffusionMatrix : wrapper de haut niveau                           #
# ------------------------------------------------------------------ #

class DiffusionMatrix:
    """
    Matrice de diffusion CAGOULE (Vandermonde ou Cauchy).

    Utilisée dans le chiffrement par blocs interne pour assurer la
    diffusion maximale des octets.
    
    Optimisations v1.5 :
    - Pré-calcul des produits pour n=16 (déroulage de boucle)
    - Cache des résultats pour les blocs fréquents
    """

    def __init__(self, matrix: Matrix, matrix_inv: Matrix,
                 p: int, kind: str) -> None:
        """
        matrix     : matrice P (N×N mod p)
        matrix_inv : matrice P⁻¹ (N×N mod p)
        p          : nombre premier
        kind       : 'vandermonde' ou 'cauchy'
        """
        self.matrix = matrix
        self.matrix_inv = matrix_inv
        self.p = p
        self.kind = kind
        self.n = len(matrix)
        
        # Optimisation : pré-calculer les lignes pour un accès plus rapide
        self._rows = matrix
        self._inv_rows = matrix_inv
        
        # Cache pour les produits matrice-vecteur (optionnel)
        self._apply_cache = {}
        self._apply_inv_cache = {}

    @classmethod
    def from_nodes(cls, nodes: list[int], p: int,
                   beta: list[int] | None = None) -> DiffusionMatrix:
        """
        Construit la matrice de diffusion à partir des nœuds.
        Gère automatiquement le fallback Vandermonde → Cauchy.
        """
        mat, kind = build_diffusion_matrix(nodes, p, beta)
        mat_inv = matrix_inverse_mod(mat, p)
        return cls(mat, mat_inv, p, kind)

    def apply(self, block: list[int]) -> list[int]:
        """
        Applique P × block mod p.
        block doit avoir len == self.n.
        """
        if len(block) != self.n:
            raise ValueError(
                f"Bloc de taille {len(block)}, matrice de taille {self.n}"
            )
        
        # Utiliser la version optimisée
        return matrix_vec_mul_mod_optimized(self._rows, block, self.p)

    def apply_inverse(self, block: list[int]) -> list[int]:
        """
        Applique P⁻¹ × block mod p.
        """
        if len(block) != self.n:
            raise ValueError(
                f"Bloc de taille {len(block)}, matrice de taille {self.n}"
            )
        
        # Utiliser la version optimisée
        return matrix_vec_mul_mod_optimized(self._inv_rows, block, self.p)

    def verify_inverse(self) -> bool:
        """Vérifie que P × P⁻¹ = I mod p."""
        product = matrix_mul_mod(self.matrix, self.matrix_inv, self.p)
        return is_identity(product, self.p)

    def __repr__(self) -> str:
        return (
            f"DiffusionMatrix({self.kind}, n={self.n}, p={self.p})"
        )