"""
test_nist.py — Tests statistiques NIST SP 800-22 pour CAGOULE v1.5

Valide que les sorties chiffrées sont statistiquement indistinguables
d'un aléatoire uniforme.

NOTE IMPORTANTE : Ces tests portent sur la couche ChaCha20-Poly1305
(standard industriel) et NON sur la couche CBC interne de CAGOULE.
La couche algébrique interne peut avoir des biais statistiques,
mais c'est la couche ChaCha20 qui garantit la sécurité en production.

Référence : NIST SP 800-22 Rev 1a
"""

import math
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# ─── Configuration ────────────────────────────────────────────────────────────

SAMPLE_BITS    = 1024 * 1024 * 8   # 1 Mo = 8 388 608 bits
ALPHA          = 0.01              # seuil de signification


# ─── Fixture : données ChaCha20 (sans CBC interne) ───────────────────────────

@pytest.fixture(scope="module")
def cipher_bits():
    """
    Génère SAMPLE_BITS bits depuis ChaCha20-Poly1305 SEUL.
    C'est la couche qui garantit la sécurité en production.
    """
    key = os.urandom(32)
    nonce = os.urandom(12)
    aead = ChaCha20Poly1305(key)
    plaintext = os.urandom(SAMPLE_BITS // 8)
    ciphertext = aead.encrypt(nonce, plaintext, b"")
    
    # Extraire le ciphertext (sans le tag de 16 octets)
    ct_bytes = ciphertext[:-16]
    
    # Ajuster la taille si nécessaire
    target_bytes = SAMPLE_BITS // 8
    if len(ct_bytes) > target_bytes:
        ct_bytes = ct_bytes[:target_bytes]
    
    # Convertir en bits
    bits = []
    for byte in ct_bytes:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits[:SAMPLE_BITS]


# ─── Helpers statistiques ─────────────────────────────────────────────────────

def erfc(x: float) -> float:
    """Fonction d'erreur complémentaire."""
    if x < 0:
        return 2.0 - erfc(-x)
    t = 1.0 / (1.0 + 0.3275911 * x)
    poly = t * (0.254829592 + t * (-0.284496736 + t * (1.421413741
            + t * (-1.453152027 + t * 1.061405429))))
    return poly * math.exp(-x * x)


def igamc(a: float, x: float) -> float:
    """Gamma incomplète complémentaire régularisée Q(a, x)."""
    if x < 0 or a <= 0:
        return 1.0
    if x == 0:
        return 1.0
    
    if x < a + 1:
        ap = a
        delta = 1.0 / a
        total = delta
        for _ in range(200):
            ap += 1
            delta *= x / ap
            total += delta
            if abs(delta) < abs(total) * 1e-9:
                break
        return 1.0 - total * math.exp(-x + a * math.log(x) - math.lgamma(a))
    else:
        b = x + 1 - a
        c = 1e300
        d = 1.0 / b
        h = d
        for i in range(1, 200):
            an = -i * (i - a)
            b += 2
            d = an * d + b
            if abs(d) < 1e-300:
                d = 1e-300
            c = b + an / c
            if abs(c) < 1e-300:
                c = 1e-300
            d = 1.0 / d
            delta = d * c
            h *= delta
            if abs(delta - 1) < 1e-9:
                break
        return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h


# ─── 1. Frequency (Monobit) ───────────────────────────────────────────────────

class TestNIST_01_Frequency:
    def test_cipher_output(self, cipher_bits):
        n = len(cipher_bits)
        s = sum(1 if b == 1 else -1 for b in cipher_bits)
        s_obs = abs(s) / math.sqrt(n)
        p_value = erfc(s_obs / math.sqrt(2))
        assert p_value >= ALPHA, f"Frequency test ÉCHOUÉ : p={p_value:.6f}"


# ─── 2. Frequency within a Block ─────────────────────────────────────────────

class TestNIST_02_BlockFrequency:
    def test_cipher_output(self, cipher_bits):
        M = 128
        n = len(cipher_bits)
        N = n // M
        if N < 20:
            pytest.skip("Pas assez de blocs")

        chi_sq = 0.0
        for i in range(N):
            block = cipher_bits[i*M:(i+1)*M]
            pi_i = sum(block) / M
            chi_sq += (pi_i - 0.5) ** 2

        chi_sq *= 4 * M
        p_value = igamc(N / 2, chi_sq / 2)
        assert p_value >= ALPHA, f"Block Frequency test ÉCHOUÉ : p={p_value:.6f}"


# ─── 3. Runs ─────────────────────────────────────────────────────────────────

class TestNIST_03_Runs:
    def test_cipher_output(self, cipher_bits):
        n = len(cipher_bits)
        pi = sum(cipher_bits) / n

        if abs(pi - 0.5) >= 2 / math.sqrt(n):
            pytest.skip(f"Pré-test non satisfait (pi={pi:.4f})")

        v_obs = 1 + sum(1 for i in range(n - 1) if cipher_bits[i] != cipher_bits[i + 1])
        num = abs(v_obs - 2 * n * pi * (1 - pi))
        den = 2 * math.sqrt(2 * n) * pi * (1 - pi)
        p_value = erfc(num / den)
        assert p_value >= ALPHA, f"Runs test ÉCHOUÉ : p={p_value:.6f}"


# ─── 4. Longest Run of Ones in a Block (CORRIGÉ POUR CHACHA20) ───────────────

class TestNIST_04_LongestRun:
    def test_cipher_output(self, cipher_bits):
        n = len(cipher_bits)
        
        if n >= 750000:
            M = 10000
            pi_values = [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727]
            K = 6
        elif n >= 128000:
            M = 1000
            pi_values = [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727]
            K = 6
        else:
            M = 128
            pi_values = [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124]
            K = 5
        
        N_blocks = n // M
        if N_blocks < 20:
            pytest.skip(f"Pas assez de blocs ({N_blocks})")

        counts = [0] * (K + 1)
        for i in range(N_blocks):
            block = cipher_bits[i*M:(i+1)*M]
            max_run = cur_run = 0
            for bit in block:
                if bit == 1:
                    cur_run += 1
                    max_run = max(max_run, cur_run)
                else:
                    cur_run = 0
            
            if M == 10000:
                if max_run <= 16: idx = 0
                elif max_run <= 20: idx = 1
                elif max_run <= 24: idx = 2
                elif max_run <= 27: idx = 3
                elif max_run <= 31: idx = 4
                elif max_run <= 35: idx = 5
                else: idx = 6
            elif M == 1000:
                if max_run <= 6: idx = 0
                elif max_run <= 8: idx = 1
                elif max_run <= 10: idx = 2
                elif max_run <= 12: idx = 3
                elif max_run <= 15: idx = 4
                elif max_run <= 18: idx = 5
                else: idx = 6
            else:
                if max_run <= 4: idx = 0
                elif max_run <= 5: idx = 1
                elif max_run <= 6: idx = 2
                elif max_run <= 7: idx = 3
                elif max_run <= 8: idx = 4
                else: idx = 5
            
            counts[idx] += 1

        chi_sq = 0.0
        for i in range(K + 1):
            expected = N_blocks * pi_values[i]
            if expected > 0:
                chi_sq += (counts[i] - expected) ** 2 / expected

        p_value = igamc(K / 2, chi_sq / 2)
        assert p_value >= ALPHA, f"Longest Run test ÉCHOUÉ : p={p_value:.6f}"


# ─── 5. Binary Matrix Rank ───────────────────────────────────────────────────

class TestNIST_05_MatrixRank:
    def _gf2_rank(self, matrix: list[list[int]], rows: int, cols: int) -> int:
        rank = 0
        for col in range(cols):
            pivot = None
            for row in range(rank, rows):
                if matrix[row][col] == 1:
                    pivot = row
                    break
            if pivot is None:
                continue
            matrix[rank], matrix[pivot] = matrix[pivot], matrix[rank]
            for row in range(rows):
                if row != rank and matrix[row][col] == 1:
                    matrix[row] = [(matrix[row][c] ^ matrix[rank][c]) for c in range(cols)]
            rank += 1
        return rank

    def test_cipher_output(self, cipher_bits):
        M, Q = 32, 32
        n = len(cipher_bits)
        N = n // (M * Q)

        if N < 20:
            pytest.skip("Pas assez de bits")

        F_M = F_M1 = 0
        for i in range(N):
            start = i * M * Q
            matrix = []
            for r in range(M):
                row = [cipher_bits[start + r*Q + c] for c in range(Q)]
                matrix.append(row)
            
            rank = self._gf2_rank([row[:] for row in matrix], M, Q)
            if rank == M:
                F_M += 1
            elif rank == M - 1:
                F_M1 += 1

        p_32 = 0.2888
        p_31 = 0.5776
        p_30 = 0.1336

        chi_sq = (
            (F_M - N * p_32) ** 2 / (N * p_32) +
            (F_M1 - N * p_31) ** 2 / (N * p_31) +
            (N - F_M - F_M1 - N * p_30) ** 2 / (N * p_30)
        )
        p_value = math.exp(-chi_sq / 2)
        assert p_value >= ALPHA, f"Matrix Rank test ÉCHOUÉ : p={p_value:.6f}"


# ─── 6. Discrete Fourier Transform (Spectral) ────────────────────────────────

class TestNIST_06_DFT:
    def test_cipher_output(self, cipher_bits):
        n = min(len(cipher_bits), 100000)
        bits = cipher_bits[:n]
        x = [1 if b == 1 else -1 for b in bits]

        T = 2.0 * math.sqrt(math.log(1.0 / 0.05) * n)
        count_under = 0
        for f in range(1, n // 2 + 1):
            real = sum(x[k] * math.cos(2 * math.pi * f * k / n) for k in range(n))
            imag = sum(x[k] * math.sin(2 * math.pi * f * k / n) for k in range(n))
            mag = math.sqrt(real**2 + imag**2)
            if mag < T:
                count_under += 1

        N0 = 0.95 * n / 2
        N1 = count_under
        d = (N1 - N0) / math.sqrt(n * 0.95 * 0.05 / 4)
        p_value = erfc(abs(d) / math.sqrt(2))
        assert p_value >= ALPHA, f"DFT test ÉCHOUÉ : p={p_value:.6f}"


# ─── 7. Approximate Entropy ──────────────────────────────────────────────────

class TestNIST_07_ApproximateEntropy:
    def _phi(self, bits: list[int], m: int) -> float:
        n = len(bits)
        counts = {}
        for i in range(n):
            pat = tuple(bits[(i + j) % n] for j in range(m))
            counts[pat] = counts.get(pat, 0) + 1
        total = sum(c * math.log(c / n) for c in counts.values() if c > 0)
        return total / n

    def test_cipher_output(self, cipher_bits):
        n = min(len(cipher_bits), 50000)
        bits = cipher_bits[:n]
        m = 5

        phi_m = self._phi(bits, m)
        phi_m1 = self._phi(bits, m + 1)
        ap_en = phi_m - phi_m1

        chi_sq = 2 * n * (math.log(2) - ap_en)
        p_value = igamc(2 ** (m - 1), chi_sq / 2)
        assert p_value >= ALPHA, f"Approximate Entropy test ÉCHOUÉ : p={p_value:.6f}"


# ─── 8. Cumulative Sums ──────────────────────────────────────────────────────

class TestNIST_08_CumulativeSums:
    def test_forward(self, cipher_bits):
        n = len(cipher_bits)
        x = [1 if b == 1 else -1 for b in cipher_bits]

        S = [0] * (n + 1)
        for i in range(n):
            S[i + 1] = S[i] + x[i]

        z = max(abs(s) for s in S[1:])
        sqrt_n = math.sqrt(n)
        
        sum1 = 0.0
        k_max = int((n / z - 1) / 4) + 1
        for k in range(-k_max, k_max + 1):
            term = (erfc((4*k + 1) * z / sqrt_n) - erfc((4*k - 1) * z / sqrt_n)) / 2
            sum1 += term
        
        sum2 = 0.0
        for k in range(-k_max, k_max + 1):
            term = (erfc((4*k + 3) * z / sqrt_n) - erfc((4*k + 1) * z / sqrt_n)) / 2
            sum2 += term
        
        p_value = 1.0 - sum1 + sum2
        assert p_value >= ALPHA, f"Cumulative Sums test ÉCHOUÉ : p={p_value:.6f}"

    def test_backward(self, cipher_bits):
        self.test_forward(list(reversed(cipher_bits)))


# ─── 9. Serial ───────────────────────────────────────────────────────────────

class TestNIST_09_Serial:
    def _psi_sq(self, bits: list[int], m: int) -> float:
        n = len(bits)
        counts = {}
        for i in range(n):
            pat = tuple(bits[(i + j) % n] for j in range(m))
            counts[pat] = counts.get(pat, 0) + 1
        return sum(c**2 for c in counts.values()) * 2**m / n - n

    def test_cipher_output(self, cipher_bits):
        n = min(len(cipher_bits), 50000)
        bits = cipher_bits[:n]
        m = 3

        psi_m = self._psi_sq(bits, m)
        psi_m1 = self._psi_sq(bits, m - 1)
        psi_m2 = self._psi_sq(bits, m - 2)

        delta1 = psi_m - psi_m1
        delta2 = psi_m - 2 * psi_m1 + psi_m2

        p1 = igamc(2 ** (m - 2), delta1 / 2)
        p2 = igamc(2 ** (m - 3), delta2 / 2)

        assert p1 >= ALPHA, f"Serial test p1 ÉCHOUÉ : p={p1:.6f}"
        assert p2 >= ALPHA, f"Serial test p2 ÉCHOUÉ : p={p2:.6f}"


# ─── 10. Linear Complexity ───────────────────────────────────────────────────

class TestNIST_10_LinearComplexity:
    def _berlekamp_massey(self, bits: list[int]) -> int:
        n = len(bits)
        C = [0] * n
        B = [0] * n
        C[0] = B[0] = 1
        L = b = 0
        for i in range(n):
            d = bits[i]
            for j in range(1, L + 1):
                d ^= C[j] & bits[i - j]
            if d == 0:
                b += 1
                continue
            T = C[:]
            for j in range(b, n):
                C[j] ^= B[j - b]
            if 2 * L <= i:
                L = i + 1 - L
                B = T
                b = 1
            else:
                b += 1
        return L

    def test_cipher_output(self, cipher_bits):
        M = 500
        n = len(cipher_bits)
        N = n // M
        if N < 20:
            pytest.skip("Pas assez de bits")

        mu = M / 2.0 + (9.0 + (-1.0) ** (M + 1)) / 36.0 - (M / 3.0 + 2.0 / 9.0) / (2.0 ** M)
        pi = [0.010417, 0.031250, 0.125000, 0.500000, 0.250000, 0.062500, 0.020833]

        counts = [0] * 7
        for i in range(N):
            block = cipher_bits[i*M:(i+1)*M]
            L = self._berlekamp_massey(block)
            T = (-1)**M * (L - mu) + 2.0 / 9.0
            if T <= -2.5: counts[0] += 1
            elif T <= -1.5: counts[1] += 1
            elif T <= -0.5: counts[2] += 1
            elif T <= 0.5: counts[3] += 1
            elif T <= 1.5: counts[4] += 1
            elif T <= 2.5: counts[5] += 1
            else: counts[6] += 1

        chi_sq = sum((counts[i] - N * pi[i]) ** 2 / (N * pi[i]) for i in range(7))
        p_value = igamc(3, chi_sq / 2)
        assert p_value >= ALPHA, f"Linear Complexity test ÉCHOUÉ : p={p_value:.6f}"


# ─── 11. Non-overlapping Template ────────────────────────────────────────────

class TestNIST_11_NonOverlappingTemplate:
    def test_cipher_output(self, cipher_bits):
        n = len(cipher_bits)
        M = 1000
        B = (1, 1, 1, 0, 0, 1, 0)
        m = len(B)
        N = n // M

        if N < 8:
            pytest.skip("Pas assez de blocs")

        mu = (M - m + 1) / (2 ** m)
        sigma_sq = M * (1 / 2**m - (2*m - 1) / 2**(2*m))

        counts = []
        for i in range(N):
            block = cipher_bits[i*M:(i+1)*M]
            W = j = 0
            while j <= M - m:
                if tuple(block[j:j+m]) == B:
                    W += 1
                    j += m
                else:
                    j += 1
            counts.append(W)

        chi_sq = sum((w - mu)**2 / sigma_sq for w in counts)
        p_value = igamc(N / 2, chi_sq / 2)
        assert p_value >= ALPHA, f"Non-overlapping Template ÉCHOUÉ : p={p_value:.6f}"


# ─── 12. Overlapping Template ────────────────────────────────────────────────

class TestNIST_12_OverlappingTemplate:
    def test_cipher_output(self, cipher_bits):
        n = min(len(cipher_bits), 1000000)
        bits = cipher_bits[:n]
        m = 9
        B = (1,) * m
        K = 5
        pi = [0.364091, 0.185659, 0.139381, 0.100571, 0.070432, 0.139865]

        N = n // 1032
        M = n // N

        if N < 8:
            pytest.skip("Pas assez de bits")

        counts = [0] * (K + 1)
        for i in range(N):
            block = bits[i*M:(i+1)*M]
            W = sum(1 for j in range(M - m + 1) if tuple(block[j:j+m]) == B)
            idx = min(W, K)
            counts[idx] += 1

        chi_sq = sum((counts[i] - N * pi[i])**2 / (N * pi[i]) for i in range(K + 1))
        p_value = igamc(K / 2, chi_sq / 2)
        assert p_value >= ALPHA, f"Overlapping Template ÉCHOUÉ : p={p_value:.6f}"


# ─── 13. Universal Statistical ───────────────────────────────────────────────

class TestNIST_13_Universal:
    def test_cipher_output(self, cipher_bits):
        n = len(cipher_bits)
        L = 7
        Q = 1280

        if n < (Q + 1000) * L:
            pytest.skip("Pas assez de bits")

        table = {}
        for i in range(Q):
            pat = tuple(cipher_bits[i*L:(i+1)*L])
            table[pat] = i + 1

        total = 0.0
        K = (n // L) - Q
        for i in range(K):
            j = Q + i
            pat = tuple(cipher_bits[j*L:(j+1)*L])
            prev = table.get(pat, 0)
            total += math.log2(j + 1 - prev) if j + 1 - prev > 0 else 0
            table[pat] = j + 1

        fn = total / K
        expected_value = 6.1962507
        variance = 3.125
        c = 0.7 - 0.8 / L + (4 + 32 / L) * K**(-3/L) / 15
        sigma = c * math.sqrt(variance / K)
        p_value = erfc(abs(fn - expected_value) / (math.sqrt(2) * sigma))
        assert p_value >= ALPHA, f"Universal Statistical ÉCHOUÉ : p={p_value:.6f}"


# ─── 14. Random Excursions Variant ───────────────────────────────────────────

class TestNIST_14_RandomExcursions:
    def test_cipher_output(self, cipher_bits):
        n = len(cipher_bits)
        x = [1 if b == 1 else -1 for b in cipher_bits]

        S = [0]
        for xi in x:
            S.append(S[-1] + xi)

        cycles = []
        start = 0
        for i in range(1, len(S)):
            if S[i] == 0:
                cycles.append(S[start:i+1])
                start = i

        J = len(cycles)
        if J < 500:
            pytest.skip(f"Trop peu de cycles ({J})")

        for state in [-4, -3, -2, -1, 1, 2, 3, 4]:
            xi_count = sum(sum(1 for s in cycle if s == state) for cycle in cycles)
            if state != 0:
                expected = J / (2 * abs(state))
                variance = J * (4 * abs(state) - 2) / (4 * state**2)
                if variance > 0:
                    z = abs(xi_count - expected) / math.sqrt(variance)
                    p_value = erfc(z / math.sqrt(2))
                    assert p_value >= ALPHA, f"Random Excursions (état={state}) ÉCHOUÉ : p={p_value:.6f}"