"""
test_nist.py — Tests statistiques NIST SP 800-22 CAGOULE v2.0.0

Note : ces tests portent sur ChaCha20-Poly1305 (couche externe).
La couche Z/pZ interne est expérimentale et n'est pas évaluée ici.
"""
import math, os, pytest, warnings
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

SAMPLE_BITS = 1024 * 1024 * 8   # 1 Mo
ALPHA       = 0.01


@pytest.fixture(scope="module")
def cipher_bits():
    key   = os.urandom(32)
    nonce = os.urandom(12)
    aead  = ChaCha20Poly1305(key)
    ct    = aead.encrypt(nonce, os.urandom(SAMPLE_BITS // 8), b"")
    ct    = ct[:-16][:SAMPLE_BITS // 8]
    bits  = []
    for byte in ct:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits[:SAMPLE_BITS]


# ── Helpers ────────────────────────────────────────────────────────────

def erfc(x):
    if x < 0: return 2.0 - erfc(-x)
    t = 1.0 / (1.0 + 0.3275911 * x)
    poly = t * (0.254829592 + t * (-0.284496736 + t * (1.421413741 + t * (-1.453152027 + t * 1.061405429))))
    return poly * math.exp(-x * x)

def igamc(a, x):
    if x <= 0 or a <= 0: return 1.0
    if x < a + 1:
        ap, delta, total = a, 1.0/a, 1.0/a
        for _ in range(200):
            ap += 1; delta *= x/ap; total += delta
            if abs(delta) < abs(total) * 1e-9: break
        return 1.0 - total * math.exp(-x + a * math.log(x) - math.lgamma(a))
    b, c, d, h = x+1-a, 1e300, 1.0/(x+1-a), 1.0/(x+1-a)
    for i in range(1, 200):
        an = -i*(i-a); b += 2; d = an*d+b
        if abs(d) < 1e-300: d = 1e-300
        c = b+an/c
        if abs(c) < 1e-300: c = 1e-300
        d = 1.0/d; delta = d*c; h *= delta
        if abs(delta-1) < 1e-9: break
    return math.exp(-x + a*math.log(x) - math.lgamma(a)) * h


# ── Tests NIST ─────────────────────────────────────────────────────────

class TestNIST_01_Frequency:
    @pytest.mark.timeout(600)
    def test_cipher(self, cipher_bits):
        n = len(cipher_bits)
        s = sum(1 if b else -1 for b in cipher_bits)
        p = erfc(abs(s) / math.sqrt(n) / math.sqrt(2))
        assert p >= ALPHA, f"Frequency p={p:.6f}"

class TestNIST_02_BlockFrequency:
    def test_cipher(self, cipher_bits):
        M, n = 128, len(cipher_bits)
        N = n // M
        if N < 20: pytest.skip("Pas assez de blocs")
        chi = sum((sum(cipher_bits[i*M:(i+1)*M])/M - 0.5)**2 for i in range(N)) * 4 * M
        p = igamc(N/2, chi/2)
        assert p >= ALPHA, f"BlockFreq p={p:.6f}"

class TestNIST_03_Runs:
    def test_cipher(self, cipher_bits):
        n = len(cipher_bits)
        pi = sum(cipher_bits) / n
        if abs(pi - 0.5) >= 2/math.sqrt(n): pytest.skip("Pré-test échoué")
        v = 1 + sum(1 for i in range(n-1) if cipher_bits[i] != cipher_bits[i+1])
        num = abs(v - 2*n*pi*(1-pi))
        den = 2*math.sqrt(2*n)*pi*(1-pi)
        p = erfc(num/den)
        assert p >= ALPHA, f"Runs p={p:.6f}"

class TestNIST_04_LongestRun:
    def test_cipher(self, cipher_bits):
        n, M = len(cipher_bits), 128
        N = n // M
        if N < 20: pytest.skip("Pas assez de blocs")
        pi = [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124]; K = 5
        counts = [0] * (K + 1)
        for i in range(N):
            block = cipher_bits[i*M:(i+1)*M]
            mr = cr = 0
            for bit in block:
                if bit: cr += 1; mr = max(mr, cr)
                else: cr = 0
            idx = min(max(mr-4, 0), K)
            counts[idx] += 1
        chi = sum((counts[i]-N*pi[i])**2/(N*pi[i]) for i in range(K+1))
        p = igamc(K/2, chi/2)
        assert p >= ALPHA, f"LongestRun p={p:.6f}"

class TestNIST_05_MatrixRank:
    def _gf2_rank(self, m, r, c):
        rank = 0
        for col in range(c):
            pv = next((row for row in range(rank, r) if m[row][col]), None)
            if pv is None: continue
            m[rank], m[pv] = m[pv], m[rank]
            for row in range(r):
                if row != rank and m[row][col]:
                    m[row] = [m[row][k]^m[rank][k] for k in range(c)]
            rank += 1
        return rank

    def test_cipher(self, cipher_bits):
        M, Q, n = 32, 32, len(cipher_bits)
        N = n // (M*Q)
        if N < 20: pytest.skip("Pas assez de bits")
        FM = FM1 = 0
        for i in range(N):
            st = i*M*Q
            mat = [[cipher_bits[st+r*Q+c] for c in range(Q)] for r in range(M)]
            rk = self._gf2_rank([row[:] for row in mat], M, Q)
            if rk == M: FM += 1
            elif rk == M-1: FM1 += 1
        chi = (FM-N*0.2888)**2/(N*0.2888) + (FM1-N*0.5776)**2/(N*0.5776) + (N-FM-FM1-N*0.1336)**2/(N*0.1336)
        p = math.exp(-chi/2)
        assert p >= ALPHA, f"MatrixRank p={p:.6f}"

class TestNIST_06_DFT:
    def test_cipher(self, cipher_bits):
        n = min(len(cipher_bits), 100000)
        x = [1 if b else -1 for b in cipher_bits[:n]]
        T = 2.0 * math.sqrt(math.log(1.0/0.05)*n)
        count = sum(1 for f in range(1, n//2+1)
                    if math.sqrt(sum(x[k]*math.cos(2*math.pi*f*k/n) for k in range(n))**2 +
                                  sum(x[k]*math.sin(2*math.pi*f*k/n) for k in range(n))**2) < T)
        N0 = 0.95*n/2
        d  = (count-N0)/math.sqrt(n*0.95*0.05/4)
        p  = erfc(abs(d)/math.sqrt(2))
        assert p >= ALPHA, f"DFT p={p:.6f}"

class TestNIST_07_ApproximateEntropy:
    def _phi(self, bits, m):
        n = len(bits)
        counts = {}
        for i in range(n):
            pat = tuple(bits[(i+j)%n] for j in range(m))
            counts[pat] = counts.get(pat, 0) + 1
        return sum(c*math.log(c/n) for c in counts.values() if c > 0) / n

    def test_cipher(self, cipher_bits):
        n = min(len(cipher_bits), 50000)
        bits = cipher_bits[:n]; m = 5
        ap_en = self._phi(bits, m) - self._phi(bits, m+1)
        chi = 2*n*(math.log(2) - ap_en)
        p   = igamc(2**(m-1), chi/2)
        assert p >= ALPHA, f"ApproxEntropy p={p:.6f}"

class TestNIST_08_CumulativeSums:
    def test_forward(self, cipher_bits):
        n = len(cipher_bits)
        x = [1 if b else -1 for b in cipher_bits]
        S = [0]; [S.append(S[-1]+xi) for xi in x]
        z = max(abs(s) for s in S[1:])
        sqrt_n = math.sqrt(n)
        k_max = int((n/z-1)/4) + 1
        s1 = sum((erfc((4*k+1)*z/sqrt_n)-erfc((4*k-1)*z/sqrt_n))/2 for k in range(-k_max,k_max+1))
        s2 = sum((erfc((4*k+3)*z/sqrt_n)-erfc((4*k+1)*z/sqrt_n))/2 for k in range(-k_max,k_max+1))
        p  = 1.0 - s1 + s2
        assert p >= ALPHA, f"CumSums p={p:.6f}"
    def test_backward(self, cipher_bits):
        self.test_forward(list(reversed(cipher_bits)))

class TestNIST_09_Serial:
    def _psi_sq(self, bits, m):
        n = len(bits)
        counts = {}
        for i in range(n):
            pat = tuple(bits[(i+j)%n] for j in range(m))
            counts[pat] = counts.get(pat, 0) + 1
        return sum(c**2 for c in counts.values()) * 2**m / n - n

    def test_cipher(self, cipher_bits):
        n = min(len(cipher_bits), 50000)
        bits = cipher_bits[:n]; m = 3
        pm, pm1, pm2 = self._psi_sq(bits,m), self._psi_sq(bits,m-1), self._psi_sq(bits,m-2)
        p1 = igamc(2**(m-2), (pm-pm1)/2)
        p2 = igamc(2**(m-3), (pm-2*pm1+pm2)/2)
        assert p1 >= ALPHA, f"Serial p1={p1:.6f}"
        assert p2 >= ALPHA, f"Serial p2={p2:.6f}"

class TestNIST_10_LinearComplexity:
    def _bm(self, bits):
        n=len(bits); C=[0]*n; B=[0]*n; C[0]=B[0]=1; L=b=0
        for i in range(n):
            d = bits[i]
            for j in range(1,L+1): d ^= C[j]&bits[i-j]
            if d==0: b+=1; continue
            T=C[:]; [C.__setitem__(j,C[j]^B[j-b]) for j in range(b,n)]
            if 2*L<=i: L=i+1-L; B=T; b=1
            else: b+=1
        return L

    def test_cipher(self, cipher_bits):
        M=500; n=len(cipher_bits); N=n//M
        if N<20: pytest.skip("Pas assez de bits")
        mu=M/2.0+(9.0+(-1.0)**(M+1))/36.0-(M/3.0+2.0/9.0)/(2.0**M)
        pi=[0.010417,0.031250,0.125000,0.500000,0.250000,0.062500,0.020833]
        counts=[0]*7
        for i in range(N):
            L=self._bm(cipher_bits[i*M:(i+1)*M])
            T=(-1)**M*(L-mu)+2.0/9.0
            idx=0 if T<=-2.5 else 1 if T<=-1.5 else 2 if T<=-0.5 else 3 if T<=0.5 else 4 if T<=1.5 else 5 if T<=2.5 else 6
            counts[idx]+=1
        chi=sum((counts[i]-N*pi[i])**2/(N*pi[i]) for i in range(7))
        p=igamc(3,chi/2)
        assert p >= ALPHA, f"LinearComplexity p={p:.6f}"

class TestNIST_11_NonOverlappingTemplate:
    def test_cipher(self, cipher_bits):
        n=len(cipher_bits); M=1000; B=(1,1,1,0,0,1,0); m=len(B); N=n//M
        if N<8: pytest.skip("Pas assez de blocs")
        mu=(M-m+1)/(2**m)
        sigma_sq=M*(1/2**m-(2*m-1)/2**(2*m))
        counts=[]
        for i in range(N):
            block=cipher_bits[i*M:(i+1)*M]; W=j=0
            while j<=M-m:
                if tuple(block[j:j+m])==B: W+=1; j+=m
                else: j+=1
            counts.append(W)
        chi=sum((w-mu)**2/sigma_sq for w in counts)
        p=igamc(N/2,chi/2)
        assert p >= ALPHA, f"NonOverlapping p={p:.6f}"

class TestNIST_12_OverlappingTemplate:
    def test_cipher(self, cipher_bits):
        n=min(len(cipher_bits),1000000); bits=cipher_bits[:n]
        m=9; B=(1,)*m; K=5
        pi=[0.364091,0.185659,0.139381,0.100571,0.070432,0.139865]
        N=n//1032; M=n//N
        if N<8: pytest.skip("Pas assez de bits")
        counts=[0]*(K+1)
        for i in range(N):
            block=bits[i*M:(i+1)*M]
            W=sum(1 for j in range(M-m+1) if tuple(block[j:j+m])==B)
            counts[min(W,K)]+=1
        chi=sum((counts[i]-N*pi[i])**2/(N*pi[i]) for i in range(K+1))
        p=igamc(K/2,chi/2)
        assert p >= ALPHA, f"Overlapping p={p:.6f}"

class TestNIST_13_Universal:
    def test_cipher(self, cipher_bits):
        n=len(cipher_bits); L=7; Q=1280
        if n<(Q+1000)*L: pytest.skip("Pas assez de bits")
        table={}
        for i in range(Q):
            pat=tuple(cipher_bits[i*L:(i+1)*L]); table[pat]=i+1
        total=0.0; K=(n//L)-Q
        for i in range(K):
            j=Q+i; pat=tuple(cipher_bits[j*L:(j+1)*L])
            prev=table.get(pat,0)
            total+=math.log2(j+1-prev) if j+1-prev>0 else 0
            table[pat]=j+1
        fn=total/K
        c=0.7-0.8/L+(4+32/L)*K**(-3/L)/15
        sigma=c*math.sqrt(3.125/K)
        p=erfc(abs(fn-6.1962507)/(math.sqrt(2)*sigma))
        assert p >= ALPHA, f"Universal p={p:.6f}"

class TestNIST_14_RandomExcursions:
    def test_cipher(self, cipher_bits):
        n=len(cipher_bits)
        x=[1 if b else -1 for b in cipher_bits]
        S=[0]; [S.append(S[-1]+xi) for xi in x]
        cycles=[]; start=0
        for i in range(1,len(S)):
            if S[i]==0: cycles.append(S[start:i+1]); start=i
        J=len(cycles)
        if J<500: pytest.skip(f"Trop peu de cycles ({J})")
        for state in [-4,-3,-2,-1,1,2,3,4]:
            xi=sum(sum(1 for s in cyc if s==state) for cyc in cycles)
            exp=J/(2*abs(state)); var=J*(4*abs(state)-2)/(4*state**2)
            if var>0:
                z=abs(xi-exp)/math.sqrt(var)
                p=erfc(z/math.sqrt(2))
                assert p >= ALPHA, f"RandExcursions state={state} p={p:.6f}"
