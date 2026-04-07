"""
cli.py — Interface ligne de commande CAGOULE v1.1

Commandes :
    cagoule encrypt <fichier>  -p <password>  [-o <output>]
    cagoule decrypt <fichier>  -p <password>  [-o <output>]
    cagoule bench              [-n <iterations>]
    cagoule inspect <fichier>

Usage :
    python3 cli.py encrypt message.txt -p "MonMotDePasse"
    python3 cli.py decrypt message.cgl1 -p "MonMotDePasse"
    python3 cli.py bench
    python3 cli.py inspect message.cgl1
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
from typing import Optional, Tuple, Any

# ------------------------------------------------------------------ #
#  Imports CAGOULE (centralisés)                                     #
# ------------------------------------------------------------------ #

# Import unique pour éviter la répétition
try:
    from cipher import encrypt
    from decipher import decrypt, CagouleAuthError, CagouleFormatError, CagouleError
    from format import inspect as fmt_inspect, parse, OVERHEAD, CGL1FormatError
    from params import CagouleParams
except ImportError as e:
    print(f"Erreur d'import : {e}", file=sys.stderr)
    print("Assurez-vous que tous les modules CAGOULE sont dans le PATH", file=sys.stderr)
    sys.exit(1)


# ------------------------------------------------------------------ #
#  Utilitaires                                                        #
# ------------------------------------------------------------------ #

def _get_password(args, prompt: str = "Mot de passe : ") -> bytes:
    """Récupère le mot de passe depuis args ou via prompt sécurisé."""
    if hasattr(args, 'password') and args.password:
        return args.password.encode('utf-8')
    pwd = getpass.getpass(prompt)
    return pwd.encode('utf-8')


def _read_input(path: str) -> bytes:
    """Lit un fichier binaire. '-' = stdin."""
    if path == '-':
        return sys.stdin.buffer.read()
    with open(path, 'rb') as f:
        return f.read()


def _write_output(path: Optional[str], data: bytes, default_suffix: str = '.out') -> str:
    """Écrit les données dans un fichier. Retourne le chemin utilisé."""
    if path is None:
        path = f"output{default_suffix}"
    if path == '-':
        sys.stdout.buffer.write(data)
        return '<stdout>'
    # Créer le répertoire parent si nécessaire
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(data)
    return path


def _human_size(n: int) -> str:
    """Convertit une taille en octets en chaîne lisible."""
    for unit in ['o', 'Ko', 'Mo', 'Go']:
        if n < 1024:
            return f"{n} {unit}"
        n //= 1024
    return f"{n} To"


def _format_duration(ms: float) -> str:
    """Formate une durée en ms de façon lisible."""
    if ms < 1:
        return f"{ms*1000:.1f} µs"
    if ms < 1000:
        return f"{ms:.1f} ms"
    return f"{ms/1000:.2f} s"


# ------------------------------------------------------------------ #
#  Commande encrypt                                                   #
# ------------------------------------------------------------------ #

def cmd_encrypt(args) -> int:
    try:
        plaintext = _read_input(args.input)
    except FileNotFoundError:
        print(f"Erreur : fichier introuvable : {args.input}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Erreur de lecture : {e}", file=sys.stderr)
        return 1

    password = _get_password(args)

    t0 = time.perf_counter()
    try:
        ciphertext = encrypt(plaintext, password)
    except Exception as e:
        print(f"Erreur de chiffrement : {e}", file=sys.stderr)
        return 1
    elapsed = time.perf_counter() - t0

    # Déterminer le chemin de sortie
    if args.output is None and args.input != '-':
        out_path = args.input + '.cgl1'
    else:
        out_path = args.output

    try:
        written = _write_output(out_path, ciphertext, default_suffix='.cgl1')
    except Exception as e:
        print(f"Erreur d'écriture : {e}", file=sys.stderr)
        return 1

    size_in = _human_size(len(plaintext))
    size_out = _human_size(len(ciphertext))
    ratio = len(ciphertext) / len(plaintext) if plaintext else 0
    
    print(f"✓ Chiffré : {size_in} → {size_out} (ratio {ratio:.2f}x) en {_format_duration(elapsed*1000)}")
    if written != '<stdout>':
        print(f"  Sortie : {written}")
    return 0


# ------------------------------------------------------------------ #
#  Commande decrypt                                                   #
# ------------------------------------------------------------------ #

def cmd_decrypt(args) -> int:
    try:
        ciphertext = _read_input(args.input)
    except FileNotFoundError:
        print(f"Erreur : fichier introuvable : {args.input}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Erreur de lecture : {e}", file=sys.stderr)
        return 1

    password = _get_password(args)

    t0 = time.perf_counter()
    try:
        plaintext = decrypt(ciphertext, password)
    except CGL1FormatError as e:
        print(f"Erreur de format CGL1 : {e}", file=sys.stderr)
        return 1
    except CagouleAuthError:
        print("Erreur : authentification échouée — mot de passe incorrect ou fichier altéré.",
              file=sys.stderr)
        return 1
    except CagouleError as e:
        print(f"Erreur de déchiffrement : {e}", file=sys.stderr)
        return 1
    elapsed = time.perf_counter() - t0

    # Déterminer le chemin de sortie
    if args.output is None and args.input != '-':
        # Retirer l'extension .cgl1 si présente
        if args.input.endswith('.cgl1'):
            out_path = args.input[:-5]
        else:
            out_path = args.input + '.dec'
    else:
        out_path = args.output

    try:
        written = _write_output(out_path, plaintext, default_suffix='.dec')
    except Exception as e:
        print(f"Erreur d'écriture : {e}", file=sys.stderr)
        return 1

    size_in = _human_size(len(ciphertext))
    size_out = _human_size(len(plaintext))
    print(f"✓ Déchiffré : {size_in} → {size_out} en {_format_duration(elapsed*1000)}")
    if written != '<stdout>':
        print(f"  Sortie : {written}")
    return 0


# ------------------------------------------------------------------ #
#  Commande bench                                                     #
# ------------------------------------------------------------------ #

def cmd_bench(args) -> int:
    n_iter = getattr(args, 'iterations', 3)
    # Tailles de test : 1 Ko, 10 Ko, 100 Ko (évite les temps trop longs)
    sizes = [1024, 10 * 1024, 100 * 1024]
    password = b'BenchmarkPassword2026'

    print("=" * 60)
    print("CAGOULE v1.1 — Benchmark de performance")
    print("=" * 60)

    # ──────────────────────────────────────────────────────────────
    # 1. KDF (dérivation de clé)
    # ──────────────────────────────────────────────────────────────
    print("\n📊 1. Dérivation de clé (Argon2id)")
    print("-" * 40)
    
    kdf_times = []
    for i in range(n_iter):
        t0 = time.perf_counter()
        params = CagouleParams.derive(password)
        kdf_times.append(time.perf_counter() - t0)
        print(f"  Essai {i+1}: {kdf_times[-1]*1000:.1f} ms")
    
    avg_kdf = sum(kdf_times) / len(kdf_times) * 1000
    print(f"\n  → Moyenne : {avg_kdf:.0f} ms sur {n_iter} essais")

    # ──────────────────────────────────────────────────────────────
    # 2. Chiffrement + Déchiffrement
    # ──────────────────────────────────────────────────────────────
    print("\n📊 2. Chiffrement / Déchiffrement (sans re-KDF)")
    print("-" * 40)
    
    # Dériver les params une seule fois pour le bench (pas représentatif du KDF)
    params = CagouleParams.derive(password)
    
    print(f"{'Taille':>10} {'CT taille':>10} {'Chiffrement':>12} {'Déchiffrement':>12} {'Débit':>10}")
    print("-" * 60)

    for size in sizes:
        msg = os.urandom(size)
        
        # Chiffrement (plusieurs itérations)
        enc_times = []
        ct = None
        for _ in range(n_iter):
            t0 = time.perf_counter()
            ct = encrypt(msg, password, params=params)  # params optionnel
            enc_times.append(time.perf_counter() - t0)
        avg_enc = sum(enc_times) / n_iter * 1000

        # Déchiffrement
        dec_times = []
        for _ in range(n_iter):
            t0 = time.perf_counter()
            decrypt(ct, password)
            dec_times.append(time.perf_counter() - t0)
        avg_dec = sum(dec_times) / n_iter * 1000

        # Débit (MB/s)
        throughput = (size / (avg_enc / 1000)) / (1024 * 1024)  # MB/s

        size_str = _human_size(size)
        ct_size = _human_size(len(ct))
        print(f"{size_str:>10} {ct_size:>10} {avg_enc:>11.1f} ms {avg_dec:>11.1f} ms {throughput:>9.1f} MB/s")

    print("\n" + "=" * 60)
    print("Notes :")
    print("  • Les temps de chiffrement incluent CBC interne + ChaCha20-Poly1305")
    print("  • Le KDF (Argon2id) est le facteur limitant pour les petits fichiers")
    print("  • Pour les gros fichiers, ChaCha20 domine (~3 GB/s sur CPU moderne)")
    print("=" * 60)
    
    return 0


# ------------------------------------------------------------------ #
#  Commande inspect                                                   #
# ------------------------------------------------------------------ #

def cmd_inspect(args) -> int:
    try:
        data = _read_input(args.input)
    except FileNotFoundError:
        print(f"Erreur : fichier introuvable : {args.input}", file=sys.stderr)
        return 1

    try:
        info = fmt_inspect(data)
    except CGL1FormatError as e:
        print(f"Format CGL1 invalide : {e}", file=sys.stderr)
        return 1

    print("=" * 60)
    print(f"Inspection CGL1 — {args.input}")
    print("=" * 60)
    print(f"\n  📦 En-tête:")
    print(f"     Magic          : {info['magic']} ({info['magic_hex']})")
    print(f"     Version        : {info['version']}")
    print(f"     Salt           : {info['salt_hex'][:32]}...")
    print(f"     Nonce          : {info['nonce_hex']}")
    
    print(f"\n  🔐 Authentification:")
    print(f"     Tag            : {info['tag_hex']}")
    print(f"     AAD (hashé)    : {info['aad_hex'][:32]}...")
    
    print(f"\n  📊 Statistiques:")
    print(f"     Données (CT)   : {_human_size(info['ciphertext_len'])}")
    print(f"     Taille totale  : {_human_size(info['total_size'])}")
    print(f"     Overhead fixe  : {info['overhead']} octets")
    print(f"     Ratio overhead : {(info['overhead']/info['total_size'])*100:.1f}%")
    
    return 0


# ------------------------------------------------------------------ #
#  Commande info (version, etc.)                                     #
# ------------------------------------------------------------------ #

def cmd_version(args) -> int:
    """Affiche la version et les informations du système."""
    print("CAGOULE v1.1 — Cryptographie Algébrique Géométrique")
    print("=" * 50)
    print(f"  Version      : 1.1 (CGL1)")
    print(f"  Python       : {sys.version.split()[0]}")
    print(f"  Mode         : Python (Phase 1C)")
    print(f"  AEAD         : ChaCha20-Poly1305 (RFC 8439)")
    print(f"  KDF          : Argon2id (t=3, m=64MB)")
    print(f"  Diffusion    : Vandermonde 16×16 (fallback Cauchy)")
    print(f"  S-box        : x³ + cx (Legendre + fallback x^d)")
    return 0


# ------------------------------------------------------------------ #
#  Point d'entrée                                                     #
# ------------------------------------------------------------------ #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='cagoule',
        description='CAGOULE v1.1 — Cryptographie Algébrique Géométrique par Ondes et Logique Entrelacée',
        epilog='Exemples:\n'
               '  cagoule encrypt secret.txt -p "monmotdepasse"\n'
               '  cagoule decrypt secret.txt.cgl1 -p "monmotdepasse"\n'
               '  cagoule bench -n 5\n'
               '  cagoule inspect fichier.cgl1',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest='command', required=True, help='Commande à exécuter')

    # ── encrypt ──
    enc = sub.add_parser('encrypt', help='Chiffrer un fichier')
    enc.add_argument('input', help='Fichier à chiffrer (- pour stdin)')
    enc.add_argument('-p', '--password', help='Mot de passe (sinon prompt sécurisé)')
    enc.add_argument('-o', '--output', help='Fichier de sortie (défaut: <input>.cgl1)')

    # ── decrypt ──
    dec = sub.add_parser('decrypt', help='Déchiffrer un fichier CGL1')
    dec.add_argument('input', help='Fichier CGL1 (- pour stdin)')
    dec.add_argument('-p', '--password', help='Mot de passe (sinon prompt sécurisé)')
    dec.add_argument('-o', '--output', help='Fichier de sortie (défaut: sans extension .cgl1)')

    # ── bench ──
    bench = sub.add_parser('bench', help='Benchmark de performance')
    bench.add_argument('-n', '--iterations', type=int, default=3,
                       help="Nombre d'itérations (défaut: 3)")

    # ── inspect ──
    ins = sub.add_parser('inspect', help='Inspecter un fichier CGL1 (sans déchiffrer)')
    ins.add_argument('input', help='Fichier CGL1 à inspecter')

    # ── version ──
    ver = sub.add_parser('version', help='Afficher la version et les informations')

    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    dispatch = {
        'encrypt': cmd_encrypt,
        'decrypt': cmd_decrypt,
        'bench': cmd_bench,
        'inspect': cmd_inspect,
        'version': cmd_version,
    }
    
    try:
        return dispatch[args.command](args)
    except KeyboardInterrupt:
        print("\nInterrompu par l'utilisateur.", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Erreur inattendue : {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())