import subprocess
import sys
import tempfile
import os

src = '#include <immintrin.h>\nint main(){__m256i x=_mm256_setzero_si256();(void)x;return 0;}\n'
with tempfile.NamedTemporaryFile(suffix='.c', mode='w', delete=False) as f:
    f.write(src)
    fname = f.name

try:
    cc = os.environ.get('CC', 'gcc')
    r = subprocess.run(
        [cc, '-mavx2', '-c', fname, '-o', os.devnull],
        capture_output=True
    )
    print('yes' if r.returncode == 0 else 'no')
finally:
    try:
        os.unlink(fname)
    except OSError:
        pass