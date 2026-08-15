#!/usr/bin/env bash
#
# scripts/bench_pinned.sh — CAGOULE v3.2.0, Item 0b
#
# Re-measures CTR throughput (C AVX2, C forced-scalar, Python e2e) with
# environment controls a shared VM cannot provide: CPU governor pinned to
# "performance", Turbo Boost disabled, process pinned to an isolated core.
#
# This script does NOT invent numbers when a control is unavailable — it
# runs anyway, but every uncontrolled variable is reported explicitly in
# the output table's own "environment" header, not silently assumed away.
#
# Usage:
#   scripts/bench_pinned.sh [--core N] [--runs N] [--warmup N] [--out FILE]
#
# Exit code is always 0 on a successful run (even with degraded controls);
# the output table itself is the record of what was actually controlled.

set -euo pipefail

CORE="${CORE:-0}"
RUNS="${RUNS:-11}"
WARMUP="${WARMUP:-3}"
OUT=""
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
C_DIR="$REPO_ROOT/cagoule/c"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --core)   CORE="$2"; shift 2 ;;
    --runs)   RUNS="$2"; shift 2 ;;
    --warmup) WARMUP="$2"; shift 2 ;;
    --out)    OUT="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

TS="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -z "$OUT" ]]; then
  mkdir -p "$REPO_ROOT/benchmark_results"
  OUT="$REPO_ROOT/benchmark_results/bench_pinned_${TS}.md"
fi

log() { echo "[bench_pinned] $*" >&2; }

# ── 1. CPU auto-detect ──────────────────────────────────────────────────
CPU_MODEL="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed 's/^ *//')"
CPU_MODEL="${CPU_MODEL:-unknown}"
NPROC="$(nproc 2>/dev/null || echo unknown)"
ARCH="$(uname -m)"
IS_VM="$(systemd-detect-virt 2>/dev/null | tr -d '\r\n' || echo none)"
log "CPU: $CPU_MODEL | arch=$ARCH | nproc=$NPROC | virt=$IS_VM"

# ── 2. Governor → performance (best-effort; requires root + real host) ──
GOVERNOR_STATUS="unavailable"
ORIG_GOV=""
GOV_PATH="/sys/devices/system/cpu/cpu${CORE}/cpufreq/scaling_governor"
if [[ -w "$GOV_PATH" ]]; then
  ORIG_GOV="$(cat "$GOV_PATH")"
  if echo performance > "$GOV_PATH" 2>/dev/null; then
    GOVERNOR_STATUS="set to performance (was: $ORIG_GOV)"
  else
    GOVERNOR_STATUS="present but write failed (needs root)"
  fi
elif command -v cpupower >/dev/null 2>&1; then
  if cpupower frequency-set -g performance >/dev/null 2>&1; then
    GOVERNOR_STATUS="set to performance (via cpupower)"
  else
    GOVERNOR_STATUS="cpupower present but failed (needs root)"
  fi
else
  GOVERNOR_STATUS="no cpufreq sysfs, no cpupower — likely a VM with no host CPU control"
fi
log "governor: $GOVERNOR_STATUS"

# ── 3. Turbo Boost → disabled (best-effort) ─────────────────────────────
TURBO_STATUS="unavailable"
if [[ -w /sys/devices/system/cpu/intel_pstate/no_turbo ]]; then
  echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null \
    && TURBO_STATUS="disabled (intel_pstate/no_turbo)" \
    || TURBO_STATUS="present but write failed (needs root)"
elif [[ -w /sys/devices/system/cpu/cpufreq/boost ]]; then
  echo 0 > /sys/devices/system/cpu/cpufreq/boost 2>/dev/null \
    && TURBO_STATUS="disabled (cpufreq/boost)" \
    || TURBO_STATUS="present but write failed (needs root)"
else
  TURBO_STATUS="no turbo control interface exposed — likely a VM"
fi
log "turbo: $TURBO_STATUS"

# ── 4. Pin to isolated core ─────────────────────────────────────────────
RUNNER=""
TASKSET_STATUS="unavailable"
if command -v taskset >/dev/null 2>&1; then
  RUNNER="taskset -c $CORE"
  TASKSET_STATUS="pinned to core $CORE"
  if grep -q "isolcpus" /proc/cmdline 2>/dev/null; then
    TASKSET_STATUS="pinned to core $CORE (isolcpus active in kernel cmdline)"
  else
    TASKSET_STATUS="pinned to core $CORE (isolcpus NOT set — core is not scheduler-isolated, other processes can still land on it)"
  fi
else
  TASKSET_STATUS="taskset not installed"
fi
log "taskset: $TASKSET_STATUS"

# ── 5. Build ─────────────────────────────────────────────────────────────
log "building test binaries..."
make -C "$C_DIR" clean >/dev/null
make -C "$C_DIR" tests -j"$(nproc)" >/dev/null
log "build OK"

# NOTE (found during Item 0b): every test_* binary uses `-Wl,-rpath,.`
# which resolves relative to the process CWD, not the binary's location.
# Worked around via LD_LIBRARY_PATH. The real fix is `-Wl,-rpath,'$ORIGIN'`
# in the Makefile — out of scope for this script.
export LD_LIBRARY_PATH="$C_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

# ── 6. Run: C, AVX2, CTR ─────────────────────────────────────────────────
run_metric () {
  local binary="$1" grep_pat="$2"
  local results=() i val
  for ((i=1; i<=WARMUP; i++)); do
    $RUNNER "$C_DIR/$binary" >/dev/null 2>&1 || true
  done
  for ((i=1; i<=RUNS; i++)); do
    val="$($RUNNER "$C_DIR/$binary" 2>&1 | grep -oE "$grep_pat" | grep -oE '[0-9]+\.[0-9]+' | head -1 || true)"
    [[ -n "$val" ]] && results+=("$val")
  done
  if [[ "${#results[@]}" -eq 0 ]]; then
    echo "n/a n/a n/a n/a"
    return
  fi
  printf '%s\n' "${results[@]}" | sort -n | awk '
    { sum+=$1; n++; if(NR==1||$1<min)min=$1; if(NR==1||$1>max)max=$1; vals[NR]=$1 }
    END {
      mean=sum/n
      med = (n%2==1) ? vals[(n+1)/2] : (vals[n/2]+vals[n/2+1])/2
      printf "%.2f %.2f %.2f %.2f", mean, med, min, max
    }'
}

CTR_LINE_PAT='[0-9]+\.[0-9]+ MB/s$'

log "measuring CTR AVX2 (production config)..."
read -r AVX2_MEAN AVX2_MED AVX2_MIN AVX2_MAX <<< "$(run_metric test_ctr "$CTR_LINE_PAT")"

log "measuring CTR forced-scalar..."
CAGOULE_FORCE_SCALAR_RESULTS=()
for ((i=1; i<=WARMUP; i++)); do
  CAGOULE_FORCE_SCALAR=1 $RUNNER "$C_DIR/test_ctr" >/dev/null 2>&1 || true
done
for ((i=1; i<=RUNS; i++)); do
  v="$(CAGOULE_FORCE_SCALAR=1 $RUNNER "$C_DIR/test_ctr" 2>&1 | grep -oE "$CTR_LINE_PAT" | grep -oE '[0-9]+\.[0-9]+' | head -1 || true)"
  [[ -n "$v" ]] && CAGOULE_FORCE_SCALAR_RESULTS+=("$v")
done
if [[ "${#CAGOULE_FORCE_SCALAR_RESULTS[@]}" -gt 0 ]]; then
  read -r SCALAR_MEAN SCALAR_MED SCALAR_MIN SCALAR_MAX <<< "$(printf '%s\n' "${CAGOULE_FORCE_SCALAR_RESULTS[@]}" | sort -n | awk '
    { sum+=$1; n++; if(NR==1||$1<min)min=$1; if(NR==1||$1>max)max=$1; vals[NR]=$1 }
    END { mean=sum/n; med=(n%2==1)?vals[(n+1)/2]:(vals[n/2]+vals[n/2+1])/2
          printf "%.2f %.2f %.2f %.2f", mean, med, min, max }')"
else
  SCALAR_MEAN=n/a; SCALAR_MED=n/a; SCALAR_MIN=n/a; SCALAR_MAX=n/a
fi

# ── 7. Run: Python e2e (pre-derived params to avoid Argon2id per iteration) ──
log "measuring Python e2e (encrypt_ctr, 1 MB payload, pre-derived params)..."
export CAGOULE_REPO_ROOT="$REPO_ROOT"
PY_SCRIPT='
import time, statistics, sys, os
sys.path.insert(0, os.environ["CAGOULE_REPO_ROOT"])
from cagoule.cipher_ctr import encrypt_ctr
from cagoule.params import CagouleParams
payload = b"\x00" * (1024 * 1024)
password = b"bench-pinned-item-0b"

params = CagouleParams.derive(password)
try:
    for _ in range(3):
        encrypt_ctr(payload, password, params=params)
    samples = []
    for _ in range(11):
        t0 = time.perf_counter()
        encrypt_ctr(payload, password, params=params)
        t1 = time.perf_counter()
        samples.append((1024*1024) / (t1 - t0) / (1024*1024))
finally:
    params.zeroize()

samples.sort()
n = len(samples)
med = samples[n//2] if n % 2 else (samples[n//2 - 1] + samples[n//2]) / 2
print(f"{statistics.mean(samples):.2f} {med:.2f} {min(samples):.2f} {max(samples):.2f}")
'
if PY_OUT="$($RUNNER python3 -c "$PY_SCRIPT" 2>/tmp/bench_pinned_py_err.log)"; then
  read -r PY_MEAN PY_MED PY_MIN PY_MAX <<< "$PY_OUT"
else
  log "WARNING: python e2e leg failed — see /tmp/bench_pinned_py_err.log"
  PY_MEAN=n/a; PY_MED=n/a; PY_MIN=n/a; PY_MAX=n/a
fi

# ── 8. Restore governor (best-effort) ────────────────────────────────────
if [[ -n "${ORIG_GOV}" && -w "$GOV_PATH" ]]; then
  echo "$ORIG_GOV" > "$GOV_PATH" 2>/dev/null || true
fi

# ── 9. Emit Markdown table — this is the ePrint-ready artifact ──────────
{
  echo "## CAGOULE v3.2.0 — Pinned-Hardware Benchmark"
  echo
  echo "Generated by \`scripts/bench_pinned.sh\` on $TS."
  echo
  echo "### Environment"
  echo
  echo "| Control | Status |"
  echo "|---|---|"
  echo "| CPU | $CPU_MODEL |"
  echo "| Architecture | $ARCH |"
  echo "| Logical cores | $NPROC |"
  echo "| Virtualization | $IS_VM |"
  echo "| Governor | $GOVERNOR_STATUS |"
  echo "| Turbo Boost | $TURBO_STATUS |"
  echo "| Core pinning | $TASKSET_STATUS |"
  echo "| Warmup runs | $WARMUP |"
  echo "| Measured runs | $RUNS |"
  echo
  if [[ "$GOVERNOR_STATUS" == *"VM"* || "$TURBO_STATUS" == *"VM"* ]]; then
    echo "> ⚠️ **This run does not meet Item 0b's acceptance bar.** One or more"
    echo "> hardware controls (governor / Turbo Boost) were not available —"
    echo "> see the environment table above for which. The methodology below"
    echo "> is correct and this script is unattended-ready; it has simply not"
    echo "> yet been run on hardware where those controls exist. Do not cite"
    echo "> the throughput numbers below as the Item 0b baseline until re-run"
    echo "> on real, non-virtualized hardware."
    echo
  fi
  echo "### Results"
  echo
  echo "| Metric | Mean (MB/s) | Median (MB/s) | Min (MB/s) | Max (MB/s) | n |"
  echo "|---|---|---|---|---|---|"
  echo "| CTR encrypt, C, AVX2, production config | $AVX2_MEAN | $AVX2_MED | $AVX2_MIN | $AVX2_MAX | $RUNS |"
  echo "| CTR encrypt, C, forced scalar | $SCALAR_MEAN | $SCALAR_MED | $SCALAR_MIN | $SCALAR_MAX | $RUNS |"
  echo "| CTR encrypt, Python end-to-end (1 MB) | $PY_MEAN | $PY_MED | $PY_MIN | $PY_MAX | $RUNS |"
  echo
  echo "### Notes"
  echo
  echo "- All figures are throughput on a single message repeated \`n\` times, not amortized across sizes — see cagoule-bench for the size-sweep suite."
  echo "- Median is reported alongside mean because MB/s figures on shared/virtualized hardware are frequently right-skewed by scheduler contention; mean alone can overstate typical performance."
  echo "- Python e2e uses pre-derived CagouleParams (Argon2id cost excluded from timing) — this measures cipher + ctypes + AEAD, not KDF."
  echo "- Source for the forced-scalar leg: \`CAGOULE_FORCE_SCALAR=1\` env var, per CHANGELOG.md."
} > "$OUT"

log "wrote $OUT"
cat "$OUT"
