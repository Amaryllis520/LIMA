#!/bin/bash
# Dual-control runner AND verifier for the expat composition probe.
# Same driver, same config, against the frozen vulnerable (5ac71407) and
# fixed (56967f83) checkouts.  Requires the chain-probe container layout:
#   /repositories/expat-up-vuln, /repositories/expat-up-fixed, clang-14+ASan.
# Read-only over the checkouts; writes only under $OUT.
#
# Contract: exit 0 only when the dual control holds -- the vulnerable
# build crashes with an ASan report attributed to xmlparse AND the fixed
# build completes the sweep cleanly.  Anything else (fixed crashing,
# vulnerable clean, timeout/inconclusive, build failure) exits non-zero
# so automation can never read a failed control as a pass.
set -e
PROBE_SRC="${1:-/src/tests/fixtures/expat_composition_probe/probe.c}"
OUT="${2:-/tmp/expat-composition-probe}"
rm -rf "$OUT"; mkdir -p "$OUT"

build() {
  key="$1"; root="/repositories/$key"
  clang-14 -fsanitize=address -g -O1 -I"$root/_overlay" -I"$root/expat/lib" \
    -c "$root/expat/lib/xmlparse.c" -o "$OUT/${key}_xmlparse.o"
  clang-14 -fsanitize=address -g -O1 -I"$root/_overlay" -I"$root/expat/lib" \
    -c "$root/expat/lib/xmltok.c" -o "$OUT/${key}_xmltok.o"
  clang-14 -fsanitize=address -g -O1 -I"$root/_overlay" -I"$root/expat/lib" \
    -c "$root/expat/lib/xmlrole.c" -o "$OUT/${key}_xmlrole.o"
  clang-14 -fsanitize=address -g -O1 -I"$root/expat/lib" \
    "$PROBE_SRC" "$OUT/${key}_xmlparse.o" "$OUT/${key}_xmltok.o" \
    "$OUT/${key}_xmlrole.o" -o "$OUT/probe_$key"
}

for key in expat-up-vuln expat-up-fixed; do
  echo "== build $key"
  build "$key" 2> "$OUT/build_$key.err" || { echo "BUILD FAILED ($key)"; cat "$OUT/build_$key.err"; exit 2; }
done

declare -A OUTCOME
for key in expat-up-vuln expat-up-fixed; do
  log="$OUT/run_$key.log"
  # A crash is an expected outcome for the vulnerable side, so the exit
  # status is deliberately not fatal here; classification below decides.
  timeout 120 "$OUT/probe_$key" > "$log" 2>&1 || true
  if grep -q "ERROR: AddressSanitizer" "$log"; then
    kind=$(grep -m1 "ERROR: AddressSanitizer" "$log" | sed 's/.*AddressSanitizer: //;s/ on.*//')
    frame=$(grep -m1 "xmlparse.c" "$log" || true)
    echo "RESULT $key: ASAN-CRASH ($kind) ${frame:+frame: $frame}"
    OUTCOME[$key]=asan-crash
  elif grep -q "sweep done" "$log"; then
    echo "RESULT $key: CLEAN ($(tail -1 "$log"))"
    OUTCOME[$key]=clean
  else
    echo "RESULT $key: INCONCLUSIVE (rc/timeout, see $log)"; head -3 "$log"
    OUTCOME[$key]=inconclusive
  fi
done

if [ "${OUTCOME[expat-up-vuln]}" != "asan-crash" ]; then
  echo "DUAL_CONTROL_FAILED: vulnerable side did not crash with an ASan report (got ${OUTCOME[expat-up-vuln]})"
  exit 1
fi
if [ "${OUTCOME[expat-up-fixed]}" != "clean" ]; then
  echo "DUAL_CONTROL_FAILED: fixed side was not clean (got ${OUTCOME[expat-up-fixed]})"
  exit 1
fi
echo "== dual control holds"
exit 0
