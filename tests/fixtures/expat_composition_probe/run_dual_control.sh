#!/bin/bash
# Dual-control runner for the expat composition probe.
# Same driver, same config, against the frozen vulnerable (5ac71407) and
# fixed (56967f83) checkouts.  Requires the chain-probe container layout:
#   /repositories/expat-up-vuln, /repositories/expat-up-fixed, clang-14+ASan.
# Read-only over the checkouts; writes only under $OUT.
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
  build "$key" 2> "$OUT/build_$key.err" || { echo "BUILD FAILED"; cat "$OUT/build_$key.err"; exit 1; }
done

for key in expat-up-vuln expat-up-fixed; do
  log="$OUT/run_$key.log"
  timeout 120 "$OUT/probe_$key" > "$log" 2>&1 || true
  if grep -q "ERROR: AddressSanitizer" "$log"; then
    kind=$(grep -m1 "ERROR: AddressSanitizer" "$log" | sed 's/.*AddressSanitizer: //;s/ on.*//')
    frame=$(grep -m1 "in doProlog\|in parserInit\|in externalParEnt\|xmlparse.c" "$log" || true)
    echo "RESULT $key: ASAN-CRASH ($kind) ${frame:+frame: $frame}"
  elif grep -q "sweep done" "$log"; then
    echo "RESULT $key: CLEAN ($(tail -1 "$log"))"
  else
    echo "RESULT $key: INCONCLUSIVE (rc/timeout, see $log)"; head -3 "$log"
  fi
done
echo "== done"
