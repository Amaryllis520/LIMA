#!/bin/bash
# Dual-control runner AND verifier for the expat composition probe.
# Same driver, same config, against the frozen vulnerable (5ac71407) and
# fixed (56967f83) checkouts.  Requires the chain-probe container layout:
#   /repositories/expat-up-vuln, /repositories/expat-up-fixed, clang-14+ASan.
# Read-only over the checkouts; writes only under $OUT.
#
# Contract: exit 0 only when the dual control holds -- the vulnerable
# build crashes with the MECHANISM SIGNATURE (heap-use-after-free,
# attributed to xmlparse.c, on the parent-reset path; enforced by
# classify_probe_log.py, which rejects any unrelated ASan report) AND
# the fixed build completes the sweep with no sanitizer report.
# Anything else (build failure, wrong crash kind, off-path attribution,
# fixed crashing, clean vulnerable side, timeout) exits non-zero so
# automation can never read a failed control as a pass.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
PROBE_SRC="${1:-$HERE/probe.c}"
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

classify() {
  key="$1"; role="$2"; log="$OUT/run_$key.log"
  # A crash is an expected outcome for the vulnerable side, so the exit
  # status is deliberately not fatal here; the classifier decides.
  timeout 120 "$OUT/probe_$key" > "$log" 2>&1 || true
  if detail=$(python3 "$HERE/classify_probe_log.py" "$log" "$role"); then
    echo "RESULT $key: EXPECTED -- ${detail#classify[$role]: OK -- }"
    return 0
  fi
  echo "RESULT $key: UNEXPECTED -- $detail"
  return 1
}

vuln_ok=0; fixed_ok=0
classify expat-up-vuln vulnerable || vuln_ok=1
classify expat-up-fixed fixed || fixed_ok=1

if [ "$vuln_ok" -ne 0 ] || [ "$fixed_ok" -ne 0 ]; then
  echo "DUAL_CONTROL_FAILED: vulnerable=$vuln_ok fixed=$fixed_ok (0 = as expected)"
  exit 1
fi
echo "== dual control holds"
exit 0
