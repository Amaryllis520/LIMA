#!/usr/bin/env python3
"""Strict outcome classifier for the expat composition dual control.

Review round 3: the runner previously accepted ANY
``ERROR: AddressSanitizer`` line on the vulnerable side, so an unrelated
ASan fault (a SEGV in the driver, a leak report, a UAF off the audited
path) could pass the dual control.  The expected vulnerable outcome is
now the exact mechanism signature:

- ``heap-use-after-free`` (the shared-DTD use), AND
- at least one ``xmlparse.c`` frame in the report (attributed to the
  audited TU, not the driver or libc), AND
- the parent-reset path: ``XML_ParserReset`` plus (``dtdReset`` or
  ``hashTableIterInit``) -- touching the freed shared DTD.

The fixed side must complete the sweep (``sweep done: 64 ordinals, no
crash``) with no AddressSanitizer and no LeakSanitizer report.

Usage:  classify_probe_log.py LOG {vulnerable,fixed}
Exit:   0 = outcome matches the role's expectation; 1 = it does not
        (reason on stdout).  Anything unexpected fails closed.
"""

from __future__ import annotations

import sys

FIXED_COMPLETION = "sweep done: 64 ordinals, no crash"


def classify(text: str, role: str) -> tuple[bool, str]:
    if role not in ("vulnerable", "fixed"):
        return False, f"unknown role: {role}"
    asan_report = "ERROR: AddressSanitizer" in text
    leak_report = "ERROR: LeakSanitizer" in text

    if role == "fixed":
        if asan_report:
            return False, "fixed side produced an AddressSanitizer report"
        if leak_report:
            return False, "fixed side produced a LeakSanitizer report"
        if FIXED_COMPLETION not in text:
            return False, "fixed side did not complete the sweep"
        return True, "clean sweep completion"

    if "ERROR: AddressSanitizer: heap-use-after-free" not in text:
        if asan_report:
            head = text.split("ERROR: AddressSanitizer", 1)[1][:80]
            return False, (
                "ASan report is not a heap-use-after-free:" + head
            )
        if leak_report:
            return False, "only a LeakSanitizer report, no crash"
        if FIXED_COMPLETION in text:
            return False, "vulnerable side completed the sweep cleanly"
        return False, "no ASan report (inconclusive or bare-crash run)"
    if "xmlparse.c" not in text:
        return False, "heap-use-after-free not attributed to xmlparse.c"
    if "XML_ParserReset" not in text:
        return False, "parent-reset frame (XML_ParserReset) missing"
    if "dtdReset" not in text and "hashTableIterInit" not in text:
        return False, "shared-DTD frame (dtdReset/hashTableIterInit) missing"
    return True, (
        "heap-use-after-free attributed to xmlparse.c on the parent-reset path"
    )


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: classify_probe_log.py LOG {vulnerable,fixed}",
              file=sys.stderr)
        return 2
    log, role = argv[1], argv[2]
    with open(log, encoding="utf-8", errors="replace") as handle:
        ok, detail = classify(handle.read(), role)
    print(f"classify[{role}]: {'OK' if ok else 'UNEXPECTED'} -- {detail}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
