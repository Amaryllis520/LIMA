#!/usr/bin/env python3
"""Measure an explicit local command without importing any analysis pipeline."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from lima.competition_performance import main
except ModuleNotFoundError as exc:
    if exc.name != "psutil":
        raise
    print(
        "collector_error: missing psutil; install requirements.txt; command_exit_code=None",
        file=sys.stderr,
    )
    raise SystemExit(125) from None

if __name__ == "__main__":
    raise SystemExit(main())
