"""Syntax-check the standalone dashboard JavaScript asset with Node.js."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_JS = ROOT / "dashboard.js"


def main() -> int:
    node = shutil.which("node")
    if not node:
        raise SystemExit(
            "Node.js is required for the dashboard JavaScript syntax check."
        )
    if not DASHBOARD_JS.is_file():
        raise SystemExit(f"Dashboard JavaScript asset is missing: {DASHBOARD_JS}")
    if DASHBOARD_JS.stat().st_size == 0:
        raise SystemExit("Dashboard JavaScript asset is empty.")

    subprocess.run([node, "--check", str(DASHBOARD_JS)], check=True)
    print("Dashboard JavaScript syntax: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
