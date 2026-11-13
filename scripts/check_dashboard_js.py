"""Extract and syntax-check the dashboard JavaScript embedded in networkradar.py."""
from __future__ import annotations

import ast
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "networkradar.py"


def main() -> int:
    node = shutil.which("node")
    if not node:
        raise SystemExit("Node.js is required for the dashboard JavaScript syntax check.")

    tree = ast.parse(SOURCE.read_text(encoding="utf-8-sig"), filename=str(SOURCE))
    value = None
    for item in tree.body:
        if isinstance(item, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "DASHBOARD_JS_BUNDLED"
            for target in item.targets
        ):
            value = ast.literal_eval(item.value)
            break
    if not isinstance(value, str) or not value.strip():
        raise SystemExit("DASHBOARD_JS_BUNDLED was not found or is empty.")

    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix=".js", delete=False
    ) as handle:
        handle.write(value)
        path = Path(handle.name)
    try:
        subprocess.run([node, "--check", str(path)], check=True)
    finally:
        path.unlink(missing_ok=True)
    print("Dashboard JavaScript syntax: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
