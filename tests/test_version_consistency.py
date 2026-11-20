"""Guard the single canonical NetworkRadar version across release metadata."""
import unittest
from pathlib import Path

from networkradar_modules import __version__


ROOT = Path(__file__).resolve().parents[1]


class VersionConsistencyTests(unittest.TestCase):
    def test_release_metadata_uses_package_version(self):
        expected = __version__
        checks = {
            "networkradar.py": f"NetworkRadar {expected}",
            "NetworkRadar.ps1": f"NetworkRadar {expected} launcher",
            "requirements.txt": f"NetworkRadar {expected} core runtime",
            "README.md": f"# NetworkRadar {expected}",
            "RELEASE_NOTES.md": f"# NetworkRadar {expected}",
            "docs/ARCHITECTURE.md": (
                f"# NetworkRadar architecture — repository snapshot {expected}"
            ),
        }
        for relative_path, marker in checks.items():
            with self.subTest(path=relative_path):
                text = (ROOT / relative_path).read_text(encoding="utf-8-sig")
                self.assertIn(marker, text)


if __name__ == "__main__":
    unittest.main()
