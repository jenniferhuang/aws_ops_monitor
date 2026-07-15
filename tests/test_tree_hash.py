from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy" / "tree-hash.py"
REMOTE_DEPLOY = ROOT / "deploy" / "remote-deploy.sh"


def calculate(directory: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(directory)],
        check=False,
        capture_output=True,
        text=True,
    )


class TreeHashTests(unittest.TestCase):
    def test_remote_extraction_normalizes_permissions_before_tree_hash(self) -> None:
        script = REMOTE_DEPLOY.read_text(encoding="utf-8")
        normalization = """umask 022
tar --no-same-owner --no-same-permissions -C \"$stage\" -xzf \"$archive\"
rm -f -- \"$archive\"
tree_sha256=$(python3 \"$stage/deploy/tree-hash.py\" \"$stage\")"""
        self.assertIn(normalization, script)

    def test_hash_is_deterministic_and_ignores_release_markers(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            (directory / "nested").mkdir()
            (directory / "nested" / "data.txt").write_text("one\n", encoding="utf-8")
            first = calculate(directory)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertRegex(first.stdout.strip(), r"^[0-9a-f]{64}$")

            (directory / "REVISION").write_text("a" * 40, encoding="ascii")
            (directory / "TREE_SHA256").write_text("b" * 64, encoding="ascii")
            second = calculate(directory)
            self.assertEqual(first.stdout, second.stdout)

            (directory / "nested" / "data.txt").write_text("two\n", encoding="utf-8")
            third = calculate(directory)
            self.assertNotEqual(second.stdout, third.stdout)

    def test_symbolic_links_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            target = directory / "target"
            target.write_text("data", encoding="utf-8")
            try:
                (directory / "link").symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symbolic links are unavailable")
            result = calculate(directory)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("symbolic link", result.stderr)


if __name__ == "__main__":
    unittest.main()
