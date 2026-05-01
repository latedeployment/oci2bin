"""
Unit tests for the .dockerignore matcher in scripts/dockerfile_build.py.
"""

import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest


_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location(
    "dockerfile_build",
    _ROOT / "scripts" / "dockerfile_build.py",
)
_MOD = importlib.util.module_from_spec(_SPEC)
sys.path.insert(0, str(_ROOT / "scripts"))
_SPEC.loader.exec_module(_MOD)


def _make(ctx, content):
    with open(os.path.join(ctx, ".dockerignore"), "w") as f:
        f.write(content)
    return _MOD._DockerIgnore(ctx)


class DockerIgnoreTest(unittest.TestCase):
    def setUp(self):
        self.ctx = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.ctx, ignore_errors=True)

    def test_missing_dockerignore_excludes_nothing(self):
        di = _MOD._DockerIgnore(self.ctx)
        self.assertFalse(di.matches("a.txt"))
        self.assertFalse(di.matches("deep/nested/path"))

    def test_simple_glob_excludes_files(self):
        di = _make(self.ctx, "*.log\n")
        self.assertTrue(di.matches("a.log"))
        self.assertTrue(di.matches("logs/app.log"))
        self.assertFalse(di.matches("a.txt"))

    def test_negation_reincludes(self):
        di = _make(self.ctx, "*.log\n!important.log\n")
        self.assertTrue(di.matches("a.log"))
        self.assertFalse(di.matches("important.log"))

    def test_directory_pattern(self):
        di = _make(self.ctx, "node_modules/\n")
        self.assertTrue(di.matches("node_modules"))
        self.assertTrue(di.matches("node_modules/foo"))
        self.assertTrue(di.matches("nested/node_modules"))
        self.assertFalse(di.matches("not_node_modules"))

    def test_anchored_pattern(self):
        di = _make(self.ctx, "/build\n")
        self.assertTrue(di.matches("build"))
        # An anchored "/build" should NOT match a deeper occurrence.
        self.assertFalse(di.matches("nested/build"))

    def test_double_star_glob(self):
        di = _make(self.ctx, "docs/**/*.md\n")
        self.assertTrue(di.matches("docs/a.md"))
        self.assertTrue(di.matches("docs/sub/a.md"))
        self.assertTrue(di.matches("docs/sub/dir/a.md"))
        self.assertFalse(di.matches("notes/a.md"))

    def test_comments_and_blank_ignored(self):
        di = _make(self.ctx, "# this is a comment\n\n*.tmp\n")
        self.assertTrue(di.matches("foo.tmp"))
        self.assertFalse(di.matches("foo.md"))

    def test_later_pattern_wins(self):
        di = _make(self.ctx, "*.log\nimportant.log\n!important.log\n")
        self.assertFalse(di.matches("important.log"))


if __name__ == "__main__":
    unittest.main()
