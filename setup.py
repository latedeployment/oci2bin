"""Setuptools hooks for bundling oci2bin runtime helper scripts."""

import importlib.util
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py
from setuptools.command.egg_info import egg_info as _egg_info
from setuptools.command.sdist import sdist as _sdist


ROOT = Path(__file__).resolve().parent


def _load_package_manifest():
    path = ROOT / "scripts" / "package_manifest.py"
    spec = importlib.util.spec_from_file_location("package_manifest", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sync_package_scripts():
    _load_package_manifest().sync_package_scripts(ROOT)


class egg_info(_egg_info):
    def run(self):
        _sync_package_scripts()
        super().run()


class build_py(_build_py):
    def run(self):
        _sync_package_scripts()
        super().run()


class sdist(_sdist):
    def run(self):
        _sync_package_scripts()
        super().run()


setup(cmdclass={"egg_info": egg_info, "build_py": build_py, "sdist": sdist})
